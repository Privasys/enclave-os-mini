// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! **WASM** — WebAssembly Component runtime module for enclave-os.
//!
//! This module embeds [wasmtime](https://wasmtime.dev/) inside the SGX
//! enclave, allowing operators to deploy complete WASM "apps" that are
//! compiled, attested, and executed within the hardware trust boundary.
//!
//! ## Architecture
//!
//! ```text
//! Client ──RA-TLS──▶ enclave OS ──dispatch──▶ WasmModule
//!                                                 │
//!                                         ┌───────┴───────┐
//!                                         │  AppRegistry  │
//!                                         │ ┌───────────┐ │
//!                                         │ │ App "A"   │ │
//!                                         │ │ exports:  │ │
//!                                         │ │ - process │ │
//!                                         │ │ - query   │ │
//!                                         │ └───────────┘ │
//!                                         │ ┌───────────┐ │
//!                                         │ │ App "B"   │ │
//!                                         │ │ exports:  │ │
//!                                         │ │ - handle  │ │
//!                                         │ └───────────┘ │
//!                                         └───────────────┘
//! ```
//!
//! Each app is a WASM **Component** (Component Model / WIT).  At load time
//! the module introspects the component's exports to build a routing table.
//! Client requests specify `(app, function, params)` and get routed to the
//! correct component instance.
//!
//! ## WASI capabilities
//!
//! WASI host functions are implemented by the enclave OS, not by the real
//! host operating system.  See [`wasi`] for the mapping:
//!
//! - **Random**: RDRAND via `getrandom` (hardware RNG, no OCALL)
//! - **Clocks**: OCALL `get_current_time()` (wall + monotonic)
//! - **Environment**: Controlled env vars from enclave config
//! - **I/O**: In-memory stdout/stderr capture, TCP sockets via OCALLs
//! - **Filesystem**: Sealed KV store backing
//!
//! ## Attestation
//!
//! Each loaded app's WASM bytecode hash (SHA-256) is:
//! 1. Included as a config Merkle leaf (`wasm.<app_name>.code_hash`)
//! 2. Aggregated into a combined hash exposed as X.509 OID
//!    `1.3.6.1.4.1.65230.2.5` in RA-TLS certificates.
//!
//! This allows clients to verify exactly which WASM apps are running
//! inside the enclave without trusting the host.
//!
//! ## Prerequisites
//!
//! This crate depends on a Privasys fork of wasmtime that includes the
//! SGX runtime backend (`target_vendor = "teaclave"` patches from
//! [commit fbbcd2ac](https://github.com/bytecodealliance/wasmtime/commit/fbbcd2ac)).
//!
//! The fork provides:
//! - Memory management via RWX code pool (`.wasm_code` section) + heap allocation
//! - Trap handling via VEH (`sgx_register_exception_handler`)
//! - Thread-local storage via `sgx_tstd::thread_local!`
//! - Stub unwind registration

pub mod enclave_sdk;
pub mod engine;
pub mod metrics;
pub mod protocol;
pub mod registry;
#[cfg(target_vendor = "teaclave")]
pub mod sgx_platform;
pub mod wasi;

use std::sync::Mutex;
use std::vec::Vec;

use ring::digest;
use enclave_os_common::hex::hex_decode;
use enclave_os_common::modules::{AppIdentity, ConfigEntry, ConfigLeaf, EnclaveModule, ModuleOid, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::types::AEAD_KEY_SIZE;

use crate::protocol::{AppPermissions, FunctionPolicy, WasmCall, WasmEnvelope, WasmManagementResult, WasmResult};
use crate::metrics::WasmMetricsStore;
use crate::registry::AppRegistry;

// ---------------------------------------------------------------------------
//  OID for WASM apps combined code hash — imported from common
// ---------------------------------------------------------------------------

pub use enclave_os_common::oids::WASM_APPS_HASH_OID;

use crate::registry::AppMeta;

// ---------------------------------------------------------------------------
//  KV keys for WASM app persistence
// ---------------------------------------------------------------------------

/// KV key storing the JSON array of all persisted app names.
const KV_MANIFEST: &[u8] = b"wasm:manifest";

/// Build the KV key for an app's serialised metadata.
fn kv_meta_key(name: &str) -> Vec<u8> {
    let mut k = b"wasm:meta:".to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

/// Build the KV key for an app's raw WASM bytecode.
fn kv_bytes_key(name: &str) -> Vec<u8> {
    let mut k = b"wasm:bytes:".to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

// ---------------------------------------------------------------------------
//  WasmModule — EnclaveModule implementation
// ---------------------------------------------------------------------------

/// The WASM module: Component Model runtime inside SGX.
///
/// Owns the [`AppRegistry`] which contains all loaded WASM apps,
/// and the [`WasmMetricsStore`] which tracks per-app/per-function
/// fuel consumption from wasmtime's fuel metering.
///
/// WASM apps are persisted in the sealed KV store and restored on
/// startup.  Only the 10 most recently used apps are kept compiled
/// in memory (LRU eviction) to conserve EPC.
pub struct WasmModule {
    registry: Mutex<AppRegistry>,
    metrics: Mutex<WasmMetricsStore>,
}

impl WasmModule {
    /// Create a new WASM module.
    ///
    /// Initialises wasmtime with SGX-appropriate settings and WASI
    /// host function bindings.  Restores persisted WASM app metadata
    /// from the sealed KV store (apps are compiled on demand).
    pub fn new() -> Result<Self, String> {
        let engine = crate::engine::WasmEngine::new()?;
        let mut registry = AppRegistry::new(engine);

        // Try to restore metrics from a previous snapshot in the KV store.
        let mut metrics_store = WasmMetricsStore::new();
        match metrics_store.load() {
            Ok(true) => { /* restored from KV */ }
            Ok(false) => { /* no snapshot — fresh start */ }
            Err(_) => { /* KV not ready or corrupt — start fresh */ }
        }

        // Restore persisted WASM app metadata from the KV store.
        // Apps are NOT compiled here — they will be lazy-loaded on
        // the first wasm_call.
        if let Some(kv) = enclave_os_kvstore::kv_store() {
            if let Ok(kv) = kv.lock() {
                if let Ok(Some(manifest_bytes)) = kv.get(KV_MANIFEST) {
                    if let Ok(names) = serde_json::from_slice::<Vec<String>>(&manifest_bytes) {
                        for name in &names {
                            if let Ok(Some(meta_bytes)) = kv.get(&kv_meta_key(name)) {
                                match serde_json::from_slice::<AppMeta>(&meta_bytes) {
                                    Ok(meta) => {
                                        enclave_os_common::enclave_log_info!(
                                            "Restored persisted WASM app: {} (hostname={})",
                                            meta.name, meta.hostname,
                                        );
                                        registry.register_known(meta);
                                    }
                                    Err(e) => {
                                        enclave_os_common::enclave_log_error!(
                                            "Failed to deserialise metadata for app '{}': {}",
                                            name, e,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            registry: Mutex::new(registry),
            metrics: Mutex::new(metrics_store),
        })
    }

    /// Load a WASM component from raw bytes.
    ///
    /// The app will be compiled, introspected, and registered under
    /// the given name.  Its code hash is automatically included in
    /// attestation (config Merkle leaves + X.509 OID).
    ///
    /// A per-app X.509 certificate identity is registered with the
    /// global [`CertStore`](cert_store::CertStore) so that clients
    /// connecting via the `hostname` SNI receive an app-specific cert.
    ///
    /// Each app gets its own AES-256 encryption key for KV store data.
    /// If `encryption_key` is `Some`, the caller supplies the key
    /// (BYOK). Otherwise a random key is generated inside the enclave.
    ///
    /// If `permissions` is `Some`, per-function access control is
    /// enforced on `wasm_call` using the app developer's own OIDC
    /// provider. The SHA-256 hash of the permissions JSON is included
    /// in the per-app RA-TLS certificate as OID 3.5.
    pub fn load_app(
        &self,
        name: &str,
        hostname: &str,
        wasm_bytes: &[u8],
        encryption_key: Option<[u8; AEAD_KEY_SIZE]>,
        permissions: Option<AppPermissions>,
        max_fuel: u64,
    ) -> Result<(), String> {
        // Load into the registry (compile + introspect + per-app key)
        let meta = {
            let mut reg = self.registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.load_app(name, hostname, wasm_bytes, encryption_key, permissions, max_fuel)?
        };

        // ── Persist to KV store ────────────────────────────────────
        self.persist_app_to_kv(name, &meta, wasm_bytes);

        // Register per-app identity with the global CertStore
        register_app_identity(&meta);

        Ok(())
    }

    /// Unload a WASM app by name.
    ///
    /// Removes the app from the registry **and** from the sealed KV
    /// store, then unregisters its identity from the global
    /// [`CertStore`](cert_store::CertStore).
    pub fn unload_app(&self, name: &str) -> bool {
        let hostname = self.registry
            .lock()
            .ok()
            .and_then(|mut r| r.remove_app(name));

        if let Some(ref h) = hostname {
            self.remove_app_from_kv(name);
            enclave_os_common::ocall::cert_store_unregister(h);
        }

        hostname.is_some()
    }

    /// List all known apps with metadata.
    ///
    /// Includes both compiled (loaded) and evicted apps. The `loaded`
    /// field on each [`AppInfo`](crate::protocol::AppInfo) indicates
    /// whether the app is currently compiled in EPC.
    pub fn list_apps(&self) -> Vec<crate::protocol::AppInfo> {
        self.registry
            .lock()
            .map(|r| r.list_apps())
            .unwrap_or_default()
    }

    /// Dispatch a parsed `WasmCall` to the appropriate app and record metrics.
    ///
    /// If the app is known but not currently compiled in memory, its
    /// WASM bytes are loaded from the sealed KV store and compiled
    /// on the fly (AOT deserialization — very fast).
    fn dispatch_call(&self, call: &WasmCall) -> WasmResult {
        // Ensure the app is compiled.  This is a no-op when the app
        // is already in the `loaded` map.
        if let Err(e) = self.ensure_app_loaded(&call.app) {
            return WasmResult::Error { message: e };
        }

        let (result, fuel_consumed) = {
            let mut registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    return WasmResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                }
            };
            registry.call(&call.app, &call.function, &call.params)
        };

        // Record fuel metrics.
        if let Ok(mut m) = self.metrics.lock() {
            match &result {
                WasmResult::Ok { .. } => {
                    m.record_call(&call.app, &call.function, fuel_consumed);
                }
                WasmResult::Error { .. } => {
                    if fuel_consumed > 0 {
                        // Execution started but failed (e.g. fuel exhaustion, trap).
                        m.record_call(&call.app, &call.function, fuel_consumed);
                    }
                    m.record_error(&call.app, &call.function);
                }
            }
        }

        result
    }

    /// Enforce per-app permission policy on a `wasm_call`.
    ///
    /// Returns `Some(Response)` with an error if the call is denied,
    /// or `None` if the call is permitted.
    ///
    /// **Logic**:
    /// - App has no permissions → call is public (no auth needed).
    /// - App has permissions → look up the function's policy:
    ///   - `public` → allow without auth.
    ///   - `authenticated` → require a valid token from the app's OIDC.
    ///   - `role` → require a valid token with at least one matching role.
    ///
    /// The app-level bearer token is taken from `call.app_auth`.
    fn check_app_permissions(&self, call: &WasmCall) -> Option<Response> {
        // Look up the app's permissions policy.
        let registry = self.registry.lock().ok()?;
        let permissions = match registry.app_permissions(&call.app) {
            Some(p) => p.clone(),
            None => return None, // No permissions → public access.
        };
        drop(registry); // Release lock before potentially slow token verification.

        // Determine the effective policy for this function.
        let (policy, required_roles) = match permissions.functions.get(&call.function) {
            Some(fp) => (&fp.policy, &fp.roles),
            None => (&permissions.default_policy, &permissions.default_roles),
        };

        // Public → no auth needed.
        if *policy == FunctionPolicy::Public {
            return None;
        }

        // The app-level bearer token is in the wasm_call's `app_auth` field.
        let token_str = match call.app_auth.as_deref() {
            Some(t) => t,
            None => {
                let err = WasmResult::Error {
                    message: format!(
                        "authentication required: function '{}' on app '{}' requires a valid token from {}",
                        call.function, call.app, permissions.oidc.issuer,
                    ),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        };

        // Verify the token against the app's OIDC provider.
        let caller_roles = match verify_app_token(token_str, &permissions.oidc) {
            Ok(roles) => roles,
            Err(e) => {
                let err = WasmResult::Error {
                    message: format!("app OIDC auth failed: {e}"),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        };

        // Authenticated → token is valid, no role check needed.
        if *policy == FunctionPolicy::Authenticated {
            return None;
        }

        // Role → check intersection.
        if !required_roles.is_empty() {
            let has_role = caller_roles.iter().any(|r| required_roles.contains(r));
            if !has_role {
                let err = WasmResult::Error {
                    message: format!(
                        "access denied: function '{}' on app '{}' requires one of {:?}",
                        call.function, call.app, required_roles,
                    ),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        }

        None // Permitted.
    }

    /// Compute the combined hash of all known apps' code hashes.
    ///
    /// `SHA-256(app1_name || app1_hash || app2_name || app2_hash || …)`
    /// where apps are sorted by name.
    fn combined_apps_hash(&self) -> [u8; 32] {
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return [0u8; 32],
        };

        let hashes = registry.all_code_hashes();
        if hashes.is_empty() {
            return [0u8; 32];
        }

        let mut ctx = digest::Context::new(&digest::SHA256);
        for (name, hash) in &hashes {
            ctx.update(name.as_bytes());
            ctx.update(*hash);
        }
        let result = ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(result.as_ref());
        out
    }

    // ── KV persistence helpers ─────────────────────────────────────

    /// Persist an app's metadata and WASM bytes to the sealed KV store
    /// and update the manifest.
    fn persist_app_to_kv(&self, name: &str, meta: &AppMeta, wasm_bytes: &[u8]) {
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return,
        };
        let kv = match kv.lock() {
            Ok(kv) => kv,
            Err(_) => return,
        };

        // Store metadata
        if let Ok(meta_json) = serde_json::to_vec(meta) {
            if let Err(e) = kv.put(&kv_meta_key(name), &meta_json) {
                enclave_os_common::enclave_log_error!(
                    "KV: failed to persist metadata for app '{}': {}", name, e,
                );
            }
        }

        // Store WASM bytes
        if let Err(e) = kv.put(&kv_bytes_key(name), wasm_bytes) {
            enclave_os_common::enclave_log_error!(
                "KV: failed to persist bytes for app '{}': {}", name, e,
            );
        }

        // Update manifest
        self.update_kv_manifest(&kv);
    }

    /// Remove an app's metadata and WASM bytes from the sealed KV
    /// store and update the manifest.
    fn remove_app_from_kv(&self, name: &str) {
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return,
        };
        let mut kv = match kv.lock() {
            Ok(kv) => kv,
            Err(_) => return,
        };

        let _ = kv.delete(&kv_meta_key(name));
        let _ = kv.delete(&kv_bytes_key(name));

        self.update_kv_manifest(&kv);
    }

    /// Rewrite the KV manifest from the current `known` map.
    fn update_kv_manifest(&self, kv: &enclave_os_kvstore::SealedKvStore) {
        let names: Vec<String> = self.registry
            .lock()
            .map(|r| {
                r.all_code_hashes()
                    .iter()
                    .map(|(name, _)| name.to_string())
                    .collect()
            })
            .unwrap_or_default();

        if let Ok(manifest_json) = serde_json::to_vec(&names) {
            if let Err(e) = kv.put(KV_MANIFEST, &manifest_json) {
                enclave_os_common::enclave_log_error!(
                    "KV: failed to update WASM manifest: {}", e,
                );
            }
        }
    }

    /// Ensure a known app is compiled in memory.
    ///
    /// If the app is already loaded this is a no-op.  Otherwise the
    /// WASM bytes are read from the sealed KV store and passed to
    /// [`AppRegistry::ensure_loaded()`] for AOT deserialization.
    fn ensure_app_loaded(&self, name: &str) -> Result<(), String> {
        // Quick check — no KV access needed if already compiled.
        {
            let reg = self.registry.lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            if reg.is_loaded(name) {
                return Ok(());
            }
            if !reg.is_known(name) {
                return Err(format!("app '{}' is not loaded", name));
            }
        }

        // Read WASM bytes from KV
        let wasm_bytes = {
            let kv = enclave_os_kvstore::kv_store()
                .ok_or_else(|| format!("KV store unavailable — cannot lazy-load app '{}'", name))?;
            let kv = kv.lock()
                .map_err(|_| String::from("KV store lock poisoned"))?;
            kv.get(&kv_bytes_key(name))
                .map_err(|e| format!("KV read failed for app '{}': {}", name, e))?
                .ok_or_else(|| format!("WASM bytes not found in KV for app '{}'", name))?
        };

        // Compile and insert into loaded map
        let mut reg = self.registry.lock()
            .map_err(|_| String::from("registry lock poisoned"))?;
        reg.ensure_loaded(name, &wasm_bytes)
    }
}

// ---------------------------------------------------------------------------
//  EnclaveModule implementation
// ---------------------------------------------------------------------------

impl EnclaveModule for WasmModule {
    fn name(&self) -> &str {
        "wasm"
    }

    /// Return identities for **all** known (persisted) WASM apps so
    /// that the CertStore registers per-app certificates on startup —
    /// even before the first `wasm_call` triggers lazy compilation.
    fn app_identities(&self) -> Vec<AppIdentity> {
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        registry.all_code_hashes()
            .iter()
            .filter_map(|(name, _)| {
                registry.get_known(name).map(|meta| build_app_identity(meta))
            })
            .collect()
    }

    /// Handle a client request.
    ///
    /// Recognises `Request::Data` containing a `WasmEnvelope` with one of:
    ///   - `wasm_call`    — call an exported function on a loaded app
    ///   - `wasm_load`    — load (or replace) a WASM app from raw bytes
    ///   - `wasm_unload`  — unload an app by name
    ///   - `wasm_list`    — list all loaded apps
    ///
    /// **Platform OIDC role requirements** (when OIDC is configured):
    /// - `wasm_load`, `wasm_unload`: requires **manager** role
    /// - `wasm_list`: requires **monitoring** role (manager also works)
    ///
    /// **App-level permissions** (when the app has a `permissions` policy):
    /// - `wasm_call`: enforced per-function using the app developer's own
    ///   OIDC provider.  If the app has no permissions, calls are public.
    ///
    /// Returns `None` if the payload doesn't match any recognised request
    /// (letting other modules handle the request).
    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };

        // Try to parse the envelope.
        let envelope: WasmEnvelope = match serde_json::from_slice(data) {
            Ok(e) => e,
            Err(e) => {
                // Log if the payload looks like a WASM envelope but failed to parse.
                if data.len() > 10 && (data.starts_with(b"{\"wasm_") || data.starts_with(b"{ \"wasm_")) {
                    enclave_os_common::enclave_log_error!(
                        "WasmModule: envelope parse failed ({} bytes): {}",
                        data.len(),
                        e
                    );
                }
                return None; // Not a WASM request — decline.
            }
        };

        // ── Platform OIDC role gate (load/unload/list) ──────────────
        let needs_manager = envelope.wasm_load.is_some()
            || envelope.wasm_unload.is_some();
        let needs_monitoring = envelope.wasm_list.is_some();

        if needs_manager {
            if let Some(ref claims) = ctx.oidc_claims {
                if !claims.has_manager() {
                    let err = serde_json::to_vec(&WasmManagementResult::Error {
                        message: String::from("manager role required"),
                    }).unwrap_or_default();
                    return Some(Response::Data(err));
                }
            } else if enclave_os_common::oidc::is_oidc_configured() {
                let err = serde_json::to_vec(&WasmManagementResult::Error {
                    message: String::from("OIDC authentication required (manager role)"),
                }).unwrap_or_default();
                return Some(Response::Data(err));
            }
        } else if needs_monitoring {
            if let Some(ref claims) = ctx.oidc_claims {
                if !claims.has_monitoring() {
                    let err = serde_json::to_vec(&WasmManagementResult::Error {
                        message: String::from("monitoring role required"),
                    }).unwrap_or_default();
                    return Some(Response::Data(err));
                }
            } else if enclave_os_common::oidc::is_oidc_configured() {
                let err = serde_json::to_vec(&WasmManagementResult::Error {
                    message: String::from("OIDC authentication required (monitoring role)"),
                }).unwrap_or_default();
                return Some(Response::Data(err));
            }
        }

        // 1. wasm_call — execute a function (app-level permissions)
        if let Some(ref call) = envelope.wasm_call {
            if let Some(err_response) = self.check_app_permissions(call) {
                return Some(err_response);
            }
            let result = self.dispatch_call(call);
            return Some(Response::Data(serialize_or_error(&result)));
        }

        // 2. wasm_load — load (or replace) an app
        if let Some(load) = envelope.wasm_load {
            let hostname = load.hostname.unwrap_or_else(|| load.name.clone());

            // Decode optional BYOK encryption key (hex → [u8; 32])
            let encryption_key = match load.encryption_key {
                Some(hex) => {
                    let bytes = match hex_decode(&hex) {
                        Some(b) => b,
                        None => {
                            let mgmt_result = WasmManagementResult::Error {
                                message: String::from("encryption_key: invalid hex encoding"),
                            };
                            return Some(Response::Data(serialize_or_error(&mgmt_result)));
                        }
                    };
                    if bytes.len() != AEAD_KEY_SIZE {
                        let mgmt_result = WasmManagementResult::Error {
                            message: format!(
                                "encryption_key: expected {} bytes, got {}",
                                AEAD_KEY_SIZE,
                                bytes.len(),
                            ),
                        };
                        return Some(Response::Data(serialize_or_error(&mgmt_result)));
                    }
                    let mut key = [0u8; AEAD_KEY_SIZE];
                    key.copy_from_slice(&bytes);
                    Some(key)
                }
                None => None,
            };

            let max_fuel = load.max_fuel.unwrap_or(10_000_000);

            let mgmt_result = match self.load_app(&load.name, &hostname, &load.bytes, encryption_key, load.permissions, max_fuel) {
                Ok(()) => {
                    // Return the loaded app's info
                    let apps = self.list_apps();
                    match apps.into_iter().find(|a| a.name == load.name) {
                        Some(info) => WasmManagementResult::Loaded { app: info },
                        None => WasmManagementResult::Error {
                            message: String::from("app loaded but not found in registry"),
                        },
                    }
                }
                Err(e) => WasmManagementResult::Error { message: e },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 3. wasm_unload — remove an app
        if let Some(unload) = envelope.wasm_unload {
            // Also remove its metrics counters.
            if let Ok(mut m) = self.metrics.lock() {
                m.remove_app(&unload.name);
            }
            let mgmt_result = if self.unload_app(&unload.name) {
                WasmManagementResult::Unloaded { name: unload.name }
            } else {
                WasmManagementResult::NotFound { name: unload.name }
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 4. wasm_list — enumerate loaded apps
        if envelope.wasm_list.is_some() {
            let apps = self.list_apps();
            let mgmt_result = WasmManagementResult::Apps { apps };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // No recognised field — decline so other modules can try.
        None
    }

    /// Enrich the core `Metrics` response with per-app fuel-metering data
    /// and persist a snapshot to the sealed KV store.
    fn enrich_metrics(&self, metrics: &mut enclave_os_common::protocol::EnclaveMetrics) {
        if let Ok(m) = self.metrics.lock() {
            metrics.wasm_app_metrics = m.to_app_metrics();
            let _ = m.save();
        }
    }

    /// Config Merkle leaves for attestation.
    ///
    /// Each known app contributes two leaves:
    ///   - `wasm.<app_name>.code_hash` = SHA-256 of the WASM bytecode
    ///   - `wasm.<app_name>.key_source` = `"generated"` or `"byok:<fingerprint>"`
    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let mut leaves = Vec::new();
        for (name, hash, key_source) in registry.all_app_metadata() {
            leaves.push(ConfigLeaf {
                name: format!("wasm.{}.code_hash", name),
                data: Some(hash.to_vec()),
            });
            leaves.push(ConfigLeaf {
                name: format!("wasm.{}.key_source", name),
                data: Some(key_source.as_bytes().to_vec()),
            });
        }
        leaves
    }

    /// Custom X.509 OIDs for RA-TLS certificates.
    ///
    /// Embeds the combined apps hash as OID `1.3.6.1.4.1.65230.2.5`.
    fn custom_oids(&self) -> Vec<ModuleOid> {
        let combined = self.combined_apps_hash();

        // Only include the OID if at least one app is known.
        if combined == [0u8; 32] {
            return Vec::new();
        }

        vec![ModuleOid {
            oid: WASM_APPS_HASH_OID,
            value: combined.to_vec(),
        }]
    }
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Build an [`AppIdentity`] from persisted metadata for CertStore registration.
fn build_app_identity(meta: &AppMeta) -> AppIdentity {
    let mut config = vec![
        ConfigEntry {
            key: format!("wasm.{}.code_hash", meta.name),
            value: meta.code_hash.to_vec(),
            oid: Some(enclave_os_common::oids::APP_CODE_HASH_OID),
        },
        ConfigEntry {
            key: format!("wasm.{}.key_source", meta.name),
            value: meta.key_source.as_bytes().to_vec(),
            oid: Some(enclave_os_common::oids::APP_KEY_SOURCE_OID),
        },
    ];
    if let Some(ph) = meta.permissions_hash {
        config.push(ConfigEntry {
            key: format!("wasm.{}.permissions_hash", meta.name),
            value: ph.to_vec(),
            oid: Some(enclave_os_common::oids::APP_PERMISSIONS_HASH_OID),
        });
    }
    AppIdentity {
        hostname: meta.hostname.clone(),
        config,
    }
}

/// Register an app's identity with the global CertStore.
fn register_app_identity(meta: &AppMeta) {
    enclave_os_common::ocall::cert_store_register(build_app_identity(meta));
}

/// Serialize any `Serialize` value to JSON bytes, falling back to an error
/// JSON blob if serialization itself fails.
fn serialize_or_error<T: serde::Serialize>(value: &T) -> Vec<u8> {
    match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(e) => {
            let fallback = WasmResult::Error {
                message: format!("result serialization failed: {}", e),
            };
            serde_json::to_vec(&fallback).unwrap_or_default()
        }
    }
}

// ---------------------------------------------------------------------------
//  App-level OIDC token verification
// ---------------------------------------------------------------------------

/// Verify a JWT against an app developer's OIDC provider.
///
/// Returns the list of role strings from the token.  Does **not** use the
/// platform's OIDC config — uses the app's own `AppOidcConfig`.
fn verify_app_token(
    token: &str,
    oidc: &crate::protocol::AppOidcConfig,
) -> Result<Vec<String>, String> {
    // Decode JWT claims (header.payload.signature)
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("malformed JWT: expected 3 dot-separated parts".into());
    }

    // Decode payload (base64url → JSON)
    let payload_bytes = base64_url_decode(parts[1])
        .map_err(|e| format!("JWT payload base64: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT payload JSON: {e}"))?;

    // Validate issuer
    let iss = claims.get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JWT missing 'iss' claim".to_string())?;
    if iss != oidc.issuer {
        return Err(format!("JWT issuer '{}' != expected '{}'", iss, oidc.issuer));
    }

    // Validate audience
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == &oidc.audience,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(&oidc.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("JWT audience does not contain '{}'", oidc.audience));
    }

    // Validate expiry
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
        let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
        if now > exp {
            return Err("JWT token expired".into());
        }
    }

    // Extract roles from the configured roles_claim path.
    let mut roles = Vec::new();
    if let Some(val) = claims.get(&oidc.roles_claim) {
        collect_role_strings(val, &mut roles);
    }
    // Also check standard paths for compatibility.
    if let Some(val) = claims.get("roles") {
        collect_role_strings(val, &mut roles);
    }
    if let Some(ra) = claims.get("realm_access") {
        if let Some(val) = ra.get("roles") {
            collect_role_strings(val, &mut roles);
        }
    }
    // Zitadel map format
    if let Some(val) = claims.get("urn:zitadel:iam:org:project:roles") {
        collect_role_strings(val, &mut roles);
    }

    roles.sort();
    roles.dedup();
    Ok(roles)
}

/// Collect role strings from a JSON value (array of strings or Zitadel
/// map `{ "role": {...} }`).
fn collect_role_strings(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                }
            }
        }
        serde_json::Value::Object(map) => {
            for key in map.keys() {
                out.push(key.clone());
            }
        }
        _ => {}
    }
}

/// Decode base64url (no padding) to bytes.
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    let standard: String = input.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();

    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    // Use ring's base64 or a simple inline decoder
    let mut result = Vec::new();
    let chars: Vec<u8> = padded.bytes().collect();
    for chunk in chars.chunks(4) {
        if chunk.len() != 4 {
            return Err("invalid base64 length".into());
        }
        let vals: Result<Vec<u8>, String> = chunk.iter().map(|&b| {
            match b {
                b'A'..=b'Z' => Ok(b - b'A'),
                b'a'..=b'z' => Ok(b - b'a' + 26),
                b'0'..=b'9' => Ok(b - b'0' + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                b'=' => Ok(0),
                _ => Err(format!("invalid base64 char: {}", b as char)),
            }
        }).collect();
        let vals = vals?;
        result.push((vals[0] << 2) | (vals[1] >> 4));
        if chunk[2] != b'=' {
            result.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if chunk[3] != b'=' {
            result.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(result)
}
