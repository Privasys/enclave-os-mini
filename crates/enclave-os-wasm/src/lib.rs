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
pub mod jwks_fetcher;
pub mod metrics;
pub mod protocol;
pub mod registry;
#[cfg(target_vendor = "teaclave")]
pub mod sgx_platform;
pub mod vaultkey;
pub mod wasi;
pub mod wasm_docs;

use std::sync::Mutex;
use std::sync::OnceLock;
use std::vec::Vec;

use enclave_os_common::hex::hex_decode;
use enclave_os_common::modules::{
    AppIdentity, ConfigEntry, ConfigLeaf, EnclaveModule, ModuleOid, RequestContext,
};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::types::AEAD_KEY_SIZE;
use ring::digest;

use crate::metrics::WasmMetricsStore;
use crate::protocol::{
    AppPermissions, FunctionPolicy, Payer, WasmCall, WasmEnvelope, WasmManagementResult, WasmParam,
    WasmResult,
    WasmSchemaRequest,
};
use crate::protocol::{AppRolesAction, AppRolesResult, UserRoles};
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
                                            meta.name,
                                            meta.hostname,
                                        );
                                        // NOTE: do NOT call register_app_identity() here.
                                        // The CertStore is initialised later in
                                        // `finalize_and_run()` and collects identities from
                                        // every module via `app_identities()` (see
                                        // `WasmModule::app_identities()` below). Calling
                                        // `cert_store()` here would panic because the global
                                        // OnceLock has not been set yet.
                                        registry.register_known(meta);
                                    }
                                    Err(e) => {
                                        enclave_os_common::enclave_log_error!(
                                            "Failed to deserialise metadata for app '{}': {}",
                                            name,
                                            e,
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
    /// provider. The SHA-256 hash of the configuration is included
    /// in the per-app RA-TLS certificate as OID 3.5.
    pub fn load_app(
        &self,
        name: &str,
        hostname: &str,
        wasm_bytes: &[u8],
        encryption_key: Option<[u8; AEAD_KEY_SIZE]>,
        permissions: Option<AppPermissions>,
        max_fuel: u64,
        mcp_enabled: bool,
        docs: Option<std::collections::BTreeMap<String, String>>,
        config_api_function: Option<String>,
        owners: Vec<String>,
        app_id: Option<[u8; 16]>,
        vault: Option<crate::registry::VaultBacking>,
        dependencies: Option<Vec<u8>>,
    ) -> Result<(), String> {
        // Load into the registry (compile + introspect + per-app key)
        let meta = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.load_app(
                name,
                hostname,
                wasm_bytes,
                encryption_key,
                permissions,
                max_fuel,
                mcp_enabled,
                docs,
                config_api_function,
                owners,
                app_id,
                vault,
                dependencies,
            )?
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
        let hostname = self
            .registry
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

    /// Install (or replace) an app-defined attestation extension at
    /// arc `1.3.6.1.4.1.65230.3.5.{arc_suffix}`. Persists the new
    /// extension set to KV (so it survives restarts) and re-registers
    /// the per-app identity with the global CertStore so the next
    /// RA-TLS handshake serves a leaf that includes the extension.
    ///
    /// Called by the `set-attestation-extension` host function in the
    /// `privasys:enclave-os/attestation@0.1.0` SDK interface.
    pub fn set_attestation_extension(
        &self,
        name: &str,
        arc_suffix: u32,
        value: Vec<u8>,
    ) -> Result<(), String> {
        let updated_meta = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.set_extension(name, arc_suffix, value)
                .ok_or_else(|| format!("unknown app: '{}'", name))?
        };
        // Persist updated metadata to KV so extensions survive restart.
        // We do not need the wasm bytes here \u2014 only the meta entry
        // changes; persist_app_to_kv writes both, so use a smaller
        // path that updates only the meta.
        self.persist_meta_to_kv(name, &updated_meta);
        register_app_identity(&updated_meta);
        Ok(())
    }

    /// Set (or clear) an app's attested cross-enclave dependency set. Persists the
    /// canonical OID 6.1 encoding to KV and re-registers the per-app identity so
    /// the next RA-TLS handshake serves a leaf carrying the updated dependency
    /// set. Runtime-owned: reached only via the `wasm_set_dependencies` management
    /// command, never by the app.
    pub fn set_dependencies(&self, name: &str, dependencies: Option<Vec<u8>>) -> Result<(), String> {
        let updated_meta = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.set_dependencies(name, dependencies)
                .ok_or_else(|| format!("unknown app: '{}'", name))?
        };
        self.persist_meta_to_kv(name, &updated_meta);
        register_app_identity(&updated_meta);
        Ok(())
    }

    /// Lift the freeze gate for `name` (no-op when the app has no
    /// declared `config_api` or is already configured). Called by
    /// the `set-config-complete` host function.
    pub fn mark_configured(&self, name: &str) -> Result<(), String> {
        let updated_meta = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.mark_configured(name)
        };
        // Persist the config_complete marker to the sealed KV so a restart whose
        // KV survives (same-MRENCLAVE replay, or a vault-recovered KV after an
        // upgrade+promote) does not re-freeze the app. None => nothing changed.
        if let Some(meta) = updated_meta {
            self.persist_meta_to_kv(name, &meta);
        }
        Ok(())
    }

    /// Apply or lift the host-driven billing freeze for `name`.
    /// `Some(reason)` freezes; `None` unfreezes. Returns `true` when
    /// the app is known. Called from the `wasm_freeze` control command.
    pub fn set_billing_frozen(&self, name: &str, reason: Option<String>) -> Result<bool, String> {
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| String::from("registry lock poisoned"))?;
        Ok(reg.set_billing_frozen(name, reason))
    }

    /// Dispatch a parsed `WasmCall` to the appropriate app and record metrics.
    ///
    /// If the app is known but not currently compiled in memory, its
    /// WASM bytes are loaded from the sealed KV store and compiled
    /// on the fly (AOT deserialization — very fast).
    fn dispatch_call(&self, call: &WasmCall, auth: Option<AuthResult>) -> WasmResult {
        // Ensure the app is compiled.  This is a no-op when the app
        // is already in the `loaded` map.
        if let Err(e) = self.ensure_app_loaded(&call.app) {
            return WasmResult::Error { message: e };
        }

        // Freeze gate: when the app declared a `config_api` function
        // at load time and has not yet called `set-config-complete`,
        // every export OTHER than the configure function returns an
        // error. The flag is in-memory only — after a restart the app
        // is frozen again and must reconfigure from its sealed state.
        {
            let registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    return WasmResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                }
            };
            if registry.is_frozen(&call.app, &call.function) {
                return WasmResult::Error {
                    message: String::from("app is awaiting initial configuration"),
                };
            }
            // Billing freeze: a host-driven pause (e.g. the account's
            // credit balance is exhausted) blocks every export until the
            // management-service lifts it on top-up. Attestation is served
            // outside this call path, so the chain stays verifiable.
            if let Some(reason) = registry.billing_freeze_reason(&call.app) {
                return WasmResult::Error {
                    message: format!("app frozen: {}", reason),
                };
            }
        }

        // x-privasys.price: capture the fee-relevant caller facts before
        // `auth` is consumed by prepare_call below. Used only in the
        // on-success fee recording at the bottom of this function.
        let fee_caller = auth.as_ref().and_then(|a| a.user_id.clone());
        let fee_wallet = auth.as_ref().map(|a| a.wallet_class).unwrap_or(false);

        // Prepare under lock, but release the lock before invoking
        // the wasm function. Wasm host bindings (e.g.
        // `attestation.set-config-complete`) re-enter `WasmModule`
        // methods that re-acquire `self.registry` — holding the
        // registry mutex across `func.call(...)` would deadlock the
        // single-threaded enclave dispatcher permanently.
        let prep = {
            let mut registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    return WasmResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                }
            };
            let caller_id = auth.as_ref().and_then(|a| a.user_id.clone());
            let caller_roles = auth.map(|a| a.roles).unwrap_or_default();
            registry.prepare_call(
                &call.app,
                &call.function,
                &call.params,
                caller_id,
                caller_roles,
            )
        };

        let mut prep = match prep {
            Ok(p) => p,
            Err(err) => {
                // Preparation failed before any wasm executed; no fuel
                // consumed and no error metric beyond the existing
                // "error" path below.
                if let Ok(mut m) = self.metrics.lock() {
                    m.record_error(&call.app, &call.function);
                }
                return err;
            }
        };

        // Execute the wasm function WITHOUT the registry mutex held.
        let mut results = vec![wasmtime::component::Val::Bool(false); prep.result_count];
        let call_err = prep
            .func
            .call(&mut prep.store, &prep.val_params, &mut results)
            .err();
        prep.store.data_mut().flush_logs();
        let fuel_after = prep.store.get_fuel().unwrap_or(0) as i64;
        let fuel_consumed = prep.fuel_before - fuel_after;

        // Snapshot this call's billable SDK resource usage (crypto / https /
        // sealed-KV). The AppContext is per-call, so this is the delta.
        let sdk_usage = prep.store.data().usage.clone();

        let result = if let Some(e) = call_err {
            WasmResult::Error {
                message: format!("call failed: {}", e),
            }
        } else {
            let returns: Vec<protocol::WasmValue> = results
                .iter()
                .map(crate::registry::val_to_wasm_value)
                .collect();
            WasmResult::Ok { returns }
        };

        // Auto-lift the configure-then-freeze gate: a successful return from the
        // app's declared config_api function lifts the gate, mirroring the
        // container manager (which lifts on the first 2xx). Apps no longer need
        // to call `set-config-complete`. A WIT-level Err return does NOT lift
        // (the configure failed), matching "a non-2xx response does not lift".
        if let WasmResult::Ok { .. } = result {
            let wit_err = matches!(
                results.first(),
                Some(wasmtime::component::Val::Result(Err(_)))
            );
            if !wit_err {
                let is_config_fn = self
                    .registry
                    .lock()
                    .ok()
                    .and_then(|r| {
                        r.config_api_function(&call.app)
                            .map(|f| f == call.function.as_str())
                    })
                    .unwrap_or(false);
                if is_config_fn {
                    let _ = self.mark_configured(&call.app);
                }

                // x-privasys.price: record the fee owed for this successful
                // priced call. The rule comes from the measured permissions
                // (an attested price); the event is pulled by the usage feed
                // and settled ledger-side (payer debited, owner 85%, platform
                // 15%), idempotent on call_id. Fee on success only; compute
                // is metered to the owner regardless, below.
                let fee = self.registry.lock().ok().and_then(|reg| {
                    let (rule, sponsor_idx) =
                        reg.price_context(&call.app, &call.function)?;
                    match rule.payer {
                        Payer::Caller => {
                            if fee_wallet && rule.free_for.iter().any(|c| c == "wallet") {
                                None // wallet-class exemption: caller pays 0
                            } else {
                                // check_app_permissions enforced an
                                // authenticated caller for priced functions;
                                // a missing sub here means an unbillable
                                // legacy path — skip, never mischarge.
                                fee_caller
                                    .clone()
                                    .map(|sub| (rule.credits, Some(sub), None))
                            }
                        }
                        Payer::Sponsor => sponsor_idx
                            .and_then(|i| match call.params.get(i) {
                                Some(WasmParam::String(s)) if !s.is_empty() => {
                                    Some(s.clone())
                                }
                                _ => None,
                            })
                            .map(|rp| (rule.credits, None, Some(rp))),
                    }
                });
                if let Some((credits, caller_sub, sponsor_rp)) = fee {
                    if let Ok(mut m) = self.metrics.lock() {
                        m.record_api_fee(
                            &call.app,
                            &call.function,
                            random_call_id(),
                            caller_sub,
                            sponsor_rp,
                            credits,
                        );
                    }
                }
            }
        }

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
            // Record billable SDK resource usage (no-op if none used).
            m.record_sdk_usage(&call.app, &sdk_usage);
        }

        result
    }

    /// Enforce per-app permission policy on a `wasm_call`.
    ///
    /// Returns `Err(Response)` with an error if the call is denied,
    /// or `Ok(Option<AuthResult>)` if permitted (`None` = public, no auth).
    ///
    /// **Logic**:
    /// - App has no permissions → call is public (no auth needed).
    /// - App has permissions → look up the function's policy:
    ///   - `public` → allow without auth.
    ///   - `authenticated` → require a valid token from the app's OIDC.
    ///   - `role` → require a valid token with at least one matching role.
    ///
    /// The app-level bearer token is taken from `call.app_auth`.
    fn check_app_permissions(
        &self,
        call: &WasmCall,
        ctx: &RequestContext,
    ) -> Result<Option<AuthResult>, Response> {
        // Look up the app's permissions policy.
        let registry = self.registry.lock().map_err(|_| {
            Response::Data(serialize_or_error(&WasmResult::Error {
                message: String::from("registry lock poisoned"),
            }))
        })?;
        // Configure-authz standard: the @config-api function is
        // owner/admin-gated on EVERY call — regardless of the app's
        // (possibly absent) permissions block or auth annotation, and
        // regardless of frozen state (reconfiguring a running app is
        // equally privileged). The freeze gate decides WHICH function
        // runs while frozen; this decides WHO may call it.
        if registry.config_api_function(&call.app) == Some(call.function.as_str()) {
            let owners = registry.app_owners(&call.app);
            let app_id = registry.app_id(&call.app);
            let permissions = registry.app_permissions(&call.app).cloned();
            let role_store = build_app_role_store(&registry, &call.app);
            drop(registry);
            return self
                .check_configure_authz(call, owners, app_id, permissions.as_ref(), role_store.as_ref())
                .map(Some);
        }

        let permissions = match registry.app_permissions(&call.app) {
            Some(p) => p.clone(),
            None => return Ok(None), // No permissions → public access.
        };
        // Build the app's role store for FIDO2 role lookup.
        let role_store = build_app_role_store(&registry, &call.app);

        // x-privasys.price pre-dispatch gate. The rule lives in the measured
        // permissions (an attested price). Sponsor mode: the request must
        // carry the sponsor's rp_id in the `sponsor_from` parameter, and —
        // once the host has pushed the funded set — that rp_id must be
        // funded ("refuse rather than silently move cost to the owner").
        let price_ctx = registry.price_context(&call.app, &call.function);
        if let Some((rule, sponsor_idx)) = &price_ctx {
            if rule.payer == Payer::Sponsor {
                let rp = sponsor_idx.and_then(|i| match call.params.get(i) {
                    Some(WasmParam::String(s)) if !s.is_empty() => Some(s.as_str()),
                    _ => None,
                });
                match rp {
                    None => {
                        let err = WasmResult::Error {
                            message: format!(
                                "payment required: function '{}' on app '{}' is sponsor-priced; the request must carry the sponsoring relying party in '{}'",
                                call.function,
                                call.app,
                                rule.sponsor_from.as_deref().unwrap_or("<unset>"),
                            ),
                        };
                        return Err(Response::Data(serialize_or_error(&err)));
                    }
                    Some(rp) if !registry.funded_rp_allowed(rp) => {
                        let err = WasmResult::Error {
                            message: format!(
                                "payment required: relying party '{}' has not funded this verification",
                                rp,
                            ),
                        };
                        return Err(Response::Data(serialize_or_error(&err)));
                    }
                    Some(_) => {}
                }
            }
        }
        drop(registry); // Release lock before potentially slow token verification.

        // Determine the effective policy for this function.
        let (policy, required_roles) = match permissions.functions.get(&call.function) {
            Some(fp) => (&fp.policy, &fp.roles),
            None => (&permissions.default_policy, &permissions.default_roles),
        };

        // A caller-priced function can never be billed anonymously: even
        // when its auth policy is `public`, require a verified token
        // (Authenticated semantics; a `free_for` class also needs the
        // token to prove the class). Sponsor-priced functions stay open —
        // the caller is never the payer.
        let priced_caller =
            matches!(&price_ctx, Some((rule, _)) if rule.payer == Payer::Caller);

        // Public → no auth needed (unless caller-priced).
        if *policy == FunctionPolicy::Public && !priced_caller {
            return Ok(None);
        }

        // Owner → restricted to the per-app owners team (the
        // platform-OIDC `sub` claims that the management service
        // shipped on `wasm_load.owners`). Used by the @config-api
        // freeze-gate entrypoint so that only a developer on the
        // owners team can initialise it. The platform `manager` role
        // is NOT a substitute: managers can deploy any app, but an
        // app's configure entrypoint is private to its owners team.
        //
        // The caller's identity is taken from the wasm_call's
        // `app_auth` bearer (the end-user's OIDC token, forwarded by
        // the management service), *not* from the RA-TLS Authorization
        // header — that header carries the management service's own
        // service-account token (used to authenticate to the enclave
        // for `wasm_load` etc.) and would otherwise cause every
        // legitimate owner-only call to fail with "not on the owners
        // team" because the SA's `sub` is the platform itself.
        if *policy == FunctionPolicy::Owner {
            // Find the owners list from the registry.
            let owners: Vec<String> = {
                let reg = self.registry.lock().map_err(|_| {
                    Response::Data(serialize_or_error(&WasmResult::Error {
                        message: String::from("registry lock poisoned"),
                    }))
                })?;
                reg.app_owners(&call.app)
            };
            if owners.is_empty() {
                let err = WasmResult::Error {
                    message: format!(
                        "owner-only: app '{}' has no owners team configured; redeploy from the platform to populate it",
                        call.app,
                    ),
                };
                return Err(Response::Data(serialize_or_error(&err)));
            }
            let token_str = match call.app_auth.as_deref() {
                Some(t) => t,
                None => {
                    let err = WasmResult::Error {
                        message: format!(
                            "owner-only: function '{}' on app '{}' requires the caller's platform OIDC bearer in app_auth",
                            call.function, call.app,
                        ),
                    };
                    return Err(Response::Data(serialize_or_error(&err)));
                }
            };
            let auth = match verify_auth_token(token_str, &permissions, role_store.as_ref()) {
                Ok(a) => a,
                Err(e) => {
                    let err = WasmResult::Error {
                        message: format!("owner-only: app_auth verification failed: {e}"),
                    };
                    return Err(Response::Data(serialize_or_error(&err)));
                }
            };
            let caller_sub = match auth.user_id.as_deref() {
                Some(s) => s,
                None => {
                    let err = WasmResult::Error {
                        message: format!(
                            "owner-only: app_auth on '{}' did not yield a caller identity (need OIDC JWT with 'sub')",
                            call.app,
                        ),
                    };
                    return Err(Response::Data(serialize_or_error(&err)));
                }
            };
            if !owners.iter().any(|s| s == caller_sub) {
                let err = WasmResult::Error {
                    message: format!(
                        "owner-only: caller '{}' is not on the owners team for app '{}' (team has {} member(s))",
                        caller_sub, call.app, owners.len(),
                    ),
                };
                return Err(Response::Data(serialize_or_error(&err)));
            }
            // Surface the caller's identity to the wasm app so it can
            // log who configured it.
            return Ok(Some(auth));
        }

        // The app-level bearer token is in the wasm_call's `app_auth` field.
        let token_str = match call.app_auth.as_deref() {
            Some(t) => t,
            None => {
                let err = WasmResult::Error {
                    message: format!(
                        "authentication required: function '{}' on app '{}' requires {}",
                        call.function,
                        call.app,
                        auth_methods_description(&permissions),
                    ),
                };
                return Err(Response::Data(serialize_or_error(&err)));
            }
        };

        // Verify the token (FIDO2 session token or OIDC JWT).
        let auth = match verify_auth_token(token_str, &permissions, role_store.as_ref()) {
            Ok(r) => r,
            Err(e) => {
                let err = WasmResult::Error {
                    message: format!("app auth failed: {e}"),
                };
                return Err(Response::Data(serialize_or_error(&err)));
            }
        };

        // Authenticated → token is valid, no role check needed.
        if *policy == FunctionPolicy::Authenticated {
            return Ok(Some(auth));
        }

        // Role → check intersection.
        if !required_roles.is_empty() {
            let has_role = auth.roles.iter().any(|r| required_roles.contains(r));
            if !has_role {
                let err = WasmResult::Error {
                    message: format!(
                        "access denied: function '{}' on app '{}' requires one of {:?}",
                        call.function, call.app, required_roles,
                    ),
                };
                return Err(Response::Data(serialize_or_error(&err)));
            }
        }

        Ok(Some(auth)) // Permitted with auth context.
    }

    /// Authorize a call to the app's `@config-api` function — the
    /// configure-authz standard.
    ///
    /// Primary: the caller's `app_auth` bearer verifies against the
    /// PLATFORM issuer and carries the per-app config role
    /// `<audience>:app:<app-id-hex>:owner|admin` (granted/revoked live by
    /// the control plane on team changes — no redeploy). Transitional
    /// fallback: a verified platform `sub` on the owners team. Legacy
    /// fallback: the pre-standard Owner behaviour (FIDO2/app-OIDC
    /// verification + owners membership) while clients migrate. Loads
    /// carrying neither an app id nor an owners team are admitted with a
    /// log — enforcement becomes possible when the platform redeploys
    /// them with the new payload. Everything else fails closed.
    fn check_configure_authz(
        &self,
        call: &WasmCall,
        owners: Vec<String>,
        app_id: Option<[u8; 16]>,
        permissions: Option<&AppPermissions>,
        role_store: Option<&enclave_os_kvstore::SealedKvStore>,
    ) -> Result<AuthResult, Response> {
        let deny = |message: String| Response::Data(serialize_or_error(&WasmResult::Error { message }));

        if app_id.is_none() && owners.is_empty() {
            enclave_os_common::enclave_log_info!(
                "configure gate: app '{}' has neither app_id nor owners (legacy load) — admitting",
                call.app
            );
            return Ok(AuthResult {
                roles: Vec::new(),
                user_id: None,
                wallet_class: false,
            });
        }

        let token = match call.app_auth.as_deref() {
            Some(t) => t,
            None => {
                return Err(deny(format!(
                    "configure is owner/admin-only: function '{}' on app '{}' requires the caller's platform OIDC bearer in app_auth",
                    call.function, call.app,
                )))
            }
        };

        // Primary: platform-issuer token + per-app config role.
        if let Some(cfg) = enclave_os_common::oidc::global_oidc_config() {
            let platform = crate::protocol::AppOidcConfig {
                issuer: cfg.issuer.clone(),
                jwks_uri: cfg.jwks_uri.clone(),
                audience: cfg.audience.clone(),
                roles_claim: cfg.role_claim.clone(),
            };
            if let Ok((roles, sub, wallet)) = verify_app_token(token, &platform) {
                if let Some(id) = app_id {
                    let hexid = enclave_os_common::hex::hex_encode(&id);
                    let owner_role = format!("{}:app:{}:owner", cfg.audience, hexid);
                    let admin_role = format!("{}:app:{}:admin", cfg.audience, hexid);
                    if roles.iter().any(|r| r == &owner_role || r == &admin_role) {
                        enclave_os_common::enclave_log_info!(
                            "configure gate: app '{}' authorized by config role (sub={})",
                            call.app,
                            sub.as_deref().unwrap_or("?")
                        );
                        return Ok(AuthResult {
                            roles,
                            user_id: sub,
                            wallet_class: wallet,
                        });
                    }
                }
                // Transitional: verified platform sub on the owners team
                // (token predates the config-role backfill).
                if let Some(s) = sub.as_deref() {
                    if owners.iter().any(|o| o == s) {
                        enclave_os_common::enclave_log_info!(
                            "configure gate: app '{}' authorized by owners-list fallback (sub={} carries no config role yet — run the config-role backfill)",
                            call.app,
                            s
                        );
                        return Ok(AuthResult {
                            roles,
                            user_id: sub,
                            wallet_class: wallet,
                        });
                    }
                }
                // A VERIFIED platform token without authority is a hard
                // deny — re-checking it as an app token cannot add
                // platform authority.
                return Err(deny(format!(
                    "configure is owner/admin-only: caller is not an owner/admin of app '{}'",
                    call.app,
                )));
            }
            // Not a platform token — fall through to the pre-standard path.
        }

        // Pre-standard fallback: FIDO2 / app-OIDC verification + owners
        // membership (the original Owner-policy behaviour), kept while
        // clients migrate to platform bearers on configure.
        if let Some(p) = permissions {
            if !owners.is_empty() {
                let auth = verify_auth_token(token, p, role_store).map_err(|e| {
                    deny(format!(
                        "configure is owner/admin-only: app_auth verification failed: {e}"
                    ))
                })?;
                if let Some(s) = auth.user_id.as_deref() {
                    if owners.iter().any(|o| o == s) {
                        return Ok(auth);
                    }
                }
            }
        }
        Err(deny(format!(
            "configure is owner/admin-only: caller is not an owner/admin of app '{}' (team has {} member(s))",
            call.app,
            owners.len(),
        )))
    }

    /// Enforce per-app permission policy on a `wasm_schema` request.
    ///
    /// Returns `Some(Response)` with an error if access is denied,
    /// or `None` if schema access is permitted.
    ///
    /// **Logic**:
    /// - App has no permissions → schema is public.
    /// - App has permissions → check `schema_policy`:
    ///   - `public` → allow without auth.
    ///   - `authenticated` → require a valid token from the app's OIDC.
    ///   - `role` → require a valid token with at least one of `schema_roles`.
    fn check_schema_permissions(&self, req: &WasmSchemaRequest) -> Option<Response> {
        let registry = self.registry.lock().ok()?;
        let permissions = match registry.app_permissions(&req.app) {
            Some(p) => p.clone(),
            None => return None, // No permissions → schema is public.
        };
        let role_store = build_app_role_store(&registry, &req.app);
        drop(registry);

        if permissions.schema_policy == FunctionPolicy::Public {
            return None;
        }

        let token_str = match req.app_auth.as_deref() {
            Some(t) => t,
            None => {
                let err = WasmManagementResult::Error {
                    message: format!(
                        "authentication required: schema for app '{}' requires {}",
                        req.app,
                        auth_methods_description(&permissions),
                    ),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        };

        let caller_roles = match verify_auth_token(token_str, &permissions, role_store.as_ref()) {
            Ok(auth) => auth.roles,
            Err(e) => {
                let err = WasmManagementResult::Error {
                    message: format!("app auth failed: {e}"),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        };

        if permissions.schema_policy == FunctionPolicy::Authenticated {
            return None;
        }

        // Role → check intersection.
        if !permissions.schema_roles.is_empty() {
            let has_role = caller_roles
                .iter()
                .any(|r| permissions.schema_roles.contains(r));
            if !has_role {
                let err = WasmManagementResult::Error {
                    message: format!(
                        "access denied: schema for app '{}' requires one of {:?}",
                        req.app, permissions.schema_roles,
                    ),
                };
                return Some(Response::Data(serialize_or_error(&err)));
            }
        }

        None // Permitted.
    }

    /// Handle an `app_roles` role management request.
    ///
    /// Authenticates the caller, checks admin privileges for admin-only
    /// actions, and delegates to `enclave_os_app_auth` for the actual
    /// role operations.
    fn handle_app_roles(&self, req: &crate::protocol::AppRolesRequest) -> WasmManagementResult {
        // Feature gate: app-auth must be enabled.
        #[cfg(not(feature = "app-auth"))]
        {
            let _ = req;
            return WasmManagementResult::Error {
                message: String::from(
                    "role management requires the enclave to be built with app-auth support",
                ),
            };
        }

        #[cfg(feature = "app-auth")]
        {
            // Verify the app exists and has permissions with FIDO2 or OIDC.
            let registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    return WasmManagementResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                }
            };

            let permissions = match registry.app_permissions(&req.app) {
                Some(p) => p.clone(),
                None => {
                    return WasmManagementResult::Error {
                        message: format!(
                            "app '{}' has no permissions policy — role management requires auth",
                            req.app,
                        ),
                    };
                }
            };

            let role_store = match build_app_role_store(&registry, &req.app) {
                Some(s) => s,
                None => {
                    return WasmManagementResult::NotFound {
                        name: req.app.clone(),
                    };
                }
            };
            drop(registry);

            // Authenticate the caller.
            let token_str = match req.app_auth.as_deref() {
                Some(t) => t,
                None => {
                    return WasmManagementResult::Error {
                        message: format!(
                            "authentication required: role management for app '{}' requires {}",
                            req.app,
                            auth_methods_description(&permissions),
                        ),
                    };
                }
            };

            let auth = match verify_auth_token(token_str, &permissions, Some(&role_store)) {
                Ok(r) => r,
                Err(e) => {
                    return WasmManagementResult::Error {
                        message: format!("app auth failed: {e}"),
                    };
                }
            };

            // my_roles is accessible to any authenticated user.
            if matches!(req.action, AppRolesAction::MyRoles) {
                let user_id = auth.user_id.unwrap_or_default();
                return WasmManagementResult::Roles {
                    result: AppRolesResult::Roles {
                        user_handle: user_id,
                        roles: auth.roles,
                    },
                };
            }

            // All other actions require admin role.
            if !auth.roles.contains(&"admin".to_string()) {
                return WasmManagementResult::Error {
                    message: String::from("admin role required for role management"),
                };
            }

            // Dispatch the action.
            match &req.action {
                AppRolesAction::GetRoles { user_handle } => {
                    match enclave_os_app_auth::get_user_roles(&role_store, user_handle) {
                        Ok(roles) => WasmManagementResult::Roles {
                            result: AppRolesResult::Roles {
                                user_handle: user_handle.clone(),
                                roles,
                            },
                        },
                        Err(e) => WasmManagementResult::Error { message: e },
                    }
                }
                AppRolesAction::SetRoles { user_handle, roles } => {
                    match enclave_os_app_auth::set_user_roles(&role_store, user_handle, roles) {
                        Ok(()) => WasmManagementResult::Roles {
                            result: AppRolesResult::Ok {
                                message: format!("roles updated for user '{}'", user_handle),
                            },
                        },
                        Err(e) => WasmManagementResult::Error { message: e },
                    }
                }
                AppRolesAction::RemoveRoles { user_handle } => {
                    match enclave_os_app_auth::remove_user_roles(&role_store, user_handle) {
                        Ok(()) => WasmManagementResult::Roles {
                            result: AppRolesResult::Ok {
                                message: format!("roles removed for user '{}'", user_handle),
                            },
                        },
                        Err(e) => WasmManagementResult::Error { message: e },
                    }
                }
                AppRolesAction::ListUsers => match enclave_os_app_auth::list_users(&role_store) {
                    Ok(users) => WasmManagementResult::Roles {
                        result: AppRolesResult::Users {
                            users: users
                                .into_iter()
                                .map(|(h, r)| UserRoles {
                                    user_handle: h,
                                    roles: r,
                                })
                                .collect(),
                        },
                    },
                    Err(e) => WasmManagementResult::Error { message: e },
                },
                AppRolesAction::GetDefaultRoles => {
                    match enclave_os_app_auth::get_default_roles(&role_store) {
                        Ok(roles) => WasmManagementResult::Roles {
                            result: AppRolesResult::DefaultRoles { roles },
                        },
                        Err(e) => WasmManagementResult::Error { message: e },
                    }
                }
                AppRolesAction::SetDefaultRoles { roles } => {
                    match enclave_os_app_auth::set_default_roles(&role_store, roles) {
                        Ok(()) => WasmManagementResult::Roles {
                            result: AppRolesResult::Ok {
                                message: String::from("default roles updated"),
                            },
                        },
                        Err(e) => WasmManagementResult::Error { message: e },
                    }
                }
                AppRolesAction::MyRoles => unreachable!(), // handled above
            }
        }
    }

    /// Convert a [`ConnectCall`] (named params as JSON) to a [`WasmCall`]
    /// (positional [`WasmParam`] values) using the function's schema.
    fn connect_to_wasm_call(
        &self,
        call: &crate::protocol::ConnectCall,
    ) -> Result<WasmCall, String> {
        // Look up the function schema from the known map.
        let registry = self
            .registry
            .lock()
            .map_err(|_| String::from("registry lock poisoned"))?;
        let resolved_app = registry.resolve_app(&call.app)?;
        let meta = registry
            .get_known(&resolved_app)
            .ok_or_else(|| format!("app '{}' is not loaded", resolved_app))?;
        let schema = meta
            .schema
            .as_ref()
            .ok_or_else(|| format!("app '{}' has no schema — try reloading it", resolved_app))?;
        let func = schema.find_function(&call.function).ok_or_else(|| {
            format!(
                "function '{}' not found in app '{}'. Available: [{}]",
                call.function,
                resolved_app,
                schema
                    .functions
                    .iter()
                    .map(|f| f.name.as_str())
                    .chain(
                        schema
                            .interfaces
                            .iter()
                            .flat_map(|i| { i.functions.iter().map(move |f| f.name.as_str()) })
                    )
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })?;

        // Convert named JSON fields to positional WasmParam values.
        let body = call.body.as_object();
        let mut params = Vec::with_capacity(func.params.len());
        for ps in &func.params {
            let val = body
                .and_then(|o| o.get(&ps.name))
                .unwrap_or(&serde_json::Value::Null);
            params.push(json_to_wasm_param(val, &ps.ty, &ps.name)?);
        }

        Ok(WasmCall {
            app: resolved_app,
            function: call.function.clone(),
            params,
            app_auth: call.app_auth.clone(),
        })
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
                    "KV: failed to persist metadata for app '{}': {}",
                    name,
                    e,
                );
            }
        }

        // Store WASM bytes
        if let Err(e) = kv.put(&kv_bytes_key(name), wasm_bytes) {
            enclave_os_common::enclave_log_error!(
                "KV: failed to persist bytes for app '{}': {}",
                name,
                e,
            );
        }

        // Update manifest
        self.update_kv_manifest(&kv);
    }

    /// Persist only an app's metadata (used after extension updates).
    fn persist_meta_to_kv(&self, name: &str, meta: &AppMeta) {
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return,
        };
        let kv = match kv.lock() {
            Ok(kv) => kv,
            Err(_) => return,
        };
        if let Ok(meta_json) = serde_json::to_vec(meta) {
            if let Err(e) = kv.put(&kv_meta_key(name), &meta_json) {
                enclave_os_common::enclave_log_error!(
                    "KV: failed to update metadata for app '{}': {}",
                    name,
                    e,
                );
            }
        }
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
        let names: Vec<String> = self
            .registry
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
                enclave_os_common::enclave_log_error!("KV: failed to update WASM manifest: {}", e,);
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
            let reg = self
                .registry
                .lock()
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
            let kv = kv
                .lock()
                .map_err(|_| String::from("KV store lock poisoned"))?;
            kv.get(&kv_bytes_key(name))
                .map_err(|e| format!("KV read failed for app '{}': {}", name, e))?
                .ok_or_else(|| format!("WASM bytes not found in KV for app '{}'", name))?
        };

        // Compile and insert into loaded map
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| String::from("registry lock poisoned"))?;
        reg.ensure_loaded(name, &wasm_bytes)
    }
}

// ---------------------------------------------------------------------------
//  Global accessor for the SDK host functions
// ---------------------------------------------------------------------------
//
// SDK host functions registered on wasmtime's Linker (e.g.
// `set-attestation-extension`) only have access to a `StoreContextMut`
// that contains an `AppContext` \u2014 not a `WasmModule`. To call back
// into the module (mutate registry, persist KV, re-register identity)
// the enclave init code installs a `'static` reference once at startup.

static WASM_MODULE_GLOBAL: OnceLock<&'static WasmModule> = OnceLock::new();

/// Install the process-wide handle to the WASM module. Call exactly
/// once during enclave initialisation, immediately after constructing
/// the [`WasmModule`]. Subsequent calls are silently ignored.
///
/// The reference must outlive the process; in practice the enclave
/// constructs `WasmModule` once and leaks it via `Box::leak` so the
/// `'static` bound is satisfied trivially.
pub fn install_global(m: &'static WasmModule) {
    let _ = WASM_MODULE_GLOBAL.set(m);
}

/// Borrow the process-wide WASM module handle. Returns `None` if
/// `install_global` was not called (e.g. SDK host fn invoked before
/// init completed). Callers should treat `None` as a
/// programmer-error and return a host-side error to the guest.
pub fn global() -> Option<&'static WasmModule> {
    WASM_MODULE_GLOBAL.get().copied()
}

/// Boxable adapter so the `'static` reference can be re-registered
/// with [`crate::modules::register_module`] (which expects
/// `Box<dyn EnclaveModule>`). Forwards every trait method to the
/// underlying singleton without taking ownership.
pub struct WasmModuleHandle(pub &'static WasmModule);

impl EnclaveModule for WasmModuleHandle {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        self.0.handle(req, ctx)
    }
    fn config_leaves(&self) -> Vec<enclave_os_common::modules::ConfigLeaf> {
        self.0.config_leaves()
    }
    fn custom_oids(&self) -> Vec<enclave_os_common::modules::ModuleOid> {
        self.0.custom_oids()
    }
    fn app_identities(&self) -> Vec<AppIdentity> {
        self.0.app_identities()
    }
    fn enrich_metrics(&self, m: &mut enclave_os_common::protocol::EnclaveMetrics) {
        self.0.enrich_metrics(m)
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

        registry
            .all_code_hashes()
            .iter()
            .filter_map(|(name, _)| {
                registry
                    .get_known(name)
                    .map(|meta| build_app_identity(meta))
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
                if data.len() > 10
                    && (data.starts_with(b"{\"wasm_") || data.starts_with(b"{ \"wasm_"))
                {
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
            || envelope.wasm_unload.is_some()
            || envelope.wasm_freeze.is_some()
            || envelope.wasm_rotate_key.is_some()
            || envelope.wasm_set_dependencies.is_some();
        let needs_monitoring = envelope.wasm_list.is_some();

        if needs_manager {
            if let Some(ref claims) = ctx.oidc_claims {
                if !claims.has_manager() {
                    let err = serde_json::to_vec(&WasmManagementResult::Error {
                        message: String::from("manager role required"),
                    })
                    .unwrap_or_default();
                    return Some(Response::Data(err));
                }
            } else if enclave_os_common::oidc::is_oidc_configured() {
                let err = serde_json::to_vec(&WasmManagementResult::Error {
                    message: String::from("OIDC authentication required (manager role)"),
                })
                .unwrap_or_default();
                return Some(Response::Data(err));
            }
        } else if needs_monitoring {
            if let Some(ref claims) = ctx.oidc_claims {
                if !claims.has_monitoring() {
                    let err = serde_json::to_vec(&WasmManagementResult::Error {
                        message: String::from("monitoring role required"),
                    })
                    .unwrap_or_default();
                    return Some(Response::Data(err));
                }
            } else if enclave_os_common::oidc::is_oidc_configured() {
                let err = serde_json::to_vec(&WasmManagementResult::Error {
                    message: String::from("OIDC authentication required (monitoring role)"),
                })
                .unwrap_or_default();
                return Some(Response::Data(err));
            }
        }

        // 1. wasm_call — execute a function (app-level permissions)
        if let Some(ref call) = envelope.wasm_call {
            let auth = match self.check_app_permissions(call, ctx) {
                Ok(a) => a,
                Err(response) => return Some(response),
            };
            let result = self.dispatch_call(call, auth);
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
            let mcp_enabled = load.mcp_enabled.unwrap_or(true);

            let app_id = parse_app_id(load.app_id.as_deref());

            // Vault-backed key (Part 2): the enclave owns the key end-to-end. The
            // platform supplies only the opt-in flag + where the directory lives;
            // the enclave derives the handle from the app id, discovers the
            // constellation itself, and self-authors the policy. `sealed` is None
            // here (a fresh wasm_load); on replay the selection comes from AppMeta.
            let vault = if load.vault_backed {
                let mgmt_url = match load.mgmt_url.as_deref() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => {
                        return Some(Response::Data(serialize_or_error(
                            &WasmManagementResult::Error {
                                message: String::from("vault_backed requires mgmt_url"),
                            },
                        )));
                    }
                };
                // The handle is namespaced by the app-id (OID 3.6, the undashed
                // hex of the 16 id bytes) so it falls under the grant scope
                // `apps.privasys.org/<app-id>`; this must match the platform's
                // minted grant exactly. The owner-bound policy is carried in the
                // grant, not authored here.
                let app_id_bytes = match app_id {
                    Some(b) => b,
                    None => {
                        return Some(Response::Data(serialize_or_error(
                            &WasmManagementResult::Error {
                                message: String::from("vault_backed requires a valid app_id"),
                            },
                        )));
                    }
                };
                // The platform supplies the current-generation handle (it is the
                // courier, not the trust root: the owner-minted grant authorises
                // it and the vault enforces it falls under this app's scope
                // against the attested app-id on the RA-TLS leaf — mirroring how
                // the container manager already takes the platform's handle).
                // Absent, we derive the v1 generation (pre-rotation behaviour).
                let handle = match load.key_handle.as_deref() {
                    Some(h) if !h.is_empty() => h.to_string(),
                    _ => format!(
                        "apps.privasys.org/{}/storage-kek/v1",
                        enclave_os_common::hex::hex_encode(&app_id_bytes)
                    ),
                };
                let environment = load
                    .environment
                    .clone()
                    .unwrap_or_else(|| String::from("prod"));
                Some(crate::registry::VaultBacking {
                    mgmt_url,
                    environment,
                    handle,
                    grant: load.key_creation_grant.clone().unwrap_or_default(),
                    sealed: None,
                })
            } else {
                None
            };

            let dependencies = match parse_dependencies(load.dependencies.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    return Some(Response::Data(serialize_or_error(
                        &WasmManagementResult::Error { message: e },
                    )));
                }
            };

            let mgmt_result = match self.load_app(
                &load.name,
                &hostname,
                &load.bytes,
                encryption_key,
                load.permissions,
                max_fuel,
                mcp_enabled,
                load.docs,
                load.config_api.map(|c| c.function),
                load.owners,
                app_id,
                vault,
                dependencies,
            ) {
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

        // 3b. wasm_freeze — host-driven billing freeze / unfreeze
        if let Some(freeze) = envelope.wasm_freeze {
            let reason = if freeze.frozen {
                Some(
                    freeze
                        .reason
                        .clone()
                        .unwrap_or_else(|| String::from("credits_exhausted")),
                )
            } else {
                None
            };
            let mgmt_result = match self.set_billing_frozen(&freeze.name, reason.clone()) {
                Ok(true) => WasmManagementResult::Frozen {
                    name: freeze.name,
                    frozen: freeze.frozen,
                    reason,
                },
                Ok(false) => WasmManagementResult::NotFound { name: freeze.name },
                Err(e) => WasmManagementResult::Error { message: e },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 3b2. wasm_funded_rps — host-pushed funded-sponsor set
        // (x-privasys.price payer:"sponsor"). Replaced wholesale each push;
        // the usage feed re-asserts it every sweep, like the freeze.
        if let Some(fr) = envelope.wasm_funded_rps {
            let mgmt_result = match self.registry.lock() {
                Ok(mut registry) => WasmManagementResult::FundedRpsSet {
                    count: registry.set_funded_rps(fr.rp_ids),
                },
                Err(_) => WasmManagementResult::Error {
                    message: String::from("registry lock poisoned"),
                },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 3c. wasm_rotate_key — rotate a vault-backed app's storage KEK
        if let Some(rot) = envelope.wasm_rotate_key {
            let mgmt_url = rot.mgmt_url.clone().unwrap_or_default();
            let environment = rot
                .environment
                .clone()
                .unwrap_or_else(|| String::from("prod"));
            // Re-wrap under the registry lock, then re-seal the advanced metadata
            // with the lock released (persist_meta_to_kv re-enters `self`).
            let result = {
                let mut registry = match self.registry.lock() {
                    Ok(r) => r,
                    Err(_) => {
                        return Some(Response::Data(serialize_or_error(
                            &WasmManagementResult::Error {
                                message: String::from("registry lock poisoned"),
                            },
                        )));
                    }
                };
                registry.rotate_vault_key(
                    &rot.name,
                    &rot.new_handle,
                    &rot.new_key_creation_grant,
                    &mgmt_url,
                    &environment,
                )
            };
            let mgmt_result = match result {
                Ok(updated) => {
                    self.persist_meta_to_kv(&rot.name, &updated);
                    WasmManagementResult::Rotated {
                        name: rot.name,
                        handle: rot.new_handle,
                    }
                }
                Err(e) => WasmManagementResult::Error { message: e },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 3d. wasm_set_dependencies — set/clear the attested dependency set
        if let Some(sd) = envelope.wasm_set_dependencies {
            let deps = match parse_dependencies(sd.dependencies.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    return Some(Response::Data(serialize_or_error(
                        &WasmManagementResult::Error { message: e },
                    )));
                }
            };
            let present = deps.is_some();
            let mgmt_result = match self.set_dependencies(&sd.name, deps) {
                Ok(()) => WasmManagementResult::DependenciesSet {
                    name: sd.name,
                    present,
                },
                Err(e) => WasmManagementResult::Error { message: e },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 4. wasm_list — enumerate loaded apps
        if envelope.wasm_list.is_some() {
            let apps = self.list_apps();
            let mgmt_result = WasmManagementResult::Apps { apps };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 5. wasm_schema — typed API schema for a single app
        //
        // No platform role required. App-level permissions control
        // schema visibility: if the app has AppPermissions with a
        // non-public `schema_policy`, the caller must present a valid
        // app-level OIDC token. If no AppPermissions, schema is public.
        if let Some(ref schema_req) = envelope.wasm_schema {
            // App-level schema access control.
            if let Some(err_response) = self.check_schema_permissions(schema_req) {
                return Some(err_response);
            }

            let registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    let mgmt_result = WasmManagementResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                    return Some(Response::Data(serialize_or_error(&mgmt_result)));
                }
            };
            let mgmt_result = match registry.get_known(&schema_req.app) {
                Some(meta) => match &meta.schema {
                    Some(s) => WasmManagementResult::Schema { schema: s.clone() },
                    None => WasmManagementResult::Error {
                        message: format!(
                            "app '{}' has no schema — try reloading it",
                            schema_req.app,
                        ),
                    },
                },
                None => WasmManagementResult::NotFound {
                    name: schema_req.app.clone(),
                },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 6. mcp_tools — MCP tool manifest for a single app
        if let Some(ref mcp_req) = envelope.mcp_tools {
            // Resolve empty `app` to the single loaded app (used by the
            // HTTP MCP route `/api/v1/mcp/tools` which doesn't carry an app).
            let resolved_app = {
                let registry = match self.registry.lock() {
                    Ok(r) => r,
                    Err(_) => {
                        let mgmt_result = WasmManagementResult::Error {
                            message: String::from("registry lock poisoned"),
                        };
                        return Some(Response::Data(serialize_or_error(&mgmt_result)));
                    }
                };
                match registry.resolve_app(&mcp_req.app) {
                    Ok(name) => name,
                    Err(msg) => {
                        let mgmt_result = WasmManagementResult::Error { message: msg };
                        return Some(Response::Data(serialize_or_error(&mgmt_result)));
                    }
                }
            };

            // Reuse schema access control (same permissions model).
            let schema_req = WasmSchemaRequest {
                app: resolved_app.clone(),
                app_auth: mcp_req.app_auth.clone(),
            };
            if let Some(err_response) = self.check_schema_permissions(&schema_req) {
                return Some(err_response);
            }

            let registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => {
                    let mgmt_result = WasmManagementResult::Error {
                        message: String::from("registry lock poisoned"),
                    };
                    return Some(Response::Data(serialize_or_error(&mgmt_result)));
                }
            };
            let mgmt_result = match registry.get_known(&resolved_app) {
                Some(meta) => match &meta.schema {
                    Some(s) if s.mcp_enabled => {
                        let mut manifest = s.to_mcp_manifest();
                        // The configure function (config_api) is owner-only setup,
                        // not a model-callable tool — exclude it from the MCP tool
                        // list offered to assistants.
                        if let Some(cfg_fn) = registry.config_api_function(&resolved_app) {
                            manifest.tools.retain(|t| t.name != cfg_fn);
                        }
                        WasmManagementResult::McpTools { manifest }
                    }
                    Some(_) => WasmManagementResult::Error {
                        message: format!("MCP is disabled for app '{}'", resolved_app,),
                    },
                    None => WasmManagementResult::Error {
                        message: format!("app '{}' has no schema — try reloading it", resolved_app,),
                    },
                },
                None => WasmManagementResult::NotFound {
                    name: resolved_app.clone(),
                },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 7. app_roles — role management (feature-gated)
        if let Some(ref roles_req) = envelope.app_roles {
            let mgmt_result = self.handle_app_roles(roles_req);
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 8. connect_call — named-param function call (Connect protocol)
        if let Some(ref call) = envelope.connect_call {
            // Translate to a WasmCall using the function schema.
            let wasm_call = match self.connect_to_wasm_call(call) {
                Ok(c) => c,
                Err(msg) => {
                    let err = WasmResult::Error { message: msg };
                    return Some(Response::Data(serialize_or_error(&err)));
                }
            };
            // Re-use the same permission + dispatch path as wasm_call.
            let auth = match self.check_app_permissions(&wasm_call, ctx) {
                Ok(a) => a,
                Err(response) => return Some(response),
            };
            let result = self.dispatch_call(&wasm_call, auth);
            return Some(Response::Data(serialize_or_error(&result)));
        }

        // No recognised field — decline so other modules can try.
        None
    }

    /// Enrich the core `Metrics` response with per-app fuel-metering data
    /// and persist a snapshot to the sealed KV store.
    fn enrich_metrics(&self, metrics: &mut enclave_os_common::protocol::EnclaveMetrics) {
        if let Ok(m) = self.metrics.lock() {
            metrics.wasm_app_metrics = m.to_app_metrics();
            // Developer API-fee events (x-privasys.price): at-least-once
            // pull — the ledger dedupes on call_id.
            metrics.api_fees = m.api_fee_events();
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
/// Parse a UUID string (with or without hyphens) into its raw 16 bytes for the
/// OID 3.6 app-id extension. Returns `None` for empty or malformed input, which
/// leaves the app in MR_ENCLAVE shape (the back-compat default before the
/// platform starts sending `app_id`). See the MR_APP / promote-step-up design.
fn parse_app_id(s: Option<&str>) -> Option<[u8; 16]> {
    let bytes = hex_decode(&s?.replace('-', ""))?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Decode and canonicalise a base64 attested-dependency set supplied by the
/// platform. `None`/empty clears the set. Runtime-owned: the bytes are validated
/// (decoded and re-encoded canonically) here, so a malformed or non-canonical
/// input is rejected before it can reach a certificate.
fn parse_dependencies(b64: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    match b64 {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let raw = STANDARD
                .decode(s)
                .map_err(|e| format!("dependencies: invalid base64: {e}"))?;
            let canon = enclave_os_common::dependencies::canonicalize_encoded(&raw)
                .map_err(|e| format!("dependencies: {e}"))?;
            Ok(Some(canon))
        }
    }
}

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
    if let Some(ch) = meta.configuration_hash {
        config.push(ConfigEntry {
            key: format!("wasm.{}.configuration_hash", meta.name),
            value: ch.to_vec(),
            oid: Some(enclave_os_common::oids::APP_CONFIGURATION_HASH_OID),
        });
    }
    // MR_APP: bind this app's leaf to its platform-assigned app-id (OID 3.6).
    // Omitted (MR_ENCLAVE) when the platform did not supply one.
    if let Some(ref id) = meta.app_id {
        config.push(ConfigEntry {
            key: format!("wasm.{}.app_id", meta.name),
            value: id.to_vec(),
            oid: Some(enclave_os_common::oids::APP_ID_OID),
        });
    }
    // Attested cross-enclave dependency set (OID 6.1). Runtime-owned: the value
    // comes from the platform (wasm_load / wasm_set_dependencies), never from the
    // app, so the advertised set and the enforced set are one object.
    if let Some(ref deps) = meta.dependencies {
        config.push(ConfigEntry {
            key: format!("wasm.{}.dependencies", meta.name),
            value: deps.clone(),
            oid: Some(enclave_os_common::oids::ATTESTED_DEPENDENCY_SET_OID),
        });
    }
    // App-defined extensions live under sub-OIDs of
    // APP_CONFIGURATION_HASH_OID (1.3.6.1.4.1.65230.3.5.{arc_suffix}).
    // The parent OID carries the WIT-derived configuration hash; the
    // sub-arc carries opaque values installed at runtime by the app.
    for (arc_suffix, value) in &meta.extensions {
        let mut full_oid: Vec<u64> = enclave_os_common::oids::APP_CONFIGURATION_HASH_OID.to_vec();
        full_oid.push(*arc_suffix as u64);
        // Leak to obtain a 'static slice. Acceptable: extensions are
        // monotonically added and the registry lives for the
        // process lifetime; the leaked memory is bounded by the
        // number of distinct (app, arc) pairs ever installed.
        let leaked: &'static [u64] = Box::leak(full_oid.into_boxed_slice());
        config.push(ConfigEntry {
            key: format!("wasm.{}.extension.{}", meta.name, arc_suffix),
            value: value.clone(),
            oid: Some(leaked),
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
//  Connect protocol: JSON → WasmParam conversion
// ---------------------------------------------------------------------------

/// Convert a JSON value to a [`WasmParam`] based on the WIT type descriptor.
fn json_to_wasm_param(
    val: &serde_json::Value,
    ty: &crate::protocol::WitType,
    name: &str,
) -> Result<crate::protocol::WasmParam, String> {
    use crate::protocol::{WasmParam, WitType};
    match ty {
        WitType::Bool => val
            .as_bool()
            .map(WasmParam::Bool)
            .ok_or_else(|| format!("param '{}': expected bool", name)),
        WitType::U8 | WitType::U16 | WitType::U32 => val
            .as_u64()
            .map(|n| WasmParam::U32(n as u32))
            .ok_or_else(|| format!("param '{}': expected unsigned integer", name)),
        WitType::U64 => val
            .as_u64()
            .map(WasmParam::U64)
            .ok_or_else(|| format!("param '{}': expected u64", name)),
        WitType::S8 | WitType::S16 | WitType::S32 => val
            .as_i64()
            .map(|n| WasmParam::S32(n as i32))
            .ok_or_else(|| format!("param '{}': expected signed integer", name)),
        WitType::S64 => val
            .as_i64()
            .map(WasmParam::S64)
            .ok_or_else(|| format!("param '{}': expected s64", name)),
        WitType::Float32 => val
            .as_f64()
            .map(|n| WasmParam::F32(n as f32))
            .ok_or_else(|| format!("param '{}': expected float", name)),
        WitType::Float64 => val
            .as_f64()
            .map(WasmParam::F64)
            .ok_or_else(|| format!("param '{}': expected float", name)),
        WitType::String | WitType::Char => val
            .as_str()
            .map(|s| WasmParam::String(s.to_string()))
            .ok_or_else(|| format!("param '{}': expected string", name)),
        WitType::List { element } if matches!(element.as_ref(), WitType::U8) => {
            // list<u8> → Bytes (base64 string or array of numbers)
            if let Some(s) = val.as_str() {
                Ok(WasmParam::Bytes(s.as_bytes().to_vec()))
            } else if let Some(arr) = val.as_array() {
                let bytes: Result<Vec<u8>, String> = arr
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .map(|n| n as u8)
                            .ok_or_else(|| format!("param '{}': list<u8> element not a u8", name))
                    })
                    .collect();
                Ok(WasmParam::Bytes(bytes?))
            } else {
                Err(format!(
                    "param '{}': expected string or byte array for list<u8>",
                    name
                ))
            }
        }
        WitType::List { element } => {
            let arr = val
                .as_array()
                .ok_or_else(|| format!("param '{}': expected array for list type", name))?;
            let items: Result<Vec<WasmParam>, String> = arr
                .iter()
                .enumerate()
                .map(|(i, v)| json_to_wasm_param(v, element, &format!("{}[{}]", name, i)))
                .collect();
            Ok(WasmParam::List(items?))
        }
        WitType::Record { fields } => {
            let obj = val
                .as_object()
                .ok_or_else(|| format!("param '{}': expected object for record type", name))?;
            let rec: Result<Vec<(String, WasmParam)>, String> = fields
                .iter()
                .map(|f| {
                    let v = obj.get(&f.name).unwrap_or(&serde_json::Value::Null);
                    let p = json_to_wasm_param(v, &f.ty, &format!("{}.{}", name, f.name))?;
                    Ok((f.name.clone(), p))
                })
                .collect();
            Ok(WasmParam::Record(rec?))
        }
        WitType::Enum { names } => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("param '{}': expected string for enum type", name))?;
            if !names.contains(&s.to_string()) {
                return Err(format!(
                    "param '{}': unknown enum case '{}', expected one of: [{}]",
                    name,
                    s,
                    names.join(", "),
                ));
            }
            Ok(WasmParam::Enum(s.to_string()))
        }
        WitType::Option { inner } => {
            if val.is_null() {
                Ok(WasmParam::Option(None))
            } else {
                let p = json_to_wasm_param(val, inner, name)?;
                Ok(WasmParam::Option(Some(Box::new(p))))
            }
        }
        WitType::Variant { cases } => {
            // Expect {"case-name": payload} or just "case-name" for unit cases.
            if let Some(s) = val.as_str() {
                if cases.iter().any(|c| c.name == s) {
                    Ok(WasmParam::Variant(s.to_string(), None))
                } else {
                    Err(format!("param '{}': unknown variant case '{}'", name, s))
                }
            } else if let Some(obj) = val.as_object() {
                if obj.len() != 1 {
                    return Err(format!(
                        "param '{}': variant object must have exactly one key",
                        name
                    ));
                }
                let (case_name, payload) = obj.iter().next().unwrap();
                let case = cases.iter().find(|c| &c.name == case_name).ok_or_else(|| {
                    format!("param '{}': unknown variant case '{}'", name, case_name)
                })?;
                match &case.ty {
                    Some(ty) => {
                        let p =
                            json_to_wasm_param(payload, ty, &format!("{}.{}", name, case_name))?;
                        Ok(WasmParam::Variant(case_name.clone(), Some(Box::new(p))))
                    }
                    None => Ok(WasmParam::Variant(case_name.clone(), None)),
                }
            } else {
                Err(format!(
                    "param '{}': expected string or object for variant type",
                    name
                ))
            }
        }
        WitType::Tuple { elements } => {
            let arr = val
                .as_array()
                .ok_or_else(|| format!("param '{}': expected array for tuple type", name))?;
            if arr.len() != elements.len() {
                return Err(format!(
                    "param '{}': tuple expects {} elements, got {}",
                    name,
                    elements.len(),
                    arr.len(),
                ));
            }
            let items: Result<Vec<WasmParam>, String> = arr
                .iter()
                .zip(elements.iter())
                .enumerate()
                .map(|(i, (v, t))| json_to_wasm_param(v, t, &format!("{}.{}", name, i)))
                .collect();
            Ok(WasmParam::Tuple(items?))
        }
        WitType::Flags { names } => {
            let arr = val.as_array().ok_or_else(|| {
                format!("param '{}': expected array of strings for flags type", name)
            })?;
            let flags: Result<Vec<String>, String> = arr
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| format!("param '{}': flag must be a string", name))
                })
                .collect();
            let flags = flags?;
            for f in &flags {
                if !names.contains(f) {
                    return Err(format!("param '{}': unknown flag '{}'", name, f));
                }
            }
            Ok(WasmParam::Flags(flags))
        }
        WitType::Result { ok, err } => {
            // Expect {"ok": value} or {"err": value}
            if let Some(obj) = val.as_object() {
                if let Some(ok_val) = obj.get("ok") {
                    let p = match ok {
                        Some(ty) => Some(Box::new(json_to_wasm_param(
                            ok_val,
                            ty,
                            &format!("{}.ok", name),
                        )?)),
                        None => None,
                    };
                    Ok(WasmParam::Variant("ok".to_string(), p))
                } else if let Some(err_val) = obj.get("err") {
                    let p = match err {
                        Some(ty) => Some(Box::new(json_to_wasm_param(
                            err_val,
                            ty,
                            &format!("{}.err", name),
                        )?)),
                        None => None,
                    };
                    Ok(WasmParam::Variant("err".to_string(), p))
                } else {
                    Err(format!(
                        "param '{}': result must have 'ok' or 'err' key",
                        name
                    ))
                }
            } else {
                Err(format!("param '{}': expected object for result type", name))
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  App-level OIDC token verification
// ---------------------------------------------------------------------------

/// Describe the authentication methods available for an app (for error messages).
fn auth_methods_description(permissions: &crate::protocol::AppPermissions) -> String {
    let mut methods = Vec::new();
    if let Some(oidc) = &permissions.oidc {
        methods.push(format!("an OIDC token from {}", oidc.issuer));
    }
    if permissions.fido2 {
        methods.push("a FIDO2 session token".into());
    }
    if methods.is_empty() {
        "authentication (no method configured)".into()
    } else {
        methods.join(" or ")
    }
}

/// Check if a token looks like a FIDO2 session token (64 hex chars).
fn is_fido2_session_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
//  Auth result & role store helpers
// ---------------------------------------------------------------------------

/// Result of authenticating an app-level token.
struct AuthResult {
    /// Caller's roles (from OIDC claims or enclave role store).
    roles: Vec<String>,
    /// Caller's identity (FIDO2 user_handle or OIDC `sub` claim).
    user_id: Option<String>,
    /// Caller holds a wallet-class token (the IdP's constant,
    /// non-identifying `wallet` claim on tokens minted from a genuine
    /// wallet WebAuthn ceremony). Drives the `free_for:["wallet"]`
    /// API-fee exemption (`x-privasys.price`); never identifies anyone.
    wallet_class: bool,
}

/// Random 128-bit hex call id for an API-fee event — the ledger's
/// idempotency key, so it must be globally unique (RDRAND-backed; a
/// deterministic id would collide across restarts and silently drop fees).
fn random_call_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 16];
    if SystemRandom::new().fill(&mut b).is_err() {
        // RDRAND failure is practically impossible; salt with the clock
        // rather than emit an all-zero (colliding) id.
        let t = enclave_os_common::ocall::get_current_time().unwrap_or(0);
        b[..8].copy_from_slice(&t.to_be_bytes());
    }
    let mut s = String::with_capacity(32);
    for byte in b {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

/// Build a [`SealedKvStore`] scoped to an app's `app:<name>` table.
///
/// Requires the registry lock to be held to read the encryption key.
fn build_app_role_store(
    registry: &AppRegistry,
    app_name: &str,
) -> Option<enclave_os_kvstore::SealedKvStore> {
    let meta = registry.get_known(app_name)?;
    let table = format!("app:{}", app_name);
    Some(
        enclave_os_kvstore::SealedKvStore::from_master_key_with_table(
            meta.encryption_key,
            table.as_bytes(),
        ),
    )
}

/// Verify an app-level auth token, trying FIDO2 then OIDC as appropriate.
///
/// Returns an [`AuthResult`] with the caller's roles and identity.
/// When `role_store` is provided, FIDO2 users get roles from the app's
/// sealed KV space (with first-user bootstrap).
fn verify_auth_token(
    token: &str,
    permissions: &crate::protocol::AppPermissions,
    role_store: Option<&enclave_os_kvstore::SealedKvStore>,
) -> Result<AuthResult, String> {
    // Try FIDO2 session token first (if enabled and token looks right).
    #[cfg(feature = "fido2")]
    if permissions.fido2 && is_fido2_session_token(token) {
        let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
        match enclave_os_fido2::sessions::validate_token(token, now) {
            Ok(entry) => {
                let user_id = entry.user_handle.clone();
                let roles = {
                    #[cfg(feature = "app-auth")]
                    {
                        match role_store {
                            Some(store) => {
                                enclave_os_app_auth::get_user_roles_with_bootstrap(store, &user_id)
                                    .unwrap_or_default()
                            }
                            None => Vec::new(),
                        }
                    }
                    #[cfg(not(feature = "app-auth"))]
                    {
                        let _ = role_store;
                        Vec::new()
                    }
                };
                return Ok(AuthResult {
                    roles,
                    user_id: Some(user_id),
                    // FIDO2 sessions carry no claims — no wallet class.
                    wallet_class: false,
                });
            }
            Err(e) => {
                // If OIDC is also available, fall through silently.
                if permissions.oidc.is_none() {
                    return Err(format!("FIDO2 auth failed: {e}"));
                }
                // Otherwise fall through to OIDC attempt.
            }
        }
    }

    #[cfg(not(feature = "fido2"))]
    if permissions.fido2 && permissions.oidc.is_none() {
        return Err(
            "app requires FIDO2 authentication but enclave was built without FIDO2 support".into(),
        );
    }

    // Suppress unused-variable warning when both features are off.
    #[cfg(not(feature = "fido2"))]
    let _ = role_store;

    // Try OIDC JWT verification.
    if let Some(oidc) = &permissions.oidc {
        let (roles, sub, wallet) = verify_app_token(token, oidc)?;
        return Ok(AuthResult {
            roles,
            user_id: sub,
            wallet_class: wallet,
        });
    }

    Err("no authentication method available for this app".into())
}

/// Verify a JWT against an app developer's OIDC provider.
///
/// Performs full JWKS-based ES256 signature verification, then validates
/// `iss`, `aud`, and `exp` claims.  Returns the list of role strings
/// and the `sub` claim (user identity).
///
/// Does **not** use the platform's OIDC config — uses the app's own
/// `AppOidcConfig`.
fn verify_app_token(
    token: &str,
    oidc: &crate::protocol::AppOidcConfig,
) -> Result<(Vec<String>, Option<String>, bool), String> {
    // Verify ES256 signature via JWKS (rejects alg:none, fetches/caches keys)
    let claims: serde_json::Value =
        crate::jwks_fetcher::verify_jwt_signature(token, &oidc.issuer, &oidc.jwks_uri)?;

    // Validate issuer
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JWT missing 'iss' claim".to_string())?;
    if iss != oidc.issuer {
        return Err(format!(
            "JWT issuer '{}' != expected '{}'",
            iss, oidc.issuer
        ));
    }

    // Validate audience
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == &oidc.audience,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(&oidc.audience))
        }
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

    // Extract subject (user identity).
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

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

    roles.sort();
    roles.dedup();

    // Wallet-class marker (`x-privasys.price` free_for:["wallet"]): the IdP
    // stamps a constant `wallet` claim (string "true" or boolean) on tokens
    // minted from a genuine wallet WebAuthn ceremony. Only meaningful when
    // the app's OIDC issuer IS the platform IdP (the deploy default); any
    // other issuer simply never yields the class.
    let wallet = match claims.get("wallet") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };

    Ok((roles, sub, wallet))
}

/// Collect role strings from a JSON value (array of strings or map
/// `{ "role": {...} }`).
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
#[allow(dead_code)]
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();

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
        let vals: Result<Vec<u8>, String> = chunk
            .iter()
            .map(|&b| match b {
                b'A'..=b'Z' => Ok(b - b'A'),
                b'a'..=b'z' => Ok(b - b'a' + 26),
                b'0'..=b'9' => Ok(b - b'0' + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                b'=' => Ok(0),
                _ => Err(format!("invalid base64 char: {}", b as char)),
            })
            .collect();
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
