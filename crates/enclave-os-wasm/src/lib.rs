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
pub mod wasi;
pub mod wasm_docs;

use std::sync::Mutex;
use std::vec::Vec;

use ring::digest;
use enclave_os_common::hex::hex_decode;
use enclave_os_common::modules::{AppIdentity, ConfigEntry, ConfigLeaf, EnclaveModule, ModuleOid, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::types::AEAD_KEY_SIZE;

use crate::protocol::{AppPermissions, FunctionPolicy, WasmCall, WasmEnvelope, WasmManagementResult, WasmResult, WasmSchemaRequest};
use crate::protocol::{AppRolesAction, AppRolesResult, UserRoles};
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
                                        // Register per-app identity with the global CertStore
                                        // so SNI-based attestation works after restart.
                                        register_app_identity(&meta);
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
    ) -> Result<(), String> {
        // Load into the registry (compile + introspect + per-app key)
        let meta = {
            let mut reg = self.registry
                .lock()
                .map_err(|_| String::from("registry lock poisoned"))?;
            reg.load_app(name, hostname, wasm_bytes, encryption_key, permissions, max_fuel, mcp_enabled, docs)?
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
    fn dispatch_call(&self, call: &WasmCall, auth: Option<AuthResult>) -> WasmResult {
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
            let caller_id = auth.as_ref().and_then(|a| a.user_id.clone());
            let caller_roles = auth.map(|a| a.roles).unwrap_or_default();
            registry.call(&call.app, &call.function, &call.params, caller_id, caller_roles)
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
    fn check_app_permissions(&self, call: &WasmCall) -> Result<Option<AuthResult>, Response> {
        // Look up the app's permissions policy.
        let registry = self.registry.lock().map_err(|_| {
            Response::Data(serialize_or_error(&WasmResult::Error {
                message: String::from("registry lock poisoned"),
            }))
        })?;
        let permissions = match registry.app_permissions(&call.app) {
            Some(p) => p.clone(),
            None => return Ok(None), // No permissions → public access.
        };
        // Build the app's role store for FIDO2 role lookup.
        let role_store = build_app_role_store(&registry, &call.app);
        drop(registry); // Release lock before potentially slow token verification.

        // Determine the effective policy for this function.
        let (policy, required_roles) = match permissions.functions.get(&call.function) {
            Some(fp) => (&fp.policy, &fp.roles),
            None => (&permissions.default_policy, &permissions.default_roles),
        };

        // Public → no auth needed.
        if *policy == FunctionPolicy::Public {
            return Ok(None);
        }

        // The app-level bearer token is in the wasm_call's `app_auth` field.
        let token_str = match call.app_auth.as_deref() {
            Some(t) => t,
            None => {
                let err = WasmResult::Error {
                    message: format!(
                        "authentication required: function '{}' on app '{}' requires {}",
                        call.function, call.app, auth_methods_description(&permissions),
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
                        req.app, auth_methods_description(&permissions),
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
            let has_role = caller_roles.iter().any(|r| permissions.schema_roles.contains(r));
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
    fn handle_app_roles(
        &self,
        req: &crate::protocol::AppRolesRequest,
    ) -> WasmManagementResult {
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
                AppRolesAction::ListUsers => {
                    match enclave_os_app_auth::list_users(&role_store) {
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
                    }
                }
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
        let registry = self.registry.lock()
            .map_err(|_| String::from("registry lock poisoned"))?;
        let meta = registry.get_known(&call.app)
            .ok_or_else(|| format!("app '{}' is not loaded", call.app))?;
        let schema = meta.schema.as_ref()
            .ok_or_else(|| format!("app '{}' has no schema — try reloading it", call.app))?;
        let func = schema.find_function(&call.function)
            .ok_or_else(|| format!(
                "function '{}' not found in app '{}'. Available: [{}]",
                call.function,
                call.app,
                schema.functions.iter().map(|f| f.name.as_str())
                    .chain(schema.interfaces.iter().flat_map(|i| {
                        i.functions.iter().map(move |f| f.name.as_str())
                    }))
                    .collect::<Vec<_>>()
                    .join(", "),
            ))?;

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
            app: call.app.clone(),
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
            let auth = match self.check_app_permissions(call) {
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

            let mgmt_result = match self.load_app(&load.name, &hostname, &load.bytes, encryption_key, load.permissions, max_fuel, mcp_enabled, load.docs) {
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
                None => WasmManagementResult::NotFound { name: schema_req.app.clone() },
            };
            return Some(Response::Data(serialize_or_error(&mgmt_result)));
        }

        // 6. mcp_tools — MCP tool manifest for a single app
        if let Some(ref mcp_req) = envelope.mcp_tools {
            // Reuse schema access control (same permissions model).
            let schema_req = WasmSchemaRequest {
                app: mcp_req.app.clone(),
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
            let mgmt_result = match registry.get_known(&mcp_req.app) {
                Some(meta) => match &meta.schema {
                    Some(s) if s.mcp_enabled => {
                        WasmManagementResult::McpTools {
                            manifest: s.to_mcp_manifest(),
                        }
                    }
                    Some(_) => WasmManagementResult::Error {
                        message: format!(
                            "MCP is disabled for app '{}'",
                            mcp_req.app,
                        ),
                    },
                    None => WasmManagementResult::Error {
                        message: format!(
                            "app '{}' has no schema — try reloading it",
                            mcp_req.app,
                        ),
                    },
                },
                None => WasmManagementResult::NotFound { name: mcp_req.app.clone() },
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
            let auth = match self.check_app_permissions(&wasm_call) {
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
    if let Some(ch) = meta.configuration_hash {
        config.push(ConfigEntry {
            key: format!("wasm.{}.configuration_hash", meta.name),
            value: ch.to_vec(),
            oid: Some(enclave_os_common::oids::APP_CONFIGURATION_HASH_OID),
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
    use crate::protocol::{WitType, WasmParam};
    match ty {
        WitType::Bool => val.as_bool()
            .map(WasmParam::Bool)
            .ok_or_else(|| format!("param '{}': expected bool", name)),
        WitType::U8 | WitType::U16 | WitType::U32 => val.as_u64()
            .map(|n| WasmParam::U32(n as u32))
            .ok_or_else(|| format!("param '{}': expected unsigned integer", name)),
        WitType::U64 => val.as_u64()
            .map(WasmParam::U64)
            .ok_or_else(|| format!("param '{}': expected u64", name)),
        WitType::S8 | WitType::S16 | WitType::S32 => val.as_i64()
            .map(|n| WasmParam::S32(n as i32))
            .ok_or_else(|| format!("param '{}': expected signed integer", name)),
        WitType::S64 => val.as_i64()
            .map(WasmParam::S64)
            .ok_or_else(|| format!("param '{}': expected s64", name)),
        WitType::Float32 => val.as_f64()
            .map(|n| WasmParam::F32(n as f32))
            .ok_or_else(|| format!("param '{}': expected float", name)),
        WitType::Float64 => val.as_f64()
            .map(WasmParam::F64)
            .ok_or_else(|| format!("param '{}': expected float", name)),
        WitType::String | WitType::Char => val.as_str()
            .map(|s| WasmParam::String(s.to_string()))
            .ok_or_else(|| format!("param '{}': expected string", name)),
        WitType::List { element } if matches!(element.as_ref(), WitType::U8) => {
            // list<u8> → Bytes (base64 string or array of numbers)
            if let Some(s) = val.as_str() {
                Ok(WasmParam::Bytes(s.as_bytes().to_vec()))
            } else if let Some(arr) = val.as_array() {
                let bytes: Result<Vec<u8>, String> = arr.iter()
                    .map(|v| v.as_u64()
                        .map(|n| n as u8)
                        .ok_or_else(|| format!("param '{}': list<u8> element not a u8", name)))
                    .collect();
                Ok(WasmParam::Bytes(bytes?))
            } else {
                Err(format!("param '{}': expected string or byte array for list<u8>", name))
            }
        }
        WitType::List { element } => {
            let arr = val.as_array()
                .ok_or_else(|| format!("param '{}': expected array for list type", name))?;
            let items: Result<Vec<WasmParam>, String> = arr.iter()
                .enumerate()
                .map(|(i, v)| json_to_wasm_param(v, element, &format!("{}[{}]", name, i)))
                .collect();
            Ok(WasmParam::List(items?))
        }
        WitType::Record { fields } => {
            let obj = val.as_object()
                .ok_or_else(|| format!("param '{}': expected object for record type", name))?;
            let rec: Result<Vec<(String, WasmParam)>, String> = fields.iter()
                .map(|f| {
                    let v = obj.get(&f.name).unwrap_or(&serde_json::Value::Null);
                    let p = json_to_wasm_param(v, &f.ty, &format!("{}.{}", name, f.name))?;
                    Ok((f.name.clone(), p))
                })
                .collect();
            Ok(WasmParam::Record(rec?))
        }
        WitType::Enum { names } => {
            let s = val.as_str()
                .ok_or_else(|| format!("param '{}': expected string for enum type", name))?;
            if !names.contains(&s.to_string()) {
                return Err(format!(
                    "param '{}': unknown enum case '{}', expected one of: [{}]",
                    name, s, names.join(", "),
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
                    return Err(format!("param '{}': variant object must have exactly one key", name));
                }
                let (case_name, payload) = obj.iter().next().unwrap();
                let case = cases.iter().find(|c| &c.name == case_name)
                    .ok_or_else(|| format!("param '{}': unknown variant case '{}'", name, case_name))?;
                match &case.ty {
                    Some(ty) => {
                        let p = json_to_wasm_param(payload, ty, &format!("{}.{}", name, case_name))?;
                        Ok(WasmParam::Variant(case_name.clone(), Some(Box::new(p))))
                    }
                    None => Ok(WasmParam::Variant(case_name.clone(), None)),
                }
            } else {
                Err(format!("param '{}': expected string or object for variant type", name))
            }
        }
        WitType::Tuple { elements } => {
            let arr = val.as_array()
                .ok_or_else(|| format!("param '{}': expected array for tuple type", name))?;
            if arr.len() != elements.len() {
                return Err(format!(
                    "param '{}': tuple expects {} elements, got {}",
                    name, elements.len(), arr.len(),
                ));
            }
            let items: Result<Vec<WasmParam>, String> = arr.iter()
                .zip(elements.iter())
                .enumerate()
                .map(|(i, (v, t))| json_to_wasm_param(v, t, &format!("{}.{}", name, i)))
                .collect();
            Ok(WasmParam::Tuple(items?))
        }
        WitType::Flags { names } => {
            let arr = val.as_array()
                .ok_or_else(|| format!("param '{}': expected array of strings for flags type", name))?;
            let flags: Result<Vec<String>, String> = arr.iter()
                .map(|v| v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| format!("param '{}': flag must be a string", name)))
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
                        Some(ty) => Some(Box::new(json_to_wasm_param(ok_val, ty, &format!("{}.ok", name))?)),
                        None => None,
                    };
                    Ok(WasmParam::Variant("ok".to_string(), p))
                } else if let Some(err_val) = obj.get("err") {
                    let p = match err {
                        Some(ty) => Some(Box::new(json_to_wasm_param(err_val, ty, &format!("{}.err", name))?)),
                        None => None,
                    };
                    Ok(WasmParam::Variant("err".to_string(), p))
                } else {
                    Err(format!("param '{}': result must have 'ok' or 'err' key", name))
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
    Some(enclave_os_kvstore::SealedKvStore::from_master_key_with_table(
        meta.encryption_key,
        table.as_bytes(),
    ))
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
                            Some(store) => enclave_os_app_auth::get_user_roles_with_bootstrap(
                                store, &user_id,
                            ).unwrap_or_default(),
                            None => Vec::new(),
                        }
                    }
                    #[cfg(not(feature = "app-auth"))]
                    { let _ = role_store; Vec::new() }
                };
                return Ok(AuthResult { roles, user_id: Some(user_id) });
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
        let (roles, sub) = verify_app_token(token, oidc)?;
        return Ok(AuthResult { roles, user_id: sub });
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
) -> Result<(Vec<String>, Option<String>), String> {
    // Verify ES256 signature via JWKS (rejects alg:none, fetches/caches keys)
    let claims: serde_json::Value = crate::jwks_fetcher::verify_jwt_signature(
        token,
        &oidc.issuer,
        &oidc.jwks_uri,
    )?;

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

    // Extract subject (user identity).
    let sub = claims.get("sub")
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
    // Zitadel map format
    if let Some(val) = claims.get("urn:zitadel:iam:org:project:roles") {
        collect_role_strings(val, &mut roles);
    }

    roles.sort();
    roles.dedup();
    Ok((roles, sub))
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
#[allow(dead_code)]
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
