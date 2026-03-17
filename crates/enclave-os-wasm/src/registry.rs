// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! App registry — loading, introspection, and routing of WASM components.
//!
//! Each loaded app is a compiled wasmtime [`Component`] with metadata
//! extracted from its WIT exports.  The registry maps app names to their
//! components and provides typed function dispatch.
//!
//! ## App lifecycle
//!
//! 1. **Load**: WASM component bytes → compile → introspect exports →
//!    register in the routing table.
//! 2. **Call**: Look up app by name → instantiate (or reuse) → find
//!    exported function → marshal params → invoke → marshal results.
//! 3. **Unload**: Remove from registry (freeing compiled code).
//!
//! ## WIT-based routing
//!
//! The Component Model organises exports by *interface*.  A component
//! declaring:
//!
//! ```wit
//! package my-org:my-app;
//! world my-app {
//!     export process: func(input: string) -> string;
//!     export my-api: interface {
//!         transform: func(data: list<u8>) -> list<u8>;
//!     }
//! }
//! ```
//!
//! will expose these callable paths:
//! - `process` (root-level export)
//! - `my-api/transform` (interface-scoped export)
//!
//! Clients address them via [`WasmCall::function`] using either the bare
//! name or the `interface/function` qualified name.
//!
//! [`Component`]: wasmtime::component::Component
//! [`WasmCall::function`]: crate::protocol::WasmCall::function

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Serialize, Deserialize};
use wasmtime::component::{Component, Func, Val};

use crate::engine::WasmEngine;
use enclave_os_common::types::AEAD_KEY_SIZE;
use crate::protocol::{AppPermissions, ExportedFunc, FunctionPolicy, WasmParam, WasmResult, WasmValue};
use crate::wasi::AppContext;

/// Maximum number of compiled WASM components kept in memory.
///
/// Enclave Page Cache (EPC) is limited, so we cap the number of
/// simultaneously compiled apps and evict the least-recently-used
/// when the limit is reached.  Apps evicted from memory remain
/// persisted in the sealed KV store and are reloaded on demand.
const MAX_LOADED_APPS: usize = 10;

// ---------------------------------------------------------------------------
//  Persisted app metadata
// ---------------------------------------------------------------------------

/// Serialisable metadata for a WASM app persisted in the sealed KV store.
///
/// This is compact enough to keep in memory for *all* known apps,
/// even when the compiled component is evicted to save EPC.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppMeta {
    pub name: String,
    pub hostname: String,
    pub code_hash: [u8; 32],
    pub encryption_key: [u8; AEAD_KEY_SIZE],
    pub key_source: String,
    pub permissions: Option<AppPermissions>,
    pub permissions_hash: Option<[u8; 32]>,
    pub max_fuel: u64,
    /// Full WIT type schema generated at load time.
    ///
    /// `None` for apps persisted before schema support was added —
    /// a fresh schema is generated when the app is next lazy-loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<crate::protocol::AppSchema>,
}

// ---------------------------------------------------------------------------
//  LoadedApp
// ---------------------------------------------------------------------------

/// A compiled WASM app with introspected metadata.
pub struct LoadedApp {
    /// User-chosen name for this app.
    pub name: String,
    /// SNI hostname for this app's dedicated TLS certificate.
    pub hostname: String,
    /// SHA-256 of the original WASM component bytecode.
    pub code_hash: [u8; 32],
    /// Per-app AES-256 encryption key for KV store data.
    ///
    /// Each app gets its own key so that data isolation is
    /// cryptographically enforced.  When the app is unloaded this key
    /// is dropped from memory, making any on-disk data permanently
    /// unrecoverable.
    encryption_key: [u8; AEAD_KEY_SIZE],
    /// How the encryption key was provisioned.
    ///
    /// - `"generated"` — key was generated inside the enclave.
    /// - `"byok:<fingerprint>"` — caller supplied the key;
    ///   `<fingerprint>` is the lowercase hex SHA-256 of the raw key
    ///   bytes so attesters can verify which key is in use.
    pub key_source: String,
    /// Compiled component (cheap to clone — refcounted internally).
    component: Component,
    /// Exported functions discovered from the component's WIT.
    ///
    /// Key: function path (e.g. `"process"` or `"my-api/transform"`).
    /// Value: `(param_count, result_count)`.
    exports: BTreeMap<String, (usize, usize)>,
    /// Optional per-app permission policy.
    pub permissions: Option<AppPermissions>,
    /// SHA-256 hash of the permissions JSON (if any).
    pub permissions_hash: Option<[u8; 32]>,
    /// Maximum fuel budget per `wasm_call` for this app.
    pub max_fuel: u64,
}

impl LoadedApp {
    /// List the exported functions.
    pub fn exported_funcs(&self) -> Vec<ExportedFunc> {
        self.exports
            .iter()
            .map(|(name, &(param_count, result_count))| ExportedFunc {
                name: name.clone(),
                param_count,
                result_count,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
//  AppRegistry
// ---------------------------------------------------------------------------

/// Registry of WASM apps with LRU-managed compiled components.
///
/// Two-tier architecture:
/// - **`known`**: Metadata for *all* persisted apps. Always in memory.
/// - **`loaded`**: Compiled components for recently-used apps (max
///   [`MAX_LOADED_APPS`]).  Evicted apps stay in `known` and are
///   recompiled on demand from KV-stored bytes.
pub struct AppRegistry {
    engine: WasmEngine,
    /// All known apps (metadata only). Always in memory.
    known: BTreeMap<String, AppMeta>,
    /// Currently compiled apps (LRU-managed).
    loaded: BTreeMap<String, LoadedApp>,
    /// LRU tracking: name → monotonic counter. Higher = more recent.
    lru: BTreeMap<String, u64>,
    /// Monotonic counter incremented on each access.
    lru_counter: u64,
}

impl AppRegistry {
    /// Create a new empty registry backed by the given engine.
    pub fn new(engine: WasmEngine) -> Self {
        Self {
            engine,
            known: BTreeMap::new(),
            loaded: BTreeMap::new(),
            lru: BTreeMap::new(),
            lru_counter: 0,
        }
    }

    /// Load a WASM component from pre-compiled AOT bytes.
    ///
    /// 1. Computes the SHA-256 code hash over the pre-compiled artifact.
    /// 2. Deserializes (no Cranelift — AOT only).
    /// 3. Introspects exports (root functions + interface members).
    /// 4. Registers under `name` with the given `hostname`.
    ///
    /// The `precompiled_bytes` must have been produced by
    /// `Engine::precompile_component()` or `Component::serialize()`
    /// outside the enclave with matching engine settings.
    ///
    /// If `encryption_key` is `Some`, the caller supplies the AES-256 key
    /// (BYOK). Otherwise a random key is generated via RDRAND.
    ///
    /// If `permissions` is `Some`, its SHA-256 hash is computed for OID
    /// attestation and the policy is stored for per-function enforcement.
    ///
    /// Returns an error if `name` is already taken or deserialization fails.
    pub fn load_app(
        &mut self,
        name: &str,
        hostname: &str,
        wasm_bytes: &[u8],
        encryption_key: Option<[u8; AEAD_KEY_SIZE]>,
        permissions: Option<AppPermissions>,
        max_fuel: u64,
    ) -> Result<AppMeta, String> {
        if self.known.contains_key(name) {
            return Err(format!("app '{}' is already loaded", name));
        }

        // ── Code hash ──────────────────────────────────────────────
        let hash = digest::digest(&digest::SHA256, wasm_bytes);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(hash.as_ref());

        // ── Deserialize (AOT) ──────────────────────────────────────
        let component = self.engine.deserialize(wasm_bytes)?;
        // ── Per-app encryption key ─────────────────────────────────
        let (app_key, key_source) = match encryption_key {
            Some(k) => {
                let fingerprint = {
                    let d = digest::digest(&digest::SHA256, &k);
                    let mut buf = String::with_capacity(64);
                    for b in d.as_ref() {
                        use core::fmt::Write;
                        let _ = write!(buf, "{:02x}", b);
                    }
                    buf
                };
                (k, format!("byok:{}", fingerprint))
            }
            None => {
                let rng = SystemRandom::new();
                let mut k = [0u8; AEAD_KEY_SIZE];
                rng.fill(&mut k)
                    .map_err(|_| String::from("RDRAND failed generating app encryption key"))?;
                (k, String::from("generated"))
            }
        };
        // ── Introspect exports (full WIT type schema) ──────────────
        let schema = self.engine.discover_exports_typed(name, hostname, &component);
        let exports = schema.to_exports_map();

        if exports.is_empty() {
            return Err(format!(
                "app '{}' has no exported functions — is it a valid Component?",
                name, 
            ));
        }

        // ── Permissions hash ────────────────────────────────────────────
        let permissions_hash = permissions.as_ref().map(|p| {
            let canonical = serde_json::to_vec(p)
                .expect("AppPermissions must be serialisable");
            let h = digest::digest(&digest::SHA256, &canonical);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.as_ref());
            out
        });

        // Validate permissions version
        if let Some(ref p) = permissions {
            if p.version != 1 {
                return Err(format!(
                    "unsupported permissions version: {} (expected 1)",
                    p.version,
                ));
            }
        }

        let meta = AppMeta {
            name: name.to_string(),
            hostname: hostname.to_string(),
            code_hash,
            encryption_key: app_key,
            key_source: key_source.clone(),
            permissions: permissions.clone(),
            permissions_hash,
            max_fuel,
            schema: Some(schema),
        };
        self.known.insert(name.to_string(), meta.clone());

        self.loaded.insert(
            name.to_string(),
            LoadedApp {
                name: name.to_string(),
                hostname: hostname.to_string(),
                code_hash,
                encryption_key: app_key,
                key_source,
                component,
                exports,
                permissions,
                permissions_hash,
                max_fuel,
            },
        );
        self.touch(name);
        self.evict_if_needed();

        Ok(meta)
    }

    /// Register metadata for a persisted app without compiling it.
    ///
    /// Used during startup to restore app identities from the sealed
    /// KV store.  The component stays uncompiled until the first
    /// `wasm_call` triggers [`ensure_loaded()`](Self::ensure_loaded).
    pub fn register_known(&mut self, meta: AppMeta) {
        self.known.insert(meta.name.clone(), meta);
    }

    /// Compile a known-but-unloaded app from its WASM bytes.
    ///
    /// If the app is already compiled, this just refreshes its LRU
    /// position.  Otherwise it deserialises the AOT component, inserts
    /// it into the `loaded` map, and evicts the least-recently-used
    /// app if the cache is full.
    pub fn ensure_loaded(&mut self, name: &str, wasm_bytes: &[u8]) -> Result<(), String> {
        if self.loaded.contains_key(name) {
            self.touch(name);
            return Ok(());
        }

        let meta = self.known.get(name)
            .ok_or_else(|| format!("unknown app: '{}'", name))?
            .clone();

        let component = self.engine.deserialize(wasm_bytes)?;

        // Prefer building exports from the schema (already in AppMeta)
        // to avoid redundant introspection. Fall back to runtime
        // discovery for apps persisted before schema support.
        let (exports, new_schema) = if let Some(ref s) = meta.schema {
            (s.to_exports_map(), None)
        } else {
            let s = self.engine.discover_exports_typed(&meta.name, &meta.hostname, &component);
            let e = s.to_exports_map();
            (e, Some(s))
        };

        // Back-fill schema into the known map for pre-schema apps.
        if let Some(ref s) = new_schema {
            if let Some(km) = self.known.get_mut(name) {
                km.schema = Some(s.clone());
            }
        }

        self.loaded.insert(name.to_string(), LoadedApp {
            name: meta.name,
            hostname: meta.hostname,
            code_hash: meta.code_hash,
            encryption_key: meta.encryption_key,
            key_source: meta.key_source,
            component,
            exports,
            permissions: meta.permissions,
            permissions_hash: meta.permissions_hash,
            max_fuel: meta.max_fuel,
        });
        self.touch(name);
        self.evict_if_needed();
        Ok(())
    }

    /// Remove an app from both `known` and `loaded` maps.
    ///
    /// Returns the hostname if found.
    pub fn remove_app(&mut self, name: &str) -> Option<String> {
        self.loaded.remove(name);
        self.lru.remove(name);
        self.known.remove(name).map(|m| m.hostname)
    }

    /// List all known apps with their metadata.
    ///
    /// Apps that are currently compiled in memory have their exports
    /// populated; evicted apps show an empty export list.
    pub fn list_apps(&self) -> Vec<crate::protocol::AppInfo> {
        self.known
            .values()
            .map(|meta| {
                let exports = self.loaded.get(&meta.name)
                    .map(|app| app.exported_funcs())
                    .unwrap_or_default();
                crate::protocol::AppInfo {
                    name: meta.name.clone(),
                    hostname: meta.hostname.clone(),
                    code_hash: enclave_os_common::hex::hex_encode(&meta.code_hash),
                    key_source: meta.key_source.clone(),
                    exports,
                    permissions_hash: meta.permissions_hash.map(|h| enclave_os_common::hex::hex_encode(&h)),
                    max_fuel: meta.max_fuel,
                    loaded: self.loaded.contains_key(&meta.name),
                }
            })
            .collect()
    }

    /// Get the code hash for a known app (for attestation).
    pub fn app_code_hash(&self, name: &str) -> Option<&[u8; 32]> {
        self.known.get(name).map(|m| &m.code_hash)
    }

    /// Get the key-source string for a known app.
    ///
    /// Returns `"generated"` or `"byok:<fingerprint>"`.
    pub fn app_key_source(&self, name: &str) -> Option<&str> {
        self.known.get(name).map(|m| m.key_source.as_str())
    }

    /// Get all known apps' code hashes (sorted by name).
    pub fn all_code_hashes(&self) -> Vec<(&str, &[u8; 32])> {
        self.known
            .iter()
            .map(|(name, meta)| (name.as_str(), &meta.code_hash))
            .collect()
    }

    /// Get all known apps' attestation metadata (sorted by name).
    ///
    /// Returns `(name, code_hash, key_source)` for each known app.
    pub fn all_app_metadata(&self) -> Vec<(&str, &[u8; 32], &str)> {
        self.known
            .iter()
            .map(|(name, meta)| (name.as_str(), &meta.code_hash, meta.key_source.as_str()))
            .collect()
    }

    /// Get the permissions hash for a known app (for OID 3.5 attestation).
    pub fn app_permissions_hash(&self, name: &str) -> Option<&[u8; 32]> {
        self.known.get(name).and_then(|m| m.permissions_hash.as_ref())
    }

    /// Get the permissions policy for a known app (for call-time enforcement).
    pub fn app_permissions(&self, name: &str) -> Option<&AppPermissions> {
        self.known.get(name).and_then(|m| m.permissions.as_ref())
    }

    /// Whether an app is known (persisted) but not necessarily compiled.
    pub fn is_known(&self, name: &str) -> bool {
        self.known.contains_key(name)
    }

    /// Whether an app is currently compiled in memory.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.loaded.contains_key(name)
    }

    /// Get metadata for a known app.
    pub fn get_known(&self, name: &str) -> Option<&AppMeta> {
        self.known.get(name)
    }

    /// Call an exported function on a loaded app.
    ///
    /// The app **must** already be in the `loaded` map (call
    /// [`ensure_loaded()`](Self::ensure_loaded) first).  Touches the
    /// LRU counter so the app is less likely to be evicted.
    ///
    /// Returns the [`WasmResult`] and the fuel consumed (0 on error
    /// before execution starts).
    pub fn call(
        &mut self,
        app_name: &str,
        function: &str,
        params: &[WasmParam],
    ) -> (WasmResult, i64) {
        self.touch(app_name);

        // ── Look up app ────────────────────────────────────────────
        let app = match self.loaded.get(app_name) {
            Some(a) => a,
            None => {
                return (WasmResult::Error {
                    message: format!("app '{}' is not loaded", app_name),
                }, 0);
            }
        };

        // ── Verify function exists ─────────────────────────────────
        if !app.exports.contains_key(function) {
            return (WasmResult::Error {
                message: format!(
                    "app '{}' has no export '{}'. Available: [{}]",
                    app_name,
                    function,
                    app.exports.keys().cloned().collect::<Vec<_>>().join(", "),
                ),
            }, 0);
        }

        // ── Instantiate ────────────────────────────────────────────
        let (mut store, instance) = match self.engine.instantiate(app_name, app.encryption_key, app.max_fuel, &app.component) {
            Ok(pair) => pair,
            Err(e) => {
                return (WasmResult::Error {
                    message: format!("instantiation failed: {}", e),
                }, 0);
            }
        };

        // Record fuel before execution for delta calculation.
        let fuel_before = store.get_fuel().unwrap_or(0) as i64;

        // ── Resolve the exported function ──────────────────────────
        // Functions can be at the root or under an exported instance.
        let func: Func = if let Some(slash) = function.find('/') {
            // Interface-scoped: "my-api/transform"
            let (iface_name, func_name) = function.split_at(slash);
            let func_name = &func_name[1..]; // skip the '/'

            // Look up the interface instance export, then the function within it.
            let iface_idx = match app.component.get_export_index(None, iface_name) {
                Some(idx) => idx,
                None => {
                    return (WasmResult::Error {
                        message: format!(
                            "interface '{}' not found in app '{}'",
                            iface_name, app_name,
                        ),
                    }, 0);
                }
            };
            match instance.get_func(&mut store, &iface_idx) {
                Some(f) => {
                    // The index resolved the instance; now get the function within it.
                    // We need to look up the function export under the interface.
                    match app
                        .component
                        .get_export_index(Some(&iface_idx), func_name)
                    {
                        Some(func_idx) => match instance.get_func(&mut store, &func_idx) {
                            Some(f) => f,
                            None => {
                                return (WasmResult::Error {
                                    message: format!(
                                        "function '{}' not found in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                }, 0);
                            }
                        },
                        None => {
                            return (WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            }, 0);
                        }
                    }
                }
                None => {
                    // Try the nested lookup approach
                    match app
                        .component
                        .get_export_index(Some(&iface_idx), func_name)
                    {
                        Some(func_idx) => match instance.get_func(&mut store, &func_idx) {
                            Some(f) => f,
                            None => {
                                return (WasmResult::Error {
                                    message: format!(
                                        "function '{}' not callable in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                }, 0);
                            }
                        },
                        None => {
                            return (WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            }, 0);
                        }
                    }
                }
            }
        } else {
            // Root-level export: "process"
            match instance.get_func(&mut store, function) {
                Some(f) => f,
                None => {
                    return (WasmResult::Error {
                        message: format!(
                            "function '{}' not found at root of app '{}'",
                            function, app_name,
                        ),
                    }, 0);
                }
            }
        };

        // ── Marshal parameters ─────────────────────────────────────
        let val_params: Vec<Val> = params.iter().map(param_to_val).collect();

        // ── Allocate result slots ──────────────────────────────────
        // We need to know how many results to expect.  For dynamic
        // dispatch (Func, not TypedFunc) we query the function type.
        let result_count = app
            .exports
            .get(function)
            .map(|&(_, r)| r)
            .unwrap_or(0);
        let mut results = vec![Val::Bool(false); result_count];

        //  Call 
        let call_err = func.call(&mut store, &val_params, &mut results).err();

        // Post-return cleanup (required by the Component Model).
        let post_err = if call_err.is_none() {
            func.post_return(&mut store).err()
        } else {
            None
        };

        // Flush any remaining partial lines from the guest's stdout/stderr.
        store.data_mut().flush_logs();

        // Calculate fuel consumed.
        let fuel_after = store.get_fuel().unwrap_or(0) as i64;
        let fuel_consumed = fuel_before - fuel_after;

        //  Check deferred errors 
        if let Some(e) = call_err {
            return (WasmResult::Error {
                message: format!("call failed: {}", e),
            }, fuel_consumed);
        }
        if let Some(e) = post_err {
            return (WasmResult::Error {
                message: format!("post_return failed: {}", e),
            }, fuel_consumed);
        }

        //  Marshal results 
        let returns: Vec<WasmValue> = results.iter().map(val_to_wasm_value).collect();

        (WasmResult::Ok { returns }, fuel_consumed)
    }

    // ── LRU helpers ────────────────────────────────────────────────

    /// Mark an app as recently used.
    fn touch(&mut self, name: &str) {
        self.lru_counter += 1;
        self.lru.insert(name.to_string(), self.lru_counter);
    }

    /// Evict the least-recently-used compiled app if over the limit.
    fn evict_if_needed(&mut self) {
        while self.loaded.len() > MAX_LOADED_APPS {
            let oldest = self.lru.iter()
                .filter(|(name, _)| self.loaded.contains_key(name.as_str()))
                .min_by_key(|(_, &counter)| counter)
                .map(|(name, _)| name.clone());

            if let Some(name) = oldest {
                self.loaded.remove(&name);
                self.lru.remove(&name);
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Value conversions: WasmParam ↔ wasmtime::component::Val
// ---------------------------------------------------------------------------

/// Convert a [`WasmParam`] to a wasmtime [`Val`].
fn param_to_val(p: &WasmParam) -> Val {
    match p {
        WasmParam::Bool(v) => Val::Bool(*v),
        WasmParam::S32(v) => Val::S32(*v),
        WasmParam::S64(v) => Val::S64(*v),
        WasmParam::U32(v) => Val::U32(*v),
        WasmParam::U64(v) => Val::U64(*v),
        WasmParam::F32(v) => Val::Float32(*v),
        WasmParam::F64(v) => Val::Float64(*v),
        WasmParam::String(v) => Val::String(v.clone().into()),
        WasmParam::Bytes(v) => {
            // Component model doesn't have a native "bytes" type;
            // map to list<u8>.
            Val::List(v.iter().map(|&b| Val::U8(b)).collect::<Vec<_>>().into())
        }
    }
}

/// Convert a wasmtime [`Val`] to a [`WasmValue`].
fn val_to_wasm_value(v: &Val) -> WasmValue {
    match v {
        Val::Bool(b) => WasmValue::Bool(*b),
        Val::S8(n) => WasmValue::S32(*n as i32),
        Val::U8(n) => WasmValue::U32(*n as u32),
        Val::S16(n) => WasmValue::S32(*n as i32),
        Val::U16(n) => WasmValue::U32(*n as u32),
        Val::S32(n) => WasmValue::S32(*n),
        Val::U32(n) => WasmValue::U32(*n),
        Val::S64(n) => WasmValue::S64(*n),
        Val::U64(n) => WasmValue::U64(*n),
        Val::Float32(v) => WasmValue::F32(*v),
        Val::Float64(v) => WasmValue::F64(*v),
        Val::String(s) => WasmValue::String(s.to_string()),
        Val::List(items) => {
            // Heuristic: if all items are U8, marshal as Bytes.
            let all_u8 = items.iter().all(|v| matches!(v, Val::U8(_)));
            if all_u8 {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|v| match v {
                        Val::U8(b) => *b,
                        _ => 0,
                    })
                    .collect();
                WasmValue::Bytes(bytes)
            } else {
                // Fallback: JSON-encode the list as a string.
                let inner: Vec<String> = items.iter().map(|v| format!("{:?}", v)).collect();
                WasmValue::String(format!("[{}]", inner.join(", ")))
            }
        }
        Val::Char(c) => WasmValue::String(c.to_string()),
        // For complex types (record, tuple, variant, enum, option, result,
        // flags, resource) — serialize a debug representation.
        other => WasmValue::String(format!("{:?}", other)),
    }
}
