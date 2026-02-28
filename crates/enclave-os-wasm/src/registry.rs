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
use wasmtime::component::{Component, Func, Val};

use crate::engine::WasmEngine;
use enclave_os_common::types::AEAD_KEY_SIZE;
use crate::protocol::{ExportedFunc, WasmParam, WasmResult, WasmValue};
use crate::wasi::AppContext;

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
    /// Compiled component (cheap to clone — refcounted internally).
    component: Component,
    /// Exported functions discovered from the component's WIT.
    ///
    /// Key: function path (e.g. `"process"` or `"my-api/transform"`).
    /// Value: `(param_count, result_count)`.
    exports: BTreeMap<String, (usize, usize)>,
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

/// Registry of loaded WASM apps.
///
/// Maintains a name→app mapping and provides load / call / unload
/// operations.  The engine is shared across all apps.
pub struct AppRegistry {
    engine: WasmEngine,
    apps: BTreeMap<String, LoadedApp>,
    /// AES-256 master key for sealed KV store (WASI FS + key persistence).
    master_key: [u8; AEAD_KEY_SIZE],
}

impl AppRegistry {
    /// Create a new empty registry backed by the given engine.
    pub fn new(engine: WasmEngine, master_key: [u8; AEAD_KEY_SIZE]) -> Self {
        Self {
            engine,
            apps: BTreeMap::new(),
            master_key,
        }
    }

    /// Load a WASM component from raw bytes.
    ///
    /// 1. Computes the SHA-256 code hash.
    /// 2. Compiles via Cranelift.
    /// 3. Introspects exports (root functions + interface members).
    /// 4. Registers under `name` with the given `hostname`.
    ///
    /// Returns an error if `name` is already taken or compilation fails.
    pub fn load_app(&mut self, name: &str, hostname: &str, wasm_bytes: &[u8]) -> Result<(), String> {
        if self.apps.contains_key(name) {
            return Err(format!("app '{}' is already loaded", name));
        }

        // ── Code hash ──────────────────────────────────────────────
        let hash = digest::digest(&digest::SHA256, wasm_bytes);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(hash.as_ref());

        // ── Compile ────────────────────────────────────────────────
        let component = self.engine.compile(wasm_bytes)?;

        // ── Introspect exports ─────────────────────────────────────
        let discovered = self.engine.discover_exports(&component);
        let mut exports = BTreeMap::new();
        for (func_name, params, results) in &discovered {
            exports.insert(func_name.clone(), (*params, *results));
        }

        if exports.is_empty() {
            return Err(format!(
                "app '{}' has no exported functions — is it a valid Component?",
                name, 
            ));
        }

        self.apps.insert(
            name.to_string(),
            LoadedApp {
                name: name.to_string(),
                hostname: hostname.to_string(),
                code_hash,
                component,
                exports,
            },
        );

        Ok(())
    }

    /// Unload an app by name. Returns the hostname if found.
    pub fn unload_app(&mut self, name: &str) -> Option<String> {
        self.apps.remove(name).map(|app| app.hostname)
    }

    /// List all loaded apps with their metadata.
    pub fn list_apps(&self) -> Vec<crate::protocol::AppInfo> {
        self.apps
            .values()
            .map(|app| crate::protocol::AppInfo {
                name: app.name.clone(),
                hostname: app.hostname.clone(),
                code_hash: enclave_os_enclave::ecall::hex_encode(&app.code_hash),
                exports: app.exported_funcs(),
            })
            .collect()
    }

    /// Get the code hash for an app (for attestation).
    pub fn app_code_hash(&self, name: &str) -> Option<&[u8; 32]> {
        self.apps.get(name).map(|app| &app.code_hash)
    }

    /// Get all loaded apps' code hashes (sorted by name).
    pub fn all_code_hashes(&self) -> Vec<(&str, &[u8; 32])> {
        self.apps
            .iter()
            .map(|(name, app)| (name.as_str(), &app.code_hash))
            .collect()
    }

    /// Call an exported function on a loaded app.
    ///
    /// This creates a fresh [`Store`] + [`Instance`] for each call
    /// (stateless execution model).  The instance is discarded after the
    /// call completes.
    ///
    /// [`Store`]: wasmtime::Store
    /// [`Instance`]: wasmtime::component::Instance
    pub fn call(
        &self,
        app_name: &str,
        function: &str,
        params: &[WasmParam],
    ) -> WasmResult {
        // ── Look up app ────────────────────────────────────────────
        let app = match self.apps.get(app_name) {
            Some(a) => a,
            None => {
                return WasmResult::Error {
                    message: format!("unknown app: '{}'", app_name),
                };
            }
        };

        // ── Verify function exists ─────────────────────────────────
        if !app.exports.contains_key(function) {
            return WasmResult::Error {
                message: format!(
                    "app '{}' has no export '{}'. Available: [{}]",
                    app_name,
                    function,
                    app.exports.keys().cloned().collect::<Vec<_>>().join(", "),
                ),
            };
        }

        // ── Instantiate ────────────────────────────────────────────
        let (mut store, instance) = match self.engine.instantiate(app_name, self.master_key, &app.component) {
            Ok(pair) => pair,
            Err(e) => {
                return WasmResult::Error {
                    message: format!("instantiation failed: {}", e),
                };
            }
        };

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
                    return WasmResult::Error {
                        message: format!(
                            "interface '{}' not found in app '{}'",
                            iface_name, app_name,
                        ),
                    };
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
                                return WasmResult::Error {
                                    message: format!(
                                        "function '{}' not found in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                };
                            }
                        },
                        None => {
                            return WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            };
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
                                return WasmResult::Error {
                                    message: format!(
                                        "function '{}' not callable in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                };
                            }
                        },
                        None => {
                            return WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            };
                        }
                    }
                }
            }
        } else {
            // Root-level export: "process"
            match instance.get_func(&mut store, function) {
                Some(f) => f,
                None => {
                    return WasmResult::Error {
                        message: format!(
                            "function '{}' not found at root of app '{}'",
                            function, app_name,
                        ),
                    };
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

        //  Check deferred errors 
        if let Some(e) = call_err {
            return WasmResult::Error {
                message: format!("call failed: {}", e),
            };
        }
        if let Some(e) = post_err {
            return WasmResult::Error {
                message: format!("post_return failed: {}", e),
            };
        }

        //  Marshal results 
        let returns: Vec<WasmValue> = results.iter().map(val_to_wasm_value).collect();

        WasmResult::Ok { returns }
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
        WasmParam::F32(v) => Val::Float32(v.to_bits()),
        WasmParam::F64(v) => Val::Float64(v.to_bits()),
        WasmParam::String(v) => Val::String(v.clone().into()),
        WasmParam::Bytes(v) => {
            // Component model doesn't have a native "bytes" type;
            // map to list<u8>.
            Val::List(v.iter().map(|&b| Val::U8(b)).collect())
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
        Val::Float32(bits) => WasmValue::F32(f32::from_bits(*bits)),
        Val::Float64(bits) => WasmValue::F64(f64::from_bits(*bits)),
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
