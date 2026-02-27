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
//!    `1.3.6.1.4.1.1337.2.3` in RA-TLS certificates.
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
//! - Memory management via SGX2 EDMM (`sgx_mm_alloc`/`sgx_mm_modify_permissions`)
//! - Trap handling via VEH (`sgx_register_exception_handler`)
//! - Thread-local storage via `sgx_tstd::thread_local!`
//! - Stub unwind registration

pub mod enclave_sdk;
pub mod engine;
pub mod protocol;
pub mod registry;
#[cfg(target_vendor = "teaclave")]
pub mod sgx_platform;
pub mod wasi;

use std::sync::Mutex;
use std::vec::Vec;

use ring::digest;
use enclave_os_common::protocol::{Request, Response};
use enclave_os_enclave::config_merkle::ConfigLeaf;
use enclave_os_enclave::ecall::hex_encode;
use enclave_os_enclave::modules::{EnclaveModule, ModuleOid};
use enclave_os_common::types::AEAD_KEY_SIZE;

use crate::protocol::{WasmCall, WasmEnvelope, WasmResult};
use crate::registry::AppRegistry;

// ---------------------------------------------------------------------------
//  OID for WASM apps combined code hash — imported from common
// ---------------------------------------------------------------------------

pub use enclave_os_common::oids::WASM_APPS_HASH_OID;


// ---------------------------------------------------------------------------
//  WasmModule — EnclaveModule implementation
// ---------------------------------------------------------------------------

/// The WASM module: Component Model runtime inside SGX.
///
/// Owns the [`AppRegistry`] which contains all loaded WASM apps.
/// Requests matching the `wasm_call` envelope are dispatched here.
pub struct WasmModule {
    registry: Mutex<AppRegistry>,
}

impl WasmModule {
    /// Create a new WASM module.
    ///
    /// Takes the enclave-wide master encryption key from [`SealedConfig`].
    /// Initialises wasmtime with SGX-appropriate settings and WASI
    /// host function bindings.
    ///
    /// Call [`load_app()`](Self::load_app) to add WASM apps before
    /// the enclave enters its event loop.
    pub fn new(master_key: [u8; AEAD_KEY_SIZE]) -> Result<Self, String> {
        let engine = crate::engine::WasmEngine::new()?;
        let registry = AppRegistry::new(engine, master_key);
        Ok(Self {
            registry: Mutex::new(registry),
        })
    }

    /// Load a WASM component from raw bytes.
    ///
    /// The app will be compiled, introspected, and registered under
    /// the given name.  Its code hash is automatically included in
    /// attestation (config Merkle leaves + X.509 OID).
    pub fn load_app(&self, name: &str, wasm_bytes: &[u8]) -> Result<(), String> {
        self.registry
            .lock()
            .map_err(|_| String::from("registry lock poisoned"))?
            .load_app(name, wasm_bytes)
    }

    /// Unload a WASM app by name.
    pub fn unload_app(&self, name: &str) -> bool {
        self.registry
            .lock()
            .map(|mut r| r.unload_app(name))
            .unwrap_or(false)
    }

    /// List all loaded apps with metadata.
    pub fn list_apps(&self) -> Vec<crate::protocol::AppInfo> {
        self.registry
            .lock()
            .map(|r| r.list_apps())
            .unwrap_or_default()
    }

    /// Dispatch a parsed `WasmCall` to the appropriate app.
    fn dispatch_call(&self, call: &WasmCall) -> WasmResult {
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => {
                return WasmResult::Error {
                    message: String::from("registry lock poisoned"),
                };
            }
        };
        registry.call(&call.app, &call.function, &call.params)
    }

    /// Compute the combined hash of all loaded apps' code hashes.
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
}

// ---------------------------------------------------------------------------
//  EnclaveModule implementation
// ---------------------------------------------------------------------------

impl EnclaveModule for WasmModule {
    fn name(&self) -> &str {
        "wasm"
    }

    /// Handle a client request.
    ///
    /// Expects the `Request::Data` payload to be JSON containing a
    /// `wasm_call` field.  If present, dispatches to the target app.
    /// Returns `None` if the payload doesn't contain a `wasm_call`
    /// (letting other modules handle the request).
    fn handle(&self, req: &Request) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };

        // Try to parse the envelope.
        let envelope: WasmEnvelope = match serde_json::from_slice(data) {
            Ok(e) => e,
            Err(_) => return None, // Not a WASM request — decline.
        };

        let call = match envelope.wasm_call {
            Some(c) => c,
            None => return None, // No wasm_call field — decline.
        };

        // Dispatch the call.
        let result = self.dispatch_call(&call);

        // Serialize the result.
        let result_json = match serde_json::to_vec(&result) {
            Ok(j) => j,
            Err(e) => {
                let err = WasmResult::Error {
                    message: format!("result serialization failed: {}", e),
                };
                serde_json::to_vec(&err).unwrap_or_default()
            }
        };

        Some(Response::Data(result_json))
    }

    /// Config Merkle leaves for attestation.
    ///
    /// Each loaded app contributes a leaf:
    ///   `wasm.<app_name>.code_hash` = SHA-256 of the WASM bytecode
    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        registry
            .all_code_hashes()
            .into_iter()
            .map(|(name, hash)| ConfigLeaf {
                name: format!("wasm.{}.code_hash", name),
                data: Some(hash.to_vec()),
            })
            .collect()
    }

    /// Custom X.509 OIDs for RA-TLS certificates.
    ///
    /// Embeds the combined apps hash as OID `1.3.6.1.4.1.1337.2.3`.
    fn custom_oids(&self) -> Vec<ModuleOid> {
        let combined = self.combined_apps_hash();

        // Only include the OID if at least one app is loaded.
        if combined == [0u8; 32] {
            return Vec::new();
        }

        vec![ModuleOid {
            oid: WASM_APPS_HASH_OID,
            value: combined.to_vec(),
        }]
    }
}
