// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Wasmtime engine setup and WASI-linked Component Linker.
//!
//! [`WasmEngine`] is the central runtime object.  It owns a configured
//! wasmtime [`Engine`] and a [`Component`][`Linker`] pre-populated with
//! the WASI host function implementations backed by the enclave OS.
//!
//! ## SGX considerations
//!
//! The wasmtime Privasys fork contains the `sys::sgx` runtime backend
//! (from commit `fbbcd2ac`) which replaces `mmap`/`mprotect`/signals
//! with SGX2 EDMM primitives:
//!
//! | Capability        | SGX backend                                  |
//! |-------------------|----------------------------------------------|
//! | Memory allocation | `sgx_mm_alloc` (reserve + commit)            |
//! | Memory protection | `sgx_mm_modify_permissions`                  |
//! | Trap handling     | `sgx_register_exception_handler` (VEH)       |
//! | Thread-local      | `std::thread_local!` (→ `sgx_tstd`)         |
//! | Unwind            | Stub (no-op)                                 |
//! | Page size         | 4096 (hardcoded)                             |
//!
//! [`Engine`]: wasmtime::Engine
//! [`Linker`]: wasmtime::component::Linker

use std::string::String;
use std::vec::Vec;

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

use crate::wasi::AppContext;
use enclave_os_common::types::AEAD_KEY_SIZE;

// ---------------------------------------------------------------------------
//  WasmEngine
// ---------------------------------------------------------------------------

/// Central WASM runtime — wraps wasmtime's [`Engine`] and a pre-configured
/// [`Linker`] with WASI host functions.
///
/// Create one per enclave lifetime.  Individual apps share the engine but
/// get their own [`Store`] + [`Instance`].
///
/// [`Instance`]: wasmtime::component::Instance
pub struct WasmEngine {
    engine: Engine,
    linker: Linker<AppContext>,
}

impl WasmEngine {
    /// Create a new `WasmEngine` with SGX-appropriate wasmtime settings.
    ///
    /// The engine is configured with:
    /// - Cranelift code generator
    /// - Component Model enabled
    /// - Conservative memory limits suitable for SGX EPC
    /// - No CoW image init (no mmap file backing in SGX)
    /// - Backtraces enabled (useful for debugging inside enclave)
    pub fn new() -> Result<Self, String> {
        let mut config = Config::new();

        // ── Core settings ──────────────────────────────────────────
        config.wasm_component_model(true);
        config.wasm_multi_memory(true);
        config.wasm_simd(true);

        // ── SGX-appropriate limits ─────────────────────────────────
        // SGX Enclave Page Cache (EPC) is limited.  Conservative defaults
        // prevent a single WASM app from exhausting enclave memory.
        //
        // static_memory_maximum_size:
        //   Max size of a single linear memory.  4 MiB is generous for
        //   most apps and avoids over-committing EPC.
        config.static_memory_maximum_size(4 * 1024 * 1024);

        // static_memory_guard_size:
        //   Guard pages after each memory.  Reduced from the default 2 GiB
        //   because SGX doesn't have virtual memory overcommit.
        config.static_memory_guard_size(64 * 1024);

        // ── No CoW / no disk-backed images ─────────────────────────
        config.memory_init_cow(false);

        let engine = Engine::new(&config).map_err(|e| {
            format!("wasmtime engine init failed: {}", e)
        })?;

        // ── Build Linker with WASI host functions ──────────────────
        let mut linker = Linker::<AppContext>::new(&engine);
        crate::wasi::add_wasi_to_linker(&mut linker).map_err(|e| {
            format!("WASI linker setup failed: {}", e)
        })?;

        // ── Register Enclave OS SDK interfaces ─────────────────────
        crate::enclave_sdk::add_to_linker(&mut linker).map_err(|e| {
            format!("Enclave SDK linker setup failed: {}", e)
        })?;

        Ok(Self { engine, linker })
    }

    /// Access the underlying wasmtime [`Engine`].
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Access the pre-configured [`Linker`].
    pub fn linker(&self) -> &Linker<AppContext> {
        &self.linker
    }

    /// Compile WASM component bytes into a [`Component`].
    ///
    /// This performs full validation and compilation via Cranelift.
    /// The resulting `Component` can be instantiated multiple times.
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Component, String> {
        Component::from_binary(&self.engine, wasm_bytes).map_err(|e| {
            format!("WASM compilation failed: {}", e)
        })
    }

    /// Create a new [`Store`] with a fresh [`AppContext`] scoped to an app.
    ///
    /// Each app instance gets its own store, which encapsulates all
    /// wasm-visible state (memories, tables, globals, app context).
    /// The `app_name` is used to namespace all KV store operations.
    pub fn new_store(&self, app_name: &str, master_key: [u8; AEAD_KEY_SIZE]) -> Store<AppContext> {
        let host = AppContext::with_app(app_name, master_key);
        let mut store = Store::new(&self.engine, host);

        // ── Fuel / resource limits ─────────────────────────────────
        // Fuel limits prevent infinite loops from hanging the enclave.
        // 10M instructions ≈ a few hundred ms of compute.
        store.set_fuel(10_000_000).ok();

        store
    }

    /// Instantiate a compiled [`Component`] in a fresh store.
    ///
    /// Returns `(Store, Instance)` ready for function calls.
    pub fn instantiate(
        &self,
        app_name: &str,
        master_key: [u8; AEAD_KEY_SIZE],
        component: &Component,
    ) -> Result<(Store<AppContext>, wasmtime::component::Instance), String> {
        let mut store = self.new_store(app_name, master_key);
        let instance = self.linker.instantiate(&mut store, component).map_err(|e| {
            format!("WASM instantiation failed: {}", e)
        })?;
        Ok((store, instance))
    }

    /// Discover exported functions from a compiled [`Component`].
    ///
    /// Returns `(function_name, param_count, result_count)` for each
    /// exported function at the root level and within exported instances.
    pub fn discover_exports(
        &self,
        component: &Component,
    ) -> Vec<(String, usize, usize)> {
        use wasmtime::component::types::ComponentItem;

        let ty = component.component_type();
        let mut exports = Vec::new();

        for (name, item) in ty.exports(&self.engine) {
            match item {
                ComponentItem::ComponentFunc(func_ty) => {
                    exports.push((
                        name.to_string(),
                        func_ty.params().len(),
                        func_ty.results().len(),
                    ));
                }
                ComponentItem::ComponentInstance(inst_ty) => {
                    // Recurse into exported instances to find nested functions.
                    // WIT interfaces appear as exported instances, e.g.
                    //   export my-api: interface { process: func(...) }
                    for (func_name, nested) in inst_ty.exports(&self.engine) {
                        if let ComponentItem::ComponentFunc(func_ty) = nested {
                            let qualified = format!("{}/{}", name, func_name);
                            exports.push((
                                qualified,
                                func_ty.params().len(),
                                func_ty.results().len(),
                            ));
                        }
                    }
                }
                _ => {} // resources, types — skip
            }
        }

        exports
    }
}
