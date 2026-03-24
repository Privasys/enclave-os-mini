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
//! with SGX-compatible primitives:
//!
//! | Capability        | SGX backend                                  |
//! |-------------------|----------------------------------------------|
//! | Memory allocation | RWX code pool (`.wasm_code` section, bump)   |
//! | Memory protection | No-op (pool=RWX, heap=RW)                    |
//! | Trap handling     | `sgx_register_exception_handler` (VEH)       |
//! | Thread-local      | `std::thread_local!` (→ `sgx_tstd`)         |
//! | Unwind            | Stub (no-op)                                 |
//! | Page size         | 4096 (hardcoded)                             |
//!
//! [`Engine`]: wasmtime::Engine
//! [`Linker`]: wasmtime::component::Linker

use std::collections::BTreeMap;
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
/// ## AOT-only
///
/// Cranelift is **not** compiled into the enclave.  WASM components must
/// be pre-compiled outside the enclave with `Engine::precompile_component`
/// or `Component::serialize`.  Inside the enclave we only call
/// `Component::deserialize` — no code generation happens at runtime.
///
/// [`Instance`]: wasmtime::component::Instance
pub struct WasmEngine {
    engine: Engine,
    linker: Linker<AppContext>,
}

impl WasmEngine {
    /// Create a new `WasmEngine` with SGX-appropriate wasmtime settings.
    ///
    /// The engine is configured for **AOT-only** operation:
    /// - No Cranelift compiler (pre-compiled components only)
    /// - Component Model enabled
    /// - Conservative memory limits suitable for SGX EPC
    /// - No CoW image init (no mmap file backing in SGX)
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
        // memory_reservation:
        //   Max size of a single linear memory.  4 MiB is generous for
        //   most apps and avoids over-committing EPC.
        config.memory_reservation(4 * 1024 * 1024);

        // memory_guard_size:
        //   Guard pages after each memory.  Reduced from the default 2 GiB
        //   because SGX doesn't have virtual memory overcommit.
        config.memory_guard_size(64 * 1024);

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

    /// Deserialize a pre-compiled component from AOT bytes.
    ///
    /// The `precompiled_bytes` must have been produced by
    /// `Engine::precompile_component()` or `Component::serialize()`
    /// **outside** the enclave with matching engine settings.
    ///
    /// # Safety
    ///
    /// The caller must ensure the bytes originate from a trusted source
    /// (the enclave build pipeline) and have not been tampered with.
    /// Wasmtime validates the header and will reject corrupt data, but
    /// loading arbitrary native code is inherently unsafe.
    pub fn deserialize(&self, precompiled_bytes: &[u8]) -> Result<Component, String> {
        // SAFETY: pre-compiled bytes come from the trusted build pipeline.
        // The enclave verifies the code hash before loading.
        unsafe {
            Component::deserialize(&self.engine, precompiled_bytes).map_err(|e| {
                format!("WASM deserialization failed: {}", e)
            })
        }
    }

    /// Create a new [`Store`] with a fresh [`AppContext`] scoped to an app.
    ///
    /// Each app instance gets its own store, which encapsulates all
    /// wasm-visible state (memories, tables, globals, app context).
    /// The `app_name` is used to namespace all KV store operations.
    /// `fuel` sets the per-call fuel budget.
    pub fn new_store(&self, app_name: &str, master_key: [u8; AEAD_KEY_SIZE], fuel: u64) -> Store<AppContext> {
        let host = AppContext::with_app(app_name, master_key);
        let mut store = Store::new(&self.engine, host);

        // ── Fuel / resource limits ─────────────────────────────
        // Fuel limits prevent infinite loops from hanging the enclave.
        store.set_fuel(fuel).ok();

        store
    }

    /// Instantiate a compiled [`Component`] in a fresh store.
    ///
    /// Returns `(Store, Instance)` ready for function calls.
    pub fn instantiate(
        &self,
        app_name: &str,
        master_key: [u8; AEAD_KEY_SIZE],
        fuel: u64,
        component: &Component,
    ) -> Result<(Store<AppContext>, wasmtime::component::Instance), String> {
        let mut store = self.new_store(app_name, master_key, fuel);
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

    /// Discover exported functions with **full WIT type information**.
    ///
    /// Unlike [`discover_exports()`](Self::discover_exports) which only
    /// returns counts, this method extracts the complete type signature
    /// for every parameter and return value.  The result is an
    /// [`AppSchema`](crate::protocol::AppSchema) suitable for serving
    /// via `wasm_schema` and generating MCP tool manifests.
    ///
    /// If `wasm_bytes` is provided, the `package-docs` custom section
    /// is parsed and `///` doc comments are attached to functions and
    /// parameters in the schema.
    pub fn discover_exports_typed(
        &self,
        app_name: &str,
        hostname: &str,
        component: &Component,
        wasm_bytes: Option<&[u8]>,
    ) -> crate::protocol::AppSchema {
        use wasmtime::component::types::ComponentItem;

        let docs = wasm_bytes
            .map(parse_package_docs)
            .unwrap_or_default();

        let ty = component.component_type();
        let mut functions = Vec::new();
        let mut interfaces = Vec::new();

        for (name, item) in ty.exports(&self.engine) {
            match item {
                ComponentItem::ComponentFunc(func_ty) => {
                    functions.push(func_type_to_schema(&name, &func_ty, &docs));
                }
                ComponentItem::ComponentInstance(inst_ty) => {
                    let mut iface_fns = Vec::new();
                    for (func_name, nested) in inst_ty.exports(&self.engine) {
                        if let ComponentItem::ComponentFunc(func_ty) = nested {
                            iface_fns.push(func_type_to_schema(&func_name, &func_ty, &docs));
                        }
                    }
                    if !iface_fns.is_empty() {
                        interfaces.push(crate::protocol::InterfaceSchema {
                            name: name.to_string(),
                            functions: iface_fns,
                            description: docs.get(&format!("interface:{}", name)).cloned(),
                        });
                    }
                }
                _ => {}
            }
        }

        crate::protocol::AppSchema {
            name: app_name.to_string(),
            hostname: hostname.to_string(),
            functions,
            interfaces,
            mcp_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
//  WIT type conversion helpers
// ---------------------------------------------------------------------------

/// Convert a wasmtime [`ComponentFunc`] type to a [`FunctionSchema`].
///
/// The `docs` map is consulted for `///` doc comments extracted from
/// the `package-docs` custom section. Keys use the convention:
/// - `"func:<name>"` for function-level descriptions
/// - `"param:<func>.<param>"` for parameter descriptions
fn func_type_to_schema(
    name: &str,
    func_ty: &wasmtime::component::types::ComponentFunc,
    docs: &BTreeMap<String, String>,
) -> crate::protocol::FunctionSchema {
    let params = func_ty.params()
        .map(|(pname, ty)| {
            let desc = docs.get(&format!("param:{}.{}", name, pname)).cloned();
            crate::protocol::ParamSchema {
                name: pname.to_string(),
                ty: wit_type_from(&ty),
                description: desc,
            }
        })
        .collect();
    let results = func_ty.results()
        .enumerate()
        .map(|(i, ty)| crate::protocol::ParamSchema {
            name: format!("ret{}", i),
            ty: wit_type_from(&ty),
            description: None,
        })
        .collect();
    crate::protocol::FunctionSchema {
        name: name.to_string(),
        params,
        results,
        description: docs.get(&format!("func:{}", name)).cloned(),
    }
}

/// Convert a wasmtime Component Model [`Type`] to a serialisable [`WitType`].
fn wit_type_from(ty: &wasmtime::component::types::Type) -> crate::protocol::WitType {
    use wasmtime::component::types::Type;
    use crate::protocol::WitType;

    match ty {
        Type::Bool => WitType::Bool,
        Type::S8 => WitType::S8,
        Type::U8 => WitType::U8,
        Type::S16 => WitType::S16,
        Type::U16 => WitType::U16,
        Type::S32 => WitType::S32,
        Type::U32 => WitType::U32,
        Type::S64 => WitType::S64,
        Type::U64 => WitType::U64,
        Type::Float32 => WitType::Float32,
        Type::Float64 => WitType::Float64,
        Type::Char => WitType::Char,
        Type::String => WitType::String,
        Type::List(l) => WitType::List {
            element: Box::new(wit_type_from(&l.ty())),
        },
        Type::Record(r) => WitType::Record {
            fields: r.fields()
                .map(|f| crate::protocol::FieldSchema {
                    name: f.name.to_string(),
                    ty: wit_type_from(&f.ty),
                })
                .collect(),
        },
        Type::Tuple(t) => WitType::Tuple {
            elements: t.types().map(|ty| wit_type_from(&ty)).collect(),
        },
        Type::Variant(v) => WitType::Variant {
            cases: v.cases()
                .map(|c| crate::protocol::CaseSchema {
                    name: c.name.to_string(),
                    ty: c.ty.map(|t| wit_type_from(&t)),
                })
                .collect(),
        },
        Type::Enum(e) => WitType::Enum {
            names: e.names().map(|n| n.to_string()).collect(),
        },
        Type::Option(o) => WitType::Option {
            inner: Box::new(wit_type_from(&o.ty())),
        },
        Type::Result(r) => WitType::Result {
            ok: r.ok().map(|t| Box::new(wit_type_from(&t))),
            err: r.err().map(|t| Box::new(wit_type_from(&t))),
        },
        Type::Flags(f) => WitType::Flags {
            names: f.names().map(|n| n.to_string()).collect(),
        },
        // Resources — not yet supported in the wire protocol.
        _ => WitType::String,
    }
}

// ---------------------------------------------------------------------------
//  package-docs custom section parser
// ---------------------------------------------------------------------------

/// Parse the `package-docs` WASM custom section into a documentation map.
///
/// The custom section contains a JSON object mapping item paths to their
/// `///` doc comments from the WIT source.  This function walks the raw
/// WASM binary looking for the custom section, then normalises the keys
/// into the conventions used by [`func_type_to_schema()`]:
///
/// - `"func:<name>"` — function-level description
/// - `"param:<func>.<param>"` — parameter description
/// - `"interface:<name>"` — interface-level description
///
/// Returns an empty map if the section is missing or unparseable.
fn parse_package_docs(wasm_bytes: &[u8]) -> BTreeMap<String, String> {
    let mut docs = BTreeMap::new();

    // Walk the WASM binary to find custom sections.
    // A WASM binary starts with the 8-byte header (\0asm + version).
    if wasm_bytes.len() < 8 {
        return docs;
    }
    let mut pos = 8; // skip header

    while pos < wasm_bytes.len() {
        if pos >= wasm_bytes.len() {
            break;
        }
        let section_id = wasm_bytes[pos];
        pos += 1;

        // Read section size (LEB128).
        let (section_size, bytes_read) = match read_leb128(&wasm_bytes[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += bytes_read;

        if section_id == 0 {
            // Custom section — read the name.
            let section_start = pos;
            let (name_len, name_leb_bytes) = match read_leb128(&wasm_bytes[pos..]) {
                Some(v) => v,
                None => { pos += section_size; continue; }
            };
            let name_start = pos + name_leb_bytes;
            let name_end = name_start + name_len;
            if name_end > wasm_bytes.len() {
                break;
            }
            if let Ok(name) = core::str::from_utf8(&wasm_bytes[name_start..name_end]) {
                if name == "package-docs" {
                    let payload_start = name_end;
                    let payload_end = section_start + section_size;
                    if payload_end <= wasm_bytes.len() {
                        let payload = &wasm_bytes[payload_start..payload_end];
                        if let Ok(map) = serde_json::from_slice::<serde_json::Value>(payload) {
                            normalise_package_docs(&map, &mut docs);
                        }
                    }
                    // Found the section — no need to continue.
                    return docs;
                }
            }
        }

        pos += section_size;
    }

    docs
}

/// Read a LEB128-encoded unsigned integer. Returns `(value, bytes_consumed)`.
fn read_leb128(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow protection.
        }
    }
    None
}

/// Normalise a `package-docs` JSON object into the keying convention
/// used by the schema builder.
///
/// The JSON from `package-docs` uses paths like:
/// - `"worlds/my-app/funcs/hello"` → function doc
/// - `"worlds/my-app/interfaces/my-api"` → interface doc
/// - `"interfaces/my-api/funcs/hello"` → interface function doc
///
/// We also accept the simpler flat format:
/// - `"hello"` → function doc
/// - `"hello.name"` → parameter doc
fn normalise_package_docs(
    val: &serde_json::Value,
    docs: &mut BTreeMap<String, String>,
) {
    let obj = match val.as_object() {
        Some(o) => o,
        None => return,
    };

    for (key, value) in obj {
        let desc = match value.as_str() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // WIT path format: worlds/<world>/funcs/<func>
        if key.contains("/funcs/") {
            let func_name = key.rsplit("/funcs/").next().unwrap_or(key);
            docs.insert(format!("func:{}", func_name), desc.to_string());
        } else if key.contains("/interfaces/") {
            let iface_name = key.rsplit("/interfaces/").next().unwrap_or(key);
            docs.insert(format!("interface:{}", iface_name), desc.to_string());
        } else if key.contains('.') {
            // Flat format: func.param
            docs.insert(format!("param:{}", key), desc.to_string());
        } else {
            // Flat format: just a function name
            docs.insert(format!("func:{}", key), desc.to_string());
        }
    }
}
