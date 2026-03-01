// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! AOT pre-compiler for WASM components targeting the enclave-os WASM runtime.
//!
//! Usage:
//!     wasm-precompile <input.wasm> [output.cwasm]
//!
//! If `output` is omitted the tool writes `<input>.cwasm` (compiled WASM).
//!
//! The resulting `.cwasm` file contains native x86-64 code that the enclave
//! loads with `Component::deserialize()` — no Cranelift compiler needed at
//! runtime, which saves ~8 MB of enclave footprint.
//!
//! **Important**: the `Config` used here MUST exactly match the `Config` in
//! `crates/enclave-os-wasm/src/engine.rs`.  If they diverge, deserialisation
//! inside the enclave will fail.

use std::env;
use std::fs;
use std::process;

use wasmtime::{Config, Engine};

/// Build the same wasmtime `Config` the enclave uses.
///
/// Keep this in sync with `WasmEngine::new()` in
/// `crates/enclave-os-wasm/src/engine.rs`.
fn enclave_compatible_config() -> Config {
    let mut config = Config::new();

    // ── Core settings ──────────────────────────────────────────
    config.wasm_component_model(true);
    config.wasm_multi_memory(true);
    config.wasm_simd(true);

    // ── SGX-appropriate limits ─────────────────────────────────
    config.memory_reservation(4 * 1024 * 1024);
    config.memory_guard_size(64 * 1024);

    // ── No CoW / no disk-backed images ─────────────────────────
    config.memory_init_cow(false);

    config
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: wasm-precompile <input.wasm> [output.cwasm]");
        process::exit(1);
    }

    let input_path = &args[1];
    let output_path = if args.len() == 3 {
        args[2].clone()
    } else {
        format!("{}.cwasm", input_path.trim_end_matches(".wasm"))
    };

    // Read the raw WASM component
    let wasm_bytes = fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("Error reading '{}': {}", input_path, e);
        process::exit(1);
    });

    eprintln!(
        "Input:  {} ({} bytes)",
        input_path,
        wasm_bytes.len()
    );

    // Create engine with enclave-matching config
    let config = enclave_compatible_config();
    let engine = Engine::new(&config).unwrap_or_else(|e| {
        eprintln!("Engine creation failed: {}", e);
        process::exit(1);
    });

    // AOT-compile the component
    let precompiled = engine.precompile_component(&wasm_bytes).unwrap_or_else(|e| {
        eprintln!("Precompilation failed: {}", e);
        process::exit(1);
    });

    eprintln!(
        "Output: {} ({} bytes)",
        output_path,
        precompiled.len()
    );

    // Write the precompiled artifact
    fs::write(&output_path, &precompiled).unwrap_or_else(|e| {
        eprintln!("Error writing '{}': {}", output_path, e);
        process::exit(1);
    });

    eprintln!("Done — AOT compilation successful.");
}
