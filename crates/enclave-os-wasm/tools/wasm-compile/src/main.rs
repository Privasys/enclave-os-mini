// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! AOT compiler for WASM components targeting Enclave OS.
//!
//! This tool pre-compiles a WASM Component (`.wasm`) into a native
//! code artefact (`.cwasm`) that can be loaded inside the SGX enclave
//! via `Component::deserialize`.
//!
//! # Why AOT?
//!
//! Cranelift JIT compilation inside SGX is impractical:
//!   - SGX2 EDMM page operations are orders of magnitude slower
//!     than normal `mmap`/`mprotect`.
//!   - Debug builds of Cranelift are especially slow.
//!   - Even release builds take 20+ minutes for a small component.
//!
//! AOT compilation runs on the host (outside the enclave) at full
//! speed, then the enclave simply deserializes the pre-compiled
//! native code — essentially a fast `memcpy` + relocation fixup.
//!
//! # Important
//!
//! The **wasmtime version** and **Engine configuration** in this tool
//! MUST exactly match what the enclave uses.  If they diverge, the
//! enclave will reject the `.cwasm` with a version mismatch error.
//!
//! # Usage
//!
//! ```bash
//! enclave-os-wasm-compile input.wasm -o output.cwasm
//! ```

use clap::Parser;
use std::path::PathBuf;
use wasmtime::{Config, Engine};
use wasmtime::component::Component;

#[derive(Parser)]
#[command(name = "enclave-os-wasm-compile")]
#[command(about = "AOT-compile a WASM Component for Enclave OS")]
struct Cli {
    /// Path to the input `.wasm` Component file.
    input: PathBuf,

    /// Path for the output `.cwasm` (pre-compiled) file.
    /// Defaults to `<input>.cwasm`.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Exact enabled `wasmparser::WasmFeatures` bits for the pinned wasmtime.
///
/// Recording the full bitset catches newly enabled proposal defaults at the
/// compatibility boundary: a wasmtime pin bump that silently turns on a new
/// proposal changes execution semantics and would otherwise ship unnoticed.
/// On mismatch, review the new default set against `build_engine_config`
/// (and the runtime `WasmEngine::new()`), then re-freeze this constant as a
/// deliberate decision.
const WASM_FEATURE_BITS: u64 = 0x0000_000c_010b_fcff;

/// Fail closed if the pinned wasmtime's enabled-proposal set drifted.
fn verify_frozen_features(engine: &Engine) -> Result<(), String> {
    let bits = engine.get_wasm_features().bits();
    if bits != WASM_FEATURE_BITS {
        return Err(format!(
            "wasmtime enabled-proposal set drifted: got {:#018x}, frozen {:#018x} — \
             review the new defaults and re-freeze WASM_FEATURE_BITS deliberately",
            bits, WASM_FEATURE_BITS
        ));
    }
    Ok(())
}

/// Build the wasmtime Engine configuration.
///
/// **This MUST stay in sync with `WasmEngine::new()` in
/// `crates/enclave-os-wasm/src/engine.rs`.**
///
/// Any mismatch will cause `Component::deserialize` inside the
/// enclave to fail with a configuration error.
fn build_engine_config() -> Config {
    let mut config = Config::new();

    // ── Core settings ──────────────────────────────────────────
    config.wasm_component_model(true);
    config.wasm_multi_memory(true);
    config.wasm_simd(true);

    // Pinned proposal set + SGX codegen — MUST match engine.rs.
    config.wasm_gc(true);
    config.wasm_function_references(true);
    config.wasm_exceptions(true);
    config.native_unwind_info(false);
    config.signals_based_traps(false);
    // Must match the enclave engine: fuel metering is compiled into
    // the generated code, so a cwasm built without it cannot load.
    config.consume_fuel(true);

    // ── SGX-appropriate limits ─────────────────────────────────
    config.memory_reservation(4 * 1024 * 1024);
    config.memory_guard_size(64 * 1024);

    // ── No CoW / no disk-backed images ─────────────────────────
    config.memory_init_cow(false);

    // ── Optimization level ─────────────────────────────────────
    // Use Speed for AOT — compilation time is not a concern on the
    // host, and the generated code runs faster inside the enclave.
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);

    config
}

fn main() {
    let cli = Cli::parse();

    // Determine output path
    let output = cli.output.unwrap_or_else(|| {
        let mut out = cli.input.clone();
        out.set_extension("cwasm");
        out
    });

    // Read input WASM
    let wasm_bytes = std::fs::read(&cli.input).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", cli.input.display(), e);
        std::process::exit(1);
    });
    eprintln!(
        "Input : {} ({} bytes)",
        cli.input.display(),
        wasm_bytes.len()
    );

    // Create engine with matching config
    let config = build_engine_config();
    let engine = Engine::new(&config).unwrap_or_else(|e| {
        eprintln!("error: engine creation failed: {}", e);
        std::process::exit(1);
    });
    if let Err(e) = verify_frozen_features(&engine) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }

    // AOT compile
    eprintln!("Compiling...");
    let cwasm = engine.precompile_component(&wasm_bytes).unwrap_or_else(|e| {
        eprintln!("error: compilation failed: {}", e);
        std::process::exit(1);
    });

    // Verify round-trip (optional sanity check)
    unsafe {
        Component::deserialize(&engine, &cwasm).unwrap_or_else(|e| {
            eprintln!("error: deserialize sanity check failed: {}", e);
            std::process::exit(1);
        });
    }

    // Write output
    std::fs::write(&output, &cwasm).unwrap_or_else(|e| {
        eprintln!("error: cannot write '{}': {}", output.display(), e);
        std::process::exit(1);
    });

    eprintln!(
        "Output: {} ({} bytes)",
        output.display(),
        cwasm.len()
    );
    eprintln!("Done.");
}

#[cfg(test)]
mod tests {
    use super::{build_engine_config, verify_frozen_features};

    #[test]
    fn enabled_proposal_set_stays_frozen() {
        let mut config = build_engine_config();
        // Explicit AOT target: the production artefact targets Linux/SGX and
        // this keeps the test host-independent (Windows hosts reject
        // `native_unwind_info(false)` for native engines).
        config.target("x86_64-unknown-linux-gnu").expect("target");
        let engine = super::Engine::new(&config).expect("engine");
        if let Err(e) = verify_frozen_features(&engine) {
            panic!("{e}");
        }
    }
}
