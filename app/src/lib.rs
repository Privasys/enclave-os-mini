// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave OS application entry point.
//!
//! This crate provides a custom `ecall_run` that loads the wasm-test-app
//! (and any future WASM apps) alongside the built-in HelloWorld module.
//!
//! ## Architecture
//!
//! ```text
//!   enclave-os-app (this crate — staticlib)
//!       ├── enclave-os-enclave (core: init, TLS server, event loop)
//!       └── enclave-os-wasm   (WASM Component runtime + WASI host)
//! ```
//!
//! The CMake build links this crate (instead of `enclave-os-enclave`
//! directly) into `enclave.so`.

use enclave_os_enclave::ecall::{init_enclave, finalize_and_run};
use enclave_os_enclave::modules::register_module;
use enclave_os_enclave::{enclave_log_info, enclave_log_error};

// ── WASM app bytecode (compiled into the enclave image) ───────────
//
// Each WASM app is baked into the binary via include_bytes!.
// The SHA-256 of these bytes is automatically included in the
// RA-TLS certificate for remote attestation.
const WASM_TEST_APP: &[u8] = include_bytes!("../wasm/wasm_test_app.wasm");

// ── ECall entry point ─────────────────────────────────────────────

/// Enclave entry point: initialise subsystems, register modules, run.
///
/// This replaces the default `ecall_run` from enclave-os-enclave.
/// It registers:
///   1. HelloWorld (built-in diagnostic module)
///   2. WasmModule with the test app loaded
#[no_mangle]
pub extern "C" fn ecall_run(config_json: *const u8, config_len: u64) -> i32 {
    // Phase 1: init enclave (parse config, CPUID cache, crypto self-test,
    //          resolve sealed config with master key + CA cert)
    let (config, sealed_cfg) = match init_enclave(config_json, config_len) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Phase 2a: register the HelloWorld diagnostic module
    register_module(Box::new(
        enclave_os_enclave::modules::helloworld::HelloWorldModule,
    ));

    // Phase 2b: register the WASM runtime with test app
    match enclave_os_wasm::WasmModule::new(sealed_cfg.master_key()) {
        Ok(wasm) => {
            match wasm.load_app("test-app", WASM_TEST_APP) {
                Ok(()) => {
                    enclave_log_info!(
                        "WASM app 'test-app' loaded ({} bytes)",
                        WASM_TEST_APP.len()
                    );
                }
                Err(e) => {
                    enclave_log_error!("Failed to load WASM test-app: {}", e);
                    return -30;
                }
            }
            register_module(Box::new(wasm));
        }
        Err(e) => {
            enclave_log_error!("Failed to init WasmModule: {}", e);
            return -31;
        }
    }

    enclave_log_info!("All modules registered (HelloWorld + WASM test-app)");

    // Phase 3: seal config, build Merkle tree, start RA-TLS server, event loop
    finalize_and_run(&config, &sealed_cfg)
}

// ── Re-export ecall_init_channel and ecall_shutdown ───────────────
//
// These are defined in enclave-os-enclave and need to be visible in
// the final staticlib. Re-exporting forces the linker to include them.

pub use enclave_os_enclave::ecall::ecall_init_channel;
pub use enclave_os_enclave::ecall::ecall_shutdown;
