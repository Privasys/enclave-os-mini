// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Example: Enclave OS with WASM runtime.
//!
//! This crate provides a custom `ecall_run` that registers the WASM
//! runtime module alongside the built-in HelloWorld module. WASM apps
//! are loaded dynamically at runtime over the RA-TLS wire protocol.
//!
//! ## How to use
//!
//! 1. Build this crate as the enclave staticlib (instead of the default
//!    `enclave-os-enclave`).
//! 2. Link into `enclave.so` via CMake as usual.
//! 3. At runtime, clients connect over RA-TLS and send `wasm_load`
//!    commands to deploy WASM apps.
//!
//! ## Wire protocol
//!
//! ```json
//! {"wasm_load": {"name": "my-app", "bytes": [0, 97, 115, 109, ...]}}
//! {"wasm_call": {"app": "my-app", "function": "hello", "params": []}}
//! {"wasm_list": {}}
//! {"wasm_unload": {"name": "my-app"}}
//! ```

use enclave_os_enclave::ecall::{init_enclave, finalize_and_run};
use enclave_os_enclave::modules::register_module;
use enclave_os_enclave::{enclave_log_info, enclave_log_error};

#[no_mangle]
pub extern "C" fn ecall_run(config_json: *const u8, config_len: u64) -> i32 {
    // Phase 1: init enclave (config, CPUID cache, crypto self-test, sealed config)
    let (config, sealed_cfg) = match init_enclave(config_json, config_len) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Phase 2a: register the HelloWorld diagnostic module (built-in)
    register_module(Box::new(
        enclave_os_enclave::modules::helloworld::HelloWorldModule,
    ));

    // Phase 2b: register the WASM runtime (dynamic loading over RA-TLS)
    match enclave_os_wasm::WasmModule::new(sealed_cfg.master_key()) {
        Ok(wasm) => {
            enclave_log_info!("WASM runtime initialised (dynamic loading enabled)");
            register_module(Box::new(wasm));
        }
        Err(e) => {
            enclave_log_error!("Failed to init WasmModule: {}", e);
            return -31;
        }
    }

    enclave_log_info!("All modules registered (HelloWorld + WASM runtime)");

    // Phase 3: seal config, build Merkle tree, start RA-TLS server, event loop
    finalize_and_run(&config, &sealed_cfg)
}

// Re-export symbols that must be visible in the final staticlib.
pub use enclave_os_enclave::ecall::ecall_init_channel;
pub use enclave_os_enclave::ecall::ecall_shutdown;
