// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Build script for the app crate.
//!
//! Minimal: just propagates SGX SDK paths.
//! The heavy lifting (EDL stubs, sysroot) is done by the enclave dep's
//! build.rs and the CMake build system.

fn main() {
    let sgx_sdk = std::env::var("SGX_SDK_PATH")
        .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    println!("cargo:rustc-link-search=native={}/lib64", sgx_sdk);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wasm/wasm_test_app.wasm");
}
