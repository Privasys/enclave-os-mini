// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host test proxy for `enclave-os-wasm/src/code_pool.rs`.
//!
//! The WASM crate cannot be compiled outside SGX (transitive sgx_types dep),
//! so this crate includes `code_pool.rs` via `#[path]`. The `#[cfg(test)]`
//! module inside the file then runs with `cargo test -p code-pool-unit`.

#[allow(dead_code)]
#[path = "../../../crates/enclave-os-wasm/src/code_pool.rs"]
pub mod code_pool;
