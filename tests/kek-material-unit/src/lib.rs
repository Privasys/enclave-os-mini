// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lightweight test proxy for `enclave-os-wasm/src/kek_material.rs`.
//!
//! The WASM crate cannot be compiled outside SGX (transitive sgx_types dep),
//! so this crate includes `kek_material.rs` via `#[path]` and re-exports it.
//! The `#[cfg(test)]` module inside the file then runs normally with
//! `cargo test -p kek-material-unit`.

#[allow(unused_imports, dead_code)]
#[path = "../../../crates/enclave-os-wasm/src/kek_material.rs"]
mod kek_material;
