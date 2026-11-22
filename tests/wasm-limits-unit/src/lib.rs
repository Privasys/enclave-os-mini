// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lightweight test proxy for `enclave-os-wasm/src/limits.rs` (metric names,
//! call parameter limits, the `@auth` annotation and the roles claim).
//!
//! The WASM crate cannot be compiled outside SGX (transitive sgx_types dep),
//! so this crate includes `limits.rs` via `#[path]`; its `#[cfg(test)]`
//! module then runs with `cargo test -p wasm-limits-unit`.

#[allow(dead_code)]
#[path = "../../../crates/enclave-os-wasm/src/limits.rs"]
mod limits;
