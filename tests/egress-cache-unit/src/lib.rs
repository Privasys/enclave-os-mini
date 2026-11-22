// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lightweight test proxy for `enclave-os-egress/src/ttl_cache.rs` (the
//! bounded expiring map behind the JWKS discovery and failure caches).
//!
//! The egress crate cannot be compiled outside SGX (sgx_types), so this
//! crate includes `ttl_cache.rs` via `#[path]`; its `#[cfg(test)]` module
//! then runs with `cargo test -p egress-cache-unit`.

#[allow(dead_code)]
#[path = "../../../crates/enclave-os-egress/src/ttl_cache.rs"]
mod ttl_cache;
