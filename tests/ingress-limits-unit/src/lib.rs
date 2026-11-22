// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lightweight test proxy for the ingress server's pure bounds:
//! `enclave/src/sni_limits.rs` (hostname normalisation and the per-name TLS
//! caches) and `enclave/src/read_budget.rs` (the shared budget for
//! buffered request bytes).
//!
//! The enclave crate cannot be compiled outside SGX, so this crate includes
//! the files via `#[path]`; their `#[cfg(test)]` modules then run with
//! `cargo test -p ingress-limits-unit`.

#[allow(dead_code)]
#[path = "../../../enclave/src/sni_limits.rs"]
mod sni_limits;

#[allow(dead_code)]
#[path = "../../../enclave/src/read_budget.rs"]
mod read_budget;
