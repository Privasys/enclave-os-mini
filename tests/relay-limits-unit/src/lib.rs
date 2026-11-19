// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lightweight test proxy for the session relay's pure parts:
//! `enclave/src/sealed_envelope.rs` (the sealed body decoder) and
//! `enclave/src/relay_limits.rs` (the session cap and the rebind table).
//!
//! The enclave crate cannot be compiled outside SGX, so this crate includes
//! both files via `#[path]`; their `#[cfg(test)]` modules then run with
//! `cargo test -p relay-limits-unit`.

#[allow(dead_code)]
#[path = "../../../enclave/src/sealed_envelope.rs"]
mod sealed_envelope;

#[allow(dead_code)]
#[path = "../../../enclave/src/relay_limits.rs"]
mod relay_limits;
