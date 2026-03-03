// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-specific attestation helpers.
//!
//! Core quote parsing primitives (`TeeType`, `QuoteIdentity`,
//! `parse_quote`, `extract_report_data`, `hex_encode`, `hex_decode`, …)
//! live in [`enclave_os_common::quote`] and are re-exported here for
//! backward compatibility.
//!
//! This module adds **policy evaluation** (`is_permitted`) which
//! is vault-specific logic (whitelist matching).

use std::string::String;

// Re-export shared primitives so existing `crate::quote::*` paths keep working.
pub use enclave_os_common::quote::{
    TeeType, QuoteIdentity,
    parse_quote, extract_report_data,
    hex_encode, hex_decode,
};

// ---------------------------------------------------------------------------
//  Policy evaluation
// ---------------------------------------------------------------------------

/// Check whether a parsed quote identity is permitted by the given policy.
///
/// A policy permits access if the quote's measurement appears in the
/// corresponding whitelist (`allowed_mrenclave` for SGX, `allowed_mrtd`
/// for TDX).  Empty whitelists deny all access for that TEE type.
pub fn is_permitted(
    identity: &QuoteIdentity,
    allowed_mrenclave: &[String],
    allowed_mrtd: &[String],
) -> bool {
    match identity.tee {
        TeeType::Sgx => allowed_mrenclave.iter().any(|m| m == &identity.measurement),
        TeeType::Tdx => allowed_mrtd.iter().any(|m| m == &identity.measurement),
    }
}
