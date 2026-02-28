// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! X.509 extension OID constants for RA-TLS certificates.
//!
//! Centralised here so that every crate (enclave, egress, WASM, tests, …)
//! imports from the same source of truth.
//!
//! Each OID is provided in **two forms**:
//!
//! | Suffix | Type | Consumer |
//! |--------|------|----------|
//! | *(none)* | `&[u64]` | `rcgen::CustomExtension::from_oid_content()` |
//! | `_STR` | `&str` | `x509_parser` OID string comparison |

// =========================================================================
//  Intel attestation quote OIDs
// =========================================================================

/// SGX DCAP Quote — `1.2.840.113741.1.13.1.0`
pub const SGX_QUOTE_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 0];
/// SGX DCAP Quote (dotted-string).
pub const SGX_QUOTE_OID_STR: &str = "1.2.840.113741.1.13.1.0";

/// TDX DCAP Quote — `1.2.840.113741.1.5.5.1.6`
pub const TDX_QUOTE_OID: &[u64] = &[1, 2, 840, 113741, 1, 5, 5, 1, 6];
/// TDX DCAP Quote (dotted-string).
pub const TDX_QUOTE_OID_STR: &str = "1.2.840.113741.1.5.5.1.6";

// =========================================================================
//  Privasys configuration OIDs
// =========================================================================

/// Config Merkle Root — `1.3.6.1.4.1.65230.1.1`
///
/// 32-byte SHA-256 hash covering all operator-chosen configuration inputs
/// (egress CA bundle, WASM app hashes, etc.).
pub const CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 1, 1];
/// Config Merkle Root (dotted-string).
pub const CONFIG_MERKLE_ROOT_OID_STR: &str = "1.3.6.1.4.1.65230.1.1";

/// Egress CA Bundle Hash — `1.3.6.1.4.1.65230.2.1`
///
/// 32-byte SHA-256 hash of the PEM-encoded CA bundle the enclave trusts
/// for outbound HTTPS.
pub const EGRESS_CA_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 1];
/// Egress CA Bundle Hash (dotted-string).
pub const EGRESS_CA_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.1";

/// WASM Apps Combined Code Hash — `1.3.6.1.4.1.65230.2.3`
///
/// 32-byte SHA-256 hash of the combined WASM application code loaded in
/// the enclave.
pub const WASM_APPS_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 3];
/// WASM Apps Combined Code Hash (dotted-string).
pub const WASM_APPS_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.3";

// =========================================================================
//  Per-app certificate OIDs
// =========================================================================

/// Per-app Config Merkle Root — `1.3.6.1.4.1.65230.3.1`
///
/// 32-byte SHA-256 hash covering the configuration entries declared by
/// a single app. Each app gets its own cert with its own Merkle root.
pub const APP_CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 1];
/// Per-app Config Merkle Root (dotted-string).
pub const APP_CONFIG_MERKLE_ROOT_OID_STR: &str = "1.3.6.1.4.1.65230.3.1";

/// Per-app Code Hash — `1.3.6.1.4.1.65230.3.2`
///
/// 32-byte SHA-256 hash of the app's code (e.g. WASM component bytecode).
/// Embedded directly in the app's leaf certificate for fast-path
/// verification without recomputing the per-app Merkle tree.
pub const APP_CODE_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 2];
/// Per-app Code Hash (dotted-string).
pub const APP_CODE_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.3.2";
