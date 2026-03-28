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

/// Runtime Version Hash — `1.3.6.1.4.1.65230.2.4`
///
/// 32-byte SHA-256 hash of the runtime version string.  In enclave-os-mini
/// this covers the Wasmtime engine version; in enclave-os-virtual it covers
/// the containerd version.  Reserved for future use in Mini.
///
/// Aligned with enclave-os-virtual OID 2.4 (Runtime Version Hash).
pub const RUNTIME_VERSION_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 4];
/// Runtime Version Hash (dotted-string).
pub const RUNTIME_VERSION_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.4";

/// Combined Workloads Hash — `1.3.6.1.4.1.65230.2.5`
///
/// 32-byte SHA-256 hash of all workload code hashes (sorted by name,
/// concatenated).  In enclave-os-mini this covers WASM app bytecode;
/// in enclave-os-virtual it covers OCI container image digests.
///
/// Aligned with enclave-os-virtual OID 2.5 (Combined Workloads Hash).
pub const COMBINED_WORKLOADS_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 5];
/// Combined Workloads Hash (dotted-string).
pub const COMBINED_WORKLOADS_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.5";

/// Attestation Servers Hash — `1.3.6.1.4.1.65230.2.7`
///
/// 32-byte SHA-256 hash of the canonical attestation server URL list
/// trusted by the enclave for remote attestation verification.  The hash
/// is computed over the sorted, newline-joined URL strings.
///
/// Aligned with enclave-os-virtual OID 2.7 (Attestation Servers Hash).
pub const ATTESTATION_SERVERS_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 7];
/// Attestation Servers Hash (dotted-string).
pub const ATTESTATION_SERVERS_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.7";

// ---- Backward-compatible aliases ----------------------------------------

/// Alias for [`COMBINED_WORKLOADS_HASH_OID`] (was `WASM_APPS_HASH_OID`
/// at `2.3`; now lives at `2.5`).
pub const WASM_APPS_HASH_OID: &[u64] = COMBINED_WORKLOADS_HASH_OID;
/// Alias for [`COMBINED_WORKLOADS_HASH_OID_STR`].
pub const WASM_APPS_HASH_OID_STR: &str = COMBINED_WORKLOADS_HASH_OID_STR;

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

/// Per-app Key Source — `1.3.6.1.4.1.65230.3.4`
///
/// UTF-8 string indicating the encryption key provenance for a WASM app:
/// `"generated"` for enclave-generated keys (RDRAND), or
/// `"byok:<fingerprint>"` where `<fingerprint>` is the hex SHA-256 of
/// the raw key bytes, allowing attesters to verify which specific key
/// is in use without revealing the key itself.
///
/// Aligned with enclave-os-virtual's OID 3.4 (Container Volume Encryption).
pub const APP_KEY_SOURCE_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 4];
/// Per-app Key Source (dotted-string).
pub const APP_KEY_SOURCE_OID_STR: &str = "1.3.6.1.4.1.65230.3.4";

/// Per-app Configuration Hash — `1.3.6.1.4.1.65230.3.5`
///
/// 32-byte SHA-256 hash of the app's configuration metadata: auth
/// policy (derived from WIT `@auth` annotations), MCP settings, and
/// any future WIT-derived configuration.  Allows attesters to verify
/// which configuration is active for the app without needing the full
/// manifest.
///
/// Shared across enclave-os-mini (WASM apps) and enclave-os-virtual
/// (container configuration).
pub const APP_CONFIGURATION_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 5];
/// Per-app Configuration Hash (dotted-string).
pub const APP_CONFIGURATION_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.3.5";
