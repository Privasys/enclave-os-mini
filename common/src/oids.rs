// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! X.509 extension OID constants of RA-TLS certificates: the Privasys OID
//! scheme v2, generated from `ra-tls-clients/oids.json` (its `docs/oids.md`
//! is the reference), with the same numbering on Enclave OS Virtual.
//!
//! Centralised here so that every crate (enclave, egress, WASM, vault, tests)
//! imports from the same source of truth. Each OID comes in two forms:
//!
//! | Suffix | Type | Consumer |
//! |--------|------|----------|
//! | *(none)* | `&[u64]` | `rcgen::CustomExtension::from_oid_content()` |
//! | `_STR` | `&str` | `x509_parser` OID string comparison |
//!
//! Scheme v2 under `1.3.6.1.4.1.65230`: platform arcs 1 to 3 mirrored by
//! workload arcs 4 to 6, then trust relationships. Attestation evidence (the
//! SGX quote) is not a certificate extension in v2: it is served after the
//! handshake (`POST /__privasys/attest`). The Intel quote OIDs stay defined so
//! a v1 leaf can be recognised and rejected.

// =========================================================================
//  Intel attestation quote OIDs (v1 certificate extensions, never emitted in v2)
// =========================================================================

/// SGX DCAP Quote — `1.2.840.113741.1.13.1.0`
pub const SGX_QUOTE_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 0];
/// SGX DCAP Quote (dotted-string).
pub const SGX_QUOTE_OID_STR: &str = "1.2.840.113741.1.13.1.0";

/// TDX DCAP Quote — `1.2.840.113741.1.5.5.1.6`
pub const TDX_QUOTE_OID: &[u64] = &[1, 2, 840, 113741, 1, 5, 5, 1, 6];
/// TDX DCAP Quote (dotted-string).
pub const TDX_QUOTE_OID_STR: &str = "1.2.840.113741.1.5.5.1.6";

/// The Privasys arc, with a trailing dot (dotted-string prefix).
pub const PRIVASYS_ARC_PREFIX_STR: &str = "1.3.6.1.4.1.65230.";

// =========================================================================
//  Arc 1, platform identity
// =========================================================================

/// Runtime Version Hash — `1.3.6.1.4.1.65230.1.1`: 32-byte SHA-256 of the
/// runtime version (Wasmtime on Mini, containerd on Virtual).
pub const RUNTIME_VERSION_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 1, 1];
/// Runtime Version Hash (dotted-string).
pub const RUNTIME_VERSION_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.1.1";

/// Image Profile — `1.3.6.1.4.1.65230.1.2`: UTF-8 `"production"` or `"dev"`.
pub const IMAGE_PROFILE_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 1, 2];
/// Image Profile (dotted-string).
pub const IMAGE_PROFILE_OID_STR: &str = "1.3.6.1.4.1.65230.1.2";

/// Enclave Instance ID — `1.3.6.1.4.1.65230.1.3`: the management-service
/// `enclave_id` (raw 16-byte UUID) received at registration.
pub const ENCLAVE_INSTANCE_ID_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 1, 3];
/// Enclave Instance ID (dotted-string).
pub const ENCLAVE_INSTANCE_ID_OID_STR: &str = "1.3.6.1.4.1.65230.1.3";

// =========================================================================
//  Arc 2, platform configuration
// =========================================================================

/// Config Merkle Root — `1.3.6.1.4.1.65230.2.1`: 32-byte SHA-256 root
/// covering all operator-chosen configuration inputs (egress CA bundle, WASM
/// app hashes, ...).
pub const CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 1];
/// Config Merkle Root (dotted-string).
pub const CONFIG_MERKLE_ROOT_OID_STR: &str = "1.3.6.1.4.1.65230.2.1";

/// Egress CA Bundle Hash — `1.3.6.1.4.1.65230.2.2`: 32-byte SHA-256 of the
/// PEM CA bundle the enclave trusts for outbound HTTPS.
pub const EGRESS_CA_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 2];
/// Egress CA Bundle Hash (dotted-string).
pub const EGRESS_CA_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.2";

/// Attestation Servers Hash — `1.3.6.1.4.1.65230.2.3`: 32-byte SHA-256 of
/// the sorted, newline-joined attestation server URL list.
pub const ATTESTATION_SERVERS_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 3];
/// Attestation Servers Hash (dotted-string).
pub const ATTESTATION_SERVERS_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.3";

/// Combined Workloads Hash — `1.3.6.1.4.1.65230.2.4`: 32-byte SHA-256 of all
/// workload code hashes (sorted by name, concatenated): WASM app bytecode on
/// Mini, container image digests on Virtual.
pub const COMBINED_WORKLOADS_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 2, 4];
/// Combined Workloads Hash (dotted-string).
pub const COMBINED_WORKLOADS_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.2.4";

// =========================================================================
//  Arc 3, platform keys and state
// =========================================================================

/// Data Encryption Key Origin — `1.3.6.1.4.1.65230.3.1` (Virtual).
pub const DEK_ORIGIN_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 1];
/// Data Encryption Key Origin (dotted-string).
pub const DEK_ORIGIN_OID_STR: &str = "1.3.6.1.4.1.65230.3.1";

/// Authenticated State Root — `1.3.6.1.4.1.65230.3.2`: 40 bytes, the 32-byte
/// root of the authenticated KV store (`enclave-os-merkle`) followed by the
/// u64 BE commit version. Recomputed at certificate generation.
pub const MERKLE_STATE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 3, 2];
/// Authenticated State Root (dotted-string).
pub const MERKLE_STATE_ROOT_OID_STR: &str = "1.3.6.1.4.1.65230.3.2";

// =========================================================================
//  Arc 4, workload identity
// =========================================================================

/// Workload App ID — `1.3.6.1.4.1.65230.4.1`: the platform-assigned app
/// identity (apps.id, raw 16-byte UUID). Stamped by the measured enclave, so a
/// peer cannot forge another app's id (MR_APP sealing mode).
pub const APP_ID_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 4, 1];
/// Workload App ID (dotted-string).
pub const APP_ID_OID_STR: &str = "1.3.6.1.4.1.65230.4.1";

/// Workload Code Digest — `1.3.6.1.4.1.65230.4.2`: 32-byte SHA-256 of the
/// app's code (WASM component bytecode).
pub const APP_CODE_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 4, 2];
/// Workload Code Digest (dotted-string).
pub const APP_CODE_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.4.2";

/// Workload Image Ref — `1.3.6.1.4.1.65230.4.3` (Virtual).
pub const APP_IMAGE_REF_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 4, 3];
/// Workload Image Ref (dotted-string).
pub const APP_IMAGE_REF_OID_STR: &str = "1.3.6.1.4.1.65230.4.3";

// =========================================================================
//  Arc 5, workload configuration
// =========================================================================

/// Workload Config Merkle Root — `1.3.6.1.4.1.65230.5.1`: 32-byte SHA-256
/// root over the configuration entries declared by one app.
pub const APP_CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 5, 1];
/// Workload Config Merkle Root (dotted-string).
pub const APP_CONFIG_MERKLE_ROOT_OID_STR: &str = "1.3.6.1.4.1.65230.5.1";

/// Workload Configuration Hash — `1.3.6.1.4.1.65230.5.2`: 32-byte SHA-256 of
/// the app's configuration metadata (auth policy derived from WIT `@auth`
/// annotations, MCP settings, ...).
pub const APP_CONFIGURATION_HASH_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 5, 2];
/// Workload Configuration Hash (dotted-string).
pub const APP_CONFIGURATION_HASH_OID_STR: &str = "1.3.6.1.4.1.65230.5.2";

/// App-defined extensions root — `1.3.6.1.4.1.65230.5.4`. Apps install values
/// at `5.4.{n}` through the SDK `set-attestation-extension(arc-suffix, value)`
/// call; the root itself never carries a value.
pub const APP_EXTENSION_ARC_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 5, 4];
/// App-defined extensions prefix (dotted-string, trailing dot).
pub const APP_EXTENSION_ARC_PREFIX_STR: &str = "1.3.6.1.4.1.65230.5.4.";

// =========================================================================
//  Arc 6, workload keys and state
// =========================================================================

/// Workload Key Source — `1.3.6.1.4.1.65230.6.1`: UTF-8 `"generated"`
/// (enclave-generated, RDRAND) or `"byok:<fingerprint>"` (hex SHA-256 of the
/// raw key bytes).
pub const APP_KEY_SOURCE_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 6, 1];
/// Workload Key Source (dotted-string).
pub const APP_KEY_SOURCE_OID_STR: &str = "1.3.6.1.4.1.65230.6.1";

// =========================================================================
//  Arc 7, trust relationships
// =========================================================================

/// Attested Dependency Set — `1.3.6.1.4.1.65230.7.1`: the set of DIRECT
/// cross-enclave dependency identities this workload is pinned to, in the
/// canonical dependency-set encoding. Runtime-owned; an app cannot install,
/// alter or remove it.
pub const ATTESTED_DEPENDENCY_SET_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 7, 1];
/// Attested Dependency Set (dotted-string).
pub const ATTESTED_DEPENDENCY_SET_OID_STR: &str = "1.3.6.1.4.1.65230.7.1";
