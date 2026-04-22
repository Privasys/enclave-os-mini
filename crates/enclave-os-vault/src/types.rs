// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault wire protocol, policy schema and persisted records.
//!
//! The vault speaks JSON inside [`Request::Data`]/[`Response::Data`].
//! The schema is HSM/vHSM-shaped: callers manipulate **keys** (with
//! handles, types, and operation policies), not opaque "secrets".
//!
//! See `docs/vault.md` for the full design.

use std::string::String;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
//  TTL constants
// ---------------------------------------------------------------------------

/// Maximum key TTL: 3 months (90 days).
pub const MAX_KEY_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Default key TTL: 1 month (30 days).
pub const DEFAULT_KEY_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
//  Wire protocol
// ---------------------------------------------------------------------------

/// A vault RPC request, JSON-encoded inside `Request::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Create a new key with caller-supplied material.
    ///
    /// The caller's OIDC identity must match `policy.principals.owner`.
    /// The handle must not already exist.
    CreateKey {
        handle: String,
        key_type: KeyType,
        /// Base64url-encoded raw key material (sealed at rest).
        material_b64: String,
        /// Whether the material may ever leave the enclave (gates `ExportKey`).
        exportable: bool,
        policy: KeyPolicy,
    },

    /// Export the raw key material.
    ///
    /// Allowed only if `exportable == true` and an `OperationRule` grants
    /// the caller [`Operation::ExportKey`].
    ExportKey { handle: String },

    /// Delete a key and its policy.
    ///
    /// Gated by an `OperationRule` granting the caller [`Operation::DeleteKey`].
    DeleteKey { handle: String },

    /// Replace the policy on an existing key.
    ///
    /// Each changed top-level field must be allowed by `policy.mutability`
    /// for the caller's role (owner / manager). Immutable fields cannot
    /// change.
    UpdatePolicy { handle: String, new_policy: KeyPolicy },

    /// Read the policy for a key (metadata only).
    ///
    /// Allowed for any principal listed in the key's `PrincipalSet`.
    GetPolicy { handle: String },

    /// Read key metadata. Never returns the key material.
    /// Same access rules as `GetPolicy`.
    GetKeyInfo { handle: String },

    /// List handles owned by the caller (OIDC).
    ListKeys,
}

/// A vault RPC response, JSON-encoded inside `Response::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultResponse {
    KeyCreated { handle: String, expires_at: u64 },
    KeyMaterial { material: Vec<u8>, expires_at: u64 },
    KeyDeleted,
    PolicyUpdated { policy_version: u32 },
    Policy { policy: KeyPolicy, policy_version: u32 },
    KeyInfo(KeyInfo),
    KeyList { keys: Vec<KeyListEntry> },
    Error(String),
}

/// Public-only metadata for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub handle: String,
    pub key_type: KeyType,
    pub exportable: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy_version: u32,
}

/// Entry returned by `VaultRequest::ListKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyListEntry {
    pub handle: String,
    pub key_type: KeyType,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
//  Key types
// ---------------------------------------------------------------------------

/// What kind of key material this handle holds.
///
/// Phase 1 only stores `RawShare` (a Shamir share of an external secret),
/// matching what the vault was used for previously. Other variants
/// (symmetric KEKs, asymmetric signing keys, BIP32 seeds) are reserved
/// in the schema and will be implemented when their operations land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// One Shamir share of an external secret. Reconstructed client-side.
    RawShare,
}

// ---------------------------------------------------------------------------
//  Operations
// ---------------------------------------------------------------------------

/// Per-key operations that can be granted by an `OperationRule`.
///
/// Management operations on the namespace (`CreateKey`, `ListKeys`) are
/// not policy-gated and have no variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    ExportKey,
    DeleteKey,
    UpdatePolicy,
}

// ---------------------------------------------------------------------------
//  Principals
// ---------------------------------------------------------------------------

/// An identity that can act on a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Principal {
    /// An OIDC subject from a specific issuer.
    ///
    /// `required_roles` is matched against the resolved roles in the
    /// caller's verified bearer token. Empty means any role is fine.
    Oidc {
        issuer: String,
        sub: String,
        #[serde(default)]
        required_roles: Vec<String>,
    },

    /// A remote TEE that authenticates via mutual RA-TLS.
    ///
    /// Bidirectional challenge-response is always required (it is the
    /// only safe mode); there is no flag for it.
    Tee(AttestationProfile),
}

/// A reference into a `PrincipalSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalRef {
    Owner,
    Manager(u32),
    Auditor(u32),
    Tee(u32),
    /// Any tee in `principals.tees` that authenticates successfully.
    AnyTee,
}

/// Named identities for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalSet {
    /// The single creator/owner. Required.
    pub owner: Principal,
    /// Optional approvers / policy mutators (governance, not runtime).
    #[serde(default)]
    pub managers: Vec<Principal>,
    /// Optional read-only principals (metadata + future audit log).
    #[serde(default)]
    pub auditors: Vec<Principal>,
    /// Remote TEE clients allowed to act on this key at runtime.
    #[serde(default)]
    pub tees: Vec<Principal>,
}

// ---------------------------------------------------------------------------
//  Attestation
// ---------------------------------------------------------------------------

/// What measurements / claims a remote TEE quote must satisfy to match
/// a `Principal::Tee`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationProfile {
    /// Human-readable label, e.g. `"app:v3 / SGX"`.
    pub name: String,

    /// Acceptable measurements. The quote's measurement must equal one
    /// of these (TEE type implied by the variant).
    pub measurements: Vec<Measurement>,

    /// Attestation servers that may verify the quote. The vault calls
    /// each in turn; first success wins.
    pub attestation_servers: Vec<AttestationServer>,

    /// Required X.509 OID extensions on the peer certificate. Each entry
    /// must be present with the exact value.
    #[serde(default)]
    pub required_oids: Vec<OidRequirement>,
}

/// A measurement value that identifies a specific enclave build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Measurement {
    /// SGX MRENCLAVE, hex-encoded (lowercase, 64 chars).
    Mrenclave(String),
    /// TDX MRTD, hex-encoded (lowercase, 96 chars).
    Mrtd(String),
}

/// An attestation server endpoint, optionally pinned by SPKI hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationServer {
    pub url: String,
    #[serde(default)]
    pub pinned_spki_sha256_hex: Option<String>,
}

/// A required X.509 OID extension on the peer certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidRequirement {
    pub oid: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
//  Operation rules
// ---------------------------------------------------------------------------

/// Grants a set of operations to a set of principals.
///
/// A request is allowed iff there exists at least one rule whose `ops`
/// includes the requested op AND whose `principals` references the
/// caller's resolved principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRule {
    pub ops: Vec<Operation>,
    pub principals: Vec<PrincipalRef>,
}

// ---------------------------------------------------------------------------
//  Lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lifecycle {
    /// Capped at [`MAX_KEY_TTL_SECONDS`]. Zero means default.
    #[serde(default)]
    pub ttl_seconds: u64,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle { ttl_seconds: DEFAULT_KEY_TTL_SECONDS }
    }
}

// ---------------------------------------------------------------------------
//  Mutability
// ---------------------------------------------------------------------------

/// Top-level fields of a `KeyPolicy` that can change via `UpdatePolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyField {
    Owner,
    Managers,
    Auditors,
    Tees,
    Operations,
    Lifecycle,
    Mutability,
}

/// Who is allowed to change which fields on `UpdatePolicy`.
///
/// Defaults are intentionally conservative: only the owner can change
/// runtime-shape fields (managers/auditors/tees/operations/lifecycle);
/// the owner field itself and the mutability rules are immutable;
/// managers can change nothing. Adopters loosen this explicitly when
/// they want to e.g. let a manager add a new TEE for an enclave upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutability {
    #[serde(default)]
    pub owner_can: Vec<PolicyField>,
    #[serde(default)]
    pub manager_can: Vec<PolicyField>,
    #[serde(default)]
    pub immutable: Vec<PolicyField>,
}

impl Default for Mutability {
    fn default() -> Self {
        Mutability {
            owner_can: vec![
                PolicyField::Managers,
                PolicyField::Auditors,
                PolicyField::Tees,
                PolicyField::Operations,
                PolicyField::Lifecycle,
            ],
            manager_can: Vec::new(),
            immutable: vec![PolicyField::Owner, PolicyField::Mutability],
        }
    }
}

// ---------------------------------------------------------------------------
//  KeyPolicy
// ---------------------------------------------------------------------------

/// The full access policy attached to a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Schema version; currently 1.
    pub version: u32,
    pub principals: PrincipalSet,
    pub operations: Vec<OperationRule>,
    #[serde(default)]
    pub mutability: Mutability,
    #[serde(default)]
    pub lifecycle: Lifecycle,
}

// ---------------------------------------------------------------------------
//  Persisted record
// ---------------------------------------------------------------------------

/// What the vault stores in the sealed KV at `key:<handle>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub handle: String,
    pub key_type: KeyType,
    pub exportable: bool,
    /// Sealed by the kvstore layer at rest; in plaintext in this struct
    /// only while it lives in enclave memory.
    pub material: Vec<u8>,
    pub policy: KeyPolicy,
    pub policy_version: u32,
    pub created_at: u64,
    pub expires_at: u64,
}
