// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault wire protocol, policy schema and persisted records.
//!
//! The vault speaks JSON inside [`Request::Data`]/[`Response::Data`].
//! The schema is HSM/vHSM-shaped: callers manipulate **keys** (with
//! handles, types, usage flags and operation policies), not opaque
//! "secrets". See `docs/vault.md` for the design.

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

/// Maximum lifetime of an [`ApprovalToken`] (1 hour).
pub const MAX_APPROVAL_TOKEN_TTL_SECONDS: u64 = 60 * 60;

/// Default lifetime of an [`ApprovalToken`] when caller asks for the
/// default (5 minutes).
pub const DEFAULT_APPROVAL_TOKEN_TTL_SECONDS: u64 = 5 * 60;

// ---------------------------------------------------------------------------
//  Wire protocol
// ---------------------------------------------------------------------------

/// A vault RPC request, JSON-encoded inside `Request::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    // --- Key management ---------------------------------------------------
    /// Create a new key with caller-supplied material.
    ///
    /// The caller's OIDC identity must match `policy.principals.owner`.
    /// `material_b64` interpretation depends on `key_type`:
    /// * `RawShare`            â€” opaque bytes (a Shamir share).
    /// * `Aes256GcmKey`        â€” 32 bytes of AES-256 key material.
    /// * `HmacSha256Key`       â€” 32â€“64 bytes of HMAC key material.
    /// * `P256SigningKey`      â€” PKCS#8 v1 ECDSA-P256 private key DER.
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
    ExportKey {
        handle: String,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// Delete a key and its policy.
    DeleteKey {
        handle: String,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// Replace the policy on an existing key.
    UpdatePolicy {
        handle: String,
        new_policy: KeyPolicy,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// Read the policy for a key (metadata only).
    GetPolicy { handle: String },

    /// Read key metadata. Never returns key material.
    GetKeyInfo { handle: String },

    /// List handles owned by the caller (OIDC).
    ListKeys,

    // --- In-enclave crypto ops -------------------------------------------
    /// AES-256-GCM encrypt with a `KeyType::Aes256GcmKey`.
    ///
    /// `iv_b64` must be exactly 12 bytes; if absent the vault generates
    /// one. The response always echoes the IV used.
    Wrap {
        handle: String,
        plaintext_b64: String,
        #[serde(default)]
        aad_b64: Option<String>,
        #[serde(default)]
        iv_b64: Option<String>,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// AES-256-GCM decrypt with a `KeyType::Aes256GcmKey`.
    Unwrap {
        handle: String,
        ciphertext_b64: String,
        iv_b64: String,
        #[serde(default)]
        aad_b64: Option<String>,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// ECDSA-P256-SHA256 sign with a `KeyType::P256SigningKey`.
    /// Returns IEEE-P1363 fixed-length 64-byte signature.
    Sign {
        handle: String,
        message_b64: String,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// HMAC-SHA-256 with a `KeyType::HmacSha256Key`.
    Mac {
        handle: String,
        message_b64: String,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    // --- Approvals --------------------------------------------------------
    /// Issue an [`ApprovalToken`] from the caller (must be one of
    /// `policy.principals.managers`) for a specific operation. The token
    /// can then be carried inside subsequent requests to satisfy
    /// [`Condition::ManagerApproval`].
    IssueApprovalToken {
        handle: String,
        op: Operation,
        /// Requested TTL in seconds; capped at
        /// [`MAX_APPROVAL_TOKEN_TTL_SECONDS`]. Zero means default
        /// ([`DEFAULT_APPROVAL_TOKEN_TTL_SECONDS`]).
        #[serde(default)]
        ttl_seconds: u64,
    },

    // --- Audit ------------------------------------------------------------
    /// Read the audit log for a key. Auditors and the owner may call.
    ReadAuditLog {
        handle: String,
        /// Only entries with `seq > since_seq` are returned. Use 0 for all.
        #[serde(default)]
        since_seq: u64,
        /// Hard cap on number of returned entries (default 256).
        #[serde(default)]
        limit: u32,
    },

    // --- Pending attestation profiles (enclave upgrade flow) -------------
    /// Stage a new `AttestationProfile` as `pending`. Owner-only by
    /// default; managers may stage if `mutability.manager_can` includes
    /// [`PolicyField::PendingProfiles`].
    StagePendingProfile {
        handle: String,
        profile: AttestationProfile,
        source: PendingProfileSource,
    },

    /// List currently-pending attestation profiles for a key.
    ListPendingProfiles { handle: String },

    /// Promote a pending profile into `policy.principals.tees`.
    /// Subject to the same `Mutability` rules as `UpdatePolicy` for
    /// [`PolicyField::Tees`] (so will normally need manager approvals).
    PromotePendingProfile {
        handle: String,
        pending_id: u32,
        #[serde(default)]
        approvals: Vec<ApprovalToken>,
    },

    /// Drop a pending profile without promoting it.
    RevokePendingProfile { handle: String, pending_id: u32 },
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

    Wrapped {
        ciphertext: Vec<u8>,
        iv: Vec<u8>,
    },
    Unwrapped {
        plaintext: Vec<u8>,
    },
    Signature {
        signature: Vec<u8>,
        alg: &'static str,
    },
    MacTag {
        mac: Vec<u8>,
        alg: &'static str,
    },

    ApprovalTokenIssued(ApprovalToken),

    AuditLog {
        entries: Vec<AuditEntry>,
        next_seq: u64,
    },

    PendingProfileStaged {
        pending_id: u32,
    },
    PendingProfileList {
        pending: Vec<PendingProfile>,
    },
    PendingProfilePromoted {
        policy_version: u32,
    },
    PendingProfileRevoked,

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
    /// Public part for asymmetric keys (raw EC point for P-256), absent
    /// for symmetric keys.
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
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
/// Each variant maps 1:1 to the operations it supports â€” see
/// [`Operation`] and the `Wrap`/`Sign`/`Mac` RPCs in [`VaultRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// One Shamir share of an external secret. Reconstructed client-side
    /// after a successful `ExportKey`.
    RawShare,
    /// AES-256-GCM symmetric KEK / DEK. Supports `Wrap`/`Unwrap`.
    Aes256GcmKey,
    /// ECDSA-P256-SHA256 signing key (PKCS#8 v1 sealed). Supports `Sign`.
    P256SigningKey,
    /// HMAC-SHA-256 key. Supports `Mac`.
    HmacSha256Key,
}

// ---------------------------------------------------------------------------
//  Operations
// ---------------------------------------------------------------------------

/// Per-key operations that can be granted by an [`OperationRule`].
///
/// Namespace operations (`CreateKey`, `ListKeys`, `IssueApprovalToken`,
/// `ReadAuditLog`, `StagePendingProfile`, `ListPendingProfiles`,
/// `RevokePendingProfile`) are not policy-gated and have no variant
/// here â€” they have their own auth rules baked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    ExportKey,
    DeleteKey,
    UpdatePolicy,
    Wrap,
    Unwrap,
    Sign,
    Mac,
    /// Granted via [`VaultRequest::PromotePendingProfile`].
    PromoteProfile,
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

    /// A FIDO2 credential previously registered via `enclave-os-fido2`.
    ///
    /// **Phase 3 status:** the variant is part of the schema and
    /// [`evaluate_op`](crate::policy::evaluate_op) will reject calls
    /// that try to authenticate as one until the wallet relay path is
    /// wired up. Policies may already be authored against it.
    Fido2 {
        rp_id: String,
        credential_id_b64: String,
    },

    /// A remote TEE that authenticates via mutual RA-TLS.
    ///
    /// Bidirectional challenge-response is always required (it is the
    /// only safe mode); there is no flag for it.
    Tee(AttestationProfile),
}

/// A reference into a [`PrincipalSet`].
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
    /// Optional read-only principals (metadata + audit log).
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

    /// Attestation servers that may verify the quote.
    pub attestation_servers: Vec<AttestationServer>,

    /// Required X.509 OID extensions on the peer certificate.
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
//  Operation rules + Conditions
// ---------------------------------------------------------------------------

/// Grants a set of operations to a set of principals, optionally subject
/// to additional conditions.
///
/// A request is allowed iff there exists at least one rule whose `ops`
/// includes the requested op AND whose `principals` contains the
/// caller's resolved principal AND every condition in `requires`
/// evaluates true.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationRule {
    pub ops: Vec<Operation>,
    pub principals: Vec<PrincipalRef>,
    /// Additional conjunctive conditions that must all hold. Empty
    /// means no extra conditions.
    #[serde(default)]
    pub requires: Vec<Condition>,
}

/// Extra access-time conditions on an [`OperationRule`].
///
/// All conditions in a rule's `requires` list are AND-ed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Condition {
    /// The caller's RA-TLS peer certificate must satisfy the named
    /// attestation profile (in addition to whatever principal match
    /// already happened).
    AttestationMatches(AttestationProfile),

    /// The request must carry a valid [`ApprovalToken`] issued for
    /// `manager` (an index into `principals.managers`) for this op.
    /// `fresh_for_seconds` bounds the maximum age of the token at
    /// verification time.
    ManagerApproval {
        manager: u32,
        fresh_for_seconds: u64,
    },

    /// The current time must lie inside `[not_before, not_after]`. Use
    /// 0 for an unbounded side.
    TimeWindow {
        #[serde(default)]
        not_before: u64,
        #[serde(default)]
        not_after: u64,
    },
}

// ---------------------------------------------------------------------------
//  Approval tokens
// ---------------------------------------------------------------------------

/// A signed approval blob issued by [`VaultRequest::IssueApprovalToken`].
///
/// On the wire this is just the JWT string. The vault that verifies it
/// is the same vault that issued it (single-vault deployment) or is
/// configured with the same vault signing key (constellation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalToken {
    pub jwt: String,
}

/// Claims inside an approval-token JWT (ES256, signed by the vault).
///
/// Public for tests / out-of-process verifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalClaims {
    /// Issuer fixed to `"enclave-os-vault"`.
    pub iss: String,
    /// Key handle this approval applies to.
    pub handle: String,
    /// Operation the approval is for.
    pub op: Operation,
    /// Index into `principals.managers` of the issuing manager.
    pub manager: u32,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expires at (unix seconds).
    pub exp: u64,
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
        Lifecycle {
            ttl_seconds: DEFAULT_KEY_TTL_SECONDS,
        }
    }
}

// ---------------------------------------------------------------------------
//  Mutability
// ---------------------------------------------------------------------------

/// Top-level fields of a `KeyPolicy` (and of the surrounding `KeyRecord`)
/// that can change via `UpdatePolicy` or other mutating RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyField {
    Owner,
    Managers,
    Auditors,
    Tees,
    Operations,
    Lifecycle,
    Mutability,
    /// The list of staged-but-not-yet-promoted attestation profiles.
    /// Controls who may call `StagePendingProfile`.
    PendingProfiles,
}

/// Who is allowed to change which fields on `UpdatePolicy`.
///
/// Defaults are intentionally conservative: the owner can change runtime-
/// shape fields (managers/auditors/tees/operations/lifecycle); the owner
/// field itself and the mutability rules are immutable; managers can
/// change nothing. Adopters loosen this explicitly when they want to
/// e.g. let a manager add a new TEE for an enclave upgrade.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
                PolicyField::PendingProfiles,
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
//  Pending attestation profiles (enclave upgrade flow)
// ---------------------------------------------------------------------------

/// How a [`PendingProfile`] entered the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingProfileSource {
    /// Staged by the platform's build pipeline (e.g. management-service
    /// after a successful WASM/enclave build that produced a new
    /// MRENCLAVE).
    PlatformBuild,
    /// Staged by a human operator from a CLI / portal manual import.
    ManualImport,
}

/// An attestation profile staged for a key but not yet promoted into
/// `policy.principals.tees`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingProfile {
    pub id: u32,
    pub profile: AttestationProfile,
    pub source: PendingProfileSource,
    pub staged_at: u64,
    pub staged_by_sub: String,
}

// ---------------------------------------------------------------------------
//  Audit log
// ---------------------------------------------------------------------------

/// Outcome of an audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditDecision {
    Allowed,
    Denied,
}

/// One entry in the per-key audit log. Stored sealed under
/// `audit:<handle>:<seq>` in the KV store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub op: String,
    pub caller: String,
    pub decision: AuditDecision,
    /// Short reason / error string for denied or noteworthy events.
    #[serde(default)]
    pub reason: String,
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
    /// only while it lives in enclave memory. Interpretation depends on
    /// `key_type` (see [`VaultRequest::CreateKey`]).
    pub material: Vec<u8>,
    /// Public part for asymmetric key types, derived at create time.
    /// `None` for symmetric / opaque keys.
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
    pub policy: KeyPolicy,
    pub policy_version: u32,
    pub created_at: u64,
    pub expires_at: u64,
    /// Pending attestation profiles staged but not yet promoted into
    /// `policy.principals.tees`.
    #[serde(default)]
    pub pending_profiles: Vec<PendingProfile>,
    /// Monotonic counter for audit log entries on this key.
    #[serde(default)]
    pub audit_next_seq: u64,
    /// Monotonic counter for [`PendingProfile::id`] allocation.
    #[serde(default)]
    pub next_pending_id: u32,
}
