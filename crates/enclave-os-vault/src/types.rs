// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault wire protocol, policy schema and persisted records.
//!
//! The vault speaks JSON inside [`Request::Data`]/[`Response::Data`].
//! The schema is HSM/vHSM-shaped: callers manipulate **keys** (with
//! handles, types, usage flags and operation policies), not opaque
//! "secrets". See `docs/vault.md` for the design.

use std::collections::BTreeMap;
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
    // --- Key management ---------------------------------------------------
    /// Create a key with caller-supplied material, authorised by a `grant`.
    ///
    /// `grant` is an IdP-issued JWT (`aud = privasys-vault-keycreate`) carrying
    /// the owner (`sub`), `scope`, `key_type`, `exportable` and `policy`. The
    /// caller (an app TEE or CLI agent) authenticates by mutual RA-TLS and
    /// supplies only the handle + material. `material_b64` matches the grant's
    /// `key_type`:
    /// * `RawShare`            — opaque bytes (a Shamir share).
    /// * `Aes256GcmKey`        — 32 bytes of AES-256 key material.
    /// * `HmacSha256Key`       — 32â€“64 bytes of HMAC key material.
    /// * `P256SigningKey`      — PKCS#8 v1 ECDSA-P256 private key DER.
    ///
    /// The vault verifies the grant, binds it to the caller (attested app-id at
    /// OID 3.6 == grant scope, or holder-of-key `cnf`), then stores the key with
    /// the granted `key_type` / `exportable` / `policy` and `owner = grant.sub`.
    /// (See the key-creation-grant design.)
    CreateKey {
        handle: String,
        /// Base64url-encoded raw key material (sealed at rest).
        material_b64: String,
        /// IdP-issued grant (JWT) carrying owner, scope, key_type, exportable
        /// and policy.
        grant: String,
        /// Renewal in place (wire formats §9): the handle of the key this one
        /// succeeds, on this vault. The vault copies its policy, version and
        /// key check value, and ignores the grant's policy.
        #[serde(default)]
        predecessor: Option<String>,
        /// Renewal onto another constellation, or rotation (wire formats §9): the
        /// key's current policy, read fresh from the source vault by the app
        /// and carried verbatim. Takes the place of the grant's policy.
        #[serde(default)]
        policy: Option<Box<serde_json::value::RawValue>>,
        /// The carried policy's version at the source.
        #[serde(default)]
        policy_version: Option<u32>,
        /// The source vault's billing id: a carried policy is accepted only
        /// from a vault under this vault's billing configuration.
        #[serde(default)]
        source_billing_id: Option<String>,
        /// The key check value of the whole key (wire formats §10.4), stored
        /// opaquely and never returned.
        #[serde(default)]
        key_check: Option<KeyCheck>,
        /// With a carried policy: the source key's `exportable` and
        /// `key_type` (from its `GetKeyInfo`). A carried create must keep
        /// them; the vault refuses a grant that says otherwise.
        #[serde(default)]
        carried_exportable: Option<bool>,
        #[serde(default)]
        carried_key_type: Option<KeyType>,
        /// Binding v2 fields of the owner's `create` approval (formats
        /// §9.3.1), required for a handle whose last segment is
        /// `new-<digits>`. The approval itself is the bearer.
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },

    /// Export the raw key material.
    ///
    /// Allowed only if `exportable == true` and an `OperationRule` grants
    /// the caller [`Operation::ExportKey`].
    ExportKey {
        handle: String,
        /// Binding v2 fields, for a key whose step-up takes `binding: 2`.
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },

    /// Delete a key and its policy.
    DeleteKey {
        handle: String,
        /// Binding v2 fields, for a key whose step-up takes `binding: 2`.
        #[serde(default)]
        binding: Option<BindingV2Request>,
        /// The old key of a migration or upgrade (wire formats §9.2): the delete
        /// is bound to its successor and refused until the successor, where
        /// this vault can see it, has succeeded.
        #[serde(default)]
        after: Option<DeleteAfter>,
    },

    /// Delete the previous generation after an automatic renewal (formats
    /// §9.1), by an enclave the key's policy names, with no approval.
    RetireKey {
        handle: String,
        successor: String,
        successor_members: Vec<String>,
    },

    /// Replace the policy on an existing key. `new_policy` is kept as sent:
    /// a v2 approval binds the digest of exactly this JSON (wire formats §5.1).
    UpdatePolicy {
        handle: String,
        new_policy: Box<serde_json::value::RawValue>,
        /// Binding v2 fields, for a key whose step-up takes `binding: 2`.
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },

    /// This vault's identity (wire formats §1): member id, billing id and a quote
    /// binding them. Unauthenticated.
    GetVaultIdentity,

    /// Check a policy against wire formats §5.1 and return its digest, storing
    /// nothing. Unauthenticated.
    CanonicalisePolicy {
        policy: Box<serde_json::value::RawValue>,
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
    /// The vault always generates the IV and echoes it in the response.
    ///
    /// `iv_b64` is REJECTED. It is retained on the wire only so that a client
    /// still sending one gets an explicit error instead of a silently
    /// different ciphertext. A caller-chosen nonce lets one key wrap many
    /// plaintexts under a repeated nonce, and GCM nonce reuse is a break
    /// rather than a degradation: it leaks the XOR of the plaintexts and the
    /// GHASH authentication key, after which forgery is possible. Because
    /// Wrap and Unwrap are separately grantable operations, that turns
    /// wrap-only access into decrypt-and-forge access.
    Wrap {
        handle: String,
        plaintext_b64: String,
        #[serde(default)]
        aad_b64: Option<String>,
        #[serde(default)]
        iv_b64: Option<String>,
    },

    /// AES-256-GCM decrypt with a `KeyType::Aes256GcmKey`.
    Unwrap {
        handle: String,
        ciphertext_b64: String,
        iv_b64: String,
        #[serde(default)]
        aad_b64: Option<String>,
    },

    /// ECDSA-P256 sign with a `KeyType::P256SigningKey`. Returns an IEEE-P1363
    /// fixed-length 64-byte signature. By default the vault hashes the message
    /// (ECDSA-P256-SHA256); when `prehashed` is set, `message_b64` is a 32-byte
    /// SHA-256 digest that is signed directly (raw ECDSA, no re-hash) — what
    /// PKCS#11 `CKM_ECDSA` and TLS stacks send.
    Sign {
        handle: String,
        message_b64: String,
        #[serde(default)]
        prehashed: bool,
    },

    /// HMAC-SHA-256 with a `KeyType::HmacSha256Key`.
    Mac {
        handle: String,
        message_b64: String,
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
    /// [`PolicyField::PendingProfiles`]. The PLATFORM (a manager-role
    /// bearer that matches no key principal) may also stage — staging is
    /// a proposal and authorises nothing — unless `PendingProfiles` is
    /// immutable on the key. If the key opted into
    /// `lifecycle.auto_migrate_to_next_attestation_profile` and the
    /// platform-staged profile is a runtime-only delta of an accepted
    /// profile, it is promoted immediately (see [`Lifecycle`]).
    StagePendingProfile {
        handle: String,
        profile: AttestationProfile,
    },

    /// List currently-pending attestation profiles for a key.
    ListPendingProfiles { handle: String },

    /// Promote a pending profile into `policy.principals.tees`.
    /// Subject to the same `Mutability` rules as `UpdatePolicy` for
    /// [`PolicyField::Tees`] (so will normally need manager approvals).
    PromotePendingProfile {
        handle: String,
        pending_id: u32,
        /// Binding v2 fields, for a key whose step-up takes `binding: 2`.
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },

    /// Drop a pending profile without promoting it.
    RevokePendingProfile { handle: String, pending_id: u32 },

    // --- Threshold keys (FROST Ed25519) -----------------------------------
    //
    // A threshold key (`KeyType::FrostEd25519`) is created by distributed key
    // generation and used by `t` of its vaults together. The CLIENT drives
    // the rounds, calling each vault directly with its own credentials and
    // relaying opaque messages between them; the vaults never call each
    // other. Bytes go as base64url (no padding). See `crate::threshold`.
    /// DKG round 1, on each participant. `vaults` lists the participants'
    /// endpoints (participant `i` at `vaults[i - 1]`); `index` is this vault's.
    /// `grant` is a key-creation grant for `key_type = FrostEd25519`,
    /// `exportable = false`, bound to the caller as for `CreateKey`.
    FrostDkgRound1 {
        session: String,
        handle: String,
        grant: String,
        index: u16,
        threshold: u16,
        vaults: Vec<String>,
        /// The owner's `create` approval, for a `new-<digits>` handle (as
        /// `CreateKey`).
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },
    /// DKG round 2: every participant's round 1 message (by index).
    FrostDkgRound2 {
        session: String,
        handle: String,
        round1: BTreeMap<u16, FrostRound1Message>,
    },
    /// DKG round 3: the sealed round 2 packages sent to this vault (by sender).
    FrostDkgRound3 {
        session: String,
        handle: String,
        packages_b64: BTreeMap<u16, String>,
    },
    /// DKG commit: the other participants' confirmations for this vault (by
    /// sender). The vault stores its share once all of them check out.
    FrostDkgCommit {
        session: String,
        handle: String,
        confirmations_b64: BTreeMap<u16, String>,
    },
    /// Abort a DKG. With `handle`, also remove the key this session
    /// committed here while it is still pending (wire formats §9.3.1): same
    /// session, same caller, never once it has served an operation.
    FrostDkgAbort {
        session: String,
        #[serde(default)]
        handle: Option<String>,
    },
    /// Signing round 1: authorised like `Sign` (the key's policy, with
    /// `approvals`); returns this vault's commitment.
    FrostSignRound1 {
        session: String,
        handle: String,
        message_b64: String,
    },
    /// Signing round 2: every signer's round 1 commitment (by index); returns
    /// this vault's signature share for the message round 1 was given.
    FrostSignRound2 {
        session: String,
        handle: String,
        commitments_b64: BTreeMap<u16, String>,
    },
    FrostSignAbort { session: String },
    /// Combine the signers' shares into the Ed25519 signature, verified under
    /// the group key. Public data; any participant answers its principals.
    FrostAggregate {
        handle: String,
        message_b64: String,
        commitments_b64: BTreeMap<u16, String>,
        shares_b64: BTreeMap<u16, String>,
    },

    // --- Resharing a threshold key (same group key, new shares) ----------
    //
    // Renewal, and moving a key to another constellation, as `secrets renew`
    // does for a Shamir secret: the client drives it, the old vaults (the
    // helpers) deal only to the owner with a fresh wallet step-up naming
    // exactly where the key goes. See `crate::threshold`.
    /// Round 1 on each NEW participant (`index` of `vaults`): a creation
    /// grant for the handle, the old key's public key package and the
    /// helpers (old participant indices). The handle may already hold the
    /// old key on this vault (renewal in place).
    FrostReshareTarget1 {
        session: String,
        handle: String,
        grant: String,
        index: u16,
        threshold: u16,
        vaults: Vec<String>,
        helpers: Vec<u16>,
        old_public_key_package_b64: String,
        /// The owner's `create` approval, for a `new-<digits>` handle new
        /// on this vault (as `CreateKey`).
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },
    /// On each helper: deal this vault's share to the new participants, whose
    /// quotes must carry `target_mrenclave`. The bearer must be the key's
    /// owner with a fresh step-up (operation `reshare`) whose measurement slot
    /// is the hex resharing context.
    FrostReshareDeal {
        session: String,
        handle: String,
        helpers: Vec<u16>,
        threshold: u16,
        vaults: Vec<String>,
        target_mrenclave: String,
        targets: BTreeMap<u16, FrostTargetMessage>,
        /// Binding v2 members of the owner's `reshare` approval (formats §5).
        #[serde(default)]
        binding: Option<BindingV2Request>,
    },
    /// Round 2 on each new participant: every new participant's first message
    /// and every helper's deal for this vault.
    FrostReshareTarget2 {
        session: String,
        handle: String,
        targets: BTreeMap<u16, FrostTargetMessage>,
        deals: BTreeMap<u16, FrostDealMessage>,
    },
    /// Store the new share once every other new participant confirmed. A
    /// renewal in place keeps the previous record until finalized.
    FrostReshareCommit {
        session: String,
        handle: String,
        confirmations_b64: BTreeMap<u16, String>,
    },
    /// Abort a resharing; `handle` as for `FrostDkgAbort`.
    FrostReshareAbort {
        session: String,
        #[serde(default)]
        handle: Option<String>,
    },
    /// Owner: drop the previous record kept by a renewal in place.
    FrostReshareFinalize { handle: String },
    /// Owner: put the previous record back (a renewal that did not commit on
    /// every vault).
    FrostReshareRollback { handle: String },
}

/// A vault RPC response, JSON-encoded inside `Response::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultResponse {
    KeyCreated {
        handle: String,
        expires_at: u64,
    },
    /// This vault's identity (wire formats §1). The quote's report data is
    /// `H("privasys-vault-identity-v1\n" member_id "\n" billing_id)`.
    VaultIdentity {
        member_id: String,
        member_public_key: String,
        billing_id: String,
        mrenclave: String,
        quote_b64: String,
        /// What this build enforces, by name (wire formats §9.1):
        /// "generations-v1" = `GetKeyInfo` reports `renewed_in_place_from`, a
        /// first creation of a generation handle (last segment `gen-<n>`) is refused,
        /// and a carried create keeps the source's exportable flag and type.
        /// A client trusts a generation link only from a build listing it.
        /// "update-policy-from-v1" = it accepts `update_policy_from` (§5.3).
        /// "tombstones-v1" = a deleted key leaves a tombstone (§9.3), a
        /// re-created name (`new-<k>`) needs its owner's bound create approval
        /// and `GetKeyInfo` reports `created_by_owner_approval`, and a pending
        /// threshold key is aborted through its session (§9.3.1).
        #[serde(default)]
        capabilities: Vec<String>,
    },
    /// A policy checked against wire formats §5.1, and its digest.
    CanonicalPolicy {
        policy: KeyPolicy,
        pd: String,
    },
    KeyMaterial {
        material: Vec<u8>,
        expires_at: u64,
    },
    KeyDeleted,
    /// `GetKeyInfo` on a deleted key, to the principals of its final policy
    /// (wire formats §9.3).
    KeyTombstone {
        handle: String,
        key_type: KeyType,
        op: String,
        deleted_at: u64,
        successor: String,
        expires_at: u64,
    },
    /// `RetireKey`: whether the predecessor was still here to delete.
    KeyRetired {
        was_present: bool,
    },
    PolicyUpdated {
        policy_version: u32,
    },
    Policy {
        policy: KeyPolicy,
        policy_version: u32,
    },
    KeyInfo(KeyInfo),
    KeyList {
        keys: Vec<KeyListEntry>,
    },

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

    AuditLog {
        entries: Vec<AuditEntry>,
        next_seq: u64,
    },

    PendingProfileStaged {
        /// Id of the staged pending profile. Meaningless (0) when
        /// `auto_promoted` — there is nothing pending to promote or revoke.
        pending_id: u32,
        /// True when no owner promote is needed: the profile was accepted
        /// immediately (the key's `auto_migrate` opt-in matched a
        /// runtime-only delta), or it was already an accepted principal
        /// (idempotent re-stage). False = staged as pending, owner promote
        /// required.
        #[serde(default)]
        auto_promoted: bool,
        /// The key's policy version after this call (bumped only when the
        /// profile was newly auto-promoted).
        #[serde(default)]
        policy_version: u32,
    },
    PendingProfileList {
        pending: Vec<PendingProfile>,
    },
    PendingProfilePromoted {
        policy_version: u32,
    },
    PendingProfileRevoked,

    FrostDkgRound1 {
        package: Vec<u8>,
        dh_public: Vec<u8>,
        quote: Vec<u8>,
    },
    /// This vault's sealed round 2 package for each other participant.
    FrostDkgSealed {
        packages: BTreeMap<u16, Vec<u8>>,
    },
    /// The group key this vault derived, and its confirmation for each other
    /// participant.
    FrostDkgConfirm {
        public_key: Vec<u8>,
        confirmations: BTreeMap<u16, Vec<u8>>,
    },
    /// This vault stored its share. `public_key` is the 32-byte Ed25519
    /// group key.
    ThresholdKeyCreated {
        handle: String,
        index: u16,
        threshold: u16,
        public_key: Vec<u8>,
        expires_at: u64,
    },
    /// This vault's signing commitment; `index` is its participant index,
    /// the key the client files it under.
    FrostCommitment {
        index: u16,
        commitment: Vec<u8>,
    },
    FrostSignatureShare {
        share: Vec<u8>,
    },
    FrostReshareTarget {
        dh_public: Vec<u8>,
        quote: Vec<u8>,
    },
    /// A helper's deal: its commitment and one sealed piece per new vault.
    FrostReshareDealt {
        commitment: Vec<Vec<u8>>,
        sealed: BTreeMap<u16, Vec<u8>>,
    },
    FrostDone,

    Error(String),
}

/// A new participant's first resharing message, as the client relays it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostTargetMessage {
    pub dh_public_b64: String,
    pub quote_b64: String,
}

/// A helper's deal for one new participant, as the client relays it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostDealMessage {
    pub commitment_b64: Vec<String>,
    pub sealed_b64: String,
}

/// What a vault holds of a threshold key (public).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThresholdKeyInfo {
    /// This vault's participant index.
    pub index: u16,
    pub threshold: u16,
    pub participants: u16,
    /// The participants' endpoints, participant `i` at `vaults[i - 1]`.
    pub vaults: Vec<String>,
    /// Serialised FROST public key package (verifying shares + group key).
    pub public_key_package: Vec<u8>,
}

/// A participant's DKG round 1 message, as the client relays it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostRound1Message {
    pub package_b64: String,
    pub dh_public_b64: String,
    pub quote_b64: String,
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
    /// Threshold keys: this vault's part (public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdKeyInfo>,
    /// The key this one renewed IN PLACE on this vault (wire formats §9.1),
    /// absent for a first creation or a carried move. A client that takes a
    /// name's newest generation accepts generation n > 1 only when it names
    /// generation n - 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewed_in_place_from: Option<String>,
    /// Created with its owner's bound `create` approval (wire formats §9.3.1):
    /// set by the vault, never from a request.
    #[serde(default, skip_serializing_if = "is_false")]
    pub created_by_owner_approval: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
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
/// Each variant maps 1:1 to the operations it supports — see
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
    /// One vault's share of a threshold Ed25519 key (FROST, RFC 9591),
    /// created by the `FrostDkg*` rounds and used by the `FrostSign*` rounds
    /// (EdDSA, by the threshold of vaults together). Never exportable.
    FrostEd25519,
}

// ---------------------------------------------------------------------------
//  Operations
// ---------------------------------------------------------------------------

/// Per-key operations that can be granted by an [`OperationRule`].
///
/// Namespace operations (`CreateKey`, `ListKeys`, `ReadAuditLog`,
/// `StagePendingProfile`, `ListPendingProfiles`, `RevokePendingProfile`) are not policy-gated and have no variant
/// here — they have their own auth rules baked in.
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
    ///
    /// If `sub` is **empty** the principal is *role-only*: it matches any
    /// subject that holds all `required_roles` (which must be non-empty). This
    /// is how a key names a set of callers by role — e.g. an app's team via the
    /// `privasys-platform:app:<id>:approver` role — without rewriting the policy
    /// when membership changes. See [`crate::policy::oidc_matches`].
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

    /// Opt-in Intel TCB-status enforcement. `None` (the default, and what
    /// every pre-existing stored policy deserialises to) = no TCB acceptance
    /// check — deliberately, so rolling out this enclave build does not
    /// reject peers on fleets whose policies have not been updated (the
    /// production hosts report `ConfigurationAndSWHardeningNeeded`).
    /// `Some(set)` = enforce: the secure floor (`UpToDate`,
    /// `SWHardeningNeeded`) always passes, other statuses must be listed in
    /// `set` (`Some([])` = strict floor-only). `"Revoked"` is never accepted,
    /// even with `None` — a revoked platform TCB always fails.
    #[serde(default)]
    pub acceptable_tcb_statuses: Option<Vec<String>>,
}

/// A measurement value that identifies a specific enclave build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Measurement {
    /// SGX MRENCLAVE, hex-encoded (lowercase, 64 chars).
    Mrenclave(String),
    /// TDX identity. `mrtd` is the TD firmware (per-platform); `rtmr1`/`rtmr2`
    /// are the image-derived registers (EFI/UKI boot path + dm-verity root) that
    /// identify the enclave-os-virtual build. All three are pinned and must
    /// match (MRTD alone is insufficient — it does not capture the guest image).
    /// All hex-encoded lowercase, 96 chars each.
    Tdx {
        mrtd: String,
        rtmr1: String,
        rtmr2: String,
    },
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
    /// The caller's OIDC bearer must prove a fresh step-up bound to this
    /// operation: its `amr` claim contains every method in `required_amr`
    /// (e.g. `["webauthn"]`), its `iat` is within `fresh_for_seconds`, and its
    /// `vault_op` is the binding v2 of this operation (wire formats §5). One
    /// rule checks the binding once.
    ///
    /// `operation_bound` and `binding` are kept as stored, so a policy's bytes
    /// and digest never change; the vault reads every step-up as binding v2
    /// whatever they say. Keys written before v2 carry `binding: 0`.
    OidcStepUp {
        #[serde(default)]
        required_amr: Vec<String>,
        #[serde(default)]
        operation_bound: bool,
        #[serde(default)]
        fresh_for_seconds: u64,
        /// 2 on keys written since binding v2, absent (0) before. Read as v2
        /// either way; any other value is refused.
        #[serde(default, skip_serializing_if = "is_zero_u8")]
        binding: u8,
    },
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

/// The request's part of a binding v2 (wire formats §5): the members it names,
/// sorted. Every other field the vault takes from its own state, the
/// operation, or the token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingV2Request {
    pub members: Vec<String>,
    /// For `update_policy_from` (wire formats §5.3): `PD` of the policy being
    /// replaced, as `GetPolicy` returns it. Absent: plain `update_policy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_pd: Option<String>,
}

/// The successor a `delete_after` is bound to (wire formats §9.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteAfter {
    pub successor: String,
    /// The successor's promote target (its profile digest), or `-` when the
    /// successor was created rather than promoted.
    pub successor_target: String,
}

/// The key check value of a whole key (wire formats §10.4): an Argon2id digest
/// under a random salt. Stored opaquely and never returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyCheck {
    pub salt_b64: String,
    pub digest_hex: String,
}

// ---------------------------------------------------------------------------
//  Lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lifecycle {
    /// Capped at [`MAX_KEY_TTL_SECONDS`]. Zero means default.
    #[serde(default)]
    pub ttl_seconds: u64,
    /// Auto-migrate opt-in (the enclave-upgrade design, item 2 —
    /// "auto-rolling"): when true, a profile staged by the PLATFORM
    /// (manager-role bearer, not a key principal) that differs from an
    /// already-accepted profile **only in the platform-runtime measurement**
    /// (SGX MRENCLAVE, or the TDX MRTD/RTMR set) is promoted immediately,
    /// without an owner promote. The app-code digest (OID …65230.3.2), the
    /// app id (…3.6) and every other required OID must be byte-identical —
    /// app-code changes ALWAYS need the owner. This is the owner's standing
    /// "trust the platform's own enclave-upgrade approval" grant; it is
    /// justified by build transparency (a bad platform measurement is
    /// publicly visible), not by any per-upgrade credential. Only the OWNER
    /// may change this flag (enforced unconditionally in
    /// `evaluate_policy_update`). Default false: every new measurement
    /// waits for an owner promote.
    #[serde(default)]
    pub auto_migrate_to_next_attestation_profile: bool,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle {
            ttl_seconds: DEFAULT_KEY_TTL_SECONDS,
            auto_migrate_to_next_attestation_profile: false,
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
///
/// **Serialisation is part of the protocol.** `PD(current)` in an
/// `update_policy_from` approval (wire formats §5.3) and the FROST quote context
/// hash this type as the vault serialises it. A NEW field on this type, or on
/// any type it contains, must be `#[serde(default, skip_serializing_if = ...)]`
/// at its default, so that an unchanged stored policy serialises exactly as
/// before; otherwise every pending approval of an unchanged key would stop
/// matching after an upgrade.
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
    /// `"none"` opts the key out of approval by default (wire formats §4): a new
    /// policy without approval rules on promote, update, delete and export
    /// is refused unless it says so. Absent on every key created before v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

// ---------------------------------------------------------------------------
//  Pending attestation profiles (enclave upgrade flow)
// ---------------------------------------------------------------------------

/// An attestation profile staged for a key but not yet promoted into
/// `policy.principals.tees`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingProfile {
    pub id: u32,
    pub profile: AttestationProfile,
    pub staged_at: u64,
    pub staged_by_sub: String,
    /// True when the stager was the PLATFORM (manager-role bearer via the
    /// staging-only capability), not a key principal. Set by the vault from
    /// the resolved identity, never from caller input.
    #[serde(default)]
    pub staged_by_platform: bool,
}

/// Hard cap on `pending_profiles` per key. Staging authorises nothing, but
/// with platform sweeps staging on every runtime roll an unbounded list is a
/// storage/DoS surface; identical profiles dedupe before this cap applies.
pub const MAX_PENDING_PROFILES: usize = 16;

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
    /// Threshold keys: the participants' endpoints, participant `i` at
    /// `threshold_vaults[i - 1]`. Empty for other keys.
    #[serde(default)]
    pub threshold_vaults: Vec<String>,
    /// The key check value of the whole key (wire formats §10.4), if the creator
    /// gave one. Never returned by any call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_check: Option<KeyCheck>,
    /// The key this one renewed IN PLACE (wire formats §9.1): set only when the
    /// policy was copied from a predecessor on this vault, never from a
    /// request, so a carried create cannot claim to supersede a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewed_in_place_from: Option<String>,
    /// Created with its owner's bound `create` approval (wire formats §9.3.1).
    #[serde(default, skip_serializing_if = "is_false")]
    pub created_by_owner_approval: bool,
    /// A threshold key committed by a DKG or resharing session and not yet
    /// used: its session may still abort it (wire formats §9.3.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_creation: Option<PendingCreation>,
}

/// Who may still abort a threshold key that has not served anything yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCreation {
    pub session: String,
    /// The threshold module's caller id of the session's opener.
    pub caller: String,
    pub committed_at: u64,
}

/// What a deleted key leaves behind (wire formats §9.3): never material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub handle: String,
    pub key_type: KeyType,
    pub final_policy: KeyPolicy,
    pub final_pd: String,
    pub final_policy_version: u32,
    /// "delete", "delete_after" or "retire".
    pub op: String,
    /// "oidc:0:<sub>" or "tee:<caller id>".
    pub approver: String,
    /// The binding's `vault_op`, or "-".
    pub vault_op: String,
    /// The successor's handle, or "-".
    pub successor: String,
    pub deleted_at: u64,
    /// The key's original expiry: the tombstone and the audit log go then.
    pub expires_at: u64,
    /// Where the key's audit log ends.
    pub audit_next_seq: u64,
}
