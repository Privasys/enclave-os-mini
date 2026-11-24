// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os — HSM-shaped key store inside SGX/TDX.
//!
//! Callers manipulate **keys** (handle + type + material + policy).
//! Access is gated by [`KeyPolicy`] which lists named principals
//! ([`PrincipalSet`]) and the operations each is allowed to perform
//! ([`OperationRule`]). Operations may also carry [`Condition`]s
//! (`AttestationMatches` / `ManagerApproval` / `TimeWindow`) that
//! tighten the grant. Remote TEE callers authenticate via mutual
//! RA-TLS with bidirectional challenge-response (always on).
//!
//! See `docs/vault.md` for the full design and `Cargo.toml` for
//! dependencies.

pub mod audit;
pub mod crypto;
pub mod grant;
pub mod policy;
pub mod quote;
pub mod signing;
pub mod threshold;
pub mod types;
pub mod v2;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_kvstore::SealedKvStore;

use crate::policy::{evaluate_op, evaluate_policy_update, resolve_caller, CallerRole};

use crate::types::{
    ApprovalToken, AttestationProfile, AuditDecision, BindingV2Request, KeyInfo, KeyListEntry, KeyPolicy, KeyRecord,
    KeyType, Operation, PendingProfile, PendingProfileSource, PolicyField, Principal, VaultRequest,
    VaultResponse, DEFAULT_APPROVAL_TOKEN_TTL_SECONDS, DEFAULT_KEY_TTL_SECONDS,
    MAX_APPROVAL_TOKEN_TTL_SECONDS, MAX_KEY_TTL_SECONDS,
};

// ---------------------------------------------------------------------------
//  VaultModule
// ---------------------------------------------------------------------------

/// Enclave module dispatching [`VaultRequest`]s.
pub struct VaultModule {
    _private: (),
}

impl VaultModule {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for VaultModule {
    fn default() -> Self {
        Self::new()
    }
}

impl EnclaveModule for VaultModule {
    fn name(&self) -> &str {
        "vault"
    }

    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };

        let vault_req: VaultRequest = match serde_json::from_slice(data) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let resp = match vault_req {
            VaultRequest::CreateKey {
                handle,
                material_b64,
                grant,
                predecessor,
                policy,
                policy_version,
                holder_records,
                source_billing_id,
                key_check,
                carried_exportable,
                carried_key_type,
            } => handle_create(
                &handle,
                &material_b64,
                &grant,
                CreateExtras {
                    predecessor,
                    policy,
                    policy_version,
                    holder_records,
                    source_billing_id,
                    key_check,
                    carried_exportable,
                    carried_key_type,
                },
                ctx,
            ),
            VaultRequest::ExportKey {
                handle,
                approvals,
                binding,
            } => handle_export(&handle, &approvals, binding, ctx),
            VaultRequest::DeleteKey {
                handle,
                approvals,
                binding,
                after,
            } => handle_delete(&handle, &approvals, binding, after, ctx),
            VaultRequest::RetireKey {
                handle,
                successor,
                successor_members,
            } => handle_retire(&handle, &successor, &successor_members, ctx),
            VaultRequest::UpdatePolicy {
                handle,
                new_policy,
                approvals,
                binding,
            } => handle_update_policy(&handle, &new_policy, &approvals, binding, ctx),
            VaultRequest::GetVaultIdentity => handle_identity(),
            VaultRequest::CanonicalisePolicy { policy } => match v2::canonical_policy(policy.get()) {
                Ok(c) => VaultResponse::CanonicalPolicy {
                    policy: c.policy,
                    pd: c.pd,
                },
                Err(e) => VaultResponse::Error(e),
            },
            VaultRequest::GetPolicy { handle } => handle_get_policy(&handle, ctx),
            VaultRequest::GetKeyInfo { handle } => handle_get_info(&handle, ctx),
            VaultRequest::ListKeys => handle_list(ctx),

            VaultRequest::Wrap {
                handle,
                plaintext_b64,
                aad_b64,
                iv_b64,
                approvals,
            } => handle_wrap(
                &handle,
                &plaintext_b64,
                aad_b64.as_deref(),
                iv_b64.as_deref(),
                &approvals,
                ctx,
            ),
            VaultRequest::Unwrap {
                handle,
                ciphertext_b64,
                iv_b64,
                aad_b64,
                approvals,
            } => handle_unwrap(
                &handle,
                &ciphertext_b64,
                &iv_b64,
                aad_b64.as_deref(),
                &approvals,
                ctx,
            ),
            VaultRequest::Sign {
                handle,
                message_b64,
                prehashed,
                approvals,
            } => handle_sign(&handle, &message_b64, prehashed, &approvals, ctx),
            VaultRequest::Mac {
                handle,
                message_b64,
                approvals,
            } => handle_mac(&handle, &message_b64, &approvals, ctx),

            VaultRequest::IssueApprovalToken {
                handle,
                op,
                ttl_seconds,
            } => handle_issue_approval(&handle, op, ttl_seconds, ctx),

            VaultRequest::ReadAuditLog {
                handle,
                since_seq,
                limit,
            } => handle_read_audit(&handle, since_seq, limit, ctx),

            VaultRequest::StagePendingProfile {
                handle,
                profile,
                source,
            } => handle_stage_pending(&handle, profile, source, ctx),
            VaultRequest::ListPendingProfiles { handle } => handle_list_pending(&handle, ctx),
            VaultRequest::PromotePendingProfile {
                handle,
                pending_id,
                approvals,
                binding,
            } => handle_promote_pending(&handle, pending_id, &approvals, binding, ctx),
            VaultRequest::RevokePendingProfile { handle, pending_id } => {
                handle_revoke_pending(&handle, pending_id, ctx)
            }

            req @ (VaultRequest::FrostDkgRound1 { .. }
            | VaultRequest::FrostDkgRound2 { .. }
            | VaultRequest::FrostDkgRound3 { .. }
            | VaultRequest::FrostDkgCommit { .. }
            | VaultRequest::FrostDkgAbort { .. }
            | VaultRequest::FrostSignRound1 { .. }
            | VaultRequest::FrostSignRound2 { .. }
            | VaultRequest::FrostSignAbort { .. }
            | VaultRequest::FrostAggregate { .. }
            | VaultRequest::FrostReshareTarget1 { .. }
            | VaultRequest::FrostReshareDeal { .. }
            | VaultRequest::FrostReshareTarget2 { .. }
            | VaultRequest::FrostReshareCommit { .. }
            | VaultRequest::FrostReshareAbort { .. }
            | VaultRequest::FrostReshareFinalize { .. }
            | VaultRequest::FrostReshareRollback { .. }) => threshold::handle(req, ctx),
        };

        match serde_json::to_vec(&resp) {
            Ok(b) => Some(Response::Data(b)),
            Err(e) => Some(Response::Error(
                format!("vault: serialise response: {e}").into_bytes(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
//  KV layout
// ---------------------------------------------------------------------------

pub(crate) fn record_key(handle: &str) -> Vec<u8> {
    format!("key:{}", handle).into_bytes()
}

fn owner_index_key(owner_sub: &str) -> Vec<u8> {
    format!("index:{}", owner_sub).into_bytes()
}

pub(crate) fn add_to_owner_index(store: &SealedKvStore, owner_sub: &str, handle: &str) -> Result<(), String> {
    let key = owner_index_key(owner_sub);
    let mut handles: Vec<String> = match store.get(&key) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Vec::new(),
    };
    if !handles.iter().any(|h| h == handle) {
        handles.push(handle.to_string());
    }
    let bytes = serde_json::to_vec(&handles).map_err(|e| format!("serialise index: {e}"))?;
    store.put(&key, &bytes)
}

fn remove_from_owner_index(
    store: &SealedKvStore,
    owner_sub: &str,
    handle: &str,
) -> Result<(), String> {
    let key = owner_index_key(owner_sub);
    let mut handles: Vec<String> = match store.get(&key) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => return Ok(()),
    };
    handles.retain(|h| h != handle);
    let bytes = serde_json::to_vec(&handles).map_err(|e| format!("serialise index: {e}"))?;
    store.put(&key, &bytes)
}

// ---------------------------------------------------------------------------
//  KV access helpers
// ---------------------------------------------------------------------------

pub(crate) fn kv() -> Result<&'static std::sync::Mutex<SealedKvStore>, VaultResponse> {
    enclave_os_kvstore::kv_store()
        .ok_or_else(|| VaultResponse::Error("kv store not initialised".into()))
}

pub(crate) fn load_record(handle: &str) -> Result<KeyRecord, VaultResponse> {
    let kv = kv()?;
    let store = kv
        .lock()
        .map_err(|_| VaultResponse::Error("kv store lock poisoned".into()))?;
    let bytes = store
        .get(&record_key(handle))
        .map_err(|e| VaultResponse::Error(format!("kv get failed: {e}")))?
        .ok_or_else(|| VaultResponse::Error("key not found".into()))?;
    serde_json::from_slice::<KeyRecord>(&bytes)
        .map_err(|e| VaultResponse::Error(format!("corrupt record: {e}")))
}

// ---------------------------------------------------------------------------
//  Time
// ---------------------------------------------------------------------------

/// Trusted time, Unix seconds. `None` when there is none: every caller
/// fails closed (a 0 would make every expiry look far away).
pub(crate) fn now_secs() -> Option<u64> {
    enclave_os_common::ocall::get_current_time().ok()
}

pub(crate) const NO_TRUSTED_TIME: &str = "no trusted time: time-bound operations are refused";

// ---------------------------------------------------------------------------
//  Audit
// ---------------------------------------------------------------------------

/// Append one audit entry to `record` and save the record. Used by every
/// op handler after a policy decision has been made.
pub(crate) fn audit_and_save(
    record: &mut KeyRecord,
    op: &str,
    caller: &str,
    decision: AuditDecision,
    reason: &str,
) -> Result<(), VaultResponse> {
    let kv = kv()?;
    let store = kv
        .lock()
        .map_err(|_| VaultResponse::Error("kv store lock poisoned".into()))?;
    audit::append(&store, record, op, caller, decision, reason)
        .map_err(|e| VaultResponse::Error(format!("audit append: {e}")))?;
    let bytes = serde_json::to_vec(record)
        .map_err(|e| VaultResponse::Error(format!("serialise record: {e}")))?;
    store
        .put(&record_key(&record.handle), &bytes)
        .map_err(|e| VaultResponse::Error(format!("kv put failed: {e}")))
}

/// Denials of callers who are not principals of the key, counted instead
/// of audited.
static UNAUDITED_DENIALS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Denials not written to an audit log: callers who are none of the key's
/// principals.
pub fn unaudited_denials() -> u64 {
    UNAUDITED_DENIALS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Record a denial. The key's audit log is permanent, so it records the
/// denials of the key's own principals (and of a platform manager bearer,
/// which stages profiles); anyone else's denial is only counted in memory,
/// so callers outside the policy cannot grow the log.
pub(crate) fn audit_denial(
    ctx: &RequestContext,
    record: &mut KeyRecord,
    op: &str,
    caller: &str,
    decision: AuditDecision,
    reason: &str,
) -> Result<(), VaultResponse> {
    let platform = ctx.oidc_claims.as_ref().map_or(false, |c| c.is_manager);
    if resolve_caller(&record.policy, ctx).is_none() && !platform {
        UNAUDITED_DENIALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return Ok(());
    }
    audit_and_save(record, op, caller, decision, reason)
}

pub(crate) fn caller_str(ctx: &RequestContext) -> String {
    if let Some(c) = ctx.oidc_claims.as_ref() {
        format!("oidc:{}", c.sub)
    } else if ctx.peer_cert_der.is_some() {
        "tee".to_string()
    } else {
        "anonymous".to_string()
    }
}

// ---------------------------------------------------------------------------
//  Policy normalisation
// ---------------------------------------------------------------------------

pub(crate) fn normalise_policy(mut policy: KeyPolicy) -> KeyPolicy {
    if policy.lifecycle.ttl_seconds == 0 {
        policy.lifecycle.ttl_seconds = DEFAULT_KEY_TTL_SECONDS;
    }
    if policy.lifecycle.ttl_seconds > MAX_KEY_TTL_SECONDS {
        policy.lifecycle.ttl_seconds = MAX_KEY_TTL_SECONDS;
    }
    let principals = std::iter::once(&mut policy.principals.owner)
        .chain(policy.principals.managers.iter_mut())
        .chain(policy.principals.auditors.iter_mut())
        .chain(policy.principals.tees.iter_mut());
    for p in principals {
        if let Principal::Tee(profile) = p {
            normalise_profile(profile);
        }
    }
    policy
}

fn normalise_profile(profile: &mut AttestationProfile) {
    for m in &mut profile.measurements {
        match m {
            crate::types::Measurement::Mrenclave(s) => *s = s.to_lowercase(),
            crate::types::Measurement::Tdx { mrtd, rtmr1, rtmr2 } => {
                *mrtd = mrtd.to_lowercase();
                *rtmr1 = rtmr1.to_lowercase();
                *rtmr2 = rtmr2.to_lowercase();
            }
        }
    }
    for oid in &mut profile.required_oids {
        oid.value = oid.value.to_lowercase();
    }
    for s in &mut profile.attestation_servers {
        if let Some(h) = s.pinned_spki_sha256_hex.as_mut() {
            h.make_ascii_lowercase();
        }
    }
}

// ---------------------------------------------------------------------------
//  Handlers — key management
// ---------------------------------------------------------------------------

/// What a grant must satisfy for `handle`, whoever presents it: the handle is
/// not reserved and falls under the grant's scope, and the granted policy is
/// owned by the grant's subject.
pub(crate) fn check_grant_for_handle(
    handle: &str,
    grant: &crate::grant::KeyCreationGrant,
) -> Result<(), String> {
    if handle.is_empty() {
        return Err("handle must not be empty".into());
    }
    if handle.starts_with("__") {
        return Err("handles starting with '__' are reserved for internal use".into());
    }
    if handle != grant.scope && !handle.starts_with(&format!("{}/", grant.scope)) {
        return Err(format!(
            "handle '{handle}' is outside the grant scope '{}'",
            grant.scope
        ));
    }
    if owner_oidc_sub(&grant.policy.principals.owner).as_deref() != Some(grant.sub.as_str()) {
        return Err("grant policy owner does not match the grant subject".into());
    }
    Ok(())
}

/// What a `CreateKey` may carry beyond the grant (formats §9, §10.4).
struct CreateExtras {
    predecessor: Option<String>,
    policy: Option<Box<serde_json::value::RawValue>>,
    policy_version: Option<u32>,
    holder_records: Vec<serde_json::Value>,
    source_billing_id: Option<String>,
    key_check: Option<crate::types::KeyCheck>,
    carried_exportable: Option<bool>,
    carried_key_type: Option<KeyType>,
}

/// The capability this build publishes in `GetVaultIdentity` for generation
/// links (formats §9.1).
pub const CAPABILITY_GENERATIONS: &str = "generations-v1";

/// The capability a build publishes when it accepts `update_policy_from`
/// (formats §5.3).
pub const CAPABILITY_UPDATE_FROM: &str = "update-policy-from-v1";

/// Whether a handle's last segment is a generation marker "gen-<digits>"
/// (formats §9.1): the suffix user-secret generations use, and nothing else.
fn is_generation_handle(handle: &str) -> bool {
    let last = handle.rsplit('/').next().unwrap_or(handle);
    match last.strip_prefix("gen-") {
        Some(n) => !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Where a new key's policy comes from.
struct NewKeyPolicy {
    policy: KeyPolicy,
    policy_version: u32,
    exportable: bool,
    key_check: Option<crate::types::KeyCheck>,
    /// For the audit log.
    how: String,
    /// Set only for a renewal in place: the predecessor on this vault, and
    /// its material (a single-vault key must keep exactly the same value).
    in_place_from: Option<(String, Vec<u8>)>,
}

/// Whether any rule granting `op` asks for a binding v2 step-up.
fn rule_takes_binding_v2(policy: &KeyPolicy, op: Operation) -> bool {
    policy.operations.iter().filter(|r| r.ops.contains(&op)).any(|r| {
        r.requires
            .iter()
            .any(|c| matches!(c, crate::types::Condition::OidcStepUp { binding: 2, .. }))
    })
}

/// The caller of a renewal must be the key's owner or one of its enclaves,
/// under the policy being renewed.
fn check_renewal_caller(policy: &KeyPolicy, ctx: &RequestContext) -> Result<(), String> {
    match resolve_caller(policy, ctx) {
        Some((_, CallerRole::Owner)) | Some((_, CallerRole::Tee)) => Ok(()),
        _ => Err("a renewal must come from the key's owner or an enclave its policy names".into()),
    }
}

/// Decide the new key's policy (formats §9): copied from a predecessor on
/// this vault, carried by the app from another constellation, or the grant's
/// for a first creation.
fn new_key_policy(
    grant: &crate::grant::KeyCreationGrant,
    extras: CreateExtras,
    ctx: &RequestContext,
) -> Result<NewKeyPolicy, String> {
    if !extras.holder_records.is_empty() {
        return Err("holder records are not accepted before step 3".into());
    }
    if let Some(kc) = &extras.key_check {
        check_key_check(kc)?;
    }

    // Renewal in place: the predecessor is here.
    if let (Some(pred), None) = (&extras.predecessor, &extras.policy) {
        let rec = load_record(pred).map_err(|e| match e {
            VaultResponse::Error(m) => format!("predecessor: {m}"),
            _ => "predecessor not found".into(),
        })?;
        if expired(&rec) {
            return Err("predecessor has expired".into());
        }
        if rec.key_type != grant.key_type {
            return Err("predecessor is of another key type".into());
        }
        if rec.exportable != grant.exportable {
            return Err("the grant changes whether the key is exportable; a renewal keeps it".into());
        }
        check_renewal_caller(&rec.policy, ctx)?;
        return Ok(NewKeyPolicy {
            policy: rec.policy,
            policy_version: rec.policy_version,
            exportable: rec.exportable,
            key_check: rec.key_check.or(extras.key_check),
            how: format!("renewal in place from {pred}"),
            in_place_from: Some((pred.clone(), rec.material)),
        });
    }

    // Moved from another constellation, or rotated: the policy the app read
    // from the source vault, carried verbatim and parsed as the vault parses
    // its own records (not held to the strictness of a policy being approved).
    if let Some(raw) = &extras.policy {
        let policy: KeyPolicy = serde_json::from_str(raw.get())
            .map_err(|e| format!("carried policy does not parse: {e}"))?;
        let policy = normalise_policy(policy);
        let version = extras
            .policy_version
            .ok_or_else(|| "a carried policy needs its policy_version".to_string())?;
        if version == 0 {
            return Err("carried policy_version must be at least 1".into());
        }
        let (_, _, own_billing) = v2::own_identity()?;
        match extras.source_billing_id.as_deref() {
            Some(b) if b == own_billing => {}
            Some(_) => {
                return Err(
                    "the source is under another billing configuration: keys do not cross it"
                        .into(),
                )
            }
            None => return Err("a carried policy needs source_billing_id".into()),
        }
        check_renewal_caller(&policy, ctx)?;
        // The source key's exportable flag and type travel with its policy;
        // a grant may not change them on the way (Security).
        let carried_exportable = extras
            .carried_exportable
            .ok_or_else(|| "a carried policy needs the source's carried_exportable".to_string())?;
        let carried_key_type = extras
            .carried_key_type
            .ok_or_else(|| "a carried policy needs the source's carried_key_type".to_string())?;
        if carried_exportable != grant.exportable || carried_key_type != grant.key_type {
            return Err(
                "the grant changes the key's type or whether it is exportable; a carried key keeps both"
                    .into(),
            );
        }
        return Ok(NewKeyPolicy {
            policy,
            policy_version: version,
            exportable: carried_exportable,
            key_check: extras.key_check,
            how: match &extras.predecessor {
                Some(p) => format!("carried from {p}"),
                None => "carried (rotation)".into(),
            },
            // A carried create never supersedes anything here (Security).
            in_place_from: None,
        });
    }

    // A first creation: the grant's policy, which must ask for approvals.
    let policy = normalise_policy(grant.policy.clone());
    v2::check_approval_by_default(&policy, grant.exportable)?;
    Ok(NewKeyPolicy {
        policy,
        policy_version: 1,
        exportable: grant.exportable,
        key_check: extras.key_check,
        how: "created".into(),
        in_place_from: None,
    })
}

/// A renewal in place keeps the key's value. For every key type but a Shamir
/// share (whose share is fresh by design, the value being whole only across
/// the vaults), the vault holds the whole value and compares it (Security).
fn check_same_value(key_type: KeyType, old: &[u8], new: &[u8]) -> Result<(), String> {
    if key_type == KeyType::RawShare {
        return Ok(());
    }
    let same = old.len() == new.len()
        && old.iter().zip(new).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if same {
        Ok(())
    } else {
        Err("a renewal must keep the key's value".into())
    }
}

/// Whether `succ` is a live renewal of `handle` made on this vault: the only
/// kind of successor that lets `RetireKey` delete `handle` (Security).
fn superseded_in_place(handle: &str, succ: &KeyRecord) -> bool {
    superseded_in_place_at(handle, succ, now_secs())
}

fn superseded_in_place_at(handle: &str, succ: &KeyRecord, now: Option<u64>) -> bool {
    let live = now.is_some_and(|n| n <= succ.expires_at);
    live && succ.renewed_in_place_from.as_deref() == Some(handle)
}

/// A key check value is opaque to the vault, but must be well formed.
fn check_key_check(kc: &crate::types::KeyCheck) -> Result<(), String> {
    match URL_SAFE_NO_PAD.decode(&kc.salt_b64) {
        Ok(s) if s.len() == 16 => {}
        _ => return Err("key_check salt must be 16 bytes, base64url".into()),
    }
    if kc.digest_hex.len() != 64 || !kc.digest_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("key_check digest must be 64 lower-case hex digits".into());
    }
    Ok(())
}

fn handle_identity() -> VaultResponse {
    let (public_key, member_id, billing_id) = match v2::own_identity() {
        Ok(v) => v,
        Err(e) => return VaultResponse::Error(e),
    };
    let report = v2::identity_report_data(&member_id, &billing_id);
    let Some(quote) = enclave_os_egress::enclave_attestation_quote(&report) else {
        return VaultResponse::Error("no attestation quote available".into());
    };
    let mrenclave = enclave_os_egress::enclave_self_mrenclave()
        .map(|m| v2::hex(m.as_slice()))
        .unwrap_or_default();
    VaultResponse::VaultIdentity {
        member_id,
        member_public_key: v2::hex(&public_key),
        billing_id,
        mrenclave,
        quote_b64: URL_SAFE_NO_PAD.encode(quote),
        capabilities: vec![
            CAPABILITY_GENERATIONS.to_string(),
            CAPABILITY_UPDATE_FROM.to_string(),
        ],
    }
}

fn handle_create(
    handle: &str,
    material_b64: &str,
    grant_jwt: &str,
    extras: CreateExtras,
    ctx: &RequestContext,
) -> VaultResponse {
    if handle.is_empty() {
        return VaultResponse::Error("handle must not be empty".into());
    }
    if handle.starts_with("__") {
        return VaultResponse::Error(
            "handles starting with '__' are reserved for internal use".into(),
        );
    }

    let Some(now) = now_secs() else {
        return VaultResponse::Error(NO_TRUSTED_TIME.into());
    };
    let grant = match crate::grant::verify_grant(grant_jwt, ctx, now) {
        Ok(g) => g,
        Err(e) => return VaultResponse::Error(e),
    };
    if let Err(e) = check_grant_for_handle(handle, &grant) {
        return VaultResponse::Error(e);
    }
    if grant.key_type == KeyType::FrostEd25519 {
        return VaultResponse::Error(
            "a FrostEd25519 key is created by the FrostDkg rounds, not CreateKey".into(),
        );
    }

    let key_type = grant.key_type;
    if extras.predecessor.as_deref() == Some(handle) {
        return VaultResponse::Error("a key cannot succeed itself".into());
    }
    // A generation ("<name>/gen-<n>") exists only through a renewal (Security):
    // whoever mints grants must not be able to plant a newer generation with
    // a value of its choosing as a first creation. The marker is used by
    // nothing else, so first creations at ".../v<n>" are untouched.
    let first_creation = extras.predecessor.is_none() && extras.policy.is_none();
    if first_creation && is_generation_handle(handle) {
        return VaultResponse::Error(
            "a handle ending in gen-<n> is a generation and can only be created by a \
             renewal (a predecessor here, or the policy carried from the source)"
                .into(),
        );
    }
    let chosen = match new_key_policy(&grant, extras, ctx) {
        Ok(c) => c,
        Err(e) => return VaultResponse::Error(e),
    };
    let exportable = chosen.exportable;
    let owner_sub = match owner_oidc_sub(&chosen.policy.principals.owner) {
        Some(s) => s,
        None => return VaultResponse::Error("the key's owner is not an OIDC subject".into()),
    };

    let material = match URL_SAFE_NO_PAD.decode(material_b64) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return VaultResponse::Error("material must not be empty".into()),
        Err(e) => return VaultResponse::Error(format!("bad base64: {e}")),
    };
    let public_key = match crypto::validate_material(key_type, &material) {
        Ok(p) => p,
        Err(e) => return VaultResponse::Error(e),
    };
    // A renewal keeps the value. A single-vault key holds the whole value
    // here, so the vault checks it; a split key's share is fresh by design.
    if let Some((_, old)) = &chosen.in_place_from {
        if let Err(e) = check_same_value(key_type, old, &material) {
            return VaultResponse::Error(e);
        }
    }
    let renewed_in_place_from = chosen.in_place_from.map(|(p, _)| p);

    let policy = chosen.policy;
    let expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);

    let kv = match kv() {
        Ok(k) => k,
        Err(e) => return e,
    };
    {
        let store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        match store.get(&record_key(handle)) {
            Ok(Some(_)) => return VaultResponse::Error("handle already exists".into()),
            Ok(None) => {}
            Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
        }
    }

    let mut record = KeyRecord {
        handle: handle.to_string(),
        key_type,
        exportable,
        material,
        public_key,
        policy,
        policy_version: chosen.policy_version,
        created_at: now,
        expires_at,
        pending_profiles: Vec::new(),
        audit_next_seq: 0,
        next_pending_id: 0,
        threshold_vaults: Vec::new(),
        key_check: chosen.key_check,
        renewed_in_place_from,
    };

    if let Err(e) = audit_and_save(
        &mut record,
        "CreateKey",
        &caller_str(ctx),
        AuditDecision::Allowed,
        &format!("owner={owner_sub}; {}", chosen.how),
    ) {
        return e;
    }

    {
        let store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        if let Err(e) = add_to_owner_index(&store, &owner_sub, handle) {
            return VaultResponse::Error(format!("kv owner index: {e}"));
        }
    }

    VaultResponse::KeyCreated {
        handle: handle.to_string(),
        expires_at,
    }
}

fn handle_export(
    handle: &str,
    approvals: &[ApprovalToken],
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }
    if !record.exportable {
        return VaultResponse::Error("key is not exportable".into());
    }
    let caller = caller_str(ctx);
    // Export has no canonical target measurement (unlike promote), so an
    // `OidcStepUp { operation_bound }` condition binds the empty measurement
    // slot: (handle, "", policy_version, nonce, exp). The empty measurement can
    // never collide with a promote binding (which always carries a non-empty
    // profile digest), so a captured promote approval cannot be replayed to
    // export the same handle, and vice versa.
    let op_binding = crate::policy::OpBinding {
        measurement_digest_hex: String::new(),
        policy_version: record.policy_version,
        v1: true,
        v2: Some(crate::policy::OpBindingV2 {
            op: "export",
            target: Ok("-".into()),
            members: binding.map(|b| b.members),
        }),
    };
    match evaluate_op(
        &record.policy,
        record.policy_version,
        Operation::ExportKey,
        handle,
        approvals,
        ctx,
        Some(&op_binding),
    ) {
        Ok(()) => {
            let _ = audit_and_save(
                &mut record,
                "ExportKey",
                &caller,
                AuditDecision::Allowed,
                "",
            );
            VaultResponse::KeyMaterial {
                material: record.material,
                expires_at: record.expires_at,
            }
        }
        Err(e) => {
            let _ = audit_denial(ctx, &mut record, "ExportKey", &caller, AuditDecision::Denied, &e);
            VaultResponse::Error(e)
        }
    }
}

fn handle_delete(
    handle: &str,
    approvals: &[ApprovalToken],
    binding: Option<BindingV2Request>,
    after: Option<crate::types::DeleteAfter>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    // The old key of a migration or upgrade: refused until its successor has
    // succeeded, checked before the approval is spent (formats §9.2).
    let (op, target, detail) = match &after {
        Some(a) => {
            if let Err(e) = check_successor_succeeded(&record, a) {
                let _ = audit_denial(ctx, &mut record, "DeleteKey", &caller, AuditDecision::Denied, &e);
                return VaultResponse::Error(e);
            }
            let target = v2::delete_after_target(&a.successor, &a.successor_target);
            ("delete_after", target, format!("after {}", a.successor))
        }
        None => ("delete", Ok("-".into()), String::new()),
    };
    // A v1 condition has no binding for delete (an operation-bound one fails
    // closed, as before); binding v2 binds the handle and policy version.
    let op_binding = crate::policy::OpBinding {
        measurement_digest_hex: String::new(),
        policy_version: record.policy_version,
        v1: false,
        v2: Some(crate::policy::OpBindingV2 {
            op,
            target,
            members: binding.map(|b| b.members),
        }),
    };
    if let Err(e) = evaluate_op(
        &record.policy,
        record.policy_version,
        Operation::DeleteKey,
        handle,
        approvals,
        ctx,
        Some(&op_binding),
    ) {
        let _ = audit_denial(ctx, &mut record, "DeleteKey", &caller, AuditDecision::Denied, &e);
        return VaultResponse::Error(e);
    }

    match remove_record(&mut record, "DeleteKey", &caller, &detail) {
        Ok(()) => VaultResponse::KeyDeleted,
        Err(e) => e,
    }
}

/// Delete a key's record after auditing it. The record itself disappears, so
/// its audit chain dies too: deletion is final and auditors snapshot the log
/// before it goes.
fn remove_record(
    record: &mut KeyRecord,
    what: &str,
    caller: &str,
    detail: &str,
) -> Result<(), VaultResponse> {
    let handle = record.handle.clone();
    let owner_sub = match owner_oidc_sub(&record.policy.principals.owner) {
        Some(s) => s,
        None => return Err(VaultResponse::Error("policy owner is not OIDC; cannot index".into())),
    };
    let _ = audit_and_save(record, what, caller, AuditDecision::Allowed, detail);

    let kv = kv()?;
    let mut store = match kv.lock() {
        Ok(s) => s,
        Err(_) => return Err(VaultResponse::Error("kv store lock poisoned".into())),
    };
    if let Err(e) = store.delete(&record_key(&handle)) {
        return Err(VaultResponse::Error(format!("kv delete failed: {e}")));
    }
    let _ = store.delete(&threshold::previous_key(&handle));
    let _ = remove_from_owner_index(&store, &owner_sub, &handle);
    Ok(())
}

/// The old key of a migration or upgrade may go only once its successor has
/// succeeded, where this vault can see it (formats §9.2).
fn check_successor_succeeded(old: &KeyRecord, after: &crate::types::DeleteAfter) -> Result<(), String> {
    // Promote K then "delete K after K" would delete the key just promoted.
    if after.successor == old.handle {
        return Err("a key cannot be the successor of itself".into());
    }
    let succ = load_record(&after.successor).ok();
    successor_check(old, after, succ.as_ref(), now_secs())
}

/// The successor checks of formats §9.2, given the successor's record when it
/// is on this vault.
fn successor_check(
    old: &KeyRecord,
    after: &crate::types::DeleteAfter,
    succ: Option<&KeyRecord>,
    now: Option<u64>,
) -> Result<(), String> {
    if after.successor == old.handle {
        return Err("a key cannot be the successor of itself".into());
    }
    let Some(succ) = succ else {
        // On another constellation: the client presents the delete only after
        // confirming the new key works; the binding confines it to that one.
        return Ok(());
    };
    if !now.is_some_and(|n| n <= succ.expires_at) {
        return Err("the successor has expired".into());
    }
    // Any live key here would otherwise pass for a created successor
    // (Security): it must belong to the same owner and be newer.
    if succ.policy.principals.owner != old.policy.principals.owner {
        return Err("the successor belongs to another owner".into());
    }
    if succ.created_at <= old.created_at {
        return Err("the successor is not newer than the key it replaces".into());
    }
    if after.successor_target != "-" {
        let promoted = succ.policy.principals.tees.iter().any(|p| {
            matches!(p, Principal::Tee(t) if crate::policy::profile_binding_digest(t) == after.successor_target)
        });
        if !promoted {
            return Err("the successor's promote has not been applied yet".into());
        }
    }
    Ok(())
}

fn handle_retire(
    handle: &str,
    successor: &str,
    successor_members: &[String],
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(_) => return VaultResponse::KeyRetired { was_present: false },
    };
    let caller = caller_str(ctx);
    let refuse = |record: &mut KeyRecord, e: String| {
        let _ = audit_denial(ctx, record, "RetireKey", &caller, AuditDecision::Denied, &e);
        VaultResponse::Error(e)
    };
    if record.key_type == KeyType::FrostEd25519 {
        return refuse(&mut record, "a threshold key is renewed by resharing, not retired".into());
    }
    match resolve_caller(&record.policy, ctx) {
        Some((_, CallerRole::Tee)) => {}
        _ => return refuse(&mut record, "only an enclave the key's policy names may retire it".into()),
    }
    if successor == handle {
        return refuse(&mut record, "a key cannot succeed itself".into());
    }
    let own = match v2::own_identity() {
        Ok((_, m, _)) => m,
        Err(e) => return refuse(&mut record, e),
    };
    let sorted = successor_members.windows(2).all(|w| w[0] < w[1]);
    if successor_members.is_empty() || !sorted {
        return refuse(&mut record, "successor_members must be sorted, unique and non-empty".into());
    }
    // Only a generation this vault KNOWS is superseded may be retired: its
    // successor is here, unexpired, and records it as its predecessor. The
    // live generation is never reachable, whatever the caller claims (Security).
    // A key that moved to another constellation is not retired this way.
    if !successor_members.iter().any(|m| m == &own) {
        return refuse(
            &mut record,
            "the successor is not on this vault: only a key superseded here can be retired".into(),
        );
    }
    let detail = match load_record(successor) {
        Ok(succ) if superseded_in_place(handle, &succ) => {
            format!("renewed in place by {successor}")
        }
        _ => {
            return refuse(
                &mut record,
                "this vault holds no live successor recording this key as its predecessor".into(),
            )
        }
    };
    match remove_record(&mut record, "RetireKey", &caller, &detail) {
        Ok(()) => VaultResponse::KeyRetired { was_present: true },
        Err(e) => e,
    }
}

fn handle_update_policy(
    handle: &str,
    new_policy_raw: &serde_json::value::RawValue,
    approvals: &[ApprovalToken],
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }
    let caller = caller_str(ctx);

    // A key whose update rule takes binding v2 approves exactly the JSON sent
    // (formats §5.1): it must be canonical, and it is stored as sent. Other
    // keys take the policy as before, normalised.
    let takes_v2 = rule_takes_binding_v2(&record.policy, Operation::UpdatePolicy);
    let canonical = v2::canonical_policy(new_policy_raw.get());
    let new_policy = if takes_v2 {
        match &canonical {
            Ok(c) => c.policy.clone(),
            Err(e) => return VaultResponse::Error(e.clone()),
        }
    } else {
        match serde_json::from_str::<KeyPolicy>(new_policy_raw.get()) {
            Ok(p) => normalise_policy(p),
            Err(e) => return VaultResponse::Error(format!("new_policy does not parse: {e}")),
        }
    };
    // update_policy_from (formats §5.3): the approval also names the policy it
    // replaces; it must be the one this vault holds now.
    let replaced_pd = binding.as_ref().and_then(|b| b.replaced_pd.clone());
    let (op, target) = match replaced_pd {
        None => ("update_policy", canonical.map(|c| c.pd)),
        Some(replaced) => {
            let current = match v2::stored_policy_digest(&record.policy) {
                Ok(pd) => pd,
                Err(e) => return VaultResponse::Error(e),
            };
            if replaced != current {
                let e = "replaced_pd is not this key's current policy: the policy changed since the approval was asked for".to_string();
                let _ = audit_denial(ctx, &mut record, "UpdatePolicy", &caller, AuditDecision::Denied, &e);
                return VaultResponse::Error(e);
            }
            (
                "update_policy_from",
                canonical.map(|c| v2::update_from_target(&current, &c.pd)),
            )
        }
    };
    let op_binding = crate::policy::OpBinding {
        measurement_digest_hex: String::new(),
        policy_version: record.policy_version,
        v1: false,
        v2: Some(crate::policy::OpBindingV2 {
            op,
            target,
            members: binding.map(|b| b.members),
        }),
    };

    if let Err(e) = evaluate_op(
        &record.policy,
        record.policy_version,
        Operation::UpdatePolicy,
        handle,
        approvals,
        ctx,
        Some(&op_binding),
    ) {
        let _ = audit_denial(ctx, 
            &mut record,
            "UpdatePolicy",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }
    let role = match resolve_caller(&record.policy, ctx) {
        Some((_pref, role)) => role,
        None => return VaultResponse::Error("caller is not in policy.principals".into()),
    };
    // Approval by default (formats §4): an update may not take away the
    // approvals a key has. A key that never had them (created before v2) may
    // still be updated, and an update may add them.
    if v2::check_approval_by_default(&record.policy, record.exportable).is_ok() {
        if let Err(e) = v2::check_approval_by_default(&new_policy, record.exportable) {
            let _ = audit_denial(ctx, &mut record, "UpdatePolicy", &caller, AuditDecision::Denied, &e);
            return VaultResponse::Error(e);
        }
    }
    if let Err(e) = evaluate_policy_update(&record.policy, &new_policy, role) {
        let _ = audit_denial(ctx, 
            &mut record,
            "UpdatePolicy",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }

    record.policy = new_policy;
    record.policy_version = record.policy_version.saturating_add(1);

    if let Err(e) = audit_and_save(
        &mut record,
        "UpdatePolicy",
        &caller,
        AuditDecision::Allowed,
        "",
    ) {
        return e;
    }
    VaultResponse::PolicyUpdated {
        policy_version: record.policy_version,
    }
}

fn handle_get_policy(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        return VaultResponse::Error("caller is not in policy.principals".into());
    }
    VaultResponse::Policy {
        policy: record.policy,
        policy_version: record.policy_version,
    }
}

fn handle_get_info(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        return VaultResponse::Error("caller is not in policy.principals".into());
    }
    let threshold = threshold::key_info(&record);
    VaultResponse::KeyInfo(KeyInfo {
        handle: record.handle,
        key_type: record.key_type,
        exportable: record.exportable,
        created_at: record.created_at,
        expires_at: record.expires_at,
        policy_version: record.policy_version,
        public_key: record.public_key,
        threshold,
        renewed_in_place_from: record.renewed_in_place_from,
    })
}

fn handle_list(ctx: &RequestContext) -> VaultResponse {
    let claims = match ctx.oidc_claims.as_ref() {
        Some(c) => c,
        None => return VaultResponse::Error("OIDC authentication required to list keys".into()),
    };
    let owner_sub = &claims.sub;

    let kv = match kv() {
        Ok(k) => k,
        Err(e) => return e,
    };
    let store = match kv.lock() {
        Ok(s) => s,
        Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
    };
    let handles: Vec<String> = match store.get(&owner_index_key(owner_sub)) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        Ok(None) => Vec::new(),
        Err(e) => return VaultResponse::Error(format!("kv index read: {e}")),
    };

    let mut keys = Vec::new();
    for handle in &handles {
        if let Ok(Some(bytes)) = store.get(&record_key(handle)) {
            if let Ok(record) = serde_json::from_slice::<KeyRecord>(&bytes) {
                keys.push(KeyListEntry {
                    handle: record.handle,
                    key_type: record.key_type,
                    expires_at: record.expires_at,
                });
            }
        }
    }
    VaultResponse::KeyList { keys }
}

// ---------------------------------------------------------------------------
//  Handlers — crypto ops
// ---------------------------------------------------------------------------

/// Shared prelude: load record, check not expired, check key_type matches,
/// run policy with conditions, audit, and on success return the record.
pub(crate) fn require_op(
    handle: &str,
    op: Operation,
    expect_type: KeyType,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> Result<KeyRecord, VaultResponse> {
    let mut record = load_record(handle)?;
    if expired(&record) {
        let _ = audit_denial(ctx, 
            &mut record,
            op_name(op),
            &caller_str(ctx),
            AuditDecision::Denied,
            "key has expired",
        );
        return Err(VaultResponse::Error("key has expired".into()));
    }
    if record.key_type != expect_type {
        let msg = format!(
            "key {} has type {:?}, op {:?} requires {:?}",
            handle, record.key_type, op, expect_type
        );
        let _ = audit_denial(ctx, 
            &mut record,
            op_name(op),
            &caller_str(ctx),
            AuditDecision::Denied,
            &msg,
        );
        return Err(VaultResponse::Error(msg));
    }
    let caller = caller_str(ctx);
    if let Err(e) = evaluate_op(&record.policy, record.policy_version, op, handle, approvals, ctx, None) {
        let _ = audit_denial(ctx, &mut record, op_name(op), &caller, AuditDecision::Denied, &e);
        return Err(VaultResponse::Error(e));
    }
    if let Err(e) = audit_and_save(
        &mut record,
        op_name(op),
        &caller,
        AuditDecision::Allowed,
        "",
    ) {
        return Err(e);
    }
    Ok(record)
}

fn op_name(op: Operation) -> &'static str {
    match op {
        Operation::ExportKey => "ExportKey",
        Operation::DeleteKey => "DeleteKey",
        Operation::UpdatePolicy => "UpdatePolicy",
        Operation::Wrap => "Wrap",
        Operation::Unwrap => "Unwrap",
        Operation::Sign => "Sign",
        Operation::Mac => "Mac",
        Operation::PromoteProfile => "PromoteProfile",
    }
}

fn handle_wrap(
    handle: &str,
    plaintext_b64: &str,
    aad_b64: Option<&str>,
    iv_b64: Option<&str>,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Wrap,
        KeyType::Aes256GcmKey,
        approvals,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let plaintext = match URL_SAFE_NO_PAD.decode(plaintext_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("plaintext base64: {e}")),
    };
    let aad = match aad_b64 {
        Some(s) => match URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("aad base64: {e}")),
        },
        None => Vec::new(),
    };
    // A caller-chosen nonce is refused: see the `Wrap` doc comment. Fail
    // loudly rather than ignoring the field, so a client that believes it is
    // fixing the nonce never receives a ciphertext under a different one.
    if iv_b64.is_some() {
        return VaultResponse::Error(
            "wrap does not accept a caller-supplied iv: the vault generates the nonce \
             and returns it (GCM nonce reuse breaks confidentiality and authenticity)"
                .to_string(),
        );
    }
    match crypto::aes_gcm_seal(&record.material, &plaintext, &aad) {
        Ok((ciphertext, iv)) => VaultResponse::Wrapped { ciphertext, iv },
        Err(e) => VaultResponse::Error(e),
    }
}

fn handle_unwrap(
    handle: &str,
    ciphertext_b64: &str,
    iv_b64: &str,
    aad_b64: Option<&str>,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Unwrap,
        KeyType::Aes256GcmKey,
        approvals,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let ciphertext = match URL_SAFE_NO_PAD.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("ciphertext base64: {e}")),
    };
    let iv = match URL_SAFE_NO_PAD.decode(iv_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("iv base64: {e}")),
    };
    let aad = match aad_b64 {
        Some(s) => match URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("aad base64: {e}")),
        },
        None => Vec::new(),
    };
    match crypto::aes_gcm_open(&record.material, &ciphertext, &iv, &aad) {
        Ok(plaintext) => VaultResponse::Unwrapped { plaintext },
        Err(e) => VaultResponse::Error(e),
    }
}

fn handle_sign(
    handle: &str,
    message_b64: &str,
    prehashed: bool,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Sign,
        KeyType::P256SigningKey,
        approvals,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let message = match URL_SAFE_NO_PAD.decode(message_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("message base64: {e}")),
    };
    // prehashed: `message` is a 32-byte SHA-256 digest, signed raw (CKM_ECDSA);
    // otherwise the vault hashes the message (ECDSA-P256-SHA256).
    let result = if prehashed {
        crypto::p256_sign_prehash(&record.material, &message)
    } else {
        crypto::p256_sign(&record.material, &message)
    };
    match result {
        Ok(signature) => VaultResponse::Signature {
            signature,
            alg: "ES256",
        },
        Err(e) => VaultResponse::Error(e),
    }
}

fn handle_mac(
    handle: &str,
    message_b64: &str,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Mac,
        KeyType::HmacSha256Key,
        approvals,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let message = match URL_SAFE_NO_PAD.decode(message_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("message base64: {e}")),
    };
    let mac = crypto::hmac_sha256(&record.material, &message);
    VaultResponse::MacTag {
        mac,
        alg: "HMAC-SHA-256",
    }
}

// ---------------------------------------------------------------------------
//  Handlers — approval tokens
// ---------------------------------------------------------------------------

fn handle_issue_approval(
    handle: &str,
    op: Operation,
    ttl_seconds: u64,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Caller must be an OIDC manager of this key.
    let claims = match ctx.oidc_claims.as_ref() {
        Some(c) => c,
        None => {
            let _ = audit_denial(ctx, 
                &mut record,
                "IssueApprovalToken",
                "anonymous",
                AuditDecision::Denied,
                "no OIDC claims",
            );
            return VaultResponse::Error(
                "OIDC authentication required to issue approval tokens".into(),
            );
        }
    };
    // Match the caller to a manager principal the same way op evaluation does:
    // a subject-bound manager by exact sub, a role-based manager by role. This
    // lets a role-holder issue an approval token for a role-based (co-sign)
    // manager even though no manager pins their sub.
    let mgr_idx = match record
        .policy
        .principals
        .managers
        .iter()
        .position(|p| policy::oidc_matches(p, claims))
    {
        Some(i) => i as u32,
        None => {
            let msg = "caller is not an OIDC manager of this key".to_string();
            let _ = audit_denial(ctx, 
                &mut record,
                "IssueApprovalToken",
                &format!("oidc:{}", claims.sub),
                AuditDecision::Denied,
                &msg,
            );
            return VaultResponse::Error(msg);
        }
    };

    let ttl = if ttl_seconds == 0 {
        DEFAULT_APPROVAL_TOKEN_TTL_SECONDS
    } else if ttl_seconds > MAX_APPROVAL_TOKEN_TTL_SECONDS {
        MAX_APPROVAL_TOKEN_TTL_SECONDS
    } else {
        ttl_seconds
    };
    let Some(now) = now_secs() else {
        return VaultResponse::Error(NO_TRUSTED_TIME.into());
    };

    let token = {
        let kv = match kv() {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        match signing::issue_approval_token(
            &mut store,
            handle,
            op,
            mgr_idx,
            &claims.sub,
            record.policy_version,
            now,
            ttl,
        )
        {
            Ok(t) => t,
            Err(e) => return VaultResponse::Error(e),
        }
    };

    let _ = audit_and_save(
        &mut record,
        "IssueApprovalToken",
        &format!("oidc:{}", claims.sub),
        AuditDecision::Allowed,
        &format!("op={:?} ttl={}s", op, ttl),
    );

    VaultResponse::ApprovalTokenIssued(token)
}

// ---------------------------------------------------------------------------
//  Handlers — audit log read
// ---------------------------------------------------------------------------

fn handle_read_audit(
    handle: &str,
    since_seq: u64,
    limit: u32,
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        return VaultResponse::Error("caller is not in policy.principals".into());
    }
    let limit = if limit == 0 { 256 } else { limit.min(1024) };

    let kv = match kv() {
        Ok(k) => k,
        Err(e) => return e,
    };
    let store = match kv.lock() {
        Ok(s) => s,
        Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
    };
    let (entries, next_seq) =
        match audit::read(&store, handle, record.audit_next_seq, since_seq, limit) {
            Ok(p) => p,
            Err(e) => return VaultResponse::Error(e),
        };
    VaultResponse::AuditLog { entries, next_seq }
}

// ---------------------------------------------------------------------------
//  Handlers — pending attestation profiles
// ---------------------------------------------------------------------------

/// Both Stage and Revoke require the caller's role to be permitted to
/// change `PolicyField::PendingProfiles` per `mutability`.
fn check_pending_mutability(
    record: &KeyRecord,
    ctx: &RequestContext,
) -> Result<CallerRole, String> {
    let role = match resolve_caller(&record.policy, ctx) {
        Some((_pref, role)) => role,
        None => return Err("caller is not in policy.principals".into()),
    };
    let m = &record.policy.mutability;
    let allowed = match role {
        CallerRole::Owner => &m.owner_can,
        CallerRole::Manager => &m.manager_can,
        CallerRole::Auditor | CallerRole::Tee => {
            return Err(format!(
                "caller role {:?} cannot stage/revoke pending profiles",
                role
            ));
        }
    };
    if m.immutable.contains(&PolicyField::PendingProfiles) {
        return Err("PolicyField::PendingProfiles is immutable on this key".into());
    }
    if !allowed.contains(&PolicyField::PendingProfiles) {
        return Err(format!(
            "caller role {:?} is not allowed to change PendingProfiles",
            role
        ));
    }
    Ok(role)
}

/// Who is staging a pending profile.
enum StagerIdentity {
    /// A key principal (owner, or a manager the Mutability rules permit).
    Principal(CallerRole),
    /// The PLATFORM: a verified manager-role bearer that matches no key
    /// principal. This is the staging-only capability from the
    /// enclave-upgrade design (item 2): after a runtime roll the platform
    /// may PROPOSE the new measurement on any key — staging authorises
    /// nothing by itself — while promote, revoke, export, update and every
    /// other operation still resolve through the key's own principals,
    /// where the platform deliberately has no slot.
    Platform,
}

/// Stage-only authority check. Principals go through the same Mutability
/// rules as [`check_pending_mutability`]; a non-principal manager-role
/// bearer is admitted as [`StagerIdentity::Platform`]. Revoke keeps using
/// `check_pending_mutability` — the platform must never drop an owner's
/// staged profile.
fn check_stage_authority(
    record: &KeyRecord,
    ctx: &RequestContext,
) -> Result<StagerIdentity, String> {
    if resolve_caller(&record.policy, ctx).is_some() {
        return check_pending_mutability(record, ctx).map(StagerIdentity::Principal);
    }
    let is_platform = ctx
        .oidc_claims
        .as_ref()
        .map(|c| c.is_manager)
        .unwrap_or(false);
    if !is_platform {
        return Err("caller is not in policy.principals".into());
    }
    // An owner who marked PendingProfiles immutable has explicitly frozen
    // the staging surface; that veto binds the platform too.
    if record
        .policy
        .mutability
        .immutable
        .contains(&PolicyField::PendingProfiles)
    {
        return Err("PolicyField::PendingProfiles is immutable on this key".into());
    }
    Ok(StagerIdentity::Platform)
}

fn handle_stage_pending(
    handle: &str,
    mut profile: AttestationProfile,
    source: PendingProfileSource,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    let stager = match check_stage_authority(&record, ctx) {
        Ok(s) => s,
        Err(e) => {
            let _ = audit_denial(ctx, 
                &mut record,
                "StagePendingProfile",
                &caller,
                AuditDecision::Denied,
                &e,
            );
            return VaultResponse::Error(e);
        }
    };
    normalise_profile(&mut profile);

    // Idempotent re-stage of an already-accepted profile: nothing pending,
    // nothing to promote. Platform sweeps re-stage on every roll; this must
    // not grow state or demand another owner approval.
    if record
        .policy
        .principals
        .tees
        .iter()
        .any(|p| matches!(p, Principal::Tee(t) if t == &profile))
    {
        return VaultResponse::PendingProfileStaged {
            pending_id: 0,
            auto_promoted: true,
            policy_version: record.policy_version,
        };
    }
    // Dedupe an identical already-pending profile: hand back its id.
    if let Some(existing) = record
        .pending_profiles
        .iter()
        .find(|p| p.profile == profile)
    {
        return VaultResponse::PendingProfileStaged {
            pending_id: existing.id,
            auto_promoted: false,
            policy_version: record.policy_version,
        };
    }

    let staged_by_platform = matches!(stager, StagerIdentity::Platform);
    // Auto-migrate acceptance (see `Lifecycle`): only for the PLATFORM
    // stager — `source` is caller-supplied and never trusted — and only a
    // runtime-only delta of a profile the owner already accepted. The
    // promote-time OID append/strengthen invariant is re-checked out of
    // defence in depth (equality of required_oids implies it).
    if staged_by_platform
        && record
            .policy
            .lifecycle
            .auto_migrate_to_next_attestation_profile
        && record.policy.principals.tees.iter().any(
            |p| matches!(p, Principal::Tee(t) if crate::policy::runtime_only_delta(&profile, t)),
        )
        && {
            let established = crate::policy::key_required_oids(&record.policy);
            established
                .iter()
                .all(|oid| profile.required_oids.iter().any(|r| &r.oid == oid))
        }
    {
        record
            .policy
            .principals
            .tees
            .push(Principal::Tee(profile));
        record.policy_version = record.policy_version.saturating_add(1);
        let new_tee_idx = record.policy.principals.tees.len() - 1;
        if let Err(e) = audit_and_save(
            &mut record,
            "AutoMigrateProfile",
            &caller,
            AuditDecision::Allowed,
            &format!("runtime-only delta -> tees[{}]", new_tee_idx),
        ) {
            return e;
        }
        return VaultResponse::PendingProfileStaged {
            pending_id: 0,
            auto_promoted: true,
            policy_version: record.policy_version,
        };
    }

    if record.pending_profiles.len() >= crate::types::MAX_PENDING_PROFILES {
        let msg = format!(
            "too many pending profiles (max {}): promote or revoke some first",
            crate::types::MAX_PENDING_PROFILES
        );
        let _ = audit_denial(ctx, 
            &mut record,
            "StagePendingProfile",
            &caller,
            AuditDecision::Denied,
            &msg,
        );
        return VaultResponse::Error(msg);
    }

    let staged_by_sub = ctx
        .oidc_claims
        .as_ref()
        .map(|c| c.sub.clone())
        .unwrap_or_else(|| "tee".into());
    let Some(staged_at) = now_secs() else {
        return VaultResponse::Error(NO_TRUSTED_TIME.into());
    };
    let pending_id = record.next_pending_id;
    record.next_pending_id = record.next_pending_id.saturating_add(1);
    record.pending_profiles.push(PendingProfile {
        id: pending_id,
        profile,
        // The platform's stage is always a platform build proposal,
        // whatever the caller claimed.
        source: if staged_by_platform {
            PendingProfileSource::PlatformBuild
        } else {
            source
        },
        staged_at,
        staged_by_sub,
        staged_by_platform,
    });

    if let Err(e) = audit_and_save(
        &mut record,
        "StagePendingProfile",
        &caller,
        AuditDecision::Allowed,
        &format!("id={}", pending_id),
    ) {
        return e;
    }
    let policy_version = record.policy_version;
    VaultResponse::PendingProfileStaged {
        pending_id,
        auto_promoted: false,
        policy_version,
    }
}

fn handle_list_pending(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        return VaultResponse::Error("caller is not in policy.principals".into());
    }
    VaultResponse::PendingProfileList {
        pending: record.pending_profiles,
    }
}

fn handle_promote_pending(
    handle: &str,
    pending_id: u32,
    approvals: &[ApprovalToken],
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);

    // Resolve the target pending profile up front so an `OidcStepUp`
    // `operation_bound` condition can be checked against THIS promote's
    // measurement + policy_version. If the id is unknown the binding is None,
    // which makes an operation-bound step-up fail closed inside evaluate_op
    // (and a non-bound policy still falls through to the not-found error below).
    let pos_opt = record
        .pending_profiles
        .iter()
        .position(|p| p.id == pending_id);
    let op_binding = pos_opt.map(|p| {
        let digest = crate::policy::profile_binding_digest(&record.pending_profiles[p].profile);
        crate::policy::OpBinding {
            measurement_digest_hex: digest.clone(),
            policy_version: record.policy_version,
            v1: true,
            v2: Some(crate::policy::OpBindingV2 {
                op: "promote",
                target: Ok(digest),
                members: binding.as_ref().map(|b| b.members.clone()),
            }),
        }
    });

    if let Err(e) = evaluate_op(
        &record.policy,
        record.policy_version,
        Operation::PromoteProfile,
        handle,
        approvals,
        ctx,
        op_binding.as_ref(),
    ) {
        let _ = audit_denial(ctx, 
            &mut record,
            "PromotePendingProfile",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }

    let pos = match pos_opt {
        Some(p) => p,
        None => {
            let msg = format!("pending profile id {} not found", pending_id);
            let _ = audit_denial(ctx, 
                &mut record,
                "PromotePendingProfile",
                &caller,
                AuditDecision::Denied,
                &msg,
            );
            return VaultResponse::Error(msg);
        }
    };
    // Append/strengthen-only: a promoted measurement must still carry every OID the
    // key already enforces, so a staged profile cannot silently downgrade an MR_APP
    // key to MR_ENCLAVE by omitting the app-id at 3.6. See the MR_APP sealing design.
    let missing_oid: Option<String> = {
        let established = crate::policy::key_required_oids(&record.policy);
        let promoted = &record.pending_profiles[pos].profile.required_oids;
        established
            .into_iter()
            .find(|oid| !promoted.iter().any(|r| &r.oid == oid))
    };
    if let Some(missing) = missing_oid {
        let msg = format!(
            "pending profile is missing required OID {}: required_oids are append/strengthen-only",
            missing
        );
        let _ = audit_denial(ctx, 
            &mut record,
            "PromotePendingProfile",
            &caller,
            AuditDecision::Denied,
            &msg,
        );
        return VaultResponse::Error(msg);
    }
    let pending = record.pending_profiles.remove(pos);
    record
        .policy
        .principals
        .tees
        .push(Principal::Tee(pending.profile));
    record.policy_version = record.policy_version.saturating_add(1);
    let new_tee_idx = record.policy.principals.tees.len() - 1;

    if let Err(e) = audit_and_save(
        &mut record,
        "PromotePendingProfile",
        &caller,
        AuditDecision::Allowed,
        &format!("id={} -> tees[{}]", pending_id, new_tee_idx),
    ) {
        return e;
    }
    VaultResponse::PendingProfilePromoted {
        policy_version: record.policy_version,
    }
}

fn handle_revoke_pending(handle: &str, pending_id: u32, ctx: &RequestContext) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    if let Err(e) = check_pending_mutability(&record, ctx) {
        let _ = audit_denial(ctx, 
            &mut record,
            "RevokePendingProfile",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }
    let before = record.pending_profiles.len();
    record.pending_profiles.retain(|p| p.id != pending_id);
    if record.pending_profiles.len() == before {
        let msg = format!("pending profile id {} not found", pending_id);
        let _ = audit_denial(ctx, 
            &mut record,
            "RevokePendingProfile",
            &caller,
            AuditDecision::Denied,
            &msg,
        );
        return VaultResponse::Error(msg);
    }
    if let Err(e) = audit_and_save(
        &mut record,
        "RevokePendingProfile",
        &caller,
        AuditDecision::Allowed,
        &format!("id={}", pending_id),
    ) {
        return e;
    }
    VaultResponse::PendingProfileRevoked
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Whether the key has expired. Without trusted time a key counts as
/// expired: fail closed.
pub(crate) fn expired(record: &KeyRecord) -> bool {
    now_secs().map_or(true, |now| now > record.expires_at)
}

fn owner_oidc_sub(owner: &Principal) -> Option<String> {
    match owner {
        Principal::Oidc { sub, .. } => Some(sub.clone()),
        Principal::Tee(_) | Principal::Fido2 { .. } => None,
    }
}

#[cfg(test)]
mod step1_tests {
    use super::*;

    #[test]
    fn delete_after_refuses_a_key_naming_itself_as_successor() {
        let after = crate::types::DeleteAfter {
            successor: "apps.privasys.org/x/k".into(),
            successor_target: "-".into(),
        };
        let mut old = record(None, 100);
        old.handle = "apps.privasys.org/x/k".into();
        let e = check_successor_succeeded(&old, &after).unwrap_err();
        assert!(e.contains("successor of itself"), "{e}");
    }

    /// Security: a created successor ("-") on this vault must be the same
    /// owner's and newer, or any live key would pass.
    #[test]
    fn delete_after_needs_a_newer_successor_of_the_same_owner() {
        let after = crate::types::DeleteAfter {
            successor: "apps.privasys.org/x/k2".into(),
            successor_target: "-".into(),
        };
        let mut old = record(None, 100);
        old.handle = "apps.privasys.org/x/k1".into();
        old.created_at = 10;
        let mut succ = record(None, 100);
        succ.handle = "apps.privasys.org/x/k2".into();
        succ.created_at = 20;
        assert!(successor_check(&old, &after, Some(&succ), Some(50)).is_ok());
        // On another constellation: not visible here, the client's word.
        assert!(successor_check(&old, &after, None, Some(50)).is_ok());

        let mut other = succ.clone();
        other.policy.principals.owner = Principal::Oidc {
            issuer: "https://privasys.id".into(),
            sub: "someone-else".into(),
            required_roles: vec![],
        };
        let e = successor_check(&old, &after, Some(&other), Some(50)).unwrap_err();
        assert!(e.contains("another owner"), "{e}");

        let mut older = succ.clone();
        older.created_at = 10;
        let e = successor_check(&old, &after, Some(&older), Some(50)).unwrap_err();
        assert!(e.contains("not newer"), "{e}");

        let e = successor_check(&old, &after, Some(&succ), Some(101)).unwrap_err();
        assert!(e.contains("expired"), "{e}");
    }

    fn record(renewed_in_place_from: Option<&str>, expires_at: u64) -> KeyRecord {
        let policy: KeyPolicy = serde_json::from_str(
            r#"{"version":1,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"o","required_roles":[]}},"managers":[],"auditors":[],"tees":[]},"operations":[]}"#,
        )
        .unwrap();
        KeyRecord {
            handle: "x".into(),
            key_type: KeyType::RawShare,
            exportable: true,
            material: vec![1],
            public_key: None,
            policy,
            policy_version: 1,
            created_at: 0,
            expires_at,
            pending_profiles: Vec::new(),
            audit_next_seq: 0,
            next_pending_id: 0,
            threshold_vaults: Vec::new(),
            key_check: None,
            renewed_in_place_from: renewed_in_place_from.map(String::from),
        }
    }

    /// Security's forged-link case: an enclave named by K's policy creates X
    /// on K's vaults with a carried policy naming K as predecessor, then asks
    /// to retire K. A carried create records no in-place link, so X never
    /// supersedes K, and only a live in-place renewal of K does.
    #[test]
    fn only_a_live_in_place_renewal_supersedes_a_key() {
        let k = "apps.privasys.org/x/data-v1";
        let carried = record(None, 100);
        assert!(!superseded_in_place_at(k, &carried, Some(50)));
        let in_place = record(Some(k), 100);
        assert!(superseded_in_place_at(k, &in_place, Some(50)));
        assert!(!superseded_in_place_at(k, &in_place, Some(101)), "an expired successor");
        assert!(!superseded_in_place_at(k, &in_place, None), "no trusted time");
        assert!(!superseded_in_place_at("apps.privasys.org/x/other", &in_place, Some(50)));
    }

    #[test]
    fn an_in_place_renewal_keeps_a_whole_key_value() {
        assert!(check_same_value(KeyType::Aes256GcmKey, &[1; 32], &[1; 32]).is_ok());
        assert!(check_same_value(KeyType::Aes256GcmKey, &[1; 32], &[2; 32]).is_err());
        assert!(check_same_value(KeyType::HmacSha256Key, &[1; 32], &[1; 33]).is_err());
        // A Shamir share is fresh by design: the value is whole only across vaults.
        assert!(check_same_value(KeyType::RawShare, &[1; 32], &[2; 32]).is_ok());
    }

    #[test]
    fn handle_generations() {
        assert!(is_generation_handle("users/s/secret/gen-2"));
        assert!(is_generation_handle("users/s/secret/gen-12"));
        assert!(!is_generation_handle("users/s/secret"));
        assert!(!is_generation_handle("users/s/secret/gen-"));
        assert!(!is_generation_handle("users/s/secret/gen-2x"));
        assert!(!is_generation_handle("users/s/gen-2/secret"));
        // The control plane's and Drive's generations stay ordinary creations.
        assert!(!is_generation_handle("apps.privasys.org/x/storage-kek/v2"));
        assert!(!is_generation_handle("users/s/data/o/mek/v7"));
    }
}
