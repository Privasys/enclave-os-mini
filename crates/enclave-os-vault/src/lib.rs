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
pub mod policy;
pub mod quote;
pub mod signing;
pub mod types;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_kvstore::SealedKvStore;

use crate::policy::{evaluate_op, evaluate_policy_update, resolve_caller, CallerRole};

use crate::types::{
    ApprovalToken, AttestationProfile, AuditDecision, KeyInfo, KeyListEntry, KeyPolicy, KeyRecord,
    KeyType, Operation, PendingProfile, PendingProfileSource, PolicyField, Principal,
    VaultRequest, VaultResponse, DEFAULT_APPROVAL_TOKEN_TTL_SECONDS, DEFAULT_KEY_TTL_SECONDS,
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
                key_type,
                material_b64,
                exportable,
                policy,
            } => handle_create(&handle, key_type, &material_b64, exportable, policy, ctx),
            VaultRequest::ExportKey { handle, approvals } => {
                handle_export(&handle, &approvals, ctx)
            }
            VaultRequest::DeleteKey { handle, approvals } => {
                handle_delete(&handle, &approvals, ctx)
            }
            VaultRequest::UpdatePolicy {
                handle,
                new_policy,
                approvals,
            } => handle_update_policy(&handle, new_policy, &approvals, ctx),
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
                approvals,
            } => handle_sign(&handle, &message_b64, &approvals, ctx),
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
            VaultRequest::ListPendingProfiles { handle } => {
                handle_list_pending(&handle, ctx)
            }
            VaultRequest::PromotePendingProfile {
                handle,
                pending_id,
                approvals,
            } => handle_promote_pending(&handle, pending_id, &approvals, ctx),
            VaultRequest::RevokePendingProfile { handle, pending_id } => {
                handle_revoke_pending(&handle, pending_id, ctx)
            }
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

fn record_key(handle: &str) -> Vec<u8> {
    format!("key:{}", handle).into_bytes()
}

fn owner_index_key(owner_sub: &str) -> Vec<u8> {
    format!("index:{}", owner_sub).into_bytes()
}

fn add_to_owner_index(
    store: &SealedKvStore,
    owner_sub: &str,
    handle: &str,
) -> Result<(), String> {
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

fn kv() -> Result<&'static std::sync::Mutex<SealedKvStore>, VaultResponse> {
    enclave_os_kvstore::kv_store()
        .ok_or_else(|| VaultResponse::Error("kv store not initialised".into()))
}

fn load_record(handle: &str) -> Result<KeyRecord, VaultResponse> {
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

fn now_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}

// ---------------------------------------------------------------------------
//  Audit
// ---------------------------------------------------------------------------

/// Append one audit entry to `record` and save the record. Used by every
/// op handler after a policy decision has been made.
fn audit_and_save(
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

fn caller_str(ctx: &RequestContext) -> String {
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

fn normalise_policy(mut policy: KeyPolicy) -> KeyPolicy {
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
            crate::types::Measurement::Mrenclave(s) | crate::types::Measurement::Mrtd(s) => {
                *s = s.to_lowercase();
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

fn handle_create(
    handle: &str,
    key_type: KeyType,
    material_b64: &str,
    exportable: bool,
    policy: KeyPolicy,
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

    let claims = match ctx.oidc_claims.as_ref() {
        Some(c) => c,
        None => {
            return VaultResponse::Error(
                "OIDC authentication required to create a key".into(),
            )
        }
    };
    if !owner_matches_oidc(&policy.principals.owner, claims) {
        return VaultResponse::Error(
            "caller's OIDC identity does not match policy.principals.owner".into(),
        );
    }
    let owner_sub = claims.sub.clone();

    let material = match URL_SAFE_NO_PAD.decode(material_b64) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return VaultResponse::Error("material must not be empty".into()),
        Err(e) => return VaultResponse::Error(format!("bad base64: {e}")),
    };

    let public_key = match crypto::validate_material(key_type, &material) {
        Ok(p) => p,
        Err(e) => return VaultResponse::Error(e),
    };

    let policy = normalise_policy(policy);
    let now = now_secs();
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
        policy_version: 1,
        created_at: now,
        expires_at,
        pending_profiles: Vec::new(),
        audit_next_seq: 0,
        next_pending_id: 0,
    };

    if let Err(e) = audit_and_save(
        &mut record,
        "CreateKey",
        &format!("oidc:{}", owner_sub),
        AuditDecision::Allowed,
        "",
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
    match evaluate_op(&record.policy, Operation::ExportKey, handle, approvals, ctx) {
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
            let _ = audit_and_save(
                &mut record,
                "ExportKey",
                &caller,
                AuditDecision::Denied,
                &e,
            );
            VaultResponse::Error(e)
        }
    }
}

fn handle_delete(
    handle: &str,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    if let Err(e) = evaluate_op(&record.policy, Operation::DeleteKey, handle, approvals, ctx) {
        let _ = audit_and_save(
            &mut record,
            "DeleteKey",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }

    let owner_sub = match owner_oidc_sub(&record.policy.principals.owner) {
        Some(s) => s,
        None => return VaultResponse::Error("policy owner is not OIDC; cannot index".into()),
    };

    // Audit before delete so the entry survives... but the record itself
    // is about to disappear, so the audit chain for this key dies too.
    // That's acceptable: deletion is final and auditors should snapshot
    // the log before it goes.
    let _ = audit_and_save(&mut record, "DeleteKey", &caller, AuditDecision::Allowed, "");

    let kv = match kv() {
        Ok(k) => k,
        Err(e) => return e,
    };
    let mut store = match kv.lock() {
        Ok(s) => s,
        Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
    };
    if let Err(e) = store.delete(&record_key(handle)) {
        return VaultResponse::Error(format!("kv delete failed: {e}"));
    }
    let _ = remove_from_owner_index(&store, &owner_sub, handle);
    VaultResponse::KeyDeleted
}

fn handle_update_policy(
    handle: &str,
    new_policy: KeyPolicy,
    approvals: &[ApprovalToken],
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

    if let Err(e) = evaluate_op(
        &record.policy,
        Operation::UpdatePolicy,
        handle,
        approvals,
        ctx,
    ) {
        let _ = audit_and_save(
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
        None => {
            return VaultResponse::Error(
                "caller is not in policy.principals".into(),
            )
        }
    };
    let new_policy = normalise_policy(new_policy);
    if let Err(e) = evaluate_policy_update(&record.policy, &new_policy, role) {
        let _ = audit_and_save(
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
    VaultResponse::KeyInfo(KeyInfo {
        handle: record.handle,
        key_type: record.key_type,
        exportable: record.exportable,
        created_at: record.created_at,
        expires_at: record.expires_at,
        policy_version: record.policy_version,
        public_key: record.public_key,
    })
}

fn handle_list(ctx: &RequestContext) -> VaultResponse {
    let claims = match ctx.oidc_claims.as_ref() {
        Some(c) => c,
        None => {
            return VaultResponse::Error("OIDC authentication required to list keys".into())
        }
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
fn require_op(
    handle: &str,
    op: Operation,
    expect_type: KeyType,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> Result<KeyRecord, VaultResponse> {
    let mut record = load_record(handle)?;
    if expired(&record) {
        let _ = audit_and_save(
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
        let _ = audit_and_save(
            &mut record,
            op_name(op),
            &caller_str(ctx),
            AuditDecision::Denied,
            &msg,
        );
        return Err(VaultResponse::Error(msg));
    }
    let caller = caller_str(ctx);
    if let Err(e) = evaluate_op(&record.policy, op, handle, approvals, ctx) {
        let _ = audit_and_save(
            &mut record,
            op_name(op),
            &caller,
            AuditDecision::Denied,
            &e,
        );
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
    let record =
        match require_op(handle, Operation::Wrap, KeyType::Aes256GcmKey, approvals, ctx) {
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
    let iv_vec = match iv_b64 {
        Some(s) => match URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => Some(b),
            Err(e) => return VaultResponse::Error(format!("iv base64: {e}")),
        },
        None => None,
    };
    match crypto::aes_gcm_seal(&record.material, &plaintext, &aad, iv_vec.as_deref()) {
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
    let record =
        match require_op(handle, Operation::Unwrap, KeyType::Aes256GcmKey, approvals, ctx) {
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
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
) -> VaultResponse {
    let record =
        match require_op(handle, Operation::Sign, KeyType::P256SigningKey, approvals, ctx) {
            Ok(r) => r,
            Err(e) => return e,
        };
    let message = match URL_SAFE_NO_PAD.decode(message_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("message base64: {e}")),
    };
    match crypto::p256_sign(&record.material, &message) {
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
    let record =
        match require_op(handle, Operation::Mac, KeyType::HmacSha256Key, approvals, ctx) {
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
            let _ = audit_and_save(
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
    let mgr_idx = match record
        .policy
        .principals
        .managers
        .iter()
        .position(|p| match p {
            Principal::Oidc { sub, .. } => sub == &claims.sub,
            _ => false,
        }) {
        Some(i) => i as u32,
        None => {
            let msg = "caller is not an OIDC manager of this key".to_string();
            let _ = audit_and_save(
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
    let now = now_secs();

    let token = {
        let kv = match kv() {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        match signing::issue_approval_token(&mut store, handle, op, mgr_idx, now, ttl) {
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
    let (entries, next_seq) = match audit::read(
        &store,
        handle,
        record.audit_next_seq,
        since_seq,
        limit,
    ) {
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
    if let Err(e) = check_pending_mutability(&record, ctx) {
        let _ = audit_and_save(
            &mut record,
            "StagePendingProfile",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }
    normalise_profile(&mut profile);

    let staged_by_sub = ctx
        .oidc_claims
        .as_ref()
        .map(|c| c.sub.clone())
        .unwrap_or_else(|| "tee".into());
    let pending_id = record.next_pending_id;
    record.next_pending_id = record.next_pending_id.saturating_add(1);
    record.pending_profiles.push(PendingProfile {
        id: pending_id,
        profile,
        source,
        staged_at: now_secs(),
        staged_by_sub,
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
    VaultResponse::PendingProfileStaged { pending_id }
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
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);

    if let Err(e) = evaluate_op(
        &record.policy,
        Operation::PromoteProfile,
        handle,
        approvals,
        ctx,
    ) {
        let _ = audit_and_save(
            &mut record,
            "PromotePendingProfile",
            &caller,
            AuditDecision::Denied,
            &e,
        );
        return VaultResponse::Error(e);
    }

    let pos = match record.pending_profiles.iter().position(|p| p.id == pending_id) {
        Some(p) => p,
        None => {
            let msg = format!("pending profile id {} not found", pending_id);
            let _ = audit_and_save(
                &mut record,
                "PromotePendingProfile",
                &caller,
                AuditDecision::Denied,
                &msg,
            );
            return VaultResponse::Error(msg);
        }
    };
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

fn handle_revoke_pending(
    handle: &str,
    pending_id: u32,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    if let Err(e) = check_pending_mutability(&record, ctx) {
        let _ = audit_and_save(
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
        let _ = audit_and_save(
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

fn expired(record: &KeyRecord) -> bool {
    now_secs() > record.expires_at
}

fn owner_matches_oidc(
    owner: &Principal,
    claims: &enclave_os_common::oidc::OidcClaims,
) -> bool {
    match owner {
        Principal::Oidc {
            issuer: _,
            sub,
            required_roles,
        } => sub == &claims.sub && policy::has_required_roles(claims, required_roles),
        Principal::Tee(_) | Principal::Fido2 { .. } => false,
    }
}

fn owner_oidc_sub(owner: &Principal) -> Option<String> {
    match owner {
        Principal::Oidc { sub, .. } => Some(sub.clone()),
        Principal::Tee(_) | Principal::Fido2 { .. } => None,
    }
}
