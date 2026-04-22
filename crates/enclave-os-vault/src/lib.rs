// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os \u2014 HSM-shaped key store inside SGX/TDX.
//!
//! Callers manipulate **keys** (handle + type + material + policy).
//! Access is gated by [`KeyPolicy`] which lists named principals
//! ([`PrincipalSet`]) and the operations each is allowed to perform
//! ([`OperationRule`]). Remote TEE callers authenticate via mutual
//! RA-TLS with bidirectional challenge-response (always on).
//!
//! See `docs/vault.md` for the full design and `Cargo.toml` for
//! dependencies. Phase 1 only implements [`KeyType::RawShare`];
//! signing / wrapping / derivation will land with their respective
//! operations.

pub mod policy;
pub mod quote;
pub mod types;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_kvstore::SealedKvStore;

use crate::policy::{evaluate_op, evaluate_policy_update, resolve_caller};
use crate::types::{
    KeyInfo, KeyListEntry, KeyPolicy, KeyRecord, KeyType, Operation, Principal, VaultRequest,
    VaultResponse, DEFAULT_KEY_TTL_SECONDS, MAX_KEY_TTL_SECONDS,
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
            VaultRequest::ExportKey { handle } => handle_export(&handle, ctx),
            VaultRequest::DeleteKey { handle } => handle_delete(&handle, ctx),
            VaultRequest::UpdatePolicy { handle, new_policy } => {
                handle_update_policy(&handle, new_policy, ctx)
            }
            VaultRequest::GetPolicy { handle } => handle_get_policy(&handle, ctx),
            VaultRequest::GetKeyInfo { handle } => handle_get_info(&handle, ctx),
            VaultRequest::ListKeys => handle_list(ctx),
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

/// Sealed KV key for a stored key record: `key:<handle>`.
fn record_key(handle: &str) -> Vec<u8> {
    format!("key:{}", handle).into_bytes()
}

/// Sealed KV key for the per-owner handle index: `index:<oidc_sub>`.
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
    let bytes =
        serde_json::to_vec(&handles).map_err(|e| format!("serialise index: {e}"))?;
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
    let bytes =
        serde_json::to_vec(&handles).map_err(|e| format!("serialise index: {e}"))?;
    store.put(&key, &bytes)
}

// ---------------------------------------------------------------------------
//  KV access helpers
// ---------------------------------------------------------------------------

/// Acquire the global sealed KV store handle, returning a vault error on failure.
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

fn save_record(record: &KeyRecord) -> Result<(), VaultResponse> {
    let kv = kv()?;
    let bytes = serde_json::to_vec(record)
        .map_err(|e| VaultResponse::Error(format!("serialise record: {e}")))?;
    let store = kv
        .lock()
        .map_err(|_| VaultResponse::Error("kv store lock poisoned".into()))?;
    store
        .put(&record_key(&record.handle), &bytes)
        .map_err(|e| VaultResponse::Error(format!("kv put failed: {e}")))
}

// ---------------------------------------------------------------------------
//  Time
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}

// ---------------------------------------------------------------------------
//  Policy normalisation
// ---------------------------------------------------------------------------

fn normalise_policy(mut policy: KeyPolicy) -> KeyPolicy {
    // TTL bounds.
    if policy.lifecycle.ttl_seconds == 0 {
        policy.lifecycle.ttl_seconds = DEFAULT_KEY_TTL_SECONDS;
    }
    if policy.lifecycle.ttl_seconds > MAX_KEY_TTL_SECONDS {
        policy.lifecycle.ttl_seconds = MAX_KEY_TTL_SECONDS;
    }
    // Lowercase hex measurements + OID values.
    let principals = std::iter::once(&mut policy.principals.owner)
        .chain(policy.principals.managers.iter_mut())
        .chain(policy.principals.auditors.iter_mut())
        .chain(policy.principals.tees.iter_mut());
    for p in principals {
        if let Principal::Tee(profile) = p {
            for m in &mut profile.measurements {
                match m {
                    crate::types::Measurement::Mrenclave(s)
                    | crate::types::Measurement::Mrtd(s) => {
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
    }
    policy
}

// ---------------------------------------------------------------------------
//  Handlers
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

    // The caller must authenticate as the owner declared in the policy.
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

    let policy = normalise_policy(policy);
    let now = now_secs();
    let expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);

    // Reject if handle already exists.
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

    let record = KeyRecord {
        handle: handle.to_string(),
        key_type,
        exportable,
        material,
        policy,
        policy_version: 1,
        created_at: now,
        expires_at,
    };

    if let Err(e) = save_record(&record) {
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

fn handle_export(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }
    if !record.exportable {
        return VaultResponse::Error("key is not exportable".into());
    }
    match evaluate_op(&record.policy, Operation::ExportKey, ctx) {
        Ok(()) => VaultResponse::KeyMaterial {
            material: record.material,
            expires_at: record.expires_at,
        },
        Err(e) => VaultResponse::Error(e),
    }
}

fn handle_delete(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if let Err(e) = evaluate_op(&record.policy, Operation::DeleteKey, ctx) {
        return VaultResponse::Error(e);
    }

    let owner_sub = match owner_oidc_sub(&record.policy.principals.owner) {
        Some(s) => s,
        None => return VaultResponse::Error("policy owner is not OIDC; cannot index".into()),
    };

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
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_record(handle) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }

    // First, the caller must be allowed to perform UpdatePolicy at all.
    if let Err(e) = evaluate_op(&record.policy, Operation::UpdatePolicy, ctx) {
        return VaultResponse::Error(e);
    }
    // Then, identify caller's role and validate the diff against `mutability`.
    let role = match resolve_caller(&record.policy, ctx) {
        Some((_pref, role)) => role,
        None => return VaultResponse::Error("caller is not in policy.principals".into()),
    };
    let new_policy = normalise_policy(new_policy);
    if let Err(e) = evaluate_policy_update(&record.policy, &new_policy, role) {
        return VaultResponse::Error(e);
    }

    record.policy = new_policy;
    record.policy_version = record.policy_version.saturating_add(1);

    if let Err(e) = save_record(&record) {
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
    // Any principal in the set may read the policy.
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
        } => {
            // Issuer is enforced by the auth layer (single global OIDC config
            // verifies all bearer tokens). Sub + role match here.
            sub == &claims.sub && policy::has_required_roles(claims, required_roles)
        }
        Principal::Tee(_) => false,
    }
}

fn owner_oidc_sub(owner: &Principal) -> Option<String> {
    match owner {
        Principal::Oidc { sub, .. } => Some(sub.clone()),
        Principal::Tee(_) => None,
    }
}
