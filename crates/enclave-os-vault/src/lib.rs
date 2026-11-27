// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os — HSM-shaped key store inside SGX/TDX.
//!
//! Callers manipulate **keys** (handle + type + material + policy).
//! Access is gated by [`KeyPolicy`] which lists named principals
//! ([`PrincipalSet`]) and the operations each is allowed to perform
//! ([`OperationRule`]). Operations may also carry [`Condition`]s (an
//! operation-bound wallet approval) that tighten the grant. Remote TEE
//! callers authenticate via mutual RA-TLS with bidirectional
//! challenge-response (always on).
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
pub mod tomb;
pub mod types;
pub mod v2;

mod create;
mod delete;
mod ops;
mod pending;
mod read;
mod rules;

pub use create::{CAPABILITY_GENERATIONS, CAPABILITY_UPDATE_FROM};
use create::*;
use delete::*;
use ops::*;
use pending::*;
use read::*;
use rules::*;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_kvstore::SealedKvStore;

use crate::policy::{evaluate_op, evaluate_policy_update, resolve_caller, CallerRole};

use crate::types::{
    AttestationProfile, AuditDecision, BindingV2Request, KeyInfo, KeyListEntry, KeyPolicy, KeyRecord,
    KeyType, Operation, PendingProfile, PolicyField, Principal, VaultRequest,
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

        housekeeping();

        let resp = match vault_req {
            VaultRequest::CreateKey {
                handle,
                material_b64,
                grant,
                predecessor,
                policy,
                policy_version,
                source_billing_id,
                key_check,
                carried_exportable,
                carried_key_type,
                binding,
            } => handle_create(
                &handle,
                &material_b64,
                &grant,
                CreateExtras {
                    predecessor,
                    policy,
                    policy_version,
                    source_billing_id,
                    key_check,
                    carried_exportable,
                    carried_key_type,
                    binding,
                },
                ctx,
            ),
            VaultRequest::ExportKey {
                handle,
                binding,
            } => handle_export(&handle, binding, ctx),
            VaultRequest::DeleteKey {
                handle,
                binding,
                after,
            } => handle_delete(&handle, binding, after, ctx),
            VaultRequest::RetireKey {
                handle,
                successor,
                successor_members,
            } => handle_retire(&handle, &successor, &successor_members, ctx),
            VaultRequest::UpdatePolicy {
                handle,
                new_policy,
                binding,
            } => handle_update_policy(&handle, &new_policy, binding, ctx),
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
            } => handle_wrap(
                &handle,
                &plaintext_b64,
                aad_b64.as_deref(),
                iv_b64.as_deref(),
                ctx,
            ),
            VaultRequest::Unwrap {
                handle,
                ciphertext_b64,
                iv_b64,
                aad_b64,
            } => handle_unwrap(
                &handle,
                &ciphertext_b64,
                &iv_b64,
                aad_b64.as_deref(),
                ctx,
            ),
            VaultRequest::Sign {
                handle,
                message_b64,
                prehashed,
            } => handle_sign(&handle, &message_b64, prehashed, ctx),
            VaultRequest::Mac {
                handle,
                message_b64,
            } => handle_mac(&handle, &message_b64, ctx),

            VaultRequest::ReadAuditLog {
                handle,
                since_seq,
                limit,
            } => handle_read_audit(&handle, since_seq, limit, ctx),

            VaultRequest::StagePendingProfile {
                handle,
                profile,
            } => handle_stage_pending(&handle, profile, ctx),
            VaultRequest::ListPendingProfiles { handle } => handle_list_pending(&handle, ctx),
            VaultRequest::PromotePendingProfile {
                handle,
                pending_id,
                binding,
            } => handle_promote_pending(&handle, pending_id, binding, ctx),
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

pub(crate) fn remove_from_owner_index(
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

/// Find a handle as it stands, finishing a cut-short deletion or purging an
/// expired tombstone on the way (wire formats §9.3).
pub(crate) fn lookup(handle: &str) -> Result<tomb::Lookup, VaultResponse> {
    let kv = kv()?;
    let mut store = kv
        .lock()
        .map_err(|_| VaultResponse::Error("kv store lock poisoned".into()))?;
    tomb::lookup(&mut store, handle, now_secs()).map_err(VaultResponse::Error)
}

/// A live key's record, for the vault's own use (a predecessor, a successor,
/// a threshold session already authorised). A deleted key is "not found".
pub(crate) fn load_record(handle: &str) -> Result<KeyRecord, VaultResponse> {
    match lookup(handle)? {
        tomb::Lookup::Live(r) => Ok(r),
        _ => Err(VaultResponse::Error("key not found".into())),
    }
}

/// Whether `ctx` may learn about a key under `policy`: one of its principals,
/// or the platform's manager bearer (which stages profiles).
fn may_see(policy: &KeyPolicy, ctx: &RequestContext) -> bool {
    resolve_caller(policy, ctx).is_some()
        || ctx.oidc_claims.as_ref().map_or(false, |c| c.is_manager)
}

/// A key's record for a request by `ctx`. Anyone outside the key's policy
/// gets the same answer for a live key and a deleted one (no existence
/// oracle); the key's principals learn that it was deleted.
pub(crate) fn load_for(handle: &str, ctx: &RequestContext) -> Result<KeyRecord, VaultResponse> {
    match lookup(handle)? {
        tomb::Lookup::Live(r) if may_see(&r.policy, ctx) => Ok(r),
        tomb::Lookup::Live(_) => {
            UNAUDITED_DENIALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Err(VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into()))
        }
        tomb::Lookup::Deleted(t) if may_see(&t.final_policy, ctx) => {
            Err(VaultResponse::Error(tomb::deleted_message(&t)))
        }
        tomb::Lookup::Deleted(_) => Err(VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into())),
        tomb::Lookup::Missing => Err(VaultResponse::Error("key not found".into())),
    }
}

/// Refuse to create `handle` while it has a tombstone or a key. Every
/// creation path calls this.
pub(crate) fn check_handle_free(handle: &str) -> Result<(), String> {
    match lookup(handle).map_err(response_text)? {
        tomb::Lookup::Missing => Ok(()),
        tomb::Lookup::Live(_) => Err("handle already exists".into()),
        tomb::Lookup::Deleted(t) => Err(tomb::creation_refusal(&t)),
    }
}

pub(crate) fn response_text(r: VaultResponse) -> String {
    match r {
        VaultResponse::Error(e) => e,
        _ => "unexpected vault response".into(),
    }
}

/// Seconds between two housekeeping passes.
const HOUSEKEEPING_EVERY: u64 = 300;
static LAST_HOUSEKEEPING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Finish cut-short deletions and purge expired tombstones, at most every
/// [`HOUSEKEEPING_EVERY`] seconds, on the back of ordinary requests.
fn housekeeping() {
    let Some(now) = now_secs() else { return };
    let last = LAST_HOUSEKEEPING.load(core::sync::atomic::Ordering::Relaxed);
    if now < last.saturating_add(HOUSEKEEPING_EVERY) {
        return;
    }
    LAST_HOUSEKEEPING.store(now, core::sync::atomic::Ordering::Relaxed);
    let Ok(kv) = kv() else { return };
    if let Ok(mut store) = kv.lock() {
        tomb::housekeep(&mut store, Some(now), tomb::HOUSEKEEPING_BATCH);
    }
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
//  Helpers
// ---------------------------------------------------------------------------

/// SHA-256 of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Whether any rule granting `op` asks for a binding v2 step-up.
fn rule_takes_binding_v2(policy: &KeyPolicy, op: Operation) -> bool {
    policy.operations.iter().filter(|r| r.ops.contains(&op)).any(|r| {
        r.requires
            .iter()
            .any(|c| matches!(c, crate::types::Condition::OidcStepUp { binding: 2, .. }))
    })
}

/// Whether the key has expired. Without trusted time a key counts as
/// expired: fail closed.
pub(crate) fn expired(record: &KeyRecord) -> bool {
    now_secs().map_or(true, |now| now > record.expires_at)
}

pub(crate) fn owner_oidc_sub(owner: &Principal) -> Option<String> {
    match owner {
        Principal::Oidc { sub, .. } => Some(sub.clone()),
        Principal::Tee(_) => None,
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

    /// A created successor ("-") on this vault must be the same
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
            created_by_owner_approval: false,
            pending_creation: None,
        }
    }

    /// The forged-link case: an enclave named by K's policy creates X
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

#[cfg(test)]
mod tombstone_tests {
    //! Formats §9.3 and §9.3.1 against an in-memory host.
    use super::*;
    use enclave_os_common::modules::AppIdentity;
    use enclave_os_common::ocall::{self, OcallVtable};
    use enclave_os_common::rpc::KvBatchOp;
    use std::collections::HashMap;
    use std::sync::{Mutex, Once};

    type Host = HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>;
    static HOST: Mutex<Option<Host>> = Mutex::new(None);
    static INIT: Once = Once::new();
    const NOW: u64 = 1_000_000;

    fn put(t: &[u8], k: &[u8], v: &[u8]) -> Result<(), i32> {
        HOST.lock().unwrap().get_or_insert_with(HashMap::new).insert((t.to_vec(), k.to_vec()), v.to_vec());
        Ok(())
    }
    fn get(t: &[u8], k: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        Ok(HOST.lock().unwrap().as_ref().and_then(|m| m.get(&(t.to_vec(), k.to_vec())).cloned()))
    }
    fn del(t: &[u8], k: &[u8]) -> Result<bool, i32> {
        Ok(HOST.lock().unwrap().as_mut().is_some_and(|m| m.remove(&(t.to_vec(), k.to_vec())).is_some()))
    }
    fn unused<T>() -> Result<T, i32> {
        Err(-1)
    }

    /// One host and one vault store for the whole test binary; every test
    /// uses its own handles.
    fn init() {
        INIT.call_once(|| {
            ocall::register(OcallVtable {
                net_tcp_listen: |_, _| unused(),
                net_tcp_accept: |_| unused(),
                net_tcp_connect: |_, _| unused(),
                net_send: |_, _| unused(),
                net_recv: |_, _| unused(),
                net_close: |_| {},
                net_udp_bind: |_, _| unused(),
                net_udp_send_to: |_, _, _, _| unused(),
                net_udp_recv_from: |_, _, _| unused(),
                net_udp_close: |_| {},
                kv_store_put: put,
                kv_store_get: get,
                kv_store_delete: del,
                kv_store_list_keys: |_, _| unused(),
                kv_store_write_batch: |_, _: &[KvBatchOp]| unused(),
                kv_store_multi_get: |_, _| unused(),
                kv_store_scan: |_, _, _, _| unused(),
                get_current_time: || Ok(NOW),
                get_current_time_ms: || Ok(NOW * 1000),
                log: |_, _| {},
                cert_store_register: |_: AppIdentity| {},
                cert_store_unregister: |_| false,
            });
            let _ = enclave_os_kvstore::KvStoreModule::new([9u8; 32]).unwrap();
            enclave_os_common::oidc::set_global_oidc_config(
                serde_json::from_value(serde_json::json!({
                    "issuer": "https://privasys.id", "audience": "privasys-platform"
                }))
                .unwrap(),
            );
        });
    }

    fn ctx(sub: &str) -> RequestContext {
        RequestContext {
            peer_cert_der: None,
            peer_evidence: None,
            attestation: "none".into(),
            oidc_claims: Some(
                serde_json::from_value(serde_json::json!({
                    "sub": sub, "roles": [], "is_manager": false, "is_monitoring": false
                }))
                .unwrap(),
            ),
            fido2_user: None,
            app_name: None,
        }
    }

    fn alice_policy(ops: serde_json::Value) -> KeyPolicy {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "principals": {
                "owner": {"Oidc": {"issuer": "https://privasys.id", "sub": "alice", "required_roles": []}},
                "managers": [], "auditors": [], "tees": []
            },
            "operations": ops
        }))
        .unwrap()
    }

    /// A key alice owns and may delete and export with no approval.
    fn put_key(handle: &str) {
        init();
        let policy = alice_policy(serde_json::json!([
            {"ops": ["DeleteKey", "ExportKey"], "principals": ["Owner"], "requires": []}
        ]));
        let mut record = KeyRecord {
            handle: handle.into(),
            key_type: KeyType::RawShare,
            exportable: true,
            material: vec![42],
            public_key: None,
            policy,
            policy_version: 1,
            created_at: NOW - 10,
            expires_at: NOW + 1000,
            pending_profiles: Vec::new(),
            audit_next_seq: 0,
            next_pending_id: 0,
            threshold_vaults: Vec::new(),
            key_check: None,
            renewed_in_place_from: None,
            created_by_owner_approval: false,
            pending_creation: None,
        };
        audit_and_save(&mut record, "CreateKey", "oidc:alice", AuditDecision::Allowed, "").unwrap();
        let store = kv().unwrap().lock().unwrap();
        add_to_owner_index(&store, "alice", handle).unwrap();
    }

    fn err(r: VaultResponse) -> String {
        match r {
            VaultResponse::Error(e) => e,
            other => panic!("expected an error, got {}", serde_json::to_string(&other).unwrap()),
        }
    }

    fn raw_record(handle: &str) -> Option<Vec<u8>> {
        kv().unwrap().lock().unwrap().get(&record_key(handle)).unwrap()
    }

    fn deleted(h: &str) {
        assert!(matches!(handle_delete(h, None, None, &ctx("alice")), VaultResponse::KeyDeleted));
    }

    #[test]
    fn a_delete_leaves_a_tombstone_and_no_material() {
        let h = "users/alice/t1";
        put_key(h);
        deleted(h);
        assert!(raw_record(h).is_none(), "the record and its material are gone");

        // Its principals read the tombstone and the log.
        match handle_get_info(h, &ctx("alice")) {
            VaultResponse::KeyTombstone { op, successor, deleted_at, expires_at, .. } => {
                assert_eq!(
                    (op.as_str(), successor.as_str(), deleted_at, expires_at),
                    ("delete", "-", NOW, NOW + 1000)
                );
            }
            other => panic!("{}", serde_json::to_string(&other).unwrap()),
        }
        match handle_read_audit(h, 0, 0, &ctx("alice")) {
            VaultResponse::AuditLog { entries, next_seq } => {
                assert_eq!(next_seq, 2);
                assert_eq!(entries.last().unwrap().op, "DeleteKey");
            }
            other => panic!("{}", serde_json::to_string(&other).unwrap()),
        }
        // Every other operation: "key deleted", distinct from "not found".
        let e = err(handle_export(h, None, &ctx("alice")));
        assert!(e.starts_with("key deleted"), "{e}");
        let e = err(handle_delete(h, None, None, &ctx("alice")));
        assert!(e.starts_with("key deleted"), "{e}");
        // Not listed.
        match handle_list(&ctx("alice")) {
            VaultResponse::KeyList { keys } => assert!(keys.iter().all(|k| k.handle != h)),
            _ => panic!("expected a key list"),
        }
        // Not creatable again, on any path (they all call this).
        let e = check_handle_free(h).unwrap_err();
        assert!(e.contains("reusable after"), "{e}");
        assert_eq!(err(handle_get_info("users/alice/never", &ctx("alice"))), "key not found");
    }

    #[test]
    fn a_successor_deleted_here_does_not_pass_for_one_elsewhere() {
        let old = "users/alice/t6-old";
        let succ = "users/alice/t6-new";
        put_key(old);
        put_key(succ);
        deleted(succ);
        let after = crate::types::DeleteAfter { successor: succ.into(), successor_target: "-".into() };
        let e = err(handle_delete(old, None, Some(after), &ctx("alice")));
        assert!(e.contains("successor has been deleted"), "{e}");
        assert!(raw_record(old).is_some());
    }

    #[test]
    fn a_stranger_cannot_tell_a_deleted_key_from_a_live_one() {
        let dead = "users/alice/t2-dead";
        let live = "users/alice/t2-live";
        put_key(dead);
        put_key(live);
        deleted(dead);
        let bob = ctx("bob");
        let members = vec!["m".to_string()];
        let pairs: Vec<(String, String)> = vec![
            (err(handle_get_info(dead, &bob)), err(handle_get_info(live, &bob))),
            (err(handle_get_policy(dead, &bob)), err(handle_get_policy(live, &bob))),
            (err(handle_export(dead, None, &bob)), err(handle_export(live, None, &bob))),
            (err(handle_delete(dead, None, None, &bob)), err(handle_delete(live, None, None, &bob))),
            (err(handle_read_audit(dead, 0, 0, &bob)), err(handle_read_audit(live, 0, 0, &bob))),
            (err(handle_list_pending(dead, &bob)), err(handle_list_pending(live, &bob))),
            (err(handle_retire(dead, "x", &members, &bob)), err(handle_retire(live, "x", &members, &bob))),
        ];
        for (d, l) in pairs {
            assert_eq!(d, l);
            assert_eq!(d, tomb::NOT_A_PRINCIPAL);
        }
    }

    #[test]
    fn a_cut_short_delete_is_finished_by_the_next_touch() {
        let h = "users/alice/t3";
        put_key(h);
        let rec: KeyRecord = serde_json::from_slice(&raw_record(h).unwrap()).unwrap();
        // The tombstone was written, then the vault stopped.
        let mut t = tomb::tomb_for_tests(rec.policy.clone());
        t.handle = h.into();
        t.expires_at = NOW + 1000;
        t.audit_next_seq = rec.audit_next_seq;
        kv().unwrap()
            .lock()
            .unwrap()
            .put(format!("tomb:{h}").as_bytes(), &serde_json::to_vec(&t).unwrap())
            .unwrap();
        assert!(raw_record(h).is_some());
        // The next touch never serves the material, and finishes the delete.
        let e = err(handle_export(h, None, &ctx("alice")));
        assert!(e.starts_with("key deleted"), "{e}");
        assert!(raw_record(h).is_none());
    }

    #[test]
    fn housekeeping_finishes_and_purges() {
        let h = "users/alice/t4";
        put_key(h);
        deleted(h);
        {
            let mut store = kv().unwrap().lock().unwrap();
            // Before the key's original expiry nothing is purged.
            tomb::housekeep(&mut store, Some(NOW), tomb::HOUSEKEEPING_BATCH);
            assert!(matches!(tomb::lookup(&mut store, h, Some(NOW)).unwrap(), tomb::Lookup::Deleted(_)));
            // After it, the tombstone and the log go and the handle is free.
            // (The housekeeping purges through the same lookup; a global pass
            // at a later time would race the other tests' tombstones.)
            assert!(matches!(tomb::lookup(&mut store, h, Some(NOW + 1001)).unwrap(), tomb::Lookup::Missing));
            assert!(store.get(format!("tomb:{h}").as_bytes()).unwrap().is_none());
            assert!(store.get(&audit::audit_key(h, 0)).unwrap().is_none());
            assert!(store.get(&audit::audit_key(h, 1)).unwrap().is_none());
            assert!(matches!(tomb::lookup(&mut store, h, Some(NOW + 1001)).unwrap(), tomb::Lookup::Missing));
        }
        // Without trusted time nothing is purged blind.
        let h2 = "users/alice/t4b";
        put_key(h2);
        deleted(h2);
        let mut store = kv().unwrap().lock().unwrap();
        assert!(matches!(tomb::lookup(&mut store, h2, None).unwrap(), tomb::Lookup::Deleted(_)));
    }

    #[test]
    fn name_rules() {
        assert_eq!(name_rule("vaults/v/k"), NameRule::Plain);
        assert_eq!(name_rule("vaults/v/k/new-2"), NameRule::ReCreated);
        assert_eq!(name_rule("vaults/v/k/new-2/gen-3"), NameRule::BeneathReCreated);
        assert_eq!(name_rule("vaults/v/k/new-x"), NameRule::Plain);
        assert_eq!(name_rule("vaults/v/k/new-"), NameRule::Plain);
        // Beneath new-<k>: only a renewal ending in gen-<m>.
        assert!(check_name_rule("vaults/v/k/new-2/gen-3", true).is_ok());
        assert!(check_name_rule("vaults/v/k/new-2/gen-3", false).is_err());
        assert!(check_name_rule("vaults/v/k/new-2/v2", true).is_err());
        assert!(check_name_rule("vaults/v/k/new-2/v2", false).is_err());
        assert_eq!(check_name_rule("vaults/v/k/new-2", false).unwrap(), NameRule::ReCreated);
    }

    #[test]
    fn a_re_created_name_needs_the_owners_bound_create_approval() {
        init();
        let policy = normalise_policy(alice_policy(serde_json::json!([])));
        // Someone else's bearer, or the owner's without a step-up: refused.
        let e = crate::policy::require_owner_create(&policy, "vaults/v/k/new-2", None, &ctx("mallory"))
            .unwrap_err();
        assert!(e.contains("only the key's owner"), "{e}");
        let e = crate::policy::require_owner_create(&policy, "vaults/v/k/new-2", None, &ctx("alice"))
            .unwrap_err();
        assert!(e.contains("create approval"), "{e}");
        // The owner's bound step-up for exactly this creation: accepted, once.
        let (_, me, _) = v2::own_identity().unwrap();
        let handle = "vaults/v/k/new-2";
        let step_up = |target_policy: &KeyPolicy, nonce: &str| {
            let pd = v2::stored_policy_digest(target_policy).unwrap();
            let exp = NOW + 300;
            let text = v2::binding_v2_text(
                &[me.clone()], "create", handle, &pd, 0, "oidc:0:alice", "-", nonce, exp,
            );
            let mut c = ctx("alice");
            let claims = c.oidc_claims.as_mut().unwrap();
            claims.amr = vec!["webauthn".into()];
            claims.iat = NOW;
            claims.exp = exp;
            claims.nonce = Some(nonce.into());
            claims.vault_op = Some(v2::vault_op_v2(&text));
            c
        };
        let ok = step_up(&policy, "n-create-1");
        crate::policy::require_owner_create(&policy, handle, Some(vec![me.clone()]), &ok).unwrap();
        let e = crate::policy::require_owner_create(&policy, handle, Some(vec![me.clone()]), &ok)
            .unwrap_err();
        assert!(e.contains("already used"), "{e}");
        // An approval of another policy, another handle, or with no members.
        let mut other = policy.clone();
        other.lifecycle.ttl_seconds = 3600;
        let wrong = step_up(&other, "n-create-2");
        assert!(crate::policy::require_owner_create(&policy, handle, Some(vec![me.clone()]), &wrong).is_err());
        let fresh = step_up(&policy, "n-create-3");
        assert!(crate::policy::require_owner_create(&policy, "vaults/v/k/new-3", Some(vec![me.clone()]), &fresh).is_err());
        let fresh = step_up(&policy, "n-create-4");
        assert!(crate::policy::require_owner_create(&policy, handle, None, &fresh).is_err());

        // A policy not in stored form is refused before any approval.
        let mut raw = policy.clone();
        raw.lifecycle.ttl_seconds = 0;
        assert!(check_stored_form(&raw).is_err());
        assert!(check_stored_form(&policy).is_ok());
    }

    #[test]
    fn a_rule_change_never_drops_approvals_and_a_refused_one_spends_nothing() {
        init();
        let h = "users/alice/t7";
        let rules = |requires: serde_json::Value| {
            serde_json::json!([
                {"ops": ["PromoteProfile", "UpdatePolicy", "DeleteKey"], "principals": ["Owner"], "requires": requires}
            ])
        };
        let step_up = serde_json::json!([{"OidcStepUp": {
            "required_amr": ["webauthn"], "operation_bound": true, "fresh_for_seconds": 300, "binding": 2
        }}]);
        let mut policy = alice_policy(rules(step_up.clone()));
        policy.mutability.owner_can =
            vec![crate::types::PolicyField::Operations, crate::types::PolicyField::Lifecycle];
        let policy = normalise_policy(policy);
        assert!(v2::check_approval_by_default(&policy, false).is_ok());
        let mut record = KeyRecord {
            handle: h.into(),
            key_type: KeyType::Aes256GcmKey,
            exportable: false,
            material: vec![42; 32],
            public_key: None,
            policy: policy.clone(),
            policy_version: 1,
            created_at: NOW - 10,
            expires_at: NOW + 1000,
            pending_profiles: Vec::new(),
            audit_next_seq: 0,
            next_pending_id: 0,
            threshold_vaults: Vec::new(),
            key_check: None,
            renewed_in_place_from: None,
            created_by_owner_approval: false,
            pending_creation: None,
        };
        audit_and_save(&mut record, "CreateKey", "oidc:alice", AuditDecision::Allowed, "").unwrap();
        let send = |p: &KeyPolicy| {
            let raw = serde_json::to_string(&normalise_policy(p.clone())).unwrap();
            let raw = serde_json::value::RawValue::from_string(raw).unwrap();
            handle_update_policy(h, &raw, None, &ctx("alice"))
        };
        // Opting out, in the same change that drops the approvals: refused,
        // and refused before any approval is asked for.
        let mut opt_out = policy.clone();
        opt_out.operations = alice_policy(rules(serde_json::json!([]))).operations;
        opt_out.approval = Some(v2::APPROVAL_NONE.into());
        let e = err(send(&opt_out));
        assert!(e.contains("may not opt a key out"), "{e}");
        // Opting out alone: refused too.
        let mut only_opt_out = policy.clone();
        only_opt_out.approval = Some(v2::APPROVAL_NONE.into());
        let e = err(send(&only_opt_out));
        assert!(e.contains("may not opt a key out"), "{e}");
        // Dropping the approvals without the opt-out: refused.
        let mut dropped = policy.clone();
        dropped.approval = None;
        dropped.operations = opt_out.operations.clone();
        let e = err(send(&dropped));
        assert!(e.contains("without an approval"), "{e}");
        // A change the vault accepts still needs the owner's approval.
        let mut longer = policy.clone();
        longer.lifecycle.ttl_seconds = 3600;
        let e = err(send(&longer));
        assert!(!e.contains("may not opt") && !e.contains("without an approval"), "{e}");
        // Nothing changed.
        let r: KeyRecord = serde_json::from_slice(&raw_record(h).unwrap()).unwrap();
        assert_eq!(r.policy_version, 1);
    }

    #[test]
    fn a_carried_policy_keeps_the_grants_subject_as_owner() {
        init();
        let (_, _, billing) = v2::own_identity().unwrap();
        let grant_policy = alice_policy(serde_json::json!([]));
        let grant = crate::grant::KeyCreationGrant {
            iss: "https://privasys.id".into(),
            aud: "privasys-platform".into(),
            sub: "alice".into(),
            scope: "users/alice".into(),
            key_type: KeyType::Aes256GcmKey,
            exportable: false,
            policy: grant_policy,
            exp: NOW + 300,
            cnf: None,
        };
        let carried = |owner: &str| {
            let mut p = alice_policy(serde_json::json!([
                {"ops": ["ExportKey"], "principals": ["Owner"], "requires": []}
            ]));
            p.principals.owner = serde_json::from_value(serde_json::json!(
                {"Oidc": {"issuer": "https://privasys.id", "sub": owner, "required_roles": []}}
            ))
            .unwrap();
            p.approval = Some(v2::APPROVAL_NONE.into());
            CreateExtras {
                predecessor: None,
                policy: Some(
                    serde_json::value::RawValue::from_string(serde_json::to_string(&p).unwrap()).unwrap(),
                ),
                policy_version: Some(4),
                source_billing_id: Some(billing.clone()),
                key_check: None,
                carried_exportable: Some(false),
                carried_key_type: Some(KeyType::Aes256GcmKey),
                binding: None,
            }
        };
        // A caller naming itself the owner of a key in alice's scope: refused,
        // even though it would pass as that policy's owner.
        let e = new_key_policy(&grant, carried("mallory"), &ctx("mallory")).err().unwrap();
        assert!(e.contains("grant's subject"), "{e}");
        // Alice's own key, carried: accepted as it is.
        let ok = new_key_policy(&grant, carried("alice"), &ctx("alice")).ok().unwrap();
        assert_eq!(ok.policy_version, 4);
    }

    #[test]
    fn an_expired_tombstone_with_a_long_log_is_purged_in_batches() {
        let h = "users/alice/t8";
        put_key(h);
        deleted(h);
        let mut store = kv().unwrap().lock().unwrap();
        // A log longer than one purge batch.
        let mut t = match tomb::lookup(&mut store, h, Some(NOW)).unwrap() {
            tomb::Lookup::Deleted(t) => t,
            _ => panic!("expected a tombstone"),
        };
        let total = tomb::PURGE_BATCH * 2 + 5;
        for seq in t.audit_next_seq..total {
            store.put(&audit::audit_key(h, seq), b"{}").unwrap();
        }
        t.audit_next_seq = total;
        store.put(format!("tomb:{h}").as_bytes(), &serde_json::to_vec(&t).unwrap()).unwrap();
        let later = Some(NOW + 1001);
        // Two lookups each delete one batch, newest first; the handle stays deleted.
        assert!(matches!(tomb::lookup(&mut store, h, later).unwrap(), tomb::Lookup::Deleted(_)));
        assert!(store.get(&audit::audit_key(h, total - 1)).unwrap().is_none());
        assert!(store.get(&audit::audit_key(h, 0)).unwrap().is_some());
        assert!(matches!(tomb::lookup(&mut store, h, later).unwrap(), tomb::Lookup::Deleted(_)));
        // The third finishes it.
        assert!(matches!(tomb::lookup(&mut store, h, later).unwrap(), tomb::Lookup::Missing));
        assert!(store.get(&audit::audit_key(h, 0)).unwrap().is_none());
        assert!(store.get(format!("tomb:{h}").as_bytes()).unwrap().is_none());
    }

    #[test]
    fn a_pending_threshold_key_is_aborted_only_by_its_session() {
        let h = "users/alice/t5";
        put_key(h);
        let set_pending = |p: Option<crate::types::PendingCreation>| {
            let mut r: KeyRecord = serde_json::from_slice(&raw_record(h).unwrap()).unwrap();
            r.pending_creation = p;
            let store = kv().unwrap().lock().unwrap();
            store.put(&record_key(h), &serde_json::to_vec(&r).unwrap()).unwrap();
        };
        let pending = || {
            Some(crate::types::PendingCreation {
                session: "s1".into(),
                caller: "alice|".into(),
                committed_at: NOW,
            })
        };
        let abort = |session: &str, caller: &str, now: u64| {
            threshold::abort_pending(false, session, Some(h), caller, now, &ctx("alice"), "dkg")
        };
        set_pending(pending());
        assert!(abort("s2", "alice|", NOW).is_err(), "another session");
        assert!(abort("s1", "bob|", NOW).is_err(), "another caller");
        assert!(abort("s1", "alice|", NOW + 10_000).is_err(), "too late");
        // Once it served something it is a key like any other.
        set_pending(None);
        assert!(abort("s1", "alice|", NOW).is_err(), "no longer pending");
        set_pending(pending());
        abort("s1", "alice|", NOW).unwrap();
        // Gone, with no tombstone. The abort stays in the handle's log, which
        // a re-creation continues.
        assert!(matches!(lookup(h).unwrap(), tomb::Lookup::Missing));
        let store = kv().unwrap().lock().unwrap();
        assert_eq!(tomb::next_audit_seq(&store, h), 2);
    }
}
