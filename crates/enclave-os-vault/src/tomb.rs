// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Tombstones (formats §9.3).
//!
//! A deleted key leaves `tomb:<handle>` (never material) until its original
//! expiry. The sealed store has no multi-key transaction, so the tombstone is
//! written FIRST and the record (with its material) and its `prev:` share are
//! deleted after. A tombstone beside a record means a deletion was cut short:
//! every lookup, and the housekeeping, finishes it before anything else.

use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use enclave_os_common::modules::RequestContext;
use enclave_os_kvstore::SealedKvStore;

use crate::policy::resolve_caller;
use crate::types::{KeyRecord, Tombstone, VaultResponse};

/// What a caller outside a key's policy is told, for a live key and a
/// deleted one alike (no existence oracle, Security).
pub const NOT_A_PRINCIPAL: &str = "caller is not in policy.principals";

/// The capability a build publishes when it keeps tombstones, enforces the
/// re-created name rules and aborts pending threshold keys (formats §9.3).
pub const CAPABILITY_TOMBSTONES: &str = "tombstones-v1";

fn tomb_key(handle: &str) -> Vec<u8> {
    format!("tomb:{handle}").into_bytes()
}

/// The handles that have a tombstone, for the housekeeping.
const TOMB_INDEX: &[u8] = b"__tombs";

/// A handle as the vault finds it.
pub enum Lookup {
    Live(KeyRecord),
    Deleted(Tombstone),
    Missing,
}

/// Find `handle`: finish a cut-short deletion, and purge an expired
/// tombstone, before answering. Without trusted time a tombstone is kept
/// (and the handle stays deleted): purging is never done blind.
pub fn lookup(store: &mut SealedKvStore, handle: &str, now: Option<u64>) -> Result<Lookup, String> {
    if let Some(t) = get_tomb(store, handle)? {
        if now.is_some_and(|n| n > t.expires_at) {
            purge(store, &t)?;
            return Ok(Lookup::Missing);
        }
        finish_delete(store, handle)?;
        return Ok(Lookup::Deleted(t));
    }
    match store
        .get(&crate::record_key(handle))
        .map_err(|e| format!("kv get failed: {e}"))?
    {
        Some(bytes) => serde_json::from_slice::<KeyRecord>(&bytes)
            .map(Lookup::Live)
            .map_err(|e| format!("corrupt record: {e}")),
        None => Ok(Lookup::Missing),
    }
}

fn get_tomb(store: &SealedKvStore, handle: &str) -> Result<Option<Tombstone>, String> {
    match store
        .get(&tomb_key(handle))
        .map_err(|e| format!("kv get failed: {e}"))?
    {
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("corrupt tombstone: {e}")),
        None => Ok(None),
    }
}

/// Delete what a tombstone replaces: the record, its kept previous share and
/// its place in the owner's index. Idempotent.
fn finish_delete(store: &mut SealedKvStore, handle: &str) -> Result<(), String> {
    let Some(bytes) = store
        .get(&crate::record_key(handle))
        .map_err(|e| format!("kv get failed: {e}"))?
    else {
        return Ok(());
    };
    let owner = serde_json::from_slice::<KeyRecord>(&bytes)
        .ok()
        .and_then(|r| crate::owner_oidc_sub(&r.policy.principals.owner));
    store
        .delete(&crate::record_key(handle))
        .map_err(|e| format!("kv delete failed: {e}"))?;
    let _ = store.delete(&crate::threshold::previous_key(handle));
    if let Some(owner) = owner {
        let _ = crate::remove_from_owner_index(store, &owner, handle);
    }
    Ok(())
}

/// At the key's original expiry: the tombstone and the key's audit log go,
/// and the handle is free again.
fn purge(store: &mut SealedKvStore, t: &Tombstone) -> Result<(), String> {
    finish_delete(store, &t.handle)?;
    for seq in 0..t.audit_next_seq {
        let _ = store.delete(&crate::audit::audit_key(&t.handle, seq));
    }
    store
        .delete(&tomb_key(&t.handle))
        .map_err(|e| format!("kv delete failed: {e}"))?;
    let mut index = read_index(store);
    index.retain(|h| h != &t.handle);
    write_index(store, &index)
}

fn read_index(store: &SealedKvStore) -> Vec<String> {
    match store.get(TOMB_INDEX) {
        Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn write_index(store: &SealedKvStore, index: &[String]) -> Result<(), String> {
    let bytes = serde_json::to_vec(index).map_err(|e| format!("serialise index: {e}"))?;
    store.put(TOMB_INDEX, &bytes)
}

/// Delete `record`, leaving `tomb`: the tombstone first, then the record.
/// The caller has audited the deletion on the record already.
pub fn delete_with_tombstone(store: &mut SealedKvStore, tomb: &Tombstone) -> Result<(), String> {
    let bytes = serde_json::to_vec(tomb).map_err(|e| format!("serialise tombstone: {e}"))?;
    store
        .put(&tomb_key(&tomb.handle), &bytes)
        .map_err(|e| format!("kv put failed: {e}"))?;
    let mut index = read_index(store);
    if !index.iter().any(|h| h == &tomb.handle) {
        index.push(tomb.handle.clone());
        // Best effort: a lookup of the handle finishes the delete anyway.
        let _ = write_index(store, &index);
    }
    finish_delete(store, &tomb.handle)
}

/// Most tombstones one housekeeping pass visits: it runs on the request
/// path, so a long index is worked through over several passes (Security).
pub const HOUSEKEEPING_BATCH: usize = 100;

/// Where the next housekeeping pass starts in the index.
static CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Finish cut-short deletions and purge expired tombstones, visiting at most
/// `max` of them, carrying on from the last pass. Without trusted time only
/// the deletions are finished.
pub fn housekeep(store: &mut SealedKvStore, now: Option<u64>, max: usize) {
    let index = read_index(store);
    if index.is_empty() {
        return;
    }
    let start = CURSOR.load(core::sync::atomic::Ordering::Relaxed) % index.len();
    let batch: Vec<String> = index.iter().cycle().skip(start).take(max.min(index.len())).cloned().collect();
    CURSOR.store(start.saturating_add(batch.len()), core::sync::atomic::Ordering::Relaxed);
    for handle in batch {
        match get_tomb(store, &handle) {
            Ok(Some(_)) => {
                let _ = lookup(store, &handle, now);
            }
            Ok(None) => {
                // Purged by a lookup: drop it from the index.
                let mut index = read_index(store);
                index.retain(|h| h != &handle);
                let _ = write_index(store, &index);
            }
            Err(_) => {}
        }
    }
}

/// Whether `ctx` is one of the principals of the deleted key's final policy.
pub fn is_principal(t: &Tombstone, ctx: &RequestContext) -> bool {
    resolve_caller(&t.final_policy, ctx).is_some()
}

/// What a principal is told about any operation on a deleted key.
pub fn deleted_message(t: &Tombstone) -> String {
    format!(
        "key deleted at {} ({}); successor {}; the handle is reusable after {}",
        t.deleted_at, t.op, t.successor, t.expires_at
    )
}

/// The answer to an operation on a deleted key: "key deleted" to its
/// principals, exactly a live key's answer to anyone else.
pub fn refusal(t: &Tombstone, ctx: &RequestContext) -> VaultResponse {
    if is_principal(t, ctx) {
        VaultResponse::Error(deleted_message(t))
    } else {
        VaultResponse::Error(NOT_A_PRINCIPAL.to_string())
    }
}

/// Why a handle cannot be created now, if it cannot.
pub fn creation_refusal(t: &Tombstone) -> String {
    format!(
        "handle deleted at {}; reusable after {}: choose another name",
        t.deleted_at, t.expires_at
    )
}

/// The next free audit sequence number for a handle: a key re-created after
/// an aborted pending key continues that handle's log instead of
/// overwriting it.
pub fn next_audit_seq(store: &SealedKvStore, handle: &str) -> u64 {
    let mut seq = 0u64;
    while let Ok(Some(_)) = store.get(&crate::audit::audit_key(handle, seq)) {
        seq += 1;
    }
    seq
}

#[cfg(test)]
pub(crate) fn tomb_for_tests(policy: crate::types::KeyPolicy) -> Tombstone {
    Tombstone {
        handle: "users/alice/k".into(),
        key_type: crate::types::KeyType::Aes256GcmKey,
        final_policy: policy,
        final_pd: "00".into(),
        final_policy_version: 1,
        op: "delete".into(),
        approver: "oidc:0:alice".into(),
        vault_op: "-".into(),
        successor: "-".into(),
        deleted_at: 100,
        expires_at: 200,
        audit_next_seq: 3,
    }
}
