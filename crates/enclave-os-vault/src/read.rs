// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Read-only handlers: the vault's identity, a key's policy and public metadata, the caller's keys and a key's audit log.

use super::*;

pub(crate) fn handle_identity() -> VaultResponse {
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
            tomb::CAPABILITY_TOMBSTONES.to_string(),
        ],
    }
}

pub(crate) fn handle_get_policy(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_for(handle, ctx) {
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

pub(crate) fn handle_get_info(handle: &str, ctx: &RequestContext) -> VaultResponse {
    // A deleted key's principals read its tombstone (wire formats §9.3).
    if let Ok(tomb::Lookup::Deleted(t)) = lookup(handle) {
        if tomb::is_principal(&t, ctx) {
            return VaultResponse::KeyTombstone {
                handle: t.handle,
                key_type: t.key_type,
                op: t.op,
                deleted_at: t.deleted_at,
                successor: t.successor,
                expires_at: t.expires_at,
            };
        }
    }
    let record = match load_for(handle, ctx) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        return VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into());
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
        created_by_owner_approval: record.created_by_owner_approval,
    })
}

pub(crate) fn handle_list(ctx: &RequestContext) -> VaultResponse {
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
    let mut store = store;
    let now = now_secs();
    for handle in &handles {
        // Live keys only: a lookup also finishes a cut-short deletion.
        if let Ok(tomb::Lookup::Live(record)) = tomb::lookup(&mut store, handle, now) {
            keys.push(KeyListEntry {
                handle: record.handle,
                key_type: record.key_type,
                expires_at: record.expires_at,
            });
        }
    }
    VaultResponse::KeyList { keys }
}
pub(crate) fn handle_read_audit(
    handle: &str,
    since_seq: u64,
    limit: u32,
    ctx: &RequestContext,
) -> VaultResponse {
    // A deleted key's log stays readable by its principals until the purge.
    let next = match lookup(handle) {
        Ok(tomb::Lookup::Deleted(t)) if tomb::is_principal(&t, ctx) => t.audit_next_seq,
        _ => {
            let record = match load_for(handle, ctx) {
                Ok(r) => r,
                Err(e) => return e,
            };
            if resolve_caller(&record.policy, ctx).is_none() {
                return VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into());
            }
            record.audit_next_seq
        }
    };
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
        match audit::read(&store, handle, next, since_seq, limit) {
            Ok(p) => p,
            Err(e) => return VaultResponse::Error(e),
        };
    VaultResponse::AuditLog { entries, next_seq }
}
