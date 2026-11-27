// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Deleting keys: a delete, a delete bound to its successor (delete_after) and the retirement of a generation renewed in place, each leaving a tombstone (wire formats §9.2, §9.3).

use super::*;

pub(crate) fn handle_delete(
    handle: &str,
    binding: Option<BindingV2Request>,
    after: Option<crate::types::DeleteAfter>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let caller = caller_str(ctx);
    // The old key of a migration or upgrade: refused until its successor has
    // succeeded, checked before the approval is spent (wire formats §9.2).
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
    // Binding v2 binds the handle and the policy version (wire formats §5).
    let op_binding = crate::policy::OpBinding {
        policy_version: record.policy_version,
        v2: Some(crate::policy::OpBindingV2 {
            op,
            target,
            members: binding.map(|b| b.members),
        }),
    };
    if let Err(e) = evaluate_op(
        &record.policy,
        Operation::DeleteKey,
        handle,
        ctx,
        Some(&op_binding),
    ) {
        let _ = audit_denial(ctx, &mut record, "DeleteKey", &caller, AuditDecision::Denied, &e);
        return VaultResponse::Error(e);
    }

    let (tomb_op, successor) = match &after {
        Some(a) => ("delete_after", a.successor.as_str()),
        None => ("delete", "-"),
    };
    match remove_record(&mut record, "DeleteKey", &caller, &detail, tomb_op, successor, ctx) {
        Ok(()) => VaultResponse::KeyDeleted,
        Err(e) => e,
    }
}

/// Delete a key after auditing it, leaving a tombstone (wire formats §9.3): the
/// tombstone is written first, then the record with its material. The audit
/// log stays until the key's original expiry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn remove_record(
    record: &mut KeyRecord,
    what: &str,
    caller: &str,
    detail: &str,
    tomb_op: &str,
    successor: &str,
    ctx: &RequestContext,
) -> Result<(), VaultResponse> {
    let Some(now) = now_secs() else {
        return Err(VaultResponse::Error(NO_TRUSTED_TIME.into()));
    };
    let final_pd = v2::stored_policy_digest(&record.policy).map_err(VaultResponse::Error)?;
    audit_and_save(record, what, caller, AuditDecision::Allowed, detail)?;
    let (approver, vault_op) = tomb_approver(&record.policy, tomb_op, ctx);
    let t = crate::types::Tombstone {
        handle: record.handle.clone(),
        key_type: record.key_type,
        final_policy: record.policy.clone(),
        final_pd,
        final_policy_version: record.policy_version,
        op: tomb_op.to_string(),
        approver,
        vault_op,
        successor: successor.to_string(),
        deleted_at: now,
        expires_at: record.expires_at,
        audit_next_seq: record.audit_next_seq,
    };
    let kv = kv()?;
    let mut store = kv
        .lock()
        .map_err(|_| VaultResponse::Error("kv store lock poisoned".into()))?;
    tomb::delete_with_tombstone(&mut store, &t).map_err(VaultResponse::Error)
}

/// Who approved a deletion, and the binding that named it ("-" unless the
/// vault checked a binding v2 for it).
pub(crate) fn tomb_approver(policy: &KeyPolicy, tomb_op: &str, ctx: &RequestContext) -> (String, String) {
    match ctx.oidc_claims.as_ref() {
        Some(c) => {
            let bound = tomb_op != "retire" && rule_asks_approval(policy, Operation::DeleteKey);
            let vault_op = match (&c.vault_op, bound) {
                (Some(v), true) => v.clone(),
                _ => "-".to_string(),
            };
            (format!("oidc:0:{}", c.sub), vault_op)
        }
        None => {
            let id = threshold::caller_id(ctx);
            (format!("tee:{}", id.trim_start_matches('|')), "-".to_string())
        }
    }
}

/// The old key of a migration or upgrade may go only once its successor has
/// succeeded, where this vault can see it (wire formats §9.2).
pub(crate) fn check_successor_succeeded(old: &KeyRecord, after: &crate::types::DeleteAfter) -> Result<(), String> {
    // Promote K then "delete K after K" would delete the key just promoted.
    if after.successor == old.handle {
        return Err("a key cannot be the successor of itself".into());
    }
    // A successor deleted here is not one "on another constellation".
    let succ = match lookup(&after.successor).map_err(response_text)? {
        tomb::Lookup::Live(r) => Some(r),
        tomb::Lookup::Deleted(_) => return Err("the successor has been deleted".into()),
        tomb::Lookup::Missing => None,
    };
    successor_check(old, after, succ.as_ref(), now_secs())
}

/// The successor checks of wire formats §9.2, given the successor's record when it
/// is on this vault.
pub(crate) fn successor_check(
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
    //: it must belong to the same owner and be newer.
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

pub(crate) fn handle_retire(
    handle: &str,
    successor: &str,
    successor_members: &[String],
    ctx: &RequestContext,
) -> VaultResponse {
    // Idempotent: a key already gone was retired (or deleted) before.
    let mut record = match lookup(handle) {
        Ok(tomb::Lookup::Live(r)) => r,
        Ok(tomb::Lookup::Deleted(t)) if !tomb::is_principal(&t, ctx) => {
            return VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into())
        }
        Ok(_) => return VaultResponse::KeyRetired { was_present: false },
        Err(e) => return e,
    };
    if resolve_caller(&record.policy, ctx).is_none() {
        UNAUDITED_DENIALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return VaultResponse::Error(tomb::NOT_A_PRINCIPAL.into());
    }
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
    // live generation is never reachable, whatever the caller claims.
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
    match remove_record(&mut record, "RetireKey", &caller, &detail, "retire", successor, ctx) {
        Ok(()) => VaultResponse::KeyRetired { was_present: true },
        Err(e) => e,
    }
}
