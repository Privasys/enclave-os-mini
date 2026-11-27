// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Changing a key's rules: UpdatePolicy, with the owner's bound approval, the mutability rules and the approval-by-default checks (wire formats §4, §5.3).

use super::*;

pub(crate) fn handle_update_policy(
    handle: &str,
    new_policy_raw: &serde_json::value::RawValue,
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }
    let caller = caller_str(ctx);

    // A key whose update rule takes binding v2 approves exactly the JSON sent
    // (wire formats §5.1): it must be canonical, and it is stored as sent. Other
    // keys take the policy as before, normalised.
    let takes_v2 = rule_takes_binding_v2(&record.policy, Operation::UpdatePolicy);
    let canonical = v2::canonical_policy(new_policy_raw.get());
    let new_policy = if takes_v2 {
        match &canonical {
            // Sent exactly as it will be stored: the owner approves
            // the JSON the vault keeps and returns.
            Ok(c) => match v2::check_sent_in_stored_form(new_policy_raw.get()) {
                Ok(()) => c.policy.clone(),
                Err(e) => return VaultResponse::Error(e),
            },
            Err(e) => return VaultResponse::Error(e.clone()),
        }
    } else {
        match serde_json::from_str::<KeyPolicy>(new_policy_raw.get()) {
            Ok(p) => normalise_policy(p),
            Err(e) => return VaultResponse::Error(format!("new_policy does not parse: {e}")),
        }
    };
    // update_policy_from (wire formats §5.3): the approval also names the policy it
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

    // The change itself is checked first, so a change the vault refuses never
    // spends the single-use approval that came with it.
    let role = match resolve_caller(&record.policy, ctx) {
        Some((_pref, role)) => role,
        None => return VaultResponse::Error("caller is not in policy.principals".into()),
    };
    if let Err(e) = v2::check_no_approval_downgrade(&record.policy, &new_policy, record.exportable)
    {
        let _ = audit_denial(ctx, &mut record, "UpdatePolicy", &caller, AuditDecision::Denied, &e);
        return VaultResponse::Error(e);
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
    if let Err(e) = evaluate_op(
        &record.policy,
        Operation::UpdatePolicy,
        handle,
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

    // A strict tightening (wire formats §4.1) is audited as its own decision.
    let (what, detail) = match v2::tightening_rules(&record.policy, &new_policy) {
        Ok(rules) if !rules.is_empty() => (
            "TightenApprovals",
            format!("bound step-up added to rules {rules:?}"),
        ),
        _ => ("UpdatePolicy", String::new()),
    };
    record.policy = new_policy;
    record.policy_version = record.policy_version.saturating_add(1);
    // Governed by its owner now: a pending threshold key can no longer be
    // aborted.
    record.pending_creation = None;

    if let Err(e) = audit_and_save(
        &mut record,
        what,
        &caller,
        AuditDecision::Allowed,
        &detail,
    ) {
        return e;
    }
    VaultResponse::PolicyUpdated {
        policy_version: record.policy_version,
    }
}
