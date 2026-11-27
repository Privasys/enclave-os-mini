// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Staged builds: staging, listing, promoting and revoking pending attestation profiles (the enclave upgrade flow).

use super::*;

/// Both Stage and Revoke require the caller's role to be permitted to
/// change `PolicyField::PendingProfiles` per `mutability`.
pub(crate) fn check_pending_mutability(
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
pub(crate) enum StagerIdentity {
    /// A key principal (owner, or a manager the Mutability rules permit).
    Principal,
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
pub(crate) fn check_stage_authority(
    record: &KeyRecord,
    ctx: &RequestContext,
) -> Result<StagerIdentity, String> {
    if resolve_caller(&record.policy, ctx).is_some() {
        return check_pending_mutability(record, ctx).map(|_| StagerIdentity::Principal);
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

pub(crate) fn handle_stage_pending(
    handle: &str,
    mut profile: AttestationProfile,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
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
    // stager, and only a runtime-only delta of a profile the owner already
    // accepted. The
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

pub(crate) fn handle_list_pending(handle: &str, ctx: &RequestContext) -> VaultResponse {
    let record = match load_for(handle, ctx) {
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

pub(crate) fn handle_promote_pending(
    handle: &str,
    pending_id: u32,
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
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
            policy_version: record.policy_version,
            v2: Some(crate::policy::OpBindingV2 {
                op: "promote",
                target: Ok(digest),
                members: binding.as_ref().map(|b| b.members.clone()),
            }),
        }
    });

    if let Err(e) = evaluate_op(
        &record.policy,
        Operation::PromoteProfile,
        handle,
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
    // Governed by its owner now: a pending threshold key can no longer be
    // aborted.
    record.pending_creation = None;
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

pub(crate) fn handle_revoke_pending(handle: &str, pending_id: u32, ctx: &RequestContext) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
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
