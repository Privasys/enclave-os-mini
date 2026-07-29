// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault policy evaluation.
//!
//! Two entry points:
//!
//! 1. [`resolve_caller`] determines which slot in the key's [`PrincipalSet`]
//!    the caller occupies, given the [`RequestContext`]. It returns
//!    `None` if the caller is not in the set at all.
//!
//! 2. [`evaluate_op`] checks that there is an [`OperationRule`] in the
//!    policy that grants the requested [`Operation`] to the caller's
//!    resolved principal.
//!
//! And one bonus, used by `UpdatePolicy`:
//!
//! 3. [`evaluate_policy_update`] computes which top-level [`PolicyField`]s
//!    differ between the old and new policy and checks each against
//!    [`Mutability`] for the caller's role.

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use enclave_os_common::digest;
use enclave_os_common::hex::hex_encode;
use enclave_os_common::modules::RequestContext;
use enclave_os_common::oidc::OidcClaims;

use crate::quote::{dissect_peer_cert, parse_quote, verify_challenge_binding, TeeType};
use crate::signing::verify_approval_token;
use crate::types::{
    ApprovalToken, AttestationProfile, Condition, KeyPolicy, Measurement, Mutability, Operation,
    OperationRule, Principal, PrincipalRef,
};

/// Domain separator for the operation-binding hash. MUST match the IdP and
/// client implementations (the vault promote-step-up design).
const VAULT_APPROVAL_DOMAIN: &str = "privasys-vault-approval/v1";

/// Per-operation binding data for `Condition::OidcStepUp { operation_bound }`.
/// Supplied by the handler that knows the operation's target (e.g. promote),
/// `None` for ops that have no canonical target measurement.
pub struct OpBinding {
    /// Hex SHA-256 of the canonical promoted profile ([`profile_binding_digest`]).
    pub measurement_digest_hex: String,
    /// The key's `policy_version` at the time of the operation.
    pub policy_version: u32,
}

/// Canonical digest of an [`AttestationProfile`] for operation binding: the
/// SHA-256 (hex) of its measurements + required OIDs, each rendered as a stable
/// `kind:value` line, lowercased, sorted, and newline-joined. MUST be computed
/// identically by the IdP and client. See the vault promote-step-up design.
pub fn profile_binding_digest(profile: &AttestationProfile) -> String {
    let mut parts: Vec<String> = Vec::new();
    for m in &profile.measurements {
        match m {
            Measurement::Mrenclave(v) => parts.push(format!("mrenclave:{}", v.to_lowercase())),
            Measurement::Tdx { mrtd, rtmr1, rtmr2 } => {
                parts.push(format!("mrtd:{}", mrtd.to_lowercase()));
                parts.push(format!("rtmr1:{}", rtmr1.to_lowercase()));
                parts.push(format!("rtmr2:{}", rtmr2.to_lowercase()));
            }
        }
    }
    for o in &profile.required_oids {
        parts.push(format!("oid:{}={}", o.oid, o.value.to_lowercase()));
    }
    parts.sort();
    let joined = parts.join("\n");
    hex_encode(digest::digest(&digest::SHA256, joined.as_bytes()).as_ref())
}

/// The operation-binding value the IdP stamps into `vault_op` and the vault
/// recomputes: `base64url(SHA-256(domain \n handle \n measurement_hex \n
/// policy_version \n nonce \n exp))`. All inputs are rendered as UTF-8 strings
/// joined by `\n` so the hash is trivially identical across Rust/Go/TS.
pub fn vault_op_binding(
    handle: &str,
    measurement_digest_hex: &str,
    policy_version: u32,
    nonce: &str,
    exp: u64,
) -> String {
    let input = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        VAULT_APPROVAL_DOMAIN, handle, measurement_digest_hex, policy_version, nonce, exp
    );
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, input.as_bytes()).as_ref())
}

// ---------------------------------------------------------------------------
//  Caller role (for mutability checks)
// ---------------------------------------------------------------------------

/// Which slot in the [`PrincipalSet`] the caller resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRole {
    Owner,
    Manager,
    Auditor,
    Tee,
}

// ---------------------------------------------------------------------------
//  Caller resolution
// ---------------------------------------------------------------------------

/// Determine which principal in the policy the caller authenticated as.
///
/// Tries OIDC first (Owner > Managers > Auditors), then mutual RA-TLS
/// against any `Principal::Tee` in `principals.tees`. Returns the
/// matching [`PrincipalRef`] and its [`CallerRole`].
pub fn resolve_caller(
    policy: &KeyPolicy,
    ctx: &RequestContext,
) -> Option<(PrincipalRef, CallerRole)> {
    if let Some(claims) = ctx.oidc_claims.as_ref() {
        if oidc_matches(&policy.principals.owner, claims) {
            return Some((PrincipalRef::Owner, CallerRole::Owner));
        }
        for (i, p) in policy.principals.managers.iter().enumerate() {
            if oidc_matches(p, claims) {
                return Some((PrincipalRef::Manager(i as u32), CallerRole::Manager));
            }
        }
        for (i, p) in policy.principals.auditors.iter().enumerate() {
            if oidc_matches(p, claims) {
                return Some((PrincipalRef::Auditor(i as u32), CallerRole::Auditor));
            }
        }
    }

    if let Some(peer_der) = ctx.peer_cert_der.as_deref() {
        for (i, p) in policy.principals.tees.iter().enumerate() {
            if let Principal::Tee(profile) = p {
                if tee_matches(profile, peer_der, ctx.client_challenge_nonce.as_deref(), ctx.channel_binder.as_deref()) {
                    return Some((PrincipalRef::Tee(i as u32), CallerRole::Tee));
                }
            }
        }
    }
    None
}

/// `Principal::Oidc` match.
///
/// Two modes:
///   - **subject-bound** (`sub` set): the caller's `sub` must match exactly AND
///     every `required_roles` entry must be present.
///   - **role-only** (`sub` empty): matches ANY subject that holds all
///     `required_roles`. This lets a policy name a *set* of callers by role
///     (e.g. an app's team via `privasys-platform:app:<id>:approver`) so the
///     policy never has to change as the membership changes.
///
/// Safety guard: an empty `sub` with empty `required_roles` would match every
/// caller, which is never the intent — it is refused.
pub(crate) fn oidc_matches(principal: &Principal, claims: &OidcClaims) -> bool {
    match principal {
        Principal::Oidc {
            issuer: _,
            sub,
            required_roles,
        } => {
            if sub.is_empty() {
                return !required_roles.is_empty() && has_required_roles(claims, required_roles);
            }
            sub == &claims.sub && has_required_roles(claims, required_roles)
        }
        Principal::Tee(_) | Principal::Fido2 { .. } => false,
    }
}

/// True iff every name in `required_roles` is present in the verified
/// claims (case-insensitive string match against the raw role strings
/// from the JWT).
pub fn has_required_roles(claims: &OidcClaims, required_roles: &[String]) -> bool {
    if required_roles.is_empty() {
        return true;
    }
    required_roles
        .iter()
        .all(|r| claims.roles.iter().any(|c| c.eq_ignore_ascii_case(r)))
}

/// Verify that the peer cert satisfies a given `AttestationProfile`.
///
/// Performs (in order):
///   1. cert dissection (quote + OID claims + pubkey),
///   2. attestation server verification of the quote,
///   3. parse + measurement match against `profile.measurements`,
///   4. bidirectional challenge-response binding,
///   5. required OID extension match.
pub(crate) fn tee_matches(
    profile: &AttestationProfile,
    peer_der: &[u8],
    challenge_nonce: Option<&[u8]>,
    channel_binder: Option<&[u8]>,
) -> bool {
    let evidence = match dissect_peer_cert(peer_der) {
        Ok(e) => e,
        Err(_) => return false,
    };

    // 2. Attestation server verification.
    let urls: Vec<String> = profile
        .attestation_servers
        .iter()
        .map(|s| s.url.clone())
        .collect();
    if urls.is_empty() {
        // Refuse: a TEE principal must list at least one attestation server.
        return false;
    }
    if enclave_os_egress::attestation::verify_quote(&evidence.evidence, &urls).is_err() {
        return false;
    }

    // 3. Parse + measurement match.
    let identity = match parse_quote(&evidence.evidence) {
        Ok(q) => q,
        Err(_) => return false,
    };
    if !measurement_matches(&identity, &profile.measurements) {
        return false;
    }

    // 4. Challenge binding.
    if verify_challenge_binding(
        &evidence.evidence,
        &evidence.pubkey_raw,
        challenge_nonce,
        channel_binder,
    )
    .is_err()
    {
        return false;
    }

    // 5. Required OIDs.
    for req in &profile.required_oids {
        let ok = evidence
            .oid_claims
            .iter()
            .any(|(oid, val)| oid == &req.oid && val == &req.value);
        if !ok {
            return false;
        }
    }
    true
}

fn measurement_matches(identity: &crate::quote::QuoteIdentity, allowed: &[Measurement]) -> bool {
    let m = identity.measurement.to_lowercase();
    // OR across the allowed list (supports old+new build during a promote
    // window); AND within a TDX entry — MRTD *and* both image-derived RTMRs must
    // match, since MRTD alone (the TD firmware) does not identify the guest build.
    allowed.iter().any(|am| match (am, identity.tee) {
        (Measurement::Mrenclave(s), TeeType::Sgx) => s.to_lowercase() == m,
        (Measurement::Tdx { mrtd, rtmr1, rtmr2 }, TeeType::Tdx) => {
            let r1 = match identity.rtmr1.as_deref() {
                Some(v) => v.to_lowercase(),
                None => return false,
            };
            let r2 = match identity.rtmr2.as_deref() {
                Some(v) => v.to_lowercase(),
                None => return false,
            };
            mrtd.to_lowercase() == m
                && rtmr1.to_lowercase() == r1
                && rtmr2.to_lowercase() == r2
        }
        _ => false,
    })
}

// ---------------------------------------------------------------------------
//  Op evaluation
// ---------------------------------------------------------------------------

/// Verify the caller is allowed to perform `op` on the key whose policy
/// is `policy`. The `handle` and `approvals` parameters are needed to
/// evaluate [`Condition::ManagerApproval`].
pub fn evaluate_op(
    policy: &KeyPolicy,
    op: Operation,
    handle: &str,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
    op_binding: Option<&OpBinding>,
) -> Result<(), String> {
    let (caller_ref, _role) = resolve_caller(policy, ctx).ok_or_else(|| {
        "caller is not in policy.principals (no OIDC subject or RA-TLS TEE \
         matches the key's PrincipalSet)"
            .to_string()
    })?;

    // First filter rules that grant op to caller. Then require at least
    // one of those rules to have all of its `requires` conditions met.
    let mut last_err: Option<String> = None;
    for rule in policy.operations.iter() {
        if !rule.ops.contains(&op) || !rule_grants_to(rule, caller_ref) {
            continue;
        }
        match evaluate_conditions(
            &rule.requires,
            policy,
            op,
            handle,
            approvals,
            ctx,
            op_binding,
        ) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }

    Err(match last_err {
        Some(e) => format!(
            "no OperationRule grants {:?} to caller with all conditions met: {}",
            op, e
        ),
        None => format!(
            "caller is in policy.principals but no OperationRule grants {:?}",
            op
        ),
    })
}

fn rule_grants_to(rule: &OperationRule, caller: PrincipalRef) -> bool {
    rule.principals.iter().any(|p| match (*p, caller) {
        (PrincipalRef::Owner, PrincipalRef::Owner) => true,
        (PrincipalRef::Manager(a), PrincipalRef::Manager(b)) => a == b,
        (PrincipalRef::Auditor(a), PrincipalRef::Auditor(b)) => a == b,
        (PrincipalRef::Tee(a), PrincipalRef::Tee(b)) => a == b,
        (PrincipalRef::AnyTee, PrincipalRef::Tee(_)) => true,
        _ => false,
    })
}

// ---------------------------------------------------------------------------
//  Condition evaluation
// ---------------------------------------------------------------------------

fn evaluate_conditions(
    conditions: &[Condition],
    policy: &KeyPolicy,
    op: Operation,
    handle: &str,
    approvals: &[ApprovalToken],
    ctx: &RequestContext,
    op_binding: Option<&OpBinding>,
) -> Result<(), String> {
    let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
    for cond in conditions {
        match cond {
            Condition::TimeWindow {
                not_before,
                not_after,
            } => {
                if *not_before != 0 && now < *not_before {
                    return Err(format!(
                        "TimeWindow: now={} before not_before={}",
                        now, not_before
                    ));
                }
                if *not_after != 0 && now > *not_after {
                    return Err(format!(
                        "TimeWindow: now={} after not_after={}",
                        now, not_after
                    ));
                }
            }
            Condition::AttestationMatches(profile) => {
                let peer = ctx.peer_cert_der.as_deref().ok_or_else(|| {
                    "AttestationMatches: no peer RA-TLS cert in request".to_string()
                })?;
                if !tee_matches(profile, peer, ctx.client_challenge_nonce.as_deref(), ctx.channel_binder.as_deref()) {
                    return Err(format!(
                        "AttestationMatches: peer does not match profile '{}'",
                        profile.name
                    ));
                }
            }
            Condition::ManagerApproval {
                manager,
                fresh_for_seconds,
            } => {
                let mgr_idx = *manager;
                let mgr = policy
                    .principals
                    .managers
                    .get(mgr_idx as usize)
                    .ok_or_else(|| {
                        format!("ManagerApproval: manager index {} out of range", mgr_idx)
                    })?;
                let mgr_sub = match mgr {
                    Principal::Oidc { sub, .. } => sub.as_str(),
                    Principal::Tee(_) | Principal::Fido2 { .. } => {
                        return Err(
                            "ManagerApproval: only OIDC managers can issue approval tokens"
                                .to_string(),
                        )
                    }
                };
                // A role-based manager (empty sub, matched by role) names a *set*
                // of approvers, so the approval must come from a DIFFERENT person
                // than whoever is driving this operation: separation-of-duties
                // co-sign. We pass the proposer's sub so the token's approver_sub
                // is checked to differ. A subject-bound manager is distinct by
                // construction, so no co-sign check applies (distinct_from = None).
                let distinct_from: Option<&str> = if mgr_sub.is_empty() {
                    match ctx.oidc_claims.as_ref() {
                        Some(c) => Some(c.sub.as_str()),
                        None => {
                            return Err("ManagerApproval: role-based co-sign requires an \
                                 authenticated OIDC proposer"
                                .to_string())
                        }
                    }
                } else {
                    None
                };
                let mut accepted = false;
                let mut last_err: Option<String> = None;
                for token in approvals {
                    match verify_approval_token(
                        token,
                        handle,
                        op,
                        mgr_idx,
                        distinct_from,
                        *fresh_for_seconds,
                        now,
                    ) {
                        Ok(()) => {
                            accepted = true;
                            break;
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                if !accepted {
                    return Err(match last_err {
                        Some(e) => format!("ManagerApproval: no token accepted ({})", e),
                        None => "ManagerApproval: no approval token supplied".into(),
                    });
                }
            }
            Condition::OidcStepUp {
                required_amr,
                operation_bound,
                fresh_for_seconds,
            } => {
                let claims = ctx
                    .oidc_claims
                    .as_ref()
                    .ok_or_else(|| "OidcStepUp: no OIDC bearer in request".to_string())?;
                if !claims.has_amr(required_amr) {
                    return Err(format!(
                        "OidcStepUp: token amr {:?} does not satisfy required {:?}",
                        claims.amr, required_amr
                    ));
                }
                if *fresh_for_seconds > 0 {
                    if claims.iat == 0 {
                        return Err(
                            "OidcStepUp: token has no iat; cannot prove freshness".to_string()
                        );
                    }
                    if now.saturating_sub(claims.iat) > *fresh_for_seconds {
                        return Err(format!(
                            "OidcStepUp: token age {}s exceeds fresh_for_seconds={}",
                            now.saturating_sub(claims.iat),
                            fresh_for_seconds
                        ));
                    }
                }
                // Operation binding: the token's `vault_op` must equal the value
                // recomputed from THIS operation's (handle, measurement,
                // policy_version) plus the token's own (nonce, exp). This proves
                // the WebAuthn step-up the IdP attests (`amr`) was performed for
                // exactly this promote, so a stolen bearer + a captured approval
                // cannot promote a different/forged measurement. Fail closed when
                // the handler supplied no binding (op has no target) or the token
                // lacks the claims. See the vault promote-step-up design.
                if *operation_bound {
                    let binding = op_binding.ok_or_else(|| {
                        "OidcStepUp: operation_bound required but this operation \
                         carries no binding context"
                            .to_string()
                    })?;
                    let vault_op = claims.vault_op.as_deref().ok_or_else(|| {
                        "OidcStepUp: token has no vault_op binding claim".to_string()
                    })?;
                    let nonce = claims
                        .nonce
                        .as_deref()
                        .ok_or_else(|| "OidcStepUp: token has no nonce claim".to_string())?;
                    let expected = vault_op_binding(
                        handle,
                        &binding.measurement_digest_hex,
                        binding.policy_version,
                        nonce,
                        claims.exp,
                    );
                    if vault_op != expected {
                        return Err("OidcStepUp: vault_op does not bind this operation \
                             (handle/measurement/policy_version/nonce/exp mismatch)"
                            .to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
//  Policy update evaluation
// ---------------------------------------------------------------------------

/// Validate a policy replacement against `Mutability`.
///
/// Computes the set of top-level [`PolicyField`]s that differ between
/// `old` and `new`. Rejects if any differ that are immutable, or that
/// the caller's role is not allowed to change.
pub fn evaluate_policy_update(
    old: &KeyPolicy,
    new: &KeyPolicy,
    role: CallerRole,
) -> Result<(), String> {
    let changed = diff_policy_fields(old, new);
    if changed.is_empty() {
        return Ok(());
    }
    let m = &old.mutability;
    let allowed = match role {
        CallerRole::Owner => &m.owner_can,
        CallerRole::Manager => &m.manager_can,
        CallerRole::Auditor | CallerRole::Tee => {
            return Err(format!(
                "caller role {:?} is not allowed to change any policy field",
                role
            ));
        }
    };
    for field in &changed {
        if m.immutable.contains(field) {
            return Err(format!("policy field {:?} is immutable", field));
        }
        if !allowed.contains(field) {
            return Err(format!(
                "caller role {:?} is not allowed to change policy field {:?}",
                role, field
            ));
        }
    }
    // Append/strengthen-only: an UpdatePolicy may not drop an OID the key already
    // enforces on every accepted measurement (e.g. downgrade an MR_APP key to
    // MR_ENCLAVE by removing the app-id at 3.6). Independent of Mutability, so it
    // holds however many approvals the caller carries. See the MR_APP sealing design.
    let old_required = key_required_oids(old);
    let new_required = key_required_oids(new);
    for oid in &old_required {
        if !new_required.iter().any(|o| o == oid) {
            return Err(format!(
                "required OID {} cannot be dropped: required_oids are append/strengthen-only",
                oid
            ));
        }
    }
    // The auto-migrate opt-in is a standing trust grant to the platform's own
    // enclave-upgrade approval; only the key OWNER may flip it, in either
    // direction. Unconditional like the OID rule above — the flag rides inside
    // `Lifecycle`, whose Mutability entry a policy may hand to managers for
    // TTL tuning, and that delegation must never extend to this grant.
    if old.lifecycle.auto_migrate_to_next_attestation_profile
        != new.lifecycle.auto_migrate_to_next_attestation_profile
        && role != CallerRole::Owner
    {
        return Err(
            "lifecycle.auto_migrate_to_next_attestation_profile may only be changed by the key owner"
                .into(),
        );
    }
    Ok(())
}

/// True iff `staged` differs from the accepted profile `active` ONLY in the
/// platform-runtime measurement — the acceptance test for the auto-migrate
/// opt-in ([`crate::types::Lifecycle`]). Requires:
///   - identical `required_oids` (as an unordered set; both sides are
///     normalised, so the app-code digest at …65230.3.2 and the app id at
///     …3.6 must be byte-identical),
///   - identical `attestation_servers` (URL + pinned SPKI, unordered),
///   - non-empty measurement lists of the SAME TEE family on both sides
///     (all-SGX or all-TDX — a runtime roll never changes the TEE type),
///   - actually different measurements (an identical profile is a re-stage,
///     not a migration — the caller dedupes that separately).
/// `name` is advisory display text and deliberately ignored.
pub(crate) fn runtime_only_delta(staged: &AttestationProfile, active: &AttestationProfile) -> bool {
    if !same_elements(&staged.required_oids, &active.required_oids) {
        return false;
    }
    if !same_elements(&staged.attestation_servers, &active.attestation_servers) {
        return false;
    }
    let family = |ms: &[Measurement]| -> Option<bool> {
        // Some(true) = all SGX, Some(false) = all TDX, None = empty or mixed.
        let mut it = ms.iter().map(|m| matches!(m, Measurement::Mrenclave(_)));
        let first = it.next()?;
        if it.all(|f| f == first) {
            Some(first)
        } else {
            None
        }
    };
    match (family(&staged.measurements), family(&active.measurements)) {
        (Some(a), Some(b)) if a == b => {}
        _ => return false,
    }
    staged.measurements != active.measurements
}

/// Unordered, duplicate-insensitive equality for small profile field vecs.
fn same_elements<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

/// The OIDs that EVERY accepted Tee profile already requires (the intersection of
/// each profile's required-OID set). Such an OID is structurally enforced by the
/// key: removing it from any one profile would let a matching caller bypass it.
/// Used to keep `required_oids` append/strengthen-only across UpdatePolicy and
/// PromotePendingProfile.
pub(crate) fn key_required_oids(policy: &KeyPolicy) -> Vec<String> {
    let mut profiles = policy.principals.tees.iter().filter_map(|p| match p {
        Principal::Tee(profile) => Some(&profile.required_oids),
        _ => None,
    });
    let first = match profiles.next() {
        Some(f) => f,
        None => return Vec::new(),
    };
    let mut acc: Vec<String> = first.iter().map(|r| r.oid.clone()).collect();
    for reqs in profiles {
        acc.retain(|oid| reqs.iter().any(|r| &r.oid == oid));
    }
    acc
}

fn diff_policy_fields(old: &KeyPolicy, new: &KeyPolicy) -> Vec<crate::types::PolicyField> {
    use crate::types::PolicyField as F;
    let mut out = Vec::new();
    if !principal_eq(&old.principals.owner, &new.principals.owner) {
        out.push(F::Owner);
    }
    if !principal_vec_eq(&old.principals.managers, &new.principals.managers) {
        out.push(F::Managers);
    }
    if !principal_vec_eq(&old.principals.auditors, &new.principals.auditors) {
        out.push(F::Auditors);
    }
    if !principal_vec_eq(&old.principals.tees, &new.principals.tees) {
        out.push(F::Tees);
    }
    if !operations_eq(&old.operations, &new.operations) {
        out.push(F::Operations);
    }
    if old.lifecycle != new.lifecycle {
        out.push(F::Lifecycle);
    }
    if !mutability_eq(&old.mutability, &new.mutability) {
        out.push(F::Mutability);
    }
    out
}

fn principal_eq(a: &Principal, b: &Principal) -> bool {
    a == b
}
fn principal_vec_eq(a: &[Principal], b: &[Principal]) -> bool {
    a == b
}
fn operations_eq(a: &[OperationRule], b: &[OperationRule]) -> bool {
    a == b
}
fn mutability_eq(a: &Mutability, b: &Mutability) -> bool {
    a == b
}

#[cfg(test)]
mod oidc_match_tests {
    use super::*;
    use enclave_os_common::oidc::OidcClaims;

    fn claims(sub: &str, roles: &[&str]) -> OidcClaims {
        OidcClaims {
            sub: sub.into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            is_manager: false,
            is_monitoring: false,
            amr: Vec::new(),
            acr: None,
            iat: 0,
            exp: 0,
            vault_op: None,
            nonce: None,
        }
    }

    fn oidc(sub: &str, roles: &[&str]) -> Principal {
        Principal::Oidc {
            issuer: "https://privasys.id".into(),
            sub: sub.into(),
            required_roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn subject_bound_requires_exact_sub() {
        let p = oidc("user-1", &[]);
        assert!(oidc_matches(&p, &claims("user-1", &[])));
        assert!(!oidc_matches(&p, &claims("user-2", &[])));
    }

    #[test]
    fn subject_bound_also_requires_roles() {
        let role = "privasys-platform:app:abc:approver";
        let p = oidc("user-1", &[role]);
        assert!(oidc_matches(&p, &claims("user-1", &[role])));
        assert!(!oidc_matches(&p, &claims("user-1", &[])));
    }

    #[test]
    fn role_only_matches_any_sub_holding_the_role() {
        let role = "privasys-platform:app:abc:approver";
        let p = oidc("", &[role]);
        assert!(oidc_matches(&p, &claims("user-1", &[role])));
        assert!(oidc_matches(&p, &claims("user-2", &[role])));
        assert!(!oidc_matches(&p, &claims("user-3", &["other:role"])));
    }

    #[test]
    fn role_only_with_no_roles_never_matches() {
        let p = oidc("", &[]);
        assert!(!oidc_matches(&p, &claims("user-1", &[])));
        assert!(!oidc_matches(&p, &claims("user-1", &["anything"])));
    }
}

#[cfg(test)]
mod measurement_match_tests {
    use super::*;
    use crate::quote::QuoteIdentity;

    fn tdx(mrtd: &str, rtmr1: &str, rtmr2: &str) -> QuoteIdentity {
        QuoteIdentity {
            tee: TeeType::Tdx,
            measurement: mrtd.into(),
            mrsigner: None,
            rtmr1: Some(rtmr1.into()),
            rtmr2: Some(rtmr2.into()),
        }
    }

    fn tdx_policy(mrtd: &str, rtmr1: &str, rtmr2: &str) -> Vec<Measurement> {
        vec![Measurement::Tdx {
            mrtd: mrtd.into(),
            rtmr1: rtmr1.into(),
            rtmr2: rtmr2.into(),
        }]
    }

    #[test]
    fn tdx_requires_mrtd_and_both_rtmrs() {
        let pol = tdx_policy("aa", "bb", "cc");
        assert!(measurement_matches(&tdx("aa", "bb", "cc"), &pol));
        // Same firmware MRTD but a different enclave-os-virtual build (RTMR1/2
        // differ) MUST be rejected — that is the whole point of this change.
        assert!(!measurement_matches(&tdx("aa", "xx", "yy"), &pol));
        assert!(!measurement_matches(&tdx("aa", "bb", "zz"), &pol)); // wrong rtmr2
        assert!(!measurement_matches(&tdx("aa", "zz", "cc"), &pol)); // wrong rtmr1
        assert!(!measurement_matches(&tdx("zz", "bb", "cc"), &pol)); // wrong mrtd
    }

    #[test]
    fn tdx_match_is_case_insensitive() {
        assert!(measurement_matches(&tdx("aa", "bb", "cc"), &tdx_policy("AA", "BB", "CC")));
    }

    #[test]
    fn tdx_quote_missing_rtmrs_is_rejected() {
        let pol = tdx_policy("aa", "bb", "cc");
        let mut id = tdx("aa", "bb", "cc");
        id.rtmr1 = None;
        assert!(!measurement_matches(&id, &pol));
    }

    #[test]
    fn or_across_allowed_builds_but_not_mixed() {
        // Promote window: old + new build both authorised.
        let pol = vec![
            Measurement::Tdx { mrtd: "aa".into(), rtmr1: "b1".into(), rtmr2: "c1".into() },
            Measurement::Tdx { mrtd: "aa".into(), rtmr1: "b2".into(), rtmr2: "c2".into() },
        ];
        assert!(measurement_matches(&tdx("aa", "b1", "c1"), &pol));
        assert!(measurement_matches(&tdx("aa", "b2", "c2"), &pol));
        // A frankenstein mix of the two builds' registers must not match.
        assert!(!measurement_matches(&tdx("aa", "b1", "c2"), &pol));
    }

    #[test]
    fn sgx_path_unaffected() {
        let pol = vec![Measurement::Mrenclave("dd".into())];
        let sgx = QuoteIdentity {
            tee: TeeType::Sgx,
            measurement: "dd".into(),
            mrsigner: None,
            rtmr1: None,
            rtmr2: None,
        };
        assert!(measurement_matches(&sgx, &pol));
        assert!(!measurement_matches(
            &QuoteIdentity {
                tee: TeeType::Sgx,
                measurement: "ee".into(),
                mrsigner: None,
                rtmr1: None,
                rtmr2: None
            },
            &pol
        ));
    }
}

#[cfg(test)]
mod auto_migrate_tests {
    use super::*;
    use crate::types::{
        AttestationProfile, AttestationServer, KeyPolicy, Lifecycle, Measurement, Mutability,
        OidRequirement, Principal, PrincipalSet,
    };

    fn profile(mrenclave: &str, code: &str, app_id: &str) -> AttestationProfile {
        AttestationProfile {
            name: format!("app:x / SGX ({})", mrenclave),
            measurements: vec![Measurement::Mrenclave(mrenclave.into())],
            attestation_servers: vec![AttestationServer {
                url: "https://as.privasys.org/verify".into(),
                pinned_spki_sha256_hex: None,
            }],
            required_oids: vec![
                OidRequirement {
                    oid: "1.3.6.1.4.1.65230.3.2".into(),
                    value: code.into(),
                },
                OidRequirement {
                    oid: "1.3.6.1.4.1.65230.3.6".into(),
                    value: app_id.into(),
                },
            ],
        }
    }

    fn tdx_profile(mrtd: &str, r1: &str, r2: &str, code: &str) -> AttestationProfile {
        let mut p = profile("unused", code, "aid");
        p.measurements = vec![Measurement::Tdx {
            mrtd: mrtd.into(),
            rtmr1: r1.into(),
            rtmr2: r2.into(),
        }];
        p
    }

    #[test]
    fn accepts_runtime_only_change() {
        let active = profile("aaaa", "code1", "aid1");
        let staged = profile("bbbb", "code1", "aid1");
        assert!(runtime_only_delta(&staged, &active));
        // Name is advisory and ignored — already differs in the fixtures.
    }

    #[test]
    fn rejects_code_or_app_id_change() {
        let active = profile("aaaa", "code1", "aid1");
        assert!(!runtime_only_delta(&profile("bbbb", "code2", "aid1"), &active));
        assert!(!runtime_only_delta(&profile("bbbb", "code1", "aid2"), &active));
        // Dropping an OID entirely is also not a runtime-only delta.
        let mut dropped = profile("bbbb", "code1", "aid1");
        dropped.required_oids.pop();
        assert!(!runtime_only_delta(&dropped, &active));
        // Adding an extra OID is a strengthening — still not auto-acceptable
        // (the platform must not author policy semantics on its own).
        let mut added = profile("bbbb", "code1", "aid1");
        added.required_oids.push(OidRequirement {
            oid: "1.3.6.1.4.1.65230.3.1".into(),
            value: "cfg".into(),
        });
        assert!(!runtime_only_delta(&added, &active));
    }

    #[test]
    fn rejects_identical_and_cross_family_and_server_changes() {
        let active = profile("aaaa", "code1", "aid1");
        // Identical profile is a re-stage, not a migration.
        assert!(!runtime_only_delta(&profile("aaaa", "code1", "aid1"), &active));
        // SGX -> TDX is never a runtime roll.
        assert!(!runtime_only_delta(&tdx_profile("m", "r1", "r2", "code1"), &active));
        // Changing the attestation server is a trust change, not a runtime roll.
        let mut moved = profile("bbbb", "code1", "aid1");
        moved.attestation_servers[0].url = "https://evil.example/verify".into();
        assert!(!runtime_only_delta(&moved, &active));
        // Empty measurement lists never qualify.
        let mut empty = profile("bbbb", "code1", "aid1");
        empty.measurements.clear();
        assert!(!runtime_only_delta(&empty, &active));
    }

    #[test]
    fn accepts_tdx_runtime_roll() {
        let active = tdx_profile("m1", "r1", "r2", "img1");
        assert!(runtime_only_delta(&tdx_profile("m2", "x1", "x2", "img1"), &active));
        assert!(!runtime_only_delta(&tdx_profile("m2", "x1", "x2", "img2"), &active));
    }

    fn policy_with_auto(auto: bool) -> KeyPolicy {
        KeyPolicy {
            version: 1,
            principals: PrincipalSet {
                owner: Principal::Oidc {
                    issuer: "https://privasys.id".into(),
                    sub: "owner".into(),
                    required_roles: vec![],
                },
                managers: vec![],
                auditors: vec![],
                tees: vec![],
            },
            operations: vec![],
            mutability: Mutability::default(),
            lifecycle: Lifecycle {
                ttl_seconds: 0,
                auto_migrate_to_next_attestation_profile: auto,
            },
        }
    }

    #[test]
    fn auto_migrate_flag_is_owner_only_to_change() {
        let off = policy_with_auto(false);
        let on = policy_with_auto(true);
        // Owner may flip it either way (Lifecycle is in owner_can by default).
        assert!(evaluate_policy_update(&off, &on, CallerRole::Owner).is_ok());
        assert!(evaluate_policy_update(&on, &off, CallerRole::Owner).is_ok());
        // A manager may not, even when Mutability delegates Lifecycle.
        let mut off_delegated = policy_with_auto(false);
        off_delegated
            .mutability
            .manager_can
            .push(crate::types::PolicyField::Lifecycle);
        let mut on_delegated = policy_with_auto(true);
        on_delegated
            .mutability
            .manager_can
            .push(crate::types::PolicyField::Lifecycle);
        let err = evaluate_policy_update(&off_delegated, &on_delegated, CallerRole::Manager)
            .unwrap_err();
        assert!(err.contains("only be changed by the key owner"), "{err}");
        // The same delegated manager may still change the TTL.
        let mut ttl_changed = off_delegated.clone();
        ttl_changed.lifecycle.ttl_seconds = 1234;
        assert!(evaluate_policy_update(&off_delegated, &ttl_changed, CallerRole::Manager).is_ok());
    }
}
