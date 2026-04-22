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

use enclave_os_common::modules::RequestContext;
use enclave_os_common::oidc::OidcClaims;

use crate::quote::{dissect_peer_cert, parse_quote, verify_challenge_binding, TeeType};
use crate::types::{
    AttestationProfile, KeyPolicy, Measurement, Mutability, Operation, OperationRule, Principal,
    PrincipalRef,
};

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
                if tee_matches(profile, peer_der, ctx.client_challenge_nonce.as_deref()) {
                    return Some((PrincipalRef::Tee(i as u32), CallerRole::Tee));
                }
            }
        }
    }
    None
}

/// `Principal::Oidc` match: same sub + all required roles present.
fn oidc_matches(principal: &Principal, claims: &OidcClaims) -> bool {
    match principal {
        Principal::Oidc {
            issuer: _,
            sub,
            required_roles,
        } => sub == &claims.sub && has_required_roles(claims, required_roles),
        Principal::Tee(_) => false,
    }
}

/// True iff every name in `required_roles` is present in the verified
/// claims (matched by the role's `as_str()` form).
pub fn has_required_roles(claims: &OidcClaims, required_roles: &[String]) -> bool {
    if required_roles.is_empty() {
        return true;
    }
    let claim_role_strs: Vec<&str> = claims.roles.iter().map(|r| oidc_role_str(r)).collect();
    required_roles
        .iter()
        .all(|r| claim_role_strs.iter().any(|c| c.eq_ignore_ascii_case(r)))
}

fn oidc_role_str(role: &enclave_os_common::oidc::OidcRole) -> &'static str {
    use enclave_os_common::oidc::OidcRole;
    match role {
        OidcRole::Manager => "manager",
        OidcRole::Monitoring => "monitoring",
        OidcRole::SecretOwner => "secret-owner",
        OidcRole::SecretManager => "secret-manager",
    }
}

/// Verify that the peer cert satisfies a given `AttestationProfile`.
///
/// Performs (in order):
///   1. cert dissection (quote + OID claims + pubkey),
///   2. attestation server verification of the quote,
///   3. parse + measurement match against `profile.measurements`,
///   4. bidirectional challenge-response binding,
///   5. required OID extension match.
fn tee_matches(
    profile: &AttestationProfile,
    peer_der: &[u8],
    challenge_nonce: Option<&[u8]>,
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
    if verify_challenge_binding(&evidence.evidence, &evidence.pubkey_raw, challenge_nonce)
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
    allowed.iter().any(|am| match (am, identity.tee) {
        (Measurement::Mrenclave(s), TeeType::Sgx) => s == &m,
        (Measurement::Mrtd(s), TeeType::Tdx) => s == &m,
        _ => false,
    })
}

// ---------------------------------------------------------------------------
//  Op evaluation
// ---------------------------------------------------------------------------

/// Verify the caller is allowed to perform `op` on the key whose policy
/// is `policy`.
pub fn evaluate_op(
    policy: &KeyPolicy,
    op: Operation,
    ctx: &RequestContext,
) -> Result<(), String> {
    let (caller_ref, _role) = resolve_caller(policy, ctx).ok_or_else(|| {
        "caller is not in policy.principals (no OIDC subject or RA-TLS TEE \
         matches the key's PrincipalSet)"
            .to_string()
    })?;

    let granted = policy
        .operations
        .iter()
        .any(|rule| rule.ops.contains(&op) && rule_grants_to(rule, caller_ref));

    if granted {
        Ok(())
    } else {
        Err(format!(
            "caller is in policy.principals but no OperationRule grants {:?}",
            op
        ))
    }
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
    Ok(())
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
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| x.ops == y.ops && x.principals == y.principals)
}
fn mutability_eq(a: &Mutability, b: &Mutability) -> bool {
    a.owner_can == b.owner_can
        && a.manager_can == b.manager_can
        && a.immutable == b.immutable
}


