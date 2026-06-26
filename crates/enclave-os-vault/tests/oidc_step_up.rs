// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `OidcStepUp` policy condition (promote step-up): an owner bearer must carry a
//! fresh WebAuthn assertion, optionally bound to the exact operation.

use std::vec::Vec;

use enclave_os_common::modules::RequestContext;
use enclave_os_common::oidc::OidcClaims;

use enclave_os_vault::types::{
    KeyPolicy, Operation, OperationRule, Principal, PrincipalRef, PrincipalSet,
};

fn owner_policy(sub: &str, ops: Vec<Operation>) -> KeyPolicy {
    KeyPolicy {
        version: 1,
        principals: PrincipalSet {
            owner: Principal::Oidc {
                issuer: "https://privasys.id".into(),
                sub: sub.into(),
                required_roles: Vec::new(),
            },
            managers: Vec::new(),
            auditors: Vec::new(),
            tees: Vec::new(),
        },
        operations: vec![OperationRule {
            ops,
            principals: vec![PrincipalRef::Owner],
            requires: Vec::new(),
        }],
        mutability: Default::default(),
        lifecycle: Default::default(),
    }
}

fn ctx_with_amr(sub: &str, amr: &[&str]) -> RequestContext {
    RequestContext {
        peer_cert_der: None,
        client_challenge_nonce: None,
        oidc_claims: Some(OidcClaims {
            sub: sub.to_string(),
            roles: Vec::new(),
            is_manager: false,
            is_monitoring: false,
            amr: amr.iter().map(|s| s.to_string()).collect(),
            acr: None,
            iat: 0,
            exp: 0,
            vault_op: None,
            nonce: None,
        }),
    }
}

fn ctx_step_up(
    sub: &str,
    amr: &[&str],
    vault_op: Option<&str>,
    nonce: Option<&str>,
    exp: u64,
) -> RequestContext {
    RequestContext {
        peer_cert_der: None,
        client_challenge_nonce: None,
        oidc_claims: Some(OidcClaims {
            sub: sub.to_string(),
            roles: Vec::new(),
            is_manager: false,
            is_monitoring: false,
            amr: amr.iter().map(|s| s.to_string()).collect(),
            acr: None,
            iat: 0,
            exp,
            vault_op: vault_op.map(|s| s.to_string()),
            nonce: nonce.map(|s| s.to_string()),
        }),
    }
}

#[test]
fn oidc_step_up_amr_gate() {
    use enclave_os_vault::policy::evaluate_op;
    use enclave_os_vault::types::Condition;

    let mut policy = owner_policy("dev", vec![Operation::PromoteProfile]);
    policy.operations[0].requires = vec![Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: false,
        fresh_for_seconds: 0, // freshness skipped (no clock in unit env)
    }];

    // owner bearer carrying a webauthn step-up: allowed.
    let c_ok = ctx_with_amr("dev", &["webauthn"]);
    assert!(evaluate_op(&policy, Operation::PromoteProfile, "h", &[], &c_ok, None).is_ok());

    // same owner, no webauthn in amr: denied.
    let c_no = ctx_with_amr("dev", &["pwd"]);
    assert!(evaluate_op(&policy, Operation::PromoteProfile, "h", &[], &c_no, None).is_err());
}

#[test]
fn oidc_step_up_operation_bound() {
    use enclave_os_vault::policy::{evaluate_op, vault_op_binding, OpBinding};
    use enclave_os_vault::types::Condition;

    let mut policy = owner_policy("dev", vec![Operation::PromoteProfile]);
    policy.operations[0].requires = vec![Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: true,
        fresh_for_seconds: 0,
    }];

    let handle = "apps.privasys.org/x/storage-kek/v1";
    let digest = "abc123"; // stand-in promoted-measurement digest
    let version = 7u32;
    let nonce = "n0nce";
    let exp = 0u64; // freshness skipped; exp is only a binding input here
    let binding = OpBinding {
        measurement_digest_hex: digest.to_string(),
        policy_version: version,
    };

    // correct, operation-bound token -> allowed.
    let good = vault_op_binding(handle, digest, version, nonce, exp);
    let ok = ctx_step_up("dev", &["webauthn"], Some(&good), Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::PromoteProfile, handle, &[], &ok, Some(&binding)).is_ok());

    // token bound to a DIFFERENT measurement -> denied.
    let wrong = vault_op_binding(handle, "deadbeef", version, nonce, exp);
    let bad = ctx_step_up("dev", &["webauthn"], Some(&wrong), Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::PromoteProfile, handle, &[], &bad, Some(&binding)).is_err());

    // operation_bound but the handler supplied no binding -> fail closed.
    assert!(evaluate_op(&policy, Operation::PromoteProfile, handle, &[], &ok, None).is_err());

    // operation_bound but the token carries no vault_op -> fail closed.
    let noop = ctx_step_up("dev", &["webauthn"], None, Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::PromoteProfile, handle, &[], &noop, Some(&binding)).is_err());
}

#[test]
fn oidc_step_up_export_operation_bound() {
    use enclave_os_vault::policy::{evaluate_op, vault_op_binding, OpBinding};
    use enclave_os_vault::types::Condition;

    // An exportable user key whose ExportKey rule requires an operation-bound
    // WebAuthn step-up. Export has no target measurement, so the binding's
    // measurement slot is empty — exactly what handle_export supplies.
    let mut policy = owner_policy("dev", vec![Operation::ExportKey]);
    policy.operations[0].requires = vec![Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: true,
        fresh_for_seconds: 0,
    }];

    let handle = "users/dev/my-secret";
    let version = 1u32;
    let nonce = "n0nce";
    let exp = 0u64;
    let binding = OpBinding {
        measurement_digest_hex: String::new(),
        policy_version: version,
    };

    // Correct export-bound token (empty measurement) -> allowed.
    let good = vault_op_binding(handle, "", version, nonce, exp);
    let ok = ctx_step_up("dev", &["webauthn"], Some(&good), Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::ExportKey, handle, &[], &ok, Some(&binding)).is_ok());

    // A token bound to a non-empty measurement (e.g. a captured promote
    // approval for the same handle) -> denied. Export and promote can never
    // share a binding.
    let promote = vault_op_binding(handle, "abc123", version, nonce, exp);
    let bad = ctx_step_up("dev", &["webauthn"], Some(&promote), Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::ExportKey, handle, &[], &bad, Some(&binding)).is_err());

    // operation_bound but no vault_op on the token -> fail closed.
    let noop = ctx_step_up("dev", &["webauthn"], None, Some(nonce), exp);
    assert!(evaluate_op(&policy, Operation::ExportKey, handle, &[], &noop, Some(&binding)).is_err());
}
