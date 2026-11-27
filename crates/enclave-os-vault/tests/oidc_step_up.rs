// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `OidcStepUp` policy condition: an owner bearer must carry a fresh WebAuthn
//! assertion bound to the exact operation (binding v2), whatever the legacy
//! `operation_bound` and `binding` fields of a stored condition say.

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
        approval: None,
    }
}

fn ctx_with_amr(sub: &str, amr: &[&str]) -> RequestContext {
    RequestContext {
        peer_cert_der: None,
        peer_evidence: None,
        attestation: "none".into(),
        fido2_user: None,
        app_name: None,
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


#[test]
fn every_step_up_is_read_as_binding_v2() {
    use enclave_os_vault::policy::evaluate_op;
    use enclave_os_vault::types::Condition;

    let c_ok = ctx_with_amr("dev", &["webauthn"]);
    let c_no = ctx_with_amr("dev", &["pwd"]);
    // Keys written before binding v2: unbound (operation_bound false) and v1
    // bound (operation_bound true), both with binding 0. A passkey bearer with
    // no binding no longer passes either, and no other method ever did.
    for (operation_bound, binding) in [(false, 0u8), (true, 0), (true, 2)] {
        let mut policy = owner_policy("dev", vec![Operation::PromoteProfile]);
        policy.operations[0].requires = vec![Condition::OidcStepUp {
            required_amr: vec!["webauthn".into()],
            operation_bound,
            fresh_for_seconds: 0,
            binding,
        }];
        let e = evaluate_op(&policy, Operation::PromoteProfile, "h", &c_ok, None).unwrap_err();
        assert!(e.contains("binding v2"), "{operation_bound} {binding}: {e}");
        assert!(evaluate_op(&policy, Operation::PromoteProfile, "h", &c_no, None).is_err());
    }
}

#[test]
fn an_unknown_binding_version_is_refused() {
    use enclave_os_vault::policy::evaluate_op;
    use enclave_os_vault::types::Condition;

    let mut policy = owner_policy("dev", vec![Operation::ExportKey]);
    policy.operations[0].requires = vec![Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: true,
        fresh_for_seconds: 0,
        binding: 1,
    }];
    let e = evaluate_op(&policy, Operation::ExportKey, "h", &ctx_with_amr("dev", &["webauthn"]), None)
        .unwrap_err();
    assert!(e.contains("unknown binding version"), "{e}");
}
