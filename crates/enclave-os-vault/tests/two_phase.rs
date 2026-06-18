// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Two-phase create (`CreateKey` without material + `ProvideMaterial`).
//!
//! Runs on the host: registers an in-memory OCall vtable and a
//! throwaway sealed KV store, then drives `VaultModule` through the
//! JSON wire protocol exactly like a remote caller would.

use std::collections::HashMap;
use std::sync::{Mutex, Once, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::{AppIdentity, EnclaveModule, RequestContext};
use enclave_os_common::ocall::OcallVtable;
use enclave_os_common::oidc::OidcClaims;
use enclave_os_common::protocol::{Request, Response};

use enclave_os_vault::types::{
    KeyPolicy, KeyType, Operation, OperationRule, Principal, PrincipalRef, PrincipalSet,
    VaultRequest, VaultResponse,
};
use enclave_os_vault::VaultModule;

// ---------------------------------------------------------------------------
//  Host-side test harness: in-memory KV + vtable
// ---------------------------------------------------------------------------

type KvMap = HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>;

fn kv_map() -> &'static Mutex<KvMap> {
    static MAP: OnceLock<Mutex<KvMap>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mem_put(table: &[u8], key: &[u8], val: &[u8]) -> Result<(), i32> {
    kv_map()
        .lock()
        .unwrap()
        .insert((table.to_vec(), key.to_vec()), val.to_vec());
    Ok(())
}

fn mem_get(table: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    Ok(kv_map()
        .lock()
        .unwrap()
        .get(&(table.to_vec(), key.to_vec()))
        .cloned())
}

fn mem_delete(table: &[u8], key: &[u8]) -> Result<bool, i32> {
    Ok(kv_map()
        .lock()
        .unwrap()
        .remove(&(table.to_vec(), key.to_vec()))
        .is_some())
}

fn mem_list(table: &[u8], prefix: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    Ok(kv_map()
        .lock()
        .unwrap()
        .keys()
        .filter(|(t, k)| t == table && k.starts_with(prefix))
        .map(|(_, k)| k.clone())
        .collect())
}

fn host_time() -> Result<u64, i32> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs())
}

fn setup() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        enclave_os_common::ocall::register(OcallVtable {
            net_tcp_listen: |_, _| Err(-1),
            net_tcp_accept: |_| Err(-1),
            net_tcp_connect: |_, _| Err(-1),
            net_send: |_, _| Err(-1),
            net_recv: |_, _| Err(-1),
            net_close: |_| {},
            kv_store_put: mem_put,
            kv_store_get: mem_get,
            kv_store_delete: mem_delete,
            kv_store_list_keys: mem_list,
            get_current_time: host_time,
            log: |_, _| {},
            cert_store_register: |_: AppIdentity| {},
            cert_store_unregister: |_| false,
        });
        enclave_os_kvstore::KvStoreModule::new([7u8; 32]).expect("init kv store");
    });
}

// ---------------------------------------------------------------------------
//  Wire helpers
// ---------------------------------------------------------------------------

fn ctx_oidc(sub: &str) -> RequestContext {
    RequestContext {
        peer_cert_der: None,
        client_challenge_nonce: None,
        oidc_claims: Some(OidcClaims {
            sub: sub.to_string(),
            roles: Vec::new(),
            is_manager: false,
            is_monitoring: false,
            amr: Vec::new(),
            acr: None,
            iat: 0,
        }),
    }
}

fn call(req: &VaultRequest, ctx: &RequestContext) -> VaultResponse {
    let module = VaultModule::new();
    let bytes = serde_json::to_vec(req).expect("serialise request");
    match module.handle(&Request::Data(bytes), ctx) {
        Some(Response::Data(b)) => serde_json::from_slice(&b).expect("parse response"),
        other => panic!("unexpected module response: {:?}", other.is_some()),
    }
}

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

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[test]
fn pending_create_requires_a_provide_material_rule() {
    setup();
    let resp = call(
        &VaultRequest::CreateKey {
            handle: "t/no-provide-rule/v1".into(),
            key_type: KeyType::RawShare,
            material_b64: None,
            exportable: true,
            // Policy grants only ExportKey: the key could never be filled.
            policy: owner_policy("alice", vec![Operation::ExportKey]),
        },
        &ctx_oidc("alice"),
    );
    match resp {
        VaultResponse::Error(e) => assert!(
            e.contains("ProvideMaterial"),
            "unexpected error: {e}"
        ),
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn two_phase_lifecycle() {
    setup();
    let handle = "t/two-phase/v1";
    let alice = ctx_oidc("alice");
    let policy = owner_policy(
        "alice",
        vec![Operation::ProvideMaterial, Operation::ExportKey],
    );

    // 1. Reserve handle + policy, no material.
    match call(
        &VaultRequest::CreateKey {
            handle: handle.into(),
            key_type: KeyType::RawShare,
            material_b64: None,
            exportable: true,
            policy,
        },
        &alice,
    ) {
        VaultResponse::KeyCreated {
            pending_material, ..
        } => assert!(pending_material, "expected pending_material=true"),
        other => panic!("expected KeyCreated, got {other:?}"),
    }

    // 2. Every key operation is denied while pending.
    match call(
        &VaultRequest::ExportKey {
            handle: handle.into(),
            approvals: Vec::new(),
        },
        &alice,
    ) {
        VaultResponse::Error(e) => {
            assert!(e.contains("not yet provided"), "unexpected error: {e}")
        }
        other => panic!("expected pending denial, got {other:?}"),
    }

    // 3. A caller outside the policy cannot fill the material.
    match call(
        &VaultRequest::ProvideMaterial {
            handle: handle.into(),
            material_b64: b64(b"attacker material"),
            approvals: Vec::new(),
        },
        &ctx_oidc("mallory"),
    ) {
        VaultResponse::Error(e) => assert!(
            e.contains("not in policy.principals"),
            "unexpected error: {e}"
        ),
        other => panic!("expected denial, got {other:?}"),
    }

    // 4. The granted principal fills the material.
    let material = b"the actual shamir share".to_vec();
    match call(
        &VaultRequest::ProvideMaterial {
            handle: handle.into(),
            material_b64: b64(&material),
            approvals: Vec::new(),
        },
        &alice,
    ) {
        VaultResponse::MaterialProvided { handle: h, .. } => assert_eq!(h, handle),
        other => panic!("expected MaterialProvided, got {other:?}"),
    }

    // 5. Operations work now.
    match call(
        &VaultRequest::ExportKey {
            handle: handle.into(),
            approvals: Vec::new(),
        },
        &alice,
    ) {
        VaultResponse::KeyMaterial { material: m, .. } => assert_eq!(m, material),
        other => panic!("expected KeyMaterial, got {other:?}"),
    }

    // 6. One-shot: refilling is rejected, even for the granted principal.
    match call(
        &VaultRequest::ProvideMaterial {
            handle: handle.into(),
            material_b64: b64(b"replacement material"),
            approvals: Vec::new(),
        },
        &alice,
    ) {
        VaultResponse::Error(e) => {
            assert!(e.contains("already provided"), "unexpected error: {e}")
        }
        other => panic!("expected one-shot denial, got {other:?}"),
    }
}

#[test]
fn single_phase_create_is_unchanged() {
    setup();
    let handle = "t/one-phase/v1";
    let alice = ctx_oidc("alice");
    let material = b"plain old single-phase".to_vec();

    match call(
        &VaultRequest::CreateKey {
            handle: handle.into(),
            key_type: KeyType::RawShare,
            material_b64: Some(b64(&material)),
            exportable: true,
            policy: owner_policy("alice", vec![Operation::ExportKey]),
        },
        &alice,
    ) {
        VaultResponse::KeyCreated {
            pending_material, ..
        } => assert!(!pending_material),
        other => panic!("expected KeyCreated, got {other:?}"),
    }

    match call(
        &VaultRequest::ExportKey {
            handle: handle.into(),
            approvals: Vec::new(),
        },
        &alice,
    ) {
        VaultResponse::KeyMaterial { material: m, .. } => assert_eq!(m, material),
        other => panic!("expected KeyMaterial, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
//  OidcStepUp condition (promote step-up, increment 1 — inert in production)
// ---------------------------------------------------------------------------

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
    assert!(evaluate_op(
        &policy,
        Operation::PromoteProfile,
        "h",
        &[],
        &ctx_with_amr("dev", &["webauthn"]),
    )
    .is_ok());

    // same owner, no webauthn in amr: denied.
    assert!(evaluate_op(
        &policy,
        Operation::PromoteProfile,
        "h",
        &[],
        &ctx_with_amr("dev", &["pwd"]),
    )
    .is_err());
}

#[test]
fn oidc_step_up_operation_bound_fails_closed() {
    use enclave_os_vault::policy::evaluate_op;
    use enclave_os_vault::types::Condition;

    let mut policy = owner_policy("dev", vec![Operation::PromoteProfile]);
    policy.operations[0].requires = vec![Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: true, // not yet enforceable -> must fail closed
        fresh_for_seconds: 0,
    }];

    assert!(evaluate_op(
        &policy,
        Operation::PromoteProfile,
        "h",
        &[],
        &ctx_with_amr("dev", &["webauthn"]),
    )
    .is_err());
}
