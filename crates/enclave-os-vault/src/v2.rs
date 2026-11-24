// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault key ownership, step 1 (`wallet-signed-authority-wire-formats.md`).
//!
//! - The vault's member id and the identity call (formats §1).
//! - The policy digest over the policy JSON exactly as a request carries it,
//!   in RFC 8785 canonical form (formats §5.1).
//! - Binding v2: the approval text that names the constellation's members,
//!   the operation, its target and the approver (formats §5).
//! - Approval by default: a new policy must ask for an approval on the
//!   operations that govern a key (formats §4).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use crate::types::{Condition, KeyPolicy, Operation};

/// Domain of the binding v2 text (formats §5).
pub const BINDING_V2_DOMAIN: &str = "privasys-vault-approval/v2";
/// Domain of a member id (formats §1).
pub const MEMBER_DOMAIN: &str = "privasys-vault-member-v1\n";
/// Domain of the identity quote's report data (formats §1).
pub const IDENTITY_DOMAIN: &str = "privasys-vault-identity-v1\n";
/// Domain of the step 1 interim billing id (formats §1; replaced in step 2).
pub const BILLING_IMPLICIT_DOMAIN: &str = "privasys-billing-implicit-v0\n";

/// The largest integer a canonical policy may hold (formats §5.1).
const MAX_SAFE_INTEGER: u64 = 1 << 53;

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn b64u(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
//  Strict JSON and RFC 8785
// ---------------------------------------------------------------------------

/// A JSON value parsed under the canonical restrictions of formats §5.1:
/// unique ASCII member names, integers within 2^53, no floats.
#[derive(Debug, Clone, PartialEq)]
pub enum Strict {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Strict>),
    Object(BTreeMap<String, Strict>),
}

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("canonical JSON")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
        Ok(Strict::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Strict, E> {
        Ok(Strict::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(E::custom("integer above 2^53"));
        }
        Ok(Strict::Int(v as i64))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer beyond 2^53"));
        }
        Ok(Strict::Int(v))
    }
    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Strict, E> {
        Err(E::custom("floating-point numbers are not canonical"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict::Str(v.to_string()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
        Ok(Strict::Str(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Strict>()? {
            out.push(v);
        }
        Ok(Strict::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = BTreeMap::new();
        while let Some(k) = map.next_key::<String>()? {
            if !k.is_ascii() {
                return Err(de::Error::custom("member names must be ASCII"));
            }
            let v = map.next_value::<Strict>()?;
            if out.insert(k, v).is_some() {
                return Err(de::Error::custom("duplicate member name"));
            }
        }
        Ok(Strict::Object(out))
    }
}

/// Parse `raw` as strict canonical-input JSON.
pub fn parse_strict(raw: &str) -> Result<Strict, String> {
    serde_json::from_str::<Strict>(raw).map_err(|e| format!("policy is not canonical JSON: {e}"))
}

/// RFC 8785 serialisation. Member names are ASCII, so sorting by bytes equals
/// sorting by UTF-16 code units; integers render as plain decimals.
pub fn jcs(v: &Strict) -> String {
    let mut out = String::new();
    write_jcs(v, &mut out);
    out
}

fn write_jcs(v: &Strict, out: &mut String) {
    match v {
        Strict::Null => out.push_str("null"),
        Strict::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Strict::Int(i) => out.push_str(&i.to_string()),
        Strict::Str(s) => write_jcs_string(s, out),
        Strict::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(e, out);
            }
            out.push(']');
        }
        Strict::Object(m) => {
            out.push('{');
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_string(k, out);
                out.push(':');
                write_jcs(e, out);
            }
            out.push('}');
        }
    }
}

/// RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify) string escaping.
fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A policy as a v2 request carries it: the typed policy, and its digest over
/// the JSON exactly as received (formats §5.1).
pub struct CanonicalPolicy {
    pub policy: KeyPolicy,
    /// `PD(policy)`: hex SHA-256 of the RFC 8785 form of the JSON as sent.
    pub pd: String,
}

/// Check a policy's JSON against formats §5.1 and compute its digest:
/// canonical input, no field the vault does not know, and nothing the vault's
/// normalisation would change.
pub fn canonical_policy(raw: &str) -> Result<CanonicalPolicy, String> {
    let strict = parse_strict(raw)?;
    let policy: KeyPolicy =
        serde_json::from_str(raw).map_err(|e| format!("policy does not parse: {e}"))?;

    // No unknown fields: every member the request names must survive the
    // typed round trip, at every depth.
    let typed: serde_json::Value =
        serde_json::to_value(&policy).map_err(|e| format!("serialise policy: {e}"))?;
    let sent: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("policy does not parse: {e}"))?;
    if let Some(path) = first_unknown_field(&sent, &typed, "") {
        return Err(format!("policy names a field the vault does not know: {path}"));
    }

    // Nothing normalised away: what is approved is what is stored.
    let normalised = crate::normalise_policy(policy.clone());
    let a = serde_json::to_value(&policy).map_err(|e| format!("serialise policy: {e}"))?;
    let b = serde_json::to_value(&normalised).map_err(|e| format!("serialise policy: {e}"))?;
    if a != b {
        return Err(
            "policy is not normalised (lower-case hex, a TTL within the vault's bounds): \
             send it as the vault would store it"
                .into(),
        );
    }

    Ok(CanonicalPolicy {
        policy,
        pd: hex(&sha256(jcs(&strict).as_bytes())),
    })
}

fn is_default_like(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_u64() == Some(0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// The first member of `sent` that the typed round trip `typed` dropped.
fn first_unknown_field(
    sent: &serde_json::Value,
    typed: &serde_json::Value,
    path: &str,
) -> Option<String> {
    use serde_json::Value;
    match (sent, typed) {
        (Value::Object(s), Value::Object(t)) => {
            for (k, sv) in s {
                let p = format!("{path}/{k}");
                match t.get(k) {
                    // The typed form leaves out a field at its default (an
                    // absent option, binding 0); sent at that default it is
                    // known and inert. Anything else it dropped is unknown.
                    None if is_default_like(sv) => {}
                    None => return Some(p),
                    Some(tv) => {
                        if let Some(x) = first_unknown_field(sv, tv, &p) {
                            return Some(x);
                        }
                    }
                }
            }
            None
        }
        (Value::Array(s), Value::Array(t)) => {
            for (i, (sv, tv)) in s.iter().zip(t.iter()).enumerate() {
                if let Some(x) = first_unknown_field(sv, tv, &format!("{path}/{i}")) {
                    return Some(x);
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
//  Identity
// ---------------------------------------------------------------------------

/// `member_id` = hex H("privasys-vault-member-v1\n" || SEC1 uncompressed key).
pub fn member_id(public_key_sec1: &[u8]) -> String {
    let mut buf = Vec::with_capacity(MEMBER_DOMAIN.len() + public_key_sec1.len());
    buf.extend_from_slice(MEMBER_DOMAIN.as_bytes());
    buf.extend_from_slice(public_key_sec1);
    hex(&sha256(&buf))
}

/// The step 1 interim billing id: the vault's one issuer and audience
/// (formats §1). Step 2 replaces it with the sealed billing configuration.
pub fn implicit_billing_id(issuer: &str, audience: &str) -> String {
    let s = format!("{BILLING_IMPLICIT_DOMAIN}{issuer}\n{audience}");
    hex(&sha256(s.as_bytes()))
}

/// Report data of the identity quote (formats §1), in its first 32 bytes.
pub fn identity_report_data(member_id: &str, billing_id: &str) -> [u8; 32] {
    sha256(format!("{IDENTITY_DOMAIN}{member_id}\n{billing_id}").as_bytes())
}

/// This vault's member id and billing id, from its sealed key and its OIDC
/// configuration.
pub fn own_identity() -> Result<(Vec<u8>, String, String), String> {
    let kv = enclave_os_kvstore::kv_store().ok_or_else(|| "kv store not initialised".to_string())?;
    let mut store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
    let public_key = crate::signing::load_or_init_public_key(&mut store)?;
    drop(store);
    let mid = member_id(&public_key);
    let cfg = enclave_os_common::oidc::global_oidc_config()
        .ok_or_else(|| "OIDC is not configured".to_string())?;
    Ok((public_key, mid, implicit_billing_id(&cfg.issuer, &cfg.audience)))
}

// ---------------------------------------------------------------------------
//  Binding v2
// ---------------------------------------------------------------------------

/// The binding v2 text (formats §5). `members` must already be checked.
#[allow(clippy::too_many_arguments)]
pub fn binding_v2_text(
    members: &[String],
    op: &str,
    handle: &str,
    target: &str,
    policy_version: u32,
    approver: &str,
    holder_head: &str,
    nonce: &str,
    exp: u64,
) -> String {
    let mut s = String::new();
    s.push_str(BINDING_V2_DOMAIN);
    s.push('\n');
    s.push_str(&members.len().to_string());
    for m in members {
        s.push('\n');
        s.push_str(m);
    }
    for line in [op, handle, target, &policy_version.to_string(), approver, holder_head, nonce, &exp.to_string()] {
        s.push('\n');
        s.push_str(line);
    }
    s
}

/// Target of a `delete_after` (formats §9.2):
/// hex H("privasys-delete-after-v1\n" successor "\n" successor_target).
pub fn delete_after_target(successor: &str, successor_target: &str) -> Result<String, String> {
    check_line("successor", successor)?;
    check_line("successor_target", successor_target)?;
    Ok(hex(&sha256(
        format!("privasys-delete-after-v1\n{successor}\n{successor_target}").as_bytes(),
    )))
}

/// How long a binding v2 may live for `op` (formats §5): 600 s, except a
/// `delete_after`, presented only once its migration has finished (24 h).
pub fn max_lifetime(op: &str) -> u64 {
    if op == "delete_after" {
        86_400
    } else {
        600
    }
}

/// `vault_op` for a v2 binding: b64u(H(text)).
pub fn vault_op_v2(text: &str) -> String {
    b64u(&sha256(text.as_bytes()))
}

/// Spent bindings, kept until their expiry (formats §5). In enclave memory:
/// the guarantee is the short expiry and the policy version, this is an extra.
static SPENT: std::sync::Mutex<BTreeMap<[u8; 32], u64>> = std::sync::Mutex::new(BTreeMap::new());
const SPENT_MAX: usize = 8192;

/// Record a binding as used. `false` if it was used before (or the table is
/// full of live entries, which refuses rather than forgets).
pub fn spend_binding(text: &str, exp: u64, now: u64) -> bool {
    let key = sha256(text.as_bytes());
    let Ok(mut spent) = SPENT.lock() else { return false };
    spent.retain(|_, e| *e >= now);
    if spent.contains_key(&key) || spent.len() >= SPENT_MAX {
        return false;
    }
    spent.insert(key, exp);
    true
}

/// Check a member set: lower-case 64-hex ids, sorted ascending, unique, and
/// containing this vault's own id.
pub fn check_members(members: &[String], own: &str) -> Result<(), String> {
    if members.is_empty() {
        return Err("binding names no members".into());
    }
    for m in members {
        if m.len() != 64 || !m.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(format!("member id {m:?} is not 64 lower-case hex digits"));
        }
    }
    if !members.windows(2).all(|w| w[0] < w[1]) {
        return Err("binding members must be sorted ascending and unique".into());
    }
    if !members.iter().any(|m| m == own) {
        return Err("the approval does not name this vault".into());
    }
    Ok(())
}

/// A value of the binding text must not contain a newline.
pub fn check_line(name: &str, v: &str) -> Result<(), String> {
    if v.contains('\n') || v.is_empty() {
        return Err(format!("binding field {name} is empty or contains a newline"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
//  Approval by default (formats §4)
// ---------------------------------------------------------------------------

/// The value of `KeyPolicy::approval` that opts a key out of approvals.
pub const APPROVAL_NONE: &str = "none";

/// Refuse a new policy that lets an operation governing the key happen
/// without an approval, unless it says so explicitly (`"approval": "none"`).
/// Promote, update and delete are always checked; export only when the key
/// is exportable.
pub fn check_approval_by_default(policy: &KeyPolicy, exportable: bool) -> Result<(), String> {
    match policy.approval.as_deref() {
        None => {}
        Some(APPROVAL_NONE) => return Ok(()),
        Some(other) => return Err(format!("policy approval {other:?} is not known (only \"none\")")),
    }
    let mut ops = vec![Operation::PromoteProfile, Operation::UpdatePolicy, Operation::DeleteKey];
    if exportable {
        ops.push(Operation::ExportKey);
    }
    for op in ops {
        for rule in policy.operations.iter().filter(|r| r.ops.contains(&op)) {
            let asks = rule.requires.iter().any(|c| {
                matches!(c, Condition::OidcStepUp { .. } | Condition::ManagerApproval { .. })
            });
            if !asks {
                return Err(format!(
                    "a rule lets {op:?} happen without an approval: add an approval rule, \
                     or set \"approval\": \"none\" in the policy to say so explicitly"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_v2_vector_matches_the_spec() {
        // wallet-signed-authority-wire-formats.md §5.2
        let members = vec!["1".repeat(64), "2".repeat(64)];
        let text = binding_v2_text(
            &members,
            "update_policy",
            "apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2",
            "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
            3,
            "oidc:0:test-subject-1",
            "-",
            "AAECAwQFBgcICQoLDA0ODw",
            1764000600,
        );
        assert_eq!(text.len(), 356);
        assert_eq!(hex(&sha256(text.as_bytes())), "f4fe5392066464c3e92ca26c442af4f53d2009e87532a398923cea5f95f31b23");
        assert_eq!(vault_op_v2(&text), "9P5TkgZkZMPpLKJsRCr09T0gCeh1MqOYkjzqX5XzGyM");
    }

    #[test]
    fn strict_json_refuses_duplicates_floats_and_big_integers() {
        assert!(parse_strict(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict(r#"{"a":1.5}"#).is_err());
        assert!(parse_strict(r#"{"a":9007199254740993}"#).is_err());
        assert!(parse_strict(r#"{"é":1}"#).is_err());
        assert!(parse_strict(r#"{"a":9007199254740992}"#).is_ok());
    }

    #[test]
    fn jcs_sorts_and_escapes() {
        let v = parse_strict("{\"b\":[1,{\"d\":\"\\u0001x\\u00e9\\n\"}],\"a\":true}").unwrap();
        assert_eq!(jcs(&v), "{\"a\":true,\"b\":[1,{\"d\":\"\\u0001xé\\n\"}]}");
    }

    #[test]
    fn members_must_be_sorted_and_name_this_vault() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert!(check_members(&[a.clone(), b.clone()], &a).is_ok());
        assert!(check_members(&[b.clone(), a.clone()], &a).is_err());
        assert!(check_members(&[b.clone()], &a).is_err());
        assert!(check_members(&["A".repeat(64)], &"A".repeat(64)).is_err());
    }

    fn policy(requires: &str, extra: &str) -> String {
        format!(
            r#"{{"version":1,"principals":{{"owner":{{"Oidc":{{"issuer":"https://privasys.id","sub":"o","required_roles":[]}}}},"managers":[],"auditors":[],"tees":[]}},"operations":[{{"ops":["PromoteProfile","UpdatePolicy","DeleteKey","ExportKey"],"principals":["Owner"],"requires":[{requires}]}}],"lifecycle":{{"ttl_seconds":7776000,"auto_migrate_to_next_attestation_profile":false}}{extra}}}"#
        )
    }
    const STEP_UP: &str = r#"{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}"#;

    #[test]
    fn approval_by_default() {
        let with = canonical_policy(&policy(STEP_UP, "")).unwrap().policy;
        assert!(check_approval_by_default(&with, true).is_ok());
        let without = canonical_policy(&policy("", "")).unwrap().policy;
        assert!(check_approval_by_default(&without, true).is_err());
        let opted_out = canonical_policy(&policy("", r#","approval":"none""#)).unwrap().policy;
        assert!(check_approval_by_default(&opted_out, true).is_ok());
        let unknown = canonical_policy(&policy("", r#","approval":"maybe""#)).unwrap().policy;
        assert!(check_approval_by_default(&unknown, true).is_err());
    }

    #[test]
    fn canonical_policy_refuses_unknown_and_unnormalised() {
        assert!(canonical_policy(&policy(STEP_UP, r#","x":1"#)).is_err());
        assert!(canonical_policy(&policy(STEP_UP, r#","x":null"#)).is_ok());
        let upper = policy(STEP_UP, "").replace(
            r#""tees":[]"#,
            r#""tees":[{"Tee":{"measurements":[{"Mrenclave":"AB"}],"required_oids":[]}}]"#,
        );
        assert!(canonical_policy(&upper).is_err());
        let zero_ttl = policy(STEP_UP, "").replace("7776000", "0");
        assert!(canonical_policy(&zero_ttl).is_err());
    }

    #[test]
    fn delete_after_targets_and_lifetimes() {
        let a = delete_after_target("h/2", "-").unwrap();
        let b = delete_after_target("h/3", "-").unwrap();
        assert_ne!(a, b);
        assert!(delete_after_target("h\n2", "-").is_err());
        assert_eq!(max_lifetime("delete_after"), 86_400);
        assert_eq!(max_lifetime("delete"), 600);
    }
}

/// Shared test vectors (formats §5.2): `testdata/v2_vectors.json`, which the
/// Go client, privasys.id and the wallet check their own code against.
/// `cargo test -- --ignored write_vectors` regenerates the file; the
/// ordinary test asserts the code still produces exactly what it holds.
#[cfg(test)]
mod vectors {
    use super::*;

    const SAMPLE_POLICY: &str = r#"{"version":1,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"tëst-sübject-1 é\n","required_roles":[]}},"managers":[{"Oidc":{"issuer":"https://privasys.id","sub":"","required_roles":["privasys-platform:app:0123456789abcdef0123456789abcdef:approver"]}}],"auditors":[],"tees":[]},"operations":[{"ops":["PromoteProfile","UpdatePolicy","DeleteKey"],"principals":["Owner",{"Manager":0}],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]}],"lifecycle":{"ttl_seconds":7776000,"auto_migrate_to_next_attestation_profile":false},"approval":null}"#;

    fn compute() -> serde_json::Value {
        let canonical = jcs(&parse_strict(SAMPLE_POLICY).unwrap());
        let pd = canonical_policy(SAMPLE_POLICY).unwrap().pd;
        let mut pk = vec![4u8];
        pk.extend(1..=64u8);
        let mid = member_id(&pk);
        let billing = implicit_billing_id("https://privasys.id", "privasys-platform-test");
        let members = vec!["1".repeat(64), "2".repeat(64)];
        let text = binding_v2_text(
            &members,
            "update_policy",
            "apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2",
            &pd,
            3,
            "oidc:0:test-subject-1",
            "-",
            "AAECAwQFBgcICQoLDA0ODw",
            1764000600,
        );
        serde_json::json!({
            "policy_digest": {
                "policy_as_sent": SAMPLE_POLICY,
                "jcs": canonical,
                "pd": pd,
            },
            "member_id": {
                "public_key_sec1_hex": hex(&pk),
                "member_id": mid,
            },
            "billing_id_implicit_v0": {
                "issuer": "https://privasys.id",
                "audience": "privasys-platform-test",
                "billing_id": billing,
            },
            "identity_report_data": {
                "member_id": mid,
                "billing_id": billing,
                "report_data_first_32_hex": hex(&identity_report_data(&mid, &billing)),
            },
            "binding_v2_update_policy_with_pd": {
                "members": members,
                "op": "update_policy",
                "handle": "apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2",
                "target": pd,
                "policy_version": 3,
                "approver": "oidc:0:test-subject-1",
                "holder_head": "-",
                "nonce": "AAECAwQFBgcICQoLDA0ODw",
                "exp": 1764000600u64,
                "text": text,
                "vault_op": vault_op_v2(&text),
            },
        })
    }

    #[test]
    #[ignore]
    fn write_vectors() {
        let v = serde_json::to_string_pretty(&compute()).unwrap();
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/v2_vectors.json"), v + "\n").unwrap();
    }

    #[test]
    fn code_matches_the_published_vectors() {
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/v2_vectors.json")).unwrap();
        assert_eq!(published, compute());
    }
}
