// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault key ownership (docs/vault-wire-formats.md).
//!
//! - The vault's member id and the identity call (wire formats §1).
//! - The policy digest over the policy JSON exactly as a request carries it,
//!   in RFC 8785 canonical form (wire formats §5.1).
//! - Binding v2: the approval text that names the constellation's members,
//!   the operation, its target and the approver (wire formats §5).
//! - Approval by default: a new policy must ask for an approval on the
//!   operations that govern a key (wire formats §4).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use crate::types::{Condition, KeyPolicy, Operation, PrincipalRef};

/// Domain of the binding v2 text (wire formats §5).
pub const BINDING_V2_DOMAIN: &str = "privasys-vault-approval/v2";
/// Domain of a member id (wire formats §1).
pub const MEMBER_DOMAIN: &str = "privasys-vault-member-v1\n";
/// Domain of the identity quote's report data (wire formats §1).
pub const IDENTITY_DOMAIN: &str = "privasys-vault-identity-v1\n";
/// Domain of the implicit billing id (wire formats §1).
pub const BILLING_IMPLICIT_DOMAIN: &str = "privasys-billing-implicit-v0\n";

/// The largest integer a canonical policy may hold (wire formats §5.1).
const MAX_SAFE_INTEGER: u64 = 1 << 53;

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    enclave_os_common::hex::hex_encode(bytes)
}

fn b64u(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
//  Strict JSON and RFC 8785
// ---------------------------------------------------------------------------

/// A JSON value parsed under the canonical restrictions of wire formats §5.1:
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
/// the JSON exactly as received (wire formats §5.1).
pub struct CanonicalPolicy {
    pub policy: KeyPolicy,
    /// `PD(policy)`: hex SHA-256 of the RFC 8785 form of the JSON as sent.
    pub pd: String,
}

/// Check a policy's JSON against wire formats §5.1 and compute its digest:
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

/// The policy fields the vault's own serialisation leaves out at their
/// default, with that default (an exemption by name, not by value,
/// so an unknown name is always refused).
fn is_known_default(name: &str, v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match name {
        // KeyPolicy::approval
        "approval" => v.is_null(),
        // Condition::OidcStepUp::binding
        "binding" => matches!(v, Value::Number(n) if n.as_u64() == Some(0)),
        _ => false,
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
                    None if is_known_default(k, sv) => {}
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

/// The implicit billing id: the vault's one issuer and audience
/// (wire formats §1).
pub fn implicit_billing_id(issuer: &str, audience: &str) -> String {
    let s = format!("{BILLING_IMPLICIT_DOMAIN}{issuer}\n{audience}");
    hex(&sha256(s.as_bytes()))
}

/// Report data of the identity quote (wire formats §1), in its first 32 bytes.
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

/// The binding v2 text (wire formats §5). `members` must already be checked.
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

/// Target of a `delete_after` (wire formats §9.2):
/// hex H("privasys-delete-after-v1\n" successor "\n" successor_target).
pub fn delete_after_target(successor: &str, successor_target: &str) -> Result<String, String> {
    check_line("successor", successor)?;
    check_line("successor_target", successor_target)?;
    Ok(hex(&sha256(
        format!("privasys-delete-after-v1\n{successor}\n{successor_target}").as_bytes(),
    )))
}

/// `PD` of a policy as the vault stores and returns it (`GetPolicy`): its own
/// serialisation, in RFC 8785 form (wire formats §5.3, "PD(current)").
pub fn stored_policy_digest(policy: &KeyPolicy) -> Result<String, String> {
    let json = serde_json::to_string(policy).map_err(|e| format!("serialise policy: {e}"))?;
    Ok(hex(&sha256(jcs(&parse_strict(&json)?).as_bytes())))
}

/// The start of the refusal of a policy that is not sent in stored form.
pub const NOT_STORED_FORM: &str = "new_policy is not in the vault's stored form";

/// A binding v2 policy update must send the new policy exactly as the vault
/// will store and return it (every default written out, nothing the vault
/// would drop or change), as `CanonicalisePolicy` returns it. Then what the
/// owner approves, what is stored and what the next `update_policy_from`
/// names as replaced are one JSON, and a wallet compares like with like. Key order and whitespace do not matter
/// (PD is over the RFC 8785 form). Call after `canonical_policy` succeeded.
pub fn check_sent_in_stored_form(raw: &str) -> Result<(), String> {
    let sent: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("policy does not parse: {e}"))?;
    let policy: KeyPolicy =
        serde_json::from_str(raw).map_err(|e| format!("policy does not parse: {e}"))?;
    let stored = serde_json::to_value(crate::normalise_policy(policy))
        .map_err(|e| format!("serialise policy: {e}"))?;
    match first_difference(&sent, &stored, "") {
        None => Ok(()),
        Some(path) => Err(format!(
            "{NOT_STORED_FORM} (first difference at {}): send the policy exactly as \
             CanonicalisePolicy returns it",
            if path.is_empty() { "/" } else { path.as_str() }
        )),
    }
}

/// The JSON-pointer path of the first place two values differ, if any.
fn first_difference(a: &serde_json::Value, b: &serde_json::Value, path: &str) -> Option<String> {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let p = format!("{path}/{k}");
                match (x.get(k), y.get(k)) {
                    (Some(u), Some(v)) => {
                        if let Some(d) = first_difference(u, v, &p) {
                            return Some(d);
                        }
                    }
                    _ => return Some(p),
                }
            }
            None
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (u, v)) in x.iter().zip(y.iter()).enumerate() {
                if let Some(d) = first_difference(u, v, &format!("{path}/{i}")) {
                    return Some(d);
                }
            }
            if x.len() != y.len() {
                return Some(format!("{path}/{}", x.len().min(y.len())));
            }
            None
        }
        (u, v) if u == v => None,
        _ => Some(path.to_string()),
    }
}

/// Target of an `update_policy_from` (wire formats §5.3):
/// hex H("privasys-update-policy-from-v1\n" PD(current) "\n" PD(new)).
pub fn update_from_target(current_pd: &str, new_pd: &str) -> String {
    hex(&sha256(
        format!("privasys-update-policy-from-v1\n{current_pd}\n{new_pd}").as_bytes(),
    ))
}

/// How long a binding v2 may live for `op` (wire formats §5): 600 s, except a
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

/// Spent bindings, kept until their expiry (wire formats §5). In enclave memory:
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
//  Approval by default (wire formats §4)
// ---------------------------------------------------------------------------

/// The value of `KeyPolicy::approval` that opts a key out of approvals.
pub const APPROVAL_NONE: &str = "none";

/// An update may not take away the approvals a key has. A key that asks for
/// approvals on its own rules (no opt-out) keeps doing so: the new policy must
/// pass on its own rules too, and may not add the `"approval": "none"` opt-out.
/// A key without them (created before approval by default, or opted out at
/// creation) may still be updated, and an update may add them.
pub fn check_no_approval_downgrade(
    old: &KeyPolicy,
    new: &KeyPolicy,
    exportable: bool,
) -> Result<(), String> {
    if old.approval.is_some() || check_approval_by_default(old, exportable).is_err() {
        return Ok(());
    }
    if new.approval.is_some() {
        return Err("an update may not opt a key out of the approvals it has".into());
    }
    check_approval_by_default(new, exportable)
}

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
        // Rules a person can use: an app fetching its own key under
        // a rule for its enclaves only (`Tee`, `AnyTee`) is not a governance act.
        let by_people = policy.operations.iter().filter(|r| {
            r.ops.contains(&op)
                && r.principals.iter().any(|p| {
                    matches!(p, PrincipalRef::Owner | PrincipalRef::Manager(_) | PrincipalRef::Auditor(_))
                })
        });
        for rule in by_people {
            let asks = rule.requires.iter().any(is_wallet_approval);
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

/// What counts as an approval for approval by default (the
/// portal's notice uses the same rule): a passkey step-up (`webauthn` in
/// `required_amr`) bound to the operation (binding v2, or v1
/// `operation_bound`). A fresh token alone, or a co-sign alone, is not.
pub fn is_wallet_approval(c: &Condition) -> bool {
    match c {
        Condition::OidcStepUp {
            required_amr,
            operation_bound,
            binding,
            ..
        } => required_amr.iter().any(|a| a == "webauthn") && (*binding == 2 || *operation_bound),
        _ => false,
    }
}

/// The one condition an owner may add to an existing key's rules (formats
/// §4.1): a bound passkey step-up, in its canonical shape.
pub fn canonical_step_up() -> Condition {
    Condition::OidcStepUp {
        required_amr: vec!["webauthn".into()],
        operation_bound: true,
        fresh_for_seconds: 300,
        binding: 2,
    }
}

/// Whether `new` differs from `old` only by a strict tightening (formats
/// §4.1): some rules gain the canonical step-up as one extra condition at the
/// end, and nothing else changes. Returns the indices of the rules tightened
/// (empty if the operations are unchanged), or why it is not a tightening.
pub fn tightening_rules(old: &KeyPolicy, new: &KeyPolicy) -> Result<Vec<usize>, String> {
    use crate::types::PrincipalRef;

    // Everything but the operations: identical, after canonicalisation.
    let strip = |p: &KeyPolicy| -> Result<serde_json::Value, String> {
        let mut v = serde_json::to_value(p).map_err(|e| format!("serialise policy: {e}"))?;
        if let Some(o) = v.as_object_mut() {
            o.remove("operations");
        }
        Ok(v)
    };
    if strip(old)? != strip(new)? {
        return Err("only the operation rules may change in a tightening".into());
    }
    if old.operations.len() != new.operations.len() {
        return Err("a tightening keeps every rule, in order".into());
    }
    let governing = [
        Operation::PromoteProfile,
        Operation::UpdatePolicy,
        Operation::DeleteKey,
        Operation::ExportKey,
    ];
    let canonical = canonical_step_up();
    let mut tightened = Vec::new();
    for (i, (o, n)) in old.operations.iter().zip(new.operations.iter()).enumerate() {
        if o.ops != n.ops || o.principals != n.principals {
            return Err(format!("rule {i}: a tightening keeps its operations and principals"));
        }
        if o.requires == n.requires {
            continue;
        }
        // Exactly one condition appended: the canonical step-up.
        let appended = n.requires.len() == o.requires.len() + 1
            && n.requires[..o.requires.len()] == o.requires[..]
            && n.requires[o.requires.len()] == canonical;
        if !appended {
            return Err(format!(
                "rule {i}: a tightening may only append the canonical bound passkey step-up"
            ));
        }
        let all_persons = !o.principals.is_empty()
            && o.principals.iter().all(|p| {
                matches!(p, PrincipalRef::Owner | PrincipalRef::Manager(_) | PrincipalRef::Auditor(_))
            });
        if !all_persons {
            return Err(format!(
                "rule {i} names an enclave: a step-up would lock it out; split the rule first"
            ));
        }
        if !o.ops.iter().any(|op| governing.contains(op)) {
            return Err(format!("rule {i} governs no promote, update, delete or export"));
        }
        if o.requires.iter().any(is_wallet_approval) {
            return Err(format!("rule {i} already asks for an approval"));
        }
        tightened.push(i);
    }
    Ok(tightened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_v2_vector_matches_the_spec() {
        // docs/vault-wire-formats.md §5.2
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
        // Only the known fields may be sent at a default the vault omits.
        assert!(canonical_policy(&policy(STEP_UP, r#","x":null"#)).is_err());
        assert!(canonical_policy(&policy(STEP_UP, r#","x":false"#)).is_err());
        assert!(canonical_policy(&policy(STEP_UP, r#","approval":null"#)).is_ok());
        let upper = policy(STEP_UP, "").replace(
            r#""tees":[]"#,
            r#""tees":[{"Tee":{"name":"app","measurements":[{"Mrenclave":"AB"}],"attestation_servers":[],"required_oids":[]}}]"#,
        );
        let e = canonical_policy(&upper).err().unwrap();
        assert!(e.contains("not normalised"), "{e}");
        let zero_ttl = policy(STEP_UP, "").replace("7776000", "0");
        let e = canonical_policy(&zero_ttl).err().unwrap();
        assert!(e.contains("not normalised"), "{e}");
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

    /// The shape of an app key as the control plane writes it: the app's
    /// enclaves export their share under an AnyTee rule with no approval, and
    /// every person's rule asks for a bound passkey step-up.
    fn app_key_policy(person_requires: &str) -> String {
        format!(
            r#"{{"version":1,"principals":{{"owner":{{"Oidc":{{"issuer":"https://privasys.id","sub":"o","required_roles":[]}}}},"managers":[{{"Oidc":{{"issuer":"https://privasys.id","sub":"","required_roles":["privasys-platform:app:0123456789abcdef0123456789abcdef:approver"]}}}}],"auditors":[],"tees":[{{"Tee":{{"name":"app","measurements":[{{"Mrenclave":"ab"}}],"attestation_servers":[],"required_oids":[]}}}}]}},"operations":[{{"ops":["ExportKey"],"principals":["AnyTee"],"requires":[]}},{{"ops":["ExportKey"],"principals":["Owner"],"requires":[{person_requires}]}},{{"ops":["PromoteProfile"],"principals":["Owner",{{"Manager":0}}],"requires":[{person_requires}]}},{{"ops":["UpdatePolicy","DeleteKey"],"principals":["Owner",{{"Manager":0}}],"requires":[{person_requires}]}}],"lifecycle":{{"ttl_seconds":7776000,"auto_migrate_to_next_attestation_profile":false}}}}"#
        )
    }

    #[test]
    fn approval_by_default_on_a_real_app_key() {
        // The app's own AnyTee export needs no approval; the people's rules do.
        let ok = canonical_policy(&app_key_policy(STEP_UP)).unwrap().policy;
        assert!(check_approval_by_default(&ok, true).is_ok());

        // A v1 bound passkey step-up counts too.
        let v1 = r#"{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300}}"#;
        let p = canonical_policy(&app_key_policy(v1)).unwrap().policy;
        assert!(check_approval_by_default(&p, true).is_ok());

        // A fresh token alone (no webauthn), or webauthn without a binding, is
        // not an approval; nor is a co-sign alone.
        for weak in [
            r#"{"OidcStepUp":{"required_amr":[],"operation_bound":false,"fresh_for_seconds":300}}"#,
            r#"{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":false,"fresh_for_seconds":300}}"#,
            r#"{"ManagerApproval":{"manager":0,"fresh_for_seconds":900}}"#,
        ] {
            let p = canonical_policy(&app_key_policy(weak)).unwrap().policy;
            assert!(check_approval_by_default(&p, true).is_err(), "{weak}");
        }
    }

    // ---- A binding v2 update sends the policy in stored form ----

    #[test]
    fn a_v2_update_must_send_the_stored_form() {
        // The control plane's typed form leaves defaults out.
        let terse = r#"{"version":1,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"o"}},"tees":[{"Tee":{"name":"app","measurements":[{"Mrenclave":"ab"}],"attestation_servers":[{"url":"https://as.privasys.org/verify"}]}}]},"operations":[{"ops":["ExportKey"],"principals":["AnyTee"]}],"lifecycle":{"ttl_seconds":7776000}}"#;
        // canonical_policy accepts it (it is valid and normalised) ...
        let c = canonical_policy(terse).unwrap();
        // ... but it is not what the vault stores: refused, naming where.
        let e = check_sent_in_stored_form(terse).unwrap_err();
        assert!(e.starts_with(NOT_STORED_FORM), "{e}");
        assert!(e.contains("first difference at /"), "{e}");
        // What CanonicalisePolicy returns is accepted, in any key order.
        let stored = serde_json::to_string(&c.policy).unwrap();
        check_sent_in_stored_form(&stored).unwrap();
        let reordered = jcs(&parse_strict(&stored).unwrap());
        check_sent_in_stored_form(&reordered).unwrap();
        // Then PD as sent is the stored PD: the next update_policy_from's
        // replaced_pd is this one, with no re-canonicalising.
        assert_eq!(canonical_policy(&stored).unwrap().pd, stored_policy_digest(&c.policy).unwrap());
        assert_ne!(c.pd, stored_policy_digest(&c.policy).unwrap());
        // "approval": null and "binding": 0 are written out only by a sender:
        // the stored form omits them.
        let mut v: serde_json::Value = serde_json::from_str(&stored).unwrap();
        v["approval"] = serde_json::Value::Null;
        let e = check_sent_in_stored_form(&v.to_string()).unwrap_err();
        assert!(e.contains("/approval"), "{e}");
        // A missing default deep inside (a TEE's required_oids) is named.
        let mut v: serde_json::Value = serde_json::from_str(&stored).unwrap();
        v["principals"]["tees"][0]["Tee"].as_object_mut().unwrap().remove("required_oids");
        let e = check_sent_in_stored_form(&v.to_string()).unwrap_err();
        assert!(e.contains("/principals/tees/0/Tee/required_oids"), "{e}");
    }

    // ---- Formats §4.1: an owner may add approvals to an existing key ----

    /// An existing app key as the control plane writes it: open person rules,
    /// Operations not in owner_can, only the owner frozen.
    fn open_app_key() -> serde_json::Value {
        let mut v: serde_json::Value = serde_json::from_str(&app_key_policy("")).unwrap();
        v["mutability"] = serde_json::json!({
            "owner_can": ["Tees", "PendingProfiles", "Lifecycle"],
            "manager_can": ["PendingProfiles"],
            "immutable": ["Owner"]
        });
        v
    }

    fn step_up_json() -> serde_json::Value {
        serde_json::to_value(canonical_step_up()).unwrap()
    }

    fn typed(v: &serde_json::Value) -> KeyPolicy {
        serde_json::from_value(v.clone()).unwrap()
    }

    /// Rules 1..=3 are the person rules (owner export, promote, update/delete);
    /// rule 0 is the app's own AnyTee export.
    fn tightened(v: &serde_json::Value) -> serde_json::Value {
        let mut t = v.clone();
        for i in 1..=3 {
            t["operations"][i]["requires"].as_array_mut().unwrap().push(step_up_json());
        }
        t
    }

    fn owner_update(old: &serde_json::Value, new: &serde_json::Value) -> Result<(), String> {
        crate::policy::evaluate_policy_update(&typed(old), &typed(new), crate::policy::CallerRole::Owner)
    }

    #[test]
    fn an_owner_may_add_the_bound_step_up_to_person_rules() {
        let old = open_app_key();
        let new = tightened(&old);
        assert_eq!(tightening_rules(&typed(&old), &typed(&new)).unwrap(), vec![1, 2, 3]);
        // Operations is not in owner_can, yet the tightening is allowed.
        owner_update(&old, &new).unwrap();
        // The result passes approval by default; the open key did not.
        assert!(check_approval_by_default(&typed(&old), true).is_err());
        assert!(check_approval_by_default(&typed(&new), true).is_ok());
        // A partial tightening is still a tightening.
        let mut partial = old.clone();
        partial["operations"][2]["requires"].as_array_mut().unwrap().push(step_up_json());
        assert_eq!(tightening_rules(&typed(&old), &typed(&partial)).unwrap(), vec![2]);
    }

    #[test]
    fn anything_but_a_strict_tightening_is_refused() {
        let old = open_app_key();
        let base = tightened(&old);
        let refused = |new: serde_json::Value, why: &str| {
            assert!(tightening_rules(&typed(&old), &typed(&new)).is_err(), "{why}");
            assert!(owner_update(&old, &new).is_err(), "{why}");
        };

        // Another principal.
        let mut v = base.clone();
        v["operations"][2]["principals"] = serde_json::json!(["Owner"]);
        refused(v, "principal changed");
        // Another op.
        let mut v = base.clone();
        v["operations"][1]["ops"] = serde_json::json!(["ExportKey", "Wrap"]);
        refused(v, "op changed");
        // Rules reordered.
        let mut v = base.clone();
        let ops = v["operations"].as_array_mut().unwrap();
        ops.swap(1, 2);
        refused(v, "rules reordered");
        // Lifecycle, mutability or approval changed alongside.
        let mut v = base.clone();
        v["lifecycle"]["ttl_seconds"] = serde_json::json!(3600);
        refused(v, "lifecycle changed");
        let mut v = base.clone();
        v["mutability"]["owner_can"] = serde_json::json!(["Tees", "Operations"]);
        refused(v, "mutability changed");
        let mut v = base.clone();
        v["approval"] = serde_json::json!("none");
        refused(v, "approval became none");
        // An existing condition removed or altered.
        let with_one: serde_json::Value = {
            let mut w = old.clone();
            w["operations"][2]["requires"] =
                serde_json::json!([{"TimeWindow":{"not_before":0,"not_after":0}}]);
            w
        };
        let mut v = with_one.clone();
        v["operations"][2]["requires"] = serde_json::json!([step_up_json()]);
        assert!(tightening_rules(&typed(&with_one), &typed(&v)).is_err(), "condition replaced");
        // A condition added to the app's own AnyTee rule (would lock it out).
        let mut v = old.clone();
        v["operations"][0]["requires"].as_array_mut().unwrap().push(step_up_json());
        refused(v, "AnyTee rule");
        // A mixed rule [Owner, AnyTee].
        let mut mixed = old.clone();
        mixed["operations"][1]["principals"] = serde_json::json!(["Owner", "AnyTee"]);
        let mut v = mixed.clone();
        v["operations"][1]["requires"].as_array_mut().unwrap().push(step_up_json());
        assert!(tightening_rules(&typed(&mixed), &typed(&v)).is_err(), "mixed rule");
        // Anything but the canonical step-up (a lock-out by freshness).
        let mut v = old.clone();
        v["operations"][2]["requires"].as_array_mut().unwrap().push(serde_json::json!(
            {"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":1,"binding":2}}
        ));
        refused(v, "non-canonical step-up");
        let mut v = old.clone();
        v["operations"][2]["requires"].as_array_mut().unwrap()
            .push(serde_json::json!({"ManagerApproval":{"manager":0,"fresh_for_seconds":900}}));
        refused(v, "co-sign added");

        // Not the owner.
        let new = tightened(&old);
        assert!(crate::policy::evaluate_policy_update(
            &typed(&old),
            &typed(&new),
            crate::policy::CallerRole::Manager
        )
        .is_err());
        // Operations frozen.
        let mut frozen = old.clone();
        frozen["mutability"]["immutable"] = serde_json::json!(["Owner", "Operations"]);
        let new = tightened(&frozen);
        assert!(owner_update(&frozen, &new).is_err(), "frozen operations");
    }
}

/// Shared test vectors (wire formats §5.2): `testdata/v2_vectors.json`, which the
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
        // update_policy_from (wire formats §5.3): the current policy is the sample as
        // the vault would store and return it; the new one is the sample as sent.
        let stored = canonical_policy(SAMPLE_POLICY).unwrap().policy;
        let stored_json = serde_json::to_string(&stored).unwrap();
        let current_pd = stored_policy_digest(&stored).unwrap();
        let from_target = update_from_target(&current_pd, &pd);
        let from_text = binding_v2_text(
            &members,
            "update_policy_from",
            "apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2",
            &from_target,
            3,
            "oidc:0:test-subject-1",
            "-",
            "AAECAwQFBgcICQoLDA0ODw",
            1764000600,
        );
        let refusal = check_sent_in_stored_form(SAMPLE_POLICY).unwrap_err();
        serde_json::json!({
            "stored_form_for_v2_updates": {
                "sent_not_stored_form": SAMPLE_POLICY,
                "refusal": refusal,
                "stored_form_as_canonicalise_policy_returns_it": stored_json,
                "pd_of_stored_form_as_sent": canonical_policy(&stored_json).unwrap().pd,
                "stored_pd": current_pd,
            },
            "binding_v2_update_policy_from": {
                "current_policy_as_get_policy_returns_it": stored_json,
                "current_pd": current_pd,
                "new_pd": pd,
                "target": from_target,
                "text": from_text,
                "vault_op": vault_op_v2(&from_text),
            },
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
