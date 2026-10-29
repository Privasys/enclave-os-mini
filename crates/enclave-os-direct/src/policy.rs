// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The owner-signed app policy: the same document and approval binding as
//! the container runtime, so one approval format serves every enclave kind.
//!
//! The control plane distributes policy; the owner authors it. The first
//! document an app accepts pins its approver, and after that only a newer
//! document that approver signed is accepted. This crate reads only the
//! parts direct domains need (`domains`, the pin); the other members are
//! carried verbatim for their own readers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The binding domain of an approval (the IdP's vault-approval formula).
pub const BINDING_DOMAIN: &str = "privasys-vault-approval/v1";
/// The document version.
pub const VERSION: u32 = 1;
/// The adopter hostnames one policy may name.
pub const MAX_DOMAINS: usize = 20;

/// The vault-op handle of an app's policy.
pub fn handle_for(app_id: &str) -> String {
    format!("app:{}:policy", app_id.to_ascii_lowercase())
}

/// An owner-signed policy document. Unknown members are refused, so a
/// runtime that does not know a member never silently drops it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub v: u32,
    pub app_id: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_callers: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constellation: Option<serde_json::Value>,
    /// The direct adopter hostnames. Absent keeps the approved list; an
    /// explicit empty list removes them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Envelope {
    document: Box<serde_json::value::RawValue>,
    approval_token: String,
}

/// A parsed envelope: the document, its exact bytes (the digest the owner
/// approved), and the approval token.
pub struct Parsed {
    pub doc: Document,
    pub raw: Vec<u8>,
    pub token: String,
}

/// Parses `{"document": {...}, "approval_token": "..."}`.
pub fn parse(raw: &[u8]) -> Result<Parsed, String> {
    let env: Envelope = serde_json::from_slice(raw).map_err(|e| format!("apppolicy: parse envelope: {e}"))?;
    let token = env.approval_token.trim().to_string();
    if token.is_empty() {
        return Err("apppolicy: envelope carries no approval token".into());
    }
    let doc_bytes = env.document.get().as_bytes().to_vec();
    let doc: Document =
        serde_json::from_slice(&doc_bytes).map_err(|e| format!("apppolicy: parse document: {e}"))?;
    if doc.v != VERSION {
        return Err(format!("apppolicy: document version {}, want {VERSION}", doc.v));
    }
    if doc.app_id.is_empty() {
        return Err("apppolicy: document names no app".into());
    }
    if doc.seq == 0 {
        return Err("apppolicy: document seq must be 1 or more".into());
    }
    validate_domains(doc.domains.as_deref().unwrap_or(&[]))?;
    Ok(Parsed { doc, raw: doc_bytes, token })
}

/// Lowercase fully qualified hostnames, no wildcard, no duplicate.
pub fn validate_domains(domains: &[String]) -> Result<(), String> {
    if domains.len() > MAX_DOMAINS {
        return Err(format!("apppolicy: {} domains, at most {MAX_DOMAINS}", domains.len()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for d in domains {
        if !valid_hostname(d) {
            return Err(format!("apppolicy: {d:?} is not a lowercase fully qualified hostname"));
        }
        if !seen.insert(d.as_str()) {
            return Err(format!("apppolicy: domain {d:?} named twice"));
        }
    }
    Ok(())
}

fn valid_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 || h.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

/// The hex SHA-256 of the document bytes: the "measurement" the owner
/// approved.
pub fn document_digest(raw: &[u8]) -> String {
    Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect()
}

/// The vault-op binding the IdP issues for an approval (unpadded base64url).
pub fn binding(handle: &str, measurement_hex: &str, seq: u64, nonce: &str, exp: i64) -> String {
    let input = format!("{BINDING_DOMAIN}\n{handle}\n{measurement_hex}\n{seq}\n{nonce}\n{exp}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// The claims of a verified approval token (its signature, issuer, audience
/// and expiry already checked by the caller).
pub struct Approval<'a> {
    pub sub: &'a str,
    pub amr: &'a [String],
    pub vault_op: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub exp: i64,
}

/// Checks that an approval is a step-up bound to exactly this document, and
/// returns the approving subject.
pub fn check_approval(doc: &Document, raw: &[u8], a: &Approval<'_>) -> Result<String, String> {
    if a.sub.is_empty() {
        return Err("apppolicy: approval names no subject".into());
    }
    if !a.amr.iter().any(|m| m == "webauthn") {
        return Err("apppolicy: approval was not a step-up (amr lacks webauthn)".into());
    }
    let (op, nonce) = match (a.vault_op, a.nonce) {
        (Some(op), Some(n)) if !op.is_empty() && !n.is_empty() => (op, n),
        _ => return Err("apppolicy: approval carries no operation binding".into()),
    };
    let want = binding(&handle_for(&doc.app_id), &document_digest(raw), doc.seq, nonce, a.exp);
    if want != op {
        return Err("apppolicy: the approval does not bind this document".into());
    }
    Ok(a.sub.to_string())
}

/// What an app remembers about its own policy. Persisted (sealed) so a
/// reload, whose re-sent document is refused as not newer, still finds the
/// approved domains.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Pin {
    pub approver: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

/// Accepts a checked document against the current pin, returning the next
/// pin. `subject` is the approver [`check_approval`] returned.
pub fn accept(current: Option<&Pin>, doc: &Document, subject: &str) -> Result<Pin, String> {
    if let Some(p) = current {
        if subject != p.approver {
            return Err(format!("apppolicy: {subject} does not approve this app's policy"));
        }
        if doc.seq <= p.seq {
            return Err(format!("apppolicy: document seq {} is not newer than {}", doc.seq, p.seq));
        }
    }
    let approver = doc.approver.clone().filter(|a| !a.is_empty()).unwrap_or_else(|| subject.to_string());
    let domains = match &doc.domains {
        Some(d) => d.clone(),
        None => current.map(|p| p.domains.clone()).unwrap_or_default(),
    };
    Ok(Pin { approver, seq: doc.seq, domains })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IdP's own vector (the container runtime pins the same one).
    #[test]
    fn binding_matches_the_identity_provider() {
        assert_eq!(
            binding(
                "app:f36925ff3553469987f9908a2d530ff7:policy",
                "d14a59e695616fe837847654828bcbd8e8e56bdc8512077f39d213814bd53a45",
                1,
                "bm9uY2U",
                1793116800,
            ),
            "4MoJ5Gksw4iT95c430SJJiI9MVWR9u64HPnp4yL9p24"
        );
    }

    fn signed(doc: serde_json::Value) -> (Parsed, String) {
        let raw = serde_json::json!({"document": doc, "approval_token": "t"}).to_string();
        let p = parse(raw.as_bytes()).unwrap();
        let op = binding(&handle_for(&p.doc.app_id), &document_digest(&p.raw), p.doc.seq, "n", 99);
        (p, op)
    }

    #[test]
    fn an_approval_must_bind_this_exact_document() {
        let (p, op) = signed(serde_json::json!({"v":1,"app_id":"A1","seq":1,"domains":["shop.example.com"]}));
        let amr = vec!["webauthn".to_string()];
        let ok = Approval { sub: "owner", amr: &amr, vault_op: Some(&op), nonce: Some("n"), exp: 99 };
        assert_eq!(check_approval(&p.doc, &p.raw, &ok).unwrap(), "owner");
        let other = Approval { exp: 100, ..ok };
        assert!(check_approval(&p.doc, &p.raw, &other).is_err(), "another expiry is another binding");
        let pwd = vec!["pwd".to_string()];
        let no_step_up = Approval { amr: &pwd, exp: 99, ..other };
        assert!(check_approval(&p.doc, &p.raw, &no_step_up).is_err());
    }

    #[test]
    fn unknown_members_and_bad_domains_are_refused() {
        let env = |d: serde_json::Value| serde_json::json!({"document": d, "approval_token": "t"}).to_string();
        assert!(parse(env(serde_json::json!({"v":1,"app_id":"A","seq":1,"surprise":1})).as_bytes()).is_err());
        for bad in ["*.example.com", "Shop.example.com", "example", "a_b.example.com"] {
            assert!(parse(env(serde_json::json!({"v":1,"app_id":"A","seq":1,"domains":[bad]})).as_bytes()).is_err(), "{bad}");
        }
        assert!(parse(env(serde_json::json!({"v":1,"app_id":"A","seq":1,"domains":["a.example.com","a.example.com"]})).as_bytes()).is_err());
    }

    #[test]
    fn the_pin_keeps_domains_unless_the_document_names_them() {
        let doc = |seq: u64, domains: Option<Vec<&str>>| Document {
            v: 1, app_id: "A".into(), seq, issued_at: None, approver: None, owners: None,
            dependencies: None, allowed_callers: None, constellation: None,
            domains: domains.map(|d| d.into_iter().map(String::from).collect()),
        };
        let p1 = accept(None, &doc(1, Some(vec!["a.example.com"])), "owner").unwrap();
        assert_eq!(p1.domains, vec!["a.example.com"]);
        let p2 = accept(Some(&p1), &doc(2, None), "owner").unwrap();
        assert_eq!(p2.domains, vec!["a.example.com"], "absent keeps");
        let p3 = accept(Some(&p2), &doc(3, Some(vec![])), "owner").unwrap();
        assert!(p3.domains.is_empty(), "explicit empty clears");
        assert!(accept(Some(&p3), &doc(3, None), "owner").is_err(), "not newer");
        assert!(accept(Some(&p3), &doc(4, None), "someone").is_err(), "pinned approver");
    }
}
