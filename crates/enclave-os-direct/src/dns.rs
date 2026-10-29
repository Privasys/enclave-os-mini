// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Readiness before ordering: every failed validation counts against the
//! CA's limit (Let's Encrypt: 5 per account, hostname and hour), and a name
//! that does not resolve yet always fails. So no order is placed until the
//! name resolves. The enclave has no resolver of its own; it asks a
//! DNS-over-HTTPS JSON endpoint over its egress. The answer is only a hint
//! for when to try: the CA's own validation is what counts.

use serde::Deserialize;

/// The DNS-over-HTTPS JSON endpoint (RFC 8484 JSON variant, as Google and
/// Cloudflare serve it).
pub const DOH_JSON: &str = "https://dns.google/resolve";

/// The query URL for the A record of `name`.
pub fn query_url(name: &str) -> String {
    format!("{DOH_JSON}?name={name}&type=A")
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohRecord>,
}

#[derive(Deserialize)]
struct DohRecord {
    #[serde(rename = "type")]
    kind: u32,
}

/// Whether a DNS-over-HTTPS JSON answer resolves the name to an address
/// (A, or an A behind a CNAME).
pub fn resolves(body: &[u8]) -> bool {
    match serde_json::from_slice::<DohAnswer>(body) {
        Ok(a) => a.status == 0 && a.answer.iter().any(|r| r.kind == 1),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_address_answer_is_ready() {
        assert!(resolves(br#"{"Status":0,"Answer":[{"name":"x.","type":1,"data":"34.155.7.30"}]}"#));
        assert!(resolves(br#"{"Status":0,"Answer":[{"type":5,"data":"edge."},{"type":1,"data":"1.2.3.4"}]}"#));
        assert!(!resolves(br#"{"Status":3}"#), "NXDOMAIN");
        assert!(!resolves(br#"{"Status":0}"#), "no answer");
        assert!(!resolves(b"not json"));
        assert_eq!(query_url("a.example.com"), "https://dns.google/resolve?name=a.example.com&type=A");
    }
}
