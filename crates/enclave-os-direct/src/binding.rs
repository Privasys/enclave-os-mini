// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! What a direct certificate is bound to: the OID 7.4 value on the app's
//! leaves, and the status the control plane reads before it lets a gateway
//! splice a name to this enclave.

use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

/// OID 7.4 under the Privasys arc: DirectDomainKeys.
pub const DIRECT_DOMAIN_KEYS_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65230, 7, 4];

/// What the control plane needs about one issued certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct LeafFacts {
    /// The hex SHA-256 of the leaf's SubjectPublicKeyInfo.
    pub spki_sha256: String,
    /// NotAfter, RFC 3339 UTC.
    pub not_after: String,
    /// NotAfter, Unix seconds (for renewal).
    pub not_after_unix: i64,
}

/// Reads the leaf (first certificate) of a PEM chain.
pub fn leaf_facts(chain_pem: &str) -> Result<LeafFacts, String> {
    let pem = Pem::iter_from_buffer(chain_pem.as_bytes())
        .next()
        .ok_or("direct: empty chain")?
        .map_err(|e| format!("direct: chain: {e}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|e| format!("direct: leaf: {e}"))?;
    let spki = Sha256::digest(cert.tbs_certificate.subject_pki.raw);
    let not_after = cert.validity().not_after;
    Ok(LeafFacts {
        spki_sha256: spki.iter().map(|b| format!("{b:02x}")).collect(),
        not_after: rfc3339(not_after.to_datetime()),
        not_after_unix: not_after.timestamp(),
    })
}

/// RFC 3339 UTC for Unix seconds (empty when out of range).
pub fn rfc3339_unix(secs: i64) -> String {
    ::time::OffsetDateTime::from_unix_timestamp(secs).map(rfc3339).unwrap_or_default()
}

/// RFC 3339 UTC, to the second (the container runtime's format).
fn rfc3339(t: ::time::OffsetDateTime) -> String {
    let t = t.to_offset(::time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The OID 7.4 value: `<host> sha256:<spki hex>` lines, sorted,
/// newline-joined. None when no name is issued.
pub fn key_bindings(issued: &[(String, String)]) -> Option<Vec<u8>> {
    if issued.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = issued.iter().map(|(h, s)| format!("{h} sha256:{s}")).collect();
    lines.sort();
    Some(lines.join("\n").into_bytes())
}

/// The control plane's view of an app's direct names (same JSON as the
/// container runtime).
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub supported: bool,
    pub account_uri: String,
    pub domains: Vec<DomainStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainStatus {
    pub name: String,
    pub issued: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub not_after: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub spki_sha256: String,
    /// The last self-probe: whether a TLS-ALPN-01 validation would reach
    /// this runtime. Absent before the first one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeStatus>,
}

/// The outcome of a self-probe.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProbeStatus {
    pub ok: bool,
    pub checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// Renew when less than a third of the lifetime remains (30 days of a
/// 90-day certificate), so a vault outage has a month of slack.
pub fn needs_renewal(not_after_unix: i64, now_unix: i64) -> bool {
    not_after_unix - now_unix < 30 * 24 * 3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bindings_are_sorted_lines() {
        assert_eq!(key_bindings(&[]), None);
        let v = key_bindings(&[("b.example.com".into(), "22".into()), ("a.example.com".into(), "11".into())]).unwrap();
        assert_eq!(String::from_utf8(v).unwrap(), "a.example.com sha256:11\nb.example.com sha256:22");
    }

    #[test]
    fn leaf_facts_read_the_first_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["shop.example.com".into()]).unwrap().self_signed(&key).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cert.der());
        let pem = format!("-----BEGIN CERTIFICATE-----
{b64}
-----END CERTIFICATE-----
");
        let facts = leaf_facts(&pem).unwrap();
        let want: String = Sha256::digest(key.public_key_der()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(facts.spki_sha256, want);
        assert!(facts.not_after.ends_with('Z'));
    }

    #[test]
    fn renewal_starts_thirty_days_out() {
        assert!(!needs_renewal(100 * 86400, 0));
        assert!(needs_renewal(29 * 86400, 0));
    }
}
