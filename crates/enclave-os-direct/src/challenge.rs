// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Certificates made in the enclave: the acme-tls/1 challenge certificate
//! (RFC 8737) and the key and CSR of the publicly trusted certificate.

use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair};
use sha2::{Digest, Sha256};

/// A certificate and its private key, DER (the key is PKCS#8).
#[derive(Clone)]
pub struct CertAndKey {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

/// The self-signed certificate answering a TLS-ALPN-01 challenge for
/// `domain`: SAN = the domain, and the critical acmeIdentifier extension
/// carrying SHA-256 of the key authorization.
pub fn tls_alpn_certificate(domain: &str, key_authorization: &str) -> Result<CertAndKey, String> {
    let key = KeyPair::generate().map_err(|e| format!("direct: challenge key: {e}"))?;
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("direct: challenge params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let digest = Sha256::digest(key_authorization.as_bytes());
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(&digest)];
    let cert = params.self_signed(&key).map_err(|e| format!("direct: challenge cert: {e}"))?;
    Ok(CertAndKey { cert_der: cert.der().to_vec(), key_pkcs8_der: key.serialize_der() })
}

/// A fresh certificate key (P-256, generated here) and the CSR for `domain`.
/// The key never leaves the enclave; only the CSR goes to the CA.
pub fn key_and_csr(domain: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = KeyPair::generate().map_err(|e| format!("direct: certificate key: {e}"))?;
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("direct: csr params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&key).map_err(|e| format!("direct: csr: {e}"))?;
    Ok((key.serialize_der(), csr.der().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn challenge_certificate_carries_the_key_authorization() {
        let ck = tls_alpn_certificate("shop.example.com", "tok.thumb").unwrap();
        let (_, cert) = X509Certificate::from_der(&ck.cert_der).unwrap();
        let oid = x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).unwrap();
        let ext = cert.extensions().iter().find(|e| e.oid == oid).expect("acmeIdentifier");
        assert!(ext.critical, "RFC 8737 requires the extension to be critical");
        // An OCTET STRING wrapping the 32-byte digest.
        let want = Sha256::digest(b"tok.thumb");
        assert_eq!(&ext.value[2..], &want[..]);
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(san.value.general_names.iter().any(|n| matches!(n, GeneralName::DNSName(d) if *d == "shop.example.com")));
    }

    #[test]
    fn csr_names_the_domain() {
        let (key, csr) = key_and_csr("shop.example.com").unwrap();
        assert!(!key.is_empty());
        let (_, req) = X509CertificationRequest::from_der(&csr).unwrap();
        req.verify_signature().unwrap();
    }
}
