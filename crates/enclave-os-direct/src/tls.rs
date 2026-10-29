// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The rustls server configs a direct name serves.
//!
//! The challenge certificate cannot go through `with_single_cert`: that
//! checks the key against the certificate by parsing the leaf with webpki,
//! and webpki refuses an unknown critical extension, which the RFC 8737
//! acmeIdentifier extension must be. The challenge config is therefore built
//! from a `CertifiedKey` behind a one-certificate resolver, which never
//! parses the leaf. The publicly trusted certificate keeps the key check.

use std::sync::Arc;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::time_provider::TimeProvider;
use rustls::ServerConfig;

use crate::challenge::CertAndKey;
use crate::ACME_TLS_ALPN;

/// Always serves the one certificate it holds.
#[derive(Debug)]
struct OneCert(Arc<CertifiedKey>);

impl ResolvesServerCert for OneCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn builder(time: Arc<dyn TimeProvider>) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, String> {
    ServerConfig::builder_with_details(Arc::new(default_provider()), time)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("direct: tls config: {e:?}"))
}

/// The config answering the TLS-ALPN-01 validation: the challenge
/// certificate, negotiating `acme-tls/1` as RFC 8737 requires.
pub fn challenge_config(c: &CertAndKey, time: Arc<dyn TimeProvider>) -> Result<Arc<ServerConfig>, String> {
    let key = default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pkcs8_der.clone())))
        .map_err(|e| format!("direct: challenge key: {e:?}"))?;
    let certified = CertifiedKey::new(vec![CertificateDer::from(c.cert_der.clone())], key);
    let mut config = builder(time)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCert(Arc::new(certified))));
    config.alpn_protocols = vec![ACME_TLS_ALPN.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

/// The config serving the publicly trusted certificate (leaf first).
pub fn public_config(chain: Vec<Vec<u8>>, key_pkcs8: Vec<u8>, time: Arc<dyn TimeProvider>) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    let config = builder(time)?
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8)))
        .map_err(|e| format!("direct: certificate: {e:?}"))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, ServerConnection, SignatureScheme};
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    use crate::challenge::tls_alpn_certificate;

    pub(crate) fn time() -> Arc<dyn TimeProvider> {
        Arc::new(rustls::time_provider::DefaultTimeProvider)
    }

    /// Accepts any certificate: the validator reads the challenge from it,
    /// it does not chain it.
    #[derive(Debug)]
    struct AnyCert;

    impl ServerCertVerifier for AnyCert {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            // Against the leaf's raw public key: webpki refuses to parse a
            // leaf with the critical acmeIdentifier extension (the CA's own
            // validator does not use webpki either).
            let (_, cert) = X509Certificate::from_der(c.as_ref()).map_err(|_| rustls::Error::General("leaf".into()))?;
            let spki = rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.tbs_certificate.subject_pki.raw.to_vec());
            rustls::crypto::verify_tls13_signature_with_raw_key(m, &spki, d, &default_provider().signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// Connects to `server` as the CA's TLS-ALPN-01 validator does (SNI the
    /// domain, ALPN exactly `acme-tls/1`) and returns the leaf it was served
    /// and the negotiated protocol.
    pub(crate) fn validate(server: Arc<ServerConfig>, domain: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        let mut client_cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![ACME_TLS_ALPN.as_bytes().to_vec()];
        let mut client = ClientConnection::new(Arc::new(client_cfg), ServerName::try_from(domain.to_string()).unwrap())
            .map_err(|e| format!("{e:?}"))?;
        let mut srv = ServerConnection::new(server).map_err(|e| format!("{e:?}"))?;
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                srv.read_tls(&mut &buf[..]).unwrap();
                srv.process_new_packets().map_err(|e| format!("server: {e:?}"))?;
            }
            let mut buf = Vec::new();
            srv.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets().map_err(|e| format!("client: {e:?}"))?;
            }
            if !client.is_handshaking() && !srv.is_handshaking() {
                let leaf = client.peer_certificates().ok_or("no certificate")?[0].to_vec();
                return Ok((leaf, client.alpn_protocol().map(|p| p.to_vec())));
            }
        }
        Err("handshake did not complete".into())
    }

    /// The defect this module exists for: the critical acmeIdentifier
    /// extension makes `with_single_cert` refuse the challenge certificate.
    #[test]
    fn with_single_cert_refuses_the_challenge_certificate() {
        let c = tls_alpn_certificate("shop.example.com", "tok.thumb").unwrap();
        let r = builder(time()).unwrap().with_no_client_auth().with_single_cert(
            vec![CertificateDer::from(c.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pkcs8_der.clone())),
        );
        assert!(r.is_err(), "rustls now accepts it; the resolver path is still correct");
    }

    #[test]
    fn a_validator_gets_the_challenge_certificate_and_acme_tls_1() {
        let c = tls_alpn_certificate("shop.example.com", "tok.thumb").unwrap();
        let (leaf, alpn) = validate(challenge_config(&c, time()).unwrap(), "shop.example.com").unwrap();
        assert_eq!(alpn.as_deref(), Some(ACME_TLS_ALPN.as_bytes()), "RFC 8737: acme-tls/1 is negotiated");
        let (_, cert) = X509Certificate::from_der(&leaf).unwrap();
        let oid = x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).unwrap();
        let ext = cert.extensions().iter().find(|e| e.oid == oid).unwrap();
        assert_eq!(ext.value[2..], Sha256::digest(b"tok.thumb")[..]);
    }

    #[test]
    fn the_public_certificate_keeps_the_key_check() {
        let key = rcgen::KeyPair::generate().unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["shop.example.com".into()]).unwrap().self_signed(&key).unwrap();
        assert!(public_config(vec![cert.der().to_vec()], key.serialize_der(), time()).is_ok());
        assert!(public_config(vec![cert.der().to_vec()], other.serialize_der(), time()).is_err());
    }
}
