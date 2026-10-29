// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! A mock CA: verifies every JWS, validates the TLS-ALPN-01 challenge the way
//! a real CA does (from the certificate the client published), and issues.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::*;
use crate::keys::{account_key, AccountKey};

const DIR: &str = "https://ca.test/directory";

#[derive(Default)]
struct Ca {
    nonce: u32,
    accounts: HashMap<String, String>, // thumbprint -> account url
    jwks: HashMap<String, serde_json::Value>, // account url -> jwk
    token: String,
    authz_valid: bool,
    finalized: bool,
    bad_nonce_once: bool,
    fail_validation: bool,
}

struct Mock<'a> {
    ca: &'a mut Ca,
    sink_cert: std::rc::Rc<std::cell::RefCell<Option<CertAndKey>>>,
}

fn json(status: u16, v: serde_json::Value, headers: Vec<(&str, String)>) -> Response {
    Response {
        status,
        headers: headers.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        body: v.to_string().into_bytes(),
    }
}

impl Mock<'_> {
    fn next_nonce(&mut self) -> String {
        self.ca.nonce += 1;
        format!("n{}", self.ca.nonce)
    }

    /// Verifies a JWS and returns (account url or thumbprint, payload).
    fn verify(&mut self, url: &str, body: &[u8]) -> Result<(String, Option<serde_json::Value>, Option<String>), String> {
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        let protected_b64 = v["protected"].as_str().unwrap();
        let payload_b64 = v["payload"].as_str().unwrap();
        let protected: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected_b64).unwrap()).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["url"], url, "the protected url must be the request url");
        let jwk = if let Some(jwk) = protected.get("jwk") {
            jwk.clone()
        } else {
            let kid = protected["kid"].as_str().unwrap();
            self.ca.jwks.get(kid).cloned().ok_or("unknown kid")?
        };
        let mut sec1 = vec![4u8];
        sec1.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
        sec1.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(v["signature"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(format!("{protected_b64}.{payload_b64}").as_bytes(), &sig)
            .map_err(|_| "bad signature")?;
        let payload = if payload_b64.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap())
        };
        let thumb = URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap()).as_bytes(),
        ));
        Ok((thumb, payload, protected.get("kid").and_then(|k| k.as_str()).map(str::to_string)))
    }
}

impl Transport for Mock<'_> {
    fn request(&mut self, method: &str, url: &str, body: Option<&[u8]>) -> Result<Response, String> {
        let nonce = self.next_nonce();
        let n = || ("Replay-Nonce", String::new());
        let _ = n;
        if method == "GET" && url == DIR {
            return Ok(json(200, serde_json::json!({
                "newNonce": "https://ca.test/nonce",
                "newAccount": "https://ca.test/account",
                "newOrder": "https://ca.test/order",
            }), vec![]));
        }
        if method == "HEAD" {
            return Ok(json(200, serde_json::json!({}), vec![("Replay-Nonce", nonce)]));
        }
        let body = body.expect("POST");
        if self.ca.bad_nonce_once {
            self.ca.bad_nonce_once = false;
            return Ok(json(400, serde_json::json!({"type": "urn:ietf:params:acme:error:badNonce"}), vec![("Replay-Nonce", nonce)]));
        }
        let (thumb, payload, kid) = self.verify(url, body)?;
        let hdr = |extra: Vec<(&'static str, String)>| {
            let mut h = vec![("Replay-Nonce", nonce.clone())];
            h.extend(extra);
            h
        };
        match url {
            "https://ca.test/account" => {
                let n = self.ca.accounts.len() + 1;
                let acct = self.ca.accounts.entry(thumb).or_insert_with(|| format!("https://ca.test/acct/{n}")).clone();
                let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                let protected: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(v["protected"].as_str().unwrap()).unwrap()).unwrap();
                self.ca.jwks.insert(acct.clone(), protected["jwk"].clone());
                Ok(json(201, serde_json::json!({"status": "valid"}), hdr(vec![("Location", acct)])))
            }
            "https://ca.test/order" => {
                assert!(kid.is_some(), "an order is signed with the account URL");
                let p = payload.unwrap();
                assert_eq!(p["identifiers"][0]["value"], "shop.example.com");
                self.ca.token = "tok123".into();
                Ok(json(201, serde_json::json!({
                    "status": "pending",
                    "authorizations": ["https://ca.test/authz/1"],
                    "finalize": "https://ca.test/finalize/1",
                }), hdr(vec![("Location", "https://ca.test/order/1".into())])))
            }
            "https://ca.test/authz/1" => {
                let status = if self.ca.authz_valid { "valid" } else { "pending" };
                Ok(json(200, serde_json::json!({
                    "status": status,
                    "challenges": [
                        {"type": "http-01", "url": "https://ca.test/chal/http", "token": "x"},
                        {"type": "tls-alpn-01", "url": "https://ca.test/chal/1", "token": self.ca.token},
                    ],
                }), hdr(vec![])))
            }
            "https://ca.test/chal/1" => {
                // Validate as the CA would: connect with acme-tls/1 and read
                // the certificate the client is serving.
                let cert = self.sink_cert.borrow().clone().expect("the challenge certificate is published before the CA is told");
                let (_, x) = X509Certificate::from_der(&cert.cert_der).unwrap();
                let oid = x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).unwrap();
                let ext = x.extensions().iter().find(|e| e.oid == oid).unwrap();
                let want = Sha256::digest(format!("{}.{}", self.ca.token, thumb).as_bytes());
                self.ca.authz_valid = !self.ca.fail_validation && ext.value[2..] == want[..];
                Ok(json(200, serde_json::json!({"status": "processing"}), hdr(vec![])))
            }
            "https://ca.test/order/1" => {
                let status = if self.ca.finalized { "valid" } else if self.ca.authz_valid { "ready" } else if self.ca.fail_validation { "invalid" } else { "pending" };
                Ok(json(200, serde_json::json!({
                    "status": status,
                    "authorizations": ["https://ca.test/authz/1"],
                    "finalize": "https://ca.test/finalize/1",
                    "certificate": if self.ca.finalized { serde_json::json!("https://ca.test/cert/1") } else { serde_json::Value::Null },
                }), hdr(vec![])))
            }
            "https://ca.test/finalize/1" => {
                let csr = URL_SAFE_NO_PAD.decode(payload.unwrap()["csr"].as_str().unwrap()).unwrap();
                let (_, req) = X509CertificationRequest::from_der(&csr).unwrap();
                req.verify_signature().unwrap();
                self.ca.finalized = true;
                Ok(json(200, serde_json::json!({"status": "valid"}), hdr(vec![])))
            }
            "https://ca.test/cert/1" => Ok(Response {
                status: 200,
                headers: vec![("Replay-Nonce".into(), nonce)],
                body: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
            }),
            other => panic!("unexpected {method} {other}"),
        }
    }

    fn sleep_ms(&mut self, _ms: u64) {}
}

struct Sink(std::rc::Rc<std::cell::RefCell<Option<CertAndKey>>>, Vec<bool>);

impl ChallengeSink for Sink {
    fn publish(&mut self, _domain: &str, cert: Option<&CertAndKey>) {
        self.1.push(cert.is_some());
        *self.0.borrow_mut() = cert.cloned();
    }
}

fn key() -> AccountKey {
    account_key(&[3u8; 32]).unwrap()
}

#[test]
fn obtains_a_certificate_over_tls_alpn_01() {
    let mut ca = Ca { bad_nonce_once: true, ..Default::default() };
    let shared = std::rc::Rc::new(std::cell::RefCell::new(None));
    let k = key();
    let mut client = Client::new(Mock { ca: &mut ca, sink_cert: shared.clone() }, &k, DIR);
    let mut sink = Sink(shared, vec![]);
    let issued = client.obtain("shop.example.com", &mut sink).unwrap();
    assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));
    assert!(!issued.key_pkcs8_der.is_empty());
    assert_eq!(sink.1, vec![true, false], "published for the validation, then removed");
    assert!(ca.finalized);
}

#[test]
fn the_same_key_finds_the_same_account() {
    let mut ca = Ca::default();
    let shared = std::rc::Rc::new(std::cell::RefCell::new(None));
    let k = key();
    let a = Client::new(Mock { ca: &mut ca, sink_cert: shared.clone() }, &k, DIR).account().unwrap();
    let b = Client::new(Mock { ca: &mut ca, sink_cert: shared }, &k, DIR).account().unwrap();
    assert_eq!(a, b, "an upgrade re-registers into the account CAA pins");
}

#[test]
fn a_failed_validation_is_an_error_and_the_challenge_is_removed() {
    let mut ca = Ca { fail_validation: true, ..Default::default() };
    let shared = std::rc::Rc::new(std::cell::RefCell::new(None));
    let k = key();
    let mut client = Client::new(Mock { ca: &mut ca, sink_cert: shared.clone() }, &k, DIR);
    client.max_polls = 2;
    let mut sink = Sink(shared, vec![]);
    assert!(client.obtain("shop.example.com", &mut sink).is_err());
    assert_eq!(sink.1.last(), Some(&false), "the challenge certificate never outlives the attempt");
}
