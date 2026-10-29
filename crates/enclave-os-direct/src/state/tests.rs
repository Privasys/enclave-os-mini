// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Issuance, renewal past the threshold, and survival across a runtime roll,
//! against a CA that issues real certificates and validates by connecting to
//! the runtime while the order is in flight.

use std::collections::BTreeMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::{CertificateParams, CertificateSigningRequestParams, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::*;
use crate::acme::Response;
use crate::policy::{binding, document_digest, handle_for, parse};

const DIR: &str = "https://ca.test/directory";
const DOMAIN: &str = "shop.example.com";
const APP: &str = "shop";
const CANONICAL: &str = "shop.apps.example.org";
const T0: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

#[derive(Default)]
struct MemStore(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);

impl Store for MemStore {
    fn get(&self, table: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let mut k = table.to_vec();
        k.extend_from_slice(key);
        self.0.lock().unwrap().get(&k).cloned()
    }
    fn put(&self, table: &[u8], key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut k = table.to_vec();
        k.extend_from_slice(key);
        self.0.lock().unwrap().insert(k, value.to_vec());
        Ok(())
    }
}

/// A CA issuing real certificates, `validity_days` from `now`.
struct RealCa<'a> {
    shared: &'a Mutex<Direct>,
    now: i64,
    validity_days: i64,
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    nonce: u32,
    accounts: BTreeMap<String, String>,
    token: String,
    thumb: String,
    valid: bool,
    pem: String,
    orders: u32,
}

impl<'a> RealCa<'a> {
    fn new(shared: &'a Mutex<Direct>, now: i64, validity_days: i64) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = p.self_signed(&ca_key).unwrap();
        RealCa {
            shared, now, validity_days, ca_key, ca_cert, nonce: 0,
            accounts: BTreeMap::new(), token: String::new(), thumb: String::new(),
            valid: false, pem: String::new(), orders: 0,
        }
    }
}

fn resp(status: u16, body: serde_json::Value, headers: Vec<(&str, String)>) -> Response {
    Response { status, headers: headers.into_iter().map(|(k, v)| (k.into(), v)).collect(), body: body.to_string().into_bytes() }
}

fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
}

impl Transport for &mut RealCa<'_> {
    fn request(&mut self, method: &str, url: &str, body: Option<&[u8]>) -> Result<Response, String> {
        self.nonce += 1;
        let nonce = ("Replay-Nonce", format!("n{}", self.nonce));
        if method == "GET" && url == DIR {
            return Ok(resp(200, serde_json::json!({"newNonce": "https://ca.test/nonce", "newAccount": "https://ca.test/account", "newOrder": "https://ca.test/order"}), vec![]));
        }
        if method == "HEAD" || url == "https://ca.test/nonce" {
            return Ok(resp(200, serde_json::json!({}), vec![nonce]));
        }
        let v: serde_json::Value = serde_json::from_slice(body.unwrap()).unwrap();
        let protected: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(v["protected"].as_str().unwrap()).unwrap()).unwrap();
        let payload: Option<serde_json::Value> = match v["payload"].as_str().unwrap() {
            "" => None,
            p => Some(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()),
        };
        match url {
            "https://ca.test/account" => {
                let jwk = &protected["jwk"];
                let thumb = URL_SAFE_NO_PAD.encode(Sha256::digest(
                    format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap()).as_bytes(),
                ));
                self.thumb = thumb.clone();
                let n = self.accounts.len() + 1;
                let acct = self.accounts.entry(thumb).or_insert_with(|| format!("https://ca.test/acct/{n}")).clone();
                Ok(resp(201, serde_json::json!({"status": "valid"}), vec![nonce, ("Location", acct)]))
            }
            "https://ca.test/order" => {
                self.orders += 1;
                self.valid = false;
                self.token = format!("tok{}", self.orders);
                Ok(resp(201, serde_json::json!({"status": "pending", "authorizations": ["https://ca.test/authz"], "finalize": "https://ca.test/finalize"}), vec![nonce, ("Location", "https://ca.test/o".into())]))
            }
            "https://ca.test/authz" => {
                let status = if self.valid { "valid" } else { "pending" };
                Ok(resp(200, serde_json::json!({"status": status, "challenges": [{"type": "tls-alpn-01", "url": "https://ca.test/chal", "token": self.token}]}), vec![nonce]))
            }
            "https://ca.test/chal" => {
                // The validation: connect to the runtime as the CA does, while
                // the client waits on this POST, through the challenge the
                // runtime's handshake would serve from the shared state.
                let cert = self.shared.lock().unwrap().name(DOMAIN).and_then(|n| n.challenge.clone())
                    .expect("the challenge is visible to the handshake while the order is in flight");
                let cfg = crate::tls::challenge_config(&cert, crate::tls::tests::time()).unwrap();
                let (leaf, _) = crate::tls::tests::validate(cfg, DOMAIN).unwrap();
                let (_, x) = X509Certificate::from_der(&leaf).unwrap();
                let oid = x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).unwrap();
                let ext = x.extensions().iter().find(|e| e.oid == oid).unwrap();
                self.valid = ext.value[2..] == Sha256::digest(format!("{}.{}", self.token, self.thumb).as_bytes())[..];
                Ok(resp(200, serde_json::json!({"status": "processing"}), vec![nonce]))
            }
            "https://ca.test/o" => {
                let status = if !self.pem.is_empty() { "valid" } else if self.valid { "ready" } else { "pending" };
                Ok(resp(200, serde_json::json!({"status": status, "authorizations": ["https://ca.test/authz"], "finalize": "https://ca.test/finalize", "certificate": "https://ca.test/cert"}), vec![nonce]))
            }
            "https://ca.test/finalize" => {
                let csr = URL_SAFE_NO_PAD.decode(payload.unwrap()["csr"].as_str().unwrap()).unwrap();
                let mut req = CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
                req.params.not_before = ::time::OffsetDateTime::from_unix_timestamp(self.now - DAY).unwrap();
                req.params.not_after = ::time::OffsetDateTime::from_unix_timestamp(self.now + self.validity_days * DAY).unwrap();
                let leaf = req.signed_by(&self.ca_cert, &self.ca_key).unwrap();
                self.pem = pem(leaf.der()) + &pem(self.ca_cert.der());
                Ok(resp(200, serde_json::json!({"status": "valid"}), vec![nonce]))
            }
            "https://ca.test/cert" => {
                let pem = std::mem::take(&mut self.pem);
                Ok(Response { status: 200, headers: vec![(nonce.0.into(), nonce.1)], body: pem.into_bytes() })
            }
            other => panic!("unexpected {method} {other}"),
        }
    }
    fn sleep_ms(&mut self, _ms: u64) {}
}

/// A transport that must not be used: restoring needs no network.
struct NoNetwork;

impl Transport for NoNetwork {
    fn request(&mut self, method: &str, url: &str, _: Option<&[u8]>) -> Result<Response, String> {
        panic!("no network call expected, got {method} {url}")
    }
    fn sleep_ms(&mut self, _ms: u64) {}
}

fn approve(shared: &Mutex<Direct>, store: &dyn Store, branch: &[u8; 32], seq: u64) -> Result<Pin, String> {
    let env = serde_json::json!({
        "document": {"v": 1, "app_id": "a1", "seq": seq, "domains": [DOMAIN]},
        "approval_token": "t",
    })
    .to_string();
    let parsed = parse(env.as_bytes()).unwrap();
    let op = binding(&handle_for("a1"), &document_digest(&parsed.raw), seq, "n", 99);
    let amr = vec!["webauthn".to_string()];
    let approval = Approval { sub: "owner", amr: &amr, vault_op: Some(&op), nonce: Some("n"), exp: 99 };
    shared.lock().unwrap().accept(store, APP, CANONICAL, branch, &parsed, &approval)
}

fn served_spki(shared: &Mutex<Direct>) -> String {
    shared.lock().unwrap().status(APP).domains[0].spki_sha256.clone()
}

/// The leaf a browser gets from the config the runtime builds.
fn browser_leaf(shared: &Mutex<Direct>) -> Vec<u8> {
    let s = shared.lock().unwrap().name(DOMAIN).unwrap().served.clone().unwrap();
    let cfg = crate::tls::public_config(s.chain_der(), s.key_pkcs8_der.clone(), crate::tls::tests::time()).unwrap();
    crate::tls::tests::validate(cfg, DOMAIN).unwrap().0
}

fn spki_of(leaf: &[u8]) -> String {
    let (_, c) = X509Certificate::from_der(leaf).unwrap();
    Sha256::digest(c.tbs_certificate.subject_pki.raw).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_status_read_renews_past_the_threshold() {
    let branch = [5u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();

    // First issuance.
    let mut ca = RealCa::new(&shared, T0, 90);
    let out = drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    assert_eq!(out.issued, vec![DOMAIN.to_string()], "{out:?}");
    let first = served_spki(&shared);
    assert_eq!(spki_of(&browser_leaf(&shared)), first, "the browser gets the issued certificate");
    assert!(String::from_utf8(shared.lock().unwrap().key_bindings(APP).unwrap()).unwrap().contains(&first));

    // Well inside the validity: nothing due, no network.
    let out = drive(&shared, &store, APP, &branch, T0 + 10 * DAY, NoNetwork, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    assert!(out.issued.is_empty());

    // 29 days left: the status read renews.
    let later = T0 + 61 * DAY;
    let mut ca = RealCa::new(&shared, later, 90);
    let out = drive(&shared, &store, APP, &branch, later, &mut ca, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    assert_eq!(out.issued, vec![DOMAIN.to_string()], "renewed: {out:?}");
    let second = served_spki(&shared);
    assert_ne!(second, first, "a renewal has a new key, born here");
    assert_eq!(spki_of(&browser_leaf(&shared)), second, "the renewed certificate is served");
    let kb = String::from_utf8(shared.lock().unwrap().key_bindings(APP).unwrap()).unwrap();
    assert_eq!(kb, format!("{DOMAIN} sha256:{second}"), "OID 7.4 names the new key only");

    // And it was sealed: a fresh runtime restores the renewed one.
    let roll = Mutex::new(Direct::new());
    roll.lock().unwrap().restore(&store, APP, CANONICAL, &branch).unwrap();
    assert_eq!(served_spki(&roll), second);
}

#[test]
fn a_roll_restores_everything_without_network_or_approval() {
    let branch = [6u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let mut ca = RealCa::new(&shared, T0, 90);
    drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    let spki = served_spki(&shared);

    // A new build: new process, same host storage, same vault-held key.
    let roll = Mutex::new(Direct::new());
    assert!(roll.lock().unwrap().restore(&store, APP, CANONICAL, &branch).unwrap());
    let st = roll.lock().unwrap().status(APP);
    assert!(st.domains[0].issued);
    assert_eq!(st.domains[0].spki_sha256, spki, "the same certificate, not a reissue");
    assert_eq!(spki_of(&browser_leaf(&roll)), spki);
    assert_eq!(roll.lock().unwrap().pin(APP).unwrap().seq, 1);
    // Nothing due: a status read after the roll makes no network call (the
    // account was never needed again; the restored names are not due).
    roll.lock().unwrap().set_account(APP, "https://ca.test/acct/1".into());
    let out = drive(&roll, &store, APP, &branch, T0 + DAY, NoNetwork, DIR, &mut |_| true, &mut reaches(&roll)).unwrap();
    assert!(out.issued.is_empty() && out.failed.is_empty());

    // The pin's sequence still only moves forward.
    assert!(approve(&roll, &store, &branch, 1).is_err(), "seq 1 again is refused after the roll");
    assert!(approve(&roll, &store, &branch, 2).is_ok());

    // A build the vaults refuse (another key) reads nothing.
    let refused = Mutex::new(Direct::new());
    assert!(!refused.lock().unwrap().restore(&store, APP, CANONICAL, &[7u8; 32]).unwrap());
    assert!(refused.lock().unwrap().name(DOMAIN).is_none());
}

/// A probe that reaches this runtime, as the CA's validator would through a
/// gateway that splices acme-tls/1: it is served whatever challenge the
/// runtime's handshake serves now.
fn reaches(shared: &Mutex<Direct>) -> impl FnMut(&str) -> Result<Vec<u8>, String> + '_ {
    move |d: &str| {
        let c = shared.lock().unwrap().name(d).and_then(|n| n.challenge.clone()).ok_or("no challenge served")?;
        let cfg = crate::tls::challenge_config(&c, crate::tls::tests::time())?;
        crate::tls::tests::validate(cfg, d).map(|(leaf, _)| leaf)
    }
}

fn probe_of(shared: &Mutex<Direct>) -> binding::ProbeStatus {
    shared.lock().unwrap().status(APP).domains[0].probe.clone().expect("a probe ran")
}

#[test]
fn a_successful_probe_lets_the_order_run_and_is_reported() {
    let branch = [8u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let mut ca = RealCa::new(&shared, T0, 90);
    let out = drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    assert_eq!(out.issued, vec![DOMAIN.to_string()]);
    let p = probe_of(&shared);
    assert!(p.ok && p.error.is_empty() && p.checked_at.ends_with('Z'), "{p:?}");
    assert!(shared.lock().unwrap().name(DOMAIN).unwrap().challenge.is_none(), "the probe certificate is removed");
}

/// The gateway is not splicing yet: something else answers acme-tls/1 (a
/// terminating proxy, another server). No order may run.
#[test]
fn a_wrong_certificate_blocks_the_order() {
    let branch = [9u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let elsewhere = crate::challenge::tls_alpn_certificate(DOMAIN, "someone-else").unwrap().cert_der;
    let mut ca = RealCa::new(&shared, T0, 90);
    let out = drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut |_: &str| Ok(elsewhere.clone())).unwrap();
    assert!(out.issued.is_empty());
    assert_eq!(ca.orders, 0, "no order is placed while the probe fails");
    let p = probe_of(&shared);
    assert!(!p.ok && p.error.contains("wrong certificate"), "{p:?}");
    assert_eq!(out.failed[0].2, PROBE_MIN_BACKOFF);
}

#[test]
fn an_unreachable_name_backs_off_and_never_orders() {
    let branch = [10u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let mut probes = 0;
    let mut refuse = |_: &str| -> Result<Vec<u8>, String> {
        probes += 1;
        Err("connection refused".into())
    };
    let mut ca = RealCa::new(&shared, T0, 90);
    drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut refuse).unwrap();
    assert!(probe_of(&shared).error.contains("refused"));
    // Inside the 2 minute backoff: not even probed.
    drive(&shared, &store, APP, &branch, T0 + 60, &mut ca, DIR, &mut |_| true, &mut refuse).unwrap();
    // Due again: probed, refused, the backoff doubles.
    let out = drive(&shared, &store, APP, &branch, T0 + PROBE_MIN_BACKOFF, &mut ca, DIR, &mut |_| true, &mut refuse).unwrap();
    assert_eq!(out.failed[0].2, 2 * PROBE_MIN_BACKOFF);
    // And it caps at 15 minutes.
    let mut t = T0 + PROBE_MIN_BACKOFF;
    for _ in 0..6 {
        t += PROBE_MAX_BACKOFF;
        let out = drive(&shared, &store, APP, &branch, t, &mut ca, DIR, &mut |_| true, &mut refuse).unwrap();
        assert!(out.failed[0].2 <= PROBE_MAX_BACKOFF);
    }
    drop(refuse);
    assert_eq!(probes, 8);
    assert_eq!(ca.orders, 0, "no order is placed while the name is unreachable");
}

#[test]
fn no_dns_is_reported_and_never_probed_or_ordered() {
    let branch = [11u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let mut ca = RealCa::new(&shared, T0, 90);
    let mut probed = false;
    drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| false, &mut |_: &str| {
        probed = true;
        Err("unused".into())
    })
    .unwrap();
    assert!(!probed);
    assert!(probe_of(&shared).error.starts_with("no DNS"));
    assert_eq!(ca.orders, 0);
}

/// A served name that is not due is re-probed at most every 15 minutes as a
/// health signal, and never ordered.
#[test]
fn a_served_name_is_reprobed_for_health_but_not_reordered() {
    let branch = [12u8; 32];
    let store = MemStore::default();
    let shared = Mutex::new(Direct::new());
    approve(&shared, &store, &branch, 1).unwrap();
    let mut ca = RealCa::new(&shared, T0, 90);
    drive(&shared, &store, APP, &branch, T0, &mut ca, DIR, &mut |_| true, &mut reaches(&shared)).unwrap();
    let orders = ca.orders;
    let mut probes = 0;
    let t = T0 + PROBE_MAX_BACKOFF;
    drive(&shared, &store, APP, &branch, t, &mut ca, DIR, &mut |_| true, &mut |d: &str| {
        probes += 1;
        reaches(&shared)(d)
    })
    .unwrap();
    assert_eq!(probes, 1);
    assert_eq!(ca.orders, orders, "a health probe never orders");
    assert!(probe_of(&shared).ok);
    // Within 15 minutes of it: no probe.
    let mut again = 0;
    drive(&shared, &store, APP, &branch, t + 60, &mut ca, DIR, &mut |_| true, &mut |_: &str| {
        again += 1;
        Err("unused".into())
    })
    .unwrap();
    assert_eq!(again, 0);
}
