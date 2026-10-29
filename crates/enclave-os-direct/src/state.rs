// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The direct-domain state of every app on a runtime, and how it survives.
//!
//! What an app holds (its accepted policy pin with the approver, sequence,
//! domains and canonical host, and each issued certificate chain and key) is
//! sealed under a key derived from the app's direct-TLS branch, itself a
//! one-way branch of the vault-held key:
//!
//!   state key = HKDF-SHA256(branch, no salt, info = `privasys-direct-state/v1`)
//!
//! Any build the vaults release the key to derives the same state key, so a
//! runtime roll that keeps the host storage restores the names, the
//! certificates and the status with no network call and no new approval.
//! A build the vaults refuse cannot read it. The host can replay an older
//! sealed pin (it holds the storage); the pin's sequence still only moves
//! forward from whatever was restored, and the app's attestation advertises
//! which keys it serves (OID 7.4), so a rollback is visible.
//!
//! No order (first issuance, retry or renewal) is placed until a self-probe
//! shows a TLS-ALPN-01 validation would reach this runtime: it serves a
//! probe challenge certificate, connects to the name over the network with
//! ALPN `acme-tls/1` as the CA would, and checks it was served that
//! certificate. Every failed validation counts against the CA's limit (Let's
//! Encrypt: 5 per account, hostname and hour); a failed probe costs nothing.
//!
//! The ACME work never holds the state lock across a network wait: the CA
//! validates by connecting to the runtime while the order is in flight, and
//! that handshake needs to read the challenge (see [`drive`]).

use std::collections::BTreeMap;
use std::sync::Mutex;

use hkdf::Hkdf;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::acme::{ChallengeSink, Client, Transport};
use crate::binding::{self, DomainStatus, LeafFacts, Status};
use crate::challenge::CertAndKey;
use crate::keys;
use crate::policy::{self, Approval, Parsed, Pin};

/// HKDF info of the state key, under the direct-TLS branch.
pub const STATE_LABEL: &str = "privasys-direct-state/v1";

/// The host storage table holding sealed direct state.
pub const TABLE: &[u8] = b"directstate";

/// The first retry after a failed order, doubling up to [`MAX_BACKOFF`].
pub const MIN_BACKOFF: i64 = 60;
pub const MAX_BACKOFF: i64 = 3600;

/// The first retry after a failed self-probe, doubling up to
/// [`PROBE_MAX_BACKOFF`]. A failed probe costs the CA nothing, so it retries
/// sooner than a failed order.
pub const PROBE_MIN_BACKOFF: i64 = 120;
pub const PROBE_MAX_BACKOFF: i64 = 900;

/// The runtime's host storage (unsealed bytes: everything stored here is
/// sealed first).
pub trait Store {
    fn get(&self, table: &[u8], key: &[u8]) -> Option<Vec<u8>>;
    fn put(&self, table: &[u8], key: &[u8], value: &[u8]) -> Result<(), String>;
}

/// AES-256-GCM under the app's state key. Sealed = nonce || ciphertext+tag;
/// the AAD binds each value to its table and key.
struct Sealer(LessSafeKey);

impl Sealer {
    fn for_branch(branch: &[u8; 32]) -> Result<Self, String> {
        let hk = Hkdf::<Sha256>::new(None, branch);
        let mut key = [0u8; 32];
        hk.expand(STATE_LABEL.as_bytes(), &mut key).map_err(|_| "direct: hkdf expand".to_string())?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "direct: state key".to_string())?;
        Ok(Sealer(LessSafeKey::new(unbound)))
    }

    fn seal(&self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(|_| "direct: no randomness".to_string())?;
        let mut buf = plain.to_vec();
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
            .map_err(|_| "direct: seal".to_string())?;
        let mut out = nonce.to_vec();
        out.extend(buf);
        Ok(out)
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return None;
        }
        let (n, rest) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(n).ok()?;
        let mut buf = rest.to_vec();
        let plain = self.0.open_in_place(nonce, Aad::from(aad), &mut buf).ok()?;
        Some(plain.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
struct PinRecord {
    pin: Pin,
    canonical: String,
}

#[derive(Serialize, Deserialize)]
struct CertRecord {
    chain_pem: String,
    key_pkcs8_der: Vec<u8>,
}

/// A certificate a direct name serves.
#[derive(Clone)]
pub struct Served {
    pub chain_pem: String,
    pub key_pkcs8_der: Vec<u8>,
    pub facts: LeafFacts,
}

impl Served {
    /// The chain as DER, leaf first.
    pub fn chain_der(&self) -> Vec<Vec<u8>> {
        x509_parser::pem::Pem::iter_from_buffer(self.chain_pem.as_bytes())
            .filter_map(|p| p.ok())
            .map(|p| p.contents)
            .collect()
    }
}

/// One direct name.
pub struct Name {
    pub app: String,
    pub served: Option<Served>,
    pub challenge: Option<CertAndKey>,
    /// Bumped whenever `served` changes, so a TLS config cache can tell.
    pub generation: u64,
    next_attempt: i64,
    backoff: i64,
    probe: Option<binding::ProbeStatus>,
    probe_next: i64,
    probe_backoff: i64,
    probe_at: i64,
}

struct App {
    canonical: String,
    domains: Vec<String>,
    account_uri: String,
    pin: Option<Pin>,
    sealer: Sealer,
}

/// Every app's direct state on this runtime.
#[derive(Default)]
pub struct Direct {
    apps: BTreeMap<String, App>,
    names: BTreeMap<String, Name>,
    generation: u64,
}

fn pin_key(app: &str) -> Vec<u8> {
    format!("pin:{app}").into_bytes()
}

fn cert_key(app: &str, domain: &str) -> Vec<u8> {
    format!("cert:{app}:{domain}").into_bytes()
}

fn aad(key: &[u8]) -> Vec<u8> {
    let mut a = TABLE.to_vec();
    a.push(b'|');
    a.extend_from_slice(key);
    a
}

impl Direct {
    pub fn new() -> Self {
        Self::default()
    }

    fn load<T: for<'a> Deserialize<'a>>(sealer: &Sealer, store: &dyn Store, key: &[u8]) -> Option<T> {
        let sealed = store.get(TABLE, key)?;
        let plain = sealer.open(&sealed, &aad(key))?;
        serde_json::from_slice(&plain).ok()
    }

    fn save<T: Serialize>(sealer: &Sealer, store: &dyn Store, key: &[u8], value: &T) -> Result<(), String> {
        let plain = serde_json::to_vec(value).map_err(|e| format!("direct: encode: {e}"))?;
        store.put(TABLE, key, &sealer.seal(&plain, &aad(key))?)
    }

    /// Restores an app's direct state from the host storage, with no network
    /// call: the names, their certificates and the status. Returns whether a
    /// pin was found. Called when the app is (re)loaded.
    pub fn restore(&mut self, store: &dyn Store, app: &str, canonical: &str, branch: &[u8; 32]) -> Result<bool, String> {
        let sealer = Sealer::for_branch(branch)?;
        let rec: Option<PinRecord> = Self::load(&sealer, store, &pin_key(app));
        let (pin, domains) = match rec {
            Some(r) => {
                let d = r.pin.domains.clone();
                (Some(r.pin), d)
            }
            None => (None, Vec::new()),
        };
        let found = pin.is_some();
        self.set_app(store, app, canonical, sealer, pin, domains);
        Ok(found)
    }

    /// Accepts an owner-signed policy whose approval token the caller has
    /// verified (signature, issuer, audience, expiry). The sequence must move
    /// forward from the sealed pin, and only its approver may sign the next.
    pub fn accept(
        &mut self,
        store: &dyn Store,
        app: &str,
        canonical: &str,
        branch: &[u8; 32],
        parsed: &Parsed,
        approval: &Approval<'_>,
    ) -> Result<Pin, String> {
        let subject = policy::check_approval(&parsed.doc, &parsed.raw, approval)?;
        let sealer = Sealer::for_branch(branch)?;
        let current: Option<PinRecord> = Self::load(&sealer, store, &pin_key(app));
        let pin = policy::accept(current.as_ref().map(|r| &r.pin), &parsed.doc, &subject)?;
        let rec = PinRecord { pin: pin.clone(), canonical: canonical.to_string() };
        Self::save(&sealer, store, &pin_key(app), &rec)?;
        let domains = pin.domains.clone();
        self.set_app(store, app, canonical, sealer, Some(pin.clone()), domains);
        Ok(pin)
    }

    fn set_app(&mut self, store: &dyn Store, app: &str, canonical: &str, sealer: Sealer, pin: Option<Pin>, domains: Vec<String>) {
        self.names.retain(|d, n| n.app != app || domains.contains(d));
        for d in &domains {
            if self.names.contains_key(d) {
                continue;
            }
            let served = Self::load::<CertRecord>(&sealer, store, &cert_key(app, d)).and_then(|c| {
                let facts = binding::leaf_facts(&c.chain_pem).ok()?;
                Some(Served { chain_pem: c.chain_pem, key_pkcs8_der: c.key_pkcs8_der, facts })
            });
            self.generation += 1;
            self.names.insert(
                d.clone(),
                Name {
                    app: app.to_string(), served, challenge: None, generation: self.generation,
                    next_attempt: 0, backoff: 0, probe: None, probe_next: 0, probe_backoff: 0, probe_at: 0,
                },
            );
        }
        let account_uri = self.apps.get(app).map(|a| a.account_uri.clone()).unwrap_or_default();
        self.apps.insert(app.to_string(), App { canonical: canonical.to_string(), domains, account_uri, pin, sealer });
    }

    /// The name a handshake asked for.
    pub fn name(&self, domain: &str) -> Option<&Name> {
        self.names.get(domain)
    }

    /// An app's canonical host and its domains.
    pub fn app(&self, app: &str) -> Option<(String, Vec<String>)> {
        self.apps.get(app).map(|a| (a.canonical.clone(), a.domains.clone()))
    }

    /// The accepted pin of an app.
    pub fn pin(&self, app: &str) -> Option<&Pin> {
        self.apps.get(app).and_then(|a| a.pin.as_ref())
    }

    /// The OID 7.4 value of an app.
    pub fn key_bindings(&self, app: &str) -> Option<Vec<u8>> {
        let issued: Vec<(String, String)> = self
            .names
            .iter()
            .filter(|(_, n)| n.app == app)
            .filter_map(|(d, n)| n.served.as_ref().map(|s| (d.clone(), s.facts.spki_sha256.clone())))
            .collect();
        binding::key_bindings(&issued)
    }

    /// The control plane's view of an app.
    pub fn status(&self, app: &str) -> Status {
        let (account_uri, domains) = self
            .apps
            .get(app)
            .map(|a| (a.account_uri.clone(), a.domains.clone()))
            .unwrap_or_default();
        Status {
            supported: true,
            account_uri,
            domains: domains
                .iter()
                .map(|d| {
                    let facts = self.names.get(d).and_then(|n| n.served.as_ref()).map(|s| s.facts.clone());
                    let probe = self.names.get(d).and_then(|n| n.probe.clone());
                    DomainStatus {
                        probe,
                        name: d.clone(),
                        issued: facts.is_some(),
                        not_after: facts.as_ref().map(|f| f.not_after.clone()).unwrap_or_default(),
                        spki_sha256: facts.map(|f| f.spki_sha256).unwrap_or_default(),
                    }
                })
                .collect(),
        }
    }

    /// The names of an app due for issuance or renewal at `now`.
    pub fn due(&self, app: &str, now: i64) -> Vec<String> {
        self.names
            .iter()
            .filter(|(_, n)| n.app == app && n.next_attempt <= now)
            .filter(|(_, n)| n.served.as_ref().map(|s| binding::needs_renewal(s.facts.not_after_unix, now)).unwrap_or(true))
            .map(|(d, _)| d.clone())
            .collect()
    }

    fn set_challenge(&mut self, domain: &str, cert: Option<&CertAndKey>) {
        if let Some(n) = self.names.get_mut(domain) {
            n.challenge = cert.cloned();
        }
    }

    fn issued(&mut self, store: &dyn Store, app: &str, domain: &str, chain_pem: String, key_pkcs8_der: Vec<u8>) -> Result<(), String> {
        let facts = binding::leaf_facts(&chain_pem)?;
        let a = self.apps.get(app).ok_or("direct: unknown app")?;
        let rec = CertRecord { chain_pem: chain_pem.clone(), key_pkcs8_der: key_pkcs8_der.clone() };
        Self::save(&a.sealer, store, &cert_key(app, domain), &rec)?;
        self.generation += 1;
        let generation = self.generation;
        if let Some(n) = self.names.get_mut(domain) {
            n.served = Some(Served { chain_pem, key_pkcs8_der, facts });
            n.generation = generation;
            n.backoff = 0;
            n.next_attempt = 0;
        }
        Ok(())
    }

    fn failed(&mut self, domain: &str, now: i64) -> i64 {
        match self.names.get_mut(domain) {
            Some(n) => {
                n.backoff = if n.backoff == 0 { MIN_BACKOFF } else { (n.backoff * 2).min(MAX_BACKOFF) };
                n.next_attempt = now + n.backoff;
                n.backoff
            }
            None => 0,
        }
    }

    /// Served names whose last probe is older than [`PROBE_MAX_BACKOFF`]:
    /// re-probed as a health signal (it costs the CA nothing), never ordered.
    fn probe_stale(&self, app: &str, now: i64) -> Vec<String> {
        self.names
            .iter()
            .filter(|(_, n)| n.app == app && n.served.is_some())
            .filter(|(_, n)| n.probe.is_none() || n.probe_at + PROBE_MAX_BACKOFF <= now)
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// Whether a name may be probed at `now` (not inside a probe backoff).
    fn probe_due(&self, domain: &str, now: i64) -> bool {
        self.names.get(domain).map(|n| n.probe_next <= now).unwrap_or(false)
    }

    fn probed(&mut self, domain: &str, now: i64, result: &Result<(), String>) -> i64 {
        let n = match self.names.get_mut(domain) {
            Some(n) => n,
            None => return 0,
        };
        let checked_at = binding::rfc3339_unix(now);
        n.probe_at = now;
        match result {
            Ok(()) => {
                n.probe = Some(binding::ProbeStatus { ok: true, checked_at, error: String::new() });
                n.probe_backoff = 0;
                n.probe_next = 0;
                0
            }
            Err(e) => {
                n.probe = Some(binding::ProbeStatus { ok: false, checked_at, error: e.clone() });
                n.probe_backoff = if n.probe_backoff == 0 {
                    PROBE_MIN_BACKOFF
                } else {
                    (n.probe_backoff * 2).min(PROBE_MAX_BACKOFF)
                };
                n.probe_next = now + n.probe_backoff;
                n.probe_backoff
            }
        }
    }

    fn account_known(&self, app: &str) -> bool {
        self.apps.get(app).map(|a| !a.account_uri.is_empty()).unwrap_or(false)
    }

    fn set_account(&mut self, app: &str, uri: String) {
        if let Some(a) = self.apps.get_mut(app) {
            a.account_uri = uri;
        }
    }
}

/// What one [`drive`] did, for the caller's log and its certificate store.
#[derive(Debug, Default)]
pub struct Outcome {
    pub issued: Vec<String>,
    pub failed: Vec<(String, String, i64)>,
}

struct SharedSink<'a>(&'a Mutex<Direct>);

impl ChallengeSink for SharedSink<'_> {
    fn publish(&mut self, domain: &str, cert: Option<&CertAndKey>) {
        if let Ok(mut d) = self.0.lock() {
            d.set_challenge(domain, cert);
        }
    }
}

/// Issues or renews what is due for `app` at `now` (the status read calls
/// this). The lock is taken only for short reads and writes, never across
/// a network call: the CA's validation handshake reads the challenge while
/// the order is in flight.
///
/// Before any order, the name must resolve (`resolves`) and pass the
/// self-probe: `probe` connects to the name as the CA's validator would
/// (SNI the name, ALPN exactly `acme-tls/1`) and returns the leaf it was
/// served. Otherwise the name backs off and no order is placed.
pub fn drive<T: Transport>(
    shared: &Mutex<Direct>,
    store: &dyn Store,
    app: &str,
    branch: &[u8; 32],
    now: i64,
    transport: T,
    directory: &str,
    resolves: &mut dyn FnMut(&str) -> bool,
    probe: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Outcome, String> {
    let (due, stale, have_account) = {
        let d = shared.lock().map_err(|_| "direct: state lock poisoned")?;
        (d.due(app, now), d.probe_stale(app, now), d.account_known(app))
    };
    let mut out = Outcome::default();
    // Health re-probes of served names that are not due: recorded, never
    // ordered.
    for domain in stale.iter().filter(|d| !due.contains(d)) {
        if !shared.lock().map_err(|_| "direct: state lock poisoned")?.probe_due(domain, now) {
            continue;
        }
        let reached = if !resolves(domain) {
            Err("no DNS: the name does not resolve".to_string())
        } else {
            self_probe(shared, domain, probe)
        };
        shared.lock().map_err(|_| "direct: state lock poisoned")?.probed(domain, now, &reached);
    }
    if due.is_empty() && have_account {
        return Ok(out);
    }
    if !shared.lock().map_err(|_| "direct: state lock poisoned")?.apps.contains_key(app) {
        return Ok(out);
    }
    let key = keys::account_key(branch)?;
    let mut client = Client::new(transport, &key, directory);
    // No sleep between polls: each poll is a full HTTPS round trip.
    client.poll_ms = 0;
    client.max_polls = 40;
    if !have_account {
        let uri = client.account()?;
        shared.lock().map_err(|_| "direct: state lock poisoned")?.set_account(app, uri);
    }
    for domain in due {
        if !shared.lock().map_err(|_| "direct: state lock poisoned")?.probe_due(&domain, now) {
            continue;
        }
        let reached = if !resolves(&domain) {
            Err("no DNS: the name does not resolve yet".to_string())
        } else {
            self_probe(shared, &domain, probe)
        };
        let b = shared.lock().map_err(|_| "direct: state lock poisoned")?.probed(&domain, now, &reached);
        if let Err(e) = reached {
            out.failed.push((domain, format!("self-probe: {e}"), b));
            continue;
        }
        let mut sink = SharedSink(shared);
        match client.obtain(&domain, &mut sink) {
            Ok(issued) => {
                let mut d = shared.lock().map_err(|_| "direct: state lock poisoned")?;
                match d.issued(store, app, &domain, issued.chain_pem, issued.key_pkcs8_der) {
                    Ok(()) => out.issued.push(domain),
                    Err(e) => {
                        let b = d.failed(&domain, now);
                        out.failed.push((domain, e, b));
                    }
                }
            }
            Err(e) => {
                let b = shared.lock().map_err(|_| "direct: state lock poisoned")?.failed(&domain, now);
                out.failed.push((domain, e, b));
            }
        }
    }
    Ok(out)
}

/// Serves a probe challenge certificate for `domain` (a random key
/// authorization), has `probe` connect to the name as the CA would, and
/// checks the served leaf carries that key authorization. The probe
/// certificate is removed whatever the outcome.
fn self_probe(
    shared: &Mutex<Direct>,
    domain: &str,
    probe: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    let mut nonce = [0u8; 16];
    SystemRandom::new().fill(&mut nonce).map_err(|_| "no randomness".to_string())?;
    let key_authorization: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let cert = crate::challenge::tls_alpn_certificate(domain, &key_authorization)?;
    shared.lock().map_err(|_| "state lock poisoned".to_string())?.set_challenge(domain, Some(&cert));
    let served = probe(domain);
    if let Ok(mut d) = shared.lock() {
        d.set_challenge(domain, None);
    }
    let leaf = served.map_err(|e| format!("refused: {e}"))?;
    let want = <Sha256 as sha2::Digest>::digest(key_authorization.as_bytes());
    if acme_identifier(&leaf).as_deref() == Some(&want[..]) {
        Ok(())
    } else {
        Err("wrong certificate: acme-tls/1 on this name does not reach this runtime (not spliced yet?)".into())
    }
}

/// The digest an acmeIdentifier extension carries (RFC 8737), if any.
fn acme_identifier(leaf: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(leaf).ok()?;
    let oid = x509_parser::oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).ok()?;
    let ext = cert.extensions().iter().find(|e| e.oid == oid)?;
    // An OCTET STRING wrapping the 32-byte digest.
    if ext.value.len() == 34 && ext.value[0] == 0x04 && ext.value[1] == 32 {
        Some(ext.value[2..].to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
