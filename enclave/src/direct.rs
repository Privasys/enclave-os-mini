// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Direct domains: an adopter hostname whose TLS ends in this enclave with a
//! publicly trusted certificate obtained here (the protocol and policy core
//! is the `enclave-os-direct` crate; this is the enclave glue).
//!
//! - The owner names the hostnames in the signed app policy
//!   (`PUT /api/v1/apps/<name>/policy`). The approval token is the
//!   authority, so the route needs no platform role. The accepted pin and
//!   the names are sealed to the host KV store, so they survive restarts.
//! - The handshake picks the certificate by ALPN: `acme-tls/1` gets the
//!   challenge certificate, `privasys-ratls/1` the RA-TLS leaf for the
//!   adopter name (through a cert-store alias), anything else the publicly
//!   trusted one. A connection served that one is the direct leg.
//! - Issuance and renewal run when the control plane reads the status
//!   (`GET /api/v1/apps/<name>/direct`, manager role): that request runs as
//!   a task, so its network waits suspend instead of blocking the enclave.
//!   No order is placed before the name resolves, and failures back off.
//! - The ACME account key derives from the app's vault-held data key, the
//!   same scheme as the container runtime, so an adopter's CAA record can
//!   pin issuance to code the vaults released that key to.
//! - OID 7.4 on the app's leaves binds each name to its certificate key.

use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex, OnceLock};
use std::vec::Vec;

use enclave_os_common::aead::AeadCipher;
use enclave_os_common::ocall;
use enclave_os_common::oidc::OidcClaims;
use enclave_os_direct::acme::{ChallengeSink, Client, Response, Transport};
use enclave_os_direct::binding::{self, DomainStatus, Status, DIRECT_DOMAIN_KEYS_OID};
use enclave_os_direct::challenge::CertAndKey;
use enclave_os_direct::policy::{self, Approval, Pin};
use enclave_os_direct::{dns, keys, select, Selection, LETS_ENCRYPT};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};

use crate::ratls::cert_store;
use crate::{enclave_log_error, enclave_log_info};

/// Host KV tables (values sealed under the direct key, AAD = table|key).
const PINS_TABLE: &[u8] = b"directpins";
const CERTS_TABLE: &[u8] = b"directcerts";
const INDEX_KEY: &[u8] = b"index";

/// HKDF label of the sealing key, from the enclave's sealed master key.
const SEAL_LABEL: &[u8] = b"privasys-direct-seal/v1";

/// The first retry after a failed attempt, doubling up to [`MAX_BACKOFF`].
const MIN_BACKOFF: u64 = 60;
const MAX_BACKOFF: u64 = 3600;

static SEAL: OnceLock<AeadCipher> = OnceLock::new();
static STATE: Mutex<State> = Mutex::new(State { names: BTreeMap::new(), apps: BTreeMap::new() });

/// One direct name.
struct Name {
    app: String,
    public: Option<(Arc<ServerConfig>, binding::LeafFacts)>,
    challenge: Option<Arc<ServerConfig>>,
    next_attempt: u64,
    backoff: u64,
}

/// One app with direct names.
#[derive(Default)]
struct App {
    canonical: String,
    domains: Vec<String>,
    account_uri: String,
}

struct State {
    names: BTreeMap<String, Name>,
    apps: BTreeMap<String, App>,
}

/// What a sealed pin record holds: the pin and the app's hostname, so names
/// can be served again at boot before the app itself is looked at.
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

// ---------------------------------------------------------------------------
//  Start-up
// ---------------------------------------------------------------------------

/// Derives the sealing key and serves every name a sealed pin holds.
pub fn init(master_key: &[u8; 32]) {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, SEAL_LABEL);
    let prk = salt.extract(master_key);
    let mut key = [0u8; 32];
    if prk
        .expand(&[b"seal"], ring::hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut key))
        .is_err()
    {
        enclave_log_error!("direct: sealing key not derived; direct domains disabled");
        return;
    }
    let _ = SEAL.set(AeadCipher::from_key(key));

    let apps: Vec<String> = load(PINS_TABLE, INDEX_KEY).unwrap_or_default();
    for app in apps {
        if let Some(rec) = load::<PinRecord>(PINS_TABLE, app.as_bytes()) {
            apply(&app, &rec.canonical, &rec.pin.domains);
        }
    }
}

// ---------------------------------------------------------------------------
//  Handshake
// ---------------------------------------------------------------------------

/// What the handshake on a direct name serves.
pub enum DirectTls {
    /// Not a direct name: the usual RA-TLS path.
    NotDirect,
    /// A direct name and a client that asked for RA-TLS: the usual path,
    /// which resolves the adopter name through its alias.
    RaTls,
    /// This config; `direct` is whether the connection is the direct leg.
    Serve { config: Arc<ServerConfig>, direct: bool },
}

/// Chooses the certificate for `sni` from the ALPN the client offered.
pub fn tls_for(sni: Option<&str>, alpn: &[String]) -> Result<DirectTls, String> {
    let sni = match sni {
        Some(s) => s.to_ascii_lowercase(),
        None => return Ok(DirectTls::NotDirect),
    };
    let st = STATE.lock().map_err(|_| "direct: state lock poisoned".to_string())?;
    let name = match st.names.get(&sni) {
        Some(n) => n,
        None => return Ok(DirectTls::NotDirect),
    };
    match select(alpn.iter().map(String::as_str)) {
        Selection::RaTls => Ok(DirectTls::RaTls),
        Selection::Challenge => name
            .challenge
            .clone()
            .map(|config| DirectTls::Serve { config, direct: false })
            .ok_or_else(|| format!("direct: no challenge in progress for {sni}")),
        Selection::Public => name
            .public
            .as_ref()
            .map(|(config, _)| DirectTls::Serve { config: config.clone(), direct: true })
            .ok_or_else(|| format!("direct: {sni} has no certificate yet")),
    }
}

fn server_config(chain: Vec<Vec<u8>>, key_pkcs8: Vec<u8>, alpn: Option<&[u8]>) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8));
    let mut config = ServerConfig::builder_with_details(
        Arc::new(default_provider()),
        Arc::new(crate::trustedtime::ServingTime),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("direct: tls config: {e:?}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| format!("direct: certificate: {e:?}"))?;
    if let Some(p) = alpn {
        config.alpn_protocols = vec![p.to_vec()];
    }
    Ok(Arc::new(config))
}

fn chain_der(chain_pem: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .filter_map(|p| p.ok())
        .map(|p| p.contents)
        .collect()
}

// ---------------------------------------------------------------------------
//  Policy
// ---------------------------------------------------------------------------

/// `PUT /api/v1/apps/<name>/policy`: an owner-signed policy for a WASM app.
/// `verify` checks the approval token's signature, issuer, audience and
/// expiry (the server's OIDC verifier).
pub fn handle_policy(
    app: &str,
    body: &[u8],
    verify: fn(&str) -> Result<OidcClaims, String>,
) -> (u16, Vec<u8>) {
    if SEAL.get().is_none() {
        return json_error(503, "direct: not initialised");
    }
    let parsed = match policy::parse(body) {
        Ok(p) => p,
        Err(e) => return json_error(400, &e),
    };
    let identity = match enclave_os_wasm::global().map(|w| w.direct_identity(app)) {
        Some(Ok(i)) => i,
        Some(Err(e)) => return json_error(404, &e),
        None => return json_error(503, "wasm module not loaded"),
    };
    let app_id = match identity.app_id {
        Some(id) => hex(&id),
        None => return json_error(409, "the app carries no app id, so it has no policy identity"),
    };
    if parsed.doc.app_id.to_ascii_lowercase().replace('-', "") != app_id {
        return json_error(403, "the document is for a different app");
    }
    let claims = match verify(&parsed.token) {
        Ok(c) => c,
        Err(e) => return json_error(403, &format!("apppolicy: approval token: {e}")),
    };
    let approval = Approval {
        sub: &claims.sub,
        amr: &claims.amr,
        vault_op: claims.vault_op.as_deref(),
        nonce: claims.nonce.as_deref(),
        exp: claims.exp as i64,
    };
    let subject = match policy::check_approval(&parsed.doc, &parsed.raw, &approval) {
        Ok(s) => s,
        Err(e) => return json_error(403, &e),
    };
    let current: Option<PinRecord> = load(PINS_TABLE, app.as_bytes());
    let pin = match policy::accept(current.as_ref().map(|r| &r.pin), &parsed.doc, &subject) {
        Ok(p) => p,
        Err(e) => return json_error(403, &e),
    };
    let rec = PinRecord { pin: pin.clone(), canonical: identity.hostname.clone() };
    if let Err(e) = store(PINS_TABLE, app.as_bytes(), &rec) {
        return json_error(500, &e);
    }
    let mut index: Vec<String> = load(PINS_TABLE, INDEX_KEY).unwrap_or_default();
    if !index.iter().any(|a| a == app) {
        index.push(app.to_string());
        let _ = store(PINS_TABLE, INDEX_KEY, &index);
    }
    apply(app, &identity.hostname, &pin.domains);
    enclave_log_info!(
        "direct: policy seq {} accepted for {} ({} domains)",
        pin.seq,
        app,
        pin.domains.len()
    );
    let applied: Vec<&str> = if parsed.doc.domains.is_some() { vec!["domains"] } else { vec![] };
    (
        200,
        serde_json::to_vec(&serde_json::json!({"app_id": app_id, "seq": pin.seq, "applied": applied}))
            .unwrap_or_default(),
    )
}

/// Serves exactly `domains` for `app`: names, cert-store aliases, and any
/// sealed certificate.
fn apply(app: &str, canonical: &str, domains: &[String]) {
    let mut st = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    st.names.retain(|d, n| n.app != app || domains.contains(d));
    for d in domains {
        if st.names.contains_key(d) {
            continue;
        }
        let public = load::<CertRecord>(CERTS_TABLE, d.as_bytes()).and_then(|c| public_from(&c).ok());
        st.names.insert(
            d.clone(),
            Name { app: app.to_string(), public, challenge: None, next_attempt: 0, backoff: 0 },
        );
    }
    let entry = st.apps.entry(app.to_string()).or_default();
    entry.canonical = canonical.to_string();
    entry.domains = domains.to_vec();
    let bindings = key_bindings_locked(&st, app);
    drop(st);
    cert_store::cert_store().set_aliases(canonical, domains);
    cert_store::cert_store().set_runtime_extension(canonical, DIRECT_DOMAIN_KEYS_OID, bindings);
}

fn public_from(c: &CertRecord) -> Result<(Arc<ServerConfig>, binding::LeafFacts), String> {
    let facts = binding::leaf_facts(&c.chain_pem)?;
    let config = server_config(chain_der(&c.chain_pem), c.key_pkcs8_der.clone(), None)?;
    Ok((config, facts))
}

fn key_bindings_locked(st: &State, app: &str) -> Option<Vec<u8>> {
    let issued: Vec<(String, String)> = st
        .names
        .iter()
        .filter(|(_, n)| n.app == app)
        .filter_map(|(d, n)| n.public.as_ref().map(|(_, f)| (d.clone(), f.spki_sha256.clone())))
        .collect();
    binding::key_bindings(&issued)
}

// ---------------------------------------------------------------------------
//  Status, issuance and renewal
// ---------------------------------------------------------------------------

/// `GET /api/v1/apps/<name>/direct`: the status the control plane reads.
/// Also the driver: a name due for issuance or renewal is attempted here.
pub fn handle_status(app: &str) -> (u16, Vec<u8>) {
    if SEAL.get().is_none() {
        return json_error(503, "direct: not initialised");
    }
    let identity = match enclave_os_wasm::global().map(|w| w.direct_identity(app)) {
        Some(Ok(i)) => i,
        Some(Err(e)) => return json_error(404, &e),
        None => return json_error(503, "wasm module not loaded"),
    };
    // No vault-held key: no account, so an empty account_uri (the control
    // plane reads that as "direct domains need a vault-backed app").
    if let Some(vault_key) = identity.vault_key {
        if let Err(e) = drive(app, &vault_key) {
            enclave_log_error!("direct: {}: {}", app, e);
        }
    }
    let st = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return json_error(500, "direct: state lock poisoned"),
    };
    let (account_uri, domains) = st
        .apps
        .get(app)
        .map(|a| (a.account_uri.clone(), a.domains.clone()))
        .unwrap_or_default();
    let status = Status {
        supported: true,
        account_uri,
        domains: domains
            .iter()
            .map(|d| {
                let facts = st.names.get(d).and_then(|n| n.public.as_ref()).map(|(_, f)| f.clone());
                DomainStatus {
                    name: d.clone(),
                    issued: facts.is_some(),
                    not_after: facts.as_ref().map(|f| f.not_after.clone()).unwrap_or_default(),
                    spki_sha256: facts.map(|f| f.spki_sha256).unwrap_or_default(),
                }
            })
            .collect(),
    };
    (200, serde_json::to_vec(&status).unwrap_or_default())
}

fn drive(app: &str, vault_key: &[u8; 32]) -> Result<(), String> {
    let now = ocall::get_current_time().map_err(|_| "no trusted time".to_string())? as i64;
    let (domains, have_account) = {
        let st = STATE.lock().map_err(|_| "state lock poisoned")?;
        match st.apps.get(app) {
            Some(a) if !a.domains.is_empty() => (a.domains.clone(), !a.account_uri.is_empty()),
            _ => return Ok(()),
        }
    };
    let key = keys::account_key(&keys::direct_branch(vault_key)?)?;
    let mut client = Client::new(Egress, &key, LETS_ENCRYPT);
    // No sleep between polls (the enclave has no timer a task can wait on):
    // each poll is a full HTTPS round trip, which paces it.
    client.poll_ms = 0;
    client.max_polls = 40;
    if !have_account {
        let uri = client.account()?;
        if let Ok(mut st) = STATE.lock() {
            if let Some(a) = st.apps.get_mut(app) {
                a.account_uri = uri;
            }
        }
    }
    for d in domains {
        let due = {
            let st = STATE.lock().map_err(|_| "state lock poisoned")?;
            match st.names.get(&d) {
                Some(n) => {
                    let wants = n
                        .public
                        .as_ref()
                        .map(|(_, f)| binding::needs_renewal(f.not_after_unix, now))
                        .unwrap_or(true);
                    wants && (n.next_attempt as i64) <= now
                }
                None => false,
            }
        };
        if !due {
            continue;
        }
        if !resolves(&d) {
            note_failure(&d, now, "the name does not resolve yet");
            continue;
        }
        let mut sink = Sink;
        match client.obtain(&d, &mut sink) {
            Ok(issued) => {
                let rec = CertRecord { chain_pem: issued.chain_pem, key_pkcs8_der: issued.key_pkcs8_der };
                let public = public_from(&rec)?;
                store(CERTS_TABLE, d.as_bytes(), &rec)?;
                let (canonical, bindings) = {
                    let mut st = STATE.lock().map_err(|_| "state lock poisoned")?;
                    if let Some(n) = st.names.get_mut(&d) {
                        n.public = Some(public);
                        n.backoff = 0;
                        n.next_attempt = 0;
                    }
                    let canonical = st.apps.get(app).map(|a| a.canonical.clone()).unwrap_or_default();
                    (canonical, key_bindings_locked(&st, app))
                };
                cert_store::cert_store().set_runtime_extension(&canonical, DIRECT_DOMAIN_KEYS_OID, bindings);
                enclave_log_info!("direct: certificate issued for {}", d);
            }
            Err(e) => note_failure(&d, now, &e),
        }
    }
    Ok(())
}

fn note_failure(domain: &str, now: i64, why: &str) {
    if let Ok(mut st) = STATE.lock() {
        if let Some(n) = st.names.get_mut(domain) {
            n.backoff = if n.backoff == 0 { MIN_BACKOFF } else { (n.backoff * 2).min(MAX_BACKOFF) };
            n.next_attempt = now as u64 + n.backoff;
            enclave_log_error!("direct: {}: {} (next attempt in {} s)", domain, why, n.backoff);
        }
    }
}

fn resolves(domain: &str) -> bool {
    match fetch("GET", &dns::query_url(domain), &[("Accept".into(), "application/dns-json".into())], None) {
        Ok(r) if r.status == 200 => dns::resolves(&r.body),
        _ => false,
    }
}

/// The challenge certificate, served by [`tls_for`] while the CA validates.
struct Sink;

impl ChallengeSink for Sink {
    fn publish(&mut self, domain: &str, cert: Option<&CertAndKey>) {
        let config = cert.and_then(|c| {
            server_config(vec![c.cert_der.clone()], c.key_pkcs8_der.clone(), Some(enclave_os_direct::ACME_TLS_ALPN.as_bytes())).ok()
        });
        if let Ok(mut st) = STATE.lock() {
            if let Some(n) = st.names.get_mut(domain) {
                n.challenge = config;
            }
        }
    }
}

/// The enclave's egress as the ACME transport.
struct Egress;

impl Transport for Egress {
    fn request(&mut self, method: &str, url: &str, body: Option<&[u8]>) -> Result<Response, String> {
        let headers: Vec<(String, String)> = match body {
            Some(_) => vec![("Content-Type".into(), "application/jose+json".into())],
            None => Vec::new(),
        };
        // HEAD responses carry no body; egress reads one, so ask with GET
        // (RFC 8555 allows GET on newNonce).
        let method = if method == "HEAD" { "GET" } else { method };
        let r = fetch(method, url, &headers, body)?;
        Ok(Response { status: r.status, headers: r.headers, body: r.body })
    }

    fn sleep_ms(&mut self, _ms: u64) {}
}

/// One HTTPS request over egress: suspending the request task when it can,
/// blocking otherwise.
fn fetch(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<enclave_os_egress::client::HttpResponse, String> {
    let roots = enclave_os_egress::client::mozilla_root_store();
    if enclave_os_wasm::executor::can_suspend() && enclave_os_egress::netchan::is_available() {
        enclave_os_wasm::executor::block_on(enclave_os_egress::client::https_fetch_async(
            method, url, headers, body, roots, None,
        ))
    } else {
        enclave_os_egress::client::https_fetch(method, url, headers, body, roots, None)
    }
}

// ---------------------------------------------------------------------------
//  Sealed host storage
// ---------------------------------------------------------------------------

fn aad(table: &[u8], key: &[u8]) -> Vec<u8> {
    let mut a = table.to_vec();
    a.push(b'|');
    a.extend_from_slice(key);
    a
}

fn store<T: Serialize>(table: &[u8], key: &[u8], value: &T) -> Result<(), String> {
    let seal = SEAL.get().ok_or("direct: not initialised")?;
    let plain = serde_json::to_vec(value).map_err(|e| format!("direct: encode: {e}"))?;
    let sealed = seal.encrypt(&plain, &aad(table, key)).map_err(|e| format!("direct: seal: {e}"))?;
    ocall::kv_store_put(table, key, &sealed).map_err(|e| format!("direct: host kv put: {e}"))
}

fn load<T: for<'a> Deserialize<'a>>(table: &[u8], key: &[u8]) -> Option<T> {
    let seal = SEAL.get()?;
    let sealed = ocall::kv_store_get(table, key).ok()??;
    let plain = seal.decrypt(&sealed, &aad(table, key)).ok()?;
    serde_json::from_slice(&plain).ok()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

fn json_error(status: u16, msg: &str) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap_or_default())
}
