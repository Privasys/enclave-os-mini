// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Direct domains: an adopter hostname whose TLS ends in this enclave with a
//! publicly trusted certificate obtained here. The protocol, the policy and
//! the state are the `enclave-os-direct` crate; this is the enclave glue.
//!
//! - The owner names the hostnames in the signed app policy
//!   (`PUT /api/v1/apps/<name>/policy`). The approval token is the
//!   authority, so the route needs no platform role.
//! - The handshake picks the certificate by ALPN: `acme-tls/1` gets the
//!   challenge certificate, `privasys-ratls/1` the RA-TLS leaf for the
//!   adopter name (through a cert-store alias), anything else the publicly
//!   trusted one. A connection served that one is the direct leg.
//! - Issuance and renewal run when the control plane reads the status
//!   (`GET /api/v1/apps/<name>/direct`, manager role): that request runs as
//!   a task, so its network waits suspend instead of blocking the enclave.
//! - Everything an app holds (the pin, the certificates and their keys) is
//!   sealed to the host store under a key from the app's vault-held key, not
//!   this enclave's: when an app is loaded on any build the vaults release
//!   that key to, its names, certificates and status come back with no
//!   network call and no new approval.
//! - OID 7.4 on the app's leaves binds each name to its certificate key.

use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex, OnceLock};
use std::vec::Vec;

use enclave_os_common::ocall;
use enclave_os_common::oidc::OidcClaims;
use enclave_os_direct::acme::{Response, Transport};
use enclave_os_direct::binding::DIRECT_DOMAIN_KEYS_OID;
use enclave_os_direct::policy::{self, Approval};
use enclave_os_direct::state::{self, Direct, Store};
use enclave_os_direct::{dns, select, tls, Selection, LETS_ENCRYPT};
use rustls::ServerConfig;

use crate::ratls::cert_store;
use crate::{enclave_log_error, enclave_log_info};

fn shared() -> &'static Mutex<Direct> {
    static STATE: OnceLock<Mutex<Direct>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Direct::new()))
}

/// Built configs of the publicly trusted certificates, by name, with the
/// generation they were built from.
fn configs() -> &'static Mutex<BTreeMap<String, (u64, Arc<ServerConfig>)>> {
    static CONFIGS: OnceLock<Mutex<BTreeMap<String, (u64, Arc<ServerConfig>)>>> = OnceLock::new();
    CONFIGS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// App hostnames registered since the last restore pass. The registration
/// hook may run under the wasm registry lock, so it only queues; the
/// restore runs at the next handshake or direct route.
fn pending() -> &'static Mutex<Vec<String>> {
    static PENDING: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

/// The host KV store; every value is already sealed by the crate.
struct HostStore;

impl Store for HostStore {
    fn get(&self, table: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        ocall::kv_store_get(table, key).ok().flatten()
    }
    fn put(&self, table: &[u8], key: &[u8], value: &[u8]) -> Result<(), String> {
        ocall::kv_store_put(table, key, value).map_err(|e| format!("direct: host kv put: {e}"))
    }
}

fn serving_time() -> Arc<dyn rustls::time_provider::TimeProvider> {
    Arc::new(crate::trustedtime::ServingTime)
}

// ---------------------------------------------------------------------------
//  Start-up and app registration
// ---------------------------------------------------------------------------

/// Queues every app already registered for a restore pass.
pub fn init() {
    if let Ok(mut p) = pending().lock() {
        p.extend(cert_store::cert_store().hostnames());
    }
}

/// Called when an app identity is registered (loaded or reloaded).
pub fn note_registered(hostname: &str) {
    if let Ok(mut p) = pending().lock() {
        p.push(hostname.to_string());
    }
}

/// Restores the direct state of the apps registered since the last pass.
fn restore_pending() {
    let hosts: Vec<String> = match pending().lock() {
        Ok(mut p) if !p.is_empty() => std::mem::take(&mut *p),
        _ => return,
    };
    let wasm = match enclave_os_wasm::global() {
        Some(w) => w,
        None => return,
    };
    let apps = wasm.list_apps();
    for host in hosts {
        let name = match apps.iter().find(|a| a.hostname == host) {
            Some(a) => a.name.clone(),
            None => continue,
        };
        let branch = match wasm.direct_identity(&name).ok().and_then(|i| i.direct_branch) {
            Some(b) => b,
            None => continue,
        };
        let restored = shared().lock().map(|mut d| d.restore(&HostStore, &name, &host, &branch));
        match restored {
            Ok(Ok(true)) => {
                publish(&name);
                enclave_log_info!("direct: {} restored from sealed state", name);
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => enclave_log_error!("direct: {}: restore: {}", name, e),
            Err(_) => enclave_log_error!("direct: state lock poisoned"),
        }
    }
}

/// Pushes an app's names and key bindings to the cert store.
fn publish(app: &str) {
    let (canonical, domains, bindings) = match shared().lock() {
        Ok(d) => match d.app(app) {
            Some((c, ds)) => (c, ds, d.key_bindings(app)),
            None => return,
        },
        Err(_) => return,
    };
    cert_store::cert_store().set_aliases(&canonical, &domains);
    cert_store::cert_store().set_runtime_extension(&canonical, DIRECT_DOMAIN_KEYS_OID, bindings);
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
    restore_pending();
    let sni = match sni {
        Some(s) => s.to_ascii_lowercase(),
        None => return Ok(DirectTls::NotDirect),
    };
    let d = shared().lock().map_err(|_| "direct: state lock poisoned".to_string())?;
    let name = match d.name(&sni) {
        Some(n) => n,
        None => return Ok(DirectTls::NotDirect),
    };
    match select(alpn.iter().map(String::as_str)) {
        Selection::RaTls => Ok(DirectTls::RaTls),
        Selection::Challenge => {
            let c = name.challenge.as_ref().ok_or_else(|| format!("direct: no challenge in progress for {sni}"))?;
            let config = tls::challenge_config(c, serving_time())?;
            Ok(DirectTls::Serve { config, direct: false })
        }
        Selection::Public => {
            let served = name.served.as_ref().ok_or_else(|| format!("direct: {sni} has no certificate yet"))?;
            let mut cache = configs().lock().map_err(|_| "direct: config lock poisoned".to_string())?;
            if let Some((generation, config)) = cache.get(&sni) {
                if *generation == name.generation {
                    return Ok(DirectTls::Serve { config: config.clone(), direct: true });
                }
            }
            let config = tls::public_config(served.chain_der(), served.key_pkcs8_der.clone(), serving_time())?;
            cache.insert(sni, (name.generation, config.clone()));
            Ok(DirectTls::Serve { config, direct: true })
        }
    }
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
    restore_pending();
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
    // The state is sealed under the vault-held key: an app without one has
    // nowhere durable to keep its pin, and could not hold an ACME account.
    let branch = match identity.direct_branch {
        Some(b) => b,
        None => return json_error(409, "direct domains need a vault-backed app"),
    };
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
    let accepted = match shared().lock() {
        Ok(mut d) => d.accept(&HostStore, app, &identity.hostname, &branch, &parsed, &approval),
        Err(_) => return json_error(500, "direct: state lock poisoned"),
    };
    let pin = match accepted {
        Ok(p) => p,
        Err(e) => return json_error(403, &e),
    };
    publish(app);
    enclave_log_info!("direct: policy seq {} accepted for {} ({} domains)", pin.seq, app, pin.domains.len());
    let applied: Vec<&str> = if parsed.doc.domains.is_some() { vec!["domains"] } else { vec![] };
    (
        200,
        serde_json::to_vec(&serde_json::json!({"app_id": app_id, "seq": pin.seq, "applied": applied}))
            .unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
//  Status, issuance and renewal
// ---------------------------------------------------------------------------

/// `GET /api/v1/apps/<name>/direct`: the status the control plane reads.
/// Also the driver: a name due for issuance or renewal is attempted here.
pub fn handle_status(app: &str) -> (u16, Vec<u8>) {
    restore_pending();
    let identity = match enclave_os_wasm::global().map(|w| w.direct_identity(app)) {
        Some(Ok(i)) => i,
        Some(Err(e)) => return json_error(404, &e),
        None => return json_error(503, "wasm module not loaded"),
    };
    // No vault-held key: no account, so an empty account_uri (the control
    // plane reads that as "direct domains need a vault-backed app").
    if let Some(branch) = identity.direct_branch {
        match ocall::get_current_time() {
            Ok(now) => {
                let mut resolves = |d: &str| resolves(d);
                match state::drive(shared(), &HostStore, app, &branch, now as i64, Egress, LETS_ENCRYPT, &mut resolves) {
                    Ok(out) => {
                        for d in &out.issued {
                            enclave_log_info!("direct: certificate issued for {}", d);
                        }
                        for (d, why, backoff) in &out.failed {
                            enclave_log_error!("direct: {}: {} (next attempt in {} s)", d, why, backoff);
                        }
                        if !out.issued.is_empty() {
                            publish(app);
                        }
                    }
                    Err(e) => enclave_log_error!("direct: {}: {}", app, e),
                }
            }
            Err(_) => enclave_log_error!("direct: {}: no trusted time, nothing issued", app),
        }
    }
    let status = match shared().lock() {
        Ok(d) => d.status(app),
        Err(_) => return json_error(500, "direct: state lock poisoned"),
    };
    (200, serde_json::to_vec(&status).unwrap_or_default())
}

fn resolves(domain: &str) -> bool {
    match fetch("GET", &dns::query_url(domain), &[("Accept".into(), "application/dns-json".into())], None) {
        Ok(r) if r.status == 200 => dns::resolves(&r.body),
        _ => false,
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

fn json_error(status: u16, msg: &str) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap_or_default())
}
