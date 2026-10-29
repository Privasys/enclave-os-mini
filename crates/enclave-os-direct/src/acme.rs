// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! An RFC 8555 client for TLS-ALPN-01 (RFC 8737), over an injected
//! transport so it runs on the enclave's egress and in tests alike.
//!
//! One CA and one account: there is no retry against a test CA. A test CA
//! refuses the production account ("KeyID header contained an invalid
//! account URL"), so falling back to one means a name whose first attempt
//! failed is never issued.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::challenge::{key_and_csr, tls_alpn_certificate, CertAndKey};
use crate::jws::{sign, KeyRef};
use crate::keys::AccountKey;

/// An HTTP response.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The network and the clock, supplied by the caller.
pub trait Transport {
    /// One HTTPS request. `body` Some means a POST with
    /// `Content-Type: application/jose+json`.
    fn request(&mut self, method: &str, url: &str, body: Option<&[u8]>) -> Result<Response, String>;
    /// Waits between polls.
    fn sleep_ms(&mut self, ms: u64);
}

/// Where the challenge certificate must be served from while the CA
/// validates: the caller installs it for the domain, and removes it on
/// `None`.
pub trait ChallengeSink {
    fn publish(&mut self, domain: &str, cert: Option<&CertAndKey>);
}

/// A certificate the CA issued.
pub struct Issued {
    /// The chain, PEM, leaf first, as the CA returned it.
    pub chain_pem: String,
    /// The certificate key, PKCS#8 DER, generated in the enclave.
    pub key_pkcs8_der: Vec<u8>,
}

#[derive(Deserialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct Authorization {
    status: String,
    #[serde(default)]
    challenges: Vec<Challenge>,
}

#[derive(Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}

/// The ACME client of one account.
pub struct Client<'k, T: Transport> {
    transport: T,
    key: &'k AccountKey,
    directory_url: String,
    directory: Option<Directory>,
    nonce: Option<String>,
    account_url: Option<String>,
    /// How many polls of an authorization or order before giving up.
    pub max_polls: u32,
    /// The wait between polls.
    pub poll_ms: u64,
}

impl<'k, T: Transport> Client<'k, T> {
    pub fn new(transport: T, key: &'k AccountKey, directory_url: &str) -> Self {
        Self {
            transport,
            key,
            directory_url: directory_url.to_string(),
            directory: None,
            nonce: None,
            account_url: None,
            max_polls: 30,
            poll_ms: 2000,
        }
    }

    fn directory(&mut self) -> Result<&Directory, String> {
        if self.directory.is_none() {
            let url = self.directory_url.clone();
            let resp = self.transport.request("GET", &url, None)?;
            if resp.status != 200 {
                return Err(format!("acme: directory answered {}", resp.status));
            }
            self.directory = Some(
                serde_json::from_slice(&resp.body).map_err(|e| format!("acme: directory: {e}"))?,
            );
        }
        Ok(self.directory.as_ref().unwrap())
    }

    fn fresh_nonce(&mut self) -> Result<String, String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let url = self.directory()?.new_nonce.clone();
        let resp = self.transport.request("HEAD", &url, None)?;
        resp.header("Replay-Nonce")
            .map(str::to_string)
            .ok_or_else(|| "acme: no Replay-Nonce".to_string())
    }

    /// A signed POST. Retries once on badNonce, as RFC 8555 section 6.5
    /// allows.
    fn post(&mut self, url: &str, payload: Option<&serde_json::Value>, jwk: bool) -> Result<Response, String> {
        for attempt in 0..2 {
            let nonce = self.fresh_nonce()?;
            let key_ref = if jwk {
                KeyRef::Jwk
            } else {
                KeyRef::Kid(self.account_url.as_deref().ok_or("acme: no account")?)
            };
            let body = sign(self.key, key_ref, &nonce, url, payload);
            let resp = self.transport.request("POST", url, Some(&body))?;
            if let Some(n) = resp.header("Replay-Nonce") {
                self.nonce = Some(n.to_string());
            }
            if resp.status == 400 && attempt == 0 && problem_type(&resp.body).ends_with(":badNonce") {
                continue;
            }
            return Ok(resp);
        }
        unreachable!()
    }

    /// Registers the account, or finds the existing one for the key: the
    /// account URL is what an adopter's CAA record pins.
    pub fn account(&mut self) -> Result<String, String> {
        if let Some(url) = &self.account_url {
            return Ok(url.clone());
        }
        let url = self.directory()?.new_account.clone();
        let resp = self.post(&url, Some(&serde_json::json!({"termsOfServiceAgreed": true})), true)?;
        if resp.status != 200 && resp.status != 201 {
            return Err(format!("acme: new account answered {}: {}", resp.status, problem_detail(&resp.body)));
        }
        let location = resp.header("Location").ok_or("acme: account has no Location")?.to_string();
        self.account_url = Some(location.clone());
        Ok(location)
    }

    /// Obtains a certificate for one domain over TLS-ALPN-01.
    pub fn obtain(&mut self, domain: &str, sink: &mut dyn ChallengeSink) -> Result<Issued, String> {
        self.account()?;
        let new_order = self.directory()?.new_order.clone();
        let resp = self.post(
            &new_order,
            Some(&serde_json::json!({"identifiers": [{"type": "dns", "value": domain}]})),
            false,
        )?;
        if resp.status != 201 {
            return Err(format!("acme: new order answered {}: {}", resp.status, problem_detail(&resp.body)));
        }
        let order_url = resp.header("Location").ok_or("acme: order has no Location")?.to_string();
        let mut order: Order = parse(&resp.body, "order")?;

        for authz_url in order.authorizations.clone() {
            let result = self.authorize(&authz_url, domain, sink);
            sink.publish(domain, None);
            result?;
        }

        let (key_der, csr_der) = key_and_csr(domain)?;
        order = self.poll_order(&order_url, &["ready", "valid"])?;
        if order.status == "ready" {
            let resp = self.post(
                &order.finalize.clone(),
                Some(&serde_json::json!({"csr": URL_SAFE_NO_PAD.encode(&csr_der)})),
                false,
            )?;
            if resp.status != 200 {
                return Err(format!("acme: finalize answered {}: {}", resp.status, problem_detail(&resp.body)));
            }
            order = self.poll_order(&order_url, &["valid"])?;
        }
        let cert_url = order.certificate.ok_or("acme: valid order has no certificate")?;
        let resp = self.post(&cert_url, None, false)?;
        if resp.status != 200 {
            return Err(format!("acme: certificate answered {}", resp.status));
        }
        let chain_pem = String::from_utf8(resp.body).map_err(|_| "acme: certificate is not PEM".to_string())?;
        Ok(Issued { chain_pem, key_pkcs8_der: key_der })
    }

    fn authorize(&mut self, authz_url: &str, domain: &str, sink: &mut dyn ChallengeSink) -> Result<(), String> {
        let resp = self.post(authz_url, None, false)?;
        let authz: Authorization = parse(&resp.body, "authorization")?;
        if authz.status == "valid" {
            return Ok(());
        }
        let chal = authz
            .challenges
            .into_iter()
            .find(|c| c.kind == "tls-alpn-01")
            .ok_or("acme: the CA offered no tls-alpn-01 challenge")?;
        let cert = tls_alpn_certificate(domain, &self.key.key_authorization(&chal.token))?;
        sink.publish(domain, Some(&cert));
        let resp = self.post(&chal.url, Some(&serde_json::json!({})), false)?;
        if resp.status != 200 {
            return Err(format!("acme: challenge answered {}: {}", resp.status, problem_detail(&resp.body)));
        }
        for _ in 0..self.max_polls {
            let resp = self.post(authz_url, None, false)?;
            let authz: Authorization = parse(&resp.body, "authorization")?;
            match authz.status.as_str() {
                "valid" => return Ok(()),
                "pending" | "processing" => self.transport.sleep_ms(self.poll_ms),
                other => {
                    return Err(format!(
                        "acme: authorization {other}: {}",
                        problem_detail(&resp.body)
                    ))
                }
            }
        }
        Err("acme: authorization still pending".into())
    }

    fn poll_order(&mut self, order_url: &str, want: &[&str]) -> Result<Order, String> {
        for _ in 0..self.max_polls {
            let resp = self.post(order_url, None, false)?;
            let order: Order = parse(&resp.body, "order")?;
            if want.contains(&order.status.as_str()) {
                return Ok(order);
            }
            if order.status == "invalid" {
                return Err(format!("acme: order invalid: {}", problem_detail(&resp.body)));
            }
            self.transport.sleep_ms(self.poll_ms);
        }
        Err("acme: order did not progress".into())
    }
}

fn parse<D: for<'a> Deserialize<'a>>(body: &[u8], what: &str) -> Result<D, String> {
    serde_json::from_slice(body).map_err(|e| format!("acme: {what}: {e}"))
}

fn problem_type(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_default()
}

fn problem_detail(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let d = v.get("detail").and_then(|t| t.as_str()).unwrap_or("");
            Some(format!("{t} {d}").trim().to_string())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
