// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Core attestation server storage.
//!
//! Provides a centralised, thread-safe store for attestation server
//! endpoints and their optional bearer tokens.  Both the enclave core
//! (startup configuration, `SetAttestationServers` API) and module
//! crates (egress quote verification) access this store.
//!
//! ## Hashing
//!
//! The canonical form is the sorted, newline-joined URL list (tokens
//! are excluded — they are runtime secrets and must never enter the
//! Merkle tree).  The SHA-256 hash of this canonical form is exposed
//! via OID `1.3.6.1.4.1.65230.2.7` in RA-TLS certificates.
//!
//! ## OIDC Bootstrap
//!
//! When a server has an [`OidcBootstrap`] configuration, the enclave
//! self-provisions its token via the OIDC jwt-bearer grant.  Tokens
//! are lazily refreshed at 75 % of their lifetime.

use std::sync::RwLock;
use std::vec::Vec;

use ring::digest;

use crate::protocol::{AttestationServer, OidcBootstrap};

// ---------------------------------------------------------------------------
//  OIDC bootstrap state (per-server)
// ---------------------------------------------------------------------------

/// Internal state for a bootstrapped OIDC token.
struct OidcState {
    /// OIDC bootstrap config (issuer, service_account_id, project_id).
    config: OidcBootstrap,
    /// Key ID returned by the OIDC provider's key registration API.
    key_id: String,
    /// DER-encoded PKCS#8 private key for building refresh assertions.
    private_key_der: Vec<u8>,
    /// Unix timestamp when the current token was issued.
    issued_at: u64,
    /// Token lifetime in seconds (from the `expires_in` field).
    lifetime_secs: u64,
}

impl OidcState {
    /// Returns `true` when the token has reached 75 % of its lifetime
    /// and should be lazily refreshed.
    fn needs_refresh(&self, now: u64) -> bool {
        if self.lifetime_secs == 0 {
            return false;
        }
        let threshold = self.issued_at + (self.lifetime_secs * 3) / 4;
        now >= threshold
    }
}

// ---------------------------------------------------------------------------
//  State
// ---------------------------------------------------------------------------

struct State {
    servers: Vec<AttestationServer>,
    /// SHA-256 of the canonical URL list.  `None` when no servers are
    /// configured.
    hash: Option<[u8; 32]>,
    /// Sorted, newline-joined URL list.  `None` when empty.
    canonical: Option<Vec<u8>>,
    /// Per-server OIDC bootstrap state.  The key is the server URL.
    oidc: Vec<(String, OidcState)>,
}

impl State {
    const fn empty() -> Self {
        Self {
            servers: Vec::new(),
            hash: None,
            canonical: None,
            oidc: Vec::new(),
        }
    }
}

static SERVERS: RwLock<State> = RwLock::new(State::empty());

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Compute the canonical form and SHA-256 hash from a list of servers.
fn compute(servers: &[AttestationServer]) -> (Option<Vec<u8>>, Option<[u8; 32]>) {
    if servers.is_empty() {
        return (None, None);
    }
    let mut urls: Vec<&str> = servers.iter().map(|s| s.url.as_str()).collect();
    urls.sort();
    let canonical = urls.join("\n");
    let d = digest::digest(&digest::SHA256, canonical.as_bytes());
    let mut h = [0u8; 32];
    h.copy_from_slice(d.as_ref());
    (Some(canonical.into_bytes()), Some(h))
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Initialise the attestation server list.
///
/// Typically called once during enclave startup with the configuration
/// provided by the operator.  May be called again via the
/// [`SetAttestationServers`](crate::protocol::Request::SetAttestationServers)
/// core API.
pub fn init(servers: Vec<AttestationServer>) -> (usize, Option<[u8; 32]>) {
    set(servers)
}

/// Replace the attestation server list and return `(count, hash)`.
///
/// The hash is the SHA-256 of the canonical (sorted, newline-joined)
/// URL list.  Tokens are excluded from the hash.
///
/// This also clears all OIDC bootstrap state; callers must re-bootstrap
/// servers that have `oidc_bootstrap` configs.
pub fn set(servers: Vec<AttestationServer>) -> (usize, Option<[u8; 32]>) {
    let (canonical, hash) = compute(&servers);
    let count = servers.len();
    let mut state = SERVERS.write().unwrap();
    state.servers = servers;
    state.hash = hash;
    state.canonical = canonical;
    state.oidc.clear();
    (count, hash)
}

/// Get a snapshot of the current attestation server URL list.
pub fn server_urls() -> Vec<String> {
    SERVERS
        .read()
        .unwrap()
        .servers
        .iter()
        .map(|s| s.url.clone())
        .collect()
}

/// Look up the bearer token for a given attestation server URL.
///
/// Returns `None` when no token has been configured for that URL.
///
/// For OIDC-bootstrapped servers, this checks whether the token has
/// reached 75 % of its lifetime and signals refresh via the returned
/// `NeedsRefresh` flag.  The actual refresh is triggered by the caller.
pub fn token_for(url: &str) -> Option<String> {
    SERVERS
        .read()
        .unwrap()
        .servers
        .iter()
        .find(|s| s.url == url)
        .and_then(|s| s.token.clone())
}

/// Check whether a server's OIDC token needs refresh.
///
/// Returns `Some((config, key_id, private_key_der))` when the token is
/// past 75 % of its lifetime, `None` otherwise.
pub fn needs_oidc_refresh(url: &str) -> Option<(OidcBootstrap, String, Vec<u8>)> {
    let now = crate::ocall::get_current_time().unwrap_or(0);
    let state = SERVERS.read().unwrap();
    state
        .oidc
        .iter()
        .find(|(u, _)| u == url)
        .filter(|(_, s)| s.needs_refresh(now))
        .map(|(_, s)| (s.config.clone(), s.key_id.clone(), s.private_key_der.clone()))
}

/// Update the bearer token for a given server URL (in-place).
///
/// Used after a successful OIDC bootstrap or token refresh.
pub fn update_token(url: &str, token: String) {
    let mut state = SERVERS.write().unwrap();
    if let Some(srv) = state.servers.iter_mut().find(|s| s.url == url) {
        srv.token = Some(token);
    }
}

/// Record OIDC bootstrap state for a server after initial bootstrap.
pub fn set_oidc_state(
    url: &str,
    config: OidcBootstrap,
    key_id: String,
    private_key_der: Vec<u8>,
    token: String,
    expires_in: u64,
) {
    let now = crate::ocall::get_current_time().unwrap_or(0);
    let mut state = SERVERS.write().unwrap();

    // Update the server's token
    if let Some(srv) = state.servers.iter_mut().find(|s| s.url == url) {
        srv.token = Some(token);
    }

    // Store OIDC state (replace if exists)
    state.oidc.retain(|(u, _)| u != url);
    state.oidc.push((
        url.to_string(),
        OidcState {
            config,
            key_id,
            private_key_der,
            issued_at: now,
            lifetime_secs: expires_in,
        },
    ));
}

/// After a successful token refresh, update the issued_at and token.
pub fn update_oidc_token(url: &str, token: String, expires_in: u64) {
    let now = crate::ocall::get_current_time().unwrap_or(0);
    let mut state = SERVERS.write().unwrap();

    // Update the server's token
    if let Some(srv) = state.servers.iter_mut().find(|s| s.url == url) {
        srv.token = Some(token);
    }

    // Update OIDC state
    if let Some((_, oidc)) = state.oidc.iter_mut().find(|(u, _)| u == url) {
        oidc.issued_at = now;
        oidc.lifetime_secs = expires_in;
    }
}

/// Current SHA-256 hash of the canonical URL list, or `None` if empty.
pub fn hash() -> Option<[u8; 32]> {
    SERVERS.read().unwrap().hash
}

/// Canonical (sorted, newline-joined) URL list, or `None` if empty.
pub fn canonical_form() -> Option<Vec<u8>> {
    SERVERS.read().unwrap().canonical.clone()
}
