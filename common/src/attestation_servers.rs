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

use std::sync::RwLock;
use std::vec::Vec;

use ring::digest;

use crate::protocol::AttestationServer;

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
}

impl State {
    const fn empty() -> Self {
        Self {
            servers: Vec::new(),
            hash: None,
            canonical: None,
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
pub fn set(servers: Vec<AttestationServer>) -> (usize, Option<[u8; 32]>) {
    let (canonical, hash) = compute(&servers);
    let count = servers.len();
    let mut state = SERVERS.write().unwrap();
    state.servers = servers;
    state.hash = hash;
    state.canonical = canonical;
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
pub fn token_for(url: &str) -> Option<String> {
    SERVERS
        .read()
        .unwrap()
        .servers
        .iter()
        .find(|s| s.url == url)
        .and_then(|s| s.token.clone())
}

/// Current SHA-256 hash of the canonical URL list, or `None` if empty.
pub fn hash() -> Option<[u8; 32]> {
    SERVERS.read().unwrap().hash
}

/// Canonical (sorted, newline-joined) URL list, or `None` if empty.
pub fn canonical_form() -> Option<Vec<u8>> {
    SERVERS.read().unwrap().canonical.clone()
}
