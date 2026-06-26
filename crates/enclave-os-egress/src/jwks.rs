// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! JWKS fetching and caching for JWT signature verification.
//!
//! Lazily fetches JWKS from an OIDC provider's well-known endpoint (or an
//! explicit `jwks_uri`), caches the keys in memory, and re-fetches when the TTL
//! expires. Lives here (not in `common`) because it needs `https_fetch`, and
//! `egress` depends on `common` rather than the reverse. Both the WASM runtime
//! and the vault crate verify JWTs through this module.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::Mutex;

use enclave_os_common::jwks::{extract_jwt_kid, JwksCache};

use crate::client::{https_fetch, mozilla_root_store};

/// Cache TTL — keys are re-fetched after this many seconds.
const JWKS_CACHE_TTL_SECS: u64 = 3600; // 1 hour

/// Per-issuer cached JWKS entry.
struct CacheEntry {
    cache: JwksCache,
    fetched_at: u64,
}

/// Global JWKS cache keyed by JWKS URI. Thread-safe via Mutex; the SGX enclave
/// processes requests on a single thread, so contention is minimal.
static JWKS_STORE: Mutex<Option<BTreeMap<String, CacheEntry>>> = Mutex::new(None);

fn ensure_store() {
    let mut store = JWKS_STORE.lock().unwrap_or_else(|e| e.into_inner());
    if store.is_none() {
        *store = Some(BTreeMap::new());
    }
}

/// Discover the JWKS URI from `{issuer}/.well-known/openid-configuration`.
fn discover_jwks_uri(issuer: &str) -> Result<String, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = https_fetch(
        "GET",
        &url,
        &[("Accept".into(), "application/json".into())],
        None,
        mozilla_root_store(),
        None,
    )?;

    if resp.status != 200 {
        return Err(format!(
            "OIDC discovery failed: {} returned HTTP {}",
            url, resp.status
        ));
    }

    let doc: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("OIDC discovery JSON: {e}"))?;

    doc.get("jwks_uri")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("OIDC discovery: missing 'jwks_uri' in {url}"))
}

/// Fetch JWKS JSON from a URI and parse it into a [`JwksCache`].
fn fetch_jwks(jwks_uri: &str) -> Result<JwksCache, String> {
    let resp = https_fetch(
        "GET",
        jwks_uri,
        &[("Accept".into(), "application/json".into())],
        None,
        mozilla_root_store(),
        None,
    )?;

    if resp.status != 200 {
        return Err(format!(
            "JWKS fetch failed: {} returned HTTP {}",
            jwks_uri, resp.status
        ));
    }

    JwksCache::from_json(&resp.body)
}

/// Resolve the JWKS URI: explicit `jwks_uri` if non-empty, else OIDC discovery.
fn resolve_jwks_uri(issuer: &str, jwks_uri: &str) -> Result<String, String> {
    if !jwks_uri.is_empty() {
        return Ok(jwks_uri.to_string());
    }
    discover_jwks_uri(issuer)
}

/// Get or fetch a [`JwksCache`] for the given JWKS URI (TTL-based expiry).
fn get_or_fetch_cache(jwks_uri: &str) -> Result<(), String> {
    ensure_store();
    let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);

    let needs_fetch = {
        let store = JWKS_STORE.lock().unwrap_or_else(|e| e.into_inner());
        match store.as_ref().and_then(|s| s.get(jwks_uri)) {
            Some(entry) if now < entry.fetched_at + JWKS_CACHE_TTL_SECS => false,
            _ => true,
        }
    };

    if needs_fetch {
        let cache = fetch_jwks(jwks_uri)?;
        let mut store = JWKS_STORE.lock().unwrap_or_else(|e| e.into_inner());
        let store = store.as_mut().unwrap();
        store.insert(
            jwks_uri.to_string(),
            CacheEntry {
                cache,
                fetched_at: now,
            },
        );
    }

    Ok(())
}

/// Verify a JWT against the issuer's JWKS (signature + `kid` lookup, rejecting
/// `alg:none`) and decode its claims into `T`.
pub fn verify_jwt_with_jwks<T: serde::de::DeserializeOwned>(
    token: &str,
    issuer: &str,
    jwks_uri: &str,
) -> Result<T, String> {
    let kid = extract_jwt_kid(token)?;
    let resolved_uri = resolve_jwks_uri(issuer, jwks_uri)?;
    get_or_fetch_cache(&resolved_uri)?;

    let store = JWKS_STORE.lock().unwrap_or_else(|e| e.into_inner());
    let entry = store
        .as_ref()
        .and_then(|s| s.get(&resolved_uri))
        .ok_or_else(|| "JWKS cache miss (should not happen)".to_string())?;

    let verifier = match &kid {
        Some(k) => entry.cache.verifier(k)?,
        None => entry.cache.first_verifier()?,
    };

    verifier.verify_and_decode(token.as_bytes())
}

/// Same as [`verify_jwt_with_jwks`] but returns the raw claims JSON.
pub fn verify_jwt_signature(
    token: &str,
    issuer: &str,
    jwks_uri: &str,
) -> Result<serde_json::Value, String> {
    verify_jwt_with_jwks(token, issuer, jwks_uri)
}

/// Return the IdP's current EC P-256 signing keys as SEC1 uncompressed points
/// (65 B each), fetching/caching the JWKS as needed. Used for raw-ES256
/// verification (EncAuth voucher `idp_sig`), which carries no `kid` — callers
/// try each key.
pub fn idp_ec_p256_keys(issuer: &str, jwks_uri: &str) -> Result<Vec<Vec<u8>>, String> {
    let resolved_uri = resolve_jwks_uri(issuer, jwks_uri)?;
    get_or_fetch_cache(&resolved_uri)?;

    let store = JWKS_STORE.lock().unwrap_or_else(|e| e.into_inner());
    let entry = store
        .as_ref()
        .and_then(|s| s.get(&resolved_uri))
        .ok_or_else(|| "JWKS cache miss (should not happen)".to_string())?;
    let keys = entry.cache.ec_p256_keys();
    if keys.is_empty() {
        return Err("JWKS contains no EC P-256 keys".into());
    }
    Ok(keys)
}
