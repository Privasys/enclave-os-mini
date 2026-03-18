// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! JWKS (JSON Web Key Set) parsing and key cache for JWT signature verification.
//!
//! Parses JWKS JSON responses from OIDC providers and extracts EC P-256
//! public keys for ES256 signature verification.  Only ES256 (ECDSA P-256)
//! is supported — RSA keys in the JWKS are silently ignored.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use enclave_os_common::jwks::JwksCache;
//!
//! // Parse a JWKS JSON response from the provider's jwks_uri endpoint.
//! let cache = JwksCache::from_json(jwks_bytes)?;
//!
//! // Look up a key by `kid` header from a JWT.
//! let verifier = cache.verifier("key-id-123")?;
//! let claims: MyClaims = verifier.verify_and_decode(jwt_bytes)?;
//! ```

#[cfg(feature = "sgx")]
use alloc::{format, string::String, vec::Vec};
#[cfg(not(feature = "sgx"))]
use std::{format, string::String, vec::Vec};

use crate::jwt::JwtVerifier;

/// A cached set of JWKS keys, indexed by `kid`.
pub struct JwksCache {
    /// (kid, raw_public_key_bytes) pairs for EC P-256 keys.
    keys: Vec<(String, Vec<u8>)>,
}

impl JwksCache {
    /// Parse a JWKS JSON response and extract EC P-256 public keys.
    ///
    /// Non-EC keys and keys with `kty` != `"EC"` or `crv` != `"P-256"`
    /// are silently skipped — only ES256 is supported.
    pub fn from_json(json_bytes: &[u8]) -> Result<Self, String> {
        let jwks: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|e| format!("JWKS JSON parse failed: {e}"))?;

        let keys_arr = jwks.get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "JWKS missing 'keys' array".to_string())?;

        let mut keys = Vec::new();

        for key in keys_arr {
            // Only accept EC keys on the P-256 curve
            let kty = key.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "EC" {
                continue;
            }
            let crv = key.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if crv != "P-256" {
                continue;
            }

            // kid is required for lookup
            let kid = match key.get("kid").and_then(|v| v.as_str()) {
                Some(k) => k.to_string(),
                None => continue,
            };

            // Extract x and y coordinates (base64url-encoded, 32 bytes each)
            let x_b64 = match key.get("x").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => continue,
            };
            let y_b64 = match key.get("y").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => continue,
            };

            let x = match base64_url_decode(x_b64) {
                Ok(v) if v.len() == 32 => v,
                _ => continue,
            };
            let y = match base64_url_decode(y_b64) {
                Ok(v) if v.len() == 32 => v,
                _ => continue,
            };

            // Build uncompressed point: 04 || x || y (65 bytes)
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);

            keys.push((kid, uncompressed));
        }

        if keys.is_empty() {
            return Err("JWKS contains no usable EC P-256 keys".into());
        }

        Ok(Self { keys })
    }

    /// Look up a [`JwtVerifier`] by `kid`.
    ///
    /// Returns `Err` if the `kid` is not found or the key is invalid.
    pub fn verifier(&self, kid: &str) -> Result<JwtVerifier, String> {
        let raw = self.keys.iter()
            .find(|(k, _)| k == kid)
            .map(|(_, v)| v.as_slice())
            .ok_or_else(|| format!("JWKS key '{}' not found", kid))?;

        JwtVerifier::from_public_key_bytes(raw)
    }

    /// Return a verifier for the first key, when there is only one key
    /// in the JWKS (or when the JWT has no `kid` header).
    pub fn first_verifier(&self) -> Result<JwtVerifier, String> {
        let raw = self.keys.first()
            .map(|(_, v)| v.as_slice())
            .ok_or_else(|| "JWKS is empty".to_string())?;

        JwtVerifier::from_public_key_bytes(raw)
    }

    /// Number of usable keys in the cache.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the cache contains no usable keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Decode base64url (no padding) to bytes.
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(input)
        .map_err(|e| format!("base64url decode: {e}"))
}

/// Extract the `kid` from a JWT header without verifying the token.
///
/// This is used to look up the correct JWKS key before verification.
pub fn extract_jwt_kid(token: &str) -> Result<Option<String>, String> {
    let header_b64 = token.splitn(2, '.').next()
        .ok_or_else(|| "malformed JWT: no dot".to_string())?;

    let header_bytes = base64_url_decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("JWT header JSON: {e}"))?;

    // Reject alg:none explicitly
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg.eq_ignore_ascii_case("none") {
        return Err("JWT with alg:none is rejected".into());
    }
    if alg != "ES256" {
        return Err(format!("unsupported JWT algorithm '{}', expected 'ES256'", alg));
    }

    Ok(header.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jwks_ec_p256() {
        // Minimal JWKS with one EC P-256 key
        let jwks_json = r#"{
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-key-1",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }]
        }"#;
        let cache = JwksCache::from_json(jwks_json.as_bytes()).unwrap();
        assert_eq!(cache.len(), 1);
        let _v = cache.verifier("test-key-1").unwrap();
    }

    #[test]
    fn skip_rsa_keys() {
        let jwks_json = r#"{
            "keys": [{
                "kty": "RSA",
                "kid": "rsa-key",
                "n": "...",
                "e": "AQAB"
            }]
        }"#;
        assert!(JwksCache::from_json(jwks_json.as_bytes()).is_err());
    }

    #[test]
    fn reject_alg_none() {
        assert!(extract_jwt_kid("eyJhbGciOiJub25lIn0.e30.").is_err());
    }

    #[test]
    fn extract_kid_es256() {
        use base64::Engine;
        // header: {"alg":"ES256","kid":"my-key"}
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","kid":"my-key"}"#);
        let token = format!("{}.e30.sig", header);
        let kid = extract_jwt_kid(&token).unwrap();
        assert_eq!(kid, Some("my-key".to_string()));
    }
}
