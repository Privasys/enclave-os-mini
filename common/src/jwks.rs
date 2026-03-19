// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! JWKS (JSON Web Key Set) parsing and key cache for JWT signature verification.
//!
//! Parses JWKS JSON responses from OIDC providers and extracts public keys
//! for ES256 (EC P-256) and RS256 (RSA) signature verification.
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

/// Key type stored in the cache.
enum KeyType {
    /// EC P-256 uncompressed point (65 bytes: 04 || x || y)
    EcP256(Vec<u8>),
    /// RSA public key in PKCS#1 DER encoding
    Rsa(Vec<u8>),
}

/// A cached set of JWKS keys, indexed by `kid`.
pub struct JwksCache {
    /// (kid, key_material) pairs.
    keys: Vec<(String, KeyType)>,
}

impl JwksCache {
    /// Parse a JWKS JSON response and extract EC P-256 and RSA public keys.
    ///
    /// Keys with unsupported types or curves are silently skipped.
    pub fn from_json(json_bytes: &[u8]) -> Result<Self, String> {
        let jwks: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|e| format!("JWKS JSON parse failed: {e}"))?;

        let keys_arr = jwks.get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "JWKS missing 'keys' array".to_string())?;

        let mut keys = Vec::new();

        for key in keys_arr {
            let kty = key.get("kty").and_then(|v| v.as_str()).unwrap_or("");

            // kid is required for lookup
            let kid = match key.get("kid").and_then(|v| v.as_str()) {
                Some(k) => k.to_string(),
                None => continue,
            };

            match kty {
                "EC" => {
                    // Only accept P-256 curve
                    let crv = key.get("crv").and_then(|v| v.as_str()).unwrap_or("");
                    if crv != "P-256" {
                        continue;
                    }

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

                    keys.push((kid, KeyType::EcP256(uncompressed)));
                }
                "RSA" => {
                    let n_b64 = match key.get("n").and_then(|v| v.as_str()) {
                        Some(v) => v,
                        None => continue,
                    };
                    let e_b64 = match key.get("e").and_then(|v| v.as_str()) {
                        Some(v) => v,
                        None => continue,
                    };

                    let n = match base64_url_decode(n_b64) {
                        Ok(v) if v.len() >= 128 => v, // at least 1024-bit modulus
                        _ => continue,
                    };
                    let e = match base64_url_decode(e_b64) {
                        Ok(v) if !v.is_empty() => v,
                        _ => continue,
                    };

                    // Encode as DER RSAPublicKey (PKCS#1)
                    let der = encode_rsa_public_key_der(&n, &e);
                    keys.push((kid, KeyType::Rsa(der)));
                }
                _ => continue,
            }
        }

        if keys.is_empty() {
            return Err("JWKS contains no usable keys".into());
        }

        Ok(Self { keys })
    }

    /// Look up a [`JwtVerifier`] by `kid`.
    ///
    /// Returns `Err` if the `kid` is not found or the key is invalid.
    pub fn verifier(&self, kid: &str) -> Result<JwtVerifier, String> {
        let key = self.keys.iter()
            .find(|(k, _)| k == kid)
            .map(|(_, v)| v)
            .ok_or_else(|| format!("JWKS key '{}' not found", kid))?;

        key_to_verifier(key)
    }

    /// Return a verifier for the first key, when there is only one key
    /// in the JWKS (or when the JWT has no `kid` header).
    pub fn first_verifier(&self) -> Result<JwtVerifier, String> {
        let key = self.keys.first()
            .map(|(_, v)| v)
            .ok_or_else(|| "JWKS is empty".to_string())?;

        key_to_verifier(key)
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

/// Construct a [`JwtVerifier`] from a [`KeyType`].
fn key_to_verifier(key: &KeyType) -> Result<JwtVerifier, String> {
    match key {
        KeyType::EcP256(raw) => JwtVerifier::from_public_key_bytes(raw),
        KeyType::Rsa(der) => JwtVerifier::from_rsa_der(der),
    }
}

/// Encode an RSA public key (n, e) as a DER-encoded RSAPublicKey (PKCS#1).
///
/// This is the minimal ASN.1 structure that ring expects:
/// ```text
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,
///     publicExponent    INTEGER
/// }
/// ```
fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let n_der = encode_der_integer(n);
    let e_der = encode_der_integer(e);
    let content_len = n_der.len() + e_der.len();
    let mut out = Vec::with_capacity(4 + content_len);
    out.push(0x30); // SEQUENCE tag
    encode_der_length(&mut out, content_len);
    out.extend_from_slice(&n_der);
    out.extend_from_slice(&e_der);
    out
}

/// Encode a byte slice as a DER INTEGER.
fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros (DER requires minimal encoding)
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &[0u8], // all zeros → encode as 0
    };
    // Prepend 0x00 if the high bit is set (positive integer)
    let needs_pad = !stripped.is_empty() && (stripped[0] & 0x80) != 0;
    let len = stripped.len() + if needs_pad { 1 } else { 0 };
    let mut out = Vec::with_capacity(2 + len + 2); // tag + max-length + data
    out.push(0x02); // INTEGER tag
    encode_der_length(&mut out, len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(stripped);
    out
}

/// Encode a DER length field (supports lengths up to 4 bytes).
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Extract the `kid` from a JWT header without verifying the token.
///
/// This is used to look up the correct JWKS key before verification.
/// Accepts both `ES256` and `RS256` algorithms. Rejects `alg:none`.
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
    if alg != "ES256" && alg != "RS256" {
        return Err(format!("unsupported JWT algorithm '{}', expected 'ES256' or 'RS256'", alg));
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
    fn parse_jwks_rsa() {
        // Minimal JWKS with one RSA key (modulus and exponent from a real JWKS)
        let jwks_json = r#"{
            "keys": [{
                "kty": "RSA",
                "kid": "rsa-key-1",
                "alg": "RS256",
                "n": "u_V8MVfOX1qFZCGPtV29hJPgTuLHgRr02eDVkKi0M55VsJQEB2SLDTfh0W64lbFvtcVRQikecJBrTtNrKZpiGQaInenVgWyngcvCRnDZl01ZPkq429MYLJ-uWe-MQfFBOQMNHoX7VCmqmgKa3SZ2XPppryQ8H8Wmt9C--10rhS9azW7aXWF8YNZ0lyt89B6UQxlzrK7GAlWE4eGZM7KEZZrnIgusIq2CuOZTOtPMqAFw8LRICSLGSYeCz-taBdXPfSfFrs9kSEPDXfR3KHzy6eu0yiJcPC9H8gGRnlwRjleAxv9ay2kBQCGmdRgPUcZU877jVzP2guiu1Uv1E2MPSQ",
                "e": "AQAB"
            }]
        }"#;
        let cache = JwksCache::from_json(jwks_json.as_bytes()).unwrap();
        assert_eq!(cache.len(), 1);
        let _v = cache.verifier("rsa-key-1").unwrap();
    }

    #[test]
    fn skip_unsupported_keys() {
        let jwks_json = r#"{
            "keys": [{
                "kty": "OKP",
                "kid": "ed25519-key",
                "crv": "Ed25519",
                "x": "... "
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

    #[test]
    fn extract_kid_rs256() {
        use base64::Engine;
        // header: {"alg":"RS256","kid":"rsa-key"}
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","kid":"rsa-key"}"#);
        let token = format!("{}.e30.sig", header);
        let kid = extract_jwt_kid(&token).unwrap();
        assert_eq!(kid, Some("rsa-key".to_string()));
    }
}
