// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Compact JWT (JWS) implementation — ECDSA P-256 (ES256) only.
//!
//! This module provides:
//! - [`JwtVerifier`]: verify and decode JWTs signed with ES256
//! - [`encode_jwt`]: create signed JWTs (useful for tests / admin tooling)
//!
//! The implementation is intentionally minimal — no `alg` negotiation, no
//! optional claims processing.  The caller provides a trusted public key
//! and gets back the verified payload bytes.
//!
//! ## Wire format
//!
//! ```text
//! BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
//! ```
//!
//! - Header **must** be `{"alg":"ES256","typ":"JWT"}` (or without `typ`).
//! - Signature is the raw IEEE P1363 encoding (64 bytes for P-256).
//!
//! ## Example
//!
//! ```rust,ignore
//! use enclave_os_common::jwt::JwtVerifier;
//!
//! let verifier = JwtVerifier::from_pkcs8_public_key(public_key_der)?;
//! let claims: MyClaims = verifier.verify_and_decode(&jwt_bytes)?;
//! ```

#[cfg(feature = "sgx")]
use alloc::{string::String, vec::Vec, format};
#[cfg(not(feature = "sgx"))]
use std::{string::String, vec::Vec, format};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

/// Expected `alg` value in the JWT header.
const EXPECTED_ALG: &str = "ES256";

// ---------------------------------------------------------------------------
//  JWT header
// ---------------------------------------------------------------------------

/// Minimal JWT header — only `alg` is required.
#[derive(serde::Deserialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    // `typ`, `kid`, etc. are ignored.
}

// ---------------------------------------------------------------------------
//  JwtVerifier
// ---------------------------------------------------------------------------

/// Verifies compact JWTs signed with ECDSA P-256 (ES256).
///
/// Create one per trusted public key and reuse it — the key is parsed once
/// at construction time.
pub struct JwtVerifier {
    /// ring public key handle (P-256, fixed-length IEEE P1363 signature).
    public_key: UnparsedPublicKey<Vec<u8>>,
}

impl JwtVerifier {
    /// Construct a verifier from a raw ECDSA P-256 public key in
    /// **uncompressed point** format (65 bytes: `04 || x || y`).
    pub fn from_public_key_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != 65 || raw[0] != 0x04 {
            return Err("expected 65-byte uncompressed P-256 point (04 || x || y)".into());
        }
        Ok(Self {
            public_key: UnparsedPublicKey::new(
                &ECDSA_P256_SHA256_FIXED,
                raw.to_vec(),
            ),
        })
    }

    /// Construct a verifier from a hex-encoded uncompressed public key.
    ///
    /// This is the format stored in `EnclaveConfig.extra["vault_jwt_pubkey_hex"]`.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex_decode(hex).ok_or("invalid hex in public key")?;
        Self::from_public_key_bytes(&bytes)
    }

    /// Verify the JWT signature and decode the payload into `T`.
    ///
    /// Returns an error if:
    /// - The JWT is malformed (not 3 dot-separated segments)
    /// - The header `alg` is not `ES256`
    /// - The signature does not verify against the public key
    /// - The payload fails to deserialize into `T`
    pub fn verify_and_decode<T: serde::de::DeserializeOwned>(
        &self,
        jwt: &[u8],
    ) -> Result<T, String> {
        let (payload_bytes, _header_raw) = self.verify(jwt)?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("jwt payload json: {e}"))
    }

    /// Verify the JWT and return the raw payload bytes (without deserializing).
    ///
    /// Also returns the raw header bytes for callers that need to inspect `kid`
    /// or other header fields.
    pub fn verify(&self, jwt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let jwt_str = core::str::from_utf8(jwt)
            .map_err(|e| format!("jwt not utf8: {e}"))?;

        // Split into exactly 3 segments
        let mut parts = jwt_str.splitn(3, '.');
        let header_b64 = parts.next().ok_or("missing header")?;
        let payload_b64 = parts.next().ok_or("missing payload")?;
        let sig_b64 = parts.next().ok_or("missing signature")?;

        // --- Decode & validate header ---
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| format!("jwt header base64: {e}"))?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| format!("jwt header json: {e}"))?;

        if header.alg != EXPECTED_ALG {
            return Err(format!(
                "unsupported alg '{}', expected '{EXPECTED_ALG}'",
                header.alg
            ));
        }

        // --- Decode signature ---
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| format!("jwt signature base64: {e}"))?;

        // --- Verify: message = "header_b64.payload_b64" (ASCII bytes) ---
        let signed_data = &jwt_str[..header_b64.len() + 1 + payload_b64.len()];

        self.public_key
            .verify(signed_data.as_bytes(), &sig_bytes)
            .map_err(|_| "jwt signature verification failed".to_string())?;

        // --- Decode payload (only after signature is verified) ---
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| format!("jwt payload base64: {e}"))?;

        Ok((payload_bytes, header_bytes))
    }
}

// ---------------------------------------------------------------------------
//  JWT encoding (for tests and tooling)
// ---------------------------------------------------------------------------

/// Create a signed ES256 JWT from a serializable payload.
///
/// The header is always `{"alg":"ES256","typ":"JWT"}`.
///
/// `key_pair` must be an ECDSA P-256 key pair in PKCS#8 format.
pub fn encode_jwt<T: serde::Serialize>(
    payload: &T,
    key_pair: &ring::signature::EcdsaKeyPair,
    rng: &dyn ring::rand::SecureRandom,
) -> Result<Vec<u8>, String> {
    let header_json = br#"{"alg":"ES256","typ":"JWT"}"#;
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| format!("payload serialisation: {e}"))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // Message to sign: "header_b64.payload_b64"
    let message = format!("{header_b64}.{payload_b64}");

    let sig = key_pair
        .sign(rng, message.as_bytes())
        .map_err(|_| "signing failed".to_string())?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Ok(format!("{message}.{sig_b64}").into_bytes())
}

// ---------------------------------------------------------------------------
//  Decode-only (skip verification) — test/debug helper
// ---------------------------------------------------------------------------

/// Decode the JWT payload **without** verifying the signature.
///
/// **WARNING**: Only use this for debugging / in contexts where the JWT
/// has already been verified or where verification is not required.
pub fn decode_payload_unverified<T: serde::de::DeserializeOwned>(
    jwt: &[u8],
) -> Result<T, String> {
    let jwt_str = core::str::from_utf8(jwt)
        .map_err(|e| format!("jwt not utf8: {e}"))?;

    let mut parts = jwt_str.splitn(3, '.');
    let _header = parts.next().ok_or("missing header")?;
    let payload_b64 = parts.next().ok_or("missing payload")?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("jwt payload base64: {e}"))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("jwt payload json: {e}"))
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Hex-decode a string into bytes. Returns `None` on invalid hex.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn generate_key_pair() -> (EcdsaKeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_key = kp.public_key().as_ref().to_vec();
        (kp, pub_key)
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestClaims {
        sub: String,
        data: u64,
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (kp, pub_bytes) = generate_key_pair();
        let rng = SystemRandom::new();

        let claims = TestClaims {
            sub: "alice".into(),
            data: 42,
        };

        let jwt = encode_jwt(&claims, &kp, &rng).unwrap();
        let verifier = JwtVerifier::from_public_key_bytes(&pub_bytes).unwrap();
        let decoded: TestClaims = verifier.verify_and_decode(&jwt).unwrap();

        assert_eq!(decoded, claims);
    }

    #[test]
    fn wrong_key_rejects() {
        let (kp, _) = generate_key_pair();
        let (_, wrong_pub) = generate_key_pair();
        let rng = SystemRandom::new();

        let claims = TestClaims {
            sub: "bob".into(),
            data: 99,
        };

        let jwt = encode_jwt(&claims, &kp, &rng).unwrap();
        let verifier = JwtVerifier::from_public_key_bytes(&wrong_pub).unwrap();
        assert!(verifier.verify_and_decode::<TestClaims>(&jwt).is_err());
    }

    #[test]
    fn tampered_payload_rejects() {
        let (kp, pub_bytes) = generate_key_pair();
        let rng = SystemRandom::new();

        let claims = TestClaims {
            sub: "eve".into(),
            data: 1,
        };

        let jwt = encode_jwt(&claims, &kp, &rng).unwrap();
        let jwt_str = String::from_utf8(jwt).unwrap();

        // Tamper with the payload segment
        let parts: Vec<&str> = jwt_str.splitn(3, '.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(
            br#"{"sub":"eve","data":999}"#,
        );
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let verifier = JwtVerifier::from_public_key_bytes(&pub_bytes).unwrap();
        assert!(verifier.verify_and_decode::<TestClaims>(tampered.as_bytes()).is_err());
    }

    #[test]
    fn bad_alg_rejects() {
        // Manually construct a JWT with alg=HS256
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        let sig = URL_SAFE_NO_PAD.encode(b"fakesig");
        let jwt = format!("{header}.{payload}.{sig}");

        let (_, pub_bytes) = generate_key_pair();
        let verifier = JwtVerifier::from_public_key_bytes(&pub_bytes).unwrap();
        let err = verifier.verify(jwt.as_bytes()).unwrap_err();
        assert!(err.contains("unsupported alg"));
    }

    #[test]
    fn malformed_jwt_rejects() {
        let (_, pub_bytes) = generate_key_pair();
        let verifier = JwtVerifier::from_public_key_bytes(&pub_bytes).unwrap();

        assert!(verifier.verify(b"no-dots").is_err());
        assert!(verifier.verify(b"one.two").is_err());
    }

    #[test]
    fn decode_unverified_works() {
        let (kp, _) = generate_key_pair();
        let rng = SystemRandom::new();

        let claims = TestClaims {
            sub: "test".into(),
            data: 7,
        };

        let jwt = encode_jwt(&claims, &kp, &rng).unwrap();
        let decoded: TestClaims = decode_payload_unverified(&jwt).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn hex_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = "deadbeef";
        let decoded = hex_decode(hex).unwrap();
        assert_eq!(decoded, original);
    }
}
