// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! WebAuthn verification: parse attestation objects, authenticator data,
//! and verify ECDSA P-256 signatures.
//!
//! Only the subset needed for FIDO2 registration and authentication is
//! implemented — no support for attestation statement verification (we
//! trust our own authenticator via AAGUID enforcement).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature;
use serde::Deserialize;

use crate::types::*;

// ---------------------------------------------------------------------------
//  Client data JSON
// ---------------------------------------------------------------------------

/// Parsed `clientDataJSON` (the browser/authenticator's signed context).
#[derive(Debug, Deserialize)]
pub struct ClientData {
    /// `"webauthn.create"` or `"webauthn.get"`.
    #[serde(rename = "type")]
    pub ceremony_type: String,
    /// base64url-encoded challenge (must match the one we issued).
    pub challenge: String,
    /// Origin that initiated the ceremony.
    pub origin: String,
}

/// Parse and validate `clientDataJSON`.
///
/// Returns the parsed structure and the raw JSON bytes (needed for
/// signature verification — the signature is over `SHA-256(clientDataJSON)`).
pub fn parse_client_data(
    client_data_json_b64: &str,
    expected_type: &str,
    expected_challenge_b64: &str,
) -> Result<(ClientData, Vec<u8>), String> {
    let raw = URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .map_err(|e| format!("clientDataJSON base64: {e}"))?;

    let cd: ClientData = serde_json::from_slice(&raw)
        .map_err(|e| format!("clientDataJSON parse: {e}"))?;

    if cd.ceremony_type != expected_type {
        return Err(format!(
            "clientDataJSON type mismatch: expected {expected_type}, got {}",
            cd.ceremony_type
        ));
    }

    if cd.challenge != expected_challenge_b64 {
        return Err("clientDataJSON challenge mismatch".into());
    }

    Ok((cd, raw))
}

// ---------------------------------------------------------------------------
//  Authenticator data
// ---------------------------------------------------------------------------

/// Parsed authenticator data (variable-length binary format).
///
/// See <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data>
#[derive(Debug)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID (32 bytes).
    pub rp_id_hash: [u8; 32],
    /// Flags byte.
    pub flags: u8,
    /// Signature counter (big-endian u32).
    pub sign_count: u32,
    /// Attested credential data (present only in registration).
    pub attested_credential: Option<AttestedCredential>,
}

/// Attested credential data inside authenticator data.
#[derive(Debug)]
pub struct AttestedCredential {
    /// Authenticator AAGUID (16 bytes).
    pub aaguid: [u8; 16],
    /// Credential ID (variable length).
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key (raw CBOR bytes).
    pub credential_public_key_cbor: Vec<u8>,
}

impl AuthenticatorData {
    /// User Present flag (bit 0).
    pub fn user_present(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// User Verified flag (bit 2).
    pub fn user_verified(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// Attested Credential Data included (bit 6).
    pub fn has_attested_credential(&self) -> bool {
        self.flags & 0x40 != 0
    }
}

/// Parse raw authenticator data bytes.
///
/// Layout (registration):
/// ```text
/// [0..32]   rpIdHash     (32 bytes, SHA-256 of RP ID)
/// [32]      flags        (1 byte)
/// [33..37]  signCount    (4 bytes, big-endian)
/// [37..53]  aaguid       (16 bytes)  — if AT flag set
/// [53..55]  credIdLen    (2 bytes, big-endian)
/// [55..55+L] credId      (L bytes)
/// [55+L..]  credPubKey   (CBOR, variable length)
/// ```
pub fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData, String> {
    if data.len() < 37 {
        return Err("authenticator data too short".into());
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);

    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    let attested_credential = if flags & 0x40 != 0 {
        // Attested credential data present
        if data.len() < 55 {
            return Err("authenticator data too short for attested credential".into());
        }

        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&data[37..53]);

        let cred_id_len = u16::from_be_bytes([data[53], data[54]]) as usize;
        let cred_id_end = 55 + cred_id_len;
        if data.len() < cred_id_end {
            return Err("authenticator data truncated in credential ID".into());
        }

        let credential_id = data[55..cred_id_end].to_vec();

        // Everything after the credential ID is the CBOR-encoded public key.
        let credential_public_key_cbor = data[cred_id_end..].to_vec();

        Some(AttestedCredential {
            aaguid,
            credential_id,
            credential_public_key_cbor,
        })
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential,
    })
}

// ---------------------------------------------------------------------------
//  COSE key extraction
// ---------------------------------------------------------------------------

/// Extract a P-256 uncompressed public key (65 bytes: 0x04 || x || y)
/// from a CBOR-encoded COSE_Key.
pub fn extract_p256_public_key(cose_cbor: &[u8]) -> Result<Vec<u8>, String> {
    let value: ciborium::Value = ciborium::from_reader(cose_cbor)
        .map_err(|e| format!("COSE key CBOR parse: {e}"))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("COSE key is not a CBOR map".into()),
    };

    // Helper: find integer key in CBOR map
    let find_int = |key: i64| -> Option<&ciborium::Value> {
        map.iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i128::from(*i) as i64 == key))
            .map(|(_, v)| v)
    };

    // Verify key type = EC2 (2)
    let kty = find_int(COSE_KEY_KTY)
        .and_then(|v| match v {
            ciborium::Value::Integer(i) => Some(i128::from(*i) as i64),
            _ => None,
        })
        .ok_or("COSE key missing kty")?;
    if kty != COSE_KTY_EC2 {
        return Err(format!("unsupported COSE key type: {kty}, expected EC2 (2)"));
    }

    // Verify curve = P-256 (1)
    let crv = find_int(COSE_KEY_CRV)
        .and_then(|v| match v {
            ciborium::Value::Integer(i) => Some(i128::from(*i) as i64),
            _ => None,
        })
        .ok_or("COSE key missing crv")?;
    if crv != COSE_CRV_P256 {
        return Err(format!("unsupported curve: {crv}, expected P-256 (1)"));
    }

    // Extract x coordinate (32 bytes)
    let x = find_int(COSE_KEY_X)
        .and_then(|v| match v {
            ciborium::Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or("COSE key missing x coordinate")?;
    if x.len() != 32 {
        return Err(format!("x coordinate wrong length: {}, expected 32", x.len()));
    }

    // Extract y coordinate (32 bytes)
    let y = find_int(COSE_KEY_Y)
        .and_then(|v| match v {
            ciborium::Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or("COSE key missing y coordinate")?;
    if y.len() != 32 {
        return Err(format!("y coordinate wrong length: {}, expected 32", y.len()));
    }

    // Uncompressed point: 0x04 || x || y
    let mut pubkey = Vec::with_capacity(65);
    pubkey.push(0x04);
    pubkey.extend_from_slice(x);
    pubkey.extend_from_slice(y);

    Ok(pubkey)
}

// ---------------------------------------------------------------------------
//  Attestation object parsing
// ---------------------------------------------------------------------------

/// Parse the CBOR attestation object returned by the authenticator
/// during registration.
///
/// We extract `authData` (raw bytes) and ignore `fmt` / `attStmt`
/// because we trust our authenticator via AAGUID enforcement.
pub fn parse_attestation_object(cbor_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value: ciborium::Value = ciborium::from_reader(cbor_bytes)
        .map_err(|e| format!("attestation object CBOR: {e}"))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("attestation object is not a CBOR map".into()),
    };

    // Find "authData" key
    for (k, v) in &map {
        if let ciborium::Value::Text(key) = k {
            if key == "authData" {
                if let ciborium::Value::Bytes(auth_data) = v {
                    return Ok(auth_data.clone());
                }
                return Err("authData is not a byte string".into());
            }
        }
    }

    Err("attestation object missing authData".into())
}

// ---------------------------------------------------------------------------
//  Signature verification
// ---------------------------------------------------------------------------

/// Verify an ECDSA P-256 / SHA-256 signature.
///
/// `signed_data` is the concatenation of `authenticator_data || SHA-256(clientDataJSON)`.
/// `signature` is the DER-encoded ECDSA signature.
/// `public_key` is the uncompressed P-256 point (65 bytes).
pub fn verify_signature(
    public_key: &[u8],
    signed_data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_ASN1,
        public_key,
    );
    peer_public_key
        .verify(signed_data, sig)
        .map_err(|_| "ECDSA signature verification failed".to_string())
}

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}
