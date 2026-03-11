// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OIDC bootstrap: self-provision bearer tokens via the jwt-bearer grant.
//!
//! The current implementation targets **Zitadel** as the OIDC provider
//! (key registration via `POST /v2/users/{id}/keys`, Zitadel-specific
//! audience scopes).  The jwt-bearer token exchange itself is standard
//! RFC 7523 and would work with any compliant provider.
//!
//! Called at startup (via `--manager-token`) or at runtime (via
//! `SetAttestationServers`) for servers that have an [`OidcBootstrap`]
//! configuration.  The flow:
//!
//! 1. Generate an ECDSA P-256 keypair inside the enclave.
//! 2. Register the public key with the OIDC provider using the manager's JWT.
//! 3. Build a JWT assertion (ES256) signed with the private key.
//! 4. Exchange the assertion for an access token (jwt-bearer grant).
//! 5. Return the token + metadata so callers can cache and refresh.
//!
//! All outbound HTTPS goes through [`crate::client::https_post`] which
//! terminates TLS inside the enclave — the host never sees plaintext.

use std::string::String;
use std::vec::Vec;

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;

use enclave_os_common::protocol::OidcBootstrap;

use crate::client;
use crate::root_store;

// ---------------------------------------------------------------------------
//  Public result type
// ---------------------------------------------------------------------------

/// Successful bootstrap result.
pub struct BootstrapResult {
    /// OIDC access token for the attestation server.
    pub access_token: String,
    /// Token lifetime in seconds (from the `expires_in` field).
    pub expires_in: u64,
    /// Zitadel key ID returned by AddKey — needed for JWT `kid` on refresh.
    pub key_id: String,
    /// DER-encoded PKCS#8 RSA private key (for building refresh assertions).
    pub private_key_der: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Zitadel API response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddKeyResponse {
    #[serde(rename = "keyId")]
    key_id: Option<String>,
    /// Some Zitadel versions return the ID in a nested `key` object.
    key: Option<AddKeyResponseKey>,
}

#[derive(Deserialize)]
struct AddKeyResponseKey {
    id: Option<String>,
}

impl AddKeyResponse {
    fn key_id(&self) -> Option<&str> {
        self.key_id
            .as_deref()
            .or_else(|| self.key.as_ref().and_then(|k| k.id.as_deref()))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

// ---------------------------------------------------------------------------
//  Bootstrap entry point
// ---------------------------------------------------------------------------

/// Execute the full bootstrap flow for a single attestation server.
///
/// # Arguments
///
/// * `config` — OIDC bootstrap configuration (issuer, service account ID, …).
/// * `manager_jwt` — The raw JWT of the calling manager.  Must carry both
///   the `enclave-os-mini:manager` project role **and** the Zitadel
///   `ORG_USER_MANAGER` IAM role (which grants `user.write`).
///
/// # Errors
///
/// Returns `Err(String)` if any step fails (key generation, Zitadel API
/// call, token exchange).
pub fn bootstrap(
    config: &OidcBootstrap,
    manager_jwt: &str,
) -> Result<BootstrapResult, String> {
    // 1. Generate ECDSA P-256 keypair inside the enclave.
    let (key_pair_der, key_pair) = generate_ecdsa_keypair()?;

    // 2. Register the public key with Zitadel.
    let key_id = register_public_key(config, manager_jwt, &key_pair)?;

    // 3. Build a signed JWT assertion and exchange it for a token.
    let (access_token, expires_in) =
        exchange_jwt_bearer(config, &key_id, &key_pair)?;

    Ok(BootstrapResult {
        access_token,
        expires_in,
        key_id,
        private_key_der: key_pair_der,
    })
}

/// Refresh an existing bootstrap: build a new JWT assertion with a
/// previously generated key and exchange it for a fresh token.
///
/// This is the "lazy refresh" path — called when `token_for()` detects
/// that the token has reached 75% of its lifetime.
pub fn refresh(
    config: &OidcBootstrap,
    key_id: &str,
    private_key_der: &[u8],
) -> Result<(String, u64), String> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        private_key_der,
        &SystemRandom::new(),
    )
    .map_err(|e| format!("failed to reload ECDSA key: {e}"))?;
    exchange_jwt_bearer(config, key_id, &key_pair)
}

// ---------------------------------------------------------------------------
//  Step 1 — ECDSA P-256 key generation
// ---------------------------------------------------------------------------

fn generate_ecdsa_keypair() -> Result<(Vec<u8>, EcdsaKeyPair), String> {
    let rng = SystemRandom::new();
    let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .map_err(|e| format!("ECDSA keygen failed: {e}"))?;
    let der = pkcs8_doc.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &rng,
    )
    .map_err(|e| format!("failed to parse generated ECDSA key: {e}"))?;
    Ok((der, key_pair))
}

// ---------------------------------------------------------------------------
//  Step 2 — Register public key with Zitadel
// ---------------------------------------------------------------------------

fn register_public_key(
    config: &OidcBootstrap,
    manager_jwt: &str,
    key_pair: &EcdsaKeyPair,
) -> Result<String, String> {
    let store = root_store().ok_or_else(|| {
        "OIDC bootstrap requires the egress CA bundle \
         (EgressModule must be initialised first)"
            .to_string()
    })?;

    // ring returns the raw uncompressed EC point (65 bytes: 04 || X || Y).
    // Zitadel expects a SubjectPublicKeyInfo (SPKI) in PEM format, so we
    // need to wrap the raw point in the fixed ASN.1 SPKI header for P-256.
    let raw_point = key_pair.public_key().as_ref();
    let mut spki_der = Vec::with_capacity(ECDSA_P256_SPKI_HEADER.len() + raw_point.len());
    spki_der.extend_from_slice(&ECDSA_P256_SPKI_HEADER);
    spki_der.extend_from_slice(raw_point);

    // Zitadel expects the publicKey field to be base64(PEM).
    // 1. PEM-encode the SPKI DER bytes.
    let spki_b64 = base64_encode(&spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for (i, ch) in spki_b64.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            pem.push('\n');
        }
        pem.push(ch);
    }
    pem.push_str("\n-----END PUBLIC KEY-----\n");
    // 2. Base64-encode the PEM string itself.
    let pub_key_b64 = base64_encode(pem.as_bytes());

    let url = format!(
        "{}/v2/users/{}/keys",
        config.issuer.trim_end_matches('/'),
        config.service_account_id
    );

    let body = format!(
        r#"{{"type":"KEY_TYPE_JSON","publicKey":"{}","expirationDate":"{}"}}"#,
        pub_key_b64,
        expiration_date_12_months(),
    );

    let auth_header = format!("Bearer {}", manager_jwt);

    let response_bytes = client::https_post(
        &url,
        body.as_bytes(),
        "application/json",
        store,
        None, // Standard HTTPS, not RA-TLS
        Some(&auth_header),
    )
    .map_err(|code| {
        format!("Zitadel AddKey request failed (error code {code})")
    })?;

    let resp: AddKeyResponse =
        serde_json::from_slice(&response_bytes).map_err(|e| {
            let body_str = String::from_utf8_lossy(&response_bytes);
            format!("invalid JSON from Zitadel AddKey: {e} — body: {body_str}")
        })?;

    resp.key_id()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            let body_str = String::from_utf8_lossy(&response_bytes);
            format!("Zitadel AddKey returned no keyId — body: {body_str}")
        })
}

// ---------------------------------------------------------------------------
//  Step 3 — JWT assertion + token exchange
// ---------------------------------------------------------------------------

fn exchange_jwt_bearer(
    config: &OidcBootstrap,
    key_id: &str,
    key_pair: &EcdsaKeyPair,
) -> Result<(String, u64), String> {
    let store = root_store().ok_or_else(|| {
        "OIDC bootstrap token exchange requires the egress CA bundle".to_string()
    })?;

    // Build the JWT assertion: { "iss": userId, "sub": userId, "aud": issuer, "kid": keyId }
    let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
    let exp = now + 3600; // assertion valid for 1 hour

    let header = format!(
        r#"{{"alg":"ES256","kid":"{}"}}"#,
        key_id,
    );
    let payload = format!(
        r#"{{"iss":"{}","sub":"{}","aud":"{}","iat":{},"exp":{}}}"#,
        config.service_account_id,
        config.service_account_id,
        config.issuer.trim_end_matches('/'),
        now,
        exp,
    );

    let header_b64 = base64url_encode(header.as_bytes());
    let payload_b64 = base64url_encode(payload.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign with ES256 (ECDSA P-256 SHA-256)
    let rng = SystemRandom::new();
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|e| format!("JWT signing failed: {e}"))?;

    let sig_b64 = base64url_encode(sig.as_ref());
    let assertion = format!("{}.{}", signing_input, sig_b64);

    // Token exchange via jwt-bearer grant
    let token_url = format!(
        "{}/oauth/v2/token",
        config.issuer.trim_end_matches('/')
    );

    // Build scopes: always request 'openid' and project roles.
    // If a project_id is specified, request its audience too.
    let mut scopes = String::from("openid urn:zitadel:iam:org:projects:roles");
    if let Some(ref pid) = config.project_id {
        scopes.push_str(&format!(
            " urn:zitadel:iam:org:project:id:{}:aud",
            pid
        ));
    }

    let form_body = format!(
        "grant_type={}&scope={}&assertion={}",
        url_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        url_encode(&scopes),
        url_encode(&assertion),
    );

    let response_bytes = client::https_post(
        &token_url,
        form_body.as_bytes(),
        "application/x-www-form-urlencoded",
        store,
        None,
        None, // No auth header — the assertion carries the identity
    )
    .map_err(|code| {
        format!("Zitadel token exchange failed (error code {code})")
    })?;

    let token_resp: TokenResponse =
        serde_json::from_slice(&response_bytes).map_err(|e| {
            let body_str = String::from_utf8_lossy(&response_bytes);
            format!("invalid JSON from Zitadel token endpoint: {e} — body: {body_str}")
        })?;

    Ok((token_resp.access_token, token_resp.expires_in))
}

// ---------------------------------------------------------------------------
//  Encoding helpers
// ---------------------------------------------------------------------------

/// Base64 standard encoding (with padding).
fn base64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data)
}

/// Base64url encoding without padding (RFC 7515 §2).
fn base64url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Minimal percent-encoding for `application/x-www-form-urlencoded` values.
fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";

/// Fixed ASN.1 SubjectPublicKeyInfo header for ECDSA P-256.
///
/// The raw EC public key from `ring` is a 65-byte uncompressed point
/// (0x04 || X || Y).  PKIX/SPKI wraps it in:
///
/// ```text
/// SEQUENCE {              -- 30 59 (89 bytes total)
///   SEQUENCE {            -- 30 13 (19 bytes) AlgorithmIdentifier
///     OID ecPublicKey     -- 06 07 2a8648ce3d0201
///     OID prime256v1      -- 06 08 2a8648ce3d030107
///   }
///   BIT STRING (66 B)    -- 03 42 00 <65 bytes>
/// }
/// ```
const ECDSA_P256_SPKI_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Return an ISO-8601 date ~12 months from now for the Zitadel key expiration.
///
/// Uses the enclave's trusted time (via OCall). We add ~365 days.
fn expiration_date_12_months() -> String {
    let now_secs = enclave_os_common::ocall::get_current_time().unwrap_or(0);
    let future = now_secs + 365 * 24 * 3600;
    // Convert epoch seconds to a rough YYYY-MM-DDT00:00:00Z.
    // This doesn't need calendar precision — Zitadel accepts any future date.
    let secs_per_day: u64 = 86400;
    let days_since_epoch = future / secs_per_day;
    // Approximate: 1970-01-01 + days
    let (year, month, day) = epoch_days_to_ymd(days_since_epoch);
    format!("{:04}-{:02}-{:02}T00:00:00Z", year, month, day)
}

/// Convert days since 1970-01-01 to (year, month, day).
fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
