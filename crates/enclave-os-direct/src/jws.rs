// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Flattened JWS (RFC 7515) with ES256, as ACME requests carry them.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;

use crate::keys::AccountKey;

/// How a request names its key: the JWK (account creation) or the account
/// URL (everything after).
pub enum KeyRef<'a> {
    Jwk,
    Kid(&'a str),
}

/// Signs an ACME request body. `payload` None is a POST-as-GET (empty
/// payload).
pub fn sign(
    key: &AccountKey,
    key_ref: KeyRef<'_>,
    nonce: &str,
    url: &str,
    payload: Option<&serde_json::Value>,
) -> Vec<u8> {
    let mut protected = serde_json::json!({
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
    });
    match key_ref {
        KeyRef::Jwk => protected["jwk"] = key.jwk(),
        KeyRef::Kid(kid) => protected["kid"] = serde_json::Value::String(kid.to_string()),
    }
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string());
    let payload_b64 = match payload {
        Some(p) => URL_SAFE_NO_PAD.encode(p.to_string()),
        None => String::new(),
    };
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig: Signature = key.signing.sign(signing_input.as_bytes());
    let body = serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    });
    body.to_string().into_bytes()
}
