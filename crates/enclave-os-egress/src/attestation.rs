// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Remote attestation server verification.
//!
//! Sends raw attestation quotes to one or more attestation servers for
//! cryptographic verification (signature chain, TCB status, platform
//! identity).  Both the vault module (server-side mutual RA-TLS) and the
//! egress client (client-side RA-TLS) use this module to ensure that
//! remote quotes are genuine and not forged by a malicious host.
//!
//! The Privasys attestation server is TEE-agnostic: it supports Intel SGX,
//! Intel TDX, AMD SEV-SNP, NVIDIA Confidential Computing, and ARM CCA
//! attestation evidence.  The same `verify_quote` API works regardless of
//! the underlying hardware.
//!
//! ## Protocol
//!
//! Each attestation server exposes a JSON endpoint:
//!
//! **Request** — `POST` with `Content-Type: application/json`:
//!
//! ```json
//! { "quote": "<base64-encoded raw attestation quote>" }
//! ```
//!
//! **Response** — `200 OK` with JSON body:
//!
//! ```json
//! {
//!   "success": true,
//!   "status": "OK",
//!   "teeType": "SGX",
//!   "mrenclave": "aabbccdd...",
//!   "mrsigner": "11223344..."
//! }
//! ```
//!
//! When `success` is `false`, the `error` field contains the reason.
//!
//! ## Multi-server verification
//!
//! Callers can specify multiple attestation server URLs.  The quote is
//! sent to **every** server, and **all** must return `{ "success": true }`.
//! This supports multi-party trust: the enclave operator and the secret
//! owner can each run their own verification infrastructure.
//!
//! ## Configuration
//!
//! Attestation server URLs and bearer tokens are managed centrally by
//! the enclave core (see [`enclave_os_common::attestation_servers`]).
//! The URL list is hashed into the config Merkle tree and exposed via
//! a dedicated X.509 OID (`1.3.6.1.4.1.65230.2.7`), making the
//! configuration auditable by remote verifiers.  Other modules (e.g. the
//! vault) access the configured servers via
//! [`enclave_os_common::attestation_servers::server_urls()`].

use std::string::String;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use serde::Deserialize;

use crate::client;
use crate::root_store;

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

/// Mock attestation quote prefix (used in development / test builds).
/// Only available when the `mock` feature is enabled.
#[cfg(feature = "mock")]
const MOCK_PREFIX: &[u8] = b"MOCK_QUOTE:";

// ---------------------------------------------------------------------------
//  Response type
// ---------------------------------------------------------------------------

/// JSON response returned by an attestation verification server.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    /// Whether the quote passed full attestation verification.
    pub success: bool,

    /// Verification status string (e.g. `"OK"`, `"TCB_OUT_OF_DATE"`).
    #[serde(default)]
    pub status: String,

    /// Detected TEE type (`"SGX"`, `"TDX"`, `"SEV-SNP"`, etc.).
    #[serde(default, rename = "teeType")]
    pub tee_type: String,

    /// Hex-encoded MRENCLAVE (SGX) extracted by the server.
    #[serde(default)]
    pub mrenclave: String,

    /// Hex-encoded MRSIGNER (SGX) extracted by the server.
    #[serde(default)]
    pub mrsigner: String,

    /// Error description when `success` is `false`.
    #[serde(default)]
    pub error: String,
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Verify a raw attestation quote against one or more attestation servers.
///
/// The quote is base64-encoded and POSTed as JSON to each server URL.
/// **All** servers must return `success: true` for verification to pass.
///
/// The attestation server is TEE-agnostic — it auto-detects the quote
/// format (SGX, TDX, SEV-SNP, etc.) and performs the appropriate
/// cryptographic verification (signature chain, TCB status, platform
/// identity).
///
/// # Returns
///
/// * `Ok(())` when:
///   - `attestation_servers` is empty (verification skipped), or
///   - `evidence` starts with `MOCK_QUOTE:` (only with `mock` feature), or
///   - every server confirmed the quote.
///
/// * `Err(String)` when:
///   - the egress root CA store is not initialised,
///   - any attestation server is unreachable, or
///   - any server returns `success: false`.
///
/// # Example
///
/// ```rust,ignore
/// use enclave_os_egress::attestation;
///
/// // Use the globally configured attestation servers
/// let servers = enclave_os_common::attestation_servers::server_urls();
/// attestation::verify_quote(&raw_quote_bytes, &servers)?;
/// ```
pub fn verify_quote(
    evidence: &[u8],
    attestation_servers: &[String],
) -> Result<(), String> {
    // Nothing to verify when no servers are configured.
    if attestation_servers.is_empty() {
        return Ok(());
    }

    // Mock quotes are used in dev/test — skip verification.
    #[cfg(feature = "mock")]
    if evidence.starts_with(MOCK_PREFIX) {
        return Ok(());
    }

    let store = root_store().ok_or_else(|| {
        "attestation verification requires the egress CA bundle \
         (EgressModule must be initialised before vault verification)"
            .to_string()
    })?;

    // Base64-encode the raw quote for the JSON request body.
    let quote_b64 = STANDARD.encode(evidence);
    let body = format!(r#"{{"quote":"{}"}}"#, quote_b64);

    for server_url in attestation_servers {
        // Check if the OIDC-bootstrapped token needs lazy refresh.
        if let Some((config, key_id, private_key_der)) =
            enclave_os_common::attestation_servers::needs_oidc_refresh(server_url)
        {
            match crate::oidc_bootstrap::refresh(&config, &key_id, &private_key_der) {
                Ok((new_token, expires_in)) => {
                    enclave_os_common::attestation_servers::update_oidc_token(
                        server_url,
                        new_token,
                        expires_in,
                    );
                }
                Err(e) => {
                    // Log but don't fail — the existing token may still work.
                    enclave_os_common::ocall::log(
                        4,
                        &format!("OIDC token refresh failed for {}: {}", server_url, e),
                    );
                }
            }
        }

        // Look up an optional bearer token from core attestation server config.
        let token = enclave_os_common::attestation_servers::token_for(server_url);
        let auth_header = token.as_deref().map(|t| {
            // Allocate the full header value; the client sends it verbatim.
            format!("Bearer {}", t)
        });

        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        if let Some(auth) = auth_header.as_deref() {
            headers.push(("Authorization".to_string(), auth.to_string()));
        }

        let resp = client::https_fetch(
            "POST",
            server_url,
            &headers,
            Some(body.as_bytes()),
            store,
            None, // Standard HTTPS — the attestation server is not behind RA-TLS.
        )
        .map_err(|e| {
            format!(
                "attestation server request to {} failed: {}",
                server_url, e
            )
        })?;

        let result: VerifyResponse =
            serde_json::from_slice(&resp.body).map_err(|e| {
                format!(
                    "invalid JSON response from attestation server {}: {}",
                    server_url, e
                )
            })?;

        if !result.success {
            return Err(format!(
                "attestation verification failed at {}: {} — {}",
                server_url, result.status, result.error
            ));
        }
    }

    Ok(())
}
