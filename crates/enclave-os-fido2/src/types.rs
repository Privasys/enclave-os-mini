// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! FIDO2/WebAuthn types: wire protocol, credential records, and WebAuthn structures.
//!
//! The FIDO2 protocol is carried inside [`Request::Data`] / [`Response::Data`]
//! — it never leaks into the shared protocol crate.
//!
//! ## Auth model
//!
//! Registration creates a hardware-bound FIDO2 credential inside the
//! Privasys Wallet authenticator (iOS Secure Enclave / Android StrongBox).
//! The enclave verifies the authenticator's AAGUID to ensure only the
//! Privasys Wallet is accepted.
//!
//! Authentication verifies an ECDSA P-256 signature over a server-issued
//! challenge.  On success, the RA-TLS session is marked as FIDO2-
//! authenticated (phone path) and an opaque session token is issued for
//! the browser's separate TLS connection.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

/// Maximum pending challenges before oldest are evicted.
pub const MAX_PENDING_CHALLENGES: usize = 1000;

/// Challenge TTL: 5 minutes in seconds.
pub const CHALLENGE_TTL_SECS: u64 = 300;

/// Default session token TTL: 1 hour in seconds.
pub const SESSION_TOKEN_TTL_SECS: u64 = 3600;

/// Maximum concurrent session tokens.
pub const MAX_SESSION_TOKENS: usize = 10_000;

/// Session token length in bytes (rendered as 64 hex chars).
pub const SESSION_TOKEN_BYTES: usize = 32;

/// Challenge length in bytes.
pub const CHALLENGE_BYTES: usize = 32;

// ---------------------------------------------------------------------------
//  FIDO2 wire protocol — request
// ---------------------------------------------------------------------------

/// FIDO2-specific request, JSON-encoded inside `Request::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Fido2Request {
    /// Begin registration: enclave generates a challenge and returns
    /// `PublicKeyCredentialCreationOptions`.
    #[serde(rename = "register_begin")]
    RegisterBegin {
        /// User-visible display name (e.g. email or username).
        user_name: String,
        /// Opaque user handle (base64url, up to 64 bytes).
        user_handle: String,
        /// Browser session ID from QR code — the token will be bound to
        /// this session so the browser can use it.
        #[serde(default)]
        browser_session_id: Option<String>,
    },

    /// Complete registration: client sends the attestation response.
    #[serde(rename = "register_complete")]
    RegisterComplete {
        /// The challenge that was issued (base64url).
        challenge: String,
        /// base64url-encoded `AttestationObject` (CBOR).
        attestation_object: String,
        /// base64url-encoded `clientDataJSON`.
        client_data_json: String,
        /// base64url-encoded credential ID.
        credential_id: String,
        /// Browser session ID — opaque session token will be bound to this.
        #[serde(default)]
        browser_session_id: Option<String>,
        /// Push notification token for future authentication requests.
        #[serde(default)]
        push_token: Option<String>,
    },

    /// Begin authentication: enclave generates a challenge and returns
    /// `PublicKeyCredentialRequestOptions`.
    #[serde(rename = "authenticate_begin")]
    AuthenticateBegin {
        /// Optional credential ID hint (base64url). If provided, the
        /// enclave includes it in `allowCredentials`.
        #[serde(default)]
        credential_id: Option<String>,
        /// Browser session ID from QR code or push payload.
        #[serde(default)]
        browser_session_id: Option<String>,
    },

    /// Complete authentication: client sends the assertion response.
    #[serde(rename = "authenticate_complete")]
    AuthenticateComplete {
        /// The challenge that was issued (base64url).
        challenge: String,
        /// base64url-encoded credential ID used.
        credential_id: String,
        /// base64url-encoded `authenticatorData`.
        authenticator_data: String,
        /// base64url-encoded signature (ECDSA P-256 / SHA-256).
        signature: String,
        /// base64url-encoded `clientDataJSON`.
        client_data_json: String,
        /// Browser session ID for token binding.
        #[serde(default)]
        browser_session_id: Option<String>,
    },
}

// ---------------------------------------------------------------------------
//  FIDO2 wire protocol — response
// ---------------------------------------------------------------------------

/// FIDO2-specific response, JSON-encoded inside `Response::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Fido2Response {
    /// Registration challenge + options.
    #[serde(rename = "register_options")]
    RegisterOptions {
        /// base64url-encoded 32-byte random challenge.
        challenge: String,
        /// Relying party info.
        rp: RelyingParty,
        /// User info (echo back).
        user: PublicKeyUser,
        /// Accepted public key algorithms.
        pub_key_cred_params: Vec<PubKeyCredParam>,
        /// Authenticator selection criteria.
        authenticator_selection: AuthenticatorSelection,
        /// Attestation conveyance preference.
        attestation: String,
    },

    /// Registration success.
    #[serde(rename = "register_ok")]
    RegisterOk {
        /// Confirmation.
        status: String,
        /// Opaque session token for the browser (hex, 64 chars).
        /// `None` if no `browser_session_id` was provided.
        #[serde(skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },

    /// Authentication challenge + options.
    #[serde(rename = "authenticate_options")]
    AuthenticateOptions {
        /// base64url-encoded 32-byte random challenge.
        challenge: String,
        /// Allowed credentials (from stored registrations).
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_credentials: Vec<AllowCredential>,
        /// User verification requirement.
        user_verification: String,
    },

    /// Authentication success.
    #[serde(rename = "authenticate_ok")]
    AuthenticateOk {
        /// Confirmation.
        status: String,
        /// Opaque session token for the browser (hex, 64 chars).
        #[serde(skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },

    /// Error.
    #[serde(rename = "error")]
    Error {
        /// Human-readable error message.
        error: String,
    },
}

// ---------------------------------------------------------------------------
//  WebAuthn sub-types (used in wire protocol)
// ---------------------------------------------------------------------------

/// Relying party identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    /// RP identifier — typically the app's SNI hostname.
    pub id: String,
    /// Human-readable RP name.
    pub name: String,
}

/// User account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyUser {
    /// Opaque user handle (base64url).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Display name (same as `name` for our purposes).
    pub display_name: String,
}

/// Public key credential algorithm parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    /// Always `"public-key"`.
    #[serde(rename = "type")]
    pub cred_type: String,
    /// COSE algorithm identifier. ES256 = -7.
    pub alg: i32,
}

/// Authenticator selection criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    /// Authenticator attachment.
    pub authenticator_attachment: String,
    /// Resident key requirement.
    pub resident_key: String,
    /// User verification requirement.
    pub user_verification: String,
}

/// Allowed credential descriptor (for authentication).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredential {
    /// Always `"public-key"`.
    #[serde(rename = "type")]
    pub cred_type: String,
    /// base64url-encoded credential ID.
    pub id: String,
}

// ---------------------------------------------------------------------------
//  Persisted credential record (sealed KV)
// ---------------------------------------------------------------------------

/// A FIDO2 credential stored in the sealed KV store.
///
/// Key: `fido2:cred:{credential_id_b64}`
/// Serialized as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Opaque user handle (base64url).
    pub user_handle: String,
    /// Display name at registration time.
    pub user_name: String,
    /// COSE-encoded public key (base64url).
    pub public_key_cose: String,
    /// Raw public key bytes for P-256: 65 bytes uncompressed (base64url).
    pub public_key_raw: String,
    /// Authenticator AAGUID (hex, 32 chars).
    pub aaguid: String,
    /// Signature counter (monotonically increasing).
    pub sign_count: u32,
    /// Unix timestamp of credential creation.
    pub created_at: u64,
    /// Relying party ID this credential is bound to.
    pub rp_id: String,
    /// Push notification token for this device.
    #[serde(default)]
    pub push_token: Option<String>,
}

// ---------------------------------------------------------------------------
//  FIDO2 session identity (TLS-native auth for phone connections)
// ---------------------------------------------------------------------------

/// Identity extracted from a successful FIDO2 ceremony.
///
/// Set on `RaTlsSession.fido2_identity` after register/authenticate
/// completes. Subsequent requests on the same TLS session are
/// authenticated without tokens.
#[derive(Debug, Clone)]
pub struct FidoIdentity {
    /// Opaque user handle.
    pub user_handle: String,
    /// Credential ID used (base64url).
    pub credential_id: String,
    /// When the FIDO2 ceremony completed (unix timestamp).
    pub authenticated_at: u64,
}

// ---------------------------------------------------------------------------
//  Session token entry (for browser connections)
// ---------------------------------------------------------------------------

/// An active session token in the in-memory token store.
#[derive(Debug, Clone)]
pub struct SessionTokenEntry {
    /// Opaque user handle.
    pub user_handle: String,
    /// Credential ID used.
    pub credential_id: String,
    /// Browser session ID this token is bound to.
    pub browser_session_id: String,
    /// Unix timestamp of expiry.
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
//  COSE constants
// ---------------------------------------------------------------------------

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
pub const COSE_ALG_ES256: i32 = -7;

/// COSE key type: EC2 (Elliptic Curve with x, y coordinates).
pub const COSE_KTY_EC2: i64 = 2;

/// COSE curve identifier: P-256.
pub const COSE_CRV_P256: i64 = 1;

/// COSE key parameter: key type (kty).
pub const COSE_KEY_KTY: i64 = 1;

/// COSE key parameter: algorithm (alg).
pub const COSE_KEY_ALG: i64 = 3;

/// COSE key parameter: curve (crv), EC2 only.
pub const COSE_KEY_CRV: i64 = -1;

/// COSE key parameter: x coordinate, EC2 only.
pub const COSE_KEY_X: i64 = -2;

/// COSE key parameter: y coordinate, EC2 only.
pub const COSE_KEY_Y: i64 = -3;
