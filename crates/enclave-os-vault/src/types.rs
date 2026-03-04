// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-specific types: wire protocol, access policies, persisted records,
//! and JWT claims.
//!
//! The vault protocol is carried inside [`Request::Data`] /
//! [`Response::Data`] — it never leaks into the shared protocol crate.

use std::string::String;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
//  TTL constants
// ---------------------------------------------------------------------------

/// Maximum secret TTL: 3 months (90 days) in seconds.
pub const MAX_SECRET_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Default secret TTL: 1 month (30 days) in seconds.
pub const DEFAULT_SECRET_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
//  Vault wire protocol
// ---------------------------------------------------------------------------

/// Vault-specific request, JSON-encoded inside `Request::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Store a named secret with an access policy.
    ///
    /// JWT payload (signed by secret owner):
    /// ```json
    /// {
    ///   "name": "customer-123-dek",
    ///   "secret": "<base64url-encoded secret>",
    ///   "policy": { ... }
    /// }
    /// ```
    StoreSecret { jwt: Vec<u8> },

    /// Open a top-level vault for a secret owner by registering their
    /// hex-encoded uncompressed P-256 public key.  Returns a `kid` that
    /// clients will put in the JWT header when later storing/deleting
    /// secrets.
    OpenVault { pubkey_hex: String },

    /// Retrieve a named secret.  Authorised by the caller's mutual RA-TLS
    /// client certificate (which contains the SGX/TDX quote and OID
    /// extensions) + optional bearer token.
    GetSecret {
        /// Secret name.
        name: String,
        /// Optional bearer token (raw bytes).
        #[serde(default)]
        bearer_token: Option<Vec<u8>>,
    },

    /// Delete a named secret.  Only the secret owner (JWT signer) can delete.
    ///
    /// JWT payload: `{ "name": "customer-123-dek" }`
    DeleteSecret { jwt: Vec<u8> },

    /// Update the access policy for an existing named secret.
    ///
    /// JWT payload:
    /// ```json
    /// {
    ///   "name": "customer-123-dek",
    ///   "policy": { ... }
    /// }
    /// ```
    UpdateSecretPolicy { jwt: Vec<u8> },
}

/// Vault-specific response, JSON-encoded inside `Response::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultResponse {
    /// Secret stored successfully.
    SecretStored {
        /// The secret name (echo back).
        name: String,
        /// Unix timestamp when this secret expires.
        expires_at: u64,
    },
    /// Secret retrieved successfully.
    SecretValue {
        /// The plaintext secret bytes.
        secret: Vec<u8>,
        /// Unix timestamp when this secret expires.
        expires_at: u64,
    },
    /// Secret deleted successfully.
    SecretDeleted,
    /// Secret policy updated successfully.
    PolicyUpdated,
    /// Vault opened successfully; contains the generated `kid` for the owner.
    VaultOpened { kid: String },
    /// Error with human-readable message.
    Error(String),
}

// ---------------------------------------------------------------------------
//  OID types
// ---------------------------------------------------------------------------

/// A single OID key-value requirement in a secret policy.
///
/// The key is a dotted OID string (e.g. `"1.3.6.1.4.1.65230.2.1"`)
/// and the value is the expected hex-encoded extension bytes.
///
/// When a caller requests a secret, the vault checks that every
/// `OidRequirement` in the policy has a matching `OidClaim` from the
/// caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidRequirement {
    /// Dotted OID string (e.g. `"1.3.6.1.4.1.65230.2.1"`).
    pub oid: String,
    /// Expected value (hex-encoded bytes).
    pub value: String,
}

/// An OID claim from the caller's RA-TLS certificate, sent alongside
/// attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidClaim {
    /// Dotted OID string.
    pub oid: String,
    /// Actual value (hex-encoded bytes).
    pub value: String,
}

// ---------------------------------------------------------------------------
//  Access policy
// ---------------------------------------------------------------------------

/// Access policy for a vault secret.
///
/// Defines which TEE measurements (MRENCLAVE for SGX, MRTD for TDX) are
/// allowed to retrieve the secret, whether a bearer token is required,
/// and which RA-TLS X.509 OID extensions must match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// SGX MRENCLAVE values (hex-encoded, 64 chars each) allowed to retrieve.
    #[serde(default)]
    pub allowed_mrenclave: Vec<String>,
    /// TDX MRTD values (hex-encoded, 96 chars each) allowed to retrieve.
    #[serde(default)]
    pub allowed_mrtd: Vec<String>,
    /// Hex-encoded uncompressed P-256 public key (65 bytes: `04 || x || y`)
    /// of the manager authorised to issue bearer tokens for this secret.
    ///
    /// If present, `GetSecret` requires a valid ES256 JWT signed by this
    /// key.  The JWT payload must contain `{ "name": "<secret-name>" }`.
    ///
    /// This provides defense-in-depth: even if remote attestation is
    /// compromised, the attacker still needs a fresh bearer token from the
    /// manager.
    #[serde(default)]
    pub manager_pubkey: Option<String>,
    /// Required X.509 OID extensions from the caller's RA-TLS certificate.
    /// Each entry must have a matching claim from the caller.  Empty means
    /// no OID checks.
    #[serde(default)]
    pub required_oids: Vec<OidRequirement>,
    /// Time-to-live in seconds from creation.  Capped at [`MAX_SECRET_TTL_SECONDS`]
    /// (3 months).  If omitted or zero, defaults to [`DEFAULT_SECRET_TTL_SECONDS`]
    /// (30 days).
    #[serde(default)]
    pub ttl_seconds: u64,
}

// ---------------------------------------------------------------------------
//  Persisted secret record
// ---------------------------------------------------------------------------

/// A named secret with its metadata, stored in the sealed KV store.
///
/// The KV key is the secret name (UTF-8 bytes).  The value is a
/// JSON-serialized `SecretRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    /// The plaintext secret bytes (encrypted at rest by the KV store layer).
    pub secret: Vec<u8>,
    /// Access policy.
    pub policy: SecretPolicy,
    /// Unix timestamp (seconds) when the secret was stored.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the secret expires.
    pub expires_at: u64,
    /// SHA-256 hash (hex) of the secret owner's public key.
    /// Used to verify that only the original owner can delete/update.
    pub owner_pubkey_hash: String,
}

// ---------------------------------------------------------------------------
//  JWT claim types
// ---------------------------------------------------------------------------

/// JWT payload for `StoreSecret`.
#[derive(Debug, Deserialize)]
pub struct StoreSecretClaims {
    /// Human-readable secret name (e.g. `"customer-123-dek"`).
    pub name: String,
    /// Base64url-encoded secret bytes.
    pub secret: String,
    /// Access policy for this secret.
    pub policy: SecretPolicy,
}

/// JWT payload for `DeleteSecret`.
#[derive(Debug, Deserialize)]
pub struct DeleteSecretClaims {
    /// Name of the secret to delete.
    pub name: String,
}

/// JWT payload for `UpdateSecretPolicy`.
#[derive(Debug, Deserialize)]
pub struct UpdateSecretPolicyClaims {
    /// Name of the secret whose policy should be updated.
    pub name: String,
    /// New access policy.
    pub policy: SecretPolicy,
}

/// JWT payload for bearer tokens issued by the manager.
///
/// The manager signs this with their ES256 private key.  The vault
/// verifies the signature against the `manager_pubkey` stored in the
/// secret's policy, then checks the `name` matches the requested secret.
#[derive(Debug, Deserialize)]
pub struct BearerTokenClaims {
    /// Name of the secret this token authorises access to.
    pub name: String,
}
