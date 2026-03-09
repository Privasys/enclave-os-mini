// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-specific types: wire protocol, access policies, and persisted records.
//!
//! The vault protocol is carried inside [`Request::Data`] /
//! [`Response::Data`] — it never leaks into the shared protocol crate.
//!
//! ## OIDC-based auth model
//!
//! Secret ownership is tied to the OIDC `sub` claim (the caller's unique
//! identity from Zitadel or any OIDC provider).  The `"auth"` bearer token
//! in the JSON envelope is verified by the enclave's auth layer before
//! reaching the vault; the vault reads `ctx.oidc_claims.sub` for ownership.
//!
//! No more `OpenVault` / `CloseVault` — the OIDC subject *is* the vault
//! namespace.

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
///
/// All mutating operations require the caller's OIDC token (via the JSON
/// `"auth"` field) with the **secret-owner** role.  `GetSecret` supports
/// a dual-path: OIDC owner *or* RA-TLS TEE with optional bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Store a named secret with an access policy.
    ///
    /// Requires OIDC **secret-owner** role.  The caller's `sub` becomes
    /// the secret owner.
    StoreSecret {
        /// Human-readable secret name (e.g. `"customer-123-dek"`).
        name: String,
        /// Base64url-encoded secret bytes.
        secret: String,
        /// Access policy for this secret.
        policy: SecretPolicy,
    },

    /// Retrieve a named secret.
    ///
    /// **Dual-path auth:**
    /// - **OIDC owner path**: caller's `sub` matches the stored owner.
    ///   No RA-TLS required.
    /// - **RA-TLS TEE path**: mutual RA-TLS client certificate with
    ///   matching measurements + optional bearer token from the secret
    ///   manager.
    GetSecret {
        /// Secret name.
        name: String,
        /// Optional bearer token (raw bytes) for defence-in-depth when
        /// using the RA-TLS path.
        #[serde(default)]
        bearer_token: Option<Vec<u8>>,
    },

    /// Delete a named secret.
    ///
    /// Requires OIDC **secret-owner** role.  Only the original owner
    /// (matching `sub`) can delete.
    DeleteSecret {
        /// Name of the secret to delete.
        name: String,
    },

    /// Update the access policy for an existing secret.
    ///
    /// Requires OIDC **secret-owner** role.  Only the original owner
    /// (matching `sub`) can update.
    UpdateSecretPolicy {
        /// Name of the secret whose policy should be updated.
        name: String,
        /// New access policy.
        policy: SecretPolicy,
    },

    /// List all secrets owned by the caller.
    ///
    /// Requires OIDC **secret-owner** role.  Returns metadata only
    /// (name + expires_at), never the secret values.
    ListSecrets,
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
    /// List of secrets owned by the caller.
    SecretList {
        /// Metadata for each owned secret.
        secrets: Vec<SecretListEntry>,
    },
    /// Error with human-readable message.
    Error(String),
}

/// Metadata for a single secret in a list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListEntry {
    /// Secret name.
    pub name: String,
    /// Unix timestamp when this secret expires.
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
//  OID types
// ---------------------------------------------------------------------------

/// A single OID key-value requirement in a secret policy.
///
/// The key is a dotted OID string (e.g. `"1.3.6.1.4.1.65230.2.1"`)
/// and the value is the expected hex-encoded extension bytes.
///
/// When a caller requests a secret via the RA-TLS path, the vault checks
/// that every `OidRequirement` in the policy has a matching `OidClaim`
/// from the caller.
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
/// allowed to retrieve the secret via the **RA-TLS path**, and optional
/// defence-in-depth via a bearer token from the secret manager.
///
/// The OIDC owner can always retrieve their own secrets without RA-TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// SGX MRENCLAVE values (hex-encoded, 64 chars each) allowed to retrieve.
    #[serde(default)]
    pub allowed_mrenclave: Vec<String>,
    /// TDX MRTD values (hex-encoded, 96 chars each) allowed to retrieve.
    #[serde(default)]
    pub allowed_mrtd: Vec<String>,
    /// OIDC `sub` of the secret manager authorised to issue bearer tokens
    /// for this secret.
    ///
    /// If present, `GetSecret` via the RA-TLS path requires a valid bearer
    /// token whose OIDC `sub` matches this value and who has the
    /// `secret-manager` role.
    ///
    /// This provides defense-in-depth: even if remote attestation is
    /// compromised, the attacker still needs a fresh bearer token from
    /// the secret manager.
    #[serde(default)]
    pub manager_sub: Option<String>,
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
/// The KV key is `"secret:{owner_sub}:{name}"` (UTF-8 bytes).
/// The value is a JSON-serialized `SecretRecord`.
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
    /// OIDC `sub` of the secret owner.
    pub owner_sub: String,
}

// ---------------------------------------------------------------------------
//  Bearer token claims (for RA-TLS path defence-in-depth)
// ---------------------------------------------------------------------------

/// JWT payload for bearer tokens issued by the secret manager.
///
/// The secret manager signs this via their OIDC provider.  The vault
/// verifies the bearer token's `sub` against the `manager_sub` stored
/// in the secret's policy.
#[derive(Debug, Deserialize)]
pub struct BearerTokenClaims {
    /// Name of the secret this token authorises access to.
    pub name: String,
}
