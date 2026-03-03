// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os — policy-gated secret store inside SGX.
//!
//! Secrets are stored in the sealed KV store (AES-256-GCM encrypted,
//! MRENCLAVE-bound).  Each secret has a named key, an access policy
//! (MRENCLAVE/MRTD whitelist + optional bearer token + optional OID
//! verification), and a TTL (max 3 months).
//!
//! The vault protocol is carried inside [`Request::Data`] /
//! [`Response::Data`] — it never pollutes the shared protocol crate.
//! See [`VaultRequest`] and [`VaultResponse`] for the inner envelope.
//!
//! ## Protocol
//!
//! | VaultRequest | Auth | VaultResponse |
//! |--------------|------|---------------|
//! | `StoreSecret { jwt }` | JWT (ES256) | `SecretStored { name, expires_at }` |
//! | `GetSecret { name, attestation_evidence, .. }` | Quote + token + OIDs | `SecretValue { secret, expires_at }` |
//! | `DeleteSecret { jwt }` | JWT (owner) | `SecretDeleted` |
//! | `UpdateSecretPolicy { jwt }` | JWT (owner) | `PolicyUpdated` |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use enclave_os_vault::VaultModule;
//! use enclave_os_enclave::ecall::{init_enclave, finalize_and_run};
//! use enclave_os_enclave::modules::register_module;
//!
//! let (config, sealed_cfg) = init_enclave(config_json, config_len)?;
//!
//! // KvStoreModule must be registered first (vault depends on it).
//! let kvstore = enclave_os_kvstore::KvStoreModule::new(sealed_cfg.master_key())?;
//! register_module(Box::new(kvstore));
//!
//! let pubkey_hex = config.extra["vault_jwt_pubkey_hex"].as_str().unwrap();
//! let vault = VaultModule::new(pubkey_hex)?;
//! register_module(Box::new(vault));
//!
//! finalize_and_run(&config, &sealed_cfg);
//! ```

pub mod quote;
pub mod types;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest;

use enclave_os_common::jwt::JwtVerifier;
use enclave_os_common::protocol::{Request, Response};
use enclave_os_enclave::modules::{EnclaveModule, RequestContext};

use crate::quote::{hex_encode, extract_report_data, is_permitted, parse_quote};
use enclave_os_common::quote::compute_report_data_hash;
use crate::types::{
    BearerTokenClaims, DeleteSecretClaims, OidClaim, SecretRecord, StoreSecretClaims,
    UpdateSecretPolicyClaims, VaultRequest, VaultResponse,
    DEFAULT_SECRET_TTL_SECONDS, MAX_SECRET_TTL_SECONDS,
};

// ---------------------------------------------------------------------------
//  VaultModule
// ---------------------------------------------------------------------------

/// Enclave module that handles named secret storage with policy-gated access.
///
/// Secrets are persisted in the sealed KV store (via `enclave-os-kvstore`).
/// The KV key is the secret name (UTF-8 bytes).
///
/// Storing, deleting, and updating secrets requires a JWT signed by the
/// secret owner's ECDSA P-256 key.  Retrieving secrets requires a valid
/// SGX/TDX attestation quote matching the secret's policy whitelist, plus
/// an optional bearer token and optional OID claims.
pub struct VaultModule {
    verifier: JwtVerifier,
    /// SHA-256 hash (hex) of the owner's raw public key bytes.
    owner_pubkey_hash: String,
}

impl VaultModule {
    /// Construct the vault module.
    ///
    /// `pubkey_hex` is the hex-encoded uncompressed P-256 public key
    /// (65 bytes: `04 || x || y`) of the authorised secret owner.
    pub fn new(pubkey_hex: &str) -> Result<Self, String> {
        let raw = crate::quote::hex_decode(pubkey_hex)?;
        let hash = digest::digest(&digest::SHA256, &raw);
        let owner_pubkey_hash = hex_encode(hash.as_ref());
        let verifier = JwtVerifier::from_public_key_bytes(&raw)?;
        Ok(Self {
            verifier,
            owner_pubkey_hash,
        })
    }

    /// Construct from raw public key bytes (65-byte uncompressed).
    pub fn from_public_key_bytes(raw: &[u8]) -> Result<Self, String> {
        let hash = digest::digest(&digest::SHA256, raw);
        let owner_pubkey_hash = hex_encode(hash.as_ref());
        let verifier = JwtVerifier::from_public_key_bytes(raw)?;
        Ok(Self {
            verifier,
            owner_pubkey_hash,
        })
    }
}

impl EnclaveModule for VaultModule {
    fn name(&self) -> &str {
        "vault"
    }

    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };

        // Try to parse as VaultRequest — if it doesn't parse, this Data
        // isn't for us; let another module try.
        let vault_req: VaultRequest = match serde_json::from_slice(data) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let vault_resp = match vault_req {
            VaultRequest::StoreSecret { jwt } => self.handle_store(&jwt),
            VaultRequest::GetSecret {
                name,
                bearer_token,
            } => self.handle_get(&name, bearer_token.as_deref(), ctx),
            VaultRequest::DeleteSecret { jwt } => self.handle_delete(&jwt),
            VaultRequest::UpdateSecretPolicy { jwt } => self.handle_update_policy(&jwt),
        };

        // Wrap VaultResponse inside Response::Data
        match serde_json::to_vec(&vault_resp) {
            Ok(bytes) => Some(Response::Data(bytes)),
            Err(e) => Some(Response::Error(
                format!("vault: serialise response: {e}").into_bytes(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
//  Request handlers
// ---------------------------------------------------------------------------

impl VaultModule {
    /// Store a named secret with an access policy.
    fn handle_store(&self, jwt: &[u8]) -> VaultResponse {
        let claims: StoreSecretClaims = match self.verifier.verify_and_decode(jwt) {
            Ok(c) => c,
            Err(e) => return VaultResponse::Error(e),
        };

        // Decode base64url secret
        let secret_bytes = match URL_SAFE_NO_PAD.decode(&claims.secret) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("bad base64: {e}")),
        };

        if secret_bytes.is_empty() {
            return VaultResponse::Error("secret must not be empty".into());
        }

        // Normalise policy (cap TTL, lowercase hex)
        let policy = normalise_policy(claims.policy);

        // Compute expiry
        let now = current_time_secs();
        let ttl = if policy.ttl_seconds == 0 {
            DEFAULT_SECRET_TTL_SECONDS
        } else {
            policy.ttl_seconds
        };
        let expires_at = now.saturating_add(ttl);

        let record = SecretRecord {
            secret: secret_bytes,
            policy,
            created_at: now,
            expires_at,
            owner_pubkey_hash: self.owner_pubkey_hash.clone(),
        };

        let record_json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => return VaultResponse::Error(format!("serialise record: {e}")),
        };

        // Persist
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };
        match kv.lock() {
            Ok(store) => {
                if let Err(e) = store.put(claims.name.as_bytes(), &record_json) {
                    return VaultResponse::Error(format!("kv put failed: {e}"));
                }
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::SecretStored {
            name: claims.name,
            expires_at,
        }
    }

    /// Retrieve a named secret — authorised by mutual RA-TLS (peer cert) + optional bearer token.
    ///
    /// The caller's SGX/TDX quote and OID claims are extracted from their
    /// TLS client certificate (mutual RA-TLS), not from the JSON payload.
    fn handle_get(
        &self,
        name: &str,
        bearer_token: Option<&[u8]>,
        ctx: &RequestContext,
    ) -> VaultResponse {
        // ── 1. Require mutual RA-TLS peer certificate ──────────────────
        let peer_der = match ctx.peer_cert_der {
            Some(ref der) => der,
            None => {
                return VaultResponse::Error(
                    "mutual RA-TLS required: no client certificate presented".into(),
                )
            }
        };

        // ── 2. Parse the peer certificate for attestation data ──────────
        let (attestation_evidence, oid_claims) = match extract_attestation_from_cert(peer_der) {
            Ok(pair) => pair,
            Err(e) => return VaultResponse::Error(format!("peer certificate: {e}")),
        };

        // ── 3. Look up the secret record ────────────────────────────────
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        let record_bytes = match kv.lock() {
            Ok(store) => match store.get(name.as_bytes()) {
                Ok(Some(v)) => v,
                Ok(None) => return VaultResponse::Error("secret not found".into()),
                Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
            },
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };

        let record: SecretRecord = match serde_json::from_slice(&record_bytes) {
            Ok(r) => r,
            Err(e) => return VaultResponse::Error(format!("corrupt record: {e}")),
        };

        // ── 4. Check expiry ─────────────────────────────────────────────
        let now = current_time_secs();
        if now > record.expires_at {
            return VaultResponse::Error("secret has expired".into());
        }

        // ── 5. Parse attestation evidence (quote) ───────────────────────
        let identity = match parse_quote(&attestation_evidence) {
            Ok(id) => id,
            Err(e) => return VaultResponse::Error(format!("attestation: {e}")),
        };

        // ── 5b. Bidirectional challenge-response verification ───────────
        //
        // When the server issued a challenge nonce (challenge mode), verify
        // that the client's RA-TLS certificate was generated specifically
        // for this connection by checking that:
        //
        //   client_report_data == SHA-512( SHA-256(client_pubkey) || server_nonce )
        //
        // This proves the client's TEE produced a fresh quote binding both
        // its public key and the server's per-connection nonce — preventing
        // replay of a previously captured client certificate.
        if let Some(ref nonce) = ctx.client_challenge_nonce {
            // Extract report_data from the client's attestation quote
            let actual_report_data = match extract_report_data(&attestation_evidence) {
                Ok(rd) => rd,
                Err(e) => return VaultResponse::Error(
                    format!("client report_data extraction: {e}")
                ),
            };

            // Extract the client's raw public key from the peer certificate
            let client_pubkey = match extract_pubkey_from_cert(peer_der) {
                Ok(pk) => pk,
                Err(e) => return VaultResponse::Error(
                    format!("client pubkey extraction: {e}")
                ),
            };

            // Compute expected: SHA-512( SHA-256(pubkey) || nonce )
            let expected = compute_report_data_hash(&client_pubkey, nonce);

            if actual_report_data[..] != expected.as_ref()[..] {
                return VaultResponse::Error(
                    "bidirectional challenge-response failed: client certificate \
                     report_data does not bind to the server's challenge nonce"
                        .into(),
                );
            }
        }

        // ── 6. Check measurement against policy whitelist ───────────────
        if !is_permitted(
            &identity,
            &record.policy.allowed_mrenclave,
            &record.policy.allowed_mrtd,
        ) {
            return VaultResponse::Error("measurement not permitted by policy".into());
        }

        // ── 7. Check manager bearer token (if policy has a manager pubkey)
        if let Some(ref mgr_pubkey_hex) = record.policy.manager_pubkey {
            let token = match bearer_token {
                Some(t) => t,
                None => {
                    return VaultResponse::Error(
                        "bearer token required (manager_pubkey set in policy)".into(),
                    )
                }
            };

            // Decode the manager's public key from hex
            let mgr_raw = match crate::quote::hex_decode(mgr_pubkey_hex) {
                Ok(b) => b,
                Err(e) => {
                    return VaultResponse::Error(format!(
                        "corrupt manager_pubkey in policy: {e}"
                    ))
                }
            };

            // Verify the bearer token as a JWT signed by the manager
            let mgr_verifier = match JwtVerifier::from_public_key_bytes(&mgr_raw) {
                Ok(v) => v,
                Err(e) => {
                    return VaultResponse::Error(format!(
                        "invalid manager_pubkey in policy: {e}"
                    ))
                }
            };

            let bearer_claims: BearerTokenClaims = match mgr_verifier.verify_and_decode(token) {
                Ok(c) => c,
                Err(e) => {
                    return VaultResponse::Error(format!("bearer token verification failed: {e}"))
                }
            };

            // The bearer token must be for this specific secret
            if bearer_claims.name != name {
                return VaultResponse::Error(format!(
                    "bearer token is for '{}', not '{}'",
                    bearer_claims.name, name
                ));
            }
        }

        // ── 8. Check required OIDs ──────────────────────────────────────
        for req_oid in &record.policy.required_oids {
            let matched = oid_claims
                .iter()
                .any(|c| c.oid == req_oid.oid && c.value == req_oid.value);
            if !matched {
                return VaultResponse::Error(format!(
                    "required OID {} not satisfied",
                    req_oid.oid
                ));
            }
        }

        VaultResponse::SecretValue {
            secret: record.secret,
            expires_at: record.expires_at,
        }
    }

    /// Delete a named secret — only the original owner can delete.
    fn handle_delete(&self, jwt: &[u8]) -> VaultResponse {
        let claims: DeleteSecretClaims = match self.verifier.verify_and_decode(jwt) {
            Ok(c) => c,
            Err(e) => return VaultResponse::Error(e),
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        // Verify ownership before deleting
        let record_bytes = match kv.lock() {
            Ok(store) => match store.get(claims.name.as_bytes()) {
                Ok(Some(v)) => v,
                Ok(None) => return VaultResponse::Error("secret not found".into()),
                Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
            },
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };

        let record: SecretRecord = match serde_json::from_slice(&record_bytes) {
            Ok(r) => r,
            Err(e) => return VaultResponse::Error(format!("corrupt record: {e}")),
        };

        if record.owner_pubkey_hash != self.owner_pubkey_hash {
            return VaultResponse::Error("not the secret owner".into());
        }

        match kv.lock() {
            Ok(mut store) => {
                if let Err(e) = store.delete(claims.name.as_bytes()) {
                    return VaultResponse::Error(format!("kv delete failed: {e}"));
                }
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::SecretDeleted
    }

    /// Update the access policy for an existing secret — owner only.
    fn handle_update_policy(&self, jwt: &[u8]) -> VaultResponse {
        let claims: UpdateSecretPolicyClaims = match self.verifier.verify_and_decode(jwt) {
            Ok(c) => c,
            Err(e) => return VaultResponse::Error(e),
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        let record_bytes = match kv.lock() {
            Ok(store) => match store.get(claims.name.as_bytes()) {
                Ok(Some(v)) => v,
                Ok(None) => return VaultResponse::Error("secret not found".into()),
                Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
            },
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };

        let mut record: SecretRecord = match serde_json::from_slice(&record_bytes) {
            Ok(r) => r,
            Err(e) => return VaultResponse::Error(format!("corrupt record: {e}")),
        };

        if record.owner_pubkey_hash != self.owner_pubkey_hash {
            return VaultResponse::Error("not the secret owner".into());
        }

        // Check not expired
        let now = current_time_secs();
        if now > record.expires_at {
            return VaultResponse::Error("secret has expired".into());
        }

        // Apply new policy (normalised)
        record.policy = normalise_policy(claims.policy);

        let record_json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => return VaultResponse::Error(format!("serialise record: {e}")),
        };

        match kv.lock() {
            Ok(store) => {
                if let Err(e) = store.put(claims.name.as_bytes(), &record_json) {
                    return VaultResponse::Error(format!("kv put failed: {e}"));
                }
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::PolicyUpdated
    }
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Normalise a secret policy: lowercase hex values, cap TTL.
fn normalise_policy(mut policy: types::SecretPolicy) -> types::SecretPolicy {
    // Cap TTL
    if policy.ttl_seconds == 0 {
        policy.ttl_seconds = DEFAULT_SECRET_TTL_SECONDS;
    }
    if policy.ttl_seconds > MAX_SECRET_TTL_SECONDS {
        policy.ttl_seconds = MAX_SECRET_TTL_SECONDS;
    }

    // Lowercase all hex measurement values
    for m in &mut policy.allowed_mrenclave {
        *m = m.to_lowercase();
    }
    for m in &mut policy.allowed_mrtd {
        *m = m.to_lowercase();
    }
    if let Some(ref mut h) = policy.manager_pubkey {
        *h = h.to_lowercase();
    }
    for oid in &mut policy.required_oids {
        oid.value = oid.value.to_lowercase();
    }

    policy
}

/// Get the current UNIX timestamp (seconds) via OCall.
fn current_time_secs() -> u64 {
    enclave_os_enclave::ocall::get_current_time().unwrap_or(0)
}

// ---------------------------------------------------------------------------
//  Peer certificate attestation extraction
// ---------------------------------------------------------------------------

/// Known attestation quote OIDs in dotted-string form.
const SGX_QUOTE_OID_STR: &str = enclave_os_common::oids::SGX_QUOTE_OID_STR;
const TDX_QUOTE_OID_STR: &str = enclave_os_common::oids::TDX_QUOTE_OID_STR;

/// Privasys configuration OIDs that are recognised as OID claims.
const CLAIM_OIDS: &[&str] = &[
    enclave_os_common::oids::CONFIG_MERKLE_ROOT_OID_STR,
    enclave_os_common::oids::EGRESS_CA_HASH_OID_STR,
    enclave_os_common::oids::WASM_APPS_HASH_OID_STR,
    enclave_os_common::oids::APP_CONFIG_MERKLE_ROOT_OID_STR,
    enclave_os_common::oids::APP_CODE_HASH_OID_STR,
];

/// Extract the attestation quote and OID claims from a DER-encoded X.509
/// peer certificate.
///
/// Returns `(attestation_evidence, oid_claims)` where
/// `attestation_evidence` is the raw SGX/TDX quote bytes and
/// `oid_claims` is a list of Privasys configuration OID extensions
/// found in the certificate.
fn extract_attestation_from_cert(der: &[u8]) -> Result<(Vec<u8>, Vec<OidClaim>), String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("invalid X.509 DER: {e}"))?;

    let mut quote_bytes: Option<Vec<u8>> = None;
    let mut oid_claims = Vec::new();

    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SGX_QUOTE_OID_STR || oid_str == TDX_QUOTE_OID_STR {
            quote_bytes = Some(ext.value.to_vec());
        } else if CLAIM_OIDS.contains(&oid_str.as_str()) {
            oid_claims.push(OidClaim {
                oid: oid_str,
                value: hex_encode(ext.value),
            });
        }
    }

    let evidence = quote_bytes.ok_or_else(|| {
        "peer certificate does not contain an SGX/TDX attestation quote extension".to_string()
    })?;

    Ok((evidence, oid_claims))
}

/// Extract the raw public key bytes from a DER-encoded X.509 certificate.
///
/// For ECDSA P-256 keys, this returns the 65-byte uncompressed elliptic
/// curve point (`0x04 || x || y`), which matches the format produced by
/// `ring::signature::EcdsaKeyPair::public_key().as_ref()`.  This is
/// critical for report_data computation:
///
/// ```text
/// report_data = SHA-512( SHA-256(pubkey_bytes) || binding )
/// ```
fn extract_pubkey_from_cert(der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("invalid X.509 DER: {e}"))?;

    let pubkey_data = cert.tbs_certificate.subject_pki.subject_public_key.data;
    if pubkey_data.is_empty() {
        return Err("empty subject public key in certificate".into());
    }

    Ok(pubkey_data.to_vec())
}
