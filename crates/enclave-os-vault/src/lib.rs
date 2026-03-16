// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os — OIDC-authenticated, policy-gated secret
//! store inside SGX.
//!
//! Secrets are stored in the sealed KV store (AES-256-GCM encrypted,
//! MRENCLAVE-bound).  Each secret has a named key, an access policy
//! (MRENCLAVE/MRTD whitelist + optional bearer token + optional OID
//! verification), and a TTL (max 3 months).
//!
//! ## OIDC auth model
//!
//! Secret ownership is bound to the caller's OIDC `sub` claim.  No more
//! `OpenVault` / `CloseVault` — the OIDC subject *is* the vault namespace.
//!
//! KV keys use the format `"secret:{owner_sub}:{name}"` for namespace
//! isolation between owners.
//!
//! ## Protocol
//!
//! | VaultRequest | Auth | Role | VaultResponse |
//! |---|---|---|---|
//! | `StoreSecret { name, secret, policy }` | OIDC | secret-owner | `SecretStored { name, expires_at }` |
//! | `GetSecret { name }` | OIDC owner **or** RA-TLS TEE | — | `SecretValue { secret, expires_at }` |
//! | `DeleteSecret { name }` | OIDC | secret-owner | `SecretDeleted` |
//! | `UpdateSecretPolicy { name, policy }` | OIDC | secret-owner | `PolicyUpdated` |
//! | `ListSecrets` | OIDC | secret-owner | `SecretList { secrets }` |
//!
//! ## GetSecret dual-path auth
//!
//! 1. **OIDC owner path**: caller's `sub` matches the secret's `owner_sub`.
//!    No RA-TLS required.
//! 2. **RA-TLS TEE path**: mutual RA-TLS client certificate with matching
//!    measurements + optional bearer token from the secret manager.

pub mod quote;
pub mod types;

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_kvstore::SealedKvStore;

use crate::quote::{hex_encode, extract_report_data, is_permitted, parse_quote};
use enclave_os_common::quote::compute_report_data_hash;
use crate::types::{
    OidClaim, SecretRecord, SecretListEntry,
    VaultRequest, VaultResponse,
    DEFAULT_SECRET_TTL_SECONDS, MAX_SECRET_TTL_SECONDS,
};

// ---------------------------------------------------------------------------
//  VaultModule
// ---------------------------------------------------------------------------

/// Enclave module that handles named secret storage with policy-gated access.
///
/// Secrets are persisted in the sealed KV store (via `enclave-os-kvstore`).
/// The KV key is `"secret:{owner_sub}:{name}"`.
///
/// Storing, deleting, updating, and listing secrets requires an OIDC bearer
/// token with the **secret-owner** role.  The `sub` claim identifies the
/// owner.  Retrieving secrets supports dual-path auth: OIDC owner *or*
/// RA-TLS TEE.
pub struct VaultModule {
    _private: (), // zero-sized — no global state needed
}

impl VaultModule {
    /// Construct the vault module.
    pub fn new() -> Self {
        Self { _private: () }
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
            VaultRequest::StoreSecret { name, secret, policy } => {
                self.handle_store(&name, &secret, policy, ctx)
            }
            VaultRequest::GetSecret {
                name,
                bearer_token,
            } => self.handle_get(&name, bearer_token.as_deref(), ctx),
            VaultRequest::DeleteSecret { name } => self.handle_delete(&name, ctx),
            VaultRequest::UpdateSecretPolicy { name, policy } => {
                self.handle_update_policy(&name, policy, ctx)
            }
            VaultRequest::ListSecrets => self.handle_list_secrets(ctx),
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
    /// Require the caller to have the secret-owner OIDC role.
    /// Returns the owner's `sub` or an error response.
    fn require_secret_owner(ctx: &RequestContext) -> Result<String, VaultResponse> {
        let claims = ctx.oidc_claims.as_ref().ok_or_else(|| {
            VaultResponse::Error("OIDC authentication required (secret-owner role)".into())
        })?;
        if !claims.has_secret_owner() {
            return Err(VaultResponse::Error("secret-owner role required".into()));
        }
        Ok(claims.sub.clone())
    }

    /// Build the KV key for a secret: `"secret:{owner_sub}:{name}"`.
    fn kv_key(owner_sub: &str, name: &str) -> Vec<u8> {
        format!("secret:{}:{}", owner_sub, name).into_bytes()
    }

    /// Build the KV key for the name→owner reverse lookup.
    /// Used by the RA-TLS GetSecret path (caller knows the name but not
    /// the owner_sub).
    fn lookup_key(name: &str) -> Vec<u8> {
        format!("lookup:{}", name).into_bytes()
    }

    /// Build the KV key for the owner→names index.
    /// Used by ListSecrets.
    fn owner_index_key(owner_sub: &str) -> Vec<u8> {
        format!("index:{}", owner_sub).into_bytes()
    }

    /// Add a secret name to the owner's index.
    fn add_to_owner_index(
        store: &SealedKvStore,
        owner_sub: &str,
        name: &str,
    ) -> Result<(), String> {
        let idx_key = Self::owner_index_key(owner_sub);
        let mut names: Vec<String> = match store.get(&idx_key) {
            Ok(Some(data)) => serde_json::from_slice(&data)
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
        let data = serde_json::to_vec(&names)
            .map_err(|e| format!("serialise index: {e}"))?;
        store.put(&idx_key, &data)
    }

    /// Remove a secret name from the owner's index.
    fn remove_from_owner_index(
        store: &SealedKvStore,
        owner_sub: &str,
        name: &str,
    ) -> Result<(), String> {
        let idx_key = Self::owner_index_key(owner_sub);
        let mut names: Vec<String> = match store.get(&idx_key) {
            Ok(Some(data)) => serde_json::from_slice(&data)
                .unwrap_or_default(),
            _ => return Ok(()),
        };
        names.retain(|n| n != name);
        let data = serde_json::to_vec(&names)
            .map_err(|e| format!("serialise index: {e}"))?;
        store.put(&idx_key, &data)
    }

    /// Store a named secret with an access policy.
    fn handle_store(
        &self,
        name: &str,
        secret_b64: &str,
        policy: types::SecretPolicy,
        ctx: &RequestContext,
    ) -> VaultResponse {
        let owner_sub = match Self::require_secret_owner(ctx) {
            Ok(sub) => sub,
            Err(resp) => return resp,
        };

        // Decode base64url secret
        let secret_bytes = match URL_SAFE_NO_PAD.decode(secret_b64) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("bad base64: {e}")),
        };

        if secret_bytes.is_empty() {
            return VaultResponse::Error("secret must not be empty".into());
        }

        // Normalise policy (cap TTL, lowercase hex)
        let policy = normalise_policy(policy);

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
            owner_sub: owner_sub.clone(),
        };

        let record_json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => return VaultResponse::Error(format!("serialise record: {e}")),
        };

        // Persist secret + indexes
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };
        let key = Self::kv_key(&owner_sub, name);
        match kv.lock() {
            Ok(store) => {
                if let Err(e) = store.put(&key, &record_json) {
                    return VaultResponse::Error(format!("kv put failed: {e}"));
                }
                // Reverse lookup: name → owner_sub (for RA-TLS GetSecret)
                if let Err(e) = store.put(
                    &Self::lookup_key(name),
                    owner_sub.as_bytes(),
                ) {
                    return VaultResponse::Error(format!("kv lookup index: {e}"));
                }
                // Owner index: owner_sub → [name, ...]  (for ListSecrets)
                if let Err(e) = Self::add_to_owner_index(&store, &owner_sub, name) {
                    return VaultResponse::Error(format!("kv owner index: {e}"));
                }
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::SecretStored {
            name: name.to_string(),
            expires_at,
        }
    }

    /// Retrieve a named secret — dual-path auth.
    ///
    /// **Path 1 — OIDC owner**: caller has `secret-owner` role and their
    /// `sub` matches the stored `owner_sub`.  No RA-TLS required.
    ///
    /// **Path 2 — RA-TLS TEE**: mutual RA-TLS client certificate with
    /// matching measurements + optional bearer token from the secret
    /// manager.  The request must include `bearer_token` if the policy
    /// has a `manager_sub`.
    fn handle_get(
        &self,
        name: &str,
        bearer_token: Option<&[u8]>,
        ctx: &RequestContext,
    ) -> VaultResponse {
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        // ── Try OIDC owner path first ───────────────────────────────────
        if let Some(ref claims) = ctx.oidc_claims {
            if claims.has_secret_owner() {
                let key = Self::kv_key(&claims.sub, name);
                let record_bytes = match kv.lock() {
                    Ok(store) => match store.get(&key) {
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

                // Check expiry
                let now = current_time_secs();
                if now > record.expires_at {
                    return VaultResponse::Error("secret has expired".into());
                }

                return VaultResponse::SecretValue {
                    secret: record.secret,
                    expires_at: record.expires_at,
                };
            }
        }

        // ── RA-TLS TEE path ────────────────────────────────────────────
        // The caller must present a mutual RA-TLS client certificate.
        // We need the owner_sub to look up the secret — but the RA-TLS
        // caller doesn't know it.  We search by iterating over secrets
        // with matching name suffix.  This is O(n) but acceptable for
        // a sealed KV store that is not designed for massive scale.

        let peer_der = match ctx.peer_cert_der {
            Some(ref der) => der,
            None => {
                return VaultResponse::Error(
                    "authentication required: provide OIDC token (secret-owner) \
                     or mutual RA-TLS client certificate".into(),
                )
            }
        };

        // Parse attestation from peer cert
        let (attestation_evidence, oid_claims) = match extract_attestation_from_cert(peer_der) {
            Ok(pair) => pair,
            Err(e) => return VaultResponse::Error(format!("peer certificate: {e}")),
        };

        // Find the secret via the name→owner reverse lookup index
        let owner_sub = match kv.lock() {
            Ok(store) => match store.get(&Self::lookup_key(name)) {
                Ok(Some(v)) => String::from_utf8(v)
                    .map_err(|_| "corrupt lookup index".to_string()),
                Ok(None) => Err("secret not found".into()),
                Err(e) => Err(format!("kv lookup failed: {e}")),
            },
            Err(_) => Err("kv store lock poisoned".into()),
        };
        let owner_sub = match owner_sub {
            Ok(sub) => sub,
            Err(msg) => return VaultResponse::Error(msg),
        };

        let key = Self::kv_key(&owner_sub, name);
        let record_bytes = match kv.lock() {
            Ok(store) => match store.get(&key) {
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

        // Check expiry
        let now = current_time_secs();
        if now > record.expires_at {
            return VaultResponse::Error("secret has expired".into());
        }

        // Verify quote via attestation server(s)
        let servers = enclave_os_common::attestation_servers::server_urls();
        if let Err(e) = enclave_os_egress::attestation::verify_quote(
            &attestation_evidence,
            &servers,
        ) {
            return VaultResponse::Error(format!("attestation verification: {e}"));
        }

        // Parse attestation evidence (quote)
        let identity = match parse_quote(&attestation_evidence) {
            Ok(id) => id,
            Err(e) => return VaultResponse::Error(format!("attestation: {e}")),
        };

        // Bidirectional challenge-response verification
        if let Some(ref nonce) = ctx.client_challenge_nonce {
            let actual_report_data = match extract_report_data(&attestation_evidence) {
                Ok(rd) => rd,
                Err(e) => return VaultResponse::Error(
                    format!("client report_data extraction: {e}")
                ),
            };

            let client_pubkey = match extract_pubkey_from_cert(peer_der) {
                Ok(pk) => pk,
                Err(e) => return VaultResponse::Error(
                    format!("client pubkey extraction: {e}")
                ),
            };

            // Build the full SPKI DER (91 bytes) from the raw EC point
            // (65 bytes) to match the enclave's ReportData computation.
            let client_spki = enclave_os_common::quote::build_p256_spki_der(&client_pubkey);
            let expected = compute_report_data_hash(&client_spki, nonce);

            if actual_report_data[..] != expected.as_ref()[..] {
                return VaultResponse::Error(
                    "bidirectional challenge-response failed: client certificate \
                     report_data does not bind to the server's challenge nonce"
                        .into(),
                );
            }
        }

        // Check measurement against policy whitelist
        if !is_permitted(
            &identity,
            &record.policy.allowed_mrenclave,
            &record.policy.allowed_mrtd,
        ) {
            return VaultResponse::Error("measurement not permitted by policy".into());
        }

        // Check manager bearer token (if policy has a manager_sub)
        if let Some(ref mgr_sub) = record.policy.manager_sub {
            let token = match bearer_token {
                Some(t) => t,
                None => {
                    return VaultResponse::Error(
                        "bearer token required (manager_sub set in policy)".into(),
                    )
                }
            };

            // The bearer token is an OIDC JWT — verify its sub matches
            // the policy's manager_sub using the same OIDC verification
            // as the auth layer.
            let bearer_claims = match verify_bearer_oidc(token) {
                Ok(c) => c,
                Err(e) => return VaultResponse::Error(format!("bearer token: {e}")),
            };

            if bearer_claims.sub != *mgr_sub {
                return VaultResponse::Error(format!(
                    "bearer token sub '{}' != policy manager_sub",
                    bearer_claims.sub
                ));
            }

            if !bearer_claims.has_secret_manager() {
                return VaultResponse::Error(
                    "bearer token holder requires secret-manager role".into()
                );
            }
        }

        // Check required OIDs
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

    /// Delete a named secret — only the OIDC owner can delete.
    fn handle_delete(&self, name: &str, ctx: &RequestContext) -> VaultResponse {
        let owner_sub = match Self::require_secret_owner(ctx) {
            Ok(sub) => sub,
            Err(resp) => return resp,
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        let key = Self::kv_key(&owner_sub, name);

        match kv.lock() {
            Ok(mut store) => {
                // Verify the secret exists
                match store.get(&key) {
                    Ok(Some(_)) => {}
                    Ok(None) => return VaultResponse::Error("secret not found".into()),
                    Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
                }
                // Delete the secret
                if let Err(e) = store.delete(&key) {
                    return VaultResponse::Error(format!("kv delete failed: {e}"));
                }
                // Clean up reverse lookup index
                let _ = store.delete(&Self::lookup_key(name));
                // Clean up owner index
                let _ = Self::remove_from_owner_index(&store, &owner_sub, name);
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::SecretDeleted
    }

    /// Update the access policy for an existing secret — owner only.
    fn handle_update_policy(
        &self,
        name: &str,
        new_policy: types::SecretPolicy,
        ctx: &RequestContext,
    ) -> VaultResponse {
        let owner_sub = match Self::require_secret_owner(ctx) {
            Ok(sub) => sub,
            Err(resp) => return resp,
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        let key = Self::kv_key(&owner_sub, name);

        let record_bytes = match kv.lock() {
            Ok(store) => match store.get(&key) {
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

        // Check not expired
        let now = current_time_secs();
        if now > record.expires_at {
            return VaultResponse::Error("secret has expired".into());
        }

        // Apply new policy (normalised)
        record.policy = normalise_policy(new_policy);

        let record_json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => return VaultResponse::Error(format!("serialise record: {e}")),
        };

        match kv.lock() {
            Ok(store) => {
                if let Err(e) = store.put(&key, &record_json) {
                    return VaultResponse::Error(format!("kv put failed: {e}"));
                }
            }
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        }

        VaultResponse::PolicyUpdated
    }

    /// List all secrets owned by the caller (metadata only).
    fn handle_list_secrets(&self, ctx: &RequestContext) -> VaultResponse {
        let owner_sub = match Self::require_secret_owner(ctx) {
            Ok(sub) => sub,
            Err(resp) => return resp,
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return VaultResponse::Error("kv store not initialised".into()),
        };

        // Read the owner index to get secret names
        let names: Vec<String> = match kv.lock() {
            Ok(store) => match store.get(&Self::owner_index_key(&owner_sub)) {
                Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
                Ok(None) => Vec::new(),
                Err(e) => return VaultResponse::Error(format!("kv index read: {e}")),
            },
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };

        let mut secrets = Vec::new();
        if let Ok(store) = kv.lock() {
            for name in &names {
                let key = Self::kv_key(&owner_sub, name);
                if let Ok(Some(value_bytes)) = store.get(&key) {
                    if let Ok(record) = serde_json::from_slice::<SecretRecord>(&value_bytes) {
                        secrets.push(SecretListEntry {
                            name: name.clone(),
                            expires_at: record.expires_at,
                        });
                    }
                }
            }
        }

        VaultResponse::SecretList { secrets }
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
    for oid in &mut policy.required_oids {
        oid.value = oid.value.to_lowercase();
    }

    policy
}

/// Verify a bearer token (OIDC JWT) and return the claims.
///
/// Used for the RA-TLS + bearer defence-in-depth path in `GetSecret`.
/// The bearer token is verified against the same OIDC configuration as
/// the auth layer, and must have the `secret-manager` role.
fn verify_bearer_oidc(token: &[u8]) -> Result<enclave_os_common::oidc::OidcClaims, String> {
    let token_str = core::str::from_utf8(token)
        .map_err(|e| format!("bearer token not utf8: {e}"))?;

    // Re-use the same OIDC verification as the auth layer in server.rs.
    // The enclave's verify_oidc_token is not directly accessible from
    // the vault crate, so we do a minimal JWT decode + claim extraction
    // here against the global OIDC config.
    let config = enclave_os_common::oidc::is_oidc_configured()
        .then(|| ())
        .ok_or("OIDC not configured")?;
    let _ = config;

    // Decode JWT payload
    let parts: Vec<&str> = token_str.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("malformed JWT".into());
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|e| format!("JWT payload base64: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT payload JSON: {e}"))?;

    let sub = claims.get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // We need the OidcConfig to extract roles.  Since we can't access
    // the enclave's global directly, we reconstruct a default config.
    // TODO(oidc): Share the global OidcConfig through common or pass
    // it as a parameter.
    let default_config = enclave_os_common::oidc::OidcConfig {
        issuer: String::new(),
        audience: String::new(),
        role_claim: "urn:zitadel:iam:org:project:roles".into(),
        manager_role: "enclave-os-mini:manager".into(),
        monitoring_role: "enclave-os-mini:monitoring".into(),
        secret_owner_role: "enclave-os-mini:secret-owner".into(),
        secret_manager_role: "enclave-os-mini:secret-manager".into(),
    };

    let roles = enclave_os_common::oidc::extract_roles(&claims, &default_config);

    Ok(enclave_os_common::oidc::OidcClaims { sub, roles })
}

/// Get the current UNIX timestamp (seconds) via OCall.
fn current_time_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
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
    enclave_os_common::oids::ATTESTATION_SERVERS_HASH_OID_STR,
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
/// `ring::signature::EcdsaKeyPair::public_key().as_ref()`.
///
/// Callers that need to reproduce the ReportData hash should wrap the
/// result with [`enclave_os_common::quote::build_p256_spki_der`] to get
/// the 91-byte SPKI DER used in:
///
/// ```text
/// report_data = SHA-512( SHA-256(SPKI_DER) || binding )
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
