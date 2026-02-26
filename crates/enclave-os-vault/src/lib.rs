// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault module for enclave-os - JWT-gated secret store inside SGX.
//!
//! Secrets are stored in the sealed KV store (AES-256-GCM encrypted,
//! MRENCLAVE-bound).  Clients submit JWTs over RA-TLS; the vault
//! verifies the ES256 signature, extracts the payload, stores or
//! retrieves the secret, and returns the result.
//!
//! ## Protocol
//!
//! | Request | JWT payload | Response |
//! |---------|-------------|----------|
//! | `StoreSecret { jwt }` | `{ "secret": "<base64url>" }` | `SecretStored { secret_hash }` |
//! | `GetSecret  { jwt }`  | `{ "secret_hash": "<hex SHA-256>" }` | `SecretValue { secret }` |
//!
//! ## Usage
//!
//! In your custom `ecall_run`:
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
//! // Build verifier from the operator-supplied public key.
//! let pubkey_hex = config.extra["vault_jwt_pubkey_hex"].as_str().unwrap();
//! let vault = VaultModule::new(pubkey_hex)?;
//! register_module(Box::new(vault));
//!
//! finalize_and_run(&config, &sealed_cfg);
//! ```

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest;
use serde::Deserialize;

use enclave_os_common::jwt::JwtVerifier;
use enclave_os_common::protocol::{Request, Response};
use enclave_os_enclave::modules::EnclaveModule;

// ---------------------------------------------------------------------------
//  JWT payload schemas
// ---------------------------------------------------------------------------

/// JWT payload for `StoreSecret`.
#[derive(Debug, Deserialize)]
struct StoreSecretClaims {
    /// Base64url-encoded secret bytes.
    secret: String,
}

/// JWT payload for `GetSecret`.
#[derive(Debug, Deserialize)]
struct GetSecretClaims {
    /// Hex-encoded SHA-256 hash of the secret.
    secret_hash: String,
}

// ---------------------------------------------------------------------------
//  VaultModule
// ---------------------------------------------------------------------------

/// Enclave module that handles `StoreSecret` / `GetSecret` requests.
///
/// Secrets are persisted in the sealed KV store (via `enclave-os-kvstore`).
/// The KV key for each secret is its SHA-256 hash (hex-encoded).
///
/// Every incoming JWT is verified against the ECDSA P-256 public key
/// provided at construction time before any payload is processed.
pub struct VaultModule {
    verifier: JwtVerifier,
}

impl VaultModule {
    /// Construct the vault module.
    ///
    /// `pubkey_hex` is the hex-encoded uncompressed P-256 public key
    /// (65 bytes: `04 || x || y`) of the authorised secret manager.
    pub fn new(pubkey_hex: &str) -> Result<Self, String> {
        let verifier = JwtVerifier::from_hex(pubkey_hex)?;
        Ok(Self { verifier })
    }

    /// Construct from raw public key bytes (65-byte uncompressed).
    pub fn from_public_key_bytes(raw: &[u8]) -> Result<Self, String> {
        let verifier = JwtVerifier::from_public_key_bytes(raw)?;
        Ok(Self { verifier })
    }
}

impl EnclaveModule for VaultModule {
    fn name(&self) -> &str {
        "vault"
    }

    fn handle(&self, req: &Request) -> Option<Response> {
        match req {
            Request::StoreSecret { jwt } => Some(self.handle_store(jwt)),
            Request::GetSecret { jwt } => Some(self.handle_get(jwt)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
//  Request handlers
// ---------------------------------------------------------------------------

impl VaultModule {
    /// Store a secret: verify JWT -> extract secret -> SHA-256 -> persist -> reply.
    fn handle_store(&self, jwt: &[u8]) -> Response {
        // Verify signature and decode claims
        let claims: StoreSecretClaims = match self.verifier.verify_and_decode(jwt) {
            Ok(c) => c,
            Err(e) => return error_response(&e),
        };

        // Base64url-decode the secret
        let secret_bytes = match URL_SAFE_NO_PAD.decode(&claims.secret) {
            Ok(b) => b,
            Err(e) => return error_response(&format!("bad base64: {e}")),
        };

        // SHA-256 hash -> hex key
        let hash = digest::digest(&digest::SHA256, &secret_bytes);
        let hex_key = hex_encode(hash.as_ref());

        // Persist in the sealed KV store
        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return error_response("kv store not initialised"),
        };
        match kv.lock() {
            Ok(store) => {
                if let Err(e) = store.put(hex_key.as_bytes(), &secret_bytes) {
                    return error_response(&format!("kv put failed: {e}"));
                }
            }
            Err(_) => return error_response("kv store lock poisoned"),
        }

        Response::SecretStored {
            secret_hash: hex_key.into_bytes(),
        }
    }

    /// Retrieve a secret: verify JWT -> extract hash -> KV lookup -> reply.
    fn handle_get(&self, jwt: &[u8]) -> Response {
        let claims: GetSecretClaims = match self.verifier.verify_and_decode(jwt) {
            Ok(c) => c,
            Err(e) => return error_response(&e),
        };

        let kv = match enclave_os_kvstore::kv_store() {
            Some(kv) => kv,
            None => return error_response("kv store not initialised"),
        };
        match kv.lock() {
            Ok(store) => match store.get(claims.secret_hash.as_bytes()) {
                Ok(Some(secret)) => Response::SecretValue { secret },
                Ok(None) => error_response("secret not found"),
                Err(e) => error_response(&format!("kv get failed: {e}")),
            },
            Err(_) => error_response("kv store lock poisoned"),
        }
    }
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Build an `Error` response from a message string.
fn error_response(msg: &str) -> Response {
    Response::Error(msg.as_bytes().to_vec())
}

/// Hex-encode bytes (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
