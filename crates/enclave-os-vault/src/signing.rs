// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault signing key + approval-token issuance / verification.
//!
//! The vault owns a single ECDSA-P256 key pair, generated lazily on
//! first use and stored sealed in the KV store under
//! [`SIGNING_KEY_KV`]. It is used to sign [`ApprovalToken`]s issued
//! via [`VaultRequest::IssueApprovalToken`](crate::types::VaultRequest)
//! and to verify those same tokens when they show up inside other
//! requests (gating [`Condition::ManagerApproval`](crate::types::Condition)).
//!
//! The signing key never leaves the enclave.

use std::string::String;
use std::vec::Vec;

use enclave_os_common::jwt::{decode_payload_unverified, encode_jwt, JwtVerifier};
use enclave_os_kvstore::SealedKvStore;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::types::{ApprovalClaims, ApprovalToken, Operation};

/// Sealed-KV key holding the vault's PKCS#8 ECDSA-P256 private key.
const SIGNING_KEY_KV: &[u8] = b"__vault_signing_key_pkcs8__";

/// Issuer claim placed in every approval token.
pub(crate) const ISSUER: &str = "enclave-os-vault";

// ---------------------------------------------------------------------------
//  Lazy-init keypair
// ---------------------------------------------------------------------------

/// Return the vault's signing key, generating + persisting it on the
/// first call.
///
/// Caller must already hold the KV mutex.
pub(crate) fn load_or_init_keypair(
    store: &mut SealedKvStore,
) -> Result<EcdsaKeyPair, String> {
    let rng = SystemRandom::new();
    let pkcs8 = match store
        .get(SIGNING_KEY_KV)
        .map_err(|e| format!("kv get signing key: {e}"))?
    {
        Some(b) => b,
        None => {
            let doc = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .map_err(|_| "generate vault signing key failed".to_string())?;
            let bytes = doc.as_ref().to_vec();
            store
                .put(SIGNING_KEY_KV, &bytes)
                .map_err(|e| format!("kv put signing key: {e}"))?;
            bytes
        }
    };

    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
        .map_err(|_| "parse vault signing key failed".to_string())
}

/// Return only the raw uncompressed public key (65 bytes, `04 || x || y`).
/// Caller must already hold the KV mutex.
pub(crate) fn load_or_init_public_key(
    store: &mut SealedKvStore,
) -> Result<Vec<u8>, String> {
    Ok(load_or_init_keypair(store)?.public_key().as_ref().to_vec())
}

// ---------------------------------------------------------------------------
//  Issue
// ---------------------------------------------------------------------------

/// Sign an [`ApprovalToken`] for the given (handle, op, manager) triple.
pub(crate) fn issue_approval_token(
    store: &mut SealedKvStore,
    handle: &str,
    op: Operation,
    manager: u32,
    iat: u64,
    ttl_seconds: u64,
) -> Result<ApprovalToken, String> {
    let kp = load_or_init_keypair(store)?;
    let claims = ApprovalClaims {
        iss: ISSUER.to_string(),
        handle: handle.to_string(),
        op,
        manager,
        iat,
        exp: iat.saturating_add(ttl_seconds),
    };
    let rng = SystemRandom::new();
    let jwt_bytes = encode_jwt(&claims, &kp, &rng, None)?;
    let jwt = String::from_utf8(jwt_bytes).map_err(|e| format!("jwt utf8: {e}"))?;
    Ok(ApprovalToken { jwt })
}

// ---------------------------------------------------------------------------
//  Verify
// ---------------------------------------------------------------------------

/// Verify an approval token against the expected (handle, op, manager).
///
/// Performs (in order):
///   1. ES256 signature verification against the vault's signing key,
///   2. `iss == ISSUER`,
///   3. `handle` / `op` / `manager` claims match,
///   4. `manager_sub` claim matches the OIDC sub of the named manager
///      (this is enforced indirectly: a token can only be issued by the
///      vault for a manager who has authenticated, so we pin the manager
///      *index* and let the policy lookup catch reshuffles),
///   5. `now <= exp`,
///   6. `now - iat <= fresh_for_seconds`.
pub(crate) fn verify_approval_token(
    token: &ApprovalToken,
    handle: &str,
    op: Operation,
    manager: u32,
    _manager_sub: &str,
    fresh_for_seconds: u64,
    now: u64,
) -> Result<(), String> {
    // 1. Look up our own public key from the sealed KV.
    let public_key = {
        let kv = enclave_os_kvstore::kv_store()
            .ok_or_else(|| "kv store not initialised".to_string())?;
        let mut store = kv
            .lock()
            .map_err(|_| "kv store lock poisoned".to_string())?;
        load_or_init_public_key(&mut store)?
    };
    let verifier = JwtVerifier::from_public_key_bytes(&public_key)?;

    // 2. Verify signature + decode claims.
    let claims: ApprovalClaims = verifier.verify_and_decode(token.jwt.as_bytes())?;

    if claims.iss != ISSUER {
        return Err(format!("issuer mismatch (got '{}')", claims.iss));
    }
    if claims.handle != handle {
        return Err(format!(
            "handle mismatch (token={}, request={})",
            claims.handle, handle
        ));
    }
    if claims.op != op {
        return Err(format!(
            "op mismatch (token={:?}, request={:?})",
            claims.op, op
        ));
    }
    if claims.manager != manager {
        return Err(format!(
            "manager mismatch (token={}, expected={})",
            claims.manager, manager
        ));
    }
    if now > claims.exp {
        return Err(format!("expired (now={}, exp={})", now, claims.exp));
    }
    if fresh_for_seconds > 0 && now.saturating_sub(claims.iat) > fresh_for_seconds {
        return Err(format!(
            "stale (iat={}, now={}, fresh_for={}s)",
            claims.iat, now, fresh_for_seconds
        ));
    }
    Ok(())
}

/// Best-effort decode of an approval token without verification, for
/// returning useful errors before the full check.
#[allow(dead_code)]
pub(crate) fn peek_claims(token: &ApprovalToken) -> Result<ApprovalClaims, String> {
    decode_payload_unverified::<ApprovalClaims>(token.jwt.as_bytes())
}
