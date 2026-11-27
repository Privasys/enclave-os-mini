// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The vault's member key.
//!
//! The vault owns a single ECDSA-P256 key pair, generated lazily on first use
//! and stored sealed in the KV store under [`SIGNING_KEY_KV`]. Its public key
//! is the vault's identity: the member id is its hash (wire formats §3).
//!
//! The key never leaves the enclave.

use std::string::String;
use std::vec::Vec;

use enclave_os_kvstore::SealedKvStore;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// Sealed-KV key holding the vault's PKCS#8 ECDSA-P256 private key.
const SIGNING_KEY_KV: &[u8] = b"__vault_signing_key_pkcs8__";

/// Return the vault's member key, generating and persisting it on the first
/// call.
///
/// Caller must already hold the KV mutex.
pub(crate) fn load_or_init_keypair(store: &mut SealedKvStore) -> Result<EcdsaKeyPair, String> {
    let rng = SystemRandom::new();
    let pkcs8 = match store
        .get(SIGNING_KEY_KV)
        .map_err(|e| format!("kv get signing key: {e}"))?
    {
        Some(b) => b,
        None => {
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
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
pub(crate) fn load_or_init_public_key(store: &mut SealedKvStore) -> Result<Vec<u8>, String> {
    Ok(load_or_init_keypair(store)?.public_key().as_ref().to_vec())
}
