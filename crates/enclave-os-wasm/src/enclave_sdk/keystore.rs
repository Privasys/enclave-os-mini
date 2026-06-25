// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/keystore@0.1.0` — Key management inside SGX.
//!
//! Keys are generated using `ring`'s `SystemRandom` (backed by RDRAND in
//! SGX), stored in-memory by name, and optionally persisted via the sealed
//! KV store.  Key material **never** leaves the enclave unencrypted.
//!
//! ## Key types
//!
//! | Type | Material | Usage |
//! |------|----------|-------|
//! | Symmetric | 32 random bytes | AES-256-GCM encrypt/decrypt |
//! | Signing | ECDSA PKCS#8 | sign/verify (P-256, P-384) |
//! | HMAC | 32/48/64 random bytes | HMAC-SHA-256/384/512 |
//!
//! The generated bindings (`Host` trait, algorithm enums) come from the
//! single `bindgen!` invocation in [`super::crypto`] — the `keystore`
//! interface `use`s crypto's `sign-algorithm` / `hmac-algorithm`, so the two
//! share one type set. This module only implements the [`Host`] trait.
//!
//! [`Host`]: super::crypto::keystore_wit::Host

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair};

use wasmtime::component::{HasSelf, Linker};

use super::crypto::{crypto_wit, keystore_wit};
use super::AppContext;

/// KV domain prefix for persisted key material.
const KEY_KV_DOMAIN: &str = "key:";
// =========================================================================
//  Key material types
// =========================================================================

/// Classification of key material stored in the keystore.
#[derive(Clone, Debug)]
pub enum KeyMaterial {
    /// Raw symmetric key bytes (32 bytes for AES-256).
    Symmetric(Vec<u8>),
    /// PKCS#8-encoded ECDSA key pair (P-256 or P-384).
    Signing(Vec<u8>),
    /// Raw HMAC key bytes (32/48/64 bytes depending on algorithm).
    Hmac(Vec<u8>),
}

/// In-memory key store that lives inside the enclave.
///
/// All key material remains in enclave memory and is never exposed
/// to the untrusted host.  Keys are referenced by name from WASM apps.
#[derive(Clone, Debug)]
pub struct KeyStore {
    keys: BTreeMap<String, KeyMaterial>,
}

impl KeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Whether a key with the given name exists.
    pub fn exists(&self, name: &str) -> bool {
        self.keys.contains_key(name)
    }

    /// Get raw bytes of a symmetric key, if present and of that type.
    pub fn get_symmetric(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Symmetric(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Get PKCS#8 bytes of a signing key, if present and of that type.
    pub fn get_signing(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Signing(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Get raw bytes of an HMAC key, if present and of that type.
    pub fn get_hmac(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Hmac(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Insert a symmetric key.
    pub fn insert_symmetric(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Symmetric(key));
    }

    /// Insert a signing key (PKCS#8).
    pub fn insert_signing(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Signing(key));
    }

    /// Insert an HMAC key.
    pub fn insert_hmac(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Hmac(key));
    }

    /// Remove a key; returns whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.keys.remove(name).is_some()
    }

    /// Get a clone of the raw key material (for persistence).
    pub fn get_raw(&self, name: &str) -> Option<KeyMaterial> {
        self.keys.get(name).cloned()
    }

    /// Number of keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

// =========================================================================
//  Key material serialization (for persist / load)
// =========================================================================

/// Serialize a [`KeyMaterial`] into a tagged byte vector.
///
/// Format: `[1 byte type tag][key bytes]`
///   - `0x01` = Symmetric
///   - `0x02` = Signing (PKCS#8)
///   - `0x03` = HMAC
fn serialize_key_material(material: &KeyMaterial) -> Vec<u8> {
    match material {
        KeyMaterial::Symmetric(k) => {
            let mut out = Vec::with_capacity(1 + k.len());
            out.push(0x01);
            out.extend_from_slice(k);
            out
        }
        KeyMaterial::Signing(k) => {
            let mut out = Vec::with_capacity(1 + k.len());
            out.push(0x02);
            out.extend_from_slice(k);
            out
        }
        KeyMaterial::Hmac(k) => {
            let mut out = Vec::with_capacity(1 + k.len());
            out.push(0x03);
            out.extend_from_slice(k);
            out
        }
    }
}

/// Deserialize a tagged byte vector back into [`KeyMaterial`].
fn deserialize_key_material(data: &[u8]) -> Option<KeyMaterial> {
    if data.is_empty() {
        return None;
    }
    let key_bytes = data[1..].to_vec();
    match data[0] {
        0x01 => Some(KeyMaterial::Symmetric(key_bytes)),
        0x02 => Some(KeyMaterial::Signing(key_bytes)),
        0x03 => Some(KeyMaterial::Hmac(key_bytes)),
        _ => None,
    }
}

// =========================================================================
//  Host trait implementation — privasys:enclave-os/keystore@0.1.0
// =========================================================================

impl keystore_wit::Host for AppContext {
    fn generate_symmetric_key(&mut self, key_name: String) -> Result<(), String> {
        if key_name.is_empty() {
            return Err("key name cannot be empty".into());
        }
        if self.keystore.exists(&key_name) {
            return Err("key already exists".into());
        }

        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32]; // AES-256
        rng.fill(&mut key_bytes).map_err(|_| "RNG failed".to_string())?;
        self.keystore.insert_symmetric(key_name, key_bytes.to_vec());
        Ok(())
    }

    fn generate_signing_key(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::SignAlgorithm,
    ) -> Result<(), String> {
        if key_name.is_empty() {
            return Err("key name cannot be empty".into());
        }
        if self.keystore.exists(&key_name) {
            return Err("key already exists".into());
        }

        let signing_algo = match algorithm {
            crypto_wit::SignAlgorithm::EcdsaP256Sha256 => {
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING
            }
            crypto_wit::SignAlgorithm::EcdsaP384Sha384 => {
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING
            }
        };

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing_algo, &rng)
            .map_err(|_| "key generation failed".to_string())?;
        self.keystore
            .insert_signing(key_name, pkcs8.as_ref().to_vec());
        Ok(())
    }

    fn generate_hmac_key(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::HmacAlgorithm,
    ) -> Result<(), String> {
        if key_name.is_empty() {
            return Err("key name cannot be empty".into());
        }
        if self.keystore.exists(&key_name) {
            return Err("key already exists".into());
        }

        let key_len = match algorithm {
            crypto_wit::HmacAlgorithm::HmacSha256 => 32usize, // SHA-256 key
            crypto_wit::HmacAlgorithm::HmacSha384 => 48usize, // SHA-384
            crypto_wit::HmacAlgorithm::HmacSha512 => 64usize, // SHA-512
        };

        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; key_len];
        rng.fill(&mut key_bytes).map_err(|_| "RNG failed".to_string())?;
        self.keystore.insert_hmac(key_name, key_bytes);
        Ok(())
    }

    fn import_symmetric_key(&mut self, key_name: String, raw_key: Vec<u8>) -> Result<(), String> {
        if key_name.is_empty() {
            return Err("key name cannot be empty".into());
        }
        if self.keystore.exists(&key_name) {
            return Err("key already exists".into());
        }
        if raw_key.len() != 32 {
            return Err("AES-256 key must be exactly 32 bytes".into());
        }

        self.keystore.insert_symmetric(key_name, raw_key);
        Ok(())
    }

    fn export_public_key(&mut self, key_name: String) -> Result<Vec<u8>, String> {
        let pkcs8 = self
            .keystore
            .get_signing(&key_name)
            .ok_or_else(|| "key not found or not a signing key".to_string())?;

        // Try P-256 first, then P-384.
        let rng = SystemRandom::new();
        let public_key = if let Ok(kp) =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
        {
            kp.public_key().as_ref().to_vec()
        } else if let Ok(kp) =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8, &rng)
        {
            kp.public_key().as_ref().to_vec()
        } else {
            return Err("failed to extract public key".into());
        };

        Ok(public_key)
    }

    fn delete_key(&mut self, key_name: String) -> Result<(), String> {
        if self.keystore.remove(&key_name) {
            Ok(())
        } else {
            Err("key not found".into())
        }
    }

    fn key_exists(&mut self, key_name: String) -> Result<bool, String> {
        Ok(self.keystore.exists(&key_name))
    }

    fn persist_key(&mut self, key_name: String) -> Result<(), String> {
        let material = self
            .keystore
            .get_raw(&key_name)
            .ok_or_else(|| "key not found".to_string())?;
        let encoded = serialize_key_material(&material);
        // Store in host KV (encrypted by sealed_kv).
        let kv_key = format!("{}{}", KEY_KV_DOMAIN, key_name);
        self.sealed_kv
            .put(kv_key.as_bytes(), &encoded)
            .map_err(|_| "KV store write failed".to_string())?;
        Ok(())
    }

    fn load_key(&mut self, key_name: String) -> Result<(), String> {
        if self.keystore.exists(&key_name) {
            return Err("key already exists in memory".into());
        }

        // Read encrypted blob from host KV (decrypted by sealed_kv).
        let kv_key = format!("{}{}", KEY_KV_DOMAIN, key_name);
        let encoded = match self.sealed_kv.get(kv_key.as_bytes()) {
            Ok(Some(data)) => data,
            Ok(None) => return Err("no persisted key with that name".into()),
            Err(_) => return Err("KV store read failed".into()),
        };

        // Deserialize and insert into KeyStore.
        match deserialize_key_material(&encoded) {
            Some(KeyMaterial::Symmetric(k)) => {
                self.keystore.insert_symmetric(key_name, k);
                Ok(())
            }
            Some(KeyMaterial::Signing(k)) => {
                self.keystore.insert_signing(key_name, k);
                Ok(())
            }
            Some(KeyMaterial::Hmac(k)) => {
                self.keystore.insert_hmac(key_name, k);
                Ok(())
            }
            None => Err("corrupted key data".into()),
        }
    }
}

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    keystore_wit::add_to_linker::<_, HasSelf<_>>(linker, |s| s)
}
