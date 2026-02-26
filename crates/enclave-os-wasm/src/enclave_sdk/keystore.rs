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

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair};

use wasmtime::component::{Linker, Val};
use wasmtime::StoreContextMut;

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

    /// Check if a key with the given name exists.
    pub fn exists(&self, name: &str) -> bool {
        self.keys.contains_key(name)
    }

    /// Retrieve a symmetric key by name.  Returns `None` if absent or wrong type.
    pub fn get_symmetric(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Symmetric(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Retrieve a signing key (PKCS#8) by name.  Returns `None` if absent or wrong type.
    pub fn get_signing(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Signing(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Retrieve an HMAC key by name.  Returns `None` if absent or wrong type.
    pub fn get_hmac(&self, name: &str) -> Option<Vec<u8>> {
        match self.keys.get(name) {
            Some(KeyMaterial::Hmac(k)) => Some(k.clone()),
            _ => None,
        }
    }

    /// Insert or overwrite a symmetric key.
    pub fn insert_symmetric(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Symmetric(key));
    }

    /// Insert or overwrite a signing key (PKCS#8).
    pub fn insert_signing(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Signing(key));
    }

    /// Insert or overwrite an HMAC key.
    pub fn insert_hmac(&mut self, name: String, key: Vec<u8>) {
        self.keys.insert(name, KeyMaterial::Hmac(key));
    }

    /// Remove a key by name.  Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.keys.remove(name).is_some()
    }

    /// Get a clone of the raw key material by name (for sealing/persistence).
    pub fn get_raw(&self, name: &str) -> Option<KeyMaterial> {
        self.keys.get(name).cloned()
    }

    /// Number of keys in the store.
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
//  privasys:enclave-os/keystore@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/keystore@0.1.0")?;

    // ── generate-symmetric-key ─────────────────────────────────────
    // func(key-name: string) -> result<_, string>
    inst.func_new(
        "generate-symmetric-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            if name.is_empty() {
                results[0] = err_result("key name cannot be empty");
                return Ok(());
            }
            if store.data().keystore.exists(&name) {
                results[0] = err_result("key already exists");
                return Ok(());
            }

            let rng = SystemRandom::new();
            let mut key_bytes = [0u8; 32]; // AES-256
            match rng.fill(&mut key_bytes) {
                Ok(()) => {
                    store
                        .data_mut()
                        .keystore
                        .insert_symmetric(name, key_bytes.to_vec());
                    results[0] = ok_unit();
                }
                Err(_) => {
                    results[0] = err_result("RNG failed");
                }
            }
            Ok(())
        },
    )?;

    // ── generate-signing-key ───────────────────────────────────────
    // func(key-name: string, algorithm: u32) -> result<_, string>
    //   algorithm: 0=ECDSA-P256-SHA256, 1=ECDSA-P384-SHA384
    inst.func_new(
        "generate-signing-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };

            if name.is_empty() {
                results[0] = err_result("key name cannot be empty");
                return Ok(());
            }
            if store.data().keystore.exists(&name) {
                results[0] = err_result("key already exists");
                return Ok(());
            }

            let signing_algo = match algo {
                0 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                1 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => {
                    results[0] = err_result("unsupported algorithm");
                    return Ok(());
                }
            };

            let rng = SystemRandom::new();
            let pkcs8 = match EcdsaKeyPair::generate_pkcs8(signing_algo, &rng) {
                Ok(p) => p,
                Err(_) => {
                    results[0] = err_result("key generation failed");
                    return Ok(());
                }
            };

            store
                .data_mut()
                .keystore
                .insert_signing(name, pkcs8.as_ref().to_vec());
            results[0] = ok_unit();
            Ok(())
        },
    )?;

    // ── generate-hmac-key ──────────────────────────────────────────
    // func(key-name: string, algorithm: u32) -> result<_, string>
    //   algorithm: 0=HMAC-SHA256 (32B), 1=HMAC-SHA384 (48B), 2=HMAC-SHA512 (64B)
    inst.func_new(
        "generate-hmac-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };

            if name.is_empty() {
                results[0] = err_result("key name cannot be empty");
                return Ok(());
            }
            if store.data().keystore.exists(&name) {
                results[0] = err_result("key already exists");
                return Ok(());
            }

            let key_len = match algo {
                0 => 32usize,  // SHA-256 block = 64, key = 32 is standard
                1 => 48usize,  // SHA-384
                2 => 64usize,  // SHA-512
                _ => {
                    results[0] = err_result("unsupported HMAC algorithm");
                    return Ok(());
                }
            };

            let rng = SystemRandom::new();
            let mut key_bytes = vec![0u8; key_len];
            match rng.fill(&mut key_bytes) {
                Ok(()) => {
                    store.data_mut().keystore.insert_hmac(name, key_bytes);
                    results[0] = ok_unit();
                }
                Err(_) => {
                    results[0] = err_result("RNG failed");
                }
            }
            Ok(())
        },
    )?;

    // ── import-symmetric-key ───────────────────────────────────────
    // func(key-name: string, raw-key: list<u8>) -> result<_, string>
    inst.func_new(
        "import-symmetric-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            let raw_key = val_to_bytes(&params[1]);

            if name.is_empty() {
                results[0] = err_result("key name cannot be empty");
                return Ok(());
            }
            if store.data().keystore.exists(&name) {
                results[0] = err_result("key already exists");
                return Ok(());
            }
            if raw_key.len() != 32 {
                results[0] = err_result("AES-256 key must be exactly 32 bytes");
                return Ok(());
            }

            store.data_mut().keystore.insert_symmetric(name, raw_key);
            results[0] = ok_unit();
            Ok(())
        },
    )?;

    // ── export-public-key ──────────────────────────────────────────
    // func(key-name: string) -> result<list<u8>, string>
    inst.func_new(
        "export-public-key",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);

            let pkcs8 = match store.data().keystore.get_signing(&name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not a signing key");
                    return Ok(());
                }
            };

            // Try P-256 first, then P-384.
            let rng = SystemRandom::new();
            let public_key = if let Ok(kp) = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &pkcs8,
                &rng,
            ) {
                kp.public_key().as_ref().to_vec()
            } else if let Ok(kp) = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &pkcs8,
                &rng,
            ) {
                kp.public_key().as_ref().to_vec()
            } else {
                results[0] = err_result("failed to extract public key");
                return Ok(());
            };

            results[0] = ok_bytes(&public_key);
            Ok(())
        },
    )?;

    // ── delete-key ─────────────────────────────────────────────────
    // func(key-name: string) -> result<_, string>
    inst.func_new(
        "delete-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            if store.data_mut().keystore.remove(&name) {
                results[0] = ok_unit();
            } else {
                results[0] = err_result("key not found");
            }
            Ok(())
        },
    )?;

    // ── key-exists ─────────────────────────────────────────────────
    // func(key-name: string) -> result<bool, string>
    inst.func_new(
        "key-exists",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);
            let exists = store.data().keystore.exists(&name);
            results[0] = ok_bool(exists);
            Ok(())
        },
    )?;

    // ── persist-key ────────────────────────────────────────────────
    // func(key-name: string) -> result<_, string>
    //
    // Seals the key material with MRENCLAVE policy and stores the
    // ciphertext in the host KV store under the app's namespace.
    inst.func_new(
        "persist-key",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);

            // Serialize the key material.
            let material = match store.data().keystore.get_raw(&name) {
                Some(m) => m,
                None => {
                    results[0] = err_result("key not found");
                    return Ok(());
                }
            };
            let encoded = serialize_key_material(&material);
            // Store in host KV (encrypted by sealed_kv).
            let kv_key = format!("{}{}", KEY_KV_DOMAIN, name);
            match store.data().sealed_kv.put(kv_key.as_bytes(), &encoded) {
                Ok(()) => {
                    results[0] = ok_unit();
                }
                Err(_) => {
                    results[0] = err_result("KV store write failed");
                }
            }
            Ok(())
        },
    )?;

    // ── load-key ───────────────────────────────────────────────────
    // func(key-name: string) -> result<_, string>
    //
    // Loads a previously persisted key from the host KV store,
    // unseals it, and inserts it into the in-memory KeyStore.
    inst.func_new(
        "load-key",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let name = val_to_string(&params[0]);

            if store.data().keystore.exists(&name) {
                results[0] = err_result("key already exists in memory");
                return Ok(());
            }

            // Read encrypted blob from host KV (decrypted by sealed_kv).
            let kv_key = format!("{}{}", KEY_KV_DOMAIN, name);
            let encoded = match store.data().sealed_kv.get(kv_key.as_bytes()) {
                Ok(Some(data)) => data,
                Ok(None) => {
                    results[0] = err_result("no persisted key with that name");
                    return Ok(());
                }
                Err(_) => {
                    results[0] = err_result("KV store read failed");
                    return Ok(());
                }
            };

            // Deserialize and insert into KeyStore.
            match deserialize_key_material(&encoded) {
                Some(KeyMaterial::Symmetric(k)) => {
                    store.data_mut().keystore.insert_symmetric(name, k);
                    results[0] = ok_unit();
                }
                Some(KeyMaterial::Signing(k)) => {
                    store.data_mut().keystore.insert_signing(name, k);
                    results[0] = ok_unit();
                }
                Some(KeyMaterial::Hmac(k)) => {
                    store.data_mut().keystore.insert_hmac(name, k);
                    results[0] = ok_unit();
                }
                None => {
                    results[0] = err_result("corrupted key data");
                }
            }
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  Val helpers
// =========================================================================

fn val_to_string(val: &Val) -> String {
    match val {
        Val::String(s) => s.to_string(),
        _ => String::new(),
    }
}

fn val_to_bytes(val: &Val) -> Vec<u8> {
    match val {
        Val::List(items) => items
            .iter()
            .filter_map(|v| match v {
                Val::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn ok_unit() -> Val {
    Val::Result(Ok(None))
}

fn ok_bytes(data: &[u8]) -> Val {
    Val::Result(Ok(Some(Box::new(Val::List(
        data.iter().map(|b| Val::U8(*b)).collect::<Vec<_>>().into(),
    )))))
}

fn ok_bool(v: bool) -> Val {
    Val::Result(Ok(Some(Box::new(Val::Bool(v)))))
}

fn err_result(msg: &str) -> Val {
    Val::Result(Err(Some(Box::new(Val::String(msg.into())))))
}
