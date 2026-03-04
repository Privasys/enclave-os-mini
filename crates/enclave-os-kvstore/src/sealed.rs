// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Sealed key-value store.
//!
//! Both keys and values are encrypted inside the enclave using AES-256-GCM
//! before being stored on the host via OCALLs. The encryption key is:
//!
//! 1. Generated randomly on first use
//! 2. Sealed with SGX using MRENCLAVE policy (so only the exact same
//!    enclave binary can unseal it)
//! 3. Stored on the host as a sealed blob
//!
//! This ensures the host never sees plaintext keys or values, and the
//! encryption key is bound to the enclave's code identity.

use std::string::String;
use std::vec::Vec;

use enclave_os_common::aead::AeadCipher;
use enclave_os_common::ocall;
use enclave_os_common::types::AEAD_KEY_SIZE;

/// AAD (Additional Authenticated Data) tags to differentiate key vs value
/// ciphertexts and prevent cross-use.
const AAD_VALUE: &[u8] = b"enclave_os_kv_val";

/// Default KV table for the sealed KV store module.
const KVSTORE_TABLE: &[u8] = b"kvstore";

/// Sealed KV store. Encrypts everything before passing to host.
pub struct SealedKvStore {
    cipher: AeadCipher,
    /// RocksDB column family (table) for this store's data.
    table: Vec<u8>,
}

impl SealedKvStore {
    /// Create a sealed KV store from an externally-provided master key.
    ///
    /// The master key is part of the unified [`SealedConfig`] and is
    /// generated on first run, then persisted across restarts via SGX
    /// sealing.
    pub fn from_master_key(key: [u8; AEAD_KEY_SIZE]) -> Self {
        Self {
            cipher: AeadCipher::from_key(key),
            table: KVSTORE_TABLE.to_vec(),
        }
    }

    /// Create a sealed KV store with a custom table name.
    pub fn from_master_key_with_table(key: [u8; AEAD_KEY_SIZE], table: &[u8]) -> Self {
        Self {
            cipher: AeadCipher::from_key(key),
            table: table.to_vec(),
        }
    }

    /// Put a key-value pair. Both key and value are encrypted before
    /// being sent to the host.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        let enc_key = self.encrypt_key(key)?;
        let enc_val = self.cipher
            .encrypt(value, AAD_VALUE)
            .map_err(|e| format!("Value encryption failed: {}", e))?;

        ocall::kv_store_put(&self.table, &enc_key, &enc_val)
            .map_err(|e| format!("Host KV put failed: {}", e))
    }

    /// Get a value by key.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let enc_key = self.encrypt_key(key)?;

        match ocall::kv_store_get(&self.table, &enc_key) {
            Ok(Some(enc_val)) => {
                let plaintext = self.cipher
                    .decrypt(&enc_val, AAD_VALUE)
                    .map_err(|e| format!("Value decryption failed: {}", e))?;
                Ok(Some(plaintext))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Host KV get failed: {}", e)),
        }
    }

    /// Delete a key-value pair.
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, String> {
        let enc_key = self.encrypt_key(key)?;
        ocall::kv_store_delete(&self.table, &enc_key)
            .map_err(|e| format!("Host KV delete failed: {}", e))
    }

    // ---- Internal helpers ----

    /// Encrypt a key deterministically using HMAC-SHA256.
    ///
    /// We need deterministic encryption for keys so that the same plaintext
    /// key always maps to the same encrypted key (for lookups). We use
    /// HMAC-SHA256(master_key, plaintext_key) as the encrypted key.
    fn encrypt_key(&self, key: &[u8]) -> Result<Vec<u8>, String> {
        use ring::hmac;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, self.cipher.key_bytes());
        let tag = hmac::sign(&hmac_key, key);
        Ok(tag.as_ref().to_vec())
    }
}
