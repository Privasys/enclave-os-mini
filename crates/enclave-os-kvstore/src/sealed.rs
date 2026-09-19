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

/// Domain tag for value ciphertexts, differentiating them from key
/// ciphertexts. It is the prefix of the full AAD built by
/// [`SealedKvStore::value_aad`], which also binds the table and the key.
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
            .encrypt(value, &self.value_aad(&enc_key))
            .map_err(|e| format!("Value encryption failed: {}", e))?;

        ocall::kv_store_put(&self.table, &enc_key, &enc_val)
            .map_err(|e| format!("Host KV put failed: {}", e))
    }

    /// Get a value by key.
    ///
    /// A value authenticates only under the AAD of the slot it is read from.
    /// Values written before that binding, under `AAD_VALUE` alone, are
    /// refused like any other value that fails authentication: accepting them
    /// would let the host place a kept old-format ciphertext in any slot.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let enc_key = self.encrypt_key(key)?;

        match ocall::kv_store_get(&self.table, &enc_key) {
            Ok(Some(enc_val)) => self
                .cipher
                .decrypt(&enc_val, &self.value_aad(&enc_key))
                .map(Some)
                .map_err(|e| format!("Value decryption failed: {}", e)),
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

    /// AAD binding a value to the exact slot it was written to.
    ///
    /// `AAD_VALUE` alone distinguishes a value ciphertext from a key
    /// ciphertext, but not one key from another, nor one table from another.
    /// The host is the untrusted party here, and it chooses which stored bytes
    /// to return for a given lookup: without this binding it can move key A's
    /// value into key B's slot and the result decrypts and authenticates
    /// cleanly. `encrypt_key` is HMAC(master_key, key) with no table input, so
    /// the same plaintext key in two tables produces byte-identical stored
    /// keys -- which is why the table has to be bound too.
    ///
    /// The table is length-prefixed so that no pair of (table, key) values can
    /// produce the same AAD by shifting the boundary between them.
    fn value_aad(&self, enc_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_VALUE.len() + 4 + self.table.len() + enc_key.len());
        aad.extend_from_slice(AAD_VALUE);
        aad.extend_from_slice(&(self.table.len() as u32).to_be_bytes());
        aad.extend_from_slice(&self.table);
        aad.extend_from_slice(enc_key);
        aad
    }

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

/// Behaviour against an in-memory map standing in for the host, which chooses
/// what bytes each lookup returns.
#[cfg(test)]
mod tests {
    use super::*;
    use enclave_os_common::modules::AppIdentity;
    use enclave_os_common::ocall::{self, OcallVtable};
    use enclave_os_common::rpc::KvBatchOp;
    use std::collections::HashMap;
    use std::sync::{Mutex, Once};

    type Host = HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>;
    static HOST: Mutex<Option<Host>> = Mutex::new(None);
    static REGISTER: Once = Once::new();

    fn put(t: &[u8], k: &[u8], v: &[u8]) -> Result<(), i32> {
        let mut h = HOST.lock().unwrap();
        h.get_or_insert_with(HashMap::new).insert((t.to_vec(), k.to_vec()), v.to_vec());
        Ok(())
    }
    fn get(t: &[u8], k: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let h = HOST.lock().unwrap();
        Ok(h.as_ref().and_then(|m| m.get(&(t.to_vec(), k.to_vec())).cloned()))
    }
    fn unused<T>() -> Result<T, i32> {
        Err(-1)
    }

    const KEY: [u8; 32] = [7u8; 32];

    /// Each test uses its own table, so the shared map needs no reset.
    fn store(table: &str) -> SealedKvStore {
        REGISTER.call_once(|| {
            ocall::register(OcallVtable {
                net_tcp_listen: |_, _| unused(),
                net_tcp_accept: |_| unused(),
                net_tcp_connect: |_, _| unused(),
                net_send: |_, _| unused(),
                net_recv: |_, _| unused(),
                net_close: |_| {},
                net_udp_bind: |_, _| unused(),
                net_udp_send_to: |_, _, _, _| unused(),
                net_udp_recv_from: |_, _, _| unused(),
                net_udp_close: |_| {},
                kv_store_put: put,
                kv_store_get: get,
                kv_store_delete: |_, _| unused(),
                kv_store_list_keys: |_, _| unused(),
                kv_store_write_batch: |_, _: &[KvBatchOp]| unused(),
                kv_store_multi_get: |_, _| unused(),
                kv_store_scan: |_, _, _, _| unused(),
                get_current_time: || Ok(0),
                get_current_time_ms: || unused(),
                log: |_, _| {},
                cert_store_register: |_: AppIdentity| {},
                cert_store_unregister: |_| false,
            });
        });
        SealedKvStore::from_master_key_with_table(KEY, table.as_bytes())
    }

    fn host_get(s: &SealedKvStore, key: &[u8]) -> Vec<u8> {
        get(&s.table, &s.encrypt_key(key).unwrap()).unwrap().unwrap()
    }
    fn host_put(s: &SealedKvStore, key: &[u8], bytes: Vec<u8>) {
        put(&s.table, &s.encrypt_key(key).unwrap(), &bytes).unwrap();
    }

    #[test]
    fn a_value_round_trips() {
        let s = store("round-trip");
        s.put(b"a", b"alpha").unwrap();
        assert_eq!(s.get(b"a").unwrap(), Some(b"alpha".to_vec()));
        assert_eq!(s.get(b"missing").unwrap(), None);
    }

    #[test]
    fn a_value_moved_to_another_key_is_refused() {
        let s = store("move-key");
        s.put(b"a", b"alpha").unwrap();
        s.put(b"b", b"beta").unwrap();
        host_put(&s, b"b", host_get(&s, b"a"));
        assert!(s.get(b"b").is_err());
    }

    #[test]
    fn a_value_moved_to_another_table_is_refused() {
        let s1 = store("move-table-1");
        let s2 = store("move-table-2");
        s1.put(b"a", b"alpha").unwrap();
        host_put(&s2, b"a", host_get(&s1, b"a"));
        assert!(s2.get(b"a").is_err());
    }

    /// A ciphertext under the old unbound AAD, as a host may have kept it, is
    /// refused in any slot, including the one it was written to.
    #[test]
    fn an_old_format_value_is_refused() {
        let s = store("legacy");
        let old = s.cipher.encrypt(b"alpha", AAD_VALUE).unwrap();
        host_put(&s, b"a", old.clone());
        assert!(s.get(b"a").is_err());
        s.put(b"b", b"beta").unwrap();
        host_put(&s, b"b", old);
        assert!(s.get(b"b").is_err());
    }
}
