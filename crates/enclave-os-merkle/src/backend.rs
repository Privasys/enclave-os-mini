// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Storage backends.
//!
//! The tree talks to storage through [`KvBackend`]: point get, atomic
//! write batch, and an ascending range scan — exactly the host KV OCALL
//! surface. [`OcallBackend`] is the production implementation (host
//! RocksDB via the OCALL vtable); [`MemBackend`] is an in-memory stand-in
//! for tests with read counting and tampering hooks.
//!
//! Node records are intentionally **plaintext** to the host (they hold
//! only hashes, versions and nibble offsets): that is what enables
//! host-side proving and host-executed pruning later. Integrity comes
//! from hash verification against the in-memory root on every read.

use enclave_os_common::rpc::KvBatchOp;

use crate::error::MerkleError;

pub trait KvBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError>;
    /// Apply all ops atomically: either every op lands or none does.
    fn write_batch(&self, ops: Vec<KvBatchOp>) -> Result<(), MerkleError>;
    /// Ascending scan over `[start, end)`; empty `end` = unbounded.
    fn scan(&self, start: &[u8], end: &[u8], limit: u32)
        -> Result<Vec<(Vec<u8>, Vec<u8>)>, MerkleError>;
}

// ---------------------------------------------------------------------------
//  OcallBackend — production, host RocksDB via the OCALL vtable
// ---------------------------------------------------------------------------

/// Production backend: one host RocksDB table (column family) named
/// `merkle:<store name>`, reached through the OCALL vtable.
#[derive(Clone)]
pub struct OcallBackend {
    table: Vec<u8>,
}

impl OcallBackend {
    pub fn new(store_name: &str) -> Self {
        let mut table = b"merkle:".to_vec();
        table.extend_from_slice(store_name.as_bytes());
        Self { table }
    }

    /// A backend over an explicit table name (no `merkle:` prefix) —
    /// for non-merkle consumers of the KV OCALLs (e.g. the raft log).
    pub fn with_table(table: &str) -> Self {
        Self { table: table.as_bytes().to_vec() }
    }
}

impl KvBackend for OcallBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        enclave_os_common::ocall::kv_store_get(&self.table, key).map_err(MerkleError::Backend)
    }

    fn write_batch(&self, ops: Vec<KvBatchOp>) -> Result<(), MerkleError> {
        enclave_os_common::ocall::kv_store_write_batch(&self.table, &ops)
            .map_err(MerkleError::Backend)
    }

    fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, MerkleError> {
        enclave_os_common::ocall::kv_store_scan(&self.table, start, end, limit)
            .map_err(MerkleError::Backend)
    }
}

// ---------------------------------------------------------------------------
//  MemBackend — tests
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// In-memory backend for tests: counts reads (I/O-complexity assertions)
/// and can tamper with stored records (fail-closed assertions).
#[derive(Default)]
pub struct MemBackend {
    map: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    reads: AtomicUsize,
}

impl MemBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of point reads served since construction or last reset.
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    pub fn reset_reads(&self) {
        self.reads.store(0, Ordering::Relaxed);
    }

    /// Number of records stored.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All record keys (for tamper sweeps).
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.map.lock().unwrap().keys().cloned().collect()
    }

    /// Flip one bit of the record at `key`. Returns false if absent.
    pub fn tamper(&self, key: &[u8]) -> bool {
        let mut map = self.map.lock().unwrap();
        match map.get_mut(key) {
            Some(v) if !v.is_empty() => {
                v[0] ^= 0x01;
                true
            }
            _ => false,
        }
    }

    /// Remove a record outright (host "loses" data).
    pub fn remove(&self, key: &[u8]) -> bool {
        self.map.lock().unwrap().remove(key).is_some()
    }
}

impl KvBackend for MemBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn write_batch(&self, ops: Vec<KvBatchOp>) -> Result<(), MerkleError> {
        let mut map = self.map.lock().unwrap();
        for op in ops {
            match op {
                KvBatchOp::Put { key, value } => {
                    map.insert(key, value);
                }
                KvBatchOp::Delete { key } => {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, MerkleError> {
        let limit = if limit == 0 { usize::MAX } else { limit as usize };
        let map = self.map.lock().unwrap();
        Ok(map
            .range(start.to_vec()..)
            .take_while(|(k, _)| end.is_empty() || k.as_slice() < end)
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}
