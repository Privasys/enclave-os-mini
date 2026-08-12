// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Authenticated key-value store for enclave-os — a versioned sparse
//! Merkle tree (16-ary storage, binary hashing) over the host KV store.
//!
//! One 32-byte root attests the entire logical data state. The root is
//! **encryption-independent**: it commits to keyed plaintext hashes
//! (`HMAC-SHA256` under a commitment key `ck`), while value bytes at
//! rest are AES-256-GCM ciphertext under a separate per-machine storage
//! key. Replicas sharing `ck` compare state as `(version, root)`
//! regardless of their storage keys.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use enclave_os_merkle::{MerkleStore, OcallBackend};
//!
//! // Keys come from the enclave's sealed config (generated on first
//! // run, sealed with MRENCLAVE policy).
//! let backend = OcallBackend::new("mystore");
//! let mut store = MerkleStore::create(backend, ck, sk)?;
//!
//! let (root, version) = store.put_batch(&[
//!     (b"alice".to_vec(), Some(b"1000".to_vec())),
//!     (b"bob".to_vec(),   Some(b"250".to_vec())),
//! ])?;
//! // Seal (root, version) as the freshness checkpoint, then on restart:
//! // MerkleStore::open(backend, ck, sk, root, version)
//!
//! assert_eq!(store.get(b"alice")?, Some(b"1000".to_vec()));
//! store.put_batch(&[(b"alice".to_vec(), None)])?; // delete
//! ```
//!
//! Reads fail closed: any record that does not verify against the
//! in-memory root (node hashes, GCM tags, value commitments) is an
//! error, never data.

mod backend;
mod cache;
mod error;
mod hash;
mod module;
mod node;
mod proof;
mod tree;

#[cfg(test)]
mod tests;

pub use backend::{KvBackend, MemBackend, OcallBackend};
pub use error::MerkleError;
pub use hash::{Hash, HASH_SIZE};
pub use module::MerkleModule;
pub use proof::{verify, Proof, Verified};
pub use tree::{MerkleStore, PruneStats};
