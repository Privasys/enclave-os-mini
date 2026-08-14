// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Transaction forks: run business logic against a virtual copy of the
//! store, then seal the result as `(root_before, write_set, root_after)`.
//!
//! A fork is a read-through overlay pinned at the store's current
//! `(root, version)`. Reads consult the buffered write-set first and
//! fall through to the store; writes only touch the buffer. Nothing is
//! persisted until the sealed write-set is applied via
//! [`MerkleStore::put_batch`] — which, from the same state, provably
//! produces the previewed root, because the tree math is pure.
//!
//! The fork holds `&mut` on the store, so no commit can interleave with
//! an open fork. That matches the cluster execution model: the leader
//! executes transactions serially in log order.

use std::collections::BTreeMap;

use crate::backend::KvBackend;
use crate::error::MerkleError;
use crate::hash::Hash;
use crate::tree::MerkleStore;

/// A pending, uncommitted transaction over a [`MerkleStore`].
pub struct MerkleFork<'a, B: KvBackend> {
    store: &'a mut MerkleStore<B>,
    root_before: Hash,
    version_before: u64,
    /// Buffered write-set: logical key → `Some(value)` (put) or `None`
    /// (delete). BTreeMap keeps the sealed write-set deterministic.
    overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

/// A sealed fork: the state transition a transaction proposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFork {
    pub root_before: Hash,
    pub version_before: u64,
    pub root_after: Hash,
    pub version_after: u64,
    /// The deterministic write-set (key-ordered).
    pub ops: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl<'a, B: KvBackend> MerkleFork<'a, B> {
    /// Fork the store at its current `(root, version)`.
    pub fn new(store: &'a mut MerkleStore<B>) -> Self {
        let (root_before, version_before) = store.root();
        Self { store, root_before, version_before, overlay: BTreeMap::new() }
    }

    /// The state this fork is based on.
    pub fn root_before(&self) -> (Hash, u64) {
        (self.root_before, self.version_before)
    }

    /// Read through the overlay, then the underlying store.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        if let Some(pending) = self.overlay.get(key) {
            return Ok(pending.clone());
        }
        self.store.get(key)
    }

    /// Buffer a put.
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.overlay.insert(key.to_vec(), Some(value.to_vec()));
    }

    /// Buffer a delete.
    pub fn delete(&mut self, key: &[u8]) {
        self.overlay.insert(key.to_vec(), None);
    }

    /// Number of buffered operations.
    pub fn pending_ops(&self) -> usize {
        self.overlay.len()
    }

    /// Seal the fork: compute `(root_after, version_after)` without
    /// committing, and hand back the deterministic write-set. Fails
    /// closed if the store moved underneath the fork (cannot happen
    /// while the fork holds the store borrow, but checked anyway).
    pub fn seal(self) -> Result<SealedFork, MerkleError> {
        let (root_now, version_now) = self.store.root();
        if (root_now, version_now) != (self.root_before, self.version_before) {
            return Err(MerkleError::Invalid(format!(
                "store moved under the fork (version {} != {})",
                version_now, self.version_before
            )));
        }
        let ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = self.overlay.into_iter().collect();
        let (root_after, version_after) = self.store.preview_batch(&ops)?;
        Ok(SealedFork {
            root_before: self.root_before,
            version_before: self.version_before,
            root_after,
            version_after,
            ops,
        })
    }
}

impl SealedFork {
    /// Is this transaction a no-op (empty or ineffective write-set)?
    pub fn is_noop(&self) -> bool {
        self.root_after == self.root_before
    }
}
