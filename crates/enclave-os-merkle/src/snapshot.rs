// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Snapshot restore: rebuild a store from streamed `(path, value)`
//! leaves, verify it lands on the advertised root, and stamp it at the
//! advertised version.
//!
//! The serving peer iterates its tree with
//! [`MerkleStore::snapshot_leaves`] and ships plaintext values over the
//! mutual-TLS peer link; the receiver re-encrypts under its OWN storage
//! key while the shared commitment key makes the rebuilt root equal the
//! advertised one — cross-key state transfer with end-to-end
//! verification, no shared storage keys ever.
//!
//! v1 applies the whole leaf set as ONE commit (transfer is chunked,
//! apply is not), so peak memory is proportional to store size; chunked
//! application with version offsetting is a later optimisation.

use crate::backend::KvBackend;
use crate::error::MerkleError;
use crate::hash::Hash;
use crate::tree::MerkleStore;

/// Accumulates streamed snapshot leaves, then builds and verifies the
/// restored store in one shot.
pub struct SnapshotBuilder<B: KvBackend> {
    store: MerkleStore<B>,
    leaves: Vec<(Hash, Vec<u8>)>,
}

impl<B: KvBackend> SnapshotBuilder<B> {
    /// Start a restore over a FRESH store (creates version 0 in the
    /// given backend; any previous contents become unreachable).
    pub fn new(
        backend: B,
        commitment_key: [u8; 32],
        storage_key: [u8; 32],
    ) -> Result<Self, MerkleError> {
        let store = MerkleStore::create(backend, commitment_key, storage_key)?;
        Ok(Self { store, leaves: Vec::new() })
    }

    /// Add a streamed chunk of `(path, plaintext value)` leaves.
    pub fn add_leaves(&mut self, chunk: Vec<(Hash, Vec<u8>)>) {
        self.leaves.extend(chunk);
    }

    /// Leaves accumulated so far.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Apply everything, verify the rebuilt root equals
    /// `expected_root`, and stamp the store at `version`. Fails closed
    /// (nothing usable is produced) on any mismatch.
    pub fn finalize(
        mut self,
        expected_root: Hash,
        version: u64,
    ) -> Result<MerkleStore<B>, MerkleError> {
        let leaves = std::mem::take(&mut self.leaves);
        let (root, built_version) = self.store.put_batch_by_path(&leaves)?;
        if root != expected_root {
            return Err(MerkleError::Corrupted(
                "snapshot root mismatch: stream does not reproduce the advertised state".into(),
            ));
        }
        if version < built_version {
            return Err(MerkleError::Invalid(format!(
                "snapshot version {version} below build version {built_version}"
            )));
        }
        self.store.stamp_version(version)?;
        Ok(self.store)
    }
}
