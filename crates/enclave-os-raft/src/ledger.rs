// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The Merkle-backed replicated state machine: seals forks into
//! transactions and applies committed transactions with fail-closed
//! root-transition verification.

use enclave_os_merkle::{KvBackend, MerkleError, MerkleFork, MerkleStore, SealedFork};

use crate::core::LedgerRoot;
use crate::transaction::Transaction;

/// Why applying a transaction failed.
#[derive(Debug)]
pub enum LedgerError {
    /// The ledger's current root does not match `root_before`, or the
    /// write-set does not produce `root_after`. Nothing was committed;
    /// this node has diverged from the log's history and must stop
    /// serving and repair via snapshot.
    RootMismatch { expected: LedgerRoot, found: LedgerRoot },
    /// Backend or crypto failure from the store (fail-closed reads,
    /// corrupt records, I/O errors).
    Store(MerkleError),
}

impl From<MerkleError> for LedgerError {
    fn from(e: MerkleError) -> Self {
        Self::Store(e)
    }
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RootMismatch { .. } => write!(f, "ledger root mismatch (divergence)"),
            Self::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

/// A [`MerkleStore`] driven as the cluster's replicated state machine.
pub struct MerkleLedger<B: KvBackend> {
    store: MerkleStore<B>,
}

impl<B: KvBackend> MerkleLedger<B> {
    pub fn new(store: MerkleStore<B>) -> Self {
        Self { store }
    }

    /// Current `(root, version)`.
    pub fn root(&self) -> (LedgerRoot, u64) {
        self.store.root()
    }

    /// Fork the ledger for transaction execution (leader side).
    pub fn fork(&mut self) -> MerkleFork<'_, B> {
        MerkleFork::new(&mut self.store)
    }

    /// Read-only access (serving reads at the committed root).
    pub fn store(&self) -> &MerkleStore<B> {
        &self.store
    }

    /// Escape hatch for repair tooling and tests. Ordinary appliers
    /// must go through [`Self::apply`].
    pub fn store_mut(&mut self) -> &mut MerkleStore<B> {
        &mut self.store
    }

    /// Apply a committed transaction, verifying the root transition.
    /// Fail-closed: on any mismatch NOTHING is committed (the write-set
    /// is previewed before it is applied), so a diverged node keeps its
    /// last consistent state for diagnosis and repair.
    pub fn apply(&mut self, txn: &Transaction) -> Result<(LedgerRoot, u64), LedgerError> {
        let (root_now, _) = self.store.root();
        if root_now != txn.root_before {
            return Err(LedgerError::RootMismatch {
                expected: txn.root_before,
                found: root_now,
            });
        }
        let (preview_root, preview_version) = self.store.preview_batch(&txn.ops)?;
        if preview_root != txn.root_after || preview_version != txn.version_after {
            return Err(LedgerError::RootMismatch {
                expected: txn.root_after,
                found: preview_root,
            });
        }
        let committed = self.store.put_batch(&txn.ops)?;
        debug_assert_eq!(committed, (preview_root, preview_version));
        Ok(committed)
    }
}

/// Seal a fork into an apply-mode transaction payload.
impl From<SealedFork> for Transaction {
    fn from(sealed: SealedFork) -> Self {
        Transaction {
            root_before: sealed.root_before,
            root_after: sealed.root_after,
            version_after: sealed.version_after,
            ops: sealed.ops,
        }
    }
}
