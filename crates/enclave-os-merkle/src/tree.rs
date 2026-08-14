// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The versioned sparse Merkle store.
//!
//! ## Commitments (encryption-independent root)
//!
//! - `path = HMAC-SHA256(ck, "p" ‖ key)` — 256-bit tree position.
//! - `vh   = HMAC-SHA256(ck, "v" ‖ path ‖ plaintext)` — value commitment.
//! - The root is a pure function of the logical state and `ck`: replicas
//!   sharing `ck` but holding different storage keys produce identical
//!   roots and compare state as `(version, root)`.
//!
//! Value bytes at rest are AES-256-GCM ciphertext under the per-machine
//! storage key; nodes are plaintext (hashes only) so the host can later
//! prove paths and execute pruning.
//!
//! ## Records (single host table, 1-byte prefix)
//!
//! | prefix | key | value |
//! |--------|-----|-------|
//! | `n` | NodeKey | node encoding |
//! | `v` | vh ‖ value_version u64 BE | GCM ciphertext |
//! | `s` | stale_since u64 BE ‖ target record key | empty |
//! | `r` | version u64 BE | root hash |
//! | `c` | (fixed) | GCM-encrypted `(root, version)` checkpoint, written
//!   atomically inside every commit batch |
//!
//! Node and value records are both versioned and immutable: a record is
//! written by exactly one commit and never again (re-inserting a value
//! after deleting it writes a *new* value record under the new
//! version). The pruner therefore deletes stale targets blindly.
//!
//! A commit lands all of the above in **one atomic** `write_batch`; only
//! after the host confirms does the in-memory `(root, version)` swing.
//!
//! ## Freshness
//!
//! `get` verifies every node against the in-memory root, so the host can
//! not roll live reads back. `get_at` authenticates content against the
//! *stored* root record for that version — the version→root binding for
//! history is host-held until the sealed root-history lands (WS4+).

use std::collections::BTreeMap;

use enclave_os_common::aead::AeadCipher;
use enclave_os_common::rpc::KvBatchOp;
use enclave_os_common::types::AEAD_KEY_SIZE;
use ring::hmac;

use crate::backend::KvBackend;
use crate::cache::NodeCache;
use crate::error::MerkleError;
use crate::hash::{placeholder, Hash, HASH_SIZE};
use crate::node::{nibble, subtree_hash, Child, InternalNode, LeafNode, Node, NodeKey};
use crate::proof::{verify, Proof, Verified};

const REC_NODE: u8 = b'n';
const REC_VALUE: u8 = b'v';
const REC_STALE: u8 = b's';
const REC_ROOT: u8 = b'r';
const REC_CHECKPOINT: u8 = b'c';

const HMAC_TAG_PATH: &[u8] = b"p";
const HMAC_TAG_VALUE: &[u8] = b"v";
const VALUE_AAD_TAG: &[u8] = b"enclave_os_merkle_val";
const CHECKPOINT_AAD: &[u8] = b"enclave_os_merkle_ckpt";

// ---------------------------------------------------------------------------
//  Record keys
// ---------------------------------------------------------------------------

fn node_record_key(nk: &NodeKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 9 + nk.prefix.len().div_ceil(2));
    k.push(REC_NODE);
    k.extend_from_slice(&nk.encode());
    k
}

fn value_record_key(vh: &Hash, value_version: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + HASH_SIZE + 8);
    k.push(REC_VALUE);
    k.extend_from_slice(vh);
    k.extend_from_slice(&value_version.to_be_bytes());
    k
}

fn stale_record_key(stale_since: u64, target_record_key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(9 + target_record_key.len());
    k.push(REC_STALE);
    k.extend_from_slice(&stale_since.to_be_bytes());
    k.extend_from_slice(target_record_key);
    k
}

fn root_record_key(version: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(REC_ROOT);
    k.extend_from_slice(&version.to_be_bytes());
    k
}

fn checkpoint_record_key() -> Vec<u8> {
    vec![REC_CHECKPOINT]
}

// ---------------------------------------------------------------------------
//  Store
// ---------------------------------------------------------------------------

/// Authenticated KV store. Single writer: mutation goes through
/// `&mut self`; wrap in a `Mutex` at the module layer.
pub struct MerkleStore<B: KvBackend> {
    backend: B,
    ck: hmac::Key,
    cipher: AeadCipher,
    root: Hash,
    version: u64,
    root_child: Option<Child>,
    cache: NodeCache,
}

/// Default node-cache capacity: ~10³ immutable node records (≈ a few
/// hundred KiB) keeps the top tree levels permanently warm.
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// One deduplicated update: `Some(vh)` = insert/overwrite, `None` = delete.
type Update = (Hash, Option<Hash>);

/// Records processed per prune scan/delete round trip.
const PRUNE_CHUNK: u32 = 512;

/// What a [`MerkleStore::prune`] call removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneStats {
    /// Stale-index entries processed (and removed).
    pub stale_entries: usize,
    /// Node + value records deleted.
    pub records_deleted: usize,
    /// Root records deleted.
    pub root_records_deleted: usize,
}

/// Work accumulated while applying a batch, flushed atomically.
struct CommitAcc {
    new_version: u64,
    /// Nodes written this commit (may be revised by leaf collapse).
    pending: BTreeMap<NodeKey, Node>,
    /// Record keys superseded this commit. Both node and value records
    /// are versioned and never rewritten, so the pruner deletes them
    /// blindly.
    stale: Vec<Vec<u8>>,
    /// Ciphertexts for this batch's inserts, by path; consumed when the
    /// insert actually lands as a new leaf.
    insert_cts: BTreeMap<Hash, Vec<u8>>,
    /// Value records to write this commit: vh → ciphertext (all at
    /// `new_version`).
    values: BTreeMap<Hash, Vec<u8>>,
}

impl<B: KvBackend> MerkleStore<B> {
    /// Create a fresh, empty store (version 0, placeholder root).
    pub fn create(
        backend: B,
        commitment_key: [u8; AEAD_KEY_SIZE],
        storage_key: [u8; AEAD_KEY_SIZE],
    ) -> Result<Self, MerkleError> {
        let store = Self {
            backend,
            ck: hmac::Key::new(hmac::HMAC_SHA256, &commitment_key),
            cipher: AeadCipher::from_key(storage_key),
            root: *placeholder(),
            version: 0,
            root_child: None,
            cache: NodeCache::new(DEFAULT_CACHE_CAPACITY),
        };
        store.backend.write_batch(vec![
            KvBatchOp::Put { key: root_record_key(0), value: placeholder().to_vec() },
            KvBatchOp::Put {
                key: checkpoint_record_key(),
                value: store.encrypt_checkpoint(placeholder(), 0)?,
            },
        ])?;
        Ok(store)
    }

    /// Open an existing store at a trusted `(root, version)` checkpoint
    /// (e.g. unsealed at enclave start). Verifies the backend actually
    /// holds that root before returning; fails closed otherwise.
    pub fn open(
        backend: B,
        commitment_key: [u8; AEAD_KEY_SIZE],
        storage_key: [u8; AEAD_KEY_SIZE],
        root: Hash,
        version: u64,
    ) -> Result<Self, MerkleError> {
        let mut store = Self {
            backend,
            ck: hmac::Key::new(hmac::HMAC_SHA256, &commitment_key),
            cipher: AeadCipher::from_key(storage_key),
            root,
            version,
            root_child: None,
            cache: NodeCache::new(DEFAULT_CACHE_CAPACITY),
        };
        store.root_child = store.load_root_child(root, version)?;
        Ok(store)
    }

    /// Open at the checkpoint record the store itself maintains (written
    /// atomically inside every commit batch, AES-256-GCM under the
    /// storage key). The host cannot forge it — at worst it can replay
    /// an old checkpoint *together with* a matching old store, the
    /// documented restart-replay residual risk. Prefer sealing
    /// `root()` externally when an extra anchor is available.
    pub fn open_latest(
        backend: B,
        commitment_key: [u8; AEAD_KEY_SIZE],
        storage_key: [u8; AEAD_KEY_SIZE],
    ) -> Result<Self, MerkleError> {
        let cipher = AeadCipher::from_key(storage_key);
        let record = backend
            .get(&checkpoint_record_key())?
            .ok_or_else(|| MerkleError::Missing("checkpoint record".into()))?;
        let (root, version) = decrypt_checkpoint(&cipher, &record)?;
        Self::open(backend, commitment_key, storage_key, root, version)
    }

    /// Open an existing store, or create a fresh one if no checkpoint
    /// exists yet. The constructor modules use.
    pub fn open_or_create(
        backend: B,
        commitment_key: [u8; AEAD_KEY_SIZE],
        storage_key: [u8; AEAD_KEY_SIZE],
    ) -> Result<Self, MerkleError> {
        let exists = backend.get(&checkpoint_record_key())?.is_some();
        if exists {
            Self::open_latest(backend, commitment_key, storage_key)
        } else {
            Self::create(backend, commitment_key, storage_key)
        }
    }

    fn encrypt_checkpoint(&self, root: &Hash, version: u64) -> Result<Vec<u8>, MerkleError> {
        let mut payload = Vec::with_capacity(HASH_SIZE + 8);
        payload.extend_from_slice(root);
        payload.extend_from_slice(&version.to_be_bytes());
        self.cipher
            .encrypt(&payload, CHECKPOINT_AAD)
            .map_err(|e| MerkleError::Corrupted(format!("checkpoint encrypt: {e}")))
    }

    /// Current `(root, version)`. Seal this pair after every commit.
    pub fn root(&self) -> (Hash, u64) {
        (self.root, self.version)
    }

    /// Borrow the backend (tests, diagnostics).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Resize the node cache (0 disables). Clears current contents.
    pub fn set_cache_capacity(&self, capacity: usize) {
        self.cache.set_capacity(capacity);
    }

    /// Consume the store, returning the backend (restart tests).
    pub fn into_backend(self) -> B {
        self.backend
    }

    // -- reads ------------------------------------------------------------

    /// Get the value for `key` at the current version.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        let path = self.path_of(key);
        self.walk(self.root_child.clone(), &path)
    }

    /// The root hash recorded for a historical `version` (same
    /// freshness caveat as [`Self::get_at`]).
    pub fn root_at(&self, version: u64) -> Result<Hash, MerkleError> {
        if version > self.version {
            return Err(MerkleError::Invalid(format!(
                "version {version} is in the future (current {})",
                self.version
            )));
        }
        self.load_root_record(version)
    }

    /// Get the value for `key` at a historical `version`.
    ///
    /// Content is authenticated against the stored root record for that
    /// version; see the module docs for the freshness caveat on history.
    pub fn get_at(&self, version: u64, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        if version > self.version {
            return Err(MerkleError::Invalid(format!(
                "version {version} is in the future (current {})",
                self.version
            )));
        }
        let root = self.load_root_record(version)?;
        let root_child = self.load_root_child(root, version)?;
        let path = self.path_of(key);
        self.walk(root_child, &path)
    }

    // -- writes -----------------------------------------------------------

    /// The pure computation shared by [`Self::put_batch`] and
    /// [`Self::preview_batch`]: dedupe, commit/encrypt values, fold the
    /// updates into the tree. Returns `None` for a no-op batch. Never
    /// mutates the store — all effects live in the returned accumulator.
    fn compute_batch(
        &mut self,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<Option<(CommitAcc, Option<Child>, Hash)>, MerkleError> {
        let new_version = self.version + 1;

        // Deduplicate (last wins) and sort by path via the BTreeMap.
        let mut deduped: BTreeMap<Hash, Option<&[u8]>> = BTreeMap::new();
        for (key, value) in ops {
            deduped.insert(self.path_of(key), value.as_deref());
        }
        if deduped.is_empty() {
            return Ok(None);
        }

        let mut acc = CommitAcc {
            new_version,
            pending: BTreeMap::new(),
            stale: Vec::new(),
            insert_cts: BTreeMap::new(),
            values: BTreeMap::new(),
        };

        // Precompute commitments and ciphertexts for inserts. Value
        // records are only written when an insert actually lands as a
        // new leaf (see `put_leaf`), so no-op overwrites leave no
        // orphaned records behind.
        let mut updates: Vec<Update> = Vec::with_capacity(deduped.len());
        for (path, value) in &deduped {
            match value {
                Some(pt) => {
                    let vh = self.vh_of(path, pt);
                    let ct = self
                        .cipher
                        .encrypt(pt, &value_aad(path))
                        .map_err(|e| MerkleError::Corrupted(format!("encrypt: {e}")))?;
                    acc.insert_cts.insert(*path, ct);
                    updates.push((*path, Some(vh)));
                }
                None => updates.push((*path, None)),
            }
        }

        let new_root_child =
            self.apply_subtree(&mut acc, self.root_child.clone(), &mut Vec::new(), &updates)?;

        if new_root_child == self.root_child {
            return Ok(None); // no-op batch
        }

        let new_root = match &new_root_child {
            Some(c) => c.hash,
            None => *placeholder(),
        };
        Ok(Some((acc, new_root_child, new_root)))
    }

    /// Compute the `(root, version)` this batch WOULD produce, without
    /// committing anything. The tree math is pure, so a later
    /// [`Self::put_batch`] with the same ops from the same state
    /// produces exactly this result. This is what a transaction fork
    /// uses to seal `root_after` before consensus decides the commit.
    pub fn preview_batch(
        &mut self,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(Hash, u64), MerkleError> {
        match self.compute_batch(ops)? {
            Some((_, _, new_root)) => Ok((new_root, self.version + 1)),
            None => Ok((self.root, self.version)),
        }
    }

    /// Apply a batch of operations as one commit: `(key, Some(value))`
    /// puts, `(key, None)` deletes. Later ops win over earlier ops on the
    /// same key. Returns the new `(root, version)`.
    ///
    /// If the batch changes nothing (deletes of absent keys, overwrites
    /// with identical values), no commit happens and the current
    /// `(root, version)` is returned unchanged.
    pub fn put_batch(
        &mut self,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(Hash, u64), MerkleError> {
        let Some((acc, new_root_child, new_root)) = self.compute_batch(ops)? else {
            return Ok((self.root, self.version)); // no-op batch
        };

        let new_version = acc.new_version;

        // Assemble the atomic commit.
        let mut batch: Vec<KvBatchOp> = Vec::with_capacity(
            acc.pending.len() + acc.values.len() + acc.stale.len() + 1,
        );
        for (nk, node) in &acc.pending {
            batch.push(KvBatchOp::Put { key: node_record_key(nk), value: node.encode() });
        }
        for (vh, ct) in &acc.values {
            batch.push(KvBatchOp::Put {
                key: value_record_key(vh, new_version),
                value: ct.clone(),
            });
        }
        for target in &acc.stale {
            batch.push(KvBatchOp::Put {
                key: stale_record_key(new_version, target),
                value: Vec::new(),
            });
        }
        batch.push(KvBatchOp::Put { key: root_record_key(new_version), value: new_root.to_vec() });
        batch.push(KvBatchOp::Put {
            key: checkpoint_record_key(),
            value: self.encrypt_checkpoint(&new_root, new_version)?,
        });

        self.backend.write_batch(batch)?;

        // Only after the host confirmed: swing the in-memory state and
        // warm the cache with this commit's nodes (root and top levels
        // are the hottest records in the store).
        for (nk, node) in acc.pending {
            self.cache.put(nk, node);
        }
        self.root = new_root;
        self.version = new_version;
        self.root_child = new_root_child;
        Ok((self.root, self.version))
    }

    // -- pruning ----------------------------------------------------------

    /// Delete storage needed only by versions strictly before
    /// `before_version`: stale records that died at or before it, and
    /// root records below it. Afterwards `get_at`/`prove_at` keep
    /// working for every version `>= before_version` and fail with
    /// [`MerkleError::Missing`] below it. The live tree is never
    /// touched — both node and value records are versioned and never
    /// rewritten, so stale targets are deleted blindly.
    ///
    /// Costs are proportional to accumulated garbage, not store size.
    /// Idempotent; safe to re-run after a partial failure.
    pub fn prune(&mut self, before_version: u64) -> Result<PruneStats, MerkleError> {
        if before_version > self.version {
            return Err(MerkleError::Invalid(format!(
                "cannot prune to future version {before_version} (current {})",
                self.version
            )));
        }
        let mut stats = PruneStats::default();

        // Deleted history must not linger in the cache.
        self.cache.clear();

        // Stale entries with stale_since <= before_version. Each entry's
        // key embeds the target record key; both die in one batch.
        let start = [REC_STALE];
        let end = match before_version.checked_add(1) {
            Some(v) => {
                let mut e = vec![REC_STALE];
                e.extend_from_slice(&v.to_be_bytes());
                e
            }
            None => vec![REC_STALE + 1],
        };
        loop {
            let entries = self.backend.scan(&start, &end, PRUNE_CHUNK)?;
            if entries.is_empty() {
                break;
            }
            let full_chunk = entries.len() == PRUNE_CHUNK as usize;
            let mut batch = Vec::with_capacity(entries.len() * 2);
            for (key, _) in entries {
                if key.len() < 10 {
                    return Err(MerkleError::Corrupted("stale entry key too short".into()));
                }
                batch.push(KvBatchOp::Delete { key: key[9..].to_vec() });
                batch.push(KvBatchOp::Delete { key });
                stats.stale_entries += 1;
                stats.records_deleted += 1;
            }
            self.backend.write_batch(batch)?;
            if !full_chunk {
                break;
            }
        }

        // Root records below the horizon.
        let start = [REC_ROOT];
        let mut end = vec![REC_ROOT];
        end.extend_from_slice(&before_version.to_be_bytes());
        loop {
            let entries = self.backend.scan(&start, &end, PRUNE_CHUNK)?;
            if entries.is_empty() {
                break;
            }
            let full_chunk = entries.len() == PRUNE_CHUNK as usize;
            let batch: Vec<KvBatchOp> = entries
                .into_iter()
                .map(|(key, _)| {
                    stats.root_records_deleted += 1;
                    KvBatchOp::Delete { key }
                })
                .collect();
            self.backend.write_batch(batch)?;
            if !full_chunk {
                break;
            }
        }

        Ok(stats)
    }

    /// Prune so that (at least) the last `window` versions stay
    /// readable: `prune(version - window)`, clamped at zero.
    pub fn retain_recent(&mut self, window: u64) -> Result<PruneStats, MerkleError> {
        self.prune(self.version.saturating_sub(window))
    }

    // -- proofs -----------------------------------------------------------

    /// Prove presence or absence of `key` at the current root.
    pub fn prove(&self, key: &[u8]) -> Result<Proof, MerkleError> {
        self.prove_path(self.root_child.clone(), &self.path_of(key))
    }

    /// Prove presence or absence of `key` at a historical `version`
    /// (same freshness caveat as [`Self::get_at`]).
    pub fn prove_at(&self, version: u64, key: &[u8]) -> Result<Proof, MerkleError> {
        if version > self.version {
            return Err(MerkleError::Invalid(format!(
                "version {version} is in the future (current {})",
                self.version
            )));
        }
        let root = self.load_root_record(version)?;
        let root_child = self.load_root_child(root, version)?;
        self.prove_path(root_child, &self.path_of(key))
    }

    /// Check a proof claiming `key` = `value` against `root`.
    /// Ok(false) = the proof is valid but proves something else
    /// (absence, or a different value).
    pub fn verify_value(
        &self,
        root: &Hash,
        key: &[u8],
        value: &[u8],
        proof: &Proof,
    ) -> Result<bool, MerkleError> {
        let path = self.path_of(key);
        Ok(match verify(root, &path, proof)? {
            Verified::Present(vh) => vh == self.vh_of(&path, value),
            Verified::Absent => false,
        })
    }

    /// Check a proof claiming `key` is absent at `root`.
    pub fn verify_absent(
        &self,
        root: &Hash,
        key: &[u8],
        proof: &Proof,
    ) -> Result<bool, MerkleError> {
        let path = self.path_of(key);
        Ok(matches!(verify(root, &path, proof)?, Verified::Absent))
    }

    /// Walk the tree for `path`, collecting binary sibling hashes.
    fn prove_path(
        &self,
        root_child: Option<Child>,
        path: &Hash,
    ) -> Result<Proof, MerkleError> {
        let mut siblings: Vec<Hash> = Vec::new(); // collected top-down
        let mut child = match root_child {
            Some(c) => c,
            None => return Ok(Proof { leaf: None, siblings }),
        };
        let mut prefix: Vec<u8> = Vec::new();

        let leaf: Option<LeafNode> = 'walk: loop {
            let nk = NodeKey { version: child.version, prefix: prefix.clone() };
            let node = self.load_node(&nk, &child.hash)?;
            if node.is_leaf() != child.is_leaf {
                return Err(MerkleError::Corrupted(format!("node {nk:?} kind mismatch")));
            }
            let internal = match node {
                // Terminal: the resident leaf (inclusion if paths match,
                // otherwise absence evidence).
                Node::Leaf(leaf) => break 'walk Some(leaf),
                Node::Internal(n) => n,
            };

            // Binary descent inside this 16-slot node, mirroring
            // `subtree_hash`: collect the off-path half at every level.
            let slot = nibble(path, prefix.len()) as usize;
            let mut start = 0usize;
            let mut width = 16usize;
            loop {
                let present: Vec<usize> = (start..start + width)
                    .filter(|i| internal.children[*i].is_some())
                    .collect();
                match present.as_slice() {
                    [] => break 'walk None, // empty range: absence
                    [idx] => {
                        let c = internal.children[*idx].clone().expect("present");
                        if c.is_leaf {
                            // The range collapses to this leaf; it covers
                            // the proven path's position here (inclusion
                            // if it sits at `slot` with equal path).
                            let mut leaf_prefix = prefix.clone();
                            leaf_prefix.push(*idx as u8);
                            let lk = NodeKey { version: c.version, prefix: leaf_prefix };
                            match self.load_node(&lk, &c.hash)? {
                                Node::Leaf(leaf) => break 'walk Some(leaf),
                                Node::Internal(_) => {
                                    return Err(MerkleError::Corrupted(format!(
                                        "node {lk:?} kind mismatch"
                                    )))
                                }
                            }
                        }
                        if width == 1 {
                            // Singleton range holding an internal child:
                            // descend one nibble deeper.
                            debug_assert_eq!(*idx, slot);
                            prefix.push(slot as u8);
                            child = c;
                            continue 'walk;
                        }
                    }
                    _ => debug_assert!(width > 1),
                }
                // Halve towards the slot, collecting the other half.
                let half = width / 2;
                let (ours, sib) = if slot < start + half {
                    (start, start + half)
                } else {
                    (start + half, start)
                };
                siblings.push(subtree_hash(&internal.children, sib, half));
                start = ours;
                width = half;
            }
        };

        siblings.reverse(); // bottom-up, as the verifier folds
        Ok(Proof { leaf: leaf.map(|l| (l.path, l.vh)), siblings })
    }

    // -- internals: commitments -------------------------------------------

    fn path_of(&self, key: &[u8]) -> Hash {
        let mut ctx = hmac::Context::with_key(&self.ck);
        ctx.update(HMAC_TAG_PATH);
        ctx.update(key);
        let tag = ctx.sign();
        let mut out = [0u8; HASH_SIZE];
        out.copy_from_slice(tag.as_ref());
        out
    }

    fn vh_of(&self, path: &Hash, plaintext: &[u8]) -> Hash {
        let mut ctx = hmac::Context::with_key(&self.ck);
        ctx.update(HMAC_TAG_VALUE);
        ctx.update(path);
        ctx.update(plaintext);
        let tag = ctx.sign();
        let mut out = [0u8; HASH_SIZE];
        out.copy_from_slice(tag.as_ref());
        out
    }

    // -- internals: loading -----------------------------------------------

    fn load_node(&self, nk: &NodeKey, expected_hash: &Hash) -> Result<Node, MerkleError> {
        // The cache removes host I/O only — cached nodes are re-verified
        // against the caller's expected hash exactly like loaded ones.
        if let Some(node) = self.cache.get(nk) {
            if &node.hash() != expected_hash {
                return Err(MerkleError::Corrupted(format!("node {nk:?} hash mismatch")));
            }
            return Ok(node);
        }
        let record = self
            .backend
            .get(&node_record_key(nk))?
            .ok_or_else(|| MerkleError::Missing(format!("node {nk:?}")))?;
        let node = Node::decode(&record)?;
        if &node.hash() != expected_hash {
            return Err(MerkleError::Corrupted(format!("node {nk:?} hash mismatch")));
        }
        self.cache.put(nk.clone(), node.clone());
        Ok(node)
    }

    fn load_root_record(&self, version: u64) -> Result<Hash, MerkleError> {
        let rec = self
            .backend
            .get(&root_record_key(version))?
            .ok_or_else(|| MerkleError::Missing(format!("root record v{version}")))?;
        rec.as_slice()
            .try_into()
            .map_err(|_| MerkleError::Corrupted(format!("root record v{version} bad length")))
    }

    /// Resolve the root child for a `(root, version)` pair, verifying the
    /// root node exists and hashes correctly. `None` for the empty tree.
    fn load_root_child(&self, root: Hash, version: u64) -> Result<Option<Child>, MerkleError> {
        if root == *placeholder() {
            return Ok(None);
        }
        let node = self.load_node(&NodeKey::root(version), &root)?;
        Ok(Some(Child { version, hash: root, is_leaf: node.is_leaf() }))
    }

    fn read_value(
        &self,
        path: &Hash,
        vh: &Hash,
        value_version: u64,
    ) -> Result<Vec<u8>, MerkleError> {
        let ct = self
            .backend
            .get(&value_record_key(vh, value_version))?
            .ok_or_else(|| MerkleError::Missing("value record".into()))?;
        let pt = self
            .cipher
            .decrypt(&ct, &value_aad(path))
            .map_err(|e| MerkleError::Corrupted(format!("value decrypt: {e}")))?;
        if &self.vh_of(path, &pt) != vh {
            return Err(MerkleError::Corrupted("value commitment mismatch".into()));
        }
        Ok(pt)
    }

    fn walk(
        &self,
        root_child: Option<Child>,
        path: &Hash,
    ) -> Result<Option<Vec<u8>>, MerkleError> {
        let mut child = match root_child {
            Some(c) => c,
            None => return Ok(None),
        };
        let mut prefix: Vec<u8> = Vec::new();
        loop {
            let nk = NodeKey { version: child.version, prefix: prefix.clone() };
            let node = self.load_node(&nk, &child.hash)?;
            if node.is_leaf() != child.is_leaf {
                return Err(MerkleError::Corrupted(format!("node {nk:?} kind mismatch")));
            }
            match node {
                Node::Leaf(leaf) => {
                    if &leaf.path == path {
                        return Ok(Some(self.read_value(
                            path,
                            &leaf.vh,
                            leaf.value_version,
                        )?));
                    }
                    return Ok(None);
                }
                Node::Internal(internal) => {
                    let nib = nibble(path, prefix.len());
                    match &internal.children[nib as usize] {
                        None => return Ok(None),
                        Some(c) => {
                            prefix.push(nib);
                            child = c.clone();
                        }
                    }
                }
            }
        }
    }

    // -- internals: batch apply -------------------------------------------

    /// Apply the (sorted) updates that fall inside the subtree at
    /// `prefix`, returning the subtree's new child reference (`None` =
    /// empty). Returns `old` untouched when nothing changed.
    fn apply_subtree(
        &self,
        acc: &mut CommitAcc,
        old: Option<Child>,
        prefix: &mut Vec<u8>,
        updates: &[Update],
    ) -> Result<Option<Child>, MerkleError> {
        if updates.is_empty() {
            return Ok(old);
        }

        let old_child = match old {
            None => {
                // Empty subtree: only inserts materialise anything.
                let pairs: Vec<(Hash, Hash, u64)> = updates
                    .iter()
                    .filter_map(|(p, vh)| vh.map(|h| (*p, h, acc.new_version)))
                    .collect();
                return self.build_from_pairs(acc, prefix, &pairs);
            }
            Some(c) => c,
        };

        let nk = NodeKey { version: old_child.version, prefix: prefix.clone() };
        let node = self.load_node(&nk, &old_child.hash)?;
        if node.is_leaf() != old_child.is_leaf {
            return Err(MerkleError::Corrupted(format!("node {nk:?} kind mismatch")));
        }

        match node {
            Node::Leaf(leaf) => {
                // Merge the resident leaf with the updates. Entries are
                // (vh, value_version): an overwrite with the identical
                // value keeps the old record, anything else routes to a
                // record written this commit.
                let mut merged: BTreeMap<Hash, (Hash, u64)> = BTreeMap::new();
                merged.insert(leaf.path, (leaf.vh, leaf.value_version));
                for (p, vh) in updates {
                    match vh {
                        Some(h) => {
                            let vv = if *p == leaf.path && *h == leaf.vh {
                                leaf.value_version
                            } else {
                                acc.new_version
                            };
                            merged.insert(*p, (*h, vv));
                        }
                        None => {
                            merged.remove(p);
                        }
                    }
                }
                if merged.len() == 1
                    && merged.get(&leaf.path) == Some(&(leaf.vh, leaf.value_version))
                {
                    return Ok(Some(old_child)); // nothing changed
                }
                // The resident leaf node is superseded in every changed case.
                acc.stale.push(node_record_key(&nk));
                match merged.get(&leaf.path) {
                    Some((vh, _)) if *vh == leaf.vh => {}
                    _ => acc.stale.push(value_record_key(&leaf.vh, leaf.value_version)),
                }
                let pairs: Vec<(Hash, Hash, u64)> = merged
                    .into_iter()
                    .map(|(p, (vh, vv))| (p, vh, vv))
                    .collect();
                self.build_from_pairs(acc, prefix, &pairs)
            }
            Node::Internal(internal) => {
                let depth = prefix.len();
                let mut children = internal.children.clone();
                let mut changed = false;

                // Updates are sorted by path, so nibble groups are
                // contiguous slices.
                let mut i = 0;
                while i < updates.len() {
                    let nib = nibble(&updates[i].0, depth);
                    let mut j = i + 1;
                    while j < updates.len() && nibble(&updates[j].0, depth) == nib {
                        j += 1;
                    }
                    prefix.push(nib);
                    let new_child = self.apply_subtree(
                        acc,
                        children[nib as usize].clone(),
                        prefix,
                        &updates[i..j],
                    )?;
                    prefix.pop();
                    if new_child != children[nib as usize] {
                        children[nib as usize] = new_child;
                        changed = true;
                    }
                    i = j;
                }

                if !changed {
                    return Ok(Some(old_child));
                }
                acc.stale.push(node_record_key(&nk));

                let mut present = children.iter().flatten();
                match (present.next().cloned(), present.next()) {
                    (None, _) => Ok(None), // subtree emptied
                    (Some(only), None) if only.is_leaf => {
                        // Collapse: the lone surviving leaf rises here.
                        let nib = children
                            .iter()
                            .position(|c| c.is_some())
                            .expect("child present") as u8;
                        prefix.push(nib);
                        let leaf = self.take_leaf(acc, &only, prefix)?;
                        prefix.pop();
                        Ok(Some(self.put_leaf(acc, prefix, leaf)?))
                    }
                    _ => {
                        let new_node = Node::Internal(InternalNode { children });
                        let hash = new_node.hash();
                        acc.pending
                            .insert(NodeKey { version: acc.new_version, prefix: prefix.clone() }, new_node);
                        Ok(Some(Child { version: acc.new_version, hash, is_leaf: false }))
                    }
                }
            }
        }
    }

    /// Build a fresh subtree at `prefix` from sorted
    /// `(path, vh, value_version)` pairs.
    fn build_from_pairs(
        &self,
        acc: &mut CommitAcc,
        prefix: &mut Vec<u8>,
        pairs: &[(Hash, Hash, u64)],
    ) -> Result<Option<Child>, MerkleError> {
        match pairs {
            [] => Ok(None),
            [(path, vh, vv)] => Ok(Some(self.put_leaf(
                acc,
                prefix,
                LeafNode { path: *path, vh: *vh, value_version: *vv },
            )?)),
            _ => {
                let depth = prefix.len();
                let mut children: [Option<Child>; 16] = Default::default();
                let mut i = 0;
                while i < pairs.len() {
                    let nib = nibble(&pairs[i].0, depth);
                    let mut j = i + 1;
                    while j < pairs.len() && nibble(&pairs[j].0, depth) == nib {
                        j += 1;
                    }
                    prefix.push(nib);
                    children[nib as usize] = self.build_from_pairs(acc, prefix, &pairs[i..j])?;
                    prefix.pop();
                    i = j;
                }
                let node = Node::Internal(InternalNode { children });
                let hash = node.hash();
                acc.pending
                    .insert(NodeKey { version: acc.new_version, prefix: prefix.clone() }, node);
                Ok(Some(Child { version: acc.new_version, hash, is_leaf: false }))
            }
        }
    }

    /// Store a leaf node at `prefix` (new version) and return its child
    /// ref. A leaf whose value was (re)written this commit also emits
    /// its value record.
    fn put_leaf(
        &self,
        acc: &mut CommitAcc,
        prefix: &[u8],
        leaf: LeafNode,
    ) -> Result<Child, MerkleError> {
        if leaf.value_version == acc.new_version && !acc.values.contains_key(&leaf.vh) {
            let ct = acc.insert_cts.get(&leaf.path).ok_or_else(|| {
                MerkleError::Corrupted("internal: landed insert without ciphertext".into())
            })?;
            acc.values.insert(leaf.vh, ct.clone());
        }
        let node = Node::Leaf(leaf);
        let hash = node.hash();
        acc.pending
            .insert(NodeKey { version: acc.new_version, prefix: prefix.to_vec() }, node);
        Ok(Child { version: acc.new_version, hash, is_leaf: true })
    }

    /// Fetch the content of a leaf child at `prefix` so it can be
    /// re-homed (collapse). If it was written this very commit it is
    /// removed from the pending set (never persisted); otherwise its
    /// stored record is marked stale.
    fn take_leaf(
        &self,
        acc: &mut CommitAcc,
        child: &Child,
        prefix: &[u8],
    ) -> Result<LeafNode, MerkleError> {
        let nk = NodeKey { version: child.version, prefix: prefix.to_vec() };
        if child.version == acc.new_version {
            match acc.pending.remove(&nk) {
                Some(Node::Leaf(leaf)) => Ok(leaf),
                other => Err(MerkleError::Corrupted(format!(
                    "pending leaf {nk:?} missing or wrong kind ({other:?})"
                ))),
            }
        } else {
            match self.load_node(&nk, &child.hash)? {
                Node::Leaf(leaf) => {
                    acc.stale.push(node_record_key(&nk));
                    Ok(leaf)
                }
                Node::Internal(_) => {
                    Err(MerkleError::Corrupted(format!("node {nk:?} kind mismatch")))
                }
            }
        }
    }
}

fn value_aad(path: &Hash) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VALUE_AAD_TAG.len() + HASH_SIZE);
    aad.extend_from_slice(VALUE_AAD_TAG);
    aad.extend_from_slice(path);
    aad
}

fn decrypt_checkpoint(cipher: &AeadCipher, record: &[u8]) -> Result<(Hash, u64), MerkleError> {
    let payload = cipher
        .decrypt(record, CHECKPOINT_AAD)
        .map_err(|e| MerkleError::Corrupted(format!("checkpoint decrypt: {e}")))?;
    if payload.len() != HASH_SIZE + 8 {
        return Err(MerkleError::Corrupted("checkpoint bad length".into()));
    }
    let mut root = [0u8; HASH_SIZE];
    root.copy_from_slice(&payload[..HASH_SIZE]);
    let version = u64::from_be_bytes(
        payload[HASH_SIZE..].try_into().map_err(|_| MerkleError::Corrupted("checkpoint version".into()))?,
    );
    Ok((root, version))
}
