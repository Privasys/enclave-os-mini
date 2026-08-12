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
//! | `v` | vh | GCM ciphertext |
//! | `s` | stale_since u64 BE ‖ target record key | node: empty, value: path |
//! | `r` | version u64 BE | root hash |
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
use crate::error::MerkleError;
use crate::hash::{placeholder, Hash, HASH_SIZE};
use crate::node::{nibble, Child, InternalNode, LeafNode, Node, NodeKey};

const REC_NODE: u8 = b'n';
const REC_VALUE: u8 = b'v';
const REC_STALE: u8 = b's';
const REC_ROOT: u8 = b'r';

const HMAC_TAG_PATH: &[u8] = b"p";
const HMAC_TAG_VALUE: &[u8] = b"v";
const VALUE_AAD_TAG: &[u8] = b"enclave_os_merkle_val";

// ---------------------------------------------------------------------------
//  Record keys
// ---------------------------------------------------------------------------

fn node_record_key(nk: &NodeKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 9 + nk.prefix.len().div_ceil(2));
    k.push(REC_NODE);
    k.extend_from_slice(&nk.encode());
    k
}

fn value_record_key(vh: &Hash) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + HASH_SIZE);
    k.push(REC_VALUE);
    k.extend_from_slice(vh);
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
}

/// One deduplicated update: `Some(vh)` = insert/overwrite, `None` = delete.
type Update = (Hash, Option<Hash>);

/// Work accumulated while applying a batch, flushed atomically.
struct CommitAcc {
    new_version: u64,
    /// Nodes written this commit (may be revised by leaf collapse).
    pending: BTreeMap<NodeKey, Node>,
    /// Record keys superseded this commit (nodes; deleted blindly at prune).
    stale_nodes: Vec<Vec<u8>>,
    /// Superseded value commitments with their path (prune re-checks
    /// liveness via the path before deleting — a later commit may have
    /// re-inserted the same (path, value) and thus the same record).
    stale_values: Vec<(Hash, Hash)>, // (vh, path)
    /// Value records to write: vh → ciphertext.
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
        };
        store.backend.write_batch(vec![KvBatchOp::Put {
            key: root_record_key(0),
            value: placeholder().to_vec(),
        }])?;
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
        };
        store.root_child = store.load_root_child(root, version)?;
        Ok(store)
    }

    /// Current `(root, version)`. Seal this pair after every commit.
    pub fn root(&self) -> (Hash, u64) {
        (self.root, self.version)
    }

    /// Borrow the backend (tests, diagnostics).
    pub fn backend(&self) -> &B {
        &self.backend
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
        let new_version = self.version + 1;

        // Deduplicate (last wins) and sort by path via the BTreeMap.
        let mut deduped: BTreeMap<Hash, Option<&[u8]>> = BTreeMap::new();
        for (key, value) in ops {
            deduped.insert(self.path_of(key), value.as_deref());
        }
        if deduped.is_empty() {
            return Ok((self.root, self.version));
        }

        let mut acc = CommitAcc {
            new_version,
            pending: BTreeMap::new(),
            stale_nodes: Vec::new(),
            stale_values: Vec::new(),
            values: BTreeMap::new(),
        };

        // Precompute commitments and ciphertexts for inserts.
        let mut updates: Vec<Update> = Vec::with_capacity(deduped.len());
        for (path, value) in &deduped {
            match value {
                Some(pt) => {
                    let vh = self.vh_of(path, pt);
                    let ct = self
                        .cipher
                        .encrypt(pt, &value_aad(path))
                        .map_err(|e| MerkleError::Corrupted(format!("encrypt: {e}")))?;
                    acc.values.insert(vh, ct);
                    updates.push((*path, Some(vh)));
                }
                None => updates.push((*path, None)),
            }
        }

        let new_root_child =
            self.apply_subtree(&mut acc, self.root_child.clone(), &mut Vec::new(), &updates)?;

        if new_root_child == self.root_child {
            return Ok((self.root, self.version)); // no-op batch
        }

        let new_root = match &new_root_child {
            Some(c) => c.hash,
            None => *placeholder(),
        };

        // Assemble the atomic commit.
        let mut batch: Vec<KvBatchOp> = Vec::with_capacity(
            acc.pending.len() + acc.values.len() + acc.stale_nodes.len()
                + acc.stale_values.len() + 1,
        );
        for (nk, node) in &acc.pending {
            batch.push(KvBatchOp::Put { key: node_record_key(nk), value: node.encode() });
        }
        for (vh, ct) in &acc.values {
            batch.push(KvBatchOp::Put { key: value_record_key(vh), value: ct.clone() });
        }
        for target in &acc.stale_nodes {
            batch.push(KvBatchOp::Put {
                key: stale_record_key(new_version, target),
                value: Vec::new(),
            });
        }
        for (vh, path) in &acc.stale_values {
            batch.push(KvBatchOp::Put {
                key: stale_record_key(new_version, &value_record_key(vh)),
                value: path.to_vec(),
            });
        }
        batch.push(KvBatchOp::Put { key: root_record_key(new_version), value: new_root.to_vec() });

        self.backend.write_batch(batch)?;

        // Only after the host confirmed: swing the in-memory state.
        self.root = new_root;
        self.version = new_version;
        self.root_child = new_root_child;
        Ok((self.root, self.version))
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
        let record = self
            .backend
            .get(&node_record_key(nk))?
            .ok_or_else(|| MerkleError::Missing(format!("node {nk:?}")))?;
        let node = Node::decode(&record)?;
        if &node.hash() != expected_hash {
            return Err(MerkleError::Corrupted(format!("node {nk:?} hash mismatch")));
        }
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

    fn read_value(&self, path: &Hash, vh: &Hash) -> Result<Vec<u8>, MerkleError> {
        let ct = self
            .backend
            .get(&value_record_key(vh))?
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
                        return Ok(Some(self.read_value(path, &leaf.vh)?));
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
                let pairs: Vec<(Hash, Hash)> = updates
                    .iter()
                    .filter_map(|(p, vh)| vh.map(|h| (*p, h)))
                    .collect();
                return Ok(self.build_from_pairs(acc, prefix, &pairs));
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
                // Merge the resident leaf with the updates.
                let mut merged: BTreeMap<Hash, Hash> = BTreeMap::new();
                merged.insert(leaf.path, leaf.vh);
                for (p, vh) in updates {
                    match vh {
                        Some(h) => {
                            merged.insert(*p, *h);
                        }
                        None => {
                            merged.remove(p);
                        }
                    }
                }
                if merged.len() == 1
                    && merged.get(&leaf.path) == Some(&leaf.vh)
                {
                    return Ok(Some(old_child)); // nothing changed
                }
                // The resident leaf node is superseded in every changed case.
                acc.stale_nodes.push(node_record_key(&nk));
                match merged.get(&leaf.path) {
                    Some(vh) if *vh == leaf.vh => {}
                    _ => acc.stale_values.push((leaf.vh, leaf.path)),
                }
                let pairs: Vec<(Hash, Hash)> = merged.into_iter().collect();
                Ok(self.build_from_pairs(acc, prefix, &pairs))
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
                acc.stale_nodes.push(node_record_key(&nk));

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
                        Ok(Some(self.put_leaf(acc, prefix, leaf)))
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

    /// Build a fresh subtree at `prefix` from sorted `(path, vh)` pairs.
    fn build_from_pairs(
        &self,
        acc: &mut CommitAcc,
        prefix: &mut Vec<u8>,
        pairs: &[(Hash, Hash)],
    ) -> Option<Child> {
        match pairs {
            [] => None,
            [(path, vh)] => Some(self.put_leaf(acc, prefix, LeafNode { path: *path, vh: *vh })),
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
                    children[nib as usize] = self.build_from_pairs(acc, prefix, &pairs[i..j]);
                    prefix.pop();
                    i = j;
                }
                let node = Node::Internal(InternalNode { children });
                let hash = node.hash();
                acc.pending
                    .insert(NodeKey { version: acc.new_version, prefix: prefix.clone() }, node);
                Some(Child { version: acc.new_version, hash, is_leaf: false })
            }
        }
    }

    /// Store a leaf node at `prefix` (new version) and return its child ref.
    fn put_leaf(&self, acc: &mut CommitAcc, prefix: &[u8], leaf: LeafNode) -> Child {
        let node = Node::Leaf(leaf);
        let hash = node.hash();
        acc.pending
            .insert(NodeKey { version: acc.new_version, prefix: prefix.to_vec() }, node);
        Child { version: acc.new_version, hash, is_leaf: true }
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
                    acc.stale_nodes.push(node_record_key(&nk));
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
