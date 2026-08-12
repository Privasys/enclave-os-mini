// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Tree node model: versioned node keys, internal/leaf nodes, binary
//! codecs and node hashing.
//!
//! Storage is 16-ary (one node per nibble level) but hashing is binary:
//! an internal node's hash is the root of a 4-level binary subtree over
//! its 16 child slots, with empty ranges standing in as the placeholder
//! hash and single-leaf ranges collapsing to the leaf hash. That keeps
//! I/O at log16 while proofs stay compact binary sibling lists.

use crate::error::MerkleError;
use crate::hash::{internal_hash, leaf_hash, placeholder, Hash, HASH_SIZE};

/// Total nibbles in a full path (256-bit path, 4 bits per nibble).
pub const NIBBLES: usize = 64;

/// Nibble `i` of a 32-byte path, MSB-first.
pub fn nibble(path: &Hash, i: usize) -> u8 {
    debug_assert!(i < NIBBLES);
    let byte = path[i / 2];
    if i % 2 == 0 {
        byte >> 4
    } else {
        byte & 0x0F
    }
}

// ---------------------------------------------------------------------------
//  NodeKey
// ---------------------------------------------------------------------------

/// Where a node lives: the version at which it was written plus its
/// position (nibble prefix) in the tree. Node records are immutable:
/// a commit writes new nodes under the new version and never mutates
/// old ones.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKey {
    pub version: u64,
    /// Nibble values (each 0..=15) from the root; empty = root node.
    pub prefix: Vec<u8>,
}

impl NodeKey {
    pub fn root(version: u64) -> Self {
        Self { version, prefix: Vec::new() }
    }

    pub fn child(&self, version: u64, nib: u8) -> Self {
        debug_assert!(nib < 16);
        let mut prefix = self.prefix.clone();
        prefix.push(nib);
        Self { version, prefix }
    }

    /// Encode as `version u64 BE ‖ nibble_count u8 ‖ packed nibbles`.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.prefix.len() <= NIBBLES);
        let mut buf = Vec::with_capacity(9 + self.prefix.len().div_ceil(2));
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.prefix.len() as u8);
        let mut i = 0;
        while i < self.prefix.len() {
            let hi = self.prefix[i] << 4;
            let lo = if i + 1 < self.prefix.len() { self.prefix[i + 1] } else { 0 };
            buf.push(hi | lo);
            i += 2;
        }
        buf
    }
}

// ---------------------------------------------------------------------------
//  Nodes
// ---------------------------------------------------------------------------

/// Reference to a child node held inside an internal node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// Version component of the child's [`NodeKey`].
    pub version: u64,
    /// The child node's hash; verified against the loaded record.
    pub hash: Hash,
    /// Whether the child is a leaf (needed for hashing and collapse).
    pub is_leaf: bool,
}

/// Internal node: up to 16 children, one per nibble value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InternalNode {
    pub children: [Option<Child>; 16],
}

/// Leaf node: terminates the path however deep it sits. `path` is the
/// full 256-bit key path; `vh` is the keyed plaintext commitment of the
/// value.
///
/// `value_version` is the commit version at which the value record was
/// written: it routes reads to the versioned value record
/// (`v ‖ vh ‖ value_version`). It is storage metadata, **not part of
/// the leaf hash** — the hash commits to `(path, vh)` only, so the root
/// stays a pure function of logical state. A tampered `value_version`
/// can only point at a missing record (fail closed) or at a record
/// whose content still has to satisfy `vh` (same plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNode {
    pub path: Hash,
    pub vh: Hash,
    pub value_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Internal(InternalNode),
    Leaf(LeafNode),
}

const NODE_TAG_INTERNAL: u8 = 1;
const NODE_TAG_LEAF: u8 = 2;

impl Node {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    /// Encode to the stored byte form.
    ///
    /// Leaf: `[2] path(32) vh(32) value_version u64 BE`.
    /// Internal: `[1] bitmap u16 LE { version u64 BE, hash(32), is_leaf u8 }*`
    /// with children serialized in ascending nibble order of set bits.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Leaf(leaf) => {
                let mut buf = Vec::with_capacity(1 + 2 * HASH_SIZE + 8);
                buf.push(NODE_TAG_LEAF);
                buf.extend_from_slice(&leaf.path);
                buf.extend_from_slice(&leaf.vh);
                buf.extend_from_slice(&leaf.value_version.to_be_bytes());
                buf
            }
            Node::Internal(node) => {
                let mut bitmap: u16 = 0;
                let mut count = 0;
                for (i, c) in node.children.iter().enumerate() {
                    if c.is_some() {
                        bitmap |= 1 << i;
                        count += 1;
                    }
                }
                let mut buf = Vec::with_capacity(3 + count * (8 + HASH_SIZE + 1));
                buf.push(NODE_TAG_INTERNAL);
                buf.extend_from_slice(&bitmap.to_le_bytes());
                for c in node.children.iter().flatten() {
                    buf.extend_from_slice(&c.version.to_be_bytes());
                    buf.extend_from_slice(&c.hash);
                    buf.push(c.is_leaf as u8);
                }
                buf
            }
        }
    }

    /// Decode a stored record. Strict: trailing bytes or malformed
    /// content are corruption, never ignored.
    pub fn decode(data: &[u8]) -> Result<Node, MerkleError> {
        let corrupt = |m: &str| MerkleError::Corrupted(format!("node decode: {m}"));
        match data.first() {
            Some(&NODE_TAG_LEAF) => {
                if data.len() != 1 + 2 * HASH_SIZE + 8 {
                    return Err(corrupt("bad leaf length"));
                }
                let mut path = [0u8; HASH_SIZE];
                let mut vh = [0u8; HASH_SIZE];
                path.copy_from_slice(&data[1..1 + HASH_SIZE]);
                vh.copy_from_slice(&data[1 + HASH_SIZE..1 + 2 * HASH_SIZE]);
                let value_version = u64::from_be_bytes(
                    data[1 + 2 * HASH_SIZE..].try_into().map_err(|_| corrupt("value_version"))?,
                );
                Ok(Node::Leaf(LeafNode { path, vh, value_version }))
            }
            Some(&NODE_TAG_INTERNAL) => {
                if data.len() < 3 {
                    return Err(corrupt("internal too short"));
                }
                let bitmap = u16::from_le_bytes([data[1], data[2]]);
                let count = bitmap.count_ones() as usize;
                if count == 0 {
                    return Err(corrupt("internal with no children"));
                }
                let entry = 8 + HASH_SIZE + 1;
                if data.len() != 3 + count * entry {
                    return Err(corrupt("bad internal length"));
                }
                let mut node = InternalNode::default();
                let mut off = 3;
                for i in 0..16 {
                    if bitmap & (1 << i) == 0 {
                        continue;
                    }
                    let version = u64::from_be_bytes(
                        data[off..off + 8].try_into().map_err(|_| corrupt("version"))?,
                    );
                    let mut hash = [0u8; HASH_SIZE];
                    hash.copy_from_slice(&data[off + 8..off + 8 + HASH_SIZE]);
                    let is_leaf = match data[off + 8 + HASH_SIZE] {
                        0 => false,
                        1 => true,
                        _ => return Err(corrupt("bad is_leaf flag")),
                    };
                    node.children[i] = Some(Child { version, hash, is_leaf });
                    off += entry;
                }
                Ok(Node::Internal(node))
            }
            _ => Err(corrupt("unknown tag")),
        }
    }

    /// The node's hash, as committed by its parent (or the root).
    pub fn hash(&self) -> Hash {
        match self {
            Node::Leaf(leaf) => leaf_hash(&leaf.path, &leaf.vh),
            Node::Internal(node) => subtree_hash(&node.children, 0, 16),
        }
    }
}

/// Binary merkle over a range of child slots.
///
/// - empty range → placeholder
/// - single slot → that child's hash (or placeholder)
/// - range holding exactly one child which is a leaf → the leaf's hash
///   (the leaf represents the whole subtree, wherever it sits)
/// - otherwise → `internal_hash(left half, right half)`
///
/// `pub(crate)`: the prover folds sibling half-ranges with this.
pub(crate) fn subtree_hash(children: &[Option<Child>; 16], start: usize, width: usize) -> Hash {
    let present: Vec<&Child> = children[start..start + width].iter().flatten().collect();
    match present.len() {
        0 => *placeholder(),
        1 if width == 1 || present[0].is_leaf => present[0].hash,
        _ => {
            let half = width / 2;
            let left = subtree_hash(children, start, half);
            let right = subtree_hash(children, start + half, half);
            internal_hash(&left, &right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(version: u64, seed: u8, is_leaf: bool) -> Child {
        Child { version, hash: [seed; 32], is_leaf }
    }

    #[test]
    fn nibble_order_is_msb_first() {
        let mut path = [0u8; 32];
        path[0] = 0xAB;
        path[31] = 0xCD;
        assert_eq!(nibble(&path, 0), 0xA);
        assert_eq!(nibble(&path, 1), 0xB);
        assert_eq!(nibble(&path, 62), 0xC);
        assert_eq!(nibble(&path, 63), 0xD);
    }

    #[test]
    fn node_key_encoding() {
        let root = NodeKey::root(7);
        assert_eq!(root.encode(), [0, 0, 0, 0, 0, 0, 0, 7, 0]);

        let k = root.child(7, 0xA).child(8, 0x3).child(9, 0xF);
        let enc = k.encode();
        assert_eq!(enc[..8], 9u64.to_be_bytes());
        assert_eq!(enc[8], 3); // nibble count
        assert_eq!(&enc[9..], &[0xA3, 0xF0]);
    }

    #[test]
    fn node_key_encoding_is_injective_at_same_version() {
        // [0xA] vs [0xA, 0x0] pack to the same nibble byte but differ in count.
        let a = NodeKey { version: 1, prefix: vec![0xA] };
        let b = NodeKey { version: 1, prefix: vec![0xA, 0x0] };
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn leaf_codec_roundtrip() {
        let node =
            Node::Leaf(LeafNode { path: [3u8; 32], vh: [4u8; 32], value_version: 900 });
        let decoded = Node::decode(&node.encode()).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn leaf_hash_excludes_value_version() {
        let a = Node::Leaf(LeafNode { path: [3u8; 32], vh: [4u8; 32], value_version: 1 });
        let b = Node::Leaf(LeafNode { path: [3u8; 32], vh: [4u8; 32], value_version: 99 });
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn internal_codec_roundtrip() {
        let mut internal = InternalNode::default();
        internal.children[0] = Some(child(5, 1, true));
        internal.children[7] = Some(child(9, 2, false));
        internal.children[15] = Some(child(1, 3, true));
        let node = Node::Internal(internal);
        let decoded = Node::decode(&node.encode()).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Node::decode(&[]).is_err());
        assert!(Node::decode(&[9, 1, 2]).is_err());
        let node =
            Node::Leaf(LeafNode { path: [3u8; 32], vh: [4u8; 32], value_version: 1 });
        let mut enc = node.encode();
        enc.push(0); // trailing byte
        assert!(Node::decode(&enc).is_err());
        // Internal claiming children it doesn't carry.
        assert!(Node::decode(&[1, 0xFF, 0xFF]).is_err());
        // Internal with no children is invalid.
        assert!(Node::decode(&[1, 0, 0]).is_err());
    }

    #[test]
    fn single_leaf_child_collapses_to_leaf_hash() {
        // An internal node holding exactly one leaf child hashes to that
        // leaf's hash regardless of which slot it occupies.
        let leaf = child(1, 9, true);
        for slot in [0usize, 3, 15] {
            let mut internal = InternalNode::default();
            internal.children[slot] = Some(leaf.clone());
            assert_eq!(Node::Internal(internal).hash(), leaf.hash);
        }
    }

    #[test]
    fn single_internal_child_does_not_collapse() {
        let inner = child(1, 9, false);
        let mut a = InternalNode::default();
        a.children[0] = Some(inner.clone());
        let mut b = InternalNode::default();
        b.children[8] = Some(inner);
        // Position matters for non-leaf children.
        assert_ne!(Node::Internal(a.clone()).hash(), Node::Internal(b).hash());
        assert_ne!(Node::Internal(a).hash(), [9u8; 32]);
    }

    #[test]
    fn hash_depends_on_slot_for_leaves_among_others() {
        let mut a = InternalNode::default();
        a.children[0] = Some(child(1, 1, true));
        a.children[1] = Some(child(1, 2, true));
        let mut b = InternalNode::default();
        b.children[0] = Some(child(1, 1, true));
        b.children[2] = Some(child(1, 2, true));
        assert_ne!(Node::Internal(a).hash(), Node::Internal(b).hash());
    }
}
