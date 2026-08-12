// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Inclusion and absence proofs, with a pure verifier.
//!
//! ## Shape
//!
//! Storage is 16-ary but hashing is binary, so every proof is a plain
//! binary sparse-Merkle proof over the 256-bit path:
//!
//! - `leaf`: the leaf found at the end of the descent, if any. Its path
//!   equal to the proven path ⇒ inclusion; different ⇒ absence evidence
//!   (the position the path would occupy is covered by another leaf).
//!   `None` ⇒ the descent ended on an empty subtree (placeholder).
//! - `siblings`: sibling hashes bottom-up. Sibling `i` (0 = deepest)
//!   pairs at binary depth `len - 1 - i`, and the proven path's bit at
//!   that depth picks the fold side. Compression only ever removes the
//!   *bottom* of the binary path (single-leaf and empty ranges), so the
//!   consumed bits are always a contiguous top prefix of the path.
//!
//! ## Verification statement
//!
//! [`verify`] recomputes the root and returns **what the proof proves**
//! about `path`: [`Verified::Present`] with the value commitment `vh`,
//! or [`Verified::Absent`]. Callers holding the commitment key compare
//! `vh` against `HMAC-SHA256(ck, "v" ‖ path ‖ plaintext)` (see
//! `MerkleStore::verify_value`). Without `ck`, statements are about
//! opaque `(path, vh)` pairs by design — the same keyed hashing that
//! stops the host dictionary-attacking values applies to any verifier.
//!
//! This module is pure (no OCALLs, no enclave state): it compiles and
//! runs on any target for client-side verification.

use crate::error::MerkleError;
use crate::hash::{internal_hash, leaf_hash, placeholder, Hash, HASH_SIZE};

/// Maximum binary depth of the tree (256-bit paths).
const MAX_DEPTH: usize = 256;

/// A proof for one path at one root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Terminal leaf `(path, vh)` found by the descent, if any.
    pub leaf: Option<(Hash, Hash)>,
    /// Sibling hashes, bottom-up (deepest first).
    pub siblings: Vec<Hash>,
}

/// What a valid proof establishes about the proven path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// The path holds a value with this commitment (`vh`).
    Present(Hash),
    /// The path holds no value at this root.
    Absent,
}

/// Bit `i` (MSB-first) of a 32-byte path.
fn bit(path: &Hash, i: usize) -> bool {
    debug_assert!(i < MAX_DEPTH);
    path[i / 8] & (0x80 >> (i % 8)) != 0
}

/// Number of leading bits shared by two paths.
fn common_prefix_bits(a: &Hash, b: &Hash) -> usize {
    for i in 0..HASH_SIZE {
        let x = a[i] ^ b[i];
        if x != 0 {
            return i * 8 + x.leading_zeros() as usize;
        }
    }
    MAX_DEPTH
}

/// Verify `proof` for `path` against `root`.
///
/// Returns the established statement, or an error if the proof does not
/// recompute `root` (or is malformed). Pure function.
pub fn verify(root: &Hash, path: &Hash, proof: &Proof) -> Result<Verified, MerkleError> {
    let n = proof.siblings.len();
    if n > MAX_DEPTH {
        return Err(MerkleError::Invalid("proof too deep".into()));
    }

    let (mut acc, statement) = match &proof.leaf {
        Some((leaf_path, vh)) => {
            if leaf_path == path {
                (leaf_hash(leaf_path, vh), Verified::Present(*vh))
            } else {
                // Absence via a divergent leaf: it must actually cover
                // the position the proven path would occupy, i.e. agree
                // with the path on every bit the fold consumes.
                if common_prefix_bits(leaf_path, path) < n {
                    return Err(MerkleError::Invalid(
                        "divergent leaf does not cover the proven path".into(),
                    ));
                }
                (leaf_hash(leaf_path, vh), Verified::Absent)
            }
        }
        None => (*placeholder(), Verified::Absent),
    };

    for (i, sibling) in proof.siblings.iter().enumerate() {
        let depth = n - 1 - i;
        acc = if bit(path, depth) {
            internal_hash(sibling, &acc)
        } else {
            internal_hash(&acc, sibling)
        };
    }

    if &acc != root {
        return Err(MerkleError::Invalid("proof does not match root".into()));
    }
    Ok(statement)
}

// ---------------------------------------------------------------------------
//  Wire format
// ---------------------------------------------------------------------------

impl Proof {
    /// Encode: `[u8 flags(bit0 = has_leaf)] (path 32 ‖ vh 32)?
    /// [u16 LE sibling_count] siblings*32`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(3 + 2 * HASH_SIZE + self.siblings.len() * HASH_SIZE);
        match &self.leaf {
            Some((path, vh)) => {
                buf.push(1);
                buf.extend_from_slice(path);
                buf.extend_from_slice(vh);
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&(self.siblings.len() as u16).to_le_bytes());
        for s in &self.siblings {
            buf.extend_from_slice(s);
        }
        buf
    }

    /// Strict decode of [`Proof::encode`]'s format.
    pub fn decode(data: &[u8]) -> Result<Proof, MerkleError> {
        let malformed = || MerkleError::Invalid("malformed proof".into());
        let (leaf, mut off) = match data.first() {
            Some(0) => (None, 1),
            Some(1) => {
                if data.len() < 1 + 2 * HASH_SIZE {
                    return Err(malformed());
                }
                let mut path = [0u8; HASH_SIZE];
                let mut vh = [0u8; HASH_SIZE];
                path.copy_from_slice(&data[1..1 + HASH_SIZE]);
                vh.copy_from_slice(&data[1 + HASH_SIZE..1 + 2 * HASH_SIZE]);
                (Some((path, vh)), 1 + 2 * HASH_SIZE)
            }
            _ => return Err(malformed()),
        };
        if data.len() < off + 2 {
            return Err(malformed());
        }
        let count = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if count > MAX_DEPTH || data.len() != off + count * HASH_SIZE {
            return Err(malformed());
        }
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            let mut s = [0u8; HASH_SIZE];
            s.copy_from_slice(&data[off..off + HASH_SIZE]);
            siblings.push(s);
            off += HASH_SIZE;
        }
        Ok(Proof { leaf, siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_extraction() {
        let mut p = [0u8; 32];
        p[0] = 0b1010_0000;
        assert!(bit(&p, 0));
        assert!(!bit(&p, 1));
        assert!(bit(&p, 2));
        p[31] = 0b0000_0001;
        assert!(bit(&p, 255));
    }

    #[test]
    fn common_prefix() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert_eq!(common_prefix_bits(&a, &b), 256);
        b[0] = 0b1000_0000;
        assert_eq!(common_prefix_bits(&a, &b), 0);
        b[0] = 0b0000_0001;
        assert_eq!(common_prefix_bits(&a, &b), 7);
        b[0] = 0;
        b[16] = 0b0100_0000;
        assert_eq!(common_prefix_bits(&a, &b), 129);
    }

    #[test]
    fn codec_roundtrip() {
        let proofs = [
            Proof { leaf: None, siblings: vec![] },
            Proof { leaf: Some(([1; 32], [2; 32])), siblings: vec![[3; 32], [4; 32]] },
            Proof { leaf: None, siblings: vec![[5; 32]] },
        ];
        for p in &proofs {
            assert_eq!(&Proof::decode(&p.encode()).unwrap(), p);
        }
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Proof::decode(&[]).is_err());
        assert!(Proof::decode(&[2]).is_err());
        assert!(Proof::decode(&[1, 0, 0]).is_err());
        let good = Proof { leaf: None, siblings: vec![[5; 32]] }.encode();
        assert!(Proof::decode(&good[..good.len() - 1]).is_err());
        let mut extended = good.clone();
        extended.push(0);
        assert!(Proof::decode(&extended).is_err());
    }

    #[test]
    fn empty_tree_absence() {
        let proof = Proof { leaf: None, siblings: vec![] };
        assert_eq!(
            verify(placeholder(), &[7u8; 32], &proof).unwrap(),
            Verified::Absent
        );
        // Same proof against a different root fails.
        assert!(verify(&[1u8; 32], &[7u8; 32], &proof).is_err());
    }

    #[test]
    fn single_leaf_inclusion_and_absence() {
        let path = [0xAAu8; 32];
        let vh = [0x55u8; 32];
        let root = leaf_hash(&path, &vh);

        let inclusion = Proof { leaf: Some((path, vh)), siblings: vec![] };
        assert_eq!(verify(&root, &path, &inclusion).unwrap(), Verified::Present(vh));

        // The same proof shows any other path absent (divergent leaf,
        // zero fold bits so the covering condition is trivially met).
        let other = [0xABu8; 32];
        assert_eq!(verify(&root, &other, &inclusion).unwrap(), Verified::Absent);
    }
}
