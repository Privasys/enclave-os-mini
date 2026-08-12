// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Domain-separated SHA-256 hashing for tree nodes.
//!
//! Every hash is `SHA-256(tag ‖ payload)` with a distinct tag per node
//! kind, so a leaf can never be confused with an internal node or a
//! placeholder, whatever its byte content.

use ring::digest;
use std::sync::OnceLock;

/// Size of every hash in the tree.
pub const HASH_SIZE: usize = 32;

/// A 32-byte SHA-256 output.
pub type Hash = [u8; HASH_SIZE];

const TAG_LEAF: &[u8] = b"enclave-os-merkle:leaf:v1";
const TAG_INTERNAL: &[u8] = b"enclave-os-merkle:node:v1";
const TAG_PLACEHOLDER: &[u8] = b"ENCLAVE_OS_MERKLE_PLACEHOLDER";

fn sha256_parts(parts: &[&[u8]]) -> Hash {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let d = ctx.finish();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(d.as_ref());
    out
}

/// The hash standing in for any empty subtree, at every height.
pub fn placeholder() -> &'static Hash {
    static PLACEHOLDER: OnceLock<Hash> = OnceLock::new();
    PLACEHOLDER.get_or_init(|| sha256_parts(&[TAG_PLACEHOLDER]))
}

/// Hash of a leaf: `SHA-256(tag ‖ path ‖ vh)`.
pub fn leaf_hash(path: &Hash, vh: &Hash) -> Hash {
    sha256_parts(&[TAG_LEAF, path, vh])
}

/// Hash of one binary step inside an internal node: `SHA-256(tag ‖ l ‖ r)`.
pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    sha256_parts(&[TAG_INTERNAL, left, right])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(leaf_hash(&a, &b), internal_hash(&a, &b));
        assert_ne!(*placeholder(), leaf_hash(&a, &b));
        assert_ne!(*placeholder(), [0u8; 32]);
    }

    #[test]
    fn placeholder_is_stable() {
        assert_eq!(placeholder(), placeholder());
    }
}
