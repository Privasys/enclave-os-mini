// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Commit certificates: quorum-signed attestations of `(index, root)`.
//!
//! Each node derives a P-256 signing key from a private seed (the
//! enclave master key, in production), announces the public key in its
//! `Hello`, and the leader registers keys through replicated
//! `RegisterKey` config entries. Followers sign every root report;
//! when a quorum of signatures agrees at an index, the leader
//! assembles a [`CommitCertificate`] — an auditable proof that the
//! cluster confirmed that state, verifiable offline against the
//! registered keys without trusting any single node. This closes the
//! Merkle store's restart-rollback residual for external verifiers.

use std::collections::BTreeMap;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ring::hmac;

use crate::core::LedgerRoot;
use crate::types::{Index, Membership, NodeId};

const SIGN_DOMAIN: &[u8] = b"enclave-os-raft:cert:v1";

/// The canonical signed preimage for `(index, root)`.
fn preimage(index: Index, root: &LedgerRoot) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGN_DOMAIN.len() + 40);
    m.extend_from_slice(SIGN_DOMAIN);
    m.extend_from_slice(&index.to_le_bytes());
    m.extend_from_slice(root);
    m
}

/// A node's certificate signing key, derived deterministically from a
/// 32-byte seed (stable across restarts).
pub struct CertSigner {
    key: SigningKey,
}

impl CertSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Hash the seed into a valid P-256 scalar (retry on the
        // negligible out-of-range case).
        let k = hmac::Key::new(hmac::HMAC_SHA256, seed);
        let mut counter = 0u32;
        loop {
            let mut ctx = hmac::Context::with_key(&k);
            ctx.update(b"enclave-os-raft:signkey:v1");
            ctx.update(&counter.to_le_bytes());
            let candidate = ctx.sign();
            if let Ok(key) = SigningKey::from_slice(candidate.as_ref()) {
                return Self { key };
            }
            counter += 1;
        }
    }

    /// Compressed SEC1 public key (33 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Sign `(index, root)`; fixed 64-byte `r ‖ s`.
    pub fn sign(&self, index: Index, root: &LedgerRoot) -> Vec<u8> {
        let sig: Signature = self.key.sign(&preimage(index, root));
        sig.to_bytes().to_vec()
    }
}

/// Verify one signature over `(index, root)` against a compressed SEC1
/// public key.
pub fn verify_sig(pubkey: &[u8], index: Index, root: &LedgerRoot, sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    vk.verify(&preimage(index, root), &sig).is_ok()
}

/// A quorum-signed attestation of the ledger state at a log index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCertificate {
    pub index: Index,
    pub root: LedgerRoot,
    /// Signatures by node id (64-byte `r ‖ s` each).
    pub sigs: BTreeMap<NodeId, Vec<u8>>,
}

impl CommitCertificate {
    /// Verify the certificate against a membership: every signature
    /// must check out under that node's registered key, and the
    /// signers must form a quorum of the voters.
    pub fn verify(&self, membership: &Membership) -> bool {
        let mut valid = 0usize;
        for (node, sig) in &self.sigs {
            if !membership.is_voter(*node) {
                continue;
            }
            let Some(key) = membership.keys.get(node) else { continue };
            if verify_sig(key, self.index, &self.root, sig) {
                valid += 1;
            } else {
                return false; // a bad signature poisons the certificate
            }
        }
        valid >= membership.quorum()
    }
}
