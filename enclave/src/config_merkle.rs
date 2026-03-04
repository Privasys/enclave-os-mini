// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Configuration Merkle tree — auditable hash commitment over all
//! operator-chosen and module-contributed config inputs.
//!
//! ## Design
//!
//! During enclave init, a [`ConfigMerkleTree`] is built by appending
//! **named leaves** in a deterministic order:
//!
//! 1. **Core leaf** (added by `ecall_run` before modules):
//!    - `core.ca_cert` — intermediary CA certificate (DER)
//!
//! 2. **Module leaves** (added by each `EnclaveModule::config_leaves()`):
//!    - `egress.ca_bundle` — egress CA bundle (PEM), or absent
//!    - `egress.attestation_servers` — attestation server URLs (canonical form), or absent
//!    - `wasm.code_hash` — WASM bytecode hash, or absent
//!    - Any custom leaves registered by third-party modules
//!
//! The tree is then **finalized**: the root is computed and the full
//! manifest (name → leaf hash) is frozen in a global [`ConfigManifest`].
//!
//! ## Auditability
//!
//! The root is embedded in every RA-TLS certificate as a custom X.509
//! OID. A client that sees the root can request the leaf manifest from
//! the enclave (via a dedicated request type) and verify:
//!
//! ```text
//!   root == SHA-256( leaf_hash_0 || leaf_hash_1 || … || leaf_hash_N )
//! ```
//!
//! Because leaf order is deterministic and names are included in the
//! manifest, the client knows exactly which config inputs produced the
//! root, and can pin individual leaf hashes (e.g. "I only trust this
//! specific CA cert hash").
//!
//! ## Fast-path OIDs
//!
//! In addition to the Merkle root, modules can register individual
//! X.509 OIDs (via `EnclaveModule::custom_oids()`) so that clients can
//! verify specific properties without recomputing the full tree.
//!
//! ## Extensibility
//!
//! Modules register leaves via the `EnclaveModule::config_leaves()`
//! trait method. The core never needs to know about module-specific
//! config — it just appends whatever leaves each module declares.

use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;
use ring::digest;

// ---------------------------------------------------------------------------
//  Builder (mutable, used during init)
// ---------------------------------------------------------------------------

/// A named leaf: `(name, raw_data)`.
pub struct ConfigLeaf {
    /// Stable, human-readable identifier (e.g. `"core.ca_cert"`).
    pub name: String,
    /// Raw bytes to hash. `None` means the input is absent (leaf = 32 zero bytes).
    pub data: Option<Vec<u8>>,
}

/// Mutable builder — accumulates leaves during enclave init.
pub struct ConfigMerkleTree {
    leaves: Vec<ConfigLeaf>,
}

impl ConfigMerkleTree {
    /// Create an empty tree.
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a leaf with the given name and raw data.
    pub fn push(&mut self, name: impl Into<String>, data: Option<&[u8]>) {
        self.leaves.push(ConfigLeaf {
            name: name.into(),
            data: data.map(|d| d.to_vec()),
        });
    }

    /// Finalize the tree: compute root + manifest, store globally.
    ///
    /// Returns the 32-byte root hash. After this call, the manifest is
    /// available via [`config_manifest()`] and the root via
    /// [`crate::config_merkle_root()`].
    pub fn finalize(self) -> [u8; 32] {
        let mut entries = Vec::with_capacity(self.leaves.len());
        let mut preimage = Vec::with_capacity(self.leaves.len() * 32);

        for leaf in &self.leaves {
            let hash = match &leaf.data {
                Some(data) => {
                    let d = digest::digest(&digest::SHA256, data);
                    let mut h = [0u8; 32];
                    h.copy_from_slice(d.as_ref());
                    h
                }
                None => [0u8; 32],
            };
            entries.push(ManifestEntry {
                name: leaf.name.clone(),
                hash,
            });
            preimage.extend_from_slice(&hash);
        }

        let root_digest = digest::digest(&digest::SHA256, &preimage);
        let mut root = [0u8; 32];
        root.copy_from_slice(root_digest.as_ref());

        let manifest = ConfigManifest { entries, root };

        // Store globally (only succeeds once)
        let _ = CONFIG_MANIFEST.set(manifest);
        root
    }
}

// ---------------------------------------------------------------------------
//  Manifest (immutable, queryable after finalize)
// ---------------------------------------------------------------------------

/// One entry in the config manifest.
#[derive(Clone)]
pub struct ManifestEntry {
    /// Human-readable leaf name (e.g. `"core.ca_cert"`).
    pub name: String,
    /// SHA-256 hash of the leaf data (or 32 zero bytes if absent).
    pub hash: [u8; 32],
}

/// Frozen config manifest — leaf names + hashes + root.
pub struct ConfigManifest {
    /// Ordered list of leaves (same order used to compute the root).
    pub entries: Vec<ManifestEntry>,
    /// SHA-256 Merkle root.
    pub root: [u8; 32],
}

impl ConfigManifest {
    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Root hash.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Iterate over all entries.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Serialize the manifest to a compact binary format that a client
    /// can use to verify the root.
    ///
    /// Format:
    /// ```text
    /// [4 bytes: num_entries (LE u32)]
    /// for each entry:
    ///   [2 bytes: name_len (LE u16)] [name bytes (UTF-8)] [32 bytes: hash]
    /// [32 bytes: root]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(&entry.hash);
        }
        buf.extend_from_slice(&self.root);
        buf
    }
}

// ---------------------------------------------------------------------------
//  Global accessor
// ---------------------------------------------------------------------------

static CONFIG_MANIFEST: OnceLock<ConfigManifest> = OnceLock::new();

/// Get the finalized config manifest (returns `None` before `finalize()`).
pub fn config_manifest() -> Option<&'static ConfigManifest> {
    CONFIG_MANIFEST.get()
}
