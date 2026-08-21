// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Version-bound sovereign sealing keys (S_N) — the sovereign-data
//! framework, Phase 1 (SGX half).
//!
//! An app flags data as user-owned and keeps each data owner's
//! wallet-delivered key element W sealed under S_N, a key only the
//! currently-loaded app VERSION can obtain:
//!
//! ```text
//! root = HKDF(runtime master key, "privasys-sovereign-seal/v1", "root")
//! S_N  = HKDF(root,               "privasys-sovereign-seal/v1", "seal" || code_hash)
//! ```
//!
//! The runtime master key is MRENCLAVE-sealed (`SealedConfig::master_key`),
//! so S_N inherits hardware version binding at the RUNTIME level, and the
//! `code_hash` input (the app's own measurement, OID 3.2) binds it at the
//! APP level: a new wasm build receives a different S_N, so the kept W is
//! unreadable to upgraded code until the data owner's wallet re-delivers
//! it — an app upgrade is a consent boundary. The enclave installs only
//! the domain-separated ROOT into this crate (never the raw master key),
//! and serving S_N can reveal neither.
//!
//! The derivation constants are WIRE FORMAT for every blob an app seals
//! under an S_N: changing any of them orphans all such blobs.
//!
//! This file is pure Rust (ring only) so its tests run off-SGX via the
//! `tests/sovereign-seal-unit` proxy crate.

use ring::hmac;

/// Domain-separation label; also returned to apps as the scheme version.
pub const SOVEREIGN_SEAL_INFO: &[u8] = b"privasys-sovereign-seal/v1";

/// HKDF-SHA256 extract (RFC 5869).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-SHA256 expand (RFC 5869), single 32-byte block.
fn hkdf_expand32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(info);
    ctx.update(&[0x01]);
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Derive the sovereign root from the runtime master key. Called by the
/// enclave init code, which installs ONLY the result into this crate —
/// the raw master key never crosses.
pub fn derive_sovereign_root(master: &[u8; 32]) -> [u8; 32] {
    let prk = hkdf_extract(SOVEREIGN_SEAL_INFO, master);
    hkdf_expand32(&prk, b"root")
}

/// Derive an app's current version-bound sealing key S_N from the
/// sovereign root and the app's code hash (SHA-256 of its module,
/// attested at OID 3.2).
pub fn derive_seal_key(root: &[u8; 32], code_hash: &[u8; 32]) -> [u8; 32] {
    let prk = hkdf_extract(SOVEREIGN_SEAL_INFO, root);
    let mut info = [0u8; 4 + 32];
    info[..4].copy_from_slice(b"seal");
    info[4..].copy_from_slice(code_hash);
    hkdf_expand32(&prk, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_separated() {
        let master = [0x42u8; 32];
        let root = derive_sovereign_root(&master);
        assert_ne!(root, master, "root must not equal the master key");
        assert_eq!(root, derive_sovereign_root(&master), "root must be deterministic");

        let hash_a = [0xaau8; 32];
        let hash_b = [0xbbu8; 32];
        let k_a = derive_seal_key(&root, &hash_a);
        let k_b = derive_seal_key(&root, &hash_b);
        assert_eq!(k_a, derive_seal_key(&root, &hash_a), "S_N must be deterministic");
        assert_ne!(k_a, k_b, "a code change must yield a different S_N");
        assert_ne!(k_a, root, "S_N must not equal the root");

        let other_root = derive_sovereign_root(&[0x43u8; 32]);
        assert_ne!(
            derive_seal_key(&other_root, &hash_a),
            k_a,
            "S_N must be bound to the runtime's own root"
        );
    }
}
