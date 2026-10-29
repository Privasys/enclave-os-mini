// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The pure half of a vault-backed app's KEK lifecycle: Shamir split and
//! reconstruct, the share framing the vaults store, the same-material
//! renewal check, and the re-wrap of the DEK blob for a new handle.
//!
//! A vault key lives 90 days from `CreateKey` and cannot be extended. A
//! RENEWAL re-creates the same KEK material under the next handle, so the
//! KEK, and everything derived from it (the direct-TLS branch, the ACME
//! account, an adopter's CAA pin), carries over. Only the handle moves, and
//! the wrapped DEK blob is AAD-bound to the handle, so it is re-wrapped.
//!
//! No vault, no host and no SGX here: this file depends on ring and on
//! `enclave_os_common` only, so its tests run off-SGX through the
//! `tests/kek-material-unit` proxy crate. `vaultkey` (the vault RPC) and
//! `registry` (the host-side blob) call into it.

use std::format;
use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use enclave_os_common::aead::AeadCipher;
use enclave_os_common::hex::hex_encode;

/// Length of the per-generation tag prefixed to each share payload. A one-shot
/// `CreateKey` retry must never split generations, so each share carries a
/// random 16-byte generation id; reconstruction groups by it.
pub const GENERATION_SIZE: usize = 16;

/// KEK length in bytes (256-bit).
pub const KEK_SIZE: usize = 32;

/// How `vaultkey::resolve_or_provision` obtained a KEK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// This call created the handle on the constellation.
    Created,
    /// The handle already existed and a share quorum reconstructed it.
    Reconstructed,
}

// ===========================================================================
//  A new generation: the KEK, its generation tag, and its shares
// ===========================================================================

/// The material a `CreateKey` round splits: the KEK, a fresh generation tag,
/// and one share per vault.
pub struct NewGeneration {
    pub kek: [u8; KEK_SIZE],
    pub generation: [u8; GENERATION_SIZE],
    pub shares: Vec<Share>,
}

/// Split `material` when given (a renewal: the next handle holds the same
/// KEK), else a freshly generated KEK. The generation tag is always fresh,
/// so a renewal's shares never mix with the old handle's.
pub fn new_generation(
    material: Option<&[u8; KEK_SIZE]>,
    threshold: usize,
    num_shares: usize,
) -> Result<NewGeneration, String> {
    let rng = SystemRandom::new();
    let kek = match material {
        Some(m) => *m,
        None => {
            let mut k = [0u8; KEK_SIZE];
            rng.fill(&mut k).map_err(|_| "vaultkey: rng (kek)")?;
            k
        }
    };
    let mut generation = [0u8; GENERATION_SIZE];
    rng.fill(&mut generation)
        .map_err(|_| "vaultkey: rng (generation)")?;
    let shares = shamir_split(&kek, threshold, num_shares)?;
    Ok(NewGeneration {
        kek,
        generation,
        shares,
    })
}

// ===========================================================================
//  Renewal: the same KEK under the next handle
// ===========================================================================

/// Constant-time equality of two KEKs.
fn ct_eq(a: &[u8; KEK_SIZE], b: &[u8; KEK_SIZE]) -> bool {
    let mut diff = 0u8;
    for i in 0..KEK_SIZE {
        diff |= a[i] ^ b[i];
    }
    core::hint::black_box(diff) == 0
}

/// A renewal switches to `new_handle` only when it holds the KEK `old_handle`
/// holds. A fresh create splits the old KEK, so they match; a retried
/// renewal reconstructs what the first attempt created, so they match too.
/// Anything else (the handle was created earlier with other material) is
/// refused, before the app is moved onto a key that cannot read its data.
pub fn check_renewed(
    old_kek: &[u8; KEK_SIZE],
    new_kek: &[u8; KEK_SIZE],
    old_handle: &str,
    new_handle: &str,
) -> Result<(), String> {
    if ct_eq(old_kek, new_kek) {
        Ok(())
    } else {
        Err(format!(
            "renew: {new_handle} holds a different key than {old_handle}; not switching to it"
        ))
    }
}

// ===========================================================================
//  The wrapped DEK blob (host-side, AAD-bound to the handle)
// ===========================================================================

/// Wrap the DEK under `kek`, bound to `handle`.
pub fn wrap_dek(kek: &[u8; KEK_SIZE], handle: &str, dek: &[u8]) -> Result<Vec<u8>, String> {
    AeadCipher::from_key(*kek)
        .encrypt(dek, handle.as_bytes())
        .map_err(|e| format!("vaultkey: wrap encryption_key: {e}"))
}

/// Unwrap a blob wrapped by [`wrap_dek`] for the same `kek` and `handle`.
pub fn unwrap_dek(kek: &[u8; KEK_SIZE], handle: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    AeadCipher::from_key(*kek)
        .decrypt(blob, handle.as_bytes())
        .map_err(|e| format!("vaultkey: unwrap encryption_key: {e}"))
}

/// Move a wrapped DEK from `old_handle` to `new_handle`: unwrap it under the
/// old KEK and AAD, wrap it under the new ones. A rotation passes two KEKs; a
/// renewal passes the same one twice, and the blob still changes because its
/// AAD is the handle.
pub fn rewrap_dek(
    old_kek: &[u8; KEK_SIZE],
    old_handle: &str,
    new_kek: &[u8; KEK_SIZE],
    new_handle: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    let dek = unwrap_dek(old_kek, old_handle, blob)?;
    wrap_dek(new_kek, new_handle, &dek)
}

/// Whether a load may generate a NEW DEK because the handle's wrapped blob is
/// missing. Right after this load created the key, a missing blob is normal.
/// For a key that already existed it is normal too when the app's KV holds
/// nothing: a crash between `CreateKey` and the blob write, or host storage
/// that was lost with the data. When the KV does hold data, a new DEK would
/// orphan it for good, so the load fails instead.
pub fn may_generate_dek(
    origin: KeyOrigin,
    app_kv_has_data: bool,
    handle: &str,
) -> Result<(), String> {
    match (origin, app_kv_has_data) {
        (KeyOrigin::Created, _) | (KeyOrigin::Reconstructed, false) => Ok(()),
        (KeyOrigin::Reconstructed, true) => Err(format!(
            "vaultkey: {handle} exists but its wrapped encryption_key is missing on this \
             host, and the app's KV holds data: refusing to generate a new key, which \
             would make that data unreadable"
        )),
    }
}

// ===========================================================================
//  Share payload framing: generation(16) || X(1) || data
// ===========================================================================

pub struct Share {
    pub x: u8,
    pub data: Vec<u8>,
}

pub fn encode_share(generation: &[u8; GENERATION_SIZE], s: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENERATION_SIZE + 1 + s.data.len());
    out.extend_from_slice(generation);
    out.push(s.x);
    out.extend_from_slice(&s.data);
    out
}

pub fn decode_share(payload: &[u8]) -> Result<(String, Share), String> {
    if payload.len() < GENERATION_SIZE + 2 {
        return Err(format!("share payload too short ({} bytes)", payload.len()));
    }
    let gen = hex_encode(&payload[..GENERATION_SIZE]);
    let x = payload[GENERATION_SIZE];
    if x == 0 {
        return Err("share X must be non-zero".into());
    }
    let data = payload[GENERATION_SIZE + 1..].to_vec();
    Ok((gen, Share { x, data }))
}

pub fn push_share(by_gen: &mut Vec<(String, Vec<Share>)>, gen: String, share: Share) {
    for (g, shares) in by_gen.iter_mut() {
        if *g == gen {
            shares.push(share);
            return;
        }
    }
    by_gen.push((gen, std::vec![share]));
}

/// Largest same-generation group meeting the threshold.
pub fn best_group(by_gen: &[(String, Vec<Share>)], threshold: usize) -> Option<&[Share]> {
    let mut best: Option<&[Share]> = None;
    for (_, shares) in by_gen {
        if shares.len() >= threshold && shares.len() > best.map_or(0, |b| b.len()) {
            best = Some(shares);
        }
    }
    best
}

pub fn to_kek(v: Vec<u8>) -> Result<[u8; KEK_SIZE], String> {
    if v.len() != KEK_SIZE {
        return Err(format!(
            "vaultkey: reconstructed KEK has {} bytes, want {}",
            v.len(),
            KEK_SIZE
        ));
    }
    let mut out = [0u8; KEK_SIZE];
    out.copy_from_slice(&v);
    Ok(out)
}

// ===========================================================================
//  Shamir Secret Sharing over GF(2^8) — ported from the Go client so split
//  and reconstruct are self-consistent (the vault stores opaque shares).
// ===========================================================================

/// `(gfExp, gfLog)` tables for GF(2^8) with generator g=3, modulus 0x11b.
fn gf_tables() -> &'static ([u8; 256], [u8; 256]) {
    static TABLES: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        let mut val: u16 = 1;
        for i in 0..255usize {
            exp[i] = val as u8;
            log[val as usize] = i as u8;
            let mut doubled = val << 1;
            if doubled & 0x100 != 0 {
                doubled ^= 0x11b;
            }
            val = doubled ^ val; // val *= 3
        }
        exp[255] = exp[0]; // g^255 = g^0 = 1
        (exp, log)
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = gf_tables();
    let log_sum = log[a as usize] as u16 + log[b as usize] as u16;
    exp[(log_sum % 255) as usize]
}

fn gf_inv(a: u8) -> u8 {
    let (exp, log) = gf_tables();
    exp[(255 - log[a as usize] as u16) as usize]
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn eval_poly(constant: u8, coeffs: &[u8], x: u8) -> u8 {
    let mut val = 0u8;
    for &c in coeffs.iter().rev() {
        val = gf_add(gf_mul(val, x), c);
    }
    gf_add(gf_mul(val, x), constant)
}

fn lagrange_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let n = xs.len();
    let mut result = 0u8;
    for i in 0..n {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            num = gf_mul(num, xs[j]); // 0 - xs[j] = xs[j] in GF(2^8)
            den = gf_mul(den, gf_add(xs[i], xs[j]));
        }
        let basis = gf_mul(num, gf_inv(den));
        result = gf_add(result, gf_mul(ys[i], basis));
    }
    result
}

pub fn shamir_split(
    secret: &[u8],
    threshold: usize,
    num_shares: usize,
) -> Result<Vec<Share>, String> {
    if threshold < 2 {
        return Err("threshold must be >= 2".into());
    }
    if num_shares < threshold {
        return Err("numShares must be >= threshold".into());
    }
    if num_shares > 255 {
        return Err("max 255 shares (GF(256))".into());
    }
    if secret.is_empty() {
        return Err("secret must not be empty".into());
    }
    let mut shares: Vec<Share> = (0..num_shares)
        .map(|i| Share {
            x: (i + 1) as u8,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();
    let rng = SystemRandom::new();
    let mut coeffs = std::vec![0u8; threshold - 1];
    for &b in secret {
        rng.fill(&mut coeffs).map_err(|_| "rng (shamir coeffs)")?;
        for share in shares.iter_mut() {
            let v = eval_poly(b, &coeffs, share.x);
            share.data.push(v);
        }
    }
    Ok(shares)
}

pub fn shamir_reconstruct(shares: &[Share]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("no shares provided".into());
    }
    let data_len = shares[0].data.len();
    for s in &shares[1..] {
        if s.data.len() != data_len {
            return Err("all shares must have the same data length".into());
        }
    }
    let mut seen = [false; 256];
    for s in shares {
        if seen[s.x as usize] {
            return Err(format!("duplicate share X={}", s.x));
        }
        seen[s.x as usize] = true;
    }
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    let mut secret = std::vec![0u8; data_len];
    let mut ys = std::vec![0u8; shares.len()];
    for (j, out) in secret.iter_mut().enumerate() {
        for (i, s) in shares.iter().enumerate() {
            ys[i] = s.data[j];
        }
        *out = lagrange_at_zero(&xs, &ys);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a vault round trip does to a share: frame, store, decode.
    fn through_vault(gen: &[u8; GENERATION_SIZE], s: &Share) -> (String, Share) {
        decode_share(&encode_share(gen, s)).unwrap()
    }

    /// Reconstruct the KEK from the given share indices, grouped by
    /// generation the way `resolve_or_provision` groups them.
    fn reconstruct(g: &NewGeneration, idx: &[usize], threshold: usize) -> [u8; KEK_SIZE] {
        let mut by_gen = Vec::new();
        for &i in idx {
            let (gen, s) = through_vault(&g.generation, &g.shares[i]);
            push_share(&mut by_gen, gen, s);
        }
        let best = best_group(&by_gen, threshold).expect("quorum");
        to_kek(shamir_reconstruct(best).unwrap()).unwrap()
    }

    #[test]
    fn material_is_what_the_shares_reconstruct() {
        let material = [0x5au8; KEK_SIZE];
        let g = new_generation(Some(&material), 2, 4).unwrap();
        assert_eq!(g.kek, material);
        assert_eq!(g.shares.len(), 4);
        // Any quorum reconstructs the given material.
        for pair in [[0, 1], [1, 3], [2, 0], [3, 2]] {
            assert_eq!(reconstruct(&g, &pair, 2), material);
        }
        assert_eq!(reconstruct(&g, &[0, 1, 2, 3], 2), material);
    }

    #[test]
    fn material_gets_a_fresh_generation_and_fresh_shares() {
        let material = [7u8; KEK_SIZE];
        let a = new_generation(Some(&material), 2, 3).unwrap();
        let b = new_generation(Some(&material), 2, 3).unwrap();
        assert_ne!(a.generation, b.generation);
        // Shamir coefficients are random: the same secret, other shares.
        assert!(a.shares.iter().zip(&b.shares).any(|(x, y)| x.data != y.data));
        assert_eq!(reconstruct(&a, &[0, 2], 2), material);
        assert_eq!(reconstruct(&b, &[1, 2], 2), material);
    }

    #[test]
    fn shares_of_two_generations_never_combine() {
        let material = [9u8; KEK_SIZE];
        let a = new_generation(Some(&material), 2, 2).unwrap();
        let b = new_generation(Some(&material), 2, 2).unwrap();
        let mut by_gen = Vec::new();
        let (ga, sa) = through_vault(&a.generation, &a.shares[0]);
        let (gb, sb) = through_vault(&b.generation, &b.shares[1]);
        push_share(&mut by_gen, ga, sa);
        push_share(&mut by_gen, gb, sb);
        assert!(best_group(&by_gen, 2).is_none());
    }

    #[test]
    fn no_material_generates_a_random_kek() {
        let a = new_generation(None, 2, 3).unwrap();
        let b = new_generation(None, 2, 3).unwrap();
        assert_ne!(a.kek, b.kek);
        assert_eq!(reconstruct(&a, &[0, 1], 2), a.kek);
    }

    #[test]
    fn split_refuses_a_bad_threshold() {
        let m = [1u8; KEK_SIZE];
        assert!(new_generation(Some(&m), 1, 3).is_err());
        assert!(new_generation(Some(&m), 4, 3).is_err());
    }

    #[test]
    fn renewal_accepts_the_same_kek_only() {
        let old = [3u8; KEK_SIZE];
        assert!(check_renewed(&old, &old, "h/v1", "h/v2").is_ok());
        let mut other = old;
        other[KEK_SIZE - 1] ^= 1;
        let err = check_renewed(&old, &other, "h/v1", "h/v2").unwrap_err();
        assert!(err.contains("h/v2") && err.contains("h/v1"));
        assert!(check_renewed(&old, &[0u8; KEK_SIZE], "h/v1", "h/v2").is_err());
    }

    #[test]
    fn renewal_rewrap_binds_the_new_handle() {
        let kek = [0x11u8; KEK_SIZE];
        let dek = [0x22u8; 32];
        let (old_h, new_h) = ("apps.privasys.org/a/storage-kek/v1", "apps.privasys.org/a/storage-kek/v2");
        let old_blob = wrap_dek(&kek, old_h, &dek).unwrap();
        let new_blob = rewrap_dek(&kek, old_h, &kek, new_h, &old_blob).unwrap();
        assert_ne!(old_blob, new_blob);
        // The new blob opens under the new handle, with the same KEK and DEK.
        assert_eq!(unwrap_dek(&kek, new_h, &new_blob).unwrap(), dek);
        // It does not open under the old handle: the AAD moved.
        assert!(unwrap_dek(&kek, old_h, &new_blob).is_err());
        // The old blob, which a renewal keeps, still opens under the old one.
        assert_eq!(unwrap_dek(&kek, old_h, &old_blob).unwrap(), dek);
    }

    #[test]
    fn rotation_rewrap_moves_to_the_new_kek() {
        let (old_k, new_k) = ([1u8; KEK_SIZE], [2u8; KEK_SIZE]);
        let dek = [0x33u8; 32];
        let blob = wrap_dek(&old_k, "h/v1", &dek).unwrap();
        let moved = rewrap_dek(&old_k, "h/v1", &new_k, "h/v2", &blob).unwrap();
        assert_eq!(unwrap_dek(&new_k, "h/v2", &moved).unwrap(), dek);
        assert!(unwrap_dek(&old_k, "h/v2", &moved).is_err());
        // A blob for another handle is refused, not re-wrapped.
        assert!(rewrap_dek(&old_k, "h/v9", &new_k, "h/v2", &blob).is_err());
    }

    #[test]
    fn missing_blob_is_fatal_only_for_an_existing_key_with_data() {
        assert!(may_generate_dek(KeyOrigin::Created, false, "h").is_ok());
        assert!(may_generate_dek(KeyOrigin::Created, true, "h").is_ok());
        assert!(may_generate_dek(KeyOrigin::Reconstructed, false, "h").is_ok());
        assert!(may_generate_dek(KeyOrigin::Reconstructed, true, "h").is_err());
    }
}
