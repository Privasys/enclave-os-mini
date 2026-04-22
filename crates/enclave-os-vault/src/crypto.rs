// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-enclave crypto operations on stored keys.
//!
//! Each function takes the raw sealed material from a [`KeyRecord`]
//! and performs one operation. None of the functions return the
//! material itself; only the operation result.

use std::string::String;
use std::vec::Vec;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

// ---------------------------------------------------------------------------
//  Material validators (called from CreateKey)
// ---------------------------------------------------------------------------

/// Validate that `material` is acceptable for `key_type` and return the
/// public key bytes (raw uncompressed EC point for P-256, `None` for
/// symmetric / opaque keys).
pub(crate) fn validate_material(
    key_type: crate::types::KeyType,
    material: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    use crate::types::KeyType;
    match key_type {
        KeyType::RawShare => Ok(None),
        KeyType::Aes256GcmKey => {
            if material.len() != 32 {
                return Err(format!(
                    "Aes256GcmKey requires 32 bytes of material, got {}",
                    material.len()
                ));
            }
            Ok(None)
        }
        KeyType::HmacSha256Key => {
            // HMAC-SHA-256 accepts any key length; insist on >= 32 to
            // match the underlying hash output and cap at 64 (one block)
            // so callers don't pass nonsense.
            if !(32..=64).contains(&material.len()) {
                return Err(format!(
                    "HmacSha256Key requires 32..=64 bytes of material, got {}",
                    material.len()
                ));
            }
            Ok(None)
        }
        KeyType::P256SigningKey => {
            // material is PKCS#8 v1; parse to derive the public key.
            let rng = SystemRandom::new();
            let kp = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                material,
                &rng,
            )
            .map_err(|_| "P256SigningKey material is not a valid PKCS#8 P-256 key".to_string())?;
            Ok(Some(kp.public_key().as_ref().to_vec()))
        }
    }
}

// ---------------------------------------------------------------------------
//  Wrap / Unwrap (AES-256-GCM)
// ---------------------------------------------------------------------------

/// AES-256-GCM seal. Returns `(ciphertext_with_tag, iv)` — IV is either
/// the caller-supplied 12 bytes or a freshly generated random one.
pub(crate) fn aes_gcm_seal(
    key_bytes: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    iv: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let nonce_bytes: [u8; NONCE_LEN] = match iv {
        Some(b) if b.len() == NONCE_LEN => {
            let mut a = [0u8; NONCE_LEN];
            a.copy_from_slice(b);
            a
        }
        Some(b) => {
            return Err(format!(
                "AES-GCM nonce must be {} bytes, got {}",
                NONCE_LEN,
                b.len()
            ))
        }
        None => {
            let mut a = [0u8; NONCE_LEN];
            SystemRandom::new()
                .fill(&mut a)
                .map_err(|_| "rng failed".to_string())?;
            a
        }
    };

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| "invalid AES-256 key".to_string())?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "AES-GCM seal failed".to_string())?;
    Ok((in_out, nonce_bytes.to_vec()))
}

/// AES-256-GCM open. Caller supplies the IV explicitly.
pub(crate) fn aes_gcm_open(
    key_bytes: &[u8],
    ciphertext: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if iv.len() != NONCE_LEN {
        return Err(format!(
            "AES-GCM nonce must be {} bytes, got {}",
            NONCE_LEN,
            iv.len()
        ));
    }
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(iv);
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| "invalid AES-256 key".to_string())?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "AES-GCM open failed (auth tag mismatch)".to_string())?;
    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
//  Sign (ECDSA-P256-SHA256, IEEE-P1363 fixed-length 64-byte signature)
// ---------------------------------------------------------------------------

pub(crate) fn p256_sign(pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
        .map_err(|_| "parse signing key failed".to_string())?;
    let sig = kp
        .sign(&rng, message)
        .map_err(|_| "ECDSA sign failed".to_string())?;
    Ok(sig.as_ref().to_vec())
}

// ---------------------------------------------------------------------------
//  Mac (HMAC-SHA-256)
// ---------------------------------------------------------------------------

pub(crate) fn hmac_sha256(key_bytes: &[u8], message: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    hmac::sign(&key, message).as_ref().to_vec()
}
