// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! AEAD (Authenticated Encryption with Associated Data) using AES-256-GCM.
//!
//! Used to encrypt keys and values before sending them to the host via OCALLs.
//! The encryption key is generated inside the enclave and sealed with SGX.

use std::vec::Vec;
use enclave_os_common::types::{AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

/// An AES-256-GCM encryption context.
pub struct AeadCipher {
    key_bytes: [u8; AEAD_KEY_SIZE],
}

impl AeadCipher {
    /// Create a new cipher with a random key.
    pub fn new_random() -> Result<Self, &'static str> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; AEAD_KEY_SIZE];
        rng.fill(&mut key_bytes).map_err(|_| "RNG failed")?;
        Ok(Self { key_bytes })
    }

    /// Create a cipher from an existing key (e.g., after unsealing).
    pub fn from_key(key_bytes: [u8; AEAD_KEY_SIZE]) -> Self {
        Self { key_bytes }
    }

    /// Get the raw key bytes (for sealing).
    pub fn key_bytes(&self) -> &[u8; AEAD_KEY_SIZE] {
        &self.key_bytes
    }

    /// Encrypt plaintext. Returns `nonce || ciphertext || tag`.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        let rng = SystemRandom::new();

        // Generate a random nonce
        let mut nonce_bytes = [0u8; AEAD_NONCE_SIZE];
        rng.fill(&mut nonce_bytes).map_err(|_| "RNG failed")?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| "Invalid key")?;
        let key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // ring encrypts in-place and appends the tag
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| "Encryption failed")?;

        // Prepend nonce: [nonce (12) || ciphertext || tag (16)]
        let mut result = Vec::with_capacity(AEAD_NONCE_SIZE + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt ciphertext. Expects `nonce || ciphertext || tag`.
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
            return Err("Ciphertext too short");
        }

        let nonce_bytes: [u8; AEAD_NONCE_SIZE] = ciphertext[..AEAD_NONCE_SIZE]
            .try_into()
            .map_err(|_| "Invalid nonce")?;
        let encrypted = &ciphertext[AEAD_NONCE_SIZE..];

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| "Invalid key")?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = encrypted.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| "Decryption failed")?;

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = AeadCipher::new_random().unwrap();
        let plaintext = b"Hello, enclave!";
        let aad = b"kv_store";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        assert_ne!(&ciphertext[AEAD_NONCE_SIZE..], plaintext);

        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let cipher = AeadCipher::new_random().unwrap();
        let plaintext = b"secret data";

        let ciphertext = cipher.encrypt(plaintext, b"correct_aad").unwrap();
        let result = cipher.decrypt(&ciphertext, b"wrong_aad");
        assert!(result.is_err());
    }
}
