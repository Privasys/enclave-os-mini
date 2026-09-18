// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The NTS AEAD algorithms this client offers.
//!
//! - AEAD_AES_SIV_CMAC_256 (id 15, RFC 5297): 32-byte key, 16-byte nonce,
//!   output is the 16-byte SIV tag followed by the ciphertext. Mandatory
//!   to implement for NTS.
//! - AEAD_AES_128_GCM_SIV (id 30, RFC 8452): 16-byte key, 12-byte nonce,
//!   output is the ciphertext followed by the 16-byte tag. Some servers
//!   pick it when offered, and some only answer NTP with it.
//!
//! Both come from RustCrypto, pure Rust. The enclave build selects their
//! portable (bitsliced, constant-time) AES and POLYVAL backends, so no CPU
//! feature detection runs inside the enclave for them.

use aes_gcm_siv::Aes128GcmSiv;
use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes128SivAead;
use alloc::vec::Vec;

/// One of the offered NTS AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtsAead {
    /// AEAD_AES_SIV_CMAC_256, IANA id 15.
    AesSivCmac256,
    /// AEAD_AES_128_GCM_SIV, IANA id 30.
    Aes128GcmSiv,
}

/// What the client offers in NTS-KE, in order of preference.
pub const OFFERED: [NtsAead; 2] = [NtsAead::Aes128GcmSiv, NtsAead::AesSivCmac256];

/// Longest key of the offered algorithms.
pub const MAX_KEY_LEN: usize = 32;
/// Longest nonce of the offered algorithms.
pub const MAX_NONCE_LEN: usize = 16;

impl NtsAead {
    /// IANA AEAD algorithm id.
    pub fn id(self) -> u16 {
        match self {
            NtsAead::AesSivCmac256 => 15,
            NtsAead::Aes128GcmSiv => 30,
        }
    }

    /// The offered algorithm with this id.
    pub fn from_id(id: u16) -> Option<Self> {
        OFFERED.iter().copied().find(|a| a.id() == id)
    }

    /// Key length, which is also the exporter output length per direction.
    pub fn key_len(self) -> usize {
        match self {
            NtsAead::AesSivCmac256 => 32,
            NtsAead::Aes128GcmSiv => 16,
        }
    }

    /// Nonce length this client sends and accepts.
    pub fn nonce_len(self) -> usize {
        match self {
            NtsAead::AesSivCmac256 => 16,
            NtsAead::Aes128GcmSiv => 12,
        }
    }

    /// Encrypt `plaintext` authenticating `aad`. `None` on a wrong key or
    /// nonce length.
    pub fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        if key.len() != self.key_len() || nonce.len() != self.nonce_len() {
            return None;
        }
        let payload = Payload { msg: plaintext, aad };
        match self {
            NtsAead::AesSivCmac256 => Aes128SivAead::new_from_slice(key)
                .ok()?
                .encrypt(aes_siv::Nonce::from_slice(nonce), payload)
                .ok(),
            NtsAead::Aes128GcmSiv => Aes128GcmSiv::new_from_slice(key)
                .ok()?
                .encrypt(aes_gcm_siv::Nonce::from_slice(nonce), payload)
                .ok(),
        }
    }

    /// Verify and decrypt. `None` when the tag does not verify (or on a
    /// wrong key or nonce length).
    pub fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if key.len() != self.key_len() || nonce.len() != self.nonce_len() {
            return None;
        }
        let payload = Payload { msg: ciphertext, aad };
        match self {
            NtsAead::AesSivCmac256 => Aes128SivAead::new_from_slice(key)
                .ok()?
                .decrypt(aes_siv::Nonce::from_slice(nonce), payload)
                .ok(),
            NtsAead::Aes128GcmSiv => Aes128GcmSiv::new_from_slice(key)
                .ok()?
                .decrypt(aes_gcm_siv::Nonce::from_slice(nonce), payload)
                .ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_siv::siv::Aes128Siv;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc5297_deterministic_vector_confirms_tag_first() {
        // RFC 5297 appendix A.1.
        let key = hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = hex("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = hex("112233445566778899aabbccddee");
        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let out = siv.encrypt(&[&ad], &pt).unwrap();
        assert_eq!(out, hex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"));
    }

    #[test]
    fn siv_aead_is_s2v_over_ad_then_nonce() {
        let key = [1u8; 32];
        let nonce = [5u8; 16];
        let a = NtsAead::AesSivCmac256.seal(&key, &nonce, b"header bytes", b"pt").unwrap();
        let b = Aes128Siv::new_from_slice(&key).unwrap().encrypt(&[&b"header bytes"[..], &nonce[..]], b"pt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rfc8452_gcm_siv_vectors() {
        // RFC 8452 appendix C.1, first two AEAD_AES_128_GCM_SIV vectors.
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let out = NtsAead::Aes128GcmSiv.seal(&key, &nonce, b"", b"").unwrap();
        assert_eq!(out, hex("dc20e2d83f25705bb49e439eca56de25"));
        let out = NtsAead::Aes128GcmSiv.seal(&key, &nonce, b"", &hex("0100000000000000")).unwrap();
        assert_eq!(out, hex("b5d839330ac7b786578782fff6013b815b287c22493a364c"));
    }

    #[test]
    fn roundtrip_and_tamper() {
        for a in OFFERED {
            let key = alloc::vec![7u8; a.key_len()];
            let nonce = alloc::vec![9u8; a.nonce_len()];
            let ct = a.seal(&key, &nonce, b"aad", b"hello").unwrap();
            assert_eq!(a.open(&key, &nonce, b"aad", &ct).unwrap(), b"hello");
            assert!(a.open(&key, &nonce, b"aaD", &ct).is_none());
            assert!(a.seal(&key[1..], &nonce, b"", b"").is_none());
            assert!(a.seal(&key, &nonce[1..], b"", b"").is_none());
            assert_eq!(NtsAead::from_id(a.id()), Some(a));
        }
        assert_eq!(NtsAead::from_id(1), None);
    }
}
