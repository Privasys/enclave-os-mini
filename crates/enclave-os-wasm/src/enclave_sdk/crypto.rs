// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/crypto@0.1.0` — Cryptographic primitives.
//!
//! All operations execute inside the SGX enclave using `ring`.
//! Keys are referenced by name from the enclave keystore (see
//! [`super::keystore`]).  The host never sees plaintext or key material.
//!
//! ## Supported algorithms
//!
//! | Operation | Algorithm | Notes |
//! |-----------|-----------|-------|
//! | Digest | SHA-256, SHA-384, SHA-512 | Stateless, no key needed |
//! | Encrypt | AES-256-GCM | 12-byte IV, returns ciphertext‖tag |
//! | Sign | ECDSA P-256+SHA-256, P-384+SHA-384 | ASN.1 DER signatures |
//! | HMAC | HMAC-SHA-256/384/512 | Tag generation + verification |
//! | Random | RDRAND | Hardware RNG (SGX) |
//!
//! ## Typed host bindings
//!
//! Like [`super::https`], this module uses [`wasmtime::component::bindgen!`]
//! so the WIT is the single source of truth: algorithm `enum`s become real
//! Rust enums and the host implements a generated [`Host`] trait. There is no
//! manual `Val` decoding — adding a new algorithm is a WIT case plus one
//! match arm the compiler forces every site to handle. The `keystore`
//! interface is generated here too (it `use`s crypto's algorithm enums, so a
//! single `bindgen!` keeps the two type sets unified); its `Host` impl lives
//! in [`super::keystore`].

use std::string::String;
use std::vec::Vec;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair};

use wasmtime::component::{HasSelf, Linker};

use super::AppContext;

// =========================================================================
//  Generated bindings — privasys:enclave-os/{crypto,keystore}@0.1.0
// =========================================================================

wasmtime::component::bindgen!({
    inline: r#"
        package privasys:enclave-os@0.1.0;

        interface crypto {
            enum digest-algorithm { sha256, sha384, sha512 }
            enum sign-algorithm { ecdsa-p256-sha256, ecdsa-p384-sha384 }
            enum hmac-algorithm { hmac-sha256, hmac-sha384, hmac-sha512 }

            digest: func(algorithm: digest-algorithm, data: list<u8>) -> result<list<u8>, string>;
            encrypt: func(key-name: string, iv: list<u8>, aad: list<u8>, plaintext: list<u8>) -> result<list<u8>, string>;
            decrypt: func(key-name: string, iv: list<u8>, aad: list<u8>, ciphertext: list<u8>) -> result<list<u8>, string>;
            sign: func(key-name: string, algorithm: sign-algorithm, data: list<u8>) -> result<list<u8>, string>;
            verify: func(key-name: string, algorithm: sign-algorithm, data: list<u8>, signature: list<u8>) -> result<bool, string>;
            hmac-sign: func(key-name: string, algorithm: hmac-algorithm, data: list<u8>) -> result<list<u8>, string>;
            hmac-verify: func(key-name: string, algorithm: hmac-algorithm, data: list<u8>, tag: list<u8>) -> result<bool, string>;
            get-random-bytes: func(len: u32) -> result<list<u8>, string>;
        }

        interface keystore {
            use crypto.{sign-algorithm, hmac-algorithm};

            generate-symmetric-key: func(key-name: string) -> result<_, string>;
            generate-signing-key: func(key-name: string, algorithm: sign-algorithm) -> result<_, string>;
            generate-hmac-key: func(key-name: string, algorithm: hmac-algorithm) -> result<_, string>;
            import-symmetric-key: func(key-name: string, raw-key: list<u8>) -> result<_, string>;
            export-public-key: func(key-name: string) -> result<list<u8>, string>;
            delete-key: func(key-name: string) -> result<_, string>;
            key-exists: func(key-name: string) -> result<bool, string>;
            persist-key: func(key-name: string) -> result<_, string>;
            load-key: func(key-name: string) -> result<_, string>;
        }

        world crypto-host {
            import crypto;
            import keystore;
        }
    "#,
    world: "crypto-host",
});

// Re-export the generated interface modules under unambiguous names so the
// sibling `keystore` host module (itself named `keystore`) can refer to the
// shared algorithm enums without a `crypto::crypto::…` path.
pub use privasys::enclave_os::crypto as crypto_wit;
pub use privasys::enclave_os::keystore as keystore_wit;

// =========================================================================
//  Host trait implementation — privasys:enclave-os/crypto@0.1.0
// =========================================================================

impl crypto_wit::Host for AppContext {
    fn digest(
        &mut self,
        algorithm: crypto_wit::DigestAlgorithm,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.usage.crypto_digest_bytes += data.len() as i64;
        let alg = match algorithm {
            crypto_wit::DigestAlgorithm::Sha256 => &digest::SHA256,
            crypto_wit::DigestAlgorithm::Sha384 => &digest::SHA384,
            crypto_wit::DigestAlgorithm::Sha512 => &digest::SHA512,
        };
        Ok(digest::digest(alg, &data).as_ref().to_vec())
    }

    fn encrypt(
        &mut self,
        key_name: String,
        iv: Vec<u8>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.usage.crypto_encdec_bytes += plaintext.len() as i64;
        if iv.len() != NONCE_LEN {
            return Err("IV must be 12 bytes".into());
        }

        let key_bytes = self
            .keystore
            .get_symmetric(&key_name)
            .ok_or_else(|| "key not found or not a symmetric key".to_string())?;

        let unbound =
            UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| "invalid AES key".to_string())?;
        let key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&iv);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext;
        key.seal_in_place_append_tag(nonce, Aad::from(&aad), &mut in_out)
            .map_err(|_| "encryption failed".to_string())?;
        Ok(in_out)
    }

    fn decrypt(
        &mut self,
        key_name: String,
        iv: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.usage.crypto_encdec_bytes += ciphertext.len() as i64;
        if iv.len() != NONCE_LEN {
            return Err("IV must be 12 bytes".into());
        }

        let key_bytes = self
            .keystore
            .get_symmetric(&key_name)
            .ok_or_else(|| "key not found or not a symmetric key".to_string())?;

        let unbound =
            UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| "invalid AES key".to_string())?;
        let key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&iv);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext;
        let plaintext = key
            .open_in_place(nonce, Aad::from(&aad), &mut in_out)
            .map_err(|_| "decryption failed (bad key, IV, AAD, or tampered data)".to_string())?;
        Ok(plaintext.to_vec())
    }

    fn sign(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::SignAlgorithm,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.usage.crypto_sign_calls += 1;
        let signing_algo = match algorithm {
            crypto_wit::SignAlgorithm::EcdsaP256Sha256 => {
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING
            }
            crypto_wit::SignAlgorithm::EcdsaP384Sha384 => {
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING
            }
        };

        let pkcs8 = self
            .keystore
            .get_signing(&key_name)
            .ok_or_else(|| "key not found or not a signing key".to_string())?;

        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_algo, &pkcs8, &rng)
            .map_err(|_| "failed to load signing key".to_string())?;

        let sig = key_pair
            .sign(&rng, &data)
            .map_err(|_| "signing failed".to_string())?;
        Ok(sig.as_ref().to_vec())
    }

    fn verify(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::SignAlgorithm,
        data: Vec<u8>,
        sig: Vec<u8>,
    ) -> Result<bool, String> {
        self.usage.crypto_verify_calls += 1;
        let (signing_algo, verify_algo): (
            &signature::EcdsaSigningAlgorithm,
            &dyn signature::VerificationAlgorithm,
        ) = match algorithm {
            crypto_wit::SignAlgorithm::EcdsaP256Sha256 => (
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            crypto_wit::SignAlgorithm::EcdsaP384Sha384 => (
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &signature::ECDSA_P384_SHA384_ASN1,
            ),
        };

        let pkcs8 = self
            .keystore
            .get_signing(&key_name)
            .ok_or_else(|| "key not found or not a signing key".to_string())?;

        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_algo, &pkcs8, &rng)
            .map_err(|_| "failed to load signing key".to_string())?;

        let public_key = key_pair.public_key();
        let peer_key = signature::UnparsedPublicKey::new(verify_algo, public_key.as_ref());
        Ok(peer_key.verify(&data, &sig).is_ok())
    }

    fn hmac_sign(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::HmacAlgorithm,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let hmac_algo = match algorithm {
            crypto_wit::HmacAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
            crypto_wit::HmacAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
            crypto_wit::HmacAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
        };

        let key_bytes = self
            .keystore
            .get_hmac(&key_name)
            .ok_or_else(|| "key not found or not an HMAC key".to_string())?;

        let hmac_key = hmac::Key::new(hmac_algo, &key_bytes);
        Ok(hmac::sign(&hmac_key, &data).as_ref().to_vec())
    }

    fn hmac_verify(
        &mut self,
        key_name: String,
        algorithm: crypto_wit::HmacAlgorithm,
        data: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<bool, String> {
        let hmac_algo = match algorithm {
            crypto_wit::HmacAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
            crypto_wit::HmacAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
            crypto_wit::HmacAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
        };

        let key_bytes = self
            .keystore
            .get_hmac(&key_name)
            .ok_or_else(|| "key not found or not an HMAC key".to_string())?;

        let hmac_key = hmac::Key::new(hmac_algo, &key_bytes);
        Ok(hmac::verify(&hmac_key, &data, &tag).is_ok())
    }

    fn get_random_bytes(&mut self, len: u32) -> Result<Vec<u8>, String> {
        let len = len as usize;
        if len > 65536 {
            return Err("maximum 65536 bytes per call".into());
        }
        self.usage.crypto_random_bytes += len as i64;

        let rng = SystemRandom::new();
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf).map_err(|_| "RNG failed".to_string())?;
        Ok(buf)
    }
}

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    crypto_wit::add_to_linker::<_, HasSelf<_>>(linker, |s| s)
}
