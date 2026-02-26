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

use std::string::String;
use std::vec::Vec;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair};

use wasmtime::component::{Linker, Val};
use wasmtime::StoreContextMut;

use super::keystore::{KeyMaterial, KeyStore};
use super::AppContext;

// =========================================================================
//  privasys:enclave-os/crypto@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/crypto@0.1.0")?;

    // ── digest ─────────────────────────────────────────────────────
    // func(algorithm: u32, data: list<u8>) -> result<list<u8>, string>
    //   algorithm: 0=SHA-256, 1=SHA-384, 2=SHA-512
    inst.func_new(
        "digest",
        |_store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let algo = match &params[0] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };
            let data = val_to_bytes(&params[1]);

            let algorithm = match algo {
                0 => &digest::SHA256,
                1 => &digest::SHA384,
                2 => &digest::SHA512,
                _ => {
                    results[0] = err_result("unsupported digest algorithm");
                    return Ok(());
                }
            };

            let hash = digest::digest(algorithm, &data);
            results[0] = ok_bytes(hash.as_ref());
            Ok(())
        },
    )?;

    // ── encrypt ────────────────────────────────────────────────────
    // func(key-name: string, iv: list<u8>, aad: list<u8>, plaintext: list<u8>)
    //      -> result<list<u8>, string>
    inst.func_new(
        "encrypt",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let iv = val_to_bytes(&params[1]);
            let aad = val_to_bytes(&params[2]);
            let plaintext = val_to_bytes(&params[3]);

            if iv.len() != NONCE_LEN {
                results[0] = err_result("IV must be 12 bytes");
                return Ok(());
            }

            let key_bytes = match store.data().keystore.get_symmetric(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not a symmetric key");
                    return Ok(());
                }
            };

            let unbound = match UnboundKey::new(&AES_256_GCM, &key_bytes) {
                Ok(k) => k,
                Err(_) => {
                    results[0] = err_result("invalid AES key");
                    return Ok(());
                }
            };
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; NONCE_LEN];
            nonce_bytes.copy_from_slice(&iv);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = plaintext;
            match key.seal_in_place_append_tag(nonce, Aad::from(&aad), &mut in_out) {
                Ok(()) => {
                    results[0] = ok_bytes(&in_out);
                }
                Err(_) => {
                    results[0] = err_result("encryption failed");
                }
            }
            Ok(())
        },
    )?;

    // ── decrypt ────────────────────────────────────────────────────
    // func(key-name: string, iv: list<u8>, aad: list<u8>, ciphertext: list<u8>)
    //      -> result<list<u8>, string>
    inst.func_new(
        "decrypt",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let iv = val_to_bytes(&params[1]);
            let aad = val_to_bytes(&params[2]);
            let ciphertext = val_to_bytes(&params[3]);

            if iv.len() != NONCE_LEN {
                results[0] = err_result("IV must be 12 bytes");
                return Ok(());
            }

            let key_bytes = match store.data().keystore.get_symmetric(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not a symmetric key");
                    return Ok(());
                }
            };

            let unbound = match UnboundKey::new(&AES_256_GCM, &key_bytes) {
                Ok(k) => k,
                Err(_) => {
                    results[0] = err_result("invalid AES key");
                    return Ok(());
                }
            };
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; NONCE_LEN];
            nonce_bytes.copy_from_slice(&iv);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = ciphertext;
            match key.open_in_place(nonce, Aad::from(&aad), &mut in_out) {
                Ok(plaintext) => {
                    results[0] = ok_bytes(plaintext);
                }
                Err(_) => {
                    results[0] = err_result("decryption failed (bad key, IV, AAD, or tampered data)");
                }
            }
            Ok(())
        },
    )?;

    // ── sign ───────────────────────────────────────────────────────
    // func(key-name: string, algorithm: u32, data: list<u8>)
    //      -> result<list<u8>, string>
    //   algorithm: 0=ECDSA-P256-SHA256, 1=ECDSA-P384-SHA384
    inst.func_new(
        "sign",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };
            let data = val_to_bytes(&params[2]);

            let signing_algo = match algo {
                0 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                1 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => {
                    results[0] = err_result("unsupported sign algorithm");
                    return Ok(());
                }
            };

            let pkcs8 = match store.data().keystore.get_signing(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not a signing key");
                    return Ok(());
                }
            };

            let rng = SystemRandom::new();
            let key_pair = match EcdsaKeyPair::from_pkcs8(signing_algo, &pkcs8, &rng) {
                Ok(kp) => kp,
                Err(_) => {
                    results[0] = err_result("failed to load signing key");
                    return Ok(());
                }
            };

            match key_pair.sign(&rng, &data) {
                Ok(sig) => {
                    results[0] = ok_bytes(sig.as_ref());
                }
                Err(_) => {
                    results[0] = err_result("signing failed");
                }
            }
            Ok(())
        },
    )?;

    // ── verify ─────────────────────────────────────────────────────
    // func(key-name: string, algorithm: u32, data: list<u8>, signature: list<u8>)
    //      -> result<bool, string>
    inst.func_new(
        "verify",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };
            let data = val_to_bytes(&params[2]);
            let sig_bytes = val_to_bytes(&params[3]);

            let (signing_algo, verify_algo): (
                &signature::EcdsaSigningAlgorithm,
                &dyn signature::VerificationAlgorithm,
            ) = match algo {
                0 => (
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &signature::ECDSA_P256_SHA256_ASN1,
                ),
                1 => (
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &signature::ECDSA_P384_SHA384_ASN1,
                ),
                _ => {
                    results[0] = err_result("unsupported sign algorithm");
                    return Ok(());
                }
            };

            // Get the public key from the stored PKCS#8 key pair.
            let pkcs8 = match store.data().keystore.get_signing(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not a signing key");
                    return Ok(());
                }
            };

            let rng = SystemRandom::new();
            let key_pair = match EcdsaKeyPair::from_pkcs8(signing_algo, &pkcs8, &rng) {
                Ok(kp) => kp,
                Err(_) => {
                    results[0] = err_result("failed to load signing key");
                    return Ok(());
                }
            };

            let public_key = key_pair.public_key();
            let peer_key =
                signature::UnparsedPublicKey::new(verify_algo, public_key.as_ref());

            let valid = peer_key.verify(&data, &sig_bytes).is_ok();
            results[0] = ok_bool(valid);
            Ok(())
        },
    )?;

    // ── hmac-sign ──────────────────────────────────────────────────
    // func(key-name: string, algorithm: u32, data: list<u8>)
    //      -> result<list<u8>, string>
    //   algorithm: 0=HMAC-SHA256, 1=HMAC-SHA384, 2=HMAC-SHA512
    inst.func_new(
        "hmac-sign",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };
            let data = val_to_bytes(&params[2]);

            let hmac_algo = match algo {
                0 => hmac::HMAC_SHA256,
                1 => hmac::HMAC_SHA384,
                2 => hmac::HMAC_SHA512,
                _ => {
                    results[0] = err_result("unsupported HMAC algorithm");
                    return Ok(());
                }
            };

            let key_bytes = match store.data().keystore.get_hmac(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not an HMAC key");
                    return Ok(());
                }
            };

            let hmac_key = hmac::Key::new(hmac_algo, &key_bytes);
            let tag = hmac::sign(&hmac_key, &data);
            results[0] = ok_bytes(tag.as_ref());
            Ok(())
        },
    )?;

    // ── hmac-verify ────────────────────────────────────────────────
    // func(key-name: string, algorithm: u32, data: list<u8>, tag: list<u8>)
    //      -> result<bool, string>
    inst.func_new(
        "hmac-verify",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let key_name = val_to_string(&params[0]);
            let algo = match &params[1] {
                Val::U32(v) => *v,
                Val::Enum(v) => *v,
                _ => {
                    results[0] = err_result("invalid algorithm parameter");
                    return Ok(());
                }
            };
            let data = val_to_bytes(&params[2]);
            let tag_bytes = val_to_bytes(&params[3]);

            let hmac_algo = match algo {
                0 => hmac::HMAC_SHA256,
                1 => hmac::HMAC_SHA384,
                2 => hmac::HMAC_SHA512,
                _ => {
                    results[0] = err_result("unsupported HMAC algorithm");
                    return Ok(());
                }
            };

            let key_bytes = match store.data().keystore.get_hmac(&key_name) {
                Some(k) => k,
                None => {
                    results[0] = err_result("key not found or not an HMAC key");
                    return Ok(());
                }
            };

            let hmac_key = hmac::Key::new(hmac_algo, &key_bytes);
            let valid = hmac::verify(&hmac_key, &data, &tag_bytes).is_ok();
            results[0] = ok_bool(valid);
            Ok(())
        },
    )?;

    // ── get-random-bytes ───────────────────────────────────────────
    // func(len: u32) -> result<list<u8>, string>
    inst.func_new(
        "get-random-bytes",
        |_store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let len = match &params[0] {
                Val::U32(v) => *v as usize,
                _ => {
                    results[0] = err_result("invalid length parameter");
                    return Ok(());
                }
            };

            if len > 65536 {
                results[0] = err_result("maximum 65536 bytes per call");
                return Ok(());
            }

            let rng = SystemRandom::new();
            let mut buf = vec![0u8; len];
            match rng.fill(&mut buf) {
                Ok(()) => {
                    results[0] = ok_bytes(&buf);
                }
                Err(_) => {
                    results[0] = err_result("RNG failed");
                }
            }
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  Val helpers
// =========================================================================

fn val_to_string(val: &Val) -> String {
    match val {
        Val::String(s) => s.to_string(),
        _ => String::new(),
    }
}

fn val_to_bytes(val: &Val) -> Vec<u8> {
    match val {
        Val::List(items) => items
            .iter()
            .filter_map(|v| match v {
                Val::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn ok_bytes(data: &[u8]) -> Val {
    Val::Result(Ok(Some(Box::new(Val::List(
        data.iter().map(|b| Val::U8(*b)).collect::<Vec<_>>().into(),
    )))))
}

fn ok_bool(v: bool) -> Val {
    Val::Result(Ok(Some(Box::new(Val::Bool(v)))))
}

fn err_result(msg: &str) -> Val {
    Val::Result(Err(Some(Box::new(Val::String(msg.into())))))
}
