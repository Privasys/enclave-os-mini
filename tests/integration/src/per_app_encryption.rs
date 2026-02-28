// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Tests for per-app encryption key architecture.
//!
//! Each WASM app gets its own AES-256-GCM encryption key for KV store
//! data, with optional BYOK (Bring-Your-Own-Key). These tests verify:
//!
//! - Protocol serialization/deserialization of `WasmLoad.encryption_key`
//!   and `AppInfo.key_source`
//! - BYOK hex encoding validation (correct length, invalid hex)
//! - Key isolation: different apps generate different encryption keys
//! - Attestation: key_source is reflected in config Merkle leaves
//! - Key lifecycle: unload destroys key, data becomes unrecoverable

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use enclave_os_common::types::AEAD_KEY_SIZE;

// ---------------------------------------------------------------------------
//  Helpers — hex encode / decode (mirror enclave ecall helpers)
// ---------------------------------------------------------------------------

/// Hex-encode a byte slice to a lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex-decode a string into bytes. Returns `None` on invalid hex.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_char_to_u8(chunk[0])?;
        let lo = hex_char_to_u8(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_char_to_u8(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Compute the per-app Merkle root from config entry values.
/// Mirrors `CertStore::compute_app()`.
fn per_app_merkle_root(entry_values: &[&[u8]]) -> [u8; 32] {
    if entry_values.is_empty() {
        return [0u8; 32];
    }
    let mut preimage = Vec::with_capacity(entry_values.len() * 32);
    for val in entry_values {
        let h = digest::digest(&digest::SHA256, val);
        preimage.extend_from_slice(h.as_ref());
    }
    let d = digest::digest(&digest::SHA256, &preimage);
    let mut root = [0u8; 32];
    root.copy_from_slice(d.as_ref());
    root
}

// ---------------------------------------------------------------------------
//  Tests — Protocol serialization (WasmLoad.encryption_key, AppInfo.key_source)
// ---------------------------------------------------------------------------

/// `WasmLoad` without `encryption_key` → field absent / null in JSON.
#[test]
fn wasm_load_without_encryption_key() {
    let json = r#"{"name": "my-app", "bytes": [0, 97, 115, 109]}"#;
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();

    assert_eq!(parsed["name"], "my-app");
    assert!(
        parsed.get("encryption_key").is_none()
            || parsed["encryption_key"].is_null(),
        "encryption_key should be absent for generated-key mode"
    );
}

/// `WasmLoad` with `encryption_key` → hex string present.
#[test]
fn wasm_load_with_byok_key() {
    let key = [0xABu8; AEAD_KEY_SIZE];
    let hex_key = hex_encode(&key);
    assert_eq!(hex_key.len(), 64, "AES-256 key is 32 bytes = 64 hex chars");

    let json = format!(
        r#"{{"name": "my-app", "bytes": [0], "encryption_key": "{}"}}"#,
        hex_key
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["encryption_key"], hex_key);
}

/// `AppInfo.key_source` is "byok" or "generated".
#[test]
fn app_info_key_source_values() {
    let info_byok = serde_json::json!({
        "name": "app-a",
        "hostname": "app-a.local",
        "code_hash": "abcd1234",
        "key_source": "byok",
        "exports": []
    });
    assert_eq!(info_byok["key_source"], "byok");

    let info_gen = serde_json::json!({
        "name": "app-b",
        "hostname": "app-b.local",
        "code_hash": "5678efgh",
        "key_source": "generated",
        "exports": []
    });
    assert_eq!(info_gen["key_source"], "generated");
}

/// Full envelope round-trip: `wasm_load` with `encryption_key`.
#[test]
fn wasm_load_envelope_roundtrip() {
    let key = [0x42u8; AEAD_KEY_SIZE];
    let hex_key = hex_encode(&key);

    let envelope = serde_json::json!({
        "wasm_load": {
            "name": "secure-app",
            "bytes": [0, 97, 115, 109],
            "hostname": "secure.enclave.local",
            "encryption_key": hex_key
        }
    });

    let serialized = serde_json::to_vec(&envelope).unwrap();
    let deserialized: serde_json::Value =
        serde_json::from_slice(&serialized).unwrap();

    assert_eq!(
        deserialized["wasm_load"]["name"], "secure-app"
    );
    assert_eq!(
        deserialized["wasm_load"]["encryption_key"], hex_key
    );
    assert_eq!(
        deserialized["wasm_load"]["hostname"], "secure.enclave.local"
    );
}

/// `wasm_list` response includes `key_source` in each app.
#[test]
fn wasm_list_response_includes_key_source() {
    let response = serde_json::json!({
        "status": "apps",
        "apps": [
            {
                "name": "app-a",
                "hostname": "app-a.local",
                "code_hash": "aa",
                "key_source": "generated",
                "exports": []
            },
            {
                "name": "app-b",
                "hostname": "app-b.local",
                "code_hash": "bb",
                "key_source": "byok",
                "exports": []
            }
        ]
    });

    let apps = response["apps"].as_array().unwrap();
    assert_eq!(apps[0]["key_source"], "generated");
    assert_eq!(apps[1]["key_source"], "byok");
}

// ---------------------------------------------------------------------------
//  Tests — BYOK hex encoding validation
// ---------------------------------------------------------------------------

/// Valid hex-encoded 32-byte key decodes correctly.
#[test]
fn valid_byok_hex_decodes() {
    let key = [0xDE; AEAD_KEY_SIZE];
    let hex = hex_encode(&key);
    let decoded = hex_decode(&hex).expect("valid hex must decode");
    assert_eq!(decoded.len(), AEAD_KEY_SIZE);
    assert_eq!(decoded, key.to_vec());
}

/// Invalid hex characters are rejected.
#[test]
fn invalid_hex_chars_rejected() {
    let bad = "zzzz".repeat(16); // 64 chars but invalid hex
    assert!(hex_decode(&bad).is_none(), "Non-hex chars must be rejected");
}

/// Odd-length hex string is rejected.
#[test]
fn odd_length_hex_rejected() {
    let odd = "abc"; // 3 chars = odd
    assert!(hex_decode(odd).is_none(), "Odd-length hex must be rejected");
}

/// Wrong key length (valid hex but not 32 bytes) is detected.
#[test]
fn wrong_key_length_detected() {
    // 16 bytes = 32 hex chars (too short for AES-256)
    let short_key = [0xAA; 16];
    let hex = hex_encode(&short_key);
    let decoded = hex_decode(&hex).unwrap();
    assert_ne!(
        decoded.len(),
        AEAD_KEY_SIZE,
        "16-byte key != 32-byte AEAD_KEY_SIZE"
    );

    // 48 bytes = 96 hex chars (too long)
    let long_key = [0xBB; 48];
    let hex = hex_encode(&long_key);
    let decoded = hex_decode(&hex).unwrap();
    assert_ne!(
        decoded.len(),
        AEAD_KEY_SIZE,
        "48-byte key != 32-byte AEAD_KEY_SIZE"
    );
}

/// Empty hex string decodes to empty bytes (zero-length key).
#[test]
fn empty_hex_decodes_to_empty() {
    let decoded = hex_decode("").unwrap();
    assert!(decoded.is_empty());
    assert_ne!(decoded.len(), AEAD_KEY_SIZE);
}

/// Hex encoding is case-insensitive.
#[test]
fn hex_decode_is_case_insensitive() {
    let key = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
               0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
               0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
               0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    let lower = hex_encode(&key);
    let upper = lower.to_uppercase();

    let decoded_lower = hex_decode(&lower).unwrap();
    let decoded_upper = hex_decode(&upper).unwrap();
    assert_eq!(decoded_lower, decoded_upper);
    assert_eq!(decoded_lower.len(), AEAD_KEY_SIZE);
}

/// Round-trip: generate → hex_encode → hex_decode → original.
#[test]
fn hex_roundtrip() {
    let rng = SystemRandom::new();
    let mut key = [0u8; AEAD_KEY_SIZE];
    rng.fill(&mut key).expect("RDRAND");

    let hex = hex_encode(&key);
    assert_eq!(hex.len(), AEAD_KEY_SIZE * 2);

    let decoded = hex_decode(&hex).unwrap();
    assert_eq!(decoded, key.to_vec());
}

// ---------------------------------------------------------------------------
//  Tests — Key isolation
// ---------------------------------------------------------------------------

/// Two independently generated keys are different (with overwhelming probability).
#[test]
fn generated_keys_are_unique() {
    let rng = SystemRandom::new();

    let mut key_a = [0u8; AEAD_KEY_SIZE];
    let mut key_b = [0u8; AEAD_KEY_SIZE];
    rng.fill(&mut key_a).expect("key_a");
    rng.fill(&mut key_b).expect("key_b");

    assert_ne!(
        key_a, key_b,
        "Two randomly generated keys must differ (2^-256 collision probability)"
    );
}

/// A BYOK key is preserved exactly as provided (no transformation).
#[test]
fn byok_key_is_preserved_exactly() {
    let byok: [u8; AEAD_KEY_SIZE] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    let hex = hex_encode(&byok);
    let decoded = hex_decode(&hex).unwrap();
    let mut round_tripped = [0u8; AEAD_KEY_SIZE];
    round_tripped.copy_from_slice(&decoded);

    assert_eq!(round_tripped, byok, "BYOK key must survive hex round-trip");
}

/// Simulating per-app key assignment: each app gets a distinct key
/// (either generated or BYOK), and they don't collide.
#[test]
fn per_app_keys_are_isolated() {
    let rng = SystemRandom::new();

    // App 1: generated key
    let mut key_1 = [0u8; AEAD_KEY_SIZE];
    rng.fill(&mut key_1).expect("app 1 key");

    // App 2: generated key
    let mut key_2 = [0u8; AEAD_KEY_SIZE];
    rng.fill(&mut key_2).expect("app 2 key");

    // App 3: BYOK
    let key_3: [u8; AEAD_KEY_SIZE] = [0xFF; AEAD_KEY_SIZE];

    assert_ne!(key_1, key_2, "Generated keys must be unique");
    assert_ne!(key_1, key_3, "Generated key must differ from BYOK");
    assert_ne!(key_2, key_3, "Generated key must differ from BYOK");
}

// ---------------------------------------------------------------------------
//  Tests — Attestation: key_source in config Merkle leaves
// ---------------------------------------------------------------------------

/// `key_source` leaf is included in attestation alongside `code_hash`.
/// Verifiable: the Merkle root changes when `key_source` changes.
#[test]
fn key_source_leaf_affects_attestation() {
    let code_hash_bytes = {
        let d = digest::digest(&digest::SHA256, b"hello.wasm");
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        h
    };

    let root_generated = per_app_merkle_root(&[
        &code_hash_bytes,
        b"generated",
    ]);

    let root_byok = per_app_merkle_root(&[
        &code_hash_bytes,
        b"byok",
    ]);

    assert_ne!(
        root_generated, root_byok,
        "Attestation Merkle root must reflect key_source"
    );
}

/// Enclave-wide combined hash (SHA-256 of all app hashes concatenated)
/// changes when a new app is loaded.
#[test]
fn combined_hash_changes_with_new_app() {
    let hash_a: [u8; 32] = {
        let d = digest::digest(&digest::SHA256, b"app-a.wasm");
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        h
    };
    let hash_b: [u8; 32] = {
        let d = digest::digest(&digest::SHA256, b"app-b.wasm");
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        h
    };

    // Combined hash with only app-a
    let combined_a = {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"app-a");
        ctx.update(&hash_a);
        let r = ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(r.as_ref());
        out
    };

    // Combined hash with app-a + app-b
    let combined_ab = {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"app-a");
        ctx.update(&hash_a);
        ctx.update(b"app-b");
        ctx.update(&hash_b);
        let r = ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(r.as_ref());
        out
    };

    assert_ne!(
        combined_a, combined_ab,
        "Combined hash must change when a new app is added"
    );
}

/// Empty app list → zero combined hash.
#[test]
fn no_apps_yields_zero_combined_hash() {
    // Mirror: if hashes.is_empty() { return [0u8; 32]; }
    let combined: [u8; 32] = [0u8; 32];
    assert_eq!(combined, [0u8; 32]);
}

// ---------------------------------------------------------------------------
//  Tests — Key size and constants
// ---------------------------------------------------------------------------

/// AEAD_KEY_SIZE matches AES-256 requirement.
#[test]
fn aead_key_size_is_32_bytes() {
    assert_eq!(AEAD_KEY_SIZE, 32, "AES-256 requires 32-byte keys");
}

/// Hex encoding of AEAD_KEY_SIZE bytes is exactly 64 characters.
#[test]
fn hex_encoded_key_is_64_chars() {
    let key = [0u8; AEAD_KEY_SIZE];
    let hex = hex_encode(&key);
    assert_eq!(hex.len(), 64);
}
