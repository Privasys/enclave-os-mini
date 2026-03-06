// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Tests for per-app X.509 certificate identity architecture.
//!
//! Each WASM app loaded into the enclave gets its own leaf X.509
//! certificate (signed by the Enclave CA) with:
//!   - A per-app config Merkle root (code_hash + key_source leaves)
//!   - A code hash OID extension for fast-path verification
//!   - A key source OID extension (`"generated"` or `"byok:<fingerprint>"`)
//!   - An SNI-routed hostname
//!
//! These tests reproduce the Merkle tree + X.509 extension logic
//! and verify that per-app identities are correctly isolated.

use ring::digest;
use rcgen::{
    CertificateParams, CustomExtension, DnType, DnValue, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use x509_parser::prelude::*;

use enclave_os_common::oids::{
    APP_CODE_HASH_OID, APP_CODE_HASH_OID_STR,
    APP_CONFIG_MERKLE_ROOT_OID, APP_CONFIG_MERKLE_ROOT_OID_STR,
    APP_KEY_SOURCE_OID, APP_KEY_SOURCE_OID_STR,
};

// ---------------------------------------------------------------------------
//  Helpers — mirror the enclave CertStore Merkle logic
// ---------------------------------------------------------------------------

/// Hash a single config entry's raw value bytes.
fn entry_hash(value: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, value);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Compute the per-app Merkle root from an ordered list of entry hashes.
///
/// `root = SHA-256( SHA-256(e0.value) || SHA-256(e1.value) || … )`
///
/// This mirrors `CertStore::compute_app()` in the enclave.
fn per_app_merkle_root(entry_values: &[&[u8]]) -> [u8; 32] {
    if entry_values.is_empty() {
        return [0u8; 32];
    }
    let mut preimage = Vec::with_capacity(entry_values.len() * 32);
    for val in entry_values {
        let h = entry_hash(val);
        preimage.extend_from_slice(&h);
    }
    let d = digest::digest(&digest::SHA256, &preimage);
    let mut root = [0u8; 32];
    root.copy_from_slice(d.as_ref());
    root
}

/// Simulate the config entries for a WASM app with a given code hash
/// and key source, then compute the per-app Merkle root.
///
/// The enclave registers these entries in `WasmModule::load_app()`:
///   1. `wasm.<name>.code_hash` → raw 32-byte SHA-256
///   2. `wasm.<name>.key_source` → `"generated"` or `"byok:<fingerprint>"`
fn app_merkle_root(code_hash: &[u8; 32], key_source: &str) -> [u8; 32] {
    per_app_merkle_root(&[code_hash.as_slice(), key_source.as_bytes()])
}

/// Generate a self-signed ECDSA P-256 CA certificate.
fn generate_ca(cn: &str) -> (Vec<u8>, Vec<u8>) {
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.into()));
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen");
    let pkcs8 = key.serialized_der().to_vec();
    let cert = params.self_signed(&key).expect("self-sign");
    (cert.der().to_vec(), pkcs8)
}

/// Build a per-app leaf certificate with both:
///   - `APP_CONFIG_MERKLE_ROOT_OID` (per-app Merkle root)
///   - `APP_CODE_HASH_OID` (per-app code hash)
///   - `APP_KEY_SOURCE_OID` (per-app key source)
///
/// This mirrors the attestation logic in `generate_app_certificate()`.
fn build_app_leaf_cert(
    ca_cert_der: &[u8],
    ca_key_pkcs8: &[u8],
    hostname: &str,
    merkle_root: &[u8; 32],
    code_hash: &[u8; 32],
    key_source: &str,
) -> Vec<u8> {
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let leaf_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");

    let mut leaf_params =
        CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String(hostname.into()),
    );
    leaf_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 12, 31);
    leaf_params.is_ca = IsCa::NoCa;

    // Per-app Merkle root extension
    leaf_params.custom_extensions.push(
        CustomExtension::from_oid_content(
            APP_CONFIG_MERKLE_ROOT_OID,
            merkle_root.to_vec(),
        ),
    );

    // Per-app code hash extension
    leaf_params.custom_extensions.push(
        CustomExtension::from_oid_content(
            APP_CODE_HASH_OID,
            code_hash.to_vec(),
        ),
    );

    // Per-app key source extension
    leaf_params.custom_extensions.push(
        CustomExtension::from_oid_content(
            APP_KEY_SOURCE_OID,
            key_source.as_bytes().to_vec(),
        ),
    );

    // Sign with the CA
    let ca_pkcs8 = PrivatePkcs8KeyDer::from(ca_key_pkcs8.to_vec());
    let ca_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &ca_pkcs8,
        &PKCS_ECDSA_P256_SHA256,
    )
    .expect("CA key parse");
    let ca_der = CertificateDer::from(ca_cert_der);
    let ca_params =
        CertificateParams::from_ca_cert_der(&ca_der).expect("CA cert parse");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA re-sign");

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf sign");

    leaf_cert.der().to_vec()
}

/// Extract an extension value by OID string from a DER certificate.
fn extract_extension(cert_der: &[u8], oid_str: &str) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).expect("parse X.509");
    for ext in cert.extensions() {
        if ext.oid.to_string() == oid_str {
            return Some(ext.value.to_vec());
        }
    }
    None
}

/// Extract the Subject CN from a DER certificate.
fn extract_cn(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).expect("parse X.509");
    let result = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    result
}

// ---------------------------------------------------------------------------
//  Tests — Per-app Merkle tree
// ---------------------------------------------------------------------------

/// Each app's Merkle root is computed from its config entries.
/// Two apps with the same code hash but different key sources → different roots.
#[test]
fn different_key_source_produces_different_merkle_root() {
    let code_hash = entry_hash(b"some wasm bytecode");

    let root_generated = app_merkle_root(&code_hash, "generated");
    let root_byok = app_merkle_root(&code_hash, "byok:abc123");

    assert_ne!(
        root_generated, root_byok,
        "Same code hash with different key_source must yield different Merkle roots"
    );
}

/// Two apps with different code hashes but the same key source → different roots.
#[test]
fn different_code_hash_produces_different_merkle_root() {
    let hash_a = entry_hash(b"wasm app A");
    let hash_b = entry_hash(b"wasm app B");

    let root_a = app_merkle_root(&hash_a, "generated");
    let root_b = app_merkle_root(&hash_b, "generated");

    assert_ne!(
        root_a, root_b,
        "Different code hashes with same key_source must yield different roots"
    );
}

/// Two apps with identical code hash and key source → identical roots.
#[test]
fn same_config_produces_same_merkle_root() {
    let code_hash = entry_hash(b"identical wasm bytecode");

    let root_a = app_merkle_root(&code_hash, "byok:abc123");
    let root_b = app_merkle_root(&code_hash, "byok:abc123");

    assert_eq!(root_a, root_b, "Identical config must produce identical roots");
}

/// Empty config entries → zero root.
#[test]
fn empty_config_produces_zero_root() {
    let root = per_app_merkle_root(&[]);
    assert_eq!(root, [0u8; 32]);
}

/// Merkle root is deterministic (same inputs always produce the same output).
#[test]
fn merkle_root_is_deterministic() {
    let code_hash = entry_hash(b"stable wasm app");
    let root_1 = app_merkle_root(&code_hash, "generated");
    let root_2 = app_merkle_root(&code_hash, "generated");
    assert_eq!(root_1, root_2);
}

/// Leaf ordering matters — code_hash first, key_source second.
/// Swapping them changes the root.
#[test]
fn entry_order_affects_merkle_root() {
    let code_hash = entry_hash(b"order test wasm");
    let key_source = b"generated";

    // Normal order (code_hash, key_source) — matches enclave logic
    let root_normal = per_app_merkle_root(&[&code_hash, key_source]);
    // Swapped order
    let root_swapped = per_app_merkle_root(&[key_source, &code_hash]);

    assert_ne!(
        root_normal, root_swapped,
        "Entry ordering must affect the Merkle root"
    );
}

// ---------------------------------------------------------------------------
//  Tests — Per-app X.509 certificates
// ---------------------------------------------------------------------------

/// Per-app leaf cert contains the Merkle root, code hash, and key source extensions.
#[test]
fn app_leaf_cert_contains_expected_extensions() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");
    let code_hash = entry_hash(b"hello.wasm");
    let root = app_merkle_root(&code_hash, "generated");

    let leaf = build_app_leaf_cert(
        &ca_der, &ca_key,
        "hello.enclave.local",
        &root, &code_hash, "generated",
    );

    let ext_root = extract_extension(&leaf, APP_CONFIG_MERKLE_ROOT_OID_STR)
        .expect("Per-app Merkle root extension missing");
    let ext_hash = extract_extension(&leaf, APP_CODE_HASH_OID_STR)
        .expect("Per-app code hash extension missing");
    let ext_ks = extract_extension(&leaf, APP_KEY_SOURCE_OID_STR)
        .expect("Per-app key source extension missing");

    assert_eq!(ext_root.as_slice(), root.as_slice());
    assert_eq!(ext_hash.as_slice(), code_hash.as_slice());
    assert_eq!(ext_ks.as_slice(), b"generated");
}

/// Per-app leaf cert has the hostname as Subject CN.
#[test]
fn app_leaf_cert_has_hostname_as_cn() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");
    let code_hash = entry_hash(b"payments.wasm");
    let root = app_merkle_root(&code_hash, "byok:abc123");

    let leaf = build_app_leaf_cert(
        &ca_der, &ca_key,
        "payments.example.com",
        &root, &code_hash, "byok:abc123",
    );

    let cn = extract_cn(&leaf).expect("Subject CN missing");
    assert_eq!(cn, "payments.example.com");
}

/// Two different apps get different Merkle roots and code hashes.
#[test]
fn different_apps_get_different_certs() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");

    let hash_a = entry_hash(b"app-a.wasm");
    let root_a = app_merkle_root(&hash_a, "generated");
    let leaf_a = build_app_leaf_cert(
        &ca_der, &ca_key, "app-a.enclave.local", &root_a, &hash_a, "generated",
    );

    let hash_b = entry_hash(b"app-b.wasm");
    let root_b = app_merkle_root(&hash_b, "byok:def456");
    let leaf_b = build_app_leaf_cert(
        &ca_der, &ca_key, "app-b.enclave.local", &root_b, &hash_b, "byok:def456",
    );

    let ext_root_a = extract_extension(&leaf_a, APP_CONFIG_MERKLE_ROOT_OID_STR).unwrap();
    let ext_root_b = extract_extension(&leaf_b, APP_CONFIG_MERKLE_ROOT_OID_STR).unwrap();
    assert_ne!(ext_root_a, ext_root_b, "Different apps must have different Merkle roots");

    let ext_hash_a = extract_extension(&leaf_a, APP_CODE_HASH_OID_STR).unwrap();
    let ext_hash_b = extract_extension(&leaf_b, APP_CODE_HASH_OID_STR).unwrap();
    assert_ne!(ext_hash_a, ext_hash_b, "Different apps must have different code hashes");

    let ext_ks_a = extract_extension(&leaf_a, APP_KEY_SOURCE_OID_STR).unwrap();
    let ext_ks_b = extract_extension(&leaf_b, APP_KEY_SOURCE_OID_STR).unwrap();
    assert_ne!(ext_ks_a, ext_ks_b, "Different apps must have different key sources");

    let cn_a = extract_cn(&leaf_a).unwrap();
    let cn_b = extract_cn(&leaf_b).unwrap();
    assert_ne!(cn_a, cn_b, "Different apps must have different hostnames");
}

/// Changing only the key_source (byok:… ↔ generated) changes the Merkle root
/// but NOT the code hash extension — proving they are independent.
#[test]
fn key_source_change_affects_only_merkle_root() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");
    let code_hash = entry_hash(b"same-code.wasm");

    let root_gen = app_merkle_root(&code_hash, "generated");
    let root_byok = app_merkle_root(&code_hash, "byok:abc123");

    let leaf_gen = build_app_leaf_cert(
        &ca_der, &ca_key, "app.local", &root_gen, &code_hash, "generated",
    );
    let leaf_byok = build_app_leaf_cert(
        &ca_der, &ca_key, "app.local", &root_byok, &code_hash, "byok:abc123",
    );

    // Merkle roots differ
    let ext_root_gen = extract_extension(&leaf_gen, APP_CONFIG_MERKLE_ROOT_OID_STR).unwrap();
    let ext_root_byok = extract_extension(&leaf_byok, APP_CONFIG_MERKLE_ROOT_OID_STR).unwrap();
    assert_ne!(ext_root_gen, ext_root_byok, "Key source change must affect Merkle root");

    // Code hashes are the same
    let ext_hash_gen = extract_extension(&leaf_gen, APP_CODE_HASH_OID_STR).unwrap();
    let ext_hash_byok = extract_extension(&leaf_byok, APP_CODE_HASH_OID_STR).unwrap();
    assert_eq!(ext_hash_gen, ext_hash_byok, "Code hash must be unchanged");

    // Key source extensions differ
    let ext_ks_gen = extract_extension(&leaf_gen, APP_KEY_SOURCE_OID_STR).unwrap();
    let ext_ks_byok = extract_extension(&leaf_byok, APP_KEY_SOURCE_OID_STR).unwrap();
    assert_eq!(ext_ks_gen.as_slice(), b"generated");
    assert!(ext_ks_byok.starts_with(b"byok:"), "BYOK key source must start with byok:");
    assert_ne!(ext_ks_gen, ext_ks_byok, "Key source extensions must differ");
}

/// Per-app binary extensions (Merkle root, code hash) are exactly 32 bytes;
/// the key source extension is a variable-length UTF-8 string.
#[test]
fn per_app_extensions_are_32_bytes() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");
    let code_hash = entry_hash(b"size-check.wasm");
    let root = app_merkle_root(&code_hash, "generated");

    let leaf = build_app_leaf_cert(
        &ca_der, &ca_key, "check.local", &root, &code_hash, "generated",
    );

    let ext_root = extract_extension(&leaf, APP_CONFIG_MERKLE_ROOT_OID_STR).unwrap();
    let ext_hash = extract_extension(&leaf, APP_CODE_HASH_OID_STR).unwrap();
    let ext_ks = extract_extension(&leaf, APP_KEY_SOURCE_OID_STR).unwrap();

    assert_eq!(ext_root.len(), 32, "Merkle root extension must be 32 bytes");
    assert_eq!(ext_hash.len(), 32, "Code hash extension must be 32 bytes");
    assert_eq!(ext_ks.as_slice(), b"generated", "Key source must be \"generated\"");
}

/// A cert without per-app extensions (simulating the enclave-wide cert)
/// does NOT contain the per-app OIDs.
#[test]
fn enclave_wide_cert_lacks_per_app_extensions() {
    let (ca_der, ca_key) = generate_ca("Test Enclave CA");

    // Build a leaf cert WITHOUT per-app extensions (enclave-wide)
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let leaf_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("enclave-wide".into()),
    );
    params.is_ca = IsCa::NoCa;

    let ca_pkcs8 = PrivatePkcs8KeyDer::from(ca_key.clone());
    let ca_kp = KeyPair::from_pkcs8_der_and_sign_algo(
        &ca_pkcs8,
        &PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let ca_cert_der = CertificateDer::from(ca_der.as_slice());
    let ca_params =
        CertificateParams::from_ca_cert_der(&ca_cert_der).unwrap();
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

    let leaf = params
        .signed_by(&leaf_key, &ca_cert, &ca_kp)
        .unwrap();

    let leaf_der = leaf.der().to_vec();

    assert!(
        extract_extension(&leaf_der, APP_CONFIG_MERKLE_ROOT_OID_STR).is_none(),
        "Enclave-wide cert must NOT contain per-app Merkle root OID"
    );
    assert!(
        extract_extension(&leaf_der, APP_CODE_HASH_OID_STR).is_none(),
        "Enclave-wide cert must NOT contain per-app code hash OID"
    );
    assert!(
        extract_extension(&leaf_der, APP_KEY_SOURCE_OID_STR).is_none(),
        "Enclave-wide cert must NOT contain per-app key source OID"
    );
}
