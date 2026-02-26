// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Integration tests for the config Merkle tree / X.509 extension round-trip.
//!
//! These tests reproduce the same logic used inside the enclave:
//!
//!   1. Build a config Merkle tree with a `core.ca_cert` leaf (the
//!      intermediary CA certificate).
//!   2. Compute the Merkle root.
//!   3. Embed the root as a custom X.509 extension at the Privasys
//!      Config Merkle Root OID (`1.3.6.1.4.1.1337.1.1`).
//!   4. Parse the extension back from the DER certificate and verify
//!      it matches.
//!
//! The key assertion: **changing the intermediary CA certificate changes
//! the Merkle root in the X.509 leaf**, proving that RA-TLS clients can
//! detect configuration drift by comparing the extension value.

use ring::digest;
use rcgen::{
    CertificateParams, CustomExtension, DnType, DnValue, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use x509_parser::prelude::*;

// Privasys OID: 1.3.6.1.4.1.1337.1.1
const CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 1337, 1, 1];

// The OID encoded as a dotted string for x509-parser lookup.
const CONFIG_MERKLE_ROOT_OID_STR: &str = "1.3.6.1.4.1.1337.1.1";

// ---------------------------------------------------------------------------
//  Helpers — mirror the enclave ConfigMerkleTree logic
// ---------------------------------------------------------------------------

/// Hash a single leaf's raw data (or 32 zero bytes if absent).
fn leaf_hash(data: Option<&[u8]>) -> [u8; 32] {
    match data {
        Some(d) => {
            let h = digest::digest(&digest::SHA256, d);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.as_ref());
            out
        }
        None => [0u8; 32],
    }
}

/// Compute the Merkle root from an ordered list of leaf hashes.
///
/// `root = SHA-256( leaf_hash_0 || leaf_hash_1 || … )`
fn merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(leaf_hashes.len() * 32);
    for h in leaf_hashes {
        preimage.extend_from_slice(h);
    }
    let d = digest::digest(&digest::SHA256, &preimage);
    let mut root = [0u8; 32];
    root.copy_from_slice(d.as_ref());
    root
}

/// Generate a self-signed ECDSA P-256 CA certificate, returning
/// `(der_cert, pkcs8_key)`.
fn generate_ca(cn: &str) -> (Vec<u8>, Vec<u8>) {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .expect("CA params");
    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.into()));
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen");
    let pkcs8 = key.serialized_der().to_vec();
    let cert = params.self_signed(&key).expect("self-sign");
    (cert.der().to_vec(), pkcs8)
}

/// Build a leaf cert signed by an intermediary CA, with the given config
/// Merkle root embedded as a custom X.509 extension.
///
/// Returns the DER-encoded leaf certificate.
fn build_leaf_cert_with_root(
    ca_cert_der: &[u8],
    ca_key_pkcs8: &[u8],
    merkle_root: &[u8; 32],
) -> Vec<u8> {
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    // Generate a fresh leaf key
    let leaf_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");

    let mut leaf_params = CertificateParams::new(Vec::<String>::new())
        .expect("leaf params");
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("RA-TLS Leaf (test)".into()),
    );
    leaf_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 12, 31);
    leaf_params.is_ca = IsCa::NoCa;

    // Embed the config Merkle root as a custom extension.
    let merkle_ext = CustomExtension::from_oid_content(
        CONFIG_MERKLE_ROOT_OID,
        merkle_root.to_vec(),
    );
    leaf_params.custom_extensions.push(merkle_ext);

    // Sign with the intermediary CA
    let ca_pkcs8 = PrivatePkcs8KeyDer::from(ca_key_pkcs8.to_vec());
    let ca_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &ca_pkcs8,
        &PKCS_ECDSA_P256_SHA256,
    )
    .expect("CA key parse");

    let ca_der = CertificateDer::from(ca_cert_der);
    let ca_params = CertificateParams::from_ca_cert_der(&ca_der)
        .expect("CA cert parse");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA re-sign");

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf sign");

    leaf_cert.der().to_vec()
}

/// Extract the config Merkle root extension value from a DER certificate.
///
/// Returns `None` if the extension is not present.
fn extract_merkle_root_extension(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).expect("parse X.509");
    for ext in cert.extensions() {
        if ext.oid.to_string() == CONFIG_MERKLE_ROOT_OID_STR {
            return Some(ext.value.to_vec());
        }
    }
    None
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

/// Building a Merkle tree with the same leaf data always produces the
/// same root — deterministic.
#[test]
fn merkle_root_is_deterministic() {
    let ca_der = b"test CA certificate bytes";
    let h = leaf_hash(Some(ca_der));
    let root_a = merkle_root(&[h]);
    let root_b = merkle_root(&[h]);
    assert_eq!(root_a, root_b);
}

/// Different leaf data produces a different root.
#[test]
fn merkle_root_changes_with_different_leaf() {
    let h_a = leaf_hash(Some(b"CA cert A"));
    let h_b = leaf_hash(Some(b"CA cert B"));
    let root_a = merkle_root(&[h_a]);
    let root_b = merkle_root(&[h_b]);
    assert_ne!(root_a, root_b);
}

/// An absent leaf (None) is a known zero hash, different from any real data.
#[test]
fn absent_leaf_produces_zero_hash() {
    let h = leaf_hash(None);
    assert_eq!(h, [0u8; 32]);

    // And the root differs from a non-absent leaf
    let root_absent = merkle_root(&[h]);
    let root_present = merkle_root(&[leaf_hash(Some(b"something"))]);
    assert_ne!(root_absent, root_present);
}

/// Multi-leaf tree: changing one leaf changes the root.
#[test]
fn multi_leaf_tree_root_changes_on_single_leaf_update() {
    let ca_hash = leaf_hash(Some(b"intermediary CA cert"));
    let egress_hash = leaf_hash(Some(b"egress CA bundle"));

    let root_before = merkle_root(&[ca_hash, egress_hash]);

    // Update the intermediary CA cert
    let ca_hash_new = leaf_hash(Some(b"new intermediary CA cert"));
    let root_after = merkle_root(&[ca_hash_new, egress_hash]);

    assert_ne!(root_before, root_after);
}

/// Leaf ordering matters — same leaves in different order yield different roots.
#[test]
fn leaf_order_affects_root() {
    let h1 = leaf_hash(Some(b"leaf one"));
    let h2 = leaf_hash(Some(b"leaf two"));
    assert_ne!(merkle_root(&[h1, h2]), merkle_root(&[h2, h1]));
}

/// End-to-end: generate two different intermediary CA certs, build the
/// Merkle tree for each, embed the root in an X.509 leaf certificate,
/// parse it back, and verify the roots differ.
#[test]
fn x509_merkle_root_changes_after_ca_update() {
    // --- Generate two distinct intermediary CAs ---
    let (ca_a_der, ca_a_key) = generate_ca("Intermediary CA A");
    let (ca_b_der, ca_b_key) = generate_ca("Intermediary CA B");
    assert_ne!(ca_a_der, ca_b_der, "CAs must differ");

    // --- Compute Merkle roots, mirroring enclave init ---
    // The enclave pushes: tree.push("core.ca_cert", Some(&ca_cert_der));
    let root_a = merkle_root(&[leaf_hash(Some(&ca_a_der))]);
    let root_b = merkle_root(&[leaf_hash(Some(&ca_b_der))]);
    assert_ne!(root_a, root_b, "Different CAs must yield different roots");

    // --- Build leaf certs with the respective Merkle roots ---
    let leaf_a = build_leaf_cert_with_root(&ca_a_der, &ca_a_key, &root_a);
    let leaf_b = build_leaf_cert_with_root(&ca_b_der, &ca_b_key, &root_b);

    // --- Extract the Merkle root extension from each leaf ---
    let ext_a = extract_merkle_root_extension(&leaf_a)
        .expect("Merkle root extension missing from leaf A");
    let ext_b = extract_merkle_root_extension(&leaf_b)
        .expect("Merkle root extension missing from leaf B");

    // --- Core assertion: X.509 extension values reflect the tree roots ---
    assert_eq!(ext_a.as_slice(), root_a.as_slice(),
        "Leaf A extension must match root A");
    assert_eq!(ext_b.as_slice(), root_b.as_slice(),
        "Leaf B extension must match root B");
    assert_ne!(ext_a, ext_b,
        "Extensions must differ after CA update");
}

/// Replacing only the intermediary CA (same egress bundle, same WASM
/// hashes) changes the root — even in a multi-leaf tree.
#[test]
fn x509_merkle_root_changes_in_multi_leaf_tree() {
    let (ca_a_der, ca_a_key) = generate_ca("Intermediary CA A (multi)");
    let (ca_b_der, ca_b_key) = generate_ca("Intermediary CA B (multi)");

    // Simulate a tree with three leaves:
    //   core.ca_cert       → changes
    //   egress.ca_bundle   → stays the same
    //   wasm.app1.code_hash → stays the same
    let egress_hash = leaf_hash(Some(b"shared PEM CA bundle"));
    let wasm_hash = leaf_hash(Some(b"app1 wasm bytecode sha256"));

    let root_a = merkle_root(&[leaf_hash(Some(&ca_a_der)), egress_hash, wasm_hash]);
    let root_b = merkle_root(&[leaf_hash(Some(&ca_b_der)), egress_hash, wasm_hash]);
    assert_ne!(root_a, root_b);

    // Build and parse leaf certs
    let leaf_a = build_leaf_cert_with_root(&ca_a_der, &ca_a_key, &root_a);
    let leaf_b = build_leaf_cert_with_root(&ca_b_der, &ca_b_key, &root_b);

    let ext_a = extract_merkle_root_extension(&leaf_a).unwrap();
    let ext_b = extract_merkle_root_extension(&leaf_b).unwrap();

    assert_eq!(ext_a.len(), 32, "Extension value must be 32 bytes");
    assert_eq!(ext_b.len(), 32, "Extension value must be 32 bytes");
    assert_ne!(ext_a, ext_b,
        "Multi-leaf root must change when only the CA leaf changes");
}

/// Verify the extension is correctly encoded and parseable as exactly 32 bytes.
#[test]
fn merkle_root_extension_is_32_bytes() {
    let (ca_der, ca_key) = generate_ca("Size Check CA");
    let root = merkle_root(&[leaf_hash(Some(&ca_der))]);
    let leaf = build_leaf_cert_with_root(&ca_der, &ca_key, &root);
    let ext = extract_merkle_root_extension(&leaf).unwrap();
    assert_eq!(ext.len(), 32);
}
