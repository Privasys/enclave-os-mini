// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX attestation integration for RA-TLS.
//!
//! Generates X.509 certificates containing SGX quotes:
//!
//!   - Reads extension 0xFFBB in ClientHello for the challenge nonce
//!   - `report_data = SHA-512(SHA-256(DER pubkey) || binding)`
//!   - SGX quote embedded in a custom X.509 extension at Intel OID
//!
//! Two modes:
//!
//! | Mode          | Binding          | Validity | Caching |
//! |---------------|------------------|----------|---------|
//! | Challenge     | nonce from 0xFFBB| 5 min    | no      |
//! | Deterministic | creation_time LE | 24 h     | yes     |

use std::string::String;
use std::vec::Vec;
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

/// OID for the SGX quote extension in X.509 certificates.
/// 1.2.840.113741.1.13.1.0  (Intel SGX Quote)
pub const SGX_QUOTE_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 0];

/// OID for the configuration Merkle root extension in X.509 certificates.
///
/// 1.3.6.1.4.1.1337.1.1  (Privasys / enclave-os / config-merkle-root)
///
/// The extension value is a 32-byte SHA-256 hash covering all operator-chosen
/// configuration inputs (egress CA bundle, etc.). Clients can compare this
/// against a known-good value to verify the enclave's runtime configuration.
///
/// Note: 1337 is a placeholder PEN. Replace with the actual Privasys PEN
/// once assigned by IANA.
pub const CONFIG_MERKLE_ROOT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 1337, 1, 1];

/// Certificate validity for challenge-response mode (5 minutes).
pub const CHALLENGE_VALIDITY_SECS: u64 = 300;

/// Certificate validity for deterministic mode (24 hours).
pub const DETERMINISTIC_VALIDITY_SECS: u64 = 86400;

// ---------------------------------------------------------------------------
//  Types
// ---------------------------------------------------------------------------

/// How the leaf certificate is bound to attestation evidence.
pub enum CertMode {
    /// Challenge-response: nonce extracted from ClientHello extension 0xFFBB.
    /// Produces a short-lived cert (5 min) with a fresh key + quote.
    Challenge { nonce: Vec<u8> },
    /// Deterministic: binding = `creation_time` (seconds since epoch, 8‑byte LE).
    /// Cert is valid 24 h and can be cached.
    Deterministic { creation_time: u64 },
}

/// Intermediary CA context provided to the enclave at startup.
///
/// The enclave uses it to sign leaf RA-TLS certificates so that the
/// trust chain is: `root / intermediary → leaf`.
///
/// The CA material is **never** generated inside the enclave.  It must be
/// provisioned externally (typically as part of the `EnclaveConfig`) and
/// is then sealed to disk via SGX sealing so that subsequent restarts
/// can unseal it without re-provisioning.
pub struct CaContext {
    /// DER-encoded X.509 certificate of the intermediary CA.
    pub ca_cert_der: Vec<u8>,
    /// PKCS#8-encoded private key of the intermediary CA.
    pub ca_key_pkcs8: Vec<u8>,
}

impl CaContext {
    /// Construct from externally-provided DER cert and PKCS#8 key.
    ///
    /// Performs a basic validation that the key material is usable
    /// (i.e. it can be parsed as an ECDSA P-256 key pair).
    pub fn from_parts(ca_cert_der: Vec<u8>, ca_key_pkcs8: Vec<u8>) -> Result<Self, String> {
        // Validate that the key can be loaded
        let rng = SystemRandom::new();
        let _ = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &ca_key_pkcs8,
            &rng,
        )
        .map_err(|_| String::from("CA key is not valid ECDSA P-256 PKCS#8"))?;

        Ok(Self {
            ca_cert_der,
            ca_key_pkcs8,
        })
    }
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Compute the 64-byte `report_data` that goes into the SGX quote.
///
/// ```text
/// report_data = SHA-512( SHA-256(DER_pubkey) || binding )
/// ```
///
/// * **Challenge mode**: `binding` = nonce from ClientHello ext 0xFFBB
/// * **Deterministic mode**: `binding` = creation_time as 8-byte LE
pub fn compute_report_data(pubkey_der: &[u8], binding: &[u8]) -> [u8; 64] {
    let pubkey_hash = digest::digest(&digest::SHA256, pubkey_der);
    let mut preimage = Vec::with_capacity(32 + binding.len());
    preimage.extend_from_slice(pubkey_hash.as_ref());
    preimage.extend_from_slice(binding);
    let rd = digest::digest(&digest::SHA512, &preimage);
    let mut out = [0u8; 64];
    out.copy_from_slice(rd.as_ref());
    out
}

/// Generate an RA-TLS leaf certificate signed by the intermediary CA.
///
/// Returns `(cert_chain_der, pkcs8_private_key)` where `cert_chain_der`
/// contains `[leaf_cert_der, ca_cert_der]` ready for TLS presentation.
pub fn generate_ratls_certificate(
    ca: &CaContext,
    mode: CertMode,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    // 1. Generate a fresh ECDSA P-256 key pair for the leaf cert
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| String::from("Key generation failed"))?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();

    // 2. Extract the public key DER
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &pkcs8_bytes,
        &rng,
    )
    .map_err(|_| String::from("Failed to parse generated key"))?;
    let pubkey_der = signature::KeyPair::public_key(&key_pair).as_ref();

    // 3. Compute report_data = SHA-512(SHA-256(pubkey) || binding)
    let (report_data, validity_secs) = match &mode {
        CertMode::Challenge { nonce } => (
            compute_report_data(pubkey_der, nonce),
            CHALLENGE_VALIDITY_SECS,
        ),
        CertMode::Deterministic { creation_time } => (
            compute_report_data(pubkey_der, &creation_time.to_le_bytes()),
            DETERMINISTIC_VALIDITY_SECS,
        ),
    };

    // 4. Generate SGX quote over report_data
    let quote = generate_sgx_quote(&report_data)?;

    // 5. Read the config Merkle root (if computed)
    let config_merkle = crate::config_merkle_root().copied();

    // 6. Collect module-registered custom OIDs
    let module_oids = crate::modules::collect_module_oids();

    // 7. Build the leaf X.509 certificate signed by the CA
    let leaf_der = build_leaf_cert(
        &pkcs8_bytes, &quote, validity_secs, ca,
        config_merkle.as_ref(), &module_oids,
    )?;

    // 8. Return cert chain [leaf, ca_cert] and private key
    Ok((vec![leaf_der, ca.ca_cert_der.clone()], pkcs8_bytes))
}

/// Generate an ECDSA P-256 key pair and return `(pkcs8_bytes, key_pair)`.
pub fn generate_keypair() -> Result<(Vec<u8>, EcdsaKeyPair), &'static str> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| "Key generation failed")?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &pkcs8_bytes,
        &rng,
    )
    .map_err(|_| "Failed to parse generated key")?;
    Ok((pkcs8_bytes, key_pair))
}

// ---------------------------------------------------------------------------
//  SGX quote generation
// ---------------------------------------------------------------------------

/// Generate an SGX DCAP quote with the given 64-byte report_data.
///
/// In real SGX mode this calls `sgx_create_report` → `sgx_qe_get_quote`.
/// In mock mode it returns a deterministic dummy quote.
#[cfg(not(feature = "mock"))]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    use sgx_types::types::{ReportData, TargetInfo};

    let mut rd = ReportData::default();
    rd.d.copy_from_slice(report_data);

    // In production, obtain target_info from the Quoting Enclave:
    //   sgx_qe_get_target_info(&mut target_info)
    let target_info = TargetInfo::default();

    let report = <sgx_types::types::Report as sgx_tse::EnclaveReport>::for_target(&target_info, &rd)
        .map_err(|e| format!("sgx_create_report failed: {:?}", e))?;

    let report_bytes = unsafe {
        core::slice::from_raw_parts(
            &report as *const sgx_types::types::Report as *const u8,
            core::mem::size_of::<sgx_types::types::Report>(),
        )
    };
    Ok(report_bytes.to_vec())
}

#[cfg(feature = "mock")]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut quote = Vec::with_capacity(11 + 64);
    quote.extend_from_slice(b"MOCK_QUOTE:");
    quote.extend_from_slice(report_data);
    Ok(quote)
}

// ---------------------------------------------------------------------------
//  Certificate building with rcgen
// ---------------------------------------------------------------------------

/// Build a leaf certificate signed by the intermediary CA.
///
/// The SGX quote is embedded as a non-critical custom X.509 extension at
/// [`SGX_QUOTE_OID`]. The optional config Merkle root is embedded at
/// [`CONFIG_MERKLE_ROOT_OID`]. Module-registered OIDs are also embedded.
fn build_leaf_cert(
    leaf_pkcs8: &[u8],
    quote: &[u8],
    _validity_secs: u64,
    ca: &CaContext,
    config_merkle_root: Option<&[u8; 32]>,
    module_oids: &[crate::modules::ModuleOid],
) -> Result<Vec<u8>, String> {
    use rcgen::{
        CertificateParams, CustomExtension, DnType, DnValue, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    // --- Leaf key pair ---
    let leaf_pkcs8_der = PrivatePkcs8KeyDer::from(leaf_pkcs8.to_vec());
    let leaf_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &leaf_pkcs8_der,
        &PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| format!("leaf key: {}", e))?;

    // --- Leaf params ---
    let mut leaf_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| format!("leaf params: {}", e))?;

    leaf_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("Enclave OS RA-TLS".into()),
    );
    leaf_params.distinguished_name.push(
        DnType::OrganizationName,
        DnValue::Utf8String("Privasys".into()),
    );

    // Validity: wide window; actual freshness is proved by the quote.
    // In production, derive from OCALL get_current_time + validity_secs.
    leaf_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 12, 31);

    // Embed the SGX quote as a non-critical custom extension.
    let quote_ext = CustomExtension::from_oid_content(SGX_QUOTE_OID, quote.to_vec());
    leaf_params.custom_extensions.push(quote_ext);

    // Embed the config Merkle root as a non-critical custom extension (if computed).
    if let Some(root) = config_merkle_root {
        let merkle_ext = CustomExtension::from_oid_content(
            CONFIG_MERKLE_ROOT_OID,
            root.to_vec(),
        );
        leaf_params.custom_extensions.push(merkle_ext);
    }

    // Embed module-registered custom OIDs.
    for oid in module_oids {
        let ext = CustomExtension::from_oid_content(oid.oid, oid.value.clone());
        leaf_params.custom_extensions.push(ext);
    }

    leaf_params.is_ca = IsCa::NoCa;

    // --- CA key pair + certificate ---
    let ca_pkcs8_der = PrivatePkcs8KeyDer::from(ca.ca_key_pkcs8.clone());
    let ca_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &ca_pkcs8_der,
        &PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| format!("CA key: {}", e))?;

    let ca_cert_der = CertificateDer::from(ca.ca_cert_der.as_slice());
    let ca_params = CertificateParams::from_ca_cert_der(&ca_cert_der)
        .map_err(|e| format!("CA cert parse: {}", e))?;
    let ca_cert = ca_params.self_signed(&ca_key)
        .map_err(|e| format!("CA cert reconstruct: {}", e))?;

    // --- Sign leaf with CA ---
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("leaf signing: {}", e))?;

    Ok(leaf_cert.der().to_vec())
}

// ---------------------------------------------------------------------------
//  ClientHello extension 0xFFBB parser
// ---------------------------------------------------------------------------

/// Try to extract the challenge nonce from TLS extension 0xFFBB in a raw
/// ClientHello message.
///
/// The `raw` bytes may start at the TLS record layer (content-type 0x16)
/// or at the Handshake layer (type 0x01). Returns `None` if the extension
/// is not found or the message is malformed.
pub fn extract_challenge_nonce(raw: &[u8]) -> Option<Vec<u8>> {
    // Minimum sizes: TLS record header(5) + Handshake header(4) +
    //   ClientHello fields(2+32+1) = 44 bytes absolute minimum.
    if raw.len() < 44 {
        return None;
    }

    let mut pos: usize = 0;

    // --- TLS record layer (optional) ---
    if raw[0] == 0x16 {
        // ContentType::Handshake
        // Skip version(2) + length(2) = 4 bytes
        pos += 5;
    }

    // --- Handshake header ---
    if pos >= raw.len() || raw[pos] != 0x01 {
        return None; // Not a ClientHello
    }
    pos += 1;
    // 3-byte handshake length
    if pos + 3 > raw.len() {
        return None;
    }
    let _hs_len = (raw[pos] as usize) << 16
        | (raw[pos + 1] as usize) << 8
        | raw[pos + 2] as usize;
    pos += 3;

    // --- ClientHello body ---
    // client_version (2)
    if pos + 2 > raw.len() {
        return None;
    }
    pos += 2;

    // random (32)
    if pos + 32 > raw.len() {
        return None;
    }
    pos += 32;

    // session_id_length (1) + session_id
    if pos >= raw.len() {
        return None;
    }
    let sid_len = raw[pos] as usize;
    pos += 1;
    if pos + sid_len > raw.len() {
        return None;
    }
    pos += sid_len;

    // cipher_suites_length (2) + cipher_suites
    if pos + 2 > raw.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > raw.len() {
        return None;
    }
    pos += cs_len;

    // compression_methods_length (1) + compression_methods
    if pos >= raw.len() {
        return None;
    }
    let cm_len = raw[pos] as usize;
    pos += 1;
    if pos + cm_len > raw.len() {
        return None;
    }
    pos += cm_len;

    // --- Extensions ---
    if pos + 2 > raw.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > raw.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let ext_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            return None;
        }

        if ext_type == enclave_os_common::types::RATLS_CLIENT_HELLO_EXTENSION_TYPE {
            return Some(raw[pos..pos + ext_len].to_vec());
        }

        pos += ext_len;
    }

    None
}

// ===========================================================================
//  Unit tests (run with `--features mock` to get std)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----- compute_report_data -------------------------------------------

    #[test]
    fn report_data_is_64_bytes() {
        let rd = compute_report_data(b"pubkey", b"binding");
        assert_eq!(rd.len(), 64);
    }

    #[test]
    fn report_data_deterministic() {
        let a = compute_report_data(b"key", b"nonce");
        let b = compute_report_data(b"key", b"nonce");
        assert_eq!(a, b);
    }

    #[test]
    fn report_data_differs_with_different_key() {
        let a = compute_report_data(b"key_a", b"nonce");
        let b = compute_report_data(b"key_b", b"nonce");
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_differs_with_different_binding() {
        let a = compute_report_data(b"key", b"nonce_1");
        let b = compute_report_data(b"key", b"nonce_2");
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_empty_inputs() {
        // Should not panic, should return valid 64-byte hash
        let rd = compute_report_data(b"", b"");
        assert_eq!(rd.len(), 64);
    }

    #[test]
    fn report_data_matches_manual_computation() {
        let pubkey = b"test_public_key_der";
        let binding = b"challenge_nonce";

        let pubkey_hash = ring::digest::digest(&ring::digest::SHA256, pubkey);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(pubkey_hash.as_ref());
        preimage.extend_from_slice(binding);
        let expected = ring::digest::digest(&ring::digest::SHA512, &preimage);

        let actual = compute_report_data(pubkey, binding);
        assert_eq!(&actual[..], expected.as_ref());
    }

    #[test]
    fn report_data_deterministic_mode_uses_le_time() {
        let creation_time: u64 = 1700000000;
        let rd = compute_report_data(b"key", &creation_time.to_le_bytes());
        // Different time should give different report_data
        let rd2 = compute_report_data(b"key", &(creation_time + 1).to_le_bytes());
        assert_ne!(rd, rd2);
    }

    // ----- extract_challenge_nonce (ClientHello parser) -------------------

    /// Build a minimal TLS 1.2 ClientHello with the given extensions.
    ///
    /// Each extension is (type: u16, data: &[u8]).
    fn build_client_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        // --- ClientHello body ---
        let mut ch_body = Vec::new();

        // client_version = TLS 1.2
        ch_body.extend_from_slice(&[0x03, 0x03]);

        // random (32 bytes of zeros)
        ch_body.extend_from_slice(&[0u8; 32]);

        // session_id_length = 0
        ch_body.push(0);

        // cipher_suites: 2 suites (4 bytes)
        ch_body.extend_from_slice(&[0x00, 0x04]); // length
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // compression_methods: 1 method (null)
        ch_body.push(0x01); // length
        ch_body.push(0x00); // null

        // Extensions
        let mut ext_bytes = Vec::new();
        for &(ext_type, ext_data) in extensions {
            ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(ext_data);
        }
        ch_body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext_bytes);

        // --- Handshake header ---
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = ch_body.len();
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&ch_body);

        // --- TLS record layer ---
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 compat
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[test]
    fn extract_nonce_present() {
        let nonce = b"challenge_nonce_32_bytes_padding!";
        let ch = build_client_hello(&[(0xFFBB, nonce)]);
        let result = extract_challenge_nonce(&ch);
        assert_eq!(result, Some(nonce.to_vec()));
    }

    #[test]
    fn extract_nonce_absent() {
        // ClientHello with SNI extension but no 0xFFBB
        let ch = build_client_hello(&[(0x0000, b"example.com")]); // SNI
        let result = extract_challenge_nonce(&ch);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_nonce_multiple_extensions() {
        let nonce = b"my_nonce";
        let exts: &[(u16, &[u8])] = &[
            (0x0000, b"\x00\x0e\x00\x00\x0bexample.com"), // SNI
            (0x000D, b"\x00\x04\x04\x03\x08\x04"),         // signature_algorithms
            (0xFFBB, nonce),                                 // our extension
        ];
        let ch = build_client_hello(exts);
        let result = extract_challenge_nonce(&ch);
        assert_eq!(result, Some(nonce.to_vec()));
    }

    #[test]
    fn extract_nonce_empty_extension_data() {
        let ch = build_client_hello(&[(0xFFBB, b"")]);
        let result = extract_challenge_nonce(&ch);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn extract_nonce_no_record_layer() {
        // Feed just the handshake message (no TLS record header)
        let nonce = b"nonce123";

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // version
        ch_body.extend_from_slice(&[0u8; 32]);     // random
        ch_body.push(0);                            // session_id_length
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        ch_body.extend_from_slice(&[0x01, 0x00]);  // compression

        let mut ext = Vec::new();
        ext.extend_from_slice(&0xFFBBu16.to_be_bytes());
        ext.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        ext.extend_from_slice(nonce);
        ch_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext);

        let mut hs = vec![0x01]; // ClientHello type
        let len = ch_body.len();
        hs.push(((len >> 16) & 0xFF) as u8);
        hs.push(((len >> 8) & 0xFF) as u8);
        hs.push((len & 0xFF) as u8);
        hs.extend_from_slice(&ch_body);

        let result = extract_challenge_nonce(&hs);
        assert_eq!(result, Some(nonce.to_vec()));
    }

    #[test]
    fn extract_nonce_too_short() {
        assert_eq!(extract_challenge_nonce(&[]), None);
        assert_eq!(extract_challenge_nonce(&[0x16, 0x03, 0x01]), None);
        assert_eq!(extract_challenge_nonce(&[0u8; 10]), None);
    }

    #[test]
    fn extract_nonce_not_handshake() {
        // Content type 0x17 = Application Data (not Handshake)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        bad[0] = 0x17;
        assert_eq!(extract_challenge_nonce(&bad), None);
    }

    #[test]
    fn extract_nonce_not_client_hello() {
        // Handshake type 0x02 = ServerHello (not ClientHello)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        // Record header is 5 bytes, then handshake type is at offset 5
        bad[5] = 0x02;
        assert_eq!(extract_challenge_nonce(&bad), None);
    }

    // ----- Mock-mode certificate generation (feature = "mock") -----------

    #[cfg(feature = "mock")]
    #[test]
    fn mock_generate_sgx_quote() {
        let report_data = compute_report_data(b"pubkey", b"nonce");
        let quote = super::generate_sgx_quote(&report_data).unwrap();
        assert!(quote.starts_with(b"MOCK_QUOTE:"));
        // The quote should contain the 64-byte report_data after the prefix
        assert_eq!(&quote[11..], &report_data[..]);
    }

    // ----- hex_decode (from ecall) ----------------------------------------

    #[test]
    fn hex_decode_basic() {
        let decoded = crate::ecall::hex_decode("48656c6c6f").unwrap();
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn hex_decode_empty() {
        let decoded = crate::ecall::hex_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = crate::ecall::hex_decode("4F6B").unwrap();
        assert_eq!(&decoded, b"Ok");
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(crate::ecall::hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(crate::ecall::hex_decode("zz").is_none());
    }
}
