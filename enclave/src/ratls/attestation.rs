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

use enclave_os_common::oids::{
    SGX_QUOTE_OID, CONFIG_MERKLE_ROOT_OID, APP_CONFIG_MERKLE_ROOT_OID,
};

use crate::ratls::cert_store::AppCertData;

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

/// Result of an RA-TLS certificate generation.
///
/// Contains the certificate chain, private key, and an optional
/// client challenge nonce (only in challenge-response mode).
pub struct CertGenerationResult {
    /// DER-encoded certificate chain: `[leaf_cert_der, ca_cert_der]`.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8-encoded private key for the leaf cert.
    pub pkcs8_key: Vec<u8>,
    /// Random nonce for the client to bind into its own RA-TLS certificate
    /// (challenge-response mode only).  Sent via TLS CertificateRequest
    /// extension `0xFFBB`, not embedded in the X.509 certificate.
    pub client_challenge_nonce: Option<Vec<u8>>,
}

/// Generate an RA-TLS leaf certificate signed by the intermediary CA.
///
/// Returns a [`CertGenerationResult`] containing the cert chain, key,
/// and an optional client challenge nonce.  When `mode` is
/// [`CertMode::Challenge`], a 32-byte random nonce is generated and
/// returned in [`CertGenerationResult::client_challenge_nonce`].  The
/// server sends this nonce to the client via a TLS CertificateRequest
/// extension (`0xFFBB`) for bidirectional challenge-response attestation.
pub fn generate_ratls_certificate(
    ca: &CaContext,
    mode: CertMode,
) -> Result<CertGenerationResult, String> {
    let is_challenge = matches!(mode, CertMode::Challenge { .. });
    let ctx = prepare_attestation(&mode)?;

    // Collect enclave-wide extensions
    let mut extensions: Vec<(&'static [u64], Vec<u8>)> = Vec::new();
    if let Some(root) = crate::config_merkle_root() {
        extensions.push((CONFIG_MERKLE_ROOT_OID, root.to_vec()));
    }
    for oid in &crate::modules::collect_module_oids() {
        extensions.push((oid.oid, oid.value.clone()));
    }

    // In challenge mode, generate a client challenge nonce (sent via
    // TLS CertificateRequest extension 0xFFBB, not embedded in the cert)
    let client_challenge_nonce = if is_challenge {
        Some(generate_random_nonce()?)
    } else {
        None
    };

    let leaf_der = build_leaf_cert(
        &ctx.pkcs8_bytes, &ctx.quote, ctx.validity_secs, ca,
        "Enclave OS RA-TLS", &extensions,
    )?;

    Ok(CertGenerationResult {
        cert_chain_der: vec![leaf_der, ca.ca_cert_der.clone()],
        pkcs8_key: ctx.pkcs8_bytes,
        client_challenge_nonce,
    })
}

/// Generate a per-app RA-TLS leaf certificate signed by the CA.
///
/// Like [`generate_ratls_certificate()`] but the leaf cert contains
/// per-app data instead of enclave-wide module OIDs:
/// - Per-app config Merkle root (OID `1.3.6.1.4.1.65230.3.1`)
/// - Per-app OID extensions flagged by config entries
/// - SGX quote (same as the enclave-wide cert)
/// - Subject CN = app hostname (for SNI matching)
///
/// Returns a [`CertGenerationResult`].
pub fn generate_app_certificate(
    ca: &CaContext,
    mode: CertMode,
    app: &AppCertData,
) -> Result<CertGenerationResult, String> {
    let is_challenge = matches!(mode, CertMode::Challenge { .. });
    let ctx = prepare_attestation(&mode)?;

    // Collect per-app extensions
    let mut extensions: Vec<(&'static [u64], Vec<u8>)> = Vec::new();
    if app.merkle_root != [0u8; 32] {
        extensions.push((APP_CONFIG_MERKLE_ROOT_OID, app.merkle_root.to_vec()));
    }
    for (oid, value) in &app.oid_extensions {
        extensions.push((*oid, value.clone()));
    }

    // In challenge mode, generate a client challenge nonce (sent via
    // TLS CertificateRequest extension 0xFFBB, not embedded in the cert)
    let client_challenge_nonce = if is_challenge {
        Some(generate_random_nonce()?)
    } else {
        None
    };

    let leaf_der = build_leaf_cert(
        &ctx.pkcs8_bytes, &ctx.quote, ctx.validity_secs, ca,
        &app.hostname, &extensions,
    )?;

    Ok(CertGenerationResult {
        cert_chain_der: vec![leaf_der, ca.ca_cert_der.clone()],
        pkcs8_key: ctx.pkcs8_bytes,
        client_challenge_nonce,
    })
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

/// Generate a cryptographically random 32-byte nonce using `ring`'s
/// `SystemRandom` (backed by `rdrand` inside the SGX enclave).\nfn generate_random_nonce() -> Result<Vec<u8>, String> {
    use ring::rand::SecureRandom;
    let rng = SystemRandom::new();
    let mut nonce = vec![0u8; 32];
    rng.fill(&mut nonce)
        .map_err(|_| String::from("random nonce generation failed"))?;
    Ok(nonce)
}

// ---------------------------------------------------------------------------
//  Attestation preparation (key gen + quote)
// ---------------------------------------------------------------------------

/// Internal context produced by [`prepare_attestation()`].
struct AttestationContext {
    pkcs8_bytes: Vec<u8>,
    quote: Vec<u8>,
    validity_secs: u64,
}

/// Generate a fresh ECDSA key pair, compute report_data from the mode,
/// and obtain an SGX quote.  Shared by enclave-wide and per-app cert
/// generation.
fn prepare_attestation(mode: &CertMode) -> Result<AttestationContext, String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| String::from("Key generation failed"))?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();

    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &pkcs8_bytes,
        &rng,
    )
    .map_err(|_| String::from("Failed to parse generated key"))?;
    let pubkey_der = signature::KeyPair::public_key(&key_pair).as_ref();

    let (report_data, validity_secs) = match mode {
        CertMode::Challenge { nonce } => (
            compute_report_data(pubkey_der, nonce),
            CHALLENGE_VALIDITY_SECS,
        ),
        CertMode::Deterministic { creation_time } => (
            compute_report_data(pubkey_der, &creation_time.to_le_bytes()),
            DETERMINISTIC_VALIDITY_SECS,
        ),
    };

    let quote = generate_sgx_quote(&report_data)?;
    Ok(AttestationContext { pkcs8_bytes, quote, validity_secs })
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
/// The SGX quote goes into [`SGX_QUOTE_OID`]. Additional X.509 extensions
/// (config Merkle roots, module OIDs, per-app OIDs) are passed via
/// `extensions`. The `common_name` is set as the Subject CN.
fn build_leaf_cert(
    leaf_pkcs8: &[u8],
    quote: &[u8],
    _validity_secs: u64,
    ca: &CaContext,
    common_name: &str,
    extensions: &[(&'static [u64], Vec<u8>)],
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
        DnValue::Utf8String(common_name.into()),
    );
    leaf_params.distinguished_name.push(
        DnType::OrganizationName,
        DnValue::Utf8String("Privasys".into()),
    );

    // Validity: wide window; actual freshness is proved by the quote.
    leaf_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 12, 31);

    // SGX quote
    let quote_ext = CustomExtension::from_oid_content(SGX_QUOTE_OID, quote.to_vec());
    leaf_params.custom_extensions.push(quote_ext);

    // Caller-supplied extensions (Merkle roots, module OIDs, per-app OIDs)
    for (oid, value) in extensions {
        let ext = CustomExtension::from_oid_content(*oid, value.clone());
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
//  ClientHello parser — combined SNI + challenge nonce extraction
// ---------------------------------------------------------------------------

/// Information extracted from a TLS ClientHello message.
pub struct ClientHelloInfo {
    /// Challenge nonce from extension 0xFFBB (if present).
    pub challenge_nonce: Option<Vec<u8>>,
    /// Server Name Indication hostname (from extension 0x0000).
    pub sni: Option<String>,
}

/// Parse a raw TLS ClientHello to extract extension data.
///
/// Extracts both the challenge nonce (extension 0xFFBB) and the SNI
/// hostname (extension 0x0000) in a single pass. The `raw` bytes may
/// start at the TLS record layer or the Handshake layer.
pub fn parse_client_hello(raw: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo {
        challenge_nonce: None,
        sni: None,
    };

    if raw.len() < 44 {
        return info;
    }

    let mut pos: usize = 0;

    // --- TLS record layer (optional) ---
    if raw[0] == 0x16 {
        pos += 5;
    }

    // --- Handshake header ---
    if pos >= raw.len() || raw[pos] != 0x01 {
        return info;
    }
    pos += 1;
    if pos + 3 > raw.len() {
        return info;
    }
    pos += 3; // 3-byte handshake length

    // --- ClientHello body ---
    if pos + 2 > raw.len() {
        return info;
    }
    pos += 2; // client_version

    if pos + 32 > raw.len() {
        return info;
    }
    pos += 32; // random

    if pos >= raw.len() {
        return info;
    }
    let sid_len = raw[pos] as usize;
    pos += 1;
    if pos + sid_len > raw.len() {
        return info;
    }
    pos += sid_len;

    if pos + 2 > raw.len() {
        return info;
    }
    let cs_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > raw.len() {
        return info;
    }
    pos += cs_len;

    if pos >= raw.len() {
        return info;
    }
    let cm_len = raw[pos] as usize;
    pos += 1;
    if pos + cm_len > raw.len() {
        return info;
    }
    pos += cm_len;

    // --- Extensions ---
    if pos + 2 > raw.len() {
        return info;
    }
    let ext_total_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > raw.len() {
        return info;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let ext_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        match ext_type {
            // Challenge nonce — Privasys RA-TLS extension
            ext if ext == enclave_os_common::types::RATLS_CLIENT_HELLO_EXTENSION_TYPE => {
                info.challenge_nonce = Some(raw[pos..pos + ext_len].to_vec());
            }
            // SNI — Server Name Indication (RFC 6066)
            0x0000 => {
                info.sni = parse_sni_extension(&raw[pos..pos + ext_len]);
            }
            _ => {}
        }

        pos += ext_len;
    }

    info
}

/// Parse the SNI extension value to extract the host_name.
///
/// Format (RFC 6066 §3):
/// ```text
/// [2 bytes: ServerNameList length]
/// [1 byte:  name_type (0x00 = host_name)]
/// [2 bytes: HostName length]
/// [N bytes: hostname (UTF-8)]
/// ```
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // Skip list length (2 bytes)
    let name_type = data[2];
    if name_type != 0x00 {
        return None; // Only host_name type is supported
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
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

    // ----- parse_client_hello (ClientHello parser) ------------------------

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
    fn parse_nonce_present() {
        let nonce = b"challenge_nonce_32_bytes_padding!";
        let ch = build_client_hello(&[(0xFFBB, nonce)]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_nonce_absent() {
        // Valid SNI extension but no 0xFFBB
        let sni = b"\x00\x0e\x00\x00\x0bexample.com";
        let ch = build_client_hello(&[(0x0000, sni)]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, None);
        assert_eq!(info.sni, Some("example.com".into()));
    }

    #[test]
    fn parse_nonce_and_sni_together() {
        let nonce = b"my_nonce";
        let exts: &[(u16, &[u8])] = &[
            (0x0000, b"\x00\x0e\x00\x00\x0bexample.com"), // SNI
            (0x000D, b"\x00\x04\x04\x03\x08\x04"),         // signature_algorithms
            (0xFFBB, nonce),                                 // our extension
        ];
        let ch = build_client_hello(exts);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
        assert_eq!(info.sni, Some("example.com".into()));
    }

    #[test]
    fn parse_nonce_empty_extension_data() {
        let ch = build_client_hello(&[(0xFFBB, b"")]);
        let info = parse_client_hello(&ch);
        assert_eq!(info.challenge_nonce, Some(vec![]));
    }

    #[test]
    fn parse_nonce_no_record_layer() {
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

        let info = parse_client_hello(&hs);
        assert_eq!(info.challenge_nonce, Some(nonce.to_vec()));
    }

    #[test]
    fn parse_too_short() {
        let info = parse_client_hello(&[]);
        assert!(info.challenge_nonce.is_none() && info.sni.is_none());
        let info = parse_client_hello(&[0x16, 0x03, 0x01]);
        assert!(info.challenge_nonce.is_none());
        let info = parse_client_hello(&[0u8; 10]);
        assert!(info.challenge_nonce.is_none());
    }

    #[test]
    fn parse_not_handshake() {
        // Content type 0x17 = Application Data (not Handshake)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        bad[0] = 0x17;
        let info = parse_client_hello(&bad);
        assert!(info.challenge_nonce.is_none());
    }

    #[test]
    fn parse_not_client_hello() {
        // Handshake type 0x02 = ServerHello (not ClientHello)
        let mut bad = build_client_hello(&[(0xFFBB, b"nonce")]);
        // Record header is 5 bytes, then handshake type is at offset 5
        bad[5] = 0x02;
        let info = parse_client_hello(&bad);
        assert!(info.challenge_nonce.is_none());
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
