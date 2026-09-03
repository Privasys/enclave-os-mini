// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX attestation integration for RA-TLS v2.
//!
//! The leaf certificate identifies the enclave (leaf key, chain to the
//! intermediary CA, Privasys OIDs) and carries no evidence. A leaf key lives
//! 24 hours and is kept across re-mints that only change extension values (an
//! app registered, a dependency set changed), so a deterministic quote minted
//! for the key stays valid across such a re-mint. Evidence is served after the
//! handshake by `POST /__privasys/attest` (see `server.rs`):
//!
//! ```text
//! deterministic: report_data = SHA-512( SHA-256(SPKI_DER) || quote_time )   cached 24 h per key
//! challenge:     report_data = SHA-512( SHA-256(SPKI_DER) || context || hctx )
//!                hctx = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2", context, 32)
//! ```

use std::string::String;
use std::vec::Vec;
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use time::OffsetDateTime;

use enclave_os_common::oids::{APP_CONFIG_MERKLE_ROOT_OID, CONFIG_MERKLE_ROOT_OID};

use crate::ratls::cert_store::AppCertData;

/// Lifetime of a serving leaf and of its key (24 hours).
pub const DETERMINISTIC_VALIDITY_SECS: u64 = 86400;

/// Validity of a minted client identity (1 hour).
pub const CLIENT_IDENTITY_VALIDITY_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
//  Types
// ---------------------------------------------------------------------------

/// Intermediary CA context provided to the enclave at startup.
///
/// The enclave uses it to sign leaf RA-TLS certificates so that the
/// trust chain is: `root / intermediary → leaf`.
///
/// The CA material is **never** generated inside the enclave.  It must be
/// provisioned externally (typically as part of the `EnclaveConfig`) and
/// is then sealed to disk via SGX sealing so that subsequent restarts
/// can unseal it without re-provisioning.
#[derive(Clone)]
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

/// A serving leaf key, kept for [`DETERMINISTIC_VALIDITY_SECS`] across
/// re-mints of the certificate.
#[derive(Clone)]
pub struct LeafKey {
    /// PKCS#8 private key.
    pub pkcs8: Vec<u8>,
    /// DER `SubjectPublicKeyInfo` (91 bytes), the input of every
    /// `report_data` recipe.
    pub spki_der: Vec<u8>,
    /// SHA-256 of `spki_der`: the `leaf` id clients name in an attest request.
    pub spki_hash: [u8; 32],
    /// Creation time (seconds since the Unix epoch).
    pub created: u64,
}

/// Generate a fresh leaf key.
pub fn new_leaf_key(now: u64) -> Result<LeafKey, String> {
    let (pkcs8, key_pair) = generate_keypair().map_err(|e| e.to_string())?;
    let raw_ec_point = signature::KeyPair::public_key(&key_pair).as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(raw_ec_point);
    let mut spki_hash = [0u8; 32];
    spki_hash.copy_from_slice(digest::digest(&digest::SHA256, &spki_der).as_ref());
    Ok(LeafKey { pkcs8, spki_der, spki_hash, created: now })
}

/// Result of certificate generation.
pub struct CertGenerationResult {
    /// DER-encoded certificate chain (leaf, then the intermediary CA).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// PKCS#8 private key of the leaf.
    pub pkcs8_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Compute the 64-byte `report_data` that goes into the SGX quote:
/// `SHA-512( SHA-256(SPKI_DER) || binding )`, with `spki_der` the full DER
/// `SubjectPublicKeyInfo` (91 bytes for P-256).
pub fn compute_report_data(spki_der: &[u8], binding: &[u8]) -> [u8; 64] {
    let pubkey_hash = digest::digest(&digest::SHA256, spki_der);
    let mut preimage = Vec::with_capacity(32 + binding.len());
    preimage.extend_from_slice(pubkey_hash.as_ref());
    preimage.extend_from_slice(binding);
    let rd = digest::digest(&digest::SHA512, &preimage);
    let mut out = [0u8; 64];
    out.copy_from_slice(rd.as_ref());
    out
}

/// Generate the enclave-wide RA-TLS leaf for `key`, signed by the CA, carrying
/// the platform OIDs (config Merkle root, attestation servers hash, module
/// OIDs) and no evidence. Valid from `now` until the key's 24-hour lifetime.
pub fn generate_ratls_certificate(
    ca: &CaContext,
    key: &LeafKey,
    now: u64,
) -> Result<CertGenerationResult, String> {
    let mut extensions: Vec<(&'static [u64], Vec<u8>)> = Vec::new();
    if let Some(root) = crate::config_merkle_root() {
        extensions.push((CONFIG_MERKLE_ROOT_OID, root.to_vec()));
    }
    if let Some(h) = enclave_os_common::attestation_servers::hash() {
        extensions.push((enclave_os_common::oids::ATTESTATION_SERVERS_HASH_OID, h.to_vec()));
    }
    for oid in &crate::modules::collect_module_oids() {
        extensions.push((oid.oid, oid.value.clone()));
    }
    let (nb, na) = leaf_validity(key, now)?;
    let leaf_der = build_leaf_cert(&key.pkcs8, nb, na, ca, "Enclave OS RA-TLS", &extensions)?;
    Ok(CertGenerationResult {
        cert_chain_der: vec![leaf_der, ca.ca_cert_der.clone()],
        pkcs8_key: key.pkcs8.clone(),
    })
}

/// Generate a per-app RA-TLS leaf for `key`: the app's config Merkle root
/// (OID 5.1) and its identity extensions (code digest 4.2, key source 6.1,
/// configuration hash 5.2, app id 4.1, dependency set 7.1, app-defined 5.4.*),
/// subject CN = app hostname (SNI). No evidence.
pub fn generate_app_certificate(
    ca: &CaContext,
    key: &LeafKey,
    app: &AppCertData,
    now: u64,
) -> Result<CertGenerationResult, String> {
    let mut extensions: Vec<(&'static [u64], Vec<u8>)> = Vec::new();
    if app.merkle_root != [0u8; 32] {
        extensions.push((APP_CONFIG_MERKLE_ROOT_OID, app.merkle_root.to_vec()));
    }
    for (oid, value) in &app.oid_extensions {
        extensions.push((*oid, value.clone()));
    }
    let (nb, na) = leaf_validity(key, now)?;
    let leaf_der = build_leaf_cert(&key.pkcs8, nb, na, ca, &app.hostname, &extensions)?;
    Ok(CertGenerationResult {
        cert_chain_der: vec![leaf_der, ca.ca_cert_der.clone()],
        pkcs8_key: key.pkcs8.clone(),
    })
}

fn leaf_validity(key: &LeafKey, now: u64) -> Result<(OffsetDateTime, OffsetDateTime), String> {
    let nb = OffsetDateTime::from_unix_timestamp(now.saturating_sub(60) as i64)
        .map_err(|e| format!("not_before out of range: {e}"))?;
    let na = OffsetDateTime::from_unix_timestamp((key.created + DETERMINISTIC_VALIDITY_SECS) as i64)
        .map_err(|e| format!("not_after out of range: {e}"))?;
    Ok((nb, na))
}

/// Mint this enclave's client identity for a mutual leg (a vault, an app-to-app
/// call): a fresh key, the app's code digest (OID 4.2) and, when present, its
/// app id (OID 4.1), signed by the CA, valid one hour, no evidence. Evidence for
/// it is minted per connection with [`sgx_quote`] over the report_data the
/// verifier predicts (`client_report_data`). Returns
/// `(cert_chain_der, pkcs8_key_der, spki_hash)`.
pub fn mint_client_identity(
    ca: &CaContext,
    cwasm_code_hash: &[u8],
    app_id: Option<&[u8]>,
    now: u64,
) -> Result<(Vec<Vec<u8>>, Vec<u8>, [u8; 32]), String> {
    let key = new_leaf_key(now)?;
    let mut oid_extensions: Vec<(&'static [u64], Vec<u8>)> = Vec::new();
    oid_extensions.push((enclave_os_common::oids::APP_CODE_HASH_OID, cwasm_code_hash.to_vec()));
    if let Some(id) = app_id {
        if !id.is_empty() {
            oid_extensions.push((enclave_os_common::oids::APP_ID_OID, id.to_vec()));
        }
    }
    let nb = OffsetDateTime::from_unix_timestamp(now.saturating_sub(60) as i64)
        .map_err(|e| format!("not_before out of range: {e}"))?;
    let na = OffsetDateTime::from_unix_timestamp((now + CLIENT_IDENTITY_VALIDITY_SECS) as i64)
        .map_err(|e| format!("not_after out of range: {e}"))?;
    let leaf_der = build_leaf_cert(&key.pkcs8, nb, na, ca, "enclave-os client", &oid_extensions)?;
    Ok((vec![leaf_der, ca.ca_cert_der.clone()], key.pkcs8, key.spki_hash))
}

/// Produce an SGX DCAP quote over `report_data` (the attest endpoint and the
/// client-evidence path).
pub fn sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    generate_sgx_quote(report_data)
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

/// Generate an SGX DCAP Quote v3 with the given 64-byte report_data.
///
/// Two-phase RPC flow:
///   1. Ask the host for the Quoting Enclave's `TargetInfo` (RPC: `QeGetTargetInfo`)
///   2. Call `sgx_create_report()` inside the enclave, targeting the QE
///   3. Send the raw report to the host (RPC: `QeGetQuote`) → host calls
///      `sgx_qe_get_quote()` → returns the full DCAP Quote v3
///
/// In mock mode this returns a deterministic dummy quote.
#[cfg(not(feature = "mock"))]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    use sgx_types::types::{ReportData, TargetInfo};

    let rpc = crate::rpc_client_ref();

    let target_info_bytes = rpc.qe_get_target_info()
        .map_err(|e| format!("QeGetTargetInfo RPC failed: status={}", e))?;

    if target_info_bytes.len() != core::mem::size_of::<TargetInfo>() {
        return Err(format!(
            "QeGetTargetInfo: unexpected size {} (expected {})",
            target_info_bytes.len(),
            core::mem::size_of::<TargetInfo>()
        ));
    }

    let target_info: TargetInfo = unsafe {
        core::ptr::read_unaligned(target_info_bytes.as_ptr() as *const TargetInfo)
    };

    let mut rd = ReportData::default();
    rd.d.copy_from_slice(report_data);

    let report = <sgx_types::types::Report as sgx_tse::EnclaveReport>::for_target(&target_info, &rd)
        .map_err(|e| format!("sgx_create_report failed: {:?}", e))?;

    let report_bytes = unsafe {
        core::slice::from_raw_parts(
            &report as *const sgx_types::types::Report as *const u8,
            core::mem::size_of::<sgx_types::types::Report>(),
        )
    };

    let quote = rpc.qe_get_quote(report_bytes)
        .map_err(|e| format!("QeGetQuote RPC failed: status={}", e))?;

    Ok(quote)
}

#[cfg(feature = "mock")]
fn generate_sgx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut quote = Vec::with_capacity(11 + 64);
    quote.extend_from_slice(b"MOCK_QUOTE:");
    quote.extend_from_slice(report_data);
    Ok(quote)
}

/// Produce a DCAP quote binding `nonce` into ReportData, for authenticating this
/// enclave to a non-RA-TLS verifier (the management-service vault directory). The
/// nonce is placed in the first 32 bytes of the 64-byte ReportData (the rest is
/// zero); the verifier reproduces the same binding from the challenge it issued.
pub fn quote_binding_nonce(nonce: &[u8]) -> Result<Vec<u8>, String> {
    let mut report_data = [0u8; 64];
    let n = core::cmp::min(nonce.len(), 32);
    report_data[..n].copy_from_slice(&nonce[..n]);
    generate_sgx_quote(&report_data)
}

// ---------------------------------------------------------------------------
//  Self measurement (MRENCLAVE)
// ---------------------------------------------------------------------------

/// Read this enclave's own MRENCLAVE (its code identity), for self-authoring a
/// vault key policy that pins the running runtime as the `Tee` measurement.
///
/// MRENCLAVE is independent of the report target, so a local SGX report suffices.
/// It sits at byte offset 64 of the SGX ReportBody (the first field of the
/// Report), so we read it from the report bytes rather than depend on the SDK
/// fork's struct field names.
#[cfg(not(feature = "mock"))]
pub fn self_mrenclave() -> Result<[u8; 32], String> {
    use sgx_types::types::{ReportData, TargetInfo};

    let rpc = crate::rpc_client_ref();
    let target_info_bytes = rpc.qe_get_target_info()
        .map_err(|e| format!("QeGetTargetInfo RPC failed: status={}", e))?;
    if target_info_bytes.len() != core::mem::size_of::<TargetInfo>() {
        return Err(format!(
            "QeGetTargetInfo: unexpected size {} (expected {})",
            target_info_bytes.len(),
            core::mem::size_of::<TargetInfo>()
        ));
    }
    let target_info: TargetInfo = unsafe {
        core::ptr::read_unaligned(target_info_bytes.as_ptr() as *const TargetInfo)
    };
    let rd = ReportData::default();
    let report = <sgx_types::types::Report as sgx_tse::EnclaveReport>::for_target(&target_info, &rd)
        .map_err(|e| format!("sgx_create_report failed: {:?}", e))?;
    let report_bytes = unsafe {
        core::slice::from_raw_parts(
            &report as *const sgx_types::types::Report as *const u8,
            core::mem::size_of::<sgx_types::types::Report>(),
        )
    };
    const MRENCLAVE_OFFSET: usize = 64;
    if report_bytes.len() < MRENCLAVE_OFFSET + 32 {
        return Err(format!("self report too short: {} bytes", report_bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&report_bytes[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + 32]);
    Ok(out)
}

#[cfg(feature = "mock")]
pub fn self_mrenclave() -> Result<[u8; 32], String> {
    Ok([0x11u8; 32])
}

// ---------------------------------------------------------------------------
//  Certificate building with rcgen
// ---------------------------------------------------------------------------

/// Build a leaf certificate signed by the intermediary CA carrying
/// `extensions` (Privasys OIDs) and no evidence. `common_name` is the Subject
/// CN (the app hostname, or the enclave-wide name).
fn build_leaf_cert(
    leaf_pkcs8: &[u8],
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    ca: &CaContext,
    common_name: &str,
    extensions: &[(&'static [u64], Vec<u8>)],
) -> Result<Vec<u8>, String> {
    use rcgen::{
        CertificateParams, CustomExtension, DnType, DnValue, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let ca_cert_der = CertificateDer::from(ca.ca_cert_der.as_slice());
    let ca_params = CertificateParams::from_ca_cert_der(&ca_cert_der)
        .map_err(|e| format!("CA cert parse: {}", e))?;

    let leaf_pkcs8_der = PrivatePkcs8KeyDer::from(leaf_pkcs8.to_vec());
    let leaf_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &leaf_pkcs8_der,
        &PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| format!("leaf key: {}", e))?;

    let mut leaf_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| format!("leaf params: {}", e))?;

    leaf_params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String(common_name.into()),
    );
    for dn_type in &[
        DnType::CountryName,
        DnType::StateOrProvinceName,
        DnType::LocalityName,
        DnType::OrganizationName,
        DnType::OrganizationalUnitName,
    ] {
        if let Some(value) = ca_params.distinguished_name.get(dn_type) {
            leaf_params.distinguished_name.push(dn_type.clone(), value.clone());
        }
    }

    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;

    for (oid, value) in extensions {
        let ext = CustomExtension::from_oid_content(*oid, value.clone());
        leaf_params.custom_extensions.push(ext);
    }

    leaf_params.is_ca = IsCa::NoCa;

    let ca_pkcs8_der = PrivatePkcs8KeyDer::from(ca.ca_key_pkcs8.clone());
    let ca_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &ca_pkcs8_der,
        &PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| format!("CA key: {}", e))?;

    let ca_cert = ca_params.self_signed(&ca_key)
        .map_err(|e| format!("CA cert reconstruct: {}", e))?;

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("leaf signing: {}", e))?;

    Ok(leaf_cert.der().to_vec())
}

// ---------------------------------------------------------------------------
//  ClientHello parser (SNI)
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
    fn ratls_time_format_matches_verifier() {
        // 1700000000 = 2023-11-14T22:13:20Z; minute-truncated -> 22:13.
        // This string must match byte-for-byte what the SDK verifiers
        // reconstruct from NotBefore, so pin it.
        let minute = 1700000000u64 - (1700000000u64 % 60);
        let t = OffsetDateTime::from_unix_timestamp(minute as i64).unwrap();
        assert_eq!(format_ratls_time(&t), "2023-11-14T22:13Z");
    }

    #[test]
    fn report_data_deterministic_binding_is_time_string() {
        let rd = compute_report_data(b"key", b"2023-11-14T22:13Z");
        // A different minute must give different report_data.
        let rd2 = compute_report_data(b"key", b"2023-11-14T22:14Z");
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

    // ----- hex_decode (from common) ----------------------------------------

    #[test]
    fn hex_decode_basic() {
        let decoded = enclave_os_common::hex::hex_decode("48656c6c6f").unwrap();
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn hex_decode_empty() {
        let decoded = enclave_os_common::hex::hex_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = enclave_os_common::hex::hex_decode("4F6B").unwrap();
        assert_eq!(&decoded, b"Ok");
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(enclave_os_common::hex::hex_decode("abc").is_none());
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(enclave_os_common::hex::hex_decode("zz").is_none());
    }
}
