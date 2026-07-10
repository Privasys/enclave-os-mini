// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault attestation helpers: extract quote + OID claims + public key
//! from an X.509 peer certificate, parse SGX/TDX quotes, and verify the
//! bidirectional challenge-response binding.
//!
//! The low-level quote primitives live in [`enclave_os_common::quote`];
//! this module is the vault-specific glue.

use std::string::String;
use std::vec::Vec;

pub use enclave_os_common::quote::{
    extract_report_data, hex_encode, parse_quote, QuoteIdentity, TeeType,
};

use enclave_os_common::quote::{build_p256_spki_der, compute_report_data_hash};

// ---------------------------------------------------------------------------
//  OID constants
// ---------------------------------------------------------------------------

const SGX_QUOTE_OID_STR: &str = enclave_os_common::oids::SGX_QUOTE_OID_STR;
const TDX_QUOTE_OID_STR: &str = enclave_os_common::oids::TDX_QUOTE_OID_STR;

/// Privasys configuration OIDs that are recognised as OID claims on the
/// peer certificate.
const CLAIM_OIDS: &[&str] = &[
    enclave_os_common::oids::CONFIG_MERKLE_ROOT_OID_STR,
    enclave_os_common::oids::EGRESS_CA_HASH_OID_STR,
    enclave_os_common::oids::WASM_APPS_HASH_OID_STR,
    enclave_os_common::oids::ATTESTATION_SERVERS_HASH_OID_STR,
    enclave_os_common::oids::APP_CONFIG_MERKLE_ROOT_OID_STR,
    enclave_os_common::oids::APP_CODE_HASH_OID_STR,
    // MR_APP: the per-app id (3.6). Without it here, dissect_peer_cert would
    // drop the leaf's app-id and a policy requiring it could never match. See
    // the MR_APP / promote-step-up design.
    enclave_os_common::oids::APP_ID_OID_STR,
];

// ---------------------------------------------------------------------------
//  Cert dissection
// ---------------------------------------------------------------------------

/// What a vault learns from a remote TEE's RA-TLS certificate.
pub struct PeerEvidence {
    /// Raw SGX/TDX quote bytes from the cert extension.
    pub evidence: Vec<u8>,
    /// All known Privasys OID extensions present on the cert (`oid`, hex `value`).
    pub oid_claims: Vec<(String, String)>,
    /// The cert's subject public key (raw DER `subject_public_key.data`).
    pub pubkey_raw: Vec<u8>,
}

/// Parse the peer certificate and pull out the attestation evidence,
/// OID claims and public key.
pub fn dissect_peer_cert(der: &[u8]) -> Result<PeerEvidence, String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("invalid X.509 DER: {e}"))?;

    let mut quote_bytes: Option<Vec<u8>> = None;
    let mut oid_claims = Vec::new();
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SGX_QUOTE_OID_STR || oid_str == TDX_QUOTE_OID_STR {
            quote_bytes = Some(ext.value.to_vec());
        } else if CLAIM_OIDS.contains(&oid_str.as_str()) {
            oid_claims.push((oid_str, hex_encode(ext.value)));
        }
    }
    let evidence = quote_bytes
        .ok_or_else(|| "peer certificate has no SGX/TDX attestation extension".to_string())?;

    let pubkey_raw = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();
    if pubkey_raw.is_empty() {
        return Err("empty subject public key in certificate".into());
    }

    Ok(PeerEvidence {
        evidence,
        oid_claims,
        pubkey_raw,
    })
}

/// Verify that the peer (client) cert's `report_data` field commits to the
/// challenge nonce we sent during the TLS handshake, and to the session
/// channel binder.
///
/// Bidirectional challenge-response is **mandatory** for any TEE
/// authentication. If `nonce` is `None` we refuse: the TLS layer must
/// have sent a challenge. `channel_binder` is the 32-byte binder derived from
/// this session's handshake key schedule (read post-handshake from the server
/// connection's `ratls_channel_binder()`); when present the client's quote must
/// commit to `nonce || binder`, so a relayed client cert from another session
/// fails closed. It is `None` only on a non-TLS-1.3 handshake.
pub fn verify_challenge_binding(
    evidence: &[u8],
    pubkey_raw: &[u8],
    nonce: Option<&[u8]>,
    channel_binder: Option<&[u8]>,
) -> Result<(), String> {
    let nonce = nonce.ok_or_else(|| {
        "TLS challenge nonce missing; bidirectional challenge-response is required".to_string()
    })?;
    let actual =
        extract_report_data(evidence).map_err(|e| format!("report_data extraction: {e}"))?;
    let spki = build_p256_spki_der(pubkey_raw);
    let mut binding = nonce.to_vec();
    if let Some(binder) = channel_binder {
        binding.extend_from_slice(binder);
    }
    let expected = compute_report_data_hash(&spki, &binding);
    if actual[..] != expected.as_ref()[..] {
        return Err(
            "bidirectional challenge-response failed: peer cert report_data \
             does not commit to the server's challenge nonce and session binder"
                .into(),
        );
    }
    Ok(())
}
