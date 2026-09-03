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
    enclave_os_common::oids::COMBINED_WORKLOADS_HASH_OID_STR,
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

/// What a vault learns from a remote TEE's RA-TLS certificate and the
/// evidence it presented after the handshake.
pub struct PeerEvidence {
    /// Raw SGX/TDX quote bytes (from the attest present message, never from
    /// the certificate: a v2 leaf carries none).
    pub evidence: Vec<u8>,
    /// All known Privasys OID extensions present on the cert (`oid`, hex `value`).
    pub oid_claims: Vec<(String, String)>,
    /// The cert's subject public key (raw DER `subject_public_key.data`).
    pub pubkey_raw: Vec<u8>,
}

/// Parse the peer certificate (OID claims, public key) and pair it with the
/// quote the peer presented. A v1 leaf (quote inside the certificate) is
/// rejected. An empty `quote` yields the claims and key only, for callers
/// that need no evidence (grant binding by app id).
pub fn dissect_peer_cert(der: &[u8], quote: &[u8]) -> Result<PeerEvidence, String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("invalid X.509 DER: {e}"))?;

    let mut oid_claims = Vec::new();
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SGX_QUOTE_OID_STR || oid_str == TDX_QUOTE_OID_STR {
            return Err("v1 RA-TLS certificate (evidence inside the certificate) is not accepted".into());
        } else if CLAIM_OIDS.contains(&oid_str.as_str()) {
            oid_claims.push((oid_str, hex_encode(ext.value)));
        }
    }
    let evidence = quote.to_vec();

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

