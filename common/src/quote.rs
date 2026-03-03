// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Attestation quote parsing — shared TEE primitives.
//!
//! Extracts TEE measurement identities (MRENCLAVE for SGX, MRTD for TDX)
//! and report data from raw DCAP attestation quotes using manual byte
//! offsets.  These are portable, `no_std`-compatible primitives used by
//! both the vault (policy enforcement) and the egress client (RA-TLS
//! verification).
//!
//! ## Quote formats
//!
//! | Version | TEE | Key measurement | Offset (bytes) | Size |
//! |---------|-----|-----------------|----------------|------|
//! | 3       | SGX | MRENCLAVE       | 112–144        | 32   |
//! | 3       | SGX | MRSIGNER        | 176–208        | 32   |
//! | 4       | TDX | MRTD            | 184–232        | 48   |
//!
//! The version field is a little-endian `u16` at bytes 0–1.

#[cfg(feature = "sgx")]
use alloc::{string::String, vec::Vec, format};
#[cfg(not(feature = "sgx"))]
use std::{string::String, vec::Vec, format};

use core::fmt::Write;

// ---------------------------------------------------------------------------
//  Constants — field offsets within DCAP quotes
// ---------------------------------------------------------------------------

/// Minimum size for an SGX v3 quote header + report body.
pub const SGX_QUOTE_MIN_SIZE: usize = 436;

/// Minimum size for a TDX v4 quote header + report body.
pub const TDX_QUOTE_MIN_SIZE: usize = 584;

// SGX v3 report body offsets (relative to quote start).
pub const SGX_MRENCLAVE_OFFSET: usize = 112;
pub const SGX_MRENCLAVE_SIZE: usize = 32;
pub const SGX_MRSIGNER_OFFSET: usize = 176;
pub const SGX_MRSIGNER_SIZE: usize = 32;

/// Offset of the 64-byte `ReportData` field within an SGX v3 quote.
///
/// SGX v3 layout: 48-byte header + 384-byte ISV Enclave Report Body.
/// Inside the report body, `ReportData` starts at byte 320 → absolute
/// offset = 48 + 320 = 368.
pub const SGX_REPORT_DATA_OFFSET: usize = 368;

// TDX v4 report body offsets (relative to quote start).
pub const TDX_MRTD_OFFSET: usize = 184;
pub const TDX_MRTD_SIZE: usize = 48;

/// Offset of the 64-byte `ReportData` field within a TDX v4 quote.
///
/// TDX v4 layout: 48-byte header + 584-byte TD Quote Body.
/// `ReportData` is the last 64 bytes of the body → absolute offset
/// = 48 + 520 = 568.
pub const TDX_REPORT_DATA_OFFSET: usize = 568;

/// Size of the report data field (same for SGX and TDX).
pub const REPORT_DATA_SIZE: usize = 64;

/// Minimum quote size needed to extract ReportData from a TDX v4 quote.
/// = TDX_REPORT_DATA_OFFSET + REPORT_DATA_SIZE = 568 + 64 = 632.
pub const TDX_REPORT_DATA_MIN_SIZE: usize = TDX_REPORT_DATA_OFFSET + REPORT_DATA_SIZE;

// ---------------------------------------------------------------------------
//  Public types
// ---------------------------------------------------------------------------

/// Detected TEE type from the quote version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeType {
    /// Intel SGX (quote version 3).
    Sgx,
    /// Intel TDX (quote version 4).
    Tdx,
}

/// Parsed measurement identity from an attestation quote.
#[derive(Debug, Clone)]
pub struct QuoteIdentity {
    /// Detected TEE type.
    pub tee: TeeType,
    /// Hex-encoded primary measurement:
    /// - SGX: MRENCLAVE (64 hex chars / 32 bytes)
    /// - TDX: MRTD (96 hex chars / 48 bytes)
    pub measurement: String,
    /// Hex-encoded MRSIGNER (SGX only, 64 hex chars).
    pub mrsigner: Option<String>,
}

// ---------------------------------------------------------------------------
//  Parsing
// ---------------------------------------------------------------------------

/// Parse raw attestation evidence and extract the TEE identity.
///
/// Returns an error if the quote is too short, has an unrecognised version,
/// or the measurement bytes cannot be extracted.
pub fn parse_quote(evidence: &[u8]) -> Result<QuoteIdentity, String> {
    if evidence.len() < 2 {
        return Err("attestation evidence too short".into());
    }

    let version = u16::from_le_bytes([evidence[0], evidence[1]]);

    match version {
        3 => parse_sgx_quote(evidence),
        4 => parse_tdx_quote(evidence),
        v => Err(format!("unsupported quote version {v} (expected 3=SGX or 4=TDX)")),
    }
}

/// Parse an SGX v3 DCAP quote.
fn parse_sgx_quote(evidence: &[u8]) -> Result<QuoteIdentity, String> {
    if evidence.len() < SGX_QUOTE_MIN_SIZE {
        return Err(format!(
            "SGX quote too short: {} bytes (need >= {SGX_QUOTE_MIN_SIZE})",
            evidence.len()
        ));
    }

    let mrenclave = &evidence[SGX_MRENCLAVE_OFFSET..SGX_MRENCLAVE_OFFSET + SGX_MRENCLAVE_SIZE];
    let mrsigner = &evidence[SGX_MRSIGNER_OFFSET..SGX_MRSIGNER_OFFSET + SGX_MRSIGNER_SIZE];

    Ok(QuoteIdentity {
        tee: TeeType::Sgx,
        measurement: hex_encode(mrenclave),
        mrsigner: Some(hex_encode(mrsigner)),
    })
}

/// Parse a TDX v4 DCAP quote.
fn parse_tdx_quote(evidence: &[u8]) -> Result<QuoteIdentity, String> {
    if evidence.len() < TDX_QUOTE_MIN_SIZE {
        return Err(format!(
            "TDX quote too short: {} bytes (need >= {TDX_QUOTE_MIN_SIZE})",
            evidence.len()
        ));
    }

    let mrtd = &evidence[TDX_MRTD_OFFSET..TDX_MRTD_OFFSET + TDX_MRTD_SIZE];

    Ok(QuoteIdentity {
        tee: TeeType::Tdx,
        measurement: hex_encode(mrtd),
        mrsigner: None,
    })
}

// ---------------------------------------------------------------------------
//  ReportData extraction
// ---------------------------------------------------------------------------

/// Extract the 64-byte `ReportData` from a raw attestation quote.
///
/// The `ReportData` field binds the TLS public key (and an optional
/// challenge nonce) to the hardware-attested quote.  It is used during
/// mutual RA-TLS challenge-response to verify that the peer generated
/// its certificate specifically for this TLS connection.
pub fn extract_report_data(evidence: &[u8]) -> Result<[u8; 64], String> {
    if evidence.len() < 2 {
        return Err("attestation evidence too short".into());
    }

    let version = u16::from_le_bytes([evidence[0], evidence[1]]);

    let offset = match version {
        3 => {
            if evidence.len() < SGX_QUOTE_MIN_SIZE {
                return Err(format!(
                    "SGX quote too short for report_data: {} bytes (need >= {SGX_QUOTE_MIN_SIZE})",
                    evidence.len()
                ));
            }
            SGX_REPORT_DATA_OFFSET
        }
        4 => {
            if evidence.len() < TDX_REPORT_DATA_MIN_SIZE {
                return Err(format!(
                    "TDX quote too short for report_data: {} bytes (need >= {TDX_REPORT_DATA_MIN_SIZE})",
                    evidence.len()
                ));
            }
            TDX_REPORT_DATA_OFFSET
        }
        v => return Err(format!("unsupported quote version {v} (expected 3=SGX or 4=TDX)")),
    };

    let mut rd = [0u8; 64];
    rd.copy_from_slice(&evidence[offset..offset + REPORT_DATA_SIZE]);
    Ok(rd)
}

// ---------------------------------------------------------------------------
//  Hex utilities
// ---------------------------------------------------------------------------

/// Hex-encode bytes (lowercase).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex-decode a string into bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at offset {i}: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
//  ReportData computation (requires `ring`)
// ---------------------------------------------------------------------------

/// Compute the expected 64-byte `ReportData` binding.
///
/// ```text
/// report_data = SHA-512( SHA-256(pubkey_bytes) || binding )
/// ```
///
/// Both SGX and TDX use this formula; they differ only in the *pubkey
/// encoding* (raw EC point vs. full SPKI DER) and the *binding* content
/// (creation-time, challenge nonce, etc.).
///
/// Requires the `ring` dependency — gated behind the `jwt` feature in
/// `enclave-os-common` (which already pulls in `ring`).
#[cfg(feature = "crypto")]
pub fn compute_report_data_hash(pubkey_bytes: &[u8], binding: &[u8]) -> ring::digest::Digest {
    let pk_hash = ring::digest::digest(&ring::digest::SHA256, pubkey_bytes);
    let mut preimage = Vec::with_capacity(32 + binding.len());
    preimage.extend_from_slice(pk_hash.as_ref());
    preimage.extend_from_slice(binding);
    ring::digest::digest(&ring::digest::SHA512, &preimage)
}
