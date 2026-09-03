// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS v2 attestation protocol: the messages and `report_data` recipes of
//! the evidence exchange that follows the handshake
//! (`ra-tls-clients/docs/ratls-v2.md`). Shared by the ingress server (which
//! answers `POST /__privasys/attest`), the egress client (which asks), the
//! vault and the raft peer link.
//!
//! ```text
//! deterministic: report_data = SHA-512( SHA-256(SPKI_DER) || quote_time )
//! challenge:     report_data = SHA-512( SHA-256(SPKI_DER) || context || hctx )
//!                hctx = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2", context, 32)
//! client:        report_data = SHA-512( SHA-256(client SPKI) || client_context || hctx_c )
//!                hctx_c = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2-client", client_context, 32)
//! ```
//!
//! with `SHA-256(gpu_evidence)` appended to the binding when GPU evidence is
//! present.

#[cfg(feature = "sgx")]
use alloc::{format, string::{String, ToString}, vec::Vec};
#[cfg(not(feature = "sgx"))]
use std::{format, string::{String, ToString}, vec::Vec};

use base64::Engine;
use ring::digest;
use serde::{Deserialize, Serialize};

/// Reserved path of the evidence endpoint (HTTP binding).
pub const ATTEST_PATH: &str = "/__privasys/attest";
/// The `v` field of every attest message.
pub const PROTOCOL_VERSION: u32 = 2;
/// Exporter label of the server evidence of a connection.
pub const EXPORTER_LABEL_SERVER: &[u8] = b"EXPORTER-privasys-ratls-attest-v2";
/// Exporter label of the client evidence of a connection (mutual leg).
pub const EXPORTER_LABEL_CLIENT: &[u8] = b"EXPORTER-privasys-ratls-attest-v2-client";
/// Exporter labels of the symmetric raft peer link, one per role.
pub const EXPORTER_LABEL_PEER_CLIENT: &[u8] = b"EXPORTER-privasys-ratls-attest-v2-peer-client";
pub const EXPORTER_LABEL_PEER_SERVER: &[u8] = b"EXPORTER-privasys-ratls-attest-v2-peer-server";
/// Length of a challenge context.
pub const CONTEXT_LEN: usize = 32;
/// Length of the exporter output.
pub const HCTX_LEN: usize = 32;
/// Length of `quote_time` (`YYYY-MM-DDTHH:MMZ`).
pub const QUOTE_TIME_LEN: usize = 17;
/// Largest attest message accepted.
pub const MAX_MESSAGE: usize = 65536;

const QUOTE_MAX_AGE_SECS: i64 = 24 * 3600 + 5 * 60;
const QUOTE_SKEW_SECS: i64 = 5 * 60;

/// What a client asks for after the handshake. `Challenge` binds the evidence
/// to the connection (Level 3); `Deterministic` is the cached "trust the TEE"
/// tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationMode {
    #[default]
    Challenge,
    Deterministic,
}

impl AttestationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationMode::Challenge => "challenge",
            AttestationMode::Deterministic => "deterministic",
        }
    }
}

// -- messages ---------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestRequest {
    pub v: u32,
    pub mode: String,
    #[serde(default)]
    pub leaf: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    // present
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_time: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AttestResponse {
    pub v: u32,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub tee: String,
    #[serde(default)]
    pub quote: String,
    #[serde(default)]
    pub gpu_evidence: Option<String>,
    #[serde(default)]
    pub quote_time: String,
    #[serde(default)]
    pub client_evidence: String,
    #[serde(default)]
    pub client_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Evidence obtained (or to be verified) for one connection.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub mode: AttestationMode,
    pub tee: String,
    pub quote: Vec<u8>,
    pub gpu_evidence: Option<Vec<u8>>,
    pub quote_time: String,
    pub context: Option<[u8; CONTEXT_LEN]>,
    pub hctx: Option<[u8; HCTX_LEN]>,
}

/// A peer's evidence accepted on the server side of a mutual leg: the quote
/// whose `report_data` was verified against the peer's leaf key, the
/// connection's client context and exporter value.
#[derive(Debug, Clone)]
pub struct PeerEvidence {
    pub tee: String,
    pub quote: Vec<u8>,
    pub gpu_evidence: Option<Vec<u8>>,
    pub quote_time: String,
}

pub fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url: {e}"))
}

// -- report_data ------------------------------------------------------------

/// `SHA-512( SHA-256(spki_der) || binding )`.
pub fn report_data(spki_der: &[u8], binding: &[u8]) -> [u8; 64] {
    let pk = digest::digest(&digest::SHA256, spki_der);
    let mut buf = Vec::with_capacity(32 + binding.len());
    buf.extend_from_slice(pk.as_ref());
    buf.extend_from_slice(binding);
    let h = digest::digest(&digest::SHA512, &buf);
    let mut out = [0u8; 64];
    out.copy_from_slice(h.as_ref());
    out
}

fn fold_gpu(mut binding: Vec<u8>, gpu: Option<&[u8]>) -> Vec<u8> {
    if let Some(g) = gpu.filter(|g| !g.is_empty()) {
        binding.extend_from_slice(digest::digest(&digest::SHA256, g).as_ref());
    }
    binding
}

/// The `report_data` a server's quote must carry for the leaf `spki_der` and
/// the evidence `ev`. The verifier predicts it; it never accepts a value from
/// the peer.
pub fn expected_report_data(spki_der: &[u8], ev: &Evidence) -> Result<[u8; 64], String> {
    let binding = match ev.mode {
        AttestationMode::Deterministic => {
            if ev.quote_time.len() != QUOTE_TIME_LEN {
                return Err("deterministic evidence needs a quote_time".into());
            }
            ev.quote_time.as_bytes().to_vec()
        }
        AttestationMode::Challenge => {
            let (ctx, hctx) = match (ev.context, ev.hctx) {
                (Some(c), Some(h)) => (c, h),
                _ => return Err("challenge evidence needs a context and an exporter value".into()),
            };
            let mut b = ctx.to_vec();
            b.extend_from_slice(&hctx);
            b
        }
    };
    Ok(report_data(spki_der, &fold_gpu(binding, ev.gpu_evidence.as_deref())))
}

/// The deterministic binding of a server quote: `quote_time` (17 bytes) with
/// the GPU fold.
pub fn deterministic_report_data(spki_der: &[u8], quote_time: &str, gpu: Option<&[u8]>) -> [u8; 64] {
    report_data(spki_der, &fold_gpu(quote_time.as_bytes().to_vec(), gpu))
}

/// The challenge binding of a server quote: `context || hctx` with the GPU fold.
pub fn challenge_report_data(spki_der: &[u8], context: &[u8], hctx: &[u8], gpu: Option<&[u8]>) -> [u8; 64] {
    let mut b = context.to_vec();
    b.extend_from_slice(hctx);
    report_data(spki_der, &fold_gpu(b, gpu))
}

/// `report_data` of client evidence on a mutual leg (same recipe, the
/// client's key, the server-chosen context and the client exporter value).
pub fn client_report_data(spki_der: &[u8], client_context: &[u8], hctx: &[u8], gpu: Option<&[u8]>) -> [u8; 64] {
    challenge_report_data(spki_der, client_context, hctx, gpu)
}

// -- quote_time -------------------------------------------------------------

/// Formats seconds since the epoch as `YYYY-MM-DDTHH:MMZ` (minute precision).
pub fn format_quote_time(unix: i64) -> String {
    let minute = unix - unix.rem_euclid(60);
    let days = minute.div_euclid(86400);
    let secs = minute.rem_euclid(86400);
    // Civil from days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}Z", y, m, d, secs / 3600, (secs % 3600) / 60)
}

/// Parses `YYYY-MM-DDTHH:MMZ` to seconds since the epoch.
pub fn parse_quote_time(raw: &str) -> Option<i64> {
    let b = raw.as_bytes();
    if b.len() != QUOTE_TIME_LEN || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b'Z' {
        return None;
    }
    let num = |s: &[u8]| -> Option<i64> {
        let mut v = 0i64;
        for &c in s {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Some(v)
    };
    let (y, m, d) = (num(&b[0..4])?, num(&b[5..7])?, num(&b[8..10])?);
    let (hh, mm) = (num(&b[11..13])?, num(&b[14..16])?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60)
}

/// Rejects a `quote_time` older than the cache lifetime (24 h) or ahead of the
/// clock by more than 5 minutes.
pub fn check_quote_time(raw: &str, now_unix: i64) -> Result<(), String> {
    let t = parse_quote_time(raw).ok_or_else(|| format!("quote_time {raw:?} is not YYYY-MM-DDTHH:MMZ"))?;
    if t > now_unix + QUOTE_SKEW_SECS {
        return Err(format!("quote_time {raw} is in the future"));
    }
    if now_unix - t > QUOTE_MAX_AGE_SECS {
        return Err(format!("quote_time {raw} is older than 24 hours"));
    }
    Ok(())
}

/// The `leaf` field of a request: base64url SHA-256 of the leaf SPKI.
pub fn leaf_id(spki_der: &[u8]) -> String {
    b64_encode(digest::digest(&digest::SHA256, spki_der).as_ref())
}

/// Parses an attest response body, checking the protocol version and the
/// echoed mode, into [`Evidence`] (context and hctx supplied by the caller).
pub fn parse_response(
    body: &[u8],
    mode: AttestationMode,
    context: Option<[u8; CONTEXT_LEN]>,
    hctx: Option<[u8; HCTX_LEN]>,
    now_unix: i64,
) -> Result<(Evidence, Option<[u8; CONTEXT_LEN]>), String> {
    let resp: AttestResponse =
        serde_json::from_slice(body).map_err(|e| format!("attest response: {e}"))?;
    if let Some(e) = resp.error {
        return Err(format!("attest failed: {e}"));
    }
    if resp.v != PROTOCOL_VERSION {
        return Err(format!("attest response version {}, want {}", resp.v, PROTOCOL_VERSION));
    }
    if resp.mode != mode.as_str() {
        return Err(format!("attest response mode {:?}, requested {}", resp.mode, mode.as_str()));
    }
    if !matches!(resp.tee.as_str(), "sgx" | "tdx" | "tdx-gpu" | "sev-snp") {
        return Err(format!("attest response: unknown tee {:?}", resp.tee));
    }
    let quote = b64_decode(&resp.quote)?;
    if quote.is_empty() {
        return Err("attest response: empty quote".into());
    }
    let gpu_evidence = match resp.gpu_evidence.as_deref().filter(|g| !g.is_empty()) {
        Some(g) => Some(b64_decode(g)?),
        None => None,
    };
    check_quote_time(&resp.quote_time, now_unix)?;
    let client_context = match resp.client_evidence.as_str() {
        "" | "none" => None,
        "required" => {
            let cc = resp
                .client_context
                .ok_or_else(|| "server requires client evidence without a client_context".to_string())?;
            let cc = b64_decode(&cc)?;
            let arr: [u8; CONTEXT_LEN] = cc
                .try_into()
                .map_err(|_| format!("client_context is not {CONTEXT_LEN} bytes"))?;
            Some(arr)
        }
        other => return Err(format!("attest response: unknown client_evidence {other:?}")),
    };
    Ok((
        Evidence {
            mode,
            tee: resp.tee,
            quote,
            gpu_evidence,
            quote_time: resp.quote_time,
            context,
            hctx,
        },
        client_context,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_time_round_trip() {
        let t = parse_quote_time("2026-09-04T12:00Z").unwrap();
        assert_eq!(t, 1788523200);
        assert_eq!(format_quote_time(t + 37), "2026-09-04T12:00Z");
        assert_eq!(format_quote_time(0), "1970-01-01T00:00Z");
        assert!(check_quote_time("2026-09-04T11:59Z", t).is_ok());
        assert!(check_quote_time("2026-09-03T11:50Z", t).is_err());
        assert!(check_quote_time("2026-09-04T12:06Z", t).is_err());
    }

    #[test]
    fn recipes() {
        let spki = [7u8; 91];
        let ctx = [1u8; 32];
        let hctx = [2u8; 32];
        let ev = Evidence {
            mode: AttestationMode::Challenge,
            tee: "sgx".into(),
            quote: vec![],
            gpu_evidence: None,
            quote_time: String::new(),
            context: Some(ctx),
            hctx: Some(hctx),
        };
        assert_eq!(expected_report_data(&spki, &ev).unwrap(), challenge_report_data(&spki, &ctx, &hctx, None));
        assert_eq!(client_report_data(&spki, &ctx, &hctx, None), challenge_report_data(&spki, &ctx, &hctx, None));
        let det = Evidence { mode: AttestationMode::Deterministic, quote_time: "2026-09-04T10:15Z".into(), context: None, hctx: None, ..ev };
        assert_eq!(expected_report_data(&spki, &det).unwrap(), deterministic_report_data(&spki, "2026-09-04T10:15Z", None));
    }
}
