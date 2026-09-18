// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Wire contracts between the runtime, management-service and the monitor.
//!
//! Keys are Ed25519. Times are Unix milliseconds. Base64 is base64url
//! without padding. Signed payloads are the exact UTF-8 bytes of their
//! lines joined with `\n`, no trailing newline:
//!
//! - floor poll: `privasys-clock-floor/v1`, `enclave_id`, `t_ms`, `seq`
//! - incident receipt: `privasys-clock-receipt/v1`, `enclave_id`, `nonce`,
//!   `incident_id`
//!
//! The clock config (`PUT /clock/config`) carries the monitor key that
//! verifies both; it comes from management-service over the manager-role
//! channel and a change is accepted only with a higher `config_version`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// First line of the signed floor payload.
pub const FLOOR_DOMAIN: &str = "privasys-clock-floor/v1";
/// First line of the signed receipt payload.
pub const RECEIPT_DOMAIN: &str = "privasys-clock-receipt/v1";

/// A refused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Malformed body or field (HTTP 400).
    BadRequest(String),
    /// Well formed, but not signed by the configured monitor, or for
    /// another enclave (HTTP 401).
    Unauthorized(&'static str),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadRequest(m) => write!(f, "{m}"),
            WireError::Unauthorized(m) => write!(f, "{m}"),
        }
    }
}

/// base64url, no padding.
pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url; trailing padding is tolerated.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Key id of a monitor key: lowercase hex of the first 8 bytes of
/// `sha256(public key)` (16 hex characters).
pub fn key_id(public_key: &[u8]) -> String {
    let h = ring::digest::digest(&ring::digest::SHA256, public_key);
    let mut s = String::with_capacity(16);
    for b in &h.as_ref()[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The bytes the monitor signs for a floor poll.
pub fn floor_signed_bytes(enclave_id: &str, t_ms: i64, seq: u64) -> Vec<u8> {
    format!("{FLOOR_DOMAIN}\n{enclave_id}\n{t_ms}\n{seq}").into_bytes()
}

/// The bytes the monitor signs for an incident receipt.
pub fn receipt_signed_bytes(enclave_id: &str, nonce: &str, incident_id: &str) -> Vec<u8> {
    format!("{RECEIPT_DOMAIN}\n{enclave_id}\n{nonce}\n{incident_id}").into_bytes()
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519(public_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(msg, sig)
        .is_ok()
}

// ---------------------------------------------------------------------------
//  Clock config
// ---------------------------------------------------------------------------

/// `PUT /clock/config` body, as sent by management-service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockConfigWire {
    /// management-service's id of this enclave.
    pub enclave_id: String,
    /// base64url 32-byte Ed25519 public key of the monitor.
    pub monitor_key: String,
    /// [`key_id`] of `monitor_key`.
    pub monitor_key_id: String,
    /// Where incidents are POSTed (`https://`).
    pub incident_url: String,
    /// Monotonic version; only a higher one replaces the current config.
    pub config_version: u64,
}

/// A validated clock config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorConfig {
    /// The config as received.
    pub wire: ClockConfigWire,
    /// Decoded `monitor_key`.
    pub key: [u8; 32],
}

impl MonitorConfig {
    /// Parse and validate a config body.
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let wire: ClockConfigWire = serde_json::from_slice(body)
            .map_err(|e| WireError::BadRequest(format!("invalid clock config: {e}")))?;
        Self::from_wire(wire)
    }

    /// Validate a decoded config.
    pub fn from_wire(wire: ClockConfigWire) -> Result<Self, WireError> {
        if wire.enclave_id.is_empty() {
            return Err(WireError::BadRequest("enclave_id is required".to_string()));
        }
        let key = b64url_decode(&wire.monitor_key)
            .filter(|k| k.len() == 32)
            .ok_or_else(|| WireError::BadRequest("monitor_key must be a base64url 32-byte Ed25519 key".to_string()))?;
        if !wire.monitor_key_id.eq_ignore_ascii_case(&key_id(&key)) {
            return Err(WireError::BadRequest("monitor_key_id does not match monitor_key".to_string()));
        }
        let url = wire.incident_url.as_str();
        if !url.starts_with("https://") || url.len() <= "https://".len() {
            return Err(WireError::BadRequest("incident_url must be an https:// URL".to_string()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        Ok(Self { wire, key: k })
    }

    /// Lowercase key id of the configured monitor key.
    pub fn key_id(&self) -> String {
        self.wire.monitor_key_id.to_ascii_lowercase()
    }
}

// ---------------------------------------------------------------------------
//  Floor poll
// ---------------------------------------------------------------------------

/// `POST /clock/poll` body, signed by the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollRequest {
    /// Must be this enclave's configured id.
    pub enclave_id: String,
    /// The monitor's claim: the time is at least this.
    pub t_ms: i64,
    /// Monitor sequence number (signed, not otherwise interpreted).
    pub seq: u64,
    /// Key id of the signing key.
    pub key_id: String,
    /// base64url Ed25519 signature over [`floor_signed_bytes`].
    pub sig: String,
}

impl PollRequest {
    /// Parse a poll body.
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        serde_json::from_slice(body).map_err(|e| WireError::BadRequest(format!("invalid poll: {e}")))
    }

    /// Check the poll is for this enclave and signed by the configured key.
    pub fn verify(&self, cfg: &MonitorConfig) -> Result<(), WireError> {
        if self.enclave_id != cfg.wire.enclave_id {
            return Err(WireError::Unauthorized("enclave_id does not match this enclave"));
        }
        if !self.key_id.eq_ignore_ascii_case(&cfg.key_id()) {
            return Err(WireError::Unauthorized("key_id is not the configured monitor key"));
        }
        let sig = b64url_decode(&self.sig).ok_or(WireError::Unauthorized("bad signature"))?;
        if !verify_ed25519(&cfg.key, &floor_signed_bytes(&self.enclave_id, self.t_ms, self.seq), &sig) {
            return Err(WireError::Unauthorized("bad signature"));
        }
        Ok(())
    }
}

/// NTS part of a poll reply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtsReply {
    /// Agreed NTS time of the fetch this poll made, or 0 when it made none.
    pub time_ms: i64,
    /// Servers of that fetch; empty when it made none.
    pub servers: Vec<String>,
}

/// Reply to a floor poll. Authentic through the RA-TLS channel it is sent on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollReply {
    pub enclave_id: String,
    /// `mini` or `virtual`.
    pub runtime: String,
    pub host_time_ms: i64,
    pub trusted_time_ms: i64,
    pub floor_ms: i64,
    pub flagged: bool,
    /// Why the clock is flagged, or empty.
    pub reason: String,
    /// `in_sync`, `monitor_clock_wrong`, `host_clock_wrong` or `ignored_stale`.
    pub verdict: String,
    pub nts: NtsReply,
    /// Key id of the configured monitor key.
    pub config_key_id: String,
}

// ---------------------------------------------------------------------------
//  Incident and receipt
// ---------------------------------------------------------------------------

/// Incident body, POSTed to the configured `incident_url`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub enclave_id: String,
    /// `host_behind_floor`, `host_clock_wrong`, `monitor_clock_wrong` or
    /// `nts_unreachable`.
    pub reason: String,
    pub host_time_ms: i64,
    pub floor_ms: i64,
    /// NTS time behind the report, or 0 when there is none.
    pub nts_time_ms: i64,
    /// base64url 32 random bytes, echoed in the signed receipt.
    pub nonce: String,
}

/// The monitor's signed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub incident_id: String,
    pub nonce: String,
    pub key_id: String,
    pub sig: String,
}

/// Verify a receipt body against the nonce sent and the configured key.
/// Returns the monitor's incident id.
pub fn verify_receipt(cfg: &MonitorConfig, nonce: &str, body: &[u8]) -> Result<String, WireError> {
    let r: Receipt =
        serde_json::from_slice(body).map_err(|e| WireError::BadRequest(format!("invalid receipt: {e}")))?;
    if r.nonce != nonce {
        return Err(WireError::Unauthorized("receipt nonce does not match"));
    }
    if !r.key_id.eq_ignore_ascii_case(&cfg.key_id()) {
        return Err(WireError::Unauthorized("receipt key_id is not the configured monitor key"));
    }
    if r.incident_id.is_empty() {
        return Err(WireError::BadRequest("receipt has no incident_id".to_string()));
    }
    let sig = b64url_decode(&r.sig).ok_or(WireError::Unauthorized("bad receipt signature"))?;
    if !verify_ed25519(&cfg.key, &receipt_signed_bytes(&cfg.wire.enclave_id, nonce, &r.incident_id), &sig) {
        return Err(WireError::Unauthorized("bad receipt signature"));
    }
    Ok(r.incident_id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub(crate) fn monitor() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[42u8; 32]).unwrap()
    }

    pub(crate) fn config(version: u64) -> MonitorConfig {
        let kp = monitor();
        let pk = kp.public_key().as_ref();
        MonitorConfig::from_wire(ClockConfigWire {
            enclave_id: "enc-1".to_string(),
            monitor_key: b64url_encode(pk),
            monitor_key_id: key_id(pk),
            incident_url: "https://monitor.example/api/v1/clock/incidents".to_string(),
            config_version: version,
        })
        .unwrap()
    }

    pub(crate) fn signed_poll(enclave_id: &str, t_ms: i64, seq: u64) -> PollRequest {
        let kp = monitor();
        PollRequest {
            enclave_id: enclave_id.to_string(),
            t_ms,
            seq,
            key_id: key_id(kp.public_key().as_ref()),
            sig: b64url_encode(kp.sign(&floor_signed_bytes(enclave_id, t_ms, seq)).as_ref()),
        }
    }

    pub(crate) fn signed_receipt(enclave_id: &str, nonce: &str, incident_id: &str) -> Vec<u8> {
        let kp = monitor();
        serde_json::to_vec(&Receipt {
            incident_id: incident_id.to_string(),
            nonce: nonce.to_string(),
            key_id: key_id(kp.public_key().as_ref()),
            sig: b64url_encode(kp.sign(&receipt_signed_bytes(enclave_id, nonce, incident_id)).as_ref()),
        })
        .unwrap()
    }

    #[test]
    fn signed_bytes_are_exact() {
        assert_eq!(
            floor_signed_bytes("e1", 1_789_000_000_000, 42),
            b"privasys-clock-floor/v1\ne1\n1789000000000\n42".to_vec()
        );
        assert_eq!(
            receipt_signed_bytes("e1", "bm9uY2U", "inc-7"),
            b"privasys-clock-receipt/v1\ne1\nbm9uY2U\ninc-7".to_vec()
        );
    }

    #[test]
    fn key_id_is_16_hex_of_sha256() {
        // sha256("") = e3b0c44298fc1c14...
        assert_eq!(key_id(b""), "e3b0c44298fc1c14");
    }

    #[test]
    fn config_validation() {
        let good = config(3);
        assert_eq!(good.wire.config_version, 3);
        let body = serde_json::to_vec(&good.wire).unwrap();
        assert_eq!(MonitorConfig::parse(&body).unwrap(), good);

        let mut w = good.wire.clone();
        w.monitor_key_id = "0000000000000000".to_string();
        assert!(matches!(MonitorConfig::from_wire(w), Err(WireError::BadRequest(_))));
        let mut w = good.wire.clone();
        w.incident_url = "http://monitor.example/x".to_string();
        assert!(matches!(MonitorConfig::from_wire(w), Err(WireError::BadRequest(_))));
        let mut w = good.wire.clone();
        w.monitor_key = b64url_encode(&[1u8; 31]);
        assert!(matches!(MonitorConfig::from_wire(w), Err(WireError::BadRequest(_))));
        let mut w = good.wire;
        w.enclave_id.clear();
        assert!(matches!(MonitorConfig::from_wire(w), Err(WireError::BadRequest(_))));
    }

    #[test]
    fn poll_verification() {
        let cfg = config(1);
        let p = signed_poll("enc-1", 1_789_700_000_000, 5);
        let body = serde_json::to_vec(&p).unwrap();
        assert_eq!(PollRequest::parse(&body).unwrap().verify(&cfg), Ok(()));

        let mut bad = p.clone();
        bad.t_ms += 1;
        assert_eq!(bad.verify(&cfg), Err(WireError::Unauthorized("bad signature")));
        let mut bad = p.clone();
        bad.seq += 1;
        assert_eq!(bad.verify(&cfg), Err(WireError::Unauthorized("bad signature")));
        let other = signed_poll("enc-2", 1_789_700_000_000, 5);
        assert!(matches!(other.verify(&cfg), Err(WireError::Unauthorized(_))));
        let mut bad = p;
        bad.key_id = "ffffffffffffffff".to_string();
        assert!(matches!(bad.verify(&cfg), Err(WireError::Unauthorized(_))));
    }

    #[test]
    fn receipt_verification() {
        let cfg = config(1);
        let body = signed_receipt("enc-1", "n0nce", "inc-1");
        assert_eq!(verify_receipt(&cfg, "n0nce", &body), Ok("inc-1".to_string()));
        assert!(verify_receipt(&cfg, "other", &body).is_err());
        let body = signed_receipt("enc-2", "n0nce", "inc-1");
        assert_eq!(verify_receipt(&cfg, "n0nce", &body), Err(WireError::Unauthorized("bad receipt signature")));
    }

    #[test]
    fn poll_reply_field_order() {
        let r = PollReply {
            enclave_id: "e".to_string(),
            runtime: "mini".to_string(),
            host_time_ms: 1,
            trusted_time_ms: 2,
            floor_ms: 3,
            flagged: false,
            reason: String::new(),
            verdict: "in_sync".to_string(),
            nts: NtsReply::default(),
            config_key_id: "k".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            "{\"enclave_id\":\"e\",\"runtime\":\"mini\",\"host_time_ms\":1,\"trusted_time_ms\":2,\
             \"floor_ms\":3,\"flagged\":false,\"reason\":\"\",\"verdict\":\"in_sync\",\
             \"nts\":{\"time_ms\":0,\"servers\":[]},\"config_key_id\":\"k\"}"
        );
    }
}
