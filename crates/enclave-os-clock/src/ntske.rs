// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! NTS Key Establishment records (RFC 8915 §4).
//!
//! NTS-KE runs over TLS 1.3 (ALPN `ntske/1`, TCP 4460). The client sends
//! one request (NTPv4 as next protocol, the AEAD algorithms it offers, end
//! of message); the server answers with NTPv4, the one algorithm it picked,
//! a set of opaque cookies and optionally another NTP host or port. The two
//! AEAD keys are not sent: both sides derive them from the TLS exporter
//! ([`EXPORTER_LABEL`], [`exporter_context`]).
//!
//! Each record is `[C|type:15][len:16][body]`, big-endian, where C marks a
//! record the receiver must understand.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::aead::{NtsAead, OFFERED};

/// End of Message.
pub const REC_END: u16 = 0;
/// NTS Next Protocol Negotiation.
pub const REC_NEXT_PROTOCOL: u16 = 1;
/// Error.
pub const REC_ERROR: u16 = 2;
/// Warning.
pub const REC_WARNING: u16 = 3;
/// AEAD Algorithm Negotiation.
pub const REC_AEAD: u16 = 4;
/// New Cookie for NTPv4.
pub const REC_NEW_COOKIE: u16 = 5;
/// NTPv4 Server Negotiation.
pub const REC_SERVER: u16 = 6;
/// NTPv4 Port Negotiation.
pub const REC_PORT: u16 = 7;

/// Protocol id of NTPv4 in Next Protocol Negotiation.
pub const PROTOCOL_NTPV4: u16 = 0;

/// TLS ALPN protocol id of NTS-KE.
pub const ALPN: &[u8] = b"ntske/1";
/// Default NTS-KE port.
pub const KE_PORT: u16 = 4460;
/// Default NTP port.
pub const NTP_PORT: u16 = 123;
/// TLS exporter label for the NTS keys.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

/// Most cookies kept from one exchange (servers send eight).
pub const MAX_COOKIES: usize = 8;
/// Largest KE response accepted, in bytes.
pub const MAX_RESPONSE: usize = 16 * 1024;

const CRITICAL: u16 = 0x8000;

/// The exporter context for one direction (§5.1): protocol id, AEAD id,
/// then 0x00 for client-to-server or 0x01 for server-to-client.
///
/// For AEAD_AES_128_GCM_SIV the AEAD id in the context is that of
/// AEAD_AES_SIV_CMAC_256 (15), not 30. The deployed servers derive their
/// keys that way (chrony introduced it, and every server of the pinned
/// list that picks GCM-SIV does it): with 30 in the context each of them
/// refuses the request (kiss code NTSN). The key length stays 16.
pub fn exporter_context(aead: NtsAead, server_to_client: bool) -> [u8; 5] {
    let p = PROTOCOL_NTPV4.to_be_bytes();
    let id = match aead {
        NtsAead::AesSivCmac256 | NtsAead::Aes128GcmSiv => NtsAead::AesSivCmac256.id(),
    };
    let a = id.to_be_bytes();
    [p[0], p[1], a[0], a[1], server_to_client as u8]
}

fn push_record(out: &mut Vec<u8>, critical: bool, rtype: u16, body: &[u8]) {
    let t = if critical { rtype | CRITICAL } else { rtype };
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// The client's request: NTPv4, the offered AEAD algorithms in order of
/// preference, end of message.
pub fn build_request() -> Vec<u8> {
    let mut algs = Vec::with_capacity(2 * OFFERED.len());
    for a in OFFERED {
        algs.extend_from_slice(&a.id().to_be_bytes());
    }
    let mut out = Vec::with_capacity(12 + algs.len());
    push_record(&mut out, true, REC_NEXT_PROTOCOL, &PROTOCOL_NTPV4.to_be_bytes());
    push_record(&mut out, true, REC_AEAD, &algs);
    push_record(&mut out, true, REC_END, &[]);
    out
}

/// What a valid server response gives the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeResponse {
    /// The AEAD algorithm the server picked.
    pub aead: NtsAead,
    /// Opaque cookies, each good for one NTP request.
    pub cookies: Vec<Vec<u8>>,
    /// NTP host to use instead of the KE host.
    pub server: Option<String>,
    /// NTP port to use instead of 123.
    pub port: Option<u16>,
}

/// Why a KE response was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeError {
    /// The server sent an Error record with this code.
    Server(u16),
    /// A record the client does not understand was marked critical.
    UnknownCritical(u16),
    /// The response did not negotiate NTPv4.
    Protocol,
    /// The response did not pick exactly one of the offered algorithms.
    Aead,
    /// No cookie.
    NoCookies,
    /// A record body is malformed, repeated, or the response is too large.
    Malformed(&'static str),
}

impl core::fmt::Display for KeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeError::Server(c) => write!(f, "server error record {c}"),
            KeError::UnknownCritical(t) => write!(f, "unknown critical record {t}"),
            KeError::Protocol => write!(f, "NTPv4 not negotiated"),
            KeError::Aead => write!(f, "no offered AEAD algorithm negotiated"),
            KeError::NoCookies => write!(f, "no cookies"),
            KeError::Malformed(m) => write!(f, "malformed response: {m}"),
        }
    }
}

/// Parse the server's response.
///
/// Returns `Ok(None)` while `buf` does not yet hold the End of Message
/// record, so the caller can read more and call again with the whole
/// buffer.
pub fn parse_response(buf: &[u8]) -> Result<Option<KeResponse>, KeError> {
    if buf.len() > MAX_RESPONSE {
        return Err(KeError::Malformed("response too large"));
    }
    let mut protocol: Option<bool> = None;
    let mut aead: Option<Option<NtsAead>> = None;
    let mut cookies = Vec::new();
    let mut server = None;
    let mut port = None;
    let mut off = 0usize;
    loop {
        if buf.len() < off + 4 {
            return Ok(None);
        }
        let raw_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if buf.len() < off + 4 + len {
            return Ok(None);
        }
        let critical = raw_type & CRITICAL != 0;
        let rtype = raw_type & !CRITICAL;
        let body = &buf[off + 4..off + 4 + len];
        off += 4 + len;
        match rtype {
            REC_END => {
                if !body.is_empty() {
                    return Err(KeError::Malformed("end of message has a body"));
                }
                break;
            }
            REC_NEXT_PROTOCOL => {
                if protocol.is_some() {
                    return Err(KeError::Malformed("repeated next protocol"));
                }
                protocol = Some(body == PROTOCOL_NTPV4.to_be_bytes());
            }
            REC_ERROR => {
                if body.len() != 2 {
                    return Err(KeError::Malformed("error record"));
                }
                return Err(KeError::Server(u16::from_be_bytes([body[0], body[1]])));
            }
            REC_WARNING => {}
            REC_AEAD => {
                if aead.is_some() {
                    return Err(KeError::Malformed("repeated aead"));
                }
                // Exactly one algorithm, and one we offered.
                aead = Some(if body.len() == 2 {
                    NtsAead::from_id(u16::from_be_bytes([body[0], body[1]]))
                } else {
                    None
                });
            }
            REC_NEW_COOKIE => {
                if body.is_empty() {
                    return Err(KeError::Malformed("empty cookie"));
                }
                if cookies.len() < MAX_COOKIES {
                    cookies.push(body.to_vec());
                }
            }
            REC_SERVER => {
                if server.is_some() {
                    return Err(KeError::Malformed("repeated server"));
                }
                let s = core::str::from_utf8(body)
                    .ok()
                    .filter(|s| !s.is_empty() && s.is_ascii())
                    .ok_or(KeError::Malformed("server name"))?;
                server = Some(s.to_string());
            }
            REC_PORT => {
                if port.is_some() || body.len() != 2 {
                    return Err(KeError::Malformed("port"));
                }
                port = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            other if critical => return Err(KeError::UnknownCritical(other)),
            _ => {}
        }
    }
    if protocol != Some(true) {
        return Err(KeError::Protocol);
    }
    let aead = aead.flatten().ok_or(KeError::Aead)?;
    if cookies.is_empty() {
        return Err(KeError::NoCookies);
    }
    Ok(Some(KeResponse { aead, cookies, server, port }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn response(aead: &[u8], extra: &[(bool, u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        push_record(&mut out, true, REC_NEXT_PROTOCOL, &[0, 0]);
        push_record(&mut out, false, REC_AEAD, aead);
        for (c, t, b) in extra {
            push_record(&mut out, *c, *t, b);
        }
        push_record(&mut out, true, REC_END, &[]);
        out
    }

    #[test]
    fn request_bytes() {
        assert_eq!(
            build_request(),
            vec![
                0x80, 0x01, 0x00, 0x02, 0x00, 0x00, // NTPv4
                0x80, 0x04, 0x00, 0x04, 0x00, 0x1e, 0x00, 0x0f, // GCM-SIV, SIV-CMAC
                0x80, 0x00, 0x00, 0x00, // end
            ]
        );
    }

    #[test]
    fn exporter_contexts() {
        assert_eq!(exporter_context(NtsAead::AesSivCmac256, false), [0, 0, 0, 15, 0]);
        assert_eq!(exporter_context(NtsAead::AesSivCmac256, true), [0, 0, 0, 15, 1]);
        // GCM-SIV keys use the SIV-CMAC id, as deployed servers do.
        assert_eq!(exporter_context(NtsAead::Aes128GcmSiv, false), [0, 0, 0, 15, 0]);
        assert_eq!(exporter_context(NtsAead::Aes128GcmSiv, true), [0, 0, 0, 15, 1]);
    }

    #[test]
    fn parses_cookies_server_port_and_the_picked_aead() {
        let buf = response(
            &[0, 30],
            &[
                (false, REC_NEW_COOKIE, b"cookie-one"),
                (false, REC_NEW_COOKIE, b"cookie-two"),
                (true, REC_SERVER, b"ntp.example.org"),
                (true, REC_PORT, &[0x01, 0x7b]),
                (false, 0x1234, b"ignored"),
            ],
        );
        let r = parse_response(&buf).unwrap().unwrap();
        assert_eq!(r.aead, NtsAead::Aes128GcmSiv);
        assert_eq!(r.cookies, vec![b"cookie-one".to_vec(), b"cookie-two".to_vec()]);
        assert_eq!(r.server.as_deref(), Some("ntp.example.org"));
        assert_eq!(r.port, Some(379));
        let r = parse_response(&response(&[0, 15], &[(false, REC_NEW_COOKIE, b"c")])).unwrap().unwrap();
        assert_eq!(r.aead, NtsAead::AesSivCmac256);
    }

    #[test]
    fn incomplete_until_end_of_message() {
        let buf = response(&[0, 15], &[(false, REC_NEW_COOKIE, b"c")]);
        for cut in 0..buf.len() {
            assert_eq!(parse_response(&buf[..cut]), Ok(None), "cut at {cut}");
        }
        assert!(parse_response(&buf).unwrap().is_some());
    }

    #[test]
    fn refusals() {
        let mut err = Vec::new();
        push_record(&mut err, true, REC_ERROR, &[0, 1]);
        assert_eq!(parse_response(&err), Err(KeError::Server(1)));

        let buf = response(&[0, 15], &[(true, 0x0042, b"x"), (false, REC_NEW_COOKIE, b"c")]);
        assert_eq!(parse_response(&buf), Err(KeError::UnknownCritical(0x42)));

        let buf = response(&[0, 15], &[]);
        assert_eq!(parse_response(&buf), Err(KeError::NoCookies));

        // Not offered, or more than one.
        for algs in [&[0u8, 17][..], &[0, 15, 0, 30][..], &[][..]] {
            let buf = response(algs, &[(false, REC_NEW_COOKIE, b"c")]);
            assert_eq!(parse_response(&buf), Err(KeError::Aead), "{algs:?}");
        }
        // No AEAD record at all.
        let mut none = Vec::new();
        push_record(&mut none, true, REC_NEXT_PROTOCOL, &[0, 0]);
        push_record(&mut none, false, REC_NEW_COOKIE, b"c");
        push_record(&mut none, true, REC_END, &[]);
        assert_eq!(parse_response(&none), Err(KeError::Aead));

        let mut wrong_proto = Vec::new();
        push_record(&mut wrong_proto, true, REC_NEXT_PROTOCOL, &[0x80, 0x01]);
        push_record(&mut wrong_proto, true, REC_AEAD, &[0, 15]);
        push_record(&mut wrong_proto, false, REC_NEW_COOKIE, b"c");
        push_record(&mut wrong_proto, true, REC_END, &[]);
        assert_eq!(parse_response(&wrong_proto), Err(KeError::Protocol));
    }

    #[test]
    fn keeps_at_most_eight_cookies() {
        let many: Vec<(bool, u16, &[u8])> = (0..12).map(|_| (false, REC_NEW_COOKIE, &b"c"[..])).collect();
        let r = parse_response(&response(&[0, 15], &many)).unwrap().unwrap();
        assert_eq!(r.cookies.len(), MAX_COOKIES);
    }
}
