// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! NTPv4 client packet with the NTS extension fields (RFC 8915 §5).
//!
//! The request is a 48-byte client-mode header followed by three extension
//! fields: Unique Identifier (32 random bytes), NTS Cookie (one cookie from
//! NTS-KE), and NTS Authenticator, whose AEAD tag (under the
//! client-to-server key) covers everything before it. The response is
//! accepted only when its own Authenticator verifies under the
//! server-to-client key, the authenticated part echoes our Unique
//! Identifier, and the origin timestamp echoes our transmit timestamp.
//!
//! Every packet crosses the host, which can drop, delay or replay it but
//! can neither forge nor alter one. The host's delay is the one thing an SGX
//! enclave cannot measure (it has no clock), so the server's transmit
//! timestamp is taken as the time.

use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::{Aes128SivAead, Nonce};
use alloc::vec::Vec;

use crate::ntske::KEY_LEN;

/// Unique Identifier extension field.
pub const EF_UNIQUE_ID: u16 = 0x0104;
/// NTS Cookie extension field.
pub const EF_COOKIE: u16 = 0x0204;
/// NTS Cookie Placeholder extension field.
pub const EF_COOKIE_PLACEHOLDER: u16 = 0x0304;
/// NTS Authenticator and Encrypted Extension Fields.
pub const EF_AUTHENTICATOR: u16 = 0x0404;

/// NTP header length.
pub const HEADER_LEN: usize = 48;
/// Unique Identifier length used by this client.
pub const UID_LEN: usize = 32;
/// SIV nonce length used by this client (and the only one accepted back).
pub const NONCE_LEN: usize = 16;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const NTP_UNIX_OFFSET: i64 = 2_208_988_800;

/// Why a response was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtpError {
    /// Shorter than an NTP header, or an extension field overruns.
    Malformed(&'static str),
    /// Not a version 4 server-mode reply.
    NotServerReply,
    /// The server says it is not synchronised (leap indicator 3 or bad stratum).
    Unsynchronised,
    /// Kiss-o'-Death with this code (e.g. `NTSN`: the cookie was refused).
    Kiss([u8; 4]),
    /// The origin timestamp does not echo our transmit timestamp.
    OriginMismatch,
    /// No authenticated Unique Identifier matching the request.
    UniqueIdMismatch,
    /// No Authenticator, or the AEAD tag does not verify.
    NotAuthenticated,
}

impl core::fmt::Display for NtpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NtpError::Malformed(m) => write!(f, "malformed reply: {m}"),
            NtpError::NotServerReply => write!(f, "not an NTPv4 server reply"),
            NtpError::Unsynchronised => write!(f, "server not synchronised"),
            NtpError::Kiss(c) => write!(f, "kiss-o'-death {}", core::str::from_utf8(c).unwrap_or("????")),
            NtpError::OriginMismatch => write!(f, "origin timestamp mismatch"),
            NtpError::UniqueIdMismatch => write!(f, "unique identifier mismatch"),
            NtpError::NotAuthenticated => write!(f, "reply not authenticated"),
        }
    }
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

fn push_ef(out: &mut Vec<u8>, ftype: u16, body: &[u8]) {
    let len = 4 + pad4(body.len());
    out.extend_from_slice(&ftype.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + pad4(body.len()) - body.len(), 0);
}

fn siv(key: &[u8; KEY_LEN]) -> Aes128SivAead {
    // A 32-byte slice always fits AEAD_AES_SIV_CMAC_256.
    Aes128SivAead::new_from_slice(key).expect("32-byte SIV key")
}

/// Append an Authenticator extension field whose tag covers `packet` as it
/// stands, sealing `plaintext` (encrypted extension fields; empty for a
/// client request).
pub fn push_authenticator(packet: &mut Vec<u8>, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) {
    let ct = siv(key)
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: packet })
        .expect("SIV encryption does not fail");
    let mut body = Vec::with_capacity(4 + NONCE_LEN + pad4(ct.len()));
    body.extend_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    body.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ct);
    body.resize(4 + NONCE_LEN + pad4(ct.len()), 0);
    push_ef(packet, EF_AUTHENTICATOR, &body);
}

/// Build the client request.
///
/// `xmt` goes into the transmit timestamp: pass random bytes, not a time,
/// so the request carries no clock reading and the server's origin echo
/// works as a second nonce.
pub fn build_request(
    c2s: &[u8; KEY_LEN],
    cookie: &[u8],
    uid: &[u8; UID_LEN],
    xmt: &[u8; 8],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(HEADER_LEN + 36 + 4 + pad4(cookie.len()) + 40);
    p.resize(HEADER_LEN, 0);
    // LI = 0, VN = 4, mode = 3 (client).
    p[0] = (4 << 3) | 3;
    p[40..48].copy_from_slice(xmt);
    push_ef(&mut p, EF_UNIQUE_ID, uid);
    push_ef(&mut p, EF_COOKIE, cookie);
    push_authenticator(&mut p, c2s, nonce, &[]);
    p
}

/// Convert an NTP 64-bit timestamp to Unix milliseconds. Era 0 covers
/// 1968 to 2036; seconds below the Unix offset are read as era 1, which
/// keeps the result right until 2104.
pub fn ntp_to_unix_ms(ts: &[u8; 8]) -> i64 {
    let secs = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]) as i64;
    let frac = u32::from_be_bytes([ts[4], ts[5], ts[6], ts[7]]) as i64;
    let secs = if secs >= NTP_UNIX_OFFSET { secs } else { secs + (1i64 << 32) };
    (secs - NTP_UNIX_OFFSET) * 1_000 + ((frac * 1_000) >> 32)
}

/// Inverse of [`ntp_to_unix_ms`], for tests and fake servers.
pub fn unix_ms_to_ntp(ms: i64) -> [u8; 8] {
    let secs = ms.div_euclid(1_000) + NTP_UNIX_OFFSET;
    let rem = ms.rem_euclid(1_000);
    // Round up so that the truncating conversion back lands on `ms`.
    let frac = (((rem << 32) + 999) / 1_000) as u32;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(secs as u32).to_be_bytes());
    out[4..].copy_from_slice(&frac.to_be_bytes());
    out
}

/// Verify a server reply and return the server's transmit time in Unix ms.
pub fn parse_response(
    pkt: &[u8],
    s2c: &[u8; KEY_LEN],
    uid: &[u8; UID_LEN],
    xmt: &[u8; 8],
) -> Result<i64, NtpError> {
    if pkt.len() < HEADER_LEN {
        return Err(NtpError::Malformed("short header"));
    }
    let li = pkt[0] >> 6;
    let vn = (pkt[0] >> 3) & 7;
    let mode = pkt[0] & 7;
    if vn != 4 || mode != 4 {
        return Err(NtpError::NotServerReply);
    }
    let stratum = pkt[1];
    if stratum == 0 {
        let mut code = [0u8; 4];
        code.copy_from_slice(&pkt[12..16]);
        return Err(NtpError::Kiss(code));
    }
    if li == 3 || stratum >= 16 {
        return Err(NtpError::Unsynchronised);
    }
    if &pkt[24..32] != xmt {
        return Err(NtpError::OriginMismatch);
    }

    // Walk the extension fields up to the Authenticator. Fields after it
    // are not covered by the tag and are ignored.
    let mut off = HEADER_LEN;
    let mut uid_seen = false;
    let mut authenticated = false;
    while off + 4 <= pkt.len() {
        let ftype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let len = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize;
        if len < 4 || len % 4 != 0 || off + len > pkt.len() {
            return Err(NtpError::Malformed("extension field length"));
        }
        let body = &pkt[off + 4..off + len];
        match ftype {
            EF_UNIQUE_ID => {
                if body == uid {
                    uid_seen = true;
                }
            }
            EF_AUTHENTICATOR => {
                if body.len() < 4 {
                    return Err(NtpError::Malformed("authenticator"));
                }
                let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                if nonce_len != NONCE_LEN || 4 + pad4(nonce_len) + pad4(ct_len) > body.len() {
                    return Err(NtpError::Malformed("authenticator lengths"));
                }
                let nonce = &body[4..4 + nonce_len];
                let ct_start = 4 + pad4(nonce_len);
                let ct = &body[ct_start..ct_start + ct_len];
                siv(s2c)
                    .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &pkt[..off] })
                    .map_err(|_| NtpError::NotAuthenticated)?;
                authenticated = true;
                break;
            }
            _ => {}
        }
        off += len;
    }
    if !authenticated {
        return Err(NtpError::NotAuthenticated);
    }
    if !uid_seen {
        return Err(NtpError::UniqueIdMismatch);
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&pkt[40..48]);
    if ts == [0u8; 8] {
        return Err(NtpError::Malformed("zero transmit timestamp"));
    }
    Ok(ntp_to_unix_ms(&ts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_siv::siv::Aes128Siv;
    use alloc::vec;

    const C2S: [u8; 32] = [1; 32];
    const S2C: [u8; 32] = [2; 32];
    const UID: [u8; 32] = [7; 32];
    const XMT: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

    /// A server reply the way an NTS server builds one.
    fn server_reply(uid: &[u8; 32], origin: &[u8; 8], time_ms: i64, key: &[u8; 32]) -> Vec<u8> {
        let mut p = vec![0u8; HEADER_LEN];
        p[0] = (4 << 3) | 4;
        p[1] = 1;
        p[24..32].copy_from_slice(origin);
        p[40..48].copy_from_slice(&unix_ms_to_ntp(time_ms));
        push_ef(&mut p, EF_UNIQUE_ID, uid);
        // One fresh cookie, encrypted, as servers do.
        let mut enc = Vec::new();
        push_ef(&mut enc, EF_COOKIE, &[0xAB; 100]);
        push_authenticator(&mut p, key, &[3; 16], &enc);
        p
    }

    #[test]
    fn rfc5297_deterministic_vector_confirms_tag_first() {
        // RFC 5297 appendix A.1.
        let key = hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = hex("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = hex("112233445566778899aabbccddee");
        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let out = siv.encrypt(&[&ad], &pt).unwrap();
        assert_eq!(out, hex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"));
    }

    #[test]
    fn aead_is_s2v_over_ad_then_nonce() {
        let aad = b"header bytes";
        let nonce = [5u8; 16];
        let a = siv(&C2S).encrypt(Nonce::from_slice(&nonce), Payload { msg: b"pt", aad }).unwrap();
        let b = Aes128Siv::new_from_slice(&C2S).unwrap().encrypt(&[&aad[..], &nonce[..]], b"pt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn request_layout() {
        let cookie = [0x55u8; 99];
        let p = build_request(&C2S, &cookie, &UID, &XMT, &[4; 16]);
        assert_eq!(p[0], 0x23);
        assert_eq!(&p[40..48], &XMT);
        // Unique Identifier: 4 + 32.
        assert_eq!(&p[48..52], &[0x01, 0x04, 0x00, 36]);
        // Cookie padded to 100.
        assert_eq!(&p[84..88], &[0x02, 0x04, 0x00, 104]);
        // Authenticator: 4 + 4 + 16 nonce + 16 tag.
        let a = 84 + 104;
        assert_eq!(&p[a..a + 8], &[0x04, 0x04, 0x00, 40, 0x00, 16, 0x00, 16]);
        assert_eq!(p.len(), a + 40);
        // The tag covers everything before the authenticator.
        let ct = &p[a + 24..a + 40];
        siv(&C2S)
            .decrypt(Nonce::from_slice(&[4; 16]), Payload { msg: ct, aad: &p[..a] })
            .unwrap();
    }

    #[test]
    fn accepts_authentic_reply() {
        let t = 1_789_700_000_123;
        let r = server_reply(&UID, &XMT, t, &S2C);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Ok(t));
    }

    #[test]
    fn refuses_forged_or_replayed_replies() {
        let t = 1_789_700_000_000;
        // Wrong key: forged.
        let r = server_reply(&UID, &XMT, t, &C2S);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::NotAuthenticated));
        // Another request's uid: replay.
        let r = server_reply(&[8; 32], &XMT, t, &S2C);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::UniqueIdMismatch));
        // Another request's origin.
        let r = server_reply(&UID, &[0; 8], t, &S2C);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::OriginMismatch));
        // Host rewrites the time: the tag covers the header.
        let mut r = server_reply(&UID, &XMT, t, &S2C);
        r[41] ^= 1;
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::NotAuthenticated));
        // Authenticator stripped.
        let mut r = vec![0u8; HEADER_LEN];
        r[0] = 0x24;
        r[1] = 1;
        r[24..32].copy_from_slice(&XMT);
        push_ef(&mut r, EF_UNIQUE_ID, &UID);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::NotAuthenticated));
    }

    #[test]
    fn unauthenticated_uid_after_authenticator_is_ignored() {
        let t = 1_789_700_000_000;
        // Reply for another uid, with ours appended after the tag.
        let mut r = server_reply(&[8; 32], &XMT, t, &S2C);
        push_ef(&mut r, EF_UNIQUE_ID, &UID);
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::UniqueIdMismatch));
    }

    #[test]
    fn kiss_and_unsynchronised() {
        let mut r = server_reply(&UID, &XMT, 1, &S2C);
        r[1] = 0;
        r[12..16].copy_from_slice(b"NTSN");
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::Kiss(*b"NTSN")));
        let mut r = server_reply(&UID, &XMT, 1, &S2C);
        r[0] |= 0xC0;
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::Unsynchronised));
        let mut r = server_reply(&UID, &XMT, 1, &S2C);
        r[0] = (4 << 3) | 3;
        assert_eq!(parse_response(&r, &S2C, &UID, &XMT), Err(NtpError::NotServerReply));
    }

    #[test]
    fn timestamp_conversion() {
        for ms in [0i64, 1_789_689_600_000, 1_789_689_600_999, 2_085_978_496_000, 4_000_000_000_500] {
            assert_eq!(ntp_to_unix_ms(&unix_ms_to_ntp(ms)), ms, "{ms}");
        }
        // 2036-02-07T06:28:16Z is NTP era 1, second 0.
        assert_eq!(ntp_to_unix_ms(&[0, 0, 0, 0, 0, 0, 0, 0]), 2_085_978_496_000);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
