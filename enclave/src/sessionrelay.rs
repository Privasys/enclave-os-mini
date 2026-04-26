// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Browser→enclave session relay.
//!
//! Implements the wire format documented in
//! `.operations/plans/session-relay-plan.md`:
//!
//! * P-256 ECDH + HKDF-SHA256 (salt=session_id, info="privasys-session/v1", L=32)
//!   to derive a 32-byte AES-GCM key per session.
//! * AES-256-GCM with 12-byte nonces composed of a 4-byte direction prefix
//!   (HKDF info "privasys-dir/c2s" or "privasys-dir/s2c") + an 8-byte
//!   big-endian counter.
//! * AD = `method || ":" || path || ":" || session_id` (UTF-8).
//! * Body envelope = canonical CBOR `{v:1, ctr:u64, ct:bytes}` (3-key map).
//! * Outer headers: `Content-Type: application/privasys-sealed+cbor` and
//!   `Authorization: PrivasysSession <session_id>`.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::hmac;
use ring::rand::SystemRandom;

extern crate alloc;

/// Outer Content-Type marker for sealed CBOR payloads.
pub const SEALED_CONTENT_TYPE: &str = "application/privasys-sealed+cbor";

/// HKDF info string for the per-session AEAD key.
const KEY_INFO: &[u8] = b"privasys-session/v1";
/// HKDF info strings for direction-specific 4-byte nonce prefixes.
const C2S_INFO: &[u8] = b"privasys-dir/c2s";
const S2C_INFO: &[u8] = b"privasys-dir/s2c";

/// Session lifetime in seconds (1 hour).
const SESSION_TTL_SECS: u64 = 3_600;

#[derive(Debug)]
pub enum SessionError {
    InvalidPubKey,
    Crypto,
    UnknownSession,
    Replay,
    BadEnvelope,
    Internal,
}

impl SessionError {
    pub fn http_status(&self) -> u16 {
        match self {
            SessionError::UnknownSession => 401,
            SessionError::Replay
            | SessionError::BadEnvelope
            | SessionError::InvalidPubKey => 400,
            SessionError::Crypto | SessionError::Internal => 500,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionError::InvalidPubKey => "invalid sdk_pub",
            SessionError::Crypto => "crypto failure",
            SessionError::UnknownSession => "unknown session",
            SessionError::Replay => "counter replay",
            SessionError::BadEnvelope => "bad sealed envelope",
            SessionError::Internal => "internal error",
        }
    }
}

#[derive(Debug)]
struct SessionEntry {
    aead_key: [u8; 32],
    c2s_prefix: [u8; 4],
    s2c_prefix: [u8; 4],
    /// Highest c2s counter we have seen (monotonic replay defence).
    c2s_last_seen: i64,
    /// Next s2c counter to use.
    s2c_next: u64,
    expires_at: u64,
}

static SESSIONS: Mutex<Option<BTreeMap<String, SessionEntry>>> = Mutex::new(None);
static LAST_SWEEP: AtomicU64 = AtomicU64::new(0);

fn with_table<R>(f: impl FnOnce(&mut BTreeMap<String, SessionEntry>) -> R) -> R {
    let mut guard = SESSIONS.lock().expect("sessions mutex poisoned");
    if guard.is_none() {
        *guard = Some(BTreeMap::new());
    }
    f(guard.as_mut().unwrap())
}

fn sweep_expired(now: u64) {
    let last = LAST_SWEEP.load(Ordering::Relaxed);
    if now < last + 60 {
        return;
    }
    LAST_SWEEP.store(now, Ordering::Relaxed);
    with_table(|t| t.retain(|_, e| e.expires_at > now));
}

// ── HKDF-SHA256 (extract + expand) ───────────────────────────────────

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    // Single-block expansion is enough for our 32-byte keys / 4-byte prefixes.
    assert!(len <= 32, "hkdf_expand: only single-block (≤32B) supported");
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(info);
    ctx.update(&[0x01u8]);
    let tag = ctx.sign();
    tag.as_ref()[..len].to_vec()
}

// ── Bootstrap ───────────────────────────────────────────────────────

/// Result of a successful bootstrap call: fresh session + serialised pubkey
/// to return to the SDK.
pub struct Bootstrap {
    pub session_id: String,
    /// Server P-256 SEC1 uncompressed pubkey (65 bytes).
    pub enc_pub: Vec<u8>,
    pub expires_at: u64,
}

/// Generate a fresh server P-256 keypair, derive the session key from
/// `sdk_pub` (SEC1 uncompressed, 65 bytes), and store it in the table.
pub fn bootstrap(sdk_pub: &[u8], now: u64) -> Result<Bootstrap, SessionError> {
    if sdk_pub.len() != 65 || sdk_pub[0] != 0x04 {
        return Err(SessionError::InvalidPubKey);
    }

    let rng = SystemRandom::new();
    let priv_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
        .map_err(|_| SessionError::Crypto)?;
    let pub_key = priv_key.compute_public_key().map_err(|_| SessionError::Crypto)?;
    let server_pub = pub_key.as_ref().to_vec();
    if server_pub.len() != 65 {
        return Err(SessionError::Crypto);
    }

    let peer = UnparsedPublicKey::new(&ECDH_P256, sdk_pub);
    let shared = agree_ephemeral(priv_key, &peer, |secret| secret.to_vec())
        .map_err(|_| SessionError::InvalidPubKey)?;

    // Generate 16 random bytes → 32-char hex session id.
    let mut sid_bytes = [0u8; 16];
    use ring::rand::SecureRandom;
    rng.fill(&mut sid_bytes).map_err(|_| SessionError::Crypto)?;
    let session_id = hex_lower(&sid_bytes);

    // HKDF: salt = session_id (UTF-8 bytes), ikm = shared_secret.
    let prk = hkdf_extract(session_id.as_bytes(), &shared);
    let key_bytes = hkdf_expand(&prk, KEY_INFO, 32);
    let mut aead_key = [0u8; 32];
    aead_key.copy_from_slice(&key_bytes);

    let c2s = hkdf_expand(&prk, C2S_INFO, 4);
    let s2c = hkdf_expand(&prk, S2C_INFO, 4);
    let mut c2s_prefix = [0u8; 4];
    let mut s2c_prefix = [0u8; 4];
    c2s_prefix.copy_from_slice(&c2s);
    s2c_prefix.copy_from_slice(&s2c);

    let expires_at = now.saturating_add(SESSION_TTL_SECS);

    sweep_expired(now);
    with_table(|t| {
        t.insert(
            session_id.clone(),
            SessionEntry {
                aead_key,
                c2s_prefix,
                s2c_prefix,
                c2s_last_seen: -1,
                s2c_next: 0,
                expires_at,
            },
        );
    });

    Ok(Bootstrap {
        session_id,
        enc_pub: server_pub,
        expires_at,
    })
}

// ── Sealed envelope decode/encode ───────────────────────────────────

/// Decode a sealed CBOR envelope (`{v:1, ctr:u64, ct:bytes}`).
fn cbor_decode_envelope(buf: &[u8]) -> Result<(u64, Vec<u8>), SessionError> {
    // Canonical encoding: 0xA3 (map of 3) + ("v", 1) + ("ctr", u64) + ("ct", bstr).
    let mut p = 0usize;
    if buf.len() < 1 || buf[p] != 0xA3 {
        return Err(SessionError::BadEnvelope);
    }
    p += 1;

    let mut version: Option<u64> = None;
    let mut ctr: Option<u64> = None;
    let mut ct: Option<Vec<u8>> = None;

    for _ in 0..3 {
        // Each key is a 1-or-3-char text string.
        let key = cbor_take_text(buf, &mut p)?;
        match key.as_str() {
            "v" => version = Some(cbor_take_uint(buf, &mut p)?),
            "ctr" => ctr = Some(cbor_take_uint(buf, &mut p)?),
            "ct" => ct = Some(cbor_take_bytes(buf, &mut p)?),
            _ => return Err(SessionError::BadEnvelope),
        }
    }

    if version != Some(1) {
        return Err(SessionError::BadEnvelope);
    }
    Ok((
        ctr.ok_or(SessionError::BadEnvelope)?,
        ct.ok_or(SessionError::BadEnvelope)?,
    ))
}

fn cbor_take_text(buf: &[u8], p: &mut usize) -> Result<String, SessionError> {
    if *p >= buf.len() {
        return Err(SessionError::BadEnvelope);
    }
    let head = buf[*p];
    if head & 0xE0 != 0x60 {
        return Err(SessionError::BadEnvelope);
    }
    let len = (head & 0x1F) as usize;
    if len > 23 {
        return Err(SessionError::BadEnvelope); // we only emit ≤3-byte keys
    }
    *p += 1;
    if *p + len > buf.len() {
        return Err(SessionError::BadEnvelope);
    }
    let s = core::str::from_utf8(&buf[*p..*p + len])
        .map_err(|_| SessionError::BadEnvelope)?
        .to_string();
    *p += len;
    Ok(s)
}

fn cbor_take_uint(buf: &[u8], p: &mut usize) -> Result<u64, SessionError> {
    if *p >= buf.len() {
        return Err(SessionError::BadEnvelope);
    }
    let head = buf[*p];
    if head & 0xE0 != 0x00 {
        return Err(SessionError::BadEnvelope);
    }
    let info = head & 0x1F;
    *p += 1;
    let v = match info {
        n @ 0..=23 => n as u64,
        24 => {
            if *p >= buf.len() {
                return Err(SessionError::BadEnvelope);
            }
            let v = buf[*p] as u64;
            *p += 1;
            v
        }
        25 => {
            if *p + 2 > buf.len() {
                return Err(SessionError::BadEnvelope);
            }
            let v = u16::from_be_bytes([buf[*p], buf[*p + 1]]) as u64;
            *p += 2;
            v
        }
        26 => {
            if *p + 4 > buf.len() {
                return Err(SessionError::BadEnvelope);
            }
            let v = u32::from_be_bytes([
                buf[*p], buf[*p + 1], buf[*p + 2], buf[*p + 3],
            ]) as u64;
            *p += 4;
            v
        }
        27 => {
            if *p + 8 > buf.len() {
                return Err(SessionError::BadEnvelope);
            }
            let v = u64::from_be_bytes([
                buf[*p], buf[*p + 1], buf[*p + 2], buf[*p + 3],
                buf[*p + 4], buf[*p + 5], buf[*p + 6], buf[*p + 7],
            ]);
            *p += 8;
            v
        }
        _ => return Err(SessionError::BadEnvelope),
    };
    Ok(v)
}

fn cbor_take_bytes(buf: &[u8], p: &mut usize) -> Result<Vec<u8>, SessionError> {
    if *p >= buf.len() {
        return Err(SessionError::BadEnvelope);
    }
    let head = buf[*p];
    if head & 0xE0 != 0x40 {
        return Err(SessionError::BadEnvelope);
    }
    let info = head & 0x1F;
    *p += 1;
    let len = match info {
        n @ 0..=23 => n as usize,
        24 => {
            if *p >= buf.len() { return Err(SessionError::BadEnvelope); }
            let n = buf[*p] as usize; *p += 1; n
        }
        25 => {
            if *p + 2 > buf.len() { return Err(SessionError::BadEnvelope); }
            let n = u16::from_be_bytes([buf[*p], buf[*p+1]]) as usize;
            *p += 2; n
        }
        26 => {
            if *p + 4 > buf.len() { return Err(SessionError::BadEnvelope); }
            let n = u32::from_be_bytes([buf[*p], buf[*p+1], buf[*p+2], buf[*p+3]]) as usize;
            *p += 4; n
        }
        27 => {
            if *p + 8 > buf.len() { return Err(SessionError::BadEnvelope); }
            let n = u64::from_be_bytes([
                buf[*p], buf[*p+1], buf[*p+2], buf[*p+3],
                buf[*p+4], buf[*p+5], buf[*p+6], buf[*p+7],
            ]) as usize;
            *p += 8; n
        }
        _ => return Err(SessionError::BadEnvelope),
    };
    if *p + len > buf.len() {
        return Err(SessionError::BadEnvelope);
    }
    let v = buf[*p..*p + len].to_vec();
    *p += len;
    Ok(v)
}

/// Encode `{v:1, ctr, ct}` in canonical CBOR (matches the SDK encoder).
fn cbor_encode_envelope(ctr: u64, ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct.len() + 32);
    out.push(0xA3); // map of 3
    out.extend_from_slice(&[0x61, b'v']); // text "v"
    out.push(0x01); // unsigned 1
    out.extend_from_slice(&[0x63, b'c', b't', b'r']); // text "ctr"
    cbor_write_uint(&mut out, ctr);
    out.extend_from_slice(&[0x62, b'c', b't']); // text "ct"
    cbor_write_bytes(&mut out, ct);
    out
}

fn cbor_write_uint(out: &mut Vec<u8>, v: u64) {
    if v <= 23 {
        out.push(v as u8);
    } else if v <= 0xFF {
        out.push(0x18);
        out.push(v as u8);
    } else if v <= 0xFFFF {
        out.push(0x19);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        out.push(0x1A);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0x1B);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn cbor_write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = b.len() as u64;
    if len <= 23 {
        out.push(0x40 | (len as u8));
    } else if len <= 0xFF {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFF_FFFF {
        out.push(0x5A);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(0x5B);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(b);
}

// ── Open / seal ─────────────────────────────────────────────────────

/// Decrypt a sealed request body. Returns the plaintext.
///
/// `method` and `path` are taken from the OUTER (cleartext) HTTP request.
pub fn open_request(
    session_id: &str,
    method: &str,
    path: &str,
    sealed_body: &[u8],
    now: u64,
) -> Result<Vec<u8>, SessionError> {
    sweep_expired(now);
    let (ctr, ct) = cbor_decode_envelope(sealed_body)?;

    with_table(|t| {
        let entry = t.get_mut(session_id).ok_or(SessionError::UnknownSession)?;
        if entry.expires_at <= now {
            t.remove(session_id);
            return Err(SessionError::UnknownSession);
        }
        if (ctr as i64) <= entry.c2s_last_seen {
            return Err(SessionError::Replay);
        }

        let unbound = UnboundKey::new(&AES_256_GCM, &entry.aead_key)
            .map_err(|_| SessionError::Crypto)?;
        let key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&entry.c2s_prefix);
        nonce_bytes[4..].copy_from_slice(&ctr.to_be_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let ad = format!("{}:{}:{}", method, path, session_id);
        let mut buf = ct;
        let pt = key
            .open_in_place(nonce, Aad::from(ad.as_bytes()), &mut buf)
            .map_err(|_| SessionError::Crypto)?;
        let pt_vec = pt.to_vec();
        entry.c2s_last_seen = ctr as i64;
        Ok(pt_vec)
    })
}

/// Seal a response body for `session_id`.
///
/// AD = `method:path:session_id` from the OUTER cleartext request that
/// triggered the response.
pub fn seal_response(
    session_id: &str,
    method: &str,
    path: &str,
    plaintext: &[u8],
    now: u64,
) -> Result<Vec<u8>, SessionError> {
    with_table(|t| {
        let entry = t.get_mut(session_id).ok_or(SessionError::UnknownSession)?;
        if entry.expires_at <= now {
            t.remove(session_id);
            return Err(SessionError::UnknownSession);
        }
        let ctr = entry.s2c_next;
        entry.s2c_next = entry.s2c_next.checked_add(1).ok_or(SessionError::Internal)?;

        let unbound = UnboundKey::new(&AES_256_GCM, &entry.aead_key)
            .map_err(|_| SessionError::Crypto)?;
        let key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&entry.s2c_prefix);
        nonce_bytes[4..].copy_from_slice(&ctr.to_be_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let ad = format!("{}:{}:{}", method, path, session_id);
        let mut buf = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(ad.as_bytes()), &mut buf)
            .map_err(|_| SessionError::Crypto)?;
        Ok(cbor_encode_envelope(ctr, &buf))
    })
}

// ── Helpers ─────────────────────────────────────────────────────────

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Decode standard-or-URL-safe base64 (with or without padding).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let mut buf: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' => buf.push((c as u8) - b'A'),
            'a'..='z' => buf.push((c as u8) - b'a' + 26),
            '0'..='9' => buf.push((c as u8) - b'0' + 52),
            '+' | '-' => buf.push(62),
            '/' | '_' => buf.push(63),
            '=' | '\r' | '\n' | ' ' | '\t' => {}
            _ => return None,
        }
    }
    let mut out = Vec::with_capacity(buf.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= buf.len() {
        out.push((buf[i] << 2) | (buf[i + 1] >> 4));
        out.push(((buf[i + 1] & 0x0F) << 4) | (buf[i + 2] >> 2));
        out.push(((buf[i + 2] & 0x03) << 6) | buf[i + 3]);
        i += 4;
    }
    let rem = buf.len() - i;
    if rem == 2 {
        out.push((buf[i] << 2) | (buf[i + 1] >> 4));
    } else if rem == 3 {
        out.push((buf[i] << 2) | (buf[i + 1] >> 4));
        out.push(((buf[i + 1] & 0x0F) << 4) | (buf[i + 2] >> 2));
    } else if rem != 0 {
        return None;
    }
    Some(out)
}

/// Encode bytes as URL-safe base64 without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let chunks = bytes.chunks_exact(3);
    let rem = chunks.remainder();
    for c in chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHA[(n & 0x3F) as usize] as char);
    }
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

/// True if a session id is currently registered and not expired.
pub fn is_known_session(session_id: &str, now: u64) -> bool {
    with_table(|t| {
        match t.get(session_id) {
            Some(e) if e.expires_at > now => true,
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_roundtrip() {
        let env = cbor_encode_envelope(7, b"hello");
        let (ctr, ct) = cbor_decode_envelope(&env).unwrap();
        assert_eq!(ctr, 7);
        assert_eq!(ct, b"hello");
    }

    #[test]
    fn cbor_long_counter() {
        let env = cbor_encode_envelope(u64::MAX, &[0u8; 1024]);
        let (ctr, ct) = cbor_decode_envelope(&env).unwrap();
        assert_eq!(ctr, u64::MAX);
        assert_eq!(ct.len(), 1024);
    }

    #[test]
    fn b64_roundtrip() {
        let raw: Vec<u8> = (0u8..200).collect();
        let enc = b64url_encode(&raw);
        let dec = b64_decode(&enc).unwrap();
        assert_eq!(dec, raw);
    }
}
