// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! EncAuth silent-rebind voucher verification (crypto-contract §8).
//!
//! Mirrors `enclave-os-virtual/internal/sessionrelay/encauth.go` byte for
//! byte on the wire. Crypto is `sgx_crypto` (the Teaclave wrapper over
//! `sgx_tcrypto` / Intel IPP): `sgx_ecdsa_verify` for the two ES256
//! signatures and the same ECC context family the static identity key
//! uses for repeated ECDH in [`crate::sessionrelay`].
//!
//! ## Byte order
//!
//! The SGX `sgx_ec256_*` structs are **little-endian** (per coordinate /
//! per 256-bit integer), while every wire encoding in the contract —
//! SEC1 uncompressed points, fixed-width R||S signatures, the ECDH
//! shared X coordinate fed to HKDF — is **big-endian**. All conversions
//! live in this module ([`sec1_to_ec256_pubkey`], [`ec256_pubkey_to_sec1`],
//! [`raw_sig_to_ec256`]) and in `sessionrelay::bootstrap` (shared-secret
//! reversal). Getting any of these wrong fails closed (signature or AEAD
//! mismatch), never open.
//!
//! ## Trust anchors
//!
//! `idp_sig` verifies against the IdP JWKS fetched over egress HTTPS
//! with the WebPKI (Mozilla) root store, against the issuer pinned in
//! the **measured** OIDC config — the same trust path the existing JWT
//! verification uses. Without the `wasm`/egress feature there is no
//! trusted key source and vouchers are rejected outright (there is
//! deliberately no unverified fallback: a voucher mints an
//! authenticated session, unlike a JWT which only gates role checks).

use alloc::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::Mutex;
use std::vec::Vec;

use sgx_crypto::ecc::{EcPublicKey, EcSignature};
use sgx_types::types::{Ec256PublicKey, Ec256Signature};

extern crate alloc;

/// Diagnostic header set when a voucher is refused (the SDK treats it
/// as "fall back to a wallet ceremony").
pub const ENCAUTH_REJECT_HEADER: &str = "X-Privasys-EncAuth-Reject";

/// Max voucher-backed bootstrap attempts (accepted or rejected) per sid
/// per window. Matches the Go runtime.
const REBIND_RATE_LIMIT: u32 = 6;
const REBIND_RATE_WINDOW_SECS: u64 = 60;
/// Sweep threshold for the rate-limit map (forged-sid growth bound).
const REBIND_MAP_SWEEP_LEN: usize = 10_000;

/// Allowed clock skew for the voucher time window (matches Go: 30 s).
const TIME_SKEW_SECS: u64 = 30;

/// On-wire JSON envelope (matches `sessions.Envelope` at the IdP).
#[derive(serde::Deserialize)]
pub struct EncAuthEnvelope {
    pub v: u8,
    /// base64url(canonical CBOR payload)
    pub payload: String,
    /// base64url(64 B R||S)
    pub hw_sig: String,
    /// base64url(64 B R||S)
    #[serde(default)]
    pub idp_sig: String,
}

/// Decoded canonical-CBOR payload (crypto-contract §8.1, integer keys
/// 1..10 ascending).
pub struct EncAuthPayload {
    pub v: u64,
    pub sub: String,
    pub sid: String,
    /// CBOR key 4, named `app_id` in the wire format (crypto-contract
    /// §8.1). NOT the static OID 3.6 app-id; it is the SHA-256 of the
    /// workload OIDs (3.1/3.2/3.3/3.4), so it moves with the OID 3.2 code
    /// hash. Integer key 4 is unchanged by this rename.
    pub workload_digest: Vec<u8>,
    pub enc_meas: Vec<u8>,
    pub enc_pub: Vec<u8>,
    pub quote_hash: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub hw_pub: Vec<u8>,
}

/// Verify an EncAuth envelope. `idp_keys` are the IdP's current P-256
/// signing keys in SEC1 uncompressed form (from the JWKS — any may have
/// produced `idp_sig`, mirroring the Go verifier's empty-kid lookup).
/// `enc_static_pub_sec1` is this enclave's identity key;
/// `expected_quote_digest`, when armed, is the wallet attestation
/// digest (crypto-contract §4.1 — never a certificate hash).
///
/// Verification order matches Go: idp_sig → hw_sig → enc_pub →
/// quote_hash → time window → non-empty sid. Nothing payload-derived is
/// trusted before `idp_sig` passes.
pub fn verify_encauth(
    env: &EncAuthEnvelope,
    idp_keys: &[Vec<u8>],
    enc_static_pub_sec1: &[u8],
    expected_quote_digest: Option<&[u8; 32]>,
    now: u64,
) -> Result<EncAuthPayload, &'static str> {
    if env.v != 1 {
        return Err("unsupported version");
    }
    let payload_bytes =
        crate::sessionrelay::b64_decode(&env.payload).ok_or("payload b64")?;
    let hw_sig_raw = crate::sessionrelay::b64_decode(&env.hw_sig).ok_or("hw_sig b64")?;
    let idp_sig_raw = crate::sessionrelay::b64_decode(&env.idp_sig).ok_or("idp_sig b64")?;

    // idp_sig over (payload || hw_sig), against any current IdP key.
    // MUST pass before any payload field is trusted.
    if idp_keys.is_empty() {
        return Err("no idp signing keys");
    }
    let idp_sig = raw_sig_to_ec256(&idp_sig_raw).ok_or("idp_sig format")?;
    let mut idp_input = Vec::with_capacity(payload_bytes.len() + hw_sig_raw.len());
    idp_input.extend_from_slice(&payload_bytes);
    idp_input.extend_from_slice(&hw_sig_raw);
    let mut idp_ok = false;
    for key in idp_keys {
        if let Some(pubkey) = sec1_to_ec256_pubkey(key) {
            if ecdsa_verify(&pubkey, &idp_input, &idp_sig) {
                idp_ok = true;
                break;
            }
        }
    }
    if !idp_ok {
        return Err("idp_sig verify failed");
    }

    let payload = decode_encauth_payload(&payload_bytes).ok_or("payload cbor")?;
    if payload.v != 1 {
        return Err("unsupported payload version");
    }

    // hw_sig over the raw payload CBOR, against the hardware key the
    // payload carries (the IdP attested it belongs to `sub` when it
    // co-signed).
    let hw_pub = sec1_to_ec256_pubkey(&payload.hw_pub).ok_or("hw_pub format")?;
    let hw_sig = raw_sig_to_ec256(&hw_sig_raw).ok_or("hw_sig format")?;
    if !ecdsa_verify(&hw_pub, &payload_bytes, &hw_sig) {
        return Err("hw_sig verify failed");
    }

    // enc_pub must match this enclave's identity key byte for byte —
    // the enclave-restart / enclave-changed signal.
    if payload.enc_pub != enc_static_pub_sec1 {
        return Err("enc_pub does not match this enclave");
    }

    // Optional attestation-digest binding (crypto-contract §4.1).
    if let Some(expected) = expected_quote_digest {
        if payload.quote_hash.as_slice() != expected.as_slice() {
            return Err("quote_hash does not match expected attestation digest");
        }
    }

    // Time window with skew.
    if now + TIME_SKEW_SECS < payload.not_before {
        return Err("not yet valid");
    }
    if now >= payload.not_after {
        return Err("expired");
    }
    if payload.sid.is_empty() {
        return Err("empty sid");
    }
    Ok(payload)
}

// ── Rate limiting ────────────────────────────────────────────────────

struct RebindWindow {
    start: u64,
    count: u32,
}

static REBINDS: Mutex<Option<BTreeMap<String, RebindWindow>>> = Mutex::new(None);

/// Record one voucher-backed bootstrap attempt for `sid` and report
/// whether it is within budget. The sid comes from a cheap unverified
/// decode — fine for bucketing (a forged sid only rate-limits the
/// forger's own bucket; signatures still gate acceptance).
pub fn allow_rebind(sid: &str, now: u64) -> bool {
    let mut guard = REBINDS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(BTreeMap::new);
    if map.len() > REBIND_MAP_SWEEP_LEN {
        map.retain(|_, w| now.saturating_sub(w.start) <= REBIND_RATE_WINDOW_SECS);
    }
    match map.get_mut(sid) {
        Some(w) if now.saturating_sub(w.start) <= REBIND_RATE_WINDOW_SECS => {
            w.count += 1;
            w.count <= REBIND_RATE_LIMIT
        }
        _ => {
            map.insert(sid.to_string(), RebindWindow { start: now, count: 1 });
            true
        }
    }
}

/// Extract the sid with a cheap decode and NO signature verification.
/// Only safe for non-authoritative uses such as rate-limit bucketing.
pub fn encauth_sid(env: &EncAuthEnvelope) -> Option<String> {
    let payload_bytes = crate::sessionrelay::b64_decode(&env.payload)?;
    decode_encauth_payload(&payload_bytes).map(|p| p.sid)
}

// ── Canonical-CBOR payload decoder ──────────────────────────────────
//
// The payload is a definite-length map with integer keys 1..10 in
// ascending order (RFC 8949 §4.2.1). We decode strictly: exactly 10
// entries, keys in canonical order, value major types as specified.

fn decode_encauth_payload(buf: &[u8]) -> Option<EncAuthPayload> {
    let mut p = 0usize;
    // map(10): canonical header is 0xAA.
    if buf.first() != Some(&0xAA) {
        return None;
    }
    p += 1;

    let mut out = EncAuthPayload {
        v: 0,
        sub: String::new(),
        sid: String::new(),
        workload_digest: Vec::new(),
        enc_meas: Vec::new(),
        enc_pub: Vec::new(),
        quote_hash: Vec::new(),
        not_before: 0,
        not_after: 0,
        hw_pub: Vec::new(),
    };

    for expected_key in 1u64..=10 {
        let key = take_uint(buf, &mut p)?;
        if key != expected_key {
            return None; // non-canonical key order / unknown key
        }
        match key {
            1 => out.v = take_uint(buf, &mut p)?,
            2 => out.sub = take_tstr(buf, &mut p)?,
            3 => out.sid = take_tstr(buf, &mut p)?,
            4 => out.workload_digest = take_bstr(buf, &mut p)?,
            5 => out.enc_meas = take_bstr(buf, &mut p)?,
            6 => out.enc_pub = take_bstr(buf, &mut p)?,
            7 => out.quote_hash = take_bstr(buf, &mut p)?,
            8 => out.not_before = take_uint(buf, &mut p)?,
            9 => out.not_after = take_uint(buf, &mut p)?,
            10 => out.hw_pub = take_bstr(buf, &mut p)?,
            _ => unreachable!(),
        }
    }
    if p != buf.len() {
        return None; // trailing bytes — not the canonical encoding
    }
    // Structural checks (the Go IdP enforced these at PUT time; cheap
    // to re-check before any crypto).
    if out.enc_pub.len() != 65 || out.enc_pub[0] != 0x04 {
        return None;
    }
    if out.hw_pub.len() != 65 || out.hw_pub[0] != 0x04 {
        return None;
    }
    if out.workload_digest.len() != 32 || out.enc_meas.len() != 32 || out.quote_hash.len() != 32 {
        return None;
    }
    Some(out)
}

fn take_head(buf: &[u8], p: &mut usize, major: u8) -> Option<u64> {
    let head = *buf.get(*p)?;
    if head >> 5 != major {
        return None;
    }
    let info = head & 0x1F;
    *p += 1;
    let v = match info {
        n @ 0..=23 => n as u64,
        24 => {
            let v = *buf.get(*p)? as u64;
            *p += 1;
            v
        }
        25 => {
            let b = buf.get(*p..*p + 2)?;
            *p += 2;
            u16::from_be_bytes([b[0], b[1]]) as u64
        }
        26 => {
            let b = buf.get(*p..*p + 4)?;
            *p += 4;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
        }
        27 => {
            let b = buf.get(*p..*p + 8)?;
            *p += 8;
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
        _ => return None, // indefinite length — not canonical
    };
    Some(v)
}

fn take_uint(buf: &[u8], p: &mut usize) -> Option<u64> {
    take_head(buf, p, 0)
}

fn take_bstr(buf: &[u8], p: &mut usize) -> Option<Vec<u8>> {
    let len = take_head(buf, p, 2)? as usize;
    let b = buf.get(*p..*p + len)?;
    *p += len;
    Some(b.to_vec())
}

fn take_tstr(buf: &[u8], p: &mut usize) -> Option<String> {
    let len = take_head(buf, p, 3)? as usize;
    let b = buf.get(*p..*p + len)?;
    *p += len;
    core::str::from_utf8(b).ok().map(|s| s.to_string())
}

// ── SGX ↔ wire byte-order conversions ───────────────────────────────

/// SEC1 uncompressed (65 B, big-endian coordinates) → SGX little-endian
/// `Ec256PublicKey`. Returns None for malformed input; on-curve checking
/// is left to IPP (`sgx_ecdsa_verify` / `sgx_ecc256_compute_shared_dhkey`
/// reject invalid points).
pub fn sec1_to_ec256_pubkey(sec1: &[u8]) -> Option<EcPublicKey> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return None;
    }
    let mut key = Ec256PublicKey::default();
    for i in 0..32 {
        key.gx[i] = sec1[32 - i]; // bytes 1..=32 reversed
        key.gy[i] = sec1[64 - i]; // bytes 33..=64 reversed
    }
    Some(EcPublicKey::from(key))
}

/// SGX little-endian `Ec256PublicKey` → SEC1 uncompressed (65 B).
pub fn ec256_pubkey_to_sec1(key: &Ec256PublicKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    for i in 0..32 {
        out[1 + i] = key.gx[31 - i];
        out[33 + i] = key.gy[31 - i];
    }
    out
}

/// Fixed-width big-endian R||S (64 B) → SGX `Ec256Signature`
/// (little-endian 256-bit integers stored as 8 LE u32 words).
pub fn raw_sig_to_ec256(sig: &[u8]) -> Option<EcSignature> {
    if sig.len() != 64 {
        return None;
    }
    let mut out = Ec256Signature::default();
    for w in 0..8 {
        let mut r_le = [0u8; 4];
        let mut s_le = [0u8; 4];
        for b in 0..4 {
            r_le[b] = sig[31 - (w * 4 + b)];
            s_le[b] = sig[63 - (w * 4 + b)];
        }
        out.x[w] = u32::from_le_bytes(r_le);
        out.y[w] = u32::from_le_bytes(s_le);
    }
    Some(EcSignature::from(out))
}

/// ECDSA-P256-SHA256 verification via `sgx_ecdsa_verify` (IPP hashes
/// the message internally with SHA-256 — same as the Go side's
/// `ecdsa.Verify(pub, sha256(msg), r, s)`).
fn ecdsa_verify(key: &EcPublicKey, msg: &[u8], sig: &EcSignature) -> bool {
    matches!(key.verify(msg, sig), Ok(true))
}

// ---------------------------------------------------------------------------
//  Tests (byte-order helpers are pure and host-runnable; signature paths
//  need the SGX runtime and are covered by the integration suite).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec1_roundtrip() {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        for i in 0..64 {
            sec1[1 + i] = i as u8;
        }
        let key = sec1_to_ec256_pubkey(&sec1).unwrap();
        let back = ec256_pubkey_to_sec1(&key.public_key());
        assert_eq!(back, sec1);
    }

    #[test]
    fn sec1_rejects_bad_prefix() {
        let sec1 = [0u8; 65];
        assert!(sec1_to_ec256_pubkey(&sec1).is_none());
        assert!(sec1_to_ec256_pubkey(&[0x04; 64]).is_none());
    }

    #[test]
    fn raw_sig_endianness() {
        // R = 1 (big-endian) → least-significant word must be 1.
        let mut sig = [0u8; 64];
        sig[31] = 0x01; // R = 1
        sig[63] = 0x02; // S = 2
        let s = raw_sig_to_ec256(&sig).unwrap().signature();
        assert_eq!(s.x[0], 1);
        assert_eq!(s.x[1..], [0u32; 7]);
        assert_eq!(s.y[0], 2);
    }

    #[test]
    fn cbor_payload_roundtrip() {
        // Hand-encode a canonical payload matching the wallet encoder.
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xAA); // map(10)
        let bstr32 = |buf: &mut Vec<u8>, fill: u8| {
            buf.push(0x58);
            buf.push(32);
            buf.extend_from_slice(&[fill; 32]);
        };
        let bstr65 = |buf: &mut Vec<u8>, fill: u8| {
            let mut v = [fill; 65];
            v[0] = 0x04;
            buf.push(0x58);
            buf.push(65);
            buf.extend_from_slice(&v);
        };
        buf.push(0x01); buf.push(0x01); // 1: v = 1
        buf.push(0x02); buf.extend_from_slice(&[0x63, b's', b'u', b'b']); // 2: "sub"
        buf.push(0x03); buf.extend_from_slice(&[0x63, b's', b'i', b'd']); // 3: "sid"
        buf.push(0x04); bstr32(&mut buf, 0xA1); // 4: workload_digest
        buf.push(0x05); bstr32(&mut buf, 0xA2); // 5: enc_meas
        buf.push(0x06); bstr65(&mut buf, 0xA3); // 6: enc_pub
        buf.push(0x07); bstr32(&mut buf, 0xA4); // 7: quote_hash
        buf.push(0x08); buf.extend_from_slice(&[0x1A, 0x65, 0x00, 0x00, 0x00]); // 8: not_before
        buf.push(0x09); buf.extend_from_slice(&[0x1A, 0x66, 0x00, 0x00, 0x00]); // 9: not_after
        buf.push(0x0A); bstr65(&mut buf, 0xA5); // 10: hw_pub

        let p = decode_encauth_payload(&buf).unwrap();
        assert_eq!(p.v, 1);
        assert_eq!(p.sub, "sub");
        assert_eq!(p.sid, "sid");
        assert_eq!(p.workload_digest, [0xA1; 32]);
        assert_eq!(p.not_before, 0x65000000);
        assert_eq!(p.not_after, 0x66000000);
        assert_eq!(p.enc_pub[0], 0x04);

        // Trailing garbage must be rejected.
        buf.push(0x00);
        assert!(decode_encauth_payload(&buf).is_none());
    }

    #[test]
    fn rate_limit_window() {
        assert!(allow_rebind("sid-rate-test", 1000));
        for _ in 0..5 {
            assert!(allow_rebind("sid-rate-test", 1001));
        }
        assert!(!allow_rebind("sid-rate-test", 1002)); // 7th in window
        assert!(allow_rebind("sid-rate-test", 1100)); // new window
    }

    // ── Cross-implementation EncAuth fixture (crypto-contract §9) ───
    //
    // Generated once by the Go reference
    // (enclave-os-virtual/internal/sessionrelay/kats_test.go,
    // TestEncAuthFixtureKAT — deterministic scalars, randomized ECDSA
    // nonces) and pinned. Accepting this envelope proves the Rust port
    // (sgx_ecdsa_verify + little-endian conversions) matches the Go
    // verifier byte for byte.

    const KAT_IDP_PUB_HEX: &str = "04a818bd9ebbbff1f75be3767981d0b80eac8f2398f0acb54acb621cf12d0f79951cc373bdcdabdff1abc828c47e2b3470f28cbcc24d37adb8913b7d8163560be2";
    const KAT_ENC_PUB_HEX: &str = "04dd511dcde3875568de732fde5634d8940b5bcfef668ace46f28bd813a27eb6af695e2fe52acb03f4d158a46335e0a726765540290c28614379953e1ab483d924";
    const KAT_PAYLOAD_B64: &str = "qgEBAmhrYXQtdXNlcgNna2F0LXNpZARYIKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhBVgg4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eEGWEEE3VEdzeOHVWjecy_eVjTYlAtbz-9mis5G8ovYE6J-tq9pXi_lKssD9NFYpGM14KcmdlVAKQwoYUN5lT4atIPZJAdYILKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyCBplU_EACRruaygAClhBBNuRe6MwWPKHvZyN8JI81MB3O5VpsUXLHk-N7_RXzfIh7WwH4HEkELLho3WJL94p40gFjUm5pANfE1C58syQdDY";
    const KAT_HW_SIG_B64: &str = "KycpT_wNX3KiOcf1BM2c6pwEumKHRRHPw0g3GijHA4ixyE11NLXOWnH9-BKG4emlHi9sx_joU_vkRcy_qKp-rA";
    const KAT_IDP_SIG_B64: &str = "YnNICq8sOff-c8cTKWtaywuhAT4cdE24nOGOJR6CdeRI8RpkD6RxBLTbMMlUBQ4kbX_fcBlIHvUbTJqqGunpYA";
    const KAT_NOW: u64 = 1_700_000_100;

    fn kat_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn kat_envelope() -> EncAuthEnvelope {
        EncAuthEnvelope {
            v: 1,
            payload: KAT_PAYLOAD_B64.to_string(),
            hw_sig: KAT_HW_SIG_B64.to_string(),
            idp_sig: KAT_IDP_SIG_B64.to_string(),
        }
    }

    /// Host-safe half: the pinned payload decodes and carries the
    /// expected fields (no IPP needed).
    #[test]
    fn encauth_fixture_payload_decodes() {
        let payload_bytes =
            crate::sessionrelay::b64_decode(KAT_PAYLOAD_B64).unwrap();
        let p = decode_encauth_payload(&payload_bytes).unwrap();
        assert_eq!(p.v, 1);
        assert_eq!(p.sub, "kat-user");
        assert_eq!(p.sid, "kat-sid");
        assert_eq!(p.workload_digest, [0xA1; 32]);
        assert_eq!(p.enc_meas, [0xE1; 32]);
        assert_eq!(p.quote_hash, [0xB2; 32]);
        assert_eq!(p.enc_pub, kat_hex(KAT_ENC_PUB_HEX));
        assert_eq!(p.not_before, 1_700_000_000);
        assert_eq!(p.not_after, 4_000_000_000);
    }

    /// Full verification against the Go-pinned fixture. Exercises
    /// sgx_ecdsa_verify (IPP), so it runs only under the SGX test
    /// harness — exactly the byte-compat proof the contract requires.
    #[test]
    fn encauth_fixture_verifies() {
        let idp_keys = vec![kat_hex(KAT_IDP_PUB_HEX)];
        let enc_pub = kat_hex(KAT_ENC_PUB_HEX);

        let p = verify_encauth(&kat_envelope(), &idp_keys, &enc_pub, None, KAT_NOW)
            .expect("pinned fixture rejected");
        assert_eq!(p.sub, "kat-user");
        assert_eq!(p.sid, "kat-sid");

        // Tampered payload → hw_sig (or idp_sig) must fail.
        let mut payload_bytes =
            crate::sessionrelay::b64_decode(KAT_PAYLOAD_B64).unwrap();
        let last = payload_bytes.len() - 1;
        payload_bytes[last] ^= 0x01;
        let mut bad = kat_envelope();
        bad.payload = crate::sessionrelay::b64url_encode(&payload_bytes);
        assert!(verify_encauth(&bad, &idp_keys, &enc_pub, None, KAT_NOW).is_err());

        // Wrong enclave identity → rejected.
        let mut other = kat_hex(KAT_ENC_PUB_HEX);
        other[10] ^= 0x01;
        assert!(verify_encauth(&kat_envelope(), &idp_keys, &other, None, KAT_NOW).is_err());

        // Outside the window → rejected.
        assert!(verify_encauth(&kat_envelope(), &idp_keys, &enc_pub, None, 4_000_000_001).is_err());
    }
}
