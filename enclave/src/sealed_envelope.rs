// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The sealed body envelope: canonical CBOR `{v:1, ctr:u64, ct:bytes}`.
//!
//! Pure (no SGX), so `tests/relay-limits-unit` runs it on the host. The
//! decoder reads untrusted bytes before any session is looked up: every
//! length is checked against the buffer with no arithmetic that can wrap.

/// Decode a sealed envelope into `(ctr, ct)`. `None` for anything that is
/// not a well-formed version-1 envelope.
pub fn decode(buf: &[u8]) -> Option<(u64, Vec<u8>)> {
    let mut p = 0usize;
    if take(buf, &mut p, 1)? != [0xA3] {
        return None;
    }

    let mut version: Option<u64> = None;
    let mut ctr: Option<u64> = None;
    let mut ct: Option<Vec<u8>> = None;

    for _ in 0..3 {
        match take_key(buf, &mut p)? {
            b"v" => version = Some(take_head(buf, &mut p, 0)?),
            b"ctr" => ctr = Some(take_head(buf, &mut p, 0)?),
            b"ct" => {
                let len = usize::try_from(take_head(buf, &mut p, 2)?).ok()?;
                ct = Some(take(buf, &mut p, len)?.to_vec());
            }
            _ => return None,
        }
    }

    if version != Some(1) {
        return None;
    }
    Some((ctr?, ct?))
}

/// Encode `{v:1, ctr, ct}` in canonical CBOR (matches the SDK encoder).
pub fn encode(ctr: u64, ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct.len() + 32);
    out.push(0xA3); // map of 3
    out.extend_from_slice(&[0x61, b'v']); // text "v"
    out.push(0x01); // unsigned 1
    out.extend_from_slice(&[0x63, b'c', b't', b'r']); // text "ctr"
    write_head(&mut out, 0x00, ctr);
    out.extend_from_slice(&[0x62, b'c', b't']); // text "ct"
    write_head(&mut out, 0x40, ct.len() as u64);
    out.extend_from_slice(ct);
    out
}

/// The next `n` bytes, advancing `p`. `None` past the end of `buf`.
fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = p.checked_add(n)?;
    let s = buf.get(*p..end)?;
    *p = end;
    Some(s)
}

/// A map key: a text string of at most 23 bytes (we only emit short keys).
fn take_key<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let head = take(buf, p, 1)?[0];
    if head & 0xE0 != 0x60 || head & 0x1F > 23 {
        return None;
    }
    take(buf, p, (head & 0x1F) as usize)
}

/// The argument of a definite-length item of major type `major`.
fn take_head(buf: &[u8], p: &mut usize, major: u8) -> Option<u64> {
    let head = take(buf, p, 1)?[0];
    if head >> 5 != major {
        return None;
    }
    let mut be = |n: usize| -> Option<u64> {
        Some(take(buf, p, n)?.iter().fold(0u64, |v, b| (v << 8) | *b as u64))
    };
    match head & 0x1F {
        n @ 0..=23 => Some(n as u64),
        24 => be(1),
        25 => be(2),
        26 => be(4),
        27 => be(8),
        _ => None,
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, v: u64) {
    if v <= 23 {
        out.push(major | v as u8);
    } else if v <= 0xFF {
        out.push(major | 24);
        out.push(v as u8);
    } else if v <= 0xFFFF {
        out.push(major | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        out.push(major | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for (ctr, len) in [(0u64, 0usize), (7, 5), (300, 24), (u64::MAX, 1024), (1, 70_000)] {
            let ct: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(decode(&encode(ctr, &ct)), Some((ctr, ct)));
        }
    }

    /// A `ct` length near 2^64 must be refused, not wrap the offset.
    #[test]
    fn huge_length_is_refused() {
        let head: &[u8] = &[0xA3, 0x61, b'v', 0x01, 0x63, b'c', b't', b'r', 0x00, 0x62, b'c', b't'];
        for len in [u64::MAX, u64::MAX - 1, u64::MAX - 13, 1 << 63, 0xFFFF_FFFF] {
            let mut buf = head.to_vec();
            buf.push(0x5B);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(b"tail");
            assert_eq!(decode(&buf), None, "len {len:#x}");
        }
    }

    #[test]
    fn truncated_and_malformed_are_refused() {
        let env = encode(9, b"hello");
        for cut in 0..env.len() {
            assert_eq!(decode(&env[..cut]), None, "cut at {cut}");
        }
        let mut wrong_version = env.clone();
        wrong_version[3] = 0x02;
        assert_eq!(decode(&wrong_version), None);
        assert_eq!(decode(&[0xA3, 0x78, 0xFF]), None); // long text key
        assert_eq!(decode(&[0xA3, 0x61, b'v', 0x1F]), None); // indefinite length
    }
}
