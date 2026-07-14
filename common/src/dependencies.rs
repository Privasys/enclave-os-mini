// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Attested cross-enclave dependency set.
//!
//! A workload that depends on other enclaves is pinned to a fixed set of
//! dependency identities. The runtime carries that set, canonically encoded, in
//! the [`crate::oids::ATTESTED_DEPENDENCY_SET_OID`] (65230.6.1) certificate
//! extension and enforces it fail-closed on outbound RA-TLS. The extension is
//! owned by the runtime, never the app, so the advertised set and the enforced
//! set are one object.
//!
//! The canonical encoding and the identity fold here are BYTE-IDENTICAL to the
//! RA-TLS client SDKs (Go/Rust/…), so a certificate this runtime mints is parsed
//! by any SDK verifier and vice-versa. The cross-check test pins that contract to
//! a shared vector.
//!
//! Depth soundness comes from the fold: an entry commits to its dependency's own
//! dependency set via `folded_identity`, so a change deep in the tree changes the
//! identity a dependent is pinned to — enforcement stays a single direct-edge
//! check at each hop while the recursion lives in the pinned identity.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Domain separator for the identity fold; must match the SDKs.
const DOMAIN_FOLD_IDENTITY: &str = "privasys-app-identity-v1";

/// One allowed measurement for a dependency, mirroring the vault `Measurement`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepMeasurement {
    /// SGX MRENCLAVE, lowercase hex.
    Sgx(String),
    /// TDX MRTD + RTMR1 + RTMR2, each lowercase hex.
    Tdx {
        mrtd: String,
        rtmr1: String,
        rtmr2: String,
    },
}

impl DepMeasurement {
    /// Stable string form used for sorting and the fold preimage.
    pub fn canonical(&self) -> String {
        match self {
            DepMeasurement::Sgx(m) => {
                let mut s = String::from("sgx:");
                s.push_str(&m.to_lowercase());
                s
            }
            DepMeasurement::Tdx { mrtd, rtmr1, rtmr2 } => {
                let mut s = String::from("tdx:");
                s.push_str(&mrtd.to_lowercase());
                s.push(':');
                s.push_str(&rtmr1.to_lowercase());
                s.push(':');
                s.push_str(&rtmr2.to_lowercase());
                s
            }
        }
    }
}

/// One direct dependency: the identity a dependent is allowed to talk to for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyEntry {
    /// Management app-id of the dependency (matches the peer's OID 65230.3.6).
    pub app_id: String,
    /// Any-of set of allowed measurement registers.
    pub measurements: Vec<DepMeasurement>,
    /// OID values the peer's certificate must carry verbatim (oid, value).
    pub required_oids: Vec<(String, Vec<u8>)>,
    /// Lowercase-hex commitment to THIS dependency's own subtree (empty for a leaf).
    pub folded_identity: String,
}

/// A workload's ordered set of direct attested dependencies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DependencySet {
    pub entries: Vec<DependencyEntry>,
}

struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    fn new() -> Self {
        CanonicalWriter { buf: Vec::new() }
    }
    fn u32(&mut self, n: usize) {
        self.buf.extend_from_slice(&(n as u32).to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len());
        self.buf.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
}

impl DependencySet {
    /// Canonicalise: entries sorted by app-id, measurements by canonical form,
    /// required OIDs by (oid, value). Output is independent of declaration order.
    fn normalised(&self) -> DependencySet {
        let mut out = self.clone();
        for e in out.entries.iter_mut() {
            e.measurements.sort_by(|a, b| a.canonical().cmp(&b.canonical()));
            e.required_oids
                .sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        }
        out.entries.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        out
    }

    fn write_canonical(&self, w: &mut CanonicalWriter) {
        let n = self.normalised();
        w.u32(n.entries.len());
        for e in &n.entries {
            w.str(&e.app_id);
            w.u32(e.measurements.len());
            for m in &e.measurements {
                w.str(&m.canonical());
            }
            w.u32(e.required_oids.len());
            for (oid, val) in &e.required_oids {
                w.str(oid);
                w.bytes(val);
            }
            w.str(&e.folded_identity.to_lowercase());
        }
    }
}

/// Canonical byte encoding placed in the OID 65230.6.1 extension.
pub fn encode_dependency_set(set: &DependencySet) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    set.write_canonical(&mut w);
    w.buf
}

/// Reader for the canonical length-prefixed encoding.
struct CanonicalReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> CanonicalReader<'a> {
    fn u32(&mut self) -> Result<usize, &'static str> {
        if self.off + 4 > self.buf.len() {
            return Err("dependency set truncated");
        }
        let n = u32::from_be_bytes([
            self.buf[self.off],
            self.buf[self.off + 1],
            self.buf[self.off + 2],
            self.buf[self.off + 3],
        ]) as usize;
        self.off += 4;
        Ok(n)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let n = self.u32()?;
        if self.off + n > self.buf.len() {
            return Err("dependency set truncated");
        }
        let b = self.buf[self.off..self.off + n].to_vec();
        self.off += n;
        Ok(b)
    }
    fn string(&mut self) -> Result<String, &'static str> {
        String::from_utf8(self.bytes()?).map_err(|_| "invalid utf-8 in dependency set")
    }
}

fn measurement_from_canonical(s: &str) -> DepMeasurement {
    if let Some(rest) = s.strip_prefix("tdx:") {
        let mut parts = rest.split(':');
        DepMeasurement::Tdx {
            mrtd: parts.next().unwrap_or("").to_string(),
            rtmr1: parts.next().unwrap_or("").to_string(),
            rtmr2: parts.next().unwrap_or("").to_string(),
        }
    } else {
        DepMeasurement::Sgx(s.strip_prefix("sgx:").unwrap_or(s).to_string())
    }
}

/// Decode the canonical encoding. Rejects truncated or trailing-byte input. Used
/// to validate a dependency set the platform supplies before the runtime seals it
/// into OID 65230.6.1.
pub fn decode_dependency_set(bytes: &[u8]) -> Result<DependencySet, &'static str> {
    let mut r = CanonicalReader { buf: bytes, off: 0 };
    let count = r.u32()?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let app_id = r.string()?;
        let m_count = r.u32()?;
        let mut measurements = Vec::with_capacity(m_count);
        for _ in 0..m_count {
            measurements.push(measurement_from_canonical(&r.string()?));
        }
        let o_count = r.u32()?;
        let mut required_oids = Vec::with_capacity(o_count);
        for _ in 0..o_count {
            let oid = r.string()?;
            let val = r.bytes()?;
            required_oids.push((oid, val));
        }
        let folded_identity = r.string()?;
        entries.push(DependencyEntry {
            app_id,
            measurements,
            required_oids,
            folded_identity,
        });
    }
    if r.off != bytes.len() {
        return Err("trailing bytes in dependency set");
    }
    Ok(DependencySet { entries })
}

/// Decode then re-encode so the stored/advertised bytes are always in canonical
/// form regardless of how the platform ordered the input. Rejects malformed input.
pub fn canonicalize_encoded(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    Ok(encode_dependency_set(&decode_dependency_set(bytes)?))
}

/// Compute a workload's folded identity:
/// `SHA-256( domain || measurements(X) || requiredOids(X) || encode(deps(X)) )`.
/// Because deps carries each dependency's own `folded_identity`, the result
/// transitively commits to the whole subtree while every hop verifies only its
/// direct edges.
#[cfg(feature = "crypto")]
pub fn fold_identity(
    own_measurements: &[String],
    own_required_oids: &[(String, Vec<u8>)],
    deps: &DependencySet,
) -> [u8; 32] {
    let mut w = CanonicalWriter::new();
    w.str(DOMAIN_FOLD_IDENTITY);

    let mut ms: Vec<String> = own_measurements.iter().map(|m| m.to_lowercase()).collect();
    ms.sort();
    w.u32(ms.len());
    for m in &ms {
        w.str(m);
    }

    let mut os: Vec<(String, Vec<u8>)> = own_required_oids.to_vec();
    os.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    w.u32(os.len());
    for (oid, val) in &os {
        w.str(oid);
        w.bytes(val);
    }

    deps.write_canonical(&mut w);

    let digest = ring::digest::digest(&ring::digest::SHA256, &w.buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// [`fold_identity`] as lowercase hex, the form stored in `folded_identity`.
#[cfg(feature = "crypto")]
pub fn fold_identity_hex(
    own_measurements: &[String],
    own_required_oids: &[(String, Vec<u8>)],
    deps: &DependencySet,
) -> String {
    crate::hex::hex_encode(&fold_identity(own_measurements, own_required_oids, deps))
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> DependencySet {
        DependencySet {
            entries: vec![DependencyEntry {
                app_id: "confidential-ai".to_string(),
                measurements: vec![
                    DepMeasurement::Sgx("aabb".to_string()),
                    DepMeasurement::Tdx {
                        mrtd: "11".to_string(),
                        rtmr1: "22".to_string(),
                        rtmr2: "33".to_string(),
                    },
                ],
                required_oids: vec![
                    ("1.3.6.1.4.1.65230.3.6".to_string(), b"ai".to_vec()),
                    ("1.3.6.1.4.1.65230.3.2".to_string(), vec![0xde, 0xad]),
                ],
                folded_identity: "00ff".to_string(),
            }],
        }
    }

    // Pinned to the exact bytes produced by the Go SDK for the same input.
    // If this fails, the enclave and the SDKs disagree on the wire format.
    const GO_ENCODE_HEX: &str = "000000010000000f636f6e666964656e7469616c2d616900000002000000087367783a616162620000000c7464783a31313a32323a33330000000200000015312e332e362e312e342e312e36353233302e332e3200000002dead00000015312e332e362e312e342e312e36353233302e332e360000000261690000000430306666";
    const GO_FOLD_HEX: &str = "cc241219ac1d170c3f65d7878aa4822112142a0ba0eda57d81eabaa206f51412";

    #[test]
    fn encoding_matches_go_sdk() {
        assert_eq!(crate::hex::hex_encode(&encode_dependency_set(&sample())), GO_ENCODE_HEX);
    }

    #[test]
    fn fold_matches_go_sdk() {
        let own = vec!["sgx:aabb".to_string()];
        let oids = vec![("1.3.6.1.4.1.65230.3.2".to_string(), b"me".to_vec())];
        assert_eq!(fold_identity_hex(&own, &oids, &sample()), GO_FOLD_HEX);
    }

    #[test]
    fn encoding_is_order_independent() {
        let a = sample();
        let mut b = sample();
        b.entries[0].measurements.reverse();
        b.entries[0].required_oids.reverse();
        assert_eq!(encode_dependency_set(&a), encode_dependency_set(&b));
    }

    #[test]
    fn decode_round_trips() {
        let enc = encode_dependency_set(&sample());
        let dec = decode_dependency_set(&enc).unwrap();
        assert_eq!(encode_dependency_set(&dec), enc);
    }

    #[test]
    fn decode_rejects_truncated_and_trailing() {
        let enc = encode_dependency_set(&sample());
        assert!(decode_dependency_set(&enc[..enc.len() - 1]).is_err());
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_dependency_set(&extra).is_err());
    }

    #[test]
    fn canonicalize_is_idempotent_and_matches_vector() {
        let enc = encode_dependency_set(&sample());
        assert_eq!(crate::hex::hex_encode(&canonicalize_encoded(&enc).unwrap()), GO_ENCODE_HEX);
    }
}
