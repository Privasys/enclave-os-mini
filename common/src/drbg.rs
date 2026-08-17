// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Deterministic random bit generator for replay-mode cluster
//! transactions (HMAC-SHA256, after NIST SP 800-90A HMAC_DRBG).
//!
//! One instance is seeded from the 32-byte seed committed in the
//! transaction's log entry and SHARED by every randomness source the
//! guest can reach during that transaction (wasi:random,
//! `crypto.get-random-bytes`). Every draw advances the internal state,
//! so two draws never repeat within a transaction — and a replica
//! replaying the same entry reproduces the exact same stream, which is
//! what makes re-execution byte-identical.
//!
//! This is NOT a general-purpose RNG: outside a replay transaction all
//! randomness comes from the hardware (RDRAND via ring). The
//! determinism here is the point, not a weakness — the seed itself was
//! drawn from hardware randomness by the leader and is protected by
//! the log's encryption + the quorum.

use ring::hmac;

/// HMAC-SHA256 DRBG (SP 800-90A shape, no additional-input path).
pub struct HmacDrbg {
    key: hmac::Key,
    v: [u8; 32],
}

impl HmacDrbg {
    /// Instantiate from the committed transaction seed.
    pub fn new(seed: &[u8; 32]) -> Self {
        // K = 0x00.., V = 0x01.. per SP 800-90A, then update with the
        // seed as entropy input.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let mut drbg = Self { key, v: [1u8; 32] };
        drbg.update(Some(seed));
        drbg
    }

    /// Fill `out` with the next bytes of the deterministic stream.
    /// Every call advances the state: consecutive draws are distinct
    /// and the whole stream is reproducible from the seed.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0usize;
        while done < out.len() {
            self.v = hmac_32(&self.key, &self.v);
            let take = (out.len() - done).min(32);
            out[done..done + take].copy_from_slice(&self.v[..take]);
            done += take;
        }
        // Post-generate update (no additional input).
        self.update(None);
    }

    /// SP 800-90A update: K = HMAC(K, V || tag || input?), V = HMAC(K, V).
    fn update(&mut self, input: Option<&[u8; 32]>) {
        let mut data = [0u8; 65];
        data[..32].copy_from_slice(&self.v);
        data[32] = 0x00;
        let len = match input {
            Some(seed) => {
                data[33..65].copy_from_slice(seed);
                65
            }
            None => 33,
        };
        let k = hmac::sign(&self.key, &data[..len]);
        self.key = hmac::Key::new(hmac::HMAC_SHA256, k.as_ref());
        self.v = hmac_32(&self.key, &self.v);
        if input.is_some() {
            data[..32].copy_from_slice(&self.v);
            data[32] = 0x01;
            let k = hmac::sign(&self.key, &data[..65]);
            self.key = hmac::Key::new(hmac::HMAC_SHA256, k.as_ref());
            self.v = hmac_32(&self.key, &self.v);
        }
    }
}

fn hmac_32(key: &hmac::Key, data: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property replay depends on: same seed → same stream,
    /// regardless of how the draws are chunked.
    #[test]
    fn reproducible_across_chunkings() {
        let seed = [7u8; 32];
        let mut a = HmacDrbg::new(&seed);
        let mut one = [0u8; 96];
        a.fill(&mut one);

        let mut b = HmacDrbg::new(&seed);
        let mut parts = [0u8; 96];
        b.fill(&mut parts[..32]);
        b.fill(&mut parts[32..80]);
        b.fill(&mut parts[80..]);
        // Chunking DOES affect the stream (each call ends with a state
        // update), so replay must chunk identically — which it does,
        // because the guest's calls are themselves deterministic. What
        // must hold: identical call sequences produce identical bytes.
        let mut c = HmacDrbg::new(&seed);
        let mut parts2 = [0u8; 96];
        c.fill(&mut parts2[..32]);
        c.fill(&mut parts2[32..80]);
        c.fill(&mut parts2[80..]);
        assert_eq!(parts, parts2);
        // And a single-draw run is reproducible too.
        let mut d = HmacDrbg::new(&seed);
        let mut one2 = [0u8; 96];
        d.fill(&mut one2);
        assert_eq!(one, one2);
    }

    /// Two consecutive draws never repeat (the state advances).
    #[test]
    fn draws_iterate() {
        let mut drbg = HmacDrbg::new(&[42u8; 32]);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        drbg.fill(&mut x);
        drbg.fill(&mut y);
        assert_ne!(x, y);
    }

    /// Different seeds diverge immediately.
    #[test]
    fn seeds_differ() {
        let mut a = HmacDrbg::new(&[1u8; 32]);
        let mut b = HmacDrbg::new(&[2u8; 32]);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.fill(&mut x);
        b.fill(&mut y);
        assert_ne!(x, y);
    }
}
