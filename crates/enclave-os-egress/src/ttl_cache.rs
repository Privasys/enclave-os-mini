// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! A small bounded map whose entries expire, used by the JWKS fetcher to
//! remember discovered JWKS URIs and recent fetch failures.
//!
//! Pure (no SGX), so `tests/egress-cache-unit` runs it on the host.

use std::collections::BTreeMap;
use std::string::String;

/// A map from string keys to values that expire at a set time, holding at
/// most `max` entries.
pub struct TtlMap<V> {
    entries: BTreeMap<String, (V, u64)>,
    max: usize,
}

impl<V> TtlMap<V> {
    pub const fn new(max: usize) -> Self {
        Self { entries: BTreeMap::new(), max }
    }

    /// The value under `key`, unless it has expired at `now`.
    pub fn get(&self, key: &str, now: u64) -> Option<&V> {
        match self.entries.get(key) {
            Some((v, expires)) if now < *expires => Some(v),
            _ => None,
        }
    }

    /// Store `value` under `key` until `now + ttl`. When full, expired
    /// entries go first, then the one expiring soonest.
    pub fn insert(&mut self, key: &str, value: V, now: u64, ttl: u64) {
        if !self.entries.contains_key(key) && self.entries.len() >= self.max.max(1) {
            self.entries.retain(|_, (_, expires)| now < *expires);
            while self.entries.len() >= self.max.max(1) {
                let soonest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, expires))| *expires)
                    .map(|(k, _)| k.clone());
                match soonest {
                    Some(k) => {
                        self.entries.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.entries.insert(key.into(), (value, now.saturating_add(ttl)));
    }

    /// Forget `key`.
    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire() {
        let mut m = TtlMap::new(8);
        m.insert("a", 1, 100, 30);
        assert_eq!(m.get("a", 100), Some(&1));
        assert_eq!(m.get("a", 129), Some(&1));
        assert_eq!(m.get("a", 130), None);
        m.remove("a");
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn a_full_map_drops_expired_then_soonest() {
        let mut m = TtlMap::new(2);
        m.insert("old", 1, 0, 10);
        m.insert("keep", 2, 0, 1000);
        // "old" has expired at 50: it goes first.
        m.insert("new", 3, 50, 100);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("keep", 50), Some(&2));
        // Nothing expired: the soonest to expire ("new", at 150) goes.
        m.insert("newer", 4, 60, 500);
        assert_eq!(m.get("new", 60), None);
        assert_eq!(m.get("keep", 60), Some(&2));
        assert_eq!(m.get("newer", 60), Some(&4));
        // A huge TTL does not wrap.
        m.insert("forever", 5, u64::MAX - 1, u64::MAX);
        assert_eq!(m.get("forever", u64::MAX - 1), Some(&5));
    }
}
