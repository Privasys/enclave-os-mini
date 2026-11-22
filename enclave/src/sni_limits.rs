// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Hostname normalisation and the bounds on the ingress server's per-name
//! TLS caches (leaf keys and server configs).
//!
//! A TLS client names any SNI it likes, so the caches are keyed by a name
//! that resolved to a registered app; every other name shares one bucket.
//! The caches then hold at most one entry per app name plus that bucket,
//! and a cap backs this up.
//!
//! Pure (no SGX), so `tests/ingress-limits-unit` runs it on the host.

use std::collections::BTreeMap;
use std::string::String;

/// Cache key shared by every name that resolves to no registered app. No
/// hostname is empty, so it cannot collide with an app's key.
pub const UNKNOWN_NAME_KEY: &str = "";

/// Most entries in a per-name cache. Far above the apps one enclave serves;
/// past it, the oldest-keyed entries go (they are re-minted on next use).
pub const MAX_NAME_ENTRIES: usize = 1024;

/// Seconds between sweeps of retired leaf keys.
pub const PRUNE_INTERVAL_SECS: u64 = 60;

/// Longest hostname kept (RFC 1035 limit on a full name).
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Normalise a TLS SNI or HTTP host name: ASCII-lowercased, one trailing
/// dot removed. DNS names are case-insensitive, and `name.` is `name`.
pub fn normalize_hostname(name: &str) -> String {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.to_ascii_lowercase()
}

/// Normalise an HTTP `Host` header: the port is dropped, then the name is
/// normalised as [`normalize_hostname`]. An IPv6 literal (`[::1]:443`)
/// keeps its brackets.
pub fn normalize_host_header(host: &str) -> String {
    let host = host.trim();
    let name = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        match host.rfind(':') {
            Some(colon) if host[colon + 1..].bytes().all(|b| b.is_ascii_digit()) => &host[..colon],
            _ => host,
        }
    };
    normalize_hostname(name)
}

/// The cache key for a normalised name: the name itself when it resolves to
/// a registered app (`resolves`), the shared [`UNKNOWN_NAME_KEY`] otherwise.
pub fn cache_key(normalized: &str, resolves: bool) -> String {
    if resolves && !normalized.is_empty() && normalized.len() <= MAX_HOSTNAME_LEN {
        normalized.into()
    } else {
        UNKNOWN_NAME_KEY.into()
    }
}

/// Make room for `key` in `map`: when `key` is new and the map is at `max`,
/// entries are removed (lowest keys first, never `key`) until one fits.
pub fn make_room<V>(map: &mut BTreeMap<String, V>, key: &str, max: usize) {
    if map.contains_key(key) {
        return;
    }
    while map.len() >= max.max(1) {
        let victim = match map.keys().find(|k| k.as_str() != key) {
            Some(k) => k.clone(),
            None => break,
        };
        map.remove(&victim);
    }
}

/// Rate limit for a periodic sweep: [`Sweep::due`] answers `true` at most
/// once per `interval` seconds.
#[derive(Debug, Default)]
pub struct Sweep {
    last: Option<u64>,
}

impl Sweep {
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Whether a sweep should run at `now`; records it when it should.
    pub fn due(&mut self, now: u64, interval: u64) -> bool {
        match self.last {
            Some(last) if now >= last && now - last < interval => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_lowercased_and_lose_a_trailing_dot() {
        assert_eq!(normalize_hostname("App.Example.ORG."), "app.example.org");
        assert_eq!(normalize_hostname("app.example.org"), "app.example.org");
        assert_eq!(normalize_hostname(""), "");
    }

    #[test]
    fn host_headers_lose_the_port() {
        assert_eq!(normalize_host_header("App.Example.org:443"), "app.example.org");
        assert_eq!(normalize_host_header("app.example.org."), "app.example.org");
        assert_eq!(normalize_host_header("[::1]:8443"), "[::1]");
        assert_eq!(normalize_host_header("app.example.org:x"), "app.example.org:x");
    }

    #[test]
    fn unknown_names_share_one_key() {
        assert_eq!(cache_key("a.example", false), UNKNOWN_NAME_KEY);
        assert_eq!(cache_key("b.example", false), UNKNOWN_NAME_KEY);
        assert_eq!(cache_key("a.example", true), "a.example");
        assert_eq!(cache_key(&"a".repeat(300), true), UNKNOWN_NAME_KEY);
    }

    #[test]
    fn make_room_keeps_the_map_at_its_cap() {
        let mut m: BTreeMap<String, u32> = BTreeMap::new();
        for i in 0..10u32 {
            let k = format!("k{i:02}");
            make_room(&mut m, &k, 4);
            m.insert(k, i);
            assert!(m.len() <= 4);
        }
        assert!(m.contains_key("k09"));
        // An existing key never evicts anything.
        make_room(&mut m, "k09", 4);
        assert_eq!(m.len(), 4);
    }

    #[test]
    fn sweep_runs_at_most_once_per_interval() {
        let mut s = Sweep::new();
        assert!(s.due(1000, 60));
        assert!(!s.due(1001, 60));
        assert!(!s.due(1059, 60));
        assert!(s.due(1060, 60));
        // A clock that steps back does not stall the sweep.
        assert!(s.due(10, 60));
    }
}
