// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Bounds on the session relay's tables: the session table and the EncAuth
//! rebind rate limiter. Both grow on unauthenticated requests and live in
//! the enclave's fixed heap, where running out aborts the enclave.
//!
//! Pure (no SGX), so `tests/relay-limits-unit` runs it on the host.

use std::collections::BTreeMap;

/// Most sessions held at once. About 150 bytes each, so a full table is a
/// few MiB of the enclave heap. A bootstrap past the cap is refused (503)
/// until sessions expire.
pub const MAX_SESSIONS: usize = 20_000;

/// Max voucher-backed bootstrap attempts (accepted or rejected) per sid
/// per window. Matches the Go runtime.
pub const REBIND_RATE_LIMIT: u32 = 6;
pub const REBIND_RATE_WINDOW_SECS: u64 = 60;
/// The sid is read before the voucher's signatures are checked, so its
/// length is bounded here: a longer one is refused.
pub const MAX_REBIND_SID_LEN: usize = 128;
/// Most sids tracked at once.
pub const MAX_REBIND_ENTRIES: usize = 10_000;

/// Whether `map`, which holds at most `max` entries, has room for one more.
/// When it is full, the entries `expired` reports are removed first, at most
/// once a second (`last_sweep`), so a full table is not walked on every
/// request.
pub fn make_room<V>(
    map: &mut BTreeMap<String, V>,
    max: usize,
    now: u64,
    last_sweep: &mut u64,
    expired: impl Fn(&V) -> bool,
) -> bool {
    if map.len() < max {
        return true;
    }
    if now > *last_sweep {
        *last_sweep = now;
        map.retain(|_, v| !expired(v));
    }
    map.len() < max
}

struct RebindWindow {
    start: u64,
    count: u32,
}

/// Per-sid rate limit on voucher-backed bootstraps.
#[derive(Default)]
pub struct RebindTable {
    map: BTreeMap<String, RebindWindow>,
    last_sweep: u64,
}

impl RebindTable {
    /// Record one attempt for `sid` and report whether it is within budget.
    ///
    /// The sid comes from an unverified decode: a forged sid only throttles
    /// the forger's own bucket, and the voucher's signatures still decide.
    /// So while the table is full, a new sid is allowed without being
    /// counted rather than refused.
    pub fn allow(&mut self, sid: &str, now: u64) -> bool {
        if sid.len() > MAX_REBIND_SID_LEN {
            return false;
        }
        if let Some(w) = self.map.get_mut(sid) {
            if now.saturating_sub(w.start) <= REBIND_RATE_WINDOW_SECS {
                w.count = w.count.saturating_add(1);
                return w.count <= REBIND_RATE_LIMIT;
            }
            *w = RebindWindow { start: now, count: 1 };
            return true;
        }
        let room = make_room(&mut self.map, MAX_REBIND_ENTRIES, now, &mut self.last_sweep, |w| {
            now.saturating_sub(w.start) > REBIND_RATE_WINDOW_SECS
        });
        if room {
            self.map.insert(sid.to_string(), RebindWindow { start: now, count: 1 });
        }
        true
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_window() {
        let mut t = RebindTable::default();
        assert!(t.allow("sid", 1000));
        for _ in 0..5 {
            assert!(t.allow("sid", 1001));
        }
        assert!(!t.allow("sid", 1002)); // 7th in window
        assert!(t.allow("sid", 1100)); // new window
    }

    #[test]
    fn long_sid_is_refused_and_not_stored() {
        let mut t = RebindTable::default();
        assert!(t.allow(&"a".repeat(MAX_REBIND_SID_LEN), 1));
        assert!(!t.allow(&"a".repeat(MAX_REBIND_SID_LEN + 1), 1));
        assert!(!t.allow(&"a".repeat(12_000_000), 1));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_is_bounded_and_expired_entries_leave() {
        let mut t = RebindTable::default();
        for i in 0..3 * MAX_REBIND_ENTRIES {
            assert!(t.allow(&format!("forged-{i}"), 10));
        }
        assert_eq!(t.len(), MAX_REBIND_ENTRIES);

        // Once the window has passed, a new sid sweeps the old ones out.
        assert!(t.allow("fresh", 10 + REBIND_RATE_WINDOW_SECS + 1));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn full_table_is_swept_at_most_once_a_second() {
        let mut m: BTreeMap<String, u64> = (0..4).map(|i| (i.to_string(), i)).collect();
        let mut last = 0;
        let sweeps = std::cell::Cell::new(0);
        let expired = |_: &u64| {
            sweeps.set(sweeps.get() + 1);
            false
        };
        assert!(!make_room(&mut m, 4, 5, &mut last, expired));
        assert!(!make_room(&mut m, 4, 5, &mut last, expired));
        assert_eq!(sweeps.get(), 4); // one walk in second 5
        assert!(!make_room(&mut m, 4, 6, &mut last, expired));
        assert_eq!(sweeps.get(), 8);
        assert!(make_room(&mut m, 4, 7, &mut last, |v| *v < 2));
        assert_eq!(m.len(), 2);
    }
}
