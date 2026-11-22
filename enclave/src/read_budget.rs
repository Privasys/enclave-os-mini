// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The enclave-wide budget for decrypted request bytes buffered by ingress
//! sessions, and the per-connection limit while a request is suspended.
//!
//! A session buffers plaintext until a whole HTTP request has arrived (up
//! to the 16 MiB body limit). Without a shared budget, many connections
//! could each hold that much in the enclave's fixed heap at once.
//!
//! Pure (no SGX), so `tests/ingress-limits-unit` runs it on the host.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Most decrypted bytes buffered across all sessions. A session whose next
/// bytes would cross it is closed.
pub const GLOBAL_MAX_BUFFERED: usize = 32 * 1024 * 1024;

/// Most bytes a connection may buffer behind a suspended request (HTTP/1.1
/// pipelining). Past it the connection is closed.
pub const MAX_BUFFERED_WHILE_PENDING: usize = 64 * 1024;

/// A shared byte budget.
pub struct Budget {
    used: AtomicUsize,
    max: usize,
}

impl Budget {
    pub const fn new(max: usize) -> Self {
        Self { used: AtomicUsize::new(0), max }
    }

    /// Take `n` bytes from the budget; `false` (nothing taken) when that
    /// would cross the maximum.
    pub fn try_reserve(&self, n: usize) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = match cur.checked_add(n) {
                Some(v) if v <= self.max => v,
                _ => return false,
            };
            match self.used.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Give `n` bytes back (never below zero).
    pub fn release(&self, n: usize) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(n);
            match self.used.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

/// The ingress sessions' shared budget.
pub static SESSION_BUFFERS: Budget = Budget::new(GLOBAL_MAX_BUFFERED);

/// Whether a connection with a suspended request and `buffered` bytes
/// behind it must be closed.
pub fn over_pending_limit(has_pending: bool, buffered: usize) -> bool {
    has_pending && buffered > MAX_BUFFERED_WHILE_PENDING
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_refuses_past_its_maximum_and_refills() {
        let b = Budget::new(100);
        assert!(b.try_reserve(60));
        assert!(b.try_reserve(40));
        assert!(!b.try_reserve(1));
        assert_eq!(b.used(), 100);
        b.release(50);
        assert!(b.try_reserve(50));
        assert!(!b.try_reserve(usize::MAX));
        b.release(1_000);
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn a_pending_connection_may_buffer_only_a_little() {
        assert!(!over_pending_limit(false, 10 * MAX_BUFFERED_WHILE_PENDING));
        assert!(!over_pending_limit(true, MAX_BUFFERED_WHILE_PENDING));
        assert!(over_pending_limit(true, MAX_BUFFERED_WHILE_PENDING + 1));
    }
}
