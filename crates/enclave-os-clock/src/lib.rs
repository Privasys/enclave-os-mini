// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Trusted time for enclave-os.
//!
//! An SGX enclave has no clock of its own: every time it reads comes from
//! the host, which can roll it back to get expired credentials accepted.
//! This crate holds the pure half of the defence, with no I/O, so it builds
//! and tests on any host:
//!
//! - [`state::Clock`]: the floor state machine. Every trusted-time read goes
//!   through it. It never returns less than the previous read, never goes
//!   below the sealed floor, and when the host clock is caught wrong it
//!   returns the NTS time **frozen** at the moment of the fetch until the
//!   host is fixed. I/O (host clock, NTS, incident POST, sealing, logging)
//!   is injected through [`state::Env`].
//! - [`ntske`] and [`ntp`]: the NTS (RFC 8915) key-establishment records and
//!   the authenticated NTPv4 packet with its extension fields.
//! - [`quorum`]: two servers picked at random must agree within 2 s; on
//!   disagreement a third decides by majority.
//! - [`wire`]: the monitor contracts (clock config, signed floor poll,
//!   incident and signed receipt) and their Ed25519 checks.
//!
//! The monitor only ever *triggers*: its time is never used as trusted time
//! on its own. The floor rises only from a host time that the monitor or
//! NTS confirmed, or from NTS itself.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod ntp;
pub mod ntske;
pub mod quorum;
pub mod servers;
pub mod state;
pub mod wire;

use alloc::string::String;

/// The earliest time any build accepts: 2026-09-18T00:00:00Z, in Unix ms.
///
/// A fresh enclave (no sealed floor yet) starts its floor here, so it never
/// accepts a time before its own build. Bump it from time to time; changing
/// it changes the measurement, like every other compiled-in trust input.
pub const MIN_TRUSTED_TIME_MS: i64 = 1_789_689_600_000;

/// Host and reference may differ by this much and still count as agreeing.
pub const TOLERANCE_MS: i64 = 10_000;

/// Host time may sit this far below the floor before it counts as having
/// gone back past a verified time.
pub const BACKSTEP_MS: i64 = 1_000;

/// While flagged (or failing closed), NTS is fetched again every this many
/// trusted-time reads. The enclave cannot tell that a monitor poll is late,
/// so this bounds how stale the frozen time gets on reads the host drives
/// itself.
pub const REFETCH_EVERY: u32 = 100;

/// Why trusted time is not available, or why a step of the algorithm failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The host clock could not be read at all.
    HostUnavailable,
    /// No NTS quorum: servers unreachable, invalid replies, or no majority.
    Nts(String),
    /// The monitor did not return a valid signed receipt for an incident.
    NoReceipt(String),
    /// A clock problem is unresolved and the retry is not due yet: fail
    /// closed without contacting anyone.
    Unavailable,
}

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClockError::HostUnavailable => write!(f, "host clock unavailable"),
            ClockError::Nts(e) => write!(f, "nts: {e}"),
            ClockError::NoReceipt(e) => write!(f, "no incident receipt: {e}"),
            ClockError::Unavailable => write!(f, "trusted time unavailable"),
        }
    }
}

/// `|a - b|` without overflow.
pub(crate) fn abs_diff(a: i64, b: i64) -> i64 {
    a.saturating_sub(b).saturating_abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_trusted_time_is_2026_09_18_utc() {
        // 20714 days after 1970-01-01.
        let days: i64 = 56 * 365 + 14 + 243 + 17;
        assert_eq!(days, 20_714);
        assert_eq!(MIN_TRUSTED_TIME_MS, days * 86_400 * 1_000);
    }

    #[test]
    fn abs_diff_saturates() {
        assert_eq!(abs_diff(5, 9), 4);
        assert_eq!(abs_diff(9, 5), 4);
        assert_eq!(abs_diff(i64::MIN, i64::MAX), i64::MAX);
    }
}
