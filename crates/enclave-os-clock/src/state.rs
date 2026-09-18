// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The trusted-time state machine.
//!
//! State: `floor` (the highest time confirmed so far, sealed), `flagged`
//! and its reason (sealed), and `last_returned` (memory only). Rules:
//!
//! - A read never returns less than the previous read, nor less than the
//!   floor.
//! - The floor rises only from a host time that the monitor or NTS
//!   confirmed, or from an NTS time. A host that jumps forward cannot push
//!   it past real time.
//! - Host time within [`TOLERANCE_MS`] of the reference is used as is. A
//!   host caught wrong makes reads return the NTS time **frozen** at the
//!   fetch (never an offset: an offset would still move at the host's
//!   pace). While flagged, NTS is fetched again every [`REFETCH_EVERY`]
//!   reads; the flag clears when NTS confirms the host.
//! - A host that goes back more than [`BACKSTEP_MS`] below the floor is an
//!   incident: report it to the monitor and wait for its signed receipt,
//!   then fetch NTS and freeze. No receipt: fail closed.
//! - What a monitor poll finds (`host_clock_wrong`, `monitor_clock_wrong`,
//!   no NTS quorum) is in the poll reply and is never sent as an incident:
//!   the monitor polls again after every incident, which would loop.
//! - Incidents are for what is found outside a poll: the boot fetch, a
//!   host behind the floor, a failed refetch. They are sent after the fact
//!   (on the next read, never inside a poll, since a single-threaded
//!   enclave waiting for a receipt could not answer the poll that follows)
//!   and a lost one is logged. Each condition is reported once, until the
//!   host time is confirmed again.
//! - A poll in sync raises the floor by at most
//!   [`MAX_UNCONFIRMED_RAISE_MS`]; a larger jump needs NTS to confirm the
//!   host, so the monitor key and the host together cannot push the floor
//!   into the future.
//! - A host that blocks the monitor's polls is not the clock's to detect:
//!   the monitor quarantines an enclave that stops answering, so the clock
//!   only acts on what a read or a poll shows it.
//! - Without a configured monitor, incidents are only logged; NTS still
//!   decides.
//! - No NTS quorum fails closed: reads return an error, and the fetch is
//!   retried every [`REFETCH_EVERY`] reads and on every monitor poll.
//! - Boot: restore the sealed floor, then one NTS fetch before the first
//!   read is answered. A host that rolls the sealed state back only
//!   restores an older floor, which this fetch corrects.
//!
//! Incidents are handled one at a time: the caller serialises every call on
//! one `Clock`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::quorum::NtsSample;
use crate::wire::{self, ClockConfigWire, Incident, MonitorConfig, NtsReply, PollReply, PollRequest, WireError};
use crate::{
    abs_diff, ClockError, BACKSTEP_MS, MAX_UNCONFIRMED_RAISE_MS, MIN_TRUSTED_TIME_MS, REFETCH_EVERY,
    TOLERANCE_MS,
};

/// Everything the state machine needs from outside.
pub trait Env {
    /// The host's current time, Unix ms. Untrusted.
    fn host_time_ms(&mut self) -> Result<i64, ClockError>;
    /// An NTS quorum. Server certificates must be checked against
    /// `floor_ms`, never against the host time.
    fn nts_quorum(&mut self, floor_ms: i64) -> Result<NtsSample, ClockError>;
    /// POST `body` (JSON) to `url` and return the response body of a 2xx
    /// reply. The caller bounds the wait.
    fn post_incident(&mut self, url: &str, body: &[u8]) -> Result<Vec<u8>, String>;
    /// 32 random bytes for an incident nonce.
    fn random_nonce(&mut self) -> Result<[u8; 32], ClockError>;
    /// Seal and store the state. Best effort: a failure is logged by the
    /// implementation, and the boot NTS fetch covers a lost seal.
    fn persist(&mut self, sealed: &[u8]);
    /// Log a line; `critical` marks clock incidents.
    fn log(&mut self, critical: bool, msg: &str);
}

/// Why the clock is flagged, or what an incident reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The host went back below a verified time.
    HostBehindFloor,
    /// NTS says the host is wrong.
    HostClockWrong,
    /// NTS says the monitor is wrong (the host is fine).
    MonitorClockWrong,
    /// No NTS quorum.
    NtsUnreachable,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::HostBehindFloor => "host_behind_floor",
            Reason::HostClockWrong => "host_clock_wrong",
            Reason::MonitorClockWrong => "monitor_clock_wrong",
            Reason::NtsUnreachable => "nts_unreachable",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "host_behind_floor" => Some(Reason::HostBehindFloor),
            "host_clock_wrong" => Some(Reason::HostClockWrong),
            "monitor_clock_wrong" => Some(Reason::MonitorClockWrong),
            "nts_unreachable" => Some(Reason::NtsUnreachable),
            _ => None,
        }
    }
}

/// Outcome of a floor poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    InSync,
    MonitorClockWrong,
    HostClockWrong,
    IgnoredStale,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::InSync => "in_sync",
            Verdict::MonitorClockWrong => "monitor_clock_wrong",
            Verdict::HostClockWrong => "host_clock_wrong",
            Verdict::IgnoredStale => "ignored_stale",
        }
    }
}

/// A refused or failed poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollError {
    /// Malformed (400) or not authentic (401).
    Wire(WireError),
    /// No clock config yet, so no key to check the signature with (409).
    NotConfigured,
    /// Host and monitor disagree and there is no NTS quorum to settle it
    /// (503). `reason` names the unresolved problem.
    Unavailable { reason: String, host_time_ms: i64, floor_ms: i64, detail: String },
}

/// A refused clock config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Malformed or invalid (400).
    Wire(WireError),
    /// Lower than the current `config_version` (409).
    Stale { current: u64 },
}

/// Result of an accepted clock config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigAck {
    pub enclave_id: String,
    pub monitor_key_id: String,
    pub config_version: u64,
    /// `false` when this `config_version` was already in place (no-op).
    pub applied: bool,
}

/// A clock problem not resolved yet. While one exists, reads fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    /// The boot NTS fetch has not succeeded yet.
    Boot,
    /// The host went back below the floor: receipt, then NTS.
    HostBehindFloor,
    /// No NTS quorum when one was needed.
    NtsUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    kind: PendingKind,
    /// The incident report has been made (or is not owed).
    reported: bool,
    /// Host time when the problem was found.
    host_ms: i64,
}

impl Pending {
    fn new(kind: PendingKind, reported: bool, host_ms: i64) -> Self {
        Self { kind, reported, host_ms }
    }

    fn reason_str(&self) -> &'static str {
        match self.kind {
            // A boot fetch that is still pending is one that failed.
            PendingKind::Boot | PendingKind::NtsUnreachable => Reason::NtsUnreachable.as_str(),
            PendingKind::HostBehindFloor => Reason::HostBehindFloor.as_str(),
        }
    }
}

/// An incident to report after the fact (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deferred {
    reason: Reason,
    host_ms: i64,
    nts_ms: i64,
}

const SEALED_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Sealed {
    v: u32,
    floor_ms: i64,
    flagged: bool,
    reason: String,
    config: Option<ClockConfigWire>,
}

/// The trusted-time state machine. See the module docs.
#[derive(Debug, Clone)]
pub struct Clock {
    floor: i64,
    flagged: bool,
    flag_reason: Option<Reason>,
    last_returned: i64,
    flagged_reads: u32,
    retry_skip: u32,
    pending: Option<Pending>,
    deferred: Option<Deferred>,
    /// The last incident reported, until the clock is confirmed again.
    last_reported: Option<Reason>,
    config: Option<MonitorConfig>,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// A fresh clock: floor at [`MIN_TRUSTED_TIME_MS`], boot fetch pending.
    pub fn new() -> Self {
        Self {
            floor: MIN_TRUSTED_TIME_MS,
            flagged: false,
            flag_reason: None,
            last_returned: MIN_TRUSTED_TIME_MS,
            flagged_reads: 0,
            retry_skip: 0,
            pending: Some(Pending::new(PendingKind::Boot, true, 0)),
            deferred: None,
            last_reported: None,
            config: None,
        }
    }

    /// Restore from [`Clock::seal`] output. The floor never starts below
    /// [`MIN_TRUSTED_TIME_MS`], and the boot fetch is always pending.
    pub fn restore(sealed: &[u8]) -> Result<Self, String> {
        let s: Sealed = serde_json::from_slice(sealed).map_err(|e| format!("sealed clock state: {e}"))?;
        if s.v != SEALED_VERSION {
            return Err(format!("sealed clock state: unknown version {}", s.v));
        }
        let mut c = Self::new();
        c.floor = s.floor_ms.max(MIN_TRUSTED_TIME_MS);
        c.last_returned = c.floor;
        c.flag_reason = if s.flagged { Reason::parse(&s.reason).or(Some(Reason::HostClockWrong)) } else { None };
        c.flagged = s.flagged;
        c.config = match s.config {
            Some(w) => Some(MonitorConfig::from_wire(w).map_err(|e| format!("sealed clock config: {e}"))?),
            None => None,
        };
        Ok(c)
    }

    /// The state to seal: floor, flag and config.
    pub fn seal(&self) -> Vec<u8> {
        serde_json::to_vec(&Sealed {
            v: SEALED_VERSION,
            floor_ms: self.floor,
            flagged: self.flagged,
            reason: self.flag_reason.map(|r| r.as_str().to_string()).unwrap_or_default(),
            config: self.config.as_ref().map(|c| c.wire.clone()),
        })
        .unwrap_or_default()
    }

    /// The highest confirmed time.
    pub fn floor_ms(&self) -> i64 {
        self.floor
    }

    /// What a frozen read returns: never below the floor or a previous read.
    pub fn frozen_ms(&self) -> i64 {
        self.floor.max(self.last_returned)
    }

    pub fn is_flagged(&self) -> bool {
        self.flagged
    }

    /// Whether reads are failing closed.
    pub fn is_failing_closed(&self) -> bool {
        self.pending.is_some()
    }

    pub fn config(&self) -> Option<&MonitorConfig> {
        self.config.as_ref()
    }

    // ------------------------------------------------------------------
    //  Reads
    // ------------------------------------------------------------------

    /// One trusted-time read, Unix ms.
    pub fn read(&mut self, env: &mut dyn Env) -> Result<i64, ClockError> {
        self.flush_deferred(env);
        if self.pending.is_some() {
            if self.retry_skip > 0 {
                self.retry_skip -= 1;
                return Err(ClockError::Unavailable);
            }
            if let Err(e) = self.resolve(env) {
                self.retry_skip = REFETCH_EVERY - 1;
                return Err(e);
            }
            self.flush_deferred(env);
        }
        let h = env.host_time_ms()?;
        if self.flagged {
            self.flagged_reads += 1;
            if self.flagged_reads >= REFETCH_EVERY {
                self.flagged_reads = 0;
                match env.nts_quorum(self.floor) {
                    Ok(n) => {
                        let host_ok = h >= self.floor && abs_diff(h, n.time_ms) <= TOLERANCE_MS;
                        self.raise_floor(n.time_ms);
                        if host_ok {
                            self.confirmed();
                            self.raise_floor(h);
                            env.log(false, "trusted time: NTS confirms the host clock again, flag cleared");
                            self.persist(env);
                            return Ok(self.ret(h));
                        }
                        self.persist(env);
                    }
                    Err(e) => {
                        env.log(true, &format!("trusted time: refetch while flagged failed, failing closed: {e}"));
                        self.pending = Some(Pending::new(PendingKind::NtsUnreachable, false, h));
                        self.retry_skip = 0;
                        return Err(e);
                    }
                }
            }
            return Ok(self.ret_frozen());
        }
        if h < self.floor.saturating_sub(BACKSTEP_MS) {
            env.log(
                true,
                &format!("trusted time: host clock {h} went back below the floor {}", self.floor),
            );
            self.pending = Some(Pending::new(PendingKind::HostBehindFloor, false, h));
            if let Err(e) = self.resolve(env) {
                self.retry_skip = REFETCH_EVERY - 1;
                return Err(e);
            }
            self.flush_deferred(env);
            return Ok(self.ret_frozen());
        }
        Ok(self.ret(h))
    }

    fn ret(&mut self, h: i64) -> i64 {
        let v = h.max(self.last_returned);
        self.last_returned = v;
        v
    }

    fn ret_frozen(&mut self) -> i64 {
        let v = self.frozen_ms();
        self.last_returned = v;
        v
    }

    fn peek(&self, h: i64) -> i64 {
        if self.flagged {
            self.frozen_ms()
        } else {
            h.max(self.last_returned)
        }
    }

    fn raise_floor(&mut self, t: i64) {
        if t > self.floor {
            self.floor = t;
        }
    }

    fn flag(&mut self, reason: Reason) {
        self.flagged = true;
        self.flag_reason = Some(reason);
        self.flagged_reads = 0;
    }

    fn unflag(&mut self) {
        self.flagged = false;
        self.flag_reason = None;
        self.flagged_reads = 0;
    }

    /// The host time was just confirmed (by the monitor or NTS): clear the
    /// flag, and let the next incident of any kind be reported again.
    fn confirmed(&mut self) {
        self.unflag();
        self.last_reported = None;
    }

    fn persist(&self, env: &mut dyn Env) {
        env.persist(&self.seal());
    }

    // ------------------------------------------------------------------
    //  Incidents
    // ------------------------------------------------------------------

    fn defer(&mut self, reason: Reason, host_ms: i64, nts_ms: i64) {
        self.deferred = Some(Deferred { reason, host_ms, nts_ms });
    }

    /// Send a deferred report, once; a lost one is logged.
    fn flush_deferred(&mut self, env: &mut dyn Env) {
        if let Some(d) = self.deferred.take() {
            if let Err(e) = self.report_once(env, d.reason, d.host_ms, d.nts_ms) {
                env.log(true, &format!("clock incident {} not acknowledged: {e}", d.reason.as_str()));
            }
        }
    }

    /// Report an incident unless the same condition was already reported
    /// and has not changed since (see [`Clock::confirmed`]).
    fn report_once(&mut self, env: &mut dyn Env, reason: Reason, host_ms: i64, nts_ms: i64) -> Result<(), ClockError> {
        if self.last_reported == Some(reason) {
            return Ok(());
        }
        self.report(env, reason, host_ms, nts_ms)?;
        self.last_reported = Some(reason);
        Ok(())
    }

    /// Resolve a pending problem: the owed report, then an NTS fetch.
    fn resolve(&mut self, env: &mut dyn Env) -> Result<(), ClockError> {
        let Some(mut p) = self.pending.clone() else { return Ok(()) };
        let h = env.host_time_ms()?;

        if !p.reported {
            let host_ms = if p.host_ms != 0 { p.host_ms } else { h };
            match p.kind {
                // The one incident that waits for its receipt.
                PendingKind::HostBehindFloor => self.report_once(env, Reason::HostBehindFloor, host_ms, 0)?,
                // Reported after the fact: this may run inside a poll.
                PendingKind::Boot | PendingKind::NtsUnreachable => {
                    self.defer(Reason::NtsUnreachable, host_ms, 0)
                }
            }
            p.reported = true;
            self.pending = Some(p.clone());
        }

        let n = match env.nts_quorum(self.floor) {
            Ok(n) => n,
            Err(e) => {
                env.log(true, &format!("trusted time: no NTS quorum, failing closed: {e}"));
                if p.kind != PendingKind::NtsUnreachable {
                    self.pending = Some(Pending::new(PendingKind::NtsUnreachable, false, h));
                }
                return Err(e);
            }
        };
        self.raise_floor(n.time_ms);
        match p.kind {
            PendingKind::HostBehindFloor => self.flag(Reason::HostBehindFloor),
            PendingKind::Boot | PendingKind::NtsUnreachable => {
                if abs_diff(h, n.time_ms) <= TOLERANCE_MS {
                    self.confirmed();
                    self.raise_floor(h);
                } else if !(self.flagged && p.kind == PendingKind::NtsUnreachable) {
                    env.log(true, &format!("trusted time: host clock {h} is wrong, NTS says {}", n.time_ms));
                    self.flag(Reason::HostClockWrong);
                    self.defer(Reason::HostClockWrong, h, n.time_ms);
                }
                // Otherwise already flagged: stay frozen.
            }
        }
        if p.kind == PendingKind::Boot {
            env.log(false, &format!("trusted time: boot NTS fetch done, floor {}", self.floor));
        }
        self.pending = None;
        self.retry_skip = 0;
        self.flagged_reads = 0;
        self.persist(env);
        Ok(())
    }

    /// Report an incident and wait for the monitor's signed receipt. No
    /// monitor configured: log only.
    fn report(&self, env: &mut dyn Env, reason: Reason, host_ms: i64, nts_ms: i64) -> Result<(), ClockError> {
        let line = format!(
            "clock incident {}: host_time_ms={} floor_ms={} nts_time_ms={}",
            reason.as_str(),
            host_ms,
            self.floor,
            nts_ms
        );
        let Some(cfg) = self.config.as_ref() else {
            env.log(true, &format!("CRITICAL {line} (no monitor configured, logged only)"));
            return Ok(());
        };
        env.log(true, &format!("CRITICAL {line}, reporting to the monitor"));
        let nonce = wire::b64url_encode(&env.random_nonce().map_err(|e| ClockError::NoReceipt(format!("nonce: {e}")))?);
        let body = serde_json::to_vec(&Incident {
            enclave_id: cfg.wire.enclave_id.clone(),
            reason: reason.as_str().to_string(),
            host_time_ms: host_ms,
            floor_ms: self.floor,
            nts_time_ms: nts_ms,
            nonce: nonce.clone(),
        })
        .map_err(|e| ClockError::NoReceipt(format!("encode: {e}")))?;
        let resp = env.post_incident(&cfg.wire.incident_url, &body).map_err(ClockError::NoReceipt)?;
        let id = wire::verify_receipt(cfg, &nonce, &resp).map_err(|e| ClockError::NoReceipt(e.to_string()))?;
        env.log(false, &format!("clock incident {} acknowledged by the monitor as {id}", reason.as_str()));
        Ok(())
    }

    // ------------------------------------------------------------------
    //  Monitor poll
    // ------------------------------------------------------------------

    /// Handle a `POST /clock/poll` body. `runtime` is `mini` or `virtual`.
    ///
    /// What a poll finds is in its reply and is never sent as an incident:
    /// the monitor polls again after every incident, so reporting here
    /// would loop. While trusted time is failing closed the reply still
    /// comes (the monitor keeps its fleet view) with `reason` naming the
    /// problem and `trusted_time_ms` 0, and the poll retries NTS first so
    /// an idle enclave recovers as soon as NTS is back.
    pub fn poll(&mut self, env: &mut dyn Env, body: &[u8], runtime: &str) -> Result<PollReply, PollError> {
        let req = PollRequest::parse(body).map_err(PollError::Wire)?;
        let cfg = self.config.as_ref().ok_or(PollError::NotConfigured)?;
        req.verify(cfg).map_err(PollError::Wire)?;

        // An unresolved problem is retried now, the signature checked.
        if self.pending.is_some() && self.resolve(env).is_err() {
            self.retry_skip = REFETCH_EVERY - 1;
        }

        let h = env.host_time_ms().map_err(|e| self.unavailable(env, e))?;
        let mut nts = NtsReply::default();
        let in_sync = abs_diff(h, req.t_ms) <= TOLERANCE_MS;
        let verdict = if req.t_ms < self.floor {
            // A replay, or a slow monitor: the floor is already past it.
            Verdict::IgnoredStale
        } else if in_sync && h <= self.floor.saturating_add(MAX_UNCONFIRMED_RAISE_MS) {
            self.raise_floor(h);
            if self.pending.is_none() {
                self.confirmed();
            }
            Verdict::InSync
        } else {
            // The monitor disagrees with the host, or agrees on a jump too
            // large to take without NTS.
            match env.nts_quorum(self.floor) {
                Err(e) => {
                    env.log(true, &format!("trusted time: poll needs NTS and there is no quorum: {e}"));
                    if self.pending.as_ref().map(|p| p.kind) != Some(PendingKind::HostBehindFloor) {
                        self.pending = Some(Pending::new(PendingKind::NtsUnreachable, true, h));
                    }
                    self.retry_skip = REFETCH_EVERY - 1;
                    self.persist(env);
                    return Err(self.unavailable(env, e));
                }
                Ok(n) => {
                    nts = NtsReply { time_ms: n.time_ms, servers: n.servers.clone() };
                    // NTS answers again: that settles a failed boot fetch or
                    // an NTS outage.
                    if matches!(
                        self.pending.as_ref().map(|p| p.kind),
                        Some(PendingKind::Boot | PendingKind::NtsUnreachable)
                    ) {
                        self.pending = None;
                        self.retry_skip = 0;
                    }
                    if abs_diff(h, n.time_ms) <= TOLERANCE_MS {
                        self.raise_floor(h);
                        if self.pending.is_none() {
                            self.confirmed();
                        }
                        if in_sync {
                            Verdict::InSync
                        } else {
                            env.log(
                                true,
                                &format!("trusted time: the monitor's clock ({}) is wrong, NTS confirms the host", req.t_ms),
                            );
                            Verdict::MonitorClockWrong
                        }
                    } else {
                        env.log(true, &format!("trusted time: host clock {h} is wrong, NTS says {}", n.time_ms));
                        self.raise_floor(n.time_ms);
                        self.flag(Reason::HostClockWrong);
                        Verdict::HostClockWrong
                    }
                }
            }
        };
        self.persist(env);

        let cfg = self.config.as_ref().ok_or(PollError::NotConfigured)?;
        let (trusted, reason) = match self.pending.as_ref() {
            Some(p) => (0, p.reason_str().to_string()),
            None => (self.peek(h), self.flag_reason.map(|r| r.as_str().to_string()).unwrap_or_default()),
        };
        Ok(PollReply {
            enclave_id: cfg.wire.enclave_id.clone(),
            runtime: runtime.to_string(),
            host_time_ms: h,
            trusted_time_ms: trusted,
            floor_ms: self.floor,
            flagged: self.flagged,
            reason,
            verdict: verdict.as_str().to_string(),
            nts,
            config_key_id: cfg.key_id(),
        })
    }

    fn unavailable(&self, env: &mut dyn Env, e: ClockError) -> PollError {
        PollError::Unavailable {
            reason: self
                .pending
                .as_ref()
                .map(|p| p.reason_str())
                .unwrap_or(Reason::NtsUnreachable.as_str())
                .to_string(),
            host_time_ms: env.host_time_ms().unwrap_or(0),
            floor_ms: self.floor,
            detail: e.to_string(),
        }
    }

    // ------------------------------------------------------------------
    //  Clock config
    // ------------------------------------------------------------------

    /// Handle a `PUT /clock/config` body. Only a higher `config_version`
    /// replaces the current config. The current version again is a no-op
    /// that succeeds (management-service re-pushes it on retries), and
    /// keeps the config already in place; a lower one is refused.
    pub fn set_config(&mut self, env: &mut dyn Env, body: &[u8]) -> Result<ConfigAck, ConfigError> {
        let cfg = MonitorConfig::parse(body).map_err(ConfigError::Wire)?;
        if let Some(cur) = self.config.as_ref() {
            let current = cur.wire.config_version;
            if cfg.wire.config_version < current {
                return Err(ConfigError::Stale { current });
            }
            if cfg.wire.config_version == current {
                return Ok(ConfigAck {
                    enclave_id: cur.wire.enclave_id.clone(),
                    monitor_key_id: cur.key_id(),
                    config_version: current,
                    applied: false,
                });
            }
        }
        let ack = ConfigAck {
            enclave_id: cfg.wire.enclave_id.clone(),
            monitor_key_id: cfg.key_id(),
            config_version: cfg.wire.config_version,
            applied: true,
        };
        env.log(
            false,
            &format!(
                "trusted time: clock config v{} applied (monitor key {}, enclave {})",
                ack.config_version, ack.monitor_key_id, ack.enclave_id
            ),
        );
        self.config = Some(cfg);
        self.persist(env);
        Ok(ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::tests::{config, signed_poll, signed_receipt};
    use alloc::vec;

    const T0: i64 = MIN_TRUSTED_TIME_MS + 86_400_000;

    struct Fake {
        host: Result<i64, ()>,
        nts: Result<i64, ()>,
        receipts: bool,
        nts_calls: u32,
        incidents: Vec<Incident>,
        logs: Vec<(bool, String)>,
        sealed: Vec<u8>,
        seen_floor: Vec<i64>,
    }

    impl Fake {
        fn new(t: i64) -> Self {
            Self {
                host: Ok(t),
                nts: Ok(t),
                receipts: true,
                nts_calls: 0,
                incidents: Vec::new(),
                logs: Vec::new(),
                sealed: Vec::new(),
                seen_floor: Vec::new(),
            }
        }

        fn reasons(&self) -> Vec<&str> {
            self.incidents.iter().map(|i| i.reason.as_str()).collect()
        }
    }

    impl Env for Fake {
        fn host_time_ms(&mut self) -> Result<i64, ClockError> {
            self.host.map_err(|_| ClockError::HostUnavailable)
        }
        fn nts_quorum(&mut self, floor_ms: i64) -> Result<NtsSample, ClockError> {
            self.nts_calls += 1;
            self.seen_floor.push(floor_ms);
            self.nts
                .map(|t| NtsSample { time_ms: t, servers: vec!["a".to_string(), "b".to_string()] })
                .map_err(|_| ClockError::Nts("blocked".to_string()))
        }
        fn post_incident(&mut self, url: &str, body: &[u8]) -> Result<Vec<u8>, String> {
            assert!(url.starts_with("https://"));
            let inc: Incident = serde_json::from_slice(body).unwrap();
            let r = signed_receipt(&inc.enclave_id, &inc.nonce, "inc-1");
            self.incidents.push(inc);
            if self.receipts {
                Ok(r)
            } else {
                Err("timeout".to_string())
            }
        }
        fn random_nonce(&mut self) -> Result<[u8; 32], ClockError> {
            Ok([9; 32])
        }
        fn persist(&mut self, sealed: &[u8]) {
            self.sealed = sealed.to_vec();
        }
        fn log(&mut self, critical: bool, msg: &str) {
            self.logs.push((critical, msg.to_string()));
        }
    }

    fn configured(env: &mut Fake) -> Clock {
        let mut c = Clock::new();
        let body = serde_json::to_vec(&config(1).wire).unwrap();
        c.set_config(env, &body).unwrap();
        c
    }

    fn poll(c: &mut Clock, env: &mut Fake, t: i64) -> Result<PollReply, PollError> {
        let body = serde_json::to_vec(&signed_poll("enc-1", t, 1)).unwrap();
        c.poll(env, &body, "mini")
    }

    #[test]
    fn boot_fetches_nts_before_the_first_read() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        assert_eq!(c.read(&mut env), Ok(T0));
        assert_eq!(env.nts_calls, 1);
        assert_eq!(env.seen_floor, vec![MIN_TRUSTED_TIME_MS]);
        assert_eq!(c.floor_ms(), T0);
        env.host = Ok(T0 + 5);
        assert_eq!(c.read(&mut env), Ok(T0 + 5));
        assert_eq!(env.nts_calls, 1);
    }

    #[test]
    fn boot_without_nts_fails_closed_and_retries_every_100_reads() {
        let mut env = Fake::new(T0);
        env.nts = Err(());
        let mut c = Clock::new();
        assert!(matches!(c.read(&mut env), Err(ClockError::Nts(_))));
        for _ in 0..REFETCH_EVERY - 1 {
            assert_eq!(c.read(&mut env), Err(ClockError::Unavailable));
        }
        assert_eq!(env.nts_calls, 1);
        env.nts = Ok(T0);
        assert_eq!(c.read(&mut env), Ok(T0));
        assert_eq!(env.nts_calls, 2);
        // No monitor configured: the nts_unreachable incident was logged only.
        assert!(env.logs.iter().any(|(crit, l)| *crit && l.contains("nts_unreachable") && l.contains("logged only")));
        assert!(env.incidents.is_empty());
    }

    #[test]
    fn reads_are_monotonic_and_never_below_the_floor() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        c.read(&mut env).unwrap();
        env.host = Ok(T0 + 2_000);
        assert_eq!(c.read(&mut env), Ok(T0 + 2_000));
        // Half a second back: within the backstep window, time stalls.
        env.host = Ok(T0 + 1_500);
        assert_eq!(c.read(&mut env), Ok(T0 + 2_000));
        // Below the floor but within the window: never below the floor.
        env.host = Ok(T0 - 500);
        assert_eq!(c.read(&mut env), Ok(T0 + 2_000));
        assert!(env.incidents.is_empty());
    }

    #[test]
    fn a_host_behind_the_floor_is_an_incident_then_frozen() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        // The host rolls back an hour; NTS still says T0 + 10 s.
        env.host = Ok(T0 - 3_600_000);
        env.nts = Ok(T0 + 10_000);
        assert_eq!(c.read(&mut env), Ok(T0 + 10_000));
        assert!(c.is_flagged());
        assert_eq!(env.reasons(), vec!["host_behind_floor"]);
        assert_eq!(env.incidents[0].host_time_ms, T0 - 3_600_000);
        // Frozen while the host stays wrong, until the refetch.
        for _ in 0..REFETCH_EVERY - 1 {
            assert_eq!(c.read(&mut env), Ok(T0 + 10_000));
        }
        env.nts = Ok(T0 + 400_000);
        assert_eq!(c.read(&mut env), Ok(T0 + 400_000));
        assert!(c.is_flagged());
        // The host is fixed: the next refetch confirms it and clears the flag.
        env.host = Ok(T0 + 500_000);
        env.nts = Ok(T0 + 500_003);
        for _ in 0..REFETCH_EVERY - 1 {
            assert_eq!(c.read(&mut env), Ok(T0 + 400_000));
        }
        assert_eq!(c.read(&mut env), Ok(T0 + 500_000));
        assert!(!c.is_flagged());
    }

    #[test]
    fn no_receipt_for_host_behind_floor_fails_closed() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        env.host = Ok(T0 - 3_600_000);
        env.receipts = false;
        assert!(matches!(c.read(&mut env), Err(ClockError::NoReceipt(_))));
        assert!(c.is_failing_closed());
        // NTS is not consulted before the receipt.
        assert_eq!(env.nts_calls, 1);
        for _ in 0..REFETCH_EVERY - 1 {
            assert_eq!(c.read(&mut env), Err(ClockError::Unavailable));
        }
        env.receipts = true;
        assert_eq!(c.read(&mut env), Ok(T0));
        assert!(c.is_flagged());
        assert_eq!(env.incidents.len(), 2);
    }

    #[test]
    fn a_forged_receipt_is_no_receipt() {
        struct Forger(Fake);
        impl Env for Forger {
            fn host_time_ms(&mut self) -> Result<i64, ClockError> {
                self.0.host_time_ms()
            }
            fn nts_quorum(&mut self, f: i64) -> Result<NtsSample, ClockError> {
                self.0.nts_quorum(f)
            }
            fn post_incident(&mut self, _: &str, body: &[u8]) -> Result<Vec<u8>, String> {
                let inc: Incident = serde_json::from_slice(body).unwrap();
                // Signed for another nonce.
                Ok(signed_receipt(&inc.enclave_id, "replayed", "inc-1"))
            }
            fn random_nonce(&mut self) -> Result<[u8; 32], ClockError> {
                Ok([1; 32])
            }
            fn persist(&mut self, s: &[u8]) {
                self.0.persist(s)
            }
            fn log(&mut self, c: bool, m: &str) {
                self.0.log(c, m)
            }
        }
        let mut env = Forger(Fake::new(T0));
        let mut c = configured(&mut env.0);
        c.read(&mut env).unwrap();
        env.0.host = Ok(T0 - 3_600_000);
        assert!(matches!(c.read(&mut env), Err(ClockError::NoReceipt(_))));
    }

    #[test]
    fn without_a_monitor_incidents_are_logged_and_nts_still_decides() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        c.read(&mut env).unwrap();
        env.host = Ok(T0 - 3_600_000);
        assert_eq!(c.read(&mut env), Ok(T0));
        assert!(c.is_flagged());
        assert!(env.incidents.is_empty());
        assert!(env.logs.iter().any(|(crit, l)| *crit && l.contains("host_behind_floor")));
        // NTS blocked: still fails closed.
        let mut env2 = Fake::new(T0);
        let mut c2 = Clock::new();
        c2.read(&mut env2).unwrap();
        env2.host = Ok(T0 - 3_600_000);
        env2.nts = Err(());
        assert!(c2.read(&mut env2).is_err());
    }

    #[test]
    fn flagged_refetch_failure_fails_closed() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        c.read(&mut env).unwrap();
        env.host = Ok(T0 - 3_600_000);
        c.read(&mut env).unwrap();
        env.nts = Err(());
        for _ in 0..REFETCH_EVERY - 1 {
            c.read(&mut env).unwrap();
        }
        assert!(c.read(&mut env).is_err());
        assert!(c.is_failing_closed());
        assert!(c.read(&mut env).is_err());
    }

    #[test]
    fn frozen_time_never_goes_below_a_previous_read() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        // The host runs an hour fast and is read.
        env.host = Ok(T0 + 3_600_000);
        assert_eq!(c.read(&mut env), Ok(T0 + 3_600_000));
        // The monitor catches it; NTS agrees with the monitor.
        env.nts = Ok(T0 + 60_000);
        let r = poll(&mut c, &mut env, T0 + 60_000).unwrap();
        assert_eq!(r.verdict, "host_clock_wrong");
        assert!(r.flagged);
        assert_eq!(r.floor_ms, T0 + 60_000);
        // Frozen, but not below what was already returned.
        assert_eq!(c.read(&mut env), Ok(T0 + 3_600_000));
    }

    #[test]
    fn poll_in_sync_raises_the_floor_from_the_confirmed_host() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        env.host = Ok(T0 + 300_000);
        let r = poll(&mut c, &mut env, T0 + 299_000).unwrap();
        assert_eq!(r.verdict, "in_sync");
        assert_eq!(r.floor_ms, T0 + 300_000);
        assert_eq!(r.host_time_ms, T0 + 300_000);
        assert_eq!(r.trusted_time_ms, T0 + 300_000);
        assert_eq!(r.runtime, "mini");
        assert_eq!(r.reason, "");
        assert_eq!(r.nts, NtsReply::default());
        assert_eq!(r.config_key_id, config(1).key_id());
        assert_eq!(env.nts_calls, 1);
        // Sealed.
        let restored = Clock::restore(&env.sealed).unwrap();
        assert_eq!(restored.floor_ms(), T0 + 300_000);
        assert!(restored.config().is_some());
    }

    #[test]
    fn poll_below_the_floor_is_ignored() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        let r = poll(&mut c, &mut env, T0 - 60_000).unwrap();
        assert_eq!(r.verdict, "ignored_stale");
        assert_eq!(c.floor_ms(), T0);
    }

    #[test]
    fn poll_with_a_wrong_monitor_keeps_the_host_and_sends_no_incident() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        let r = poll(&mut c, &mut env, T0 + 3_600_000).unwrap();
        assert_eq!(r.verdict, "monitor_clock_wrong");
        assert!(!r.flagged);
        assert_eq!(r.nts.time_ms, T0);
        assert_eq!(r.nts.servers.len(), 2);
        // In the reply only: the monitor re-polls after an incident.
        assert_eq!(c.read(&mut env), Ok(T0));
        assert!(env.incidents.is_empty());
        // The monitor's time never became the floor.
        assert_eq!(c.floor_ms(), T0);
        poll(&mut c, &mut env, T0 + 3_600_000).unwrap();
        assert_eq!(c.read(&mut env), Ok(T0));
    }

    #[test]
    fn poll_with_a_wrong_host_freezes_and_sends_no_incident() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        env.host = Ok(T0 - 600_000 + 5_000);
        env.nts = Ok(T0 + 5_000);
        env.receipts = false;
        let r = poll(&mut c, &mut env, T0 + 5_000).unwrap();
        assert_eq!(r.verdict, "host_clock_wrong");
        assert_eq!(r.reason, "host_clock_wrong");
        assert!(r.flagged);
        assert_eq!(r.trusted_time_ms, T0 + 5_000);
        assert!(!c.is_failing_closed());
        // Frozen; in the reply only, no incident.
        assert_eq!(c.read(&mut env), Ok(T0 + 5_000));
        assert!(env.incidents.is_empty());
    }

    #[test]
    fn poll_without_nts_is_unavailable_and_fails_closed() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        env.nts = Err(());
        match poll(&mut c, &mut env, T0 + 3_600_000) {
            Err(PollError::Unavailable { reason, floor_ms, host_time_ms, .. }) => {
                assert_eq!(reason, "nts_unreachable");
                assert_eq!(floor_ms, T0);
                assert_eq!(host_time_ms, T0);
            }
            other => panic!("{other:?}"),
        }
        assert!(c.is_failing_closed());
        assert_eq!(c.read(&mut env), Err(ClockError::Unavailable));
        assert!(env.incidents.is_empty());

        // A poll in sync while failing closed still gets a reply.
        let r = poll(&mut c, &mut env, T0).unwrap();
        assert_eq!(r.verdict, "in_sync");
        assert_eq!(r.reason, "nts_unreachable");
        assert_eq!(r.trusted_time_ms, 0);
        assert_eq!(r.nts, NtsReply::default());

        // NTS back: the next poll that needs it settles the outage.
        env.nts = Ok(T0);
        let r = poll(&mut c, &mut env, T0 + 3_600_000).unwrap();
        assert_eq!(r.verdict, "monitor_clock_wrong");
        assert_eq!(r.reason, "");
        assert_eq!(r.trusted_time_ms, T0);
        assert!(!c.is_failing_closed());
    }

    #[test]
    fn a_poll_in_sync_raises_the_floor_by_at_most_an_hour_without_nts() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        // Host and monitor agree on a date far in the future; NTS does not.
        let far = T0 + 74 * 365 * 86_400_000;
        env.host = Ok(far);
        let r = poll(&mut c, &mut env, far).unwrap();
        assert_eq!(r.verdict, "host_clock_wrong");
        assert_eq!(c.floor_ms(), T0);
        assert!(c.is_flagged());
        // Within an hour: no NTS needed.
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        env.host = Ok(T0 + 3_000_000);
        let r = poll(&mut c, &mut env, T0 + 3_000_000).unwrap();
        assert_eq!(r.verdict, "in_sync");
        assert_eq!(c.floor_ms(), T0 + 3_000_000);
        assert_eq!(env.nts_calls, 1);
        // Beyond, confirmed by NTS: taken.
        env.host = Ok(T0 + 3_000_000 + 7_200_000);
        env.nts = Ok(T0 + 3_000_000 + 7_200_000);
        let r = poll(&mut c, &mut env, T0 + 3_000_000 + 7_200_000).unwrap();
        assert_eq!(r.verdict, "in_sync");
        assert_eq!(r.nts.servers.len(), 2);
        assert_eq!(c.floor_ms(), T0 + 3_000_000 + 7_200_000);
    }

    #[test]
    fn reads_between_polls_never_reach_nts() {
        let mut env = Fake::new(T0);
        let mut c = configured(&mut env);
        c.read(&mut env).unwrap();
        let calls = env.nts_calls;
        // However many reads come between two polls, an unflagged clock
        // answers them from the host and the floor alone.
        env.nts = Ok(T0 + 900_000);
        for _ in 0..10_000 {
            assert_eq!(c.read(&mut env), Ok(T0));
        }
        assert_eq!(env.nts_calls, calls);
        assert!(!c.is_flagged());
    }

    #[test]
    fn a_signed_poll_retries_nts_while_failing_closed() {
        let mut env = Fake::new(T0);
        env.nts = Err(());
        let mut c = configured(&mut env);
        assert!(c.read(&mut env).is_err());
        assert!(c.is_failing_closed());
        let calls = env.nts_calls;
        // A forged poll triggers nothing.
        let mut bad = signed_poll("enc-1", T0, 1);
        bad.seq = 9;
        assert!(c.poll(&mut env, &serde_json::to_vec(&bad).unwrap(), "mini").is_err());
        assert_eq!(env.nts_calls, calls);
        // A signed one retries NTS at once, and recovers.
        env.nts = Ok(T0);
        let r = poll(&mut c, &mut env, T0).unwrap();
        assert_eq!(env.nts_calls, calls + 1);
        assert!(!c.is_failing_closed());
        assert_eq!(r.trusted_time_ms, T0);
        assert_eq!(c.read(&mut env), Ok(T0));
    }

    #[test]
    fn each_condition_is_reported_once_until_confirmed() {
        let mut env = Fake::new(T0);
        env.nts = Err(());
        let mut c = configured(&mut env);
        // Boot fetch fails, and keeps failing across retries.
        assert!(c.read(&mut env).is_err());
        for _ in 0..3 * REFETCH_EVERY {
            let _ = c.read(&mut env);
        }
        assert_eq!(env.reasons(), vec!["nts_unreachable"]);
        // Recovery confirms the host; a new outage is reported again.
        env.nts = Ok(T0);
        for _ in 0..REFETCH_EVERY {
            let _ = c.read(&mut env);
        }
        assert!(!c.is_failing_closed());
        env.host = Ok(T0 - 3_600_000);
        c.read(&mut env).unwrap();
        assert_eq!(env.reasons(), vec!["nts_unreachable", "host_behind_floor"]);
    }

    #[test]
    fn poll_authentication() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        let body = serde_json::to_vec(&signed_poll("enc-1", T0, 1)).unwrap();
        assert_eq!(c.poll(&mut env, &body, "mini"), Err(PollError::NotConfigured));
        let mut c = configured(&mut env);
        let mut p = signed_poll("enc-1", T0, 1);
        p.t_ms += 1;
        let body = serde_json::to_vec(&p).unwrap();
        assert!(matches!(c.poll(&mut env, &body, "mini"), Err(PollError::Wire(WireError::Unauthorized(_)))));
        assert!(matches!(c.poll(&mut env, b"{", "mini"), Err(PollError::Wire(WireError::BadRequest(_)))));
        // Nothing was fetched for a refused poll.
        assert_eq!(env.nts_calls, 0);
    }

    #[test]
    fn config_versions() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        let v3 = serde_json::to_vec(&config(3).wire).unwrap();
        assert!(c.set_config(&mut env, &v3).unwrap().applied);
        // Same again: no-op, not an error.
        let ack = c.set_config(&mut env, &v3).unwrap();
        assert!(!ack.applied);
        assert_eq!(ack.config_version, 3);
        // Lower: refused.
        let v2 = serde_json::to_vec(&config(2).wire).unwrap();
        assert_eq!(c.set_config(&mut env, &v2), Err(ConfigError::Stale { current: 3 }));
        // Same version with other content: succeeds as a no-op, keeps the
        // config in place.
        let mut w = config(3).wire;
        w.incident_url = "https://other.example/x".to_string();
        let ack = c.set_config(&mut env, &serde_json::to_vec(&w).unwrap()).unwrap();
        assert!(!ack.applied);
        assert_eq!(c.config().unwrap().wire.incident_url, config(3).wire.incident_url);
        let v4 = serde_json::to_vec(&config(4).wire).unwrap();
        assert!(c.set_config(&mut env, &v4).unwrap().applied);
        assert!(matches!(c.set_config(&mut env, b"{}"), Err(ConfigError::Wire(_))));
    }

    #[test]
    fn restore_never_below_min_and_always_refetches() {
        let mut env = Fake::new(T0);
        let sealed = serde_json::to_vec(&Sealed {
            v: SEALED_VERSION,
            floor_ms: 5,
            flagged: true,
            reason: "host_clock_wrong".to_string(),
            config: None,
        })
        .unwrap();
        let mut c = Clock::restore(&sealed).unwrap();
        assert_eq!(c.floor_ms(), MIN_TRUSTED_TIME_MS);
        assert!(c.is_flagged());
        assert!(c.is_failing_closed());
        // The boot fetch finds the host fine and clears the restored flag.
        assert_eq!(c.read(&mut env), Ok(T0));
        assert!(!c.is_flagged());
        assert!(Clock::restore(b"junk").is_err());
    }

    #[test]
    fn boot_with_a_wrong_host_reports_and_freezes() {
        let mut env = Fake::new(T0 - 7_200_000);
        env.nts = Ok(T0);
        let mut c = configured(&mut env);
        assert_eq!(c.read(&mut env), Ok(T0));
        assert!(c.is_flagged());
        assert_eq!(env.reasons(), vec!["host_clock_wrong"]);
        assert_eq!(env.incidents[0].nts_time_ms, T0);
        // A lost receipt does not fail closed here.
        let mut env = Fake::new(T0 - 7_200_000);
        env.nts = Ok(T0);
        env.receipts = false;
        let mut c = configured(&mut env);
        assert_eq!(c.read(&mut env), Ok(T0));
    }

    #[test]
    fn a_host_that_jumps_forward_does_not_move_the_floor() {
        let mut env = Fake::new(T0);
        let mut c = Clock::new();
        c.read(&mut env).unwrap();
        env.host = Ok(T0 + 86_400_000);
        c.read(&mut env).unwrap();
        assert_eq!(c.floor_ms(), T0);
        assert_eq!(Clock::restore(&c.seal()).unwrap().floor_ms(), T0);
    }
}
