// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Trusted time: the one place the enclave reads the time.
//!
//! The host answers every time read, and a host that rolls its clock back
//! could get expired credentials accepted (quotes, certificates, tokens,
//! vouchers). Every time read in the enclave therefore goes through
//! [`now_ms`] (the OCall vtable's `get_current_time[_ms]` point here),
//! which runs the [`enclave_os_clock::state::Clock`] state machine:
//!
//! - never less than the previous read, never below the sealed floor;
//! - a boot NTS fetch before the first read is answered;
//! - a host caught wrong (by the platform monitor's signed poll, or by
//!   going back below the floor) yields the NTS time frozen at the fetch,
//!   refetched every 100 reads until NTS confirms the host again;
//! - a host that went back below the floor is reported to the monitor and
//!   fails closed without its signed receipt; the other incidents are
//!   reported after the fact (all are logged only while no monitor is
//!   configured);
//! - no NTS quorum when one is needed fails closed.
//!
//! When there is no trusted time, reads return
//! [`NO_TRUSTED_TIME`](enclave_os_common::ocall::NO_TRUSTED_TIME) and every
//! caller fails closed. A clock that cannot answer never answers 0.
//!
//! Reading `std::time::SystemTime` directly would bypass all of this (the
//! Teaclave sysroot answers it with its own untrusted ocall); it is a
//! disallowed method for clippy in every enclave crate. The TLS stacks that
//! verify a peer get the same time through [`RustlsTime`]; the RA-TLS
//! server serves with [`ServingTime`], which never fails.

mod io;
pub mod nts;

use std::cell::Cell;
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::vec::Vec;

use enclave_os_clock::quorum::NtsSample;
use enclave_os_clock::state::{Clock, Env};
use enclave_os_clock::{ClockError, MIN_TRUSTED_TIME_MS};
use enclave_os_common::ocall::NO_TRUSTED_TIME;

use crate::crypto::sealing;
use crate::{enclave_log_error, enclave_log_info};

/// KV table and tag of the sealed clock state (floor, flag, monitor config).
const SYSTEM_TABLE: &[u8] = b"system";
const CLOCK_TAG_SEED: &[u8] = b"__enclave_os_trusted_clock__";
/// AAD of the MRENCLAVE seal of the clock state.
const CLOCK_AAD: &[u8] = b"enclave_os_trusted_clock_v1";

static CLOCK: OnceLock<Mutex<Clock>> = OnceLock::new();

/// What a read made from inside a clock operation returns (see
/// [`with_clock`]): the frozen time, never below the floor or a previous
/// read.
static FROZEN_MS: AtomicI64 = AtomicI64::new(MIN_TRUSTED_TIME_MS);

/// Whether trusted time is failing closed, as of the last clock operation.
/// Lets the times the enclave issues itself skip a read that would only
/// fail (or start an NTS retry in the middle of a TLS handshake).
static FAILING_CLOSED: AtomicBool = AtomicBool::new(false);

std::thread_local! {
    /// Who runs the current clock operation: a request task's id, or 0 for
    /// code outside tasks (start-up, the event loop). `None`: the clock is
    /// free.
    ///
    /// An operation can be suspended halfway (its NTS fetch or incident POST
    /// waits on the network, see [`nts`]), and the enclave serves other
    /// requests meanwhile, on this same thread. So ownership is per task,
    /// not per thread.
    static OWNER: Cell<Option<usize>> = Cell::new(None);
}

/// Tasks waiting for the clock to be free.
static WAITERS: Mutex<Vec<core::task::Waker>> = Mutex::new(Vec::new());

struct OwnerGuard;

impl Drop for OwnerGuard {
    fn drop(&mut self) {
        OWNER.with(|o| o.set(None));
        let waiters = core::mem::take(&mut *WAITERS.lock().unwrap_or_else(|e| e.into_inner()));
        for w in waiters {
            w.wake();
        }
    }
}

/// What [`with_clock`] could do.
enum Access<T> {
    Done(T),
    /// Called from inside the operation this caller is running: an incident
    /// report or NTS fetch goes through TLS stacks that read the time
    /// themselves. Those nested reads get the frozen time instead of waiting
    /// for themselves.
    Nested,
    /// Another task's operation is suspended and this caller cannot wait
    /// for it: a time read (it may hold a lock), code outside a task, or a
    /// guest call.
    Busy,
}

/// Run `f` on the clock, one operation at a time.
///
/// `lock_free` declares that the caller holds no lock another request may
/// take: only then may the operation suspend its task (its network waits,
/// or waiting for another task's operation). A task suspended while holding
/// a mutex would block the next request that takes it, on the enclave's one
/// thread, for ever. Time reads come from everywhere, under any lock, so
/// they pass `false` and block instead; the clock's own routes, at the top
/// of their request, pass `true`.
fn with_clock<T>(lock_free: bool, f: impl FnOnce(&mut Clock, &mut CoreEnv) -> T) -> Access<T> {
    let me = io::caller_id();
    loop {
        match OWNER.with(|o| o.get()) {
            None => break,
            Some(owner) if owner == me => return Access::Nested,
            Some(_) if lock_free && io::can_wait() => io::wait_until(|cx| {
                if OWNER.with(|o| o.get()).is_none() {
                    return true;
                }
                WAITERS.lock().unwrap_or_else(|e| e.into_inner()).push(cx.waker().clone());
                false
            }),
            Some(_) => return Access::Busy,
        }
    }
    // Uncontended: while an operation runs, OWNER keeps everyone else out.
    let cell = CLOCK.get_or_init(|| Mutex::new(load()));
    let mut clock = cell.lock().unwrap_or_else(|e| e.into_inner());
    OWNER.with(|o| o.set(Some(me)));
    let _guard = OwnerGuard;
    let _suspendable = io::SuspendScope::enter(lock_free);
    let r = f(&mut clock, &mut CoreEnv);
    FROZEN_MS.store(clock.frozen_ms(), Ordering::Relaxed);
    FAILING_CLOSED.store(clock.is_failing_closed(), Ordering::Relaxed);
    Access::Done(r)
}

/// Trusted time, Unix milliseconds. `Err(NO_TRUSTED_TIME)`: fail closed.
pub fn now_ms() -> Result<u64, i32> {
    match with_clock(false, |clock, env| clock.read(env)) {
        Access::Nested => Ok(FROZEN_MS.load(Ordering::Relaxed).max(0) as u64),
        // Another task's operation is under way: the state as of the last
        // operation. Failing closed stays failing closed; otherwise the
        // frozen time (the last read or the floor: time pauses, never goes
        // back) until the operation settles.
        Access::Busy if FAILING_CLOSED.load(Ordering::Relaxed) => Err(NO_TRUSTED_TIME),
        Access::Busy => Ok(FROZEN_MS.load(Ordering::Relaxed).max(0) as u64),
        Access::Done(Ok(t)) => Ok(t.max(0) as u64),
        Access::Done(Err(ClockError::Unavailable)) => Err(NO_TRUSTED_TIME),
        Access::Done(Err(e)) => {
            enclave_log_error!("trusted time unavailable: {}", e);
            Err(NO_TRUSTED_TIME)
        }
    }
}

/// Trusted time, Unix seconds. `Err(NO_TRUSTED_TIME)`: fail closed.
pub fn now_secs() -> Result<u64, i32> {
    now_ms().map(|t| t / 1_000)
}

/// A time for what this enclave issues itself (its own certificate
/// validity, the `quote_time` it stamps, leaf key rotation): trusted time
/// when there is one, otherwise the frozen floor. Never use it for a check
/// on something presented to the enclave; use [`now_secs`] and fail closed.
pub fn issue_secs() -> u64 {
    issue_ms() / 1_000
}

/// [`issue_secs`] in milliseconds. Never fails and never waits on NTS:
/// while trusted time is failing closed it is the frozen floor.
pub fn issue_ms() -> u64 {
    let frozen = FROZEN_MS.load(Ordering::Relaxed).max(0) as u64;
    if FAILING_CLOSED.load(Ordering::Relaxed) {
        return frozen;
    }
    now_ms().unwrap_or(frozen)
}

/// Run the boot NTS fetch now rather than on the first request.
pub fn boot() {
    match now_ms() {
        Ok(t) => enclave_log_info!("Trusted time ready: {} ms", t),
        Err(_) => enclave_log_error!("Trusted time not available yet: time-sensitive operations fail closed until it is"),
    }
}

// ---------------------------------------------------------------------------
//  Core routes: clock config (management-service) and floor poll (monitor)
// ---------------------------------------------------------------------------

/// `PUT /clock/config`: the monitor key, incident URL and this enclave's
/// id, sealed with the floor. The caller checks the manager role. Returns
/// `(status, JSON body)`: 200 with `{enclave_id, monitor_key_id,
/// config_version, applied}` (`applied` false for the version already in
/// place), 400 for an invalid config, 409 for a lower `config_version`.
pub fn handle_config(body: &[u8]) -> (u16, Vec<u8>) {
    use enclave_os_clock::state::ConfigError;
    match with_clock(true, |clock, env| clock.set_config(env, body)) {
        Access::Done(Ok(ack)) => (200, serde_json::to_vec(&ack).unwrap_or_default()),
        Access::Done(Err(ConfigError::Wire(e))) => json_error(400, &e.to_string()),
        Access::Done(Err(ConfigError::Stale { current })) => (
            409,
            serde_json::to_vec(&serde_json::json!({
                "error": "config_version is lower than the current one",
                "config_version": current,
            }))
            .unwrap_or_default(),
        ),
        Access::Nested | Access::Busy => json_error(503, "clock busy"),
    }
}

/// `POST /clock/poll`: the monitor's signed floor. No bearer: the Ed25519
/// signature with the configured monitor key is the authentication.
/// Returns `(status, JSON body)`: 200 with the poll reply, 400 for a
/// malformed body, 401 for a poll not signed by the configured key or not
/// for this enclave, 409 while no monitor is configured, 503 when host and
/// monitor disagree and there is no NTS quorum to settle it.
pub fn handle_poll(body: &[u8]) -> (u16, Vec<u8>) {
    use enclave_os_clock::state::PollError;
    use enclave_os_clock::wire::WireError;
    match with_clock(true, |clock, env| clock.poll(env, body, "mini")) {
        Access::Done(Ok(reply)) => (200, serde_json::to_vec(&reply).unwrap_or_default()),
        Access::Done(Err(PollError::Wire(WireError::BadRequest(m)))) => json_error(400, &m),
        Access::Done(Err(PollError::Wire(WireError::Unauthorized(m)))) => json_error(401, m),
        Access::Done(Err(PollError::NotConfigured)) => json_error(409, "clock not configured"),
        Access::Done(Err(PollError::Unavailable { reason, host_time_ms, floor_ms, detail })) => (
            503,
            serde_json::to_vec(&serde_json::json!({
                "error": reason,
                "detail": detail,
                "host_time_ms": host_time_ms,
                "floor_ms": floor_ms,
            }))
            .unwrap_or_default(),
        ),
        Access::Nested | Access::Busy => json_error(503, "clock busy"),
    }
}

fn json_error(status: u16, msg: &str) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap_or_default())
}

// ---------------------------------------------------------------------------
//  rustls
// ---------------------------------------------------------------------------

/// The trusted clock for rustls configs (certificate validity checks,
/// ticket lifetimes). No trusted time makes the handshake fail.
#[derive(Debug)]
pub struct RustlsTime;

/// The clock of the RA-TLS server config. Serving TLS is not a decision
/// the enclave makes on trusted time (its client-certificate check does
/// not look at dates; ticket lifetimes are bookkeeping), so it gets
/// [`issue_ms`] and never fails: while trusted time is failing closed the
/// enclave must stay reachable, above all for the monitor's poll.
/// Verification decisions keep [`RustlsTime`] and fail closed.
#[derive(Debug)]
pub struct ServingTime;

impl rustls::time_provider::TimeProvider for ServingTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(issue_ms())))
    }
}

impl rustls::time_provider::TimeProvider for RustlsTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        now_ms()
            .ok()
            .map(|ms| rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_millis(ms)))
    }
}

// ---------------------------------------------------------------------------
//  Environment of the state machine
// ---------------------------------------------------------------------------

struct CoreEnv;

impl Env for CoreEnv {
    fn host_time_ms(&mut self) -> Result<i64, ClockError> {
        crate::ocall::host_time_ms()
            .map(|t| t.min(i64::MAX as u64) as i64)
            .map_err(|_| ClockError::HostUnavailable)
    }

    fn nts_quorum(&mut self, floor_ms: i64) -> Result<NtsSample, ClockError> {
        nts::quorum(floor_ms)
    }

    fn post_incident(&mut self, url: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        post_incident(url, body)
    }

    fn random_nonce(&mut self) -> Result<[u8; 32], ClockError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut n = [0u8; 32];
        SystemRandom::new()
            .fill(&mut n)
            .map_err(|_| ClockError::NoReceipt("rng failure".into()))?;
        Ok(n)
    }

    fn persist(&mut self, sealed: &[u8]) {
        if let Err(e) = store(sealed) {
            enclave_log_error!("trusted time: sealing the clock state failed: {}", e);
        }
    }

    fn log(&mut self, critical: bool, msg: &str) {
        if critical {
            enclave_log_error!("{}", msg);
        } else {
            enclave_log_info!("{}", msg);
        }
    }
}

/// POST an incident to the monitor and return the body of its 2xx reply.
///
/// The enclave cannot time the wait itself (it has no clock): the host
/// socket timeouts of the connection bound it (see
/// [`nts::post_to_monitor`]), and anything but a reply carrying a valid
/// signed receipt counts as no receipt.
fn post_incident(url: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    nts::post_to_monitor(url, body, FROZEN_MS.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
//  Sealed state
// ---------------------------------------------------------------------------

fn storage_tag() -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, CLOCK_TAG_SEED).as_ref().to_vec()
}

fn store(sealed: &[u8]) -> Result<(), String> {
    let blob = sealing::seal_with_mrenclave(sealed, CLOCK_AAD)?;
    crate::ocall::kv_store_put(SYSTEM_TABLE, &storage_tag(), &blob).map_err(|e| format!("host KV put: {e}"))
}

fn load() -> Clock {
    let clock = match crate::ocall::kv_store_get(SYSTEM_TABLE, &storage_tag(), 64 * 1024) {
        Ok(Some(blob)) => match sealing::unseal_with_mrenclave(&blob) {
            Ok((plaintext, aad)) if aad == CLOCK_AAD => match Clock::restore(&plaintext) {
                Ok(c) => {
                    enclave_log_info!("Trusted time: sealed floor {} ms restored", c.floor_ms());
                    c
                }
                Err(e) => {
                    enclave_log_error!("Trusted time: {}; starting from the build floor", e);
                    Clock::new()
                }
            },
            Ok(_) => {
                enclave_log_error!("Trusted time: sealed state has the wrong AAD; starting from the build floor");
                Clock::new()
            }
            Err(e) => {
                enclave_log_error!("Trusted time: unseal failed ({}); starting from the build floor", e);
                Clock::new()
            }
        },
        Ok(None) => {
            enclave_log_info!("Trusted time: no sealed floor yet; starting from the build floor");
            Clock::new()
        }
        Err(e) => {
            enclave_log_error!("Trusted time: host KV get failed ({}); starting from the build floor", e);
            Clock::new()
        }
    };
    FROZEN_MS.store(clock.frozen_ms(), Ordering::Relaxed);
    clock
}
