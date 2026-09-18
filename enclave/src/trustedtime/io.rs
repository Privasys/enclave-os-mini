// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! How the clock waits: suspending the request task that reads the time, or
//! blocking the enclave.
//!
//! When a clock operation was started where no lock is held (the clock's own
//! routes, at the top of their request task; WASM builds only, see
//! `enclave_os_wasm::executor`), its NTS fetch and incident POST go over
//! sockets the host proxy drives, and their network waits suspend the task:
//! the enclave keeps serving other requests. Anywhere else (a time read,
//! which may come from under any lock; start-up; the event loop; a guest
//! call's synchronous host function; a build without tasks) they block on
//! the host's RPC sockets, as before.

use core::cell::Cell;
use core::future::Future;
use core::task::Context;

std::thread_local! {
    /// Whether the clock operation running now was declared lock-free by
    /// its caller (see `with_clock`): only then may it suspend.
    static LOCK_FREE_OP: Cell<bool> = Cell::new(false);
}

/// Marks the clock operation that holds it as lock-free (or not) for its
/// duration.
pub(crate) struct SuspendScope {
    prev: bool,
}

impl SuspendScope {
    pub(crate) fn enter(lock_free: bool) -> Self {
        Self { prev: LOCK_FREE_OP.with(|c| c.replace(lock_free)) }
    }
}

impl Drop for SuspendScope {
    fn drop(&mut self) {
        LOCK_FREE_OP.with(|c| c.set(self.prev));
    }
}

/// Whether the network waits of the running clock operation can suspend
/// the caller instead of blocking: a lock-free operation, in a task that can
/// suspend, with the proxy's sockets available.
pub(crate) fn can_suspend() -> bool {
    #[cfg(feature = "wasm")]
    {
        LOCK_FREE_OP.with(|c| c.get())
            && enclave_os_wasm::executor::can_suspend()
            && enclave_os_egress::netchan::is_available()
    }
    #[cfg(not(feature = "wasm"))]
    {
        false
    }
}

/// Run `fut` to completion: suspending the task when `suspend` is set
/// (it must come from [`can_suspend`]), polling in place otherwise (the
/// future then only uses blocking sockets and never waits).
pub(crate) fn run<F: Future>(suspend: bool, fut: F) -> F::Output {
    #[cfg(feature = "wasm")]
    if suspend {
        return enclave_os_wasm::executor::block_on(fut);
    }
    let _ = suspend;
    let mut fut = core::pin::pin!(fut);
    let mut cx = Context::from_waker(core::task::Waker::noop());
    loop {
        if let core::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// Who is calling: the running task's id, or 0 outside tasks.
pub(crate) fn caller_id() -> usize {
    #[cfg(feature = "wasm")]
    {
        enclave_os_wasm::executor::current_task_id()
    }
    #[cfg(not(feature = "wasm"))]
    {
        0
    }
}

/// Whether the caller can wait for another task (it is a task that can
/// suspend).
pub(crate) fn can_wait() -> bool {
    #[cfg(feature = "wasm")]
    {
        enclave_os_wasm::executor::can_suspend()
    }
    #[cfg(not(feature = "wasm"))]
    {
        false
    }
}

/// Suspend the calling task until `ready` returns true. `ready` registers
/// the waker before returning false. Only call when [`can_wait`].
pub(crate) fn wait_until(mut ready: impl FnMut(&mut Context<'_>) -> bool) {
    #[cfg(feature = "wasm")]
    enclave_os_wasm::executor::block_on(core::future::poll_fn(|cx| {
        if ready(cx) {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    }));
    #[cfg(not(feature = "wasm"))]
    let _ = &mut ready;
}
