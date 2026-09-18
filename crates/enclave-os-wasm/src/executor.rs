// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Coroutines inside the enclave: fibers for guest calls, tasks for requests.
//!
//! Every guest call runs on a wasmtime fiber, so an `async` host function
//! (e.g. `https.fetch`) can suspend the guest mid-call without the guest
//! noticing. The call is a future; [`block_on`] drives it.
//!
//! A [`Task`] runs a synchronous function (the ingress request handler) on
//! its own fiber. When code inside a task reaches [`block_on`] and the future
//! is not ready, the task suspends and control returns to whoever resumed it
//! (the enclave event loop), which keeps serving other connections. The
//! task's waker marks it runnable again; the event loop then resumes it and
//! [`block_on`] polls once more.
//!
//! Outside a task (enclave start-up, raft replay) [`block_on`] polls in a
//! loop, as before.
//!
//! Everything here runs on the enclave's single event-loop thread.

use core::cell::Cell;
use core::future::Future;
use core::ops::Range;
use core::pin::pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use std::boxed::Box;
use std::string::String;
use std::sync::{Arc, Mutex};
use std::task::Wake;
use std::vec::Vec;

use wasmtime::{StackCreator, StackMemory};
use wasmtime_internal_fiber::{Fiber, RuntimeFiberStack, Suspend};

/// Stack size of a request task: the same as the enclave thread stack
/// (`StackMaxSize`), since a task runs the handler that used to run there.
const TASK_STACK_SIZE: usize = 1024 * 1024;

/// Task stacks kept for reuse.
const TASK_STACK_POOL: usize = 8;

// ---------------------------------------------------------------------------
//  block_on
// ---------------------------------------------------------------------------

/// Poll `fut` to completion. Inside a task, the task suspends while `fut` is
/// pending; elsewhere this polls in a loop.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let ctx = CURRENT.with(|c| c.get());
    if ctx.is_null() {
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
    // SAFETY: CURRENT points at the running task's context, which outlives
    // this call (the task owns it and is resumed through `Task::resume`).
    let ctx = unsafe { &*ctx };
    let mut cx = Context::from_waker(&ctx.waker);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        // SAFETY: `suspend` was set when the task's fiber started and stays
        // valid until the fiber returns.
        unsafe { (ctx.yield_now)(ctx.suspend.get()) };
    }
}

/// Whether the caller runs inside a [`Task`].
pub fn in_task() -> bool {
    CURRENT.with(|c| !c.get().is_null())
}

// ---------------------------------------------------------------------------
//  Tasks
// ---------------------------------------------------------------------------

std::thread_local! {
    /// Context of the task currently running on this thread, or null.
    static CURRENT: Cell<*const TaskCtx> = Cell::new(ptr::null());
}

/// Set when any task is woken; cleared by [`take_runnable`].
static RUNNABLE: AtomicBool = AtomicBool::new(false);

/// Whether a task was woken since the last call. The event loop uses this to
/// skip scanning its tasks when none can make progress.
pub fn take_runnable() -> bool {
    RUNNABLE.swap(false, Ordering::AcqRel)
}

/// Whether a task was woken, without clearing the flag.
pub fn has_runnable() -> bool {
    RUNNABLE.load(Ordering::Acquire)
}

struct TaskFlag {
    woken: AtomicBool,
}

impl Wake for TaskFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        RUNNABLE.store(true, Ordering::Release);
    }
}

struct TaskCtx {
    /// The running fiber's `Suspend`, type-erased; set when it starts.
    suspend: Cell<*mut ()>,
    /// `Suspend::suspend` for the task's return type.
    yield_now: unsafe fn(*mut ()),
    waker: Waker,
    flag: Arc<TaskFlag>,
}

unsafe fn yield_now<R>(suspend: *mut ()) {
    unsafe { (*suspend.cast::<Suspend<(), (), R>>()).suspend(()) }
}

/// A function running on its own fiber, suspended whenever it waits in
/// [`block_on`].
pub struct Task<R: 'static> {
    ctx: Box<TaskCtx>,
    fiber: Option<Fiber<'static, (), (), R>>,
}

impl<R: 'static> Task<R> {
    /// Prepare `f` to run as a task. Nothing runs until [`Task::resume`].
    pub fn spawn(f: impl FnOnce() -> R + 'static) -> Result<Self, String> {
        let flag = Arc::new(TaskFlag {
            woken: AtomicBool::new(true),
        });
        let ctx = Box::new(TaskCtx {
            suspend: Cell::new(ptr::null_mut()),
            yield_now: yield_now::<R>,
            waker: Waker::from(flag.clone()),
            flag,
        });
        let ctx_ptr: *const TaskCtx = &*ctx;
        let stack = take_task_stack()?;
        let fiber = Fiber::new(stack, move |(), suspend: &mut Suspend<(), (), R>| {
            // SAFETY: the task owns `ctx` (boxed, so it does not move) and
            // outlives its fiber.
            unsafe { (*ctx_ptr).suspend.set((suspend as *mut Suspend<(), (), R>).cast()) };
            f()
        })
        .map_err(|(e, stack)| {
            give_back_task_stack(stack);
            format!("task fiber creation failed: {e:#}")
        })?;
        Ok(Self {
            ctx,
            fiber: Some(fiber),
        })
    }

    /// Whether the task can make progress (it was woken, or never ran).
    pub fn is_woken(&self) -> bool {
        self.ctx.flag.woken.load(Ordering::Acquire)
    }

    /// Run the task until it suspends (`None`) or returns (`Some`).
    ///
    /// Panics if the task already returned.
    pub fn resume(&mut self) -> Option<R> {
        let fiber = self.fiber.as_ref().expect("resumed a finished task");
        self.ctx.flag.woken.store(false, Ordering::Release);
        let result = {
            let _current = CurrentGuard::enter(&self.ctx);
            fiber.resume(())
        };
        match result {
            Ok(out) => {
                if let Some(fiber) = self.fiber.take() {
                    give_back_task_stack(fiber.into_stack());
                }
                Some(out)
            }
            Err(()) => None,
        }
    }
}

// SAFETY: a task is created, resumed and dropped on the enclave's event-loop
// thread only; it is `Send` so that the ingress server holding it can live in
// the enclave's global state behind a mutex.
unsafe impl<R: Send + 'static> Send for Task<R> {}

impl<R: 'static> Drop for Task<R> {
    fn drop(&mut self) {
        // A fiber must not be dropped mid-execution: its frames would be
        // discarded without running their destructors. Only an enclave
        // shutting down drops an unfinished task; leak it.
        if let Some(fiber) = self.fiber.take() {
            if !fiber.done() {
                core::mem::forget(fiber);
            }
        }
    }
}

/// Makes a task current for the duration of a resume, restoring the previous
/// value even if the task panics.
struct CurrentGuard {
    prev: *const TaskCtx,
}

impl CurrentGuard {
    fn enter(ctx: &TaskCtx) -> Self {
        let prev = CURRENT.with(|c| c.replace(ctx));
        Self { prev }
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.prev));
    }
}

static TASK_STACKS: Mutex<Vec<wasmtime_internal_fiber::FiberStack>> = Mutex::new(Vec::new());

fn take_task_stack() -> Result<wasmtime_internal_fiber::FiberStack, String> {
    if let Some(stack) = TASK_STACKS.lock().ok().and_then(|mut pool| pool.pop()) {
        return Ok(stack);
    }
    let stack = FiberStack::new(TASK_STACK_SIZE).map_err(|e| format!("{e:#}"))?;
    wasmtime_internal_fiber::FiberStack::from_custom(Box::new(stack))
        .map_err(|e| format!("task stack: {e:#}"))
}

fn give_back_task_stack(stack: wasmtime_internal_fiber::FiberStack) {
    if let Ok(mut pool) = TASK_STACKS.lock() {
        if pool.len() < TASK_STACK_POOL {
            pool.push(stack);
        }
    }
}

// ---------------------------------------------------------------------------
//  Fiber stacks
// ---------------------------------------------------------------------------

#[cfg(target_vendor = "teaclave")]
extern "C" {
    fn sgx_register_alt_stack(addr: *const u8, size: usize) -> usize;
    fn sgx_unregister_alt_stack(handle: usize) -> i32;
}

/// Heap-allocated fiber stacks for guest calls, registered with the SGX
/// runtime (see [`FiberStack`]).
pub struct FiberStacks;

unsafe impl StackCreator for FiberStacks {
    fn new_stack(&self, size: usize, _zeroed: bool) -> wasmtime::Result<Box<dyn StackMemory>> {
        Ok(Box::new(FiberStack::new(size)?))
    }
}

/// A heap-allocated fiber stack, registered with the SGX runtime.
///
/// The SGX runtime refuses an exception raised while the stack pointer is
/// outside the thread's own stack, and crashes the enclave instead. Our VEH
/// emulates CPUID (which faults inside SGX), and crates run CPUID lazily, so
/// any host code on a fiber could trigger one. Registering the stack makes
/// such an exception legal.
///
/// There is no guard page: an overflow runs into the heap below the stack.
/// wasmtime bounds the guest's own frames with `max_wasm_stack`; the rest of
/// `async_stack_size` is host-code headroom (see `WasmEngine::new`).
struct FiberStack {
    buf: Vec<u128>,
    /// Handle from `sgx_register_alt_stack` (0 outside SGX).
    alt_stack: usize,
}

impl FiberStack {
    fn new(size: usize) -> wasmtime::Result<Self> {
        // u128 elements keep the base 16-byte aligned; round the length up so
        // the top is aligned too.
        let words = size.div_ceil(16);
        let mut buf: Vec<u128> = Vec::new();
        buf.try_reserve_exact(words)
            .map_err(|_| wasmtime::format_err!("fiber stack allocation of {size} bytes failed"))?;
        buf.resize(words, 0);

        #[cfg(target_vendor = "teaclave")]
        let alt_stack = {
            let handle = unsafe { sgx_register_alt_stack(buf.as_ptr().cast(), buf.len() * 16) };
            if handle == 0 {
                wasmtime::bail!("fiber stack registration with the SGX runtime failed");
            }
            handle
        };
        #[cfg(not(target_vendor = "teaclave"))]
        let alt_stack = 0;

        Ok(Self { buf, alt_stack })
    }

    fn top(&self) -> *mut u8 {
        self.buf.as_ptr().wrapping_add(self.buf.len()) as *mut u8
    }

    fn range(&self) -> Range<usize> {
        let base = self.buf.as_ptr() as usize;
        base..base + self.buf.len() * 16
    }

    fn guard_range(&self) -> Range<*mut u8> {
        let base = self.buf.as_ptr() as *mut u8;
        base..base
    }
}

unsafe impl StackMemory for FiberStack {
    fn top(&self) -> *mut u8 {
        FiberStack::top(self)
    }

    fn range(&self) -> Range<usize> {
        FiberStack::range(self)
    }

    fn guard_range(&self) -> Range<*mut u8> {
        FiberStack::guard_range(self)
    }
}

unsafe impl RuntimeFiberStack for FiberStack {
    fn top(&self) -> *mut u8 {
        FiberStack::top(self)
    }

    fn range(&self) -> Range<usize> {
        FiberStack::range(self)
    }

    fn guard_range(&self) -> Range<*mut u8> {
        FiberStack::guard_range(self)
    }
}

impl Drop for FiberStack {
    fn drop(&mut self) {
        #[cfg(target_vendor = "teaclave")]
        unsafe {
            sgx_unregister_alt_stack(self.alt_stack);
        }
        let _ = self.alt_stack;
    }
}
