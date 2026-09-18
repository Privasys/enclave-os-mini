// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Driving wasmtime's async entry points inside the enclave.
//!
//! Every guest call runs on a wasmtime fiber, so an `async` host function
//! (e.g. `https.fetch`) can suspend the guest mid-call without the guest
//! noticing. [`block_on`] polls such a call to completion; [`FiberStacks`]
//! provides the fibers' stacks.

use core::future::Future;
use core::ops::Range;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use std::boxed::Box;
use std::vec::Vec;

use wasmtime::{StackCreator, StackMemory};

/// Poll `fut` to completion on this thread.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
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

/// Heap-allocated fiber stacks, registered with the SGX runtime.
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
pub struct FiberStacks;

unsafe impl StackCreator for FiberStacks {
    fn new_stack(&self, size: usize, _zeroed: bool) -> wasmtime::Result<Box<dyn StackMemory>> {
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

        Ok(Box::new(FiberStack { buf, alt_stack }))
    }
}

struct FiberStack {
    buf: Vec<u128>,
    /// Handle from `sgx_register_alt_stack` (0 outside SGX).
    alt_stack: usize,
}

unsafe impl StackMemory for FiberStack {
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

impl Drop for FiberStack {
    fn drop(&mut self) {
        #[cfg(target_vendor = "teaclave")]
        unsafe {
            sgx_unregister_alt_stack(self.alt_stack);
        }
        let _ = self.alt_stack;
    }
}
