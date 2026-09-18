// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Custom wasmtime platform layer for SGX enclaves.
//!
//! Wasmtime's `sys::custom` API requires C-ABI functions for memory
//! management, trap handling, and system queries.
//!
//! ## Memory architecture
//!
//! SGX enclaves have two memory constraints:
//!
//! 1. **Heap pages** (EADD'd during ECREATE) have RW permissions.
//!    These CANNOT be made executable: EMODPE only extends EAUG'd pages.
//!
//! 2. **Dynamic pages** (EAUG'd via EDMM) can have flexible permissions,
//!    but EDMM operations hang on some server configurations.
//!
//! Our solution: pre-allocate an **RWX section** in the enclave ELF binary
//! using `global_asm!`. The `sgx_sign` tool creates EADD entries with RWX
//! permissions for these pages. Wasmtime gets code memory from this pool and
//! data memory from the heap.
//!
//! ## Which allocations are code
//!
//! `wasmtime_mmap_new` is not told what a mapping is for, but with the
//! features we build (no pooling allocator, no copy-on-write images, no
//! compiler) wasmtime asks for memory in exactly two ways:
//!
//! - `Mmap::new` (`prot = READ | WRITE`), reached only through `MmapVec`,
//!   which holds a code image: `Component::deserialize` copies the whole
//!   `.cwasm` into one and later makes its `.text` executable. These go to
//!   the pool, whatever their size.
//! - `Mmap::reserve` (`prot = NONE`), for linear memories and GC heaps, which
//!   are never executed. These go to the heap.
//!
//! Pool pages are tracked by [`PagePool`] and reclaimed when wasmtime unmaps
//! them, so loads, unloads, LRU evictions and redeploys reuse the same pages.
//! When the pool cannot hold a code image the allocation fails and wasmtime
//! fails that one load. Code never falls back to the heap: the enclave would
//! crash the first time it ran it. As a second line of defence,
//! `wasmtime_mprotect` refuses to make anything outside a pool allocation
//! executable, which also fails the load instead of the enclave.
//!
//! ## C API symbols provided
//!
//! | C API function               | SGX implementation                         |
//! |------------------------------|--------------------------------------------|
//! | `wasmtime_mmap_new`          | code image: RWX pool; reservation: heap    |
//! | `wasmtime_mprotect`          | no-op; EXEC outside the pool is refused    |
//! | `wasmtime_munmap`            | pool: pages reclaimed; heap: dealloc       |
//! | `wasmtime_mmap_remap`        | zero the range                             |
//! | `wasmtime_page_size`         | 4096                                       |
//! | `wasmtime_init_traps`        | `sgx_register_exception_handler` (VEH)     |
//! | `wasmtime_tls_get/set`       | `AtomicPtr` (single-threaded per TCS)      |
//! | `wasmtime_memory_image_*`    | disabled (no CoW / memfd in SGX)           |

#![allow(unused_unsafe)]

extern crate alloc;

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::code_pool::{FreeError, PagePool};

// =========================================================================
//  RWX Code Pool: pre-allocated executable memory
// =========================================================================

/// Page size (x86-64 SGX).
const PAGE_SIZE: usize = 4096;

/// Size of the RWX code pool (16 MiB).
///
/// Bounds the code images of all apps held at once (loaded apps, plus one
/// being loaded). Pages are reclaimed on unload, so this is a limit on what
/// is resident, not on how many loads the enclave serves.
const CODE_POOL_SIZE: usize = 16 * 1024 * 1024;

// Define an RWX section in the enclave ELF binary.
// The "awx" flags mean: Allocatable + Writable + eXecutable.
// sgx_sign will create EADD entries with RWX permissions.
core::arch::global_asm!(
    ".section .wasm_code, \"awx\", @progbits",
    ".balign 4096",
    ".globl _wasm_code_pool_start",
    "_wasm_code_pool_start:",
    ".space {size}",
    ".globl _wasm_code_pool_end",
    "_wasm_code_pool_end:",
    ".section .text",
    size = const CODE_POOL_SIZE,
);

extern "C" {
    static _wasm_code_pool_start: u8;
    static _wasm_code_pool_end: u8;
}

/// Which pool pages are in use.
static CODE_POOL: Mutex<PagePool> = Mutex::new(PagePool::new(CODE_POOL_SIZE / PAGE_SIZE));

/// Lock the pool bookkeeping. A panic while it was held cannot leave it
/// inconsistent (every update is a single `Vec` edit), so poisoning is
/// ignored rather than unwinding through an `extern "C"` function.
fn code_pool() -> MutexGuard<'static, PagePool> {
    CODE_POOL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn code_pool_base() -> usize {
    unsafe { &_wasm_code_pool_start as *const u8 as usize }
}

/// Allocate `size` bytes (page-aligned) of zeroed memory from the RWX code
/// pool. Returns null, having logged why, if no free run is long enough.
unsafe fn code_pool_alloc(size: usize) -> *mut u8 {
    let pages = size / PAGE_SIZE;
    let mut pool = code_pool();
    let Some(first) = pool.alloc(pages) else {
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] code pool: no room for a {} KiB code image ({} of {} KiB in use \
             by {} images, largest free run {} KiB); refusing the load",
            size / 1024,
            pool.in_use() * PAGE_SIZE / 1024,
            pool.total() * PAGE_SIZE / 1024,
            pool.allocation_count(),
            pool.largest_free_run() * PAGE_SIZE / 1024
        );
        return ptr::null_mut();
    };
    let addr = (code_pool_base() + first * PAGE_SIZE) as *mut u8;
    ptr::write_bytes(addr, 0, size);
    enclave_os_common::enclave_log_info!(
        "[sgx_platform] code pool: +{} KiB at {:p} ({} of {} KiB in use, peak {} KiB)",
        size / 1024,
        addr,
        pool.in_use() * PAGE_SIZE / 1024,
        pool.total() * PAGE_SIZE / 1024,
        pool.peak() * PAGE_SIZE / 1024
    );
    addr
}

/// Return a code pool allocation. Freed code is overwritten with `int3` so a
/// stale jump into it traps instead of running old code.
unsafe fn code_pool_free(addr: *mut u8, size: usize) {
    let offset = addr as usize - code_pool_base();
    let mut pool = code_pool();
    if offset % PAGE_SIZE != 0 {
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] code pool: unmap of unaligned {:p} ignored; pages kept",
            addr
        );
        return;
    }
    match pool.free(offset / PAGE_SIZE, size / PAGE_SIZE) {
        Ok(()) => {
            ptr::write_bytes(addr, 0xCC, size);
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] code pool: -{} KiB at {:p} ({} of {} KiB in use)",
                size / 1024,
                addr,
                pool.in_use() * PAGE_SIZE / 1024,
                pool.total() * PAGE_SIZE / 1024
            );
        }
        // Freeing pages other than exactly one allocation could hand out
        // code still in use; keep them (a leak, never a corruption).
        Err(FreeError::NotAllocated) => {
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] code pool: unmap of {:p} ({} KiB) matches no allocation; ignored",
                addr,
                size / 1024
            );
        }
        Err(FreeError::SizeMismatch { allocated }) => {
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] code pool: unmap of {:p} for {} KiB, allocation is {} KiB; \
                 pages kept",
                addr,
                size / 1024,
                allocated * PAGE_SIZE / 1024
            );
        }
    }
}

/// Whether an address lies within the RWX code pool section. Used by the VEH,
/// so it takes no lock.
fn is_code_pool(addr: *const u8) -> bool {
    let start = code_pool_base();
    let a = addr as usize;
    a >= start && a < start + CODE_POOL_SIZE
}

/// Whether `[addr, addr + size)` lies inside one live code pool allocation.
fn is_code_pool_allocation(addr: *const u8, size: usize) -> bool {
    if !is_code_pool(addr) || size == 0 {
        return false;
    }
    let offset = addr as usize - code_pool_base();
    let first = offset / PAGE_SIZE;
    let last = (offset + size - 1) / PAGE_SIZE;
    code_pool().is_allocated(first, last - first + 1)
}

// =========================================================================
//  Heap allocation helpers (for data/linear memory)
// =========================================================================

fn page_align(size: usize) -> usize {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Allocate page-aligned memory from the enclave heap.
unsafe fn heap_alloc_pages(size: usize) -> *mut u8 {
    let layout = alloc::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);
    alloc::alloc::alloc_zeroed(layout)
}

/// Deallocate page-aligned memory from the enclave heap.
unsafe fn heap_dealloc_pages(ptr: *mut u8, size: usize) {
    let layout = alloc::alloc::Layout::from_size_align_unchecked(size, PAGE_SIZE);
    alloc::alloc::dealloc(ptr, layout);
}

// =========================================================================
//  SGX FFI declarations
// =========================================================================

/// Intel SGX `sgx_cpu_context_t` (x86-64) — the general-purpose register file
/// captured at the faulting instruction, as delivered to a registered
/// exception handler. Field order/offsets are ABI and must not change; the VEH
/// reads `rbp`/`rip` and rewrites `rip` to redirect execution.
#[repr(C)]
struct SgxCpuContext {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u64,
    rip: u64,
}

#[repr(C)]
struct SgxExceptionInfo {
    cpu_context: SgxCpuContext,
    exception_vector: u32,
    exception_type: u32,
}

type SgxExceptionHandler = unsafe extern "C" fn(info: *mut SgxExceptionInfo) -> i32;

extern "C" {
    fn sgx_register_exception_handler(
        is_first_handler: i32,
        handler: SgxExceptionHandler,
    ) -> *const c_void;
}

// =========================================================================
//  Wasmtime platform API (C-ABI)
// =========================================================================

/// Protection flag of the `sys::custom` C API (`WASMTIME_PROT_EXEC`).
const PROT_EXEC: u32 = 1 << 2;

/// Allocate memory for wasmtime.
///
/// A mapping created accessible (`prot_flags != 0`, i.e. `Mmap::new`) is a
/// code image and comes from the RWX pool; a reservation (`prot_flags == 0`,
/// i.e. `Mmap::reserve`) is a linear memory or GC heap and comes from the
/// heap. See the module documentation for why this is exact for the features
/// we build. A code image that does not fit in the pool fails here (wasmtime
/// fails the load); it is never placed on the non-executable heap.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_new(
    size: usize,
    prot_flags: u32,
    ret_addr: *mut *mut u8,
) -> i32 {
    let aligned = page_align(size);
    if aligned == 0 {
        return -1;
    }

    let addr = if prot_flags != 0 {
        code_pool_alloc(aligned)
    } else {
        let ptr = heap_alloc_pages(aligned);
        if ptr.is_null() {
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] mmap: heap allocation of {} KiB failed",
                aligned / 1024
            );
        }
        ptr
    };

    if addr.is_null() {
        return -1;
    }
    *ret_addr = addr;
    0
}

/// Replace `size` bytes at `addr` with a fresh blank mapping: zero them.
///
/// The C API is `wasmtime_mmap_remap(addr, size, prot_flags)` and never
/// resizes. This shim used to take `(addr, old_size, new_size, prot)`, so it
/// read the protection flags as the size and zeroed 0 or 4096 bytes instead
/// of the range. Only the copy-on-write and pooling paths call it, and
/// neither is built, so it is not reached today.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(addr: *mut u8, size: usize, _prot_flags: u32) -> i32 {
    ptr::write_bytes(addr, 0, page_align(size));
    0
}

/// Unmap memory: pool pages go back to the pool, heap memory is freed.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_munmap(ptr: *mut u8, size: usize) -> i32 {
    let aligned = page_align(size);
    if is_code_pool(ptr) {
        code_pool_free(ptr, aligned);
    } else {
        heap_dealloc_pages(ptr, aligned);
    }
    0
}

/// Change memory protection.
///
/// Nothing to change: pool pages are always RWX and heap pages always RW.
/// But making a range executable is only honoured inside a live pool
/// allocation; anywhere else the code could not run, so the call fails and
/// wasmtime fails the load ("unable to make memory executable") instead of
/// the enclave crashing on the first call.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mprotect(ptr: *mut u8, size: usize, prot_flags: u32) -> i32 {
    if prot_flags & PROT_EXEC != 0 && !is_code_pool_allocation(ptr, size) {
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] mprotect: refusing to make {:p} ({} KiB) executable: \
             it is not in the code pool",
            ptr,
            page_align(size) / 1024
        );
        return -1;
    }
    0
}

/// Page size (always 4 KiB for x86-64 SGX).
#[no_mangle]
pub extern "C" fn wasmtime_page_size() -> usize {
    4096
}

// =========================================================================
//  Trap handling — SGX Vectored Exception Handler
// =========================================================================

/// wasmtime's trap-handler callback (`handle_trap` in wasmtime's
/// `sys::custom::traphandlers`). Given the faulting pc/fp it decides whether the
/// fault is a wasm trap; if so it never returns (it resumes at the enclosing
/// `try_call`/`catch_traps` landing pad via the tail-call exception ABI),
/// otherwise it returns normally. Registered via `wasmtime_init_traps`.
type WasmtimeTrapHandler =
    extern "C" fn(pc: usize, fp: usize, has_faulting_addr: bool, faulting_addr: usize);

/// wasmtime's trap handler, stored at `wasmtime_init_traps` time.
static WASMTIME_TRAP_HANDLER: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Faulting pc/fp stashed by the VEH for [`wasm_trap_trampoline`]. SGX runs one
/// thread per TCS, so plain statics are sufficient (no cross-thread race).
static TRAP_PC: AtomicUsize = AtomicUsize::new(0);
static TRAP_FP: AtomicUsize = AtomicUsize::new(0);

// Intel SGX exception-handler return codes.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// Trampoline the VEH redirects `rip` to. It runs on the faulting thread AFTER
/// the SGX runtime has restored context (so the SSA frame is cleaned up — we
/// must not call `resume_tailcc`, which never returns, from inside the VEH
/// itself, or the SGX exception state would leak). It hands the fault to
/// wasmtime, which unwinds to the wasm trap handler and never returns here.
extern "C" fn wasm_trap_trampoline() -> ! {
    let pc = TRAP_PC.load(Ordering::SeqCst);
    let fp = TRAP_FP.load(Ordering::SeqCst);
    let handler = WASMTIME_TRAP_HANDLER.load(Ordering::SeqCst);
    if !handler.is_null() {
        // SAFETY: `handler` is the `wasmtime_trap_handler_t` stored by
        // wasmtime in `wasmtime_init_traps`. It resumes at the wasm trap
        // landing pad and does not return for a genuine wasm trap.
        let handler: WasmtimeTrapHandler = unsafe { core::mem::transmute(handler) };
        // We force explicit (PC-based) bounds checks via
        // `Config::signals_based_traps(false)`, so every wasm trap is an
        // explicit trap opcode at a known PC — no faulting address is needed.
        handler(pc, fp, false, 0);
    }
    // Only reached if wasmtime declined the fault (should not happen for a
    // fault whose PC lies in the wasm code pool). Abort the thread cleanly.
    core::panic!("wasm trap trampoline: unhandled fault at pc={:#x}", pc);
}

/// SGX Vectored Exception Handler.
///
/// Faults whose faulting instruction (`rip`) lies inside the RWX wasm code pool
/// are wasm traps (unreachable, integer div-by-zero, out-of-bounds access with
/// explicit bounds checks, indirect-call type mismatch, …). For those we stash
/// pc/fp, rewrite `rip` to [`wasm_trap_trampoline`], and let the SGX runtime
/// resume there with the SSA properly unwound. Any other fault is not ours and
/// is passed on (which, with no other handler, ends the enclave — as before).
unsafe extern "C" fn sgx_veh_handler(info: *mut SgxExceptionInfo) -> i32 {
    let info = &mut *info;
    let rip = info.cpu_context.rip as *const u8;
    if !is_code_pool(rip) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    TRAP_PC.store(info.cpu_context.rip as usize, Ordering::SeqCst);
    TRAP_FP.store(info.cpu_context.rbp as usize, Ordering::SeqCst);
    info.cpu_context.rip = wasm_trap_trampoline as usize as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

/// Register the SGX VEH trap handler (called once by wasmtime during init).
///
/// wasmtime 47 passes its own trap callback and expects `0` on success
/// (non-zero = failure). We store the callback and register the VEH, which
/// forwards wasm-code-pool faults to it — so wasm traps surface as clean
/// `Trap` errors instead of crashing the enclave.
#[no_mangle]
pub extern "C" fn wasmtime_init_traps(handler: WasmtimeTrapHandler) -> i32 {
    WASMTIME_TRAP_HANDLER.store(handler as *mut (), Ordering::SeqCst);
    unsafe {
        let handle = sgx_register_exception_handler(1, sgx_veh_handler);
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] VEH trap handler registered (handle={:p})",
            handle
        );
        if handle.is_null() {
            -1
        } else {
            0
        }
    }
}

/// Deregister trap handler (cleanup).
#[no_mangle]
pub extern "C" fn wasmtime_deinit_traps() {
    // VEH handlers in SGX persist for the enclave lifetime.
}

// =========================================================================
//  Memory images — disabled for SGX (no CoW, no file mapping)
// =========================================================================

/// Memory image support — disabled.
#[no_mangle]
pub extern "C" fn wasmtime_memory_image_new(
    _ptr: *const u8,
    _len: usize,
    _ret: *mut *mut u8,
) -> i32 {
    // Memory images not supported in SGX
    -1
}

/// Map a memory image into the given range — disabled.
#[no_mangle]
pub extern "C" fn wasmtime_memory_image_map_at(
    _image: *mut u8,
    _addr: *mut u8,
    _size: usize,
) -> i32 {
    -1
}

/// Free a memory image — no-op.
#[no_mangle]
pub extern "C" fn wasmtime_memory_image_free(_image: *mut u8) {}

// =========================================================================
//  Thread-local storage for wasmtime trap handling
// =========================================================================

/// Trap-handling TLS slots.
///
/// wasmtime v47 addresses its runtime TLS by slot index: slot 0 is the
/// default runtime pointer and slot 1 is the (optional) component-model-async
/// state. WASM execution is single-threaded per TCS, so plain atomics suffice;
/// both slots default to NULL. `.get(slot)` keeps an unexpected index from
/// panicking inside this `extern "C"` boundary (which cannot unwind).
static TRAP_TLS: [AtomicPtr<u8>; 2] =
    [AtomicPtr::new(ptr::null_mut()), AtomicPtr::new(ptr::null_mut())];

/// Get the current trap-handling TLS value for `slot`.
#[no_mangle]
pub extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    TRAP_TLS
        .get(slot)
        .map_or(ptr::null_mut(), |s| s.load(Ordering::Relaxed))
}

/// Set the trap-handling TLS value for `slot`.
#[no_mangle]
pub extern "C" fn wasmtime_tls_set(slot: usize, val: *mut u8) {
    if let Some(s) = TRAP_TLS.get(slot) {
        s.store(val, Ordering::Relaxed);
    }
}
