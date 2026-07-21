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
//!    These CANNOT be made executable — EMODPE only extends EAUG'd pages.
//!
//! 2. **Dynamic pages** (EAUG'd via EDMM) can have flexible permissions,
//!    but EDMM operations hang on some server configurations.
//!
//! Our solution: pre-allocate an **RWX section** in the enclave ELF binary
//! using `global_asm!`. The `sgx_sign` tool creates EADD entries with RWX
//! permissions for these pages. Wasmtime gets code memory from this pool
//! (bump allocator), and data memory from the heap (standard allocator).
//!
//! ## C API symbols provided
//!
//! | C API function               | SGX implementation                        |
//! |------------------------------|-------------------------------------------|
//! | `wasmtime_mmap_new`          | RWX code pool (≤1MB) or heap alloc (>1MB) |
//! | `wasmtime_mprotect`          | no-op (pool=RWX, heap=RW)                 |
//! | `wasmtime_munmap`            | heap dealloc (pool: retained)             |
//! | `wasmtime_mmap_remap`        | zero memory                               |
//! | `wasmtime_page_size`         | 4096                                      |
//! | `wasmtime_init_traps`        | `sgx_register_exception_handler` (VEH)    |
//! | `wasmtime_tls_get/set`       | `AtomicPtr` (single-threaded per TCS)     |
//! | `wasmtime_memory_image_*`    | disabled (no CoW / memfd in SGX)          |

#![allow(unused_unsafe)]

extern crate alloc;

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

// =========================================================================
//  RWX Code Pool — pre-allocated executable memory
// =========================================================================

/// Size of the RWX code pool (16 MiB).
///
/// This is the maximum total size of pre-compiled WASM code that can be
/// loaded into the enclave. Adjust based on your needs.
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

/// Bump pointer for the RWX code pool.
static CODE_POOL_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Allocate `size` bytes from the RWX code pool (page-aligned).
/// Returns null on exhaustion.
unsafe fn code_pool_alloc(size: usize) -> *mut u8 {
    let aligned = page_align(size);
    let pool_start = &_wasm_code_pool_start as *const u8 as usize;

    loop {
        let current = CODE_POOL_OFFSET.load(Ordering::Relaxed);
        let new_offset = current + aligned;
        if new_offset > CODE_POOL_SIZE {
            return ptr::null_mut(); // Pool exhausted
        }
        if CODE_POOL_OFFSET
            .compare_exchange_weak(current, new_offset, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let addr = (pool_start + current) as *mut u8;
            // Zero the memory
            ptr::write_bytes(addr, 0, aligned);
            return addr;
        }
    }
}

/// Check if an address is within the RWX code pool.
unsafe fn is_code_pool(addr: *const u8) -> bool {
    let pool_start = &_wasm_code_pool_start as *const u8 as usize;
    let pool_end = pool_start + CODE_POOL_SIZE;
    let a = addr as usize;
    a >= pool_start && a < pool_end
}

// =========================================================================
//  Heap allocation helpers (for data/linear memory)
// =========================================================================

fn page_align(size: usize) -> usize {
    (size + 4095) & !4095
}

/// Allocate page-aligned memory from the enclave heap.
unsafe fn heap_alloc_pages(size: usize) -> *mut u8 {
    let layout = alloc::alloc::Layout::from_size_align_unchecked(size, 4096);
    alloc::alloc::alloc_zeroed(layout)
}

/// Deallocate page-aligned memory from the enclave heap.
unsafe fn heap_dealloc_pages(ptr: *mut u8, size: usize) {
    let layout = alloc::alloc::Layout::from_size_align_unchecked(size, 4096);
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

/// Allocate memory for wasmtime.
///
/// Uses the RWX code pool for small allocations (likely code segments)
/// and the heap allocator for large allocations (likely linear memory).
///
/// The heuristic: allocations that will later be mprotect'd to RX are code.
/// Since we can't predict this at allocation time, we use a size heuristic:
/// - Allocations ≤ 1 MiB go to the code pool (WASM code segments)
/// - Larger allocations go to the heap (linear memory, which is RW only)
///
/// prot_flags: 0=NONE, 1=READ, 2=WRITE, 3=RW, 4=EXEC, 5=RX, 7=RWX
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_new(
    size: usize,
    _prot_flags: u32,
    ret_addr: *mut *mut u8,
) -> i32 {
    let aligned = page_align(size);

    // Strategy: code segments are typically < 1MB, linear memory is >= 4MB.
    let use_code_pool = aligned <= 1024 * 1024;

    let addr = if use_code_pool {
        let ptr = code_pool_alloc(aligned);
        if ptr.is_null() {
            // Code pool exhausted, fall back to heap
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] mmap: code pool exhausted, falling back to heap for {} bytes",
                aligned
            );
            heap_alloc_pages(aligned)
        } else {
            enclave_os_common::enclave_log_info!(
                "[sgx_platform] mmap: code pool alloc {} bytes at {:p}",
                aligned,
                ptr
            );
            ptr
        }
    } else {
        let ptr = heap_alloc_pages(aligned);
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] mmap: heap alloc {} bytes at {:p}",
            aligned,
            ptr
        );
        ptr
    };

    if addr.is_null() {
        return -1;
    }
    *ret_addr = addr;
    0
}

/// Remap memory (resize). Zero the new region.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(
    addr: *mut u8,
    _old_size: usize,
    new_size: usize,
    _prot_flags: u32,
) -> i32 {
    let aligned = page_align(new_size);
    ptr::write_bytes(addr, 0, aligned);
    0
}

/// Unmap memory.
///
/// Code pool memory is NOT freed (bump allocator doesn't support individual frees).
/// Heap memory is properly deallocated.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_munmap(ptr: *mut u8, size: usize) -> i32 {
    let aligned = page_align(size);
    if is_code_pool(ptr) {
        // Code pool: can't free individual allocations from bump allocator.
        // The memory stays allocated until enclave teardown.
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] munmap: code pool page {:p} ({} bytes) — retained",
            ptr,
            aligned
        );
    } else {
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] munmap: heap dealloc {:p} ({} bytes)",
            ptr,
            aligned
        );
        heap_dealloc_pages(ptr, aligned);
    }
    0
}

/// Change memory protection.
///
/// No-op: code pool pages are already RWX, heap pages are RW.
/// Wasmtime calls this to set code pages to RX after writing code,
/// but since our pool is already RWX, no action is needed.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mprotect(ptr: *mut u8, size: usize, prot_flags: u32) -> i32 {
    let aligned = page_align(size);
    let in_pool = is_code_pool(ptr);
    enclave_os_common::enclave_log_info!(
        "[sgx_platform] mprotect: addr={:p} size={} prot={} pool={} (no-op)",
        ptr,
        aligned,
        prot_flags,
        in_pool
    );
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
