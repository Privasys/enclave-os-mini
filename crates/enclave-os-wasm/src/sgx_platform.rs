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

#[repr(C)]
struct SgxCpuContext {
    _pad: [u64; 20],
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
                aligned, ptr
            );
            ptr
        }
    } else {
        let ptr = heap_alloc_pages(aligned);
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] mmap: heap alloc {} bytes at {:p}",
            aligned, ptr
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
            ptr, aligned
        );
    } else {
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] munmap: heap dealloc {:p} ({} bytes)",
            ptr, aligned
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
pub unsafe extern "C" fn wasmtime_mprotect(
    ptr: *mut u8,
    size: usize,
    prot_flags: u32,
) -> i32 {
    let aligned = page_align(size);
    let in_pool = is_code_pool(ptr);
    enclave_os_common::enclave_log_info!(
        "[sgx_platform] mprotect: addr={:p} size={} prot={} pool={} (no-op)",
        ptr, aligned, prot_flags, in_pool
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

/// VEH handler for SIGILL/SIGSEGV-like exceptions inside the enclave.
///
/// Wasmtime uses this to catch traps from WASM code (e.g. unreachable,
/// out-of-bounds memory access, division by zero).
unsafe extern "C" fn sgx_veh_handler(info: *mut SgxExceptionInfo) -> i32 {
    let _info = &*info;
    // 0 = continue searching handlers, 1 = continue execution
    // Let wasmtime's internal handler manage trap details.
    0
}

/// Register a VEH trap handler (called once by wasmtime during init).
///
/// Returns a non-null handle on success.
#[no_mangle]
pub extern "C" fn wasmtime_init_traps() -> *const u8 {
    unsafe {
        let handle = sgx_register_exception_handler(1, sgx_veh_handler);
        enclave_os_common::enclave_log_info!(
            "[sgx_platform] VEH trap handler registered (handle={:p})",
            handle
        );
        handle as *const u8
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

/// Per-thread trap state pointer.
///
/// In SGX, WASM execution is single-threaded per TCS, so a simple
/// atomic pointer suffices.
static TRAP_TLS: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

/// Get the current trap handling TLS value.
#[no_mangle]
pub extern "C" fn wasmtime_tls_get() -> *mut u8 {
    TRAP_TLS.load(Ordering::Relaxed)
}

/// Set the trap handling TLS value.
#[no_mangle]
pub extern "C" fn wasmtime_tls_set(val: *mut u8) {
    TRAP_TLS.store(val, Ordering::Relaxed);
}
