// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX platform backend for wasmtime's `sys::custom` C API.
//!
//! When wasmtime is compiled with `custom-virtual-memory` +
//! `custom-native-signals` and routed to `sys::custom` (via
//! `target_vendor = "teaclave"` in the fork's `mod.rs`), it declares
//! a set of `extern "C"` symbols that the embedding application must
//! provide at link time.
//!
//! This module satisfies those symbols using SGX2 EDMM primitives:
//!
//! | C API function               | SGX implementation                        |
//! |------------------------------|-------------------------------------------|
//! | `wasmtime_mmap_new`          | `sgx_mm_alloc` (COMMIT_NOW / RESERVE)     |
//! | `wasmtime_mprotect`          | `sgx_mm_modify_permissions`               |
//! | `wasmtime_munmap`            | `sgx_mm_dealloc`                          |
//! | `wasmtime_mmap_remap`        | zero memory + modify_permissions          |
//! | `wasmtime_page_size`         | 4096                                      |
//! | `wasmtime_init_traps`        | `sgx_register_exception_handler` (VEH)    |
//! | `wasmtime_tls_get/set`       | `std::thread_local!`                      |
//! | `wasmtime_memory_image_*`    | disabled (no CoW / memfd in SGX)          |
//!
//! # Protection flag compatibility
//!
//! Wasmtime's `PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4` map directly to
//! SGX's `SI_FLAG_R=1, SI_FLAG_W=2, SI_FLAG_X=4`, so values pass through
//! without translation.
//!
//! # Trap handling
//!
//! SGX Vectored Exception Handling (VEH) catches hardware exceptions inside
//! the enclave.  When WASM code triggers a trap (division by zero, OOB
//! memory access, etc.), our VEH handler extracts `(RIP, RBP)` from the
//! SSA frame and forwards them to wasmtime's trap callback.  If wasmtime
//! recognises the PC as compiled WASM code the callback does **not return**
//! (it uses `resume_tailcc` to unwind).  If the callback returns, the
//! exception was not WASM-related and we continue the VEH search chain.
//!
//! # References
//!
//! - Wasmtime `sys::custom::capi`: symbol declarations
//! - SGX SDK: `sgx_mm.h`, `sgx_trts_exception.h`
//! - Original SGX port: <https://github.com/bytecodealliance/wasmtime/commit/fbbcd2ac>

use core::cell::Cell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

// ---------------------------------------------------------------------------
// SGX FFI declarations (sgx_trts / sgx_mm)
// ---------------------------------------------------------------------------

/// `sgx_mm_alloc` allocation mode: reserve virtual range, do not commit.
const SGX_EMA_RESERVE: i32 = 0x1;

/// `sgx_mm_alloc` allocation mode: commit EPC pages immediately.
const SGX_EMA_COMMIT_NOW: i32 = 0x2;

/// SGX exception vector: page fault (SGX2 EDMM).
const SGX_EXCEPTION_VECTOR_PF: u32 = 14;

/// VEH return: exception not handled, continue searching.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// CPU register state saved in the SSA frame on exception entry.
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

/// Exception info structure passed to VEH handlers by the SGX runtime.
#[repr(C)]
struct SgxExceptionInfo {
    cpu_context: SgxCpuContext,
    exception_vector: u32,
    exception_type: u32,
}

/// VEH handler function pointer type.
type SgxExceptionHandler = unsafe extern "C" fn(info: *mut SgxExceptionInfo) -> i32;

extern "C" {
    /// Allocate enclave memory (SGX2 EDMM).
    ///
    /// - `flags`: `SGX_EMA_RESERVE` or `SGX_EMA_COMMIT_NOW`
    /// - `out`: receives the allocated base address
    fn sgx_mm_alloc(
        addr: *mut c_void,
        length: usize,
        flags: i32,
        handler: *const c_void,
        handler_input: *const c_void,
        out: *mut *mut c_void,
    ) -> i32;

    /// Change page protection (SGX2 EDMM).
    ///
    /// `prot` uses POSIX-style flags: `R=1, W=2, X=4`.
    fn sgx_mm_modify_permissions(
        addr: *const c_void,
        length: usize,
        prot: i32,
    ) -> i32;

    /// Free enclave pages (SGX2 EDMM).
    fn sgx_mm_dealloc(
        addr: *mut c_void,
        length: usize,
    ) -> i32;

    /// Register a vectored exception handler.
    ///
    /// `is_first_handler = 1` inserts at the front of the chain.
    fn sgx_register_exception_handler(
        is_first_handler: i32,
        handler: SgxExceptionHandler,
    ) -> *const c_void;
}

// ---------------------------------------------------------------------------
// Compile-time assertion: wasmtime and SGX protection flags are identical
// ---------------------------------------------------------------------------

const WASMTIME_PROT_READ: u32 = 1 << 0;
const WASMTIME_PROT_WRITE: u32 = 1 << 1;
#[allow(dead_code)]
const WASMTIME_PROT_EXEC: u32 = 1 << 2;

const _: () = assert!(WASMTIME_PROT_READ == 1);  // == SI_FLAG_R
const _: () = assert!(WASMTIME_PROT_WRITE == 2);  // == SI_FLAG_W
const _: () = assert!(WASMTIME_PROT_EXEC == 4);   // == SI_FLAG_X

// ---------------------------------------------------------------------------
// Thread-local storage for wasmtime VMContext pointer
// ---------------------------------------------------------------------------

std::thread_local! {
    static WASMTIME_TLS: Cell<*mut u8> = const { Cell::new(ptr::null_mut()) };
}

/// Get the wasmtime TLS pointer for the current thread.
#[no_mangle]
pub extern "C" fn wasmtime_tls_get() -> *mut u8 {
    WASMTIME_TLS.with(|cell| cell.get())
}

/// Set the wasmtime TLS pointer for the current thread.
#[no_mangle]
pub extern "C" fn wasmtime_tls_set(ptr: *mut u8) {
    WASMTIME_TLS.with(|cell| cell.set(ptr));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Round `size` up to the next 4 KiB page boundary.
#[inline]
fn page_align(size: usize) -> usize {
    (size + 4095) & !4095
}

// ---------------------------------------------------------------------------
// Virtual memory — SGX2 EDMM
// ---------------------------------------------------------------------------

/// Allocate `size` bytes of enclave memory.
///
/// - `prot_flags == 0`: reserve only (no physical pages committed)
/// - `prot_flags != 0`: commit immediately, then apply the requested
///   protection via `sgx_mm_modify_permissions`
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_new(
    size: usize,
    prot_flags: u32,
    ret: *mut *mut u8,
) -> i32 {
    let aligned = page_align(size);
    let flags = if prot_flags == 0 {
        SGX_EMA_RESERVE
    } else {
        SGX_EMA_COMMIT_NOW
    };

    let mut out: *mut c_void = ptr::null_mut();
    let rc = sgx_mm_alloc(
        ptr::null_mut(), // let the runtime choose the address
        aligned,
        flags,
        ptr::null(),     // no page-fault handler
        ptr::null(),     // no handler context
        &mut out,
    );
    if rc != 0 {
        return rc;
    }

    // Committed pages default to R|W.  Adjust if the caller wants
    // something else (e.g. R|X for code pages).
    if prot_flags != 0 && prot_flags != (WASMTIME_PROT_READ | WASMTIME_PROT_WRITE) {
        let prc = sgx_mm_modify_permissions(out, aligned, prot_flags as i32);
        if prc != 0 {
            let _ = sgx_mm_dealloc(out, aligned);
            return prc;
        }
    }

    *ret = out as *mut u8;
    0
}

/// Remap an existing region: zero the contents and apply new protection.
///
/// In SGX there is no true "unmap + remap" — we zero the memory in-place
/// and change permissions.  Wasmtime calls this for:
/// - `erase_existing_mapping(prot=0)` — invalidate the region
/// - `decommit_pages(prot=R|W)` — reset and re-protect
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mmap_remap(
    addr: *mut u8,
    size: usize,
    prot_flags: u32,
) -> i32 {
    let aligned = page_align(size);

    // Ensure the region is writable so we can zero it.
    let rc = sgx_mm_modify_permissions(
        addr as *const c_void,
        aligned,
        (WASMTIME_PROT_READ | WASMTIME_PROT_WRITE) as i32,
    );
    if rc != 0 {
        return rc;
    }

    // Zero the memory.
    ptr::write_bytes(addr, 0u8, size);

    // Apply the target protection (if not already R|W).
    if prot_flags != 0 && prot_flags != (WASMTIME_PROT_READ | WASMTIME_PROT_WRITE) {
        let prc = sgx_mm_modify_permissions(
            addr as *const c_void,
            aligned,
            prot_flags as i32,
        );
        if prc != 0 {
            return prc;
        }
    }

    0
}

/// Release enclave pages (SGX2 EDMM).
///
/// On SGX1 (no EDMM) this is a no-op — pages are reclaimed when the
/// enclave is destroyed.  On SGX2, `sgx_mm_dealloc` frees EPC pages.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_munmap(ptr: *mut u8, size: usize) -> i32 {
    let _ = sgx_mm_dealloc(ptr as *mut c_void, page_align(size));
    // Always return success — if deallocation is unsupported the pages
    // are simply leaked until enclave teardown, which is acceptable.
    0
}

/// Change page protection on an existing allocation.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_mprotect(
    ptr: *mut u8,
    size: usize,
    prot_flags: u32,
) -> i32 {
    sgx_mm_modify_permissions(
        ptr as *const c_void,
        page_align(size),
        prot_flags as i32,
    )
}

/// Page size inside the enclave (always 4 KiB for x86-64 SGX).
#[no_mangle]
pub extern "C" fn wasmtime_page_size() -> usize {
    4096
}

// ---------------------------------------------------------------------------
// Trap handling — SGX Vectored Exception Handler
// ---------------------------------------------------------------------------

/// Wasmtime trap handler callback signature:
///   `handler(ip, fp, has_faulting_addr, faulting_addr)`
///
/// If the IP falls within compiled WASM code, the callback does **not
/// return** (it uses `resume_tailcc` to unwind to the host call site).
type WasmtimeTrapHandler = extern "C" fn(usize, usize, bool, usize);

/// Global storage for the wasmtime trap callback.
static TRAP_HANDLER: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// VEH handler registered with `sgx_register_exception_handler`.
///
/// Extracts (RIP, RBP) from the SSA-saved CPU context and forwards to
/// wasmtime's trap handler.
unsafe extern "C" fn sgx_veh_handler(info: *mut SgxExceptionInfo) -> i32 {
    let handler_ptr = TRAP_HANDLER.load(Ordering::SeqCst);
    if handler_ptr.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let handler: WasmtimeTrapHandler = core::mem::transmute(handler_ptr);
    let ctx = &(*info).cpu_context;

    let ip = ctx.rip as usize;
    let fp = ctx.rbp as usize;

    // In SGX the faulting virtual address (CR2) is not exposed to the
    // enclave.  Wasmtime can still identify the trap by instruction
    // pointer lookup, so we conservatively report no faulting address.
    let (has_faulting_addr, faulting_addr) =
        if (*info).exception_vector == SGX_EXCEPTION_VECTOR_PF {
            // Future: SGX2 EXINFO may expose the address — enable when
            // SDK support is confirmed.
            (false, 0usize)
        } else {
            (false, 0usize)
        };

    // Forward to wasmtime.  If it handles the trap this call does NOT
    // return (resume_tailcc).  If it returns, the exception is not from
    // compiled WASM code.
    handler(ip, fp, has_faulting_addr, faulting_addr);

    EXCEPTION_CONTINUE_SEARCH
}

/// Register the wasmtime trap handler using SGX VEH.
///
/// Called once by `TrapHandler::new` during `Engine` initialisation.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_init_traps(
    handler: WasmtimeTrapHandler,
) -> i32 {
    TRAP_HANDLER.store(handler as *mut (), Ordering::SeqCst);

    // Register as first-chance handler so we see exceptions before any
    // other enclave VEH handlers.
    let result = sgx_register_exception_handler(1, sgx_veh_handler);
    if result.is_null() {
        return -1;
    }

    0
}

// ---------------------------------------------------------------------------
// Memory images — disabled (no CoW / memfd inside SGX)
// ---------------------------------------------------------------------------

/// Opaque type matching wasmtime's `wasmtime_memory_image`.
///
/// Never actually instantiated — `wasmtime_memory_image_new` always
/// returns NULL, causing wasmtime to fall back to data-segment copying
/// on each instantiation.
#[repr(C)]
pub struct WasmtimeMemoryImage {
    _opaque: [u8; 0],
}

/// Always returns `*ret = NULL` → wasmtime uses copy-on-instantiate.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_memory_image_new(
    _ptr: *const u8,
    _len: usize,
    ret: *mut *mut WasmtimeMemoryImage,
) -> i32 {
    *ret = ptr::null_mut();
    0
}

/// Unreachable — wasmtime only calls this with a non-NULL image.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_memory_image_map_at(
    _image: *mut WasmtimeMemoryImage,
    _addr: *mut u8,
    _len: usize,
) -> i32 {
    -1
}

/// No-op — no images are ever created.
#[no_mangle]
pub unsafe extern "C" fn wasmtime_memory_image_free(
    _image: *mut WasmtimeMemoryImage,
) {
    // nothing to free
}
