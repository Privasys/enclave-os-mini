// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! CPUID cache – one-time OCALL at init, zero-cost VEH interception thereafter.
//!
//! Inside an SGX enclave the CPUID instruction triggers #UD (illegal opcode).
//! Intel's C `sgx_trts.a` normally intercepts this via a built-in VEH and
//! makes an OCALL, but when using Teaclave's Rust-only `sgx_trts` (sysroot
//! build) there is **no** automatic CPUID handler registered.
//!
//! This module:
//!   1. Makes one OCALL per CPUID leaf at init time (fast – only ~10 calls)
//!   2. Caches the results in a static table
//!   3. Registers a first-chance VEH that intercepts #UD from CPUID
//!      instructions and returns the cached values – zero OCALLs at runtime
//!
//! ring, rustls and other crypto crates use CPUID for feature detection
//! (SHA-NI, AES-NI, AVX2, SSSE3, etc.) so this **must** be initialised
//! before any crypto operations.

use core::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{enclave_log_error, enclave_log_info};

// ---------------------------------------------------------------------------
//  CPUID result cache
// ---------------------------------------------------------------------------

/// Maximum number of CPUID (leaf, subleaf) pairs we pre-cache.
const MAX_CACHED_LEAVES: usize = 32;

/// A cached CPUID result for a given (leaf, subleaf) pair.
#[derive(Copy, Clone)]
struct CpuidEntry {
    leaf: u32,
    subleaf: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

/// Static cache array – written once during `init()`, read-only afterwards.
static mut CPUID_CACHE: [CpuidEntry; MAX_CACHED_LEAVES] = [CpuidEntry {
    leaf: 0,
    subleaf: 0,
    eax: 0,
    ebx: 0,
    ecx: 0,
    edx: 0,
}; MAX_CACHED_LEAVES];

/// Number of valid entries. Uses Release/Acquire ordering so that any
/// thread reading the cache (via the VEH) sees the fully-written entries.
static CPUID_CACHE_LEN: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
//  OCALL declaration (host provides `ocall_cpuidex`)
// ---------------------------------------------------------------------------

extern "C" {
    /// OCALL to execute CPUID on the host side.
    ///
    /// Provided by the Teaclave SDK's `sgx_cpuid.edl` (imported in our EDL).
    /// The host-side implementation must be linked as `sgx_oc_cpuidex`.
    fn sgx_oc_cpuidex(cpuinfo: *mut i32, leaf: i32, subleaf: i32) -> u32;
}

// ---------------------------------------------------------------------------
//  SGX exception-handling types & FFI
// ---------------------------------------------------------------------------

/// Exception vector for #UD (Undefined Opcode).
const SGX_EXCEPTION_VECTOR_UD: u32 = 6;

/// Return from VEH: resume execution with (possibly modified) context.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// Return from VEH: pass exception to next handler / crash.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// CPU register context saved on exception (matches Intel SDK layout).
#[repr(C)]
#[allow(dead_code)]
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

/// Exception info passed to the VEH handler.
#[repr(C)]
#[allow(dead_code)]
struct SgxExceptionInfo {
    cpu_context: SgxCpuContext,
    exception_vector: u32,
    exception_type: u32,
}

extern "C" {
    /// Register a Vectored Exception Handler inside the enclave.
    ///
    /// * `is_first_handler` – 1 = first-chance handler (called before others)
    /// * `exception_handler` – function pointer
    ///
    /// Returns a non-null handle on success.
    fn sgx_register_exception_handler(
        is_first_handler: i32,
        exception_handler: unsafe extern "C" fn(*mut SgxExceptionInfo) -> i32,
    ) -> *const c_void;
}

// ---------------------------------------------------------------------------
//  Fetch + cache helpers
// ---------------------------------------------------------------------------

/// Call the host OCALL to fetch one CPUID leaf and store it in the cache.
fn fetch_and_cache(leaf: u32, subleaf: u32) {
    let idx = CPUID_CACHE_LEN.load(Ordering::Relaxed);
    if idx >= MAX_CACHED_LEAVES {
        return;
    }

    let mut info = [0i32; 4];
    let status = unsafe { sgx_oc_cpuidex(info.as_mut_ptr(), leaf as i32, subleaf as i32) };
    if status != 0 {
        // OCALL failed – leave the entry zeroed (better than crashing).
        enclave_log_error!("ocall_cpuidex failed for leaf={:#x} sub={}: status={}", leaf, subleaf, status);
        return;
    }

    unsafe {
        CPUID_CACHE[idx] = CpuidEntry {
            leaf,
            subleaf,
            eax: info[0] as u32,
            ebx: info[1] as u32,
            ecx: info[2] as u32,
            edx: info[3] as u32,
        };
    }
    // Release store so VEH readers on other threads see the data.
    CPUID_CACHE_LEN.store(idx + 1, Ordering::Release);
}

/// Look up a cached CPUID result by (leaf, subleaf).
/// Returns `Some((eax, ebx, ecx, edx))` or `None` if not cached.
#[inline]
fn lookup(leaf: u32, subleaf: u32) -> Option<(u32, u32, u32, u32)> {
    let len = CPUID_CACHE_LEN.load(Ordering::Acquire);
    for i in 0..len {
        let e = unsafe { &CPUID_CACHE[i] };
        if e.leaf == leaf && e.subleaf == subleaf {
            return Some((e.eax, e.ebx, e.ecx, e.edx));
        }
    }
    None
}

// ---------------------------------------------------------------------------
//  Vectored Exception Handler
// ---------------------------------------------------------------------------

/// First-chance VEH for intercepting CPUID (#UD) inside the enclave.
///
/// When the CPU encounters a CPUID instruction (opcode `0F A2`), it raises
/// #UD. This handler:
///   1. Verifies the exception is #UD
///   2. Reads the 2-byte instruction at RIP to confirm it is CPUID
///   3. Retrieves leaf (EAX) and subleaf (ECX) from the saved registers
///   4. Looks up the cached result (or returns zeros if not cached)
///   5. Patches EAX/EBX/ECX/EDX in the saved context
///   6. Advances RIP by 2 bytes (past the CPUID instruction)
///   7. Returns `EXCEPTION_CONTINUE_EXECUTION` to resume
///
/// Cost: one cache lookup per CPUID instruction – no OCALL, no syscall.
unsafe extern "C" fn cpuid_exception_handler(info: *mut SgxExceptionInfo) -> i32 {
    let info = &mut *info;

    // Only handle #UD exceptions.
    if info.exception_vector != SGX_EXCEPTION_VECTOR_UD {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if the faulting instruction is CPUID (0x0F 0xA2).
    let rip = info.cpu_context.rip as *const u8;
    let byte0 = core::ptr::read(rip);
    let byte1 = core::ptr::read(rip.add(1));
    if byte0 != 0x0F || byte1 != 0xA2 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Read leaf (EAX) and subleaf (ECX) from the register context.
    let leaf = info.cpu_context.rax as u32;
    let subleaf = info.cpu_context.rcx as u32;

    // Look up cached result.
    let (eax, ebx, ecx, edx) = lookup(leaf, subleaf).unwrap_or((0, 0, 0, 0));

    // Patch register context.
    info.cpu_context.rax = eax as u64;
    info.cpu_context.rbx = ebx as u64;
    info.cpu_context.rcx = ecx as u64;
    info.cpu_context.rdx = edx as u64;

    // Advance RIP past the 2-byte CPUID instruction.
    info.cpu_context.rip += 2;

    EXCEPTION_CONTINUE_EXECUTION
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Initialise the CPUID cache and register the VEH.
///
/// **Must** be called before any code that executes CPUID – in particular
/// before `ring::digest`, `ring::aead`, `rustls` TLS handshake, etc.
///
/// This performs ~10 OCALLs (one per leaf) at init time. After that, all
/// CPUID instructions inside the enclave are served from the cache with
/// zero OCALL overhead.
pub fn init() {
    // ----- 1. Fetch common CPUID leaves via OCALL -----
    //
    // Leaves used by ring, BoringSSL, rustls, and general x86 feature detection:
    let leaves: &[(u32, u32)] = &[
        (0x00, 0), // Max standard leaf + vendor string
        (0x01, 0), // Feature flags (SSE, AES-NI, XSAVE, OSXSAVE, …)
        (0x04, 0), // Deterministic cache params (sub 0-3)
        (0x04, 1),
        (0x04, 2),
        (0x04, 3),
        (0x07, 0), // Extended features (SHA-NI, AVX2, AVX-512, BMI2, …)
        (0x07, 1), // Extended features sub-1
        (0x0D, 0), // XSAVE state size
        (0x0D, 1), // XSAVE features
        (0x80000000, 0), // Max extended leaf
        (0x80000001, 0), // Extended feature flags (LAHF, LZCNT, …)
    ];

    for &(leaf, subleaf) in leaves {
        fetch_and_cache(leaf, subleaf);
    }

    let cached = CPUID_CACHE_LEN.load(Ordering::Acquire);
    enclave_log_info!("CPUID cache: {} leaves fetched via OCALL", cached);

    // Log key CPU feature results for diagnostics.
    if let Some((_eax, _ebx, ecx, edx)) = lookup(0x01, 0) {
        enclave_log_info!(
            "  Leaf 1: SSE2={} SSSE3={} SSE4.1={} SSE4.2={} AES-NI={} XSAVE={} OSXSAVE={}",
            (edx >> 26) & 1,
            (ecx >> 9) & 1,
            (ecx >> 19) & 1,
            (ecx >> 20) & 1,
            (ecx >> 25) & 1,
            (ecx >> 26) & 1,
            (ecx >> 27) & 1,
        );
    }
    if let Some((_eax, ebx, _ecx, _edx)) = lookup(0x07, 0) {
        enclave_log_info!(
            "  Leaf 7: AVX2={} BMI2={} SHA-NI={} AVX-512F={}",
            (ebx >> 5) & 1,
            (ebx >> 8) & 1,
            (ebx >> 29) & 1,
            (ebx >> 16) & 1,
        );
    }

    // ----- 2. Register first-chance VEH -----
    let handle = unsafe { sgx_register_exception_handler(1, cpuid_exception_handler) };

    if handle.is_null() {
        enclave_log_error!("CPUID VEH registration FAILED – CPUID will crash!");
    } else {
        enclave_log_info!("CPUID VEH registered (first-chance, handle={:?})", handle);
    }
}
