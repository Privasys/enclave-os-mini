// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! DCAP Quoting Library (QL) FFI bindings for the host side.
//!
//! Provides safe wrappers around the Intel DCAP QL untrusted API:
//!   - `sgx_qe_get_target_info`  → [`qe_get_target_info()`]
//!   - `sgx_qe_get_quote_size`   → (used internally)
//!   - `sgx_qe_get_quote`        → [`qe_get_quote()`]
//!
//! These functions call the Quoting Enclave (QE) through `libsgx_dcap_ql.so`,
//! which must be installed on the host (package `libsgx-dcap-ql`).

use log::{debug, error};

// ---------------------------------------------------------------------------
//  FFI types matching the SGX SDK C headers
// ---------------------------------------------------------------------------

/// `sgx_target_info_t` — 512 bytes.
const SGX_TARGET_INFO_SIZE: usize = 512;

/// `sgx_report_t` — 432 bytes.
const SGX_REPORT_SIZE: usize = 432;

/// `quote3_error_t` — the DCAP QL uses u32 error codes.
/// `SGX_QL_SUCCESS = 0`.
const SGX_QL_SUCCESS: u32 = 0;

// ---------------------------------------------------------------------------
//  C FFI declarations  (libsgx_dcap_ql.so)
// ---------------------------------------------------------------------------

extern "C" {
    /// Get the Quoting Enclave's target info so the application enclave
    /// can produce a report targeting the QE.
    fn sgx_qe_get_target_info(p_qe_target_info: *mut u8) -> u32;

    /// Get the required buffer size for the quote.
    fn sgx_qe_get_quote_size(p_quote_size: *mut u32) -> u32;

    /// Generate a DCAP Quote v3 from an SGX report.
    fn sgx_qe_get_quote(
        p_app_report: *const u8,
        quote_size: u32,
        p_quote: *mut u8,
    ) -> u32;
}

// ---------------------------------------------------------------------------
//  Safe wrappers
// ---------------------------------------------------------------------------

/// Get the Quoting Enclave's `sgx_target_info_t` (512 bytes).
///
/// The enclave needs this to call `sgx_create_report()` targeting the QE.
pub fn qe_get_target_info() -> Result<Vec<u8>, String> {
    let mut target_info = vec![0u8; SGX_TARGET_INFO_SIZE];
    let ret = unsafe { sgx_qe_get_target_info(target_info.as_mut_ptr()) };
    if ret != SGX_QL_SUCCESS {
        error!("sgx_qe_get_target_info failed: 0x{:04x}", ret);
        return Err(format!("sgx_qe_get_target_info failed: 0x{:04x}", ret));
    }
    debug!("sgx_qe_get_target_info: OK ({} bytes)", SGX_TARGET_INFO_SIZE);
    Ok(target_info)
}

/// Generate a DCAP Quote v3 from a raw SGX report (432 bytes).
///
/// Returns the full quote bytes (typically ~4-5 KB with cert chain).
pub fn qe_get_quote(report_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if report_bytes.len() != SGX_REPORT_SIZE {
        return Err(format!(
            "invalid report size: expected {} bytes, got {}",
            SGX_REPORT_SIZE,
            report_bytes.len()
        ));
    }

    // 1. Get the required quote buffer size
    let mut quote_size: u32 = 0;
    let ret = unsafe { sgx_qe_get_quote_size(&mut quote_size) };
    if ret != SGX_QL_SUCCESS {
        error!("sgx_qe_get_quote_size failed: 0x{:04x}", ret);
        return Err(format!("sgx_qe_get_quote_size failed: 0x{:04x}", ret));
    }
    debug!("sgx_qe_get_quote_size: {} bytes", quote_size);

    // 2. Allocate buffer and generate the quote
    let mut quote = vec![0u8; quote_size as usize];
    let ret = unsafe {
        sgx_qe_get_quote(
            report_bytes.as_ptr(),
            quote_size,
            quote.as_mut_ptr(),
        )
    };
    if ret != SGX_QL_SUCCESS {
        error!("sgx_qe_get_quote failed: 0x{:04x}", ret);
        return Err(format!("sgx_qe_get_quote failed: 0x{:04x}", ret));
    }
    debug!("sgx_qe_get_quote: OK ({} bytes)", quote_size);
    Ok(quote)
}
