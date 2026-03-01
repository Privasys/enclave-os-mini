// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave lifecycle management – loading, shared-channel setup, ECall wrappers.
//!
//! With the SPSC queue architecture, the host:
//! 1. Creates the enclave
//! 2. Allocates two shared-memory SPSC queues (enc_to_host, host_to_enc)
//! 3. Calls `ecall_init_channel` to pass queue pointers to enclave
//! 4. Starts the RPC dispatcher thread
//! 5. Calls `ecall_run` (blocks in the enclave event loop)
//! 6. On shutdown, calls `ecall_shutdown` and joins dispatcher

use std::alloc::{alloc_zeroed, dealloc, Layout};

use enclave_os_common::queue::{SpscQueueHeader, SpscConsumer, SpscProducer};

// ---------------------------------------------------------------------------
//  Shared channel allocation
// ---------------------------------------------------------------------------

/// Holds the allocated shared-memory regions and the dispatcher thread.
pub struct SharedChannel {
    /// enc_to_host header (enclave writes, host reads)
    pub enc_to_host_header: *mut SpscQueueHeader,
    pub enc_to_host_buf: *mut u8,
    /// host_to_enc header (host writes, enclave reads)
    pub host_to_enc_header: *mut SpscQueueHeader,
    pub host_to_enc_buf: *mut u8,
    /// Ring buffer capacity (shared)
    pub capacity: u64,
    /// Buffer layout for deallocation
    buf_layout: Layout,
    hdr_layout: Layout,
}

unsafe impl Send for SharedChannel {}

impl SharedChannel {
    /// Allocate a new bidirectional channel in host memory.
    pub fn new(capacity: u64) -> Self {
        assert!(capacity.is_power_of_two());
        let hdr_layout = Layout::new::<SpscQueueHeader>();
        let buf_layout = Layout::from_size_align(capacity as usize, 64).unwrap();

        unsafe {
            let enc_to_host_header = alloc_zeroed(hdr_layout) as *mut SpscQueueHeader;
            let enc_to_host_buf = alloc_zeroed(buf_layout);
            let host_to_enc_header = alloc_zeroed(hdr_layout) as *mut SpscQueueHeader;
            let host_to_enc_buf = alloc_zeroed(buf_layout);

            // Initialise headers
            core::ptr::write(enc_to_host_header, SpscQueueHeader::new(capacity));
            core::ptr::write(host_to_enc_header, SpscQueueHeader::new(capacity));

            Self {
                enc_to_host_header,
                enc_to_host_buf,
                host_to_enc_header,
                host_to_enc_buf,
                capacity,
                buf_layout,
                hdr_layout,
            }
        }
    }

    /// Create the host-side queue endpoints:
    /// - Consumer for enc_to_host (host reads enclave requests)
    /// - Producer for host_to_enc (host writes enclave responses)
    pub unsafe fn host_endpoints(&self) -> (SpscConsumer, SpscProducer) {
        let consumer = SpscConsumer::from_raw(
            self.enc_to_host_header as *const SpscQueueHeader,
            self.enc_to_host_buf as *const u8,
        );
        let producer = SpscProducer::from_raw(
            self.host_to_enc_header as *const SpscQueueHeader,
            self.host_to_enc_buf,
        );
        (consumer, producer)
    }
}

impl Drop for SharedChannel {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.enc_to_host_buf, self.buf_layout);
            dealloc(self.enc_to_host_header as *mut u8, self.hdr_layout);
            dealloc(self.host_to_enc_buf, self.buf_layout);
            dealloc(self.host_to_enc_header as *mut u8, self.hdr_layout);
        }
    }
}

// ---------------------------------------------------------------------------
//  SGX real mode (Linux with SGX SDK)
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "linux", not(feature = "mock")))]
mod sgx {
    use sgx_types::error::SgxStatus;
    use sgx_types::types::EnclaveId;
    use sgx_urts::enclave::SgxEnclave;
    use std::sync::OnceLock;

    static ENCLAVE: OnceLock<SgxEnclave> = OnceLock::new();

    extern "C" {
        fn ecall_init_channel(
            eid: EnclaveId,
            retval: *mut i32,
            enc_to_host_header: *mut u8,
            enc_to_host_buf: *mut u8,
            host_to_enc_header: *mut u8,
            host_to_enc_buf: *mut u8,
            capacity: u64,
        ) -> SgxStatus;

        fn ecall_init_data_channel(
            eid: EnclaveId,
            retval: *mut i32,
            enc_to_host_header: *mut u8,
            enc_to_host_buf: *mut u8,
            host_to_enc_header: *mut u8,
            host_to_enc_buf: *mut u8,
            capacity: u64,
        ) -> SgxStatus;

        fn ecall_run(
            eid: EnclaveId,
            retval: *mut i32,
            config_json: *const u8,
            config_len: u64,
        ) -> SgxStatus;

        fn ecall_shutdown(
            eid: EnclaveId,
            retval: *mut i32,
        ) -> SgxStatus;
    }

    pub fn create_enclave(path: &str) -> anyhow::Result<u64> {
        let debug = cfg!(debug_assertions);
        let enclave = SgxEnclave::create(path, debug)
            .map_err(|e| anyhow::anyhow!("SgxEnclave::create failed: {:?}", e))?;
        let eid = enclave.eid();
        let _ = ENCLAVE.set(enclave);
        Ok(eid)
    }

    pub fn destroy_enclave(_eid: u64) {
        // SgxEnclave's Drop will call sgx_destroy_enclave
    }

    pub fn call_ecall_init_channel(
        eid: u64,
        enc_to_host_header: *mut u8,
        enc_to_host_buf: *mut u8,
        host_to_enc_header: *mut u8,
        host_to_enc_buf: *mut u8,
        capacity: u64,
    ) -> i32 {
        let mut retval: i32 = -1;
        let status = unsafe {
            ecall_init_channel(
                eid, &mut retval,
                enc_to_host_header, enc_to_host_buf,
                host_to_enc_header, host_to_enc_buf,
                capacity,
            )
        };
        if status != SgxStatus::Success {
            log::error!("ecall_init_channel SGX status: {:?}", status);
            return -1;
        }
        retval
    }

    pub fn call_ecall_init_data_channel(
        eid: u64,
        enc_to_host_header: *mut u8,
        enc_to_host_buf: *mut u8,
        host_to_enc_header: *mut u8,
        host_to_enc_buf: *mut u8,
        capacity: u64,
    ) -> i32 {
        let mut retval: i32 = -1;
        let status = unsafe {
            ecall_init_data_channel(
                eid, &mut retval,
                enc_to_host_header, enc_to_host_buf,
                host_to_enc_header, host_to_enc_buf,
                capacity,
            )
        };
        if status != SgxStatus::Success {
            log::error!("ecall_init_data_channel SGX status: {:?}", status);
            return -1;
        }
        retval
    }

    pub fn call_ecall_run(eid: u64, config_json: &[u8]) -> i32 {
        let mut retval: i32 = -1;
        let status = unsafe {
            ecall_run(
                eid, &mut retval,
                config_json.as_ptr(), config_json.len() as u64,
            )
        };
        if status != SgxStatus::Success {
            log::error!("ecall_run SGX status: {:?}", status);
            return -1;
        }
        retval
    }

    pub fn call_ecall_shutdown(eid: u64) -> i32 {
        let mut retval: i32 = -1;
        let status = unsafe { ecall_shutdown(eid, &mut retval) };
        if status != SgxStatus::Success {
            log::error!("ecall_shutdown SGX status: {:?}", status);
            return -1;
        }
        retval
    }
}

// ---------------------------------------------------------------------------
//  Mock mode (Windows / no SGX) – for development and testing
// ---------------------------------------------------------------------------
#[cfg(any(target_os = "windows", feature = "mock"))]
mod sgx {
    use log::info;

    static mut MOCK_EID: u64 = 0;

    pub fn create_enclave(path: &str) -> anyhow::Result<u64> {
        info!("[MOCK] create_enclave({})", path);
        unsafe {
            MOCK_EID += 1;
            Ok(MOCK_EID)
        }
    }

    pub fn destroy_enclave(eid: u64) {
        info!("[MOCK] destroy_enclave({})", eid);
    }

    pub fn call_ecall_init_channel(
        _eid: u64,
        _enc_to_host_header: *mut u8,
        _enc_to_host_buf: *mut u8,
        _host_to_enc_header: *mut u8,
        _host_to_enc_buf: *mut u8,
        _capacity: u64,
    ) -> i32 {
        info!("[MOCK] ecall_init_channel");
        0
    }

    pub fn call_ecall_init_data_channel(
        _eid: u64,
        _enc_to_host_header: *mut u8,
        _enc_to_host_buf: *mut u8,
        _host_to_enc_header: *mut u8,
        _host_to_enc_buf: *mut u8,
        _capacity: u64,
    ) -> i32 {
        info!("[MOCK] ecall_init_data_channel");
        0
    }

    pub fn call_ecall_run(_eid: u64, config_json: &[u8]) -> i32 {
        info!("[MOCK] ecall_run (config {} bytes)", config_json.len());
        // In mock mode, just return immediately
        0
    }

    pub fn call_ecall_shutdown(_eid: u64) -> i32 {
        info!("[MOCK] ecall_shutdown");
        0
    }
}

// Re-export public API
pub use sgx::*;
