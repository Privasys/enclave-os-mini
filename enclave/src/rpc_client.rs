// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave-side RPC client.
//!
//! Wraps the SPSC queues to provide a typed, synchronous call interface.
//! Each method encodes an RPC request, sends it to the host via the
//! `enc_to_host` queue, calls `ocall_notify()` to wake the host dispatcher,
//! and then spin-waits for the matching response on the `host_to_enc` queue.
//!
//! This replaces all the individual OCALL wrappers with a single
//! message-passing channel.

use std::string::String;
use std::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use enclave_os_common::queue::{SpscProducer, SpscConsumer};
use enclave_os_common::rpc::{self, RpcMethod};

// ---------------------------------------------------------------------------
//  External: the single OCALL
// ---------------------------------------------------------------------------

extern "C" {
    fn ocall_notify() -> u32;
}

/// Notify the host that there is a pending request.
#[inline]
fn notify_host() {
    unsafe {
        ocall_notify();
    }
}

// ---------------------------------------------------------------------------
//  RPC client state
// ---------------------------------------------------------------------------

/// Global request ID counter (monotonically increasing).
static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);

fn next_req_id() -> u64 {
    NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed)
}

/// Enclave-side RPC client for calling host services.
pub struct RpcClient {
    /// Sends requests to the host.
    request_tx: SpscProducer,
    /// Receives responses from the host.
    response_rx: SpscConsumer,
}

// SAFETY: RpcClient uses SPSC queues backed by shared memory pointers.
// In the SGX enclave, it is accessed from a single thread only.
// The raw pointers inside SpscProducer/SpscConsumer point to host memory
// that remains valid for the enclave's lifetime.
unsafe impl Send for RpcClient {}
unsafe impl Sync for RpcClient {}

impl RpcClient {
    /// Create a client from the queue endpoints.
    ///
    /// - `request_tx`: producer for `enc_to_host` (enclave writes, host reads)
    /// - `response_rx`: consumer for `host_to_enc` (host writes, enclave reads)
    pub fn new(request_tx: SpscProducer, response_rx: SpscConsumer) -> Self {
        Self {
            request_tx,
            response_rx,
        }
    }

    // ====================================================================
    //  Core RPC call
    // ====================================================================

    /// Send an RPC request and wait for the matching response.
    ///
    /// Returns `(status, payload)` from the host's response.
    fn call(&self, method: RpcMethod, payload: &[u8]) -> (i32, Vec<u8>) {
        let req_id = next_req_id();
        let msg = rpc::encode_request(req_id, method, payload);

        // Send
        self.request_tx.send(&msg);

        // Wake the host dispatcher
        notify_host();

        // Wait for response
        loop {
            let resp_raw = self.response_rx.recv();
            if let Some((resp_id, status, resp_payload)) = rpc::decode_response(&resp_raw) {
                if resp_id == req_id {
                    return (status, resp_payload.to_vec());
                }
                // Mismatched ID – shouldn't happen in SPSC, but be safe
                // In a single-threaded enclave, responses arrive in order.
            }
            // Malformed response – try again
        }
    }

    // ====================================================================
    //  Network calls
    // ====================================================================

    /// Create a TCP listener on `port` with `backlog`. Returns fd.
    pub fn net_tcp_listen(&self, port: u16, backlog: i32) -> Result<i32, i32> {
        let payload = rpc::encode_net_tcp_listen_req(port, backlog);
        let (status, resp) = self.call(RpcMethod::NetTcpListen, &payload);
        if status == 0 {
            Ok(rpc::decode_fd(&resp).unwrap_or(-1))
        } else {
            Err(status)
        }
    }

    /// Accept a connection on listener `fd`. Returns (client_fd, peer_addr).
    pub fn net_tcp_accept(&self, listener_fd: i32) -> Result<(i32, String), i32> {
        let payload = rpc::encode_net_tcp_accept_req(listener_fd);
        let (status, resp) = self.call(RpcMethod::NetTcpAccept, &payload);
        if status == 0 {
            match rpc::decode_net_tcp_accept_resp(&resp) {
                Some((fd, addr)) => Ok((fd, addr)),
                None => Err(-1),
            }
        } else {
            Err(status)
        }
    }

    /// Connect to `host:port`. Returns fd.
    pub fn net_tcp_connect(&self, host: &str, port: u16) -> Result<i32, i32> {
        let payload = rpc::encode_net_tcp_connect_req(host, port);
        let (status, resp) = self.call(RpcMethod::NetTcpConnect, &payload);
        if status == 0 {
            Ok(rpc::decode_fd(&resp).unwrap_or(-1))
        } else {
            Err(status)
        }
    }

    /// Send `data` on `fd`. Returns bytes sent.
    pub fn net_send(&self, fd: i32, data: &[u8]) -> Result<usize, i32> {
        let payload = rpc::encode_net_send_req(fd, data);
        let (status, resp) = self.call(RpcMethod::NetSend, &payload);
        if status == 0 {
            Ok(rpc::decode_i32(&resp).unwrap_or(0) as usize)
        } else {
            Err(status)
        }
    }

    /// Receive up to `max_len` bytes from `fd`.
    pub fn net_recv(&self, fd: i32, max_len: u32) -> Result<Vec<u8>, i32> {
        let payload = rpc::encode_net_recv_req(fd, max_len);
        let (status, resp) = self.call(RpcMethod::NetRecv, &payload);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }

    /// Close socket `fd`.
    pub fn net_close(&self, fd: i32) {
        let payload = rpc::encode_net_close_req(fd);
        let _ = self.call(RpcMethod::NetClose, &payload);
    }

    // ====================================================================
    //  KV store calls
    // ====================================================================

    /// Store an encrypted KV pair in the given table.
    pub fn kv_put(&self, table: &[u8], enc_key: &[u8], enc_val: &[u8]) -> Result<(), i32> {
        let payload = rpc::encode_kv_put_req(table, enc_key, enc_val);
        let (status, _) = self.call(RpcMethod::KvPut, &payload);
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Get an encrypted value from the given table. Returns `Ok(None)` if not found (status == 1).
    pub fn kv_get(&self, table: &[u8], enc_key: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let payload = rpc::encode_kv_get_req(table, enc_key);
        let (status, resp) = self.call(RpcMethod::KvGet, &payload);
        match status {
            0 => Ok(Some(resp)),
            1 => Ok(None),
            _ => Err(status),
        }
    }

    /// Delete an entry from the given table. Returns true if it existed.
    pub fn kv_delete(&self, table: &[u8], enc_key: &[u8]) -> Result<bool, i32> {
        let payload = rpc::encode_kv_delete_req(table, enc_key);
        let (status, _) = self.call(RpcMethod::KvDelete, &payload);
        match status {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(status),
        }
    }

    /// List keys in the given table, optionally filtered by prefix.
    pub fn kv_list_keys(&self, table: &[u8], prefix: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        let payload = rpc::encode_kv_list_keys_req(table, prefix);
        let (status, resp) = self.call(RpcMethod::KvListKeys, &payload);
        if status == 0 {
            Ok(rpc::decode_kv_list_keys_resp(&resp).unwrap_or_default())
        } else {
            Err(status)
        }
    }

    // ====================================================================
    //  Utility calls
    // ====================================================================

    /// Get current UNIX timestamp from the host.
    pub fn get_current_time(&self) -> Result<u64, i32> {
        let (status, resp) = self.call(RpcMethod::GetCurrentTime, &[]);
        if status == 0 {
            Ok(rpc::decode_u64(&resp).unwrap_or(0))
        } else {
            Err(status)
        }
    }

    /// Log a message via the host.
    pub fn log(&self, level: u8, message: &str) {
        let payload = rpc::encode_log_req(level as i32, message);
        // Fire-and-forget: we still wait for the response to maintain ordering,
        // but we discard the result.
        let _ = self.call(RpcMethod::Log, &payload);
    }

    /// Signal shutdown to the host.
    pub fn shutdown(&self) {
        let _ = self.call(RpcMethod::Shutdown, &[]);
    }

    // ====================================================================
    //  DCAP attestation calls
    // ====================================================================

    /// Get the Quoting Enclave's target info (512-byte `sgx_target_info_t`).
    ///
    /// The enclave needs this to call `sgx_create_report()` targeting the QE,
    /// which then signs the report as a DCAP Quote v3.
    pub fn qe_get_target_info(&self) -> Result<Vec<u8>, i32> {
        let (status, resp) = self.call(RpcMethod::QeGetTargetInfo, &[]);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }

    /// Get a DCAP Quote v3 from a raw SGX report (432 bytes).
    ///
    /// The host calls `sgx_qe_get_quote()` which engages the Quoting Enclave
    /// to sign the report. Returns the full DCAP quote (typically ~4-5 KB).
    pub fn qe_get_quote(&self, report_bytes: &[u8]) -> Result<Vec<u8>, i32> {
        let (status, resp) = self.call(RpcMethod::QeGetQuote, report_bytes);
        if status == 0 {
            Ok(resp)
        } else {
            Err(status)
        }
    }
}
