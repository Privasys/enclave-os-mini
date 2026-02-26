// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side RPC dispatcher.
//!
//! Reads requests from the `enc_to_host` SPSC queue, dispatches them to
//! the appropriate handler (network, KV store, utility), and writes
//! responses back into the `host_to_enc` queue.
//!
//! This replaces ALL of the old individual OCALLs with a single message loop.
//!
//! # Threading model
//!
//! The dispatcher runs on a dedicated host thread (or the main thread).
//! It spin-polls the `enc_to_host` queue with exponential backoff.
//! When the enclave calls `ocall_notify()`, the host can optionally
//! wake immediately, but spinning is fine for high-throughput workloads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use log::{trace, debug, info, warn, error};

use enclave_os_common::queue::{SpscConsumer, SpscProducer};
use enclave_os_common::rpc::{self, RpcMethod};

use crate::kvstore;
use crate::net;

/// RPC dispatcher that bridges enclave requests to host services.
pub struct RpcDispatcher {
    /// Reads requests from the enclave.
    request_rx: SpscConsumer,
    /// Writes responses back to the enclave.
    response_tx: SpscProducer,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl RpcDispatcher {
    /// Create a new dispatcher from the raw queue endpoints.
    ///
    /// # Safety
    /// The producers/consumers must be correctly paired to the shared-memory
    /// queues allocated for the enclave channel.
    pub fn new(
        request_rx: SpscConsumer,
        response_tx: SpscProducer,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            request_rx,
            response_tx,
            shutdown,
        }
    }

    /// Run the dispatcher loop. Blocks until shutdown is signalled.
    pub fn run(&self) {
        info!("RPC dispatcher started");

        let mut backoff = Backoff::new();

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("RPC dispatcher: shutdown requested");
                break;
            }

            match self.request_rx.try_recv() {
                Some(msg) => {
                    backoff.reset();
                    self.dispatch(&msg);
                }
                None => {
                    backoff.spin();
                }
            }
        }

        info!("RPC dispatcher stopped");
    }

    /// Dispatch a single RPC request message.
    fn dispatch(&self, raw_msg: &[u8]) {
        let (req_id, method, payload) = match rpc::decode_request(raw_msg) {
            Some(r) => r,
            None => {
                error!("RPC dispatcher: malformed request ({} bytes)", raw_msg.len());
                return;
            }
        };

        trace!("RPC dispatch: req_id={} method={:?} payload_len={}", req_id, method, payload.len());

        let (status, response_payload) = match method {
            // ---- Network ----
            RpcMethod::NetTcpListen => self.handle_net_tcp_listen(payload),
            RpcMethod::NetTcpAccept => self.handle_net_tcp_accept(payload),
            RpcMethod::NetTcpConnect => self.handle_net_tcp_connect(payload),
            RpcMethod::NetSend => self.handle_net_send(payload),
            RpcMethod::NetRecv => self.handle_net_recv(payload),
            RpcMethod::NetClose => self.handle_net_close(payload),

            // ---- KV Store ----
            RpcMethod::KvPut => self.handle_kv_put(payload),
            RpcMethod::KvGet => self.handle_kv_get(payload),
            RpcMethod::KvDelete => self.handle_kv_delete(payload),
            RpcMethod::KvListKeys => self.handle_kv_list_keys(payload),

            // ---- Utility ----
            RpcMethod::GetCurrentTime => self.handle_get_current_time(),
            RpcMethod::Log => self.handle_log(payload),

            // ---- Lifecycle ----
            RpcMethod::Shutdown => {
                info!("RPC: Shutdown requested by enclave");
                self.shutdown.store(true, Ordering::Relaxed);
                (0, Vec::new())
            }
        };

        // Send response back to the enclave
        let resp = rpc::encode_response(req_id, status, &response_payload);
        self.response_tx.send(&resp);
    }

    // ====================================================================
    //  Network handlers
    // ====================================================================

    fn handle_net_tcp_listen(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (port, backlog) = match rpc::decode_net_tcp_listen_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        debug!("RPC: NetTcpListen(port={}, backlog={})", port, backlog);
        match net::tcp_listen(port, backlog) {
            Ok(fd) => (0, rpc::encode_fd(fd)),
            Err(e) => {
                error!("NetTcpListen failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_net_tcp_accept(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let listener_fd = match rpc::decode_net_tcp_accept_req(payload) {
            Some(fd) => fd,
            None => return (-1, Vec::new()),
        };
        match net::tcp_accept(listener_fd) {
            Ok((client_fd, addr)) => {
                trace!("RPC: NetTcpAccept -> fd={} peer={}", client_fd, addr);
                (0, rpc::encode_net_tcp_accept_resp(client_fd, &addr))
            }
            Err(_) => {
                // EWOULDBLOCK is normal
                (-11, Vec::new()) // EAGAIN
            }
        }
    }

    fn handle_net_tcp_connect(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (host, port) = match rpc::decode_net_tcp_connect_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        debug!("RPC: NetTcpConnect(host={}, port={})", host, port);
        match net::tcp_connect(&host, port) {
            Ok(fd) => (0, rpc::encode_fd(fd)),
            Err(e) => {
                error!("NetTcpConnect failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_net_send(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (fd, data) = match rpc::decode_net_send_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        match net::tcp_send(fd, data) {
            Ok(n) => (0, rpc::encode_i32(n as i32)),
            Err(e) => {
                error!("NetSend failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_net_recv(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (fd, max_len) = match rpc::decode_net_recv_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let mut buf = vec![0u8; max_len as usize];
        match net::tcp_recv(fd, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                (0, buf)
            }
            Err(_) => {
                // EWOULDBLOCK or error
                (-11, Vec::new())
            }
        }
    }

    fn handle_net_close(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if let Some(fd) = rpc::decode_net_close_req(payload) {
            debug!("RPC: NetClose(fd={})", fd);
            net::tcp_close(fd);
        }
        (0, Vec::new())
    }

    // ====================================================================
    //  KV store handlers
    // ====================================================================

    fn handle_kv_put(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key, value) = match rpc::decode_kv_put_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::put(table_str, key, value) {
            Ok(()) => (0, Vec::new()),
            Err(e) => {
                error!("KvPut failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_get(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key) = match rpc::decode_kv_get_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::get(table_str, key) {
            Ok(Some(val)) => (0, val),
            Ok(None) => (1, Vec::new()), // not found
            Err(e) => {
                error!("KvGet failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_delete(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, key) = match rpc::decode_kv_delete_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::delete(table_str, key) {
            Ok(true) => (0, Vec::new()),
            Ok(false) => (1, Vec::new()), // not found
            Err(e) => {
                error!("KvDelete failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    fn handle_kv_list_keys(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let (table, prefix) = match rpc::decode_kv_list_keys_req(payload) {
            Some(r) => r,
            None => return (-1, Vec::new()),
        };
        let table_str = core::str::from_utf8(table).unwrap_or("default");
        match kvstore::list_keys(table_str, prefix, 10_000) {
            Ok(keys) => {
                let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
                (0, rpc::encode_kv_list_keys_resp(&refs))
            }
            Err(e) => {
                error!("KvListKeys failed: {}", e);
                (-1, Vec::new())
            }
        }
    }

    // ====================================================================
    //  Utility handlers
    // ====================================================================

    fn handle_get_current_time(&self) -> (i32, Vec<u8>) {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (0, rpc::encode_u64(d.as_secs())),
            Err(_) => (-1, Vec::new()),
        }
    }

    fn handle_log(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if let Some((level, msg)) = rpc::decode_log_req(payload) {
            match level {
                0 => trace!("[enclave] {}", msg),
                1 => debug!("[enclave] {}", msg),
                2 => info!("[enclave] {}", msg),
                3 => warn!("[enclave] {}", msg),
                _ => error!("[enclave] {}", msg),
            }
        }
        // Log is fire-and-forget; no meaningful response needed.
        (0, Vec::new())
    }
}

// ---------------------------------------------------------------------------
//  Exponential backoff spinner
// ---------------------------------------------------------------------------

/// Simple exponential backoff for the polling loop.
struct Backoff {
    spin_count: u32,
}

impl Backoff {
    fn new() -> Self {
        Self { spin_count: 0 }
    }

    fn reset(&mut self) {
        self.spin_count = 0;
    }

    fn spin(&mut self) {
        if self.spin_count < 6 {
            // Hot spin with CPU hint (1-64 iterations)
            for _ in 0..(1 << self.spin_count) {
                core::hint::spin_loop();
            }
            self.spin_count += 1;
        } else if self.spin_count < 10 {
            // Yield to OS scheduler
            std::thread::yield_now();
            self.spin_count += 1;
        } else {
            // Sleep briefly (1ms) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“ the enclave will call ocall_notify to wake us
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
