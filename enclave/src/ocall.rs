// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall wrappers – safe Rust interfaces to host services.
//!
//! All host calls now go through the shared-memory SPSC queue via
//! `RpcClient`. The only actual OCALL is `ocall_notify()` (used
//! internally by `RpcClient` to wake the host dispatcher).
//!
//! The public API is kept identical so that `ratls/`, `https/`, and
//! `kvstore/` code does not need any changes.

use std::string::String;
use std::vec::Vec;

use crate::rpc_client::RpcClient;

// ---------------------------------------------------------------------------
//  Global RPC client accessor
// ---------------------------------------------------------------------------

/// Access the global RPC client (set during `ecall_init_channel`).
fn rpc() -> &'static RpcClient {
    crate::rpc_client_ref()
}

// ==========================================================================
//  Network wrappers
// ==========================================================================

/// Create a TCP listener, bind, and listen. Returns a socket handle.
pub fn net_tcp_listen(port: u16, backlog: i32) -> Result<i32, i32> {
    rpc().net_tcp_listen(port, backlog)
}

/// Accept an incoming TCP connection. Returns (client_fd, peer_address).
pub fn net_tcp_accept(listener_fd: i32) -> Result<(i32, String), i32> {
    rpc().net_tcp_accept(listener_fd)
}

/// Connect to a remote TCP endpoint. Returns a socket handle.
pub fn net_tcp_connect(host: &str, port: u16) -> Result<i32, i32> {
    rpc().net_tcp_connect(host, port)
}

/// Send data on a socket. Returns the number of bytes sent.
pub fn net_send(fd: i32, data: &[u8]) -> Result<usize, i32> {
    rpc().net_send(fd, data)
}

/// Receive data from a socket. Returns the bytes read.
pub fn net_recv(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let result = rpc().net_recv(fd, buf.len() as u32)?;
    let copy_len = result.len().min(buf.len());
    buf[..copy_len].copy_from_slice(&result[..copy_len]);
    Ok(copy_len)
}

/// Close a socket.
pub fn net_close(fd: i32) {
    rpc().net_close(fd);
}

// ==========================================================================
//  KV store wrappers
// ==========================================================================

/// Store an encrypted KV pair on the host in the given table.
pub fn kv_store_put(table: &[u8], enc_key: &[u8], enc_val: &[u8]) -> Result<(), i32> {
    rpc().kv_put(table, enc_key, enc_val)
}

/// Get an encrypted value from the host. Returns None if not found.
pub fn kv_store_get(table: &[u8], enc_key: &[u8], _max_val_size: usize) -> Result<Option<Vec<u8>>, i32> {
    // max_val_size is no longer needed – the RPC response carries the full value
    rpc().kv_get(table, enc_key)
}

/// Delete an encrypted KV entry on the host.
pub fn kv_store_delete(table: &[u8], enc_key: &[u8]) -> Result<bool, i32> {
    rpc().kv_delete(table, enc_key)
}

/// List keys in a table, optionally filtered by prefix.
pub fn kv_store_list_keys(table: &[u8], prefix: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    rpc().kv_list_keys(table, prefix)
}

// ==========================================================================
//  Utility wrappers
// ==========================================================================

/// Get the current UNIX timestamp from the host.
pub fn get_current_time() -> Result<u64, i32> {
    rpc().get_current_time()
}

/// Log a message via the host.
pub fn log(level: enclave_os_common::types::LogLevel, message: &str) {
    let level_u8 = match level {
        enclave_os_common::types::LogLevel::Trace => 0,
        enclave_os_common::types::LogLevel::Debug => 1,
        enclave_os_common::types::LogLevel::Info => 2,
        enclave_os_common::types::LogLevel::Warn => 3,
        enclave_os_common::types::LogLevel::Error => 4,
    };
    rpc().log(level_u8, message);
}

/// Convenience macros for logging (enclave-side).
#[macro_export]
macro_rules! enclave_log_info {
    ($($arg:tt)*) => {
        $crate::ocall::log(
            enclave_os_common::types::LogLevel::Info,
            &format!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! enclave_log_error {
    ($($arg:tt)*) => {
        $crate::ocall::log(
            enclave_os_common::types::LogLevel::Error,
            &format!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! enclave_log_debug {
    ($($arg:tt)*) => {
        $crate::ocall::log(
            enclave_os_common::types::LogLevel::Debug,
            &format!($($arg)*)
        )
    };
}
