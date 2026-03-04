// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OCall vtable — function pointers registered by the enclave core,
//! called by module crates to reach host services without depending
//! on the enclave crate directly.
//!
//! The enclave core registers the vtable once during startup (in
//! `ecall_run`, after the RPC channel is initialised).  Module crates
//! then call the convenience wrappers below — identical in signature
//! to the original `enclave::ocall::*` functions.

use crate::modules::AppIdentity;
use std::sync::OnceLock;

/// Function-pointer table for host services (network, KV store, time, log)
/// and enclave-internal services (cert store) that module crates need.
///
/// Each field matches the signature of the corresponding wrapper in
/// `enclave::ocall` or `enclave::ratls::cert_store`.
pub struct OcallVtable {
    // ── Network ──────────────────────────────────────────────────────
    pub net_tcp_listen: fn(u16, i32) -> Result<i32, i32>,
    pub net_tcp_accept: fn(i32) -> Result<(i32, String), i32>,
    pub net_tcp_connect: fn(&str, u16) -> Result<i32, i32>,
    pub net_send: fn(i32, &[u8]) -> Result<usize, i32>,
    pub net_recv: fn(i32, &mut [u8]) -> Result<usize, i32>,
    pub net_close: fn(i32),

    // ── KV store ─────────────────────────────────────────────────────
    pub kv_store_put: fn(&[u8], &[u8], &[u8]) -> Result<(), i32>,
    pub kv_store_get: fn(&[u8], &[u8]) -> Result<Option<Vec<u8>>, i32>,
    pub kv_store_delete: fn(&[u8], &[u8]) -> Result<bool, i32>,
    pub kv_store_list_keys: fn(&[u8], &[u8]) -> Result<Vec<Vec<u8>>, i32>,

    // ── Utility ──────────────────────────────────────────────────────
    pub get_current_time: fn() -> Result<u64, i32>,
    pub log: fn(u8, &str),

    // ── Cert store (enclave-internal, for dynamic app identities) ────
    pub cert_store_register: fn(AppIdentity),
    pub cert_store_unregister: fn(&str) -> bool,
}

static VTABLE: OnceLock<OcallVtable> = OnceLock::new();

/// Register the OCall vtable.  Must be called exactly once, before any
/// module code runs.  Panics if called a second time.
pub fn register(vt: OcallVtable) {
    VTABLE.set(vt).ok().expect("OcallVtable already registered");
}

// ---------------------------------------------------------------------------
//  Internal accessor
// ---------------------------------------------------------------------------

fn vt() -> &'static OcallVtable {
    VTABLE
        .get()
        .expect("OcallVtable not registered — call enclave_os_common::ocall::register() first")
}

// ---------------------------------------------------------------------------
//  Convenience wrappers (same signatures as enclave::ocall::*)
// ---------------------------------------------------------------------------

pub fn net_tcp_listen(port: u16, backlog: i32) -> Result<i32, i32> {
    (vt().net_tcp_listen)(port, backlog)
}

pub fn net_tcp_accept(listener_fd: i32) -> Result<(i32, String), i32> {
    (vt().net_tcp_accept)(listener_fd)
}

pub fn net_tcp_connect(host: &str, port: u16) -> Result<i32, i32> {
    (vt().net_tcp_connect)(host, port)
}

pub fn net_send(fd: i32, data: &[u8]) -> Result<usize, i32> {
    (vt().net_send)(fd, data)
}

pub fn net_recv(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    (vt().net_recv)(fd, buf)
}

pub fn net_close(fd: i32) {
    (vt().net_close)(fd)
}

pub fn kv_store_put(table: &[u8], enc_key: &[u8], enc_val: &[u8]) -> Result<(), i32> {
    (vt().kv_store_put)(table, enc_key, enc_val)
}

pub fn kv_store_get(table: &[u8], enc_key: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    (vt().kv_store_get)(table, enc_key)
}

pub fn kv_store_delete(table: &[u8], enc_key: &[u8]) -> Result<bool, i32> {
    (vt().kv_store_delete)(table, enc_key)
}

pub fn kv_store_list_keys(table: &[u8], prefix: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    (vt().kv_store_list_keys)(table, prefix)
}

pub fn get_current_time() -> Result<u64, i32> {
    (vt().get_current_time)()
}

pub fn log(level: u8, message: &str) {
    (vt().log)(level, message)
}

// ---------------------------------------------------------------------------
//  Cert store wrappers
// ---------------------------------------------------------------------------

/// Register a dynamic app identity (generates a per-app cert with its own Merkle tree).
pub fn cert_store_register(identity: AppIdentity) {
    (vt().cert_store_register)(identity)
}

/// Unregister an app by SNI hostname. Returns `true` if it was found.
pub fn cert_store_unregister(hostname: &str) -> bool {
    (vt().cert_store_unregister)(hostname)
}
