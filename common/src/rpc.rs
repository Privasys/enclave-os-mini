// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RPC protocol over SPSC shared-memory queues.
//!
//! Replaces all individual OCALLs with a single message-passing interface.
//! The enclave serializes an `RpcRequest` into the `enc_to_host` queue;
//! the host deserializes, dispatches, and writes an `RpcResponse` back
//! into the `host_to_enc` queue.
//!
//! # Wire format
//!
//! ```text
//! Request:  [8: req_id (LE u64)] [2: method (LE u16)] [4: payload_len (LE u32)] [payload...]
//! Response: [8: req_id (LE u64)] [4: status (LE i32)]  [4: payload_len (LE u32)] [payload...]
//! ```
//!
//! Total request header:  14 bytes
//! Total response header: 16 bytes
//!
//! The payload is method-specific, serialized with a compact binary encoding
//! (postcard/serde or hand-rolled, depending on no_std constraints).

#[cfg(feature = "sgx")]
use alloc::{string::String, string::ToString, vec::Vec};

use serde::{Deserialize, Serialize};

// ========================================================================
//  Method IDs
// ========================================================================

/// All RPC methods the enclave can call on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum RpcMethod {
    // -- Network --
    NetTcpListen     = 0x0100,
    NetTcpAccept     = 0x0101,
    NetTcpConnect    = 0x0102,
    NetSend          = 0x0103,
    NetRecv          = 0x0104,
    NetClose         = 0x0105,

    // -- KV Store --
    KvPut            = 0x0200,
    KvGet            = 0x0201,
    KvDelete         = 0x0202,
    KvListKeys       = 0x0203,

    // -- Utility --
    GetCurrentTime   = 0x0300,
    Log              = 0x0301,

    // -- Lifecycle --
    Shutdown         = 0xFF00,
}

impl RpcMethod {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0100 => Some(Self::NetTcpListen),
            0x0101 => Some(Self::NetTcpAccept),
            0x0102 => Some(Self::NetTcpConnect),
            0x0103 => Some(Self::NetSend),
            0x0104 => Some(Self::NetRecv),
            0x0105 => Some(Self::NetClose),
            0x0200 => Some(Self::KvPut),
            0x0201 => Some(Self::KvGet),
            0x0202 => Some(Self::KvDelete),
            0x0203 => Some(Self::KvListKeys),
            0x0300 => Some(Self::GetCurrentTime),
            0x0301 => Some(Self::Log),
            0xFF00 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

// ========================================================================
//  Request / Response wire encoding
// ========================================================================

/// Request header size in bytes: req_id(8) + method(2) + payload_len(4) = 14.
pub const REQ_HEADER_SIZE: usize = 14;

/// Response header size in bytes: req_id(8) + status(4) + payload_len(4) = 16.
pub const RESP_HEADER_SIZE: usize = 16;

/// Encode an RPC request into a byte buffer.
///
/// Format: `[u64 req_id LE] [u16 method LE] [u32 payload_len LE] [payload]`
pub fn encode_request(req_id: u64, method: RpcMethod, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REQ_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&req_id.to_le_bytes());
    buf.extend_from_slice(&(method as u16).to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode an RPC request header. Returns `(req_id, method, payload)`.
pub fn decode_request(data: &[u8]) -> Option<(u64, RpcMethod, &[u8])> {
    if data.len() < REQ_HEADER_SIZE {
        return None;
    }
    let req_id = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let method_raw = u16::from_le_bytes(data[8..10].try_into().ok()?);
    let payload_len = u32::from_le_bytes(data[10..14].try_into().ok()?) as usize;
    let method = RpcMethod::from_u16(method_raw)?;

    if data.len() < REQ_HEADER_SIZE + payload_len {
        return None;
    }
    let payload = &data[REQ_HEADER_SIZE..REQ_HEADER_SIZE + payload_len];
    Some((req_id, method, payload))
}

/// Encode an RPC response.
///
/// Format: `[u64 req_id LE] [i32 status LE] [u32 payload_len LE] [payload]`
pub fn encode_response(req_id: u64, status: i32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RESP_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&req_id.to_le_bytes());
    buf.extend_from_slice(&status.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode an RPC response header. Returns `(req_id, status, payload)`.
pub fn decode_response(data: &[u8]) -> Option<(u64, i32, &[u8])> {
    if data.len() < RESP_HEADER_SIZE {
        return None;
    }
    let req_id = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let status = i32::from_le_bytes(data[8..12].try_into().ok()?);
    let payload_len = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;

    if data.len() < RESP_HEADER_SIZE + payload_len {
        return None;
    }
    let payload = &data[RESP_HEADER_SIZE..RESP_HEADER_SIZE + payload_len];
    Some((req_id, status, payload))
}

// ========================================================================
//  Typed request/response payloads (compact binary encoding)
// ========================================================================

/// We use a minimal hand-rolled binary encoding for each method's arguments
/// and return values. This avoids pulling in a heavy serialization framework
/// in the enclave (postcard is an alternative if more complex types are needed).

// -- NetTcpListen --
pub fn encode_net_tcp_listen_req(port: u16, backlog: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6);
    buf.extend_from_slice(&port.to_le_bytes());
    buf.extend_from_slice(&backlog.to_le_bytes());
    buf
}
pub fn decode_net_tcp_listen_req(p: &[u8]) -> Option<(u16, i32)> {
    if p.len() < 6 { return None; }
    let port = u16::from_le_bytes(p[0..2].try_into().ok()?);
    let backlog = i32::from_le_bytes(p[2..6].try_into().ok()?);
    Some((port, backlog))
}
/// Response payload for listen: just the fd (4 bytes), status carries error.
pub fn encode_fd(fd: i32) -> Vec<u8> { fd.to_le_bytes().to_vec() }
pub fn decode_fd(p: &[u8]) -> Option<i32> {
    if p.len() < 4 { return None; }
    Some(i32::from_le_bytes(p[0..4].try_into().ok()?))
}

// -- NetTcpAccept --
pub fn encode_net_tcp_accept_req(listener_fd: i32) -> Vec<u8> {
    listener_fd.to_le_bytes().to_vec()
}
pub fn decode_net_tcp_accept_req(p: &[u8]) -> Option<i32> { decode_fd(p) }
/// Response: [i32 client_fd] [peer_addr as utf8 string]
pub fn encode_net_tcp_accept_resp(client_fd: i32, peer_addr: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + peer_addr.len());
    buf.extend_from_slice(&client_fd.to_le_bytes());
    buf.extend_from_slice(peer_addr.as_bytes());
    buf
}
pub fn decode_net_tcp_accept_resp(p: &[u8]) -> Option<(i32, String)> {
    if p.len() < 4 { return None; }
    let fd = i32::from_le_bytes(p[0..4].try_into().ok()?);
    let addr = core::str::from_utf8(&p[4..]).ok()?.to_string();
    Some((fd, addr))
}

// -- NetTcpConnect --
/// Payload: [u16 port] [host as utf8]
pub fn encode_net_tcp_connect_req(host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + host.len());
    buf.extend_from_slice(&port.to_le_bytes());
    buf.extend_from_slice(host.as_bytes());
    buf
}
pub fn decode_net_tcp_connect_req(p: &[u8]) -> Option<(String, u16)> {
    if p.len() < 2 { return None; }
    let port = u16::from_le_bytes(p[0..2].try_into().ok()?);
    let host = core::str::from_utf8(&p[2..]).ok()?.to_string();
    Some((host, port))
}

// -- NetSend --
/// Payload: [i32 fd] [data bytes]
pub fn encode_net_send_req(fd: i32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&fd.to_le_bytes());
    buf.extend_from_slice(data);
    buf
}
pub fn decode_net_send_req(p: &[u8]) -> Option<(i32, &[u8])> {
    if p.len() < 4 { return None; }
    let fd = i32::from_le_bytes(p[0..4].try_into().ok()?);
    Some((fd, &p[4..]))
}
/// Response: number of bytes sent (i32)
pub fn encode_i32(v: i32) -> Vec<u8> { v.to_le_bytes().to_vec() }
pub fn decode_i32(p: &[u8]) -> Option<i32> {
    if p.len() < 4 { return None; }
    Some(i32::from_le_bytes(p[0..4].try_into().ok()?))
}

// -- NetRecv --
/// Payload: [i32 fd] [u32 max_len]
pub fn encode_net_recv_req(fd: i32, max_len: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.extend_from_slice(&fd.to_le_bytes());
    buf.extend_from_slice(&max_len.to_le_bytes());
    buf
}
pub fn decode_net_recv_req(p: &[u8]) -> Option<(i32, u32)> {
    if p.len() < 8 { return None; }
    let fd = i32::from_le_bytes(p[0..4].try_into().ok()?);
    let max_len = u32::from_le_bytes(p[4..8].try_into().ok()?);
    Some((fd, max_len))
}
/// Response payload: the raw bytes received (or empty if error/status != 0)

// -- NetClose --
/// Payload: just fd
pub fn encode_net_close_req(fd: i32) -> Vec<u8> { fd.to_le_bytes().to_vec() }
pub fn decode_net_close_req(p: &[u8]) -> Option<i32> { decode_fd(p) }

// -- KvPut --
/// Payload: [u16 table_len] [table] [u32 key_len] [key] [value]
pub fn encode_kv_put_req(table: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + table.len() + 4 + key.len() + value.len());
    buf.extend_from_slice(&(table.len() as u16).to_le_bytes());
    buf.extend_from_slice(table);
    buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
    buf.extend_from_slice(key);
    buf.extend_from_slice(value);
    buf
}
pub fn decode_kv_put_req(p: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if p.len() < 2 { return None; }
    let table_len = u16::from_le_bytes(p[0..2].try_into().ok()?) as usize;
    if p.len() < 2 + table_len + 4 { return None; }
    let table = &p[2..2 + table_len];
    let off = 2 + table_len;
    let key_len = u32::from_le_bytes(p[off..off + 4].try_into().ok()?) as usize;
    if p.len() < off + 4 + key_len { return None; }
    let key = &p[off + 4..off + 4 + key_len];
    let value = &p[off + 4 + key_len..];
    Some((table, key, value))
}

// -- KvGet --
/// Payload: [u16 table_len] [table] [key]
/// Response payload: the value bytes (status=1 if not found, status=0 if found)
pub fn encode_kv_get_req(table: &[u8], key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + table.len() + key.len());
    buf.extend_from_slice(&(table.len() as u16).to_le_bytes());
    buf.extend_from_slice(table);
    buf.extend_from_slice(key);
    buf
}
pub fn decode_kv_get_req(p: &[u8]) -> Option<(&[u8], &[u8])> {
    if p.len() < 2 { return None; }
    let table_len = u16::from_le_bytes(p[0..2].try_into().ok()?) as usize;
    if p.len() < 2 + table_len { return None; }
    let table = &p[2..2 + table_len];
    let key = &p[2 + table_len..];
    Some((table, key))
}

// -- KvDelete --
/// Payload: [u16 table_len] [table] [key]
/// Response: status=0 deleted, status=1 not found
pub fn encode_kv_delete_req(table: &[u8], key: &[u8]) -> Vec<u8> {
    encode_kv_get_req(table, key) // same wire format
}
pub fn decode_kv_delete_req(p: &[u8]) -> Option<(&[u8], &[u8])> {
    decode_kv_get_req(p) // same wire format
}

// -- KvListKeys --
/// Request payload: [u16 table_len] [table] [prefix (optional)]
/// Response payload: [u32 count] { [u32 key_len] [key] }*
pub fn encode_kv_list_keys_req(table: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + table.len() + prefix.len());
    buf.extend_from_slice(&(table.len() as u16).to_le_bytes());
    buf.extend_from_slice(table);
    buf.extend_from_slice(prefix);
    buf
}
pub fn decode_kv_list_keys_req(p: &[u8]) -> Option<(&[u8], &[u8])> {
    decode_kv_get_req(p) // same layout: table + remaining bytes = prefix
}
pub fn encode_kv_list_keys_resp(keys: &[&[u8]]) -> Vec<u8> {
    let total: usize = keys.iter().map(|k| 4 + k.len()).sum();
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for key in keys {
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(key);
    }
    buf
}
pub fn decode_kv_list_keys_resp(p: &[u8]) -> Option<Vec<Vec<u8>>> {
    if p.len() < 4 { return None; }
    let count = u32::from_le_bytes(p[0..4].try_into().ok()?) as usize;
    let mut off = 4;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 4 > p.len() { return None; }
        let kl = u32::from_le_bytes(p[off..off + 4].try_into().ok()?) as usize;
        off += 4;
        if off + kl > p.len() { return None; }
        keys.push(p[off..off + kl].to_vec());
        off += kl;
    }
    Some(keys)
}

// -- GetCurrentTime --
/// Request: no payload
/// Response: [u64 timestamp LE]
pub fn encode_u64(v: u64) -> Vec<u8> { v.to_le_bytes().to_vec() }
pub fn decode_u64(p: &[u8]) -> Option<u64> {
    if p.len() < 8 { return None; }
    Some(u64::from_le_bytes(p[0..8].try_into().ok()?))
}

// -- Log --
/// Payload: [i32 level] [message utf8]
pub fn encode_log_req(level: i32, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + message.len());
    buf.extend_from_slice(&level.to_le_bytes());
    buf.extend_from_slice(message.as_bytes());
    buf
}
pub fn decode_log_req(p: &[u8]) -> Option<(i32, &str)> {
    if p.len() < 4 { return None; }
    let level = i32::from_le_bytes(p[0..4].try_into().ok()?);
    let msg = core::str::from_utf8(&p[4..]).ok()?;
    Some((level, msg))
}

// ========================================================================
//  Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ==============================================================
    //  Request / Response header encoding
    // ==============================================================

    #[test]
    fn test_request_roundtrip() {
        let payload = b"hello";
        let encoded = encode_request(42, RpcMethod::NetTcpListen, payload);
        let (req_id, method, decoded_payload) = decode_request(&encoded).unwrap();
        assert_eq!(req_id, 42);
        assert_eq!(method, RpcMethod::NetTcpListen);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_response_roundtrip() {
        let payload = b"world";
        let encoded = encode_response(42, 0, payload);
        let (req_id, status, decoded_payload) = decode_response(&encoded).unwrap();
        assert_eq!(req_id, 42);
        assert_eq!(status, 0);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_request_empty_payload() {
        let encoded = encode_request(1, RpcMethod::Shutdown, &[]);
        assert_eq!(encoded.len(), REQ_HEADER_SIZE);
        let (req_id, method, payload) = decode_request(&encoded).unwrap();
        assert_eq!(req_id, 1);
        assert_eq!(method, RpcMethod::Shutdown);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_response_empty_payload() {
        let encoded = encode_response(99, -1, &[]);
        assert_eq!(encoded.len(), RESP_HEADER_SIZE);
        let (req_id, status, payload) = decode_response(&encoded).unwrap();
        assert_eq!(req_id, 99);
        assert_eq!(status, -1);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_request_truncated_header() {
        assert!(decode_request(&[0u8; 13]).is_none()); // 13 < 14
    }

    #[test]
    fn test_response_truncated_header() {
        assert!(decode_response(&[0u8; 15]).is_none()); // 15 < 16
    }

    #[test]
    fn test_request_truncated_payload() {
        // Header says 100 bytes of payload, but only 5 are present
        let mut buf = encode_request(1, RpcMethod::Log, &[0u8; 100]);
        buf.truncate(REQ_HEADER_SIZE + 5);
        assert!(decode_request(&buf).is_none());
    }

    #[test]
    fn test_response_truncated_payload() {
        let mut buf = encode_response(1, 0, &[0u8; 50]);
        buf.truncate(RESP_HEADER_SIZE + 10);
        assert!(decode_response(&buf).is_none());
    }

    #[test]
    fn test_request_unknown_method() {
        let mut buf = vec![0u8; REQ_HEADER_SIZE];
        // req_id = 1
        buf[0..8].copy_from_slice(&1u64.to_le_bytes());
        // method = 0xBEEF (unknown)
        buf[8..10].copy_from_slice(&0xBEEFu16.to_le_bytes());
        // payload_len = 0
        buf[10..14].copy_from_slice(&0u32.to_le_bytes());
        assert!(decode_request(&buf).is_none());
    }

    #[test]
    fn test_all_method_ids_roundtrip() {
        let methods = [
            RpcMethod::NetTcpListen,
            RpcMethod::NetTcpAccept,
            RpcMethod::NetTcpConnect,
            RpcMethod::NetSend,
            RpcMethod::NetRecv,
            RpcMethod::NetClose,
            RpcMethod::KvPut,
            RpcMethod::KvGet,
            RpcMethod::KvDelete,
            RpcMethod::KvListKeys,
            RpcMethod::GetCurrentTime,
            RpcMethod::Log,
            RpcMethod::Shutdown,
        ];
        for (i, &method) in methods.iter().enumerate() {
            let req_id = (i as u64) + 1;
            let payload = format!("payload_{}", i);
            let encoded = encode_request(req_id, method, payload.as_bytes());
            let (rid, m, p) = decode_request(&encoded).unwrap();
            assert_eq!(rid, req_id);
            assert_eq!(m, method);
            assert_eq!(p, payload.as_bytes());
        }
    }

    #[test]
    fn test_response_negative_status() {
        let encoded = encode_response(5, -42, b"error detail");
        let (req_id, status, payload) = decode_response(&encoded).unwrap();
        assert_eq!(req_id, 5);
        assert_eq!(status, -42);
        assert_eq!(payload, b"error detail");
    }

    #[test]
    fn test_large_req_id() {
        let encoded = encode_request(u64::MAX, RpcMethod::Shutdown, &[]);
        let (req_id, method, _) = decode_request(&encoded).unwrap();
        assert_eq!(req_id, u64::MAX);
        assert_eq!(method, RpcMethod::Shutdown);
    }

    // ==============================================================
    //  Typed payload encoding
    // ==============================================================

    #[test]
    fn test_net_tcp_listen_payload() {
        let encoded = encode_net_tcp_listen_req(443, 128);
        let (port, backlog) = decode_net_tcp_listen_req(&encoded).unwrap();
        assert_eq!(port, 443);
        assert_eq!(backlog, 128);
    }

    #[test]
    fn test_net_tcp_listen_boundary_values() {
        // Port 0 (ephemeral)
        let e = encode_net_tcp_listen_req(0, 0);
        let (p, b) = decode_net_tcp_listen_req(&e).unwrap();
        assert_eq!(p, 0);
        assert_eq!(b, 0);

        // Max port
        let e = encode_net_tcp_listen_req(u16::MAX, i32::MAX);
        let (p, b) = decode_net_tcp_listen_req(&e).unwrap();
        assert_eq!(p, u16::MAX);
        assert_eq!(b, i32::MAX);
    }

    #[test]
    fn test_net_tcp_listen_too_short() {
        assert!(decode_net_tcp_listen_req(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_fd_roundtrip() {
        assert_eq!(decode_fd(&encode_fd(42)).unwrap(), 42);
        assert_eq!(decode_fd(&encode_fd(-1)).unwrap(), -1);
        assert_eq!(decode_fd(&encode_fd(0)).unwrap(), 0);
        assert_eq!(decode_fd(&encode_fd(i32::MAX)).unwrap(), i32::MAX);
        assert_eq!(decode_fd(&encode_fd(i32::MIN)).unwrap(), i32::MIN);
    }

    #[test]
    fn test_kv_put_payload() {
        let table = b"my_table";
        let key = b"my_key";
        let value = b"my_value";
        let encoded = encode_kv_put_req(table, key, value);
        let (dt, dk, dv) = decode_kv_put_req(&encoded).unwrap();
        assert_eq!(dt, table);
        assert_eq!(dk, key);
        assert_eq!(dv, value);
    }

    #[test]
    fn test_kv_put_empty_value() {
        let encoded = encode_kv_put_req(b"t", b"key", b"");
        let (dt, dk, dv) = decode_kv_put_req(&encoded).unwrap();
        assert_eq!(dt, b"t");
        assert_eq!(dk, b"key");
        assert!(dv.is_empty());
    }

    #[test]
    fn test_kv_put_empty_key() {
        let encoded = encode_kv_put_req(b"t", b"", b"value");
        let (_dt, dk, dv) = decode_kv_put_req(&encoded).unwrap();
        assert!(dk.is_empty());
        assert_eq!(dv, b"value");
    }

    #[test]
    fn test_kv_put_large() {
        let table = b"app:test";
        let key = vec![0xAA; 256];
        let value = vec![0xBB; 64000];
        let encoded = encode_kv_put_req(table, &key, &value);
        let (dt, dk, dv) = decode_kv_put_req(&encoded).unwrap();
        assert_eq!(dt, table);
        assert_eq!(dk, &key[..]);
        assert_eq!(dv, &value[..]);
    }

    #[test]
    fn test_kv_put_truncated() {
        // table_len = 3 but then key_len = 10 with not enough data
        let mut buf = vec![0u8; 2];
        buf[0..2].copy_from_slice(&3u16.to_le_bytes()); // table_len = 3
        buf.extend_from_slice(b"abc"); // table
        buf.extend_from_slice(&10u32.to_le_bytes()); // key_len = 10
        buf.extend_from_slice(&[1, 2]); // only 2 bytes of "key"
        assert!(decode_kv_put_req(&buf).is_none());
    }

    #[test]
    fn test_kv_get_req() {
        let table = b"app:myapp";
        let key = b"some_key";
        let encoded = encode_kv_get_req(table, key);
        let (dt, dk) = decode_kv_get_req(&encoded).unwrap();
        assert_eq!(dt, table);
        assert_eq!(dk, key);
    }

    #[test]
    fn test_kv_list_keys_roundtrip() {
        let table = b"app:test";
        let prefix = b"fs:";
        let encoded = encode_kv_list_keys_req(table, prefix);
        let (dt, dp) = decode_kv_list_keys_req(&encoded).unwrap();
        assert_eq!(dt, table);
        assert_eq!(dp, prefix);
    }

    #[test]
    fn test_kv_list_keys_resp_roundtrip() {
        let keys: &[&[u8]] = &[b"key1", b"key2", b"key3"];
        let encoded = encode_kv_list_keys_resp(keys);
        let decoded = decode_kv_list_keys_resp(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], b"key1");
        assert_eq!(decoded[1], b"key2");
        assert_eq!(decoded[2], b"key3");
    }

    #[test]
    fn test_kv_list_keys_resp_empty() {
        let keys: &[&[u8]] = &[];
        let encoded = encode_kv_list_keys_resp(keys);
        let decoded = decode_kv_list_keys_resp(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_accept_resp() {
        let encoded = encode_net_tcp_accept_resp(42, "192.168.1.1:5000");
        let (fd, addr) = decode_net_tcp_accept_resp(&encoded).unwrap();
        assert_eq!(fd, 42);
        assert_eq!(addr, "192.168.1.1:5000");
    }

    #[test]
    fn test_accept_resp_ipv6() {
        let encoded = encode_net_tcp_accept_resp(100, "[::1]:443");
        let (fd, addr) = decode_net_tcp_accept_resp(&encoded).unwrap();
        assert_eq!(fd, 100);
        assert_eq!(addr, "[::1]:443");
    }

    #[test]
    fn test_connect_req_roundtrip() {
        let encoded = encode_net_tcp_connect_req("api.example.com", 443);
        let (host, port) = decode_net_tcp_connect_req(&encoded).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_send_req_roundtrip() {
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        let encoded = encode_net_send_req(10, data);
        let (fd, d) = decode_net_send_req(&encoded).unwrap();
        assert_eq!(fd, 10);
        assert_eq!(d, data);
    }

    #[test]
    fn test_recv_req_roundtrip() {
        let encoded = encode_net_recv_req(10, 16384);
        let (fd, max) = decode_net_recv_req(&encoded).unwrap();
        assert_eq!(fd, 10);
        assert_eq!(max, 16384);
    }

    #[test]
    fn test_close_req_roundtrip() {
        let encoded = encode_net_close_req(7);
        let fd = decode_net_close_req(&encoded).unwrap();
        assert_eq!(fd, 7);
    }

    #[test]
    fn test_i32_roundtrip() {
        assert_eq!(decode_i32(&encode_i32(0)).unwrap(), 0);
        assert_eq!(decode_i32(&encode_i32(-1)).unwrap(), -1);
        assert_eq!(decode_i32(&encode_i32(12345)).unwrap(), 12345);
    }

    #[test]
    fn test_u64_roundtrip() {
        assert_eq!(decode_u64(&encode_u64(0)).unwrap(), 0);
        assert_eq!(decode_u64(&encode_u64(u64::MAX)).unwrap(), u64::MAX);
        assert_eq!(decode_u64(&encode_u64(1709123456)).unwrap(), 1709123456);
    }

    #[test]
    fn test_log_req_roundtrip() {
        let encoded = encode_log_req(2, "Hello from enclave");
        let (level, msg) = decode_log_req(&encoded).unwrap();
        assert_eq!(level, 2);
        assert_eq!(msg, "Hello from enclave");
    }

    #[test]
    fn test_log_req_empty_message() {
        let encoded = encode_log_req(0, "");
        let (level, msg) = decode_log_req(&encoded).unwrap();
        assert_eq!(level, 0);
        assert_eq!(msg, "");
    }

    #[test]
    fn test_log_req_unicode() {
        let encoded = encode_log_req(3, "Ünïcödë 日本語 🔒");
        let (level, msg) = decode_log_req(&encoded).unwrap();
        assert_eq!(level, 3);
        assert_eq!(msg, "Ünïcödë 日本語 🔒");
    }

    // ==============================================================
    //  Request → SPSC → Response full roundtrip
    // ==============================================================

    #[test]
    fn test_rpc_over_spsc_roundtrip() {
        use crate::queue::{SpscQueueHeader, SpscProducer, SpscConsumer};

        fn alloc(cap: u64) -> (SpscProducer, SpscConsumer) {
            let header = Box::into_raw(Box::new(SpscQueueHeader::new(cap)));
            let buffer = vec![0u8; cap as usize];
            let buf_ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut u8;
            unsafe {
                let p = SpscProducer::from_raw(header, buf_ptr);
                let c = SpscConsumer::from_raw(header, buf_ptr);
                (p, c)
            }
        }

        // Simulate enclave→host request and host→enclave response via queues
        let (enc_tx, host_rx) = alloc(8192);
        let (host_tx, enc_rx) = alloc(8192);

        // Enclave: send NetTcpListen request
        let req_id = 1u64;
        let payload = encode_net_tcp_listen_req(443, 128);
        let msg = encode_request(req_id, RpcMethod::NetTcpListen, &payload);
        enc_tx.send(&msg);

        // Host: read, decode, respond
        let raw = host_rx.recv();
        let (rid, method, p) = decode_request(&raw).unwrap();
        assert_eq!(rid, req_id);
        assert_eq!(method, RpcMethod::NetTcpListen);
        let (port, backlog) = decode_net_tcp_listen_req(p).unwrap();
        assert_eq!(port, 443);
        assert_eq!(backlog, 128);

        // Host responds with fd=100
        let resp = encode_response(rid, 0, &encode_fd(100));
        host_tx.send(&resp);

        // Enclave: read response
        let resp_raw = enc_rx.recv();
        let (resp_id, status, resp_payload) = decode_response(&resp_raw).unwrap();
        assert_eq!(resp_id, req_id);
        assert_eq!(status, 0);
        assert_eq!(decode_fd(resp_payload).unwrap(), 100);
    }

    #[test]
    fn test_rpc_method_from_u16_exhaustive() {
        // All valid method IDs
        assert_eq!(RpcMethod::from_u16(0x0100), Some(RpcMethod::NetTcpListen));
        assert_eq!(RpcMethod::from_u16(0x0101), Some(RpcMethod::NetTcpAccept));
        assert_eq!(RpcMethod::from_u16(0x0102), Some(RpcMethod::NetTcpConnect));
        assert_eq!(RpcMethod::from_u16(0x0103), Some(RpcMethod::NetSend));
        assert_eq!(RpcMethod::from_u16(0x0104), Some(RpcMethod::NetRecv));
        assert_eq!(RpcMethod::from_u16(0x0105), Some(RpcMethod::NetClose));
        assert_eq!(RpcMethod::from_u16(0x0200), Some(RpcMethod::KvPut));
        assert_eq!(RpcMethod::from_u16(0x0201), Some(RpcMethod::KvGet));
        assert_eq!(RpcMethod::from_u16(0x0202), Some(RpcMethod::KvDelete));
        assert_eq!(RpcMethod::from_u16(0x0203), Some(RpcMethod::KvListKeys));
        assert_eq!(RpcMethod::from_u16(0x0300), Some(RpcMethod::GetCurrentTime));
        assert_eq!(RpcMethod::from_u16(0x0301), Some(RpcMethod::Log));
        assert_eq!(RpcMethod::from_u16(0xFF00), Some(RpcMethod::Shutdown));

        // Invalid IDs
        assert_eq!(RpcMethod::from_u16(0x0000), None);
        assert_eq!(RpcMethod::from_u16(0x0106), None);
        assert_eq!(RpcMethod::from_u16(0x0204), None);
        assert_eq!(RpcMethod::from_u16(0xFFFF), None);
    }
}
