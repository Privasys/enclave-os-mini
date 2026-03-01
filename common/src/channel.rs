// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Data channel protocol: multiplexed TCP proxy ↔ enclave communication.
//!
//! The data channel carries raw TCP bytes between the host-side TCP proxy
//! and the enclave's TLS stack. Each message is tagged with a `conn_id`
//! so the enclave can multiplex many TCP connections over a single SPSC
//! queue pair.
//!
//! # Wire format (inside SPSC queue messages)
//!
//! The SPSC queue already provides length-delimited framing (4-byte LE
//! length prefix per message). Within each queue message:
//!
//! ```text
//! [1 byte: msg_type] [4 bytes: conn_id (LE u32)] [payload ...]
//! ```
//!
//! # Message types
//!
//! ## host → enclave (`data_host_to_enc` queue)
//!
//! | Type | Value | Payload | Description |
//! |------|-------|---------|-------------|
//! | `TcpNew`   | 0x01 | UTF-8 peer address | New TCP connection accepted |
//! | `TcpData`  | 0x02 | raw bytes          | TCP segment(s) from client |
//! | `TcpClose` | 0x03 | (empty)            | Connection closed by peer  |
//!
//! ## enclave → host (`data_enc_to_host` queue)
//!
//! | Type | Value | Payload | Description |
//! |------|-------|---------|-------------|
//! | `TcpData`  | 0x02 | raw bytes | TLS bytes to send to client |
//! | `TcpClose` | 0x03 | (empty)   | Enclave closing connection  |
//!
//! # Queue layout
//!
//! Two SPSC queue pairs are used:
//! - **RPC channel** (existing): enclave ↔ host RPC for KV, time, log,
//!   shutdown, and egress socket calls.
//! - **Data channel** (new): host TCP proxy ↔ enclave TLS engine for
//!   inbound connections only.

#[cfg(feature = "sgx")]
use alloc::string::String;
#[cfg(feature = "sgx")]
use alloc::vec::Vec;

/// Header size: 1 byte msg_type + 4 bytes conn_id = 5.
pub const CHANNEL_MSG_HEADER: usize = 5;

/// Maximum data channel payload size: 1 MiB.
///
/// With the TCP proxy buffering full reads, typical messages are 1–64 KB.
/// The 1 MiB limit is a safety cap — large WASM uploads arrive as
/// multiple TCP segments anyway.
pub const MAX_CHANNEL_PAYLOAD: usize = 1024 * 1024;

// ========================================================================
//  Message types
// ========================================================================

/// Data channel message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelMsgType {
    /// New TCP connection accepted (host → enclave).
    /// Payload: UTF-8 peer address string.
    TcpNew = 0x01,

    /// Raw TCP data (bidirectional).
    /// Payload: raw bytes (TLS records).
    TcpData = 0x02,

    /// Connection closed (bidirectional).
    /// Payload: empty.
    TcpClose = 0x03,
}

impl ChannelMsgType {
    /// Parse a message type from a byte.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::TcpNew),
            0x02 => Some(Self::TcpData),
            0x03 => Some(Self::TcpClose),
            _ => None,
        }
    }
}

// ========================================================================
//  Encoding / decoding
// ========================================================================

/// Encode a data channel message.
///
/// Format: `[u8 msg_type] [u32 conn_id LE] [payload]`
///
/// The caller writes the returned buffer into the SPSC queue (which adds
/// its own 4-byte length prefix).
pub fn encode_channel_msg(msg_type: ChannelMsgType, conn_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHANNEL_MSG_HEADER + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&conn_id.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a data channel message.
///
/// Returns `Some((msg_type, conn_id, payload))` on success.
pub fn decode_channel_msg(data: &[u8]) -> Option<(ChannelMsgType, u32, &[u8])> {
    if data.len() < CHANNEL_MSG_HEADER {
        return None;
    }
    let msg_type = ChannelMsgType::from_u8(data[0])?;
    let conn_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload = &data[CHANNEL_MSG_HEADER..];

    if payload.len() > MAX_CHANNEL_PAYLOAD {
        return None; // reject oversized
    }

    Some((msg_type, conn_id, payload))
}

/// Convenience: encode a TcpNew message.
#[inline]
pub fn encode_tcp_new(conn_id: u32, peer_addr: &str) -> Vec<u8> {
    encode_channel_msg(ChannelMsgType::TcpNew, conn_id, peer_addr.as_bytes())
}

/// Convenience: encode a TcpData message.
#[inline]
pub fn encode_tcp_data(conn_id: u32, data: &[u8]) -> Vec<u8> {
    encode_channel_msg(ChannelMsgType::TcpData, conn_id, data)
}

/// Convenience: encode a TcpClose message.
#[inline]
pub fn encode_tcp_close(conn_id: u32) -> Vec<u8> {
    encode_channel_msg(ChannelMsgType::TcpClose, conn_id, &[])
}

// ========================================================================
//  Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_tcp_new() {
        let msg = encode_tcp_new(42, "127.0.0.1:8080");
        let (typ, id, payload) = decode_channel_msg(&msg).unwrap();
        assert_eq!(typ, ChannelMsgType::TcpNew);
        assert_eq!(id, 42);
        assert_eq!(core::str::from_utf8(payload).unwrap(), "127.0.0.1:8080");
    }

    #[test]
    fn test_roundtrip_tcp_data() {
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x05]; // fake TLS record
        let msg = encode_tcp_data(99, &data);
        let (typ, id, payload) = decode_channel_msg(&msg).unwrap();
        assert_eq!(typ, ChannelMsgType::TcpData);
        assert_eq!(id, 99);
        assert_eq!(payload, &data[..]);
    }

    #[test]
    fn test_roundtrip_tcp_close() {
        let msg = encode_tcp_close(7);
        let (typ, id, payload) = decode_channel_msg(&msg).unwrap();
        assert_eq!(typ, ChannelMsgType::TcpClose);
        assert_eq!(id, 7);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_decode_too_short() {
        assert!(decode_channel_msg(&[0x01, 0x00]).is_none());
    }

    #[test]
    fn test_decode_unknown_type() {
        let mut msg = encode_tcp_data(1, b"hello");
        msg[0] = 0xFF; // corrupt type
        assert!(decode_channel_msg(&msg).is_none());
    }
}
