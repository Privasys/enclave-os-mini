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
//! | `TcpNew`       | 0x01 | UTF-8 peer address | New TCP connection accepted |
//! | `TcpData`      | 0x02 | raw bytes          | TCP segment(s) from client |
//! | `TcpClose`     | 0x03 | (empty)            | Connection closed by peer (also: outbound connect failed) |
//! | `TcpConnected` | 0x06 | (empty)            | Enclave-requested outbound connect succeeded |
//!
//! ## enclave → host (`data_enc_to_host` queue)
//!
//! | Type | Value | Payload | Description |
//! |------|-------|---------|-------------|
//! | `TcpData`    | 0x02 | raw bytes | TLS bytes to send to client            |
//! | `TcpClose`   | 0x03 | (empty)   | Enclave closing connection             |
//! | `DataReady`  | 0x04 | (empty)   | Data channel consumer ready — start accepting |
//! | `TcpConnect` | 0x05 | UTF-8 `host:port` | Open an outbound TCP connection owned by the proxy |
//!
//! # Connection-id ranges
//!
//! `conn_id` provenance is encoded in its range so the enclave event loop
//! can route without extra state and ids never collide:
//!
//! - `[1, 0x3FFF_FFFF]` — proxy-assigned, inbound on the ingress port
//! - `[0x4000_0000, 0x7FFF_FFFF]` — proxy-assigned, inbound on the peer port
//! - `[0x8000_0000, 0xFFFF_FFFF]` — enclave-assigned, outbound (`TcpConnect`)
//!
//! Outbound flow: the enclave picks a conn_id from its range and sends
//! `TcpConnect`. The proxy performs a non-blocking connect; `TcpData`
//! sent by the enclave before the connect completes is buffered by the
//! proxy (so a TLS ClientHello can be emitted immediately). On success
//! the host sends `TcpConnected`; on failure or timeout it sends
//! `TcpClose`. After that the connection behaves exactly like an inbound
//! one.
//!
//! # Queue layout
//!
//! Two SPSC queue pairs are used:
//! - **RPC channel** (existing): enclave ↔ host RPC for KV, time, log,
//!   shutdown, and egress socket calls.
//! - **Data channel**: host TCP proxy ↔ enclave TLS engine, inbound and
//!   proxy-owned outbound connections.

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

    /// Enclave data channel is ready (enclave → host).
    /// Sent once, right before the enclave enters the data channel
    /// event loop.  The TCP proxy must not accept connections until
    /// it has received this message.
    DataReady = 0x04,

    /// Open an outbound TCP connection (enclave → host).
    /// Payload: UTF-8 `host:port`. The conn_id MUST come from the
    /// enclave-assigned outbound range (`CONN_ID_OUTBOUND_BASE..`).
    TcpConnect = 0x05,

    /// An enclave-requested outbound connect succeeded (host → enclave).
    /// Payload: empty. Failure is reported as `TcpClose`.
    TcpConnected = 0x06,

    /// Periodic timer tick (host → enclave, conn_id 0, empty payload).
    /// Sent by the proxy every ~100 ms when a peer port is configured;
    /// drives raft election/heartbeat timers. Untrusted like all host
    /// input: only liveness depends on it, never safety.
    Tick = 0x07,
}

impl ChannelMsgType {
    /// Parse a message type from a byte.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::TcpNew),
            0x02 => Some(Self::TcpData),
            0x03 => Some(Self::TcpClose),
            0x04 => Some(Self::DataReady),
            0x05 => Some(Self::TcpConnect),
            0x06 => Some(Self::TcpConnected),
            0x07 => Some(Self::Tick),
            _ => None,
        }
    }
}

// ========================================================================
//  Connection-id ranges
// ========================================================================

/// First conn_id of the proxy-assigned inbound *peer-port* range.
pub const CONN_ID_PEER_IN_BASE: u32 = 0x4000_0000;

/// First conn_id of the enclave-assigned *outbound* range.
pub const CONN_ID_OUTBOUND_BASE: u32 = 0x8000_0000;

/// Is this conn_id an inbound connection on the ingress port?
#[inline]
pub fn conn_id_is_ingress(conn_id: u32) -> bool {
    conn_id < CONN_ID_PEER_IN_BASE
}

/// Is this conn_id an inbound connection on the peer port?
#[inline]
pub fn conn_id_is_peer_inbound(conn_id: u32) -> bool {
    (CONN_ID_PEER_IN_BASE..CONN_ID_OUTBOUND_BASE).contains(&conn_id)
}

/// Is this conn_id an enclave-initiated outbound connection?
#[inline]
pub fn conn_id_is_outbound(conn_id: u32) -> bool {
    conn_id >= CONN_ID_OUTBOUND_BASE
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

/// Convenience: encode a TcpConnect message (enclave → host).
#[inline]
pub fn encode_tcp_connect(conn_id: u32, addr: &str) -> Vec<u8> {
    encode_channel_msg(ChannelMsgType::TcpConnect, conn_id, addr.as_bytes())
}

/// Convenience: encode a TcpConnected message (host → enclave).
#[inline]
pub fn encode_tcp_connected(conn_id: u32) -> Vec<u8> {
    encode_channel_msg(ChannelMsgType::TcpConnected, conn_id, &[])
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
    fn test_roundtrip_tcp_connect() {
        let msg = encode_tcp_connect(0x8000_0001, "10.0.0.7:7400");
        let (typ, id, payload) = decode_channel_msg(&msg).unwrap();
        assert_eq!(typ, ChannelMsgType::TcpConnect);
        assert_eq!(id, 0x8000_0001);
        assert_eq!(core::str::from_utf8(payload).unwrap(), "10.0.0.7:7400");
    }

    #[test]
    fn test_roundtrip_tcp_connected() {
        let msg = encode_tcp_connected(0x8000_0001);
        let (typ, id, payload) = decode_channel_msg(&msg).unwrap();
        assert_eq!(typ, ChannelMsgType::TcpConnected);
        assert_eq!(id, 0x8000_0001);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_conn_id_ranges() {
        assert!(conn_id_is_ingress(1));
        assert!(conn_id_is_ingress(CONN_ID_PEER_IN_BASE - 1));
        assert!(!conn_id_is_ingress(CONN_ID_PEER_IN_BASE));
        assert!(conn_id_is_peer_inbound(CONN_ID_PEER_IN_BASE));
        assert!(conn_id_is_peer_inbound(CONN_ID_OUTBOUND_BASE - 1));
        assert!(!conn_id_is_peer_inbound(CONN_ID_OUTBOUND_BASE));
        assert!(conn_id_is_outbound(CONN_ID_OUTBOUND_BASE));
        assert!(conn_id_is_outbound(u32::MAX));
        assert!(!conn_id_is_outbound(CONN_ID_OUTBOUND_BASE - 1));
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
