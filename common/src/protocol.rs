// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Simple wire protocol for communication over RA-TLS connections.
//!
//! Frame format:
//!   [4 bytes: payload length (big-endian u32)] [payload ...]
//!
//! This is intentionally minimal – the enclave OS only needs
//! length-delimited framing on top of TLS.

#[cfg(feature = "sgx")]
use alloc::vec::Vec;
#[cfg(not(feature = "sgx"))]
use std::vec::Vec;

use serde::{Deserialize, Serialize};

/// Maximum single frame payload: 16 MiB.
///
/// The WASM management protocol double-encodes payloads (inner JSON
/// inside Request::Data byte vector), which inflates the wire size
/// significantly for large WASM artifacts.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// A simple request type for the RA-TLS ingress server.
///
/// Module-specific protocols (vault, WASM, etc.) are carried inside
/// [`Data`](Request::Data) — each module deserializes the inner bytes
/// into its own request type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Ping / health check.
    Ping,
    /// Arbitrary application-defined payload.
    ///
    /// Module-specific protocols are JSON-encoded inside this variant.
    Data(Vec<u8>),
    /// Shutdown the server gracefully.
    Shutdown,
}

/// Response from the enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Pong reply.
    Pong,
    /// Application data reply.
    ///
    /// Module-specific responses are JSON-encoded inside this variant.
    Data(Vec<u8>),
    /// Acknowledgement.
    Ok,
    /// Error with human-readable message.
    Error(Vec<u8>),
}

/// Encode a length-delimited frame: [u32 BE length][payload].
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Try to decode a frame from a buffer. Returns `Some((payload, consumed))`
/// if a complete frame is available, `None` otherwise.
pub fn decode_frame(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len as u32 > MAX_FRAME_SIZE {
        return None; // reject oversized
    }
    if buf.len() < 4 + len {
        return None;
    }
    let payload = buf[4..4 + len].to_vec();
    Some((payload, 4 + len))
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let data = b"hello world";
        let frame = encode_frame(data);
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn test_decode_incomplete_frame() {
        assert!(decode_frame(&[0, 0, 0, 10, 1, 2]).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        assert!(decode_frame(&[0, 0]).is_none());
    }

    #[test]
    fn test_request_ping_serde() {
        let req = Request::Ping;
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        assert!(matches!(back, Request::Ping));
    }

    #[test]
    fn test_request_data_serde() {
        let req = Request::Data(vec![1, 2, 3]);
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        match back {
            Request::Data(d) => assert_eq!(d, vec![1, 2, 3]),
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn test_request_shutdown_serde() {
        let req = Request::Shutdown;
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        assert!(matches!(back, Request::Shutdown));
    }

    #[test]
    fn test_response_pong_serde() {
        let resp = Response::Pong;
        let json = serde_json::to_vec(&resp).unwrap();
        let back: Response = serde_json::from_slice(&json).unwrap();
        assert!(matches!(back, Response::Pong));
    }

    #[test]
    fn test_response_error_serde() {
        let resp = Response::Error(b"something went wrong".to_vec());
        let json = serde_json::to_vec(&resp).unwrap();
        let back: Response = serde_json::from_slice(&json).unwrap();
        match back {
            Response::Error(msg) => assert_eq!(msg, b"something went wrong"),
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let req = Request::Data(b"hello vault".to_vec());
        let payload = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&payload);
        let (decoded_payload, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let decoded: Request = serde_json::from_slice(&decoded_payload).unwrap();
        match decoded {
            Request::Data(d) => assert_eq!(d, b"hello vault"),
            _ => panic!("expected Data"),
        }
    }
}
