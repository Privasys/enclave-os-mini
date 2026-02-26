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

/// Maximum single frame payload: 4 MiB.
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// A simple request type for the RA-TLS ingress server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Ping / health check.
    Ping,
    /// Arbitrary application-defined payload.
    Data(Vec<u8>),
    /// Store a secret. The body is a JWT (compact serialisation) signed by
    /// the secret manager.  The JWT payload must contain:
    ///   `{ "secret": "<base64-encoded secret bytes>" }`
    StoreSecret { jwt: Vec<u8> },
    /// Retrieve a secret by its SHA-256 hash (hex-encoded in the JWT payload).
    /// The body is a JWT signed by the same secret manager.
    ///   `{ "secret_hash": "<hex SHA-256 of the secret>" }`
    GetSecret { jwt: Vec<u8> },
    /// Shutdown the server gracefully.
    Shutdown,
}

/// Response from the enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Pong reply.
    Pong,
    /// Application data reply.
    Data(Vec<u8>),
    /// Secret stored successfully. Contains the SHA-256 hash of the secret.
    SecretStored { secret_hash: Vec<u8> },
    /// Secret retrieved successfully.
    SecretValue { secret: Vec<u8> },
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
    fn test_request_store_secret_serde() {
        let req = Request::StoreSecret {
            jwt: b"eyJhbGciOi...".to_vec(),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        match back {
            Request::StoreSecret { jwt } => assert_eq!(jwt, b"eyJhbGciOi..."),
            _ => panic!("expected StoreSecret"),
        }
    }

    #[test]
    fn test_request_get_secret_serde() {
        let req = Request::GetSecret {
            jwt: b"eyJhbGciOi...get".to_vec(),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        match back {
            Request::GetSecret { jwt } => assert_eq!(jwt, b"eyJhbGciOi...get"),
            _ => panic!("expected GetSecret"),
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
    fn test_response_secret_stored_serde() {
        let resp = Response::SecretStored {
            secret_hash: b"abcdef".to_vec(),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: Response = serde_json::from_slice(&json).unwrap();
        match back {
            Response::SecretStored { secret_hash } => {
                assert_eq!(secret_hash, b"abcdef")
            }
            _ => panic!("expected SecretStored"),
        }
    }

    #[test]
    fn test_response_secret_value_serde() {
        let resp = Response::SecretValue {
            secret: vec![0xDE, 0xAD],
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: Response = serde_json::from_slice(&json).unwrap();
        match back {
            Response::SecretValue { secret } => assert_eq!(secret, vec![0xDE, 0xAD]),
            _ => panic!("expected SecretValue"),
        }
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
    fn test_store_secret_frame_roundtrip() {
        let req = Request::StoreSecret {
            jwt: b"test.jwt.token".to_vec(),
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&payload);
        let (decoded_payload, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let decoded: Request = serde_json::from_slice(&decoded_payload).unwrap();
        match decoded {
            Request::StoreSecret { jwt } => assert_eq!(jwt, b"test.jwt.token"),
            _ => panic!("expected StoreSecret"),
        }
    }

    #[test]
    fn test_get_secret_frame_roundtrip() {
        let req = Request::GetSecret {
            jwt: b"get.jwt.token".to_vec(),
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let frame = encode_frame(&payload);
        let (decoded_payload, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let decoded: Request = serde_json::from_slice(&decoded_payload).unwrap();
        match decoded {
            Request::GetSecret { jwt } => assert_eq!(jwt, b"get.jwt.token"),
            _ => panic!("expected GetSecret"),
        }
    }
}
