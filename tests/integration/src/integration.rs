// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Integration tests for enclave-os-mini.
//!
//! These tests exercise the common protocol and type definitions.
//! Full end-to-end tests require the enclave to be built and signed
//! (run with `cargo test` from the workspace root for unit tests,
//! or `cmake --build . --target run_tests` for the full suite).

use enclave_os_common::protocol::{self, Request, Response};
use enclave_os_common::types::*;

#[test]
fn test_frame_encode_decode_roundtrip() {
    let payload = b"Hello, enclave!";
    let frame = protocol::encode_frame(payload);

    // Frame should be 4 bytes length + payload
    assert_eq!(frame.len(), 4 + payload.len());

    let (decoded, consumed) = protocol::decode_frame(&frame).expect("decode should succeed");
    assert_eq!(decoded, payload);
    assert_eq!(consumed, frame.len());
}

#[test]
fn test_frame_incomplete() {
    // Only 2 bytes – incomplete header
    assert!(protocol::decode_frame(&[0, 0]).is_none());

    // Header says 10 bytes but only 5 available
    let frame = &[0, 0, 0, 10, 1, 2, 3, 4, 5];
    assert!(protocol::decode_frame(frame).is_none());
}

#[test]
fn test_request_serialization() {
    let req = Request::Ping;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: Request = serde_json::from_slice(&json).unwrap();
    match decoded {
        Request::Ping => {}
        _ => panic!("Expected Ping"),
    }
}

#[test]
fn test_response_serialization() {
    let resp = Response::Data(vec![1, 2, 3, 4]);
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: Response = serde_json::from_slice(&json).unwrap();
    match decoded {
        Response::Data(d) => assert_eq!(d, vec![1, 2, 3, 4]),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_error_codes() {
    assert_eq!(EnclaveError::Unknown as i32, -1);
    assert_eq!(EnclaveError::KeyNotFound as i32, -9);
}

#[test]
fn test_constants() {
    assert_eq!(AEAD_KEY_SIZE, 32);
    assert_eq!(AEAD_NONCE_SIZE, 12);
    assert_eq!(AEAD_TAG_SIZE, 16);
    assert_eq!(SGX_QUOTE_MAX_SIZE, 16384);
}
