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
fn test_parse_http_get_request() {
    let raw = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (req, consumed) = protocol::parse_http_request(raw).unwrap();
    assert_eq!(req.method, protocol::HttpMethod::Get);
    assert_eq!(req.path, "/healthz");
    assert!(req.body.is_empty());
    assert_eq!(consumed, raw.len());
}

#[test]
fn test_parse_http_post_with_body() {
    let body = b"{\"hello\":\"world\"}";
    let raw = format!(
        "POST /data HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        core::str::from_utf8(body).unwrap(),
    );
    let (req, consumed) = protocol::parse_http_request(raw.as_bytes()).unwrap();
    assert_eq!(req.method, protocol::HttpMethod::Post);
    assert_eq!(req.path, "/data");
    assert_eq!(req.body, body);
    assert_eq!(consumed, raw.len());
}

#[test]
fn test_format_http_response() {
    let body = b"{\"status\":\"ok\"}";
    let resp = protocol::format_http_response(200, body, false);
    let resp_str = core::str::from_utf8(&resp).unwrap();
    assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(resp_str.contains("Content-Length: 15\r\n"));
    assert!(resp_str.ends_with("{\"status\":\"ok\"}"));
}

#[test]
fn test_request_serialization() {
    let req = Request::Healthz;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: Request = serde_json::from_slice(&json).unwrap();
    match decoded {
        Request::Healthz => {}
        _ => panic!("Expected Healthz"),
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
