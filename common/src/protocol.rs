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
    /// Liveness probe — always succeeds, no auth required.
    /// Aligned with Enclave OS Virtual's `GET /healthz`.
    Healthz,
    /// Readiness probe — returns whether the enclave is ready to serve.
    /// Requires Monitoring+ role.
    Readyz,
    /// Status — returns enabled modules + per-module state.
    /// Requires Monitoring+ role.
    Status,
    /// Metrics — lightweight counters: connections, frames, calls, etc.
    /// Requires Monitoring+ role.
    Metrics,
    /// Update the attestation server list (URLs and optional bearer tokens).
    ///
    /// This is a core operation — handled at the same level as Readyz, Status
    /// and Metrics.  Requires the **Manager** role when OIDC is configured.
    ///
    /// Changes are immediately reflected in the attestation servers OID
    /// (`1.3.6.1.4.1.65230.2.7`) of subsequent RA-TLS certificates.
    SetAttestationServers {
        /// New set of attestation server endpoints.
        servers: Vec<AttestationServer>,
    },
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
    /// Healthz reply — always `{"status":"ok"}`.
    Healthz { status: String },
    /// Readyz reply.
    Readyz {
        status: String,
        modules: usize,
    },
    /// Status reply with per-module info.
    StatusReport(Vec<ModuleStatus>),
    /// Metrics reply with enclave counters.
    MetricsReport(EnclaveMetrics),
    /// Application data reply.
    ///
    /// Module-specific responses are JSON-encoded inside this variant.
    Data(Vec<u8>),
    /// Acknowledgement.
    Ok,
    /// Attestation servers updated successfully.
    AttestationServersUpdated {
        /// Number of attestation servers now configured.
        server_count: usize,
        /// Hex-encoded SHA-256 hash of the new canonical server URL list.
        hash: String,
    },
    /// Error with human-readable message.
    Error(Vec<u8>),
}

/// Per-module status entry returned by `Status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    /// Module name (e.g. "wasm", "vault", "kvstore").
    pub name: String,
    /// Module-specific status details (JSON value).
    pub details: serde_json::Value,
}

/// OIDC bootstrap configuration for an attestation server.
///
/// When present on an [`AttestationServer`], the enclave will
/// self-provision its own bearer token instead of relying on a
/// statically provided one.  The flow:
///
/// 1. Generate an RSA-2048 keypair inside the enclave.
/// 2. Register the public key with Zitadel (`POST /v2/users/{service_account_id}/keys`)
///    using the manager's JWT (passed via the `"auth"` field of the request).
/// 3. Build a JWT assertion signed with the private key and exchange it
///    for an access token via the `jwt-bearer` OIDC grant.
/// 4. Store the token; lazily refresh at 75 % of its lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcBootstrap {
    /// OIDC issuer URL (e.g. `https://auth.privasys.org`).
    pub issuer: String,
    /// Zitadel service-account user ID that will own the registered key.
    pub service_account_id: String,
    /// Zitadel project ID — used as `aud` when requesting scoped tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
}

/// An attestation server endpoint with an optional bearer token.
///
/// Used by the management API to configure per-server authentication
/// credentials on the egress module.  The URL is the verification
/// endpoint (e.g. `https://as.privasys.org/`); the token is a
/// long-lived OIDC bearer token that the enclave presents when
/// submitting quotes for verification.
///
/// When [`oidc_bootstrap`](Self::oidc_bootstrap) is set, the enclave
/// provisions its own token automatically and the static `token` field
/// is ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServer {
    /// Attestation server verification URL.
    pub url: String,
    /// Optional OIDC bearer token for authenticated servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Optional OIDC bootstrap config — when set the enclave will
    /// self-provision a bearer token via the Zitadel jwt-bearer grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_bootstrap: Option<OidcBootstrap>,
}

/// Enclave-level metrics counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclaveMetrics {
    /// Total TLS connections served.
    pub connections_total: u64,
    /// Total application frames processed.
    pub frames_total: u64,
    /// Total WASM calls executed (0 if WASM not enabled).
    pub wasm_calls_total: u64,
    /// Total secrets stored (0 if vault not enabled).
    pub secrets_stored_total: u64,
    /// Total secrets retrieved (0 if vault not enabled).
    pub secrets_retrieved_total: u64,
    /// Total attestation verifications performed.
    pub attestation_verifications_total: u64,
    /// Enclave uptime in seconds.
    pub uptime_seconds: u64,
    /// Per-app WASM fuel metering metrics (empty if WASM not enabled).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasm_app_metrics: Vec<WasmAppMetrics>,
}

/// Aggregated fuel metrics for a single WASM app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmAppMetrics {
    /// App identifier.
    pub name: String,
    /// Total number of calls across all functions.
    pub calls_total: i64,
    /// Total fuel consumed across all functions.
    pub fuel_consumed_total: i64,
    /// Number of calls that resulted in an error.
    pub errors_total: i64,
    /// Per-function breakdown.
    pub functions: Vec<WasmFunctionMetrics>,
}

/// Fuel metrics for a single exported function within a WASM app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmFunctionMetrics {
    /// Function name (e.g. `"process"` or `"my-api/transform"`).
    pub name: String,
    /// Number of times this function was called.
    pub calls: i64,
    /// Total fuel consumed by this function across all calls.
    pub fuel_consumed: i64,
    /// Number of calls that resulted in an error.
    pub errors: i64,
    /// Minimum fuel consumed in a single call (0 if never called).
    pub fuel_min: i64,
    /// Maximum fuel consumed in a single call.
    pub fuel_max: i64,
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
    fn test_request_healthz_serde() {
        let req = Request::Healthz;
        let json = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        assert!(matches!(back, Request::Healthz));
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
    fn test_response_healthz_serde() {
        let resp = Response::Healthz { status: "ok" };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: Response = serde_json::from_slice(&json).unwrap();
        assert!(matches!(back, Response::Healthz { .. }));
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
