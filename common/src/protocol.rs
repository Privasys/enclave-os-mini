// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Minimal HTTP/1.1 wire protocol for communication over RA-TLS connections.
//!
//! The enclave speaks a strict subset of HTTP/1.1 so that clients can use
//! standard tools (`curl`, any HTTP library) without a custom framing layer.
//!
//! Supported methods: GET, POST, PUT.
//! Authentication: `Authorization: Bearer <token>` header.
//! Body encoding: `Content-Length` only (no chunked transfer-encoding).

#[cfg(feature = "sgx")]
use alloc::string::String;
#[cfg(feature = "sgx")]
use alloc::vec::Vec;
#[cfg(feature = "sgx")]
use alloc::format;
#[cfg(not(feature = "sgx"))]
use std::string::String;
#[cfg(not(feature = "sgx"))]
use std::vec::Vec;

use serde::{Deserialize, Serialize};

/// Maximum HTTP request body: 16 MiB.
pub const MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// Maximum HTTP header section: 8 KiB (enforced via header count).
pub const MAX_HEADERS: usize = 32;

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

/// An attestation server endpoint with an optional bearer token.
///
/// Used by the management API to configure per-server authentication
/// credentials on the egress module.  The URL is the verification
/// endpoint (e.g. `https://as.privasys.org/`); the token is a
/// long-lived OIDC bearer token that the enclave presents when
/// submitting quotes for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServer {
    /// Attestation server verification URL.
    pub url: String,
    /// Optional OIDC bearer token for authenticated servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
    /// Developer API-fee events (`x-privasys.price`) recorded by the WASM
    /// runtime on successful priced calls. Unlike the cumulative fuel
    /// counters these are discrete billable events: the runtime keeps a
    /// bounded ring of recent events and the management-service pulls them
    /// at-least-once — the ledger deduplicates on `call_id`, so replays
    /// across polls or restarts never double-charge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_fees: Vec<ApiFeeEvent>,
}

/// One developer API fee owed for one successful priced WASM call.
///
/// Emitted by the attested runtime (the metering authority): the price and
/// payer rule come from the measured app manifest, so the fee reported here
/// is exactly the advertised price. The runtime reports OIDC subjects and
/// rp_ids, never ledger account UUIDs — account resolution is the
/// management-service's job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFeeEvent {
    /// Monotonic per-enclave sequence number (restart-safe: persisted with
    /// the metrics snapshot). Lets the poller skip already-applied events.
    pub seq: u64,
    /// App identifier (the load name; the platform maps it to the app row).
    pub app: String,
    /// The priced exported function that was called.
    pub function: String,
    /// Unique id for this call — the ledger's idempotency key.
    pub call_id: String,
    /// Verified caller subject (payer mode "caller"). The payer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_sub: Option<String>,
    /// Relying-party id extracted from the request (payer mode "sponsor").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor_rp_id: Option<String>,
    /// Fee in credits, as declared by the measured manifest.
    pub credits: u64,
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

    // ── Billable SDK resource counters (schema v2) ─────────────────
    /// Sealed-KV read operations.
    #[serde(default)]
    pub ledger_read_calls: i64,
    /// Bytes read from the sealed KV store.
    #[serde(default)]
    pub ledger_read_bytes: i64,
    /// Sealed-KV write operations.
    #[serde(default)]
    pub ledger_write_calls: i64,
    /// Bytes written to the sealed KV store.
    #[serde(default)]
    pub ledger_write_bytes: i64,
    /// Bytes hashed via crypto digest / HMAC.
    #[serde(default)]
    pub crypto_digest_bytes: i64,
    /// Plaintext/ciphertext bytes processed via crypto encrypt / decrypt.
    #[serde(default)]
    pub crypto_encdec_bytes: i64,
    /// Number of crypto sign calls.
    #[serde(default)]
    pub crypto_sign_calls: i64,
    /// Number of crypto verify calls.
    #[serde(default)]
    pub crypto_verify_calls: i64,
    /// Random bytes drawn via crypto get-random-bytes.
    #[serde(default)]
    pub crypto_random_bytes: i64,
    /// Number of plain (non-RA-TLS) HTTPS fetch calls.
    #[serde(default)]
    pub https_plain_calls: i64,
    /// Request+response bytes for plain HTTPS fetch calls.
    #[serde(default)]
    pub https_plain_bytes: i64,
    /// Number of RA-TLS HTTPS fetch calls.
    #[serde(default)]
    pub https_ratls_calls: i64,
    /// Request+response bytes for RA-TLS HTTPS fetch calls.
    #[serde(default)]
    pub https_ratls_bytes: i64,

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

// =========================================================================
//  HTTP/1.1 wire protocol (powered by httparse)
// =========================================================================

/// HTTP method (strict subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

/// A parsed HTTP/1.1 request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    /// Bearer token value (without the `"Bearer "` prefix), if present.
    pub authorization: Option<String>,
    /// App-level OIDC bearer token from the `X-App-Auth` header.
    ///
    /// Separate from `authorization` (platform OIDC) so that app-level
    /// permissions can use a different OIDC provider.
    pub app_auth: Option<String>,
    /// Privasys browser-session id (without the `"PrivasysSession "` prefix), if present.
    /// Set when `Authorization: PrivasysSession <id>` is sent (mutually exclusive with `Bearer`).
    pub privasys_session: Option<String>,
    /// Value of the `Content-Type` header (lowercased), if present.
    pub content_type: Option<String>,
    /// Value of the `Host` header (lowercased, port stripped), if present.
    /// The platform gateway routes to a workload by its hostname
    /// (`<app>.apps-*.privasys.org`), so on a multi-app enclave this is
    /// how a request that doesn't name the app explicitly (e.g. the
    /// MCP-over-HTTP shim's bare `GET /api/v1/mcp/tools`) is disambiguated.
    pub host: Option<String>,
    /// Request body (empty for GET).
    pub body: Vec<u8>,
    /// Whether the client sent `Connection: close`.
    pub connection_close: bool,
    /// True when the request arrived via a gateway-terminated TLS leg
    /// (`X-Privasys-Edge: terminate`, injected by the platform gateway
    /// after stripping any client-supplied value). Plaintext app
    /// requests on such a leg must be refused — the gateway must never
    /// see app data. Splice/RA-TLS traffic never carries the marker.
    pub edge_terminated: bool,
}

/// Errors that can occur while parsing an HTTP request.
#[derive(Debug)]
pub enum HttpParseError {
    /// Not enough data yet — caller should buffer more bytes.
    Incomplete,
    /// Too many headers.
    TooManyHeaders,
    /// Body exceeds [`MAX_BODY_SIZE`].
    BodyTooLarge,
    /// HTTP method is not GET, POST, or PUT.
    UnsupportedMethod,
    /// `Content-Length` header has a non-numeric value.
    InvalidContentLength,
    /// httparse reported a malformed request.
    Malformed,
}

/// Try to parse an HTTP/1.1 request from a byte buffer.
///
/// Returns `Ok((request, consumed))` where `consumed` is the number of
/// bytes consumed from the front of `buf`, or `Err(Incomplete)` if the
/// buffer does not yet contain a complete request.
pub fn parse_http_request(buf: &[u8]) -> Result<(HttpRequest, usize), HttpParseError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    let header_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Err(HttpParseError::Incomplete),
        Err(_) => return Err(HttpParseError::Malformed),
    };

    let method = match req.method.unwrap_or("") {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        _ => return Err(HttpParseError::UnsupportedMethod),
    };

    let path = req.path.unwrap_or("/").to_string();

    // Extract relevant headers
    let mut content_length: Option<usize> = None;
    let mut authorization: Option<String> = None;
    let mut app_auth: Option<String> = None;
    let mut privasys_session: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut host: Option<String> = None;
    let mut connection_close = false;
    let mut edge_terminated = false;

    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let val = core::str::from_utf8(h.value)
                .map_err(|_| HttpParseError::InvalidContentLength)?;
            content_length = Some(
                val.trim().parse().map_err(|_| HttpParseError::InvalidContentLength)?,
            );
        } else if h.name.eq_ignore_ascii_case("authorization") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                if let Some(token) = val.strip_prefix("Bearer ") {
                    authorization = Some(token.to_string());
                } else if let Some(sid) = val.strip_prefix("PrivasysSession ") {
                    privasys_session = Some(sid.trim().to_string());
                }
            }
        } else if h.name.eq_ignore_ascii_case("content-type") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                content_type = Some(val.trim().to_ascii_lowercase());
            }
        } else if h.name.eq_ignore_ascii_case("host") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                // Lowercase + strip any :port so callers can match on the
                // bare hostname.
                let v = val.trim().to_ascii_lowercase();
                let v = v.split(':').next().unwrap_or("").to_string();
                if !v.is_empty() {
                    host = Some(v);
                }
            }
        } else if h.name.eq_ignore_ascii_case("x-app-auth") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                let val = val.trim();
                if !val.is_empty() {
                    app_auth = Some(val.to_string());
                }
            }
        } else if h.name.eq_ignore_ascii_case("connection") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                connection_close = val.eq_ignore_ascii_case("close");
            }
        } else if h.name.eq_ignore_ascii_case("x-privasys-edge") {
            if let Ok(val) = core::str::from_utf8(h.value) {
                edge_terminated = val.trim().eq_ignore_ascii_case("terminate");
            }
        }
        // All other headers are silently ignored.
    }

    // Body
    let body_len = content_length.unwrap_or(0);

    if body_len > MAX_BODY_SIZE {
        return Err(HttpParseError::BodyTooLarge);
    }

    let total = header_len + body_len;

    if buf.len() < total {
        return Err(HttpParseError::Incomplete);
    }

    let body = buf[header_len..total].to_vec();

    Ok((
        HttpRequest {
            method,
            path,
            authorization,
            app_auth,
            privasys_session,
            content_type,
            host,
            body,
            connection_close,
            edge_terminated,
        },
        total,
    ))
}

/// Format a minimal HTTP/1.1 response.
///
/// The response always includes `Content-Type: application/json` and
/// `Content-Length`.  `Connection: close` is added when `close` is true.
pub fn format_http_response(status: u16, body: &[u8], close: bool) -> Vec<u8> {
    format_http_response_with_type(status, "application/json", body, close)
}

/// Format an HTTP/1.1 response with a caller-chosen `Content-Type`.
pub fn format_http_response_with_type(
    status: u16,
    content_type: &str,
    body: &[u8],
    close: bool,
) -> Vec<u8> {
    format_http_response_with_headers(status, content_type, &[], body, close)
}

/// Format an HTTP/1.1 response with extra response headers (e.g. the
/// session-relay diagnostic `X-Privasys-EncAuth-Reject`). Header names
/// and values containing CR/LF are skipped (response-splitting guard).
pub fn format_http_response_with_headers(
    status: u16,
    content_type: &str,
    extra_headers: &[(String, String)],
    body: &[u8],
    close: bool,
) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let conn_header = if close { "Connection: close\r\n" } else { "" };

    let mut extras = String::new();
    for (name, value) in extra_headers {
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        extras.push_str(name);
        extras.push_str(": ");
        extras.push_str(value);
        extras.push_str("\r\n");
    }

    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}{}\r\n",
        status, reason, content_type, body.len(), extras, conn_header,
    );

    let mut resp = header.into_bytes();
    resp.extend_from_slice(body);
    resp
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Request / Response serde tests ──────────────────────────────

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
        let resp = Response::Healthz { status: "ok".into() };
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

    // ── HTTP parser tests ───────────────────────────────────────────

    #[test]
    fn test_parse_get_request() {
        let raw = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, consumed) = parse_http_request(raw).unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/healthz");
        assert!(req.body.is_empty());
        assert!(req.authorization.is_none());
        assert_eq!(req.host.as_deref(), Some("localhost"));
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn test_parse_host_header_lowercased_port_stripped() {
        let raw = b"GET /api/v1/mcp/tools HTTP/1.1\r\nHost: Web-Search-Brave.apps-test.privasys.org:443\r\n\r\n";
        let (req, _) = parse_http_request(raw).unwrap();
        // Lowercased and :port stripped so the shim can take the first label.
        assert_eq!(
            req.host.as_deref(),
            Some("web-search-brave.apps-test.privasys.org")
        );
    }

    #[test]
    fn test_parse_post_with_body() {
        let body = b"{\"command\":\"hello\"}";
        let raw = format!(
            "POST /data HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            core::str::from_utf8(body).unwrap(),
        );
        let (req, consumed) = parse_http_request(raw.as_bytes()).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.path, "/data");
        assert_eq!(req.body, body);
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn test_parse_authorization_header() {
        let raw = b"GET /status HTTP/1.1\r\nAuthorization: Bearer tok123\r\n\r\n";
        let (req, _) = parse_http_request(raw).unwrap();
        assert_eq!(req.authorization.as_deref(), Some("tok123"));
    }

    #[test]
    fn test_parse_connection_close() {
        let raw = b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n";
        let (req, _) = parse_http_request(raw).unwrap();
        assert!(req.connection_close);
    }

    #[test]
    fn test_parse_incomplete() {
        let raw = b"GET /healthz HTTP/1.1\r\n";
        assert!(matches!(
            parse_http_request(raw),
            Err(HttpParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_incomplete_body() {
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        assert!(matches!(
            parse_http_request(raw),
            Err(HttpParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_unsupported_method() {
        let raw = b"DELETE /foo HTTP/1.1\r\n\r\n";
        assert!(matches!(
            parse_http_request(raw),
            Err(HttpParseError::UnsupportedMethod)
        ));
    }

    #[test]
    fn test_format_http_response_200() {
        let body = b"{\"status\":\"ok\"}";
        let resp = format_http_response(200, body, false);
        let resp_str = core::str::from_utf8(&resp).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp_str.contains("Content-Length: 15\r\n"));
        assert!(resp_str.ends_with("{\"status\":\"ok\"}"));
        assert!(!resp_str.contains("Connection: close"));
    }

    #[test]
    fn test_format_http_response_close() {
        let body = b"{}";
        let resp = format_http_response(404, body, true);
        let resp_str = core::str::from_utf8(&resp).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(resp_str.contains("Connection: close\r\n"));
    }

    #[test]
    fn test_parse_multiple_requests_in_buffer() {
        let r1 = b"GET /healthz HTTP/1.1\r\n\r\n";
        let r2 = b"GET /status HTTP/1.1\r\n\r\n";
        let mut buf = Vec::new();
        buf.extend_from_slice(r1);
        buf.extend_from_slice(r2);

        let (req1, consumed1) = parse_http_request(&buf).unwrap();
        assert_eq!(req1.path, "/healthz");
        assert_eq!(consumed1, r1.len());

        let (req2, consumed2) = parse_http_request(&buf[consumed1..]).unwrap();
        assert_eq!(req2.path, "/status");
        assert_eq!(consumed2, r2.len());
    }

    #[test]
    fn test_parse_case_insensitive_headers() {
        let raw = b"POST /data HTTP/1.1\r\ncONTENT-LENGTH: 2\r\nAUTHORIZATION: Bearer abc\r\n\r\nhi";
        let (req, _) = parse_http_request(raw).unwrap();
        assert_eq!(req.body, b"hi");
        assert_eq!(req.authorization.as_deref(), Some("abc"));
    }
}
