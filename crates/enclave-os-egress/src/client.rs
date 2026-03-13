// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HTTPS egress client – makes outbound HTTPS requests from inside the enclave.
//!
//! Uses rustls for TLS and a minimal HTTP/1.1 implementation. Network I/O
//! flows through OCALLs to the host, but the TLS termination happens inside
//! the enclave, so the host never sees plaintext.
//!
//! The single public entry point is [`https_fetch`], which returns an
//! [`HttpResponse`] (status + headers + body) and supports all HTTP methods,
//! custom headers, and optional RA-TLS verification.

use std::io::{Read, Write};
use std::string::String;
use std::sync::{Arc, OnceLock};
use std::vec::Vec;

use core::mem;

use ring::digest;
use enclave_os_common::ocall;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};

use x509_parser::prelude::*;

// sgx_types is provided by the Teaclave sysroot — gives us Quote3, Quote4,
// ReportBody, Report2Body with typed field access.
extern crate sgx_types;
use sgx_types::types::{Quote3, Quote4};

use enclave_os_common::oids;

// Re-export shared quote primitives for callers building `RaTlsPolicy` values.
pub use enclave_os_common::quote::TeeType;

// Re-export the dotted-string OIDs for callers building `ExpectedOid` values.
pub use enclave_os_common::oids::{
    CONFIG_MERKLE_ROOT_OID_STR as OID_CONFIG_MERKLE_ROOT,
    EGRESS_CA_HASH_OID_STR as OID_EGRESS_CA_HASH,
    WASM_APPS_HASH_OID_STR as OID_WASM_APPS_HASH,
    ATTESTATION_SERVERS_HASH_OID_STR as OID_ATTESTATION_SERVERS_HASH,
};

// =========================================================================
//  Constants
// =========================================================================

/// Maximum HTTP response body size (2 MiB).
///
/// Prevents a single response from dominating the enclave heap. Applied
/// both during the read loop (to stop reading early) and after HTTP parsing
/// (to truncate if Content-Length exceeded the cap).
pub const MAX_RESPONSE_BODY: usize = 2 * 1024 * 1024;

// =========================================================================
//  Mozilla root CA store (for general-purpose HTTPS egress)
// =========================================================================

static MOZILLA_ROOT_STORE: OnceLock<RootCertStore> = OnceLock::new();

/// Returns a shared reference to the Mozilla root CA store.
///
/// The store is lazily initialized from `webpki-roots` on first call
/// (~150 root CAs). Subsequent calls return the cached reference.
pub fn mozilla_root_store() -> &'static RootCertStore {
    MOZILLA_ROOT_STORE.get_or_init(|| {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    })
}

// =========================================================================
//  Full HTTP response type
// =========================================================================

/// A parsed HTTP response with status code, headers, and body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404, 500).
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body (truncated to [`MAX_RESPONSE_BODY`] bytes).
    pub body: Vec<u8>,
}

// =========================================================================
//  RA-TLS verification types
// =========================================================================

/// Mock quote prefix used in development/test builds.
/// Only available when the `mock` feature is enabled.
#[cfg(feature = "mock")]
const MOCK_PREFIX: &[u8] = b"MOCK_QUOTE:";

/// How the verifier reproduces the 64-byte `ReportData` field in the quote.
///
/// Both modes compute `SHA-512( SHA-256(pubkey) || binding )`, but the
/// *pubkey encoding* and the *binding* differ:
///
/// | TEE | Pubkey encoding | Deterministic binding | Challenge binding |
/// |-----|-----------------|----------------------|-------------------|
/// | SGX | Raw EC point (65 B) | *skipped* (creation_time not in cert) | Client nonce |
/// | TDX | Full SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` | Client nonce |
#[derive(Debug, Clone)]
pub enum ReportDataBinding {
    /// Deterministic — reproduced from the certificate alone.
    ///
    /// * **TDX**: `SHA-512(SHA-256(SPKI DER) || NotBefore "YYYY-MM-DDTHH:MMZ")`
    /// * **SGX**: verification is **skipped** because `creation_time`
    ///   (8-byte LE epoch used as binding) is not recoverable from the
    ///   certificate's `NotBefore` (enclave-os sets it to a fixed date).
    Deterministic,

    /// Challenge-response — binding is a client-supplied nonce.
    ///
    /// * **TDX**: `SHA-512(SHA-256(SPKI DER) || nonce)`
    /// * **SGX**: `SHA-512(SHA-256(raw EC point) || nonce)`
    ///
    /// The nonce is typically sent in TLS ClientHello extension `0xFFBB`
    /// and must be **exactly** the bytes the server used as binding.
    ChallengeResponse {
        /// The nonce bytes that were included in the ClientHello.
        nonce: Vec<u8>,
    },
}

/// An expected X.509 extension OID and its value.
///
/// Used in [`RaTlsPolicy::expected_oids`] to verify configuration-specific
/// extensions embedded in RA-TLS certificates (e.g. config Merkle root,
/// egress CA bundle hash, WASM apps hash).
///
/// # Example
///
/// ```rust,ignore
/// use enclave_os_egress::client::{ExpectedOid, OID_CONFIG_MERKLE_ROOT};
///
/// let expected_merkle = ExpectedOid {
///     oid: OID_CONFIG_MERKLE_ROOT.into(),
///     expected_value: known_good_merkle_root.to_vec(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ExpectedOid {
    /// Dotted-string OID (e.g. `"1.3.6.1.4.1.65230.1.1"`).
    ///
    /// Use the constants [`OID_CONFIG_MERKLE_ROOT`], [`OID_EGRESS_CA_HASH`],
    /// [`OID_WASM_APPS_HASH`], or [`OID_ATTESTATION_SERVERS_HASH`] for well-known
    /// Privasys OIDs.
    pub oid: String,
    /// Expected raw extension value. The certificate's extension value must
    /// match this exactly.
    pub expected_value: Vec<u8>,
}

/// RA-TLS verification policy.
///
/// Pass to [`https_fetch`] to verify the
/// remote server's RA-TLS certificate after standard chain validation.
///
/// ## What is verified
///
/// 1. **Quote presence** — the leaf certificate must contain an attestation
///    quote in the expected TEE-specific X.509 extension.
/// 2. **Measurement registers** — MRENCLAVE / MRSIGNER (SGX) or MRTD (TDX)
///    must match the provided expected values (when set).
/// 3. **ReportData binding** — `SHA-512(SHA-256(pubkey) || binding)` is
///    verified according to the [`report_data`](Self::report_data) mode.
///    See [`ReportDataBinding`] for details.
/// 4. **Configuration OIDs** — custom X.509 extensions (config Merkle root,
///    egress CA hash, WASM apps hash, etc.) are compared against expected
///    values when provided in [`expected_oids`](Self::expected_oids).
/// 5. **Attestation server verification** — when
///    [`attestation_servers`](Self::attestation_servers) is non-empty, the
///    raw attestation quote is POSTed to each server for cryptographic
///    verification (signature chain, TCB status, platform identity).  The
///    attestation server is TEE-agnostic (SGX, TDX, SEV-SNP, etc.).
///    All servers must confirm the quote.
#[derive(Debug, Clone)]
pub struct RaTlsPolicy {
    /// Which TEE type to expect.
    pub tee: TeeType,
    /// Expected MRENCLAVE (SGX, 32 bytes). `None` = skip check.
    pub mr_enclave: Option<[u8; 32]>,
    /// Expected MRSIGNER (SGX, 32 bytes). `None` = skip check.
    pub mr_signer: Option<[u8; 32]>,
    /// Expected MRTD (TDX, 48 bytes). `None` = skip check.
    pub mr_td: Option<[u8; 48]>,
    /// How to verify the quote's 64-byte ReportData field.
    ///
    /// Defaults to [`ReportDataBinding::Deterministic`] which reproduces the
    /// binding from the certificate's public key and `NotBefore` (TDX) or
    /// skips verification (SGX deterministic — creation_time unavailable).
    ///
    /// Set to [`ReportDataBinding::ChallengeResponse`] when the client
    /// included a nonce in TLS extension `0xFFBB`.
    pub report_data: ReportDataBinding,
    /// Expected configuration OIDs to verify in the certificate.
    ///
    /// Each entry specifies an OID and its expected raw value. Common OIDs:
    ///
    /// | Constant | OID | What it proves |
    /// |----------|-----|----------------|
    /// | [`OID_CONFIG_MERKLE_ROOT`] | `1.3.6.1.4.1.65230.1.1` | All config inputs (Merkle tree root) |
    /// | [`OID_EGRESS_CA_HASH`] | `1.3.6.1.4.1.65230.2.1` | Egress CA bundle identity |
    /// | [`OID_WASM_APPS_HASH`] | `1.3.6.1.4.1.65230.2.5` | Combined workloads (WASM apps) hash |
    /// | [`OID_ATTESTATION_SERVERS_HASH`] | `1.3.6.1.4.1.65230.2.7` | Attestation server URL list identity |
    ///
    /// An empty `Vec` (the default) skips OID verification.
    pub expected_oids: Vec<ExpectedOid>,

    /// Attestation server URLs for cryptographic quote verification.
    ///
    /// When non-empty, the raw attestation quote from the server's
    /// certificate is POSTed to each URL.  **All** servers must confirm
    /// the quote for the TLS handshake to succeed.
    ///
    /// This enables multi-party trust: the enclave operator and the secret
    /// owner can each run an independent attestation verification server.
    ///
    /// The Privasys attestation server is TEE-agnostic and supports
    /// Intel SGX, Intel TDX, AMD SEV-SNP, NVIDIA, and ARM CCA.
    ///
    /// The default is an empty `Vec` (no remote verification).  Callers
    /// who want attestation server verification can populate this from
    /// the core attestation server config via
    /// [`enclave_os_common::attestation_servers::server_urls()`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let servers = enclave_os_common::attestation_servers::server_urls();
    ///
    /// let policy = RaTlsPolicy {
    ///     // ... other fields ...
    ///     attestation_servers: servers,
    /// };
    /// ```
    pub attestation_servers: Vec<String>,
}

/// Perform a full HTTPS request with any method, custom headers, and
/// optional body. Returns the complete [`HttpResponse`] (status, headers,
/// body).
///
/// ## Parameters
///
/// | Param | Description |
/// |-------|-------------|
/// | `method` | HTTP method string (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`, `"HEAD"`, `"OPTIONS"`). |
/// | `url` | Full URL (`https://host[:port]/path`). Only `https://` is supported. |
/// | `headers` | Custom request headers as `(name, value)` pairs. `Host` and `Connection: close` are always added. |
/// | `body` | Optional request body. `Content-Length` is added automatically unless already present in `headers`. |
/// | `root_store` | Trusted root CAs for TLS certificate validation. |
/// | `ratls` | Optional RA-TLS policy for attestation verification. |
///
/// ## Example
///
/// ```rust,ignore
/// use enclave_os_egress::client::{https_fetch, mozilla_root_store};
///
/// let resp = https_fetch(
///     "GET",
///     "https://example.com/api/data",
///     &[("Accept".into(), "application/json".into())],
///     None,
///     mozilla_root_store(),
///     None,
/// )?;
/// assert_eq!(resp.status, 200);
/// ```
pub fn https_fetch(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_url(url)?;

    // Build HTTP/1.1 request.
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, path, host
    );
    for (k, v) in headers {
        request.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            request.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
    }
    request.push_str("\r\n");

    let mut request_bytes = request.into_bytes();
    if let Some(b) = body {
        request_bytes.extend_from_slice(b);
    }

    https_request_inner(&host, port, &request_bytes, root_store, ratls)
}

/// Internal: perform an HTTPS request and return the full parsed response.
fn https_request_inner(
    host: &str,
    port: u16,
    request: &[u8],
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<HttpResponse, String> {
    let tls_config = build_client_config(root_store, ratls)
        .map_err(|e| e.to_string())?;

    let fd = ocall::net_tcp_connect(host, port)
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name.to_owned())
        .map_err(|e| format!("TLS init failed: {}", e))?;

    tls_handshake(fd, &mut tls_conn)
        .map_err(|_| "TLS handshake failed".to_string())?;

    // Send the HTTP request.
    {
        let mut writer = tls_conn.writer();
        writer.write_all(request).map_err(|e| format!("write failed: {}", e))?;
    }
    flush_tls(fd, &mut tls_conn).map_err(|_| "flush failed".to_string())?;

    // Read the complete response with cursor-based multi-record TLS
    // reads and drain-all-plaintext inner loop.
    let mut response_data = Vec::new();
    let mut net_buf = vec![0u8; 16384];
    let mut app_buf = vec![0u8; 16384];
    let mut body_limit_hit = false;

    loop {
        match ocall::net_recv(fd, &mut net_buf) {
            Ok(0) => break,
            Ok(n) => {
                // A single net_recv may contain multiple TLS records.
                // Use a cursor to feed them all to rustls.
                let mut cursor = std::io::Cursor::new(&net_buf[..n]);
                while (cursor.position() as usize) < n {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn.process_new_packets()
                                .map_err(|e| format!("TLS error: {:?}", e))?;
                        }
                        Err(e) => return Err(format!("read_tls error: {:?}", e)),
                    }
                }

                // Drain ALL available application data. A single
                // process_new_packets() call can produce multiple
                // plaintext chunks.
                loop {
                    match tls_conn.reader().read(&mut app_buf) {
                        Ok(0) => break,
                        Ok(m) => {
                            response_data.extend_from_slice(&app_buf[..m]);
                            if response_data.len() > MAX_RESPONSE_BODY + 16384 {
                                body_limit_hit = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                if body_limit_hit {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Close.
    tls_conn.send_close_notify();
    let _ = flush_tls(fd, &mut tls_conn);
    ocall::net_close(fd);

    // Parse HTTP response.
    let (status, headers, mut body) = parse_http_response(&response_data)?;
    if body.len() > MAX_RESPONSE_BODY {
        body.truncate(MAX_RESPONSE_BODY);
    }
    Ok(HttpResponse { status, headers, body })
}

/// Build a rustls `ClientConfig` using the provided root CAs.
///
/// When `ratls` is `Some`, a custom [`RaTlsVerifier`] is installed that
/// wraps the standard WebPKI chain validation with additional RA-TLS
/// checks (quote presence, measurements, ReportData binding).
fn build_client_config(
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<Arc<ClientConfig>, &'static str> {
    let provider = Arc::new(default_provider());

    let config = if let Some(policy) = ratls {
        // Build a WebPkiServerVerifier for standard chain validation,
        // then wrap it with our RA-TLS verifier.
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store.clone()),
            provider.clone(),
        )
        .build()
        .map_err(|_| "WebPKI verifier build error")?;

        let verifier = RaTlsVerifier {
            inner,
            policy: policy.clone(),
        };

        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        // When the policy uses challenge-response attestation, inject the
        // nonce into the ClientHello extension 0xFFBB so the remote server
        // can bind its attestation quote to our challenge.
        if let ReportDataBinding::ChallengeResponse { ref nonce } = policy.report_data {
            cfg.ratls_challenge = Some(nonce.clone());
        }

        cfg
    } else {
        // Standard TLS — no RA-TLS verification.
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .with_root_certificates(root_store.clone())
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// Perform the TLS handshake with cursor-based multi-record reads.
fn tls_handshake(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    loop {
        // Flush any pending outbound TLS data (e.g. ClientHello, Finished).
        flush_tls(fd, tls_conn)?;

        // In TLS 1.3 the handshake completes as soon as the client Finished
        // is flushed — there is nothing more to receive. Checking *after*
        // flush avoids a blocking recv on an idle socket.
        if !tls_conn.is_handshaking() {
            return Ok(());
        }

        // Read the next chunk of TLS handshake data from the server.
        let mut buf = vec![0u8; 16384];
        match ocall::net_recv(fd, &mut buf) {
            Ok(n) if n > 0 => {
                // A single recv may contain multiple TLS records; drain
                // them all via cursor.
                let mut cursor = std::io::Cursor::new(&buf[..n]);
                while (cursor.position() as usize) < n {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn.process_new_packets().map_err(|_| -1i32)?;
                        }
                        Err(_) => return Err(-1i32),
                    }
                }
            }
            Ok(_) => {
                // EOF — server closed before handshake completed.
                return Err(-1i32);
            }
            Err(_) => {
                // Read error.
                return Err(-1i32);
            }
        }
    }
}

/// Flush TLS output to the network via OCALL.
fn flush_tls(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    let mut buf = vec![0u8; 16384];
    loop {
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        match tls_conn.write_tls(&mut cursor) {
            Ok(0) => break,
            Ok(n) => {
                let data = &buf[..n];
                let mut offset = 0;
                while offset < data.len() {
                    match ocall::net_send(fd, &data[offset..]) {
                        Ok(sent) => offset += sent,
                        Err(_) => return Err(-1),
                    }
                }
            }
            Err(_) => return Err(-1),
        }
    }
    Ok(())
}

/// Parse a URL into (host, port, path). Only `https://` is supported.
fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.trim();

    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "only https:// URLs are supported".to_string())?;

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let port: u16 = host_port[i + 1..]
                .parse()
                .map_err(|_| "invalid port".to_string())?;
            (&host_port[..i], port)
        }
        None => (host_port, 443u16),
    };

    Ok((String::from(host), port, String::from(path)))
}

/// Parse a raw HTTP response into (status, headers, body).
fn parse_http_response(
    data: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let sep = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid HTTP response: no header terminator")?;

    let header_bytes = &data[..sep];
    let body = data[sep + 4..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "invalid HTTP response: non-UTF-8 headers")?;

    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or("empty HTTP response")?;

    // Parse "HTTP/1.1 200 OK"
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("invalid status line")?
        .parse()
        .map_err(|_| "invalid status code")?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    Ok((status, headers, body))
}

// =========================================================================
//  RA-TLS custom certificate verifier
// =========================================================================

/// Wraps a standard [`WebPkiServerVerifier`] with additional RA-TLS
/// attestation checks. The TLS handshake is rejected if any check fails.
#[derive(Debug)]
struct RaTlsVerifier {
    /// Standard WebPKI chain verifier (root CA validation).
    inner: Arc<WebPkiServerVerifier>,
    /// Caller-provided attestation expectations.
    policy: RaTlsPolicy,
}

impl ServerCertVerifier for RaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Standard certificate chain validation.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // 2. RA-TLS attestation verification.
        verify_ratls_cert(end_entity.as_ref(), &self.policy)
            .map_err(Error::General)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// =========================================================================
//  RA-TLS verification logic
// =========================================================================

/// Verify the RA-TLS attestation evidence in a DER-encoded leaf certificate.
fn verify_ratls_cert(der: &[u8], policy: &RaTlsPolicy) -> Result<(), String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| "RA-TLS: failed to parse leaf certificate DER".to_string())?;

    // --- Find the expected attestation extension ---
    let expected_oid = match policy.tee {
        TeeType::Sgx => oids::SGX_QUOTE_OID_STR,
        TeeType::Tdx => oids::TDX_QUOTE_OID_STR,
    };

    let quote_ext = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == expected_oid)
        .ok_or_else(|| {
            format!(
                "RA-TLS: no {} attestation quote found in certificate (expected OID {})",
                match policy.tee {
                    TeeType::Sgx => "SGX",
                    TeeType::Tdx => "TDX",
                },
                expected_oid
            )
        })?;

    let quote = quote_ext.value;

    // --- Parse quote via sgx_types and verify measurements + ReportData ---
    #[cfg(feature = "mock")]
    let is_mock = quote.starts_with(MOCK_PREFIX);
    #[cfg(not(feature = "mock"))]
    let is_mock = false;

    if !is_mock {
        match policy.tee {
            TeeType::Sgx => {
                let q = parse_quote3(quote)?;
                verify_sgx_measurements(&q, policy)?;
                verify_sgx_report_data(&q, &cert, policy)?;
            }
            TeeType::Tdx => {
                let q = parse_quote4(quote)?;
                verify_tdx_measurements(&q, policy)?;
                verify_tdx_report_data(&q, &cert, policy)?;
            }
        }
    }

    // --- Verify configuration OIDs ---
    verify_expected_oids(&cert, &policy.expected_oids)?;

    // --- Verify quote via attestation server(s) ---
    //
    // After all local checks pass, send the raw quote to each configured
    // attestation server for full cryptographic verification (signature
    // chain, TCB status, platform identity).  The attestation server is
    // TEE-agnostic and auto-detects the quote format.  This is the
    // authoritative proof that the quote was produced by genuine TEE
    // hardware and has not been tampered with.
    crate::attestation::verify_quote(quote, &policy.attestation_servers)?;

    Ok(())
}

/// Verify expected configuration OIDs in the certificate.
///
/// For each [`ExpectedOid`] in the policy the function locates the
/// corresponding X.509 extension by its dotted-string OID, extracts the raw
/// value, and compares it byte-for-byte against `expected_value`.
///
/// Returns `Err` when:
/// - A required OID is missing from the certificate.
/// - The value for a present OID does not match the expected value.
fn verify_expected_oids(
    cert: &X509Certificate<'_>,
    expected: &[ExpectedOid],
) -> Result<(), String> {
    for exp in expected {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == exp.oid)
            .ok_or_else(|| {
                format!(
                    "RA-TLS: expected OID {} not found in certificate",
                    exp.oid
                )
            })?;

        if ext.value != exp.expected_value.as_slice() {
            return Err(format!(
                "RA-TLS: OID {} value mismatch (got {} bytes, expected {} bytes)",
                exp.oid,
                ext.value.len(),
                exp.expected_value.len(),
            ));
        }
    }

    Ok(())
}

// =========================================================================
//  Quote parsing — directly via sgx_types #[repr(C, packed)] structs
// =========================================================================

/// Parse raw bytes into an SGX DCAP v3 `Quote3` (QuoteHeader + ReportBody).
fn parse_quote3(data: &[u8]) -> Result<Quote3, String> {
    if data.len() < mem::size_of::<Quote3>() {
        return Err(format!(
            "RA-TLS: SGX quote too short ({} bytes, need >= {})",
            data.len(),
            mem::size_of::<Quote3>(),
        ));
    }
    // SAFETY: Quote3 is #[repr(C, packed)] (alignment 1). Length validated above.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Quote3) })
}

/// Parse raw bytes into a TDX DCAP v4 `Quote4` (Quote4Header + Report2Body).
fn parse_quote4(data: &[u8]) -> Result<Quote4, String> {
    if data.len() < mem::size_of::<Quote4>() {
        return Err(format!(
            "RA-TLS: TDX quote too short ({} bytes, need >= {})",
            data.len(),
            mem::size_of::<Quote4>(),
        ));
    }
    // SAFETY: Quote4 is #[repr(C, packed)] (alignment 1). Length validated above.
    Ok(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Quote4) })
}

// =========================================================================
//  Measurement verification — typed field access via sgx_types
// =========================================================================

/// Verify SGX measurements (MRENCLAVE, MRSIGNER) from the parsed `Quote3`.
fn verify_sgx_measurements(quote: &Quote3, policy: &RaTlsPolicy) -> Result<(), String> {
    if let Some(expected) = &policy.mr_enclave {
        if quote.report_body.mr_enclave.m != *expected {
            return Err("RA-TLS: MRENCLAVE mismatch".to_string());
        }
    }
    if let Some(expected) = &policy.mr_signer {
        if quote.report_body.mr_signer.m != *expected {
            return Err("RA-TLS: MRSIGNER mismatch".to_string());
        }
    }
    Ok(())
}

/// Verify TDX measurements (MRTD) from the parsed `Quote4`.
fn verify_tdx_measurements(quote: &Quote4, policy: &RaTlsPolicy) -> Result<(), String> {
    if let Some(expected) = &policy.mr_td {
        if quote.report_body.mr_td.m != *expected {
            return Err("RA-TLS: MRTD mismatch".to_string());
        }
    }
    Ok(())
}

// =========================================================================
//  ReportData verification — deterministic & challenge-response
// =========================================================================

/// Verify the SGX quote's ReportData field.
///
/// | Mode | pubkey | binding |
/// |------|--------|---------|
/// | ChallengeResponse | raw EC point (65 B) | client nonce |
/// | Deterministic | — | *skipped* (creation_time not in cert) |
fn verify_sgx_report_data(
    quote: &Quote3,
    cert: &X509Certificate<'_>,
    policy: &RaTlsPolicy,
) -> Result<(), String> {
    match &policy.report_data {
        ReportDataBinding::ChallengeResponse { nonce } => {
            // SGX (enclave-os) uses the raw EC point (65 bytes) — not SPKI DER.
            let ec_point = cert.public_key().subject_public_key.as_ref();
            let expected = compute_report_data_hash(ec_point, nonce);
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: SGX ReportData mismatch (challenge-response)".into());
            }
        }
        ReportDataBinding::Deterministic => {
            // SGX deterministic certs use `creation_time` (8-byte LE epoch)
            // as the binding, but this value is not recoverable from the
            // certificate's NotBefore which is set to a fixed date.
            // Verification is skipped; quote presence + measurements still
            // provide trust.
        }
    }
    Ok(())
}

/// Verify the TDX quote's ReportData field.
///
/// | Mode | pubkey | binding |
/// |------|--------|---------|
/// | Deterministic | SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` |
/// | ChallengeResponse | SPKI DER (91 B) | client nonce |
fn verify_tdx_report_data(
    quote: &Quote4,
    cert: &X509Certificate<'_>,
    policy: &RaTlsPolicy,
) -> Result<(), String> {
    let ec_point = cert.public_key().subject_public_key.as_ref();
    let spki_der = build_p256_spki_der(ec_point);

    match &policy.report_data {
        ReportDataBinding::Deterministic => {
            let not_before = cert.validity().not_before.to_datetime();
            let binding = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}Z",
                not_before.year(),
                not_before.month() as u8,
                not_before.day(),
                not_before.hour(),
                not_before.minute(),
            );
            let expected = compute_report_data_hash(&spki_der, binding.as_bytes());
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: TDX ReportData mismatch (deterministic)".into());
            }
        }
        ReportDataBinding::ChallengeResponse { nonce } => {
            let expected = compute_report_data_hash(&spki_der, nonce);
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: TDX ReportData mismatch (challenge-response)".into());
            }
        }
    }
    Ok(())
}

/// `SHA-512( SHA-256(pubkey_bytes) || binding )`
///
/// Re-exported from [`enclave_os_common::quote::compute_report_data_hash`].
fn compute_report_data_hash(pubkey_bytes: &[u8], binding: &[u8]) -> digest::Digest {
    enclave_os_common::quote::compute_report_data_hash(pubkey_bytes, binding)
}

/// Build the DER-encoded SubjectPublicKeyInfo for an ECDSA P-256 public key.
///
/// This reproduces the exact bytes that Go's `x509.MarshalPKIXPublicKey`
/// produces for P-256 keys, which is what the Caddy RA-TLS module uses
/// when computing `SHA-256(DER public key)` for the ReportData.
///
/// The `ec_point` must be the 65-byte uncompressed EC point (`04 || x || y`).
fn build_p256_spki_der(ec_point: &[u8]) -> Vec<u8> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm  AlgorithmIdentifier ::= SEQUENCE {
    //     algorithm  OID 1.2.840.10045.2.1 (ecPublicKey)
    //     parameters OID 1.2.840.10045.3.1.7 (prime256v1)
    //   }
    //   subjectPublicKey BIT STRING (04 || x || y)
    // }

    // Pre-encoded AlgorithmIdentifier for ecPublicKey + prime256v1.
    #[rustfmt::skip]
    const ALGO: &[u8] = &[
        0x30, 0x13,                                                 // SEQUENCE (19)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,     // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
    ];

    // BIT STRING header: tag(1) + length(1) + unused-bits(1) = 3 bytes.
    // Content length = 1 (unused bits) + ec_point.len().
    let bit_string_len = 1 + ec_point.len(); // 66 for P-256

    // Outer SEQUENCE inner length = ALGO(21) + BIT STRING header(3) + ec_point.
    let inner_len = ALGO.len() + 3 + ec_point.len(); // 89 for P-256

    let mut spki = Vec::with_capacity(2 + inner_len);
    spki.push(0x30); // SEQUENCE tag
    spki.push(inner_len as u8); // length (fits in one byte for P-256)
    spki.extend_from_slice(ALGO);
    spki.push(0x03); // BIT STRING tag
    spki.push(bit_string_len as u8);
    spki.push(0x00); // unused bits
    spki.extend_from_slice(ec_point);
    spki
}
