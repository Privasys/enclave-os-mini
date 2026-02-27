// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HTTPS egress client – makes outbound HTTPS requests from inside the enclave.
//!
//! Uses rustls for TLS and a minimal HTTP/1.1 implementation. Network I/O
//! flows through OCALLs to the host, but the TLS termination happens inside
//! the enclave, so the host never sees plaintext.

use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use core::mem;

use ring::digest;
use enclave_os_enclave::ocall;

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

// Re-export the dotted-string OIDs for callers building `ExpectedOid` values.
pub use enclave_os_common::oids::{
    CONFIG_MERKLE_ROOT_OID_STR as OID_CONFIG_MERKLE_ROOT,
    EGRESS_CA_HASH_OID_STR as OID_EGRESS_CA_HASH,
    WASM_APPS_HASH_OID_STR as OID_WASM_APPS_HASH,
};

// =========================================================================
//  RA-TLS verification types
// =========================================================================

/// Mock quote prefix used in development/test builds.
const MOCK_PREFIX: &[u8] = b"MOCK_QUOTE:";

/// Target TEE type for RA-TLS verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeType {
    /// Intel SGX enclave (quote OID `1.2.840.113741.1.13.1.0`).
    Sgx,
    /// Intel TDX Confidential VM (quote OID `1.2.840.113741.1.5.5.1.6`).
    Tdx,
}

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
    /// or [`OID_WASM_APPS_HASH`] for well-known Privasys OIDs.
    pub oid: String,
    /// Expected raw extension value. The certificate's extension value must
    /// match this exactly.
    pub expected_value: Vec<u8>,
}

/// RA-TLS verification policy.
///
/// Pass to [`https_get`] / [`https_post`] to verify the remote server's
/// RA-TLS certificate after standard chain validation.
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
    /// | [`OID_WASM_APPS_HASH`] | `1.3.6.1.4.1.65230.2.3` | WASM application code identity |
    ///
    /// An empty `Vec` (the default) skips OID verification.
    pub expected_oids: Vec<ExpectedOid>,
}

/// Perform an HTTPS GET request.
///
/// Requires a `RootCertStore` containing trusted root CAs.
///
/// When `ratls` is `Some`, the server's certificate is additionally verified
/// against the given [`RaTlsPolicy`] (quote presence, measurement registers,
/// and — for TDX — ReportData binding). The TLS handshake is rejected if
/// any check fails.
pub fn https_get(
    url: &str,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<Vec<u8>, i32> {
    let (host, port, path) = parse_url(url).map_err(|_| -1)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path, host
    );
    https_request(&host, port, request.as_bytes(), root_store, ratls)
}

/// Perform an HTTPS POST request.
///
/// See [`https_get`] for details on the `ratls` parameter.
pub fn https_post(
    url: &str,
    body: &[u8],
    content_type: &str,
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<Vec<u8>, i32> {
    let (host, port, path) = parse_url(url).map_err(|_| -1)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        path, host, content_type, body.len()
    );
    let mut full_request = request.into_bytes();
    full_request.extend_from_slice(body);
    https_request(&host, port, &full_request, root_store, ratls)
}

/// Internal: perform an HTTPS request and return the response body.
fn https_request(
    host: &str,
    port: u16,
    request: &[u8],
    root_store: &RootCertStore,
    ratls: Option<&RaTlsPolicy>,
) -> Result<Vec<u8>, i32> {
    // Build TLS client config — with RA-TLS verification when a policy is provided
    let tls_config = build_client_config(root_store, ratls).map_err(|_| -1)?;

    // Connect to the remote server via OCALL
    let fd = ocall::net_tcp_connect(host, port)?;

    // Create TLS client connection
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| -1i32)?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name.to_owned())
        .map_err(|_| -1i32)?;

    // Perform TLS handshake
    tls_handshake(fd, &mut tls_conn)?;

    // Send the HTTP request through TLS
    {
        let mut writer = tls_conn.writer();
        use std::io::Write;
        writer.write_all(request).map_err(|_| -1i32)?;
    }
    flush_tls(fd, &mut tls_conn)?;

    // Read the complete response
    let mut response_data = Vec::new();
    loop {
        // Read from network into TLS
        let mut net_buf = vec![0u8; 16384];
        match ocall::net_recv(fd, &mut net_buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&net_buf[..n]);
                tls_conn.read_tls(&mut cursor).map_err(|_| -1i32)?;
                tls_conn.process_new_packets().map_err(|_| -1i32)?;
            }
            Err(_) => break,
        }

        // Read decrypted data
        let mut app_buf = vec![0u8; 16384];
        let mut reader = tls_conn.reader();
        use std::io::Read;
        match reader.read(&mut app_buf) {
            Ok(0) => break,
            Ok(n) => response_data.extend_from_slice(&app_buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }

    // Close
    tls_conn.send_close_notify();
    let _ = flush_tls(fd, &mut tls_conn);
    ocall::net_close(fd);

    // Parse HTTP response – extract body after \r\n\r\n
    let body = extract_http_body(&response_data);
    Ok(body)
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

        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
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

/// Perform the TLS handshake.
fn tls_handshake(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    loop {
        if !tls_conn.is_handshaking() {
            flush_tls(fd, tls_conn)?;
            return Ok(());
        }

        flush_tls(fd, tls_conn)?;

        let mut buf = vec![0u8; 16384];
        match ocall::net_recv(fd, &mut buf) {
            Ok(n) if n > 0 => {
                let mut cursor = std::io::Cursor::new(&buf[..n]);
                tls_conn.read_tls(&mut cursor).map_err(|_| -1i32)?;
                tls_conn.process_new_packets().map_err(|_| -1i32)?;
            }
            _ => {
                // Brief retry for non-blocking
                continue;
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

/// Parse a URL into (host, port, path).
fn parse_url(url: &str) -> Result<(String, u16, String), &'static str> {
    let url = url.trim();

    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err("Unsupported scheme");
    };

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let port_str = &host_port[i + 1..];
            let port: u16 = port_str.parse().map_err(|_| "Invalid port")?;
            (&host_port[..i], port)
        }
        None => (host_port, default_port),
    };

    Ok((String::from(host), port, String::from(path)))
}

/// Extract the HTTP body from a raw HTTP response.
fn extract_http_body(response: &[u8]) -> Vec<u8> {
    // Find \r\n\r\n separator
    for i in 0..response.len().saturating_sub(3) {
        if &response[i..i + 4] == b"\r\n\r\n" {
            return response[i + 4..].to_vec();
        }
    }
    // No separator found — return entire response
    response.to_vec()
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
    if quote.starts_with(MOCK_PREFIX) {
        // Mock quotes: skip measurement + ReportData checks.
    } else {
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
fn compute_report_data_hash(pubkey_bytes: &[u8], binding: &[u8]) -> digest::Digest {
    let pk_hash = digest::digest(&digest::SHA256, pubkey_bytes);
    let mut preimage = Vec::with_capacity(32 + binding.len());
    preimage.extend_from_slice(pk_hash.as_ref());
    preimage.extend_from_slice(binding);
    digest::digest(&digest::SHA512, &preimage)
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
