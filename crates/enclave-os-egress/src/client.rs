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
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme,
};

use x509_parser::prelude::*;

// sgx_types is provided by the Teaclave sysroot — gives us Quote3, Quote4,
// ReportBody, Report2Body with typed field access.
extern crate sgx_types;
use sgx_types::types::{Quote3, Quote4};

use enclave_os_common::oids;

// Re-export shared quote primitives for callers building `RaTlsPolicy` values.
pub use enclave_os_common::quote::TeeType;

/// Re-export of `rustls::RootCertStore` so downstream callers can refer to
/// the trust-anchor type without depending on `rustls` directly.
pub use rustls::RootCertStore;

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

/// Build a fresh [`RootCertStore`] from caller-supplied DER root certificates.
///
/// Useful for callers (e.g. the WASM SDK host shim) that want to use a
/// custom set of trust anchors without depending on `rustls` directly.
/// Returns an error if any DER cannot be parsed as an X.509 certificate.
pub fn root_store_from_der<I, B>(ders: I) -> Result<RootCertStore, String>
where
    I: IntoIterator<Item = B>,
    B: Into<Vec<u8>>,
{
    let mut store = RootCertStore::empty();
    for (i, der) in ders.into_iter().enumerate() {
        store
            .add(rustls::pki_types::CertificateDer::from(der.into()))
            .map_err(|e| format!("ca-roots-der[{}]: invalid root certificate: {}", i, e))?;
    }
    Ok(store)
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

    /// Mutual RA-TLS: when `Some`, the connection presents a client
    /// certificate carrying this (OS-derived) app identity, minted by the
    /// registered [`EnclaveClientCertSigner`] and bound to the server's
    /// challenge. `None` (the default) presents no client certificate.
    pub client_identity: Option<ClientCertIdentity>,
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
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    // Send the HTTP request.
    {
        let mut writer = tls_conn.writer();
        writer.write_all(request).map_err(|e| format!("write failed: {}", e))?;
    }
    flush_tls(fd, &mut tls_conn).map_err(|_| "flush failed".to_string())?;

    // Read the complete response with cursor-based multi-record TLS
    // reads. We MUST drain decrypted plaintext between successive
    // `process_new_packets` calls — otherwise rustls's internal
    // received-plaintext buffer fills up on large responses (each
    // 16 KiB TLS record contributes ~16 KiB plaintext) and yields
    // `Custom { kind: Other, error: "received plaintext buffer full" }`.
    let mut response_data = Vec::new();
    let mut net_buf = vec![0u8; 16384];
    let mut app_buf = vec![0u8; 16384];
    let mut body_limit_hit = false;

    // Disable rustls's internal plaintext buffer cap; we drain
    // aggressively below and enforce our own MAX_RESPONSE_BODY limit
    // on `response_data`.
    tls_conn.set_buffer_limit(None);

    'outer: loop {
        match ocall::net_recv(fd, &mut net_buf) {
            Ok(0) => break,
            Ok(n) => {
                // A single net_recv may contain multiple TLS records.
                // Feed them all to rustls, draining plaintext after
                // each decryption pass.
                let mut cursor = std::io::Cursor::new(&net_buf[..n]);
                while (cursor.position() as usize) < n {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn.process_new_packets()
                                .map_err(|e| format!("TLS error: {:?}", e))?;

                            // Drain plaintext NOW (inside the cursor
                            // loop) so the rustls deframer / decrypter
                            // buffers stay near-empty across the
                            // remaining records in this chunk.
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
                                break 'outer;
                            }
                        }
                        Err(e) => return Err(format!("read_tls error: {:?}", e)),
                    }
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

// =========================================================================
//  RA-TLS client authentication (mutual attestation)
// =========================================================================

/// The per-app measurement a client RA-TLS certificate must carry so the
/// remote enclave (e.g. an Enclave Vault) can authorise it via OID 3.2 / 3.6.
///
/// These values are **derived by the OS from real enclave state** (the loaded
/// component's code hash, the platform-assigned app id) — never supplied by an
/// untrusted caller. A connection presents a client cert iff its
/// [`RaTlsPolicy::client_identity`] is `Some`.
#[derive(Debug, Clone)]
pub struct ClientCertIdentity {
    /// App code hash (`sha256(cwasm)`), stamped at OID 3.2.
    pub code_hash: Vec<u8>,
    /// App-id, stamped at OID 3.6 (MR_APP). `None` keeps the MR_ENCLAVE shape.
    pub app_id: Option<Vec<u8>>,
}

/// Signs the enclave's RA-TLS **client** certificate for mutual attestation.
///
/// Implemented by the OS, which holds the SGX quote primitive and the enclave
/// CA signing key, and registered **once** at enclave init via
/// [`register_enclave_client_cert_signer`]. This keeps `egress` decoupled from
/// the attestation crate: egress never sees CA material, and a caller can only
/// name which app identity to present (via the policy) — the OS stamps the
/// real measurement and signs.
pub trait EnclaveClientCertSigner: Send + Sync {
    /// Mint a client cert carrying `identity`, with the SGX quote's ReportData
    /// bound to the server's `challenge` (ext `0xFFBB`). Returns
    /// `(cert_chain_der, pkcs8_key_der)`, or `None` to decline.
    fn sign(
        &self,
        challenge: &[u8],
        identity: &ClientCertIdentity,
    ) -> Option<(Vec<Vec<u8>>, Vec<u8>)>;
}

static CLIENT_CERT_SIGNER: OnceLock<&'static dyn EnclaveClientCertSigner> = OnceLock::new();

/// Register the OS's client-certificate signer. Call once during enclave init,
/// after the enclave CA is available. Subsequent calls are ignored.
pub fn register_enclave_client_cert_signer(signer: &'static dyn EnclaveClientCertSigner) {
    let _ = CLIENT_CERT_SIGNER.set(signer);
}

/// Exposes the OS's attestation facts to higher crates (notably the wasm crate's
/// vault directory client and key-policy authoring), which cannot call the
/// attestation crate directly because the dep runs enclave→wasm.
///
/// Implemented by the OS (it holds the SGX quote primitive and can self-report)
/// and registered once at enclave init via [`register_enclave_attestation_provider`].
/// Mirrors [`EnclaveClientCertSigner`]: the OS — not the caller — produces the
/// real measurement; a quote travels in the request body, not the TLS layer, so
/// it authenticates the enclave to a verifier that is **not** an RA-TLS peer (in
/// particular the management-service vault directory behind a TLS-terminating LB).
pub trait EnclaveAttestationProvider: Send + Sync {
    /// Return a DCAP quote whose ReportData binds `nonce`, or `None` to decline.
    fn quote(&self, nonce: &[u8]) -> Option<Vec<u8>>;
    /// This enclave's own runtime MRENCLAVE (code identity), for self-authoring a
    /// vault key policy that pins the running runtime as the `Tee` measurement.
    fn self_mrenclave(&self) -> Option<[u8; 32]>;
}

static ATTESTATION_PROVIDER: OnceLock<&'static dyn EnclaveAttestationProvider> = OnceLock::new();

/// Register the OS's attestation provider. Call once during enclave init.
/// Subsequent calls are ignored.
pub fn register_enclave_attestation_provider(provider: &'static dyn EnclaveAttestationProvider) {
    let _ = ATTESTATION_PROVIDER.set(provider);
}

/// Produce an attestation quote binding `nonce`, via the registered
/// [`EnclaveAttestationProvider`]. `None` if none is registered (e.g. the host
/// build) or it declined.
pub fn enclave_attestation_quote(nonce: &[u8]) -> Option<Vec<u8>> {
    ATTESTATION_PROVIDER.get().and_then(|p| p.quote(nonce))
}

/// This enclave's own runtime MRENCLAVE, via the registered
/// [`EnclaveAttestationProvider`]. `None` if none is registered.
pub fn enclave_self_mrenclave() -> Option<[u8; 32]> {
    ATTESTATION_PROVIDER.get().and_then(|p| p.self_mrenclave())
}

/// Adapter that presents the enclave's client identity during the handshake,
/// minting via the registered [`EnclaveClientCertSigner`] and binding to the
/// server's RA-TLS challenge (fork `CertificateRequest` extension `0xFFBB`).
#[derive(Debug)]
struct ChallengeBoundClientAuth {
    identity: ClientCertIdentity,
    provider: Arc<CryptoProvider>,
}

impl ResolvesClientCert for ChallengeBoundClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
        ratls_challenge: Option<&[u8]>,
    ) -> Option<Arc<CertifiedKey>> {
        // Bidirectional challenge-response is mandatory: without the server's
        // nonce we cannot bind a fresh quote, so decline rather than present
        // an unbound identity.
        let challenge = ratls_challenge?;
        let signer = *CLIENT_CERT_SIGNER.get()?;
        let (chain_der, pkcs8) = signer.sign(challenge, &self.identity)?;
        let certs: Vec<CertificateDer<'static>> =
            chain_der.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        let signing_key = self.provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Build a rustls `ClientConfig` using the provided root CAs.
///
/// When `ratls` is `Some`, a custom [`RaTlsVerifier`] is installed that
/// wraps the standard WebPKI chain validation with additional RA-TLS
/// checks (quote presence, measurements, ReportData binding).
///
/// When the policy's [`RaTlsPolicy::client_identity`] is `Some`, the client
/// presents a measurement-bound certificate minted on demand by the registered
/// [`EnclaveClientCertSigner`], for mutual attestation against a server that
/// requests one (e.g. a vault).
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

        let wants_client_cert = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS config error")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        let mut cfg = match &policy.client_identity {
            Some(identity) => wants_client_cert.with_client_cert_resolver(Arc::new(
                ChallengeBoundClientAuth {
                    identity: identity.clone(),
                    provider: provider.clone(),
                },
            )),
            None => wants_client_cert.with_no_client_auth(),
        };

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
fn tls_handshake(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), String> {
    loop {
        // Flush any pending outbound TLS data (e.g. ClientHello, Finished).
        flush_tls(fd, tls_conn).map_err(|_| String::from("flush failed"))?;

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
                        // The peer-cert verifier runs inside process_new_packets,
                        // so its rejection reason surfaces here — propagate it.
                        Ok(_) => {
                            tls_conn.process_new_packets().map_err(|e| format!("{e}"))?;
                        }
                        Err(e) => return Err(format!("read_tls: {e}")),
                    }
                }
            }
            Ok(_) => {
                // EOF — server closed before handshake completed.
                return Err(String::from("server closed before handshake completed"));
            }
            Err(_) => {
                // Read error.
                return Err(String::from("network read error"));
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
    let raw_body = &data[sep + 4..];

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
    let mut chunked = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            // A reverse proxy (e.g. Caddy in front of the management-service)
            // streams larger JSON with `Transfer-Encoding: chunked` rather than a
            // Content-Length. We must de-chunk it; otherwise the body still
            // carries the hex chunk-size framing and fails to parse.
            if key.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((key, value));
        }
    }

    let body = if chunked {
        dechunk(raw_body)?
    } else {
        raw_body.to_vec()
    };

    Ok((status, headers, body))
}

/// Decode an HTTP/1.1 chunked transfer-encoding body: a sequence of
/// `<hex-size>[;chunk-ext]\r\n<data>\r\n` chunks ended by a `0\r\n` chunk
/// (trailers, if any, are ignored).
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    loop {
        let nl = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("chunked: missing size CRLF")?;
        // Size is hex, up to an optional ';' introducing chunk extensions.
        let size_field = &data[..nl];
        let size_hex = size_field.split(|&b| b == b';').next().unwrap_or(size_field);
        let size_str = std::str::from_utf8(size_hex)
            .map_err(|_| "chunked: non-UTF-8 size")?
            .trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "chunked: bad size")?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return Err("chunked: truncated chunk data".into());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Consume the CRLF that terminates the chunk data.
        if data.len() >= 2 && &data[..2] == b"\r\n" {
            data = &data[2..];
        }
    }
    Ok(out)
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
        // 1. Standard certificate chain validation (issuer, expiry, signature).
        //    RA-TLS identity is the attestation quote, NOT the DNS/IP name: an
        //    attested peer's leaf (e.g. a vault's, dialed by IP) commonly carries
        //    no SAN, so a name mismatch is expected and ignored here. Every other
        //    chain failure still rejects the handshake.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(e) => return Err(e),
        }

        // 2. RA-TLS attestation verification (the real identity check).
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
/// | ChallengeResponse | SPKI DER (91 B) | client nonce |
/// | Deterministic | SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` |
fn verify_sgx_report_data(
    quote: &Quote3,
    cert: &X509Certificate<'_>,
    policy: &RaTlsPolicy,
) -> Result<(), String> {
    // SGX (enclave-os) uses the full SPKI DER (91 bytes for P-256), matching
    // Go's x509.MarshalPKIXPublicKey and standard X.509 certificate viewers'
    // "Public Key SHA-256" fingerprint.
    let ec_point = cert.public_key().subject_public_key.as_ref();
    let spki_der = enclave_os_common::quote::build_p256_spki_der(ec_point);

    match &policy.report_data {
        ReportDataBinding::ChallengeResponse { nonce } => {
            let expected = compute_report_data_hash(&spki_der, nonce);
            if quote.report_body.report_data.d != expected.as_ref() {
                return Err("RA-TLS: SGX ReportData mismatch (challenge-response)".into());
            }
        }
        ReportDataBinding::Deterministic => {
            // SGX sets NotBefore to the minute-truncated creation time and binds
            // "YYYY-MM-DDTHH:MMZ", same as the container/TDX issuer, so the
            // binding is reproducible from the certificate.
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
                return Err("RA-TLS: SGX ReportData mismatch (deterministic)".into());
            }
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
    let spki_der = enclave_os_common::quote::build_p256_spki_der(ec_point);

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

/// `SHA-512( SHA-256(spki_der) || binding )`
///
/// Re-exported from [`enclave_os_common::quote::compute_report_data_hash`].
fn compute_report_data_hash(pubkey_bytes: &[u8], binding: &[u8]) -> digest::Digest {
    enclave_os_common::quote::compute_report_data_hash(pubkey_bytes, binding)
}
