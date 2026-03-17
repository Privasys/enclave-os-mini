// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS ingress server — data-channel driven.
//!
//! The host TCP proxy accepts TCP connections, assigns a `conn_id`, and
//! shuttles raw encrypted bytes through the SPSC data channel. This
//! server processes those messages:
//!
//!   1. `TcpNew(conn_id, peer_addr)` — record a pending connection.
//!   2. `TcpData(conn_id, bytes)` — feed raw TLS bytes into the session.
//!      On first data for a new connection, parse the ClientHello,
//!      generate the RA-TLS certificate, create the TLS session.
//!   3. `TcpClose(conn_id)` — tear down the session.
//!
//! Outgoing TLS bytes (handshake responses, encrypted app data) are
//! written to the `data_enc_to_host` SPSC queue for the TCP proxy to
//! send on the wire.
//!
//! ## No OCALLs for I/O
//!
//! All network I/O is mediated by the data channel. The enclave never
//! calls `net_recv`/`net_send` for inbound connections. OCALLs are still
//! used for non-network operations (KV store, time, logging) via the
//! separate RPC channel.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use crate::modules;
use crate::ocall;
use crate::ratls::attestation::{self, CaContext, CertMode};
use crate::ratls::cert_store;
use crate::ratls::session::RaTlsSession;
use crate::{enclave_log_info, enclave_log_error};

use enclave_os_common::channel::{self, ChannelMsgType};
use enclave_os_common::queue::SpscProducer;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::Acceptor;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig, SignatureScheme};

// ========================================================================
//  Session states
// ========================================================================

/// Per-connection state. A connection progresses through:
///   `Pending` → `Handshaking` → `Established`
enum SessionState {
    /// TCP connection accepted but no TLS data received yet.
    Pending {
        peer_addr: String,
    },
    /// TLS handshake is in progress.
    Handshaking(RaTlsSession),
    /// TLS handshake complete, processing application data.
    Established(RaTlsSession),
}

// ========================================================================
//  IngressServer
// ========================================================================

/// RA-TLS ingress server driven by data channel messages.
pub struct IngressServer {
    /// Per-connection state, keyed by conn_id from the TCP proxy.
    sessions: BTreeMap<u32, SessionState>,
    /// Intermediary CA for certificate generation.
    ca: Arc<CaContext>,
    /// Producer for `data_enc_to_host` — sends TLS bytes to the TCP proxy.
    data_tx: &'static SpscProducer,
    /// Shutdown flag.
    shutdown: bool,
    /// Per-hostname cached deterministic TLS configs.
    cached_configs: BTreeMap<String, CachedConfig>,
}

/// A cached ServerConfig for deterministic (non-challenge) connections.
struct CachedConfig {
    config: Arc<ServerConfig>,
    expires_at: u64,
    /// CertStore generation at the time this config was created.
    /// Used to detect stale caches after app register/unregister.
    store_generation: u64,
}

impl IngressServer {
    /// Create a new ingress server.
    ///
    /// `data_tx` is the producer for the `data_enc_to_host` SPSC queue.
    /// The host TCP proxy reads from the other end and sends bytes on
    /// the wire.
    pub fn new(ca: Arc<CaContext>, data_tx: &'static SpscProducer) -> Self {
        Self {
            sessions: BTreeMap::new(),
            ca,
            data_tx,
            shutdown: false,
            cached_configs: BTreeMap::new(),
        }
    }

    /// Process a single data channel message.
    ///
    /// Called from the enclave event loop for each message received on
    /// the `data_host_to_enc` queue.
    pub fn handle_message(
        &mut self,
        msg_type: ChannelMsgType,
        conn_id: u32,
        payload: &[u8],
    ) {
        match msg_type {
            ChannelMsgType::TcpNew => {
                let peer_addr = core::str::from_utf8(payload)
                    .unwrap_or("<invalid>")
                    .to_string();
                enclave_log_info!(
                    "New connection conn_id={} from {}", conn_id, peer_addr
                );
                self.sessions.insert(conn_id, SessionState::Pending {
                    peer_addr,
                });
            }

            ChannelMsgType::TcpData => {
                self.handle_tcp_data(conn_id, payload);
            }

            ChannelMsgType::TcpClose => {
                if let Some(state) = self.sessions.remove(&conn_id) {
                    if let SessionState::Established(mut session)
                        | SessionState::Handshaking(mut session) = state
                    {
                        let close_bytes = session.close_notify();
                        if !close_bytes.is_empty() {
                            self.send_to_proxy(conn_id, &close_bytes);
                        }
                    }
                    enclave_log_info!("Connection closed conn_id={}", conn_id);
                }
            }
        }
    }

    /// Are we shutting down?
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Invalidate cached cert for a hostname (called when an app is
    /// loaded/unloaded).
    pub fn invalidate_cached_config(&mut self, hostname: &str) {
        self.cached_configs.remove(hostname);
    }

    // ====================================================================
    //  TCP data handling
    // ====================================================================

    /// Handle incoming TLS bytes for a connection.
    fn handle_tcp_data(&mut self, conn_id: u32, data: &[u8]) {
        // Take ownership of the session state to avoid borrow issues
        let state = match self.sessions.remove(&conn_id) {
            Some(s) => s,
            None => {
                enclave_log_error!(
                    "TcpData for unknown conn_id={}", conn_id
                );
                return;
            }
        };

        match state {
            SessionState::Pending { peer_addr } => {
                // First TLS data — should contain the ClientHello.
                // Parse it, generate cert, create the TLS session.
                match self.create_session(conn_id, &peer_addr, data) {
                    Ok(session) => {
                        if session.is_handshaking() {
                            self.sessions.insert(
                                conn_id,
                                SessionState::Handshaking(session),
                            );
                        } else {
                            self.sessions.insert(
                                conn_id,
                                SessionState::Established(session),
                            );
                        }
                    }
                    Err(e) => {
                        enclave_log_error!(
                            "Session creation failed for conn_id={}: {}",
                            conn_id, e
                        );
                        self.send_close(conn_id);
                    }
                }
            }

            SessionState::Handshaking(mut session) => {
                match self.process_session_data(conn_id, &mut session, data) {
                    Ok(()) => {
                        if session.is_handshaking() {
                            self.sessions.insert(
                                conn_id,
                                SessionState::Handshaking(session),
                            );
                        } else {
                            enclave_log_info!(
                                "TLS handshake complete for conn_id={}",
                                conn_id
                            );
                            // The client may have sent application data
                            // (e.g. an HTTP request) in the same TLS
                            // flight as the handshake Finished message.
                            // Dispatch any buffered requests now.
                            self.dispatch_requests(conn_id, &mut session);
                            self.sessions.insert(
                                conn_id,
                                SessionState::Established(session),
                            );
                        }
                    }
                    Err(e) => {
                        enclave_log_error!(
                            "Handshake error conn_id={}: {}", conn_id, e
                        );
                        self.send_close(conn_id);
                    }
                }
            }

            SessionState::Established(mut session) => {
                match self.process_session_data(conn_id, &mut session, data) {
                    Ok(()) => {
                        // Dispatch any complete HTTP requests
                        self.dispatch_requests(conn_id, &mut session);
                        self.sessions.insert(
                            conn_id,
                            SessionState::Established(session),
                        );
                    }
                    Err(e) => {
                        enclave_log_error!(
                            "Session error conn_id={}: {}", conn_id, e
                        );
                        self.send_close(conn_id);
                    }
                }
            }
        }
    }

    /// Feed TLS bytes into a session and send any output back.
    fn process_session_data(
        &mut self,
        conn_id: u32,
        session: &mut RaTlsSession,
        data: &[u8],
    ) -> Result<(), &'static str> {
        session.feed_tls_bytes(data)?;
        let output = session.collect_tls_output()?;
        if !output.is_empty() {
            self.send_to_proxy(conn_id, &output);
        }
        Ok(())
    }

    /// Process all complete HTTP/1.1 requests from a session.
    fn dispatch_requests(&mut self, conn_id: u32, session: &mut RaTlsSession) {
        // Build per-connection request context with optional peer cert
        // and client challenge nonce (for bidirectional RA-TLS verification,
        // sent via TLS CertificateRequest extension 0xFFBB).
        //
        // OIDC claims are populated per-request in handle_http_request()
        // because different requests in the same session may carry
        // different tokens (or none — e.g. GET /healthz).
        let base_ctx = enclave_os_common::modules::RequestContext {
            peer_cert_der: session.peer_cert_der(),
            client_challenge_nonce: session.client_challenge_nonce().cloned(),
            oidc_claims: None,
        };

        loop {
            match session.recv_http_request() {
                Ok(Some(http_req)) => {
                    let close = http_req.connection_close;
                    let result = handle_http_request(&http_req, &base_ctx);

                    // Send HTTP response
                    let send_close = close || result.shutdown;
                    match session.send_http_response(
                        result.status,
                        &result.body,
                        send_close,
                    ) {
                        Ok(tls_bytes) => {
                            if !tls_bytes.is_empty() {
                                self.send_to_proxy(conn_id, &tls_bytes);
                            }
                        }
                        Err(e) => {
                            enclave_log_error!(
                                "send_http_response failed conn_id={}: {}",
                                conn_id, e
                            );
                            self.send_close(conn_id);
                            return;
                        }
                    }

                    if result.shutdown {
                        enclave_log_info!(
                            "Shutdown requested by conn_id={}", conn_id
                        );
                        self.shutdown = true;
                        self.send_close(conn_id);
                        return;
                    }

                    if close {
                        self.send_close(conn_id);
                        return;
                    }
                }
                Ok(None) => break, // no more complete requests
                Err(e) => {
                    enclave_log_error!(
                        "recv_http_request error conn_id={}: {}", conn_id, e
                    );
                    // Send a 400 Bad Request before closing
                    let err_body = b"{\"error\":\"malformed request\"}";
                    if let Ok(tls_bytes) =
                        session.send_http_response(400, err_body, true)
                    {
                        if !tls_bytes.is_empty() {
                            self.send_to_proxy(conn_id, &tls_bytes);
                        }
                    }
                    self.send_close(conn_id);
                    return;
                }
            }
        }
    }

    // ====================================================================
    //  Connection setup (ClientHello → TLS session)
    // ====================================================================

    /// Create a TLS session from the first TCP data (ClientHello).
    ///
    /// 1. Parse ClientHello for nonce (0xFFBB) and SNI (0x0000).
    /// 2. Generate appropriate certificate.
    /// 3. Feed the data into `rustls::server::Acceptor`.
    /// 4. Build the `ServerConnection` and wrap in `RaTlsSession`.
    /// 5. Collect and send any handshake output (ServerHello etc.).
    fn create_session(
        &mut self,
        conn_id: u32,
        _peer_addr: &str,
        raw: &[u8],
    ) -> Result<RaTlsSession, String> {
        // Parse ClientHello for challenge nonce and SNI
        let hello = attestation::parse_client_hello(raw);
        if let Some(ref sni) = hello.sni {
            enclave_log_info!("SNI: {} (conn_id={})", sni, conn_id);
        }

        // Build per-connection TLS config (includes client challenge nonce)
        let tls_result = self.tls_config_for(
            &hello.challenge_nonce, &hello.sni,
        )?;

        // Feed the raw ClientHello into a rustls Acceptor
        let mut acceptor = Acceptor::default();
        {
            let mut cursor = std::io::Cursor::new(raw);
            if acceptor.read_tls(&mut cursor).is_err() {
                return Err(format!(
                    "Acceptor read_tls failed for conn_id={}", conn_id
                ));
            }
        }

        // Try to accept
        let accepted = match acceptor.accept() {
            Ok(Some(a)) => a,
            Ok(None) => {
                return Err(format!(
                    "Incomplete ClientHello for conn_id={}", conn_id
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Acceptor error for conn_id={}: {:?}", conn_id, e
                ));
            }
        };

        // Create the ServerConnection
        let server_conn = match accepted.into_connection(tls_result.config) {
            Ok(conn) => conn,
            Err(e) => {
                return Err(format!(
                    "into_connection failed for conn_id={}: {:?}",
                    conn_id, e
                ));
            }
        };

        // Wrap in our session type, storing the client challenge nonce
        let mut session = RaTlsSession::new(
            server_conn,
            tls_result.client_challenge_nonce,
        );

        // Collect any initial handshake output (ServerHello, etc.)
        let output = session.collect_tls_output()
            .map_err(|e| format!("collect_tls_output: {}", e))?;
        if !output.is_empty() {
            self.send_to_proxy(conn_id, &output);
        }

        Ok(session)
    }

    // ====================================================================
    //  TLS config resolution (same logic as before)
    // ====================================================================

    /// Obtain a `ServerConfig` for this connection.
    ///
    /// - If `nonce` is present → challenge mode (fresh cert, per-app if
    ///   SNI matches).  Also returns a client challenge nonce.
    /// - Otherwise → deterministic mode (cached by hostname, per-app if
    ///   SNI matches).  No client challenge nonce.
    fn tls_config_for(
        &mut self,
        nonce: &Option<Vec<u8>>,
        sni: &Option<String>,
    ) -> Result<TlsConfigResult, String> {
        // Resolve per-app identity from the global CertStore
        let app_data = sni.as_deref()
            .and_then(|h| cert_store::cert_store().resolve(h));

        if let Some(n) = nonce {
            let mode = CertMode::Challenge { nonce: n.clone() };
            return build_tls_config(&self.ca, mode, app_data.as_ref());
        }

        // Deterministic: check per-hostname cache
        let cache_key = sni.clone().unwrap_or_default();
        let now = ocall::get_current_time().unwrap_or(0);
        let current_gen = cert_store::cert_store().generation();

        if let Some(cached) = self.cached_configs.get(&cache_key) {
            if now < cached.expires_at && cached.store_generation == current_gen {
                return Ok(TlsConfigResult {
                    config: cached.config.clone(),
                    client_challenge_nonce: None,
                });
            }
        }

        let mode = CertMode::Deterministic { creation_time: now };
        let tls_result = build_tls_config(&self.ca, mode, app_data.as_ref())?;

        self.cached_configs.insert(cache_key, CachedConfig {
            config: tls_result.config.clone(),
            expires_at: now + attestation::DETERMINISTIC_VALIDITY_SECS,
            store_generation: current_gen,
        });
        Ok(TlsConfigResult {
            config: tls_result.config,
            client_challenge_nonce: None, // deterministic mode: no nonce
        })
    }

    // ====================================================================
    //  Data channel output helpers
    // ====================================================================

    /// Send TLS bytes to the TCP proxy via the data channel.
    ///
    /// Large payloads are split into chunks to stay under
    /// `MAX_CHANNEL_PAYLOAD` (1 MiB) — the host-side decoder rejects
    /// anything larger.
    fn send_to_proxy(&self, conn_id: u32, tls_bytes: &[u8]) {
        // Leave room for the 5-byte channel message header.
        const CHUNK: usize = channel::MAX_CHANNEL_PAYLOAD;
        for chunk in tls_bytes.chunks(CHUNK) {
            let msg = channel::encode_tcp_data(conn_id, chunk);
            self.data_tx.send(&msg);
        }
    }

    /// Send a TcpClose to the TCP proxy.
    fn send_close(&self, conn_id: u32) {
        let msg = channel::encode_tcp_close(conn_id);
        self.data_tx.send(&msg);
    }
}

impl Drop for IngressServer {
    fn drop(&mut self) {
        // Close all active sessions
        let conn_ids: Vec<u32> = self.sessions.keys().copied().collect();
        for conn_id in conn_ids {
            if let Some(state) = self.sessions.remove(&conn_id) {
                if let SessionState::Established(mut session)
                    | SessionState::Handshaking(mut session) = state
                {
                    let close_bytes = session.close_notify();
                    if !close_bytes.is_empty() {
                        self.send_to_proxy(conn_id, &close_bytes);
                    }
                }
                self.send_close(conn_id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  TLS configuration helpers
// ---------------------------------------------------------------------------

// ── Permissive client-certificate verifier ────────────────────────────────
//
// The server optionally accepts client certificates but does NOT require
// them (browsers never present one). When a client *does* present a cert
// (mutual RA-TLS for vault GetSecret), we store it verbatim and let the
// vault module extract and verify the SGX/TDX quote at the application
// layer — there is no X.509 chain validation here.

/// A [`ClientCertVerifier`] that *optionally* accepts any client cert.
///
/// * `client_auth_mandatory()` returns `false` → browsers may skip.
/// * `verify_client_cert()` always succeeds → the vault module does
///   the real attestation verification from the cert's extensions.
#[derive(Debug)]
struct PermissiveClientAuth;

impl ClientCertVerifier for PermissiveClientAuth {
    fn offer_client_auth(&self) -> bool {
        true // ask for a client cert in the CertificateRequest
    }

    fn client_auth_mandatory(&self) -> bool {
        false // don't close the connection if client declines
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[] // no CA hints — accept any issuer
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // Accept unconditionally — quote verification happens in the vault module.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// Result of building a TLS config for a single connection.
struct TlsConfigResult {
    config: Arc<ServerConfig>,
    /// Client challenge nonce (present only in challenge-response mode).
    client_challenge_nonce: Option<Vec<u8>>,
}

/// Build a `ServerConfig` from an RA-TLS certificate.
fn build_tls_config(
    ca: &CaContext,
    mode: CertMode,
    app: Option<&cert_store::AppCertData>,
) -> Result<TlsConfigResult, String> {
    let result = match app {
        Some(a) => attestation::generate_app_certificate(ca, mode, a)?,
        None => attestation::generate_ratls_certificate(ca, mode)?,
    };

    let certs: Vec<CertificateDer<'static>> = result.cert_chain_der
        .into_iter()
        .map(|der| CertificateDer::from(der).into_owned())
        .collect();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(result.pkcs8_key));

    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS config error: {:?}", e))?
        .with_client_cert_verifier(Arc::new(PermissiveClientAuth))
        .with_single_cert(certs, key)
        .map_err(|e| format!("cert chain error: {:?}", e))?;

    // Inject the client's challenge nonce into the CertificateRequest
    // extension 0xFFBB so the client can verify it against its own nonce
    // (bidirectional challenge-response RA-TLS).
    if let Some(ref nonce) = result.client_challenge_nonce {
        config.ratls_challenge = Some(nonce.clone());
    }

    Ok(TlsConfigResult {
        config: Arc::new(config),
        client_challenge_nonce: result.client_challenge_nonce,
    })
}

// ---------------------------------------------------------------------------
//  HTTP request handling
// ---------------------------------------------------------------------------

/// Result of handling an HTTP request.
struct HttpHandleResult {
    status: u16,
    body: Vec<u8>,
    shutdown: bool,
}

impl HttpHandleResult {
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body, shutdown: false }
    }
    fn err(status: u16, msg: &str) -> Self {
        Self {
            status,
            body: format!("{{\"error\":\"{}\"}}", msg).into_bytes(),
            shutdown: false,
        }
    }
    fn shutdown() -> Self {
        Self { status: 200, body: b"{}".to_vec(), shutdown: true }
    }
}

/// Handle a complete HTTP/1.1 request.
///
/// Routes are:
///   GET  /healthz             — liveness probe (no auth)
///   GET  /readyz              — readiness probe (monitoring+)
///   GET  /status              — module statuses (monitoring+)
///   GET  /metrics             — enclave metrics (monitoring+)
///   PUT  /attestation-servers — update attestation servers (manager)
///   POST /data                — module dispatch (module-dependent)
///   POST /shutdown            — graceful shutdown (manager)
///
/// Auth is via `Authorization: Bearer <token>` header.
fn handle_http_request(
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::HttpMethod;

    match (&http_req.method, http_req.path.as_str()) {
        // ── Healthz (no auth) ───────────────────────────────────────
        (HttpMethod::Get, "/healthz") => {
            HttpHandleResult::ok(b"{\"status\":\"ok\"}".to_vec())
        }

        // ── Readyz (monitoring+) ────────────────────────────────────
        (HttpMethod::Get, "/readyz") => {
            if let Some(ctx) = require_monitoring(http_req, base_ctx) {
                let _ = ctx; // auth passed
            } else {
                return monitoring_required_error(http_req);
            }
            let module_count = modules::module_count();
            let status = if module_count > 0 { "ready" } else { "not_ready" };
            let body = format!(
                "{{\"status\":\"{}\",\"modules\":{}}}",
                status, module_count
            );
            HttpHandleResult::ok(body.into_bytes())
        }

        // ── Status (monitoring+) ────────────────────────────────────
        (HttpMethod::Get, "/status") => {
            if let Some(ctx) = require_monitoring(http_req, base_ctx) {
                let _ = ctx;
            } else {
                return monitoring_required_error(http_req);
            }
            let statuses = modules::collect_module_statuses();
            let body = serde_json::to_vec(&statuses).unwrap_or_default();
            HttpHandleResult::ok(body)
        }

        // ── Metrics (monitoring+) ───────────────────────────────────
        (HttpMethod::Get, "/metrics") => {
            if let Some(ctx) = require_monitoring(http_req, base_ctx) {
                let _ = ctx;
            } else {
                return monitoring_required_error(http_req);
            }
            let mut metrics = enclave_os_common::protocol::EnclaveMetrics::default();
            modules::enrich_metrics(&mut metrics);
            let body = serde_json::to_vec(&metrics).unwrap_or_default();
            HttpHandleResult::ok(body)
        }

        // ── SetAttestationServers (manager) ─────────────────────────
        (HttpMethod::Put, "/attestation-servers") => {
            handle_set_attestation_servers(http_req, base_ctx)
        }

        // ── Data / module dispatch ──────────────────────────────────
        (HttpMethod::Post, "/data") => {
            handle_data_request_http(http_req, base_ctx)
        }

        // ── Shutdown (manager) ──────────────────────────────────────
        (HttpMethod::Post, "/shutdown") => {
            if let Some(ref oidc_config) = crate::oidc_config() {
                let _ = oidc_config;
                match verify_auth_header(http_req) {
                    Some(claims) if claims.has_manager() => {}
                    _ => return HttpHandleResult::err(403, "manager role required"),
                }
            }
            HttpHandleResult::shutdown()
        }

        // ── Method mismatch on known paths ──────────────────────────
        (_, "/healthz") | (_, "/readyz") | (_, "/status") | (_, "/metrics")
        | (_, "/attestation-servers") | (_, "/data") | (_, "/shutdown") => {
            HttpHandleResult::err(405, "method not allowed")
        }

        // ── Unknown path ────────────────────────────────────────────
        _ => HttpHandleResult::err(404, "not found"),
    }
}

/// Verify the `Authorization: Bearer` header and return OIDC claims.
fn verify_auth_header(
    http_req: &enclave_os_common::protocol::HttpRequest,
) -> Option<enclave_os_common::oidc::OidcClaims> {
    let token = http_req.authorization.as_deref()?;
    verify_oidc_token(token).ok()
}

/// Check monitoring role requirement.  Returns `Some(claims)` if auth
/// passes (or OIDC is not configured), `None` if auth fails.
fn require_monitoring(
    http_req: &enclave_os_common::protocol::HttpRequest,
    _base_ctx: &enclave_os_common::modules::RequestContext,
) -> Option<Option<enclave_os_common::oidc::OidcClaims>> {
    if crate::oidc_config().is_none() {
        return Some(None); // OIDC not configured, no auth needed
    }
    match verify_auth_header(http_req) {
        Some(claims) if claims.has_monitoring() => Some(Some(claims)),
        _ => None,
    }
}

fn monitoring_required_error(
    http_req: &enclave_os_common::protocol::HttpRequest,
) -> HttpHandleResult {
    if http_req.authorization.is_none() {
        HttpHandleResult::err(401, "authorization required")
    } else {
        HttpHandleResult::err(403, "monitoring role required")
    }
}

// ---------------------------------------------------------------------------
//  SetAttestationServers handler (HTTP)
// ---------------------------------------------------------------------------

/// Handle `PUT /attestation-servers`.
///
/// Request body: `{"servers": [{"url": "...", "token": "...", ...}, ...]}`.
fn handle_set_attestation_servers(
    http_req: &enclave_os_common::protocol::HttpRequest,
    _base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    // Require Manager role when OIDC is configured.
    let raw_auth_token = http_req.authorization.clone();
    if let Some(ref oidc_config) = crate::oidc_config() {
        let _ = oidc_config;
        match verify_auth_header(http_req) {
            Some(claims) if claims.has_manager() => {}
            _ => return HttpHandleResult::err(403, "manager role required"),
        }
    }

    // Parse request body
    #[derive(serde::Deserialize)]
    struct SetAttestationServersRequest {
        servers: Vec<enclave_os_common::protocol::AttestationServer>,
    }

    let parsed: SetAttestationServersRequest = match serde_json::from_slice(&http_req.body) {
        Ok(p) => p,
        Err(e) => {
            return HttpHandleResult::err(
                400,
                &format!("invalid request body: {e}"),
            );
        }
    };

    let servers = parsed.servers;

    // Collect servers that need OIDC bootstrap before we move `servers`.
    let bootstrap_configs: Vec<(String, enclave_os_common::protocol::OidcBootstrap)> =
        servers
            .iter()
            .filter_map(|s| {
                s.oidc_bootstrap
                    .as_ref()
                    .map(|b| (s.url.clone(), b.clone()))
            })
            .collect();

    let (count, hash) = enclave_os_common::attestation_servers::set(servers);

    // OIDC bootstrap: for each server with oidc_bootstrap config,
    // generate a keypair, register with Zitadel, and obtain a token.
    #[cfg(feature = "egress")]
    if !bootstrap_configs.is_empty() {
        let manager_jwt = match raw_auth_token.as_deref() {
            Some(jwt) => jwt,
            None => {
                return HttpHandleResult::err(
                    400,
                    "OIDC bootstrap requires an auth token (manager JWT)",
                );
            }
        };

        for (url, config) in &bootstrap_configs {
            match enclave_os_egress::oidc_bootstrap::bootstrap(config, manager_jwt) {
                Ok(result) => {
                    enclave_os_common::attestation_servers::set_oidc_state(
                        url,
                        config.clone(),
                        result.key_id,
                        result.private_key_der,
                        result.access_token,
                        result.expires_in,
                    );
                    enclave_log_info!(
                        "OIDC bootstrap succeeded for {} (key registered, token expires in {}s)",
                        url,
                        result.expires_in,
                    );
                }
                Err(e) => {
                    enclave_log_error!(
                        "OIDC bootstrap failed for {}: {}",
                        url, e
                    );
                    return HttpHandleResult::err(
                        500,
                        &format!("OIDC bootstrap failed for {url}: {e}"),
                    );
                }
            }
        }
    }

    let hash_hex = hash
        .map(|h| enclave_os_common::hex::hex_encode(&h))
        .unwrap_or_default();
    let body = format!(
        "{{\"server_count\":{},\"hash\":\"{}\"}}",
        count, hash_hex
    );
    HttpHandleResult::ok(body.into_bytes())
}

// ---------------------------------------------------------------------------
//  Data request handling (HTTP)
// ---------------------------------------------------------------------------

/// Handle `POST /data` — module dispatch.
///
/// Auth comes from the `Authorization: Bearer` header (not from the body).
/// The HTTP body is passed directly to the module as `Request::Data(body)`.
fn handle_data_request_http(
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::{Request, Response};

    // Extract auth from the Authorization header.
    let oidc_claims = if crate::oidc_config().is_some() {
        match verify_auth_header(http_req) {
            Some(claims) => Some(claims),
            None if http_req.authorization.is_some() => {
                return HttpHandleResult::err(401, "invalid or expired token");
            }
            None => None,
        }
    } else {
        None
    };

    let ctx = enclave_os_common::modules::RequestContext {
        peer_cert_der: base_ctx.peer_cert_der.clone(),
        client_challenge_nonce: base_ctx.client_challenge_nonce.clone(),
        oidc_claims,
    };

    let req = Request::Data(http_req.body.clone());

    if let Some(resp) = modules::dispatch(&req, &ctx) {
        match resp {
            Response::Data(data) => HttpHandleResult::ok(data),
            Response::Error(msg) => HttpHandleResult {
                status: 400,
                body: msg,
                shutdown: false,
            },
            Response::Ok => HttpHandleResult::ok(b"{}".to_vec()),
            other => {
                // Serialize any other response variant as JSON
                HttpHandleResult::ok(
                    serde_json::to_vec(&other).unwrap_or_default(),
                )
            }
        }
    } else if let Request::Data(inner) = req {
        // Fallback: echo Data back if no module handled it
        enclave_log_info!(
            "No module handled POST /data ({} bytes body), echoing back",
            inner.len()
        );
        HttpHandleResult::ok(inner)
    } else {
        HttpHandleResult::err(500, "unhandled request")
    }
}

/// Verify an OIDC bearer token against the global OIDC configuration.
///
/// Validates `iss`, `aud`, and `exp` claims, then extracts roles.
///
/// Signature verification is intentionally deferred: tokens arrive over
/// RA-TLS (already mutually authenticated), and JWKS fetching would
/// require egress HTTPS to the provider on every request (or a cache
/// with TTL-based refresh).  Adding JWKS verification is a future
/// defence-in-depth enhancement.
fn verify_oidc_token(token: &str) -> Result<enclave_os_common::oidc::OidcClaims, String> {
    let config = crate::oidc_config()
        .ok_or_else(|| "OIDC not configured".to_string())?;

    // Decode JWT claims (header.payload.signature)
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("malformed JWT: expected 3 dot-separated parts".into());
    }

    // Decode payload (base64url → JSON)
    let payload_bytes = base64_url_decode(parts[1])
        .map_err(|e| format!("JWT payload base64: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT payload JSON: {e}"))?;

    // Validate issuer
    let iss = claims.get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JWT missing 'iss' claim".to_string())?;
    if iss != config.issuer {
        return Err(format!("JWT issuer '{}' != expected '{}'", iss, config.issuer));
    }

    // Validate audience
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == &config.audience,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(&config.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("JWT audience does not contain '{}'", config.audience));
    }

    // Validate expiry
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
        let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
        if now > exp {
            return Err("JWT token expired".into());
        }
    }

    // Extract subject
    let sub = claims.get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Extract roles
    let roles = enclave_os_common::oidc::extract_roles(&claims, config);

    Ok(enclave_os_common::oidc::OidcClaims { sub, roles })
}

/// Decode base64url (no padding) to bytes.
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    // Replace URL-safe chars with standard base64 chars
    let standard: String = input.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();

    // Add padding if needed
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    // Use a simple base64 decoder — no external dep needed since
    // we already link ring which provides what we need, but for
    // simplicity we manually decode:
    base64_decode_standard(&padded)
}

/// Standard base64 decode (with padding).
fn base64_decode_standard(input: &str) -> Result<Vec<u8>, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 char: {}", c as char)),
        }
    }
    let _ = CHARS; // suppress unused warning

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("base64 input length not multiple of 4".into());
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c_val = val(chunk[2])?;
        let d = val(chunk[3])?;

        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c_val as u32) << 6) | (d as u32);

        out.push((triple >> 16) as u8);
        if chunk[2] != b'=' { out.push((triple >> 8) as u8); }
        if chunk[3] != b'=' { out.push(triple as u8); }
    }
    Ok(out)
}
