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
use rustls::server::RaTlsBindCertificate;
use rustls::sign::CertifiedKey;

// ========================================================================
//  Session states
// ========================================================================

/// Per-connection state. A connection progresses through:
///   `Pending` → `Handshaking` → `Established`
enum SessionState {
    /// TCP connection accepted; ClientHello not yet complete.
    Pending {
        peer_addr: String,
        /// Raw TLS bytes received so far. A ClientHello can arrive split
        /// across several TcpData chunks (more likely now that the RA-TLS
        /// challenge extension enlarges it); accumulate until the record
        /// is complete before handing it to the rustls Acceptor.
        buffered: Vec<u8>,
    },
    /// TLS handshake is in progress.
    Handshaking(RaTlsSession),
    /// TLS handshake complete, processing application data.
    Established(RaTlsSession),
}

/// Upper bound on buffered ClientHello bytes while waiting for a
/// fragmented hello to complete. A TLS record maxes at 16 KiB; a real
/// ClientHello (even with the RA-TLS challenge extension) is ~1-2 KiB.
const MAX_PENDING_CLIENTHELLO: usize = 16 * 1024;

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
                    buffered: Vec::new(),
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

            ChannelMsgType::DataReady => {
                // DataReady is an enclave→host signal; ignore if received inbound.
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
            SessionState::Pending { peer_addr, mut buffered } => {
                // Accumulate TLS bytes until the ClientHello record is
                // complete — it can arrive split across several TcpData
                // chunks. Re-feeding the whole buffer to a fresh Acceptor
                // each round is idempotent.
                buffered.extend_from_slice(data);
                match self.create_session(conn_id, &peer_addr, &buffered) {
                    Ok(Some(session)) => {
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
                    Ok(None) => {
                        // Incomplete ClientHello — keep the bytes and wait
                        // for the next TcpData. Cap the buffer so a
                        // malformed/never-completing hello can't grow
                        // unbounded.
                        if buffered.len() > MAX_PENDING_CLIENTHELLO {
                            enclave_log_error!(
                                "ClientHello exceeded {} bytes for conn_id={}, dropping",
                                MAX_PENDING_CLIENTHELLO, conn_id
                            );
                            self.send_close(conn_id);
                        } else {
                            self.sessions.insert(
                                conn_id,
                                SessionState::Pending { peer_addr, buffered },
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
                    let result = handle_http_request_with_session(&http_req, &base_ctx);

                    // Send HTTP response
                    let send_close = close || result.shutdown;
                    let ct = result.content_type.as_deref()
                        .unwrap_or("application/json");
                    match session.send_http_response_with_headers(
                        result.status,
                        ct,
                        &result.extra_headers,
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
    /// Try to create a TLS session from the accumulated ClientHello bytes.
    ///
    /// Returns `Ok(None)` when `raw` does not yet hold a complete
    /// ClientHello — the caller buffers more TcpData and retries.
    fn create_session(
        &mut self,
        conn_id: u32,
        _peer_addr: &str,
        raw: &[u8],
    ) -> Result<Option<RaTlsSession>, String> {
        // Feed the bytes into a rustls Acceptor and confirm the
        // ClientHello is complete BEFORE parsing it: a partial hello would
        // yield a truncated challenge nonce / SNI.
        let mut acceptor = Acceptor::default();
        {
            let mut cursor = std::io::Cursor::new(raw);
            if acceptor.read_tls(&mut cursor).is_err() {
                return Err(format!(
                    "Acceptor read_tls failed for conn_id={}", conn_id
                ));
            }
        }

        let accepted = match acceptor.accept() {
            Ok(Some(a)) => a,
            Ok(None) => return Ok(None), // Incomplete — caller waits for more.
            Err(e) => {
                return Err(format!(
                    "Acceptor error for conn_id={}: {:?}", conn_id, e
                ));
            }
        };

        // Complete ClientHello: parse it for the challenge nonce and SNI.
        let hello = attestation::parse_client_hello(raw);
        if let Some(ref sni) = hello.sni {
            enclave_log_info!("SNI: {} (conn_id={})", sni, conn_id);
        }

        // Build per-connection TLS config (includes client challenge nonce)
        let tls_result = self.tls_config_for(
            &hello.challenge_nonce, &hello.sni,
        )?;

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

        Ok(Some(session))
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
            // binder=None here: pre-handshake mint has no key schedule yet.
            // The channel binder is injected by the deferred mint hook (later
            // slice), which re-mints with the handshake secret available.
            let mode = CertMode::Challenge { nonce: n.clone(), binder: None };
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

/// Per-connection RA-TLS channel-binding minter. Captures the challenge
/// context so that at the TLS 1.3 Certificate-emit seam (once the handshake
/// secret exists) it can re-mint the leaf with the 32-byte session channel
/// binder folded into the quote's `report_data`.
struct ChannelBindingMinter {
    ca: CaContext,
    nonce: Vec<u8>,
    app: Option<cert_store::AppCertData>,
}

impl core::fmt::Debug for ChannelBindingMinter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the captured CA key / nonce.
        f.debug_struct("ChannelBindingMinter").finish_non_exhaustive()
    }
}

impl RaTlsBindCertificate for ChannelBindingMinter {
    fn bind_certificate(&self, binder: &[u8; 32]) -> Option<Arc<CertifiedKey>> {
        let mode = CertMode::Challenge {
            nonce: self.nonce.clone(),
            binder: Some(*binder),
        };
        let result = match &self.app {
            Some(a) => attestation::generate_app_certificate(&self.ca, mode, a),
            None => attestation::generate_ratls_certificate(&self.ca, mode),
        }
        .ok()?;
        let certs: Vec<CertificateDer<'static>> = result
            .cert_chain_der
            .into_iter()
            .map(|der| CertificateDer::from(der).into_owned())
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(result.pkcs8_key));
        CertifiedKey::from_der(certs, key, &default_provider())
            .ok()
            .map(Arc::new)
    }
}

/// Build a `ServerConfig` from an RA-TLS certificate.
fn build_tls_config(
    ca: &CaContext,
    mode: CertMode,
    app: Option<&cert_store::AppCertData>,
) -> Result<TlsConfigResult, String> {
    // Capture the challenge nonce for the channel-binding hook before `mode`
    // is consumed by the initial (placeholder) mint below.
    let challenge_nonce = match &mode {
        CertMode::Challenge { nonce, .. } => Some(nonce.clone()),
        CertMode::Deterministic { .. } => None,
    };

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

    // Channel binding: install the per-connection re-mint hook for challenge
    // connections so the served leaf's quote commits to this TLS session. It
    // fires once the handshake secret is derived (the TLS 1.3 emit seam).
    if let Some(nonce) = challenge_nonce {
        config.ratls_bind_certificate = Some(Arc::new(ChannelBindingMinter {
            ca: ca.clone(),
            nonce,
            app: app.cloned(),
        }));
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
    /// Optional Content-Type override (defaults to `application/json`).
    content_type: Option<String>,
    /// Extra response headers (e.g. `X-Privasys-EncAuth-Reject`).
    extra_headers: Vec<(String, String)>,
}

impl HttpHandleResult {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            shutdown: false,
            content_type: None,
            extra_headers: Vec::new(),
        }
    }
    fn err(status: u16, msg: &str) -> Self {
        Self {
            status,
            body: format!("{{\"error\":\"{}\"}}", msg).into_bytes(),
            shutdown: false,
            content_type: None,
            extra_headers: Vec::new(),
        }
    }
    fn shutdown() -> Self {
        Self {
            status: 200,
            body: b"{}".to_vec(),
            shutdown: true,
            content_type: None,
            extra_headers: Vec::new(),
        }
    }
    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.extra_headers.push((name.to_string(), value.to_string()));
        self
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

        // ── Connect-protocol RPC ────────────────────────────────────
        // POST /rpc/<app>/<function> — named-param call dispatched via WasmEnvelope.
        // GET  /rpc/<app>/schema    — fetch the app's WIT type schema.
        (method, path) if path.starts_with("/rpc/") => {
            handle_rpc_request(method, path, http_req, base_ctx)
        }

        // ── MCP-server HTTP shim ────────────────────────────────────
        // GET  /api/v1/mcp/tools           — list MCP tool manifest (single loaded app).
        // POST /api/v1/mcp/tools/<fn>      — invoke an MCP tool by name.
        //
        // Mirrors the public MCP-over-HTTP transport expected by
        // confidential-ai's `privasys_http` tool catalog. App is implicit:
        // the single loaded WASM app on this enclave.
        (method, path)
            if path == "/api/v1/mcp/tools"
                || path.starts_with("/api/v1/mcp/tools/") =>
        {
            handle_mcp_tools_request(method, path, http_req, base_ctx)
        }

        // ── FIDO2 endpoints ─────────────────────────────────────────
        // These routes wrap the body into the FIDO2 module's protocol
        // format and dispatch through the standard module pipeline.
        #[cfg(feature = "fido2")]
        (HttpMethod::Post, path) if path.starts_with("/fido2/") => {
            handle_fido2_request(path, http_req, base_ctx)
        }

        // ── Session-relay bootstrap (no auth required) ──────────────
        (HttpMethod::Post, "/__privasys/session-bootstrap") => {
            handle_session_bootstrap(http_req)
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

/// Wrap [`handle_http_request`] with the browser→enclave session relay.
///
/// If the incoming request carries `Content-Type: application/privasys-sealed+cbor`
/// and `Authorization: PrivasysSession <id>`, decrypt the body, dispatch the
/// inner request, then seal the response. Otherwise dispatch the request as-is.
fn handle_http_request_with_session(
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    let is_sealed = http_req
        .content_type
        .as_deref()
        .map(|ct| ct.starts_with(crate::sessionrelay::SEALED_CONTENT_TYPE))
        .unwrap_or(false);

    if !is_sealed {
        // No plaintext app traffic through intermediaries: when the
        // platform gateway terminated the public TLS leg it marks the
        // request with `X-Privasys-Edge: terminate` (stripping any
        // client-supplied value first). Refuse plaintext requests on
        // that leg except for the bootstrap endpoint (JSON by design)
        // and operational/metadata endpoints. RA-TLS (splice) clients
        // terminate TLS here and never carry the marker.
        if http_req.edge_terminated && path_requires_sealed(&http_req.path) {
            return HttpHandleResult::err(403, "sealed-transport-required");
        }
        return handle_http_request(http_req, base_ctx);
    }

    let session_id = match http_req.privasys_session.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return HttpHandleResult::err(401, "missing PrivasysSession"),
    };

    let now = wall_seconds_now();
    let method_str = http_method_str(&http_req.method);

    let plaintext = match crate::sessionrelay::open_request(
        session_id,
        method_str,
        &http_req.path,
        &http_req.body,
        now,
    ) {
        Ok(v) => v,
        Err(e) => return HttpHandleResult::err(e.http_status(), e.as_str()),
    };

    // Build inner request with decrypted body and JSON Content-Type.
    let mut inner = http_req.clone();
    inner.body = plaintext;
    inner.content_type = Some("application/json".to_string());
    // Inner dispatch must NOT see the PrivasysSession token as auth.
    inner.privasys_session = None;

    let inner_result = handle_http_request(&inner, base_ctx);

    // Seal response body using the SAME (method, path) AD as the request.
    let sealed = match crate::sessionrelay::seal_response(
        session_id,
        method_str,
        &http_req.path,
        &inner_result.body,
        now,
    ) {
        Ok(v) => v,
        Err(e) => return HttpHandleResult::err(e.http_status(), e.as_str()),
    };

    HttpHandleResult {
        status: inner_result.status,
        body: sealed,
        shutdown: inner_result.shutdown,
        content_type: Some(crate::sessionrelay::SEALED_CONTENT_TYPE.to_string()),
        extra_headers: Vec::new(),
    }
}

/// Paths that must be sealed when reached via a gateway-terminated leg.
/// Exempt: the session bootstrap (carries only signed voucher material
/// and public keys), operational probes, and well-known metadata.
fn path_requires_sealed(path: &str) -> bool {
    !matches!(
        path,
        "/__privasys/session-bootstrap"
            | "/healthz"
            | "/readyz"
            | "/status"
            | "/metrics"
            | "/attestation-servers"
    ) && !path.starts_with("/.well-known/")
}

fn http_method_str(m: &enclave_os_common::protocol::HttpMethod) -> &'static str {
    use enclave_os_common::protocol::HttpMethod;
    match m {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
    }
}

fn wall_seconds_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `POST /__privasys/session-bootstrap` — returns
/// `{"session_id":"...","enc_pub":"<base64url>","expires_at":<u64>,
///   "sub":"..."}` (`sub` only when an EncAuth voucher was accepted).
///
/// Request body: `{"sdk_pub":"<base64url SEC1 uncompressed P-256>",
/// "encauth": { ... }}` (`encauth` optional — silent rebind, crypto-
/// contract §8).
fn handle_session_bootstrap(
    http_req: &enclave_os_common::protocol::HttpRequest,
) -> HttpHandleResult {
    #[derive(serde::Deserialize)]
    struct Req {
        sdk_pub: String,
        #[serde(default)]
        encauth: Option<crate::encauth::EncAuthEnvelope>,
    }
    let req: Req = match serde_json::from_slice(&http_req.body) {
        Ok(v) => v,
        Err(_) => return HttpHandleResult::err(400, "invalid bootstrap body"),
    };
    let sdk_pub = match crate::sessionrelay::b64_decode(&req.sdk_pub) {
        Some(v) => v,
        None => return HttpHandleResult::err(400, "invalid sdk_pub base64"),
    };
    let now = wall_seconds_now();

    // Optional silent rebind. On verify failure we fall through to the
    // legacy anonymous bootstrap with a diagnostic header (mirroring
    // the Go middleware) so the SDK knows to trigger a wallet ceremony.
    let mut sub: Option<String> = None;
    let mut reject: Option<String> = None;
    if let Some(env) = req.encauth.as_ref() {
        // Rate-limit voucher-backed attempts per sid BEFORE the
        // signature checks (failed attempts are the abuse vector; a
        // forged sid only throttles the forger's own bucket).
        if let Some(sid) = crate::encauth::encauth_sid(env) {
            if !crate::encauth::allow_rebind(&sid, now) {
                return HttpHandleResult::err(429, "encauth rate-limited")
                    .with_header(crate::encauth::ENCAUTH_REJECT_HEADER, "rate-limited");
            }
        }
        match verify_encauth_request(env, now) {
            Ok(payload) => sub = Some(payload.sub),
            Err(e) => reject = Some(e.to_string()),
        }
    }

    let bs = match crate::sessionrelay::bootstrap(&sdk_pub, now) {
        Ok(b) => b,
        Err(e) => return HttpHandleResult::err(e.http_status(), e.as_str()),
    };
    let body = match &sub {
        Some(s) => format!(
            "{{\"session_id\":\"{}\",\"enc_pub\":\"{}\",\"expires_at\":{},\"sub\":{}}}",
            bs.session_id,
            crate::sessionrelay::b64url_encode(&bs.enc_pub),
            bs.expires_at,
            serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        ),
        None => format!(
            "{{\"session_id\":\"{}\",\"enc_pub\":\"{}\",\"expires_at\":{}}}",
            bs.session_id,
            crate::sessionrelay::b64url_encode(&bs.enc_pub),
            bs.expires_at,
        ),
    };
    let mut result = HttpHandleResult::ok(body.into_bytes());
    if let Some(reason) = reject {
        result = result.with_header(crate::encauth::ENCAUTH_REJECT_HEADER, &reason);
    }
    result
}

/// Verify an EncAuth voucher against the IdP's JWKS and this enclave's
/// identity key.
///
/// The trusted IdP keys come over egress HTTPS (WebPKI roots) from the
/// issuer pinned in the measured OIDC config — the same trust path JWT
/// verification uses. Without the `wasm`/egress feature there is no
/// trusted key source and the voucher is rejected: unlike the JWT
/// fallback (which only gates role checks), accepting an unverified
/// voucher would mint an authenticated session.
fn verify_encauth_request(
    env: &crate::encauth::EncAuthEnvelope,
    now: u64,
) -> Result<crate::encauth::EncAuthPayload, &'static str> {
    #[cfg(feature = "wasm")]
    {
        let config = crate::oidc_config().ok_or("oidc not configured")?;
        let keys = enclave_os_wasm::jwks_fetcher::idp_ec_p256_keys(
            &config.issuer,
            &config.jwks_uri,
        )
        .map_err(|_| "idp jwks unavailable")?;
        let enc_pub = crate::sessionrelay::identity_pub_sec1()
            .map_err(|_| "identity key unavailable")?;
        crate::encauth::verify_encauth(env, &keys, &enc_pub, None, now)
    }
    #[cfg(not(feature = "wasm"))]
    {
        let _ = (env, now);
        Err("no trusted idp key source (egress disabled)")
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

    let (count, hash) = enclave_os_common::attestation_servers::set(servers);

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
//  FIDO2 request handling
// ---------------------------------------------------------------------------

/// Handle `POST /fido2/*` — FIDO2/WebAuthn ceremony endpoints.
///
/// No OIDC auth required — the FIDO2 ceremony IS the authentication.
/// The body is forwarded as `Request::Data` to the module pipeline.
///
/// Supported paths:
///   POST /fido2/register/begin
///   POST /fido2/register/complete
///   POST /fido2/authenticate/begin
///   POST /fido2/authenticate/complete
#[cfg(feature = "fido2")]
fn handle_fido2_request(
    path: &str,
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::Request;

    // Split path from query string (e.g. "/fido2/register/begin?session_id=x")
    let (base_path, query_string) = match path.find('?') {
        Some(pos) => (&path[..pos], Some(&path[pos + 1..])),
        None => (path, None),
    };

    // Validate the base path (without query parameters)
    match base_path {
        "/fido2/register/begin"
        | "/fido2/register/complete"
        | "/fido2/authenticate/begin"
        | "/fido2/authenticate/complete" => {}
        _ => return HttpHandleResult::err(404, "unknown FIDO2 endpoint"),
    }

    // FIDO2 does not use OIDC auth — the ceremony authenticates the session.
    // We still check for session tokens (for browser connections using
    // previously issued tokens).
    let oidc_claims = if let Some(ref auth) = http_req.authorization {
        // Check if it's a FIDO2 session token (hex, 64 chars)
        if auth.len() == 64 && auth.chars().all(|c| c.is_ascii_hexdigit()) {
            // This is a FIDO2 session token — validate it
            let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
            match enclave_os_fido2::sessions::validate_token(auth, now) {
                Ok(_entry) => None, // Token valid — no OIDC claims needed
                Err(_) => return HttpHandleResult::err(401, "invalid session token"),
            }
        } else if crate::oidc_config().is_some() {
            // Try as OIDC token
            verify_auth_header(http_req)
        } else {
            None
        }
    } else {
        None
    };

    let ctx = enclave_os_common::modules::RequestContext {
        peer_cert_der: base_ctx.peer_cert_der.clone(),
        client_challenge_nonce: base_ctx.client_challenge_nonce.clone(),
        oidc_claims,
    };

    // Inject the endpoint path as the serde `"type"` discriminator so
    // the FIDO2 module can dispatch without seeing HTTP details.
    // "/fido2/register/begin" → type = "register/begin"
    let route = &base_path["/fido2/".len()..]; // "register/begin" etc.

    // Helper: inject query-string parameters into a serde_json::Map.
    // Maps known snake_case query param names to the camelCase field
    // names expected by `Fido2Request` serde renames.
    let inject_query_params = |map: &mut serde_json::Map<String, serde_json::Value>| {
        if let Some(qs) = query_string {
            for pair in qs.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    // Simple percent-decode: only `%XX` sequences used by
                    // encodeURIComponent on base64url / UUID values.
                    let decoded: String = {
                        let mut out = String::with_capacity(value.len());
                        let mut chars = value.as_bytes().iter();
                        while let Some(&b) = chars.next() {
                            if b == b'%' {
                                if let (Some(&h), Some(&l)) = (chars.next(), chars.next()) {
                                    let hi = (h as char).to_digit(16).unwrap_or(0) as u8;
                                    let lo = (l as char).to_digit(16).unwrap_or(0) as u8;
                                    out.push((hi << 4 | lo) as char);
                                }
                            } else {
                                out.push(b as char);
                            }
                        }
                        out
                    };
                    // Map snake_case query params → camelCase JSON field names
                    let json_key = match key {
                        "session_id" => "sessionId",
                        _ => key,
                    };
                    // Don't overwrite values already present in the body.
                    map.entry(json_key)
                        .or_insert(serde_json::Value::String(decoded));
                }
            }
        }
    };

    let body = match serde_json::from_slice::<serde_json::Value>(&http_req.body) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("type".into(), serde_json::Value::String(route.into()));
            inject_query_params(&mut map);
            serde_json::to_vec(&map).unwrap_or_else(|_| http_req.body.clone())
        }
        _ => {
            // Empty body (e.g. authenticate/begin with no args) — create
            // a minimal JSON object with just the type discriminator.
            let mut map = serde_json::Map::new();
            map.insert("type".into(), serde_json::Value::String(route.into()));
            inject_query_params(&mut map);
            serde_json::to_vec(&map).unwrap_or_else(|_| http_req.body.clone())
        }
    };

    let req = Request::Data(body);
    dispatch_and_respond(req, &ctx)
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
                content_type: None,
                extra_headers: Vec::new(),
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

// ---------------------------------------------------------------------------
//  Connect-protocol RPC handler
// ---------------------------------------------------------------------------

/// Handle `/rpc/<app>/<function>` (POST) and `/rpc/<app>/schema` (GET).
///
/// Constructs a [`WasmEnvelope`] with a `connect_call` or `wasm_schema`
/// field and dispatches it via `modules::dispatch` — reusing the existing
/// WASM module handler pipeline (auth, fuel metering, etc.).
fn handle_rpc_request(
    method: &enclave_os_common::protocol::HttpMethod,
    path: &str,
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::{HttpMethod, Request};

    // Parse path: /rpc/<app>/<function_or_schema>
    let rest = &path[5..]; // strip "/rpc/"
    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return HttpHandleResult::err(400, "expected /rpc/<app>/<function>");
    }
    let app_name = parts[0];
    let tail = parts[1];

    // Build OIDC claims from auth header (same as /data).
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

    // GET /rpc/<app>/schema → wasm_schema envelope
    if *method == HttpMethod::Get && tail == "schema" {
        // Pass app_auth from X-App-Auth header so app-level permissions
        // can gate schema access using the app developer's OIDC provider.
        let app_auth = http_req.app_auth.as_deref();
        let envelope = serde_json::json!({
            "wasm_schema": { "app": app_name, "app_auth": app_auth }
        });
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        let req = Request::Data(body);
        return dispatch_and_respond(req, &ctx);
    }

    // POST /rpc/<app>/<function> → connect_call envelope
    if *method != HttpMethod::Post {
        return HttpHandleResult::err(405, "POST required for /rpc/<app>/<function>");
    }

    // Parse the request body as a JSON object (the named params).
    let body_value: serde_json::Value = if http_req.body.is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_slice(&http_req.body) {
            Ok(v) => v,
            Err(e) => {
                return HttpHandleResult::err(
                    400,
                    &format!("invalid JSON body: {e}"),
                );
            }
        }
    };

    // Build app_auth from the body's "app_auth" field if present.
    let app_auth = body_value.get("app_auth")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Remove "app_auth" from the body so it doesn't pollute the params.
    let params_body = if let serde_json::Value::Object(mut map) = body_value {
        map.remove("app_auth");
        serde_json::Value::Object(map)
    } else {
        body_value
    };

    let envelope = serde_json::json!({
        "connect_call": {
            "app": app_name,
            "function": tail,
            "body": params_body,
            "app_auth": app_auth,
        }
    });
    let body = serde_json::to_vec(&envelope).unwrap_or_default();
    let req = Request::Data(body);
    dispatch_and_respond(req, &ctx)
}

// ---------------------------------------------------------------------------
//  MCP-over-HTTP shim
// ---------------------------------------------------------------------------

/// Handle `GET /api/v1/mcp/tools` and `POST /api/v1/mcp/tools/<function>`.
///
/// Adapts the public MCP-over-HTTP transport (expected by external clients
/// such as confidential-ai's `privasys_http` catalog) onto the existing
/// WasmEnvelope dispatch pipeline:
///
/// - `GET /api/v1/mcp/tools`      → `mcp_tools` envelope (single-app enclave).
/// - `POST /api/v1/mcp/tools/<fn>` → `connect_call` envelope with named params.
///
/// The single loaded app is resolved inside the WASM module so callers don't
/// need to know the app name. The MCP-spec `inputSchema` field is rewritten
/// to snake-case `input_schema` to match the public MCP HTTP contract.
/// Derive the target app name from the request's Host header: the platform
/// gateway routes `<app>.apps-<env>.privasys.org` to this enclave, so the
/// first DNS label is the app. Returns "" when there is no usable Host
/// (e.g. a bare-IP or localhost probe), which makes `resolve_app` fall back
/// to the single-loaded-app behaviour — so single-app enclaves keep working
/// with no Host, while multi-app enclaves disambiguate correctly.
fn app_from_host(http_req: &enclave_os_common::protocol::HttpRequest) -> String {
    match &http_req.host {
        Some(h) => {
            let label = h.split('.').next().unwrap_or("");
            if label.is_empty() || label == "localhost" {
                String::new()
            } else {
                label.to_string()
            }
        }
        None => String::new(),
    }
}

fn handle_mcp_tools_request(
    method: &enclave_os_common::protocol::HttpMethod,
    path: &str,
    http_req: &enclave_os_common::protocol::HttpRequest,
    base_ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::{HttpMethod, Request};

    // Build OIDC claims from auth header (same pattern as /data and /rpc/).
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

    const PREFIX: &str = "/api/v1/mcp/tools";
    let rest = &path[PREFIX.len()..];

    // GET /api/v1/mcp/tools → list manifest.
    if rest.is_empty() || rest == "/" {
        if *method != HttpMethod::Get {
            return HttpHandleResult::err(405, "GET required for /api/v1/mcp/tools");
        }
        let envelope = serde_json::json!({
            "mcp_tools": {
                "app": app_from_host(http_req),
                "app_auth": http_req.app_auth,
            }
        });
        let body = serde_json::to_vec(&envelope).unwrap_or_default();
        let result = dispatch_and_respond(Request::Data(body), &ctx);
        return transform_mcp_tools_response(result);
    }

    // POST /api/v1/mcp/tools/<fn> → call.
    if !rest.starts_with('/') {
        return HttpHandleResult::err(404, "not found");
    }
    let fn_name = &rest[1..];
    if fn_name.is_empty() || fn_name.contains('/') {
        return HttpHandleResult::err(400, "expected /api/v1/mcp/tools/<function>");
    }
    if *method != HttpMethod::Post {
        return HttpHandleResult::err(
            405,
            "POST required for /api/v1/mcp/tools/<function>",
        );
    }

    let body_value: serde_json::Value = if http_req.body.is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_slice(&http_req.body) {
            Ok(v) => v,
            Err(e) => {
                return HttpHandleResult::err(
                    400,
                    &format!("invalid JSON body: {e}"),
                );
            }
        }
    };

    // Allow an inline `app_auth` field on the body just like /rpc/.
    let (params_body, app_auth) = match body_value {
        serde_json::Value::Object(mut map) => {
            let auth = map
                .remove("app_auth")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .or_else(|| http_req.app_auth.clone());
            (serde_json::Value::Object(map), auth)
        }
        other => (other, http_req.app_auth.clone()),
    };

    let envelope = serde_json::json!({
        "connect_call": {
            "app": app_from_host(http_req),
            "function": fn_name,
            "body": params_body,
            "app_auth": app_auth,
        }
    });
    let body = serde_json::to_vec(&envelope).unwrap_or_default();
    let result = dispatch_and_respond(Request::Data(body), &ctx);
    transform_mcp_call_response(result)
}

/// Reshape a `WasmManagementResult::McpTools` JSON envelope into the
/// public MCP HTTP transport contract used by confidential-ai:
///
/// ```json
/// {"tools": [{"name": "...", "description": "...", "input_schema": {...}}]}
/// ```
///
/// On error or non-OK statuses, returns a 400 with `{"error": "<msg>"}`.
fn transform_mcp_tools_response(result: HttpHandleResult) -> HttpHandleResult {
    if result.status != 200 {
        return result;
    }
    let parsed: serde_json::Value = match serde_json::from_slice(&result.body) {
        Ok(v) => v,
        Err(_) => return result,
    };
    match parsed.get("status").and_then(|s| s.as_str()) {
        Some("mcp_tools") => {
            let tools = parsed
                .get("manifest")
                .and_then(|m| m.get("tools"))
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();
            let transformed: Vec<serde_json::Value> = tools
                .into_iter()
                .map(|t| {
                    let mut obj = serde_json::Map::new();
                    if let Some(name) = t.get("name") {
                        obj.insert("name".to_string(), name.clone());
                    }
                    if let Some(desc) = t.get("description") {
                        if !desc.is_null() {
                            obj.insert("description".to_string(), desc.clone());
                        }
                    }
                    // McpTool serialises `input_schema` as `inputSchema`
                    // (MCP-spec). Rewrite to snake-case for the HTTP contract.
                    if let Some(schema) = t
                        .get("inputSchema")
                        .or_else(|| t.get("input_schema"))
                    {
                        obj.insert("input_schema".to_string(), schema.clone());
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();
            let out = serde_json::json!({ "tools": transformed });
            HttpHandleResult::ok(serde_json::to_vec(&out).unwrap_or_default())
        }
        Some("error") | Some("not_found") => {
            let msg = parsed
                .get("message")
                .and_then(|s| s.as_str())
                .or_else(|| parsed.get("name").and_then(|s| s.as_str()))
                .unwrap_or("error");
            HttpHandleResult {
                status: 400,
                body: serde_json::to_vec(&serde_json::json!({"error": msg}))
                    .unwrap_or_default(),
                shutdown: false,
                content_type: None,
                extra_headers: Vec::new(),
            }
        }
        _ => result,
    }
}

/// Reshape a `WasmResult` JSON envelope into the bare return value(s)
/// expected by the MCP HTTP transport.
///
/// - `{"status":"ok","returns":[{"type":"...","value": V}]}` → `V`.
/// - Empty returns → `{}`.
/// - Multiple returns → array of `value` fields.
/// - `{"status":"error","message": M}` → 400 with `{"error": M}`.
fn transform_mcp_call_response(result: HttpHandleResult) -> HttpHandleResult {
    if result.status != 200 {
        return result;
    }
    let parsed: serde_json::Value = match serde_json::from_slice(&result.body) {
        Ok(v) => v,
        Err(_) => return result,
    };
    match parsed.get("status").and_then(|s| s.as_str()) {
        Some("ok") => {
            let returns = parsed
                .get("returns")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            let value = match returns.len() {
                0 => serde_json::json!({}),
                1 => returns[0]
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                _ => serde_json::Value::Array(
                    returns
                        .into_iter()
                        .map(|r| {
                            r.get("value")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        })
                        .collect(),
                ),
            };
            HttpHandleResult::ok(serde_json::to_vec(&value).unwrap_or_default())
        }
        Some("error") => {
            let msg = parsed
                .get("message")
                .and_then(|s| s.as_str())
                .unwrap_or("error");
            HttpHandleResult {
                status: 400,
                body: serde_json::to_vec(&serde_json::json!({"error": msg}))
                    .unwrap_or_default(),
                shutdown: false,
                content_type: None,
                extra_headers: Vec::new(),
            }
        }
        _ => result,
    }
}

/// Dispatch a `Request::Data` to modules and convert to `HttpHandleResult`.
fn dispatch_and_respond(
    req: enclave_os_common::protocol::Request,
    ctx: &enclave_os_common::modules::RequestContext,
) -> HttpHandleResult {
    use enclave_os_common::protocol::Response;

    if let Some(resp) = modules::dispatch(&req, ctx) {
        match resp {
            Response::Data(data) => HttpHandleResult::ok(data),
            Response::Error(msg) => HttpHandleResult {
                status: 400,
                body: msg,
                shutdown: false,
                content_type: None,
                extra_headers: Vec::new(),
            },
            Response::Ok => HttpHandleResult::ok(b"{}".to_vec()),
            other => HttpHandleResult::ok(
                serde_json::to_vec(&other).unwrap_or_default(),
            ),
        }
    } else {
        HttpHandleResult::err(404, "no module handled the request")
    }
}

/// Verify an OIDC bearer token against the global OIDC configuration.
///
/// When the `wasm` feature is enabled (which brings in `enclave-os-wasm` and
/// egress), full ES256 signature verification is performed via JWKS with
/// automatic key discovery and caching.  The `alg:none` algorithm is
/// explicitly rejected.
///
/// When running without egress, falls back to payload-only decoding over the
/// RA-TLS channel (signature not verified cryptographically).
fn verify_oidc_token(token: &str) -> Result<enclave_os_common::oidc::OidcClaims, String> {
    let config = crate::oidc_config()
        .ok_or_else(|| "OIDC not configured".to_string())?;

    // ── Signature verification + payload decode ──────────────────────
    #[cfg(feature = "wasm")]
    let claims: serde_json::Value = {
        enclave_os_wasm::jwks_fetcher::verify_jwt_signature(
            token,
            &config.issuer,
            &config.jwks_uri,
        )?
    };

    #[cfg(not(feature = "wasm"))]
    let claims: serde_json::Value = {
        // Fallback: decode payload without signature check (RA-TLS channel)
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("malformed JWT: expected 3 dot-separated parts".into());
        }
        let payload_bytes = base64_url_decode(parts[1])
            .map_err(|e| format!("JWT payload base64: {e}"))?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("JWT payload JSON: {e}"))?
    };

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

    // Step-up claims (amr/acr/iat + the operation-binding exp/vault_op/nonce)
    // for conditions like the vault's OidcStepUp.
    let amr = enclave_os_common::oidc::extract_amr(&claims);
    let acr = claims
        .get("acr")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let iat = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
    let exp = claims.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
    let vault_op = claims
        .get("vault_op")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut oc = enclave_os_common::oidc::OidcClaims::from_raw(sub, roles, config)
        .with_step_up(amr, acr, iat);
    oc.exp = exp;
    oc.vault_op = vault_op;
    oc.nonce = nonce;
    Ok(oc)
}

/// Decode base64url (no padding) to bytes.
#[cfg_attr(feature = "wasm", allow(dead_code))]
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
#[cfg_attr(feature = "wasm", allow(dead_code))]
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
