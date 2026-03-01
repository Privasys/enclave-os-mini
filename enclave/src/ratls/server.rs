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

use crate::ocall;
use crate::ratls::attestation::{self, CaContext, CertMode};
use crate::ratls::cert_store;
use crate::ratls::session::RaTlsSession;
use crate::{enclave_log_info, enclave_log_error};

use enclave_os_common::channel::{self, ChannelMsgType};
use enclave_os_common::queue::SpscProducer;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::ServerConfig;

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
                        // Dispatch any complete application frames
                        self.dispatch_frames(conn_id, &mut session);
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

    /// Process all complete application-level frames from a session.
    fn dispatch_frames(&mut self, conn_id: u32, session: &mut RaTlsSession) {
        loop {
            match session.recv_frame() {
                Ok(Some(payload)) => {
                    match handle_frame(&payload) {
                        HandleResult::Response(resp) => {
                            match session.send_frame(&resp) {
                                Ok(tls_bytes) => {
                                    if !tls_bytes.is_empty() {
                                        self.send_to_proxy(conn_id, &tls_bytes);
                                    }
                                }
                                Err(e) => {
                                    enclave_log_error!(
                                        "send_frame failed conn_id={}: {}",
                                        conn_id, e
                                    );
                                    self.send_close(conn_id);
                                    return;
                                }
                            }
                        }
                        HandleResult::Shutdown => {
                            enclave_log_info!(
                                "Shutdown requested by conn_id={}", conn_id
                            );
                            self.shutdown = true;
                            self.send_close(conn_id);
                            return;
                        }
                        HandleResult::Close => {
                            self.send_close(conn_id);
                            return;
                        }
                    }
                }
                Ok(None) => break, // no more complete frames
                Err(e) => {
                    enclave_log_error!(
                        "recv_frame error conn_id={}: {}", conn_id, e
                    );
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

        // Build per-connection TLS config
        let tls_config = self.tls_config_for(
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
        let server_conn = match accepted.into_connection(tls_config) {
            Ok(conn) => conn,
            Err(e) => {
                return Err(format!(
                    "into_connection failed for conn_id={}: {:?}",
                    conn_id, e
                ));
            }
        };

        // Wrap in our session type
        let mut session = RaTlsSession::new(server_conn);

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
    ///   SNI matches).
    /// - Otherwise → deterministic mode (cached by hostname, per-app if
    ///   SNI matches).
    fn tls_config_for(
        &mut self,
        nonce: &Option<Vec<u8>>,
        sni: &Option<String>,
    ) -> Result<Arc<ServerConfig>, String> {
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

        if let Some(cached) = self.cached_configs.get(&cache_key) {
            if now < cached.expires_at {
                return Ok(cached.config.clone());
            }
        }

        let mode = CertMode::Deterministic { creation_time: now };
        let config = build_tls_config(&self.ca, mode, app_data.as_ref())?;

        self.cached_configs.insert(cache_key, CachedConfig {
            config: config.clone(),
            expires_at: now + attestation::DETERMINISTIC_VALIDITY_SECS,
        });
        Ok(config)
    }

    // ====================================================================
    //  Data channel output helpers
    // ====================================================================

    /// Send TLS bytes to the TCP proxy via the data channel.
    fn send_to_proxy(&self, conn_id: u32, tls_bytes: &[u8]) {
        let msg = channel::encode_tcp_data(conn_id, tls_bytes);
        self.data_tx.send(&msg);
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

/// Build a `ServerConfig` from an RA-TLS certificate.
fn build_tls_config(
    ca: &CaContext,
    mode: CertMode,
    app: Option<&cert_store::AppCertData>,
) -> Result<Arc<ServerConfig>, String> {
    let (cert_chain_der, pkcs8_key) = match app {
        Some(a) => attestation::generate_app_certificate(ca, mode, a)?,
        None => attestation::generate_ratls_certificate(ca, mode)?,
    };

    let certs: Vec<CertificateDer<'static>> = cert_chain_der
        .into_iter()
        .map(|der| CertificateDer::from(der).into_owned())
        .collect();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_key));

    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS config error: {:?}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("cert chain error: {:?}", e))?;

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
//  Request handling (unchanged)
// ---------------------------------------------------------------------------

enum HandleResult {
    Response(Vec<u8>),
    Shutdown,
    #[allow(dead_code)]
    Close,
}

/// Handle a complete, already-decoded frame payload from a client.
fn handle_frame(payload: &[u8]) -> HandleResult {
    use enclave_os_common::protocol::{Request, Response};
    use crate::modules;
    match serde_json::from_slice::<Request>(payload) {
        Ok(Request::Ping) => {
            let resp = serde_json::to_vec(&Response::Pong).unwrap_or_default();
            HandleResult::Response(resp)
        }
        Ok(Request::Shutdown) => HandleResult::Shutdown,
        Ok(req) => {
            // Try all registered modules first
            if let Some(resp) = modules::dispatch(&req) {
                HandleResult::Response(serde_json::to_vec(&resp).unwrap_or_default())
            } else if let Request::Data(payload) = req {
                // Fallback: echo Data back if no module handled it
                let resp = serde_json::to_vec(&Response::Data(payload)).unwrap_or_default();
                HandleResult::Response(resp)
            } else {
                let err = Response::Error(b"unhandled request".to_vec());
                HandleResult::Response(serde_json::to_vec(&err).unwrap_or_default())
            }
        }
        Err(_) => {
            let err = Response::Error(b"invalid JSON request".to_vec());
            HandleResult::Response(serde_json::to_vec(&err).unwrap_or_default())
        }
    }
}
