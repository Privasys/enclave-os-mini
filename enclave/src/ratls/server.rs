// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS ingress server.
//!
//! Accepts incoming TCP connections (via OCALLs to the host), performs
//! TLS 1.3 handshake with per-session RA-TLS certificate generation,
//! and handles client requests.
//!
//! Certificate generation follows the challenge-response pattern:
//!
//!   1. Host listens on a TCP port (via OCALLs).
//!   2. On accept, read raw ClientHello; parse extension 0xFFBB for nonce.
//!   3. Generate a fresh ECDSA key pair.
//!   4. Compute `report_data = SHA-512(SHA-256(DER pubkey) || binding)`.
//!   5. Obtain an SGX quote over `report_data`.
//!   6. Build a leaf X.509 cert (quote in extension @ Intel OID) signed
//!      by the intermediary CA.
//!   7. Create a per-connection `ServerConfig` and resume the handshake.
//!   8. Bidirectional TLS communication.
//!
//! If the client does **not** send extension 0xFFBB, the server generates
//! a deterministic certificate (binding = creation_time) and caches it
//! for 24 h.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use crate::ocall;
use crate::ratls::attestation::{self, CaContext, CertMode};
use crate::ratls::session::RaTlsSession;
use crate::{enclave_log_info, enclave_log_error};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::ServerConfig;

/// RA-TLS TCP server running inside the enclave.
pub struct RaTlsServer {
    listener_fd: i32,
    sessions: BTreeMap<i32, RaTlsSession>,
    ca: Arc<CaContext>,
    shutdown: bool,
    /// Cached deterministic TLS config (reused when 0xFFBB is absent).
    cached_config: Option<CachedConfig>,
}

/// A cached ServerConfig for deterministic (non-challenge) connections.
struct CachedConfig {
    config: Arc<ServerConfig>,
    expires_at: u64,
}

impl RaTlsServer {
    /// Create a new RA-TLS server bound to the given port.
    pub fn new(port: u16, backlog: i32, ca: Arc<CaContext>) -> Result<Self, String> {
        let listener_fd = ocall::net_tcp_listen(port, backlog)
            .map_err(|e| format!("TCP listen failed: {}", e))?;

        Ok(Self {
            listener_fd,
            sessions: BTreeMap::new(),
            ca,
            shutdown: false,
            cached_config: None,
        })
    }

    /// Poll for events: accept new connections and handle existing sessions.
    pub fn poll(&mut self) -> Result<(), String> {
        if self.shutdown {
            return Err("Server is shut down".into());
        }

        // Try to accept a new connection
        match ocall::net_tcp_accept(self.listener_fd) {
            Ok((client_fd, peer_addr)) => {
                enclave_log_info!(
                    "Accepted connection from {} (fd={})",
                    peer_addr,
                    client_fd
                );
                self.handle_new_connection(client_fd);
            }
            Err(_) => {
                // No pending connections (non-blocking) – normal
            }
        }

        // Process existing sessions
        let mut to_remove = Vec::new();
        for (&fd, session) in self.sessions.iter_mut() {
            match session.read() {
                Ok(data) if data.is_empty() => { /* no data yet */ }
                Ok(data) => match handle_request(&data) {
                    HandleResult::Response(resp) => {
                        if let Err(e) = session.send_frame(&resp) {
                            enclave_log_error!(
                                "Failed to send response to fd={}: {}",
                                fd,
                                e
                            );
                            to_remove.push(fd);
                        }
                    }
                    HandleResult::Shutdown => {
                        enclave_log_info!("Shutdown requested by fd={}", fd);
                        self.shutdown = true;
                        to_remove.push(fd);
                    }
                    HandleResult::Close => {
                        to_remove.push(fd);
                    }
                },
                Err(e) => {
                    enclave_log_error!("Read error on fd={}: {}", fd, e);
                    to_remove.push(fd);
                }
            }
        }

        for fd in to_remove {
            if let Some(session) = self.sessions.remove(&fd) {
                session.close();
            }
        }

        Ok(())
    }

    // ---- Connection setup with Acceptor ---------------------------------

    /// Handle a freshly accepted TCP connection.
    ///
    /// 1. Read raw ClientHello from the socket.
    /// 2. Parse extension 0xFFBB to detect a challenge nonce.
    /// 3. Generate an appropriate certificate.
    /// 4. Use `rustls::server::Acceptor` to build a `ServerConnection`.
    /// 5. Complete the handshake and register the session.
    fn handle_new_connection(&mut self, client_fd: i32) {
        // Read initial TLS data (ClientHello is typically < 1 KB).
        //
        // The accepted socket is non-blocking, so the ClientHello may not
        // be available yet — especially for remote clients with higher
        // network latency.  Retry on EAGAIN (-11) with a spin-wait.
        let mut raw_buf = vec![0u8; 16384];
        let raw_len = {
            let mut attempts = 0u32;
            const MAX_ATTEMPTS: u32 = 2000; // ~1-2 s total wall time
            loop {
                match ocall::net_recv(client_fd, &mut raw_buf) {
                    Ok(n) if n > 0 => break n,
                    Ok(_) => {
                        // Ok(0) = genuine EOF – peer closed before sending data
                        enclave_log_error!(
                            "Peer closed before ClientHello on fd={}",
                            client_fd
                        );
                        ocall::net_close(client_fd);
                        return;
                    }
                    Err(-11) if attempts < MAX_ATTEMPTS => {
                        // EAGAIN / WOULDBLOCK – data not yet available
                        attempts += 1;
                        // Brief spin (~150-500 µs per iteration depending on clock)
                        for _ in 0..500_000 {
                            core::hint::spin_loop();
                        }
                    }
                    Err(e) => {
                        enclave_log_error!(
                            "Failed to read ClientHello from fd={}: err={}",
                            client_fd,
                            e
                        );
                        ocall::net_close(client_fd);
                        return;
                    }
                }
            }
        };
        let raw = &raw_buf[..raw_len];

        // Parse extension 0xFFBB for challenge nonce
        let nonce = attestation::extract_challenge_nonce(raw);

        // Build the per-connection TLS config
        let tls_config = match self.tls_config_for(&nonce) {
            Ok(cfg) => cfg,
            Err(e) => {
                enclave_log_error!("Cert generation failed for fd={}: {}", client_fd, e);
                ocall::net_close(client_fd);
                return;
            }
        };

        // Feed the raw ClientHello into a rustls Acceptor
        let mut acceptor = Acceptor::default();
        {
            let mut cursor = std::io::Cursor::new(raw);
            if acceptor.read_tls(&mut cursor).is_err() {
                enclave_log_error!("Acceptor read_tls failed for fd={}", client_fd);
                ocall::net_close(client_fd);
                return;
            }
        }

        // Try to accept
        let accepted = match acceptor.accept() {
            Ok(Some(a)) => a,
            Ok(None) => {
                // Need more data – unusual for a single ClientHello read
                enclave_log_error!("Incomplete ClientHello for fd={}", client_fd);
                ocall::net_close(client_fd);
                return;
            }
            Err(e) => {
                enclave_log_error!("Acceptor error for fd={}: {:?}", client_fd, e);
                ocall::net_close(client_fd);
                return;
            }
        };

        // Create the ServerConnection from the accepted state
        let server_conn = match accepted.into_connection(tls_config) {
            Ok(conn) => conn,
            Err(e) => {
                enclave_log_error!("into_connection failed for fd={}: {:?}", client_fd, e);
                ocall::net_close(client_fd);
                return;
            }
        };

        // Wrap in our session type and complete the handshake
        let mut session = RaTlsSession::from_connection(client_fd, server_conn);
        match session.handshake() {
            Ok(()) => {
                enclave_log_info!("TLS handshake complete for fd={}", client_fd);
                self.sessions.insert(client_fd, session);
            }
            Err(e) => {
                enclave_log_error!(
                    "TLS handshake failed for fd={}: {}",
                    client_fd,
                    e
                );
                ocall::net_close(client_fd);
            }
        }
    }

    /// Obtain a `ServerConfig` for this connection.
    ///
    /// - If `nonce` is `Some`, generate a fresh challenge-response cert.
    /// - Otherwise, return a cached deterministic config (or generate one).
    fn tls_config_for(
        &mut self,
        nonce: &Option<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>, String> {
        if let Some(n) = nonce {
            // Challenge-response: always generate a fresh cert
            let mode = CertMode::Challenge {
                nonce: n.clone(),
            };
            return build_tls_config_from_cert(&self.ca, mode);
        }

        // Deterministic: check cache
        let now = ocall::get_current_time().unwrap_or(0);
        if let Some(ref cached) = self.cached_config {
            if now < cached.expires_at {
                return Ok(cached.config.clone());
            }
        }

        let mode = CertMode::Deterministic {
            creation_time: now,
        };
        let config = build_tls_config_from_cert(&self.ca, mode)?;
        self.cached_config = Some(CachedConfig {
            config: config.clone(),
            expires_at: now + attestation::DETERMINISTIC_VALIDITY_SECS,
        });
        Ok(config)
    }
}

impl Drop for RaTlsServer {
    fn drop(&mut self) {
        let keys: Vec<i32> = self.sessions.keys().copied().collect();
        for fd in keys {
            if let Some(session) = self.sessions.remove(&fd) {
                session.close();
            }
        }
        ocall::net_close(self.listener_fd);
    }
}

// ---------------------------------------------------------------------------
//  TLS configuration helpers
// ---------------------------------------------------------------------------

/// Build a `ServerConfig` from a freshly generated RA-TLS certificate.
fn build_tls_config_from_cert(
    ca: &CaContext,
    mode: CertMode,
) -> Result<Arc<ServerConfig>, String> {
    let (cert_chain_der, pkcs8_key) = attestation::generate_ratls_certificate(ca, mode)?;

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
//  Request handling
// ---------------------------------------------------------------------------

enum HandleResult {
    Response(Vec<u8>),
    Shutdown,
    #[allow(dead_code)]
    Close,
}

/// Handle an incoming request from a client.
fn handle_request(data: &[u8]) -> HandleResult {
    use enclave_os_common::protocol::{Request, Response};
    use crate::modules;
    match enclave_os_common::protocol::decode_frame(data) {
        Some((payload, _consumed)) => {
            match serde_json::from_slice::<Request>(&payload) {
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
                Err(_) => HandleResult::Response(data.to_vec()),
            }
        }
        None => HandleResult::Response(data.to_vec()),
    }
}
