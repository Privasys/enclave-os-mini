// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Peer links: mutual-TLS sessions between cluster nodes, multiplexed
//! over the data channel (no sockets — the host proxy shuttles
//! ciphertext, TLS terminates here).
//!
//! Both directions are **fleet-CA pinned**: the peer must present a
//! certificate chaining to this enclave's intermediary CA, which only
//! provisioned enclaves hold. The server side REQUIRES a client
//! certificate (WebPKI-verified against the fleet CA); the client side
//! chain-verifies the server and ignores only the DNS-name check
//! (RA-TLS leaves carry no SAN — identity is the fleet CA, not a
//! name; same convention as the egress RaTlsVerifier). Quote-based
//! measurement pinning on peer links is a planned tightening on top of
//! this.
//!
//! Framing on the TLS stream: `[len u32 LE][payload]`, max 8 MiB. The
//! payload is an `enclave_os_raft::Message` (which itself authenticates
//! nothing — the channel does).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Connection, DigitallySignedStruct,
    Error as TlsError, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
};

use enclave_os_common::channel::{
    self, ChannelMsgType, conn_id_is_outbound, conn_id_is_peer_inbound, CONN_ID_OUTBOUND_BASE,
};

use crate::enclave_log_error;
use crate::ratls::attestation::{self, CaContext, CertMode};

/// Max frame payload (a raft AppendEntries batch or snapshot chunk).
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// What a batch of channel messages produced for the layer above.
#[derive(Debug)]
pub enum PeerEvent {
    /// TLS handshake completed on this connection.
    Established(u32),
    /// A complete frame arrived.
    Frame(u32, Vec<u8>),
    /// Connection closed (TCP close, TLS error, or connect failure).
    Closed(u32),
}

struct PeerSession {
    conn: Connection,
    /// Plaintext assembly buffer for frame extraction.
    rx: Vec<u8>,
    established_reported: bool,
}

/// Mutual-TLS peer sessions over the data channel.
pub struct PeerLink {
    ca: CaContext,
    fleet_roots: Arc<RootCertStore>,
    sessions: BTreeMap<u32, PeerSession>,
    next_out: u32,
}

impl PeerLink {
    pub fn new(ca: CaContext) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der.clone()))
            .map_err(|e| format!("fleet CA root: {e:?}"))?;
        Ok(Self {
            ca,
            fleet_roots: Arc::new(roots),
            sessions: BTreeMap::new(),
            next_out: CONN_ID_OUTBOUND_BASE,
        })
    }

    /// Mint this node's peer certificate (deterministic mode — peer
    /// links are long-lived, fleet-CA possession is the credential).
    fn own_identity(
        &self,
        now_secs: u64,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        let minted = attestation::generate_ratls_certificate(
            &self.ca,
            CertMode::Deterministic { creation_time: now_secs },
        )?;
        let chain: Vec<CertificateDer<'static>> = minted
            .cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::try_from(minted.pkcs8_key)
            .map_err(|e| format!("peer key: {e}"))?;
        Ok((chain, key))
    }

    /// Open an outbound peer connection. The ClientHello is emitted
    /// immediately (the proxy buffers it until TCP connects). Returns
    /// the conn_id.
    pub fn dial(&mut self, addr: &str, now_secs: u64) -> Result<u32, String> {
        let (chain, key) = self.own_identity(now_secs)?;
        let verifier = FleetCaVerifier::new(self.fleet_roots.clone())?;
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("peer client config: {e:?}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(chain, key)
            .map_err(|e| format!("peer client cert: {e:?}"))?;
        cfg.enable_sni = false;

        // The name is not verified (no SAN on RA-TLS leaves); any
        // syntactically valid ServerName satisfies rustls.
        let server_name = ServerName::try_from("peer.enclave-os.internal")
            .map_err(|_| "server name".to_string())?;
        let conn = ClientConnection::new(Arc::new(cfg), server_name)
            .map_err(|e| format!("peer client conn: {e:?}"))?;

        let conn_id = self.next_out;
        self.next_out = self.next_out.checked_add(1).unwrap_or(CONN_ID_OUTBOUND_BASE);

        crate::data_tx().send(&channel::encode_tcp_connect(conn_id, addr));
        self.sessions.insert(
            conn_id,
            PeerSession { conn: Connection::Client(conn), rx: Vec::new(), established_reported: false },
        );
        // Push the ClientHello out right away.
        self.pump_out(conn_id);
        Ok(conn_id)
    }

    /// Handle one data-channel message for a peer-range conn_id.
    pub fn handle_message(
        &mut self,
        msg_type: ChannelMsgType,
        conn_id: u32,
        payload: &[u8],
        now_secs: u64,
    ) -> Vec<PeerEvent> {
        let mut events = Vec::new();
        match msg_type {
            ChannelMsgType::TcpNew if conn_id_is_peer_inbound(conn_id) => {
                match self.accept_inbound(now_secs) {
                    Ok(conn) => {
                        self.sessions.insert(
                            conn_id,
                            PeerSession {
                                conn: Connection::Server(conn),
                                rx: Vec::new(),
                                established_reported: false,
                            },
                        );
                    }
                    Err(e) => {
                        enclave_log_error!("peer accept failed: {}", e);
                        crate::data_tx().send(&channel::encode_tcp_close(conn_id));
                    }
                }
            }
            ChannelMsgType::TcpConnected => {
                // TCP-level only; the TLS handshake is already in flight.
            }
            ChannelMsgType::TcpData => {
                self.feed(conn_id, payload, &mut events);
            }
            ChannelMsgType::TcpClose => {
                if self.sessions.remove(&conn_id).is_some() {
                    events.push(PeerEvent::Closed(conn_id));
                }
            }
            _ => {
                // TcpNew for a non-peer range, Tick, DataReady: not ours.
            }
        }
        events
    }

    fn accept_inbound(&self, now_secs: u64) -> Result<ServerConnection, String> {
        let (chain, key) = self.own_identity(now_secs)?;
        let client_verifier = WebPkiClientVerifier::builder_with_provider(
            self.fleet_roots.clone(),
            Arc::new(default_provider()),
        )
        .build()
        .map_err(|e| format!("peer client verifier: {e:?}"))?;
        let cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("peer server config: {e:?}"))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(chain, key)
            .map_err(|e| format!("peer server cert: {e:?}"))?;
        ServerConnection::new(Arc::new(cfg)).map_err(|e| format!("peer server conn: {e:?}"))
    }

    /// Feed inbound TLS bytes, emit output, extract frames.
    fn feed(&mut self, conn_id: u32, data: &[u8], events: &mut Vec<PeerEvent>) {
        let mut failed = false;
        let mut established = false;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        {
            let Some(session) = self.sessions.get_mut(&conn_id) else { return };
            let mut cursor = std::io::Cursor::new(data);
            let len = data.len() as u64;
            // Never call read_tls on an exhausted cursor: rustls reads
            // Ok(0) as EOF and poisons the connection.
            while cursor.position() < len {
                match session.conn.read_tls(&mut cursor) {
                    Ok(0) => break,
                    Ok(_) => {
                        if session.conn.process_new_packets().is_err() {
                            failed = true;
                            break;
                        }
                        // Drain plaintext after every record so the
                        // internal buffer never fills.
                        let mut buf = [0u8; 16384];
                        loop {
                            match session.conn.reader().read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => session.rx.extend_from_slice(&buf[..n]),
                                Err(ref e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock =>
                                {
                                    break
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }

            if !failed {
                if !session.conn.is_handshaking() && !session.established_reported {
                    session.established_reported = true;
                    established = true;
                }
                // Extract complete frames.
                loop {
                    if session.rx.len() < 4 {
                        break;
                    }
                    let flen =
                        u32::from_le_bytes(session.rx[0..4].try_into().unwrap()) as usize;
                    if flen > MAX_FRAME {
                        failed = true;
                        break;
                    }
                    if session.rx.len() < 4 + flen {
                        break;
                    }
                    frames.push(session.rx[4..4 + flen].to_vec());
                    session.rx.drain(0..4 + flen);
                }
            }
        }

        if failed {
            self.drop_session(conn_id, events);
            return;
        }
        if established {
            events.push(PeerEvent::Established(conn_id));
        }
        for f in frames {
            events.push(PeerEvent::Frame(conn_id, f));
        }
        self.pump_out(conn_id);
    }

    /// Send a frame on an established session. Returns false if the
    /// session is gone or not yet ready.
    pub fn send_frame(&mut self, conn_id: u32, frame: &[u8]) -> bool {
        let Some(session) = self.sessions.get_mut(&conn_id) else { return false };
        if session.conn.is_handshaking() {
            return false;
        }
        let mut msg = Vec::with_capacity(4 + frame.len());
        msg.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        msg.extend_from_slice(frame);
        if session.conn.writer().write_all(&msg).is_err() {
            return false;
        }
        self.pump_out(conn_id);
        true
    }

    /// Is this session past its handshake?
    pub fn is_established(&self, conn_id: u32) -> bool {
        self.sessions
            .get(&conn_id)
            .map(|s| !s.conn.is_handshaking())
            .unwrap_or(false)
    }

    /// Close and forget a session.
    pub fn close(&mut self, conn_id: u32) {
        if self.sessions.remove(&conn_id).is_some() {
            crate::data_tx().send(&channel::encode_tcp_close(conn_id));
        }
    }

    /// Flush pending TLS output to the proxy.
    fn pump_out(&mut self, conn_id: u32) {
        let Some(session) = self.sessions.get_mut(&conn_id) else { return };
        let mut out = Vec::new();
        while session.conn.wants_write() {
            let mut chunk = Vec::new();
            match session.conn.write_tls(&mut chunk) {
                Ok(0) => break,
                Ok(_) => out.extend_from_slice(&chunk),
                Err(_) => break,
            }
        }
        if !out.is_empty() {
            crate::data_tx().send(&channel::encode_tcp_data(conn_id, &out));
        }
    }

    fn drop_session(&mut self, conn_id: u32, events: &mut Vec<PeerEvent>) {
        if self.sessions.remove(&conn_id).is_some() {
            crate::data_tx().send(&channel::encode_tcp_close(conn_id));
            events.push(PeerEvent::Closed(conn_id));
        }
    }

    /// Is the given conn_id one of ours (either range)?
    pub fn owns(conn_id: u32) -> bool {
        conn_id_is_peer_inbound(conn_id) || conn_id_is_outbound(conn_id)
    }
}

// ── Fleet-CA server verifier (client side) ──────────────────────────

/// Chain-verifies the peer's certificate against the fleet CA and
/// ignores ONLY the DNS-name check (RA-TLS leaves carry no SAN) — the
/// same convention as the egress RaTlsVerifier.
#[derive(Debug)]
struct FleetCaVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl FleetCaVerifier {
    fn new(roots: Arc<RootCertStore>) -> Result<Self, String> {
        let inner = WebPkiServerVerifier::builder_with_provider(
            roots,
            Arc::new(default_provider()),
        )
        .build()
        .map_err(|e| format!("fleet verifier: {e:?}"))?;
        Ok(Self { inner })
    }
}

impl ServerCertVerifier for FleetCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => Ok(ServerCertVerified::assertion()),
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
