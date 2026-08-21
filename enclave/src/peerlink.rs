// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Peer links: mutual RA-TLS sessions between cluster nodes, multiplexed
//! over the data channel (no sockets — the host proxy shuttles
//! ciphertext, TLS terminates here).
//!
//! Both directions are **fleet-CA pinned** and **challenge-verified**:
//! the peer must present a certificate chaining to this enclave's
//! intermediary CA (which only provisioned enclaves hold), and that
//! certificate's embedded quote must commit — via `report_data` — to
//! the fresh challenge nonce WE issued for this connection plus the
//! TLS 1.3 channel binder (bidirectional challenge-response RA-TLS,
//! extension `0xFFBB`, exactly as the vaults authenticate TEE peers).
//! A deterministic (non-challenge) peer is refused. On top of the
//! binding, the peer's quote measurement must be in the admissible set
//! sourced from the cluster credential's policy. These checks run at
//! the established seam via the shared TEE checker
//! (`enclave_os_common::quote`); they parse the quote but cannot verify
//! its signature — the raft glue additionally sends the quote to the
//! configured attestation servers after the handshake, which restores
//! the guarantee even against a stolen fleet-CA key.
//!
//! Framing on the TLS stream: `[len u32 LE][payload]`, max 8 MiB. The
//! payload is an `enclave_os_raft::Message` (which itself authenticates
//! nothing — the channel does).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::server::{Acceptor, RaTlsBindCertificate, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Connection, DigitallySignedStruct,
    Error as TlsError, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
};

use enclave_os_common::channel::{
    self, ChannelMsgType, conn_id_is_outbound, conn_id_is_peer_inbound, CONN_ID_OUTBOUND_BASE,
};

use enclave_os_common::quote::TeeMeasurement;

use crate::enclave_log_error;
use crate::ratls::attestation::{self, CaContext, CertMode};

/// Max frame payload (a raft AppendEntries batch or snapshot chunk).
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Cap on buffered pre-hello bytes for an inbound connection. A real
/// ClientHello (with the RA-TLS challenge extension) is ~1-2 KiB.
const MAX_HELLO: usize = 16 * 1024;

/// What a batch of channel messages produced for the layer above.
#[derive(Debug)]
pub enum PeerEvent {
    /// TLS handshake completed AND the peer passed the local RA-TLS
    /// checks (challenge binding + measurement pin) on this connection.
    Established(u32),
    /// A complete frame arrived.
    Frame(u32, Vec<u8>),
    /// Connection closed (TCP close, TLS error, verification failure,
    /// or connect failure).
    Closed(u32),
}

enum SessionState {
    /// Inbound: buffering TCP data until the ClientHello is complete.
    /// The server certificate must bind the CLIENT's challenge nonce,
    /// so the TLS config can only be built once the hello is parsed.
    AwaitingHello(Vec<u8>),
    /// TLS running (either direction).
    Tls(Connection),
}

struct PeerSession {
    state: SessionState,
    /// Plaintext assembly buffer for frame extraction.
    rx: Vec<u8>,
    established_reported: bool,
    /// The challenge nonce WE issued to the peer for this connection.
    /// Outbound: sent in the ClientHello extension `0xFFBB`. Inbound:
    /// sent in the CertificateRequest extension `0xFFBB`. The peer's
    /// quote must commit to it (plus the session channel binder).
    our_nonce: Option<Vec<u8>>,
}

/// Mutual RA-TLS peer sessions over the data channel.
pub struct PeerLink {
    ca: CaContext,
    fleet_roots: Arc<RootCertStore>,
    /// The peer's certificate must carry a quote whose TEE-typed
    /// measurement is IN this set. The set is sourced from the cluster
    /// credential's policy (own measurement always included); an
    /// owner-approved upgrade window widens it to {old, new}.
    pinned_measurements: Arc<Vec<TeeMeasurement>>,
    sessions: BTreeMap<u32, PeerSession>,
    next_out: u32,
}

impl PeerLink {
    pub fn new(ca: CaContext, pinned_measurements: Vec<TeeMeasurement>) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der.clone()))
            .map_err(|e| format!("fleet CA root: {e:?}"))?;
        Ok(Self {
            ca,
            fleet_roots: Arc::new(roots),
            pinned_measurements: Arc::new(pinned_measurements),
            sessions: BTreeMap::new(),
            next_out: CONN_ID_OUTBOUND_BASE,
        })
    }

    /// The admissible measurement set.
    pub fn pinned(&self) -> &[TeeMeasurement] {
        self.pinned_measurements.as_slice()
    }

    /// Replace the admissible measurement set. Applies to future
    /// dials/accepts; existing sessions keep the set they were
    /// verified under until the re-attestation recycle brings them
    /// back through a fresh handshake.
    pub fn set_pinned(&mut self, set: Vec<TeeMeasurement>) {
        self.pinned_measurements = Arc::new(set);
    }

    /// The peer's end-entity certificate (DER) once the handshake is
    /// done — the raft layer verifies its embedded quote against the
    /// attestation servers before admitting the link.
    pub fn peer_cert_der(&self, conn_id: u32) -> Option<Vec<u8>> {
        let session = self.sessions.get(&conn_id)?;
        let SessionState::Tls(ref conn) = session.state else { return None };
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref().to_vec())
    }

    /// Open an outbound peer connection. The ClientHello (carrying our
    /// challenge nonce in extension `0xFFBB`) is emitted immediately
    /// (the proxy buffers it until TCP connects). Returns the conn_id.
    pub fn dial(&mut self, addr: &str) -> Result<u32, String> {
        let mut nonce = vec![0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "rng (peer challenge nonce)".to_string())?;

        let provider = Arc::new(default_provider());
        let verifier = FleetCaVerifier::new(self.fleet_roots.clone())?;
        let mut cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("peer client config: {e:?}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            // Our client certificate is minted at the TLS 1.3
            // Certificate-emit seam, bound to the SERVER's challenge
            // nonce (CertificateRequest extension 0xFFBB) plus this
            // session's channel binder. No challenge → we decline and
            // the handshake fails (challenge mode is mandatory).
            .with_client_cert_resolver(Arc::new(PeerClientAuth {
                ca: self.ca.clone(),
                provider,
            }));
        cfg.enable_sni = false;
        // Our challenge to the server: its certificate quote must
        // commit to this nonce (plus the channel binder).
        cfg.ratls_challenge = Some(nonce.clone());

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
            PeerSession {
                state: SessionState::Tls(Connection::Client(conn)),
                rx: Vec::new(),
                established_reported: false,
                our_nonce: Some(nonce),
            },
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
    ) -> Vec<PeerEvent> {
        let mut events = Vec::new();
        match msg_type {
            ChannelMsgType::TcpNew if conn_id_is_peer_inbound(conn_id) => {
                // The TLS config for an inbound connection depends on
                // the client's ClientHello (its challenge nonce), so
                // just start buffering.
                self.sessions.insert(
                    conn_id,
                    PeerSession {
                        state: SessionState::AwaitingHello(Vec::new()),
                        rx: Vec::new(),
                        established_reported: false,
                        our_nonce: None,
                    },
                );
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

    /// Try to build the inbound TLS session from the accumulated
    /// ClientHello bytes. `Ok(None)` = incomplete, keep buffering.
    /// On success returns the connection and OUR challenge nonce for
    /// the client (sent in the CertificateRequest extension `0xFFBB`).
    fn accept_inbound(
        &self,
        buf: &[u8],
    ) -> Result<Option<(ServerConnection, Vec<u8>)>, String> {
        // Feed the bytes into a rustls Acceptor and confirm the
        // ClientHello is complete BEFORE parsing it: a partial hello
        // would yield a truncated challenge nonce.
        let mut acceptor = Acceptor::default();
        {
            let mut cursor = std::io::Cursor::new(buf);
            acceptor
                .read_tls(&mut cursor)
                .map_err(|e| format!("peer hello read: {e:?}"))?;
        }
        let accepted = match acceptor.accept() {
            Ok(Some(a)) => a,
            Ok(None) => return Ok(None), // Incomplete — caller buffers more.
            Err(e) => return Err(format!("peer hello accept: {e:?}")),
        };

        let hello = attestation::parse_client_hello(buf);
        let Some(client_nonce) = hello.challenge_nonce else {
            return Err(
                "peer sent no RA-TLS challenge (challenge mode is mandatory on peer links)"
                    .to_string(),
            );
        };

        // Initial mint binds the client's nonce; the fork's bind hook
        // re-mints at the Certificate-emit seam once the handshake
        // secret exists, folding in the channel binder.
        let minted = attestation::generate_ratls_certificate(
            &self.ca,
            CertMode::Challenge { nonce: client_nonce.clone(), binder: None },
        )?;
        let our_nonce = minted
            .client_challenge_nonce
            .ok_or_else(|| "challenge mint produced no client nonce".to_string())?;
        let chain: Vec<CertificateDer<'static>> = minted
            .cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(minted.pkcs8_key));

        // Mandatory client certificates, chained to the fleet CA.
        let client_verifier = WebPkiClientVerifier::builder_with_provider(
            self.fleet_roots.clone(),
            Arc::new(default_provider()),
        )
        .build()
        .map_err(|e| format!("peer client verifier: {e:?}"))?;
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("peer server config: {e:?}"))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(chain, key)
            .map_err(|e| format!("peer server cert: {e:?}"))?;
        // Our challenge to the client (CertificateRequest ext 0xFFBB):
        // its client certificate quote must commit to it.
        cfg.ratls_challenge = Some(our_nonce.clone());
        // Re-mint our leaf with the session channel binder at the
        // emit seam so our quote commits to this exact TLS session.
        cfg.ratls_bind_certificate = Some(Arc::new(PeerBindingMinter {
            ca: self.ca.clone(),
            nonce: client_nonce,
        }));

        let conn = accepted
            .into_connection(Arc::new(cfg))
            .map_err(|e| format!("peer server conn: {e:?}"))?;
        Ok(Some((conn, our_nonce)))
    }

    /// Feed inbound TLS bytes, emit output, extract frames.
    fn feed(&mut self, conn_id: u32, data: &[u8], events: &mut Vec<PeerEvent>) {
        // Inbound pre-hello: buffer until the ClientHello is complete,
        // then build the TLS session (any flight bytes beyond the
        // hello are carried over by the Acceptor).
        enum HelloStep {
            NotPending,
            Oversized,
            Complete(Vec<u8>),
        }
        let step = {
            let Some(session) = self.sessions.get_mut(&conn_id) else { return };
            match session.state {
                SessionState::AwaitingHello(ref mut buf) => {
                    buf.extend_from_slice(data);
                    if buf.len() > MAX_HELLO {
                        HelloStep::Oversized
                    } else {
                        HelloStep::Complete(buf.clone())
                    }
                }
                SessionState::Tls(_) => HelloStep::NotPending,
            }
        };
        if let HelloStep::Oversized = step {
            enclave_log_error!("peer conn {}: oversized ClientHello", conn_id);
            self.drop_session(conn_id, events);
            return;
        }
        if let HelloStep::Complete(buf) = step {
            match self.accept_inbound(&buf) {
                Ok(None) => {} // incomplete — keep buffering
                Ok(Some((conn, our_nonce))) => {
                    let Some(session) = self.sessions.get_mut(&conn_id) else { return };
                    session.state = SessionState::Tls(Connection::Server(conn));
                    session.our_nonce = Some(our_nonce);
                    // Flush the server flight; no plaintext yet.
                    self.pump_out(conn_id);
                }
                Err(e) => {
                    enclave_log_error!("peer accept failed: {}", e);
                    self.drop_session(conn_id, events);
                }
            }
            return;
        }

        let mut failed = false;
        let mut established = false;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        {
            let Some(session) = self.sessions.get_mut(&conn_id) else { return };
            let SessionState::Tls(ref mut conn) = session.state else { return };
            let mut cursor = std::io::Cursor::new(data);
            let len = data.len() as u64;
            // Never call read_tls on an exhausted cursor: rustls reads
            // Ok(0) as EOF and poisons the connection.
            while cursor.position() < len {
                match conn.read_tls(&mut cursor) {
                    Ok(0) => break,
                    Ok(_) => {
                        if conn.process_new_packets().is_err() {
                            failed = true;
                            break;
                        }
                        // Drain plaintext after every record so the
                        // internal buffer never fills.
                        let mut buf = [0u8; 16384];
                        loop {
                            match conn.reader().read(&mut buf) {
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
                if !conn.is_handshaking() && !session.established_reported {
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
            // Local RA-TLS checks at the established seam: challenge
            // binding (nonce + channel binder) and the measurement
            // pin, via the shared TEE checker. Fail-closed.
            if let Err(e) = self.verify_established(conn_id) {
                enclave_log_error!("peer conn {} rejected: {}", conn_id, e);
                self.drop_session(conn_id, events);
                return;
            }
            events.push(PeerEvent::Established(conn_id));
        }
        for f in frames {
            events.push(PeerEvent::Frame(conn_id, f));
        }
        self.pump_out(conn_id);
    }

    /// Verify the peer at the established seam: its certificate quote
    /// must commit to OUR challenge nonce plus this session's channel
    /// binder (bidirectional challenge-response), and its measurement
    /// must be in the admissible set. Uses the shared TEE checker
    /// (`enclave_os_common::quote` — SGX and TDX alike). This parses
    /// the quote but cannot verify its signature; the raft glue's
    /// attestation-server gate covers that.
    fn verify_established(&self, conn_id: u32) -> Result<(), String> {
        let session = self
            .sessions
            .get(&conn_id)
            .ok_or_else(|| "session gone".to_string())?;
        let SessionState::Tls(ref conn) = session.state else {
            return Err("session not in TLS state".to_string());
        };
        let cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| "no peer certificate".to_string())?;
        let (quote, pubkey_raw) = dissect_peer_cert(cert.as_ref())?;
        let binder = match conn {
            Connection::Client(c) => c.ratls_channel_binder().map(|b| b.to_vec()),
            Connection::Server(c) => c.ratls_channel_binder().map(|b| b.to_vec()),
        };
        enclave_os_common::quote::verify_challenge_binding(
            &quote,
            &pubkey_raw,
            session.our_nonce.as_deref(),
            binder.as_deref(),
        )?;
        let identity = enclave_os_common::quote::parse_quote(&quote)
            .map_err(|e| format!("peer quote: {e}"))?;
        if !self.pinned_measurements.iter().any(|m| identity.matches(m)) {
            return Err(format!(
                "peer measurement {:?}:{} not in the admissible set ({} entries)",
                identity.tee,
                identity.measurement,
                self.pinned_measurements.len()
            ));
        }
        Ok(())
    }

    /// Send a frame on an established session. Returns false if the
    /// session is gone or not yet ready.
    pub fn send_frame(&mut self, conn_id: u32, frame: &[u8]) -> bool {
        let Some(session) = self.sessions.get_mut(&conn_id) else { return false };
        let SessionState::Tls(ref mut conn) = session.state else { return false };
        if conn.is_handshaking() {
            return false;
        }
        let mut msg = Vec::with_capacity(4 + frame.len());
        msg.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        msg.extend_from_slice(frame);
        if conn.writer().write_all(&msg).is_err() {
            return false;
        }
        self.pump_out(conn_id);
        true
    }

    /// Is this session past its handshake?
    pub fn is_established(&self, conn_id: u32) -> bool {
        self.sessions
            .get(&conn_id)
            .map(|s| match &s.state {
                SessionState::Tls(conn) => !conn.is_handshaking(),
                SessionState::AwaitingHello(_) => false,
            })
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
        let SessionState::Tls(ref mut conn) = session.state else { return };
        let mut out = Vec::new();
        while conn.wants_write() {
            let mut chunk = Vec::new();
            match conn.write_tls(&mut chunk) {
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

// ── Certificate dissection (shared-checker input) ───────────────────

/// Extract the raw attestation quote (SGX or TDX extension) and the
/// raw subject public key from a peer certificate. The quote goes to
/// the shared TEE checker locally and to the attestation servers for
/// independent verification.
fn dissect_peer_cert(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| "peer cert: DER parse failed".to_string())?;
    let quote = cert
        .extensions()
        .iter()
        .find(|ext| {
            let oid = ext.oid.to_id_string();
            oid == enclave_os_common::oids::SGX_QUOTE_OID_STR
                || oid == enclave_os_common::oids::TDX_QUOTE_OID_STR
        })
        .map(|ext| ext.value.to_vec())
        .ok_or_else(|| "peer cert: no attestation quote extension".to_string())?;
    let pubkey_raw = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .as_ref()
        .to_vec();
    Ok((quote, pubkey_raw))
}

/// Extract the raw attestation quote from a peer certificate. Public:
/// the raft layer sends this quote to the attestation servers for
/// independent verification (signature chain, TCB status) after the
/// handshake.
pub fn extract_quote(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    dissect_peer_cert(cert_der).map(|(quote, _)| quote)
}

// ── Challenge-bound identity minting ────────────────────────────────

/// Client-certificate resolver for outbound peer connections: at the
/// TLS 1.3 Certificate-emit seam, mint a fresh fleet cert whose quote
/// commits to the SERVER's challenge nonce (CertificateRequest
/// extension `0xFFBB`) plus this session's channel binder. Declines
/// without a challenge — a peer that does not challenge us is not one
/// of ours, and the handshake fails.
struct PeerClientAuth {
    ca: CaContext,
    provider: Arc<CryptoProvider>,
}

impl core::fmt::Debug for PeerClientAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the captured CA key material.
        f.debug_struct("PeerClientAuth").finish_non_exhaustive()
    }
}

impl ResolvesClientCert for PeerClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
        ratls_challenge: Option<&[u8]>,
        ratls_channel_binder: Option<&[u8]>,
    ) -> Option<Arc<CertifiedKey>> {
        let challenge = ratls_challenge?;
        let binder: Option<[u8; 32]> =
            ratls_channel_binder.and_then(|b| b.try_into().ok());
        let minted = attestation::generate_ratls_certificate(
            &self.ca,
            CertMode::Challenge { nonce: challenge.to_vec(), binder },
        )
        .ok()?;
        let certs: Vec<CertificateDer<'static>> = minted
            .cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(minted.pkcs8_key));
        let signing_key = self.provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Server-side re-mint hook: once the handshake secret exists (the
/// TLS 1.3 Certificate-emit seam), re-mint our leaf with the session
/// channel binder folded into the quote's `report_data`, so our
/// evidence commits to this exact TLS session.
struct PeerBindingMinter {
    ca: CaContext,
    /// The CLIENT's challenge nonce from its ClientHello.
    nonce: Vec<u8>,
}

impl core::fmt::Debug for PeerBindingMinter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the captured CA key / nonce.
        f.debug_struct("PeerBindingMinter").finish_non_exhaustive()
    }
}

impl RaTlsBindCertificate for PeerBindingMinter {
    fn bind_certificate(&self, binder: &[u8; 32]) -> Option<Arc<CertifiedKey>> {
        let minted = attestation::generate_ratls_certificate(
            &self.ca,
            CertMode::Challenge { nonce: self.nonce.clone(), binder: Some(*binder) },
        )
        .ok()?;
        let certs: Vec<CertificateDer<'static>> = minted
            .cert_chain_der
            .into_iter()
            .map(|der| CertificateDer::from(der).into_owned())
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(minted.pkcs8_key));
        CertifiedKey::from_der(certs, key, &default_provider())
            .ok()
            .map(Arc::new)
    }
}

// ── Fleet-CA server verifier (client side) ──────────────────────────

/// Chain-verifies the peer's certificate against the fleet CA and
/// ignores ONLY the DNS-name check (RA-TLS leaves carry no SAN) — the
/// same convention as the egress RaTlsVerifier. Quote checks (challenge
/// binding + measurement) run at the established seam, where the
/// channel binder is available.
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
            Ok(_) => {}
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(e) => return Err(e),
        }
        Ok(ServerCertVerified::assertion())
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
