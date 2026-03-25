// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS session management — pure bytes-in / bytes-out interface.
//!
//! The session receives raw TCP bytes from the data channel (via the
//! enclave event loop) and emits raw TCP bytes to send back. No OCALLs
//! are performed — all network I/O is handled by the host TCP proxy.
//!
//! This design:
//! - Eliminates per-byte OCALL round-trips (huge perf win)
//! - Decouples TLS logic from transport (testable, composable)
//! - Supports future multi-threading (sessions are `Send`)

use std::vec::Vec;
use crate::enclave_log_error;
use enclave_os_common::protocol;

/// A TLS session backed by a rustls `ServerConnection`.
///
/// The session does NOT own a socket. It operates on raw byte buffers:
/// - `feed_tls_bytes()`: feed raw TCP bytes (encrypted) into the TLS engine
/// - `recv_http_request()`: extract a decoded HTTP/1.1 request
/// - `send_http_response()`: encrypt and emit an HTTP/1.1 response
/// - `close_notify()`: produce the TLS close_notify alert
///
/// All methods that produce network output return the raw TLS bytes that
/// must be sent to the peer (via the data channel → TCP proxy).
pub struct RaTlsSession {
    /// TLS connection state (rustls ServerConnection).
    tls_conn: rustls::ServerConnection,
    /// Accumulation buffer for incomplete application-level frames.
    read_buf: Vec<u8>,
    /// Random nonce sent to the client via the TLS CertificateRequest
    /// extension `0xFFBB` (challenge mode only).  The client binds it
    /// into its own attestation report_data.
    client_challenge_nonce: Option<Vec<u8>>,
    /// FIDO2 identity, set after a successful FIDO2 ceremony on this
    /// session.  When present, subsequent requests on this TLS session
    /// are authenticated without tokens.
    fido2_identity: Option<FidoIdentity>,
}

/// Identity extracted from a successful FIDO2 registration or
/// authentication ceremony.
#[derive(Debug, Clone)]
pub struct FidoIdentity {
    /// Opaque user handle.
    pub user_handle: String,
    /// Credential ID used (base64url).
    pub credential_id: String,
    /// When the FIDO2 ceremony completed (unix timestamp).
    pub authenticated_at: u64,
}

// SAFETY: RaTlsSession contains only owned types. rustls::ServerConnection
// is Send. Ready for future multi-threaded worker dispatch.
unsafe impl Send for RaTlsSession {}

impl RaTlsSession {
    /// Create a session from a `ServerConnection`.
    ///
    /// The caller (IngressServer) is responsible for creating the
    /// ServerConnection from the Acceptor flow.
    ///
    /// `client_challenge_nonce` is the random nonce sent to the client
    /// via the TLS CertificateRequest extension `0xFFBB` (challenge mode
    /// only).  It will be used later to verify the client's RA-TLS cert
    /// report_data.
    pub fn new(
        tls_conn: rustls::ServerConnection,
        client_challenge_nonce: Option<Vec<u8>>,
    ) -> Self {
        Self { tls_conn, read_buf: Vec::new(), client_challenge_nonce, fido2_identity: None }
    }

    /// Whether the TLS handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.tls_conn.is_handshaking()
    }

    // ================================================================
    //  Bytes in → TLS engine
    // ================================================================

    /// Feed raw TCP bytes (encrypted) into the TLS engine.
    ///
    /// After calling this, check:
    /// - `collect_tls_output()` for bytes to send back (handshake msgs,
    ///    encrypted app data, NewSessionTicket, etc.)
    /// - `recv_http_request()` for decoded HTTP/1.1 requests
    ///
    /// Returns an error on fatal TLS protocol errors.
    pub fn feed_tls_bytes(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }

        let mut cursor = std::io::Cursor::new(data);
        let len = data.len();

        // Feed all received bytes into rustls. read_tls may only
        // consume a portion per call (internal deframer buffer limit),
        // so loop until the cursor is fully drained.
        //
        // IMPORTANT: Do NOT call read_tls on an exhausted cursor.
        // Cursor::read() returns Ok(0), and rustls interprets that as
        // TCP EOF — corrupting the connection state.
        while (cursor.position() as usize) < len {
            match self.tls_conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {
                    self.tls_conn
                        .process_new_packets()
                        .map_err(|e| {
                            enclave_log_error!(
                                "process_new_packets error: {:?}", e
                            );
                            "TLS process_new_packets failed"
                        })?;

                    // Drain decrypted plaintext into read_buf after each
                    // record to prevent the internal rustls plaintext
                    // buffer from filling up ("received plaintext buffer full").
                    self.drain_plaintext()?;
                }
                Err(e) => {
                    enclave_log_error!("read_tls failed: {:?}", e);
                    return Err("TLS read_tls failed");
                }
            }
        }
        Ok(())
    }

    // ================================================================
    //  TLS engine → bytes out
    // ================================================================

    /// Collect all pending TLS output (handshake messages, encrypted
    /// application data, post-handshake alerts, NewSessionTicket, etc.)
    ///
    /// The caller must send the returned bytes to the peer via the data
    /// channel.  Returns an empty Vec if there is nothing to send.
    pub fn collect_tls_output(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::new();
        let mut buf = vec![0u8; 16384];
        loop {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            match self.tls_conn.write_tls(&mut cursor) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(_) => return Err("TLS write_tls failed"),
            }
        }
        Ok(output)
    }

    // ================================================================
    //  Application data: read (decrypt)
    // ================================================================

    /// Try to receive a complete HTTP/1.1 request from decrypted
    /// application data.
    ///
    /// Call this after `feed_tls_bytes()`. Returns:
    /// - `Ok(Some(request))` — a complete HTTP request is available
    /// - `Ok(None)` — more data needed (partial request)
    /// - `Err` — fatal TLS or parse error
    pub fn recv_http_request(
        &mut self,
    ) -> Result<Option<protocol::HttpRequest>, &'static str> {
        // Drain any available decrypted plaintext into read_buf
        self.drain_plaintext()?;

        match protocol::parse_http_request(&self.read_buf) {
            Ok((request, consumed)) => {
                self.read_buf.drain(..consumed);
                Ok(Some(request))
            }
            Err(protocol::HttpParseError::Incomplete) => Ok(None),
            Err(protocol::HttpParseError::TooManyHeaders) => {
                Err("HTTP: too many headers")
            }
            Err(protocol::HttpParseError::BodyTooLarge) => {
                Err("HTTP body too large")
            }
            Err(_) => Err("malformed HTTP request"),
        }
    }

    /// Encrypt and send an HTTP/1.1 response.
    ///
    /// Returns the raw TLS output bytes to send to the peer.  For large
    /// responses the TLS layer may produce multiple records; this method
    /// flushes incrementally so the internal rustls buffer never fills up.
    pub fn send_http_response(
        &mut self,
        status: u16,
        body: &[u8],
        close: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let response = protocol::format_http_response(status, body, close);
        let mut all_output = Vec::new();
        self.write_plaintext_chunked(&response, &mut all_output)?;
        let final_output = self.collect_tls_output()?;
        all_output.extend_from_slice(&final_output);
        Ok(all_output)
    }

    /// Drain all available decrypted plaintext from the TLS reader into
    /// the internal accumulation buffer.
    fn drain_plaintext(&mut self) -> Result<(), &'static str> {
        let mut buf = vec![0u8; 16384];
        loop {
            let mut reader = self.tls_conn.reader();
            use std::io::Read;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.read_buf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    enclave_log_error!(
                        "reader.read error: kind={:?} msg={}", e.kind(), e
                    );
                    return Err("TLS read failed");
                }
            }
        }
        Ok(())
    }

    // ================================================================
    //  Application data: write (encrypt)
    // ================================================================

    /// Write plaintext into the TLS writer in chunks, flushing TLS
    /// output records into `output` whenever the internal buffer fills.
    ///
    /// This prevents the ~64 KB rustls internal buffer from truncating
    /// large responses.
    fn write_plaintext_chunked(
        &mut self,
        data: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), &'static str> {
        use std::io::Write;
        let mut offset = 0;
        while offset < data.len() {
            let n = {
                let mut writer = self.tls_conn.writer();
                writer.write(&data[offset..]).map_err(|e| {
                    enclave_log_error!(
                        "writer.write failed ({}B remaining): kind={:?} msg={}",
                        data.len() - offset, e.kind(), e
                    );
                    "TLS write failed"
                })?
            };
            if n == 0 {
                // rustls internal buffer full — flush encrypted records
                // to make room, then continue writing.
                let flushed = self.collect_tls_output()?;
                if flushed.is_empty() {
                    // No progress possible — should not happen but avoid
                    // an infinite loop.
                    enclave_log_error!(
                        "write_plaintext_chunked: no progress at offset {}/{}",
                        offset, data.len()
                    );
                    return Err("TLS write stalled: no progress");
                }
                output.extend_from_slice(&flushed);
            } else {
                offset += n;
            }
        }
        Ok(())
    }

    // ================================================================
    //  Peer certificate access
    // ================================================================

    /// Return the DER-encoded leaf certificate presented by the TLS client.
    ///
    /// Returns `Some(der)` when the client presented a certificate during
    /// the handshake (mutual RA-TLS), or `None` for unauthenticated
    /// clients (e.g. browsers).
    pub fn peer_cert_der(&self) -> Option<Vec<u8>> {
        self.tls_conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| cert.as_ref().to_vec())
    }

    /// Return the client challenge nonce stored for this connection.
    ///
    /// Present only when the server generated a challenge-mode certificate.
    /// The nonce is sent to the client via the TLS CertificateRequest
    /// extension `0xFFBB`.
    pub fn client_challenge_nonce(&self) -> Option<&Vec<u8>> {
        self.client_challenge_nonce.as_ref()
    }

    /// Return the FIDO2 identity for this session, if authenticated.
    pub fn fido2_identity(&self) -> Option<&FidoIdentity> {
        self.fido2_identity.as_ref()
    }

    /// Mark this session as FIDO2-authenticated.
    pub fn set_fido2_identity(&mut self, identity: FidoIdentity) {
        self.fido2_identity = Some(identity);
    }

    // ================================================================
    //  Lifecycle
    // ================================================================

    /// Produce a TLS close_notify alert.
    ///
    /// Returns the raw TLS bytes to send to the peer. The caller should
    /// send these via the data channel, then close the connection.
    pub fn close_notify(&mut self) -> Vec<u8> {
        self.tls_conn.send_close_notify();
        self.collect_tls_output().unwrap_or_default()
    }
}
