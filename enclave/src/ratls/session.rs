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
/// - `recv_frame()`: extract a decoded application-level frame
/// - `send_frame()`: encrypt and frame an application response
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
        Self { tls_conn, read_buf: Vec::new(), client_challenge_nonce }
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
    /// - `recv_frame()` for decrypted application-level frames
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

    /// Try to receive a complete length-delimited frame from decrypted
    /// application data.
    ///
    /// Call this after `feed_tls_bytes()`. Returns:
    /// - `Ok(Some(payload))` — a complete frame is available
    /// - `Ok(None)` — more data needed (partial frame or no data yet)
    /// - `Err` — fatal TLS error
    pub fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        // Drain any available decrypted plaintext into read_buf
        self.drain_plaintext()?;

        // Try to decode a complete frame
        if let Some((payload, consumed)) = protocol::decode_frame(&self.read_buf) {
            self.read_buf.drain(..consumed);
            Ok(Some(payload))
        } else {
            Ok(None)
        }
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

    /// Encrypt a framed application response.
    ///
    /// Encodes `payload` as a length-delimited frame, encrypts it via
    /// the TLS connection, and returns the raw TLS output bytes to send
    /// to the peer.
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        let frame = protocol::encode_frame(payload);
        self.write_plaintext(&frame)?;
        self.collect_tls_output()
    }

    /// Write raw plaintext into the TLS writer (will be encrypted).
    fn write_plaintext(&mut self, data: &[u8]) -> Result<(), &'static str> {
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
                // rustls internal buffer full — flush encrypted records.
                // The output is collected after this method returns.
                // For now, just break and trust the caller collects.
                break;
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
