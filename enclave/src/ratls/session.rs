// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS session management.
//!
//! Wraps a TLS connection over a socket handle (using OCALLs for I/O).

use std::vec::Vec;
use crate::ocall;
use crate::enclave_log_error;
use enclave_os_common::protocol;

/// A TLS session over an OCALL-backed socket.
pub struct RaTlsSession {
    client_fd: i32,
    /// TLS connection state (rustls ServerConnection)
    tls_conn: rustls::ServerConnection,
    /// Accumulation buffer for incomplete frames.
    read_buf: Vec<u8>,
}

impl RaTlsSession {
    /// Create a session from a pre-built `ServerConnection`.
    ///
    /// Used by the Acceptor-based flow in [`super::server::RaTlsServer`]
    /// where the `ServerConnection` is created via
    /// `Accepted::into_connection()`.
    pub fn from_connection(client_fd: i32, tls_conn: rustls::ServerConnection) -> Self {
        Self { client_fd, tls_conn, read_buf: Vec::new() }
    }

    /// Perform the TLS handshake by reading/writing via OCALLs.
    pub fn handshake(&mut self) -> Result<(), &'static str> {
        loop {
            if self.tls_conn.is_handshaking() {
                // Write any pending TLS data to the network
                self.flush_tls_to_network()?;

                // Read data from the network into TLS
                self.read_network_to_tls()?;
            } else {
                // Handshake complete
                self.flush_tls_to_network()?;
                return Ok(());
            }
        }
    }

    /// Read application data from the TLS session.
    pub fn read(&mut self) -> Result<Vec<u8>, &'static str> {
        // First, read any network data into TLS
        self.read_network_to_tls()?;

        // Then read decrypted application data
        let mut buf = vec![0u8; 16384];
        let mut reader = self.tls_conn.reader();
        use std::io::Read;
        match reader.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => {
                enclave_log_error!(
                    "fd={}: reader.read error: kind={:?} msg={}",
                    self.client_fd, e.kind(), e
                );
                Err("TLS read failed")
            }
        }
    }

    /// Try to receive a complete length-delimited frame.
    ///
    /// Reads data from the TLS connection and accumulates it in an
    /// internal buffer.  Returns `Ok(Some(payload))` when a complete
    /// frame is available, `Ok(None)` when more data is needed, or
    /// `Err` on a fatal TLS/connection error.
    pub fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        // Read a chunk of data from the network / TLS layer
        let chunk = self.read()?;
        if !chunk.is_empty() {
            self.read_buf.extend_from_slice(&chunk);
        }

        // Try to decode a complete frame from the accumulated buffer
        if let Some((payload, consumed)) = protocol::decode_frame(&self.read_buf) {
            // Remove the consumed bytes from the front of the buffer
            self.read_buf.drain(..consumed);
            Ok(Some(payload))
        } else {
            Ok(None)
        }
    }

    /// Write application data to the TLS session.
    ///
    /// Writes the data in chunks, flushing encrypted TLS records to the
    /// network between chunks.  This avoids hitting rustls's internal
    /// buffer limit on large payloads.
    pub fn write(&mut self, data: &[u8]) -> Result<(), &'static str> {
        use std::io::Write;
        let mut offset = 0;
        while offset < data.len() {
            let n = {
                let mut writer = self.tls_conn.writer();
                writer.write(&data[offset..]).map_err(|e| {
                    enclave_log_error!(
                        "fd={}: writer.write failed ({}B remaining): kind={:?} msg={}",
                        self.client_fd, data.len() - offset, e.kind(), e
                    );
                    "TLS write failed"
                })?
            };
            if n == 0 {
                // Internal buffer full — flush encrypted records out
                self.flush_tls_to_network()?;
            } else {
                offset += n;
            }
        }
        // Final flush for any remaining buffered records
        self.flush_tls_to_network()?;
        Ok(())
    }

    /// Send a framed response.
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        let frame = protocol::encode_frame(payload);
        self.write(&frame)
    }

    /// Close the session.
    pub fn close(mut self) {
        self.tls_conn.send_close_notify();
        let _ = self.flush_tls_to_network();
        ocall::net_close(self.client_fd);
    }

    // ---- Internal helpers ----

    /// Flush TLS output to the network via OCALLs.
    fn flush_tls_to_network(&mut self) -> Result<(), &'static str> {
        let mut buf = vec![0u8; 16384];
        loop {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            match self.tls_conn.write_tls(&mut cursor) {
                Ok(0) => break,
                Ok(n) => {
                    let written = &buf[..n];
                    let mut offset = 0;
                    while offset < written.len() {
                        match ocall::net_send(self.client_fd, &written[offset..]) {
                            Ok(sent) => offset += sent,
                            Err(_) => return Err("Network send failed"),
                        }
                    }
                }
                Err(_) => return Err("TLS write_tls failed"),
            }
        }
        Ok(())
    }

    /// Read network data into the TLS connection via OCALLs.
    ///
    /// Reads raw bytes from the socket and feeds them into the rustls
    /// connection.  `read_tls()` may consume fewer bytes than are
    /// available (its internal deframer buffer has a finite capacity),
    /// so we loop until the cursor is exhausted.
    fn read_network_to_tls(&mut self) -> Result<(), &'static str> {
        let mut buf = vec![0u8; 16384];
        match ocall::net_recv(self.client_fd, &mut buf) {
            Ok(0) => Ok(()), // No data available (non-blocking)
            Ok(n) => {
                let data = &buf[..n];
                let mut cursor = std::io::Cursor::new(data);

                // Feed all received bytes into rustls.  read_tls may
                // only consume a portion per call (internal buffer limit),
                // so loop until the cursor is fully drained.
                //
                // IMPORTANT: We must NOT call read_tls on an exhausted
                // cursor.  Cursor::read() returns Ok(0) when empty, and
                // rustls interprets Ok(0) as TCP EOF, which corrupts the
                // connection state (UnexpectedEof on subsequent reads).
                while (cursor.position() as usize) < n {
                    match self.tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,        // should not happen (guarded above)
                        Ok(_) => {
                            self.tls_conn
                                .process_new_packets()
                                .map_err(|e| {
                                    enclave_log_error!(
                                        "fd={}: process_new_packets error: {:?}",
                                        self.client_fd, e
                                    );
                                    "TLS process_new_packets failed"
                                })?;
                            // Flush any TLS control messages (e.g. NewSessionTicket,
                            // KeyUpdate) that process_new_packets may have queued.
                            self.flush_tls_to_network()?;
                        }
                        Err(e) => {
                            enclave_log_error!(
                                "fd={}: read_tls failed: {:?}",
                                self.client_fd, e
                            );
                            return Err("TLS read_tls failed");
                        }
                    }
                }
                Ok(())
            }
            Err(_) => {
                // EWOULDBLOCK / no data yet – that's fine for non-blocking
                Ok(())
            }
        }
    }
}
