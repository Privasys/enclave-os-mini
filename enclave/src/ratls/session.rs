// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS session management.
//!
//! Wraps a TLS connection over a socket handle (using OCALLs for I/O).

use std::vec::Vec;
use crate::ocall;
use enclave_os_common::protocol;

/// A TLS session over an OCALL-backed socket.
pub struct RaTlsSession {
    client_fd: i32,
    /// TLS connection state (rustls ServerConnection)
    tls_conn: rustls::ServerConnection,
}

impl RaTlsSession {
    /// Create a session from a pre-built `ServerConnection`.
    ///
    /// Used by the Acceptor-based flow in [`super::server::RaTlsServer`]
    /// where the `ServerConnection` is created via
    /// `Accepted::into_connection()`.
    pub fn from_connection(client_fd: i32, tls_conn: rustls::ServerConnection) -> Self {
        Self { client_fd, tls_conn }
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
            Err(_) => Err("TLS read failed"),
        }
    }

    /// Write application data to the TLS session.
    pub fn write(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let mut writer = self.tls_conn.writer();
        use std::io::Write;
        writer.write_all(data).map_err(|_| "TLS write failed")?;
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
    fn read_network_to_tls(&mut self) -> Result<(), &'static str> {
        let mut buf = vec![0u8; 16384];
        match ocall::net_recv(self.client_fd, &mut buf) {
            Ok(0) => Ok(()), // No data available (non-blocking)
            Ok(n) => {
                let data = &buf[..n];
                let mut cursor = std::io::Cursor::new(data);
                self.tls_conn
                    .read_tls(&mut cursor)
                    .map_err(|_| "TLS read_tls failed")?;
                self.tls_conn
                    .process_new_packets()
                    .map_err(|_| "TLS process_new_packets failed")?;
                Ok(())
            }
            Err(_) => {
                // EWOULDBLOCK / no data yet – that's fine for non-blocking
                Ok(())
            }
        }
    }
}
