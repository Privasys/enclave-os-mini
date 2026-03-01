// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side TCP proxy for enclave inbound connections.
//!
//! This module replaces the old OCALL-based TCP I/O path. Instead of
//! the enclave making `net_recv`/`net_send` OCALLs (one per chunk,
//! ~24 round-trips per request), the host TCP proxy:
//!
//!   1. Accepts TCP connections on the listen port.
//!   2. Assigns a `conn_id` and sends `TcpNew` on the data channel.
//!   3. Reads raw TCP bytes → sends `TcpData` to the enclave.
//!   4. Reads enclave TLS output from the data channel → writes to socket.
//!   5. Handles close in both directions.
//!
//! All sockets are non-blocking. The proxy runs in its own thread.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use enclave_os_common::channel::{
    self, ChannelMsgType, CHANNEL_MSG_HEADER,
};
use enclave_os_common::queue::{SpscProducer, SpscConsumer};

use log::{info, warn, error, debug};

/// Maximum bytes to read from a TCP socket in one call.
const TCP_READ_BUF: usize = 32_768;

/// TCP proxy for enclave inbound connections.
pub struct TcpProxy {
    /// TCP listener socket (non-blocking).
    listener: TcpListener,
    /// Active connections: conn_id → stream.
    connections: HashMap<u32, TcpStream>,
    /// Next connection ID to assign.
    next_conn_id: u32,
    /// Producer for `data_host_to_enc` — sends TCP data to the enclave.
    data_tx: SpscProducer,
    /// Consumer for `data_enc_to_host` — reads enclave TLS output.
    data_rx: SpscConsumer,
    /// Shared shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl TcpProxy {
    /// Create a new TCP proxy bound to the given port.
    pub fn new(
        port: u16,
        _backlog: i32,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        info!("TCP proxy listening on {}", addr);

        Ok(Self {
            listener,
            connections: HashMap::new(),
            next_conn_id: 1,
            data_tx,
            data_rx,
            shutdown,
        })
    }

    /// Run the proxy loop. Blocks until shutdown is signalled.
    pub fn run(&mut self) {
        info!("TCP proxy thread started");
        let mut read_buf = vec![0u8; TCP_READ_BUF];

        while !self.shutdown.load(Ordering::Relaxed) {
            let mut did_work = false;

            // 1. Accept new connections
            did_work |= self.accept_connections();

            // 2. Read from TCP sockets → send to enclave
            did_work |= self.read_sockets(&mut read_buf);

            // 3. Read from enclave → write to TCP sockets
            did_work |= self.drain_enclave_output();

            // If no work was done, yield briefly to avoid busy-spinning
            if !did_work {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
        }

        // Clean up: close all connections
        for (&conn_id, _) in &self.connections {
            debug!("Closing connection conn_id={} on shutdown", conn_id);
        }
        self.connections.clear();
        info!("TCP proxy thread stopped");
    }

    /// Accept pending connections. Returns true if any work was done.
    fn accept_connections(&mut self) -> bool {
        let mut accepted = false;
        // Accept up to 16 connections per poll cycle
        for _ in 0..16 {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    let conn_id = self.next_conn_id;
                    self.next_conn_id = self.next_conn_id.wrapping_add(1);
                    if self.next_conn_id == 0 {
                        self.next_conn_id = 1; // skip 0
                    }

                    if let Err(e) = stream.set_nonblocking(true) {
                        warn!("set_nonblocking failed for conn_id={}: {}", conn_id, e);
                        continue;
                    }
                    // Disable Nagle's algorithm for lower latency
                    let _ = stream.set_nodelay(true);

                    let peer_addr = addr.to_string();
                    info!("Accepted conn_id={} from {}", conn_id, peer_addr);

                    // Send TcpNew to enclave
                    let msg = channel::encode_tcp_new(conn_id, &peer_addr);
                    self.data_tx.send(&msg);

                    self.connections.insert(conn_id, stream);
                    accepted = true;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Accept error: {}", e);
                    break;
                }
            }
        }
        accepted
    }

    /// Read from all TCP sockets and forward to enclave. Returns true if
    /// any data was read.
    fn read_sockets(&mut self, buf: &mut [u8]) -> bool {
        let mut did_work = false;
        let mut to_close = Vec::new();

        for (&conn_id, stream) in self.connections.iter_mut() {
            match stream.read(buf) {
                Ok(0) => {
                    // Peer closed connection
                    debug!("Peer closed conn_id={}", conn_id);
                    to_close.push(conn_id);
                }
                Ok(n) => {
                    let msg = channel::encode_tcp_data(conn_id, &buf[..n]);
                    self.data_tx.send(&msg);
                    did_work = true;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available — normal for non-blocking
                }
                Err(e) => {
                    warn!("Read error on conn_id={}: {}", conn_id, e);
                    to_close.push(conn_id);
                }
            }
        }

        // Close connections and notify enclave
        for conn_id in to_close {
            self.connections.remove(&conn_id);
            let msg = channel::encode_tcp_close(conn_id);
            self.data_tx.send(&msg);
            did_work = true;
        }

        did_work
    }

    /// Read messages from the enclave data channel and process them.
    /// Returns true if any messages were processed.
    fn drain_enclave_output(&mut self) -> bool {
        let mut did_work = false;
        // Process up to 64 messages per poll cycle
        for _ in 0..64 {
            match self.data_rx.try_recv() {
                Some(msg) => {
                    did_work = true;
                    if msg.len() < CHANNEL_MSG_HEADER {
                        warn!("Short message from enclave ({} bytes)", msg.len());
                        continue;
                    }
                    match channel::decode_channel_msg(&msg) {
                        Some((ChannelMsgType::TcpData, conn_id, payload)) => {
                            self.write_to_socket(conn_id, payload);
                        }
                        Some((ChannelMsgType::TcpClose, conn_id, _)) => {
                            debug!("Enclave closed conn_id={}", conn_id);
                            self.connections.remove(&conn_id);
                        }
                        Some((ChannelMsgType::TcpNew, conn_id, _)) => {
                            // Enclave shouldn't send TcpNew — ignore
                            warn!(
                                "Unexpected TcpNew from enclave for conn_id={}",
                                conn_id
                            );
                        }
                        None => {
                            warn!("Failed to decode enclave message");
                        }
                    }
                }
                None => break, // no more messages
            }
        }
        did_work
    }

    /// Write data to a TCP socket. If the write fails, close the connection.
    fn write_to_socket(&mut self, conn_id: u32, data: &[u8]) {
        if let Some(stream) = self.connections.get_mut(&conn_id) {
            // Write all data (may need multiple writes for large payloads)
            let mut offset = 0;
            while offset < data.len() {
                match stream.write(&data[offset..]) {
                    Ok(0) => {
                        warn!("Zero-length write on conn_id={}", conn_id);
                        self.connections.remove(&conn_id);
                        let msg = channel::encode_tcp_close(conn_id);
                        self.data_tx.send(&msg);
                        return;
                    }
                    Ok(n) => {
                        offset += n;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Socket buffer full — spin briefly and retry
                        std::thread::yield_now();
                    }
                    Err(e) => {
                        warn!("Write error on conn_id={}: {}", conn_id, e);
                        self.connections.remove(&conn_id);
                        let msg = channel::encode_tcp_close(conn_id);
                        self.data_tx.send(&msg);
                        return;
                    }
                }
            }
        } else {
            debug!("Write to unknown conn_id={}, ignoring", conn_id);
        }
    }
}
