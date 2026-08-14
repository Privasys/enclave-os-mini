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
use std::time::{Duration, Instant};

use enclave_os_common::channel::{
    self, ChannelMsgType, CHANNEL_MSG_HEADER,
    CONN_ID_PEER_IN_BASE, CONN_ID_OUTBOUND_BASE,
};
use enclave_os_common::queue::{SpscProducer, SpscConsumer};

use log::{info, warn, error, debug};

/// Maximum bytes to read from a TCP socket in one call.
const TCP_READ_BUF: usize = 32_768;

/// Timeout for enclave-requested outbound connects.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on bytes buffered for a not-yet-connected outbound connection
/// (the enclave emits its TLS ClientHello before the connect completes).
const MAX_PENDING_WRITE: usize = 256 * 1024;

/// Raft tick cadence (sent to the enclave when a peer port is set).
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Errno for a non-blocking connect in progress. The host only runs on
/// Linux (SGX); `WouldBlock` covers other platforms as a fallback.
#[cfg(target_os = "linux")]
const EINPROGRESS: i32 = 115;
#[cfg(not(target_os = "linux"))]
const EINPROGRESS: i32 = -1;

/// Hard cap on simultaneously-tracked connections. Leaves headroom under
/// the conventional 1024 default `RLIMIT_NOFILE`. New `accept()` calls
/// past this cap drop the freshly-accepted socket immediately so the
/// listener never wedges with `EMFILE`.
const MAX_CONNS: usize = 800;

/// Per-connection idle timeout. Any tracked connection that has not
/// produced read/write activity for this long is force-closed and the
/// enclave is notified. Catches half-dead peers (NAT timeouts, suspended
/// laptops, slow-loris ClientHello stalls) that never trigger TCP keepalive.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How often the proxy loop scans for idle connections.
const IDLE_SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// TCP keepalive parameters applied to every accepted socket. The kernel
/// sends the first probe after `KEEPALIVE_IDLE`, then `KEEPALIVE_RETRIES`
/// further probes spaced by `KEEPALIVE_INTERVAL`. Dead peers are reaped
/// in roughly `KEEPALIVE_IDLE + retries * interval` (~3.5 min by default).
const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_RETRIES: u32 = 3;

/// Per-connection state tracked by the proxy.
struct ConnState {
    stream: TcpStream,
    last_activity: Instant,
}

/// An enclave-requested outbound connection whose non-blocking connect
/// has not completed yet. `TcpData` from the enclave is buffered until
/// the socket is writable.
struct PendingConn {
    stream: TcpStream,
    buffered: Vec<Vec<u8>>,
    buffered_len: usize,
    started: Instant,
}

/// TCP proxy for enclave inbound and proxy-owned outbound connections.
pub struct TcpProxy {
    /// Ingress TCP listener socket (non-blocking).
    listener: TcpListener,
    /// Optional peer-port listener (raft peer links). Inbound conns from
    /// this listener get ids from the `CONN_ID_PEER_IN_BASE` range.
    peer_listener: Option<TcpListener>,
    /// Active connections: conn_id → state.
    connections: HashMap<u32, ConnState>,
    /// Outbound connects in progress: conn_id → pending state.
    pending_connects: HashMap<u32, PendingConn>,
    /// Next ingress connection ID to assign.
    next_conn_id: u32,
    /// Next peer-port connection ID to assign.
    next_peer_conn_id: u32,
    /// Producer for `data_host_to_enc` — sends TCP data to the enclave.
    data_tx: SpscProducer,
    /// Consumer for `data_enc_to_host` — reads enclave TLS output.
    data_rx: SpscConsumer,
    /// Shared shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// True once the enclave has signalled DataReady.
    ready: bool,
    /// Last time we ran the idle-connection sweep.
    last_idle_scan: Instant,
    /// Last raft tick sent (peer-port mode only).
    last_tick: Instant,
}

impl TcpProxy {
    /// Create a new TCP proxy bound to the given port, with an optional
    /// second listener for peer links.
    pub fn new(
        port: u16,
        _backlog: i32,
        peer_port: Option<u16>,
        data_tx: SpscProducer,
        data_rx: SpscConsumer,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        info!("TCP proxy listening on {}", addr);

        let peer_listener = match peer_port {
            Some(p) => {
                let peer_addr = format!("0.0.0.0:{}", p);
                let l = TcpListener::bind(&peer_addr)?;
                l.set_nonblocking(true)?;
                info!("TCP proxy peer listener on {}", peer_addr);
                Some(l)
            }
            None => None,
        };

        Ok(Self {
            listener,
            peer_listener,
            connections: HashMap::new(),
            pending_connects: HashMap::new(),
            next_conn_id: 1,
            next_peer_conn_id: CONN_ID_PEER_IN_BASE,
            data_tx,
            data_rx,
            shutdown,
            ready: false,
            last_idle_scan: Instant::now(),
            last_tick: Instant::now(),
        })
    }

    /// Run the proxy loop. Blocks until shutdown is signalled.
    pub fn run(&mut self) {
        info!("TCP proxy thread started");
        let mut read_buf = vec![0u8; TCP_READ_BUF];

        while !self.shutdown.load(Ordering::Relaxed) {
            let mut did_work = false;

            // 3 (first). Read from enclave → write to TCP sockets / check DataReady
            did_work |= self.drain_enclave_output();

            if !self.ready {
                // Don't accept or read until the enclave signals DataReady
                if !did_work {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                continue;
            }

            // 1. Accept new connections
            did_work |= self.accept_connections();

            // 1b. Progress enclave-requested outbound connects
            did_work |= self.poll_pending_connects();

            // 2. Read from TCP sockets → send to enclave
            did_work |= self.read_sockets(&mut read_buf);

            // 4. Periodically reap idle connections (catches half-dead peers
            //    that never trigger TCP keepalive — e.g. stalled TLS handshakes).
            if self.last_idle_scan.elapsed() >= IDLE_SCAN_INTERVAL {
                self.reap_idle_connections();
                self.last_idle_scan = Instant::now();
            }

            // 5. Raft timer ticks (only when a peer port is configured).
            if self.peer_listener.is_some() && self.last_tick.elapsed() >= TICK_INTERVAL {
                self.data_tx.send(&channel::encode_channel_msg(
                    ChannelMsgType::Tick,
                    0,
                    &[],
                ));
                self.last_tick = Instant::now();
            }

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

    /// Accept pending connections from both listeners. Returns true if
    /// any work was done.
    fn accept_connections(&mut self) -> bool {
        // Drain both listeners first (accept only borrows the listener),
        // then register the sockets.
        let mut incoming: Vec<(TcpStream, std::net::SocketAddr, bool)> = Vec::new();

        // Accept up to 16 connections per listener per poll cycle
        for _ in 0..16 {
            match self.listener.accept() {
                Ok((stream, addr)) => incoming.push((stream, addr, false)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Accept error: {}", e);
                    break;
                }
            }
        }
        if let Some(ref peer_listener) = self.peer_listener {
            for _ in 0..16 {
                match peer_listener.accept() {
                    Ok((stream, addr)) => incoming.push((stream, addr, true)),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!("Peer accept error: {}", e);
                        break;
                    }
                }
            }
        }

        let mut accepted = false;
        for (stream, addr, is_peer) in incoming {
            // Hard cap to avoid wedging the listener with EMFILE.
            // Drop the freshly-accepted socket immediately if we're
            // already tracking too many connections — better to refuse
            // a single connection than to leak FDs and DoS ourselves.
            if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
                warn!(
                    "Connection cap reached ({}), dropping new connection from {}",
                    MAX_CONNS, addr
                );
                drop(stream);
                continue;
            }

            let conn_id = if is_peer {
                let id = self.next_peer_conn_id;
                self.next_peer_conn_id = self.next_peer_conn_id.wrapping_add(1);
                if self.next_peer_conn_id >= CONN_ID_OUTBOUND_BASE {
                    self.next_peer_conn_id = CONN_ID_PEER_IN_BASE;
                }
                id
            } else {
                let id = self.next_conn_id;
                self.next_conn_id = self.next_conn_id.wrapping_add(1);
                if self.next_conn_id == 0 || self.next_conn_id >= CONN_ID_PEER_IN_BASE {
                    self.next_conn_id = 1; // skip 0, stay in the ingress range
                }
                id
            };

            if let Err(e) = stream.set_nonblocking(true) {
                warn!("set_nonblocking failed for conn_id={}: {}", conn_id, e);
                continue;
            }
            // Disable Nagle's algorithm for lower latency
            let _ = stream.set_nodelay(true);
            // Enable TCP keepalive so the kernel reaps half-dead peers
            // (NAT timeouts, suspended laptops, killed clients) that
            // never sent FIN/RST. Without this the host never sees a
            // read error and the FD leaks until process restart.
            if let Err(e) = enable_keepalive(&stream) {
                warn!("set keepalive failed for conn_id={}: {}", conn_id, e);
            }

            let peer_addr = addr.to_string();
            info!(
                "Accepted conn_id={} from {}{} (active={})",
                conn_id,
                peer_addr,
                if is_peer { " [peer port]" } else { "" },
                self.connections.len() + 1
            );

            // Send TcpNew to enclave
            let msg = channel::encode_tcp_new(conn_id, &peer_addr);
            self.data_tx.send(&msg);

            self.connections.insert(
                conn_id,
                ConnState { stream, last_activity: Instant::now() },
            );
            accepted = true;
        }
        accepted
    }

    /// Start an enclave-requested outbound connect (`TcpConnect`).
    ///
    /// The connect is non-blocking; completion is polled in
    /// [`Self::poll_pending_connects`]. Failures are reported to the
    /// enclave as `TcpClose` for the conn_id.
    fn start_outbound_connect(&mut self, conn_id: u32, addr_str: &str) {
        use std::net::ToSocketAddrs;

        if !channel::conn_id_is_outbound(conn_id) {
            warn!("TcpConnect with non-outbound conn_id={}, rejecting", conn_id);
            self.data_tx.send(&channel::encode_tcp_close(conn_id));
            return;
        }
        if self.connections.contains_key(&conn_id)
            || self.pending_connects.contains_key(&conn_id)
        {
            warn!("TcpConnect with duplicate conn_id={}, rejecting", conn_id);
            self.data_tx.send(&channel::encode_tcp_close(conn_id));
            return;
        }
        if self.connections.len() + self.pending_connects.len() >= MAX_CONNS {
            warn!("Connection cap reached, rejecting outbound conn_id={}", conn_id);
            self.data_tx.send(&channel::encode_tcp_close(conn_id));
            return;
        }

        // Resolve. This can block briefly for DNS names; peer addresses
        // are normally numeric, in which case resolution is a parse.
        let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => {
                warn!("TcpConnect conn_id={}: cannot resolve '{}'", conn_id, addr_str);
                self.data_tx.send(&channel::encode_tcp_close(conn_id));
                return;
            }
        };

        // Non-blocking connect via socket2 (std's TcpStream::connect blocks).
        let socket = match socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("TcpConnect conn_id={}: socket create failed: {}", conn_id, e);
                self.data_tx.send(&channel::encode_tcp_close(conn_id));
                return;
            }
        };
        if let Err(e) = socket.set_nonblocking(true) {
            warn!("TcpConnect conn_id={}: set_nonblocking failed: {}", conn_id, e);
            self.data_tx.send(&channel::encode_tcp_close(conn_id));
            return;
        }
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            // In-progress is the normal non-blocking outcome
            // (EINPROGRESS on Unix, WSAEWOULDBLOCK on Windows).
            Err(ref e)
                if e.raw_os_error() == Some(EINPROGRESS)
                    || e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                warn!("TcpConnect conn_id={} to {}: {}", conn_id, addr, e);
                self.data_tx.send(&channel::encode_tcp_close(conn_id));
                return;
            }
        }

        debug!("Outbound connect started conn_id={} to {}", conn_id, addr);
        self.pending_connects.insert(
            conn_id,
            PendingConn {
                stream: socket.into(),
                buffered: Vec::new(),
                buffered_len: 0,
                started: Instant::now(),
            },
        );
    }

    /// Poll outbound connects for completion, failure, or timeout.
    /// Returns true if any connection changed state.
    fn poll_pending_connects(&mut self) -> bool {
        if self.pending_connects.is_empty() {
            return false;
        }
        let mut done: Vec<(u32, bool)> = Vec::new(); // (conn_id, success)
        for (&conn_id, pending) in self.pending_connects.iter() {
            // A socket error means the connect failed.
            match pending.stream.take_error() {
                Ok(Some(e)) => {
                    warn!("Outbound connect failed conn_id={}: {}", conn_id, e);
                    done.push((conn_id, false));
                    continue;
                }
                Err(e) => {
                    warn!("Outbound connect failed conn_id={}: {}", conn_id, e);
                    done.push((conn_id, false));
                    continue;
                }
                Ok(None) => {}
            }
            // peer_addr() succeeds once the socket is connected.
            match pending.stream.peer_addr() {
                Ok(_) => done.push((conn_id, true)),
                Err(_) => {
                    if pending.started.elapsed() >= CONNECT_TIMEOUT {
                        warn!("Outbound connect timeout conn_id={}", conn_id);
                        done.push((conn_id, false));
                    }
                }
            }
        }

        let changed = !done.is_empty();
        for (conn_id, success) in done {
            let pending = match self.pending_connects.remove(&conn_id) {
                Some(p) => p,
                None => continue,
            };
            if !success {
                self.data_tx.send(&channel::encode_tcp_close(conn_id));
                continue;
            }
            let _ = pending.stream.set_nodelay(true);
            if let Err(e) = enable_keepalive(&pending.stream) {
                warn!("set keepalive failed for conn_id={}: {}", conn_id, e);
            }
            info!(
                "Outbound connected conn_id={} to {} (active={})",
                conn_id,
                pending.stream.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
                self.connections.len() + 1
            );
            self.connections.insert(
                conn_id,
                ConnState { stream: pending.stream, last_activity: Instant::now() },
            );
            self.data_tx.send(&channel::encode_tcp_connected(conn_id));
            // Flush any TLS bytes the enclave emitted while connecting.
            for chunk in pending.buffered {
                self.write_to_socket(conn_id, &chunk);
                if !self.connections.contains_key(&conn_id) {
                    break; // write failed and closed the connection
                }
            }
        }
        changed
    }

    /// Read from all TCP sockets and forward to enclave. Returns true if
    /// any data was read.
    fn read_sockets(&mut self, buf: &mut [u8]) -> bool {
        let mut did_work = false;
        let mut to_close = Vec::new();

        for (&conn_id, conn) in self.connections.iter_mut() {
            match conn.stream.read(buf) {
                Ok(0) => {
                    // Peer closed connection
                    debug!("Peer closed conn_id={}", conn_id);
                    to_close.push(conn_id);
                }
                Ok(n) => {
                    let msg = channel::encode_tcp_data(conn_id, &buf[..n]);
                    self.data_tx.send(&msg);
                    conn.last_activity = Instant::now();
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

    /// Force-close any connection that has been idle for longer than
    /// `IDLE_TIMEOUT`. Belt-and-braces to TCP keepalive: catches stalled
    /// TLS handshakes and slow-loris peers where the kernel still considers
    /// the connection healthy. Notifies the enclave so its rustls state
    /// is freed too.
    fn reap_idle_connections(&mut self) {
        let now = Instant::now();
        let stale: Vec<u32> = self
            .connections
            .iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) >= IDLE_TIMEOUT)
            .map(|(&id, _)| id)
            .collect();
        if stale.is_empty() {
            return;
        }
        warn!(
            "Reaping {} idle connection(s) (idle ≥ {}s, active={})",
            stale.len(),
            IDLE_TIMEOUT.as_secs(),
            self.connections.len()
        );
        for conn_id in stale {
            self.connections.remove(&conn_id);
            let msg = channel::encode_tcp_close(conn_id);
            self.data_tx.send(&msg);
        }
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
                            // Also cancels a connect still in progress.
                            self.pending_connects.remove(&conn_id);
                        }
                        Some((ChannelMsgType::TcpConnect, conn_id, payload)) => {
                            match core::str::from_utf8(payload) {
                                Ok(addr) => self.start_outbound_connect(conn_id, addr),
                                Err(_) => {
                                    warn!(
                                        "TcpConnect conn_id={} with non-UTF-8 address",
                                        conn_id
                                    );
                                    self.data_tx.send(&channel::encode_tcp_close(conn_id));
                                }
                            }
                        }
                        Some((ChannelMsgType::TcpNew, conn_id, _))
                        | Some((ChannelMsgType::TcpConnected, conn_id, _)) => {
                            // Host-bound only in the other direction — ignore
                            warn!(
                                "Unexpected host-bound message from enclave for conn_id={}",
                                conn_id
                            );
                        }
                        Some((ChannelMsgType::DataReady, _, _)) => {
                            info!("Enclave data channel ready — accepting connections");
                            self.ready = true;
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
    /// Data for an outbound connection still connecting is buffered.
    fn write_to_socket(&mut self, conn_id: u32, data: &[u8]) {
        if let Some(pending) = self.pending_connects.get_mut(&conn_id) {
            if pending.buffered_len + data.len() > MAX_PENDING_WRITE {
                warn!(
                    "Pre-connect buffer overflow on conn_id={}, dropping connection",
                    conn_id
                );
                self.pending_connects.remove(&conn_id);
                self.data_tx.send(&channel::encode_tcp_close(conn_id));
                return;
            }
            pending.buffered_len += data.len();
            pending.buffered.push(data.to_vec());
            return;
        }
        if let Some(conn) = self.connections.get_mut(&conn_id) {
            // Write all data (may need multiple writes for large payloads)
            let mut offset = 0;
            while offset < data.len() {
                match conn.stream.write(&data[offset..]) {
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
            conn.last_activity = Instant::now();
        } else {
            debug!("Write to unknown conn_id={}, ignoring", conn_id);
        }
    }
}

/// Enable TCP keepalive on a stream with our standard parameters.
/// Uses `socket2` for portable access to `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/
/// `TCP_KEEPCNT` (the std lib's `TcpKeepalive` only exposes `time`).
fn enable_keepalive(stream: &TcpStream) -> io::Result<()> {
    use socket2::{SockRef, TcpKeepalive};
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    sock.set_tcp_keepalive(&ka)
}
