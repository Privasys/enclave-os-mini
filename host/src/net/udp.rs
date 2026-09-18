// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side UDP socket management.
//!
//! Generic datagram sockets for the enclave (bind, send_to, recv_from with
//! a timeout, close). The enclave refers to sockets by integer handles,
//! drawn from their own range so a UDP handle is never mistaken for a TCP
//! one. Hostnames are resolved here, on the host: whatever travels over
//! these sockets must be authenticated end to end by the enclave.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

/// Longest a single `recv_from` may block the RPC dispatcher.
pub const MAX_UDP_TIMEOUT_MS: u32 = 10_000;

/// Largest datagram handed back to the enclave.
pub const MAX_UDP_DATAGRAM: u32 = 65_535;

static UDP_TABLE: std::sync::LazyLock<Mutex<UdpTable>> =
    std::sync::LazyLock::new(|| Mutex::new(UdpTable::new()));

struct UdpTable {
    next_fd: i32,
    sockets: HashMap<i32, UdpSocket>,
}

impl UdpTable {
    fn new() -> Self {
        Self {
            // Well clear of the TCP handles, which count up from 100.
            next_fd: 0x4000_0000,
            sockets: HashMap::new(),
        }
    }
}

fn socket(fd: i32) -> Result<UdpSocket> {
    let table = UDP_TABLE.lock().unwrap();
    let sock = table
        .sockets
        .get(&fd)
        .ok_or_else(|| anyhow::anyhow!("Invalid UDP fd {}", fd))?;
    // A clone, so a blocking receive does not hold the table lock.
    Ok(sock.try_clone()?)
}

/// Bind a UDP socket to `bind_addr:port` (`0.0.0.0` when empty; port 0
/// picks an ephemeral port).
pub fn udp_bind(bind_addr: &str, port: u16) -> Result<i32> {
    let host = if bind_addr.is_empty() { "0.0.0.0" } else { bind_addr };
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("Invalid UDP bind address {}:{}", host, port))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No address for {}:{}", host, port))?;
    let sock = UdpSocket::bind(addr).with_context(|| format!("Failed to bind UDP {}", addr))?;
    let mut table = UDP_TABLE.lock().unwrap();
    let fd = table.next_fd;
    table.next_fd += 1;
    table.sockets.insert(fd, sock);
    Ok(fd)
}

/// Send one datagram to `host:port`, resolved to the socket's address family.
pub fn udp_send_to(fd: i32, host: &str, port: u16, data: &[u8]) -> Result<usize> {
    let sock = socket(fd)?;
    let v6 = sock.local_addr()?.is_ipv6();
    let target: SocketAddr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}:{}", host, port))?
        .find(|a| a.is_ipv6() == v6)
        .ok_or_else(|| anyhow::anyhow!("No {} address for {}", if v6 { "IPv6" } else { "IPv4" }, host))?;
    Ok(sock.send_to(data, target)?)
}

/// Receive one datagram, waiting at most `timeout_ms` (capped at
/// [`MAX_UDP_TIMEOUT_MS`]). `Ok(None)` when nothing arrived in time.
pub fn udp_recv_from(fd: i32, max_len: u32, timeout_ms: u32) -> Result<Option<(Vec<u8>, SocketAddr)>> {
    let sock = socket(fd)?;
    let wait = timeout_ms.clamp(1, MAX_UDP_TIMEOUT_MS);
    sock.set_read_timeout(Some(Duration::from_millis(wait as u64)))?;
    let mut buf = vec![0u8; max_len.clamp(1, MAX_UDP_DATAGRAM) as usize];
    match sock.recv_from(&mut buf) {
        Ok((n, peer)) => {
            buf.truncate(n);
            Ok(Some((buf, peer)))
        }
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Close a UDP socket.
pub fn udp_close(fd: i32) {
    UDP_TABLE.lock().unwrap().sockets.remove(&fd);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_roundtrip_and_timeout() {
        let a = udp_bind("127.0.0.1", 0).unwrap();
        let b = udp_bind("127.0.0.1", 0).unwrap();
        assert_ne!(a, b);
        let b_port = socket(b).unwrap().local_addr().unwrap().port();

        assert_eq!(udp_send_to(a, "127.0.0.1", b_port, b"ping").unwrap(), 4);
        let (data, peer) = udp_recv_from(b, 1500, 2_000).unwrap().unwrap();
        assert_eq!(data, b"ping");
        assert_eq!(peer.port(), socket(a).unwrap().local_addr().unwrap().port());

        assert!(udp_recv_from(b, 1500, 50).unwrap().is_none());

        udp_close(a);
        udp_close(b);
        assert!(udp_send_to(a, "127.0.0.1", b_port, b"x").is_err());
    }
}
