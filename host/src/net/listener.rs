// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side TCP socket management.
//!
//! Maintains a table of open file descriptors so the enclave can reference
//! sockets by integer handles through OCALLs.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
//  Global socket table
// ---------------------------------------------------------------------------

static SOCKET_TABLE: std::sync::LazyLock<Mutex<SocketTable>> =
    std::sync::LazyLock::new(|| Mutex::new(SocketTable::new()));

struct SocketTable {
    next_fd: i32,
    listeners: HashMap<i32, TcpListener>,
    streams: HashMap<i32, TcpStream>,
}

impl SocketTable {
    fn new() -> Self {
        Self {
            next_fd: 100, // start above stdin/stdout/stderr range
            listeners: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    fn alloc_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }
}

// ---------------------------------------------------------------------------
//  Public API (called from OCall implementations)
// ---------------------------------------------------------------------------

/// Create a TCP listener socket, bind to `0.0.0.0:port`, and listen.
pub fn tcp_listen(port: u16, _backlog: i32) -> Result<i32> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let listener = TcpListener::bind(addr)
        .with_context(|| format!("Failed to bind to {}", addr))?;

    // Set non-blocking so the enclave poll loop doesn't block forever
    listener.set_nonblocking(true)?;

    let mut table = SOCKET_TABLE.lock().unwrap();
    let fd = table.alloc_fd();
    table.listeners.insert(fd, listener);
    Ok(fd)
}

/// Accept an incoming connection on a listener.
pub fn tcp_accept(listener_fd: i32) -> Result<(i32, String)> {
    let mut table = SOCKET_TABLE.lock().unwrap();
    let listener = table.listeners.get(&listener_fd)
        .ok_or_else(|| anyhow::anyhow!("Invalid listener fd {}", listener_fd))?;

    let (stream, peer_addr) = listener.accept()
        .with_context(|| "accept() failed")?;

    stream.set_nonblocking(true)?;

    let addr_str = peer_addr.to_string();
    let fd = table.alloc_fd();
    table.streams.insert(fd, stream);
    Ok((fd, addr_str))
}

/// Connect to a remote TCP endpoint.
pub fn tcp_connect(host: &str, port: u16) -> Result<i32> {
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr)
        .with_context(|| format!("Failed to connect to {}", addr))?;

    let mut table = SOCKET_TABLE.lock().unwrap();
    let fd = table.alloc_fd();
    table.streams.insert(fd, stream);
    Ok(fd)
}

/// Send data on a connected socket.
pub fn tcp_send(fd: i32, data: &[u8]) -> Result<usize> {
    let mut table = SOCKET_TABLE.lock().unwrap();
    let stream = table.streams.get_mut(&fd)
        .ok_or_else(|| anyhow::anyhow!("Invalid stream fd {}", fd))?;
    let n = stream.write(data)?;
    Ok(n)
}

/// Receive data from a connected socket.
pub fn tcp_recv(fd: i32, buf: &mut [u8]) -> Result<usize> {
    let mut table = SOCKET_TABLE.lock().unwrap();
    let stream = table.streams.get_mut(&fd)
        .ok_or_else(|| anyhow::anyhow!("Invalid stream fd {}", fd))?;
    let n = stream.read(buf)?;
    Ok(n)
}

/// Close a socket (listener or stream).
pub fn tcp_close(fd: i32) {
    let mut table = SOCKET_TABLE.lock().unwrap();
    table.listeners.remove(&fd);
    table.streams.remove(&fd);
    // Rust's Drop will close the underlying OS socket
}
