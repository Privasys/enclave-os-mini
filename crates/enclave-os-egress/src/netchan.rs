// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Outbound TCP over the data channel, for code that can suspend.
//!
//! The host TCP proxy owns the socket and does its I/O without blocking the
//! enclave. The enclave sends `TcpConnect` and `TcpData`; the proxy answers
//! with `TcpConnected`, `TcpData` and `TcpClose`, which the event loop hands
//! to [`handle_message`]. A reader waiting in [`NetConn::recv`] is a pending
//! future: its task suspends, and the next message for its connection wakes
//! it. Connection ids come from the egress range
//! (`channel::CONN_ID_EGRESS_BASE..`).
//!
//! Only code driven by the event loop (a request task) may wait here: the
//! messages it waits for are only read by that loop. Elsewhere, use the
//! blocking RPC sockets (`ocall::net_*`).

use core::future::poll_fn;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Poll, Waker};

use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use enclave_os_common::channel::{self, ChannelMsgType, CONN_ID_EGRESS_BASE};
use enclave_os_common::queue::SpscProducer;

/// Producer end of the `data_enc_to_host` queue, set once the data channel
/// is up.
static DATA_TX: OnceLock<&'static SpscProducer> = OnceLock::new();

static CONNS: Mutex<BTreeMap<u32, Conn>> = Mutex::new(BTreeMap::new());

static NEXT_ID: AtomicU32 = AtomicU32::new(CONN_ID_EGRESS_BASE);

#[derive(Default)]
struct Conn {
    /// Bytes received and not yet read.
    rx: Vec<u8>,
    /// The proxy reported the connect succeeded (or sent data).
    connected: bool,
    /// The proxy closed the connection (or the connect failed).
    closed: bool,
    /// The task waiting to read.
    waker: Option<Waker>,
}

/// Enable data-channel sockets. Called by the enclave once the data channel
/// to the host proxy is ready.
pub fn init(data_tx: &'static SpscProducer) {
    let _ = DATA_TX.set(data_tx);
}

/// Whether data-channel sockets are available.
pub fn is_available() -> bool {
    DATA_TX.get().is_some()
}

/// Handle a data-channel message for an egress connection id. Called by the
/// enclave event loop.
pub fn handle_message(msg_type: ChannelMsgType, conn_id: u32, payload: &[u8]) {
    let mut conns = match CONNS.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(conn) = conns.get_mut(&conn_id) else {
        // Nobody reads this connection any more; let the proxy drop it.
        drop(conns);
        if msg_type != ChannelMsgType::TcpClose {
            send(&channel::encode_tcp_close(conn_id));
        }
        return;
    };
    match msg_type {
        ChannelMsgType::TcpConnected => conn.connected = true,
        ChannelMsgType::TcpData => {
            conn.connected = true;
            conn.rx.extend_from_slice(payload);
        }
        ChannelMsgType::TcpClose => conn.closed = true,
        _ => return,
    }
    if let Some(waker) = conn.waker.take() {
        waker.wake();
    }
}

fn send(msg: &[u8]) {
    if let Some(tx) = DATA_TX.get() {
        tx.send(msg);
    }
}

fn alloc_id(conns: &BTreeMap<u32, Conn>) -> u32 {
    loop {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if id < CONN_ID_EGRESS_BASE {
            // Wrapped past u32::MAX: restart at the bottom of the range.
            NEXT_ID.store(CONN_ID_EGRESS_BASE, Ordering::Relaxed);
            continue;
        }
        if !conns.contains_key(&id) {
            return id;
        }
    }
}

/// A TCP connection owned by the host proxy. Closed when dropped.
pub struct NetConn {
    id: u32,
}

impl NetConn {
    /// Ask the proxy to connect to `host:port`. Returns at once; the first
    /// [`NetConn::recv`] reports a failed connect. Data sent before the
    /// connect completes is buffered by the proxy.
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        if !is_available() {
            return Err("egress data channel not initialised".to_string());
        }
        let id = {
            let mut conns = CONNS.lock().map_err(|_| "egress connections lock poisoned")?;
            let id = alloc_id(&conns);
            conns.insert(id, Conn::default());
            id
        };
        send(&channel::encode_tcp_connect(id, &format!("{host}:{port}")));
        Ok(Self { id })
    }

    /// Send bytes on the connection.
    pub fn send(&self, data: &[u8]) -> Result<(), String> {
        let closed = CONNS
            .lock()
            .ok()
            .and_then(|conns| conns.get(&self.id).map(|c| c.closed))
            .unwrap_or(true);
        if closed {
            return Err("connection closed".to_string());
        }
        for chunk in data.chunks(channel::MAX_CHANNEL_PAYLOAD) {
            send(&channel::encode_tcp_data(self.id, chunk));
        }
        Ok(())
    }

    /// Read available bytes into `buf`, waiting until some arrive. Returns 0
    /// once the peer closed the connection.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        poll_fn(|cx| {
            let mut conns = match CONNS.lock() {
                Ok(c) => c,
                Err(_) => return Poll::Ready(Err("egress connections lock poisoned".to_string())),
            };
            let Some(conn) = conns.get_mut(&self.id) else {
                return Poll::Ready(Err("connection gone".to_string()));
            };
            if !conn.rx.is_empty() {
                let n = conn.rx.len().min(buf.len());
                buf[..n].copy_from_slice(&conn.rx[..n]);
                conn.rx.drain(..n);
                return Poll::Ready(Ok(n));
            }
            if conn.closed {
                return Poll::Ready(if conn.connected {
                    Ok(0)
                } else {
                    Err("connect failed".to_string())
                });
            }
            conn.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl Drop for NetConn {
    fn drop(&mut self) {
        let closed = CONNS
            .lock()
            .ok()
            .and_then(|mut conns| conns.remove(&self.id))
            .map(|c| c.closed)
            .unwrap_or(true);
        if !closed {
            send(&channel::encode_tcp_close(self.id));
        }
    }
}
