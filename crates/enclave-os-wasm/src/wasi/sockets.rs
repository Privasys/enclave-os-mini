// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `wasi:sockets/{network,instance-network,tcp,tcp-create-socket}@0.2.3`
//!
//! TCP sockets backed by enclave OS OCALLs.  The host performs the actual
//! `socket()` / `bind()` / `listen()` / `accept()` / `connect()` kernel
//! calls and returns file descriptors that the enclave tracks.
//!
//! ## Design
//!
//! The WASI sockets interface uses a two-phase pattern:
//! - `start-connect` / `finish-connect`
//! - `start-bind` / `finish-bind` + `start-listen` / `finish-listen`
//!
//! Our synchronous model performs the work in the `start-*` phase and
//! the `finish-*` phase is a no-op that returns success.
//!
//! ## Streams
//!
//! After connecting or accepting, the caller receives an
//! `(input-stream, output-stream)` pair.  These are backed by the
//! socket fd through the enclave OS network OCALLs.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::{Linker, Resource, ResourceType, Val};
use wasmtime::StoreContextMut;

use super::{
    AppContext, InputStreamKind, InputStreamRes, NetworkRes,
    OutputStreamKind, OutputStreamRes, TcpSocketRes, TcpSocketState,
};

// =========================================================================
//  wasi:sockets/network@0.2.3
// =========================================================================

fn add_network(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:sockets/network@0.2.3")?;

    // resource: network
    inst.resource(
        "network",
        ResourceType::host::<NetworkRes>(),
        |_store, _rep| Ok(()),
    )?;

    Ok(())
}

// =========================================================================
//  wasi:sockets/instance-network@0.2.3
// =========================================================================

fn add_instance_network(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:sockets/instance-network@0.2.3")?;

    // instance-network: func() -> network
    inst.func_wrap(
        "instance-network",
        |mut store: StoreContextMut<'_, AppContext>, _params: ()| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<NetworkRes>::new_own(rep),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:sockets/tcp-create-socket@0.2.3
// =========================================================================

fn add_tcp_create_socket(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:sockets/tcp-create-socket@0.2.3")?;

    // create-tcp-socket: func(address-family: ip-address-family) -> result<tcp-socket, error-code>
    //
    // ip-address-family is an enum { ipv4, ipv6 }
    // error-code is an enum with ~40 cases
    //
    // We use func_new for the complex return type.
    inst.func_new(
        "create-tcp-socket",
        |mut store: StoreContextMut<'_, AppContext>,
         _params: &[Val],
         results: &mut [Val]| {
            let rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .tcp_sockets
                .insert(rep, TcpSocketState::new());

            let resource = Resource::<TcpSocketRes>::new_own(rep);
            // result<tcp-socket, error-code> → ok(resource)
            // We use try_from_resource to convert to ResourceAny.
            let any = wasmtime::component::ResourceAny::try_from_resource(resource, &mut store)?;
            results[0] = Val::Result(Ok(Some(Box::new(Val::Resource(any)))));
            Ok(())
        },
    )?;

    Ok(())
}

// =========================================================================
//  wasi:sockets/tcp@0.2.3
// =========================================================================

fn add_tcp(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("wasi:sockets/tcp@0.2.3")?;

    // ── resource: tcp-socket ───────────────────────────────────────
    inst.resource(
        "tcp-socket",
        ResourceType::host::<TcpSocketRes>(),
        |mut store, rep| {
            if let Some(sock) = store.data_mut().tcp_sockets.remove(&rep) {
                if let Some(fd) = sock.fd {
                    enclave_os_enclave::ocall::net_close(fd);
                }
            }
            Ok(())
        },
    )?;

    // ── start-bind ─────────────────────────────────────────────────
    // func(self: borrow<tcp-socket>, network: borrow<network>,
    //       local-address: ip-socket-address) -> result<_, error-code>
    inst.func_new(
        "[method]tcp-socket.start-bind",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            // params[1] = network (ignored — we have one implicit network)
            let port = extract_port_from_address(&params[2]);

            let fd = match enclave_os_enclave::ocall::net_tcp_listen(port, 128) {
                Ok(fd) => fd,
                Err(_) => {
                    results[0] = error_code_result(7); // address-in-use
                    return Ok(());
                }
            };

            if let Some(sock) = store.data_mut().tcp_sockets.get_mut(&sock_rep) {
                sock.fd = Some(fd);
                sock.bound = true;
                sock.local_port = port;
            }

            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── finish-bind ────────────────────────────────────────────────
    inst.func_new(
        "[method]tcp-socket.finish-bind",
        |_store: StoreContextMut<'_, AppContext>,
         _params: &[Val],
         results: &mut [Val]| {
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── start-connect ──────────────────────────────────────────────
    // func(self, network, remote-address: ip-socket-address) -> result<_, error-code>
    inst.func_new(
        "[method]tcp-socket.start-connect",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            // params[1] = network
            let (host, port) = extract_host_port_from_address(&params[2]);

            let fd = match enclave_os_enclave::ocall::net_tcp_connect(&host, port) {
                Ok(fd) => fd,
                Err(_) => {
                    results[0] = error_code_result(13); // connection-refused
                    return Ok(());
                }
            };

            if let Some(sock) = store.data_mut().tcp_sockets.get_mut(&sock_rep) {
                sock.fd = Some(fd);
                sock.connected = true;
                sock.remote_host = host;
                sock.remote_port = port;
            }

            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── finish-connect ─────────────────────────────────────────────
    // Returns result<tuple<input-stream, output-stream>, error-code>
    inst.func_new(
        "[method]tcp-socket.finish-connect",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            let fd = match store.data().tcp_sockets.get(&sock_rep) {
                Some(s) if s.connected => match s.fd {
                    Some(fd) => fd,
                    None => {
                        results[0] = error_code_result(0); // unknown
                        return Ok(());
                    }
                },
                _ => {
                    results[0] = error_code_result(14); // not-connected
                    return Ok(());
                }
            };

            // Create input + output streams for this socket.
            let in_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .input_streams
                .insert(in_rep, InputStreamKind::TcpSocket(fd));
            let in_res = Resource::<InputStreamRes>::new_own(in_rep);
            let in_any =
                wasmtime::component::ResourceAny::try_from_resource(in_res, &mut store)?;

            let out_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(out_rep, OutputStreamKind::TcpSocket(fd));
            let out_res = Resource::<OutputStreamRes>::new_own(out_rep);
            let out_any =
                wasmtime::component::ResourceAny::try_from_resource(out_res, &mut store)?;

            // result<tuple<input-stream, output-stream>, error-code>
            results[0] = Val::Result(Ok(Some(Box::new(Val::Tuple(
                vec![Val::Resource(in_any), Val::Resource(out_any)].into(),
            )))));
            Ok(())
        },
    )?;

    // ── start-listen ───────────────────────────────────────────────
    inst.func_new(
        "[method]tcp-socket.start-listen",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            if let Some(sock) = store.data_mut().tcp_sockets.get_mut(&sock_rep) {
                sock.listening = true;
            }
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── finish-listen ──────────────────────────────────────────────
    inst.func_new(
        "[method]tcp-socket.finish-listen",
        |_store: StoreContextMut<'_, AppContext>,
         _params: &[Val],
         results: &mut [Val]| {
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── accept ─────────────────────────────────────────────────────
    // func(self) -> result<tuple<tcp-socket, input-stream, output-stream>, error-code>
    inst.func_new(
        "[method]tcp-socket.accept",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            let listener_fd = match store.data().tcp_sockets.get(&sock_rep) {
                Some(s) if s.listening => match s.fd {
                    Some(fd) => fd,
                    None => {
                        results[0] = error_code_result(0);
                        return Ok(());
                    }
                },
                _ => {
                    results[0] = error_code_result(14);
                    return Ok(());
                }
            };

            let (client_fd, _peer_addr) =
                match enclave_os_enclave::ocall::net_tcp_accept(listener_fd) {
                    Ok(pair) => pair,
                    Err(_) => {
                        results[0] = error_code_result(0);
                        return Ok(());
                    }
                };

            // Create a new tcp-socket resource for the accepted connection.
            let new_sock_rep = store.data_mut().alloc_rep();
            let mut new_state = TcpSocketState::new();
            new_state.fd = Some(client_fd);
            new_state.connected = true;
            store
                .data_mut()
                .tcp_sockets
                .insert(new_sock_rep, new_state);
            let sock_res = Resource::<TcpSocketRes>::new_own(new_sock_rep);
            let sock_any =
                wasmtime::component::ResourceAny::try_from_resource(sock_res, &mut store)?;

            // Create streams for the accepted socket.
            let in_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .input_streams
                .insert(in_rep, InputStreamKind::TcpSocket(client_fd));
            let in_res = Resource::<InputStreamRes>::new_own(in_rep);
            let in_any =
                wasmtime::component::ResourceAny::try_from_resource(in_res, &mut store)?;

            let out_rep = store.data_mut().alloc_rep();
            store
                .data_mut()
                .output_streams
                .insert(out_rep, OutputStreamKind::TcpSocket(client_fd));
            let out_res = Resource::<OutputStreamRes>::new_own(out_rep);
            let out_any =
                wasmtime::component::ResourceAny::try_from_resource(out_res, &mut store)?;

            results[0] = Val::Result(Ok(Some(Box::new(Val::Tuple(
                vec![
                    Val::Resource(sock_any),
                    Val::Resource(in_any),
                    Val::Resource(out_any),
                ]
                .into(),
            )))));
            Ok(())
        },
    )?;

    // ── shutdown ───────────────────────────────────────────────────
    // func(self, shutdown-type: shutdown-type) -> result<_, error-code>
    inst.func_new(
        "[method]tcp-socket.shutdown",
        |mut store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            if let Some(sock) = store.data_mut().tcp_sockets.get_mut(&sock_rep) {
                if let Some(fd) = sock.fd.take() {
                    enclave_os_enclave::ocall::net_close(fd);
                }
                sock.connected = false;
            }
            results[0] = Val::Result(Ok(None));
            Ok(())
        },
    )?;

    // ── local-address ──────────────────────────────────────────────
    // func(self) -> result<ip-socket-address, error-code>
    inst.func_new(
        "[method]tcp-socket.local-address",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            let port = store
                .data()
                .tcp_sockets
                .get(&sock_rep)
                .map(|s| s.local_port)
                .unwrap_or(0);
            // Return ipv4 0.0.0.0:<port> as a simplified address.
            results[0] = Val::Result(Ok(Some(Box::new(make_ipv4_address(0, 0, 0, 0, port)))));
            Ok(())
        },
    )?;

    // ── remote-address ─────────────────────────────────────────────
    inst.func_new(
        "[method]tcp-socket.remote-address",
        |store: StoreContextMut<'_, AppContext>,
         params: &[Val],
         results: &mut [Val]| {
            let sock_rep = io_rep(&params[0])?;
            let port = store
                .data()
                .tcp_sockets
                .get(&sock_rep)
                .map(|s| s.remote_port)
                .unwrap_or(0);
            results[0] = Val::Result(Ok(Some(Box::new(make_ipv4_address(0, 0, 0, 0, port)))));
            Ok(())
        },
    )?;

    // ── subscribe ──────────────────────────────────────────────────
    inst.func_wrap(
        "[method]tcp-socket.subscribe",
        |mut store: StoreContextMut<'_, AppContext>,
         (_self,): (Resource<TcpSocketRes>,)| {
            let rep = store.data_mut().alloc_rep();
            Ok((Resource::<super::PollableRes>::new_own(rep),))
        },
    )?;

    // ── Stubs for optional methods ─────────────────────────────────
    // These are present in the WIT but rarely used by basic apps.
    for method in &[
        "[method]tcp-socket.is-listening",
        "[method]tcp-socket.address-family",
        "[method]tcp-socket.set-listen-backlog-size",
        "[method]tcp-socket.keep-alive-enabled",
        "[method]tcp-socket.set-keep-alive-enabled",
        "[method]tcp-socket.keep-alive-idle-time",
        "[method]tcp-socket.set-keep-alive-idle-time",
        "[method]tcp-socket.keep-alive-interval",
        "[method]tcp-socket.set-keep-alive-interval",
        "[method]tcp-socket.keep-alive-count",
        "[method]tcp-socket.set-keep-alive-count",
        "[method]tcp-socket.hop-limit",
        "[method]tcp-socket.set-hop-limit",
        "[method]tcp-socket.receive-buffer-size",
        "[method]tcp-socket.set-receive-buffer-size",
        "[method]tcp-socket.send-buffer-size",
        "[method]tcp-socket.set-send-buffer-size",
    ] {
        let name = method.to_string();
        inst.func_new(
            &name,
            |_store: StoreContextMut<'_, AppContext>,
             _params: &[Val],
             results: &mut [Val]| {
                // Return a reasonable default or ok(()).
                // Most of these return result<T, error-code>.
                if !results.is_empty() {
                    results[0] = Val::Result(Err(Some(Box::new(
                        Val::Enum(0), // error-code::unknown
                    ))));
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

// =========================================================================
//  Top-level linker registration
// =========================================================================

/// Register all `wasi:sockets/*` interfaces in the linker.
pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    add_network(linker)?;
    add_instance_network(linker)?;
    add_tcp_create_socket(linker)?;
    add_tcp(linker)?;
    Ok(())
}

// =========================================================================
//  Helpers
// =========================================================================

/// Extract resource rep from a Val.
fn io_rep(val: &Val) -> Result<u32, wasmtime::Error> {
    match val {
        Val::Resource(any) => Ok(any.rep()),
        _ => Err(wasmtime::Error::msg("expected resource")),
    }
}

/// Build a `result<_, error-code>` error value.
///
/// `error-code` is an enum with many cases; the discriminant maps to
/// the case index (0 = unknown, 7 = address-in-use, 13 = connection-refused, etc.).
fn error_code_result(code: u32) -> Val {
    Val::Result(Err(Some(Box::new(Val::Enum(code)))))
}

/// Extract port from a `Val` representing `ip-socket-address`.
///
/// ip-socket-address is a variant { ipv4(ipv4-socket-address), ipv6(ipv6-socket-address) }.
/// ipv4-socket-address is a record { port: u16, address: tuple<u8,u8,u8,u8> }.
///
/// For simplicity, we extract the port from whatever variant is present.
fn extract_port_from_address(val: &Val) -> u16 {
    // Try to walk the variant → record → port field.
    if let Val::Variant(_disc, Some(inner)) = val {
        if let Val::Record(fields) = inner.as_ref() {
            for (name, field_val) in fields.iter() {
                if name.as_ref() == "port" {
                    if let Val::U16(p) = field_val {
                        return *p;
                    }
                }
            }
        }
    }
    0
}

/// Extract (host, port) from an ip-socket-address for connect.
fn extract_host_port_from_address(val: &Val) -> (String, u16) {
    let mut host = String::from("127.0.0.1");
    let mut port: u16 = 0;

    if let Val::Variant(disc, Some(inner)) = val {
        if let Val::Record(fields) = inner.as_ref() {
            for (name, field_val) in fields.iter() {
                if name.as_ref() == "port" {
                    if let Val::U16(p) = field_val {
                        port = *p;
                    }
                }
                if name.as_ref() == "address" {
                    if *disc == 0 {
                        // ipv4 — tuple<u8,u8,u8,u8>
                        if let Val::Tuple(parts) = field_val {
                            let octets: Vec<u8> = parts
                                .iter()
                                .filter_map(|v| match v {
                                    Val::U8(b) => Some(*b),
                                    _ => None,
                                })
                                .collect();
                            if octets.len() == 4 {
                                host = format!(
                                    "{}.{}.{}.{}",
                                    octets[0], octets[1], octets[2], octets[3]
                                );
                            }
                        }
                    }
                    // ipv6 — not fully implemented yet
                }
            }
        }
    }
    (host, port)
}

/// Construct an `ip-socket-address` variant for ipv4.
fn make_ipv4_address(a: u8, b: u8, c: u8, d: u8, port: u16) -> Val {
    // variant case 0 = ipv4
    Val::Variant(
        0,
        Some(Box::new(Val::Record(
            vec![
                (
                    "port".into(),
                    Val::U16(port),
                ),
                (
                    "address".into(),
                    Val::Tuple(vec![Val::U8(a), Val::U8(b), Val::U8(c), Val::U8(d)].into()),
                ),
            ]
            .into(),
        ))),
    )
}
