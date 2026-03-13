// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/https@0.1.0` — Secure HTTPS egress from WASM apps.
//!
//! TLS terminates **inside the enclave** using `rustls` + `ring`.
//! The host only transports encrypted bytes via OCALLs.
//!
//! This reuses the same TLS stack as the enclave's native HTTPS egress
//! ([`enclave_os_egress`]), but exposed via a
//! Component Model interface so WASM apps never need their own TLS.
//!
//! ## Typed bindings
//!
//! Uses wasmtime's `func_wrap` API instead of the dynamic `func_new` / `Val`
//! API. This maps Component Model `list<u8>` directly to `Vec<u8>` via the
//! canonical ABI — no per-byte `Val::U8` wrapping (which previously caused
//! a ~24× memory amplification and OOM on large HTTPS responses).
//!
//! ## Security properties
//!
//! - Host **never** sees request or response plaintext
//! - TLS 1.3 (preferred) or TLS 1.2
//! - Trust anchors: Mozilla root CA bundle (`webpki-roots`)
//! - Certificate validation inside SGX enclave

use std::string::String;
use std::sync::{Arc, LazyLock};
use std::vec::Vec;
use std::io::{Read, Write};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use super::AppContext;

/// Maximum HTTP response body size (2 MiB).
///
/// With typed bindings (`func_wrap`) there is no per-byte `Val` overhead,
/// so this cap exists purely as a safety net to prevent a single response
/// from dominating the enclave heap.
const MAX_RESPONSE_BODY: usize = 2 * 1024 * 1024;

/// Shared TLS client configuration (Mozilla root CAs, TLS 1.3/1.2).
///
/// Building a `RootCertStore` with ~150 root CAs is expensive;
/// caching the `ClientConfig` saves ~200 KiB + CPU per fetch call.
static TLS_CLIENT_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS config")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
});

// =========================================================================
//  privasys:enclave-os/https@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/https@0.1.0")?;

    // ── fetch ──────────────────────────────────────────────────────
    // func(method: u32, url: string, headers: list<tuple<string,string>>,
    //       body: option<list<u8>>)
    //      -> result<tuple<u16, list<tuple<string,string>>, list<u8>>, string>
    //
    //   method: 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=PATCH, 5=HEAD, 6=OPTIONS
    //
    // Uses `func_wrap` (typed bindings) so `list<u8>` maps to `Vec<u8>`
    // directly via the canonical ABI — no per-byte `Val::U8` wrapping.
    inst.func_wrap(
        "fetch",
        |_store: StoreContextMut<'_, AppContext>,
         (method, url, headers, body): (
            u32,
            String,
            Vec<(String, String)>,
            Option<Vec<u8>>,
        )|
         -> wasmtime::Result<(
            Result<(u16, Vec<(String, String)>, Vec<u8>), String>,
        )> {
            let method_str = match method {
                0 => "GET",
                1 => "POST",
                2 => "PUT",
                3 => "DELETE",
                4 => "PATCH",
                5 => "HEAD",
                6 => "OPTIONS",
                _ => return Ok((Err("unsupported HTTP method".into()),)),
            };

            Ok((do_https_fetch(method_str, &url, &headers, body.as_deref()),))
        },
    )?;

    Ok(())
}

// =========================================================================
//  Core HTTPS implementation (reuses enclave TLS stack)
// =========================================================================

fn do_https_fetch(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let (host, port, path) = parse_url(url).map_err(|e| e.to_string())?;

    // Build HTTP/1.1 request.
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, path, host
    );
    for (k, v) in headers {
        request.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            request.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
    }
    request.push_str("\r\n");

    let mut request_bytes = request.into_bytes();
    if let Some(b) = body {
        request_bytes.extend_from_slice(b);
    }

    // Reuse cached TLS config (Mozilla root CAs).
    let tls_config = TLS_CLIENT_CONFIG.clone();

    // TCP connect via OCALL.
    let fd = enclave_os_common::ocall::net_tcp_connect(&host, port)
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    // TLS handshake.
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| "invalid server name")?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name.to_owned())
        .map_err(|e| format!("TLS init failed: {}", e))?;

    tls_handshake(fd, &mut tls_conn)
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    // Send request.
    {
        let mut writer = tls_conn.writer();
        writer.write_all(&request_bytes).map_err(|_| "write failed")?;
    }
    flush_tls(fd, &mut tls_conn).map_err(|_| "flush failed")?;

    // Read response (capped at MAX_RESPONSE_BODY to prevent OOM).
    let mut response_data = Vec::new();
    let mut net_buf = vec![0u8; 16384];
    let mut app_buf = vec![0u8; 16384];
    let mut body_limit_hit = false;
    loop {
        match enclave_os_common::ocall::net_recv(fd, &mut net_buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&net_buf[..n]);
                while (cursor.position() as usize) < n {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn
                                .process_new_packets()
                                .map_err(|e| format!("TLS error: {:?}", e))?;
                        }
                        Err(e) => return Err(format!("read_tls error: {:?}", e)),
                    }
                }

                // Drain all available application data.
                loop {
                    match tls_conn.reader().read(&mut app_buf) {
                        Ok(0) => break,
                        Ok(m) => {
                            response_data.extend_from_slice(&app_buf[..m]);
                            if response_data.len() > MAX_RESPONSE_BODY + 16384 {
                                // Stop reading to keep memory bounded; we'll
                                // truncate the body below after header parsing.
                                body_limit_hit = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                if body_limit_hit {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Close.
    tls_conn.send_close_notify();
    let _ = flush_tls(fd, &mut tls_conn);
    enclave_os_common::ocall::net_close(fd);

    // Parse HTTP response (body truncated to MAX_RESPONSE_BODY).
    let (status, resp_headers, mut resp_body) = parse_http_response(&response_data)?;
    if resp_body.len() > MAX_RESPONSE_BODY {
        resp_body.truncate(MAX_RESPONSE_BODY);
    }
    Ok((status, resp_headers, resp_body))
}

// =========================================================================
//  TLS helpers (same pattern as enclave-os-egress)
// =========================================================================

fn tls_handshake(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    loop {
        // Flush any pending outbound TLS data (e.g. ClientHello, Finished).
        flush_tls(fd, tls_conn)?;

        // In TLS 1.3 the handshake completes as soon as the client Finished
        // is flushed — there is nothing more to receive.  Checking *after*
        // flush avoids a blocking recv on an idle socket.
        if !tls_conn.is_handshaking() {
            return Ok(());
        }

        // Read the next chunk of TLS handshake data from the server.
        let mut buf = vec![0u8; 16384];
        match enclave_os_common::ocall::net_recv(fd, &mut buf) {
            Ok(n) if n > 0 => {
                let mut cursor = std::io::Cursor::new(&buf[..n]);
                while (cursor.position() as usize) < n {
                    match tls_conn.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {
                            tls_conn.process_new_packets().map_err(|_| -1i32)?;
                        }
                        Err(_) => return Err(-1i32),
                    }
                }
            }
            Ok(_) => {
                // EOF — server closed before handshake completed.
                return Err(-1i32);
            }
            Err(_) => {
                // Read error.
                return Err(-1i32);
            }
        }
    }
}

fn flush_tls(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    let mut buf = vec![0u8; 16384];
    loop {
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        match tls_conn.write_tls(&mut cursor) {
            Ok(0) => break,
            Ok(n) => {
                let data = &buf[..n];
                let mut offset = 0;
                while offset < data.len() {
                    match enclave_os_common::ocall::net_send(fd, &data[offset..]) {
                        Ok(sent) => offset += sent,
                        Err(_) => return Err(-1),
                    }
                }
            }
            Err(_) => return Err(-1),
        }
    }
    Ok(())
}

// =========================================================================
//  HTTP parsing
// =========================================================================

fn parse_url(url: &str) -> Result<(String, u16, String), &'static str> {
    let url = url.trim();
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        return Err("only https:// URLs are supported");
    };

    let default_port: u16 = 443;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let port: u16 = host_port[i + 1..]
                .parse()
                .map_err(|_| "invalid port")?;
            (&host_port[..i], port)
        }
        None => (host_port, default_port),
    };

    Ok((host.to_string(), port, path.to_string()))
}

fn parse_http_response(
    data: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    // Find header/body separator.
    let sep = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid HTTP response: no header terminator")?;

    let header_bytes = &data[..sep];
    let body = data[sep + 4..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "invalid HTTP response: non-UTF-8 headers")?;

    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or("empty HTTP response")?;

    // Parse "HTTP/1.1 200 OK"
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("invalid status line")?
        .parse()
        .map_err(|_| "invalid status code")?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    Ok((status, headers, body))
}


