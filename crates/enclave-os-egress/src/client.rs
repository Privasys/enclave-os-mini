// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HTTPS egress client – makes outbound HTTPS requests from inside the enclave.
//!
//! Uses rustls for TLS and a minimal HTTP/1.1 implementation. Network I/O
//! flows through OCALLs to the host, but the TLS termination happens inside
//! the enclave, so the host never sees plaintext.

use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use enclave_os_enclave::ocall;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// Perform an HTTPS GET request.
///
/// Requires a `RootCertStore` containing trusted root CAs.
pub fn https_get(url: &str, root_store: &RootCertStore) -> Result<Vec<u8>, i32> {
    let (host, port, path) = parse_url(url).map_err(|_| -1)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path, host
    );
    https_request(&host, port, request.as_bytes(), root_store)
}

/// Perform an HTTPS POST request.
pub fn https_post(url: &str, body: &[u8], content_type: &str, root_store: &RootCertStore) -> Result<Vec<u8>, i32> {
    let (host, port, path) = parse_url(url).map_err(|_| -1)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        path, host, content_type, body.len()
    );
    let mut full_request = request.into_bytes();
    full_request.extend_from_slice(body);
    https_request(&host, port, &full_request, root_store)
}

/// Internal: perform an HTTPS request and return the response body.
fn https_request(host: &str, port: u16, request: &[u8], root_store: &RootCertStore) -> Result<Vec<u8>, i32> {
    // Build TLS client config with provided root CAs
    let tls_config = build_client_config(root_store).map_err(|_| -1)?;

    // Connect to the remote server via OCALL
    let fd = ocall::net_tcp_connect(host, port)?;

    // Create TLS client connection
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| -1i32)?;
    let mut tls_conn = ClientConnection::new(tls_config, server_name.to_owned())
        .map_err(|_| -1i32)?;

    // Perform TLS handshake
    tls_handshake(fd, &mut tls_conn)?;

    // Send the HTTP request through TLS
    {
        let mut writer = tls_conn.writer();
        use std::io::Write;
        writer.write_all(request).map_err(|_| -1i32)?;
    }
    flush_tls(fd, &mut tls_conn)?;

    // Read the complete response
    let mut response_data = Vec::new();
    loop {
        // Read from network into TLS
        let mut net_buf = vec![0u8; 16384];
        match ocall::net_recv(fd, &mut net_buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&net_buf[..n]);
                tls_conn.read_tls(&mut cursor).map_err(|_| -1i32)?;
                tls_conn.process_new_packets().map_err(|_| -1i32)?;
            }
            Err(_) => break,
        }

        // Read decrypted data
        let mut app_buf = vec![0u8; 16384];
        let mut reader = tls_conn.reader();
        use std::io::Read;
        match reader.read(&mut app_buf) {
            Ok(0) => break,
            Ok(n) => response_data.extend_from_slice(&app_buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }

    // Close
    tls_conn.send_close_notify();
    let _ = flush_tls(fd, &mut tls_conn);
    ocall::net_close(fd);

    // Parse HTTP response – extract body after \r\n\r\n
    let body = extract_http_body(&response_data);
    Ok(body)
}

/// Build a rustls ClientConfig using the provided root CAs.
fn build_client_config(root_store: &RootCertStore) -> Result<Arc<ClientConfig>, &'static str> {
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "TLS config error")?
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Perform the TLS handshake.
fn tls_handshake(fd: i32, tls_conn: &mut ClientConnection) -> Result<(), i32> {
    loop {
        if !tls_conn.is_handshaking() {
            flush_tls(fd, tls_conn)?;
            return Ok(());
        }

        flush_tls(fd, tls_conn)?;

        let mut buf = vec![0u8; 16384];
        match ocall::net_recv(fd, &mut buf) {
            Ok(n) if n > 0 => {
                let mut cursor = std::io::Cursor::new(&buf[..n]);
                tls_conn.read_tls(&mut cursor).map_err(|_| -1i32)?;
                tls_conn.process_new_packets().map_err(|_| -1i32)?;
            }
            _ => {
                // Brief retry for non-blocking
                continue;
            }
        }
    }
}

/// Flush TLS output to the network via OCALL.
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
                    match ocall::net_send(fd, &data[offset..]) {
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

/// Parse a URL into (host, port, path).
fn parse_url(url: &str) -> Result<(String, u16, String), &'static str> {
    let url = url.trim();

    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err("Unsupported scheme");
    };

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let port_str = &host_port[i + 1..];
            let port: u16 = port_str.parse().map_err(|_| "Invalid port")?;
            (&host_port[..i], port)
        }
        None => (host_port, default_port),
    };

    Ok((String::from(host), port, String::from(path)))
}

/// Extract the HTTP body from a raw HTTP response.
fn extract_http_body(response: &[u8]) -> Vec<u8> {
    // Find \r\n\r\n separator
    for i in 0..response.len().saturating_sub(3) {
        if &response[i..i + 4] == b"\r\n\r\n" {
            return response[i + 4..].to_vec();
        }
    }
    // No separator found — return entire response
    response.to_vec()
}
