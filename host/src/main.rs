// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-host: the untrusted host application.
//!
//! Responsibilities:
//! - Load and manage the SGX enclave
//! - Allocate shared-memory SPSC queues for RPC
//! - Run the RPC dispatcher (reads enclave requests, dispatches to handlers)
//! - Implement the single OCALL: `ocall_notify()`
//! - Provide the CLI entry point

mod dispatcher;
mod enclave;
mod ocall_impl;
mod net;
mod kvstore;
mod tcp_proxy;
#[cfg(target_os = "linux")]
mod dcap;

use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use enclave::SharedChannel;
use enclave_os_common::queue::DEFAULT_QUEUE_CAPACITY;

#[derive(Parser, Debug)]
#[command(name = "enclave-os-host", about = "Host for enclave-os-mini SGX application")]
struct Cli {
    /// Path to the signed enclave binary (.signed.so)
    #[arg(short, long, default_value = "enclave.signed.so")]
    enclave_path: String,

    /// Port for the RA-TLS ingress server
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// TCP listen backlog
    #[arg(short, long, default_value_t = 128)]
    backlog: i32,

    /// Path for the KV store data directory
    #[arg(short, long, default_value = "./kvdata")]
    kv_path: String,

    /// Path to intermediary CA certificate (DER or PEM).
    /// Required on first run; sealed to disk for subsequent restarts.
    #[arg(long)]
    ca_cert: Option<String>,

    /// Path to intermediary CA private key (PKCS#8 DER or PEM).
    /// Required on first run; sealed to disk for subsequent restarts.
    #[arg(long)]
    ca_key: Option<String>,

    /// Path to a PEM bundle of trusted root CAs for HTTPS egress.
    /// e.g. /etc/ssl/certs/ca-certificates.crt or a custom bundle.
    /// If omitted, the enclave cannot make outbound HTTPS requests.
    #[arg(long)]
    egress_ca_bundle: Option<String>,

    /// Comma-separated list of attestation server URLs for remote quote
    /// verification.  e.g. "https://as.privasys.org/verify,https://as.customer.com/verify"
    /// The list is hashed into the config Merkle tree (leaf: egress.attestation_servers)
    /// and embedded as X.509 OID 1.3.6.1.4.1.65230.2.7.
    #[arg(long, value_delimiter = ',')]
    attestation_servers: Option<Vec<String>>,

    /// OIDC issuer URL (e.g. https://auth.privasys.org).
    /// When set (together with --oidc-audience), enables OIDC-based RBAC.
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// OIDC audience claim (e.g. the Zitadel project ID).
    /// Required when --oidc-issuer is set.
    #[arg(long)]
    oidc_audience: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logging
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();

    info!("enclave-os-host starting");
    info!("Enclave path : {}", cli.enclave_path);
    info!("RA-TLS port  : {}", cli.port);
    info!("KV store path: {}", cli.kv_path);

    // Initialise the KV store backend
    kvstore::init(&cli.kv_path)?;

    // Create the SGX enclave
    let enclave_id = enclave::create_enclave(&cli.enclave_path)?;
    info!("Enclave created, id = {}", enclave_id);

    // Allocate shared-memory SPSC queues for RPC channel
    let channel = SharedChannel::new(DEFAULT_QUEUE_CAPACITY);
    info!("RPC channel allocated (capacity = {} bytes per queue)", DEFAULT_QUEUE_CAPACITY);

    // Allocate shared-memory SPSC queues for data channel (TCP proxy ↔ enclave)
    let data_channel = SharedChannel::new(DEFAULT_QUEUE_CAPACITY);
    info!("Data channel allocated (capacity = {} bytes per queue)", DEFAULT_QUEUE_CAPACITY);

    // Pass RPC queue pointers to the enclave
    let ret = enclave::call_ecall_init_channel(
        enclave_id,
        channel.enc_to_host_header as *mut u8,
        channel.enc_to_host_buf,
        channel.host_to_enc_header as *mut u8,
        channel.host_to_enc_buf,
        channel.capacity,
    );
    if ret != 0 {
        error!("ecall_init_channel failed: {}", ret);
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave RPC channel");
    }
    info!("Enclave RPC channel initialised");

    // Pass data channel queue pointers to the enclave
    let ret = enclave::call_ecall_init_data_channel(
        enclave_id,
        data_channel.enc_to_host_header as *mut u8,
        data_channel.enc_to_host_buf,
        data_channel.host_to_enc_header as *mut u8,
        data_channel.host_to_enc_buf,
        data_channel.capacity,
    );
    if ret != 0 {
        error!("ecall_init_data_channel failed: {}", ret);
        enclave::destroy_enclave(enclave_id);
        anyhow::bail!("Failed to initialise enclave data channel");
    }
    info!("Enclave data channel initialised");

    // Create host-side queue endpoints (consumer for requests, producer for responses)
    let (request_rx, response_tx) = unsafe { channel.host_endpoints() };

    // Create host-side data channel endpoints
    // For data channel: host writes to host_to_enc (raw TCP → enclave),
    // host reads from enc_to_host (TLS output from enclave)
    let (data_from_enc_rx, data_to_enc_tx) = unsafe { data_channel.host_endpoints() };

    // Set up shared shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));

    // Store notify flag for the OCALL handler
    ocall_impl::set_notify_flag(shutdown.clone());

    // Spawn the RPC dispatcher thread
    let shutdown_clone = shutdown.clone();
    let dispatcher_handle = thread::Builder::new()
        .name("rpc-dispatcher".into())
        .spawn(move || {
            let dispatcher = dispatcher::RpcDispatcher::new(
                request_rx,
                response_tx,
                shutdown_clone,
            );
            dispatcher.run();
        })?;
    info!("RPC dispatcher thread started");

    // Spawn the TCP proxy thread
    let proxy_port = cli.port;
    let proxy_backlog = cli.backlog;
    let shutdown_clone = shutdown.clone();
    let proxy_handle = thread::Builder::new()
        .name("tcp-proxy".into())
        .spawn(move || {
            match tcp_proxy::TcpProxy::new(
                proxy_port,
                proxy_backlog,
                data_to_enc_tx,
                data_from_enc_rx,
                shutdown_clone,
            ) {
                Ok(mut proxy) => proxy.run(),
                Err(e) => {
                    error!("TCP proxy failed to start: {}", e);
                }
            }
        })?;
    info!("TCP proxy thread started on port {}", cli.port);

    // Build config JSON for the enclave
    let mut config = serde_json::json!({
        "port": cli.port,
        "backlog": cli.backlog,
    });

    // If intermediary CA cert + key are provided, read them and add as hex
    if let (Some(cert_path), Some(key_path)) = (&cli.ca_cert, &cli.ca_key) {
        let cert_der = read_pem_or_der(cert_path, "CERTIFICATE")
            .map_err(|e| anyhow::anyhow!("Failed to read CA cert '{}': {}", cert_path, e))?;
        let key_der = read_pem_or_der(key_path, "PRIVATE KEY")
            .map_err(|e| anyhow::anyhow!("Failed to read CA key '{}': {}", key_path, e))?;
        info!("CA cert: {} bytes (DER), CA key: {} bytes (DER)", cert_der.len(), key_der.len());
        config["ca_cert_hex"] = serde_json::Value::String(hex::encode(&cert_der));
        config["ca_key_hex"] = serde_json::Value::String(hex::encode(&key_der));
    } else if cli.ca_cert.is_some() || cli.ca_key.is_some() {
        anyhow::bail!("Both --ca-cert and --ca-key must be specified together");
    }

    // If an egress CA bundle is provided, read it and hex-encode for the enclave
    if let Some(ref bundle_path) = cli.egress_ca_bundle {
        let pem_bytes = std::fs::read(bundle_path)
            .map_err(|e| anyhow::anyhow!("Failed to read egress CA bundle '{}': {}", bundle_path, e))?;
        info!("Egress CA bundle: {} bytes from {}", pem_bytes.len(), bundle_path);
        config["egress_ca_bundle_hex"] = serde_json::Value::String(hex::encode(&pem_bytes));
    }

    // If attestation server URLs are provided, pass them as a JSON array
    if let Some(ref servers) = cli.attestation_servers {
        info!("Attestation servers: {:?}", servers);
        config["attestation_servers"] = serde_json::to_value(servers)
            .map_err(|e| anyhow::anyhow!("Failed to serialise attestation servers: {}", e))?;
    }

    // OIDC configuration
    if let Some(ref issuer) = cli.oidc_issuer {
        let audience = cli.oidc_audience.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--oidc-audience is required when --oidc-issuer is set"))?;
        info!("OIDC enabled: issuer={}, audience={}", issuer, audience);
        config["oidc"] = serde_json::json!({
            "issuer": issuer,
            "audience": audience,
        });
    } else if cli.oidc_audience.is_some() {
        anyhow::bail!("--oidc-issuer is required when --oidc-audience is set");
    }

    let config_bytes = serde_json::to_vec(&config)?;

    // Enter the enclave (blocks until enclave returns)
    info!("Calling ecall_run (Ctrl+C to stop)...");
    let ret = enclave::call_ecall_run(enclave_id, &config_bytes);
    if ret != 0 {
        error!("ecall_run returned: {}", ret);
    }

    // Signal dispatcher and proxy to stop
    shutdown.store(true, Ordering::Relaxed);

    // Graceful shutdown
    let _ = enclave::call_ecall_shutdown(enclave_id);
    info!("Waiting for dispatcher thread...");
    let _ = dispatcher_handle.join();
    info!("Waiting for TCP proxy thread...");
    let _ = proxy_handle.join();
    enclave::destroy_enclave(enclave_id);
    info!("Enclave destroyed. Goodbye.");

    // Keep channels alive until after enclave is destroyed
    drop(channel);
    drop(data_channel);

    Ok(())
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Read a file as DER. If the file contains PEM, extract the first block
/// matching `expected_label` (e.g. "CERTIFICATE" or "PRIVATE KEY").
///
/// For key files, also accepts "EC PRIVATE KEY" (SEC1 format) and wraps
/// it in PKCS#8 so the enclave always receives PKCS#8.
fn read_pem_or_der(path: &str, expected_label: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;

    // Try PEM first
    if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN") {
            // Try the exact label first, then fall back to "EC PRIVATE KEY"
            let labels_to_try: Vec<&str> = if expected_label == "PRIVATE KEY" {
                vec!["PRIVATE KEY", "EC PRIVATE KEY"]
            } else {
                vec![expected_label]
            };

            for label in &labels_to_try {
                let begin = format!("-----BEGIN {}-----", label);
                let end = format!("-----END {}-----", label);
                if let Some(start_idx) = text.find(&begin) {
                    let after_begin = start_idx + begin.len();
                    if let Some(end_idx) = text[after_begin..].find(&end) {
                        let b64: String = text[after_begin..after_begin + end_idx]
                            .chars()
                            .filter(|c| !c.is_whitespace())
                            .collect();
                        use base64::Engine;
                        let der = base64::engine::general_purpose::STANDARD
                            .decode(&b64)
                            .map_err(|e| anyhow::anyhow!("PEM base64 decode: {}", e))?;

                        // If SEC1 "EC PRIVATE KEY", wrap it in PKCS#8
                        if *label == "EC PRIVATE KEY" {
                            return Ok(wrap_ec_sec1_in_pkcs8(&der));
                        }
                        return Ok(der);
                    }
                }
            }
            anyhow::bail!("PEM file does not contain a '{}' block", expected_label);
        }
    }

    // Not PEM → assume raw DER
    Ok(data)
}

/// Wrap an SEC1 EC private key in a PKCS#8 envelope for P-256.
///
/// PKCS#8 structure:
/// ```asn1
/// PrivateKeyInfo ::= SEQUENCE {
///   version       INTEGER (0),
///   algorithm     AlgorithmIdentifier { SEQUENCE { OID ecPublicKey, OID prime256v1 } },
///   privateKey    OCTET STRING (containing the SEC1 key)
/// }
/// ```
fn wrap_ec_sec1_in_pkcs8(sec1_der: &[u8]) -> Vec<u8> {
    // Fixed PKCS#8 header for P-256 (ecPublicKey + prime256v1)
    //
    // SEQUENCE (outer)
    //   INTEGER version = 0
    //   SEQUENCE (AlgorithmIdentifier)
    //     OID 1.2.840.10045.2.1 (ecPublicKey)
    //     OID 1.2.840.10045.3.1.7 (prime256v1)
    //   OCTET STRING (SEC1 key)

    // The OCTET STRING wrapping the SEC1 key
    let sec1_len = sec1_der.len();
    let octet_len_bytes = der_length_bytes(sec1_len);
    let inner_len = 3 + 21 + 1 + octet_len_bytes.len() + sec1_len; // version + algid + octet tag + octet len + sec1
    let outer_len_bytes = der_length_bytes(inner_len);

    let mut out = Vec::with_capacity(1 + outer_len_bytes.len() + inner_len);
    out.push(0x30); // SEQUENCE tag
    out.extend_from_slice(&outer_len_bytes);
    out.extend_from_slice(&[0x02, 0x01, 0x00]); // version = 0
    out.extend_from_slice(&[
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ]);
    out.push(0x04); // OCTET STRING tag
    out.extend_from_slice(&octet_len_bytes);
    out.extend_from_slice(sec1_der);
    out
}

/// Encode a length in DER format.
fn der_length_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}
