// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! ECall entry points – functions called by the host into the enclave.
//!
//! With the SPSC queue architecture, only three ECALLs are needed:
//! - `ecall_init_channel`: receive shared-memory queue pointers
//! - `ecall_run`: main enclave entry – init subsystems, run event loop
//! - `ecall_shutdown`: signal graceful stop
//!
//! ## Adopter integration
//!
//! When the `default-ecall` feature is enabled (the default), this module
//! provides a vanilla `ecall_run` that registers only the HelloWorld
//! example module.
//!
//! Adopters that need custom modules should:
//! 1. Depend on `enclave-os-enclave` with `default-features = false` and
//!    `features = ["sgx"]` (excluding `default-ecall`).
//! 2. Provide their own `#[no_mangle] pub extern "C" fn ecall_run(…)`.
//! 3. Call [`init_enclave()`] to get the parsed config and sealed state.
//! 4. Construct modules using `sealed_cfg.master_key()` and
//!    [`register_module()`](crate::modules::register_module) them.
//! 5. Call [`finalize_and_run()`] to build the Merkle tree, start the
//!    RA-TLS server, and enter the event loop.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::rpc_client::RpcClient;
use crate::ratls::attestation::CaContext;
use crate::ratls::server::RaTlsServer;
use crate::sealed_config::SealedConfig;
use crate::{enclave_log_info, enclave_log_error};
use enclave_os_common::types::AEAD_KEY_SIZE;
use enclave_os_common::queue::{SpscProducer, SpscConsumer, SpscQueueHeader};

// ==========================================================================
//  ecall_init_channel – set up the shared-memory RPC channel
// ==========================================================================

/// Called by the host to pass shared-memory queue pointers into the enclave.
///
/// # Parameters
/// - `enc_to_host_header`/`enc_to_host_buf`: queue for enclave→host requests
/// - `host_to_enc_header`/`host_to_enc_buf`: queue for host→enclave responses
/// - `capacity`: ring buffer size (same for both queues)
///
/// All pointers are in host (untrusted) memory. The enclave accesses them
/// directly – no OCALL needed for data transfer.
#[no_mangle]
pub extern "C" fn ecall_init_channel(
    enc_to_host_header: *mut u8,
    enc_to_host_buf: *mut u8,
    host_to_enc_header: *mut u8,
    host_to_enc_buf: *mut u8,
    _capacity: u64,
) -> i32 {
    if enc_to_host_header.is_null()
        || enc_to_host_buf.is_null()
        || host_to_enc_header.is_null()
        || host_to_enc_buf.is_null()
    {
        return -1;
    }

    // The enclave is the **producer** for enc_to_host and the **consumer**
    // for host_to_enc.
    let request_tx = unsafe {
        SpscProducer::from_raw(
            enc_to_host_header as *const SpscQueueHeader,
            enc_to_host_buf,
        )
    };
    let response_rx = unsafe {
        SpscConsumer::from_raw(
            host_to_enc_header as *const SpscQueueHeader,
            host_to_enc_buf as *const u8,
        )
    };

    let client = RpcClient::new(request_tx, response_rx);

    match crate::set_rpc_client(client) {
        Ok(()) => {
            // Use raw ocall_notify briefly to confirm init – or just return 0.
            0
        }
        Err(_) => -1,
    }
}

// ==========================================================================
//  init_enclave – parse config, CPUID, crypto self-tests, sealed config
// ==========================================================================

/// Initialise the enclave core: parse configuration, set up CPUID caching,
/// run cryptographic self-tests, and resolve the sealed configuration.
///
/// Returns the parsed [`EnclaveConfig`] and a mutable [`SealedConfig`].
/// The caller (either the default `ecall_run` or an adopter's custom one)
/// is responsible for registering modules and calling [`finalize_and_run()`].
pub fn init_enclave(
    config_json: *const u8,
    config_len: u64,
) -> Result<(EnclaveConfig, SealedConfig), i32> {
    // Parse config
    let config_bytes = if !config_json.is_null() && config_len > 0 {
        unsafe { core::slice::from_raw_parts(config_json, config_len as usize) }
    } else {
        b"{}" as &[u8]
    };

    let config: EnclaveConfig = match serde_json::from_slice(config_bytes) {
        Ok(c) => c,
        Err(e) => {
            enclave_log_error!("Config parse failed: {}", e);
            return Err(-2);
        }
    };

    // ── CPUID cache: must be initialised BEFORE any crypto ──────────
    // ring / rustls use CPUID for feature detection (SHA-NI, AES-NI, …).
    // Inside SGX, CPUID triggers #UD. We fetch results via OCALL once
    // at init and register a VEH to serve cached values thereafter.
    crate::cpuid_cache::init();

    // Crypto self-tests
    {
        let mut buf = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut buf) {
            enclave_log_error!("getrandom FAILED: {}", e);
            return Err(-10);
        }
        use ring::rand::{SecureRandom, SystemRandom};
        if SystemRandom::new().fill(&mut buf).is_err() {
            enclave_log_error!("ring::rand FAILED");
            return Err(-11);
        }
        use ring::digest;
        let _ = digest::digest(&digest::SHA256, b"self-test");
    }
    enclave_log_info!("Crypto self-tests passed");

    // ── Resolve unified sealed config ──────────────────────────────
    let sealed_cfg = match resolve_sealed_config(&config) {
        Ok(cfg) => cfg,
        Err(e) => {
            enclave_log_error!("Sealed config resolution failed: {}", e);
            return Err(-12);
        }
    };
    enclave_log_info!("Sealed config resolved");

    Ok((config, sealed_cfg))
}

// ==========================================================================
//  finalize_and_run – Merkle tree, RA-TLS server, event loop
// ==========================================================================

/// Build the config Merkle tree, start the RA-TLS server, and enter the
/// main event loop.
///
/// Call this after all modules have been registered and the sealed config
/// has been updated with any module-generated data.
///
/// This function **blocks** until shutdown is signalled. It re-seals the
/// config to disk before starting the server (persisting any module data
/// written during init).
pub fn finalize_and_run(config: &EnclaveConfig, sealed_cfg: &SealedConfig) -> i32 {
    // Persist the (possibly updated) sealed config
    if let Err(e) = sealed_cfg.seal_to_disk() {
        enclave_log_error!("Failed to seal config: {}", e);
        return -12;
    }
    enclave_log_info!("Sealed config persisted to disk");

    // ── Config Merkle tree ─────────────────────────────────────────
    // Core leaves + module-contributed leaves → auditable root hash.
    let merkle_root = {
        let mut tree = crate::config_merkle::ConfigMerkleTree::new();

        // Core leaf (fixed order — append-only, never reorder)
        tree.push("core.ca_cert", Some(sealed_cfg.ca_cert_der.as_slice()));

        // Module leaves (collected from all registered modules)
        for leaf in crate::modules::collect_module_config_leaves() {
            tree.push(leaf.name, leaf.data.as_deref());
        }

        tree.finalize()
    };
    enclave_log_info!("Config Merkle root: {}", hex_encode(&merkle_root));

    // Log the full manifest for auditability
    if let Some(manifest) = crate::config_merkle::config_manifest() {
        for (i, entry) in manifest.entries().iter().enumerate() {
            enclave_log_info!("  leaf[{}] {} = {}", i, entry.name, hex_encode(&entry.hash));
        }
    }

    // Initialise enclave state
    if let Err(code) = crate::init_state() {
        enclave_log_error!("init_state failed ({})", code);
        return code;
    }
    enclave_log_info!("Enclave state initialised");

    // Build CA context from sealed config
    let ca = match CaContext::from_parts(
        sealed_cfg.ca_cert_der.clone(),
        sealed_cfg.ca_key_pkcs8.clone(),
    ) {
        Ok(ca) => Arc::new(ca),
        Err(e) => {
            enclave_log_error!("CA validation failed: {}", e);
            return -20;
        }
    };
    let server = match RaTlsServer::new(config.port, config.backlog, ca) {
        Ok(s) => s,
        Err(e) => {
            enclave_log_error!("RA-TLS server init failed: {}", e);
            return -21;
        }
    };
    {
        let mut st = match crate::state().lock() {
            Ok(st) => st,
            Err(_) => return -22,
        };
        st.ratls_server = Some(server);
    }
    enclave_log_info!("RA-TLS server listening on port {}", config.port);

    // Main event loop: poll RA-TLS server until shutdown
    while !crate::is_shutdown() {
        let poll_result = {
            let mut st = match crate::state().lock() {
                Ok(st) => st,
                Err(_) => break,
            };
            if let Some(ref mut srv) = st.ratls_server {
                srv.poll()
            } else {
                break;
            }
        };
        if let Err(e) = poll_result {
            if crate::is_shutdown() {
                break;
            }
            enclave_log_error!("Poll error: {}", e);
            break;
        }
        // Yield to avoid busy-spinning too aggressively
        core::hint::spin_loop();
    }

    enclave_log_info!("Event loop exited");
    0
}

// ==========================================================================
//  ecall_run – default implementation (feature-gated)
// ==========================================================================

/// Default `ecall_run` implementation that registers only the HelloWorld
/// example module.
///
/// Adopters should disable the `default-ecall` feature and provide their
/// own `ecall_run` that calls [`init_enclave()`] and [`finalize_and_run()`].
#[cfg(feature = "default-ecall")]
#[no_mangle]
pub extern "C" fn ecall_run(config_json: *const u8, config_len: u64) -> i32 {
    let (config, sealed_cfg) = match init_enclave(config_json, config_len) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Register the HelloWorld example module
    crate::modules::register_module(Box::new(
        crate::modules::helloworld::HelloWorldModule,
    ));
    enclave_log_info!("All modules registered (default-ecall: HelloWorld only)");

    finalize_and_run(&config, &sealed_cfg)
}

// ==========================================================================
//  ecall_shutdown – graceful stop
// ==========================================================================

#[no_mangle]
pub extern "C" fn ecall_shutdown() -> i32 {
    enclave_log_info!("Enclave shutting down");
    crate::signal_shutdown();

    // Clean up subsystems
    if let Ok(mut st) = crate::state().lock() {
        st.ratls_server = None;
    }
    0
}

// ==========================================================================
//  Public types & helpers
// ==========================================================================

/// Enclave configuration parsed from JSON.
///
/// Core fields are deserialized into named fields. Module-specific config
/// is captured in [`extra`](Self::extra) via `#[serde(flatten)]`, so
/// adopters can read their module config with e.g.
/// `config.extra["egress_ca_bundle_hex"]`.
#[derive(serde::Deserialize)]
pub struct EnclaveConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_backlog")]
    pub backlog: i32,
    /// Hex-encoded DER of the intermediary CA certificate.
    pub ca_cert_hex: Option<String>,
    /// Hex-encoded PKCS#8 of the intermediary CA private key.
    pub ca_key_hex: Option<String>,
    /// Module-specific configuration (catch-all for unknown JSON fields).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_port() -> u16 { 443 }
fn default_backlog() -> i32 { 128 }

/// Minimal hex decoder (no external dependency).
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

pub fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Minimal hex encoder (no external dependency).
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ==========================================================================
//  Unified sealed config resolution
// ==========================================================================

/// Resolve the unified sealed configuration.
///
/// 1. Try to unseal an existing `SealedConfig` from disk.
/// 2. Override CA material if provided in the current config.
/// 3. Preserve any existing `module_data` from the sealed blob.
/// 4. Re-seal after modules have had a chance to update it
///    (done in [`finalize_and_run()`]).
///
/// This ensures that:
/// - First run requires `--ca-cert` + `--ca-key`.
/// - Subsequent restarts unseal everything automatically.
/// - Passing new config params on restart updates the sealed blob.
fn resolve_sealed_config(config: &EnclaveConfig) -> Result<SealedConfig, String> {
    // Try to unseal existing config from disk
    let existing = SealedConfig::unseal_from_disk().ok();
    let is_fresh = existing.is_none();

    // ── CA material: config params override sealed state ─────────────
    let (ca_cert_der, ca_key_pkcs8) = if let (Some(cert_hex), Some(key_hex)) =
        (&config.ca_cert_hex, &config.ca_key_hex)
    {
        let cert = hex_decode(cert_hex)
            .ok_or_else(|| String::from("ca_cert_hex is not valid hex"))?;
        let key = hex_decode(key_hex)
            .ok_or_else(|| String::from("ca_key_hex is not valid hex"))?;
        // Validate the key material early
        CaContext::from_parts(cert.clone(), key.clone())?;
        enclave_log_info!("CA loaded from config (cert={} B, key={} B)", cert.len(), key.len());
        (cert, key)
    } else if let Some(ref ex) = existing {
        enclave_log_info!("CA loaded from sealed config");
        (ex.ca_cert_der.clone(), ex.ca_key_pkcs8.clone())
    } else {
        return Err(
            "No CA material found on disk and none provided in config. \
             Pass --ca-cert + --ca-key on first run."
                .into(),
        );
    };

    // ── Module data: preserve from existing sealed config ────────────
    let module_data = if let Some(ref ex) = existing {
        enclave_log_info!("Loaded {} module data entries from sealed config", ex.module_data.len());
        ex.module_data.clone()
    } else {
        BTreeMap::new()
    };

    //  Master encryption key: reuse existing or generate fresh 
    let master_key: [u8; AEAD_KEY_SIZE] = if let Some(ref ex) = existing {
        enclave_log_info!("Master key loaded from sealed config");
        ex.master_key
    } else {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; AEAD_KEY_SIZE];
        ring::rand::SecureRandom::fill(&rng, &mut key)
            .map_err(|_| String::from("Failed to generate master key"))?;
        enclave_log_info!("Generated fresh master encryption key");
        key
    };

    let cfg = SealedConfig {
        master_key,
        ca_cert_der,
        ca_key_pkcs8,
        module_data,
    };

    if is_fresh {
        enclave_log_info!("First run: sealed config created");
    } else {
        enclave_log_info!("Sealed config loaded from disk");
    }

    Ok(cfg)
}
