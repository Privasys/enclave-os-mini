// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! HTTPS Egress module for enclave-os.
//!
//! Provides outbound HTTPS from inside the SGX enclave. The TLS termination
//! happens inside the enclave; the host never sees plaintext.
//!
//! ## RA-TLS verification
//!
//! When connecting to a server that serves RA-TLS certificates (e.g. another
//! enclave-os instance or a Caddy RA-TLS reverse proxy), callers can pass an
//! [`RaTlsPolicy`] to [`client::https_get`] / [`client::https_post`]. The
//! policy specifies the expected TEE type and measurement registers; the
//! egress client will verify the attestation quote during the TLS handshake
//! and reject the connection if any check fails.
//!
//! ## Responsibilities
//!
//! - Owns the egress root CA store (loaded from operator-provided PEM bundle)
//! - Owns the attestation server URL list (passed at startup, used by vault
//!   and other modules for remote quote verification)
//! - Registers config Merkle leaves: `egress.ca_bundle`, `egress.attestation_servers`
//! - Registers custom X.509 OIDs:
//!   - `1.3.6.1.4.1.65230.2.1` — CA bundle SHA-256 hash
//!   - `1.3.6.1.4.1.65230.2.4` — attestation servers SHA-256 hash
//!   so clients can verify the egress trust anchors and attestation
//!   server configuration without a full Merkle audit.
//!
//! ## Usage
//!
//! In your custom `ecall_run`:
//!
//! ```rust,ignore
//! use enclave_os_egress::{EgressModule, client};
//! use enclave_os_enclave::ecall::{init_enclave, finalize_and_run};
//! use enclave_os_enclave::modules::register_module;
//! use enclave_os_common::hex::hex_decode;
//!
//! let (config, mut sealed_cfg) = init_enclave(config_json, config_len)?;
//!
//! // Load egress CA bundle from config
//! let pem = config.extra.get("egress_ca_bundle_hex")
//!     .and_then(|v| v.as_str())
//!     .and_then(|hex| hex_decode(hex));
//!
//! // Load attestation server URLs from config
//! let attestation_servers = config.extra.get("attestation_servers")
//!     .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok());
//!
//! let (egress, cert_count) = EgressModule::new(pem, attestation_servers)?;
//! register_module(Box::new(egress));
//!
//! finalize_and_run(&config, &sealed_cfg);
//! ```

pub mod client;
pub mod attestation;

// Re-export RA-TLS verification types for convenience.
pub use client::{
    ExpectedOid, RaTlsPolicy, ReportDataBinding, TeeType,
    OID_CONFIG_MERKLE_ROOT, OID_EGRESS_CA_HASH, OID_WASM_APPS_HASH,
    OID_ATTESTATION_SERVERS_HASH,
};

use std::sync::OnceLock;
use std::vec::Vec;

use ring::digest;
use rustls::RootCertStore;

use enclave_os_common::modules::ConfigLeaf;
use enclave_os_common::modules::{EnclaveModule, ModuleOid, RequestContext};
use enclave_os_common::protocol::{Request, Response};

/// OID for the egress CA bundle hash — imported from common.
pub use enclave_os_common::oids::EGRESS_CA_HASH_OID;

/// OID for the attestation servers hash — imported from common.
pub use enclave_os_common::oids::ATTESTATION_SERVERS_HASH_OID;

// ---------------------------------------------------------------------------
//  Global root CA store
// ---------------------------------------------------------------------------

static EGRESS_ROOT_STORE: OnceLock<RootCertStore> = OnceLock::new();

/// Get the egress root CA store (returns `None` if no bundle was provided).
pub fn root_store() -> Option<&'static RootCertStore> {
    EGRESS_ROOT_STORE.get()
}

// ---------------------------------------------------------------------------
//  Global attestation server list
// ---------------------------------------------------------------------------

static ATTESTATION_SERVERS: OnceLock<Vec<String>> = OnceLock::new();

/// Get the configured attestation server URLs.
///
/// Returns `None` before `EgressModule::new()` is called.
/// Returns `Some(&[])` when no attestation servers were configured
/// (attestation server verification disabled).
pub fn attestation_servers() -> Option<&'static Vec<String>> {
    ATTESTATION_SERVERS.get()
}

// ---------------------------------------------------------------------------
//  EgressModule
// ---------------------------------------------------------------------------

pub struct EgressModule {
    /// Raw PEM bytes of the CA bundle (kept for config leaf hashing).
    ca_pem: Option<Vec<u8>>,
    /// SHA-256 hash of the PEM bytes (used as OID value).
    ca_hash: Option<[u8; 32]>,
    /// Canonical attestation server URL list (kept for config leaf hashing).
    attestation_servers_canonical: Option<Vec<u8>>,
    /// SHA-256 hash of the canonical URL list (used as OID value).
    attestation_servers_hash: Option<[u8; 32]>,
}

impl EgressModule {
    /// Construct the egress module, parsing and loading the CA bundle and
    /// attestation server list.
    ///
    /// Both the CA bundle and the attestation server URLs are registered
    /// as Merkle tree leaves and individual X.509 OIDs in RA-TLS
    /// certificates, making them auditable by remote verifiers.
    ///
    /// Returns `(module, cert_count)`.  `cert_count` is 0 when `pem` is
    /// `None` (egress disabled).
    pub fn new(
        pem: Option<Vec<u8>>,
        attestation_server_urls: Option<Vec<String>>,
    ) -> Result<(Self, usize), String> {
        let ca_hash = pem.as_ref().map(|p| {
            let d = digest::digest(&digest::SHA256, p);
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());
            h
        });

        // Build canonical form: sorted, newline-joined.
        let (as_canonical, as_hash) = match attestation_server_urls {
            Some(ref urls) if !urls.is_empty() => {
                let mut sorted = urls.clone();
                sorted.sort();
                let canonical = sorted.join("\n");
                let d = digest::digest(&digest::SHA256, canonical.as_bytes());
                let mut h = [0u8; 32];
                h.copy_from_slice(d.as_ref());
                (Some(canonical.into_bytes()), Some(h))
            }
            _ => (None, None),
        };

        // Store the server list globally for vault and other consumers.
        if let Some(ref urls) = attestation_server_urls {
            let _ = ATTESTATION_SERVERS.set(urls.clone());
        } else {
            let _ = ATTESTATION_SERVERS.set(Vec::new());
        }

        let cert_count = if let Some(ref pem_bytes) = pem {
            let mut store = RootCertStore::empty();
            let mut reader = std::io::BufReader::new(pem_bytes.as_slice());
            let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
                .filter_map(|r| r.ok())
                .collect();
            let count = certs.len();
            if count == 0 {
                return Err("No valid certificates found in egress CA bundle".into());
            }
            for cert in certs {
                store.add(cert).map_err(|e| format!("Bad root cert: {}", e))?;
            }
            EGRESS_ROOT_STORE
                .set(store)
                .map_err(|_| "Egress root store already set".to_string())?;
            count
        } else {
            0
        };

        Ok((Self { ca_pem: pem, ca_hash, attestation_servers_canonical: as_canonical, attestation_servers_hash: as_hash }, cert_count))
    }
}

impl EnclaveModule for EgressModule {
    fn name(&self) -> &str {
        "egress"
    }

    fn handle(&self, _req: &Request, _ctx: &RequestContext) -> Option<Response> {
        // Egress is an internal service — not a direct request handler.
        // Other modules call client::https_get / https_post directly.
        None
    }

    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        vec![
            ConfigLeaf {
                name: "egress.ca_bundle".into(),
                data: self.ca_pem.clone(),
            },
            ConfigLeaf {
                name: "egress.attestation_servers".into(),
                data: self.attestation_servers_canonical.clone(),
            },
        ]
    }

    fn custom_oids(&self) -> Vec<ModuleOid> {
        let mut oids = Vec::new();
        if let Some(hash) = self.ca_hash {
            oids.push(ModuleOid {
                oid: EGRESS_CA_HASH_OID,
                value: hash.to_vec(),
            });
        }
        if let Some(hash) = self.attestation_servers_hash {
            oids.push(ModuleOid {
                oid: ATTESTATION_SERVERS_HASH_OID,
                value: hash.to_vec(),
            });
        }
        oids
    }
}
