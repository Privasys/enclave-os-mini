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
//! [`RaTlsPolicy`] to [`client::https_fetch`]. The policy specifies the expected TEE type and
//! measurement registers; the egress client will verify the attestation
//! quote during the TLS handshake and reject the connection if any check fails.
//!
//! ## Responsibilities
//!
//! - Owns the egress root CA store (loaded from operator-provided PEM bundle)
//! - Registers a config Merkle leaf: `egress.ca_bundle`
//! - Registers a custom X.509 OID:
//!   - `1.3.6.1.4.1.65230.2.1` — CA bundle SHA-256 hash
//!   so clients can verify the egress trust anchors without a full Merkle audit.
//!
//! Attestation servers and their bearer tokens are managed centrally by
//! the enclave core (see [`enclave_os_common::attestation_servers`]). The
//! egress module reads from that store during quote verification.
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
//! let (egress, cert_count) = EgressModule::new(pem)?;
//! register_module(Box::new(egress));
//!
//! finalize_and_run(&config, &sealed_cfg);
//! ```

pub mod client;
pub mod attestation;
pub mod oidc_bootstrap;

// Re-export RA-TLS verification types for convenience.
pub use client::{
    ExpectedOid, HttpResponse, RaTlsPolicy, ReportDataBinding, TeeType,
    OID_CONFIG_MERKLE_ROOT, OID_EGRESS_CA_HASH, OID_WASM_APPS_HASH,
    OID_ATTESTATION_SERVERS_HASH,
    MAX_RESPONSE_BODY,
    https_fetch,
    mozilla_root_store,
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
//  EgressModule
// ---------------------------------------------------------------------------

pub struct EgressModule {
    /// Raw PEM bytes of the CA bundle (kept for config leaf hashing).
    ca_pem: Option<Vec<u8>>,
    /// SHA-256 hash of the PEM bytes (used as OID value).
    ca_hash: Option<[u8; 32]>,
}

impl EgressModule {
    /// Construct the egress module, parsing and loading the CA bundle.
    ///
    /// The CA bundle is registered as a Merkle tree leaf and an individual
    /// X.509 OID in RA-TLS certificates, making it auditable by remote
    /// verifiers.
    ///
    /// Returns `(module, cert_count)`.  `cert_count` is 0 when `pem` is
    /// `None` (egress disabled).
    pub fn new(pem: Option<Vec<u8>>) -> Result<(Self, usize), String> {
        let ca_hash = pem.as_ref().map(|p| {
            let d = digest::digest(&digest::SHA256, p);
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());
            h
        });

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

        Ok((Self { ca_pem: pem, ca_hash }, cert_count))
    }
}

impl EnclaveModule for EgressModule {
    fn name(&self) -> &str {
        "egress"
    }

    fn handle(&self, _req: &Request, _ctx: &RequestContext) -> Option<Response> {
        None // Egress has no module-level management operations.
    }

    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        vec![ConfigLeaf {
            name: "egress.ca_bundle".into(),
            data: self.ca_pem.clone(),
        }]
    }

    fn custom_oids(&self) -> Vec<ModuleOid> {
        let mut oids = Vec::new();
        if let Some(hash) = self.ca_hash {
            oids.push(ModuleOid {
                oid: EGRESS_CA_HASH_OID,
                value: hash.to_vec(),
            });
        }
        oids
    }
}
