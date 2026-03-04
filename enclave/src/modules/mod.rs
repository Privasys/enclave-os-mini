// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Module registry, trait interface, and built-in module implementations.
//!
//! Modules implement [`EnclaveModule`] to:
//! - Handle client requests via [`handle()`](EnclaveModule::handle)
//! - Register config inputs for the Merkle tree via [`config_leaves()`](EnclaveModule::config_leaves)
//! - Register custom X.509 OIDs for RA-TLS certs via [`custom_oids()`](EnclaveModule::custom_oids)
//! - Declare per-app identities for SNI-routed certs via [`app_identities()`](EnclaveModule::app_identities)

// ---------------------------------------------------------------------------
//  Built-in modules
// ---------------------------------------------------------------------------
// HelloWorld is the only built-in module — it exists as a minimal smoke-test
// for when no module features are enabled.  Additional modules (egress,
// kvstore, vault, wasm) live in `crates/enclave-os-*` and are pulled in
// via Cargo features (e.g. `--features vault`).  The default `ecall_run`
// registers whichever modules are enabled.  For fully custom registration,
// disable `default-ecall` and use an external composition crate.

pub mod helloworld;

use std::sync::Mutex;
use std::vec::Vec;

use enclave_os_common::protocol::{Request, Response};
use crate::config_merkle::ConfigLeaf;

// ---------------------------------------------------------------------------
//  Module OID
// ---------------------------------------------------------------------------

/// A custom X.509 OID extension registered by a module.
///
/// Each OID is embedded as a non-critical extension in every RA-TLS leaf
/// certificate, allowing clients to verify individual module properties
/// without computing the full config Merkle tree.
pub struct ModuleOid {
    /// OID arc sequence (e.g. `&[1, 3, 6, 1, 4, 1, 65230, 2, 1]`).
    pub oid: &'static [u64],
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Per-app identity types
// ---------------------------------------------------------------------------

/// A configuration entry declared by a module or app at init time.
///
/// Each entry is SHA-256 hashed and included in the app's per-identity
/// Merkle tree. Entries flagged with an [`oid`](Self::oid) are also
/// embedded as direct X.509 extensions in the app's certificate for
/// fast-path verification (clients can check the OID without
/// recomputing the full Merkle tree).
pub struct ConfigEntry {
    /// Human-readable key (e.g. `"code_hash"`, `"policy_version"`).
    pub key: String,
    /// Raw value bytes (SHA-256 hashed into the Merkle tree).
    pub value: Vec<u8>,
    /// If `Some`, also embed this entry as a direct X.509 OID extension
    /// in the app's leaf certificate.
    pub oid: Option<&'static [u64]>,
}

/// Identity of an app endpoint that gets its own X.509 certificate.
///
/// Each identity is served via SNI-based TLS routing. The app's leaf
/// certificate (signed by the Enclave CA) contains:
/// - A per-app Merkle tree root computed from [`config`](Self::config)
/// - Any OID-flagged config entries as direct extensions
/// - The SGX quote (proving the enclave is genuine)
pub struct AppIdentity {
    /// SNI hostname this app responds to (e.g. `"payments.example.com"`).
    pub hostname: String,
    /// Configuration entries for this app's Merkle tree.
    ///
    /// The tree is computed as:
    /// `root = SHA-256( SHA-256(entry_0.value) || SHA-256(entry_1.value) || … )`
    pub config: Vec<ConfigEntry>,
}

// ---------------------------------------------------------------------------
//  Request context
// ---------------------------------------------------------------------------

/// Per-request context passed to [`EnclaveModule::handle()`].
///
/// Carries optional metadata extracted from the TLS session, such as the
/// peer's client certificate (when mutual RA-TLS is in use).
pub struct RequestContext {
    /// DER-encoded leaf certificate presented by the TLS client.
    ///
    /// `Some(…)` when the client provided a certificate during the TLS
    /// handshake (mutual RA-TLS). `None` for regular browser clients
    /// that do not present client certificates.
    ///
    /// Modules that require mutual attestation (e.g. the vault) can
    /// extract the SGX/TDX quote and custom OID extensions from this
    /// certificate to verify the caller's identity.
    pub peer_cert_der: Option<Vec<u8>>,

    /// Random nonce sent to the client via the TLS CertificateRequest
    /// extension `0xFFBB` for bidirectional challenge-response attestation.
    ///
    /// When present (challenge mode only), modules can verify that the
    /// client's RA-TLS certificate was generated specifically for this
    /// connection by checking that the client's `report_data` binds to
    /// this nonce: `report_data == SHA-512(SHA-256(client_pubkey) || nonce)`.
    pub client_challenge_nonce: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
//  EnclaveModule trait
// ---------------------------------------------------------------------------

/// Trait for pluggable enclave business logic modules.
pub trait EnclaveModule: Send + Sync {
    /// Human-readable module name (used as config leaf prefix).
    fn name(&self) -> &str;

    /// Handle a client request. Returns `Some(response)` if handled.
    ///
    /// The [`RequestContext`] carries per-connection metadata (e.g. the
    /// peer's client certificate for mutual RA-TLS verification).
    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response>;

    /// Config leaves to include in the configuration Merkle tree.
    ///
    /// Called once during enclave init. Each leaf is hashed and included
    /// in the RA-TLS certificate's config Merkle root OID.
    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        Vec::new()
    }

    /// Custom X.509 OIDs to embed in RA-TLS certificates.
    ///
    /// These provide a fast-path for clients to verify individual module
    /// properties (e.g. egress CA bundle hash) without recomputing the
    /// full Merkle tree.
    fn custom_oids(&self) -> Vec<ModuleOid> {
        Vec::new()
    }

    /// App identities for per-app X.509 certificates.
    ///
    /// Each returned [`AppIdentity`] gets its own leaf cert (signed by
    /// the Enclave CA) with a dedicated Merkle tree and OID extensions.
    /// Connections are routed to the correct cert via SNI.
    ///
    /// Called once during init to collect initial identities. For
    /// dynamically loaded apps (e.g. WASM), modules should also call
    /// [`crate::ratls::cert_store::cert_store()`] directly to
    /// register/unregister identities at runtime.
    fn app_identities(&self) -> Vec<AppIdentity> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
//  Registry
// ---------------------------------------------------------------------------

/// Global registry of modules.
static MODULES: Mutex<Vec<Box<dyn EnclaveModule>>> = Mutex::new(Vec::new());

/// Register a module. Call during enclave startup.
pub fn register_module(module: Box<dyn EnclaveModule>) {
    MODULES.lock().unwrap().push(module);
}

/// Collect config leaves from all registered modules.
pub fn collect_module_config_leaves() -> Vec<ConfigLeaf> {
    let mut leaves = Vec::new();
    for module in MODULES.lock().unwrap().iter() {
        leaves.extend(module.config_leaves());
    }
    leaves
}

/// Collect custom OIDs from all registered modules.
pub fn collect_module_oids() -> Vec<ModuleOid> {
    let mut oids = Vec::new();
    for module in MODULES.lock().unwrap().iter() {
        oids.extend(module.custom_oids());
    }
    oids
}

/// Collect app identities from all registered modules.
pub fn collect_app_identities() -> Vec<AppIdentity> {
    let mut identities = Vec::new();
    for module in MODULES.lock().unwrap().iter() {
        identities.extend(module.app_identities());
    }
    identities
}

/// Dispatch a request to the first module that handles it.
pub fn dispatch(req: &Request, ctx: &RequestContext) -> Option<Response> {
    for module in MODULES.lock().unwrap().iter() {
        if let Some(resp) = module.handle(req, ctx) {
            return Some(resp);
        }
    }
    None
}
