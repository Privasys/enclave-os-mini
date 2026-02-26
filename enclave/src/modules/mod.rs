// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Module registry, trait interface, and built-in module implementations.
//!
//! Modules implement [`EnclaveModule`] to:
//! - Handle client requests via [`handle()`](EnclaveModule::handle)
//! - Register config inputs for the Merkle tree via [`config_leaves()`](EnclaveModule::config_leaves)
//! - Register custom X.509 OIDs for RA-TLS certs via [`custom_oids()`](EnclaveModule::custom_oids)

// ---------------------------------------------------------------------------
//  Built-in modules
// ---------------------------------------------------------------------------
// HelloWorld is the only built-in module -- it exists as a minimal smoke-test
// for the `default-ecall` feature.  All production modules (egress, kvstore,
// vault, wasm, ...) live in `crates/enclave-os-*` and are registered by the
// adopter's custom `ecall_run`.

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
    /// OID arc sequence (e.g. `&[1, 3, 6, 1, 4, 1, 1337, 2, 1]`).
    pub oid: &'static [u64],
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  EnclaveModule trait
// ---------------------------------------------------------------------------

/// Trait for pluggable enclave business logic modules.
pub trait EnclaveModule: Send + Sync {
    /// Human-readable module name (used as config leaf prefix).
    fn name(&self) -> &str;

    /// Handle a client request. Returns `Some(response)` if handled.
    fn handle(&self, req: &Request) -> Option<Response>;

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

/// Dispatch a request to the first module that handles it.
pub fn dispatch(req: &Request) -> Option<Response> {
    for module in MODULES.lock().unwrap().iter() {
        if let Some(resp) = module.handle(req) {
            return Some(resp);
        }
    }
    None
}
