// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Module registry, trait interface, and built-in module implementations.
//!
//! Modules implement [`EnclaveModule`] to:
//! - Handle client requests via [`handle()`](EnclaveModule::handle)
//! - Register config inputs for the Merkle tree via [`config_leaves()`](EnclaveModule::config_leaves)
//! - Register custom X.509 OIDs for RA-TLS certs via [`custom_oids()`](EnclaveModule::custom_oids)
//! - Declare per-app identities for SNI-routed certs via [`app_identities()`](EnclaveModule::app_identities)
//!
//! The trait and its associated types live in `enclave-os-common::modules`.
//! The registry (global module list, dispatch, collect helpers) is
//! enclave-specific and lives here.

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

use enclave_os_common::modules::{
    AppIdentity, ConfigLeaf, EnclaveModule, ModuleOid, RequestContext,
};
use enclave_os_common::protocol::{Request, Response};

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

/// Return the number of registered modules.
pub fn module_count() -> usize {
    MODULES.lock().unwrap().len()
}

/// Let every module enrich the enclave-level metrics.
pub fn enrich_metrics(metrics: &mut enclave_os_common::protocol::EnclaveMetrics) {
    for module in MODULES.lock().unwrap().iter() {
        module.enrich_metrics(metrics);
    }
}

/// Collect module statuses for the /status endpoint.
pub fn collect_module_statuses() -> Vec<enclave_os_common::protocol::ModuleStatus> {
    MODULES
        .lock()
        .unwrap()
        .iter()
        .map(|m| enclave_os_common::protocol::ModuleStatus {
            name: m.name().to_string(),
            details: serde_json::json!({ "status": "ok" }),
        })
        .collect()
}
