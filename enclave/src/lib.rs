// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-enclave: trusted core running inside the SGX enclave.
//!
//! This crate provides the core infrastructure for SGX enclave applications:
//! - RA-TLS ingress TCP server with per-session attestation
//! - Pluggable module architecture ([`modules::EnclaveModule`] trait)
//! - Sealed (encrypted) configuration bound to MRENCLAVE
//! - Config Merkle tree for auditable attestation
//! - Cryptographic primitives (AEAD, sealing)
//! - OCALL wrappers for host communication
//!
//! Business logic modules (egress, KV store, WASM, etc.) live in
//! separate crates and register themselves via
//! [`modules::register_module()`].
//!
//! ## Adopter integration
//!
//! By default, the `default-ecall` feature provides a minimal `ecall_run`
//! that registers only the HelloWorld example module. Adopters disable
//! this feature and provide their own `ecall_run`, using
//! [`ecall::init_enclave()`] and [`ecall::finalize_and_run()`] as
//! building blocks.
//!
//! **Build mode**: sysroot replacement.
//! `sgx_tstd` is compiled as `std` in a custom sysroot, so all crates
//! (including third-party deps like rustls) resolve `std` to `sgx_tstd`.
//! No `#![no_std]` or `extern crate sgx_tstd as std` is needed.

// sgx_types is provided by the sysroot (as a dependency of std/sgx_tstd).
// We access it via `extern crate` rather than a Cargo.toml dep to avoid
// having two copies of the same crate (sysroot vs. git).
extern crate sgx_types;

pub mod config_merkle;
pub mod cpuid_cache;
pub mod crypto;
pub mod ecall;
pub mod modules;
pub mod ocall;
pub mod ratls;
pub mod rpc_client;
pub mod sealed_config;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use std::sync::Mutex;

use crate::ratls::server::RaTlsServer;
use crate::rpc_client::RpcClient;

// ---------------------------------------------------------------------------
//  Global state
// ---------------------------------------------------------------------------

/// Global RPC client (set by `ecall_init_channel`).
static RPC_CLIENT: OnceLock<RpcClient> = OnceLock::new();

/// Shutdown flag – set when `ecall_shutdown` is called.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Configuration Merkle root – delegates to the [`config_merkle`] manifest.
///
/// Returns `None` before the tree is finalized during init.
pub fn config_merkle_root() -> Option<&'static [u8; 32]> {
    config_merkle::config_manifest().map(|m| m.root())
}

/// Global enclave application state, initialised by `ecall_run`.
pub struct EnclaveState {
    pub ratls_server: Option<RaTlsServer>,
}

static ENCLAVE_STATE: OnceLock<Mutex<EnclaveState>> = OnceLock::new();

/// Get a reference to the global enclave state.
pub fn state() -> &'static Mutex<EnclaveState> {
    ENCLAVE_STATE.get().expect("Enclave not initialised")
}

/// Get a reference to the global RPC client.
pub fn rpc_client_ref() -> &'static RpcClient {
    RPC_CLIENT.get().expect("RPC channel not initialised")
}

/// Check if shutdown has been requested.
pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Initialise the enclave state.
pub fn init_state() -> Result<(), i32> {
    let st = EnclaveState {
        ratls_server: None,
    };
    ENCLAVE_STATE
        .set(Mutex::new(st))
        .map_err(|_| -1)?;
    Ok(())
}

/// Store the RPC client. Called once from `ecall_init_channel`.
pub fn set_rpc_client(client: RpcClient) -> Result<(), i32> {
    RPC_CLIENT.set(client).map_err(|_| -1)
}

/// Signal shutdown.
pub fn signal_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}
