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
//! ## Composition
//!
//! By default, the `default-ecall` feature provides a minimal `ecall_run`
//! that registers only the HelloWorld diagnostic module, keeping the
//! enclave binary small.
//!
//! To add modules (e.g. WASM runtime), create a separate crate that:
//! 1. Depends on `enclave-os-enclave` with `default-features = false`
//!    and `features = ["sgx"]` (disabling `default-ecall`).
//! 2. Provides its own `#[no_mangle] pub extern "C" fn ecall_run(…)`.
//! 3. Calls [`ecall::init_enclave()`] → registers modules →
//!    [`ecall::finalize_and_run()`].
//!
//! See https://github.com/Privasys/wasm-app-example for a complete example.
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

use crate::ratls::server::IngressServer;
use crate::rpc_client::RpcClient;

use enclave_os_common::queue::{SpscProducer, SpscConsumer};

// ---------------------------------------------------------------------------
//  Global state
// ---------------------------------------------------------------------------

/// Global RPC client (set by `ecall_init_channel`).
static RPC_CLIENT: OnceLock<RpcClient> = OnceLock::new();

/// Shutdown flag – set when `ecall_shutdown` is called.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Data channel: enclave → host TCP proxy (set by `ecall_init_data_channel`).
static DATA_TX: OnceLock<SpscProducer> = OnceLock::new();

/// Data channel: host TCP proxy → enclave (set by `ecall_init_data_channel`).
static DATA_RX: OnceLock<SpscConsumer> = OnceLock::new();

/// Configuration Merkle root – delegates to the [`config_merkle`] manifest.
///
/// Returns `None` before the tree is finalized during init.
pub fn config_merkle_root() -> Option<&'static [u8; 32]> {
    config_merkle::config_manifest().map(|m| m.root())
}

/// Global enclave application state, initialised by `ecall_run`.
pub struct EnclaveState {
    pub ingress_server: Option<IngressServer>,
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

/// Get a reference to the data channel producer (enclave → host).
pub fn data_tx() -> &'static SpscProducer {
    DATA_TX.get().expect("Data channel not initialised")
}

/// Get a reference to the data channel consumer (host → enclave).
pub fn data_rx() -> &'static SpscConsumer {
    DATA_RX.get().expect("Data channel not initialised")
}

/// Check if shutdown has been requested.
pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Initialise the enclave state.
pub fn init_state() -> Result<(), i32> {
    let st = EnclaveState {
        ingress_server: None,
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

/// Store the data channel endpoints. Called once from `ecall_init_data_channel`.
pub fn set_data_channel(tx: SpscProducer, rx: SpscConsumer) -> Result<(), i32> {
    DATA_TX.set(tx).map_err(|_| -1)?;
    DATA_RX.set(rx).map_err(|_| -1)?;
    Ok(())
}

/// Signal shutdown.
pub fn signal_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}
