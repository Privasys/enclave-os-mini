// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-common: shared types and constants between host and enclave.
//!
//! This crate is `no_std`-compatible when the `sgx` feature is enabled,
//! so it can be linked into the enclave.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
extern crate alloc;
pub mod channel;
pub mod hex;
pub mod modules;
pub mod ocall;
pub mod oids;
pub mod protocol;
pub mod queue;
pub mod quote;
pub mod rpc;
pub mod types;

#[cfg(feature = "jwt")]
pub mod jwt;

pub mod oidc;

#[cfg(feature = "crypto")]
pub mod aead;

/// Re-export `ring::digest` for downstream crates that need hashing.
#[cfg(feature = "crypto")]
pub use ring::digest;

// ── Convenience logging macros (call through the OCall vtable) ──────────

/// Log an info-level message via the host.
#[macro_export]
macro_rules! enclave_log_info {
    ($($arg:tt)*) => {
        $crate::ocall::log(2, &format!($($arg)*))
    };
}

/// Log an error-level message via the host.
#[macro_export]
macro_rules! enclave_log_error {
    ($($arg:tt)*) => {
        $crate::ocall::log(4, &format!($($arg)*))
    };
}

/// Log a debug-level message via the host.
#[macro_export]
macro_rules! enclave_log_debug {
    ($($arg:tt)*) => {
        $crate::ocall::log(1, &format!($($arg)*))
    };
}
