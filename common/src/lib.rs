// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! enclave-os-common: shared types and constants between host and enclave.
//!
//! This crate is `no_std`-compatible when the `sgx` feature is enabled,
//! so it can be linked into the enclave.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
extern crate alloc;

pub mod protocol;
pub mod queue;
pub mod rpc;
pub mod types;

#[cfg(feature = "jwt")]
pub mod jwt;
