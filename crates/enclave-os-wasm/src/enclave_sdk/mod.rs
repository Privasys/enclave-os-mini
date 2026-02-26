// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! **Enclave OS SDK** — `privasys:enclave-os@0.1.0` host function implementations.
//!
//! This module exposes three Component Model interfaces to WASM apps:
//!
//! | Interface | Purpose |
//! |-----------|---------|
//! | `privasys:enclave-os/crypto@0.1.0` | Cryptographic primitives (digest, AEAD, ECDSA, HMAC, RNG) |
//! | `privasys:enclave-os/keystore@0.1.0` | Key generation / import / export / lifecycle |
//! | `privasys:enclave-os/https@0.1.0` | Secure HTTPS egress (TLS inside enclave) |
//!
//! ## Security model
//!
//! All operations run inside the SGX enclave:
//! - Crypto uses `ring` (backed by RDRAND for RNG)
//! - Key material stays in enclave memory, referenced by name
//! - HTTPS terminates TLS inside the enclave; the host only transports ciphertext
//!
//! ## Usage
//!
//! Called from [`crate::engine::WasmEngine::new`] to register with the
//! wasmtime [`Linker`][wasmtime::component::Linker]:
//!
//! ```ignore
//! enclave_sdk::add_to_linker(&mut linker)?;
//! ```

pub mod crypto;
pub mod https;
pub mod keystore;

pub use crate::wasi::AppContext;
pub use keystore::{KeyMaterial, KeyStore};

use wasmtime::component::Linker;

/// Register all `privasys:enclave-os@0.1.0` host function implementations.
///
/// This populates three interface namespaces on the linker:
/// - `privasys:enclave-os/crypto@0.1.0`
/// - `privasys:enclave-os/keystore@0.1.0`
/// - `privasys:enclave-os/https@0.1.0`
pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    crypto::add_to_linker(linker)?;
    keystore::add_to_linker(linker)?;
    https::add_to_linker(linker)?;
    Ok(())
}
