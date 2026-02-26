// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Shared type definitions between host and enclave.

use serde::{Deserialize, Serialize};

/// Result type for enclave OS operations.
pub type EnclaveResult<T> = Result<T, EnclaveError>;

/// Error codes shared between host and enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum EnclaveError {
    /// Generic failure
    Unknown = -1,
    /// An SGX-specific error occurred
    SgxError = -2,
    /// Network I/O error
    NetworkError = -3,
    /// TLS handshake or protocol error
    TlsError = -4,
    /// RA-TLS attestation verification failed
    AttestationError = -5,
    /// Key-value store operation failed
    KvStoreError = -6,
    /// Sealing or unsealing failed
    SealingError = -7,
    /// Buffer too small
    BufferTooSmall = -8,
    /// Key not found in the KV store
    KeyNotFound = -9,
    /// Invalid argument
    InvalidArgument = -10,
    /// HTTP error (status code stored separately)
    HttpError = -11,
}

/// Log levels matching the OCall interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// Maximum sizes (bytes) for KV store operations.
pub const KV_MAX_KEY_SIZE: usize = 1024;
pub const KV_MAX_VALUE_SIZE: usize = 1024 * 1024; // 1 MiB

/// AES-256-GCM nonce size.
pub const AEAD_NONCE_SIZE: usize = 12;
/// AES-256-GCM tag size.
pub const AEAD_TAG_SIZE: usize = 16;
/// AES-256 key size.
pub const AEAD_KEY_SIZE: usize = 32;

/// RA-TLS custom TLS extension type for challenge nonce (0xFFBB).
/// Clients include this extension in ClientHello to request a
/// challenge-response attestation. The extension data is the nonce.
pub const RATLS_CLIENT_HELLO_EXTENSION_TYPE: u16 = 0xFFBB;

/// Size of an SGX quote buffer.
pub const SGX_QUOTE_MAX_SIZE: usize = 16384;
