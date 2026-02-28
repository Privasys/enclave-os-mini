// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Wire protocol types for WASM inter-module communication.
//!
//! Clients send [`WasmCall`] requests (serialised as JSON inside
//! [`Request::Data`]) and receive [`WasmResult`] responses.
//!
//! ## Request format
//!
//! ```json
//! {
//!   "wasm_call": {
//!     "app": "my-app",
//!     "function": "process",
//!     "params": [{"type": "string", "value": "hello"}]
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::vec::Vec;

// ---------------------------------------------------------------------------
//  Envelope — top-level JSON discriminator
// ---------------------------------------------------------------------------

/// Top-level request envelope.
///
/// The `Request::Data` payload is deserialized into this.  Exactly one of
/// the fields should be `Some` — the WASM module checks them in order:
/// `wasm_call`, `wasm_load`, `wasm_unload`, `wasm_list`.
///
/// If all fields are `None`, the WASM module declines the request
/// (returning `None` so other modules can handle it).
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmEnvelope {
    /// Call an exported function on a loaded WASM app.
    #[serde(default)]
    pub wasm_call: Option<WasmCall>,

    /// Load (or replace) a WASM app from raw component bytes.
    #[serde(default)]
    pub wasm_load: Option<WasmLoad>,

    /// Unload a WASM app by name.
    #[serde(default)]
    pub wasm_unload: Option<WasmUnload>,

    /// List all loaded WASM apps (no payload needed, just `"wasm_list": {}`).
    #[serde(default)]
    pub wasm_list: Option<WasmList>,
}

// ---------------------------------------------------------------------------
//  Management commands — load / unload / list
// ---------------------------------------------------------------------------

/// Load a WASM component into the enclave at runtime.
///
/// ```json
/// {
///   "wasm_load": {
///     "name": "my-app",
///     "bytes": [0, 97, 115, 109, ...]
///   }
/// }
/// ```
///
/// The `bytes` field contains the raw WASM component bytecode.
/// If an app with the same name is already loaded, it will be replaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmLoad {
    /// App identifier — used in subsequent `wasm_call` requests.
    pub name: String,
    /// Raw WASM component bytecode (AOT-compiled).
    pub bytes: Vec<u8>,
    /// SNI hostname for this app's dedicated TLS certificate.
    ///
    /// If absent, defaults to the app `name`. Clients connecting via
    /// this hostname will receive a per-app X.509 certificate containing
    /// the app's config Merkle root and any declared OID extensions.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Bring-Your-Own-Key: hex-encoded 32-byte AES-256 encryption key
    /// for this app's KV store data.
    ///
    /// If absent, a random key is generated inside the enclave via
    /// RDRAND. The generated key exists only in enclave memory and is
    /// destroyed when the app is unloaded — making any on-disk data
    /// permanently unrecoverable.
    ///
    /// If present, the caller supplies the key so the same data can be
    /// read across app reloads.
    #[serde(default)]
    pub encryption_key: Option<String>,
}

/// Unload a WASM app by name.
///
/// ```json
/// { "wasm_unload": { "name": "my-app" } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmUnload {
    /// App identifier to remove.
    pub name: String,
}

/// List all loaded WASM apps.
///
/// ```json
/// { "wasm_list": {} }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmList {}

/// Result of a management operation (load / unload / list).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum WasmManagementResult {
    /// App loaded successfully.
    #[serde(rename = "loaded")]
    Loaded {
        /// The loaded app's metadata.
        app: AppInfo,
    },
    /// App unloaded successfully.
    #[serde(rename = "unloaded")]
    Unloaded {
        /// Name of the removed app.
        name: String,
    },
    /// App not found (unload of non-existent app).
    #[serde(rename = "not_found")]
    NotFound {
        /// Name that was requested.
        name: String,
    },
    /// List of all loaded apps.
    #[serde(rename = "apps")]
    Apps {
        /// All currently loaded apps with metadata.
        apps: Vec<AppInfo>,
    },
    /// Management operation failed.
    #[serde(rename = "error")]
    Error {
        /// Human-readable error message.
        message: String,
    },
}

// ---------------------------------------------------------------------------
//  WasmCall — incoming request
// ---------------------------------------------------------------------------

/// A call targeting a specific WASM app and exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmCall {
    /// Registered app identifier (the name used when the app was loaded).
    pub app: String,
    /// Exported function name to invoke.
    pub function: String,
    /// Positional parameters, each with a type tag and value.
    ///
    /// An empty vec means no parameters.
    #[serde(default)]
    pub params: Vec<WasmParam>,
}

/// A typed parameter passed to a WASM function.
///
/// This mirrors the Component Model value types that can cross the
/// host↔guest boundary.  We keep this simple: the JSON carries a type
/// tag so the host can construct the correct `wasmtime::component::Val`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum WasmParam {
    /// A boolean value.
    #[serde(rename = "bool")]
    Bool(bool),
    /// A signed 32-bit integer.
    #[serde(rename = "s32")]
    S32(i32),
    /// A signed 64-bit integer.
    #[serde(rename = "s64")]
    S64(i64),
    /// An unsigned 32-bit integer.
    #[serde(rename = "u32")]
    U32(u32),
    /// An unsigned 64-bit integer.
    #[serde(rename = "u64")]
    U64(u64),
    /// A 32-bit float.
    #[serde(rename = "f32")]
    F32(f32),
    /// A 64-bit float.
    #[serde(rename = "f64")]
    F64(f64),
    /// A UTF-8 string.
    #[serde(rename = "string")]
    String(String),
    /// Raw bytes (base64-encoded in JSON).
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
//  WasmResult — outgoing response
// ---------------------------------------------------------------------------

/// Result of a WASM function call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum WasmResult {
    /// Successful execution with return values.
    #[serde(rename = "ok")]
    Ok {
        /// Return values from the function (may be empty for void fns).
        #[serde(default)]
        returns: Vec<WasmValue>,
    },
    /// Execution failed.
    #[serde(rename = "error")]
    Error {
        /// Human-readable error message.
        message: String,
    },
}

/// A value returned from a WASM function call.
///
/// Mirrors [`WasmParam`] but is output-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum WasmValue {
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "s32")]
    S32(i32),
    #[serde(rename = "s64")]
    S64(i64),
    #[serde(rename = "u32")]
    U32(u32),
    #[serde(rename = "u64")]
    U64(u64),
    #[serde(rename = "f32")]
    F32(f32),
    #[serde(rename = "f64")]
    F64(f64),
    #[serde(rename = "string")]
    String(String),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
//  App metadata (returned by list-apps)
// ---------------------------------------------------------------------------

/// Metadata for a loaded WASM app, suitable for inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    /// App identifier.
    pub name: String,
    /// SNI hostname for this app's dedicated TLS certificate.
    pub hostname: String,
    /// SHA-256 of the WASM component bytecode (hex-encoded).
    pub code_hash: String,
    /// How the app's KV store encryption key was provisioned.
    ///
    /// - `"byok"`: Bring-Your-Own-Key — caller supplied the key.
    /// - `"generated"`: Key was generated inside the enclave via RDRAND.
    pub key_source: String,
    /// Exported function signatures discovered from the component.
    pub exports: Vec<ExportedFunc>,
}

/// An exported function signature discovered from a WASM component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFunc {
    /// Function name.
    pub name: String,
    /// Number of parameters.
    pub param_count: usize,
    /// Number of return values.
    pub result_count: usize,
}
