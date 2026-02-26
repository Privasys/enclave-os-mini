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
/// The `Request::Data` payload is deserialized into this.  The `wasm_call`
/// field acts as a discriminator so the WASM module knows the request is
/// for it (other modules get `None` and decline).
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmEnvelope {
    pub wasm_call: Option<WasmCall>,
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
    /// SHA-256 of the WASM component bytecode (hex-encoded).
    pub code_hash: String,
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
