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
use std::collections::BTreeMap;
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

    /// Get the full typed API schema for a WASM app.
    #[serde(default)]
    pub wasm_schema: Option<WasmSchemaRequest>,

    /// Connect-protocol-style function call (named params as JSON object).
    #[serde(default)]
    pub connect_call: Option<ConnectCall>,

    /// Request the MCP tool manifest for a WASM app.
    #[serde(default)]
    pub mcp_tools: Option<WasmMcpRequest>,
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
    /// Optional per-app permission policy.
    ///
    /// When present, the enclave enforces per-function access control on
    /// `wasm_call` requests using the app developer's own OIDC provider.
    /// The SHA-256 hash of the serialised permissions JSON is embedded in
    /// the per-app RA-TLS certificate as OID `1.3.6.1.4.1.65230.3.5`.
    ///
    /// When absent, all exported functions are callable without
    /// authentication.
    #[serde(default)]
    pub permissions: Option<AppPermissions>,
    /// Maximum fuel budget per call for this app.
    ///
    /// Each `wasm_call` invocation starts with this many fuel units.
    /// When the budget is exhausted, the WASM instance traps.
    /// Defaults to 10 000 000 (~a few hundred ms of compute) when absent.
    #[serde(default)]
    pub max_fuel: Option<u64>,
    /// Whether to expose this app as an MCP tool server.
    ///
    /// When `true` (the default), the schema endpoint includes an
    /// MCP-compatible tool manifest derived from the app's WIT types
    /// and `///` doc comments embedded in the `package-docs` custom
    /// section of the `.wasm` binary.
    ///
    /// Set to `false` to disable MCP tool generation for this app.
    #[serde(default = "default_mcp_enabled")]
    pub mcp_enabled: Option<bool>,
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

/// Request the typed API schema for a WASM app.
///
/// ```json
/// { "wasm_schema": { "app": "my-app" } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSchemaRequest {
    /// App identifier.
    pub app: String,
    /// App-level OIDC bearer token (same semantics as [`WasmCall::app_auth`]).
    ///
    /// Required when the app has a `permissions` policy with a non-public
    /// `schema_policy`.
    #[serde(default)]
    pub app_auth: Option<String>,
}

/// Connect-protocol-style function call.
///
/// Instead of positional [`WasmParam`] values, the caller sends a JSON
/// object with named fields.  The enclave uses the function's WIT schema
/// to convert names to positional parameters.
///
/// ```json
/// { "connect_call": { "app": "my-app", "function": "get", "body": {"key": "hello"} } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectCall {
    /// App identifier.
    pub app: String,
    /// Function name (or qualified `interface/function`).
    pub function: String,
    /// Named parameters as a JSON object.
    #[serde(default)]
    pub body: serde_json::Value,
    /// App-level OIDC bearer token (same semantics as [`WasmCall::app_auth`]).
    #[serde(default)]
    pub app_auth: Option<String>,
}

/// Request the MCP tool manifest for a WASM app.
///
/// ```json
/// { "mcp_tools": { "app": "my-app" } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmMcpRequest {
    /// App identifier.
    pub app: String,
    /// App-level OIDC bearer token (same semantics as [`WasmCall::app_auth`]).
    #[serde(default)]
    pub app_auth: Option<String>,
}

// ---------------------------------------------------------------------------
//  MCP tool manifest types
// ---------------------------------------------------------------------------

/// MCP-compatible tool manifest for a WASM app.
///
/// Each exported function becomes an MCP tool whose `inputSchema` is a
/// JSON Schema object derived from the function's WIT parameter types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolManifest {
    /// App identifier.
    pub name: String,
    /// List of tools (one per exported function).
    pub tools: Vec<McpTool>,
}

/// A single MCP tool derived from a WIT exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// Tool name (function path, e.g. `"hello"` or `"my-api/transform"`).
    pub name: String,
    /// Human-readable description from `///` doc comments in WIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

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
    /// App schema response.
    #[serde(rename = "schema")]
    Schema {
        /// Full typed API schema.
        schema: AppSchema,
    },
    /// MCP tool manifest response.
    #[serde(rename = "mcp_tools")]
    McpTools {
        /// MCP-compatible tool manifest.
        manifest: McpToolManifest,
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
    /// App-level OIDC bearer token.
    ///
    /// When the app has a `permissions` policy, this token is verified
    /// against the app developer's OIDC provider (not the platform's).
    /// The field is separate from the top-level `"auth"` to avoid
    /// collision with the platform auth layer.
    #[serde(default)]
    pub app_auth: Option<String>,
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
    /// - `"byok:<fingerprint>"`: Bring-Your-Own-Key — caller supplied the
    ///   key; `<fingerprint>` is the hex SHA-256 of the raw key bytes.
    /// - `"generated"`: Key was generated inside the enclave via RDRAND.
    pub key_source: String,
    /// Exported function signatures discovered from the component.
    pub exports: Vec<ExportedFunc>,
    /// SHA-256 hash of the permissions JSON (hex), or `null` if no
    /// permissions policy is configured (all functions are public).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_hash: Option<String>,
    /// Maximum fuel budget per call for this app.
    pub max_fuel: u64,
    /// Whether the app is currently compiled in enclave memory.
    ///
    /// Unloaded apps are still persisted in the sealed KV store and
    /// will be recompiled on the next `wasm_call`.
    pub loaded: bool,
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

// ---------------------------------------------------------------------------
//  Per-app permission policy
// ---------------------------------------------------------------------------

/// Per-app permission policy supplied by the app developer.
///
/// Allows the app developer to bring their own OIDC provider and define
/// per-function access control.  The enclave enforces these rules at
/// `wasm_call` time.
///
/// The SHA-256 hash of the canonical JSON serialisation is included in
/// the per-app RA-TLS certificate (OID `1.3.6.1.4.1.65230.3.5`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPermissions {
    /// Schema version (must be `1`).
    pub version: u32,
    /// App developer's OIDC provider configuration for token verification.
    pub oidc: AppOidcConfig,
    /// Default policy for functions not listed in `functions`.
    ///
    /// - `"public"` — no authentication required
    /// - `"authenticated"` — valid OIDC token required (any role)
    /// - `"role"` — requires `default_roles`
    #[serde(default = "default_policy")]
    pub default_policy: FunctionPolicy,
    /// Roles required when `default_policy` is `Role`.
    #[serde(default)]
    pub default_roles: Vec<String>,
    /// Per-function policy overrides.  Key is the exported function name
    /// (e.g. `"process"` or `"my-api/transform"`).
    #[serde(default)]
    pub functions: BTreeMap<String, FunctionPermission>,
    /// Access policy for the schema endpoint (`wasm_schema` / `GET /rpc/<app>/schema`).
    ///
    /// Defaults to `public` — anyone can view the schema.  Set to
    /// `authenticated` or `role` to restrict schema discovery.
    #[serde(default = "default_policy")]
    pub schema_policy: FunctionPolicy,
    /// Roles required when `schema_policy` is `Role`.
    #[serde(default)]
    pub schema_roles: Vec<String>,
}

/// OIDC provider configuration for an app's own identity provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppOidcConfig {
    /// OIDC issuer URL (e.g. `https://auth.app-owner.com`).
    pub issuer: String,
    /// JWKS endpoint for token signature verification.
    pub jwks_uri: String,
    /// Expected `aud` claim in app user tokens.
    pub audience: String,
    /// Claim path for roles (default: `"roles"`).
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
}

/// Access policy for a single exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPermission {
    /// The policy type.
    pub policy: FunctionPolicy,
    /// Roles required when `policy` is `Role`.  Caller must have at
    /// least one of these roles.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Access policy type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FunctionPolicy {
    /// No authentication required — anyone can call.
    Public,
    /// A valid OIDC token is required but no specific role.
    Authenticated,
    /// A valid OIDC token with at least one of the specified roles.
    Role,
}

fn default_policy() -> FunctionPolicy {
    FunctionPolicy::Public
}

fn default_roles_claim() -> String {
    "roles".into()
}

fn default_mcp_enabled() -> Option<bool> {
    Some(true)
}

// ---------------------------------------------------------------------------
//  WIT type descriptors & API schema
// ---------------------------------------------------------------------------

/// Serialisable WIT type descriptor.
///
/// Represents the full WIT type system: scalars, strings, lists, records,
/// variants, options, results, tuples, enums, and flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum WitType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    #[serde(rename = "f32")]
    Float32,
    #[serde(rename = "f64")]
    Float64,
    Char,
    String,
    List {
        element: Box<WitType>,
    },
    Option {
        inner: Box<WitType>,
    },
    Result {
        #[serde(skip_serializing_if = "Option::is_none")]
        ok: Option<Box<WitType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        err: Option<Box<WitType>>,
    },
    Record {
        fields: Vec<FieldSchema>,
    },
    Variant {
        cases: Vec<CaseSchema>,
    },
    Tuple {
        elements: Vec<WitType>,
    },
    Flags {
        names: Vec<String>,
    },
    Enum {
        names: Vec<String>,
    },
}

/// A field within a WIT record type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: WitType,
}

/// A case within a WIT variant type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSchema {
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub ty: Option<WitType>,
}

/// A named + typed parameter or return value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: WitType,
    /// Human-readable description from `///` doc comment in WIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Full signature of an exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSchema {
    pub name: String,
    pub params: Vec<ParamSchema>,
    pub results: Vec<ParamSchema>,
    /// Human-readable description from `///` doc comment in WIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An exported interface containing one or more functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSchema {
    pub name: String,
    pub functions: Vec<FunctionSchema>,
    /// Human-readable description from `///` doc comment in WIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Complete typed API schema for a WASM app.
///
/// Generated from the WIT type information at load time and persisted
/// in the sealed KV store alongside the app metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSchema {
    /// App identifier.
    pub name: String,
    /// SNI hostname.
    pub hostname: String,
    /// Root-level exported functions (not inside any interface).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<FunctionSchema>,
    /// Exported interfaces with their functions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceSchema>,
    /// Whether MCP tool generation is enabled for this app.
    #[serde(default = "default_true")]
    pub mcp_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl AppSchema {
    /// Build the exports routing table from the schema.
    ///
    /// Returns `(function_name, (param_count, result_count))` pairs
    /// suitable for the [`LoadedApp`](crate::registry::LoadedApp) exports map.
    pub fn to_exports_map(&self) -> std::collections::BTreeMap<String, (usize, usize)> {
        let mut map = std::collections::BTreeMap::new();
        for f in &self.functions {
            map.insert(f.name.clone(), (f.params.len(), f.results.len()));
        }
        for iface in &self.interfaces {
            for f in &iface.functions {
                let qualified = format!("{}/{}", iface.name, f.name);
                map.insert(qualified, (f.params.len(), f.results.len()));
            }
        }
        map
    }

    /// Find the schema for a function by name (root or qualified).
    pub fn find_function(&self, name: &str) -> Option<&FunctionSchema> {
        // Check root functions first.
        if let Some(f) = self.functions.iter().find(|f| f.name == name) {
            return Some(f);
        }
        // Check qualified interface/function names.
        for iface in &self.interfaces {
            for f in &iface.functions {
                let qualified = format!("{}/{}", iface.name, f.name);
                if qualified == name {
                    return Some(f);
                }
            }
        }
        None
    }

    /// Generate an MCP tool manifest from the schema.
    ///
    /// Each exported function becomes an [`McpTool`] with a JSON Schema
    /// `inputSchema` derived from its WIT parameter types.
    pub fn to_mcp_manifest(&self) -> McpToolManifest {
        let mut tools = Vec::new();

        for f in &self.functions {
            tools.push(function_to_mcp_tool(&f.name, f));
        }
        for iface in &self.interfaces {
            for f in &iface.functions {
                let qualified = format!("{}/{}", iface.name, f.name);
                tools.push(function_to_mcp_tool(&qualified, f));
            }
        }

        McpToolManifest {
            name: self.name.clone(),
            tools,
        }
    }
}

/// Convert a [`FunctionSchema`] to an [`McpTool`] with JSON Schema input.
fn function_to_mcp_tool(name: &str, func: &FunctionSchema) -> McpTool {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for p in &func.params {
        let mut schema = wit_type_to_json_schema(&p.ty);
        if let Some(ref desc) = p.description {
            if let serde_json::Value::Object(ref mut m) = schema {
                m.insert("description".into(), serde_json::Value::String(desc.clone()));
            }
        }
        properties.insert(p.name.clone(), schema);
        // All WIT params are required unless the type is option.
        if !matches!(p.ty, WitType::Option { .. }) {
            required.push(serde_json::Value::String(p.name.clone()));
        }
    }

    let input_schema = serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    });

    McpTool {
        name: name.to_string(),
        description: func.description.clone(),
        input_schema,
    }
}

/// Convert a [`WitType`] to a JSON Schema value.
fn wit_type_to_json_schema(ty: &WitType) -> serde_json::Value {
    match ty {
        WitType::Bool => serde_json::json!({ "type": "boolean" }),
        WitType::U8 | WitType::U16 | WitType::U32 | WitType::U64
        | WitType::S8 | WitType::S16 | WitType::S32 | WitType::S64 => {
            serde_json::json!({ "type": "integer" })
        }
        WitType::Float32 | WitType::Float64 => {
            serde_json::json!({ "type": "number" })
        }
        WitType::Char | WitType::String => {
            serde_json::json!({ "type": "string" })
        }
        WitType::List { element } => serde_json::json!({
            "type": "array",
            "items": wit_type_to_json_schema(element),
        }),
        WitType::Option { inner } => {
            let inner_schema = wit_type_to_json_schema(inner);
            serde_json::json!({
                "anyOf": [inner_schema, { "type": "null" }]
            })
        }
        WitType::Result { ok, err } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), serde_json::Value::String("object".into()));
            let mut props = serde_json::Map::new();
            if let Some(ok_ty) = ok {
                props.insert("ok".into(), wit_type_to_json_schema(ok_ty));
            }
            if let Some(err_ty) = err {
                props.insert("err".into(), wit_type_to_json_schema(err_ty));
            }
            obj.insert("properties".into(), serde_json::Value::Object(props));
            serde_json::Value::Object(obj)
        }
        WitType::Record { fields } => {
            let mut props = serde_json::Map::new();
            let mut req = Vec::new();
            for f in fields {
                props.insert(f.name.clone(), wit_type_to_json_schema(&f.ty));
                req.push(serde_json::Value::String(f.name.clone()));
            }
            serde_json::json!({
                "type": "object",
                "properties": props,
                "required": req,
            })
        }
        WitType::Tuple { elements } => {
            let items: Vec<serde_json::Value> = elements.iter()
                .map(wit_type_to_json_schema)
                .collect();
            serde_json::json!({
                "type": "array",
                "prefixItems": items,
                "items": false,
            })
        }
        WitType::Enum { names } => serde_json::json!({
            "type": "string",
            "enum": names,
        }),
        WitType::Variant { cases } => {
            let one_of: Vec<serde_json::Value> = cases.iter()
                .map(|c| {
                    if let Some(ref t) = c.ty {
                        serde_json::json!({
                            "type": "object",
                            "properties": {
                                "tag": { "const": c.name },
                                "value": wit_type_to_json_schema(t),
                            },
                            "required": ["tag", "value"],
                        })
                    } else {
                        serde_json::json!({
                            "type": "object",
                            "properties": {
                                "tag": { "const": c.name },
                            },
                            "required": ["tag"],
                        })
                    }
                })
                .collect();
            serde_json::json!({ "oneOf": one_of })
        }
        WitType::Flags { names } => serde_json::json!({
            "type": "array",
            "items": { "type": "string", "enum": names },
            "uniqueItems": true,
        }),
    }
}
