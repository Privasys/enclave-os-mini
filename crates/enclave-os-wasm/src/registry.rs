// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! App registry — loading, introspection, and routing of WASM components.
//!
//! Each loaded app is a compiled wasmtime [`Component`] with metadata
//! extracted from its WIT exports.  The registry maps app names to their
//! components and provides typed function dispatch.
//!
//! ## App lifecycle
//!
//! 1. **Load**: WASM component bytes → compile → introspect exports →
//!    register in the routing table.
//! 2. **Call**: Look up app by name → instantiate (or reuse) → find
//!    exported function → marshal params → invoke → marshal results.
//! 3. **Unload**: Remove from registry (freeing compiled code).
//!
//! ## WIT-based routing
//!
//! The Component Model organises exports by *interface*.  A component
//! declaring:
//!
//! ```wit
//! package my-org:my-app;
//! world my-app {
//!     export process: func(input: string) -> string;
//!     export my-api: interface {
//!         transform: func(data: list<u8>) -> list<u8>;
//!     }
//! }
//! ```
//!
//! will expose these callable paths:
//! - `process` (root-level export)
//! - `my-api/transform` (interface-scoped export)
//!
//! Clients address them via [`WasmCall::function`] using either the bare
//! name or the `interface/function` qualified name.
//!
//! [`Component`]: wasmtime::component::Component
//! [`WasmCall::function`]: crate::protocol::WasmCall::function

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use wasmtime::component::{Component, Func, Val};
use wasmtime::Store;

use crate::engine::WasmEngine;
use crate::protocol::{
    AppPermissions, ExportedFunc, FunctionPermission, FunctionPolicy, WasmParam, WasmResult,
    WasmValue,
};
use crate::wasi::AppContext;
use enclave_os_common::types::AEAD_KEY_SIZE;

/// Host-KV table holding each vault-backed app's wrapped `encryption_key`.
/// The value is AES-256-GCM(encryption_key, KEK), so it is safe at rest on the
/// untrusted host; only an enclave that can reconstruct the KEK can unwrap it.
const VAULTWRAP_TABLE: &[u8] = b"vaultwrap";

/// Instructs `load_app` to vault-back an app's `encryption_key`. The platform
/// authors the owner-bound policy and delivers it as a key-creation grant; the
/// enclave discovers the constellation from the directory (`mgmt_url`), then on
/// first boot CREATES the key with the grant + reconstructs the KEK over its Tee
/// cert. No secret location comes over the wire — only the opt-in, the directory
/// location, and the grant.
pub struct VaultBacking {
    /// Management-service base URL (the directory `GET /api/v1/vaults`).
    pub mgmt_url: String,
    /// Platform environment for the directory query (`dev` / `prod`).
    pub environment: String,
    /// Vault key handle, derived by the caller from the app id
    /// (`apps.privasys.org/<app-id>/storage-kek/v1`).
    pub handle: String,
    /// Platform-minted key-creation grant (JWT), presented to create the key on
    /// first boot. Empty once the key exists.
    pub grant: String,
    /// The enclave's sealed selection from a prior load (`AppMeta.vault_config`),
    /// or `None` on first load (then the directory is consulted).
    pub sealed: Option<crate::vaultkey::VaultConfig>,
}

/// Resolve a vault-backed app's `encryption_key` (the KV DEK): reconstruct the
/// KEK from the constellation (creating the key on first ever load), then unwrap
/// the host-persistent wrapped DEK blob, or — when no blob exists yet — generate
/// (or take BYOK), wrap it under the KEK, and persist the blob.
///
/// Returns `(dek, key_source, selection)`. The DEK never changes here; only how
/// it is protected does — which is what lets the data survive an enclave upgrade
/// and makes KEK rotation a cheap re-wrap. The returned `selection` is sealed
/// into `AppMeta` by the caller.
fn resolve_vault_backed_key(
    vb: &VaultBacking,
    code_hash: &[u8; 32],
    app_id: Option<[u8; 16]>,
    byok: Option<[u8; AEAD_KEY_SIZE]>,
) -> Result<([u8; AEAD_KEY_SIZE], String, crate::vaultkey::VaultConfig), String> {
    use crate::vaultkey;
    use enclave_os_common::aead::AeadCipher;
    use enclave_os_common::ocall;

    let app_id_slice = app_id.as_ref().map(|a| a.as_slice());

    // The selection: the sealed one if we have it, else discovered from the
    // directory (authenticated by a timestamp-bound quote, inside `discover`).
    let cfg = match &vb.sealed {
        Some(c) => c.clone(),
        None => vaultkey::discover(&vb.mgmt_url, &vb.environment)?,
    };

    // Reconstruct the KEK; on first boot resolve_or_provision creates the key with
    // the platform-minted grant. A policy denial is the upgrade gate (fail closed),
    // not a first boot.
    let kek = vaultkey::resolve_or_provision(&cfg, &vb.handle, &vb.grant, code_hash, app_id_slice)?;

    let cipher = AeadCipher::from_key(kek);
    let key_id = vb.handle.as_bytes();
    // Bind the wrapped blob to this handle so it can't be swapped between apps.
    let aad = vb.handle.as_bytes();

    let (dek, source) = match ocall::kv_store_get(VAULTWRAP_TABLE, key_id)
        .map_err(|e| format!("vaultkey: host kv get: {e}"))?
    {
        Some(blob) => {
            let key_vec = cipher
                .decrypt(&blob, aad)
                .map_err(|e| format!("vaultkey: unwrap encryption_key: {e}"))?;
            let key: [u8; AEAD_KEY_SIZE] = key_vec
                .as_slice()
                .try_into()
                .map_err(|_| String::from("vaultkey: wrapped encryption_key has wrong length"))?;
            (key, format!("vault:{}", vb.handle))
        }
        None => {
            let key = match byok {
                Some(k) => k,
                None => {
                    let mut k = [0u8; AEAD_KEY_SIZE];
                    SystemRandom::new()
                        .fill(&mut k)
                        .map_err(|_| String::from("vaultkey: RDRAND failed generating key"))?;
                    k
                }
            };
            let blob = cipher
                .encrypt(&key, aad)
                .map_err(|e| format!("vaultkey: wrap encryption_key: {e}"))?;
            ocall::kv_store_put(VAULTWRAP_TABLE, key_id, &blob)
                .map_err(|e| format!("vaultkey: host kv put: {e}"))?;
            (key, format!("vault:{}", vb.handle))
        }
    };

    Ok((dek, source, cfg))
}

/// Rotate a vault-backed app's storage KEK: re-wrap the `encryption_key` (the KV
/// DEK) from the OLD key generation to a NEW one on the same constellation.
///
/// This is the WASM analog of the container's LUKS keyslot re-key: the DEK never
/// changes, so the sealed KV (encrypted under the DEK) is untouched — only the
/// KEK that protects the host-side wrapped DEK blob advances. The old KEK is
/// reconstructed by EXPORT (it exists, so no grant is needed); the new KEK is
/// reconstructed by CREATE with the owner-minted `new_grant`. The freshly wrapped
/// blob is stored under the new handle (AAD-bound to it) and the old blob is
/// retired. The vault retires the old KEK generation separately (owner-proxied),
/// after which the old blob is permanently un-unwrappable.
fn rotate_vault_backed_key(
    cfg: &crate::vaultkey::VaultConfig,
    old_handle: &str,
    new_handle: &str,
    new_grant: &str,
    code_hash: &[u8; 32],
    app_id: Option<[u8; 16]>,
) -> Result<(), String> {
    use crate::vaultkey;
    use enclave_os_common::aead::AeadCipher;
    use enclave_os_common::ocall;

    let app_id_slice = app_id.as_ref().map(|a| a.as_slice());

    // Old KEK: the key already exists, so export it (a grant is only needed to
    // CREATE). A policy denial here is the upgrade gate, not a first boot.
    let old_kek = vaultkey::resolve_or_provision(cfg, old_handle, "", code_hash, app_id_slice)?;
    // New KEK: create the new generation with the owner-minted grant.
    let new_kek =
        vaultkey::resolve_or_provision(cfg, new_handle, new_grant, code_hash, app_id_slice)?;

    let old_cipher = AeadCipher::from_key(old_kek);
    let new_cipher = AeadCipher::from_key(new_kek);

    // Unwrap the DEK from the old blob (AAD-bound to the old handle).
    let blob = ocall::kv_store_get(VAULTWRAP_TABLE, old_handle.as_bytes())
        .map_err(|e| format!("vaultkey: host kv get: {e}"))?
        .ok_or_else(|| format!("vaultkey: no wrapped key at handle {old_handle}"))?;
    let dek = old_cipher
        .decrypt(&blob, old_handle.as_bytes())
        .map_err(|e| format!("vaultkey: unwrap encryption_key (old KEK): {e}"))?;

    // Re-wrap under the new KEK (AAD-bound to the new handle) and persist before
    // retiring the old blob, so a crash mid-rotation never loses the only copy.
    let new_blob = new_cipher
        .encrypt(&dek, new_handle.as_bytes())
        .map_err(|e| format!("vaultkey: wrap encryption_key (new KEK): {e}"))?;
    ocall::kv_store_put(VAULTWRAP_TABLE, new_handle.as_bytes(), &new_blob)
        .map_err(|e| format!("vaultkey: host kv put: {e}"))?;

    // Retire the old wrapped blob (best-effort; the vault retires the old KEK
    // generation, which is what actually makes the old blob unrecoverable).
    let _ = ocall::kv_store_delete(VAULTWRAP_TABLE, old_handle.as_bytes());
    Ok(())
}

/// Owned per-invocation state produced by
/// [`AppRegistry::prepare_call()`]. Holds everything needed to run
/// the wasm function **without** the registry mutex held — this is
/// critical because wasm host functions (e.g.
/// `attestation.set-config-complete`) re-enter the registry to
/// mutate freeze-gate / extension state; holding the registry mutex
/// across `func.call()` would deadlock the single-threaded enclave
/// dispatcher.
pub struct CallPrep {
    pub store: Store<AppContext>,
    pub func: Func,
    pub val_params: Vec<Val>,
    pub result_count: usize,
    pub fuel_before: i64,
}

/// Maximum number of compiled WASM components kept in memory.
///
/// Enclave Page Cache (EPC) is limited, so we cap the number of
/// simultaneously compiled apps and evict the least-recently-used
/// when the limit is reached.  Apps evicted from memory remain
/// persisted in the sealed KV store and are reloaded on demand.
const MAX_LOADED_APPS: usize = 10;

// ---------------------------------------------------------------------------
//  WIT @auth annotation extraction
// ---------------------------------------------------------------------------

/// Parse a single `@auth` annotation value into a policy and optional roles.
///
/// Supported forms:
///   - `"public"`                   → (Public, [])
///   - `"authenticated"`            → (Authenticated, [])
///   - `"role(role-a, role-b)"`     → (Role, ["role-a", "role-b"])
fn parse_auth_annotation(value: &str) -> (FunctionPolicy, Vec<String>) {
    let v = value.trim();
    if v.eq_ignore_ascii_case("public") {
        return (FunctionPolicy::Public, Vec::new());
    }
    if v.eq_ignore_ascii_case("authenticated") {
        return (FunctionPolicy::Authenticated, Vec::new());
    }
    if v.eq_ignore_ascii_case("owner") {
        return (FunctionPolicy::Owner, Vec::new());
    }
    // role(role-a, role-b, ...)
    if let Some(inner) = v.strip_prefix("role(").and_then(|s| s.strip_suffix(')')) {
        let roles: Vec<String> = inner
            .split(',')
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        return (FunctionPolicy::Role, roles);
    }
    // Unrecognised → default to authenticated (safe fallback).
    (FunctionPolicy::Authenticated, Vec::new())
}

/// Extract per-function auth policies from docs `auth:*` keys.
///
/// Returns a merged `AppPermissions` if any `auth:` entries are found:
/// - `auth:__default__` → `default_policy` / `default_roles`
/// - `auth:<func-name>` → per-function override in `functions`
/// - OIDC/FIDO2 provider config is taken from the operator-supplied
///   `permissions` (if any).
fn merge_auth_from_docs(
    docs: &BTreeMap<String, String>,
    permissions: Option<AppPermissions>,
) -> Option<AppPermissions> {
    let auth_entries: Vec<(&str, &str)> = docs
        .iter()
        .filter_map(|(k, v)| k.strip_prefix("auth:").map(|name| (name, v.as_str())))
        .collect();

    if auth_entries.is_empty() {
        return permissions;
    }

    // Start with existing permissions or a fresh default.
    let mut perms = permissions.unwrap_or(AppPermissions {
        version: 1,
        oidc: None,
        fido2: false,
        default_policy: FunctionPolicy::Public,
        default_roles: Vec::new(),
        functions: BTreeMap::new(),
        schema_policy: FunctionPolicy::Public,
        schema_roles: Vec::new(),
    });

    for (name, value) in auth_entries {
        let (policy, roles) = parse_auth_annotation(value);
        if name == "__default__" {
            perms.default_policy = policy;
            perms.default_roles = roles;
        } else {
            perms
                .functions
                .insert(name.to_string(), FunctionPermission { policy, roles });
        }
    }

    Some(perms)
}

// ---------------------------------------------------------------------------
//  Persisted app metadata
// ---------------------------------------------------------------------------

/// Serialisable metadata for a WASM app persisted in the sealed KV store.
///
/// This is compact enough to keep in memory for *all* known apps,
/// even when the compiled component is evicted to save EPC.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppMeta {
    pub name: String,
    pub hostname: String,
    pub code_hash: [u8; 32],
    pub encryption_key: [u8; AEAD_KEY_SIZE],
    pub key_source: String,
    pub permissions: Option<AppPermissions>,
    pub configuration_hash: Option<[u8; 32]>,
    pub max_fuel: u64,
    /// Full WIT type schema generated at load time.
    ///
    /// `None` for apps persisted before schema support was added —
    /// a fresh schema is generated when the app is next lazy-loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<crate::protocol::AppSchema>,
    /// App-defined attestation extensions installed at runtime via the
    /// SDK `set-attestation-extension(arc_suffix, value)` call. Each
    /// entry is embedded in the per-app RA-TLS leaf certificate as a
    /// non-critical extension under OID
    /// `1.3.6.1.4.1.65230.3.5.{arc_suffix}`. Persisted so the
    /// extensions survive enclave restarts; the cert is replayed
    /// before traffic is unblocked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<u32, Vec<u8>>,
    /// Optional configure-only function name. When `Some(fn_name)`,
    /// only `wasm_call` invocations targeting `fn_name` are allowed
    /// until the app calls `set-config-complete`. Persisted so that
    /// after every enclave restart the app re-enters the frozen
    /// state and must be reconfigured before serving traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_api_function: Option<String>,
    /// Per-app owners team. Platform OIDC `sub` claims authorised to
    /// invoke exports decorated with the `Owner` auth policy
    /// (typically the `@config-api` configure entrypoint). Persisted
    /// so the freeze-gate stays callable by the right principals
    /// across restarts without consulting the platform.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<String>,
    /// Platform-assigned app identity (apps.id, raw 16-byte UUID). Stamped at
    /// OID 3.6 on the per-app leaf so a vault key can be bound to THIS app
    /// (MR_APP). `None` for apps loaded before app-id support (and for app-less
    /// callers), which keeps the MR_ENCLAVE behaviour. See the MR_APP / promote-step-up design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<[u8; 16]>,
    /// Vault-backed apps (Part 2): the enclave's sealed *selection* — which
    /// constellation vaults hold this app's KEK shares, plus the pins needed to
    /// reconstruct from them. Sensitive (it names the vaults), so it rides only
    /// inside this MRENCLAVE-sealed metadata, never on the host or the wire. The
    /// wrapped DEK blob lives host-side (`vaultwrap`); the KEK lives in the
    /// vaults. `None` for non-vault-backed apps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_config: Option<crate::vaultkey::VaultConfig>,
    /// Vault-backed apps (Part 2): the handle of the app's CURRENT key
    /// generation (`apps.privasys.org/<app-id>/storage-kek/v<N>`). Sealed so a
    /// key rotation that advances the generation survives an enclave restart: a
    /// same-MRENCLAVE replay reads the DEK straight from this sealed metadata,
    /// while a fresh load (upgrade) takes the live handle from the platform.
    /// `None` for non-vault-backed apps (and apps sealed before rotation support,
    /// which keeps the derived-`v1` behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_handle: Option<String>,
}

// ---------------------------------------------------------------------------
//  LoadedApp
// ---------------------------------------------------------------------------

/// A compiled WASM app with introspected metadata.
pub struct LoadedApp {
    /// User-chosen name for this app.
    pub name: String,
    /// SNI hostname for this app's dedicated TLS certificate.
    pub hostname: String,
    /// SHA-256 of the original WASM component bytecode.
    pub code_hash: [u8; 32],
    /// Per-app AES-256 encryption key for KV store data.
    ///
    /// Each app gets its own key so that data isolation is
    /// cryptographically enforced.  When the app is unloaded this key
    /// is dropped from memory, making any on-disk data permanently
    /// unrecoverable.
    encryption_key: [u8; AEAD_KEY_SIZE],
    /// How the encryption key was provisioned.
    ///
    /// - `"generated"` — key was generated inside the enclave.
    /// - `"byok:<fingerprint>"` — caller supplied the key;
    ///   `<fingerprint>` is the lowercase hex SHA-256 of the raw key
    ///   bytes so attesters can verify which key is in use.
    pub key_source: String,
    /// Compiled component (cheap to clone — refcounted internally).
    component: Component,
    /// Exported functions discovered from the component's WIT.
    ///
    /// Key: function path (e.g. `"process"` or `"my-api/transform"`).
    /// Value: `(param_count, result_count)`.
    exports: BTreeMap<String, (usize, usize)>,
    /// Optional per-app permission policy.
    pub permissions: Option<AppPermissions>,
    /// SHA-256 hash of the app configuration (auth policy + MCP settings).
    pub configuration_hash: Option<[u8; 32]>,
    /// Maximum fuel budget per `wasm_call` for this app.
    pub max_fuel: u64,
}

impl LoadedApp {
    /// List the exported functions.
    pub fn exported_funcs(&self) -> Vec<ExportedFunc> {
        self.exports
            .iter()
            .map(|(name, &(param_count, result_count))| ExportedFunc {
                name: name.clone(),
                param_count,
                result_count,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
//  AppRegistry
// ---------------------------------------------------------------------------

/// Registry of WASM apps with LRU-managed compiled components.
///
/// Two-tier architecture:
/// - **`known`**: Metadata for *all* persisted apps. Always in memory.
/// - **`loaded`**: Compiled components for recently-used apps (max
///   [`MAX_LOADED_APPS`]).  Evicted apps stay in `known` and are
///   recompiled on demand from KV-stored bytes.
pub struct AppRegistry {
    engine: WasmEngine,
    /// All known apps (metadata only). Always in memory.
    known: BTreeMap<String, AppMeta>,
    /// Currently compiled apps (LRU-managed).
    loaded: BTreeMap<String, LoadedApp>,
    /// LRU tracking: name → monotonic counter. Higher = more recent.
    lru: BTreeMap<String, u64>,
    /// Monotonic counter incremented on each access.
    lru_counter: u64,
    /// Per-app configure-only function name. Apps not present here
    /// have no freeze gate and accept calls to any export.
    config_api: BTreeMap<String, String>,
    /// Per-app freeze flag. `false` means only the configure function
    /// is callable; `true` means all exports are callable. In-memory
    /// only — always reset to `false` on (re)load when `config_api`
    /// is set.
    configured: BTreeMap<String, bool>,
    /// Per-app host-driven billing freeze (name → reason). Present
    /// means the app is paused for billing (e.g. `credits_exhausted`)
    /// and every export returns an error carrying the reason. Set by
    /// the management-service over the control channel and cleared on
    /// top-up. In-memory only — the feed re-applies it after a restart.
    /// Independent of the `configured` config-gate.
    billing_frozen: BTreeMap<String, String>,
}

impl AppRegistry {
    /// Create a new empty registry backed by the given engine.
    pub fn new(engine: WasmEngine) -> Self {
        Self {
            engine,
            known: BTreeMap::new(),
            loaded: BTreeMap::new(),
            lru: BTreeMap::new(),
            lru_counter: 0,
            config_api: BTreeMap::new(),
            configured: BTreeMap::new(),
            billing_frozen: BTreeMap::new(),
        }
    }

    /// Load a WASM component from pre-compiled AOT bytes.
    ///
    /// 1. Computes the SHA-256 code hash over the pre-compiled artifact.
    /// 2. Deserializes (no Cranelift — AOT only).
    /// 3. Introspects exports (root functions + interface members).
    /// 4. Registers under `name` with the given `hostname`.
    ///
    /// The `precompiled_bytes` must have been produced by
    /// `Engine::precompile_component()` or `Component::serialize()`
    /// outside the enclave with matching engine settings.
    ///
    /// If `encryption_key` is `Some`, the caller supplies the AES-256 key
    /// (BYOK). Otherwise a random key is generated via RDRAND.
    ///
    /// If `permissions` is `Some`, its SHA-256 hash is computed for OID
    /// attestation and the policy is stored for per-function enforcement.
    ///
    /// Returns an error if `name` is already taken or deserialization fails.
    pub fn load_app(
        &mut self,
        name: &str,
        hostname: &str,
        wasm_bytes: &[u8],
        encryption_key: Option<[u8; AEAD_KEY_SIZE]>,
        permissions: Option<AppPermissions>,
        max_fuel: u64,
        mcp_enabled: bool,
        docs: Option<std::collections::BTreeMap<String, String>>,
        config_api_function: Option<String>,
        owners: Vec<String>,
        app_id: Option<[u8; 16]>,
        vault: Option<VaultBacking>,
    ) -> Result<AppMeta, String> {
        if self.known.contains_key(name) {
            return Err(format!("app '{}' is already loaded", name));
        }

        // ── Code hash ──────────────────────────────────────────────
        let hash = digest::digest(&digest::SHA256, wasm_bytes);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(hash.as_ref());

        // ── Deserialize (AOT) ──────────────────────────────────────
        let component = self.engine.deserialize(wasm_bytes)?;

        // ── Trial instantiation ────────────────────────────────────
        // Eagerly verify that the component can be linked against the
        // host SDK (auth, kvstore, egress, etc.).  Without this check
        // a missing import (e.g. auth@0.1.0 on an old binary) would
        // only surface on the first wasm_call, after the management
        // service already reported a successful deployment.
        {
            let mut probe_store = self.engine.new_store(name, [0u8; AEAD_KEY_SIZE], 1);
            self.engine
                .linker()
                .instantiate(&mut probe_store, &component)
                .map_err(|e| {
                    format!("component failed trial instantiation (linker error): {}", e)
                })?;
        }

        // ── Per-app encryption key ─────────────────────────────────
        // Vault-backed apps reconstruct a KEK from the constellation and
        // envelope-wrap the KV `encryption_key` under it (so data survives an
        // enclave upgrade); others keep the BYOK / generated key as before.
        let (app_key, key_source, vault_config) = match &vault {
            Some(vb) => {
                let (k, src, cfg) =
                    resolve_vault_backed_key(vb, &code_hash, app_id, encryption_key)?;
                (k, src, Some(cfg))
            }
            None => match encryption_key {
                Some(k) => {
                    let fingerprint = {
                        let d = digest::digest(&digest::SHA256, &k);
                        let mut buf = String::with_capacity(64);
                        for b in d.as_ref() {
                            use core::fmt::Write;
                            let _ = write!(buf, "{:02x}", b);
                        }
                        buf
                    };
                    (k, format!("byok:{}", fingerprint), None)
                }
                None => {
                    let rng = SystemRandom::new();
                    let mut k = [0u8; AEAD_KEY_SIZE];
                    rng.fill(&mut k)
                        .map_err(|_| String::from("RDRAND failed generating app encryption key"))?;
                    (k, String::from("generated"), None)
                }
            },
        };
        // ── Introspect exports (full WIT type schema) ──────────────
        // Extract @auth annotations from docs before passing to schema builder.
        let permissions = match docs {
            Some(ref d) => merge_auth_from_docs(d, permissions),
            None => permissions,
        };
        // Extract @config-api decoration from docs. The WIT-derived
        // decoration is the source of truth; the protocol-level
        // `config_api_function` parameter (sourced from privasys.json
        // or a Dockerfile LABEL) is only honoured as a fallback when
        // the WIT does not declare one. This keeps the freeze gate
        // bound to the measured app code rather than to deploy-time
        // metadata that is not part of the attestation.
        let config_api_function = match docs.as_ref().and_then(|d| d.get("config-api")) {
            Some(name) => Some(name.clone()),
            None => config_api_function,
        };
        let mut schema =
            self.engine
                .discover_exports_typed(name, hostname, &component, Some(wasm_bytes), docs);
        schema.mcp_enabled = mcp_enabled;
        let exports = schema.to_exports_map();

        if exports.is_empty() {
            return Err(format!(
                "app '{}' has no exported functions — is it a valid Component?",
                name,
            ));
        }

        // ── Configuration hash ──────────────────────────────────────
        // Hash of the per-app permissions policy (auth + MCP). When
        // no permissions are declared, this is None and no
        // configuration-hash OID is emitted.
        let configuration_hash = if permissions.is_some() {
            #[derive(Serialize)]
            struct ConfigDigestInput<'a> {
                permissions: Option<&'a AppPermissions>,
            }
            let canonical = serde_json::to_vec(&ConfigDigestInput {
                permissions: permissions.as_ref(),
            })
            .expect("config digest input must be serialisable");
            let h = digest::digest(&digest::SHA256, &canonical);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.as_ref());
            Some(out)
        } else {
            None
        };

        // Validate permissions version
        if let Some(ref p) = permissions {
            if p.version != 1 {
                return Err(format!(
                    "unsupported permissions version: {} (expected 1)",
                    p.version,
                ));
            }
        }

        let meta = AppMeta {
            name: name.to_string(),
            hostname: hostname.to_string(),
            code_hash,
            encryption_key: app_key,
            key_source: key_source.clone(),
            permissions: permissions.clone(),
            configuration_hash,
            max_fuel,
            schema: Some(schema),
            extensions: BTreeMap::new(),
            config_api_function: config_api_function.clone(),
            owners,
            app_id,
            vault_config,
            vault_handle: vault.as_ref().map(|vb| vb.handle.clone()),
        };
        self.known.insert(name.to_string(), meta.clone());
        // Wire the freeze gate: when a config_api function is
        // declared, the app is frozen until set-config-complete.
        if let Some(ref f) = config_api_function {
            self.config_api.insert(name.to_string(), f.clone());
            self.configured.insert(name.to_string(), false);
        }

        self.loaded.insert(
            name.to_string(),
            LoadedApp {
                name: name.to_string(),
                hostname: hostname.to_string(),
                code_hash,
                encryption_key: app_key,
                key_source,
                component,
                exports,
                permissions,
                configuration_hash,
                max_fuel,
            },
        );
        self.touch(name);
        self.evict_if_needed();

        Ok(meta)
    }

    /// Register metadata for a persisted app without compiling it.
    ///
    /// Used during startup to restore app identities from the sealed
    /// KV store.  The component stays uncompiled until the first
    /// `wasm_call` triggers [`ensure_loaded()`](Self::ensure_loaded).
    pub fn register_known(&mut self, meta: AppMeta) {
        // Re-arm the freeze gate on every restart: an app that was
        // configured before reboot must reconfigure (re-supply its
        // secrets) before serving traffic again.
        if let Some(ref f) = meta.config_api_function {
            self.config_api.insert(meta.name.clone(), f.clone());
            self.configured.insert(meta.name.clone(), false);
        }
        self.known.insert(meta.name.clone(), meta);
    }

    /// Rotate a vault-backed app's storage KEK to `new_handle`, re-wrapping the
    /// DEK under the new generation and advancing the app's sealed handle.
    ///
    /// Returns the updated [`AppMeta`] so the caller can re-seal it to the KV.
    /// The DEK and the sealed KV are untouched — only the KEK that protects the
    /// host-side wrapped DEK advances (a cheap re-wrap, like the container's LUKS
    /// keyslot re-key). `mgmt_url`/`environment` are only consulted if the app has
    /// no sealed selection to reuse.
    pub fn rotate_vault_key(
        &mut self,
        name: &str,
        new_handle: &str,
        new_grant: &str,
        mgmt_url: &str,
        environment: &str,
    ) -> Result<AppMeta, String> {
        let meta = self
            .known
            .get(name)
            .ok_or_else(|| format!("app '{name}' is not known"))?;
        let old_handle = meta
            .vault_handle
            .clone()
            .ok_or_else(|| format!("app '{name}' is not vault-backed (no sealed handle)"))?;
        if old_handle == new_handle {
            return Err(format!(
                "rotate: new handle equals the current handle {new_handle}"
            ));
        }
        let cfg = match &meta.vault_config {
            Some(c) => c.clone(),
            None => crate::vaultkey::discover(mgmt_url, environment)?,
        };
        let code_hash = meta.code_hash;
        let app_id = meta.app_id;

        rotate_vault_backed_key(&cfg, &old_handle, new_handle, new_grant, &code_hash, app_id)?;

        // Advance the sealed handle (the DEK and vault_config are unchanged).
        let source = format!("vault:{new_handle}");
        let updated = {
            let m = self.known.get_mut(name).expect("known checked above");
            m.vault_handle = Some(new_handle.to_string());
            m.key_source = source.clone();
            m.clone()
        };
        if let Some(la) = self.loaded.get_mut(name) {
            la.key_source = source;
        }
        Ok(updated)
    }

    /// Compile a known-but-unloaded app from its WASM bytes.
    ///
    /// If the app is already compiled, this just refreshes its LRU
    /// position.  Otherwise it deserialises the AOT component, inserts
    /// it into the `loaded` map, and evicts the least-recently-used
    /// app if the cache is full.
    pub fn ensure_loaded(&mut self, name: &str, wasm_bytes: &[u8]) -> Result<(), String> {
        if self.loaded.contains_key(name) {
            self.touch(name);
            return Ok(());
        }

        let meta = self
            .known
            .get(name)
            .ok_or_else(|| format!("unknown app: '{}'", name))?
            .clone();

        let component = self.engine.deserialize(wasm_bytes)?;

        // Prefer building exports from the schema (already in AppMeta)
        // to avoid redundant introspection. Fall back to runtime
        // discovery for apps persisted before schema support.
        let (exports, new_schema) = if let Some(ref s) = meta.schema {
            (s.to_exports_map(), None)
        } else {
            let s = self.engine.discover_exports_typed(
                &meta.name,
                &meta.hostname,
                &component,
                Some(wasm_bytes),
                None,
            );
            let e = s.to_exports_map();
            (e, Some(s))
        };

        // Back-fill schema into the known map for pre-schema apps.
        if let Some(ref s) = new_schema {
            if let Some(km) = self.known.get_mut(name) {
                km.schema = Some(s.clone());
            }
        }

        self.loaded.insert(
            name.to_string(),
            LoadedApp {
                name: meta.name,
                hostname: meta.hostname,
                code_hash: meta.code_hash,
                encryption_key: meta.encryption_key,
                key_source: meta.key_source,
                component,
                exports,
                permissions: meta.permissions,
                configuration_hash: meta.configuration_hash,
                max_fuel: meta.max_fuel,
            },
        );
        self.touch(name);
        self.evict_if_needed();
        Ok(())
    }

    /// Remove an app from both `known` and `loaded` maps.
    ///
    /// Returns the hostname if found.
    pub fn remove_app(&mut self, name: &str) -> Option<String> {
        self.loaded.remove(name);
        self.lru.remove(name);
        self.config_api.remove(name);
        self.configured.remove(name);
        self.billing_frozen.remove(name);
        self.known.remove(name).map(|m| m.hostname)
    }

    /// Returns `true` when the app is frozen (declared a `config_api`
    /// at load time and has not yet called `set-config-complete`) and
    /// the requested function is NOT the configure function.
    pub fn is_frozen(&self, name: &str, function: &str) -> bool {
        let configured = self.configured.get(name).copied().unwrap_or(true);
        if configured {
            return false;
        }
        match self.config_api.get(name) {
            Some(cfg_fn) => cfg_fn != function,
            None => false,
        }
    }

    /// Flip the in-memory freeze flag for `name` to `true`. No-op when
    /// the app has no declared `config_api` or is already configured.
    pub fn mark_configured(&mut self, name: &str) {
        if self.config_api.contains_key(name) {
            self.configured.insert(name.to_string(), true);
        }
    }

    /// Apply (or lift) the host-driven billing freeze for `name`.
    ///
    /// `Some(reason)` freezes the app (recording the reason);
    /// `None` lifts the freeze. Returns `true` when `name` is a known
    /// app, `false` otherwise (so the caller can report `not_found`).
    /// Independent of the configure-then-freeze gate.
    pub fn set_billing_frozen(&mut self, name: &str, reason: Option<String>) -> bool {
        if !self.known.contains_key(name) {
            return false;
        }
        match reason {
            Some(r) => {
                self.billing_frozen.insert(name.to_string(), r);
            }
            None => {
                self.billing_frozen.remove(name);
            }
        }
        true
    }

    /// Returns the billing-freeze reason for `name` when the app is
    /// host-frozen, or `None` when it is billing-runnable. This is
    /// orthogonal to [`is_frozen`](Self::is_frozen) (the config gate).
    pub fn billing_freeze_reason(&self, name: &str) -> Option<&str> {
        self.billing_frozen.get(name).map(|s| s.as_str())
    }

    /// Install (or replace) an app-defined attestation extension at
    /// arc `1.3.6.1.4.1.65230.3.5.{arc_suffix}`. Returns the updated
    /// metadata so the caller can re-register the app identity with
    /// the global CertStore. Persistence to KV is the caller's job.
    pub fn set_extension(
        &mut self,
        name: &str,
        arc_suffix: u32,
        value: Vec<u8>,
    ) -> Option<AppMeta> {
        let meta = self.known.get_mut(name)?;
        meta.extensions.insert(arc_suffix, value);
        Some(meta.clone())
    }

    /// List all known apps with their metadata.
    ///
    /// Apps that are currently compiled in memory have their exports
    /// populated; evicted apps show an empty export list.
    pub fn list_apps(&self) -> Vec<crate::protocol::AppInfo> {
        self.known
            .values()
            .map(|meta| {
                let exports = self
                    .loaded
                    .get(&meta.name)
                    .map(|app| app.exported_funcs())
                    .unwrap_or_default();
                crate::protocol::AppInfo {
                    name: meta.name.clone(),
                    hostname: meta.hostname.clone(),
                    code_hash: enclave_os_common::hex::hex_encode(&meta.code_hash),
                    key_source: meta.key_source.clone(),
                    exports,
                    configuration_hash: meta
                        .configuration_hash
                        .map(|h| enclave_os_common::hex::hex_encode(&h)),
                    max_fuel: meta.max_fuel,
                    loaded: self.loaded.contains_key(&meta.name),
                }
            })
            .collect()
    }

    /// Get the code hash for a known app (for attestation).
    pub fn app_code_hash(&self, name: &str) -> Option<&[u8; 32]> {
        self.known.get(name).map(|m| &m.code_hash)
    }

    /// Get the key-source string for a known app.
    ///
    /// Returns `"generated"` or `"byok:<fingerprint>"`.
    pub fn app_key_source(&self, name: &str) -> Option<&str> {
        self.known.get(name).map(|m| m.key_source.as_str())
    }

    /// Get all known apps' code hashes (sorted by name).
    pub fn all_code_hashes(&self) -> Vec<(&str, &[u8; 32])> {
        self.known
            .iter()
            .map(|(name, meta)| (name.as_str(), &meta.code_hash))
            .collect()
    }

    /// Get all known apps' attestation metadata (sorted by name).
    ///
    /// Returns `(name, code_hash, key_source)` for each known app.
    pub fn all_app_metadata(&self) -> Vec<(&str, &[u8; 32], &str)> {
        self.known
            .iter()
            .map(|(name, meta)| (name.as_str(), &meta.code_hash, meta.key_source.as_str()))
            .collect()
    }

    /// Get the configuration hash for a known app (for OID 3.5 attestation).
    pub fn app_configuration_hash(&self, name: &str) -> Option<&[u8; 32]> {
        self.known
            .get(name)
            .and_then(|m| m.configuration_hash.as_ref())
    }

    /// Get the permissions policy for a known app (for call-time enforcement).
    pub fn app_permissions(&self, name: &str) -> Option<&AppPermissions> {
        self.known.get(name).and_then(|m| m.permissions.as_ref())
    }

    /// Per-app owners team (platform-OIDC `sub` claims). Used to
    /// authorize the `Owner` auth policy on `wasm_call`. Returns an
    /// empty `Vec` for unknown apps or apps with no owners (which
    /// also means the @config-api freeze gate is uncallable).
    pub fn app_owners(&self, name: &str) -> Vec<String> {
        self.known
            .get(name)
            .map(|m| m.owners.clone())
            .unwrap_or_default()
    }

    /// Whether an app is known (persisted) but not necessarily compiled.
    pub fn is_known(&self, name: &str) -> bool {
        self.known.contains_key(name)
    }

    /// Resolve an app reference, defaulting to the single known app when
    /// `supplied` is empty.
    ///
    /// - `supplied` non-empty → returned as-is.
    /// - `supplied` empty and exactly one app is known → that app's name.
    /// - `supplied` empty and zero or more-than-one apps → `Err`.
    ///
    /// Used by the MCP HTTP routes so a generic `/api/v1/mcp/tools` URL
    /// can target a single-app enclave without naming the app explicitly.
    pub fn resolve_app(&self, supplied: &str) -> Result<String, String> {
        if !supplied.is_empty() {
            return Ok(supplied.to_string());
        }
        let names: Vec<&String> = self.known.keys().collect();
        match names.len() {
            0 => Err(String::from("no apps loaded; cannot resolve default app")),
            1 => Ok(names[0].clone()),
            _ => Err(format!(
                "multiple apps loaded ({:?}); specify 'app' explicitly",
                names
            )),
        }
    }

    /// Whether an app is currently compiled in memory.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.loaded.contains_key(name)
    }

    /// Get metadata for a known app.
    pub fn get_known(&self, name: &str) -> Option<&AppMeta> {
        self.known.get(name)
    }

    /// Prepare to call an exported function on a loaded app.
    ///
    /// The app **must** already be in the `loaded` map (call
    /// [`ensure_loaded()`](Self::ensure_loaded) first).  Touches the
    /// LRU counter so the app is less likely to be evicted.
    ///
    /// Returns a [`CallPrep`] containing an instantiated [`Store`]
    /// and resolved [`Func`] ready for invocation. The caller MUST
    /// drop the registry mutex before invoking `prep.func.call(...)` —
    /// wasm host functions registered in [`enclave_sdk`] re-acquire
    /// the registry lock to mutate freeze / extension state, so
    /// holding the lock across wasm execution would deadlock the
    /// enclave's single-threaded dispatcher.
    ///
    /// Returns `Err(WasmResult::Error)` if the app or function is
    /// missing or instantiation fails.
    pub fn prepare_call(
        &mut self,
        app_name: &str,
        function: &str,
        params: &[WasmParam],
        caller_id: Option<String>,
        caller_roles: Vec<String>,
    ) -> Result<CallPrep, WasmResult> {
        self.touch(app_name);

        // ── Look up app ────────────────────────────────────────────
        let app = match self.loaded.get(app_name) {
            Some(a) => a,
            None => {
                return Err(WasmResult::Error {
                    message: format!("app '{}' is not loaded", app_name),
                });
            }
        };

        // ── Verify function exists ─────────────────────────────────
        if !app.exports.contains_key(function) {
            return Err(WasmResult::Error {
                message: format!(
                    "app '{}' has no export '{}'. Available: [{}]",
                    app_name,
                    function,
                    app.exports.keys().cloned().collect::<Vec<_>>().join(", "),
                ),
            });
        }

        // ── Instantiate ────────────────────────────────────────────
        let (mut store, instance) = match self.engine.instantiate(
            app_name,
            app.encryption_key,
            app.max_fuel,
            &app.component,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                return Err(WasmResult::Error {
                    message: format!("instantiation failed: {}", e),
                });
            }
        };

        // Record fuel before execution for delta calculation.
        let fuel_before = store.get_fuel().unwrap_or(0) as i64;

        // ── Inject authenticated caller context ────────────────────
        {
            let ctx = store.data_mut();
            ctx.caller_id = caller_id;
            ctx.caller_roles = caller_roles;
        }

        // ── Resolve the exported function ──────────────────────────
        // Functions can be at the root or under an exported instance.
        let func: Func = if let Some(slash) = function.find('/') {
            // Interface-scoped: "my-api/transform"
            let (iface_name, func_name) = function.split_at(slash);
            let func_name = &func_name[1..]; // skip the '/'

            // Look up the interface instance export, then the function within it.
            let iface_idx = match app.component.get_export_index(None, iface_name) {
                Some(idx) => idx,
                None => {
                    return Err(WasmResult::Error {
                        message: format!(
                            "interface '{}' not found in app '{}'",
                            iface_name, app_name,
                        ),
                    });
                }
            };
            match instance.get_func(&mut store, &iface_idx) {
                Some(_) => {
                    // The index resolved the instance; now get the function within it.
                    // We need to look up the function export under the interface.
                    match app.component.get_export_index(Some(&iface_idx), func_name) {
                        Some(func_idx) => match instance.get_func(&mut store, &func_idx) {
                            Some(f) => f,
                            None => {
                                return Err(WasmResult::Error {
                                    message: format!(
                                        "function '{}' not found in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                });
                            }
                        },
                        None => {
                            return Err(WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            });
                        }
                    }
                }
                None => {
                    // Try the nested lookup approach
                    match app.component.get_export_index(Some(&iface_idx), func_name) {
                        Some(func_idx) => match instance.get_func(&mut store, &func_idx) {
                            Some(f) => f,
                            None => {
                                return Err(WasmResult::Error {
                                    message: format!(
                                        "function '{}' not callable in interface '{}' of app '{}'",
                                        func_name, iface_name, app_name,
                                    ),
                                });
                            }
                        },
                        None => {
                            return Err(WasmResult::Error {
                                message: format!(
                                    "function '{}' not found in interface '{}' of app '{}'",
                                    func_name, iface_name, app_name,
                                ),
                            });
                        }
                    }
                }
            }
        } else {
            // Root-level export: "process"
            match instance.get_func(&mut store, function) {
                Some(f) => f,
                None => {
                    return Err(WasmResult::Error {
                        message: format!(
                            "function '{}' not found at root of app '{}'",
                            function, app_name,
                        ),
                    });
                }
            }
        };

        // ── Marshal parameters ─────────────────────────────────────
        let val_params: Vec<Val> = params.iter().map(param_to_val).collect();

        // ── Determine expected result count ────────────────────────
        // For dynamic dispatch (Func, not TypedFunc) we look up the
        // declared result count from the exports map.
        let result_count = app.exports.get(function).map(|&(_, r)| r).unwrap_or(0);

        // Hand off to the caller; wasm execution must happen with the
        // registry mutex released so host functions can re-enter.
        Ok(CallPrep {
            store,
            func,
            val_params,
            result_count,
            fuel_before,
        })
    }

    // ── LRU helpers ────────────────────────────────────────────────

    /// Mark an app as recently used.
    fn touch(&mut self, name: &str) {
        self.lru_counter += 1;
        self.lru.insert(name.to_string(), self.lru_counter);
    }

    /// Evict the least-recently-used compiled app if over the limit.
    fn evict_if_needed(&mut self) {
        while self.loaded.len() > MAX_LOADED_APPS {
            let oldest = self
                .lru
                .iter()
                .filter(|(name, _)| self.loaded.contains_key(name.as_str()))
                .min_by_key(|(_, &counter)| counter)
                .map(|(name, _)| name.clone());

            if let Some(name) = oldest {
                self.loaded.remove(&name);
                self.lru.remove(&name);
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Value conversions: WasmParam ↔ wasmtime::component::Val
// ---------------------------------------------------------------------------

/// Convert a [`WasmParam`] to a wasmtime [`Val`].
fn param_to_val(p: &WasmParam) -> Val {
    match p {
        WasmParam::Bool(v) => Val::Bool(*v),
        WasmParam::S32(v) => Val::S32(*v),
        WasmParam::S64(v) => Val::S64(*v),
        WasmParam::U32(v) => Val::U32(*v),
        WasmParam::U64(v) => Val::U64(*v),
        WasmParam::F32(v) => Val::Float32(*v),
        WasmParam::F64(v) => Val::Float64(*v),
        WasmParam::String(v) => Val::String(v.clone().into()),
        WasmParam::Bytes(v) => {
            // Component model doesn't have a native "bytes" type;
            // map to list<u8>.
            Val::List(v.iter().map(|&b| Val::U8(b)).collect::<Vec<_>>().into())
        }
        WasmParam::List(items) => {
            Val::List(items.iter().map(param_to_val).collect::<Vec<_>>().into())
        }
        WasmParam::Record(fields) => Val::Record(
            fields
                .iter()
                .map(|(n, v)| (n.clone(), param_to_val(v)))
                .collect::<Vec<_>>()
                .into(),
        ),
        WasmParam::Enum(name) => Val::Enum(name.clone()),
        WasmParam::Option(inner) => Val::Option(inner.as_ref().map(|v| Box::new(param_to_val(v)))),
        WasmParam::Variant(name, payload) => Val::Variant(
            name.clone(),
            payload.as_ref().map(|v| Box::new(param_to_val(v))),
        ),
        WasmParam::Tuple(items) => {
            Val::Tuple(items.iter().map(param_to_val).collect::<Vec<_>>().into())
        }
        WasmParam::Flags(names) => Val::Flags(names.clone()),
    }
}

/// Convert a wasmtime [`Val`] to a [`WasmValue`].
pub(crate) fn val_to_wasm_value(v: &Val) -> WasmValue {
    match v {
        Val::Bool(b) => WasmValue::Bool(*b),
        Val::S8(n) => WasmValue::S32(*n as i32),
        Val::U8(n) => WasmValue::U32(*n as u32),
        Val::S16(n) => WasmValue::S32(*n as i32),
        Val::U16(n) => WasmValue::U32(*n as u32),
        Val::S32(n) => WasmValue::S32(*n),
        Val::U32(n) => WasmValue::U32(*n),
        Val::S64(n) => WasmValue::S64(*n),
        Val::U64(n) => WasmValue::U64(*n),
        Val::Float32(v) => WasmValue::F32(*v),
        Val::Float64(v) => WasmValue::F64(*v),
        Val::String(s) => WasmValue::String(s.to_string()),
        Val::List(items) => {
            // Heuristic: if all items are U8, marshal as Bytes.
            let all_u8 = items.iter().all(|v| matches!(v, Val::U8(_)));
            if all_u8 {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|v| match v {
                        Val::U8(b) => *b,
                        _ => 0,
                    })
                    .collect();
                WasmValue::Bytes(bytes)
            } else {
                WasmValue::List(val_to_json(v))
            }
        }
        Val::Char(c) => WasmValue::String(c.to_string()),
        Val::Record(_) => WasmValue::Record(val_to_json(v)),
        // For other complex types (tuple, variant, enum, option, result,
        // flags, resource) — emit a JSON object describing the value so
        // callers receive structured data instead of a Debug string.
        _ => WasmValue::Record(val_to_json(v)),
    }
}

/// Recursively convert a wasmtime [`Val`] into a [`serde_json::Value`].
///
/// Records become JSON objects keyed by WIT field name; lists become arrays;
/// options become `null` or the inner value; variants become
/// `{"<case>": <payload>}`; enums become their case name as a string;
/// flags become an array of set flag names; tuples become arrays;
/// results become `{"ok": ...}` or `{"err": ...}`.
fn val_to_json(v: &Val) -> serde_json::Value {
    use serde_json::{Map, Number, Value};
    match v {
        Val::Bool(b) => Value::Bool(*b),
        Val::S8(n) => Value::Number((*n as i64).into()),
        Val::U8(n) => Value::Number((*n as u64).into()),
        Val::S16(n) => Value::Number((*n as i64).into()),
        Val::U16(n) => Value::Number((*n as u64).into()),
        Val::S32(n) => Value::Number((*n as i64).into()),
        Val::U32(n) => Value::Number((*n as u64).into()),
        Val::S64(n) => Value::Number((*n).into()),
        Val::U64(n) => Value::Number((*n).into()),
        Val::Float32(f) => Number::from_f64(*f as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Val::Float64(f) => Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Val::String(s) => Value::String(s.to_string()),
        Val::Char(c) => Value::String(c.to_string()),
        Val::List(items) => Value::Array(items.iter().map(val_to_json).collect()),
        Val::Record(fields) => {
            let mut m = Map::new();
            for (name, val) in fields.iter() {
                m.insert(name.clone(), val_to_json(val));
            }
            Value::Object(m)
        }
        Val::Tuple(items) => Value::Array(items.iter().map(val_to_json).collect()),
        Val::Option(inner) => match inner {
            Some(boxed) => val_to_json(boxed.as_ref()),
            None => Value::Null,
        },
        Val::Variant(case, payload) => {
            let mut m = Map::new();
            let payload_val = match payload {
                Some(boxed) => val_to_json(boxed.as_ref()),
                None => Value::Null,
            };
            m.insert(case.clone(), payload_val);
            Value::Object(m)
        }
        Val::Enum(name) => Value::String(name.clone()),
        Val::Flags(names) => Value::Array(names.iter().map(|n| Value::String(n.clone())).collect()),
        Val::Result(r) => {
            let mut m = Map::new();
            match r {
                Ok(opt) => {
                    let v = match opt {
                        Some(boxed) => val_to_json(boxed.as_ref()),
                        None => Value::Null,
                    };
                    m.insert("ok".to_string(), v);
                }
                Err(opt) => {
                    let v = match opt {
                        Some(boxed) => val_to_json(boxed.as_ref()),
                        None => Value::Null,
                    };
                    m.insert("err".to_string(), v);
                }
            }
            Value::Object(m)
        }
        // Resources and any unhandled variants — emit Debug as a string fallback.
        other => Value::String(format!("{:?}", other)),
    }
}
