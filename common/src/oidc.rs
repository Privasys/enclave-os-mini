// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OIDC token verification for enclave-os.
//!
//! Provides JWT validation against Privasys ID (or any OIDC-compliant
//! provider). Tokens are verified using public keys fetched from the
//! provider's JWKS endpoint, with a configurable cache TTL.
//!
//! ## Role model
//!
//! `OidcClaims` carries the raw role strings extracted from the JWT plus
//! two precomputed booleans for the two **platform** roles enforced by
//! the enclave host code itself:
//!
//! | Booleans on `OidcClaims` | Default claim value | Scope |
//! |--------------------------|---------------------|-------|
//! | `is_manager` | `privasys-platform:manager` | WASM lifecycle, TLS CA rotation, all monitoring |
//! | `is_monitoring` | `privasys-platform:monitoring` | Read-only health/status/metrics |
//!
//! `is_manager` implies `is_monitoring`.
//!
//! All other roles (notably the `vault:*` family) are not interpreted in
//! `common`: they are kept as raw strings in `OidcClaims.roles` and matched
//! by the consuming crate against its own per-resource policy. This keeps
//! `common` agnostic to feature crates and avoids a closed enum that has
//! to be edited every time a new role is introduced.
//!
//! ## Token delivery
//!
//! Since enclave-os-mini uses a frame protocol (not HTTP), the OIDC bearer
//! token is passed inside the JSON envelope as an `"auth"` field:
//!
//! ```json
//! {
//!   "auth": "eyJhbGciOiJSUzI1NiIs...",
//!   "wasm_load": { "name": "my-app", "bytes": [...] }
//! }
//! ```
//!
//! The auth layer strips `"auth"`, verifies it via JWKS, and populates
//! [`OidcClaims`] in the [`RequestContext`](super::modules::RequestContext).

#[cfg(feature = "sgx")]
use alloc::{string::String, vec::Vec};
#[cfg(not(feature = "sgx"))]
use std::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

#[cfg(not(feature = "sgx"))]
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
#[cfg(feature = "sgx")]
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// Global flag indicating whether OIDC has been configured.
///
/// Set to `true` by the enclave startup code after a valid [`OidcConfig`]
/// is installed. Modules check this via [`is_oidc_configured()`] to decide
/// whether to enforce token requirements.
static OIDC_CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Global [`OidcConfig`] pointer, set once at startup.
///
/// Any crate that depends on `enclave-os-common` can read the config
/// without needing access to the enclave crate's local storage.
static OIDC_CONFIG: AtomicPtr<OidcConfig> = AtomicPtr::new(core::ptr::null_mut());

/// Store the global [`OidcConfig`] and mark OIDC as configured.
///
/// Must be called exactly once during enclave init.  Subsequent calls
/// are silently ignored (first-writer-wins).
pub fn set_global_oidc_config(config: OidcConfig) {
    let ptr = Box::into_raw(Box::new(config));
    // Only store if still null (first writer wins).
    let prev = OIDC_CONFIG.compare_exchange(
        core::ptr::null_mut(),
        ptr,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if prev.is_err() {
        // Another call already set it — free our copy.
        unsafe { drop(Box::from_raw(ptr)); }
    }
    OIDC_CONFIGURED.store(true, Ordering::Release);
}

/// Mark OIDC as configured (called once at startup).
pub fn set_oidc_configured() {
    OIDC_CONFIGURED.store(true, Ordering::Release);
}

/// Returns `true` if OIDC has been configured for this enclave.
pub fn is_oidc_configured() -> bool {
    OIDC_CONFIGURED.load(Ordering::Acquire)
}

/// Returns a reference to the global [`OidcConfig`], if set.
pub fn global_oidc_config() -> Option<&'static OidcConfig> {
    let ptr = OIDC_CONFIG.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: ptr was created from Box::into_raw in set_global_oidc_config
        // and is never freed during the enclave's lifetime.
        Some(unsafe { &*ptr })
    }
}

// ---------------------------------------------------------------------------
//  OIDC configuration
// ---------------------------------------------------------------------------

/// OIDC provider configuration, passed via [`EnclaveConfig`].
///
/// Only the two **platform** role names (`manager_role`, `monitoring_role`)
/// are configurable here, because they are enforced inside the enclave
/// host code (WASM lifecycle, TLS CA rotation, monitoring endpoints).
/// Roles enforced by feature crates — e.g. `vault:owner`,
/// `vault:manager`, `vault:auditor` — live in those crates' own per-key
/// or per-resource policy, not in this global config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g. `https://privasys.id`).
    pub issuer: String,
    /// Expected `aud` claim (e.g. `privasys-platform`).
    pub audience: String,
    /// Optional JWKS URI for token signature verification.
    /// If empty, auto-discovered from `{issuer}/.well-known/openid-configuration`.
    #[serde(default)]
    pub jwks_uri: String,
    /// Role claim path in the token (default: `roles`, the RFC 9068 flat
    /// string array Privasys ID emits). `extract_roles` also tries
    /// Keycloak's `realm_access.roles` for compatibility.
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// Claim value for the manager role (default: `privasys-platform:manager`).
    #[serde(default = "default_manager_role")]
    pub manager_role: String,
    /// Claim value for the monitoring role (default: `privasys-platform:monitoring`).
    #[serde(default = "default_monitoring_role")]
    pub monitoring_role: String,
}

fn default_role_claim() -> String {
    "roles".into()
}
fn default_manager_role() -> String {
    "privasys-platform:manager".into()
}
fn default_monitoring_role() -> String {
    "privasys-platform:monitoring".into()
}

// ---------------------------------------------------------------------------
//  Verified claims
// ---------------------------------------------------------------------------

/// Verified OIDC claims extracted from a bearer token.
///
/// Populated by the auth layer in
/// [`RequestContext`](super::modules::RequestContext) after successful
/// token verification.
///
/// `roles` carries the raw role strings collected from the JWT (deduped,
/// claim-path agnostic). The two platform booleans are precomputed
/// against the configured `manager_role` / `monitoring_role` so host
/// code does not need to reach back into the global config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// OIDC subject (`sub` claim) — unique user/service identity.
    pub sub: String,
    /// Raw role strings extracted from the JWT, deduped.
    pub roles: Vec<String>,
    /// Precomputed: bearer holds the configured manager role.
    pub is_manager: bool,
    /// Precomputed: bearer holds either the manager or monitoring role.
    pub is_monitoring: bool,
    /// Authentication Methods References (`amr` claim, RFC 8176): how the
    /// subject authenticated for THIS token (e.g. `["webauthn"]`). Empty when
    /// the claim is absent. Used by step-up conditions (e.g. the vault's
    /// `OidcStepUp`) to require a fresh hardware/WebAuthn factor.
    #[serde(default)]
    pub amr: Vec<String>,
    /// Authentication Context Class Reference (`acr` claim). `None` when absent.
    #[serde(default)]
    pub acr: Option<String>,
    /// Issued-at (`iat` claim, unix seconds; 0 when absent). Lets a condition
    /// require a *fresh* token rather than a replayed long-lived session.
    #[serde(default)]
    pub iat: u64,
    /// Expiry (`exp` claim, unix seconds; 0 when absent). Part of the
    /// operation-binding input for `OidcStepUp { operation_bound }`.
    #[serde(default)]
    pub exp: u64,
    /// `vault_op` claim: base64url(SHA-256 of the operation-binding input)
    /// proving the step-up was performed for THIS operation. `None` when absent.
    /// See policies-plan.md §9 for the exact input layout.
    #[serde(default)]
    pub vault_op: Option<String>,
    /// `nonce` claim echoed by the IdP into the operation-binding input (an
    /// opaque base64url string). `None` when absent.
    #[serde(default)]
    pub nonce: Option<String>,
}

impl OidcClaims {
    /// Build verified claims from a subject and the raw role strings
    /// returned by [`extract_roles`], applying the platform-role hierarchy
    /// (manager implies monitoring). Step-up fields (`amr`/`acr`/`iat`) default
    /// to empty; set them with [`OidcClaims::with_step_up`].
    pub fn from_raw(sub: String, roles: Vec<String>, config: &OidcConfig) -> Self {
        let is_manager = roles.iter().any(|r| r == &config.manager_role);
        let is_monitoring =
            is_manager || roles.iter().any(|r| r == &config.monitoring_role);
        Self {
            sub,
            roles,
            is_manager,
            is_monitoring,
            amr: Vec::new(),
            acr: None,
            iat: 0,
            exp: 0,
            vault_op: None,
            nonce: None,
        }
    }

    /// Attach the step-up claims (`amr`/`acr`/`iat`) parsed from the JWT.
    pub fn with_step_up(mut self, amr: Vec<String>, acr: Option<String>, iat: u64) -> Self {
        self.amr = amr;
        self.acr = acr;
        self.iat = iat;
        self
    }

    /// True iff every method in `required` is present in this token's `amr`.
    pub fn has_amr(&self, required: &[String]) -> bool {
        required
            .iter()
            .all(|r| self.amr.iter().any(|m| m.eq_ignore_ascii_case(r)))
    }

    /// Returns `true` if the token has the configured manager role.
    pub fn has_manager(&self) -> bool {
        self.is_manager
    }

    /// Returns `true` if the token has monitoring access (manager or monitoring).
    pub fn has_monitoring(&self) -> bool {
        self.is_monitoring
    }
}

// ---------------------------------------------------------------------------
//  Role extraction from raw JWT claims
// ---------------------------------------------------------------------------

/// Extract role strings from raw JWT claims JSON, searching multiple
/// claim paths:
///
/// 1. Configured `role_claim` (default: `roles`, RFC 9068 flat string array)
///    — supports array `["role1", "role2"]` or map `{ "role": {...} }`
/// 2. Standard `roles` array (always tried, even if `role_claim` differs)
/// 3. Keycloak `realm_access.roles`
///
/// Returns the deduped union of role strings found in all paths. The
/// returned strings are not interpreted: it is up to the caller (or
/// [`OidcClaims::from_raw`]) to map them to platform booleans and to
/// the per-resource policy of feature crates.
pub fn extract_roles(
    claims: &serde_json::Value,
    config: &OidcConfig,
) -> Vec<String> {
    let mut roles: Vec<String> = Vec::new();

    // Path 1: configured role_claim
    if let Some(val) = claims.get(&config.role_claim) {
        collect_role_strings(val, &mut roles);
    }

    // Path 2: standard "roles" array (skip if role_claim already pointed there)
    if config.role_claim != "roles" {
        if let Some(val) = claims.get("roles") {
            collect_role_strings(val, &mut roles);
        }
    }

    // Path 3: Keycloak realm_access.roles
    if let Some(ra) = claims.get("realm_access") {
        if let Some(val) = ra.get("roles") {
            collect_role_strings(val, &mut roles);
        }
    }

    roles
}

/// Collect role strings from a JSON value that is either:
/// - An object `{ "role-name": { ... } }` — keys are the role names
/// - An array of strings `["role1", "role2"]`
fn collect_role_strings(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            for key in map.keys() {
                if !out.contains(key) {
                    out.push(key.clone());
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    let s = s.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Extract the `amr` (Authentication Methods References, RFC 8176) array from
/// raw JWT claims. Returns the deduped method strings; empty when the claim is
/// absent or not a string array.
pub fn extract_amr(claims: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = claims.get("amr") {
        for item in arr {
            if let Some(s) = item.as_str() {
                let s = s.to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://privasys.id".into(),
            audience: "privasys-platform".into(),
            jwks_uri: String::new(),
            role_claim: default_role_claim(),
            manager_role: default_manager_role(),
            monitoring_role: default_monitoring_role(),
        }
    }

    fn claims_with(roles: &[&str]) -> OidcClaims {
        OidcClaims::from_raw(
            "svc".into(),
            roles.iter().map(|s| s.to_string()).collect(),
            &test_config(),
        )
    }

    // -- extract_roles: claim shapes -----------------------------------------

    #[test]
    fn object_map_format() {
        // role_claim default is "roles"; map shape (legacy compatibility)
        // is still accepted by collect_role_strings.
        let mut config = test_config();
        config.role_claim = "app_roles".into();
        let claims = json!({
            "app_roles": {
                "privasys-platform:manager": { "orgId": "123" },
                "vault:owner": { "orgId": "123" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.iter().any(|r| r == "privasys-platform:manager"));
        assert!(roles.iter().any(|r| r == "vault:owner"));
        assert_eq!(roles.len(), 2);
    }

    #[test]
    fn standard_array_format() {
        let config = test_config();
        let claims = json!({ "roles": ["privasys-platform:monitoring"] });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec!["privasys-platform:monitoring".to_string()]);
    }

    #[test]
    fn keycloak_realm_access() {
        let config = test_config();
        let claims = json!({
            "realm_access": { "roles": ["vault:manager"] }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec!["vault:manager".to_string()]);
    }

    #[test]
    fn no_roles() {
        let config = test_config();
        let claims = json!({"sub": "user1"});
        assert!(extract_roles(&claims, &config).is_empty());
    }

    #[test]
    fn duplicate_roles_across_paths_deduplicated() {
        let config = test_config();
        let claims = json!({
            "roles": ["privasys-platform:manager"],
            "realm_access": { "roles": ["privasys-platform:manager"] }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec!["privasys-platform:manager".to_string()]);
    }

    #[test]
    fn custom_role_claim_path() {
        let mut config = test_config();
        config.role_claim = "custom_roles".into();
        let claims = json!({ "custom_roles": ["admin"] });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec!["admin".to_string()]);
    }

    // -- Platform booleans ---------------------------------------------------

    #[test]
    fn manager_implies_monitoring() {
        let claims = claims_with(&["privasys-platform:manager"]);
        assert!(claims.has_manager());
        assert!(claims.has_monitoring(), "manager must imply monitoring");
    }

    #[test]
    fn monitoring_does_not_imply_manager() {
        let claims = claims_with(&["privasys-platform:monitoring"]);
        assert!(claims.has_monitoring());
        assert!(!claims.has_manager(), "monitoring must not imply manager");
    }

    #[test]
    fn vault_roles_do_not_imply_platform_roles() {
        let claims = claims_with(&["vault:owner", "vault:manager", "vault:auditor"]);
        assert!(!claims.has_manager());
        assert!(!claims.has_monitoring());
        // Raw strings are still visible to feature crates.
        assert_eq!(claims.roles.len(), 3);
        assert!(claims.roles.iter().any(|r| r == "vault:owner"));
    }

    #[test]
    fn empty_roles() {
        let claims = claims_with(&[]);
        assert!(!claims.has_manager());
        assert!(!claims.has_monitoring());
        assert!(claims.roles.is_empty());
    }

    // -- collect_role_strings: edge cases ------------------------------------

    #[test]
    fn collect_from_non_string_array_items() {
        let mut out = Vec::new();
        collect_role_strings(&json!([42, "valid", null, true]), &mut out);
        assert_eq!(out, vec!["valid"]);
    }

    #[test]
    fn collect_from_scalar_is_noop() {
        let mut out = Vec::new();
        collect_role_strings(&json!("single-string"), &mut out);
        collect_role_strings(&json!(42), &mut out);
        collect_role_strings(&json!(null), &mut out);
        assert!(out.is_empty());
    }

    // -- amr / step-up -------------------------------------------------------

    #[test]
    fn extract_amr_reads_string_array_deduped() {
        let claims = json!({"sub": "u", "amr": ["webauthn", "webauthn", "pwd"]});
        assert_eq!(extract_amr(&claims), vec!["webauthn", "pwd"]);
    }

    #[test]
    fn extract_amr_absent_or_malformed_is_empty() {
        assert!(extract_amr(&json!({"sub": "u"})).is_empty());
        assert!(extract_amr(&json!({"amr": "webauthn"})).is_empty()); // not an array
        assert!(extract_amr(&json!({"amr": [1, 2, 3]})).is_empty()); // not strings
    }

    #[test]
    fn has_amr_requires_all_methods_case_insensitive() {
        let c = claims_with(&[]).with_step_up(
            vec!["WebAuthn".into(), "pwd".into()],
            Some("aal2".into()),
            1000,
        );
        assert!(c.has_amr(&["webauthn".into()]));
        assert!(c.has_amr(&["webauthn".into(), "pwd".into()]));
        assert!(c.has_amr(&[])); // vacuously true
        assert!(!c.has_amr(&["webauthn".into(), "otp".into()]));
        assert_eq!(c.acr.as_deref(), Some("aal2"));
        assert_eq!(c.iat, 1000);
    }

    #[test]
    fn from_raw_defaults_step_up_fields_empty() {
        let c = claims_with(&["x"]);
        assert!(c.amr.is_empty());
        assert!(c.acr.is_none());
        assert_eq!(c.iat, 0);
    }
}
