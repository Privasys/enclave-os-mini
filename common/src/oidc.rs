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
    /// OIDC issuer URL (e.g. `https://auth.privasys.org`).
    pub issuer: String,
    /// Expected `aud` claim (e.g. `enclave-os-mini`).
    pub audience: String,
    /// Optional JWKS URI for token signature verification.
    /// If empty, auto-discovered from `{issuer}/.well-known/openid-configuration`.
    #[serde(default)]
    pub jwks_uri: String,
    /// Role claim path in the token (default: `urn:zitadel:iam:org:project:roles`).
    ///
    /// The default value is the Zitadel-compatible claim Privasys ID
    /// emits. Other OIDC providers (Keycloak, Auth0, Okta, …) use other
    /// paths — `extract_roles` also tries the standard `roles` array
    /// and Keycloak's `realm_access.roles`.
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
    "urn:zitadel:iam:org:project:roles".into()
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
}

impl OidcClaims {
    /// Build verified claims from a subject and the raw role strings
    /// returned by [`extract_roles`], applying the platform-role hierarchy
    /// (manager implies monitoring).
    pub fn from_raw(sub: String, roles: Vec<String>, config: &OidcConfig) -> Self {
        let is_manager = roles.iter().any(|r| r == &config.manager_role);
        let is_monitoring =
            is_manager || roles.iter().any(|r| r == &config.monitoring_role);
        Self { sub, roles, is_manager, is_monitoring }
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
/// claim paths (aligned with Enclave OS Virtual):
///
/// 1. Configured `role_claim` (default: `urn:zitadel:iam:org:project:roles`)
///    — supports map `{ "role": {...} }` or array `["role1", "role2"]`
/// 2. Standard `roles` array
/// 3. Keycloak `realm_access.roles`
/// 4. Project-specific claims (`urn:zitadel:iam:org:project:{id}:roles`),
///    used by service accounts with the plural `projects` scope
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

    // Path 2: standard "roles" array
    if let Some(val) = claims.get("roles") {
        collect_role_strings(val, &mut roles);
    }

    // Path 3: Keycloak realm_access.roles
    if let Some(ra) = claims.get("realm_access") {
        if let Some(val) = ra.get("roles") {
            collect_role_strings(val, &mut roles);
        }
    }

    // Path 4: project-specific role claims.
    // Service accounts using the plural `urn:zitadel:iam:org:projects:roles`
    // scope get roles under `urn:zitadel:iam:org:project:{projectId}:roles`
    // instead of the generic `urn:zitadel:iam:org:project:roles`.
    if let Some(obj) = claims.as_object() {
        for (key, val) in obj {
            if key.starts_with("urn:zitadel:iam:org:project:")
                && key.ends_with(":roles")
                && *key != config.role_claim
            {
                collect_role_strings(val, &mut roles);
            }
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

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://auth.privasys.org".into(),
            audience: "enclave-os-mini".into(),
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
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
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
            "urn:zitadel:iam:org:project:roles": {
                "privasys-platform:manager": { "org": "1" }
            },
            "roles": ["privasys-platform:manager"]
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

    #[test]
    fn project_specific_role_claim() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:363345836026888196:roles": {
                "privasys-platform:manager": { "363334360528650244": "privasys.auth.privasys.org" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec!["privasys-platform:manager".to_string()]);
    }

    #[test]
    fn project_specific_multiple_projects() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:111:roles": {
                "privasys-platform:manager": { "org": "1" }
            },
            "urn:zitadel:iam:org:project:222:roles": {
                "privasys-platform:monitoring": { "org": "1" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r == "privasys-platform:manager"));
        assert!(roles.iter().any(|r| r == "privasys-platform:monitoring"));
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
}
