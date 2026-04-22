// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OIDC token verification for enclave-os.
//!
//! Provides JWT validation against a Zitadel (or any OIDC-compliant) provider.
//! Tokens are verified using public keys fetched from the provider's JWKS
//! endpoint, with a configurable cache TTL.
//!
//! ## Role Model
//!
//! Five roles are defined, scoped to different parts of the enclave:
//!
//! | Role | Default claim value | Scope |
//! |------|---------------------|-------|
//! | Manager | `privasys-platform:manager` | WASM load/unload, TLS CA rotation, + all monitoring |
//! | Monitoring | `privasys-platform:monitoring` | Read-only health/status/metrics |
//! | Vault Owner | `vault:owner` | Create/delete/update/list own keys; export own keys |
//! | Vault Manager | `vault:manager` | Issue ApprovalTokens for policy-gated operations |
//! | Vault Auditor | `vault:auditor` | Read metadata + audit log for keys they auditor |
//!
//! Manager implies Monitoring.  Vault roles are independent from
//! Manager/Monitoring.
//!
//! ## Token Delivery
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
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// Claim value for the manager role (default: `privasys-platform:manager`).
    #[serde(default = "default_manager_role")]
    pub manager_role: String,
    /// Claim value for the monitoring role (default: `privasys-platform:monitoring`).
    #[serde(default = "default_monitoring_role")]
    pub monitoring_role: String,
    /// Claim value for the vault-owner role (default: `vault:owner`).
    #[serde(default = "default_vault_owner_role")]
    pub vault_owner_role: String,
    /// Claim value for the vault-manager role (default: `vault:manager`).
    #[serde(default = "default_vault_manager_role")]
    pub vault_manager_role: String,
    /// Claim value for the vault-auditor role (default: `vault:auditor`).
    #[serde(default = "default_vault_auditor_role")]
    pub vault_auditor_role: String,
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
fn default_vault_owner_role() -> String {
    "vault:owner".into()
}
fn default_vault_manager_role() -> String {
    "vault:manager".into()
}
fn default_vault_auditor_role() -> String {
    "vault:auditor".into()
}

// ---------------------------------------------------------------------------
//  Verified claims
// ---------------------------------------------------------------------------

/// The resolved role from an OIDC token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OidcRole {
    /// Platform operator — WASM lifecycle, TLS CA rotation, + all monitoring.
    Manager,
    /// Read-only monitoring — healthz, readyz, status, metrics.
    Monitoring,
    /// Vault owner — create/delete/update/list/export own keys.
    VaultOwner,
    /// Vault manager — issue ApprovalTokens for policy-gated operations.
    VaultManager,
    /// Vault auditor — read metadata + audit log for keys they auditor.
    VaultAuditor,
}

/// Verified OIDC claims extracted from a bearer token.
///
/// Populated by the auth layer in [`RequestContext`](super::modules::RequestContext)
/// after successful token verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// OIDC subject (`sub` claim) — unique user/service identity.
    pub sub: String,
    /// Resolved roles from the token.
    pub roles: Vec<OidcRole>,
}

impl OidcClaims {
    /// Returns `true` if the token has the Manager role.
    pub fn has_manager(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::Manager))
    }

    /// Returns `true` if the token has Monitoring access
    /// (either explicit Monitoring role or Manager, which implies it).
    pub fn has_monitoring(&self) -> bool {
        self.roles.iter().any(|r| {
            matches!(r, OidcRole::Manager | OidcRole::Monitoring)
        })
    }

    /// Returns `true` if the token has the VaultOwner role.
    pub fn has_vault_owner(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::VaultOwner))
    }

    /// Returns `true` if the token has the VaultManager role.
    pub fn has_vault_manager(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::VaultManager))
    }

    /// Returns `true` if the token has the VaultAuditor role.
    pub fn has_vault_auditor(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::VaultAuditor))
    }
}

// ---------------------------------------------------------------------------
//  Role extraction from raw JWT claims
// ---------------------------------------------------------------------------

/// Extract [`OidcRole`]s from raw JWT claims JSON, searching multiple
/// claim paths (aligned with Enclave OS Virtual):
///
/// 1. Configured `role_claim` (default: `urn:zitadel:iam:org:project:roles`)
///    — supports map `{ "role": {...} }` or array `["role1", "role2"]`
/// 2. Standard `roles` array
/// 3. Keycloak `realm_access.roles`
/// 4. Zitadel project-specific claims (`urn:zitadel:iam:org:project:{id}:roles`)
///    — used by service accounts with the `projects` (plural) scope
pub fn extract_roles(
    claims: &serde_json::Value,
    config: &OidcConfig,
) -> Vec<OidcRole> {
    let mut role_strings: Vec<String> = Vec::new();

    // Path 1: configured role_claim
    if let Some(val) = claims.get(&config.role_claim) {
        collect_role_strings(val, &mut role_strings);
    }

    // Path 2: standard "roles" array
    if let Some(val) = claims.get("roles") {
        collect_role_strings(val, &mut role_strings);
    }

    // Path 3: Keycloak realm_access.roles
    if let Some(ra) = claims.get("realm_access") {
        if let Some(val) = ra.get("roles") {
            collect_role_strings(val, &mut role_strings);
        }
    }

    // Path 4: Zitadel project-specific role claims
    // Service accounts using the plural `urn:zitadel:iam:org:projects:roles` scope
    // get roles under `urn:zitadel:iam:org:project:{projectId}:roles` instead of
    // the generic `urn:zitadel:iam:org:project:roles`.
    if let Some(obj) = claims.as_object() {
        for (key, val) in obj {
            if key.starts_with("urn:zitadel:iam:org:project:")
                && key.ends_with(":roles")
                && *key != config.role_claim
            {
                collect_role_strings(val, &mut role_strings);
            }
        }
    }

    // Map role strings to OidcRole
    let mut roles = Vec::new();
    for s in &role_strings {
        if s == &config.manager_role {
            if !roles.contains(&OidcRole::Manager) {
                roles.push(OidcRole::Manager);
            }
        } else if s == &config.monitoring_role {
            if !roles.contains(&OidcRole::Monitoring) {
                roles.push(OidcRole::Monitoring);
            }
        } else if s == &config.vault_owner_role {
            if !roles.contains(&OidcRole::VaultOwner) {
                roles.push(OidcRole::VaultOwner);
            }
        } else if s == &config.vault_manager_role {
            if !roles.contains(&OidcRole::VaultManager) {
                roles.push(OidcRole::VaultManager);
            }
        } else if s == &config.vault_auditor_role {
            if !roles.contains(&OidcRole::VaultAuditor) {
                roles.push(OidcRole::VaultAuditor);
            }
        }
    }
    roles
}

/// Collect role strings from a JSON value that is either:
/// - An object (Zitadel format): `{ "role-name": { ... } }` → keys are roles
/// - An array of strings: `["role1", "role2"]`
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
            vault_owner_role: default_vault_owner_role(),
            vault_manager_role: default_vault_manager_role(),
            vault_auditor_role: default_vault_auditor_role(),
        }
    }

    #[test]
    fn test_zitadel_map_format() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
                "privasys-platform:manager": { "orgId": "123" },
                "vault:owner": { "orgId": "123" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.contains(&OidcRole::Manager));
        assert!(roles.contains(&OidcRole::VaultOwner));
        assert!(!roles.contains(&OidcRole::Monitoring));
    }

    #[test]
    fn test_standard_array_format() {
        let config = test_config();
        let claims = json!({
            "roles": ["privasys-platform:monitoring"]
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.contains(&OidcRole::Monitoring));
        assert!(!roles.contains(&OidcRole::Manager));
    }

    #[test]
    fn test_keycloak_realm_access() {
        let config = test_config();
        let claims = json!({
            "realm_access": {
                "roles": ["vault:manager"]
            }
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.contains(&OidcRole::VaultManager));
    }

    #[test]
    fn test_has_monitoring_via_manager() {
        let claims = OidcClaims {
            sub: "user1".into(),
            roles: vec![OidcRole::Manager],
        };
        assert!(claims.has_monitoring()); // manager implies monitoring
        assert!(claims.has_manager());
    }

    #[test]
    fn test_no_roles() {
        let config = test_config();
        let claims = json!({"sub": "user1"});
        let roles = extract_roles(&claims, &config);
        assert!(roles.is_empty());
    }

    // -- Role hierarchy: manager implies monitoring --------------------------

    #[test]
    fn manager_implies_monitoring() {
        let claims = OidcClaims { sub: "svc".into(), roles: vec![OidcRole::Manager] };
        assert!(claims.has_manager());
        assert!(claims.has_monitoring(), "manager must imply monitoring");
    }

    #[test]
    fn monitoring_does_not_imply_manager() {
        let claims = OidcClaims { sub: "svc".into(), roles: vec![OidcRole::Monitoring] };
        assert!(claims.has_monitoring());
        assert!(!claims.has_manager(), "monitoring must not imply manager");
    }

    #[test]
    fn manager_does_not_imply_secret_owner() {
        let claims = OidcClaims { sub: "svc".into(), roles: vec![OidcRole::Manager] };
        assert!(!claims.has_vault_owner());
        assert!(!claims.has_vault_manager());
        assert!(!claims.has_vault_auditor());
    }

    #[test]
    fn secret_roles_are_independent() {
        let claims = OidcClaims {
            sub: "svc".into(),
            roles: vec![OidcRole::VaultOwner, OidcRole::VaultManager, OidcRole::VaultAuditor],
        };
        assert!(claims.has_vault_owner());
        assert!(claims.has_vault_manager());
        assert!(claims.has_vault_auditor());
        assert!(!claims.has_manager());
        assert!(!claims.has_monitoring());
    }

    // -- Multiple roles ------------------------------------------------------

    #[test]
    fn all_four_roles() {
        let claims = OidcClaims {
            sub: "admin".into(),
            roles: vec![
                OidcRole::Manager,
                OidcRole::Monitoring,
                OidcRole::VaultOwner,
                OidcRole::VaultManager,
                OidcRole::VaultAuditor,
            ],
        };
        assert!(claims.has_manager());
        assert!(claims.has_monitoring());
        assert!(claims.has_vault_owner());
        assert!(claims.has_vault_manager());
        assert!(claims.has_vault_auditor());
    }

    #[test]
    fn empty_roles() {
        let claims = OidcClaims { sub: "nobody".into(), roles: vec![] };
        assert!(!claims.has_manager());
        assert!(!claims.has_monitoring());
        assert!(!claims.has_vault_owner());
        assert!(!claims.has_vault_manager());
        assert!(!claims.has_vault_auditor());
    }

    // -- extract_roles: Zitadel map format -----------------------------------

    #[test]
    fn zitadel_all_roles() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
                "privasys-platform:manager": { "org": "1" },
                "privasys-platform:monitoring": { "org": "1" },
                "vault:owner": { "org": "1" },
                "vault:manager": { "org": "1" },
                "vault:auditor": { "org": "1" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles.len(), 5);
    }

    #[test]
    fn zitadel_unknown_roles_ignored() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
                "some-other-app:admin": { "org": "1" },
                "privasys-platform:manager": { "org": "1" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec![OidcRole::Manager]);
    }

    // -- extract_roles: duplicate role claim paths ---------------------------

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
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0], OidcRole::Manager);
    }

    // -- extract_roles: custom role_claim config -----------------------------

    #[test]
    fn custom_role_claim_path() {
        let mut config = test_config();
        config.role_claim = "custom_roles".into();
        config.manager_role = "admin".into();
        let claims = json!({
            "custom_roles": ["admin"]
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec![OidcRole::Manager]);
    }

    // -- extract_roles: Zitadel project-specific claims ----------------------

    #[test]
    fn zitadel_project_specific_role_claim() {
        let config = test_config();
        // Service accounts using the plural `projects` scope get roles under
        // project-specific claim paths.
        let claims = json!({
            "urn:zitadel:iam:org:project:363345836026888196:roles": {
                "privasys-platform:manager": { "363334360528650244": "privasys.auth.privasys.org" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert_eq!(roles, vec![OidcRole::Manager]);
    }

    #[test]
    fn zitadel_project_specific_multiple_projects() {
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
        assert!(roles.contains(&OidcRole::Manager));
        assert!(roles.contains(&OidcRole::Monitoring));
    }

    // -- collect_role_strings: edge cases ------------------------------------

    #[test]
    fn collect_from_non_string_array_items() {
        let mut out = Vec::new();
        let val = json!([42, "valid", null, true]);
        collect_role_strings(&val, &mut out);
        assert_eq!(out, vec!["valid"]);
    }

    #[test]
    fn collect_from_scalar_is_noop() {
        let mut out = Vec::new();
        collect_role_strings(&json!("single-string"), &mut out);
        assert!(out.is_empty());
        collect_role_strings(&json!(42), &mut out);
        assert!(out.is_empty());
        collect_role_strings(&json!(null), &mut out);
        assert!(out.is_empty());
    }
}
