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
//! | Manager | `enclave-os-mini:manager` | WASM load/unload, TLS CA rotation, + all monitoring |
//! | Monitoring | `enclave-os-mini:monitoring` | Read-only health/status/metrics |
//! | Secret Owner | `enclave-os-mini:secret-owner` | Store/delete/update/list own secrets |
//! | Secret Manager | `enclave-os-mini:secret-manager` | Issue bearer tokens for GetSecret defence-in-depth |
//!
//! Manager implies Monitoring.  Secret Owner and Secret Manager are
//! independent from Manager/Monitoring.
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
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "sgx")]
use core::sync::atomic::{AtomicBool, Ordering};

/// Global flag indicating whether OIDC has been configured.
///
/// Set to `true` by the enclave startup code after a valid [`OidcConfig`]
/// is installed. Modules check this via [`is_oidc_configured()`] to decide
/// whether to enforce token requirements.
static OIDC_CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Mark OIDC as configured (called once at startup).
pub fn set_oidc_configured() {
    OIDC_CONFIGURED.store(true, Ordering::Release);
}

/// Returns `true` if OIDC has been configured for this enclave.
pub fn is_oidc_configured() -> bool {
    OIDC_CONFIGURED.load(Ordering::Acquire)
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
    /// Role claim path in the token (default: `urn:zitadel:iam:org:project:roles`).
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// Claim value for the manager role (default: `enclave-os-mini:manager`).
    #[serde(default = "default_manager_role")]
    pub manager_role: String,
    /// Claim value for the monitoring role (default: `enclave-os-mini:monitoring`).
    #[serde(default = "default_monitoring_role")]
    pub monitoring_role: String,
    /// Claim value for the secret-owner role (default: `enclave-os-mini:secret-owner`).
    #[serde(default = "default_secret_owner_role")]
    pub secret_owner_role: String,
    /// Claim value for the secret-manager role (default: `enclave-os-mini:secret-manager`).
    #[serde(default = "default_secret_manager_role")]
    pub secret_manager_role: String,
}

fn default_role_claim() -> String {
    "urn:zitadel:iam:org:project:roles".into()
}
fn default_manager_role() -> String {
    "enclave-os-mini:manager".into()
}
fn default_monitoring_role() -> String {
    "enclave-os-mini:monitoring".into()
}
fn default_secret_owner_role() -> String {
    "enclave-os-mini:secret-owner".into()
}
fn default_secret_manager_role() -> String {
    "enclave-os-mini:secret-manager".into()
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
    /// Vault secret owner — store/delete/update/list own secrets.
    SecretOwner,
    /// Vault secret manager — defence-in-depth bearer tokens for GetSecret.
    SecretManager,
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

    /// Returns `true` if the token has the SecretOwner role.
    pub fn has_secret_owner(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::SecretOwner))
    }

    /// Returns `true` if the token has the SecretManager role.
    pub fn has_secret_manager(&self) -> bool {
        self.roles.iter().any(|r| matches!(r, OidcRole::SecretManager))
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
        } else if s == &config.secret_owner_role {
            if !roles.contains(&OidcRole::SecretOwner) {
                roles.push(OidcRole::SecretOwner);
            }
        } else if s == &config.secret_manager_role {
            if !roles.contains(&OidcRole::SecretManager) {
                roles.push(OidcRole::SecretManager);
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
            role_claim: default_role_claim(),
            manager_role: default_manager_role(),
            monitoring_role: default_monitoring_role(),
            secret_owner_role: default_secret_owner_role(),
            secret_manager_role: default_secret_manager_role(),
        }
    }

    #[test]
    fn test_zitadel_map_format() {
        let config = test_config();
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
                "enclave-os-mini:manager": { "orgId": "123" },
                "enclave-os-mini:secret-owner": { "orgId": "123" }
            }
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.contains(&OidcRole::Manager));
        assert!(roles.contains(&OidcRole::SecretOwner));
        assert!(!roles.contains(&OidcRole::Monitoring));
    }

    #[test]
    fn test_standard_array_format() {
        let config = test_config();
        let claims = json!({
            "roles": ["enclave-os-mini:monitoring"]
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
                "roles": ["enclave-os-mini:secret-manager"]
            }
        });
        let roles = extract_roles(&claims, &config);
        assert!(roles.contains(&OidcRole::SecretManager));
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
}
