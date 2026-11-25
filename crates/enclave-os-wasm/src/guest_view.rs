// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! What an app's code may see of its caller (Security, defence in depth).
//!
//! The runtime consumes the caller's bearer (`app_auth`) for its own checks
//! and never hands it to the guest. The guest sees the caller's id and the
//! roles scoped to the app itself: never the platform's own roles (whether a
//! caller is Privasys staff is not an app's business), and never a parameter
//! carrying the bearer.

use std::string::String;
use std::vec::Vec;

/// The body field that carries the caller's bearer. Never a parameter.
pub const APP_AUTH_FIELD: &str = "app_auth";

/// Whether `role` is one of the platform's own roles: any role namespaced by
/// a platform audience (`privasys-platform:<role>`,
/// `privasys-platform-test:<role>`, ...), or one of the configured platform
/// role names (`extra`, from the platform OIDC config).
pub fn is_platform_role(role: &str, extra: &[&str]) -> bool {
    if extra.iter().any(|r| !r.is_empty() && *r == role) {
        return true;
    }
    match role.split_once(':') {
        Some((ns, _)) => ns == "privasys-platform" || ns.starts_with("privasys-platform-"),
        None => false,
    }
}

/// The caller's roles as the guest sees them: the platform's roles removed.
/// Bare role names (`admin`, `user-management`, ...) come from the app's own
/// role store or the app's own identity provider and stay.
pub fn guest_visible_roles(roles: Vec<String>, extra: &[&str]) -> Vec<String> {
    roles.into_iter().filter(|r| !is_platform_role(r, extra)).collect()
}

/// The value of parameter `name` from a call's named body: never the bearer,
/// even for a function that declares a parameter named `app_auth`.
pub fn guest_param<'a>(
    body: Option<&'a serde_json::Map<String, serde_json::Value>>,
    name: &str,
) -> &'a serde_json::Value {
    static NULL: serde_json::Value = serde_json::Value::Null;
    if name == APP_AUTH_FIELD {
        return &NULL;
    }
    body.and_then(|o| o.get(name)).unwrap_or(&NULL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_roles_never_reach_the_guest() {
        let roles: Vec<String> = [
            "privasys-platform:manager",
            "privasys-platform:monitoring",
            "privasys-platform:admin",
            "privasys-platform-test:manager",
            "custom-manager",
            "admin",
            "user-management",
            "app:my-app:editor",
            "reader",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let seen = guest_visible_roles(roles, &["custom-manager", ""]);
        assert_eq!(seen, vec!["admin", "user-management", "app:my-app:editor", "reader"]);
        // A look-alike namespace is the app's own.
        assert!(!is_platform_role("privasys-platformx:admin", &[]));
        assert!(!is_platform_role("privasys-platform", &[]));
    }

    #[test]
    fn the_bearer_is_never_a_parameter() {
        let body: serde_json::Map<String, serde_json::Value> = serde_json::from_value(serde_json::json!({
            "app_auth": "eyJhbGciOi.secret.token",
            "name": "x"
        }))
        .unwrap();
        assert_eq!(guest_param(Some(&body), "app_auth"), &serde_json::Value::Null);
        assert_eq!(guest_param(Some(&body), "name"), &serde_json::json!("x"));
        assert_eq!(guest_param(Some(&body), "missing"), &serde_json::Value::Null);
        assert_eq!(guest_param(None, "name"), &serde_json::Value::Null);
    }
}
