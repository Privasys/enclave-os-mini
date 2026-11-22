// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Pure checks on caller- and developer-supplied input: metric names, the
//! size of a call's parameters, the WIT `@auth` annotation and the roles
//! claim of an app OIDC token.
//!
//! No SGX or wasmtime types, so `tests/wasm-limits-unit` runs it on the host.

use std::string::String;
use std::vec::Vec;

// ---------------------------------------------------------------------------
//  Metric names
// ---------------------------------------------------------------------------

/// Bucket for every function name that is not one of the app's exports.
pub const UNKNOWN_FUNCTION: &str = "<unknown>";

/// Longest function name kept in metrics.
pub const MAX_METRIC_NAME_LEN: usize = 128;

/// Most distinct function names kept per app when metrics are reloaded.
pub const MAX_METRIC_FUNCTIONS: usize = 1024;

/// The name a call's metrics are recorded under: the function itself when
/// it is one of the app's exports (`is_export`) and not over-long, the
/// shared [`UNKNOWN_FUNCTION`] bucket otherwise.
pub fn metric_function_name(function: &str, is_export: bool) -> &str {
    if is_export && function.len() <= MAX_METRIC_NAME_LEN {
        function
    } else {
        UNKNOWN_FUNCTION
    }
}

// ---------------------------------------------------------------------------
//  Call parameters
// ---------------------------------------------------------------------------

/// Most values one call's parameters may expand to (each byte of a `bytes`
/// parameter becomes one value).
pub const MAX_PARAM_VALUES: usize = 1024 * 1024;

/// Most bytes one call's `bytes` and `string` parameters may carry.
pub const MAX_PARAM_BYTES: usize = 4 * 1024 * 1024;

/// What a call's parameters have used of the per-call limits.
#[derive(Debug, Default)]
pub struct ParamBudget {
    values: usize,
    bytes: usize,
}

impl ParamBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count `values` more values carrying `bytes` more bytes; an error once
    /// either limit is crossed.
    pub fn take(&mut self, values: usize, bytes: usize) -> Result<(), String> {
        self.values = self.values.saturating_add(values);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.values > MAX_PARAM_VALUES {
            return Err(format!("call parameters exceed {MAX_PARAM_VALUES} values"));
        }
        if self.bytes > MAX_PARAM_BYTES {
            return Err(format!("call parameters exceed {MAX_PARAM_BYTES} bytes"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
//  @auth annotation
// ---------------------------------------------------------------------------

/// A parsed WIT `@auth` annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAnnotation {
    Public,
    Authenticated,
    Owner,
    /// `role(a, b)`: never empty.
    Role(Vec<String>),
}

/// Parse an `@auth` annotation value: `public`, `authenticated`, `owner` or
/// `role(a, b, ...)`, case-insensitively and with optional spaces (`Role (
/// a )`). Anything else, and a `role()` naming no role, is an error: the
/// app is refused rather than run under a policy its developer did not
/// write.
pub fn parse_auth_annotation(value: &str) -> Result<AuthAnnotation, String> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("public") {
        return Ok(AuthAnnotation::Public);
    }
    if v.eq_ignore_ascii_case("authenticated") {
        return Ok(AuthAnnotation::Authenticated);
    }
    if v.eq_ignore_ascii_case("owner") {
        return Ok(AuthAnnotation::Owner);
    }
    if v.len() >= 4 && v.as_bytes()[..4].eq_ignore_ascii_case(b"role") {
        let rest = v[4..].trim_start();
        if let Some(inner) = rest.strip_prefix('(').and_then(|s| s.trim_end().strip_suffix(')')) {
            let roles: Vec<String> = inner
                .split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect();
            if roles.is_empty() {
                return Err(format!("@auth '{v}' names no role"));
            }
            return Ok(AuthAnnotation::Role(roles));
        }
    }
    Err(format!(
        "unrecognised @auth '{v}' (expected public, authenticated, owner or role(...))"
    ))
}

// ---------------------------------------------------------------------------
//  Roles claim
// ---------------------------------------------------------------------------

/// The roles an app OIDC token carries under the app's configured
/// `roles_claim`, and nowhere else: a top-level claim of that exact name,
/// or else a dotted path into nested objects (`realm_access.roles`). The
/// value is an array of strings or an object whose keys are the roles.
pub fn roles_from_claims(claims: &serde_json::Value, roles_claim: &str) -> Vec<String> {
    let mut out = Vec::new();
    let found = claims.get(roles_claim).or_else(|| {
        if !roles_claim.contains('.') {
            return None;
        }
        roles_claim
            .split('.')
            .try_fold(claims, |v, seg| v.get(seg))
    });
    match found {
        Some(serde_json::Value::Array(arr)) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                }
            }
        }
        Some(serde_json::Value::Object(map)) => {
            for key in map.keys() {
                out.push(key.clone());
            }
        }
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_exports_get_their_own_metric_name() {
        assert_eq!(metric_function_name("hello", true), "hello");
        assert_eq!(metric_function_name("hello", false), UNKNOWN_FUNCTION);
        let long = "f".repeat(MAX_METRIC_NAME_LEN + 1);
        assert_eq!(metric_function_name(&long, true), UNKNOWN_FUNCTION);
    }

    #[test]
    fn the_param_budget_stops_at_either_limit() {
        let mut b = ParamBudget::new();
        assert!(b.take(MAX_PARAM_VALUES, 0).is_ok());
        assert!(b.take(1, 0).is_err());

        let mut b = ParamBudget::new();
        assert!(b.take(1, MAX_PARAM_BYTES).is_ok());
        assert!(b.take(1, 1).is_err());

        let mut b = ParamBudget::new();
        assert!(b.take(usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn auth_annotations_parse_leniently_in_form_and_strictly_in_meaning() {
        assert_eq!(parse_auth_annotation(" Public ").unwrap(), AuthAnnotation::Public);
        assert_eq!(parse_auth_annotation("AUTHENTICATED").unwrap(), AuthAnnotation::Authenticated);
        assert_eq!(parse_auth_annotation("owner").unwrap(), AuthAnnotation::Owner);
        let roles = AuthAnnotation::Role(vec!["a".into(), "b".into()]);
        assert_eq!(parse_auth_annotation("role(a, b)").unwrap(), roles);
        assert_eq!(parse_auth_annotation("Role ( a ,b )").unwrap(), roles);
        assert!(parse_auth_annotation("role()").is_err());
        assert!(parse_auth_annotation("role( , )").is_err());
        assert!(parse_auth_annotation("admin").is_err());
        assert!(parse_auth_annotation("roles(a)").is_err());
        assert!(parse_auth_annotation("role(a").is_err());
        assert!(parse_auth_annotation("").is_err());
    }

    #[test]
    fn roles_come_only_from_the_configured_claim() {
        let claims = json!({
            "roles": ["from-roles"],
            "realm_access": { "roles": ["from-realm"] },
            "groups": ["g1", "g2", "g1"],
        });
        assert_eq!(roles_from_claims(&claims, "groups"), vec!["g1", "g2"]);
        assert_eq!(roles_from_claims(&claims, "roles"), vec!["from-roles"]);
        assert_eq!(roles_from_claims(&claims, "realm_access.roles"), vec!["from-realm"]);
        assert!(roles_from_claims(&claims, "missing").is_empty());
        let obj = json!({ "perm": { "editor": {}, "viewer": {} } });
        assert_eq!(roles_from_claims(&obj, "perm"), vec!["editor", "viewer"]);
    }
}
