// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Role storage and lookup using the app's sealed KV store.
//!
//! Keys use the `roles:` prefix within the `app:<name>` table:
//!
//! - `roles:<user_handle>` — JSON array of role strings
//! - `roles:__manifest__` — JSON array of all known user handles
//! - `roles:__default__` — JSON array of roles auto-assigned to new users

use std::string::String;
use std::vec::Vec;

use enclave_os_kvstore::SealedKvStore;

/// KV key prefix for per-user role entries.
const ROLES_PREFIX: &str = "roles:";

/// KV key for the manifest of all user handles that have been seen.
const MANIFEST_KEY: &[u8] = b"roles:__manifest__";

/// KV key for the default roles assigned to newly seen users.
const DEFAULT_KEY: &[u8] = b"roles:__default__";

/// Longest accepted user handle. Comfortably above a FIDO2 user handle (64
/// bytes at most) and an OIDC `sub`, while keeping the key bounded.
const MAX_HANDLE_LEN: usize = 256;

/// Reject a handle that is unusable or that would address a reserved key.
///
/// `user_key` interpolates the handle straight after `roles:`, so a handle of
/// `__manifest__` or `__default__` addresses the control entries rather than a
/// user. That is reachable: the handle arrives caller-supplied and unvalidated
/// from FIDO2 `register/begin`. The damage is not limited to one user's roles
/// -- `set_user_roles` would write the default-roles array over the manifest,
/// and both are JSON string arrays, so it parses back cleanly. An emptied
/// manifest then makes `get_user_roles_with_bootstrap` treat the next user as
/// the first user ever and hand them `admin`.
///
/// Reserved names are rejected by their `__` prefix rather than by an exact
/// list, so a control key added later is covered by construction.
pub fn validate_user_handle(user_handle: &str) -> Result<(), String> {
    if user_handle.is_empty() {
        return Err("user handle must not be empty".into());
    }
    if user_handle.len() > MAX_HANDLE_LEN {
        return Err(format!(
            "user handle must be at most {MAX_HANDLE_LEN} bytes, got {}",
            user_handle.len()
        ));
    }
    if user_handle.starts_with("__") {
        return Err("user handle must not start with '__' (reserved)".into());
    }
    if user_handle.chars().any(|c| c.is_control()) {
        return Err("user handle must not contain control characters".into());
    }
    Ok(())
}

/// Build the KV key for a user's role entry.
///
/// Fallible by design: a handle that would collide with a control key must
/// never reach the store, so every caller is forced to handle the refusal.
fn user_key(user_handle: &str) -> Result<Vec<u8>, String> {
    validate_user_handle(user_handle)?;
    Ok(format!("{}{}", ROLES_PREFIX, user_handle).into_bytes())
}

/// Get the roles assigned to a user.
///
/// Returns an empty vec if the user has no roles stored.
pub fn get_user_roles(store: &SealedKvStore, user_handle: &str) -> Result<Vec<String>, String> {
    match store.get(&user_key(user_handle)?)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("roles deserialization failed: {e}")),
        None => Ok(Vec::new()),
    }
}

/// Get a user's roles with automatic bootstrapping.
///
/// - If the user is already known (in manifest), returns their stored roles.
/// - If the user is new and the manifest is empty (first user ever),
///   auto-assigns `["admin"]` and returns it.
/// - If the user is new and other users exist, assigns the configured
///   default roles.
pub fn get_user_roles_with_bootstrap(
    store: &SealedKvStore,
    user_handle: &str,
) -> Result<Vec<String>, String> {
    let manifest = load_manifest(store)?;

    if manifest.contains(&user_handle.to_string()) {
        // Known user — return stored roles.
        return get_user_roles(store, user_handle);
    }

    // New user.
    if manifest.is_empty() {
        // First user ever — auto-assign admin.
        let admin_roles = vec!["admin".to_string()];
        set_user_roles(store, user_handle, &admin_roles)?;
        return Ok(admin_roles);
    }

    // Assign defaults (may be empty).
    let defaults = get_default_roles(store)?;
    set_user_roles(store, user_handle, &defaults)?;
    Ok(defaults)
}

/// Set the roles for a user (overwrites any existing roles).
///
/// Also ensures the user is in the manifest.
pub fn set_user_roles(
    store: &SealedKvStore,
    user_handle: &str,
    roles: &[String],
) -> Result<(), String> {
    let value = serde_json::to_vec(roles)
        .map_err(|e| format!("roles serialization failed: {e}"))?;
    store.put(&user_key(user_handle)?, &value)?;

    // Ensure user is in manifest.
    let mut manifest = load_manifest(store)?;
    let handle = user_handle.to_string();
    if !manifest.contains(&handle) {
        manifest.push(handle);
        save_manifest(store, &manifest)?;
    }
    Ok(())
}

/// Remove all roles from a user.
///
/// The user remains in the manifest (so they won't be re-bootstrapped
/// on next authentication).
pub fn remove_user_roles(store: &SealedKvStore, user_handle: &str) -> Result<(), String> {
    store.put(&user_key(user_handle)?, b"[]")?;

    // Ensure user stays in manifest (prevents re-bootstrap).
    let mut manifest = load_manifest(store)?;
    let handle = user_handle.to_string();
    if !manifest.contains(&handle) {
        manifest.push(handle);
        save_manifest(store, &manifest)?;
    }
    Ok(())
}

/// Get the default roles assigned to new users.
pub fn get_default_roles(store: &SealedKvStore) -> Result<Vec<String>, String> {
    match store.get(DEFAULT_KEY)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("default roles deserialization failed: {e}")),
        None => Ok(Vec::new()),
    }
}

/// Set the default roles for new users.
pub fn set_default_roles(store: &SealedKvStore, roles: &[String]) -> Result<(), String> {
    let value = serde_json::to_vec(roles)
        .map_err(|e| format!("default roles serialization failed: {e}"))?;
    store.put(DEFAULT_KEY, &value)
}

/// List all users and their roles.
///
/// Includes users with empty roles (distinguishes "no roles" from "never seen").
pub fn list_users(store: &SealedKvStore) -> Result<Vec<(String, Vec<String>)>, String> {
    let manifest = load_manifest(store)?;
    let mut result = Vec::with_capacity(manifest.len());
    for handle in manifest {
        let roles = get_user_roles(store, &handle)?;
        result.push((handle, roles));
    }
    Ok(result)
}

/// Check if no users have been seen yet (manifest is empty).
pub fn is_first_user(store: &SealedKvStore) -> Result<bool, String> {
    let manifest = load_manifest(store)?;
    Ok(manifest.is_empty())
}

// ── Internal helpers ───────────────────────────────────────────────

fn load_manifest(store: &SealedKvStore) -> Result<Vec<String>, String> {
    match store.get(MANIFEST_KEY)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("roles manifest deserialization failed: {e}")),
        None => Ok(Vec::new()),
    }
}

fn save_manifest(store: &SealedKvStore, manifest: &[String]) -> Result<(), String> {
    let value = serde_json::to_vec(manifest)
        .map_err(|e| format!("roles manifest serialization failed: {e}"))?;
    store.put(MANIFEST_KEY, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_the_reserved_control_keys() {
        // These are the two that exist today; `__`-prefixed is refused as a
        // class so a control key added later is covered without a code change.
        assert!(validate_user_handle("__manifest__").is_err());
        assert!(validate_user_handle("__default__").is_err());
        assert!(validate_user_handle("__whatever_comes_next__").is_err());
    }

    #[test]
    fn rejects_unusable_handles() {
        assert!(validate_user_handle("").is_err());
        assert!(validate_user_handle(&"a".repeat(MAX_HANDLE_LEN + 1)).is_err());
        assert!(validate_user_handle("has\nnewline").is_err());
        assert!(validate_user_handle("has\0nul").is_err());
    }

    #[test]
    fn accepts_realistic_handles() {
        // A pairwise IdP sub, a base64url FIDO2 handle, and an email-shaped
        // sub all have to keep working.
        assert!(validate_user_handle("r2C7Km0L").is_ok());
        assert!(validate_user_handle("dXNlci1oYW5kbGUtYnl0ZXM").is_ok());
        assert!(validate_user_handle("someone@example.com").is_ok());
        assert!(validate_user_handle(&"a".repeat(MAX_HANDLE_LEN)).is_ok());
        // A single leading underscore is not reserved.
        assert!(validate_user_handle("_leading").is_ok());
    }

    #[test]
    fn user_key_carries_the_refusal() {
        assert!(user_key("__manifest__").is_err());
        assert_eq!(user_key("alice").unwrap(), b"roles:alice".to_vec());
    }
}
