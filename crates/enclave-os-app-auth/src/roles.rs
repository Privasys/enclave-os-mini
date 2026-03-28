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

/// Build the KV key for a user's role entry.
fn user_key(user_handle: &str) -> Vec<u8> {
    format!("{}{}", ROLES_PREFIX, user_handle).into_bytes()
}

/// Get the roles assigned to a user.
///
/// Returns an empty vec if the user has no roles stored.
pub fn get_user_roles(store: &SealedKvStore, user_handle: &str) -> Result<Vec<String>, String> {
    match store.get(&user_key(user_handle))? {
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
    store.put(&user_key(user_handle), &value)?;

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
    store.put(&user_key(user_handle), b"[]")?;

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
