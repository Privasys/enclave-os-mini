// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Role storage and lookup using the app's sealed KV store.
//!
//! Keys use the `roles:` prefix within the `app:<name>` table:
//!
//! - `roles:<user_handle>` — JSON array of role strings
//! - `roles:__manifest__` — JSON array of all known user handles
//! - `roles:__default__` — JSON array of roles auto-assigned to new users
//!
//! This store never confers [`ADMIN_ROLE`]. Admin comes only from the `roles`
//! claim of an OIDC token issued by the identity provider; it is refused on
//! write here and stripped on read, so a value already on disk is inert.
//!
//! It used to be the other way round: the first user to authenticate with a
//! FIDO2 session was made `admin`. FIDO2 registration needs no prior identity,
//! every WASM app is loaded with FIDO2 enabled, and apps whose users sign in
//! through the identity provider never write here, so the manifest stayed empty
//! and the admin seat stayed open to whoever registered first, at any time.
//! Stripping on read, rather than only removing the grant, also neutralises any
//! admin that was claimed that way before the fix.

use std::string::String;
use std::vec::Vec;

use enclave_os_kvstore::SealedKvStore;

/// The role this store can never grant. See the module documentation.
pub const ADMIN_ROLE: &str = "admin";

/// Refuse a role list that would confer [`ADMIN_ROLE`].
fn reject_admin(roles: &[String]) -> Result<(), String> {
    if roles.iter().any(|r| r == ADMIN_ROLE) {
        return Err(format!(
            "the '{ADMIN_ROLE}' role cannot be stored; it is granted only by the identity provider"
        ));
    }
    Ok(())
}

/// Drop [`ADMIN_ROLE`] from a role list read back from the store.
fn without_admin(mut roles: Vec<String>) -> Vec<String> {
    roles.retain(|r| r != ADMIN_ROLE);
    roles
}

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
/// manifest used to make the next user count as the first user ever, and the
/// first user was handed `admin`.
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
/// Returns an empty vec if the user has no roles stored. Never contains
/// [`ADMIN_ROLE`], whatever is on disk.
pub fn get_user_roles(store: &SealedKvStore, user_handle: &str) -> Result<Vec<String>, String> {
    match store.get(&user_key(user_handle)?)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(without_admin)
            .map_err(|e| format!("roles deserialization failed: {e}")),
        None => Ok(Vec::new()),
    }
}

/// Get a user's roles, enrolling them with the default roles if new.
///
/// - A known user (in the manifest) gets their stored roles.
/// - A new user is recorded with the configured default roles, which may be
///   empty. Being first confers nothing.
pub fn get_or_enroll_user_roles(
    store: &SealedKvStore,
    user_handle: &str,
) -> Result<Vec<String>, String> {
    let manifest = load_manifest(store)?;

    if manifest.contains(&user_handle.to_string()) {
        return get_user_roles(store, user_handle);
    }

    // New user: assign defaults (may be empty).
    let defaults = get_default_roles(store)?;
    set_user_roles(store, user_handle, &defaults)?;
    Ok(defaults)
}

/// Set the roles for a user (overwrites any existing roles).
///
/// Also ensures the user is in the manifest. Refuses [`ADMIN_ROLE`].
pub fn set_user_roles(
    store: &SealedKvStore,
    user_handle: &str,
    roles: &[String],
) -> Result<(), String> {
    reject_admin(roles)?;
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
/// The user remains in the manifest, so their next authentication does not
/// enroll them afresh with the default roles.
pub fn remove_user_roles(store: &SealedKvStore, user_handle: &str) -> Result<(), String> {
    store.put(&user_key(user_handle)?, b"[]")?;

    // Ensure user stays in manifest (prevents re-enrollment).
    let mut manifest = load_manifest(store)?;
    let handle = user_handle.to_string();
    if !manifest.contains(&handle) {
        manifest.push(handle);
        save_manifest(store, &manifest)?;
    }
    Ok(())
}

/// Get the default roles assigned to new users. Never contains
/// [`ADMIN_ROLE`], whatever is on disk.
pub fn get_default_roles(store: &SealedKvStore) -> Result<Vec<String>, String> {
    match store.get(DEFAULT_KEY)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(without_admin)
            .map_err(|e| format!("default roles deserialization failed: {e}")),
        None => Ok(Vec::new()),
    }
}

/// Set the default roles for new users. Refuses [`ADMIN_ROLE`].
pub fn set_default_roles(store: &SealedKvStore, roles: &[String]) -> Result<(), String> {
    reject_admin(roles)?;
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

/// Behaviour through a real `SealedKvStore`, with an in-memory map standing
/// in for the host.
#[cfg(test)]
mod store_tests {
    use super::*;
    use enclave_os_common::modules::AppIdentity;
    use enclave_os_common::ocall::{self, OcallVtable};
    use enclave_os_common::rpc::KvBatchOp;
    use std::collections::HashMap;
    use std::sync::{Mutex, Once};

    static HOST: Mutex<Option<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>> = Mutex::new(None);
    static REGISTER: Once = Once::new();

    fn put(t: &[u8], k: &[u8], v: &[u8]) -> Result<(), i32> {
        let mut h = HOST.lock().unwrap();
        h.get_or_insert_with(HashMap::new).insert((t.to_vec(), k.to_vec()), v.to_vec());
        Ok(())
    }
    fn get(t: &[u8], k: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let h = HOST.lock().unwrap();
        Ok(h.as_ref().and_then(|m| m.get(&(t.to_vec(), k.to_vec())).cloned()))
    }
    fn unused<T>() -> Result<T, i32> {
        Err(-1)
    }

    /// Each test gets its own table, so the shared map needs no reset and
    /// tests can run in parallel.
    fn store(table: &str) -> SealedKvStore {
        REGISTER.call_once(|| {
            ocall::register(OcallVtable {
                net_tcp_listen: |_, _| unused(),
                net_tcp_accept: |_| unused(),
                net_tcp_connect: |_, _| unused(),
                net_send: |_, _| unused(),
                net_recv: |_, _| unused(),
                net_close: |_| {},
                kv_store_put: put,
                kv_store_get: get,
                kv_store_delete: |_, _| unused(),
                kv_store_list_keys: |_, _| unused(),
                kv_store_write_batch: |_, _: &[KvBatchOp]| unused(),
                kv_store_multi_get: |_, _| unused(),
                kv_store_scan: |_, _, _, _| unused(),
                get_current_time: || Ok(0),
                log: |_, _| {},
                cert_store_register: |_: AppIdentity| {},
                cert_store_unregister: |_| false,
            });
        });
        SealedKvStore::from_master_key_with_table([7u8; 32], table.as_bytes())
    }

    fn roles(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_first_user_is_not_made_admin() {
        let s = store("first-user");
        assert_eq!(get_or_enroll_user_roles(&s, "alice").unwrap(), Vec::<String>::new());
        // And stays that way on the next authentication.
        assert_eq!(get_or_enroll_user_roles(&s, "alice").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_new_user_gets_the_default_roles() {
        let s = store("defaults");
        set_default_roles(&s, &roles(&["viewer"])).unwrap();
        assert_eq!(get_or_enroll_user_roles(&s, "alice").unwrap(), roles(&["viewer"]));
    }

    #[test]
    fn admin_is_refused_on_write() {
        let s = store("refuse-write");
        assert!(set_user_roles(&s, "alice", &roles(&["admin"])).is_err());
        assert!(set_user_roles(&s, "alice", &roles(&["viewer", "admin"])).is_err());
        assert!(set_default_roles(&s, &roles(&["admin"])).is_err());
        // Other roles are unaffected.
        set_user_roles(&s, "alice", &roles(&["editor"])).unwrap();
        assert_eq!(get_user_roles(&s, "alice").unwrap(), roles(&["editor"]));
    }

    /// The case that matters for a store written before the fix: an `admin`
    /// already on disk, whoever claimed it, confers nothing.
    #[test]
    fn an_admin_already_on_disk_is_inert() {
        let s = store("pre-fix");
        s.put(b"roles:mallory", br#"["admin","viewer"]"#).unwrap();
        s.put(b"roles:__manifest__", br#"["mallory"]"#).unwrap();
        s.put(b"roles:__default__", br#"["admin"]"#).unwrap();

        assert_eq!(get_user_roles(&s, "mallory").unwrap(), roles(&["viewer"]));
        assert_eq!(get_or_enroll_user_roles(&s, "mallory").unwrap(), roles(&["viewer"]));
        assert_eq!(
            list_users(&s).unwrap(),
            vec![("mallory".to_string(), roles(&["viewer"]))]
        );

        // A default of `admin` on disk neither grants it nor blocks enrollment.
        assert_eq!(get_default_roles(&s).unwrap(), Vec::<String>::new());
        assert_eq!(get_or_enroll_user_roles(&s, "bob").unwrap(), Vec::<String>::new());
    }
}
