// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! FIDO2 credential persistence in the sealed KV store.
//!
//! Storage schema:
//! - `fido2:cred:{credential_id_b64}` → JSON-serialized [`CredentialRecord`]
//! - `fido2:user:{rp_id}:{user_handle}` → JSON array of credential IDs
//! - `fido2:aaguid_allow` → JSON array of allowed AAGUID hex strings

use enclave_os_kvstore::{kv_store, SealedKvStore};

use crate::types::CredentialRecord;

// ---------------------------------------------------------------------------
//  Key builders
// ---------------------------------------------------------------------------

fn cred_key(credential_id_b64: &str) -> Vec<u8> {
    format!("fido2:cred:{credential_id_b64}").into_bytes()
}

fn user_index_key(rp_id: &str, user_handle: &str) -> Vec<u8> {
    format!("fido2:user:{rp_id}:{user_handle}").into_bytes()
}

const AAGUID_ALLOW_KEY: &[u8] = b"fido2:aaguid_allow";

// ---------------------------------------------------------------------------
//  Credential CRUD
// ---------------------------------------------------------------------------

/// Store a new credential.
pub fn store_credential(record: &CredentialRecord, credential_id_b64: &str) -> Result<(), String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    let json = serde_json::to_vec(record).map_err(|e| format!("serialise credential: {e}"))?;
    store.put(&cred_key(credential_id_b64), &json)?;

    // Update user→credential index
    add_to_user_index(&store, &record.rp_id, &record.user_handle, credential_id_b64)?;

    Ok(())
}

/// Load a credential by ID.
pub fn load_credential(credential_id_b64: &str) -> Result<Option<CredentialRecord>, String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    match store.get(&cred_key(credential_id_b64))? {
        Some(bytes) => {
            let record: CredentialRecord = serde_json::from_slice(&bytes)
                .map_err(|e| format!("deserialise credential: {e}"))?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

/// Update a credential's sign count and push token.
pub fn update_credential(
    credential_id_b64: &str,
    sign_count: u32,
    push_token: Option<&str>,
) -> Result<(), String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    let key = cred_key(credential_id_b64);
    let bytes = store
        .get(&key)?
        .ok_or("credential not found")?;

    let mut record: CredentialRecord =
        serde_json::from_slice(&bytes).map_err(|e| format!("deserialise credential: {e}"))?;

    record.sign_count = sign_count;
    if let Some(token) = push_token {
        record.push_token = Some(token.to_string());
    }

    let json = serde_json::to_vec(&record).map_err(|e| format!("serialise credential: {e}"))?;
    store.put(&key, &json)
}

/// List all credential IDs for a given RP ID and user handle.
pub fn list_credentials(rp_id: &str, user_handle: &str) -> Result<Vec<String>, String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    let key = user_index_key(rp_id, user_handle);
    match store.get(&key)? {
        Some(bytes) => {
            let ids: Vec<String> =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialise index: {e}"))?;
            Ok(ids)
        }
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
//  AAGUID allowlist
// ---------------------------------------------------------------------------

/// Check whether an AAGUID (16 bytes) is in the allowlist.
///
/// If no allowlist is stored, all AAGUIDs are accepted (open mode).
pub fn is_aaguid_allowed(aaguid: &[u8; 16]) -> Result<bool, String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    match store.get(AAGUID_ALLOW_KEY)? {
        Some(bytes) => {
            let allowed: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("deserialise aaguid list: {e}"))?;
            let hex = hex_encode(aaguid);
            Ok(allowed.iter().any(|a| a.eq_ignore_ascii_case(&hex)))
        }
        // No allowlist = accept all (open mode for initial development)
        None => Ok(true),
    }
}

/// Set the AAGUID allowlist.
pub fn set_aaguid_allowlist(aaguids: &[String]) -> Result<(), String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    let json = serde_json::to_vec(aaguids).map_err(|e| format!("serialise aaguid list: {e}"))?;
    store.put(AAGUID_ALLOW_KEY, &json)
}

// ---------------------------------------------------------------------------
//  Internal helpers
// ---------------------------------------------------------------------------

fn add_to_user_index(
    store: &SealedKvStore,
    rp_id: &str,
    user_handle: &str,
    credential_id_b64: &str,
) -> Result<(), String> {
    let key = user_index_key(rp_id, user_handle);
    let mut ids: Vec<String> = match store.get(&key)? {
        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        None => Vec::new(),
    };
    if !ids.iter().any(|id| id == credential_id_b64) {
        ids.push(credential_id_b64.to_string());
    }
    let json = serde_json::to_vec(&ids).map_err(|e| format!("serialise user index: {e}"))?;
    store.put(&key, &json)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
