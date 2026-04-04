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

/// Privasys Wallet AAGUID: f47ac10b-58cc-4372-a567-0e02b2c3d479
pub const PRIVASYS_WALLET_AAGUID: [u8; 16] = [
    0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x43, 0x72,
    0xa5, 0x67, 0x0e, 0x02, 0xb2, 0xc3, 0xd4, 0x79,
];

/// Privasys Wallet AAGUID as a hex string.
pub const PRIVASYS_WALLET_AAGUID_HEX: &str = "f47ac10b58cc4372a5670e02b2c3d479";

/// Initialise the AAGUID allowlist if none is stored.
///
/// Called during `Fido2Module::new()`. If the KV store has no allowlist,
/// sets the default to Privasys Wallet only. If an explicit list is
/// provided, it overrides whatever is stored.
pub fn init_aaguid_allowlist(explicit: Option<&[String]>) -> Result<(), String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    if let Some(list) = explicit {
        let json =
            serde_json::to_vec(list).map_err(|e| format!("serialise aaguid list: {e}"))?;
        return store.put(AAGUID_ALLOW_KEY, &json);
    }

    // Only set default if nothing is stored yet
    if store.get(AAGUID_ALLOW_KEY)?.is_none() {
        let default = vec![PRIVASYS_WALLET_AAGUID_HEX.to_string()];
        let json =
            serde_json::to_vec(&default).map_err(|e| format!("serialise aaguid list: {e}"))?;
        store.put(AAGUID_ALLOW_KEY, &json)?;
    }

    Ok(())
}

/// Check whether an AAGUID (16 bytes) is in the allowlist.
///
/// If no allowlist is stored (should not happen after init), rejects all
/// — secure by default.
pub fn is_aaguid_allowed(aaguid: &[u8; 16]) -> Result<bool, String> {
    let kv = kv_store().ok_or("kv store not initialised")?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned")?;

    match store.get(AAGUID_ALLOW_KEY)? {
        Some(bytes) => {
            let allowed: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("deserialise aaguid list: {e}"))?;
            // Wildcard: ["*"] accepts all (for development/testing only)
            if allowed.iter().any(|a| a == "*") {
                return Ok(true);
            }
            let hex = hex_encode(aaguid);
            Ok(allowed.iter().any(|a| a.eq_ignore_ascii_case(&hex)))
        }
        // No allowlist after init = reject all (secure by default)
        None => Ok(false),
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

/// Pure-logic AAGUID check: returns true if the AAGUID hex is in the allowlist,
/// or if the list contains the wildcard `"*"`.
pub fn check_aaguid_in_list(aaguid: &[u8; 16], allowed: &[String]) -> bool {
    if allowed.iter().any(|a| a == "*") {
        return true;
    }
    let hex = hex_encode(aaguid);
    allowed.iter().any(|a| a.eq_ignore_ascii_case(&hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVASYS_AAGUID: [u8; 16] = PRIVASYS_WALLET_AAGUID;
    const WINDOWS_HELLO_AAGUID: [u8; 16] = [
        0x08, 0x98, 0x70, 0x58, 0xca, 0xdc, 0x4b, 0x81,
        0xb6, 0xe1, 0x30, 0xde, 0x50, 0xdc, 0xbe, 0x96,
    ];
    const ZERO_AAGUID: [u8; 16] = [0u8; 16];

    #[test]
    fn privasys_aaguid_allowed_by_default_list() {
        let list = vec![PRIVASYS_WALLET_AAGUID_HEX.to_string()];
        assert!(check_aaguid_in_list(&PRIVASYS_AAGUID, &list));
    }

    #[test]
    fn windows_hello_rejected_by_default_list() {
        let list = vec![PRIVASYS_WALLET_AAGUID_HEX.to_string()];
        assert!(!check_aaguid_in_list(&WINDOWS_HELLO_AAGUID, &list));
    }

    #[test]
    fn zero_aaguid_rejected() {
        let list = vec![PRIVASYS_WALLET_AAGUID_HEX.to_string()];
        assert!(!check_aaguid_in_list(&ZERO_AAGUID, &list));
    }

    #[test]
    fn wildcard_allows_everything() {
        let list = vec!["*".to_string()];
        assert!(check_aaguid_in_list(&PRIVASYS_AAGUID, &list));
        assert!(check_aaguid_in_list(&WINDOWS_HELLO_AAGUID, &list));
        assert!(check_aaguid_in_list(&ZERO_AAGUID, &list));
    }

    #[test]
    fn empty_list_rejects_all() {
        let list: Vec<String> = vec![];
        assert!(!check_aaguid_in_list(&PRIVASYS_AAGUID, &list));
        assert!(!check_aaguid_in_list(&WINDOWS_HELLO_AAGUID, &list));
    }

    #[test]
    fn case_insensitive_match() {
        let list = vec!["F47AC10B58CC4372A5670E02B2C3D479".to_string()];
        assert!(check_aaguid_in_list(&PRIVASYS_AAGUID, &list));
    }

    #[test]
    fn multiple_aaguids_in_list() {
        let list = vec![
            PRIVASYS_WALLET_AAGUID_HEX.to_string(),
            "0898705800000000000000000000beef".to_string(),
        ];
        assert!(check_aaguid_in_list(&PRIVASYS_AAGUID, &list));
        // Windows Hello not in the list
        assert!(!check_aaguid_in_list(&WINDOWS_HELLO_AAGUID, &list));
    }

    #[test]
    fn hex_encode_produces_lowercase() {
        assert_eq!(hex_encode(&PRIVASYS_AAGUID), PRIVASYS_WALLET_AAGUID_HEX);
    }

    #[test]
    fn aaguid_constant_matches_hex_constant() {
        assert_eq!(hex_encode(&PRIVASYS_WALLET_AAGUID), PRIVASYS_WALLET_AAGUID_HEX);
    }
}
