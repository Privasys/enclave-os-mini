// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-memory session token store for browser connections.
//!
//! After a FIDO2 ceremony completes on the phone's RA-TLS session, the
//! enclave issues an opaque session token that the browser uses via
//! `Authorization: Bearer <token>`.  Tokens are meaningless outside
//! the enclave that issued them.
//!
//! Tokens expire (default 1h) and are lost on enclave restart — users
//! re-authenticate, which is the correct security posture.

use std::collections::HashMap;
use std::sync::Mutex;

use ring::rand::{SecureRandom, SystemRandom};

use crate::types::*;

// ---------------------------------------------------------------------------
//  Token store
// ---------------------------------------------------------------------------

static TOKEN_STORE: Mutex<Option<HashMap<String, SessionTokenEntry>>> = Mutex::new(None);

/// Initialise the session token store (call once at module init).
pub fn init() {
    let mut store = TOKEN_STORE.lock().unwrap_or_else(|e| e.into_inner());
    *store = Some(HashMap::new());
}

/// Issue a new opaque session token.
///
/// Returns the hex-encoded token string (64 chars).
pub fn issue_token(
    now: u64,
    user_handle: &str,
    credential_id: &str,
    browser_session_id: &str,
    app: Option<String>,
) -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; SESSION_TOKEN_BYTES];
    rng.fill(&mut bytes).map_err(|_| "RNG failure")?;

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let entry = SessionTokenEntry {
        user_handle: user_handle.to_string(),
        credential_id: credential_id.to_string(),
        browser_session_id: browser_session_id.to_string(),
        app,
        expires_at: now + SESSION_TOKEN_TTL_SECS,
    };

    let mut guard = TOKEN_STORE.lock().map_err(|_| "token store lock poisoned")?;
    let store = guard.as_mut().ok_or("token store not initialised")?;

    // Evict expired tokens if at capacity
    if store.len() >= MAX_SESSION_TOKENS {
        store.retain(|_, e| e.expires_at > now);
    }

    if store.len() >= MAX_SESSION_TOKENS {
        return Err("too many active sessions".into());
    }

    store.insert(hex.clone(), entry);
    Ok(hex)
}

/// Validate a session token. Returns the entry if valid.
pub fn validate_token(token: &str, now: u64) -> Result<SessionTokenEntry, String> {
    let guard = TOKEN_STORE.lock().map_err(|_| "token store lock poisoned")?;
    let store = guard.as_ref().ok_or("token store not initialised")?;

    let entry = store.get(token).ok_or("invalid session token")?;

    if now > entry.expires_at {
        return Err("session token expired".into());
    }

    Ok(entry.clone())
}

/// Validate a session token presented to `app`. A token is accepted only by
/// the app its ceremony was run for.
pub fn validate_token_for_app(token: &str, now: u64, app: &str) -> Result<SessionTokenEntry, String> {
    let entry = validate_token(token, now)?;
    if entry.app.as_deref() != Some(app) {
        return Err("session token was not issued for this app".into());
    }
    Ok(entry)
}

/// Revoke a session token (explicit logout).
pub fn revoke_token(token: &str) -> Result<(), String> {
    let mut guard = TOKEN_STORE.lock().map_err(|_| "token store lock poisoned")?;
    let store = guard.as_mut().ok_or("token store not initialised")?;
    store.remove(token);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_accepted_only_by_its_app() {
        init();
        let a = issue_token(100, "alice", "cred", "sid", Some("app-a".into())).unwrap();
        assert!(validate_token_for_app(&a, 101, "app-a").is_ok());
        assert!(validate_token_for_app(&a, 101, "app-b").is_err());

        // A ceremony that named no app yields a token no app accepts.
        let none = issue_token(100, "alice", "cred", "sid", None).unwrap();
        assert!(validate_token_for_app(&none, 101, "app-a").is_err());
        assert!(validate_token_for_app(&none, 101, "").is_err());
    }
}
