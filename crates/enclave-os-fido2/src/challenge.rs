// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-memory challenge store with TTL and bounded capacity.
//!
//! Challenges are ephemeral — they survive only in enclave memory.
//! After an enclave restart, all pending challenges are lost (users
//! must re-initiate the ceremony).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};

use crate::types::*;

// ---------------------------------------------------------------------------
//  Challenge metadata
// ---------------------------------------------------------------------------

/// Metadata associated with a pending challenge.
#[derive(Debug, Clone)]
struct ChallengeEntry {
    /// The raw 32-byte challenge.
    challenge: Vec<u8>,
    /// Unix timestamp when this challenge expires.
    expires_at: u64,
    /// Browser session ID (for token binding after completion).
    browser_session_id: Option<String>,
    /// Whether this is a registration or authentication challenge.
    ceremony: Ceremony,
    /// User handle (stored at begin, needed at complete).
    user_handle: Option<String>,
    /// User display name (stored at begin, needed at complete).
    user_name: Option<String>,
    /// The app the ceremony is for (the session token is bound to it).
    app: Option<String>,
    /// Registration only: the signed-in user is adding a credential to
    /// their own handle.
    extends_user: bool,
}

/// What a begin request records for its complete.
#[derive(Debug, Clone)]
pub struct PendingCeremony {
    pub browser_session_id: Option<String>,
    pub ceremony: Ceremony,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub app: Option<String>,
    pub extends_user: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Registration,
    Authentication,
}

// ---------------------------------------------------------------------------
//  Challenge store
// ---------------------------------------------------------------------------

static CHALLENGE_STORE: Mutex<Option<HashMap<String, ChallengeEntry>>> = Mutex::new(None);

/// Initialise the challenge store (call once at module init).
pub fn init() {
    let mut store = CHALLENGE_STORE.lock().unwrap_or_else(|e| e.into_inner());
    *store = Some(HashMap::new());
}

/// Generate a new challenge and store it.
///
/// Returns the base64url-encoded challenge string.
pub fn create_challenge(
    now: u64,
    pending: PendingCeremony,
) -> Result<String, String> {
    for (what, field) in [
        ("session ID", pending.browser_session_id.as_deref()),
        ("user handle", pending.user_handle.as_deref()),
        ("user name", pending.user_name.as_deref()),
    ] {
        if field.map_or(false, |f| f.len() > MAX_FIELD_LEN) {
            return Err(format!("{what} must be at most {MAX_FIELD_LEN} bytes"));
        }
    }

    let rng = SystemRandom::new();
    let mut bytes = [0u8; CHALLENGE_BYTES];
    rng.fill(&mut bytes).map_err(|_| "RNG failure")?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let entry = ChallengeEntry {
        challenge: bytes.to_vec(),
        expires_at: now + CHALLENGE_TTL_SECS,
        browser_session_id: pending.browser_session_id,
        ceremony: pending.ceremony,
        user_handle: pending.user_handle,
        user_name: pending.user_name,
        app: pending.app,
        extends_user: pending.extends_user,
    };

    let mut guard = CHALLENGE_STORE.lock().map_err(|_| "challenge store lock poisoned")?;
    let store = guard.as_mut().ok_or("challenge store not initialised")?;

    // At capacity: drop expired entries, then, if still full, the oldest
    // pending challenge. A flood of begins then only displaces older
    // ceremonies, the flood's own first, instead of refusing every begin.
    if store.len() >= MAX_PENDING_CHALLENGES {
        store.retain(|_, e| e.expires_at > now);
    }
    while store.len() >= MAX_PENDING_CHALLENGES {
        let oldest = store
            .iter()
            .min_by_key(|(_, e)| e.expires_at)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                store.remove(&k);
            }
            None => break,
        }
    }

    store.insert(b64.clone(), entry);
    Ok(b64)
}

/// Consumed challenge metadata.
pub struct ConsumedChallenge {
    pub browser_session_id: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub app: Option<String>,
    pub extends_user: bool,
}

/// Consume a challenge — returns the stored metadata if valid.
///
/// The challenge is removed from the store (one-time use).
pub fn consume_challenge(
    challenge_b64: &str,
    now: u64,
    expected_ceremony: Ceremony,
) -> Result<ConsumedChallenge, String> {
    let mut guard = CHALLENGE_STORE.lock().map_err(|_| "challenge store lock poisoned")?;
    let store = guard.as_mut().ok_or("challenge store not initialised")?;

    let entry = store
        .remove(challenge_b64)
        .ok_or("unknown or already-consumed challenge")?;

    if now > entry.expires_at {
        return Err("challenge expired".into());
    }

    if entry.ceremony != expected_ceremony {
        return Err("challenge ceremony type mismatch".into());
    }

    Ok(ConsumedChallenge {
        browser_session_id: entry.browser_session_id,
        user_handle: entry.user_handle,
        user_name: entry.user_name,
        app: entry.app,
        extends_user: entry.extends_user,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(now: u64, sid: &str) -> Result<String, String> {
        create_challenge(
            now,
            PendingCeremony {
                browser_session_id: Some(sid.to_string()),
                ceremony: Ceremony::Authentication,
                user_handle: None,
                user_name: None,
                app: None,
                extends_user: false,
            },
        )
    }

    /// One test: the store is a global, and tests run in parallel.
    #[test]
    fn a_full_store_evicts_the_oldest_and_fields_are_bounded() {
        init();
        let first = begin(1_000, "first").unwrap();
        for _ in 1..MAX_PENDING_CHALLENGES {
            begin(1_001, "flood").unwrap();
        }
        // Full and nothing expired: one more begin still succeeds, and only
        // the oldest pending challenge is gone.
        let late = begin(1_002, "late").unwrap();
        assert!(consume_challenge(&first, 1_002, Ceremony::Authentication).is_err());
        assert!(consume_challenge(&late, 1_002, Ceremony::Authentication).is_ok());

        let long = "x".repeat(MAX_FIELD_LEN + 1);
        assert!(begin(1_002, &long).is_err());
        assert!(begin(1_002, &"x".repeat(MAX_FIELD_LEN)).is_ok());
    }
}
