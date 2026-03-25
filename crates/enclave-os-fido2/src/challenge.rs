// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-memory challenge store with TTL and bounded capacity.
//!
//! Challenges are ephemeral — they survive only in enclave memory.
//! After an enclave restart, all pending challenges are lost (users
//! must re-initiate the ceremony).

use std::collections::HashMap;
use std::sync::Mutex;

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
    browser_session_id: Option<String>,
    ceremony: Ceremony,
    user_handle: Option<String>,
    user_name: Option<String>,
) -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; CHALLENGE_BYTES];
    rng.fill(&mut bytes).map_err(|_| "RNG failure")?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let entry = ChallengeEntry {
        challenge: bytes.to_vec(),
        expires_at: now + CHALLENGE_TTL_SECS,
        browser_session_id,
        ceremony,
        user_handle,
        user_name,
    };

    let mut guard = CHALLENGE_STORE.lock().map_err(|_| "challenge store lock poisoned")?;
    let store = guard.as_mut().ok_or("challenge store not initialised")?;

    // Evict expired entries if at capacity
    if store.len() >= MAX_PENDING_CHALLENGES {
        store.retain(|_, e| e.expires_at > now);
    }

    // If still at capacity after eviction, reject
    if store.len() >= MAX_PENDING_CHALLENGES {
        return Err("too many pending challenges".into());
    }

    store.insert(b64.clone(), entry);
    Ok(b64)
}

/// Consumed challenge metadata.
pub struct ConsumedChallenge {
    pub browser_session_id: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
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
    })
}
