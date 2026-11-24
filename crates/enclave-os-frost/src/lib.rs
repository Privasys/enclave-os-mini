// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Threshold Ed25519 for the Enclave Vault: FROST(Ed25519, SHA-512), RFC 9591.
//!
//! A threshold key is never whole anywhere. The vaults of a constellation
//! create it together by distributed key generation (Pedersen DKG with proofs
//! of knowledge), each keeps one share sealed, and any `t` of them sign
//! together in two rounds.
//!
//! The CLIENT orchestrates, as it does for Shamir secrets: it calls each vault
//! directly, with its own credentials, and relays opaque messages between
//! them. The vaults never call each other. This crate holds one vault's
//! protocol state; it is pure (no I/O), so it is tested on the host.
//!
//! # What the client relays, and why it learns nothing
//!
//! * **DKG round 1** packages are public. Each vault also draws an X25519 key
//!   for the session and binds `(session, handle, index, package, x25519 key)`
//!   into an attestation quote ([`round1_binding`]). A vault checks every other
//!   vault's quote (the vault crate passes the check in) before it uses that
//!   vault's package or key, so the client can neither forge a package nor
//!   slip in an X25519 key of its own.
//! * **DKG round 2** packages are secret. Each is encrypted (AES-256-GCM) for
//!   its recipient under a key from the X25519 exchange of the two vaults, with
//!   the digest of the round 1 transcript as associated data. The client
//!   carries ciphertexts it cannot open; a vault that was shown a different
//!   round 1 set than the sender cannot open them either.
//! * **Confirmation.** After deriving its share, each vault MACs the transcript
//!   digest and the group key for every other vault (HMAC-SHA-256 under the
//!   pairwise key). A vault stores its share only once every other vault has
//!   confirmed the same transcript and group key ([`DkgStore::commit`]).
//! * **Signing** commitments and signature shares are public by design; a
//!   client that tampers with them only makes the signature fail to aggregate.
//!
//! # Nonces
//!
//! Signing nonces are the dangerous part: one nonce used with two challenges
//! gives away the share. Here they
//! * exist only in a [`SignStore`] in enclave memory: never serialised, never
//!   sealed, so a restart or a rollback of sealed state cannot bring one back;
//! * are taken out of the store before the signature share is computed, so a
//!   session yields one share at most, and are zeroised when dropped;
//! * are bound to the session id, the key handle and the message: round 2
//!   builds the signing package from the message round 1 stored, and refuses
//!   commitments that do not carry this vault's own;
//! * expire after [`SESSION_TTL_SECS`].

use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;

use curve25519_dalek::montgomery::MontgomeryPoint;
use frost_ed25519 as frost;
use frost::keys::dkg;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::{Identifier, SigningPackage};
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// How long a signing session lives, in seconds.
pub const SESSION_TTL_SECS: u64 = 60;

/// How long a DKG session lives, in seconds: the client makes four rounds of
/// calls to every vault, each with attestation checks.
pub const DKG_SESSION_TTL_SECS: u64 = 300;

/// Most sessions of one kind a vault holds at once.
pub const MAX_SESSIONS: usize = 256;

/// Most participants of one key.
pub const MAX_PARTICIPANTS: u16 = 16;

/// Longest message a threshold key signs. Ed25519 signs the message itself
/// (no pre-hash), and round 1 keeps it until round 2.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024;

/// Algorithm name of the signatures (JOSE `alg`).
pub const ALG: &str = "EdDSA";

fn err(e: impl core::fmt::Display) -> String {
    e.to_string()
}

/// The FROST identifier of participant `index` (1-based).
pub fn identifier(index: u16) -> Result<Identifier, String> {
    if index == 0 || index > MAX_PARTICIPANTS {
        return Err(format!("participant index {index} is out of range 1..={MAX_PARTICIPANTS}"));
    }
    Identifier::try_from(index).map_err(err)
}

/// Check a (threshold, participants) pair: 2 <= t <= n <= MAX_PARTICIPANTS.
pub fn check_threshold(min_signers: u16, max_signers: u16) -> Result<(), String> {
    if !(2..=MAX_PARTICIPANTS).contains(&max_signers) {
        return Err(format!("a threshold key needs 2..={MAX_PARTICIPANTS} vaults, got {max_signers}"));
    }
    if min_signers < 2 || min_signers > max_signers {
        return Err(format!("threshold must be 2..={max_signers}, got {min_signers}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
//  The share a vault keeps
// ---------------------------------------------------------------------------

/// One vault's part of a threshold key: the material sealed in its key record.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredShare {
    /// This vault's participant index (1-based).
    pub index: u16,
    pub min_signers: u16,
    pub max_signers: u16,
    /// Serialised FROST `KeyPackage`: holds the secret signing share.
    pub key_package: Vec<u8>,
    /// Serialised FROST `PublicKeyPackage`: every participant's verifying
    /// share and the group key. Public.
    pub public_key_package: Vec<u8>,
}

impl StoredShare {
    /// The sealed form (JSON), zeroised when dropped.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        serde_json::to_vec(self).map(Zeroizing::new).map_err(err)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let s: StoredShare = serde_json::from_slice(bytes).map_err(|e| format!("threshold share: {e}"))?;
        check_threshold(s.min_signers, s.max_signers)?;
        if s.index == 0 || s.index > s.max_signers {
            return Err(format!("threshold share index {} is out of range", s.index));
        }
        Ok(s)
    }

    fn key_package(&self) -> Result<KeyPackage, String> {
        KeyPackage::deserialize(&self.key_package).map_err(err)
    }

    fn public_key_package(&self) -> Result<PublicKeyPackage, String> {
        PublicKeyPackage::deserialize(&self.public_key_package).map_err(err)
    }

    /// The group public key: a plain 32-byte Ed25519 public key.
    pub fn group_public_key(&self) -> Result<Vec<u8>, String> {
        self.public_key_package()?.verifying_key().serialize().map_err(err)
    }
}

impl Drop for StoredShare {
    fn drop(&mut self) {
        self.key_package.zeroize();
    }
}

// ---------------------------------------------------------------------------
//  Sessions
// ---------------------------------------------------------------------------

/// Check a session id: 16..=64 characters of [A-Za-z0-9_-].
pub fn check_session_id(id: &str) -> Result<(), String> {
    let ok = (16..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err("session id must be 16..=64 characters of [A-Za-z0-9_-]".into())
    }
}

/// A fresh random session id (32 hex characters).
pub fn new_session_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn admit<V>(map: &mut BTreeMap<String, V>, created: impl Fn(&V) -> u64, ttl: u64, id: &str, now: u64) -> Result<(), String> {
    check_session_id(id)?;
    map.retain(|_, v| now < created(v).saturating_add(ttl));
    if map.contains_key(id) {
        return Err("session id already in use".into());
    }
    if map.len() >= MAX_SESSIONS {
        return Err("too many threshold sessions in progress; retry shortly".into());
    }
    Ok(())
}

fn live<'a, V>(map: &'a mut BTreeMap<String, V>, created: impl Fn(&V) -> u64, ttl: u64, id: &str, now: u64) -> Result<&'a mut V, String> {
    map.retain(|_, v| now < created(v).saturating_add(ttl));
    map.get_mut(id).ok_or_else(|| "unknown or expired threshold session".to_string())
}

// ---------------------------------------------------------------------------
//  DKG: the pairwise channel between two vaults
// ---------------------------------------------------------------------------

/// A vault's X25519 key for one DKG session (clamped scalar).
struct DhKey(Zeroizing<[u8; 32]>);

impl DhKey {
    fn generate() -> Self {
        let mut sk = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut sk[..]);
        DhKey(sk)
    }

    fn public(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(*self.0).to_bytes()
    }

    /// The X25519 shared secret with `peer`; refused if it is all zero (a
    /// low-order point).
    fn shared(&self, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
        let s = Zeroizing::new(MontgomeryPoint(*peer).mul_clamped(*self.0).to_bytes());
        if s.iter().all(|b| *b == 0) {
            return Err("X25519 key of the other vault is a low-order point".into());
        }
        Ok(s)
    }
}

fn kdf(label: &[u8], shared: &[u8; 32], session: &str, a: u16, b: u16) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(label);
    h.update(shared);
    h.update((session.len() as u64).to_be_bytes());
    h.update(session.as_bytes());
    h.update(a.to_be_bytes());
    h.update(b.to_be_bytes());
    Zeroizing::new(h.finalize().into())
}

/// Encryption key for round 2 packages from `from` to `to` (one per direction).
fn enc_key(shared: &[u8; 32], session: &str, from: u16, to: u16) -> Zeroizing<[u8; 32]> {
    kdf(b"privasys-frost-dkg-enc-v1", shared, session, from, to)
}

/// Confirmation (MAC) key for the pair, the same in both directions.
fn confirm_key(shared: &[u8; 32], session: &str, a: u16, b: u16) -> Zeroizing<[u8; 32]> {
    kdf(b"privasys-frost-dkg-confirm-v1", shared, session, a.min(b), a.max(b))
}

fn pair_aad(digest: &[u8; 32], from: u16, to: u16) -> Vec<u8> {
    let mut aad = digest.to_vec();
    aad.extend_from_slice(&from.to_be_bytes());
    aad.extend_from_slice(&to.to_be_bytes());
    aad
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| "aead key")?);
    let mut buf = plaintext.to_vec();
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
        .map_err(|_| "aead seal failed")?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err("round 2 package is too short".into());
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| "aead key")?);
    let mut buf = Zeroizing::new(sealed[NONCE_LEN..].to_vec());
    let n = k
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
        .map_err(|_| "round 2 package does not open: another round 1 set, or not meant for this vault")?
        .len();
    buf.truncate(n);
    Ok(buf)
}

fn confirm_message(digest: &[u8; 32], group_key: &[u8], from: u16, to: u16) -> Vec<u8> {
    let mut msg = b"privasys-frost-dkg-confirmation-v1".to_vec();
    msg.extend_from_slice(digest);
    msg.extend_from_slice(&(group_key.len() as u64).to_be_bytes());
    msg.extend_from_slice(group_key);
    msg.extend_from_slice(&from.to_be_bytes());
    msg.extend_from_slice(&to.to_be_bytes());
    msg
}

// ---------------------------------------------------------------------------
//  DKG: one vault's side
// ---------------------------------------------------------------------------

/// Checks an attestation quote against the value it must bind: supplied by
/// the vault crate (attestation servers, MRENCLAVE, report data).
pub type QuoteCheck<'a> = &'a dyn Fn(&[u8], &[u8; 32]) -> Result<(), String>;

/// A vault's round 1 message as the client relays it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Round1Msg {
    /// Serialised FROST round 1 package (commitments + proof of knowledge).
    pub package: Vec<u8>,
    /// The vault's X25519 public key for this session.
    pub dh_public: Vec<u8>,
    /// The vault's attestation quote over [`round1_binding`].
    pub quote: Vec<u8>,
}

/// What a vault's round 1 quote attests: SHA-256 over the session, the key
/// handle, the DKG context (the vault crate's digest of the participant list
/// and the threshold), the participant index, the round 1 package and the
/// X25519 key. A vault checks the other vaults' quotes against ITS context,
/// so every participant must have been given the same list and threshold.
pub fn round1_binding(
    session: &str,
    handle: &str,
    context: &[u8; 32],
    index: u16,
    package: &[u8],
    dh_public: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"privasys-frost-dkg-round1-v2");
    for part in [session.as_bytes(), handle.as_bytes(), &context[..], &index.to_be_bytes(), package, dh_public] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// The digest of a whole round 1 transcript (every participant's package and
/// X25519 key, in index order).
fn transcript_digest(session: &str, handle: &str, context: &[u8; 32], round1: &BTreeMap<u16, Round1Msg>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"privasys-frost-dkg-transcript-v2");
    h.update(context);
    h.update((session.len() as u64).to_be_bytes());
    h.update(session.as_bytes());
    h.update((handle.len() as u64).to_be_bytes());
    h.update(handle.as_bytes());
    for (i, m) in round1 {
        h.update(i.to_be_bytes());
        for part in [&m.package, &m.dh_public] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
    }
    h.finalize().into()
}

/// What round 1 gives the vault to return: its package, its X25519 key, and
/// the value its quote must bind.
pub struct Round1Out {
    pub package: Vec<u8>,
    pub dh_public: Vec<u8>,
    pub binding: [u8; 32],
}

/// What round 3 gives the vault to return.
pub struct Round3Out {
    /// The 32-byte Ed25519 group public key.
    pub group_public_key: Vec<u8>,
    /// For each other participant, this vault's confirmation for it.
    pub confirmations: BTreeMap<u16, Vec<u8>>,
}

struct DkgSession {
    handle: String,
    context: [u8; 32],
    index: u16,
    min_signers: u16,
    max_signers: u16,
    created: u64,
    dh: DhKey,
    own_package: Vec<u8>,
    round1_secret: Option<dkg::round1::SecretPackage>,
    /// Fixed by round 2.
    digest: Option<[u8; 32]>,
    round1: BTreeMap<Identifier, dkg::round1::Package>,
    peers_dh: BTreeMap<u16, [u8; 32]>,
    round2_secret: Option<dkg::round2::SecretPackage>,
    /// Set by round 3.
    result: Option<(StoredShare, Vec<u8>)>,
}

/// One vault's DKG sessions, in enclave memory only.
#[derive(Default)]
pub struct DkgStore {
    sessions: BTreeMap<String, DkgSession>,
}

impl DkgStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn session(&mut self, session_id: &str, handle: &str, now: u64) -> Result<&mut DkgSession, String> {
        let s = live(&mut self.sessions, |s| s.created, DKG_SESSION_TTL_SECS, session_id, now)?;
        if s.handle != handle {
            return Err("DKG session is for another key".into());
        }
        Ok(s)
    }

    #[allow(clippy::too_many_arguments)]
    /// Round 1: draw this vault's polynomial and X25519 key. The vault returns
    /// the package and key with a quote over `binding`.
    pub fn round1(
        &mut self,
        session_id: &str,
        handle: &str,
        context: &[u8; 32],
        index: u16,
        min_signers: u16,
        max_signers: u16,
        now: u64,
    ) -> Result<Round1Out, String> {
        check_threshold(min_signers, max_signers)?;
        if index == 0 || index > max_signers {
            return Err(format!("participant index {index} is out of range 1..={max_signers}"));
        }
        admit(&mut self.sessions, |s| s.created, DKG_SESSION_TTL_SECS, session_id, now)?;
        let (secret, package) = dkg::part1(identifier(index)?, max_signers, min_signers, OsRng).map_err(err)?;
        let package = package.serialize().map_err(err)?;
        let dh = DhKey::generate();
        let dh_public = dh.public().to_vec();
        let binding = round1_binding(session_id, handle, context, index, &package, &dh_public);
        self.sessions.insert(
            session_id.to_string(),
            DkgSession {
                handle: handle.to_string(),
                context: *context,
                index,
                min_signers,
                max_signers,
                created: now,
                dh,
                own_package: package.clone(),
                round1_secret: Some(secret),
                digest: None,
                round1: BTreeMap::new(),
                peers_dh: BTreeMap::new(),
                round2_secret: None,
                result: None,
            },
        );
        Ok(Round1Out { package, dh_public, binding })
    }

    /// Round 2: take every participant's round 1 message, check each other
    /// vault's quote with `verify_quote(quote, binding)`, and return this
    /// vault's secret round 2 package for each other participant, encrypted
    /// for it.
    /// Any failure ends the session: a DKG is never retried.
    pub fn round2(
        &mut self,
        session_id: &str,
        handle: &str,
        round1: &BTreeMap<u16, Round1Msg>,
        verify_quote: QuoteCheck<'_>,
        now: u64,
    ) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        self.session(session_id, handle, now)?;
        let out = self.round2_inner(session_id, handle, round1, verify_quote, now);
        if out.is_err() {
            self.sessions.remove(session_id);
        }
        out
    }

    fn round2_inner(
        &mut self,
        session_id: &str,
        handle: &str,
        round1: &BTreeMap<u16, Round1Msg>,
        verify_quote: QuoteCheck<'_>,
        now: u64,
    ) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let s = self.session(session_id, handle, now)?;
        if s.digest.is_some() {
            return Err("DKG round 2 already ran for this session".into());
        }
        let expected: Vec<u16> = (1..=s.max_signers).collect();
        if round1.keys().copied().collect::<Vec<_>>() != expected {
            return Err(format!("round 2 needs the round 1 message of each of the {} participants", s.max_signers));
        }
        let mine = &round1[&s.index];
        if mine.package != s.own_package || mine.dh_public.as_slice() != s.dh.public() {
            return Err("the round 1 set does not carry this vault's own message".into());
        }
        let mut others = BTreeMap::new();
        let mut peers_dh = BTreeMap::new();
        for (i, m) in round1 {
            if *i == s.index {
                continue;
            }
            let binding = round1_binding(session_id, handle, &s.context, *i, &m.package, &m.dh_public);
            verify_quote(&m.quote, &binding).map_err(|e| format!("participant {i}: {e}"))?;
            let dh: [u8; 32] = m
                .dh_public
                .as_slice()
                .try_into()
                .map_err(|_| format!("participant {i}: X25519 key must be 32 bytes"))?;
            others.insert(identifier(*i)?, dkg::round1::Package::deserialize(&m.package).map_err(err)?);
            peers_dh.insert(*i, dh);
        }
        let digest = transcript_digest(session_id, handle, &s.context, round1);
        let secret = s.round1_secret.take().ok_or("DKG round 1 secret already used")?;
        let (r2_secret, out) = dkg::part2(secret, &others).map_err(err)?;
        let mut sealed = BTreeMap::new();
        for (to, dh) in &peers_dh {
            let pkg = Zeroizing::new(
                out.get(&identifier(*to)?)
                    .ok_or("missing round 2 package")?
                    .serialize()
                    .map_err(err)?,
            );
            let shared = s.dh.shared(dh)?;
            let key = enc_key(&shared, session_id, s.index, *to);
            sealed.insert(*to, seal(&key, &pair_aad(&digest, s.index, *to), &pkg)?);
        }
        s.round2_secret = Some(r2_secret);
        s.round1 = others;
        s.peers_dh = peers_dh;
        s.digest = Some(digest);
        Ok(sealed)
    }

    /// Round 3: open the round 2 packages sent to this vault, derive its
    /// share, and return the group key and a confirmation for each other
    /// participant. The share is held until [`DkgStore::commit`].
    /// Any failure ends the session.
    pub fn round3(
        &mut self,
        session_id: &str,
        handle: &str,
        for_me: &BTreeMap<u16, Vec<u8>>,
        now: u64,
    ) -> Result<Round3Out, String> {
        self.session(session_id, handle, now)?;
        let out = self.round3_inner(session_id, handle, for_me, now);
        if out.is_err() {
            self.sessions.remove(session_id);
        }
        out
    }

    fn round3_inner(
        &mut self,
        session_id: &str,
        handle: &str,
        for_me: &BTreeMap<u16, Vec<u8>>,
        now: u64,
    ) -> Result<Round3Out, String> {
        let s = self.session(session_id, handle, now)?;
        let digest = s.digest.ok_or("DKG round 2 has not run on this vault")?;
        if s.result.is_some() {
            return Err("DKG round 3 already ran for this session".into());
        }
        let expected: Vec<u16> = (1..=s.max_signers).filter(|i| *i != s.index).collect();
        if for_me.keys().copied().collect::<Vec<_>>() != expected {
            return Err(format!(
                "round 3 needs a round 2 package from each of the other {} participants",
                expected.len()
            ));
        }
        let mut received = BTreeMap::new();
        for (from, sealed) in for_me {
            let shared = s.dh.shared(&s.peers_dh[from])?;
            let key = enc_key(&shared, session_id, *from, s.index);
            let plain = open(&key, &pair_aad(&digest, *from, s.index), sealed)
                .map_err(|e| format!("participant {from}: {e}"))?;
            received.insert(identifier(*from)?, dkg::round2::Package::deserialize(&plain).map_err(err)?);
        }
        let secret = s.round2_secret.as_ref().ok_or("DKG round 2 has not run on this vault")?;
        let (kp, pkp) = dkg::part3(secret, &s.round1, &received).map_err(err)?;
        let share = StoredShare {
            index: s.index,
            min_signers: s.min_signers,
            max_signers: s.max_signers,
            key_package: kp.serialize().map_err(err)?,
            public_key_package: pkp.serialize().map_err(err)?,
        };
        let group = share.group_public_key()?;
        let mut confirmations = BTreeMap::new();
        for (to, dh) in &s.peers_dh {
            let shared = s.dh.shared(dh)?;
            let key = confirm_key(&shared, session_id, s.index, *to);
            let tag = hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA256, &key[..]),
                &confirm_message(&digest, &group, s.index, *to),
            );
            confirmations.insert(*to, tag.as_ref().to_vec());
        }
        s.result = Some((share, group.clone()));
        Ok(Round3Out { group_public_key: group, confirmations })
    }

    /// Commit: check that every other participant confirmed the same round 1
    /// transcript and group key as this vault, then hand back the share to
    /// store. Ends the session either way.
    pub fn commit(
        &mut self,
        session_id: &str,
        handle: &str,
        confirmations_for_me: &BTreeMap<u16, Vec<u8>>,
        now: u64,
    ) -> Result<StoredShare, String> {
        self.session(session_id, handle, now)?;
        let s = self.sessions.remove(session_id).ok_or("unknown or expired threshold session")?;
        let digest = s.digest.ok_or("DKG round 2 has not run on this vault")?;
        let (share, group) = s.result.as_ref().ok_or("DKG round 3 has not run on this vault")?;
        let expected: Vec<u16> = (1..=s.max_signers).filter(|i| *i != s.index).collect();
        if confirmations_for_me.keys().copied().collect::<Vec<_>>() != expected {
            return Err(format!(
                "commit needs a confirmation from each of the other {} participants",
                expected.len()
            ));
        }
        for (from, tag) in confirmations_for_me {
            let shared = s.dh.shared(&s.peers_dh[from])?;
            let key = confirm_key(&shared, session_id, *from, s.index);
            hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, &key[..]),
                &confirm_message(&digest, group, *from, s.index),
                tag,
            )
            .map_err(|_| {
                format!("participant {from} did not confirm the same transcript and group key: the key is not stored")
            })?;
        }
        Ok(share.clone())
    }

    /// Drop a session (an abandoned DKG).
    pub fn abort(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

// ---------------------------------------------------------------------------
//  Signing: one vault's side
// ---------------------------------------------------------------------------

struct SignSession {
    handle: String,
    message: Vec<u8>,
    nonces: SigningNonces,
    commitments: SigningCommitments,
    created: u64,
}

fn signing_package(commitments: &BTreeMap<u16, Vec<u8>>, message: &[u8]) -> Result<SigningPackage, String> {
    let mut map = BTreeMap::new();
    for (i, c) in commitments {
        map.insert(identifier(*i)?, SigningCommitments::deserialize(c).map_err(err)?);
    }
    Ok(SigningPackage::new(map, message))
}

/// One vault's signing sessions, in enclave memory only.
#[derive(Default)]
pub struct SignStore {
    sessions: BTreeMap<String, SignSession>,
}

impl SignStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Round 1: draw fresh nonces for (session, key, message), keep the
    /// message, and return the public commitments.
    pub fn commit(
        &mut self,
        session_id: &str,
        handle: &str,
        share: &StoredShare,
        message: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(format!("message is longer than {MAX_MESSAGE_LEN} bytes"));
        }
        admit(&mut self.sessions, |s| s.created, SESSION_TTL_SECS, session_id, now)?;
        let kp = share.key_package()?;
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut OsRng);
        let out = commitments.serialize().map_err(err)?;
        self.sessions.insert(
            session_id.to_string(),
            SignSession {
                handle: handle.to_string(),
                message: message.to_vec(),
                nonces,
                commitments,
                created: now,
            },
        );
        Ok(out)
    }

    /// Round 2: this vault's signature share, given every signer's round 1
    /// commitments (by participant index). The signing package is built here
    /// from the message round 1 kept. The nonces leave the store before
    /// anything is checked: whatever the outcome, this session never signs
    /// again.
    pub fn sign(
        &mut self,
        session_id: &str,
        handle: &str,
        share: &StoredShare,
        commitments: &BTreeMap<u16, Vec<u8>>,
        now: u64,
    ) -> Result<Vec<u8>, String> {
        live(&mut self.sessions, |s| s.created, SESSION_TTL_SECS, session_id, now)?;
        let s = self.sessions.remove(session_id).ok_or("unknown or expired threshold session")?;
        if s.handle != handle {
            return Err("signing session is for another key".into());
        }
        let n = commitments.len();
        if n < usize::from(share.min_signers) || n > usize::from(share.max_signers) {
            return Err(format!(
                "{n} signers, the threshold is {} of {}",
                share.min_signers, share.max_signers
            ));
        }
        let package = signing_package(commitments, &s.message)?;
        let me = identifier(share.index)?;
        if package.signing_commitments().get(&me) != Some(&s.commitments) {
            return Err("the commitments do not carry this vault's round 1 commitment".into());
        }
        let kp = share.key_package()?;
        let sig_share = frost::round2::sign(&package, &s.nonces, &kp).map_err(err)?;
        Ok(sig_share.serialize())
        // `s` (and its nonces, ZeroizeOnDrop) is dropped here.
    }

    /// Drop a session (an abandoned signature).
    pub fn abort(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    /// Sessions currently held (for tests and metrics).
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Aggregate the signers' shares into one Ed25519 signature (64 bytes) and
/// verify it under the group key. Public data only: any participant can do
/// it for the client.
pub fn aggregate(
    message: &[u8],
    commitments: &BTreeMap<u16, Vec<u8>>,
    shares: &BTreeMap<u16, Vec<u8>>,
    share: &StoredShare,
) -> Result<Vec<u8>, String> {
    if commitments.keys().ne(shares.keys()) {
        return Err("a signature share is needed from each signer, and only from them".into());
    }
    let package = signing_package(commitments, message)?;
    let mut map = BTreeMap::new();
    for (i, s) in shares {
        map.insert(identifier(*i)?, frost::round2::SignatureShare::deserialize(s).map_err(err)?);
    }
    let pkp = share.public_key_package()?;
    let sig = frost::aggregate(&package, &map, &pkp).map_err(|e| format!("aggregate: {e}"))?;
    pkp.verifying_key()
        .verify(message, &sig)
        .map_err(|e| format!("aggregate signature does not verify: {e}"))?;
    sig.serialize().map_err(err)
}

/// Verify an Ed25519 signature under a 32-byte public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let vk = frost::VerifyingKey::deserialize(public_key).map_err(err)?;
    let sig = frost::Signature::deserialize(signature).map_err(err)?;
    vk.verify(message, &sig).map_err(err)
}

pub mod reshare;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reshare_tests;
