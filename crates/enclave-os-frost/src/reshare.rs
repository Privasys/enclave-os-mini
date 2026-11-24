// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Resharing a threshold key: the SAME group key, fresh shares, held by a
//! new set of vaults (possibly the same ones, possibly another constellation)
//! under a threshold that may change.
//!
//! The construction is the classic one for Shamir-based keys, on FROST's own
//! primitives:
//!
//! 1. Each of a set `H` of at least `t` OLD participants (the helpers) takes
//!    its share `s_i`, weights it by its Lagrange coefficient `λ_i` over `H`
//!    (so `Σ λ_i s_i` is the group secret), and deals `λ_i s_i` to the NEW
//!    participants with a fresh Feldman VSS of the new threshold
//!    ([`deal`]). Each new participant's piece is sealed for it alone, under
//!    the X25519 key it bound into its attestation quote.
//! 2. Each new participant ([`ReshareStore`]) checks every helper's
//!    commitment: its constant term must be `λ_i · Y_i`, with `Y_i` the
//!    helper's PUBLIC verifying share from the old key. Only the holder of
//!    `s_i` can then hand out pieces consistent with it, so a client relaying
//!    the messages cannot slip in a polynomial of its own. It checks its
//!    piece against the commitment, sums the pieces into its new share, sums
//!    the commitments into the new public key package, and checks the group
//!    key did not change.
//! 3. As in the DKG, the new participants confirm to each other the same
//!    transcript and key before any of them stores its share.
//!
//! Renewing a key in place is the same operation with the old vaults as the
//! new ones: every share changes, the group key does not. The helpers keep
//! no state: dealing is one call.

use super::*;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use frost::keys::{IdentifierList, SigningShare, VerifyingShare};

fn scalar_of(index: u16) -> Scalar {
    Scalar::from(u64::from(index))
}

/// Lagrange coefficient at 0 of participant `i` over the set `set`.
pub(crate) fn lagrange(i: u16, set: &[u16]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &m in set {
        if m != i {
            num *= scalar_of(m);
            den *= scalar_of(m) - scalar_of(i);
        }
    }
    num * den.invert()
}

fn point(bytes: &[u8], what: &str) -> Result<EdwardsPoint, String> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| format!("{what} must be 32 bytes"))?;
    CompressedEdwardsY(b)
        .decompress()
        .ok_or_else(|| format!("{what} is not a curve point"))
}

fn scalar(bytes: &[u8], what: &str) -> Result<Scalar, String> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| format!("{what} must be 32 bytes"))?;
    Option::from(Scalar::from_canonical_bytes(b)).ok_or_else(|| format!("{what} is not a scalar"))
}

/// Evaluate a commitment (points `C_0..C_{t-1}`) at participant `index`.
fn eval(commitment: &[EdwardsPoint], index: u16) -> EdwardsPoint {
    let x = scalar_of(index);
    let mut acc = EdwardsPoint::default();
    let mut pow = Scalar::ONE;
    for c in commitment {
        acc += c * pow;
        pow *= x;
    }
    acc
}

/// Check a helper set against a key: sorted, unique, within the old
/// participants, at least the old threshold.
fn check_helpers(helpers: &[u16], min_signers: u16, max_signers: u16) -> Result<(), String> {
    if helpers.windows(2).any(|w| w[0] >= w[1]) {
        return Err("helpers must be distinct participant indices in increasing order".into());
    }
    if helpers.len() < usize::from(min_signers) {
        return Err(format!("resharing needs at least {min_signers} of the old vaults, got {}", helpers.len()));
    }
    if helpers.iter().any(|h| *h == 0 || *h > max_signers) {
        return Err("a helper is not a participant of the key".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
//  Messages
// ---------------------------------------------------------------------------

/// A new participant's first message, as the client relays it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetMsg {
    /// Its X25519 public key for this session.
    pub dh_public: Vec<u8>,
    /// Its attestation quote over [`target_binding`].
    pub quote: Vec<u8>,
}

/// A helper's deal: its commitment (public, the same for every new
/// participant) and one sealed piece per new participant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deal {
    /// Serialised VSS commitment `C_0..C_{t'-1}` (one compressed point each).
    pub commitment: Vec<Vec<u8>>,
    /// Per new participant: ephemeral X25519 key (32 bytes) || AES-GCM nonce
    /// || ciphertext of the piece.
    pub sealed: BTreeMap<u16, Vec<u8>>,
}

/// What a new participant's quote attests: SHA-256 over the session, the NEW
/// key handle, the resharing context (the vault crate's digest of the old
/// key, the helpers, the new participants and threshold), its index and its
/// X25519 key.
pub fn target_binding(session: &str, handle: &str, context: &[u8; 32], index: u16, dh_public: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"privasys-frost-reshare-target-v1");
    for part in [session.as_bytes(), handle.as_bytes(), &context[..], &index.to_be_bytes(), dh_public] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

fn targets_digest(session: &str, handle: &str, context: &[u8; 32], targets: &BTreeMap<u16, TargetMsg>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"privasys-frost-reshare-targets-v1");
    for part in [session.as_bytes(), handle.as_bytes(), &context[..]] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    for (i, t) in targets {
        h.update(i.to_be_bytes());
        h.update((t.dh_public.len() as u64).to_be_bytes());
        h.update(&t.dh_public);
    }
    h.finalize().into()
}

fn commitment_digest(commitment: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"privasys-frost-reshare-commitment-v1");
    for c in commitment {
        h.update((c.len() as u64).to_be_bytes());
        h.update(c);
    }
    h.finalize().into()
}

fn deal_aad(targets: &[u8; 32], commitment: &[u8; 32], from: u16, to: u16) -> Vec<u8> {
    let mut aad = targets.to_vec();
    aad.extend_from_slice(commitment);
    aad.extend_from_slice(&from.to_be_bytes());
    aad.extend_from_slice(&to.to_be_bytes());
    aad
}

fn check_targets(
    session: &str,
    handle: &str,
    context: &[u8; 32],
    targets: &BTreeMap<u16, TargetMsg>,
    new_n: u16,
    skip: Option<u16>,
    verify_quote: QuoteCheck<'_>,
) -> Result<BTreeMap<u16, [u8; 32]>, String> {
    let expected: Vec<u16> = (1..=new_n).collect();
    if targets.keys().copied().collect::<Vec<_>>() != expected {
        return Err(format!("resharing needs the first message of each of the {new_n} new vaults"));
    }
    let mut keys = BTreeMap::new();
    for (j, t) in targets {
        let dh: [u8; 32] = t
            .dh_public
            .as_slice()
            .try_into()
            .map_err(|_| format!("new vault {j}: X25519 key must be 32 bytes"))?;
        if Some(*j) != skip {
            verify_quote(&t.quote, &target_binding(session, handle, context, *j, &t.dh_public))
                .map_err(|e| format!("new vault {j}: {e}"))?;
        }
        keys.insert(*j, dh);
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
//  Helper (an old participant)
// ---------------------------------------------------------------------------

/// Deal this vault's weighted share to the new participants. `share` is the
/// old key's share on this vault; `handle` the NEW key's handle; `helpers`
/// the old participants dealing (this one among them). Every new
/// participant's quote is checked with `verify_quote` before anything is
/// sealed for it: a piece only ever leaves for an attested vault.
#[allow(clippy::too_many_arguments)]
pub fn deal(
    share: &StoredShare,
    session: &str,
    handle: &str,
    context: &[u8; 32],
    helpers: &[u16],
    new_threshold: u16,
    new_n: u16,
    targets: &BTreeMap<u16, TargetMsg>,
    verify_quote: QuoteCheck<'_>,
) -> Result<Deal, String> {
    check_session_id(session)?;
    check_threshold(new_threshold, new_n)?;
    check_helpers(helpers, share.min_signers, share.max_signers)?;
    if !helpers.contains(&share.index) {
        return Err("this vault is not among the helpers".into());
    }
    let target_keys = check_targets(session, handle, context, targets, new_n, None, verify_quote)?;
    let tdigest = targets_digest(session, handle, context, targets);

    let kp = share.key_package()?;
    let s = Zeroizing::new(scalar(&kp.signing_share().serialize(), "signing share")?);
    let weighted = Zeroizing::new(lagrange(share.index, helpers) * *s);
    let key = frost::SigningKey::deserialize(weighted.as_bytes()).map_err(err)?;
    let (pieces, _) = frost::keys::split(&key, new_n, new_threshold, IdentifierList::Default, &mut OsRng)
        .map_err(err)?;

    let mut commitment = None;
    let mut sealed = BTreeMap::new();
    for j in 1..=new_n {
        let piece = pieces.get(&identifier(j)?).ok_or("missing piece")?;
        let c = piece.commitment().serialize().map_err(err)?;
        let cdigest = commitment_digest(&c);
        if commitment.is_none() {
            commitment = Some(c);
        }
        let eph = DhKey::generate();
        let shared = eph.shared(&target_keys[&j])?;
        let k = kdf(b"privasys-frost-reshare-enc-v1", &shared, session, share.index, j);
        let plain = Zeroizing::new(piece.signing_share().serialize());
        let mut out = eph.public().to_vec();
        out.extend_from_slice(&seal(&k, &deal_aad(&tdigest, &cdigest, share.index, j), &plain)?);
        sealed.insert(j, out);
    }
    Ok(Deal {
        commitment: commitment.ok_or("no piece")?,
        sealed,
    })
}

// ---------------------------------------------------------------------------
//  New participant
// ---------------------------------------------------------------------------

struct ReshareSession {
    handle: String,
    context: [u8; 32],
    index: u16,
    new_threshold: u16,
    new_n: u16,
    created: u64,
    dh: DhKey,
    old: PublicKeyPackage,
    helpers: Vec<u16>,
    digest: Option<[u8; 32]>,
    peers_dh: BTreeMap<u16, [u8; 32]>,
    result: Option<(StoredShare, Vec<u8>)>,
}

/// One vault's resharing sessions as a NEW participant, in memory only.
#[derive(Default)]
pub struct ReshareStore {
    sessions: BTreeMap<String, ReshareSession>,
}

/// What a new participant returns first: its X25519 key and the value its
/// quote must bind.
pub struct TargetOut {
    pub dh_public: Vec<u8>,
    pub binding: [u8; 32],
}

impl ReshareStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn session(&mut self, session_id: &str, handle: &str, now: u64) -> Result<&mut ReshareSession, String> {
        let s = live(&mut self.sessions, |s| s.created, DKG_SESSION_TTL_SECS, session_id, now)?;
        if s.handle != handle {
            return Err("resharing session is for another key".into());
        }
        Ok(s)
    }

    /// Round 1 (new participant `index` of `new_n`): take the OLD key's public
    /// key package and the helpers, draw this session's X25519 key.
    #[allow(clippy::too_many_arguments)]
    pub fn round1(
        &mut self,
        session_id: &str,
        handle: &str,
        context: &[u8; 32],
        index: u16,
        new_threshold: u16,
        new_n: u16,
        old_public_key_package: &[u8],
        helpers: &[u16],
        now: u64,
    ) -> Result<TargetOut, String> {
        check_threshold(new_threshold, new_n)?;
        if index == 0 || index > new_n {
            return Err(format!("participant index {index} is out of range 1..={new_n}"));
        }
        let old = PublicKeyPackage::deserialize(old_public_key_package).map_err(err)?;
        let old_t = old.min_signers().ok_or("the old key has no threshold")?;
        let old_n = u16::try_from(old.verifying_shares().len()).map_err(|_| "old key too large")?;
        check_helpers(helpers, old_t, old_n)?;
        for h in helpers {
            if !old.verifying_shares().contains_key(&identifier(*h)?) {
                return Err(format!("helper {h} is not a participant of the old key"));
            }
        }
        admit(&mut self.sessions, |s| s.created, DKG_SESSION_TTL_SECS, session_id, now)?;
        let dh = DhKey::generate();
        let dh_public = dh.public().to_vec();
        let binding = target_binding(session_id, handle, context, index, &dh_public);
        self.sessions.insert(
            session_id.to_string(),
            ReshareSession {
                handle: handle.to_string(),
                context: *context,
                index,
                new_threshold,
                new_n,
                created: now,
                dh,
                old,
                helpers: helpers.to_vec(),
                digest: None,
                peers_dh: BTreeMap::new(),
                result: None,
            },
        );
        Ok(TargetOut { dh_public, binding })
    }

    /// Round 2: every new participant's first message and every helper's
    /// deal (its commitment and the piece sealed for this vault). Derives the
    /// new share and returns the confirmations for the other new
    /// participants. Any failure ends the session.
    pub fn round2(
        &mut self,
        session_id: &str,
        handle: &str,
        targets: &BTreeMap<u16, TargetMsg>,
        deals: &BTreeMap<u16, (Vec<Vec<u8>>, Vec<u8>)>,
        verify_quote: QuoteCheck<'_>,
        now: u64,
    ) -> Result<Round3Out, String> {
        self.session(session_id, handle, now)?;
        let out = self.round2_inner(session_id, handle, targets, deals, verify_quote, now);
        if out.is_err() {
            self.sessions.remove(session_id);
        }
        out
    }

    fn round2_inner(
        &mut self,
        session_id: &str,
        handle: &str,
        targets: &BTreeMap<u16, TargetMsg>,
        deals: &BTreeMap<u16, (Vec<Vec<u8>>, Vec<u8>)>,
        verify_quote: QuoteCheck<'_>,
        now: u64,
    ) -> Result<Round3Out, String> {
        let s = self.session(session_id, handle, now)?;
        if s.digest.is_some() {
            return Err("resharing round 2 already ran for this session".into());
        }
        let me = s.index;
        let mine = targets.get(&me).ok_or("the targets do not carry this vault")?;
        if mine.dh_public.as_slice() != s.dh.public() {
            return Err("the targets do not carry this vault's own message".into());
        }
        let peers = check_targets(session_id, handle, &s.context, targets, s.new_n, Some(me), verify_quote)?;
        if deals.keys().copied().collect::<Vec<_>>() != s.helpers {
            return Err("resharing needs a deal from each helper, and only from them".into());
        }
        let tdigest = targets_digest(session_id, handle, &s.context, targets);
        let group = point(&s.old.verifying_key().serialize().map_err(err)?, "group key")?;

        let t = usize::from(s.new_threshold);
        let mut new_share = Zeroizing::new(Scalar::ZERO);
        let mut summed = vec![EdwardsPoint::default(); t];
        let mut transcript = Sha256::new();
        transcript.update(b"privasys-frost-reshare-transcript-v1");
        transcript.update(tdigest);
        for (i, (commitment, sealed)) in deals {
            if commitment.len() != t {
                return Err(format!("helper {i}: commitment has {} terms, the threshold is {t}", commitment.len()));
            }
            let c: Vec<EdwardsPoint> = commitment
                .iter()
                .map(|b| point(b, "commitment"))
                .collect::<Result<_, _>>()?;
            // Only the holder of s_i can deal pieces consistent with this.
            let yi = s
                .old
                .verifying_shares()
                .get(&identifier(*i)?)
                .ok_or_else(|| format!("helper {i} is not a participant of the old key"))?;
            let yi = point(&yi.serialize().map_err(err)?, "verifying share")?;
            if c[0] != yi * lagrange(*i, &s.helpers) {
                return Err(format!("helper {i}: its deal is not of its share of this key"));
            }
            if sealed.len() < 32 {
                return Err(format!("helper {i}: sealed piece too short"));
            }
            let eph: [u8; 32] = sealed[..32].try_into().map_err(|_| "ephemeral key")?;
            let shared = s.dh.shared(&eph)?;
            let k = kdf(b"privasys-frost-reshare-enc-v1", &shared, session_id, *i, me);
            let plain = open(&k, &deal_aad(&tdigest, &commitment_digest(commitment), *i, me), &sealed[32..])
                .map_err(|e| format!("helper {i}: {e}"))?;
            let piece = Zeroizing::new(scalar(&plain, "piece")?);
            if EdwardsPoint::mul_base(&piece) != eval(&c, me) {
                return Err(format!("helper {i}: the piece does not match its commitment"));
            }
            *new_share += *piece;
            for (acc, ci) in summed.iter_mut().zip(&c) {
                *acc += ci;
            }
            transcript.update(i.to_be_bytes());
            transcript.update(commitment_digest(commitment));
        }
        if summed[0] != group {
            return Err("the deals do not add up to this key".into());
        }

        // The new key: same group key, new verifying shares.
        let mut shares = BTreeMap::new();
        for k in 1..=s.new_n {
            let v = eval(&summed, k).compress().to_bytes();
            shares.insert(identifier(k)?, VerifyingShare::deserialize(&v).map_err(err)?);
        }
        let my_vs = eval(&summed, me);
        if EdwardsPoint::mul_base(&new_share) != my_vs {
            return Err("the new share does not match the new verifying share".into());
        }
        let vk = s.old.verifying_key().to_owned();
        let pkp = PublicKeyPackage::new(shares, vk, Some(s.new_threshold));
        let kp = KeyPackage::new(
            identifier(me)?,
            SigningShare::deserialize(new_share.as_bytes()).map_err(err)?,
            VerifyingShare::deserialize(&my_vs.compress().to_bytes()).map_err(err)?,
            vk,
            s.new_threshold,
        );
        let stored = StoredShare {
            index: me,
            min_signers: s.new_threshold,
            max_signers: s.new_n,
            key_package: kp.serialize().map_err(err)?,
            public_key_package: pkp.serialize().map_err(err)?,
        };
        let group_bytes = stored.group_public_key()?;
        transcript.update(&group_bytes);
        let digest: [u8; 32] = transcript.finalize().into();

        let mut confirmations = BTreeMap::new();
        for (to, dh) in &peers {
            if *to == me {
                continue;
            }
            let shared = s.dh.shared(dh)?;
            let key = confirm_key(&shared, session_id, me, *to);
            let tag = hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA256, &key[..]),
                &confirm_message(&digest, &group_bytes, me, *to),
            );
            confirmations.insert(*to, tag.as_ref().to_vec());
        }
        peers.into_iter().filter(|(j, _)| *j != me).for_each(|(j, k)| {
            s.peers_dh.insert(j, k);
        });
        s.digest = Some(digest);
        s.result = Some((stored, group_bytes.clone()));
        Ok(Round3Out { group_public_key: group_bytes, confirmations })
    }

    /// Commit: store only once every other new participant confirmed the
    /// same transcript and key. Ends the session either way.
    pub fn commit(
        &mut self,
        session_id: &str,
        handle: &str,
        confirmations_for_me: &BTreeMap<u16, Vec<u8>>,
        now: u64,
    ) -> Result<StoredShare, String> {
        self.session(session_id, handle, now)?;
        let s = self.sessions.remove(session_id).ok_or("unknown or expired threshold session")?;
        let digest = s.digest.ok_or("resharing round 2 has not run on this vault")?;
        let (share, group) = s.result.as_ref().ok_or("resharing round 2 has not run on this vault")?;
        let expected: Vec<u16> = (1..=s.new_n).filter(|i| *i != s.index).collect();
        if confirmations_for_me.keys().copied().collect::<Vec<_>>() != expected {
            return Err(format!(
                "commit needs a confirmation from each of the other {} new vaults",
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
            .map_err(|_| format!("new vault {from} did not confirm the same transcript and key: nothing is stored"))?;
        }
        Ok(share.clone())
    }

    /// Drop a session.
    pub fn abort(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

/// The 32-byte group key of a serialised public key package.
pub fn group_key_of(public_key_package: &[u8]) -> Result<Vec<u8>, String> {
    PublicKeyPackage::deserialize(public_key_package)
        .map_err(err)?
        .verifying_key()
        .serialize()
        .map_err(err)
}
