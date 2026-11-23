// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The vaults as the client drives them. A "quote" here is the binding
//! itself, checked by equality: the vault crate verifies real quotes.

use super::*;

const H: &str = "users/sub/k";
const NOW: u64 = 1_800_000_000;
const CTX: [u8; 32] = [7u8; 32];

fn fake_verify(quote: &[u8], binding: &[u8; 32]) -> Result<(), String> {
    if quote == binding {
        Ok(())
    } else {
        Err("quote does not bind this message".into())
    }
}

struct Vault {
    dkg: DkgStore,
    sign: SignStore,
    share: Option<StoredShare>,
}

fn vaults(n: u16) -> Vec<Vault> {
    (0..n).map(|_| Vault { dkg: DkgStore::new(), sign: SignStore::new(), share: None }).collect()
}

fn v(vs: &mut [Vault], i: u16) -> &mut Vault {
    &mut vs[usize::from(i) - 1]
}

/// The client's side of a DKG, split by round so tests can tamper in between.
struct Dkg {
    sid: String,
    n: u16,
    round1: BTreeMap<u16, Round1Msg>,
    /// sealed[from][to]
    sealed: BTreeMap<u16, BTreeMap<u16, Vec<u8>>>,
    /// confirmations[from][to]
    confirmations: BTreeMap<u16, BTreeMap<u16, Vec<u8>>>,
    group: BTreeMap<u16, Vec<u8>>,
}

fn dkg_round1(vs: &mut [Vault], t: u16) -> Dkg {
    let n = vs.len() as u16;
    let sid = new_session_id();
    let mut round1 = BTreeMap::new();
    for i in 1..=n {
        let out = v(vs, i).dkg.round1(&sid, H, &CTX, i, t, n, NOW).unwrap();
        round1.insert(i, Round1Msg { package: out.package, dh_public: out.dh_public, quote: out.binding.to_vec() });
    }
    Dkg { sid, n, round1, sealed: BTreeMap::new(), confirmations: BTreeMap::new(), group: BTreeMap::new() }
}

fn dkg_round2(vs: &mut [Vault], d: &mut Dkg) -> Result<(), String> {
    for i in 1..=d.n {
        let out = v(vs, i).dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW)?;
        d.sealed.insert(i, out);
    }
    Ok(())
}

fn for_vault(m: &BTreeMap<u16, BTreeMap<u16, Vec<u8>>>, to: u16) -> BTreeMap<u16, Vec<u8>> {
    m.iter().filter(|(f, _)| **f != to).map(|(f, x)| (*f, x[&to].clone())).collect()
}

fn dkg_round3(vs: &mut [Vault], d: &mut Dkg) -> Result<(), String> {
    for i in 1..=d.n {
        let out = v(vs, i).dkg.round3(&d.sid, H, &for_vault(&d.sealed, i), NOW)?;
        d.group.insert(i, out.group_public_key);
        d.confirmations.insert(i, out.confirmations);
    }
    Ok(())
}

fn dkg_commit(vs: &mut [Vault], d: &mut Dkg) -> Result<(), String> {
    for i in 1..=d.n {
        let share = v(vs, i).dkg.commit(&d.sid, H, &for_vault(&d.confirmations, i), NOW)?;
        v(vs, i).share = Some(share);
    }
    Ok(())
}

fn run_dkg(vs: &mut [Vault], t: u16) -> Vec<u8> {
    let mut d = dkg_round1(vs, t);
    dkg_round2(vs, &mut d).unwrap();
    dkg_round3(vs, &mut d).unwrap();
    dkg_commit(vs, &mut d).unwrap();
    let g = d.group[&1].clone();
    assert!(d.group.values().all(|x| x == &g), "every vault derives the same group key");
    g
}

fn share(vs: &mut [Vault], i: u16) -> StoredShare {
    v(vs, i).share.clone().unwrap()
}

/// A signature by the given signers, the client relaying.
fn run_sign(vs: &mut [Vault], signers: &[u16], msg: &[u8]) -> Result<Vec<u8>, String> {
    let sid = new_session_id();
    let mut commitments = BTreeMap::new();
    for &i in signers {
        let s = share(vs, i);
        commitments.insert(i, v(vs, i).sign.commit(&sid, H, &s, msg, NOW)?);
    }
    let mut shares = BTreeMap::new();
    for &i in signers {
        let s = share(vs, i);
        shares.insert(i, v(vs, i).sign.sign(&sid, H, &s, &commitments, NOW)?);
    }
    let any = share(vs, signers[0]);
    aggregate(msg, &commitments, &shares, &any)
}

fn dalek_verify(pk: &[u8], msg: &[u8], sig: &[u8]) {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(pk.try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(sig.try_into().unwrap());
    vk.verify(msg, &sig).expect("a plain Ed25519 verifier accepts the threshold signature");
}

// --- the happy paths ------------------------------------------------------

#[test]
fn two_of_two_signs_a_plain_ed25519_signature() {
    let mut vs = vaults(2);
    let pk = run_dkg(&mut vs, 2);
    assert_eq!(pk.len(), 32);
    let sig = run_sign(&mut vs, &[1, 2], b"hello").unwrap();
    assert_eq!(sig.len(), 64);
    dalek_verify(&pk, b"hello", &sig);
    verify(&pk, b"hello", &sig).unwrap();
    assert!(verify(&pk, b"hellO", &sig).is_err());
    assert!(vs.iter().all(|x| x.sign.is_empty()), "no nonce outlives its signature");
}

#[test]
fn two_of_three_any_pair_signs() {
    let mut vs = vaults(3);
    let pk = run_dkg(&mut vs, 2);
    for pair in [[1u16, 2], [1, 3], [2, 3]] {
        let sig = run_sign(&mut vs, &pair, b"m").unwrap();
        dalek_verify(&pk, b"m", &sig);
    }
}

#[test]
fn three_of_four() {
    let mut vs = vaults(4);
    let pk = run_dkg(&mut vs, 3);
    let sig = run_sign(&mut vs, &[2, 3, 4], b"m").unwrap();
    dalek_verify(&pk, b"m", &sig);
}

#[test]
fn stored_share_round_trips() {
    let mut vs = vaults(2);
    let pk = run_dkg(&mut vs, 2);
    let s = share(&mut vs, 1);
    let back = StoredShare::from_bytes(&s.to_bytes().unwrap()).unwrap();
    assert_eq!(back.group_public_key().unwrap(), pk);
    assert_eq!((back.index, back.min_signers, back.max_signers), (1, 2, 2));
}

// --- signing: what a client cannot do --------------------------------------

#[test]
fn below_threshold_cannot_sign() {
    let mut vs = vaults(3);
    run_dkg(&mut vs, 3);
    let e = run_sign(&mut vs, &[1, 2], b"m").unwrap_err();
    assert!(e.contains("threshold"), "{e}");
}

#[test]
fn a_session_signs_once() {
    let mut vs = vaults(2);
    run_dkg(&mut vs, 2);
    let sid = new_session_id();
    let (s1, s2) = (share(&mut vs, 1), share(&mut vs, 2));
    let mut c = BTreeMap::new();
    c.insert(1, vs[0].sign.commit(&sid, H, &s1, b"a", NOW).unwrap());
    c.insert(2, vs[1].sign.commit(&sid, H, &s2, b"a", NOW).unwrap());
    vs[1].sign.sign(&sid, H, &s2, &c, NOW).unwrap();
    assert!(vs[1].sign.sign(&sid, H, &s2, &c, NOW).is_err(), "the nonces are gone");
    assert!(vs[0].sign.commit(&sid, H, &s1, b"b", NOW).is_err(), "a live session id is not reused");
}

#[test]
fn round_two_signs_the_round_one_message_only() {
    // Two vaults committed to different messages (a client lying to one of
    // them): each signs what IT was given, and the shares do not aggregate.
    let mut vs = vaults(2);
    run_dkg(&mut vs, 2);
    let sid = new_session_id();
    let (s1, s2) = (share(&mut vs, 1), share(&mut vs, 2));
    let mut c = BTreeMap::new();
    c.insert(1, vs[0].sign.commit(&sid, H, &s1, b"pay 1", NOW).unwrap());
    c.insert(2, vs[1].sign.commit(&sid, H, &s2, b"pay 1000", NOW).unwrap());
    let mut sh = BTreeMap::new();
    sh.insert(1, vs[0].sign.sign(&sid, H, &s1, &c, NOW).unwrap());
    sh.insert(2, vs[1].sign.sign(&sid, H, &s2, &c, NOW).unwrap());
    assert!(aggregate(b"pay 1000", &c, &sh, &s1).is_err());
    assert!(aggregate(b"pay 1", &c, &sh, &s1).is_err());
}

#[test]
fn round_two_refuses_a_swapped_commitment() {
    let mut vs = vaults(2);
    run_dkg(&mut vs, 2);
    let (sid, other) = (new_session_id(), new_session_id());
    let (s1, s2) = (share(&mut vs, 1), share(&mut vs, 2));
    let mut c = BTreeMap::new();
    c.insert(1, vs[0].sign.commit(&sid, H, &s1, b"m", NOW).unwrap());
    vs[1].sign.commit(&sid, H, &s2, b"m", NOW).unwrap();
    c.insert(2, vs[1].sign.commit(&other, H, &s2, b"m", NOW).unwrap());
    let e = vs[1].sign.sign(&sid, H, &s2, &c, NOW).unwrap_err();
    assert!(e.contains("commitment"), "{e}");
}

#[test]
fn round_two_refuses_another_key() {
    let mut vs = vaults(2);
    run_dkg(&mut vs, 2);
    let sid = new_session_id();
    let (s1, s2) = (share(&mut vs, 1), share(&mut vs, 2));
    let mut c = BTreeMap::new();
    c.insert(1, vs[0].sign.commit(&sid, H, &s1, b"m", NOW).unwrap());
    c.insert(2, vs[1].sign.commit(&sid, H, &s2, b"m", NOW).unwrap());
    assert!(vs[1].sign.sign(&sid, "users/sub/other", &s2, &c, NOW).is_err());
}

#[test]
fn sessions_expire() {
    let mut vs = vaults(2);
    run_dkg(&mut vs, 2);
    let sid = new_session_id();
    let s2 = share(&mut vs, 2);
    let mut c = BTreeMap::new();
    c.insert(2, vs[1].sign.commit(&sid, H, &s2, b"m", NOW).unwrap());
    c.insert(1, c[&2].clone());
    let e = vs[1].sign.sign(&sid, H, &s2, &c, NOW + SESSION_TTL_SECS).unwrap_err();
    assert!(e.contains("expired"), "{e}");
    assert!(vs[1].sign.is_empty());
}

#[test]
fn aggregate_needs_a_share_from_each_signer() {
    let mut vs = vaults(3);
    run_dkg(&mut vs, 2);
    let sid = new_session_id();
    let (s1, s2) = (share(&mut vs, 1), share(&mut vs, 2));
    let mut c = BTreeMap::new();
    c.insert(1, vs[0].sign.commit(&sid, H, &s1, b"m", NOW).unwrap());
    c.insert(2, vs[1].sign.commit(&sid, H, &s2, b"m", NOW).unwrap());
    let mut sh = BTreeMap::new();
    sh.insert(1, vs[0].sign.sign(&sid, H, &s1, &c, NOW).unwrap());
    assert!(aggregate(b"m", &c, &sh, &s1).is_err());
}

// --- DKG: what a client relaying the messages cannot do ---------------------

#[test]
fn dkg_refuses_a_forged_round1_package() {
    // The client replaces vault 3's package with one it made itself.
    let mut vs = vaults(3);
    let mut d = dkg_round1(&mut vs, 2);
    let mut spare = DkgStore::new();
    let forged = spare.round1(&new_session_id(), H, &CTX, 3, 2, 3, NOW).unwrap();
    d.round1.get_mut(&3).unwrap().package = forged.package;
    let e = vs[0].dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW).unwrap_err();
    assert!(e.contains("participant 3") && e.contains("quote"), "{e}");
}

#[test]
fn dkg_refuses_a_client_x25519_key() {
    // The client slips in its own X25519 key for vault 2, to read what vault 1
    // encrypts for it.
    let mut vs = vaults(2);
    let mut d = dkg_round1(&mut vs, 2);
    d.round1.get_mut(&2).unwrap().dh_public = DhKey::generate().public().to_vec();
    let e = vs[0].dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW).unwrap_err();
    assert!(e.contains("participant 2"), "{e}");
}

#[test]
fn dkg_refuses_a_set_without_my_message() {
    let mut vs = vaults(2);
    let mut d = dkg_round1(&mut vs, 2);
    let mut spare = DkgStore::new();
    let other = spare.round1(&d.sid, H, &CTX, 1, 2, 2, NOW).unwrap();
    d.round1.insert(1, Round1Msg { package: other.package, dh_public: other.dh_public, quote: other.binding.to_vec() });
    let e = vs[0].dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW).unwrap_err();
    assert!(e.contains("own message"), "{e}");
}

#[test]
fn dkg_needs_every_participant() {
    let mut vs = vaults(3);
    let mut d = dkg_round1(&mut vs, 2);
    d.round1.remove(&3);
    assert!(vs[0].dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW).is_err());
}

#[test]
fn dkg_round2_packages_open_only_for_their_recipient() {
    // The client hands vault 3 the package vault 1 sealed for vault 2.
    let mut vs = vaults(3);
    let mut d = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut d).unwrap();
    let mut for_3 = for_vault(&d.sealed, 3);
    for_3.insert(1, d.sealed[&1][&2].clone());
    let e = vs[2].dkg.round3(&d.sid, H, &for_3, NOW).err().unwrap();
    assert!(e.contains("participant 1") && e.contains("does not open"), "{e}");
}

#[test]
fn dkg_catches_two_round1_sets() {
    // Two concurrent DKGs on the same vaults, the client mixing them: vault 3
    // gets vault 1's sealed package from the other run. It does not open.
    let mut vs = vaults(3);
    let mut a = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut a).unwrap();
    let mut ws = vaults(3);
    let mut b = dkg_round1(&mut ws, 2);
    dkg_round2(&mut ws, &mut b).unwrap();
    let mut for_3 = for_vault(&a.sealed, 3);
    for_3.insert(1, b.sealed[&1][&3].clone());
    assert!(vs[2].dkg.round3(&a.sid, H, &for_3, NOW).is_err());
}

#[test]
fn dkg_commit_needs_every_confirmation() {
    let mut vs = vaults(3);
    let mut d = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut d).unwrap();
    dkg_round3(&mut vs, &mut d).unwrap();
    let mut for_1 = for_vault(&d.confirmations, 1);
    for_1.remove(&3);
    let e = vs[0].dkg.commit(&d.sid, H, &for_1, NOW).err().unwrap();
    assert!(e.contains("confirmation"), "{e}");
}

#[test]
fn dkg_commit_refuses_a_forged_confirmation() {
    let mut vs = vaults(2);
    let mut d = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut d).unwrap();
    dkg_round3(&mut vs, &mut d).unwrap();
    let mut for_1 = for_vault(&d.confirmations, 1);
    for_1.insert(2, vec![0u8; 32]);
    let e = vs[0].dkg.commit(&d.sid, H, &for_1, NOW).err().unwrap();
    assert!(e.contains("did not confirm"), "{e}");
    // The share was not handed out, and the session is gone.
    assert!(vs[0].dkg.commit(&d.sid, H, &for_vault(&d.confirmations, 1), NOW).is_err());
}

#[test]
fn dkg_confirmation_is_directional() {
    // Vault 2's confirmation for vault 3 is no good to vault 1.
    let mut vs = vaults(3);
    let mut d = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut d).unwrap();
    dkg_round3(&mut vs, &mut d).unwrap();
    let mut for_1 = for_vault(&d.confirmations, 1);
    for_1.insert(2, d.confirmations[&2][&3].clone());
    assert!(vs[0].dkg.commit(&d.sid, H, &for_1, NOW).is_err());
}

#[test]
fn dkg_rounds_run_once() {
    // Repeating a round ends that vault's session: a DKG is never retried.
    let mut vs = vaults(2);
    let mut d = dkg_round1(&mut vs, 2);
    dkg_round2(&mut vs, &mut d).unwrap();
    assert!(vs[0].dkg.round2(&d.sid, H, &d.round1, &fake_verify, NOW).is_err());
    let e = vs[0].dkg.round3(&d.sid, H, &for_vault(&d.sealed, 1), NOW).err().unwrap();
    assert!(e.contains("unknown or expired"), "{e}");
    // Vault 2 runs round 3 once; a second time ends its session too.
    vs[1].dkg.round3(&d.sid, H, &for_vault(&d.sealed, 2), NOW).unwrap();
    assert!(vs[1].dkg.round3(&d.sid, H, &for_vault(&d.sealed, 2), NOW).is_err());
    assert!(vs[1].dkg.commit(&d.sid, H, &BTreeMap::new(), NOW).is_err());
}

#[test]
fn dkg_session_is_bound_to_its_key() {
    let mut vs = vaults(2);
    let d = dkg_round1(&mut vs, 2);
    assert!(vs[0].dkg.round2(&d.sid, "users/sub/other", &d.round1, &fake_verify, NOW).is_err());
}

#[test]
fn x25519_refuses_a_low_order_key() {
    let me = DhKey::generate();
    assert!(me.shared(&[0u8; 32]).is_err());
}

#[test]
fn threshold_bounds() {
    assert!(check_threshold(2, 2).is_ok());
    assert!(check_threshold(1, 2).is_err());
    assert!(check_threshold(3, 2).is_err());
    assert!(check_threshold(2, 1).is_err());
    assert!(check_threshold(2, MAX_PARTICIPANTS + 1).is_err());
    assert!(check_session_id("short").is_err());
    assert!(check_session_id("abcdefABCDEF0123-_").is_ok());
    assert!(check_session_id("abcdefABCDEF0123/.").is_err());
}

#[test]
fn dkg_needs_one_participant_list() {
    // Vault 2 was told another participant list (or threshold): vault 1
    // refuses its quote, and the failed round ends vault 1's session.
    let mut vs = vaults(2);
    let sid = new_session_id();
    let a = vs[0].dkg.round1(&sid, H, &CTX, 1, 2, 2, NOW).unwrap();
    let b = vs[1].dkg.round1(&sid, H, &[8u8; 32], 2, 2, 2, NOW).unwrap();
    let mut round1 = BTreeMap::new();
    round1.insert(1, Round1Msg { package: a.package, dh_public: a.dh_public, quote: a.binding.to_vec() });
    round1.insert(2, Round1Msg { package: b.package, dh_public: b.dh_public, quote: b.binding.to_vec() });
    let e = vs[0].dkg.round2(&sid, H, &round1, &fake_verify, NOW).unwrap_err();
    assert!(e.contains("participant 2"), "{e}");
    let e = vs[0].dkg.round2(&sid, H, &round1, &fake_verify, NOW).unwrap_err();
    assert!(e.contains("unknown or expired"), "a failed round 2 is not retried: {e}");
}
