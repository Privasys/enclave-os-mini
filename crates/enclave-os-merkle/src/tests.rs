// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Store-level tests: reference-model property tests, root determinism,
//! tamper fail-closed sweeps, history, restart and I/O complexity.

use std::collections::BTreeMap;

use crate::backend::MemBackend;
use crate::error::MerkleError;
use crate::hash::placeholder;
use crate::tree::MerkleStore;

const CK: [u8; 32] = [0x11; 32];
const SK: [u8; 32] = [0x22; 32];

fn new_store() -> MerkleStore<MemBackend> {
    MerkleStore::create(MemBackend::new(), CK, SK).unwrap()
}

/// Deterministic PRNG (splitmix64) — no external deps, reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

fn key(i: u64) -> Vec<u8> {
    format!("key-{i}").into_bytes()
}

fn val(i: u64) -> Vec<u8> {
    format!("value-{i}").into_bytes()
}

// ---------------------------------------------------------------------------
//  Basics
// ---------------------------------------------------------------------------

#[test]
fn empty_store() {
    let store = new_store();
    let (root, version) = store.root();
    assert_eq!(root, *placeholder());
    assert_eq!(version, 0);
    assert_eq!(store.get(b"nothing").unwrap(), None);
}

#[test]
fn put_get_roundtrip() {
    let mut store = new_store();
    let (root, version) = store
        .put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))])
        .unwrap();
    assert_eq!(version, 1);
    assert_ne!(root, *placeholder());
    assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));
    assert_eq!(store.get(b"other").unwrap(), None);
}

#[test]
fn overwrite_and_delete() {
    let mut store = new_store();
    store.put_batch(&[(b"k".to_vec(), Some(b"v1".to_vec()))]).unwrap();
    let (root_v1, _) = store.root();

    store.put_batch(&[(b"k".to_vec(), Some(b"v2".to_vec()))]).unwrap();
    assert_eq!(store.get(b"k").unwrap(), Some(b"v2".to_vec()));
    assert_ne!(store.root().0, root_v1);

    let (root, version) = store.put_batch(&[(b"k".to_vec(), None)]).unwrap();
    assert_eq!(version, 3);
    // Tree with all keys deleted has the empty root again.
    assert_eq!(root, *placeholder());
    assert_eq!(store.get(b"k").unwrap(), None);
}

#[test]
fn noop_batches_do_not_commit() {
    let mut store = new_store();
    store.put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))]).unwrap();
    let before = store.root();

    // Delete of an absent key.
    assert_eq!(store.put_batch(&[(b"absent".to_vec(), None)]).unwrap(), before);
    // Overwrite with the identical value.
    assert_eq!(
        store.put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))]).unwrap(),
        before
    );
    // Empty batch.
    assert_eq!(store.put_batch(&[]).unwrap(), before);
    assert_eq!(store.root(), before);
}

#[test]
fn last_write_wins_within_a_batch() {
    let mut store = new_store();
    store
        .put_batch(&[
            (b"k".to_vec(), Some(b"first".to_vec())),
            (b"k".to_vec(), Some(b"second".to_vec())),
        ])
        .unwrap();
    assert_eq!(store.get(b"k").unwrap(), Some(b"second".to_vec()));

    store
        .put_batch(&[
            (b"k".to_vec(), None),
            (b"k".to_vec(), Some(b"resurrected".to_vec())),
        ])
        .unwrap();
    assert_eq!(store.get(b"k").unwrap(), Some(b"resurrected".to_vec()));
}

#[test]
fn empty_value_is_a_value() {
    let mut store = new_store();
    store.put_batch(&[(b"k".to_vec(), Some(Vec::new()))]).unwrap();
    assert_eq!(store.get(b"k").unwrap(), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
//  Root determinism (the BFT-Raft requirement)
// ---------------------------------------------------------------------------

/// The root must be a pure function of (logical state, ck): independent
/// of insertion history, batch grouping and storage key.
#[test]
fn root_is_history_independent() {
    // Store A: many incremental batches with churn (overwrites, deletes).
    let mut a = new_store();
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = Rng(7);
    for _ in 0..40 {
        let mut batch = Vec::new();
        for _ in 0..(rng.next() % 8 + 1) {
            let k = key(rng.next() % 50);
            if rng.next() % 4 == 0 {
                batch.push((k, None));
            } else {
                let v = val(rng.next() % 1000);
                batch.push((k, Some(v)));
            }
        }
        for (k, v) in &batch {
            match v {
                Some(v) => {
                    model.insert(k.clone(), v.clone());
                }
                None => {
                    model.remove(k);
                }
            }
        }
        a.put_batch(&batch).unwrap();
    }

    // Store B: the final state in one batch.
    let mut b = new_store();
    let final_state: Vec<(Vec<u8>, Option<Vec<u8>>)> =
        model.iter().map(|(k, v)| (k.clone(), Some(v.clone()))).collect();
    b.put_batch(&final_state).unwrap();

    assert_eq!(a.root().0, b.root().0);

    // Store C: same logical state, different storage key — same root.
    let mut c = MerkleStore::create(MemBackend::new(), CK, [0x33; 32]).unwrap();
    c.put_batch(&final_state).unwrap();
    assert_eq!(a.root().0, c.root().0);

    // Different commitment key — different root.
    let mut d = MerkleStore::create(MemBackend::new(), [0x44; 32], SK).unwrap();
    d.put_batch(&final_state).unwrap();
    assert_ne!(a.root().0, d.root().0);
}

// ---------------------------------------------------------------------------
//  Property test against a reference model
// ---------------------------------------------------------------------------

#[test]
fn random_ops_match_reference_model() {
    let mut store = new_store();
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = Rng(42);
    let mut snapshots: Vec<(u64, BTreeMap<Vec<u8>, Vec<u8>>)> = Vec::new();

    for round in 0..60 {
        let mut batch = Vec::new();
        for _ in 0..(rng.next() % 10 + 1) {
            // Small keyspace so overwrites, deletes and collisions happen.
            let k = key(rng.next() % 30);
            if rng.next() % 3 == 0 {
                batch.push((k, None));
            } else {
                batch.push((k, Some(val(rng.next()))));
            }
        }
        for (k, v) in &batch {
            match v {
                Some(v) => {
                    model.insert(k.clone(), v.clone());
                }
                None => {
                    model.remove(k);
                }
            }
        }
        store.put_batch(&batch).unwrap();

        // Full read-back every round.
        for i in 0..30 {
            let k = key(i);
            assert_eq!(store.get(&k).unwrap(), model.get(&k).cloned(), "round {round}");
        }
        if round % 20 == 19 {
            snapshots.push((store.root().1, model.clone()));
        }
    }

    // Historical reads reproduce each snapshot exactly.
    for (version, snapshot) in &snapshots {
        for i in 0..30 {
            let k = key(i);
            assert_eq!(
                store.get_at(*version, &k).unwrap(),
                snapshot.get(&k).cloned(),
                "get_at v{version}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
//  Restart / open
// ---------------------------------------------------------------------------

#[test]
fn reopen_at_checkpoint() {
    let backend = MemBackend::new();
    let mut store = MerkleStore::create(backend, CK, SK).unwrap();
    store
        .put_batch(&[
            (b"a".to_vec(), Some(b"1".to_vec())),
            (b"b".to_vec(), Some(b"2".to_vec())),
        ])
        .unwrap();
    let (root, version) = store.root();
    let backend = store.into_backend();

    let reopened = MerkleStore::open(backend, CK, SK, root, version).unwrap();
    assert_eq!(reopened.root(), (root, version));
    assert_eq!(reopened.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(reopened.get(b"b").unwrap(), Some(b"2".to_vec()));
}

#[test]
fn reopen_with_wrong_root_fails_closed() {
    let backend = MemBackend::new();
    let mut store = MerkleStore::create(backend, CK, SK).unwrap();
    store.put_batch(&[(b"a".to_vec(), Some(b"1".to_vec()))]).unwrap();
    let (mut root, version) = store.root();
    root[0] ^= 0xFF;
    let backend = store.into_backend();
    assert!(MerkleStore::open(backend, CK, SK, root, version).is_err());
}

#[test]
fn reopen_empty_store() {
    let store = new_store();
    let (root, version) = store.root();
    let backend = store.into_backend();
    let reopened = MerkleStore::open(backend, CK, SK, root, version).unwrap();
    assert_eq!(reopened.get(b"x").unwrap(), None);
}

// ---------------------------------------------------------------------------
//  Tamper: every record is fail-closed
// ---------------------------------------------------------------------------

/// Corrupt every stored record one at a time. A read must then return
/// either the correct value or an error — never wrong data, never a
/// silent absence for a present key.
#[test]
fn tamper_sweep_fails_closed() {
    let mut store = new_store();
    store.set_cache_capacity(0); // every read must hit the backend
    let n = 40u64;
    let batch: Vec<_> = (0..n).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();

    let record_keys = store.backend().keys();
    assert!(!record_keys.is_empty());

    for rk in record_keys {
        assert!(store.backend().tamper(&rk), "tamper {rk:?}");
        for i in 0..n {
            match store.get(&key(i)) {
                Ok(Some(v)) => assert_eq!(v, val(i), "wrong data after tampering {rk:?}"),
                Ok(None) => panic!("silent absence of present key after tampering {rk:?}"),
                Err(
                    MerkleError::Corrupted(_) | MerkleError::Missing(_),
                ) => {}
                Err(e) => panic!("unexpected error kind: {e}"),
            }
        }
        // Undo (tamper is an XOR flip).
        store.backend().tamper(&rk);
        // Sanity: everything reads clean again.
        assert_eq!(store.get(&key(0)).unwrap(), Some(val(0)));
    }
}

/// Removing records (host "loses" data) must never yield wrong data.
#[test]
fn missing_records_fail_closed() {
    let mut store = new_store();
    store.set_cache_capacity(0); // force every read to hit the backend
    store.put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))]).unwrap();
    for rk in store.backend().keys() {
        if rk[0] == b'r' || rk[0] == b'c' {
            continue; // root/checkpoint records are not on the live read path
        }
        store.backend().remove(&rk);
        match store.get(b"k") {
            Err(MerkleError::Missing(_)) | Err(MerkleError::Corrupted(_)) => {}
            other => panic!("expected fail-closed, got {other:?}"),
        }
        // Rebuild the store for the next iteration.
        store = new_store();
        store.set_cache_capacity(0);
        store.put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))]).unwrap();
    }
}

// ---------------------------------------------------------------------------
//  Structure: collapse correctness via root equality
// ---------------------------------------------------------------------------

#[test]
fn delete_collapses_to_equivalent_tree() {
    // Insert many keys, delete most of them; the root must equal a
    // freshly built tree holding only the survivors. This exercises
    // internal-node collapse (single surviving leaf rising).
    let mut store = new_store();
    let n = 64u64;
    let batch: Vec<_> = (0..n).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();

    let deletes: Vec<_> = (0..n).filter(|i| i % 7 != 0).map(|i| (key(i), None)).collect();
    store.put_batch(&deletes).unwrap();

    let mut fresh = new_store();
    let survivors: Vec<_> =
        (0..n).filter(|i| i % 7 == 0).map(|i| (key(i), Some(val(i)))).collect();
    fresh.put_batch(&survivors).unwrap();

    assert_eq!(store.root().0, fresh.root().0);
    for i in 0..n {
        let expected = if i % 7 == 0 { Some(val(i)) } else { None };
        assert_eq!(store.get(&key(i)).unwrap(), expected);
    }
}

// ---------------------------------------------------------------------------
//  Proofs
// ---------------------------------------------------------------------------

#[test]
fn inclusion_proofs_for_every_key() {
    let mut store = new_store();
    let n = 200u64;
    let batch: Vec<_> = (0..n).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();
    let (root, _) = store.root();

    for i in 0..n {
        let proof = store.prove(&key(i)).unwrap();
        // Wire round-trip, then verify the decoded proof.
        let proof = crate::proof::Proof::decode(&proof.encode()).unwrap();
        assert!(store.verify_value(&root, &key(i), &val(i), &proof).unwrap());
        // The right key with the wrong value does not verify.
        assert!(!store.verify_value(&root, &key(i), b"forged", &proof).unwrap());
        // And it is not an absence proof.
        assert!(!store.verify_absent(&root, &key(i), &proof).unwrap());
    }
}

#[test]
fn absence_proofs_both_kinds() {
    let mut store = new_store();
    // Enough keys that absent paths hit both divergent leaves and
    // empty slots.
    let batch: Vec<_> = (0..300u64).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();
    let (root, _) = store.root();

    let mut with_leaf = 0;
    let mut with_empty = 0;
    for i in 0..300u64 {
        let absent = format!("absent-{i}").into_bytes();
        let proof = store.prove(&absent).unwrap();
        match proof.leaf {
            Some(_) => with_leaf += 1,
            None => with_empty += 1,
        }
        assert!(store.verify_absent(&root, &absent, &proof).unwrap());
        // An absence proof never verifies a value.
        assert!(!store.verify_value(&root, &absent, b"x", &proof).unwrap());
    }
    // Both terminal kinds must actually be exercised.
    assert!(with_leaf > 0, "no divergent-leaf absence proofs seen");
    assert!(with_empty > 0, "no empty-slot absence proofs seen");
}

#[test]
fn proofs_on_empty_and_single_key_trees() {
    let store = new_store();
    let (root, _) = store.root();
    let proof = store.prove(b"anything").unwrap();
    assert!(store.verify_absent(&root, b"anything", &proof).unwrap());

    let mut store = new_store();
    store.put_batch(&[(b"only".to_vec(), Some(b"v".to_vec()))]).unwrap();
    let (root, _) = store.root();
    let proof = store.prove(b"only").unwrap();
    assert!(store.verify_value(&root, b"only", b"v", &proof).unwrap());
    let proof = store.prove(b"other").unwrap();
    assert!(store.verify_absent(&root, b"other", &proof).unwrap());
}

#[test]
fn historical_proofs() {
    let mut store = new_store();
    store.put_batch(&[(b"k".to_vec(), Some(b"v1".to_vec()))]).unwrap();
    let (root_v1, v1) = store.root();
    store.put_batch(&[(b"k".to_vec(), Some(b"v2".to_vec()))]).unwrap();
    store.put_batch(&[(b"k".to_vec(), None)]).unwrap();
    let (root_v3, _) = store.root();

    // v1: k = v1.
    let proof = store.prove_at(v1, b"k").unwrap();
    assert!(store.verify_value(&root_v1, b"k", b"v1", &proof).unwrap());
    // Current: k absent.
    let proof = store.prove(b"k").unwrap();
    assert!(store.verify_absent(&root_v3, b"k", &proof).unwrap());
    // Cross-version confusion fails: v1 proof against v3 root.
    let proof_v1 = store.prove_at(v1, b"k").unwrap();
    assert!(store.verify_value(&root_v3, b"k", b"v1", &proof_v1).is_err());
}

#[test]
fn proofs_do_not_transfer_between_keys() {
    let mut store = new_store();
    let batch: Vec<_> = (0..100u64).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();
    let (root, _) = store.root();

    let proof_0 = store.prove(&key(0)).unwrap();
    for i in 1..100u64 {
        // key(0)'s proof must not verify key(i)'s value, nor absence.
        assert!(!store.verify_value(&root, &key(i), &val(i), &proof_0).unwrap_or(false));
        assert!(!store.verify_absent(&root, &key(i), &proof_0).unwrap_or(false));
    }
}

/// Any single mutation of an encoded proof must either fail to verify
/// or establish the identical statement — never a different one.
#[test]
fn proof_mutation_fuzz() {
    let mut store = new_store();
    let batch: Vec<_> = (0..64u64).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();
    let (root, _) = store.root();

    let target = key(7);
    let path_free_check = |proof: &crate::proof::Proof| {
        store.verify_value(&root, &target, &val(7), proof)
    };
    let original = store.prove(&target).unwrap();
    assert!(path_free_check(&original).unwrap());
    let encoded = original.encode();

    let mut rng = Rng(99);
    for _ in 0..500 {
        let mut mutated = encoded.clone();
        let pos = (rng.next() as usize) % mutated.len();
        let bit = 1u8 << (rng.next() % 8);
        mutated[pos] ^= bit;
        if mutated == encoded {
            continue;
        }
        match crate::proof::Proof::decode(&mutated) {
            Err(_) => {}
            Ok(p) => match path_free_check(&p) {
                // A mutated proof may still decode, but it must not
                // verify the target statement...
                Ok(true) => panic!("mutated proof still verifies at byte {pos}"),
                // ...rejecting or proving nothing is fine.
                Ok(false) | Err(_) => {}
            },
        }
    }
}

// ---------------------------------------------------------------------------
//  Pruning
// ---------------------------------------------------------------------------

/// Count backend records by type prefix: (nodes, values, stale, roots).
fn record_census(store: &MerkleStore<MemBackend>) -> (usize, usize, usize, usize) {
    let (mut n, mut v, mut s, mut r) = (0, 0, 0, 0);
    for k in store.backend().keys() {
        match k[0] {
            b'n' => n += 1,
            b'v' => v += 1,
            b's' => s += 1,
            b'r' => r += 1,
            b'c' => {} // the single checkpoint record
            other => panic!("unknown record prefix {other}"),
        }
    }
    (n, v, s, r)
}

/// After pruning all history, the store holds exactly what a freshly
/// built store with the same content holds: same node count, same value
/// count, zero stale entries, one live root record.
#[test]
fn prune_removes_exactly_the_garbage() {
    let mut store = new_store();
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = Rng(3);
    for _ in 0..50 {
        let mut batch = Vec::new();
        for _ in 0..(rng.next() % 8 + 1) {
            let k = key(rng.next() % 40);
            if rng.next() % 4 == 0 {
                batch.push((k, None));
            } else {
                batch.push((k, Some(val(rng.next() % 500))));
            }
        }
        for (k, v) in &batch {
            match v {
                Some(v) => {
                    model.insert(k.clone(), v.clone());
                }
                None => {
                    model.remove(k);
                }
            }
        }
        store.put_batch(&batch).unwrap();
    }
    let (root, version) = store.root();
    let before_census = record_census(&store);
    assert!(before_census.2 > 0, "churn should have produced stale entries");

    let stats = store.prune(version).unwrap();
    assert!(stats.records_deleted > 0);

    // Root and content untouched.
    assert_eq!(store.root(), (root, version));
    for (k, v) in &model {
        assert_eq!(store.get(k).unwrap().as_ref(), Some(v));
    }

    // Census matches a fresh store with identical content.
    let mut fresh = new_store();
    let final_state: Vec<_> = model.iter().map(|(k, v)| (k.clone(), Some(v.clone()))).collect();
    fresh.put_batch(&final_state).unwrap();
    let (n, v, s, r) = record_census(&store);
    let (fn_, fv, _fs, _fr) = record_census(&fresh);
    assert_eq!(s, 0, "stale entries must all be consumed");
    assert_eq!(r, 1, "only the live root record remains");
    assert_eq!(n, fn_, "node count must match a fresh build");
    assert_eq!(v, fv, "value count must match a fresh build");

    // Roots still equal, of course.
    assert_eq!(store.root().0, fresh.root().0);
}

#[test]
fn prune_keeps_the_retained_window() {
    let mut store = new_store();
    let mut snapshots: Vec<(u64, Vec<(Vec<u8>, Option<Vec<u8>>)>)> = Vec::new();
    for round in 0..10u64 {
        store
            .put_batch(&[(key(round % 4), Some(val(round))), (key(100 + round), Some(val(round)))])
            .unwrap();
        let (_, v) = store.root();
        // Snapshot the small keyspace via live reads.
        let mut snap = Vec::new();
        for i in 0..4u64 {
            snap.push((key(i), store.get(&key(i)).unwrap()));
        }
        snapshots.push((v, snap));
    }

    let horizon = 6u64;
    store.prune(horizon).unwrap();

    for (v, snap) in &snapshots {
        if *v >= horizon {
            for (k, expected) in snap {
                assert_eq!(&store.get_at(*v, k).unwrap(), expected, "v{v}");
            }
        } else {
            // Below the horizon: root record gone, clean Missing error.
            let r = store.get_at(*v, &key(0));
            assert!(
                matches!(r, Err(MerkleError::Missing(_))),
                "v{v} expected Missing, got {r:?}"
            );
        }
    }
}

/// Delete + re-insert of the same (key, value) across commits: the
/// resurrected value must survive pruning of the deletion's stale entry.
#[test]
fn resurrection_survives_prune() {
    let mut store = new_store();
    store.put_batch(&[(b"k".to_vec(), Some(b"same".to_vec()))]).unwrap(); // v1
    store.put_batch(&[(b"k".to_vec(), None)]).unwrap(); // v2 (stales v1 records)
    store.put_batch(&[(b"k".to_vec(), Some(b"same".to_vec()))]).unwrap(); // v3, same vh
    let (_, v) = store.root();
    assert_eq!(v, 3);

    store.prune(3).unwrap();
    assert_eq!(store.get(b"k").unwrap(), Some(b"same".to_vec()));

    // Exactly one value record remains (the v3 one); v1's was pruned.
    let values = store
        .backend()
        .keys()
        .into_iter()
        .filter(|k| k[0] == b'v')
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1);
    assert_eq!(&values[0][values[0].len() - 8..], &3u64.to_be_bytes());
}

#[test]
fn prune_is_idempotent_and_validates() {
    let mut store = new_store();
    for i in 0..5u64 {
        store.put_batch(&[(key(i), Some(val(i)))]).unwrap();
    }
    let (_, version) = store.root();

    let first = store.prune(version).unwrap();
    assert!(first.records_deleted > 0 || first.root_records_deleted > 0);
    let second = store.prune(version).unwrap();
    assert_eq!(second, crate::tree::PruneStats::default());

    // Future horizon is rejected.
    assert!(matches!(store.prune(version + 1), Err(MerkleError::Invalid(_))));
}

#[test]
fn retain_recent_window() {
    let mut store = new_store();
    for i in 0..20u64 {
        store.put_batch(&[(key(i % 3), Some(val(i)))]).unwrap();
    }
    let (_, version) = store.root();
    store.retain_recent(5).unwrap();

    // version-5 .. version stay readable.
    for v in version - 5..=version {
        store.get_at(v, &key(0)).unwrap();
    }
    assert!(matches!(
        store.get_at(version - 6, &key(0)),
        Err(MerkleError::Missing(_))
    ));
}

/// Pruning must not disturb fail-closed behaviour of what remains.
#[test]
fn pruned_store_still_fails_closed() {
    let mut store = new_store();
    store.set_cache_capacity(0); // every read must hit the backend
    let batch: Vec<_> = (0..30u64).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();
    store.put_batch(&[(key(0), Some(val(999)))]).unwrap();
    let (_, version) = store.root();
    store.prune(version).unwrap();

    for rk in store.backend().keys() {
        if rk[0] == b'r' {
            continue;
        }
        assert!(store.backend().tamper(&rk));
        for i in 0..30u64 {
            match store.get(&key(i)) {
                Ok(Some(v)) => {
                    let expected = if i == 0 { val(999) } else { val(i) };
                    assert_eq!(v, expected, "wrong data after tampering {rk:?}");
                }
                Ok(None) => panic!("silent absence after tampering {rk:?}"),
                Err(MerkleError::Corrupted(_) | MerkleError::Missing(_)) => {}
                Err(e) => panic!("unexpected error kind: {e}"),
            }
        }
        store.backend().tamper(&rk); // undo
    }
}

// ---------------------------------------------------------------------------
//  Checkpoint record (open_latest / open_or_create)
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_reopen_without_external_state() {
    let store = MerkleStore::open_or_create(MemBackend::new(), CK, SK).unwrap();
    let mut store = store;
    store
        .put_batch(&[
            (b"a".to_vec(), Some(b"1".to_vec())),
            (b"b".to_vec(), Some(b"2".to_vec())),
        ])
        .unwrap();
    let expected = store.root();

    // Reopen purely from the backend: the checkpoint record carries
    // (root, version), atomically written with the commit.
    let backend = store.into_backend();
    let reopened = MerkleStore::open_or_create(backend, CK, SK).unwrap();
    assert_eq!(reopened.root(), expected);
    assert_eq!(reopened.get(b"a").unwrap(), Some(b"1".to_vec()));

    // A tampered checkpoint fails closed (GCM tag).
    let backend = reopened.into_backend();
    assert!(backend.tamper(&[b'c']));
    assert!(matches!(
        MerkleStore::open_latest(backend, CK, SK),
        Err(MerkleError::Corrupted(_))
    ));
}

// ---------------------------------------------------------------------------
//  Module envelope
// ---------------------------------------------------------------------------

mod module_tests {
    use super::*;
    use crate::module::MerkleModule;
    use enclave_os_common::hex::{hex_decode, hex_encode};
    use enclave_os_common::modules::{EnclaveModule, RequestContext};
    use enclave_os_common::oidc::{OidcClaims, OidcConfig};
    use enclave_os_common::protocol::{Request, Response};

    fn claims(roles: &[&str]) -> OidcClaims {
        let config: OidcConfig =
            serde_json::from_str(r#"{"issuer":"i","audience":"a"}"#).unwrap();
        OidcClaims::from_raw(
            "tester".into(),
            roles.iter().map(|s| s.to_string()).collect(),
            &config,
        )
    }

    fn ctx(oidc_claims: Option<OidcClaims>) -> RequestContext {
        RequestContext {
            peer_cert_der: None,
            client_challenge_nonce: None,
            channel_binder: None,
            oidc_claims,
        }
    }

    fn new_module() -> MerkleModule<MemBackend> {
        let store = MerkleStore::create(MemBackend::new(), CK, SK).unwrap();
        MerkleModule::with_store(store, "test")
    }

    fn call(
        module: &MerkleModule<MemBackend>,
        body: serde_json::Value,
        context: &RequestContext,
    ) -> Option<Response> {
        module.handle(&Request::Data(body.to_string().into_bytes()), context)
    }

    fn data_json(resp: Response) -> serde_json::Value {
        match resp {
            Response::Data(d) => serde_json::from_slice(&d).unwrap(),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    fn error_text(resp: Response) -> String {
        match resp {
            Response::Error(d) => {
                serde_json::from_slice::<serde_json::Value>(&d).unwrap()["error"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let module = new_module();
        let manager = ctx(Some(claims(&["privasys-platform:manager"])));

        // Put two keys, one delete of an absent key.
        let resp = call(
            &module,
            serde_json::json!({"merkle_put": {"ops": [
                {"key": hex_encode(b"alice"), "value": hex_encode(b"1000")},
                {"key": hex_encode(b"bob"),   "value": hex_encode(b"250")},
            ]}}),
            &manager,
        )
        .unwrap();
        let put = data_json(resp);
        assert_eq!(put["version"], 1);

        // Root query matches.
        let root = data_json(call(&module, serde_json::json!({"merkle_root": {}}), &manager).unwrap());
        assert_eq!(root["root"], put["root"]);

        // Get present + absent.
        let got = data_json(
            call(&module, serde_json::json!({"merkle_get": {"key": hex_encode(b"alice")}}), &manager)
                .unwrap(),
        );
        assert_eq!(got["value"], hex_encode(b"1000"));
        let got = data_json(
            call(&module, serde_json::json!({"merkle_get": {"key": hex_encode(b"nobody")}}), &manager)
                .unwrap(),
        );
        assert!(got["value"].is_null());

        // Prove: decodes and reports the live root.
        let proved = data_json(
            call(&module, serde_json::json!({"merkle_prove": {"key": hex_encode(b"alice")}}), &manager)
                .unwrap(),
        );
        assert_eq!(proved["root"], root["root"]);
        let proof_bytes = hex_decode(proved["proof"].as_str().unwrap()).unwrap();
        crate::proof::Proof::decode(&proof_bytes).unwrap();

        // Delete + prune via retain_recent.
        let resp = call(
            &module,
            serde_json::json!({"merkle_put": {"ops": [{"key": hex_encode(b"bob")}]}}),
            &manager,
        )
        .unwrap();
        assert_eq!(data_json(resp)["version"], 2);
        let pruned = data_json(
            call(&module, serde_json::json!({"merkle_prune": {"retain_recent": 0}}), &manager)
                .unwrap(),
        );
        assert!(pruned["records_deleted"].as_u64().unwrap() > 0);
    }

    #[test]
    fn declines_foreign_payloads() {
        let module = new_module();
        let manager = ctx(Some(claims(&["privasys-platform:manager"])));
        // Another module's envelope: decline (None), never an error.
        assert!(call(&module, serde_json::json!({"wasm_schema": {"app": "x"}}), &manager).is_none());
        // Non-JSON body: decline.
        assert!(module.handle(&Request::Data(b"not json".to_vec()), &manager).is_none());
        // Non-Data requests: decline.
        assert!(module.handle(&Request::Healthz, &manager).is_none());
    }

    #[test]
    fn role_gates() {
        let module = new_module();

        // No claims at all.
        let resp = call(&module, serde_json::json!({"merkle_root": {}}), &ctx(None)).unwrap();
        assert_eq!(error_text(resp), "authentication required");

        // Monitoring can read but not write.
        let monitoring = ctx(Some(claims(&["privasys-platform:monitoring"])));
        assert!(matches!(
            call(&module, serde_json::json!({"merkle_root": {}}), &monitoring).unwrap(),
            Response::Data(_)
        ));
        let resp = call(
            &module,
            serde_json::json!({"merkle_put": {"ops": [{"key": "00", "value": "00"}]}}),
            &monitoring,
        )
        .unwrap();
        assert_eq!(error_text(resp), "manager role required");

        // No roles: cannot even read.
        let nobody = ctx(Some(claims(&[])));
        let resp = call(&module, serde_json::json!({"merkle_root": {}}), &nobody).unwrap();
        assert_eq!(error_text(resp), "monitoring role required");
    }

    #[test]
    fn custom_oid_tracks_commits() {
        let module = new_module();
        let manager = ctx(Some(claims(&["privasys-platform:manager"])));

        let oids = module.custom_oids();
        assert_eq!(oids.len(), 1);
        assert_eq!(oids[0].value.len(), 40);
        let before = oids[0].value.clone();

        call(
            &module,
            serde_json::json!({"merkle_put": {"ops": [{"key": "aa", "value": "bb"}]}}),
            &manager,
        )
        .unwrap();
        let after = module.custom_oids()[0].value.clone();
        assert_ne!(before, after);
        assert_eq!(&after[32..], &1u64.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
//  I/O complexity
// ---------------------------------------------------------------------------

#[test]
fn point_lookups_stay_logarithmic() {
    let mut store = new_store();
    store.set_cache_capacity(0); // measure raw tree I/O
    let n = 4096u64; // expected depth ≈ log16(4096) = 3
    let batch: Vec<_> = (0..n).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();

    // Present keys: nodes on the path + 1 value read.
    for i in (0..n).step_by(97) {
        store.backend().reset_reads();
        assert!(store.get(&key(i)).unwrap().is_some());
        let reads = store.backend().reads();
        assert!(reads <= 8, "present-key get cost {reads} reads");
    }

    // Absent keys must not cost more than present ones.
    for i in 0..20 {
        store.backend().reset_reads();
        assert!(store.get(format!("absent-{i}").as_bytes()).unwrap().is_none());
        let reads = store.backend().reads();
        assert!(reads <= 7, "absent-key get cost {reads} reads");
    }
}

#[test]
fn node_cache_cuts_reads() {
    let mut store = new_store(); // default cache on
    let n = 4096u64;
    let batch: Vec<_> = (0..n).map(|i| (key(i), Some(val(i)))).collect();
    store.put_batch(&batch).unwrap();

    // Repeat read: all nodes cached, only the value record hits the host.
    store.get(&key(7)).unwrap();
    store.backend().reset_reads();
    store.get(&key(7)).unwrap();
    assert_eq!(store.backend().reads(), 1, "warm get must cost exactly the value read");

    // Commit warm-fill: straight after a commit the touched path is hot.
    store.put_batch(&[(key(1), Some(val(9999)))]).unwrap();
    store.backend().reset_reads();
    store.get(&key(1)).unwrap();
    assert_eq!(store.backend().reads(), 1);

    // Cold keys still benefit from shared upper levels: with the top of
    // the tree cached, a first-touch get costs fewer node reads than
    // the uncached depth.
    store.backend().reset_reads();
    store.get(&key(4000)).unwrap();
    assert!(store.backend().reads() <= 4, "shared levels should be warm");

    // Correctness is untouched by cache state.
    for i in (0..n).step_by(211) {
        let expected = if i == 1 { val(9999) } else { val(i) };
        assert_eq!(store.get(&key(i)).unwrap(), Some(expected));
    }
}

/// Not a benchmark, a sanity meter: prints reads-per-get and rough
/// timings at 100k keys. Run manually: `cargo test --release bench_smoke
/// -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench_smoke() {
    use std::time::Instant;
    let mut store = new_store();
    let n = 100_000u64;
    let t0 = Instant::now();
    for chunk in (0..n).collect::<Vec<_>>().chunks(1000) {
        let batch: Vec<_> = chunk.iter().map(|i| (key(*i), Some(val(*i)))).collect();
        store.put_batch(&batch).unwrap();
    }
    let build = t0.elapsed();

    let t1 = Instant::now();
    let mut reads = 0usize;
    let samples = 10_000u64;
    for i in 0..samples {
        let k = key((i * 7919) % n);
        store.backend().reset_reads();
        assert!(store.get(&k).unwrap().is_some());
        reads += store.backend().reads();
    }
    let get_time = t1.elapsed();
    println!(
        "bench_smoke: n={n} build={build:?} ({:.1}µs/op) get={get_time:?} \
         ({:.1}µs/op, {:.2} backend reads/op incl. value)",
        build.as_micros() as f64 / n as f64,
        get_time.as_micros() as f64 / samples as f64,
        reads as f64 / samples as f64,
    );
}

// ---------------------------------------------------------------------------
//  Forks (transaction overlays)
// ---------------------------------------------------------------------------

#[test]
fn fork_reads_through_overlay_and_store() {
    let mut store = new_store();
    store.put_batch(&[(key(1), Some(val(1))), (key(2), Some(val(2)))]).unwrap();

    let mut fork = crate::fork::MerkleFork::new(&mut store);
    // Read-through to the store.
    assert_eq!(fork.get(&key(1)).unwrap(), Some(val(1)));
    // Overlay wins over the store.
    fork.put(&key(1), &val(100));
    assert_eq!(fork.get(&key(1)).unwrap(), Some(val(100)));
    // Overlay delete hides the stored value.
    fork.delete(&key(2));
    assert_eq!(fork.get(&key(2)).unwrap(), None);
    // New key visible only in the fork.
    fork.put(&key(3), &val(3));
    assert_eq!(fork.get(&key(3)).unwrap(), Some(val(3)));

    // Nothing committed: the store is untouched after the fork drops.
    drop(fork);
    assert_eq!(store.get(&key(1)).unwrap(), Some(val(1)));
    assert_eq!(store.get(&key(2)).unwrap(), Some(val(2)));
    assert_eq!(store.get(&key(3)).unwrap(), None);
}

#[test]
fn sealed_fork_root_matches_actual_commit() {
    let mut store = new_store();
    store.put_batch(&[(key(1), Some(val(1))), (key(2), Some(val(2)))]).unwrap();
    let (root_before, v_before) = store.root();

    let mut fork = crate::fork::MerkleFork::new(&mut store);
    fork.put(&key(1), &val(100));
    fork.delete(&key(2));
    fork.put(&key(9), &val(9));
    let sealed = fork.seal().unwrap();

    assert_eq!(sealed.root_before, root_before);
    assert_eq!(sealed.version_before, v_before);
    assert_ne!(sealed.root_after, root_before);
    assert_eq!(sealed.version_after, v_before + 1);
    // Sealing did not commit.
    assert_eq!(store.root(), (root_before, v_before));

    // Applying the sealed write-set produces exactly the previewed root.
    let (root, version) = store.put_batch(&sealed.ops).unwrap();
    assert_eq!((root, version), (sealed.root_after, sealed.version_after));
    assert_eq!(store.get(&key(1)).unwrap(), Some(val(100)));
    assert_eq!(store.get(&key(2)).unwrap(), None);
}

#[test]
fn sealed_fork_applies_identically_on_replica_with_different_storage_key() {
    // The BFT requirement, fork edition: a write-set sealed on one node
    // produces the same root_after on a replica sharing ck but holding
    // a different storage key.
    let mut leader = new_store();
    let mut replica = MerkleStore::create(MemBackend::new(), CK, [0x77; 32]).unwrap();
    let genesis = &[(key(1), Some(val(1))), (key(2), Some(val(2)))];
    leader.put_batch(genesis).unwrap();
    replica.put_batch(genesis).unwrap();
    assert_eq!(leader.root(), replica.root());

    let mut fork = crate::fork::MerkleFork::new(&mut leader);
    fork.put(&key(5), &val(5));
    fork.delete(&key(1));
    let sealed = fork.seal().unwrap();

    // Replica checks root_before, applies the write-set, checks root_after.
    assert_eq!(replica.root().0, sealed.root_before);
    let (r_root, r_version) = replica.put_batch(&sealed.ops).unwrap();
    assert_eq!((r_root, r_version), (sealed.root_after, sealed.version_after));

    let (l_root, _) = leader.put_batch(&sealed.ops).unwrap();
    assert_eq!(l_root, r_root);
}

#[test]
fn noop_fork_seals_to_unchanged_root() {
    let mut store = new_store();
    store.put_batch(&[(key(1), Some(val(1)))]).unwrap();
    let before = store.root();

    let mut fork = crate::fork::MerkleFork::new(&mut store);
    fork.put(&key(1), &val(1)); // same value: ineffective
    fork.delete(&key(42)); // absent key: ineffective
    let sealed = fork.seal().unwrap();
    assert!(sealed.is_noop());
    assert_eq!(sealed.root_after, before.0);
    assert_eq!(sealed.version_after, before.1);
}

#[test]
fn preview_batch_does_not_mutate() {
    let mut store = new_store();
    store.put_batch(&[(key(1), Some(val(1)))]).unwrap();
    let before = store.root();
    let ops = vec![(key(2), Some(val(2)))];
    let (preview_root, preview_version) = store.preview_batch(&ops).unwrap();
    assert_ne!(preview_root, before.0);
    assert_eq!(store.root(), before, "preview must not commit");
    // Previewing twice is stable, and committing matches the preview.
    assert_eq!(store.preview_batch(&ops).unwrap(), (preview_root, preview_version));
    assert_eq!(store.put_batch(&ops).unwrap(), (preview_root, preview_version));
}
