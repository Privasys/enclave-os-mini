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
    store.put_batch(&[(b"k".to_vec(), Some(b"v".to_vec()))]).unwrap();
    for rk in store.backend().keys() {
        if rk[0] == b'r' {
            continue; // root records are not on the live read path
        }
        store.backend().remove(&rk);
        match store.get(b"k") {
            Err(MerkleError::Missing(_)) | Err(MerkleError::Corrupted(_)) => {}
            other => panic!("expected fail-closed, got {other:?}"),
        }
        // Rebuild the store for the next iteration.
        store = new_store();
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
//  I/O complexity
// ---------------------------------------------------------------------------

#[test]
fn point_lookups_stay_logarithmic() {
    let mut store = new_store();
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
