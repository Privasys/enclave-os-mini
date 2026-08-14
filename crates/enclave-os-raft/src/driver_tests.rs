// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Driver + log-store tests: a mini cluster of full [`RaftDriver`]s
//! over shared in-memory backends, exercising the production Ready
//! loop, encrypted log recovery, restart replay (including the
//! applied-floor crash window) and tamper fail-closed behaviour.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use enclave_os_common::rpc::KvBatchOp;
use enclave_os_merkle::{KvBackend, MemBackend, MerkleError, MerkleStore};

use crate::core::{Config, Ready};
use crate::driver::RaftDriver;
use crate::logstore::{LogError, LogStore};
use crate::message::Message;
use crate::types::{Entry, EntryKind, HardState, Membership, NodeId, Role};

const CK: [u8; 32] = [0x11; 32];
const LOG_KEY: [u8; 32] = [0x33; 32];

/// Shareable in-memory backend: several store instances over the same
/// data, so a "restart" can reopen what the previous instance wrote.
#[derive(Clone)]
struct SharedMem(Arc<MemBackend>);

impl SharedMem {
    fn new() -> Self {
        Self(Arc::new(MemBackend::new()))
    }
}

impl KvBackend for SharedMem {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleError> {
        self.0.get(key)
    }
    fn write_batch(&self, ops: Vec<KvBatchOp>) -> Result<(), MerkleError> {
        self.0.write_batch(ops)
    }
    fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, MerkleError> {
        self.0.scan(start, end, limit)
    }
}

fn sk(id: NodeId) -> [u8; 32] {
    [id as u8 + 1; 32]
}

struct MiniCluster {
    drivers: BTreeMap<NodeId, RaftDriver<SharedMem>>,
    /// Per node: (log backend, ledger backend), kept for restarts.
    backends: BTreeMap<NodeId, (SharedMem, SharedMem)>,
    queue: VecDeque<(NodeId, Message)>,
}

impl MiniCluster {
    fn new(n: u64) -> Self {
        let ids: Vec<NodeId> = (1..=n).collect();
        let mut drivers = BTreeMap::new();
        let mut backends = BTreeMap::new();
        for &id in &ids {
            let log_b = SharedMem::new();
            let ledger_b = SharedMem::new();
            let store = MerkleStore::create(ledger_b.clone(), CK, sk(id)).unwrap();
            let driver = RaftDriver::bootstrap(
                Config::new(id, 0, id.wrapping_mul(7919)),
                &ids,
                log_b.clone(),
                LOG_KEY,
                store,
            )
            .unwrap();
            drivers.insert(id, driver);
            backends.insert(id, (log_b, ledger_b));
        }
        Self { drivers, backends, queue: VecDeque::new() }
    }

    fn pump(&mut self) {
        for _ in 0..100_000 {
            let Some((to, msg)) = self.queue.pop_front() else { return };
            let Some(driver) = self.drivers.get_mut(&to) else { continue };
            let out = driver.step(msg).expect("driver step");
            self.queue.extend(out.messages);
        }
        panic!("mini cluster did not quiesce");
    }

    fn tick_all(&mut self) {
        let ids: Vec<NodeId> = self.drivers.keys().copied().collect();
        for id in ids {
            let out = self.drivers.get_mut(&id).unwrap().tick().expect("driver tick");
            self.queue.extend(out.messages);
        }
        self.pump();
    }

    fn wait_for_leader(&mut self, max_ticks: u32) -> NodeId {
        for _ in 0..max_ticks {
            self.tick_all();
            if let Some(l) = self.leader() {
                if self.drivers[&l].core().commit_index() >= 1 {
                    return l;
                }
            }
        }
        panic!("no leader");
    }

    fn leader(&self) -> Option<NodeId> {
        self.drivers
            .iter()
            .filter(|(_, d)| d.core().role() == Role::Leader)
            .max_by_key(|(_, d)| d.core().term())
            .map(|(&id, _)| id)
    }

    fn propose_txn(&mut self, ops: &[(&[u8], Option<&[u8]>)]) {
        let l = self.leader().expect("leader");
        let ops: Vec<(Vec<u8>, Option<Vec<u8>>)> =
            ops.iter().map(|(k, v)| (k.to_vec(), v.map(|v| v.to_vec()))).collect();
        let (_, out) =
            self.drivers.get_mut(&l).unwrap().propose_transaction(&ops).expect("propose");
        self.queue.extend(out.messages);
        self.pump();
    }

    /// Restart a node from its persisted backends (fresh incarnation).
    fn restart(&mut self, id: NodeId, incarnation: u64) {
        let (log_b, ledger_b) = self.backends[&id].clone();
        self.drivers.remove(&id);
        let store = MerkleStore::open_latest(ledger_b, CK, sk(id)).unwrap();
        let driver = RaftDriver::restore(
            Config::new(id, incarnation, id.wrapping_mul(7919).wrapping_add(incarnation)),
            log_b,
            LOG_KEY,
            store,
        )
        .unwrap();
        self.drivers.insert(id, driver);
    }

    fn root(&self, id: NodeId) -> [u8; 32] {
        self.drivers[&id].ledger().root().0
    }
}

// ── Log store units ─────────────────────────────────────────────────

fn entry(term: u64, index: u64, data: &[u8]) -> Entry {
    Entry { term, index, kind: EntryKind::App, data: data.to_vec() }
}

#[test]
fn logstore_persists_and_recovers() {
    let backend = SharedMem::new();
    let genesis = Membership::bootstrap(&[1, 2, 3]);
    let mut log = LogStore::create(backend.clone(), LOG_KEY, &genesis).unwrap();

    let ready = Ready {
        entries_to_persist: vec![entry(1, 1, b"a"), entry(1, 2, b"b"), entry(2, 3, b"c")],
        hard_state: Some(HardState { term: 2, voted_for: Some(3) }),
        ..Default::default()
    };
    log.persist(&ready).unwrap();
    log.set_applied_floor(2).unwrap();

    // Truncate the divergent suffix and replace it.
    let ready = Ready {
        truncate_from: Some(3),
        entries_to_persist: vec![entry(3, 3, b"c2"), entry(3, 4, b"d")],
        ..Default::default()
    };
    log.persist(&ready).unwrap();
    assert_eq!(log.last_index(), 4);

    let (log2, recovered) = LogStore::open(backend, LOG_KEY).unwrap();
    assert_eq!(log2.last_index(), 4);
    assert_eq!(recovered.genesis, genesis);
    assert_eq!(recovered.hard_state, HardState { term: 2, voted_for: Some(3) });
    assert_eq!(recovered.applied_floor, 2);
    let data: Vec<&[u8]> = recovered.entries.iter().map(|e| e.data.as_slice()).collect();
    assert_eq!(data, vec![b"a" as &[u8], b"b", b"c2", b"d"]);
    assert_eq!(recovered.entries[2].term, 3);
}

#[test]
fn logstore_fails_closed_on_tamper() {
    let backend = SharedMem::new();
    let genesis = Membership::bootstrap(&[1]);
    let mut log = LogStore::create(backend.clone(), LOG_KEY, &genesis).unwrap();
    log.persist(&Ready {
        entries_to_persist: vec![entry(1, 1, b"secret")],
        hard_state: Some(HardState { term: 1, voted_for: None }),
        ..Default::default()
    })
    .unwrap();

    // Tamper each record in turn; every open must fail closed.
    for key in backend.0.keys() {
        assert!(backend.0.tamper(&key));
        match LogStore::open(backend.clone(), LOG_KEY) {
            Err(LogError::Corrupted(_)) => {}
            other => panic!("tampered {:?} not detected: {:?}", key, other.is_ok()),
        }
        assert!(backend.0.tamper(&key)); // untamper (bit flip back)
    }
    // Sanity: untouched log opens fine.
    assert!(LogStore::open(backend, LOG_KEY).is_ok());
}

#[test]
fn logstore_wrong_key_fails() {
    let backend = SharedMem::new();
    let genesis = Membership::bootstrap(&[1]);
    LogStore::create(backend.clone(), LOG_KEY, &genesis).unwrap();
    assert!(matches!(
        LogStore::open(backend, [0x44; 32]),
        Err(LogError::Corrupted(_))
    ));
}

// ── Full driver cluster ─────────────────────────────────────────────

#[test]
fn driver_cluster_commits_transactions() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.propose_txn(&[(b"alice", Some(b"1000")), (b"bob", Some(b"250"))]);
    c.propose_txn(&[(b"alice", Some(b"900"))]);
    c.tick_all();
    c.tick_all();

    let root = c.root(l);
    for id in 1..=3 {
        assert_eq!(c.root(id), root, "node {id} diverged");
        let store = c.drivers[&id].ledger().store();
        assert_eq!(store.get(b"alice").unwrap(), Some(b"900".to_vec()));
        assert!(!c.drivers[&id].is_halted());
    }
    let leader = c.drivers[&l].core();
    assert_eq!(leader.verified_index(), leader.commit_index());
}

#[test]
fn driver_restart_recovers_from_checkpoint_without_replay_divergence() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.propose_txn(&[(b"k1", Some(b"v1"))]);
    c.propose_txn(&[(b"k2", Some(b"v2")), (b"k1", None)]);
    c.tick_all();
    let root = c.root(l);

    // Restart a follower: ledger restores from its checkpoint, the log
    // replays, and the applied-floor rule must not re-apply anything.
    let f = (1..=3).find(|&id| id != l).unwrap();
    c.restart(f, 1);
    assert_eq!(c.root(f), root, "checkpoint restore lost state");
    assert!(!c.drivers[&f].is_halted());

    // The restarted node keeps working (and gets re-admitted).
    for _ in 0..30 {
        c.tick_all();
    }
    c.propose_txn(&[(b"k3", Some(b"v3"))]);
    c.tick_all();
    assert_eq!(c.root(f), c.root(l));
    assert!(c.drivers[&f].core().self_admitted());
}

/// The crash window: the ledger checkpoint outran the persisted applied
/// floor by one batch. The replay rule (`root_after == current root` ⇒
/// already applied) must absorb it without divergence.
#[test]
fn driver_restart_absorbs_applied_floor_lag() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.propose_txn(&[(b"x", Some(b"1"))]);
    c.propose_txn(&[(b"y", Some(b"2"))]);
    c.tick_all();
    let root = c.root(l);

    let f = (1..=3).find(|&id| id != l).unwrap();
    // Simulate the crash: roll the persisted floor back by one batch
    // (as if the crash hit after the merkle commit, before the floor
    // write). The ledger checkpoint stays ahead.
    {
        let (log_b, _) = c.backends[&f].clone();
        let (_, recovered) = LogStore::open(log_b.clone(), LOG_KEY).unwrap();
        assert!(recovered.applied_floor >= 2);
        let (mut log, _) = LogStore::open(log_b, LOG_KEY).unwrap();
        log.set_applied_floor(recovered.applied_floor - 1).unwrap();
    }
    c.restart(f, 1);
    assert!(!c.drivers[&f].is_halted(), "floor lag must not read as divergence");
    assert_eq!(c.root(f), root);

    for _ in 0..30 {
        c.tick_all();
    }
    c.propose_txn(&[(b"z", Some(b"3"))]);
    c.tick_all();
    assert_eq!(c.root(f), c.root(l));
}
