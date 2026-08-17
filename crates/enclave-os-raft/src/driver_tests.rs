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
    /// Driver events surfaced by any node: `(node, event)`.
    events: Vec<(NodeId, crate::core::RaftEvent)>,
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
        Self { drivers, backends, queue: VecDeque::new(), events: Vec::new() }
    }

    fn pump(&mut self) {
        for _ in 0..100_000 {
            let Some((to, msg)) = self.queue.pop_front() else { return };
            let Some(driver) = self.drivers.get_mut(&to) else { continue };
            let out = driver.step(msg).expect("driver step");
            self.queue.extend(out.messages);
            self.events.extend(out.events.into_iter().map(|e| (to, e)));
        }
        panic!("mini cluster did not quiesce");
    }

    fn tick_all(&mut self) {
        let ids: Vec<NodeId> = self.drivers.keys().copied().collect();
        for id in ids {
            let out = self.drivers.get_mut(&id).unwrap().tick().expect("driver tick");
            self.queue.extend(out.messages);
            self.events.extend(out.events.into_iter().map(|e| (id, e)));
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

/// A diverged ledger is repaired by full replay: fresh store, zeroed
/// applied floor, every committed transaction re-applies from the log.
#[test]
fn driver_rebuild_repairs_diverged_ledger() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.propose_txn(&[(b"a", Some(b"1"))]);
    c.propose_txn(&[(b"b", Some(b"2"))]);
    c.tick_all();
    let root = c.root(l);

    // Corrupt a follower's ledger out-of-band (the host cannot do this
    // undetected — this models a diverged replica after the fact).
    let f = (1..=3).find(|&id| id != l).unwrap();
    c.drivers
        .get_mut(&f)
        .unwrap()
        .ledger_mut()
        .store_mut()
        .put_batch(&[(b"__evil__".to_vec(), Some(b"x".to_vec()))])
        .unwrap();
    assert_ne!(c.root(f), root);

    // The next committed transaction fails its root_before check.
    let ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![(b"c".to_vec(), Some(b"3".to_vec()))];
    let (_, out) = c.drivers.get_mut(&l).unwrap().propose_transaction(&ops).unwrap();
    c.queue.extend(out.messages);
    // Pump manually: the diverged follower's step returns Diverged.
    let mut diverged = false;
    for _ in 0..10_000 {
        let Some((to, msg)) = c.queue.pop_front() else { break };
        match c.drivers.get_mut(&to).unwrap().step(msg) {
            Ok(out) => c.queue.extend(out.messages),
            Err(crate::driver::DriverError::Diverged { .. }) => {
                assert_eq!(to, f);
                diverged = true;
            }
            Err(e) => panic!("unexpected driver error: {e:?}"),
        }
    }
    assert!(diverged, "divergence must be detected");
    assert!(c.drivers[&f].is_halted());

    // Repair: fresh ledger over the same backend, full replay.
    let (log_b, ledger_b) = c.backends[&f].clone();
    c.drivers.remove(&f);
    let fresh = MerkleStore::create(ledger_b, CK, sk(f)).unwrap();
    let driver = RaftDriver::rebuild(
        Config::new(f, 999, f.wrapping_mul(7919).wrapping_add(999)),
        log_b,
        LOG_KEY,
        fresh,
    )
    .unwrap();
    c.drivers.insert(f, driver);

    // The repaired node replays, catches up and re-verifies.
    for _ in 0..40 {
        c.tick_all();
    }
    assert!(!c.drivers[&f].is_halted());
    assert_eq!(c.root(f), c.root(l));
    let store = c.drivers[&f].ledger().store();
    assert_eq!(store.get(b"c").unwrap(), Some(b"3".to_vec()));
    assert_eq!(store.get(b"__evil__").unwrap(), None, "corruption gone after rebuild");
}

/// A brand-new node (not in genesis) joins as a learner via config
/// change, catches up by log replication, and is promoted to voter.
#[test]
fn driver_learner_joins_and_promotes() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.propose_txn(&[(b"base", Some(b"1"))]);
    c.tick_all();

    // Node 4: knows the CLUSTER's genesis voters (1..3), is not one.
    let log_b = SharedMem::new();
    let ledger_b = SharedMem::new();
    let store = MerkleStore::create(ledger_b.clone(), CK, sk(4)).unwrap();
    let driver = RaftDriver::bootstrap(
        Config::new(4, 7, 4 * 7919),
        &[1, 2, 3], // cluster genesis, not including itself
        log_b.clone(),
        LOG_KEY,
        store,
    )
    .unwrap();
    c.drivers.insert(4, driver);
    c.backends.insert(4, (log_b, ledger_b));

    let (_, out) = c
        .drivers
        .get_mut(&l)
        .unwrap()
        .propose_conf_change(crate::types::ConfigChange::AddLearner { node: 4 })
        .unwrap();
    c.queue.extend(out.messages);
    c.pump();
    for _ in 0..20 {
        c.tick_all();
    }
    assert_eq!(c.root(4), c.root(l), "learner failed to catch up");
    assert!(!c.drivers[&4].core().membership().is_voter(4));

    let inc = c.drivers[&l].core().peer_incarnation(4).expect("leader saw learner");
    let (_, out) = c
        .drivers
        .get_mut(&l)
        .unwrap()
        .propose_conf_change(crate::types::ConfigChange::PromoteVoter { node: 4, incarnation: inc })
        .unwrap();
    c.queue.extend(out.messages);
    c.pump();
    for _ in 0..10 {
        c.tick_all();
    }
    assert!(c.drivers[&l].core().membership().is_voter(4));
    assert!(c.drivers[&4].core().self_admitted());

    // The new voter counts: 4-voter quorum (3) survives one crash.
    let crash = (1..=3).find(|&id| id != l).unwrap();
    c.drivers.remove(&crash);
    c.propose_txn(&[(b"after", Some(b"2"))]);
    for _ in 0..10 {
        c.tick_all();
    }
    assert_eq!(c.drivers[&4].ledger().store().get(b"after").unwrap(), Some(b"2".to_vec()));
}

// ── Log compaction + snapshot install (phase 2) ─────────────────────

impl MiniCluster {
    fn txn(&mut self, k: &[u8], v: &[u8]) {
        self.propose_txn(&[(k, Some(v))]);
        self.tick_all();
    }
}

#[test]
fn compaction_preserves_operation_and_restart() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    for i in 0..8u8 {
        c.txn(&[b'k', i], &[i]);
    }

    // Compact everywhere through the applied index.
    let ids: Vec<NodeId> = c.drivers.keys().copied().collect();
    for id in &ids {
        let applied = c.drivers[id].core().applied_index();
        c.drivers.get_mut(id).unwrap().compact_to(applied).unwrap();
        let (base, _) = c.drivers[id].core().base();
        assert_eq!(base, applied);
        assert!(c.drivers[id].core().entries().is_empty());
    }

    // The cluster keeps committing after compaction.
    c.txn(b"post", b"1");
    for id in &ids {
        assert_eq!(
            c.drivers[id].ledger().store().get(b"post").unwrap(),
            Some(b"1".to_vec())
        );
    }

    // A restart from the compacted log recovers cleanly.
    let f = (1..=3).find(|&id| id != l).unwrap();
    c.restart(f, 41);
    assert!(!c.drivers[&f].is_halted());
    for _ in 0..30 {
        c.tick_all();
    }
    c.txn(b"post2", b"2");
    assert_eq!(
        c.drivers[&f].ledger().store().get(b"post2").unwrap(),
        Some(b"2".to_vec())
    );
    assert_eq!(c.root(f), c.root(l));
    assert!(c.drivers[&f].core().self_admitted());
}

/// A follower that fell behind the leader's compaction base cannot be
/// served from the log: the leader signals SnapshotNeeded, the driver
/// streams the ledger via the merkle snapshot primitives, the follower
/// installs and resumes ordinary replication.
#[test]
fn snapshot_transfer_catches_up_lagging_follower() {
    use enclave_os_merkle::SnapshotBuilder;

    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    c.txn(b"a", b"1");

    // Take a follower down, move on without it, then compact past
    // everything it ever saw.
    let f = (1..=3).find(|&id| id != l).unwrap();
    let dead = c.drivers.remove(&f).unwrap();
    drop(dead);
    for i in 0..5u8 {
        c.txn(&[b'x', i], &[i]);
    }
    let applied = c.drivers[&l].core().applied_index();
    c.drivers.get_mut(&l).unwrap().compact_to(applied).unwrap();

    // The follower returns from its old (pre-compaction) state.
    c.restart(f, 42);
    let mut snapshot_needed = false;
    for _ in 0..40 {
        c.tick_all();
        let evs = std::mem::take(&mut c.events);
        for (node, ev) in evs {
            if let crate::core::RaftEvent::SnapshotNeeded { node: target, .. } = ev {
                assert_eq!(node, l);
                assert_eq!(target, f);
                snapshot_needed = true;
            }
        }
        if snapshot_needed {
            break;
        }
    }
    assert!(snapshot_needed, "leader must request a snapshot transfer");

    // Driver-level transfer (the wire protocol is phase 3): stream the
    // leader's ledger at its checkpoint and rebuild on the follower
    // under the follower's OWN storage key.
    let (index, term) = c.drivers[&l].core().base();
    let membership = c.drivers[&l].core().membership().clone();
    let (root, version) = c.drivers[&l].ledger().root();
    let mut chunks: Vec<Vec<([u8; 32], Vec<u8>)>> = Vec::new();
    let mut start_after: Option<[u8; 32]> = None;
    loop {
        let (leaves, done) = c.drivers[&l]
            .ledger()
            .store()
            .snapshot_leaves(version, start_after.as_ref(), 3)
            .unwrap();
        start_after = leaves.last().map(|(p, _)| *p);
        chunks.push(leaves);
        if done {
            break;
        }
    }
    let fresh_backend = SharedMem::new();
    let mut builder = SnapshotBuilder::new(fresh_backend.clone(), CK, sk(f)).unwrap();
    for chunk in chunks {
        builder.add_leaves(chunk);
    }
    let restored = builder.finalize(root, version).unwrap();
    let installed = c
        .drivers
        .get_mut(&f)
        .unwrap()
        .install_snapshot_state(index, term, membership, restored)
        .unwrap();
    assert!(installed);
    c.backends.get_mut(&f).unwrap().1 = fresh_backend;

    // Transfer complete: the leader resumes appends from the base
    // (phase 3's SnapshotAck triggers this over the wire).
    let out = c.drivers.get_mut(&l).unwrap().snapshot_transferred(f, index).unwrap();
    c.queue.extend(out.messages);
    c.pump();

    // Ordinary replication resumes past the base; everyone converges.
    for _ in 0..40 {
        c.tick_all();
    }
    c.txn(b"final", b"9");
    assert_eq!(c.root(f), c.root(l));
    let store = c.drivers[&f].ledger().store();
    assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(store.get(b"final").unwrap(), Some(b"9".to_vec()));
    assert!(c.drivers[&f].core().self_admitted(), "re-admitted after install");
}

#[test]
fn maybe_compact_policy() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    for i in 0..10u8 {
        c.txn(&[b'p', i], &[i]);
    }
    let d = c.drivers.get_mut(&l).unwrap();
    let applied = d.core().applied_index();
    // Span ≤ 2×retain: no-op.
    d.maybe_compact(applied).unwrap();
    assert_eq!(d.core().base().0, 0);
    // Span > 2×retain: compacts to applied - retain.
    d.maybe_compact(3).unwrap();
    assert_eq!(d.core().base().0, applied - 3);
}

/// The full phase-3 wire protocol: SnapshotNeeded fires, the sender
/// streams Start + ack-paced chunks over Messages, the receiver
/// rebuilds cross-key, installs, acks done, and appends resume.
#[test]
fn wire_snapshot_transfer_protocol() {
    use crate::message::MsgMeta;
    use crate::transfer::{ReceiverStep, SenderStep, SnapshotReceiver, SnapshotSender};

    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(300);
    for i in 0..9u8 {
        c.txn(&[b'w', i], &[i]);
    }

    // A follower misses everything past its crash, and the leader
    // compacts beyond it.
    let f = (1..=3).find(|&id| id != l).unwrap();
    drop(c.drivers.remove(&f).unwrap());
    for i in 9..14u8 {
        c.txn(&[b'w', i], &[i]);
    }
    let applied = c.drivers[&l].core().applied_index();
    c.drivers.get_mut(&l).unwrap().compact_to(applied).unwrap();
    c.restart(f, 77);
    let mut needed = false;
    for _ in 0..40 {
        c.tick_all();
        if c.events.iter().any(|(_, ev)| {
            matches!(ev, crate::core::RaftEvent::SnapshotNeeded { node, .. } if *node == f)
        }) {
            needed = true;
            break;
        }
    }
    assert!(needed);

    let meta = |from: NodeId| MsgMeta { from, term: 0, incarnation: 0 };

    // Sender start (leader side): pins the ledger version.
    let (mut sender, start_msg) =
        SnapshotSender::start(c.drivers.get_mut(&l).unwrap(), f, meta(l));

    // Receiver start (follower side) over a fresh ledger backend.
    let fresh = SharedMem::new();
    let Message::SnapshotStart { index, term, ledger_version, root, membership, .. } =
        start_msg
    else {
        panic!("expected SnapshotStart")
    };
    let (receiver, first_ack) = SnapshotReceiver::start(
        l,
        index,
        term,
        ledger_version,
        root,
        membership,
        fresh.clone(),
        CK,
        sk(f),
        meta(f),
    )
    .unwrap();
    let mut receiver = Some(receiver);

    // Ack-paced chunk loop, entirely over Messages.
    let mut ack = first_ack;
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 10_000, "transfer did not converge");
        let Message::SnapshotAck { seq, done, .. } = ack else { panic!("expected ack") };
        match sender.on_ack(&c.drivers[&l], meta(l), seq, done).unwrap() {
            SenderStep::Send(Message::SnapshotChunk { seq, leaves, done, .. }) => {
                let (next, step) = receiver
                    .take()
                    .expect("receiver still active")
                    .on_chunk(
                        c.drivers.get_mut(&f).unwrap(),
                        meta(f),
                        seq,
                        leaves,
                        done,
                    )
                    .unwrap();
                match step {
                    ReceiverStep::Ack(a) => {
                        receiver = Some(next.expect("transfer continues"));
                        ack = a;
                    }
                    ReceiverStep::Installed(a) => {
                        assert!(next.is_none());
                        ack = a;
                    }
                }
            }
            SenderStep::Send(_) => panic!("sender must send chunks"),
            SenderStep::Finished { index } => {
                c.drivers.get_mut(&l).unwrap().ledger_pin(None);
                let out =
                    c.drivers.get_mut(&l).unwrap().snapshot_transferred(f, index).unwrap();
                c.queue.extend(out.messages);
                break;
            }
            SenderStep::Ignore => panic!("unexpected stale ack"),
        }
    }
    c.backends.get_mut(&f).unwrap().1 = fresh;
    c.pump();

    // Ordinary replication resumes; the follower converges fully.
    for _ in 0..40 {
        c.tick_all();
    }
    c.txn(b"tail", b"1");
    assert_eq!(c.root(f), c.root(l));
    let store = c.drivers[&f].ledger().store();
    assert_eq!(store.get(&[b'w', 0]).unwrap(), Some(vec![0]));
    assert_eq!(store.get(&[b'w', 13]).unwrap(), Some(vec![13]));
    assert_eq!(store.get(b"tail").unwrap(), Some(b"1".to_vec()));
    assert!(c.drivers[&f].core().self_admitted());
}

#[test]
fn snapshot_message_codec_roundtrip() {
    use crate::message::MsgMeta;
    let meta = MsgMeta { from: 1, term: 2, incarnation: 3 };
    let m = Message::SnapshotStart {
        meta,
        index: 9,
        term: 2,
        ledger_version: 5,
        root: [0xAA; 32],
        membership: Membership::bootstrap(&[1, 2, 3]),
    };
    assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    let m = Message::SnapshotChunk {
        meta,
        seq: 4,
        leaves: vec![([1; 32], b"v1".to_vec()), ([2; 32], Vec::new())],
        done: true,
    };
    assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    let m = Message::SnapshotAck { meta, seq: 4, done: false };
    assert_eq!(Message::decode(&m.encode()).unwrap(), m);
}

/// Commit certificates: keys announced via Hello, registered by the
/// leader through the log, signatures collected from root reports, a
/// quorum certificate assembled and offline-verifiable — with tampered
/// signatures and roots rejected.
#[test]
fn commit_certificates_assemble_and_verify() {
    let mut c = MiniCluster::new(3);
    for id in 1..=3u64 {
        let seed = [id as u8 + 0x40; 32];
        c.drivers.get_mut(&id).unwrap().set_signer(&seed);
    }
    let l = c.wait_for_leader(300);

    // Hellos carry the followers' signing keys to the leader (the
    // transport sends these on link establishment).
    let hellos: Vec<Message> =
        (1..=3).filter(|&i| i != l).map(|i| c.drivers[&i].core().hello()).collect();
    for h in hellos {
        let out = c.drivers.get_mut(&l).unwrap().step(h).unwrap();
        c.queue.extend(out.messages);
    }
    c.pump();
    // Key registrations commit one config change at a time.
    for _ in 0..40 {
        c.tick_all();
        if c.drivers[&l].core().membership().keys.len() == 3 {
            break;
        }
    }
    let m = c.drivers[&l].core().membership().clone();
    assert_eq!(m.keys.len(), 3, "all signing keys registered");

    c.txn(b"certified", b"1");
    for _ in 0..10 {
        c.tick_all();
    }

    let cert = c.drivers[&l].core().latest_certificate().expect("certificate").clone();
    assert!(cert.sigs.len() >= m.quorum(), "quorum of signatures");
    assert!(cert.verify(&m), "certificate verifies against registered keys");

    // A tampered signature poisons the certificate.
    let mut bad = cert.clone();
    let k = *bad.sigs.keys().next().unwrap();
    bad.sigs.get_mut(&k).unwrap()[0] ^= 1;
    assert!(!bad.verify(&m));

    // A tampered root fails every signature.
    let mut bad = cert.clone();
    bad.root[0] ^= 1;
    assert!(!bad.verify(&m));

    // A certificate signed by fewer than a quorum does not verify.
    let mut thin = cert.clone();
    while thin.sigs.len() >= m.quorum() {
        let k = *thin.sigs.keys().next().unwrap();
        thin.sigs.remove(&k);
    }
    assert!(!thin.verify(&m));
}

// ── Replay mode: deterministic re-execution at apply time ───────────

#[test]
fn replay_reexecution_verifies_and_converges() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(50);
    // Every node re-executes deterministically from the envelope: the
    // mock app writes value = seed[..8] under the key in params.
    for d in c.drivers.values_mut() {
        d.set_replay_verifier(Box::new(|env, fork| {
            fork.put(&env.params, &env.seed[..8]);
            Ok(())
        }));
    }
    let env = crate::transaction::ReplayEnvelope {
        app: b"mock".to_vec(),
        function: b"credit".to_vec(),
        params: b"acct".to_vec(),
        seed: [9; 32],
        timestamp_ms: 1_234,
        fuel: 10_000,
    };
    let key = env.params.clone();
    let val = env.seed[..8].to_vec();
    let (_, _, out) = c
        .drivers
        .get_mut(&l)
        .unwrap()
        .propose_with(Some(env), move |fork| {
            fork.put(&key, &val);
            Ok(())
        })
        .expect("propose");
    c.queue.extend(out.messages);
    c.pump();
    for _ in 0..5 {
        c.tick_all();
    }
    // All three applied through re-execution and agree.
    let r = c.root(1);
    assert_eq!(r, c.root(2));
    assert_eq!(r, c.root(3));
    for d in c.drivers.values() {
        assert!(!d.is_halted());
    }
}

#[test]
fn replay_divergent_reexecution_fails_closed() {
    let mut c = MiniCluster::new(3);
    let l = c.wait_for_leader(50);
    let bad = *c.drivers.keys().find(|&&id| id != l).unwrap();
    for (&id, d) in c.drivers.iter_mut() {
        let divergent = id == bad;
        d.set_replay_verifier(Box::new(move |env, fork| {
            if divergent {
                fork.put(b"evil", b"other");
            } else {
                fork.put(&env.params, &env.seed[..8]);
            }
            Ok(())
        }));
    }
    let env = crate::transaction::ReplayEnvelope {
        app: b"mock".to_vec(),
        function: b"credit".to_vec(),
        params: b"acct".to_vec(),
        seed: [7; 32],
        timestamp_ms: 1,
        fuel: 10_000,
    };
    let key = env.params.clone();
    let val = env.seed[..8].to_vec();
    let (_, _, out) = c
        .drivers
        .get_mut(&l)
        .unwrap()
        .propose_with(Some(env), move |fork| {
            fork.put(&key, &val);
            Ok(())
        })
        .expect("propose");
    c.queue.extend(out.messages);
    // Manual pump: the divergent node halts with Diverged; everyone
    // else proceeds.
    let mut diverged = false;
    let mut hops = 0;
    while let Some((to, msg)) = c.queue.pop_front() {
        hops += 1;
        assert!(hops < 100_000);
        let Some(d) = c.drivers.get_mut(&to) else { continue };
        match d.step(msg) {
            Ok(out) => c.queue.extend(out.messages),
            Err(crate::driver::DriverError::Diverged { .. }) if to == bad => {
                diverged = true;
            }
            Err(e) => panic!("unexpected driver error: {e:?}"),
        }
    }
    assert!(diverged, "the divergent node must fail closed");
    assert!(c.drivers[&bad].is_halted());
    // The honest quorum agrees and is live.
    let honest: Vec<NodeId> = c.drivers.keys().copied().filter(|&id| id != bad).collect();
    assert_eq!(c.root(honest[0]), c.root(honest[1]));
}
