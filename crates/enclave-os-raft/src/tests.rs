// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Simulated-cluster test suite.
//!
//! The simulator drives real `RaftCore` instances over an in-memory
//! network with controllable loss, duplication, reordering and
//! partitions, honouring the driver contract (truncate → persist →
//! send → apply). Invariants checked continuously:
//!
//! - election safety: at most one leader per term, ever
//! - log matching: same (index, term) ⇒ same entry
//! - applied prefix: all state machines apply the same sequence
//! - committed durability: the applied sequence never rewrites history

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use enclave_os_merkle::{MemBackend, MerkleStore};

use crate::core::{Config, ProposeError, RaftCore, RaftEvent};
use crate::ledger::{LedgerError, MerkleLedger};
use crate::message::{Message, MsgMeta};
use crate::transaction::Transaction;
use crate::types::{
    ConfigChange, Entry, EntryKind, HardState, Incarnation, Index, Membership, NodeId, Role,
};

/// Cluster commitment key (shared) — per-node storage keys differ, the
/// whole point of the encryption-independent root.
const CK: [u8; 32] = [0x11; 32];

fn node_ledger(id: NodeId) -> MerkleLedger<MemBackend> {
    let sk = [id as u8 + 1; 32];
    MerkleLedger::new(MerkleStore::create(MemBackend::new(), CK, sk).unwrap())
}

// ── Deterministic RNG (same construction as the merkle test suite) ──

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn pct(&mut self) -> u64 {
        self.next() % 100
    }
}

// ── Simulator ───────────────────────────────────────────────────────

struct SimNode {
    core: RaftCore,
    /// Persisted mirror of the log (what survives a restart).
    disk_log: Vec<Entry>,
    /// Persisted mirror of the hard state.
    disk_hs: HardState,
    /// The state machine: every committed entry applied, in order.
    applied: Vec<Entry>,
    /// The Merkle ledger this node maintains (its own storage key).
    ledger: MerkleLedger<MemBackend>,
    /// Set when a transaction failed root verification: the node has
    /// diverged and stopped serving (awaiting WS4 snapshot repair).
    halted: bool,
    /// Fault injection: apply committed write-sets WITH an extra sneaky
    /// op, computing a divergent root (a corrupted replica).
    sabotage: bool,
    alive: bool,
    seed: u64,
}

struct Sim {
    nodes: BTreeMap<NodeId, SimNode>,
    genesis: Membership,
    inflight: VecDeque<(NodeId, Message)>, // (destination, msg)
    rng: Rng,
    drop_pct: u64,
    dup_pct: u64,
    reorder: bool,
    /// Directed blocked pairs (from, to).
    blocked: BTreeSet<(NodeId, NodeId)>,
    /// Election safety history: term → leader observed.
    leaders_by_term: BTreeMap<u64, NodeId>,
    /// Committed durability history: the longest applied sequence seen.
    history: Vec<Entry>,
    /// Verification events surfaced by any node: `(node, event)`.
    events: Vec<(NodeId, RaftEvent)>,
    next_incarnation: Incarnation,
}

impl Sim {
    fn new(n: u64, seed: u64) -> Self {
        let ids: Vec<NodeId> = (1..=n).collect();
        let genesis = Membership::bootstrap(&ids);
        let mut nodes = BTreeMap::new();
        for &id in &ids {
            let node_seed = seed.wrapping_add(id.wrapping_mul(7919));
            nodes.insert(
                id,
                SimNode {
                    core: RaftCore::new(
                        Config::new(id, 0, node_seed),
                        genesis.clone(),
                        Vec::new(),
                        HardState::default(),
                    ),
                    disk_log: Vec::new(),
                    disk_hs: HardState::default(),
                    applied: Vec::new(),
                    ledger: node_ledger(id),
                    halted: false,
                    sabotage: false,
                    alive: true,
                    seed: node_seed,
                },
            );
        }
        Self {
            nodes,
            genesis,
            inflight: VecDeque::new(),
            rng: Rng::new(seed),
            drop_pct: 0,
            dup_pct: 0,
            reorder: false,
            blocked: BTreeSet::new(),
            leaders_by_term: BTreeMap::new(),
            history: Vec::new(),
            events: Vec::new(),
            next_incarnation: 0,
        }
    }

    /// Add a node object that is not part of the genesis membership
    /// (it joins later via AddLearner).
    fn add_node(&mut self, id: NodeId) {
        let node_seed = 0xBEEF_u64.wrapping_add(id.wrapping_mul(7919));
        self.nodes.insert(
            id,
            SimNode {
                core: RaftCore::new(
                    Config::new(id, 0, node_seed),
                    self.genesis.clone(),
                    Vec::new(),
                    HardState::default(),
                ),
                disk_log: Vec::new(),
                disk_hs: HardState::default(),
                applied: Vec::new(),
                ledger: node_ledger(id),
                halted: false,
                sabotage: false,
                alive: true,
                seed: node_seed,
            },
        );
    }

    /// Drain every node's Ready (honouring the driver contract) and
    /// deliver all in-flight messages until the cluster is quiet.
    fn pump(&mut self) {
        for _ in 0..100_000 {
            let mut progressed = false;

            // 1. Drain readies: truncate → persist → send → apply.
            let ids: Vec<NodeId> = self.nodes.keys().copied().collect();
            for id in &ids {
                let node = self.nodes.get_mut(id).unwrap();
                if !node.alive {
                    continue;
                }
                let ready = node.core.ready();
                if ready.is_empty() {
                    continue;
                }
                progressed = true;
                if let Some(t) = ready.truncate_from {
                    node.disk_log.truncate(t as usize - 1);
                }
                for e in ready.entries_to_persist {
                    let pos = e.index as usize - 1;
                    if pos < node.disk_log.len() {
                        node.disk_log[pos] = e;
                    } else {
                        assert_eq!(pos, node.disk_log.len(), "non-contiguous persist");
                        node.disk_log.push(e);
                    }
                }
                if let Some(hs) = ready.hard_state {
                    node.disk_hs = hs;
                }
                for (to, msg) in ready.messages {
                    self.inflight.push_back((to, msg));
                }
                for ev in ready.events {
                    self.events.push((*id, ev));
                }
                let node = self.nodes.get_mut(id).unwrap();
                for e in ready.committed_entries {
                    node.applied.push(e.clone());
                    if node.halted {
                        continue; // diverged: stopped serving, no reports
                    }
                    // Apply to the ledger and report the resulting root
                    // (the driver contract for verified commits).
                    let root = match e.kind {
                        EntryKind::App => match Transaction::decode(&e.data) {
                            Some(txn) => {
                                if node.sabotage {
                                    // Corrupted replica: applies the
                                    // write-set plus a sneaky extra op.
                                    let mut ops = txn.ops.clone();
                                    ops.push((b"__sneak__".to_vec(), Some(vec![0x66])));
                                    node.ledger
                                        .store_mut()
                                        .put_batch(&ops)
                                        .ok()
                                        .map(|(r, _)| r)
                                } else {
                                    match node.ledger.apply(&txn) {
                                        Ok((r, _)) => Some(r),
                                        Err(LedgerError::RootMismatch { .. }) => {
                                            node.halted = true;
                                            None
                                        }
                                        Err(LedgerError::Store(_)) => None,
                                    }
                                }
                            }
                            // Opaque payloads (non-transaction tests):
                            // the ledger is untouched.
                            None => Some(node.ledger.root().0),
                        },
                        _ => Some(node.ledger.root().0),
                    };
                    if let Some(r) = root {
                        node.core.report_applied(e.index, r);
                    }
                }
                self.check_node_history(*id);
            }

            self.record_leaders();

            // 2. Deliver in-flight messages.
            if self.reorder && self.inflight.len() > 1 {
                let k = (self.rng.next() as usize) % self.inflight.len();
                self.inflight.swap(0, k);
            }
            if let Some((to, msg)) = self.inflight.pop_front() {
                progressed = true;
                let from = msg.meta().from;
                let dropped = self.blocked.contains(&(from, to))
                    || !self.nodes.get(&to).map(|n| n.alive).unwrap_or(false)
                    || (self.drop_pct > 0 && self.rng.pct() < self.drop_pct);
                if !dropped {
                    if self.dup_pct > 0 && self.rng.pct() < self.dup_pct {
                        self.inflight.push_back((to, msg.clone()));
                    }
                    self.nodes.get_mut(&to).unwrap().core.step(msg);
                }
            }

            if !progressed {
                self.check_invariants();
                return;
            }
        }
        panic!("pump did not quiesce");
    }

    fn tick(&mut self, ticks: u32) {
        for _ in 0..ticks {
            for node in self.nodes.values_mut() {
                if node.alive {
                    node.core.tick();
                }
            }
            self.pump();
        }
    }

    fn leader(&self) -> Option<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.alive && n.core.role() == Role::Leader)
            .max_by_key(|(_, n)| n.core.term())
            .map(|(&id, _)| id)
    }

    fn wait_for_leader(&mut self, max_ticks: u32) -> NodeId {
        for _ in 0..max_ticks {
            self.tick(1);
            if let Some(l) = self.leader() {
                // A usable leader has committed its own noop.
                let n = &self.nodes[&l];
                if n.core.commit_index() >= 1 {
                    return l;
                }
            }
        }
        panic!("no leader after {} ticks", max_ticks);
    }

    fn propose(&mut self, data: &[u8]) -> Result<Index, ProposeError> {
        let l = self.leader().ok_or(ProposeError::NotLeader)?;
        let r = self.nodes.get_mut(&l).unwrap().core.propose(data.to_vec());
        self.pump();
        r
    }

    /// Leader-side transaction: fork the ledger, buffer the ops, seal,
    /// propose the encoded transaction.
    fn propose_txn(
        &mut self,
        ops: &[(&[u8], Option<&[u8]>)],
    ) -> Result<Index, ProposeError> {
        let l = self.leader().ok_or(ProposeError::NotLeader)?;
        let node = self.nodes.get_mut(&l).unwrap();
        let mut fork = node.ledger.fork();
        for (k, v) in ops {
            match v {
                Some(v) => fork.put(k, v),
                None => fork.delete(k),
            }
        }
        let txn: Transaction = fork.seal().expect("seal fork").into();
        let r = node.core.propose(txn.encode());
        self.pump();
        r
    }

    fn ledger_root(&self, id: NodeId) -> [u8; 32] {
        self.nodes[&id].ledger.root().0
    }

    fn crash(&mut self, id: NodeId) {
        self.nodes.get_mut(&id).unwrap().alive = false;
    }

    /// Restart from the persisted mirrors with a fresh incarnation —
    /// exactly what a real enclave does (the incarnation is drawn from
    /// in-enclave randomness, so even a rolled-back host cannot pin it).
    fn restart(&mut self, id: NodeId) {
        self.next_incarnation += 1;
        let inc = self.next_incarnation;
        let node = self.nodes.get_mut(&id).unwrap();
        let cfg = Config::new(id, inc, node.seed.wrapping_add(inc));
        node.core = RaftCore::new(
            cfg,
            self.genesis.clone(),
            node.disk_log.clone(),
            node.disk_hs,
        );
        node.applied.clear();
        // A restarted node rebuilds its ledger by replaying the
        // re-delivered committed entries (a real node opens its
        // checkpoint instead; same resulting state).
        node.ledger = node_ledger(id);
        node.halted = false;
        node.sabotage = false;
        node.alive = true;
    }

    fn partition(&mut self, groups: &[&[NodeId]]) {
        self.blocked.clear();
        for (gi, ga) in groups.iter().enumerate() {
            for (gj, gb) in groups.iter().enumerate() {
                if gi == gj {
                    continue;
                }
                for &a in *ga {
                    for &b in *gb {
                        self.blocked.insert((a, b));
                    }
                }
            }
        }
    }

    fn heal(&mut self) {
        self.blocked.clear();
    }

    fn applied_app(&self, id: NodeId) -> Vec<Vec<u8>> {
        self.nodes[&id]
            .applied
            .iter()
            .filter(|e| e.kind == EntryKind::App)
            .map(|e| e.data.clone())
            .collect()
    }

    // ── Invariants ──────────────────────────────────────────────────

    fn record_leaders(&mut self) {
        for (&id, n) in &self.nodes {
            if n.alive && n.core.role() == Role::Leader {
                let term = n.core.term();
                if let Some(&prev) = self.leaders_by_term.get(&term) {
                    assert_eq!(prev, id, "two leaders in term {}", term);
                } else {
                    self.leaders_by_term.insert(term, id);
                }
            }
        }
    }

    fn check_node_history(&mut self, id: NodeId) {
        let applied = &self.nodes[&id].applied;
        for (i, e) in applied.iter().enumerate() {
            if i < self.history.len() {
                assert_eq!(
                    &self.history[i], e,
                    "node {} rewrote committed history at position {}",
                    id, i
                );
            } else {
                self.history.push(e.clone());
            }
        }
    }

    fn check_invariants(&self) {
        let nodes: Vec<&SimNode> = self.nodes.values().collect();
        for a in &nodes {
            for b in &nodes {
                // Log matching: same (index, term) ⇒ identical entry.
                let la = a.core.entries();
                let lb = b.core.entries();
                for i in 0..la.len().min(lb.len()) {
                    if la[i].term == lb[i].term {
                        assert_eq!(la[i], lb[i], "log matching violated at index {}", i + 1);
                    }
                }
                // Applied prefix.
                let (short, long) = if a.applied.len() <= b.applied.len() {
                    (&a.applied, &b.applied)
                } else {
                    (&b.applied, &a.applied)
                };
                assert_eq!(
                    short.as_slice(),
                    &long[..short.len()],
                    "applied sequences diverge"
                );
            }
        }
    }

    fn assert_converged(&self, expected_app: &[&[u8]]) {
        for (&id, n) in &self.nodes {
            if !n.alive {
                continue;
            }
            let got = self.applied_app(id);
            assert_eq!(
                got.len(),
                expected_app.len(),
                "node {} applied {} app entries, expected {}",
                id,
                got.len(),
                expected_app.len()
            );
            for (g, e) in got.iter().zip(expected_app) {
                assert_eq!(g.as_slice(), *e);
            }
        }
    }
}

// ── Basic elections and replication ─────────────────────────────────

#[test]
fn single_node_cluster() {
    let mut sim = Sim::new(1, 1);
    let l = sim.wait_for_leader(50);
    assert_eq!(l, 1);
    sim.propose(b"a").unwrap();
    sim.propose(b"b").unwrap();
    sim.assert_converged(&[b"a", b"b"]);
}

#[test]
fn three_nodes_elect_and_replicate() {
    let mut sim = Sim::new(3, 2);
    sim.wait_for_leader(200);
    for d in [b"t1", b"t2", b"t3", b"t4", b"t5"] {
        sim.propose(d).unwrap();
    }
    sim.tick(5);
    sim.assert_converged(&[b"t1", b"t2", b"t3", b"t4", b"t5"]);
}

#[test]
fn leader_failover_preserves_commits() {
    let mut sim = Sim::new(3, 3);
    let l1 = sim.wait_for_leader(200);
    sim.propose(b"x1").unwrap();
    sim.propose(b"x2").unwrap();
    sim.tick(5);

    sim.crash(l1);
    let l2 = sim.wait_for_leader(400);
    assert_ne!(l1, l2);
    sim.propose(b"x3").unwrap();
    sim.tick(5);

    // The old leader restarts and catches up (and is re-admitted).
    sim.restart(l1);
    sim.tick(60);
    sim.assert_converged(&[b"x1", b"x2", b"x3"]);
    assert!(sim.nodes[&l1].core.self_admitted(), "restarted node not re-admitted");
}

#[test]
fn minority_partition_cannot_commit() {
    let mut sim = Sim::new(5, 4);
    let l1 = sim.wait_for_leader(300);

    // Cut the leader plus one node off from the other three.
    let mut minority = vec![l1];
    let mut majority = Vec::new();
    for id in 1..=5 {
        if id != l1 {
            if minority.len() < 2 {
                minority.push(id);
            } else {
                majority.push(id);
            }
        }
    }
    sim.partition(&[&minority, &majority]);

    // Proposal in the minority: accepted locally, never committed.
    let stale = sim.nodes.get_mut(&l1).unwrap().core.propose(b"stale".to_vec());
    assert!(stale.is_ok());
    sim.tick(40);
    for &id in &majority {
        assert!(
            !sim.applied_app(id).iter().any(|d| d == b"stale"),
            "minority entry leaked into the majority"
        );
    }

    // The majority elects its own leader and commits.
    let l2 = sim.wait_for_leader(600);
    assert!(majority.contains(&l2));
    sim.propose(b"good").unwrap();
    sim.tick(5);

    // Heal: the stale entry is overwritten everywhere.
    sim.heal();
    sim.tick(80);
    sim.assert_converged(&[b"good"]);
    for (_, n) in &sim.nodes {
        assert!(!n.applied.iter().any(|e| e.data == b"stale"));
    }
}

#[test]
fn survives_message_loss() {
    let mut sim = Sim::new(3, 5);
    sim.drop_pct = 20;
    sim.wait_for_leader(2000);
    for i in 0..10u8 {
        // Under loss the leader can change; retry the proposal.
        for _ in 0..200 {
            if sim.propose(&[i]).is_ok() {
                break;
            }
            sim.tick(1);
        }
        sim.tick(3);
    }
    sim.drop_pct = 0;
    sim.tick(60);
    let expected: Vec<[u8; 1]> = (0..10u8).map(|i| [i]).collect();
    let expected_refs: Vec<&[u8]> = expected.iter().map(|a| a.as_slice()).collect();
    sim.assert_converged(&expected_refs);
}

#[test]
fn survives_duplication_and_reordering() {
    let mut sim = Sim::new(3, 6);
    sim.dup_pct = 25;
    sim.reorder = true;
    sim.wait_for_leader(2000);
    for i in 0..10u8 {
        for _ in 0..200 {
            if sim.propose(&[i]).is_ok() {
                break;
            }
            sim.tick(1);
        }
        sim.tick(3);
    }
    sim.tick(60);
    let expected: Vec<[u8; 1]> = (0..10u8).map(|i| [i]).collect();
    let expected_refs: Vec<&[u8]> = expected.iter().map(|a| a.as_slice()).collect();
    sim.assert_converged(&expected_refs);
}

// ── Incarnation-gated voting (the host-rollback hardening) ──────────

#[test]
fn restart_demotes_to_learner_until_refreshed() {
    let mut sim = Sim::new(3, 7);
    let l = sim.wait_for_leader(200);
    sim.propose(b"a").unwrap();
    sim.tick(5);

    let follower = (1..=3).find(|&id| id != l).unwrap();
    sim.restart(follower);
    assert!(!sim.nodes[&follower].core.self_admitted());

    // The leader observes the new incarnation via append responses and
    // commits a RefreshIncarnation for it.
    sim.tick(30);
    assert!(
        sim.nodes[&follower].core.self_admitted(),
        "leader did not re-admit the restarted follower"
    );
    // Membership records the new incarnation on every node.
    let rec = sim.nodes[&l].core.membership().voters[&follower];
    assert_eq!(rec, sim.next_incarnation);
    sim.assert_converged(&[b"a"]);
}

/// THE attack this design exists to block: the host rolls back a
/// node's disk (including its vote record) and restarts it, hoping it
/// votes twice in the same term. The restarted enclave draws a fresh
/// incarnation, does not match the incarnation in the replicated
/// membership, and refuses to vote until a leader re-admits it.
#[test]
fn vote_rollback_attack_is_blocked() {
    let voters = [1u64, 2, 3];
    let genesis = Membership::bootstrap(&voters);

    // Node 3 grants its vote to candidate 1 in term 2.
    let mut n3 = RaftCore::new(
        Config::new(3, 0, 99),
        genesis.clone(),
        Vec::new(),
        HardState::default(),
    );
    n3.step(Message::RequestVote {
        meta: MsgMeta { from: 1, term: 2, incarnation: 0 },
        last_log_index: 0,
        last_log_term: 0,
    });
    let ready = n3.ready();
    let hs = ready.hard_state.expect("vote must be persisted");
    assert_eq!(hs.voted_for, Some(1));
    let granted = matches!(
        ready.messages.as_slice(),
        [(1, Message::VoteResponse { granted: true, .. })]
    );
    assert!(granted, "baseline vote should be granted");

    // Host attack: restart node 3 from a rolled-back disk (the vote is
    // gone), but the enclave draws a fresh incarnation.
    let mut n3_rolled = RaftCore::new(
        Config::new(3, 1, 100), // incarnation 1 ≠ recorded 0
        genesis.clone(),
        Vec::new(),
        HardState::default(), // rolled back: no vote recorded
    );
    n3_rolled.step(Message::RequestVote {
        meta: MsgMeta { from: 2, term: 2, incarnation: 0 },
        last_log_index: 0,
        last_log_term: 0,
    });
    let ready = n3_rolled.ready();
    let refused = matches!(
        ready.messages.as_slice(),
        [(2, Message::VoteResponse { granted: false, .. })]
    );
    assert!(refused, "rolled-back node must refuse to vote again");

    // Control: without the incarnation gate (same state, incarnation
    // still matching), the double vote WOULD be granted — the gate is
    // what blocks the attack.
    let mut n3_plain = RaftCore::new(
        Config::new(3, 0, 101),
        genesis,
        Vec::new(),
        HardState::default(),
    );
    n3_plain.step(Message::RequestVote {
        meta: MsgMeta { from: 2, term: 2, incarnation: 0 },
        last_log_index: 0,
        last_log_term: 0,
    });
    let ready = n3_plain.ready();
    let granted = matches!(
        ready.messages.as_slice(),
        [(2, Message::VoteResponse { granted: true, .. })]
    );
    assert!(granted, "control shows plain Raft would double-vote here");
}

#[test]
fn full_cluster_restart_recovers_via_recovery_timeout() {
    let mut sim = Sim::new(3, 8);
    sim.wait_for_leader(200);
    sim.propose(b"before").unwrap();
    sim.tick(5);

    for id in 1..=3 {
        sim.restart(id);
    }
    for id in 1..=3 {
        assert!(!sim.nodes[&id].core.self_admitted());
    }

    // Nobody is admitted; only the recovery timeout can restore the
    // cluster. Default: recovery_ticks = 100.
    sim.tick(400);
    let l = sim.leader().expect("cluster did not recover from full restart");
    assert!(sim.nodes[&l].core.self_admitted(), "recovered leader must re-admit itself");
    sim.propose(b"after").unwrap();
    sim.tick(30);
    sim.assert_converged(&[b"before", b"after"]);
}

// ── Membership changes ──────────────────────────────────────────────

#[test]
fn add_learner_then_promote_to_voter() {
    let mut sim = Sim::new(3, 9);
    let l = sim.wait_for_leader(200);
    sim.propose(b"a").unwrap();
    sim.tick(5);

    sim.add_node(4);
    sim.nodes
        .get_mut(&l)
        .unwrap()
        .core
        .propose_conf_change(ConfigChange::AddLearner { node: 4 })
        .unwrap();
    sim.tick(20);

    // The learner replicates but is not a voter.
    assert_eq!(sim.applied_app(4), vec![b"a".to_vec()]);
    assert!(!sim.nodes[&l].core.membership().is_voter(4));

    let inc = sim.nodes[&l].core.peer_incarnation(4).expect("leader saw the learner");
    sim.nodes
        .get_mut(&l)
        .unwrap()
        .core
        .propose_conf_change(ConfigChange::PromoteVoter { node: 4, incarnation: inc })
        .unwrap();
    sim.tick(20);
    assert!(sim.nodes[&l].core.membership().is_voter(4));

    // Quorum is now 3 of 4: one crash still commits.
    let crash_id = (1..=3).find(|&id| id != l).unwrap();
    sim.crash(crash_id);
    sim.propose(b"b").unwrap();
    sim.tick(10);
    assert_eq!(sim.applied_app(4), vec![b"a".to_vec(), b"b".to_vec()]);
}

#[test]
fn remove_node_shrinks_quorum() {
    let mut sim = Sim::new(3, 10);
    let l = sim.wait_for_leader(200);
    let removed = (1..=3).find(|&id| id != l).unwrap();
    sim.nodes
        .get_mut(&l)
        .unwrap()
        .core
        .propose_conf_change(ConfigChange::RemoveNode { node: removed })
        .unwrap();
    sim.tick(10);
    sim.crash(removed);

    // Quorum of the remaining two voters is 2 — commits still work.
    sim.propose(b"post-removal").unwrap();
    sim.tick(10);
    for id in (1..=3).filter(|&id| id != removed) {
        assert_eq!(sim.applied_app(id), vec![b"post-removal".to_vec()]);
    }
}

#[test]
fn one_config_change_in_flight() {
    let mut sim = Sim::new(3, 11);
    let l = sim.wait_for_leader(200);
    sim.add_node(4);
    sim.add_node(5);
    // Block replication so the first change stays uncommitted.
    let minority: Vec<NodeId> = vec![l];
    let rest: Vec<NodeId> = (1..=5).filter(|&i| i != l).collect();
    sim.partition(&[&minority, &rest]);
    let leader = &mut sim.nodes.get_mut(&l).unwrap().core;
    leader.propose_conf_change(ConfigChange::AddLearner { node: 4 }).unwrap();
    assert_eq!(
        leader.propose_conf_change(ConfigChange::AddLearner { node: 5 }),
        Err(ProposeError::ConfigChangePending)
    );
    sim.heal();
    sim.tick(30);
}

// ── Commit safety ───────────────────────────────────────────────────

/// §5.4.2: a leader may only advance the commit index by counting
/// replicas of entries from its *own* term (the figure-8 scenario).
#[test]
fn no_commit_of_old_term_entries_by_counting() {
    let voters = [1u64, 2, 3, 4, 5];
    let genesis = Membership::bootstrap(&voters);
    // Node 1 holds an uncommitted entry from term 2 and wins term 4.
    let old_entry = Entry { term: 2, index: 1, kind: EntryKind::App, data: b"old".to_vec() };
    let mut n1 = RaftCore::new(
        Config::new(1, 0, 42),
        genesis,
        vec![old_entry],
        HardState { term: 3, voted_for: None },
    );
    // Win an election for term 4.
    while n1.role() != Role::Candidate {
        n1.tick();
    }
    assert_eq!(n1.term(), 4);
    for from in [2u64, 3] {
        n1.step(Message::VoteResponse {
            meta: MsgMeta { from, term: 4, incarnation: 0 },
            granted: true,
        });
    }
    assert_eq!(n1.role(), Role::Leader);
    let _ = n1.ready();

    // Followers 2 and 3 acknowledge ONLY the old term-2 entry.
    for from in [2u64, 3] {
        n1.step(Message::AppendResponse {
            meta: MsgMeta { from, term: 4, incarnation: 0 },
            success: true,
            match_index: 1,
            conflict_index: 0,
            applied_root: None,
            root_sig: None,
        });
    }
    assert_eq!(
        n1.commit_index(),
        0,
        "old-term entry must not commit by counting replicas"
    );

    // Once the term-4 noop (index 2) is replicated, both commit.
    for from in [2u64, 3] {
        n1.step(Message::AppendResponse {
            meta: MsgMeta { from, term: 4, incarnation: 0 },
            success: true,
            match_index: 2,
            conflict_index: 0,
            applied_root: None,
            root_sig: None,
        });
    }
    assert_eq!(n1.commit_index(), 2);
}

/// §5.4.1: a candidate with a stale log cannot win an election.
#[test]
fn stale_log_cannot_win_election() {
    let voters = [1u64, 2, 3];
    let genesis = Membership::bootstrap(&voters);
    let e = Entry { term: 1, index: 1, kind: EntryKind::App, data: b"x".to_vec() };
    let mut n1 = RaftCore::new(
        Config::new(1, 0, 1),
        genesis.clone(),
        vec![e],
        HardState { term: 1, voted_for: None },
    );
    // Candidate 3 has an empty log: refused.
    n1.step(Message::RequestVote {
        meta: MsgMeta { from: 3, term: 2, incarnation: 0 },
        last_log_index: 0,
        last_log_term: 0,
    });
    let r = n1.ready();
    assert!(matches!(
        r.messages.as_slice(),
        [(3, Message::VoteResponse { granted: false, .. })]
    ));
    // Candidate 2 with a log at least as complete: granted.
    n1.step(Message::RequestVote {
        meta: MsgMeta { from: 2, term: 3, incarnation: 0 },
        last_log_index: 1,
        last_log_term: 1,
    });
    let r = n1.ready();
    assert!(matches!(
        r.messages.as_slice(),
        [(2, Message::VoteResponse { granted: true, .. })]
    ));
}

// ── Randomized end-to-end fuzz ──────────────────────────────────────

/// Random crashes, restarts, partitions and proposals; after healing,
/// every live node holds the same applied sequence and every invariant
/// held throughout (checked continuously inside the simulator).
#[test]
fn fuzz_random_faults_converge() {
    for seed in 0..6u64 {
        let mut sim = Sim::new(5, 1000 + seed);
        let mut rng = Rng::new(seed);
        let mut proposed = 0u32;
        let mut dead: Option<NodeId> = None;

        for _ in 0..60 {
            match rng.next() % 10 {
                0 => {
                    // Crash one node (at most one down at a time).
                    if dead.is_none() {
                        let id = 1 + rng.next() % 5;
                        sim.crash(id);
                        dead = Some(id);
                    }
                }
                1 => {
                    if let Some(id) = dead.take() {
                        sim.restart(id);
                    }
                }
                2 => {
                    let a = 1 + rng.next() % 5;
                    let group_a: Vec<NodeId> = vec![a];
                    let group_b: Vec<NodeId> = (1..=5).filter(|&i| i != a).collect();
                    sim.partition(&[&group_a, &group_b]);
                }
                3 => sim.heal(),
                _ => {
                    if sim.propose(format!("p{}", proposed).as_bytes()).is_ok() {
                        proposed += 1;
                    }
                }
            }
            sim.tick(1 + (rng.next() % 8) as u32);
        }

        // Heal everything and converge.
        sim.heal();
        if let Some(id) = dead.take() {
            sim.restart(id);
        }
        sim.tick(500);

        // All live nodes agree on the same applied sequence.
        let reference = sim.applied_app(1);
        for id in 2..=5 {
            assert_eq!(
                sim.applied_app(id),
                reference,
                "seed {}: node {} diverged",
                seed,
                id
            );
        }
        sim.check_invariants();
    }
}

// ── Verified commits over the Merkle ledger (WS3) ───────────────────

#[test]
fn transactions_replicate_and_verify() {
    let mut sim = Sim::new(3, 20);
    let l = sim.wait_for_leader(200);

    sim.propose_txn(&[
        (b"alice", Some(b"1000")),
        (b"bob", Some(b"250")),
    ])
    .unwrap();
    sim.propose_txn(&[(b"alice", Some(b"900")), (b"carol", Some(b"42"))]).unwrap();
    sim.propose_txn(&[(b"bob", None)]).unwrap();
    sim.tick(6);

    // Every replica computed the same root from a different storage key.
    let root = sim.ledger_root(l);
    for id in 1..=3 {
        assert_eq!(sim.ledger_root(id), root, "node {} ledger diverged", id);
        let store = sim.nodes[&id].ledger.store();
        assert_eq!(store.get(b"alice").unwrap(), Some(b"900".to_vec()));
        assert_eq!(store.get(b"bob").unwrap(), None);
        assert_eq!(store.get(b"carol").unwrap(), Some(b"42".to_vec()));
    }

    // The leader verified everything it committed, and propagated the
    // watermark to the followers.
    let leader = &sim.nodes[&l].core;
    assert_eq!(leader.verified_index(), leader.commit_index());
    for id in (1..=3).filter(|&id| id != l) {
        assert!(
            sim.nodes[&id].core.verified_index() > 0,
            "node {} never learned the verified watermark",
            id
        );
    }
    assert!(sim.events.is_empty(), "no disputes expected: {:?}", sim.events);
}

#[test]
fn diverging_follower_flagged_as_outlier() {
    let mut sim = Sim::new(3, 21);
    let l = sim.wait_for_leader(200);
    let bad = (1..=3).find(|&id| id != l).unwrap();
    sim.nodes.get_mut(&bad).unwrap().sabotage = true;

    sim.propose_txn(&[(b"k1", Some(b"v1"))]).unwrap();
    sim.tick(10);

    // The leader confirmed the root with the healthy follower (quorum)
    // and flagged the corrupted one.
    let flagged = sim.events.iter().any(|(n, ev)| {
        *n == l && matches!(ev, RaftEvent::OutlierFollower { node, .. } if *node == bad)
    });
    assert!(flagged, "outlier follower not flagged: {:?}", sim.events);
    assert!(
        sim.nodes[&l].core.verified_index() >= 1,
        "verification must advance with the healthy quorum"
    );

    // The corruption stops but the ledger has already diverged: the
    // honest apply path fails its root_before check and the node halts
    // fail-closed.
    sim.nodes.get_mut(&bad).unwrap().sabotage = false;
    sim.propose_txn(&[(b"k2", Some(b"v2"))]).unwrap();
    sim.tick(6);
    assert!(sim.nodes[&bad].halted, "diverged node must stop serving");

    // Healthy nodes agree.
    let good = (1..=3).find(|&id| id != l && id != bad).unwrap();
    assert_eq!(sim.ledger_root(l), sim.ledger_root(good));
}

#[test]
fn diverging_leader_is_deposed() {
    let mut sim = Sim::new(3, 22);
    let l1 = sim.wait_for_leader(200);
    sim.propose_txn(&[(b"base", Some(b"1"))]).unwrap();
    sim.tick(6);

    // The leader's ledger goes bad: it applies its own committed
    // transactions with a sneaky extra op from now on.
    sim.nodes.get_mut(&l1).unwrap().sabotage = true;
    sim.propose_txn(&[(b"k", Some(b"v"))]).unwrap();
    sim.tick(20);

    // A quorum of followers agreed against the leader: LeaderOutlier
    // fired on the (now deposed) leader.
    let deposed = sim.events.iter().any(|(n, ev)| {
        *n == l1 && matches!(ev, RaftEvent::LeaderOutlier { .. })
    });
    assert!(deposed, "diverged leader not deposed: {:?}", sim.events);
    assert_ne!(sim.nodes[&l1].core.role(), Role::Leader);

    // Driver reaction per the plan: the outlier stops serving and
    // awaits snapshot repair. Take it down and continue on the healthy
    // majority.
    sim.crash(l1);
    let l2 = sim.wait_for_leader(600);
    assert_ne!(l2, l1);
    sim.propose_txn(&[(b"after", Some(b"2"))]).unwrap();
    sim.tick(6);
    let good: Vec<NodeId> = (1..=3).filter(|&id| id != l1).collect();
    assert_eq!(sim.ledger_root(good[0]), sim.ledger_root(good[1]));
    for &id in &good {
        let store = sim.nodes[&id].ledger.store();
        assert_eq!(store.get(b"after").unwrap(), Some(b"2".to_vec()));
    }
}

#[test]
fn restarted_node_rebuilds_ledger_by_replay() {
    let mut sim = Sim::new(3, 23);
    let l = sim.wait_for_leader(200);
    sim.propose_txn(&[(b"a", Some(b"1")), (b"b", Some(b"2"))]).unwrap();
    sim.propose_txn(&[(b"a", None), (b"c", Some(b"3"))]).unwrap();
    sim.tick(6);
    let root = sim.ledger_root(l);

    let f = (1..=3).find(|&id| id != l).unwrap();
    sim.restart(f);
    sim.tick(60);
    assert_eq!(sim.ledger_root(f), root, "replayed ledger must reach the same root");
    assert!(!sim.nodes[&f].halted);
}
