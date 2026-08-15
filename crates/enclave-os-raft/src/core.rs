// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The sans-I/O Raft state machine.
//!
//! No I/O, no clock, no randomness source: the driver feeds messages
//! ([`RaftCore::step`]) and time ([`RaftCore::tick`]), and drains
//! obligations from [`RaftCore::ready`]. See the crate docs for the
//! driver contract and the incarnation-gated voting model.

use std::collections::{BTreeMap, BTreeSet};

use crate::message::{Message, MsgMeta};
use crate::types::{
    ConfigChange, Entry, EntryKind, HardState, Incarnation, Index, Membership, NodeId, Role, Term,
};

/// A ledger root as reported by the state machine (the Merkle store's
/// 32-byte root hash).
pub type LedgerRoot = [u8; 32];

/// Verification events surfaced to the driver via [`Ready::events`].
/// These are the dispute outcomes of the verified-commit protocol; the
/// driver decides the operational reaction (alerting, snapshot repair,
/// halting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftEvent {
    /// A quorum confirmed the leader's root at `index`, but this
    /// follower reported a different root: the follower is the outlier
    /// and must stop serving and repair via snapshot.
    OutlierFollower { node: NodeId, index: Index, reported: LedgerRoot },
    /// A quorum of voters agreed on the same root at `index` and it
    /// differs from our own: we (the leader) are the outlier. The core
    /// has already stepped down; the driver must stop serving and
    /// repair via snapshot.
    LeaderOutlier { index: Index, quorum_root: LedgerRoot },
    /// Every voter reported a root at `index` and no root reached a
    /// quorum: genuine cluster corruption. Halt and page a human.
    VerificationDeadlock { index: Index },
    /// This follower is behind our compaction base: the log cannot
    /// serve it. The driver must stream it a ledger snapshot at (or
    /// after) `base_index`; appends to it pause until the follower's
    /// match index passes the base.
    SnapshotNeeded { node: NodeId, base_index: Index },
}

/// Static configuration for one node.
#[derive(Debug, Clone)]
pub struct Config {
    /// This node's id.
    pub id: NodeId,
    /// This boot's incarnation (drawn fresh at every enclave start).
    pub incarnation: Incarnation,
    /// Base election timeout in ticks; the effective timeout is
    /// randomized in `[election_tick, 2 * election_tick)`.
    pub election_tick: u32,
    /// Leader heartbeat interval in ticks.
    pub heartbeat_tick: u32,
    /// Ticks without leader contact after which an *unadmitted* voter
    /// regains election rights (full-cluster-restart recovery). Must be
    /// much larger than `election_tick`; see the crate docs for the
    /// safety argument.
    pub recovery_ticks: u32,
    /// Max log entries carried per AppendEntries message.
    pub max_entries_per_msg: usize,
    /// Seed for the election-timeout jitter (any entropy; the driver
    /// should derive it from in-enclave randomness).
    pub seed: u64,
}

impl Config {
    pub fn new(id: NodeId, incarnation: Incarnation, seed: u64) -> Self {
        Self {
            id,
            incarnation,
            election_tick: 10,
            heartbeat_tick: 2,
            recovery_ticks: 100,
            max_entries_per_msg: 256,
            seed,
        }
    }
}

/// Why a proposal was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposeError {
    /// This node is not the leader (the driver should forward to
    /// [`RaftCore::leader_id`]).
    NotLeader,
    /// A membership change is still uncommitted; only one may be in
    /// flight at a time.
    ConfigChangePending,
}

/// The obligations produced by a batch of `step`/`tick`/`propose`
/// calls. See the driver contract in the crate docs: truncate, persist,
/// then send, then apply.
#[derive(Debug, Default)]
pub struct Ready {
    /// If set, delete persisted log entries with `index >= this` before
    /// persisting `entries_to_persist` (a follower dropped a divergent
    /// uncommitted suffix).
    pub truncate_from: Option<Index>,
    /// New log entries to persist, in index order.
    pub entries_to_persist: Vec<Entry>,
    /// New durable term/vote state, if changed.
    pub hard_state: Option<HardState>,
    /// Messages to send once the above is durable: `(destination, msg)`.
    pub messages: Vec<(NodeId, Message)>,
    /// Entries newly committed: apply to the state machine in order,
    /// and report the resulting ledger root per entry via
    /// [`RaftCore::report_applied`].
    pub committed_entries: Vec<Entry>,
    /// Verification events (disputes) for the driver to act on.
    pub events: Vec<RaftEvent>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.truncate_from.is_none()
            && self.entries_to_persist.is_empty()
            && self.hard_state.is_none()
            && self.messages.is_empty()
            && self.committed_entries.is_empty()
            && self.events.is_empty()
    }
}

/// Leader-side replication progress for one peer.
#[derive(Debug, Clone)]
struct Progress {
    match_index: Index,
    next_index: Index,
    /// The peer is behind our compaction base: appends are paused
    /// until a snapshot transfer (driven outside the core) completes.
    needs_snapshot: bool,
}

/// The Raft state machine for one node.
pub struct RaftCore {
    cfg: Config,

    // ── Durable state (mirrored to the driver via Ready) ────────────
    term: Term,
    voted_for: Option<NodeId>,
    /// The retained log; entry with index `i` lives at position
    /// `i - base_index - 1`.
    log: Vec<Entry>,
    /// Compaction/snapshot base: everything at or below this index is
    /// discarded from the log (committed and applied by definition).
    base_index: Index,
    /// Term of the entry at `base_index` (0 when uncompacted).
    base_term: Term,

    // ── Volatile state ──────────────────────────────────────────────
    role: Role,
    leader_id: Option<NodeId>,
    commit: Index,
    applied: Index,
    /// Current membership: base + every config entry in the log.
    membership: Membership,
    /// Membership as of `base_index` (genesis when uncompacted).
    base_membership: Membership,
    /// Candidate vote tally for the current election.
    votes: BTreeMap<NodeId, bool>,
    /// Leader replication progress (members except self).
    progress: BTreeMap<NodeId, Progress>,
    /// Latest incarnation observed from each peer (any message).
    seen_incarnations: BTreeMap<NodeId, Incarnation>,

    election_elapsed: u32,
    heartbeat_elapsed: u32,
    randomized_election_tick: u32,
    /// Sticky recovery flag: set after `recovery_ticks` without leader
    /// contact while unadmitted; cleared on leader contact/admission.
    recovery_active: bool,
    rng: SplitMix64,

    // ── Verified-commit state ───────────────────────────────────────
    /// Our state machine's latest report: `(applied_index, root)`.
    last_applied_report: Option<(Index, LedgerRoot)>,
    /// Highest index whose root a quorum has confirmed.
    verified: Index,
    /// Leader: our own roots per index, kept from `verified` upward.
    root_history: BTreeMap<Index, LedgerRoot>,
    /// Leader: each voter's latest report.
    latest_reports: BTreeMap<NodeId, (Index, LedgerRoot)>,
    /// Leader: highest index at which each peer's root matched ours.
    match_watermark: BTreeMap<NodeId, Index>,
    /// Leader: peers already flagged as outliers (event dedupe).
    disputed: BTreeSet<NodeId>,
    /// Deadlock event dedupe.
    deadlock_reported: Option<Index>,

    // ── Ready accumulation ──────────────────────────────────────────
    msgs: Vec<(NodeId, Message)>,
    events: Vec<RaftEvent>,
    /// Index of the first log entry not yet handed to the driver.
    persist_from: Index,
    pending_truncate: Option<Index>,
    hard_state_dirty: bool,
}

impl RaftCore {
    /// Build a core from persisted state with an uncompacted log
    /// (base 0). For a fresh cluster use [`RaftCore::bootstrap`]; for
    /// a compacted log use [`RaftCore::with_base`].
    pub fn new(
        cfg: Config,
        base_membership: Membership,
        log: Vec<Entry>,
        hard_state: HardState,
    ) -> Self {
        Self::with_base(cfg, base_membership, 0, 0, log, hard_state)
    }

    /// Build a core whose log starts AFTER a compaction/snapshot base:
    /// `base_membership` is the membership as of `base_index` (whose
    /// entry had `base_term`), and `log` must be contiguous from
    /// `base_index + 1`. Everything at or below the base is committed
    /// and applied by definition.
    pub fn with_base(
        cfg: Config,
        base_membership: Membership,
        base_index: Index,
        base_term: Term,
        log: Vec<Entry>,
        hard_state: HardState,
    ) -> Self {
        for (i, e) in log.iter().enumerate() {
            assert_eq!(
                e.index,
                base_index + i as Index + 1,
                "log must be contiguous from the base"
            );
        }
        let persist_from = log.last().map(|e| e.index).unwrap_or(base_index) + 1;
        let seed = cfg.seed;
        let mut core = Self {
            cfg,
            term: hard_state.term,
            voted_for: hard_state.voted_for,
            log,
            base_index,
            base_term,
            role: Role::Follower,
            leader_id: None,
            commit: base_index,
            applied: base_index,
            membership: base_membership.clone(),
            base_membership,
            votes: BTreeMap::new(),
            progress: BTreeMap::new(),
            seen_incarnations: BTreeMap::new(),
            election_elapsed: 0,
            heartbeat_elapsed: 0,
            randomized_election_tick: 0,
            recovery_active: false,
            rng: SplitMix64::new(seed),
            last_applied_report: None,
            verified: 0,
            root_history: BTreeMap::new(),
            latest_reports: BTreeMap::new(),
            match_watermark: BTreeMap::new(),
            disputed: BTreeSet::new(),
            deadlock_reported: None,
            msgs: Vec::new(),
            events: Vec::new(),
            persist_from,
            pending_truncate: None,
            hard_state_dirty: false,
        };
        core.rebuild_membership();
        core.reset_election_timeout();
        core
    }

    /// Genesis: a fresh cluster with the given voters, all admitted at
    /// incarnation 0.
    pub fn bootstrap(cfg: Config, voters: &[NodeId]) -> Self {
        Self::new(cfg, Membership::bootstrap(voters), Vec::new(), HardState::default())
    }

    // ── Accessors ───────────────────────────────────────────────────

    pub fn id(&self) -> NodeId {
        self.cfg.id
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn term(&self) -> Term {
        self.term
    }
    pub fn leader_id(&self) -> Option<NodeId> {
        self.leader_id
    }
    pub fn commit_index(&self) -> Index {
        self.commit
    }
    pub fn membership(&self) -> &Membership {
        &self.membership
    }
    pub fn entries(&self) -> &[Entry] {
        &self.log
    }
    pub fn last_index(&self) -> Index {
        self.log.last().map(|e| e.index).unwrap_or(self.base_index)
    }
    pub fn last_term(&self) -> Term {
        self.log.last().map(|e| e.term).unwrap_or(self.base_term)
    }
    /// The compaction/snapshot base `(index, term)`.
    pub fn base(&self) -> (Index, Term) {
        (self.base_index, self.base_term)
    }
    pub fn applied_index(&self) -> Index {
        self.applied
    }

    /// Log-vector position of index `idx` (valid for
    /// `base_index < idx ≤ last_index`).
    fn pos(&self, idx: Index) -> Option<usize> {
        idx.checked_sub(self.base_index + 1).map(|p| p as usize)
    }

    /// Latest incarnation observed from a peer (for the driver to build
    /// `PromoteVoter` changes).
    pub fn peer_incarnation(&self, id: NodeId) -> Option<Incarnation> {
        self.seen_incarnations.get(&id).copied()
    }

    /// A link-layer introduction frame carrying this node's identity;
    /// the transport sends it when a peer session establishes.
    pub fn hello(&self) -> Message {
        Message::Hello {
            meta: MsgMeta {
                from: self.cfg.id,
                term: self.term,
                incarnation: self.cfg.incarnation,
            },
        }
    }

    /// Is this node admitted to vote (its incarnation matches the one
    /// recorded in the replicated membership)?
    pub fn self_admitted(&self) -> bool {
        self.membership.voters.get(&self.cfg.id) == Some(&self.cfg.incarnation)
    }

    /// Highest index whose post-apply ledger root a quorum confirmed.
    /// On followers this is the leader-propagated watermark, capped at
    /// the local commit index. Clients asking for `wait: verified`
    /// block on this.
    pub fn verified_index(&self) -> Index {
        self.verified
    }

    /// Restore-time only: entries at or below `floor` are already
    /// reflected in the state machine (its checkpoint outran the
    /// persisted applied marker by at most one batch) and must not be
    /// re-delivered through [`Ready::committed_entries`]. Call once,
    /// right after construction, before any tick/step.
    pub fn set_applied_floor(&mut self, floor: Index) {
        assert_eq!(
            self.applied, self.base_index,
            "applied floor must be set before any Ready"
        );
        self.applied = floor.clamp(self.base_index, self.last_index());
    }

    // ── Compaction and snapshots ────────────────────────────────────

    /// Discard log entries at or below `through` (which must be ≤ the
    /// applied index). Returns the new base `(index, term, membership)`
    /// for the driver to persist. No-op (returning the current base)
    /// when `through` is at or below the existing base.
    pub fn compact(&mut self, through: Index) -> (Index, Term, Membership) {
        if through <= self.base_index {
            return (self.base_index, self.base_term, self.base_membership.clone());
        }
        assert!(through <= self.applied, "cannot compact unapplied entries");
        let new_term = self.term_at(through).expect("compact point in log");
        // Membership as of `through`: base + config entries ≤ through.
        let mut m = self.base_membership.clone();
        for e in &self.log {
            if e.index > through {
                break;
            }
            if e.kind == EntryKind::Config {
                if let Some(cc) = ConfigChange::decode(&e.data) {
                    m.apply(&cc);
                }
            }
        }
        let keep_from = self.pos(through).expect("compact point in log") + 1;
        self.log.drain(..keep_from);
        self.base_index = through;
        self.base_term = new_term;
        self.base_membership = m.clone();
        self.persist_from = self.persist_from.max(through + 1);
        (through, new_term, m)
    }

    /// Leader: the snapshot transfer to `node` completed at our base
    /// (appends were paused during it). Mark the base as matched and
    /// resume ordinary replication from there.
    pub fn snapshot_transferred(&mut self, node: NodeId) {
        let base = self.base_index;
        if let Some(pr) = self.progress.get_mut(&node) {
            pr.needs_snapshot = false;
            pr.match_index = pr.match_index.max(base);
            pr.next_index = pr.match_index + 1;
        }
        if self.role == Role::Leader {
            self.send_append(node);
        }
    }

    /// Install a snapshot base received from the leader: the ledger has
    /// been restored to the state as of `index`, whose entry had
    /// `term`, under `membership`. Discards the entire retained log.
    /// Returns false (and does nothing) if the snapshot is stale
    /// (`index ≤ commit`).
    pub fn install_snapshot(
        &mut self,
        index: Index,
        term: Term,
        membership: Membership,
    ) -> bool {
        if index <= self.commit {
            return false;
        }
        self.log.clear();
        self.base_index = index;
        self.base_term = term;
        self.base_membership = membership.clone();
        self.membership = membership;
        self.commit = index;
        self.applied = index;
        self.persist_from = index + 1;
        self.pending_truncate = None;
        if self.role == Role::Leader {
            self.sync_progress();
        }
        true
    }

    // ── Verified commits ────────────────────────────────────────────

    /// The driver MUST call this after applying a committed entry to
    /// the ledger, with the ledger root as of that entry (for Noop and
    /// Config entries: the unchanged current root). Reports ride to the
    /// leader in AppendResponse; the leader cross-checks them against
    /// its own roots to advance the verified index and to detect
    /// divergence (see [`RaftEvent`]).
    pub fn report_applied(&mut self, index: Index, root: LedgerRoot) {
        if let Some((prev, _)) = self.last_applied_report {
            debug_assert!(
                index >= prev,
                "applied reports must be monotonic (node {} got {} after {})",
                self.cfg.id,
                index,
                prev
            );
        }
        self.last_applied_report = Some((index, root));
        if self.role == Role::Leader {
            self.root_history.insert(index, root);
            // Late follower reports may have been waiting for our own
            // root at this index.
            let pending: Vec<(NodeId, (Index, LedgerRoot))> = self
                .latest_reports
                .iter()
                .filter(|(_, (i, _))| *i == index)
                .map(|(&n, &r)| (n, r))
                .collect();
            for (node, (i, r)) in pending {
                self.evaluate_report(node, i, r);
            }
            self.advance_verified();
        }
    }

    /// Leader: process a follower's `(applied_index, root)` report.
    fn record_report(&mut self, from: NodeId, index: Index, root: LedgerRoot) {
        if self.role != Role::Leader || !self.membership.is_voter(from) {
            return;
        }
        match self.latest_reports.get(&from) {
            Some(&(prev_index, _)) if index < prev_index => return, // stale
            _ => {}
        }
        self.latest_reports.insert(from, (index, root));
        self.evaluate_report(from, index, root);
        self.advance_verified();
    }

    fn evaluate_report(&mut self, from: NodeId, index: Index, root: LedgerRoot) {
        let own = match self.root_history.get(&index) {
            Some(r) => *r,
            None => {
                // Either we have not applied this far yet (the report
                // re-evaluates when we do) or the index is below the
                // trimmed history. Below the verified watermark a
                // mismatch is impossible to confuse: quorum already
                // agreed there, so any late divergent report marks the
                // sender as outlier when it next aligns.
                return;
            }
        };
        if root == own {
            let w = self.match_watermark.entry(from).or_insert(0);
            if index > *w {
                *w = index;
            }
            self.disputed.remove(&from);
            return;
        }

        // Divergence at `index`. Attribute the fault: group the latest
        // reports of all voters at exactly this index.
        let mut same_as_reporter = 1usize; // the reporter itself
        let mut same_as_us = 1usize; // ourselves
        let mut aligned_voters = 1usize; // voters with a report at `index` (incl. us)
        for (&v, &(i, r)) in &self.latest_reports {
            if v == from || !self.membership.is_voter(v) || i != index {
                continue;
            }
            aligned_voters += 1;
            if r == root {
                same_as_reporter += 1;
            } else if r == own {
                same_as_us += 1;
            }
        }
        if self.membership.is_voter(self.cfg.id) {
            aligned_voters += 1; // we reported at this index (root_history hit)
        }
        let quorum = self.membership.quorum();

        if same_as_reporter >= quorum {
            // A quorum agrees with each other against us: we are the
            // outlier. Step down; the driver repairs us via snapshot.
            self.events.push(RaftEvent::LeaderOutlier { index, quorum_root: root });
            let term = self.term;
            self.become_follower(term, None);
        } else if same_as_us >= quorum {
            // Quorum confirms our root: the reporter is the outlier.
            if self.disputed.insert(from) {
                self.events.push(RaftEvent::OutlierFollower { node: from, index, reported: root });
            }
        } else if aligned_voters >= self.membership.voters.len()
            && self.deadlock_reported != Some(index)
        {
            // Everyone reported at this index and nobody has a quorum.
            self.deadlock_reported = Some(index);
            self.events.push(RaftEvent::VerificationDeadlock { index });
        }
    }

    /// Leader: the verified index is the highest index (≤ our own
    /// applied report) that a quorum of voters has root-confirmed.
    /// Matching at index i implies matching at every j < i (roots are a
    /// deterministic chain over the same log), so per-node watermarks
    /// compose into a quorum watermark.
    fn advance_verified(&mut self) {
        let Some((own_applied, _)) = self.last_applied_report else { return };
        let mut marks: Vec<Index> = Vec::with_capacity(self.membership.voters.len());
        for &v in self.membership.voters.keys() {
            if v == self.cfg.id {
                marks.push(own_applied);
            } else {
                marks.push(self.match_watermark.get(&v).copied().unwrap_or(0));
            }
        }
        marks.sort_unstable_by(|a, b| b.cmp(a));
        let quorum = self.membership.quorum();
        let quorum_mark = marks.get(quorum - 1).copied().unwrap_or(0);
        let new_verified = quorum_mark.min(self.commit);
        if new_verified > self.verified {
            self.verified = new_verified;
            // Trim history below the verified watermark (keep it).
            self.root_history = self.root_history.split_off(&self.verified);
        }
    }

    // ── Time ────────────────────────────────────────────────────────

    /// Advance logical time by one tick.
    pub fn tick(&mut self) {
        match self.role {
            Role::Leader => {
                self.heartbeat_elapsed += 1;
                if self.heartbeat_elapsed >= self.cfg.heartbeat_tick {
                    self.heartbeat_elapsed = 0;
                    self.maybe_refresh_incarnations();
                    self.bcast_append();
                }
            }
            Role::Follower | Role::Candidate => {
                self.election_elapsed += 1;
                if !self.self_admitted()
                    && self.membership.is_voter(self.cfg.id)
                    && self.election_elapsed >= self.cfg.recovery_ticks
                {
                    // Full-cluster-restart recovery: no leader contact
                    // for a long time — regain election rights.
                    self.recovery_active = true;
                }
                if self.election_elapsed >= self.randomized_election_tick && self.vote_rights() {
                    self.campaign();
                }
            }
        }
    }

    /// May this node vote / campaign right now?
    fn vote_rights(&self) -> bool {
        self.membership.is_voter(self.cfg.id) && (self.self_admitted() || self.recovery_active)
    }

    // ── Proposals ───────────────────────────────────────────────────

    /// Propose an application entry (leader only). Returns its index.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<Index, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader);
        }
        let idx = self.append_local(EntryKind::App, data);
        self.bcast_append();
        self.advance_commit();
        Ok(idx)
    }

    /// Propose a membership change (leader only, one in flight at a
    /// time). Applied to the active membership at append.
    pub fn propose_conf_change(&mut self, cc: ConfigChange) -> Result<Index, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader);
        }
        if self.has_pending_conf_change() {
            return Err(ProposeError::ConfigChangePending);
        }
        let idx = self.append_local(EntryKind::Config, cc.encode());
        self.bcast_append();
        self.advance_commit();
        Ok(idx)
    }

    fn has_pending_conf_change(&self) -> bool {
        self.log
            .iter()
            .rev()
            .take_while(|e| e.index > self.commit)
            .any(|e| e.kind == EntryKind::Config)
    }

    // ── Messages ────────────────────────────────────────────────────

    /// Feed a peer message into the state machine.
    pub fn step(&mut self, msg: Message) {
        let meta = msg.meta();

        // Attested membership: drop messages from unknown nodes. (The
        // transport additionally refuses such peers at the RA-TLS
        // layer; this guard also stops removed nodes from disrupting
        // elections with high terms.)
        if !self.membership.contains(meta.from) {
            return;
        }
        self.seen_incarnations.insert(meta.from, meta.incarnation);

        if meta.term > self.term {
            self.become_follower(meta.term, None);
        }

        match msg {
            Message::RequestVote { meta, last_log_index, last_log_term } => {
                self.handle_request_vote(meta, last_log_index, last_log_term);
            }
            Message::VoteResponse { meta, granted } => {
                self.handle_vote_response(meta, granted);
            }
            Message::AppendEntries {
                meta, prev_log_index, prev_log_term, commit, verified, entries,
            } => {
                self.handle_append_entries(
                    meta,
                    prev_log_index,
                    prev_log_term,
                    commit,
                    verified,
                    entries,
                );
            }
            Message::AppendResponse {
                meta, success, match_index, conflict_index, applied_root,
            } => {
                self.handle_append_response(meta, success, match_index, conflict_index);
                if success {
                    if let Some((index, root)) = applied_root {
                        self.record_report(meta.from, index, root);
                    }
                }
            }
            Message::Hello { .. } => {
                // Link-layer introduction; the prologue above already
                // recorded the sender's incarnation.
            }
        }
    }

    fn handle_request_vote(&mut self, meta: MsgMeta, last_log_index: Index, last_log_term: Term) {
        let up_to_date = (last_log_term, last_log_index) >= (self.last_term(), self.last_index());
        let grant = meta.term == self.term
            && self.membership.is_voter(meta.from)
            && self.vote_rights()
            && (self.voted_for.is_none() || self.voted_for == Some(meta.from))
            && up_to_date;
        if grant {
            self.voted_for = Some(meta.from);
            self.hard_state_dirty = true;
            // Granting resets the election timer so a live candidate is
            // not disrupted by us campaigning right after.
            self.election_elapsed = 0;
        }
        self.send(meta.from, |m| Message::VoteResponse { meta: m, granted: grant });
    }

    fn handle_vote_response(&mut self, meta: MsgMeta, granted: bool) {
        if self.role != Role::Candidate || meta.term != self.term {
            return;
        }
        self.votes.insert(meta.from, granted);
        let granted_count = 1 // self vote
            + self
                .votes
                .iter()
                .filter(|(id, &g)| g && **id != self.cfg.id && self.membership.is_voter(**id))
                .count();
        if granted_count >= self.membership.quorum() {
            self.become_leader();
        }
    }

    fn handle_append_entries(
        &mut self,
        meta: MsgMeta,
        prev_log_index: Index,
        prev_log_term: Term,
        leader_commit: Index,
        leader_verified: Index,
        entries: Vec<Entry>,
    ) {
        if meta.term < self.term {
            self.send(meta.from, |m| Message::AppendResponse {
                meta: m,
                success: false,
                match_index: 0,
                conflict_index: 0,
                applied_root: None,
            });
            return;
        }

        // Valid leader for our term: follow it and reset timers.
        self.become_follower(meta.term, Some(meta.from));
        self.recovery_active = false;

        // Everything at or below our commit index is settled (and may
        // be compacted away): the leader's entries there are ours by
        // definition. Report the committed prefix so the leader
        // advances next_index instead of probing a compacted range.
        if prev_log_index < self.commit {
            let commit = self.commit;
            let applied_root = self.last_applied_report;
            self.send(meta.from, |m| Message::AppendResponse {
                meta: m,
                success: true,
                match_index: commit,
                conflict_index: 0,
                applied_root,
            });
            return;
        }

        // Consistency check on the previous entry.
        if prev_log_index > self.last_index() {
            let conflict = self.last_index() + 1;
            self.send(meta.from, |m| Message::AppendResponse {
                meta: m,
                success: false,
                match_index: 0,
                conflict_index: conflict,
                applied_root: None,
            });
            return;
        }
        if self.term_at(prev_log_index) != Some(prev_log_term) {
            // Hint: first index of the conflicting term, never at or
            // below the commit index.
            let mut conflict = prev_log_index;
            let bad_term = self.term_at(prev_log_index);
            while conflict > self.commit + 1 && self.term_at(conflict - 1) == bad_term {
                conflict -= 1;
            }
            self.send(meta.from, |m| Message::AppendResponse {
                meta: m,
                success: false,
                match_index: 0,
                conflict_index: conflict,
                applied_root: None,
            });
            return;
        }

        // Append, truncating a divergent (uncommitted) suffix.
        let new_match = prev_log_index + entries.len() as Index;
        let mut truncated = false;
        for e in entries {
            match self.term_at(e.index) {
                Some(t) if t == e.term => {} // already present
                Some(_) => {
                    if e.index <= self.commit {
                        // A leader contradicting our committed prefix
                        // is protocol corruption; fail closed.
                        return;
                    }
                    self.truncate_from(e.index);
                    truncated = true;
                    self.append_entry(e);
                }
                None => self.append_entry(e),
            }
        }
        if truncated {
            self.rebuild_membership();
        }

        // Commit what the leader has committed, capped to the prefix we
        // know matches the leader.
        let new_commit = leader_commit.min(new_match).max(self.commit);
        self.advance_commit_to(new_commit);

        // Adopt the leader's verified watermark for whatever we have
        // committed ourselves (monotonic).
        let v = leader_verified.min(self.commit);
        if v > self.verified {
            self.verified = v;
        }

        let applied_root = self.last_applied_report;
        self.send(meta.from, |m| Message::AppendResponse {
            meta: m,
            success: true,
            match_index: new_match,
            conflict_index: 0,
            applied_root,
        });
    }

    fn handle_append_response(
        &mut self,
        meta: MsgMeta,
        success: bool,
        match_index: Index,
        conflict_index: Index,
    ) {
        if self.role != Role::Leader || meta.term != self.term {
            return;
        }
        let last = self.last_index();
        let base = self.base_index;
        let Some(pr) = self.progress.get_mut(&meta.from) else {
            return;
        };
        if success {
            // Cap at our own last index: an honest follower can never
            // match beyond what we sent, and a corrupt report must not
            // poison progress accounting.
            let match_index = match_index.min(last);
            if match_index > pr.match_index {
                pr.match_index = match_index;
            }
            pr.next_index = pr.match_index + 1;
            if pr.match_index >= base {
                // Snapshot installed (or never needed): appends resume.
                pr.needs_snapshot = false;
            }
            let more = pr.next_index <= last;
            self.advance_commit();
            if more {
                self.send_append(meta.from);
            }
        } else {
            // Back off to the follower's hint and re-probe.
            let floor = pr.match_index + 1;
            pr.next_index = conflict_index.clamp(floor, last + 1).max(1);
            self.send_append(meta.from);
        }
    }

    // ── Role transitions ────────────────────────────────────────────

    fn become_follower(&mut self, term: Term, leader: Option<NodeId>) {
        if term > self.term {
            self.term = term;
            self.voted_for = None;
            self.hard_state_dirty = true;
        }
        self.role = Role::Follower;
        self.leader_id = leader;
        self.election_elapsed = 0;
        self.heartbeat_elapsed = 0;
        self.votes.clear();
        self.progress.clear();
        // Leader-side verification bookkeeping is meaningless as a
        // follower; the verified watermark itself is monotonic and kept.
        self.root_history.clear();
        self.latest_reports.clear();
        self.match_watermark.clear();
        self.disputed.clear();
        self.deadlock_reported = None;
        self.reset_election_timeout();
    }

    fn campaign(&mut self) {
        self.role = Role::Candidate;
        self.term += 1;
        self.voted_for = Some(self.cfg.id);
        self.hard_state_dirty = true;
        self.leader_id = None;
        self.votes.clear();
        self.election_elapsed = 0;
        self.reset_election_timeout();

        if self.membership.quorum() == 1 {
            self.become_leader();
            return;
        }
        let (last_log_index, last_log_term) = (self.last_index(), self.last_term());
        let voters: Vec<NodeId> = self
            .membership
            .voters
            .keys()
            .copied()
            .filter(|&id| id != self.cfg.id)
            .collect();
        for to in voters {
            self.send(to, |m| Message::RequestVote { meta: m, last_log_index, last_log_term });
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_id = Some(self.cfg.id);
        self.heartbeat_elapsed = 0;
        self.votes.clear();
        self.recovery_active = false;
        // Seed our root history with the state machine's current
        // report so aligned follower reports compare immediately.
        self.root_history.clear();
        self.latest_reports.clear();
        self.match_watermark.clear();
        self.disputed.clear();
        self.deadlock_reported = None;
        if let Some((i, r)) = self.last_applied_report {
            self.root_history.insert(i, r);
        }
        self.sync_progress();
        // Commit-the-term entry (§5.4.2: a leader may only count
        // replicas for entries of its own term).
        self.append_local(EntryKind::Noop, Vec::new());
        self.maybe_refresh_incarnations();
        self.bcast_append();
        self.advance_commit();
    }

    // ── Log helpers ─────────────────────────────────────────────────

    fn term_at(&self, idx: Index) -> Option<Term> {
        if idx == self.base_index {
            return Some(self.base_term);
        }
        if idx < self.base_index {
            return None; // compacted away
        }
        self.pos(idx).and_then(|p| self.log.get(p)).map(|e| e.term)
    }

    fn append_local(&mut self, kind: EntryKind, data: Vec<u8>) -> Index {
        let index = self.last_index() + 1;
        let entry = Entry { term: self.term, index, kind, data };
        self.append_entry(entry);
        index
    }

    fn append_entry(&mut self, e: Entry) {
        debug_assert_eq!(e.index, self.last_index() + 1);
        if e.kind == EntryKind::Config {
            if let Some(cc) = ConfigChange::decode(&e.data) {
                self.membership.apply(&cc);
                if self.role == Role::Leader {
                    self.sync_progress();
                }
                if self.self_admitted() {
                    self.recovery_active = false;
                }
            }
        }
        if e.index < self.persist_from {
            self.persist_from = e.index;
        }
        self.log.push(e);
    }

    fn truncate_from(&mut self, idx: Index) {
        debug_assert!(idx > self.commit, "never truncate committed entries");
        let pos = self.pos(idx).expect("truncate below base");
        self.log.truncate(pos);
        self.persist_from = self.persist_from.min(idx);
        self.pending_truncate =
            Some(self.pending_truncate.map_or(idx, |t| t.min(idx)));
    }

    fn rebuild_membership(&mut self) {
        let mut m = self.base_membership.clone();
        for e in &self.log {
            if e.kind == EntryKind::Config {
                if let Some(cc) = ConfigChange::decode(&e.data) {
                    m.apply(&cc);
                }
            }
        }
        self.membership = m;
        if self.role == Role::Leader {
            self.sync_progress();
        }
    }

    /// Leader: keep one progress entry per member (except self).
    fn sync_progress(&mut self) {
        let next_default = self.last_index() + 1;
        let members: Vec<NodeId> = self
            .membership
            .voters
            .keys()
            .copied()
            .chain(self.membership.learners.iter().copied())
            .filter(|&id| id != self.cfg.id)
            .collect();
        self.progress.retain(|id, _| members.contains(id));
        for id in members {
            self.progress
                .entry(id)
                .or_insert(Progress {
                    match_index: 0,
                    next_index: next_default,
                    needs_snapshot: false,
                });
        }
    }

    // ── Replication ─────────────────────────────────────────────────

    fn bcast_append(&mut self) {
        let peers: Vec<NodeId> = self.progress.keys().copied().collect();
        for to in peers {
            self.send_append(to);
        }
    }

    fn send_append(&mut self, to: NodeId) {
        let Some(pr) = self.progress.get(&to) else { return };
        if pr.needs_snapshot {
            return; // transfer in progress, driven outside the core
        }
        let prev_log_index = pr.next_index - 1;
        let Some(prev_log_term) = self.term_at(prev_log_index) else {
            // The follower is behind our compaction base: the log
            // cannot serve it, only a snapshot can. Signal the driver
            // once; cleared when the follower's match passes the base.
            let base = self.base_index;
            if let Some(pr) = self.progress.get_mut(&to) {
                pr.needs_snapshot = true;
            }
            self.events.push(RaftEvent::SnapshotNeeded { node: to, base_index: base });
            return;
        };
        let from = pr.next_index;
        let Some(from_pos) = self.pos(from) else { return };
        let entries: Vec<Entry> = self
            .log
            .iter()
            .skip(from_pos)
            .take(self.cfg.max_entries_per_msg)
            .cloned()
            .collect();
        let commit = self.commit;
        let verified = self.verified;
        self.send(to, |m| Message::AppendEntries {
            meta: m,
            prev_log_index,
            prev_log_term,
            commit,
            verified,
            entries,
        });
    }

    /// Leader: advance the commit index over quorum-matched entries of
    /// the current term (§5.4.2).
    fn advance_commit(&mut self) {
        if self.role != Role::Leader {
            return;
        }
        let mut n = self.last_index();
        while n > self.commit {
            if self.term_at(n) == Some(self.term) {
                let count = self
                    .membership
                    .voters
                    .keys()
                    .filter(|&&v| {
                        if v == self.cfg.id {
                            true // our own log always matches
                        } else {
                            self.progress.get(&v).is_some_and(|p| p.match_index >= n)
                        }
                    })
                    .count();
                if count >= self.membership.quorum() {
                    self.advance_commit_to(n);
                    // Propagate the new commit index promptly.
                    self.bcast_append();
                    return;
                }
            }
            n -= 1;
        }
    }

    fn advance_commit_to(&mut self, new_commit: Index) {
        if new_commit <= self.commit {
            return;
        }
        let old = self.commit;
        self.commit = new_commit;
        // A committed RemoveNode(self) deposes a leader.
        for i in (old + 1)..=new_commit {
            let Some(e) = self.pos(i).and_then(|p| self.log.get(p)) else { break };
            if e.kind == EntryKind::Config {
                if let Some(ConfigChange::RemoveNode { node }) = ConfigChange::decode(&e.data) {
                    if node == self.cfg.id && self.role == Role::Leader {
                        let term = self.term;
                        self.become_follower(term, None);
                    }
                }
            }
        }
    }

    /// Leader: re-admit restarted voters whose observed incarnation
    /// differs from the recorded one (one config change at a time).
    fn maybe_refresh_incarnations(&mut self) {
        if self.role != Role::Leader || self.has_pending_conf_change() {
            return;
        }
        // Self first (a recovery-elected leader re-admits itself).
        if !self.self_admitted() && self.membership.is_voter(self.cfg.id) {
            let cc = ConfigChange::RefreshIncarnation {
                node: self.cfg.id,
                incarnation: self.cfg.incarnation,
            };
            let _ = self.propose_conf_change(cc);
            return;
        }
        let stale: Option<(NodeId, Incarnation)> =
            self.membership.voters.iter().find_map(|(&id, &rec)| {
                if id == self.cfg.id {
                    return None;
                }
                match self.seen_incarnations.get(&id) {
                    Some(&seen) if seen != rec => Some((id, seen)),
                    _ => None,
                }
            });
        if let Some((node, incarnation)) = stale {
            let _ = self.propose_conf_change(ConfigChange::RefreshIncarnation { node, incarnation });
        }
    }

    // ── Ready ───────────────────────────────────────────────────────

    /// Drain accumulated obligations. See the driver contract.
    pub fn ready(&mut self) -> Ready {
        let entries_to_persist: Vec<Entry> = match self.pos(self.persist_from) {
            Some(p) => self.log.iter().skip(p).cloned().collect(),
            None => Vec::new(),
        };
        self.persist_from = self.last_index() + 1;

        let hard_state = if self.hard_state_dirty {
            self.hard_state_dirty = false;
            Some(HardState { term: self.term, voted_for: self.voted_for })
        } else {
            None
        };

        let committed_entries: Vec<Entry> = ((self.applied + 1)..=self.commit)
            .filter_map(|i| self.pos(i).and_then(|p| self.log.get(p)).cloned())
            .collect();
        // max(): after a restart the applied floor can be ahead of the
        // not-yet-recovered commit index; it must never move backwards.
        self.applied = self.applied.max(self.commit);

        Ready {
            truncate_from: self.pending_truncate.take(),
            entries_to_persist,
            hard_state,
            messages: std::mem::take(&mut self.msgs),
            committed_entries,
            events: std::mem::take(&mut self.events),
        }
    }

    // ── Internals ───────────────────────────────────────────────────

    fn send(&mut self, to: NodeId, build: impl FnOnce(MsgMeta) -> Message) {
        let meta =
            MsgMeta { from: self.cfg.id, term: self.term, incarnation: self.cfg.incarnation };
        self.msgs.push((to, build(meta)));
    }

    fn reset_election_timeout(&mut self) {
        let jitter = (self.rng.next() % self.cfg.election_tick as u64) as u32;
        self.randomized_election_tick = self.cfg.election_tick + jitter;
    }
}

/// SplitMix64 — deterministic jitter source, seeded by the driver.
struct SplitMix64(u64);

impl SplitMix64 {
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
}
