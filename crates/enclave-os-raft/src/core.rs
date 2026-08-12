// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The sans-I/O Raft state machine.
//!
//! No I/O, no clock, no randomness source: the driver feeds messages
//! ([`RaftCore::step`]) and time ([`RaftCore::tick`]), and drains
//! obligations from [`RaftCore::ready`]. See the crate docs for the
//! driver contract and the incarnation-gated voting model.

use std::collections::BTreeMap;

use crate::message::{Message, MsgMeta};
use crate::types::{
    ConfigChange, Entry, EntryKind, HardState, Incarnation, Index, Membership, NodeId, Role, Term,
};

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
    /// Entries newly committed: apply to the state machine in order.
    pub committed_entries: Vec<Entry>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.truncate_from.is_none()
            && self.entries_to_persist.is_empty()
            && self.hard_state.is_none()
            && self.messages.is_empty()
            && self.committed_entries.is_empty()
    }
}

/// Leader-side replication progress for one peer.
#[derive(Debug, Clone)]
struct Progress {
    match_index: Index,
    next_index: Index,
}

/// The Raft state machine for one node.
pub struct RaftCore {
    cfg: Config,

    // ── Durable state (mirrored to the driver via Ready) ────────────
    term: Term,
    voted_for: Option<NodeId>,
    /// The full log; entry with index `i` lives at position `i - 1`
    /// (no compaction in v1, first index is 1).
    log: Vec<Entry>,

    // ── Volatile state ──────────────────────────────────────────────
    role: Role,
    leader_id: Option<NodeId>,
    commit: Index,
    applied: Index,
    /// Current membership: base + every config entry in the log.
    membership: Membership,
    /// Membership before the first log entry (genesis in v1).
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

    // ── Ready accumulation ──────────────────────────────────────────
    msgs: Vec<(NodeId, Message)>,
    /// Index of the first log entry not yet handed to the driver.
    persist_from: Index,
    pending_truncate: Option<Index>,
    hard_state_dirty: bool,
}

impl RaftCore {
    /// Build a core from persisted state. For a fresh cluster use
    /// [`RaftCore::bootstrap`]. `log` must be contiguous from index 1;
    /// entries are assumed already persisted by the driver.
    pub fn new(
        cfg: Config,
        base_membership: Membership,
        log: Vec<Entry>,
        hard_state: HardState,
    ) -> Self {
        for (i, e) in log.iter().enumerate() {
            assert_eq!(e.index, i as Index + 1, "log must be contiguous from index 1");
        }
        let persist_from = log.len() as Index + 1;
        let seed = cfg.seed;
        let mut core = Self {
            cfg,
            term: hard_state.term,
            voted_for: hard_state.voted_for,
            log,
            role: Role::Follower,
            leader_id: None,
            commit: 0,
            applied: 0,
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
            msgs: Vec::new(),
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
        self.log.last().map(|e| e.index).unwrap_or(0)
    }
    pub fn last_term(&self) -> Term {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    /// Latest incarnation observed from a peer (for the driver to build
    /// `PromoteVoter` changes).
    pub fn peer_incarnation(&self, id: NodeId) -> Option<Incarnation> {
        self.seen_incarnations.get(&id).copied()
    }

    /// Is this node admitted to vote (its incarnation matches the one
    /// recorded in the replicated membership)?
    pub fn self_admitted(&self) -> bool {
        self.membership.voters.get(&self.cfg.id) == Some(&self.cfg.incarnation)
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
            Message::AppendEntries { meta, prev_log_index, prev_log_term, commit, entries } => {
                self.handle_append_entries(meta, prev_log_index, prev_log_term, commit, entries);
            }
            Message::AppendResponse { meta, success, match_index, conflict_index, .. } => {
                self.handle_append_response(meta, success, match_index, conflict_index);
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

        self.send(meta.from, |m| Message::AppendResponse {
            meta: m,
            success: true,
            match_index: new_match,
            conflict_index: 0,
            applied_root: None,
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
        if idx == 0 {
            return Some(0);
        }
        self.log.get(idx as usize - 1).map(|e| e.term)
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
        self.log.truncate(idx as usize - 1);
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
                .or_insert(Progress { match_index: 0, next_index: next_default });
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
        let prev_log_index = pr.next_index - 1;
        let Some(prev_log_term) = self.term_at(prev_log_index) else {
            // next_index below our first entry: needs a snapshot (WS4);
            // cannot happen in v1 (no compaction).
            return;
        };
        let from = pr.next_index;
        let entries: Vec<Entry> = self
            .log
            .iter()
            .skip(from as usize - 1)
            .take(self.cfg.max_entries_per_msg)
            .cloned()
            .collect();
        let commit = self.commit;
        self.send(to, |m| Message::AppendEntries {
            meta: m,
            prev_log_index,
            prev_log_term,
            commit,
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
            let Some(e) = self.log.get(i as usize - 1) else { break };
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
        let entries_to_persist: Vec<Entry> = self
            .log
            .iter()
            .skip(self.persist_from as usize - 1)
            .cloned()
            .collect();
        self.persist_from = self.last_index() + 1;

        let hard_state = if self.hard_state_dirty {
            self.hard_state_dirty = false;
            Some(HardState { term: self.term, voted_for: self.voted_for })
        } else {
            None
        };

        let committed_entries: Vec<Entry> = ((self.applied + 1)..=self.commit)
            .filter_map(|i| self.log.get(i as usize - 1).cloned())
            .collect();
        self.applied = self.commit;

        Ready {
            truncate_from: self.pending_truncate.take(),
            entries_to_persist,
            hard_state,
            messages: std::mem::take(&mut self.msgs),
            committed_entries,
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
