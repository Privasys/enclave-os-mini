// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Cluster glue: owns the [`RaftDriver`] and the [`PeerLink`], routes
//! data-channel messages and ticks into consensus, and exposes the
//! `raft_*` module envelope over `POST /data`.
//!
//! Lock discipline: `RAFT` is a global independent of
//! [`crate::state()`]. The event loop takes it WITHOUT the state lock
//! (peer traffic never touches the ingress server); module dispatch
//! takes it while the state lock is held (st → RAFT order). There is
//! no RAFT → st path, so no deadlock.
//!
//! Cluster keys: the ledger commitment key `ck` derives from the
//! operator-provisioned `raft_cluster_key` (all replicas share it — the
//! encryption-independent root requires it), while the ledger storage
//! key and the log key derive from this enclave's sealed master key
//! (node-local). In-band attested `ck` provisioning replaces the
//! operator secret when the join flow lands.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use enclave_os_common::channel::ChannelMsgType;
use enclave_os_common::hex::{hex_decode, hex_encode};
use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};

use enclave_os_merkle::{MerkleStore, OcallBackend};
use enclave_os_raft::{
    Config, DriverError, DriverOutput, LogStore, Message, MsgMeta, NodeId, RaftDriver,
    RaftEvent, ReceiverStep, Role, SenderStep, SnapshotReceiver, SnapshotSender,
};

use crate::enclave_log_error;
use crate::enclave_log_info;
use crate::peerlink::{PeerEvent, PeerLink};
use crate::ratls::attestation::CaContext;

/// Ticks (100 ms each) between redial attempts to a down peer.
const REDIAL_TICKS: u32 = 20;

/// Compaction check cadence (ticks).
const COMPACT_EVERY_TICKS: u64 = 64;

/// A snapshot transfer with no progress for this many ticks is dropped
/// (the pause re-signals and the transfer restarts).
const TRANSFER_STALL_TICKS: u64 = 100;

static RAFT: OnceLock<Mutex<RaftGlue>> = OnceLock::new();

/// Install the glue (once, at module registration).
pub fn install(glue: RaftGlue) -> bool {
    RAFT.set(Mutex::new(glue)).is_ok()
}

/// Event-loop entry: returns true if the raft layer consumed the
/// message (peer-range conn or tick).
pub fn handle_channel_msg(msg_type: ChannelMsgType, conn_id: u32, payload: &[u8]) -> bool {
    let Some(glue) = RAFT.get() else { return false };
    let mut g = match glue.lock() {
        Ok(g) => g,
        Err(_) => return true, // poisoned: swallow rather than wedge ingress
    };
    if msg_type == ChannelMsgType::Tick {
        g.tick();
    } else {
        g.handle_peer_msg(msg_type, conn_id, payload);
    }
    true
}

fn derive(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, label);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn now_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}

/// The cluster runtime for this node.
pub struct RaftGlue {
    driver: RaftDriver<OcallBackend>,
    link: PeerLink,
    /// Configured peers: node id → `host:port`.
    peers: BTreeMap<NodeId, String>,
    /// Established connection per peer (either direction).
    node_conns: BTreeMap<NodeId, u32>,
    conn_nodes: BTreeMap<u32, NodeId>,
    /// Outbound dials awaiting establishment: conn → intended peer.
    dial_pending: BTreeMap<u32, NodeId>,
    /// Ticks until the next dial attempt per down peer.
    backoff: BTreeMap<NodeId, u32>,
    /// Materials for ledger repair-by-replay.
    node_id: NodeId,
    ck: [u8; 32],
    sk: [u8; 32],
    log_key: [u8; 32],
    seed: u64,
    /// One automatic repair per boot; a repeat divergence is a bug.
    repair_attempted: bool,
    diverged_logged: bool,
    /// Keep roughly this many applied entries in the log.
    log_retain: u64,
    /// Tick counter (compaction cadence + transfer stall detection).
    ticks: u64,
    /// Leader-side snapshot transfers: node → (sender, last activity).
    snapshot_sends: BTreeMap<NodeId, (SnapshotSender, u64)>,
    /// Follower-side transfer in progress (one at a time).
    snapshot_recv: Option<(SnapshotReceiver<OcallBackend>, u64)>,
    /// Last logged (role, term, leader, commit, verified) for
    /// transition logging.
    last_logged: Option<(Role, u64, Option<NodeId>, u64, u64)>,
}

impl RaftGlue {
    pub fn new(
        master_key: [u8; 32],
        cluster_key: [u8; 32],
        node_id: NodeId,
        peers: BTreeMap<NodeId, String>,
        genesis_voters: Option<Vec<NodeId>>,
        ca: CaContext,
        pin_measurement: bool,
        log_retain: u64,
    ) -> Result<Self, String> {
        let ck = derive(&cluster_key, b"enclave-os-raft:ck:v1");
        let sk = derive(&master_key, b"enclave-os-raft:sk:v1");
        let log_key = derive(&master_key, b"enclave-os-raft:log:v1");

        let ledger_backend = OcallBackend::with_table("raft:ledger");
        let log_backend = OcallBackend::with_table("raft:log");

        let store = MerkleStore::open_or_create(ledger_backend, ck, sk)
            .map_err(|e| format!("raft ledger: {e}"))?;

        // Jitter seed + restart incarnation from in-enclave randomness:
        // the incarnation gate depends on the host being unable to pin
        // these across a rollback.
        let rng = SystemRandom::new();
        let mut buf = [0u8; 16];
        rng.fill(&mut buf).map_err(|_| "rng".to_string())?;
        let random_incarnation = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let seed = u64::from_le_bytes(buf[8..16].try_into().unwrap());

        let exists = LogStore::exists(&log_backend).map_err(|e| format!("raft log: {e}"))?;
        // Genesis convention: a bootstrapping node starts at
        // incarnation 0, which is what the genesis membership admits.
        // Every restart draws a fresh random incarnation (the
        // anti-double-vote gate). Residual: a host that wipes the log
        // back to genesis re-enters at incarnation 0 until the first
        // committed refresh retires it — documented in the plan,
        // constrained by quorum root confirmation.
        // A joining node supplies the CLUSTER's genesis voters via
        // config (itself not among them) and enters as a non-member
        // until the leader commits an AddLearner for it. Bootstrapping
        // founders default to "all configured nodes are voters".
        let joining =
            genesis_voters.as_ref().map(|v| !v.contains(&node_id)).unwrap_or(false);
        let incarnation = if exists || joining { random_incarnation } else { 0 };
        let cfg = Config::new(node_id, incarnation, seed);
        let driver = if exists {
            RaftDriver::restore(cfg, log_backend, log_key, store)
        } else {
            let voters: Vec<NodeId> = match genesis_voters {
                Some(v) => v,
                None => {
                    let mut voters: Vec<NodeId> = peers.keys().copied().collect();
                    voters.push(node_id);
                    voters.sort_unstable();
                    voters
                }
            };
            RaftDriver::bootstrap(cfg, &voters, log_backend, log_key, store)
        }
        .map_err(|e| format!("raft driver: {e:?}"))?;

        // Peer links only accept enclaves running the SAME binary
        // unless the operator explicitly disables the pin (needed
        // transiently during a measurement rotation).
        let pinned = if pin_measurement {
            Some(
                crate::ratls::attestation::self_mrenclave()
                    .map_err(|e| format!("self measurement for peer pinning: {e}"))?,
            )
        } else {
            None
        };
        let link = PeerLink::new(ca, pinned)?;
        enclave_log_info!(
            "raft node {} up ({} peers, {})",
            node_id,
            peers.len(),
            if exists { "restored" } else { "bootstrapped" }
        );
        Ok(Self {
            driver,
            link,
            peers,
            node_conns: BTreeMap::new(),
            conn_nodes: BTreeMap::new(),
            dial_pending: BTreeMap::new(),
            backoff: BTreeMap::new(),
            node_id,
            ck,
            sk,
            log_key,
            seed,
            repair_attempted: false,
            diverged_logged: false,
            log_retain,
            ticks: 0,
            snapshot_sends: BTreeMap::new(),
            snapshot_recv: None,
            last_logged: None,
        })
    }

    fn own_meta(&self) -> MsgMeta {
        let Message::Hello { meta } = self.driver.core().hello() else { unreachable!() };
        meta
    }

    /// Repair-by-replay: fresh ledger over the same backend, zeroed
    /// applied floor, full deterministic replay of the committed log.
    fn repair(&mut self) -> Result<(), String> {
        let rng = SystemRandom::new();
        let mut buf = [0u8; 8];
        rng.fill(&mut buf).map_err(|_| "rng".to_string())?;
        let incarnation = u64::from_le_bytes(buf);
        let fresh = MerkleStore::create(
            OcallBackend::with_table("raft:ledger"),
            self.ck,
            self.sk,
        )
        .map_err(|e| format!("fresh ledger: {e}"))?;
        let cfg = Config::new(self.node_id, incarnation, self.seed.wrapping_add(incarnation));
        self.driver = enclave_os_raft::RaftDriver::rebuild(
            cfg,
            OcallBackend::with_table("raft:log"),
            self.log_key,
            fresh,
        )
        .map_err(|e| format!("rebuild: {e:?}"))?;
        Ok(())
    }

    // ── Event-loop inputs ───────────────────────────────────────────

    fn handle_peer_msg(&mut self, msg_type: ChannelMsgType, conn_id: u32, payload: &[u8]) {
        let events = self.link.handle_message(msg_type, conn_id, payload, now_secs());
        for ev in events {
            match ev {
                PeerEvent::Established(cid) => {
                    if let Some(node) = self.dial_pending.remove(&cid) {
                        self.map_conn(node, cid);
                    }
                    // Introduce ourselves so the peer can map this
                    // connection before any consensus traffic (a
                    // joining non-member never speaks otherwise).
                    let hello = self.driver.core().hello().encode();
                    self.link.send_frame(cid, &hello);
                }
                PeerEvent::Frame(cid, bytes) => {
                    let Some(msg) = Message::decode(&bytes) else {
                        enclave_log_error!("peer frame decode failed, closing conn {}", cid);
                        self.unmap_conn(cid);
                        self.link.close(cid);
                        continue;
                    };
                    // Learn the peer behind an inbound connection from
                    // its first message (the channel authenticated it
                    // as fleet; the id is routing metadata).
                    let from = msg.meta().from;
                    if !self.conn_nodes.contains_key(&cid) {
                        self.map_conn(from, cid);
                    }
                    // Snapshot transfer runs outside the core.
                    match msg {
                        Message::SnapshotStart {
                            meta, index, term, ledger_version, root, membership,
                        } => self.on_snapshot_start(
                            meta.from, index, term, ledger_version, root, membership,
                        ),
                        Message::SnapshotChunk { seq, leaves, done, .. } => {
                            self.on_snapshot_chunk(seq, leaves, done)
                        }
                        Message::SnapshotAck { meta, seq, done } => {
                            self.on_snapshot_ack(meta.from, seq, done)
                        }
                        msg => self.drive(|d| d.step(msg)),
                    }
                }
                PeerEvent::Closed(cid) => {
                    self.dial_pending.remove(&cid);
                    self.unmap_conn(cid);
                }
            }
        }
    }

    // ── Snapshot transfer (outside the core) ────────────────────────

    fn send_to(&mut self, node: NodeId, msg: &Message) {
        if let Some(&cid) = self.node_conns.get(&node) {
            self.link.send_frame(cid, &msg.encode());
        }
    }

    /// Pin the oldest ledger version any active transfer streams from.
    fn repin(&mut self) {
        let min = self.snapshot_sends.values().map(|(s, _)| s.ledger_version()).min();
        self.driver.ledger_pin(min);
    }

    fn start_snapshot_send(&mut self, node: NodeId) {
        if self.snapshot_sends.contains_key(&node) {
            return;
        }
        let meta = self.own_meta();
        let (sender, start_msg) = SnapshotSender::start(&mut self.driver, node, meta);
        enclave_log_info!(
            "raft: streaming snapshot to {} at index {} (ledger v{})",
            node,
            sender.index(),
            sender.ledger_version()
        );
        self.snapshot_sends.insert(node, (sender, self.ticks));
        self.repin();
        self.send_to(node, &start_msg);
    }

    /// Drop a (failed or stalled) transfer and nudge the core so its
    /// next append attempt re-detects the lag and restarts it.
    fn abort_snapshot_send(&mut self, node: NodeId) {
        if self.snapshot_sends.remove(&node).is_some() {
            self.repin();
            self.drive(|d| d.snapshot_transferred(node, 0));
        }
    }

    fn on_snapshot_start(
        &mut self,
        from: NodeId,
        index: u64,
        term: u64,
        ledger_version: u64,
        root: [u8; 32],
        membership: enclave_os_raft::Membership,
    ) {
        enclave_log_info!(
            "raft: receiving snapshot from {} at index {} (ledger v{})",
            from,
            index,
            ledger_version
        );
        // Building writes over the live ledger table; this node is
        // behind anyway, and a crash mid-transfer recovers by
        // repair-by-replay of the intact local log.
        let backend = OcallBackend::with_table("raft:ledger");
        let meta = self.own_meta();
        match SnapshotReceiver::start(
            from,
            index,
            term,
            ledger_version,
            root,
            membership,
            backend,
            self.ck,
            self.sk,
            meta,
        ) {
            Ok((recv, ack)) => {
                self.snapshot_recv = Some((recv, self.ticks));
                self.send_to(from, &ack);
            }
            Err(e) => enclave_log_error!("raft: snapshot receive start failed: {:?}", e),
        }
    }

    fn on_snapshot_chunk(&mut self, seq: u64, leaves: Vec<([u8; 32], Vec<u8>)>, done: bool) {
        let Some((recv, _)) = self.snapshot_recv.take() else { return };
        let from = recv.from;
        let meta = self.own_meta();
        match recv.on_chunk(&mut self.driver, meta, seq, leaves, done) {
            Ok((next, ReceiverStep::Ack(ack))) => {
                if let Some(n) = next {
                    self.snapshot_recv = Some((n, self.ticks));
                }
                self.send_to(from, &ack);
            }
            Ok((_, ReceiverStep::Installed(ack))) => {
                enclave_log_info!("raft: snapshot installed");
                self.send_to(from, &ack);
            }
            Err(e) => {
                enclave_log_error!("raft: snapshot receive failed: {:?}", e);
            }
        }
    }

    fn on_snapshot_ack(&mut self, from: NodeId, seq: u64, done: bool) {
        let meta = self.own_meta();
        let ticks = self.ticks;
        let step = {
            let Some((sender, act)) = self.snapshot_sends.get_mut(&from) else { return };
            *act = ticks;
            match sender.on_ack(&self.driver, meta, seq, done) {
                Ok(s) => s,
                Err(e) => {
                    enclave_log_error!("raft: snapshot send failed: {:?}", e);
                    self.abort_snapshot_send(from);
                    return;
                }
            }
        };
        match step {
            SenderStep::Send(msg) => self.send_to(from, &msg),
            SenderStep::Finished { index } => {
                self.snapshot_sends.remove(&from);
                self.repin();
                enclave_log_info!("raft: snapshot to {} complete at index {}", from, index);
                self.drive(|d| d.snapshot_transferred(from, index));
            }
            SenderStep::Ignore => {}
        }
    }

    fn tick(&mut self) {
        self.ticks += 1;
        self.drive(|d| d.tick());

        // Periodic log compaction (all roles compact their own log).
        if self.ticks % COMPACT_EVERY_TICKS == 0 {
            let retain = self.log_retain;
            if let Err(e) = self.driver.maybe_compact(retain) {
                enclave_log_error!("raft: compaction failed: {:?}", e);
            }
        }

        // Drop stalled transfers; the pause re-signals and they restart.
        let stalled: Vec<NodeId> = self
            .snapshot_sends
            .iter()
            .filter(|(_, (_, act))| self.ticks.saturating_sub(*act) > TRANSFER_STALL_TICKS)
            .map(|(&n, _)| n)
            .collect();
        for n in stalled {
            enclave_log_error!("raft: snapshot to {} stalled, retrying", n);
            self.abort_snapshot_send(n);
        }
        if let Some((_, act)) = &self.snapshot_recv {
            if self.ticks.saturating_sub(*act) > TRANSFER_STALL_TICKS {
                enclave_log_error!("raft: snapshot receive stalled, dropping");
                self.snapshot_recv = None;
            }
        }

        // Log consensus-state transitions (role, term, leader, commit,
        // verified) so cluster health is visible from container logs.
        {
            let core = self.driver.core();
            let now = (
                core.role(),
                core.term(),
                core.leader_id(),
                core.commit_index(),
                core.verified_index(),
            );
            if self.last_logged != Some(now) {
                self.last_logged = Some(now);
                enclave_log_info!(
                    "raft: role={:?} term={} leader={:?} commit={} verified={}",
                    now.0,
                    now.1,
                    now.2,
                    now.3,
                    now.4
                );
            }
        }

        // Redial down peers with backoff.
        let down: Vec<(NodeId, String)> = self
            .peers
            .iter()
            .filter(|(id, _)| !self.node_conns.contains_key(id))
            .map(|(&id, addr)| (id, addr.clone()))
            .collect();
        for (node, addr) in down {
            let b = self.backoff.entry(node).or_insert(0);
            if *b > 0 {
                *b -= 1;
                continue;
            }
            *b = REDIAL_TICKS;
            match self.link.dial(&addr, now_secs()) {
                Ok(cid) => {
                    self.dial_pending.insert(cid, node);
                }
                Err(e) => {
                    enclave_log_error!("raft dial {} ({}): {}", node, addr, e);
                }
            }
        }
    }

    // ── Driving the consensus core ──────────────────────────────────

    fn drive(
        &mut self,
        f: impl FnOnce(&mut RaftDriver<OcallBackend>) -> Result<DriverOutput, DriverError>,
    ) {
        match f(&mut self.driver) {
            Ok(out) => self.dispatch(out),
            Err(DriverError::Diverged { index, .. }) => {
                enclave_log_error!("raft ledger DIVERGED at index {}", index);
                if self.repair_attempted {
                    if !self.diverged_logged {
                        self.diverged_logged = true;
                        enclave_log_error!(
                            "raft: divergence AFTER repair — halted, operator needed"
                        );
                    }
                    return;
                }
                self.repair_attempted = true;
                match self.repair() {
                    Ok(()) => enclave_log_error!(
                        "raft: ledger rebuilt by replay after divergence at index {}",
                        index
                    ),
                    Err(e) => {
                        self.diverged_logged = true;
                        enclave_log_error!("raft: repair failed: {} — halted", e);
                    }
                }
            }
            Err(e) => enclave_log_error!("raft driver error: {:?}", e),
        }
    }

    fn dispatch(&mut self, out: DriverOutput) {
        for (to, msg) in out.messages {
            if let Some(&cid) = self.node_conns.get(&to) {
                self.link.send_frame(cid, &msg.encode());
            }
            // No link yet: drop — raft retries via heartbeat.
        }
        for ev in out.events {
            match ev {
                RaftEvent::SnapshotNeeded { node, .. } => self.start_snapshot_send(node),
                ev => enclave_log_error!("raft verification event: {:?}", ev),
            }
        }
    }

    fn map_conn(&mut self, node: NodeId, cid: u32) {
        // A newer connection supersedes an older one to the same peer.
        if let Some(old) = self.node_conns.insert(node, cid) {
            if old != cid {
                self.conn_nodes.remove(&old);
                self.link.close(old);
            }
        }
        self.conn_nodes.insert(cid, node);
        self.backoff.insert(node, 0);
    }

    fn unmap_conn(&mut self, cid: u32) {
        if let Some(node) = self.conn_nodes.remove(&cid) {
            if self.node_conns.get(&node) == Some(&cid) {
                self.node_conns.remove(&node);
            }
            self.backoff.insert(node, REDIAL_TICKS);
        }
    }

    // ── Module surface ──────────────────────────────────────────────

    fn status_json(&self) -> serde_json::Value {
        let core = self.driver.core();
        let (root, version) = self.driver.ledger().root();
        let m = core.membership();
        serde_json::json!({
            "node": core.id(),
            "role": match core.role() {
                Role::Leader => "leader",
                Role::Candidate => "candidate",
                Role::Follower => "follower",
            },
            "term": core.term(),
            "leader": core.leader_id(),
            "commit": core.commit_index(),
            "verified": core.verified_index(),
            "log_base": core.base().0,
            "ledger_root": hex_encode(&root),
            "ledger_version": version,
            "admitted": core.self_admitted(),
            "halted": self.driver.is_halted(),
            "voters": m.voters.keys().collect::<Vec<_>>(),
            "learners": m.learners.iter().collect::<Vec<_>>(),
            "connected_peers": self.node_conns.keys().collect::<Vec<_>>(),
        })
    }

    fn propose(&mut self, ops: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Response {
        match self.driver.propose_transaction(&ops) {
            Ok((index, out)) => {
                self.dispatch(out);
                ok_json(serde_json::json!({ "index": index, "status": "proposed" }))
            }
            Err(_) => self.not_leader(),
        }
    }

    fn propose_member_change(&mut self, cc: enclave_os_raft::ConfigChange) -> Response {
        match self.driver.propose_conf_change(cc) {
            Ok((index, out)) => {
                self.dispatch(out);
                ok_json(serde_json::json!({ "index": index, "status": "proposed" }))
            }
            Err(enclave_os_raft::ProposeError::ConfigChangePending) => {
                err_json("a membership change is already in flight")
            }
            Err(_) => self.not_leader(),
        }
    }

    fn not_leader(&self) -> Response {
        err_json_with(serde_json::json!({
            "error": "not the leader",
            "leader": self.driver.core().leader_id(),
        }))
    }
}

// ── The module ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RaftEnvelope {
    #[serde(default)]
    raft_status: Option<serde_json::Value>,
    #[serde(default)]
    raft_txn: Option<TxnReq>,
    #[serde(default)]
    raft_add_learner: Option<MemberReq>,
    #[serde(default)]
    raft_promote: Option<MemberReq>,
    #[serde(default)]
    raft_remove: Option<MemberReq>,
}

#[derive(Deserialize)]
struct MemberReq {
    node: u64,
}

#[derive(Deserialize)]
struct TxnReq {
    ops: Vec<TxnOp>,
}

#[derive(Deserialize)]
struct TxnOp {
    key: String,
    #[serde(default)]
    value: Option<String>,
}

fn ok_json(value: serde_json::Value) -> Response {
    Response::Data(value.to_string().into_bytes())
}

fn err_json(msg: &str) -> Response {
    Response::Error(serde_json::json!({ "error": msg }).to_string().into_bytes())
}

fn err_json_with(value: serde_json::Value) -> Response {
    Response::Error(value.to_string().into_bytes())
}

/// `POST /data` envelope: `raft_status` (monitoring), `raft_txn`
/// (manager; keys/values hex, op without `value` = delete).
pub struct RaftModule;

impl EnclaveModule for RaftModule {
    fn name(&self) -> &str {
        "raft"
    }

    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };
        let env: RaftEnvelope = match serde_json::from_slice(data) {
            Ok(e) => e,
            Err(_) => return None,
        };
        let is_read = env.raft_status.is_some();
        let is_write = env.raft_txn.is_some()
            || env.raft_add_learner.is_some()
            || env.raft_promote.is_some()
            || env.raft_remove.is_some();
        if !is_read && !is_write {
            return None;
        }
        let claims = match &ctx.oidc_claims {
            Some(c) => c,
            None => return Some(err_json("authentication required")),
        };
        if is_write && !claims.has_manager() {
            return Some(err_json("manager role required"));
        }
        if !is_write && !claims.has_monitoring() {
            return Some(err_json("monitoring role required"));
        }

        let glue = RAFT.get()?;
        let mut g = match glue.lock() {
            Ok(g) => g,
            Err(_) => return Some(err_json("raft state poisoned")),
        };

        if env.raft_status.is_some() {
            let status = g.status_json();
            return Some(ok_json(status));
        }
        if let Some(req) = env.raft_add_learner {
            return Some(g.propose_member_change(
                enclave_os_raft::ConfigChange::AddLearner { node: req.node },
            ));
        }
        if let Some(req) = env.raft_promote {
            let Some(incarnation) = g.driver.core().peer_incarnation(req.node) else {
                return Some(err_json("node not seen yet (is the learner connected?)"));
            };
            return Some(g.propose_member_change(
                enclave_os_raft::ConfigChange::PromoteVoter { node: req.node, incarnation },
            ));
        }
        if let Some(req) = env.raft_remove {
            return Some(g.propose_member_change(
                enclave_os_raft::ConfigChange::RemoveNode { node: req.node },
            ));
        }
        if let Some(txn) = env.raft_txn {
            let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(txn.ops.len());
            for op in txn.ops {
                let Some(key) = hex_decode(&op.key) else {
                    return Some(err_json("key must be hex"));
                };
                let value = match op.value {
                    Some(v) => match hex_decode(&v) {
                        Some(v) => Some(v),
                        None => return Some(err_json("value must be hex")),
                    },
                    None => None,
                };
                ops.push((key, value));
            }
            return Some(g.propose(ops));
        }
        None
    }
}
