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
//! Cluster keys: the ledger commitment key `ck` (all replicas share
//! it — the encryption-independent root requires it) comes from ONE of
//! two sources: the vault constellation (`raft_vault` config — the key
//! is generated inside the first node's enclave, Shamir-split across
//! the vaults, and released only under the owner-authored grant policy
//! measurement + TCB checks; fetching the credential IS admission), or
//! the operator-provisioned `raft_cluster_key` (standalone/dev mode —
//! the host sees this secret, documented as the weaker model). A
//! vault-resolved `ck` is sealed node-locally so restarts do not
//! depend on vault availability. The ledger storage key and the log
//! key derive from this enclave's sealed master key (node-local).
//!
//! Peer admission: beyond the fleet-CA + measurement-set pin enforced
//! in the TLS layer (see `peerlink`), each established link's peer
//! quote is sent to the configured attestation servers (central
//! config, OID 2.7) and gated on the verified MRENCLAVE + the Intel
//! TCB status against `raft_acceptable_tcb_statuses` — tri-state
//! exactly like the vault: absent = no TCB check (rollout safety),
//! `[]` = strict floor-only, a list = floor + list, Revoked never
//! accepted. Verdicts are cached per cert fingerprint; links older
//! than the re-attestation window are recycled so fresh quotes are
//! presented (certs are minted per connection).

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

/// How long a PASSED attestation-server verdict for a peer cert is
/// cached (1 hour) — keeps the AS off the steady-state hot path.
const VERIFY_PASS_TICKS: u64 = 36_000;

/// How long a FAILED verdict is cached (1 minute) — rate-limits AS
/// calls while a rejected peer keeps redialing, without pinning the
/// rejection long past a TCB recovery.
const VERIFY_FAIL_TICKS: u64 = 600;

/// How often the admissible measurement set is re-read from the
/// credential policy in vault mode (10 minutes): an owner-approved
/// measurement change reaches every RUNNING node within this window,
/// which is what lets a rolling upgrade proceed without touching the
/// old nodes' configuration.
const PIN_REFRESH_TICKS: u64 = 6_000;

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

// ── Cluster key resolution (vault-anchored) ─────────────────────────

/// Vault addressing for the cluster credential (config `raft_vault`).
#[derive(Clone)]
pub struct RaftVaultConfig {
    /// Management-service base URL (the vault directory).
    pub mgmt_url: String,
    /// Directory environment (`production` / `development`).
    pub environment: String,
    /// The cluster key's vault handle — one per cluster.
    pub handle: String,
    /// Key-creation grant, needed only on the FIRST boot of the first
    /// node (the platform mints it with the owner-authored policy).
    /// Empty on every later boot/node. The grant is an authorisation
    /// token, not secret material: presenting it requires passing the
    /// policy's attestation checks over mutual RA-TLS.
    pub grant: String,
    /// Optional app identity (raw bytes) to present on the client
    /// certificate, when the credential policy pins one.
    pub app_id: Option<Vec<u8>>,
}

const CK_SEAL_TABLE: &str = "raft:meta";
const CK_SEAL_RECORD: &[u8] = b"ck.sealed.v1";
const CK_SEAL_AAD: &[u8] = b"enclave-os-raft:ck-seal:v1";

/// Resolve the cluster key: node-local sealed copy first (restarts do
/// not depend on vault availability), else fetch from the vault
/// constellation under the credential's grant policy and seal it.
/// Fail-closed: no credential, no cluster.
pub fn resolve_cluster_key(
    master_key: &[u8; 32],
    cfg: &RaftVaultConfig,
) -> Result<[u8; 32], String> {
    if let Some(ck) = load_sealed_ck(master_key) {
        enclave_log_info!("raft: cluster key restored from the sealed copy");
        return Ok(ck);
    }
    let ck = fetch_vault_ck(cfg)?;
    store_sealed_ck(master_key, &ck)?;
    enclave_log_info!("raft: cluster key resolved from the vault constellation and sealed");
    Ok(ck)
}

/// The attested-unwrap leg, reusing the wasm KEK client verbatim: the
/// key is generated inside the FIRST node's enclave, Shamir-split
/// across the constellation, and released to later nodes only if they
/// pass every vault's grant-policy checks (measurement set, OIDs,
/// acceptable TCB statuses, optional owner approval). No single vault
/// ever holds the whole key; the host never sees it at all.
#[cfg(all(feature = "wasm", feature = "egress"))]
fn fetch_vault_ck(cfg: &RaftVaultConfig) -> Result<[u8; 32], String> {
    use enclave_os_wasm::vaultkey;
    let vcfg = vaultkey::discover(&cfg.mgmt_url, &cfg.environment)
        .map_err(|e| format!("vault discovery: {e}"))?;
    let code_hash = crate::ratls::attestation::self_mrenclave()
        .map_err(|e| format!("self measurement: {e}"))?;
    vaultkey::resolve_or_provision(
        &vcfg,
        &cfg.handle,
        &cfg.grant,
        &code_hash,
        cfg.app_id.as_deref(),
    )
    .map_err(|e| format!("cluster credential: {e}"))
}

#[cfg(not(all(feature = "wasm", feature = "egress")))]
fn fetch_vault_ck(_cfg: &RaftVaultConfig) -> Result<[u8; 32], String> {
    Err("raft_vault requires a build with the wasm and egress modules \
         (the cluster flavor); use raft_cluster_key on this build"
        .to_string())
}

/// Read the admissible measurement set from the credential policy's
/// Tees (the vault authorises `GetPolicy` by principal resolution, so
/// the node reads its OWN credential's policy).
#[cfg(all(feature = "wasm", feature = "egress"))]
fn fetch_policy_measurements(cfg: &RaftVaultConfig) -> Result<Vec<[u8; 32]>, String> {
    use enclave_os_wasm::vaultkey;
    let vcfg = vaultkey::discover(&cfg.mgmt_url, &cfg.environment)
        .map_err(|e| format!("vault discovery: {e}"))?;
    let code_hash = crate::ratls::attestation::self_mrenclave()
        .map_err(|e| format!("self measurement: {e}"))?;
    vaultkey::read_policy_measurements(&vcfg, &cfg.handle, &code_hash, cfg.app_id.as_deref())
}

#[cfg(not(all(feature = "wasm", feature = "egress")))]
fn fetch_policy_measurements(_cfg: &RaftVaultConfig) -> Result<Vec<[u8; 32]>, String> {
    Err("policy-sourced pinning requires the cluster flavor".to_string())
}

fn ck_seal_key(master_key: &[u8; 32]) -> [u8; 32] {
    derive(master_key, b"enclave-os-raft:ckseal:v1")
}

fn load_sealed_ck(master_key: &[u8; 32]) -> Option<[u8; 32]> {
    use enclave_os_merkle::KvBackend;
    let backend = OcallBackend::with_table(CK_SEAL_TABLE);
    let rec = backend.get(CK_SEAL_RECORD).ok()??;
    if rec.len() != 12 + 32 + 16 {
        return None;
    }
    let key =
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &ck_seal_key(master_key)).ok()?;
    let key = ring::aead::LessSafeKey::new(key);
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&rec[..12]).ok()?;
    let mut ct = rec[12..].to_vec();
    let pt = key
        .open_in_place(nonce, ring::aead::Aad::from(CK_SEAL_AAD), &mut ct)
        .ok()?;
    if pt.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(pt);
    Some(out)
}

fn store_sealed_ck(master_key: &[u8; 32], ck: &[u8; 32]) -> Result<(), String> {
    use enclave_os_common::rpc::KvBatchOp;
    use enclave_os_merkle::KvBackend;
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| "rng (ck seal nonce)".to_string())?;
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &ck_seal_key(master_key))
        .map_err(|_| "ck seal key".to_string())?;
    let key = ring::aead::LessSafeKey::new(key);
    let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = ck.to_vec();
    key.seal_in_place_append_tag(nonce, ring::aead::Aad::from(CK_SEAL_AAD), &mut buf)
        .map_err(|_| "ck seal".to_string())?;
    let mut record = nonce_bytes.to_vec();
    record.extend_from_slice(&buf);
    OcallBackend::with_table(CK_SEAL_TABLE)
        .write_batch(std::vec![KvBatchOp::Put {
            key: CK_SEAL_RECORD.to_vec(),
            value: record,
        }])
        .map_err(|e| format!("ck seal persist: {e:?}"))
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
    master_key: [u8; 32],
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
    /// Intel TCB statuses accepted on peer quotes beyond the secure
    /// floor (tri-state, vault semantics).
    acceptable_tcb_statuses: Option<Vec<String>>,
    /// Recycle links older than this many ticks so fresh quotes are
    /// presented (0 = off).
    reattest_ticks: u64,
    /// Cached attestation-server verdicts: cert fingerprint →
    /// (passed, expiry tick).
    verdicts: BTreeMap<[u8; 32], (bool, u64)>,
    /// Tick each connection completed its handshake (re-attestation).
    conn_established: BTreeMap<u32, u64>,
    /// Vault addressing, kept for the policy-sourced pin refresh.
    vault: Option<RaftVaultConfig>,
    /// The pin set follows the credential policy (vault mode without
    /// an explicit `raft_pin_measurements` list).
    pin_from_policy: bool,
    /// Own measurement, always included in a policy-sourced pin set.
    own_measurement: Option<[u8; 32]>,
}

/// Peer-admission configuration (from `--extra`, resolved by ecall).
pub struct RaftNetConfig {
    /// Admissible peer MRENCLAVEs; `None` disables the local pin
    /// (`raft_pin_measurement: false`, transitional only).
    pub pinned_measurements: Option<Vec<[u8; 32]>>,
    /// Tri-state acceptable-TCB set for peer quotes (vault semantics).
    pub acceptable_tcb_statuses: Option<Vec<String>>,
    /// Link max age in ticks before recycling for a fresh quote.
    pub reattest_ticks: u64,
    /// Vault mode without an explicit pin list: the admissible set is
    /// read from the credential policy's Tees (own measurement always
    /// included) at startup and refreshed periodically — the policy is
    /// the single source of truth, so an owner-approved measurement
    /// change opens/closes the upgrade window without touching node
    /// configuration.
    pub pin_from_policy: bool,
}

impl RaftGlue {
    pub fn new(
        master_key: [u8; 32],
        cluster_key: [u8; 32],
        node_id: NodeId,
        peers: BTreeMap<NodeId, String>,
        genesis_voters: Option<Vec<NodeId>>,
        ca: CaContext,
        net: RaftNetConfig,
        vault: Option<RaftVaultConfig>,
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
        let mut driver = driver;
        // Commit certificates: derive the signing key from the master
        // key; the public key rides in Hello and the leader registers
        // it through the log.
        driver.set_signer(&master_key);

        // Policy-sourced pin: in vault mode without an explicit list,
        // the admissible set = the credential policy's Tees ∪ own
        // measurement. If the vaults are unreachable right now (e.g.
        // this boot came up from the sealed ck copy) fall back to
        // own-only; the periodic refresh recovers the full set.
        let own_measurement = net
            .pinned_measurements
            .as_ref()
            .map(|_| crate::ratls::attestation::self_mrenclave())
            .transpose()
            .map_err(|e| format!("self measurement: {e}"))?;
        let mut pinned = net.pinned_measurements;
        if net.pin_from_policy {
            if let (Some(v), Some(own)) = (vault.as_ref(), own_measurement) {
                match fetch_policy_measurements(v) {
                    Ok(mut set) => {
                        if !set.contains(&own) {
                            set.push(own);
                        }
                        enclave_log_info!(
                            "raft: admissible measurement set from policy ({} entries)",
                            set.len()
                        );
                        pinned = Some(set);
                    }
                    Err(e) => enclave_log_error!(
                        "raft: policy pin fetch failed ({}), starting own-only",
                        e
                    ),
                }
            }
        }
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
            master_key,
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
            acceptable_tcb_statuses: net.acceptable_tcb_statuses,
            reattest_ticks: net.reattest_ticks,
            verdicts: BTreeMap::new(),
            conn_established: BTreeMap::new(),
            vault,
            pin_from_policy: net.pin_from_policy,
            own_measurement,
        })
    }

    /// Periodic policy-pin refresh (vault mode): re-read the
    /// credential policy's Tees and swap the admissible set when it
    /// changed. New connections verify against the new set at once;
    /// existing links roll through re-attestation recycling.
    fn refresh_policy_pin(&mut self) {
        let (Some(v), Some(own)) = (self.vault.clone(), self.own_measurement) else {
            return;
        };
        match fetch_policy_measurements(&v) {
            Ok(mut set) => {
                if !set.contains(&own) {
                    set.push(own);
                }
                let current = self.link.pinned().map(|s| s.to_vec());
                let mut sorted = set.clone();
                sorted.sort_unstable();
                let changed = match current {
                    Some(mut c) => {
                        c.sort_unstable();
                        c != sorted
                    }
                    None => true,
                };
                if changed {
                    enclave_log_info!(
                        "raft: admissible measurement set updated from policy ({} entries)",
                        set.len()
                    );
                    self.link.set_pinned(set);
                }
            }
            Err(e) => enclave_log_error!("raft: policy pin refresh failed: {}", e),
        }
    }

    fn own_meta(&self) -> MsgMeta {
        let Message::Hello { meta, .. } = self.driver.core().hello() else { unreachable!() };
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
        self.driver.set_signer(&self.master_key);
        Ok(())
    }

    // ── Event-loop inputs ───────────────────────────────────────────

    fn handle_peer_msg(&mut self, msg_type: ChannelMsgType, conn_id: u32, payload: &[u8]) {
        let events = self.link.handle_message(msg_type, conn_id, payload, now_secs());
        for ev in events {
            match ev {
                PeerEvent::Established(cid) => {
                    // Independent quote verification (attestation
                    // servers) BEFORE the link carries anything. On
                    // failure the connection is closed; the redial
                    // path re-verifies (fresh cert, fresh verdict).
                    if !self.verify_peer(cid) {
                        self.dial_pending.remove(&cid);
                        self.link.close(cid);
                        continue;
                    }
                    self.conn_established.insert(cid, self.ticks);
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
                    self.conn_established.remove(&cid);
                    self.unmap_conn(cid);
                }
            }
        }
    }

    // ── Peer admission: attestation-server quote verification ───────

    /// Verify the peer's certificate quote against the configured
    /// attestation servers (signature chain to the Intel root, QE
    /// identity, PCK CRL, DEBUG — everything the hardened AS checks)
    /// and gate the reported `tcbStatus` + AS-verified MRENCLAVE.
    /// No servers configured = pass (standalone mode: the TLS-layer
    /// parse pin is the only measurement check). Requires egress; a
    /// build without it skips (and cannot configure servers anyway).
    fn verify_peer(&mut self, cid: u32) -> bool {
        #[cfg(feature = "egress")]
        {
            let servers = enclave_os_common::attestation_servers::server_urls();
            if servers.is_empty() {
                return true;
            }
            let Some(cert) = self.link.peer_cert_der(cid) else {
                enclave_log_error!("raft: peer conn {} has no certificate", cid);
                return false;
            };
            let fp: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &cert)
                .as_ref()
                .try_into()
                .unwrap();
            if let Some(&(passed, expiry)) = self.verdicts.get(&fp) {
                if self.ticks < expiry {
                    return passed;
                }
            }
            let passed = match self.verify_peer_cert(&cert) {
                Ok(()) => true,
                Err(e) => {
                    enclave_log_error!("raft: peer conn {} rejected: {}", cid, e);
                    false
                }
            };
            let ttl = if passed { VERIFY_PASS_TICKS } else { VERIFY_FAIL_TICKS };
            self.verdicts.insert(fp, (passed, self.ticks + ttl));
            passed
        }
        #[cfg(not(feature = "egress"))]
        {
            let _ = cid;
            true
        }
    }

    #[cfg(feature = "egress")]
    fn verify_peer_cert(&self, cert: &[u8]) -> Result<(), String> {
        let quote = crate::peerlink::extract_quote(cert)?;
        let servers = enclave_os_common::attestation_servers::server_urls();
        let responses =
            enclave_os_egress::attestation::verify_quote_statuses(&quote, &servers)?;
        for resp in &responses {
            // TCB status: tri-state vault semantics (floor + set,
            // Revoked never, absent set = no check).
            if !enclave_os_egress::attestation::tcb_status_acceptable(
                &resp.tcb_status,
                self.acceptable_tcb_statuses.as_deref(),
            ) {
                return Err(format!(
                    "peer TCB status {:?} not acceptable",
                    resp.tcb_status
                ));
            }
            // AS-verified measurement must be in the admissible set —
            // independent of the TLS-layer parse (which a stolen
            // fleet-CA key could satisfy with a fabricated quote).
            if let Some(set) = self.link.pinned() {
                if !resp.mrenclave.is_empty()
                    && !set.iter().any(|m| resp.mrenclave == hex_encode(m))
                {
                    return Err(format!(
                        "AS-verified MRENCLAVE {} not in the admissible set",
                        resp.mrenclave
                    ));
                }
            }
        }
        Ok(())
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

        // Re-attestation: recycle links older than the window so both
        // sides present freshly minted certs (with fresh quotes) and
        // get re-verified against the attestation servers. The redial
        // path brings the link back within seconds.
        if self.reattest_ticks > 0 {
            let aged: Vec<u32> = self
                .conn_established
                .iter()
                .filter(|(_, &at)| self.ticks.saturating_sub(at) > self.reattest_ticks)
                .map(|(&cid, _)| cid)
                .collect();
            for cid in aged {
                enclave_log_info!("raft: recycling conn {} for re-attestation", cid);
                self.conn_established.remove(&cid);
                self.unmap_conn(cid);
                self.link.close(cid);
            }
        }

        // Policy-sourced pin refresh (vault mode): the credential
        // policy is the single source of truth for the admissible
        // measurement set; an owner-approved change reaches running
        // nodes within this cadence.
        if self.pin_from_policy && self.ticks % PIN_REFRESH_TICKS == 0 {
            self.refresh_policy_pin();
        }

        // Expired verdicts are re-checked on next use; drop them so
        // the cache cannot grow unboundedly under cert churn.
        if self.ticks % 1024 == 0 {
            let now = self.ticks;
            self.verdicts.retain(|_, (_, expiry)| *expiry > now);
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

        // Redial down peers with backoff. Only the HIGHER node id dials
        // a pair: with both sides dialing, each side's inbound mapping
        // supersede-closes its own outbound and the two links destroy
        // each other forever. One deterministic dialer per pair ends
        // the fight (new nodes join with higher ids, so a joiner dials
        // every founder).
        let down: Vec<(NodeId, String)> = self
            .peers
            .iter()
            .filter(|(&id, _)| id < self.node_id && !self.node_conns.contains_key(&id))
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
                self.conn_established.remove(&old);
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

    /// Execute a WASM app function against a fork of the ledger and
    /// propose its write-set through consensus (apply mode). The app
    /// reaches the fork via `privasys:enclave-os/ledger`; a trap or
    /// error aborts with nothing proposed.
    #[cfg(feature = "wasm")]
    fn propose_wasm_txn(&mut self, call: enclave_os_wasm::protocol::WasmCall) -> Response {
        use enclave_os_wasm::enclave_sdk::ledger::{with_txn_ledger, TxnLedger};

        let Some(wasm) = enclave_os_wasm::global() else {
            return err_json("wasm module not available");
        };

        struct ForkLedger<'a, 'b>(&'a mut enclave_os_merkle::MerkleFork<'b, OcallBackend>);
        impl TxnLedger for ForkLedger<'_, '_> {
            fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
                self.0.get(key).map_err(|e| format!("ledger get: {e:?}"))
            }
            fn put(&mut self, key: &[u8], value: &[u8]) {
                self.0.put(key, value);
            }
            fn delete(&mut self, key: &[u8]) {
                self.0.delete(key);
            }
        }

        match self.driver.propose_with(|fork| {
            let mut adapter = ForkLedger(fork);
            with_txn_ledger(&mut adapter, || wasm.call_for_transaction(&call))
        }) {
            Ok((index, returns, out)) => {
                self.dispatch(out);
                ok_json(serde_json::json!({
                    "index": index,
                    "status": "proposed",
                    "returns": returns,
                }))
            }
            Err(enclave_os_raft::ProposeError::ExecutorFailed(e)) => {
                err_json(&format!("transaction failed: {e}"))
            }
            Err(enclave_os_raft::ProposeError::ConfigChangePending) => {
                err_json("a membership change is already in flight")
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
    raft_certificate: Option<serde_json::Value>,
    #[serde(default)]
    raft_txn: Option<TxnReq>,
    /// Execute a WASM app export inside a cluster transaction
    /// (`{"app", "function", "params"?, "app_auth"?}` — the WasmCall
    /// shape, parsed lazily so non-wasm builds reject it cleanly).
    #[serde(default)]
    raft_wasm_txn: Option<serde_json::Value>,
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
        let is_read = env.raft_status.is_some() || env.raft_certificate.is_some();
        let is_write = env.raft_txn.is_some()
            || env.raft_wasm_txn.is_some()
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
        if env.raft_certificate.is_some() {
            let core = g.driver.core();
            let keys: serde_json::Map<String, serde_json::Value> = core
                .membership()
                .keys
                .iter()
                .map(|(id, k)| (id.to_string(), serde_json::json!(hex_encode(k))))
                .collect();
            let cert = core.latest_certificate().map(|c| {
                let sigs: serde_json::Map<String, serde_json::Value> = c
                    .sigs
                    .iter()
                    .map(|(id, s)| (id.to_string(), serde_json::json!(hex_encode(s))))
                    .collect();
                serde_json::json!({
                    "index": c.index,
                    "root": hex_encode(&c.root),
                    "sigs": sigs,
                })
            });
            return Some(ok_json(serde_json::json!({
                "certificate": cert,
                "keys": keys,
                "quorum": core.membership().quorum(),
            })));
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
        if let Some(raw) = env.raft_wasm_txn {
            #[cfg(feature = "wasm")]
            {
                let call: enclave_os_wasm::protocol::WasmCall = match serde_json::from_value(raw) {
                    Ok(c) => c,
                    Err(e) => return Some(err_json(&format!("invalid wasm call: {e}"))),
                };
                return Some(g.propose_wasm_txn(call));
            }
            #[cfg(not(feature = "wasm"))]
            {
                let _ = raw;
                return Some(err_json("this build has no wasm runtime"));
            }
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
