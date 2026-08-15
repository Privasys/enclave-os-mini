// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The production Ready loop: one object owning the consensus core,
//! the Merkle ledger and the encrypted log store, exposing exactly
//! what a transport needs — `step(msg) -> outputs`, `tick() ->
//! outputs` — while enforcing the driver contract internally
//! (truncate → persist → send → apply → report).
//!
//! ## Restart replay
//!
//! The ledger restores from its own checkpoint; the core re-delivers
//! committed entries from the persisted applied floor (which may lag
//! the checkpoint by one batch). The driver resolves each committed
//! transaction against the ledger root:
//!
//! - `root_before == root` → apply it (the normal path),
//! - `root_after == root` → already applied (the crash-window replay
//!   or a no-op transaction): report, don't re-apply,
//! - neither → genuine divergence: halt fail-closed and surface it.

use enclave_os_merkle::{KvBackend, MerkleStore};

use crate::core::{Config, LedgerRoot, ProposeError, RaftCore, RaftEvent};
use crate::ledger::{LedgerError, MerkleLedger};
use crate::logstore::{LogError, LogStore};
use crate::message::Message;
use crate::transaction::Transaction;
use crate::types::{EntryKind, Index, Membership, NodeId};

/// What one `step`/`tick`/`propose` produced for the transport and the
/// operator.
#[derive(Debug, Default)]
pub struct DriverOutput {
    /// Send after this call returns (persistence already happened).
    pub messages: Vec<(NodeId, Message)>,
    /// Verification / dispute events for the operator layer.
    pub events: Vec<RaftEvent>,
}

/// Fatal driver states.
#[derive(Debug)]
pub enum DriverError {
    Log(LogError),
    Ledger(LedgerError),
    /// This node's ledger diverged from the committed history: it has
    /// stopped serving and needs snapshot repair.
    Diverged { index: Index, expected: LedgerRoot, found: LedgerRoot },
}

impl From<LogError> for DriverError {
    fn from(e: LogError) -> Self {
        Self::Log(e)
    }
}

/// Consensus + ledger + log persistence, glued per the driver contract.
pub struct RaftDriver<B: KvBackend> {
    core: RaftCore,
    ledger: MerkleLedger<B>,
    log: LogStore<B>,
    applied_floor: Index,
    /// Set on divergence: the node stops applying and reporting.
    halted: bool,
}

impl<B: KvBackend> RaftDriver<B> {
    /// First boot: initialise the log table with the genesis membership
    /// and start a fresh core.
    pub fn bootstrap(
        cfg: Config,
        voters: &[NodeId],
        log_backend: B,
        log_key: [u8; 32],
        ledger_store: MerkleStore<B>,
    ) -> Result<Self, DriverError> {
        let genesis = Membership::bootstrap(voters);
        let log = LogStore::create(log_backend, log_key, &genesis)?;
        let ledger = MerkleLedger::new(ledger_store);
        let (root, _) = ledger.root();
        let mut core = RaftCore::new(cfg, genesis, Vec::new(), Default::default());
        // Seed the verification protocol with the ledger's genesis root.
        core.report_applied(0, root);
        Ok(Self { core, ledger, log, applied_floor: 0, halted: false })
    }

    /// Repair a diverged (or discarded) ledger by full replay: zero
    /// the applied floor and restore with a FRESH ledger store, so
    /// every committed transaction re-applies from the log. Safe
    /// because apply is deterministic; the rebuilt state ends at
    /// exactly the committed history. This is the repair path while
    /// the log is uncompacted; snapshot streaming replaces it once
    /// pruning lands.
    pub fn rebuild(
        cfg: Config,
        log_backend: B,
        log_key: [u8; 32],
        fresh_ledger: MerkleStore<B>,
    ) -> Result<Self, DriverError>
    where
        B: Clone,
    {
        let (mut log, _) = LogStore::open(log_backend.clone(), log_key)?;
        log.set_applied_floor(0)?;
        drop(log);
        Self::restore(cfg, log_backend, log_key, fresh_ledger)
    }

    /// Restart: recover the log, rebuild the core, restore the ledger
    /// from its checkpoint, and reconcile the applied floor.
    pub fn restore(
        cfg: Config,
        log_backend: B,
        log_key: [u8; 32],
        ledger_store: MerkleStore<B>,
    ) -> Result<Self, DriverError> {
        let (log, recovered) = LogStore::open(log_backend, log_key)?;
        let mut core = RaftCore::with_base(
            cfg,
            recovered.base_membership,
            recovered.base_index,
            recovered.base_term,
            recovered.entries,
            recovered.hard_state,
        );
        let floor = recovered.applied_floor.max(recovered.base_index);
        core.set_applied_floor(floor);
        let ledger = MerkleLedger::new(ledger_store);
        let (root, _) = ledger.root();
        core.report_applied(floor, root);
        Ok(Self { core, ledger, log, applied_floor: floor, halted: false })
    }

    /// Compact the log through `through` (capped at the applied index):
    /// discard covered entries in core and store, recording the base.
    /// The ledger keeps serving — its checkpoint IS the snapshot state.
    pub fn compact_to(&mut self, through: Index) -> Result<(), DriverError> {
        let through = through.min(self.core.applied_index());
        let (old_base, _) = self.core.base();
        if through <= old_base {
            return Ok(());
        }
        let (idx, term, membership) = self.core.compact(through);
        self.log.compact(idx, term, &membership)?;
        Ok(())
    }

    /// Keep roughly the last `retain` applied entries in the log;
    /// compact when the retained span grows past twice that.
    pub fn maybe_compact(&mut self, retain: u64) -> Result<(), DriverError> {
        let applied = self.core.applied_index();
        let (base, _) = self.core.base();
        if applied.saturating_sub(base) > retain.saturating_mul(2) {
            self.compact_to(applied.saturating_sub(retain))?;
        }
        Ok(())
    }

    /// Install a snapshot received from the leader: `restored_ledger`
    /// is the finalized [`enclave_os_merkle::SnapshotBuilder`] output
    /// (already verified against the advertised root and stamped at the
    /// advertised version), representing the state as of log `index`
    /// (term `term`, membership as of it). Returns false if the
    /// snapshot is stale.
    pub fn install_snapshot_state(
        &mut self,
        index: Index,
        term: u64,
        membership: crate::types::Membership,
        restored_ledger: MerkleStore<B>,
    ) -> Result<bool, DriverError> {
        if !self.core.install_snapshot(index, term, membership.clone()) {
            return Ok(false);
        }
        self.ledger = MerkleLedger::new(restored_ledger);
        self.log.install(index, term, &membership)?;
        self.log.set_applied_floor(index)?;
        self.applied_floor = index;
        self.halted = false;
        let (root, _) = self.ledger.root();
        self.core.report_applied(index, root);
        Ok(true)
    }

    /// Leader side: the snapshot transfer to `node` completed; resume
    /// appends from the base. Returns the messages to send.
    pub fn snapshot_transferred(&mut self, node: NodeId) -> Result<DriverOutput, DriverError> {
        self.core.snapshot_transferred(node);
        self.process()
    }

    // ── Accessors ───────────────────────────────────────────────────

    pub fn core(&self) -> &RaftCore {
        &self.core
    }
    pub fn ledger(&self) -> &MerkleLedger<B> {
        &self.ledger
    }
    /// Repair tooling only.
    pub fn ledger_mut(&mut self) -> &mut MerkleLedger<B> {
        &mut self.ledger
    }
    /// Has this node diverged and stopped serving?
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    // ── Inputs ──────────────────────────────────────────────────────

    /// Feed one peer message.
    pub fn step(&mut self, msg: Message) -> Result<DriverOutput, DriverError> {
        self.core.step(msg);
        self.process()
    }

    /// Advance logical time by one tick.
    pub fn tick(&mut self) -> Result<DriverOutput, DriverError> {
        self.core.tick();
        self.process()
    }

    /// Leader-side transaction: fork the ledger, run the buffered ops,
    /// seal, propose. `ops`: `(key, Some(value))` puts, `(key, None)`
    /// deletes. Returns the log index and the outputs to send.
    pub fn propose_transaction(
        &mut self,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(Index, DriverOutput), ProposeError> {
        if self.halted {
            return Err(ProposeError::NotLeader);
        }
        let mut fork = self.ledger.fork();
        for (k, v) in ops {
            match v {
                Some(v) => fork.put(k, v),
                None => fork.delete(k),
            }
        }
        let sealed = fork.seal().map_err(|_| ProposeError::NotLeader)?;
        let txn: Transaction = sealed.into();
        let index = self.core.propose(txn.encode())?;
        let out = self.process().map_err(|_| ProposeError::NotLeader)?;
        Ok((index, out))
    }

    /// Membership change passthrough.
    pub fn propose_conf_change(
        &mut self,
        cc: crate::types::ConfigChange,
    ) -> Result<(Index, DriverOutput), ProposeError> {
        let index = self.core.propose_conf_change(cc)?;
        let out = self.process().map_err(|_| ProposeError::NotLeader)?;
        Ok((index, out))
    }

    // ── The Ready loop ──────────────────────────────────────────────

    fn process(&mut self) -> Result<DriverOutput, DriverError> {
        let mut out = DriverOutput::default();
        // Applying entries reports roots, which can raise events (but
        // no new persistence), so drain until quiet; bounded because
        // each iteration strictly consumes pending work.
        for _ in 0..8 {
            let ready = self.core.ready();
            if ready.is_empty() {
                break;
            }
            // 1-2. Truncate + persist, atomically.
            self.log.persist(&ready)?;
            // 3. Messages are now safe to send.
            out.messages.extend(ready.messages);
            out.events.extend(ready.events);
            // 4. Apply committed entries and report roots.
            let mut last_applied: Option<Index> = None;
            for e in &ready.committed_entries {
                if self.halted {
                    break;
                }
                let root = match e.kind {
                    EntryKind::App => match Transaction::decode(&e.data) {
                        Some(txn) => {
                            let (root_now, _) = self.ledger.root();
                            if txn.root_before == root_now {
                                match self.ledger.apply(&txn) {
                                    Ok((r, _)) => r,
                                    Err(LedgerError::RootMismatch { expected, found }) => {
                                        self.halted = true;
                                        return Err(DriverError::Diverged {
                                            index: e.index,
                                            expected,
                                            found,
                                        });
                                    }
                                    Err(e) => return Err(DriverError::Ledger(e)),
                                }
                            } else if txn.root_after == root_now {
                                // Already applied (restart replay of the
                                // crash window, or a no-op transaction).
                                root_now
                            } else {
                                self.halted = true;
                                return Err(DriverError::Diverged {
                                    index: e.index,
                                    expected: txn.root_before,
                                    found: root_now,
                                });
                            }
                        }
                        // Opaque payload (not a transaction): the
                        // ledger is untouched.
                        None => self.ledger.root().0,
                    },
                    _ => self.ledger.root().0,
                };
                self.core.report_applied(e.index, root);
                last_applied = Some(e.index);
            }
            if let Some(i) = last_applied {
                if i > self.applied_floor {
                    self.applied_floor = i;
                    self.log.set_applied_floor(i)?;
                }
            }
        }
        Ok(out)
    }
}
