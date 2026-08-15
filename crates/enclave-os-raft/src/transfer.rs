// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Snapshot transfer state machines: one chunk in flight, ack-paced.
//!
//! The SENDER answers `RaftEvent::SnapshotNeeded`: it captures a
//! consistent descriptor (applied index/term/membership + the ledger
//! `(root, version)` at the same instant), pins the ledger version
//! against pruning, and streams path-ordered leaf chunks — each next
//! chunk only after the previous ack. The RECEIVER accumulates into a
//! [`SnapshotBuilder`], and on the final chunk finalizes (verifying
//! the advertised root), hands the restored store to the driver for
//! install, and acks `done`, which resumes ordinary appends.
//!
//! Crash mid-transfer is safe on both sides: the sender just unpins
//! and the pause re-signals; the receiver's clobbered ledger recovers
//! by repair-by-replay of its (still intact) local log, after which
//! the leader re-detects the lag and restarts the transfer.

use enclave_os_merkle::{KvBackend, SnapshotBuilder};

use crate::core::LedgerRoot;
use crate::driver::{DriverError, RaftDriver};
use crate::message::{Message, MsgMeta};
use crate::types::{Index, Membership, NodeId, Term};

/// Leaves per chunk (~a few hundred KiB of typical values per frame).
pub const SNAPSHOT_CHUNK_LEAVES: usize = 256;

/// What [`SnapshotSender::on_ack`] decided.
pub enum SenderStep {
    /// Send this next chunk.
    Send(Message),
    /// The receiver installed the snapshot at `index`: call
    /// `driver.snapshot_transferred(node, index)` and drop the sender.
    Finished { index: Index },
    /// Stale or out-of-order ack: ignore.
    Ignore,
}

/// Leader-side transfer to one follower.
pub struct SnapshotSender {
    pub to: NodeId,
    index: Index,
    term: Term,
    ledger_version: u64,
    root: LedgerRoot,
    membership: Membership,
    next_seq: u64,
    last_path: Option<[u8; 32]>,
    done_sent: bool,
}

impl SnapshotSender {
    /// Capture a consistent snapshot descriptor from the driver, pin
    /// the ledger version, and produce the SnapshotStart message.
    pub fn start<B: KvBackend>(
        driver: &mut RaftDriver<B>,
        to: NodeId,
        meta: MsgMeta,
    ) -> (Self, Message) {
        let (index, term, membership) = driver.core().snapshot_info();
        let (root, ledger_version) = driver.ledger().root();
        driver.ledger_pin(Some(ledger_version));
        let sender = Self {
            to,
            index,
            term,
            ledger_version,
            root,
            membership: membership.clone(),
            next_seq: 1,
            last_path: None,
            done_sent: false,
        };
        let msg = Message::SnapshotStart {
            meta,
            index,
            term,
            ledger_version,
            root,
            membership,
        };
        (sender, msg)
    }

    /// The installed log index this transfer represents.
    pub fn index(&self) -> Index {
        self.index
    }

    /// The pinned ledger version this transfer streams from.
    pub fn ledger_version(&self) -> u64 {
        self.ledger_version
    }

    /// Handle an ack; when it acknowledges the previous chunk, read and
    /// return the next one from the (pinned) ledger version.
    pub fn on_ack<B: KvBackend>(
        &mut self,
        driver: &RaftDriver<B>,
        meta: MsgMeta,
        seq: u64,
        done: bool,
    ) -> Result<SenderStep, DriverError> {
        if done {
            return Ok(SenderStep::Finished { index: self.index });
        }
        if seq + 1 != self.next_seq || self.done_sent {
            return Ok(SenderStep::Ignore);
        }
        let (leaves, exhausted) = driver
            .ledger()
            .store()
            .snapshot_leaves(
                self.ledger_version,
                self.last_path.as_ref(),
                SNAPSHOT_CHUNK_LEAVES,
            )
            .map_err(|e| DriverError::Ledger(crate::ledger::LedgerError::Store(e)))?;
        self.last_path = leaves.last().map(|(p, _)| *p).or(self.last_path);
        let msg = Message::SnapshotChunk {
            meta,
            seq: self.next_seq,
            leaves,
            done: exhausted,
        };
        self.next_seq += 1;
        self.done_sent = exhausted;
        Ok(SenderStep::Send(msg))
    }
}

/// What [`SnapshotReceiver::on_chunk`] decided.
pub enum ReceiverStep {
    /// Send this ack (and wait for the next chunk).
    Ack(Message),
    /// All chunks received and verified: the restored store was
    /// installed into the driver; send this final ack.
    Installed(Message),
}

/// Follower-side transfer state.
pub struct SnapshotReceiver<B: KvBackend> {
    pub from: NodeId,
    index: Index,
    term: Term,
    ledger_version: u64,
    root: LedgerRoot,
    membership: Membership,
    builder: SnapshotBuilder<B>,
    expect_seq: u64,
}

impl<B: KvBackend> SnapshotReceiver<B> {
    /// Begin a transfer announced by SnapshotStart. `backend` is a
    /// fresh handle to the ledger table; `ck`/`sk` are this node's
    /// commitment and storage keys. Returns the receiver and the ack
    /// requesting the first chunk.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        from: NodeId,
        index: Index,
        term: Term,
        ledger_version: u64,
        root: LedgerRoot,
        membership: Membership,
        backend: B,
        ck: [u8; 32],
        sk: [u8; 32],
        meta: MsgMeta,
    ) -> Result<(Self, Message), DriverError> {
        let builder = SnapshotBuilder::new(backend, ck, sk)
            .map_err(|e| DriverError::Ledger(crate::ledger::LedgerError::Store(e)))?;
        let recv = Self {
            from,
            index,
            term,
            ledger_version,
            root,
            membership,
            builder,
            expect_seq: 1,
        };
        let ack = Message::SnapshotAck { meta, seq: 0, done: false };
        Ok((recv, ack))
    }

    /// Ingest one chunk. On the final chunk, finalize (verifying the
    /// advertised root), install into the driver, and return the
    /// `done` ack.
    pub fn on_chunk(
        mut self,
        driver: &mut RaftDriver<B>,
        meta: MsgMeta,
        seq: u64,
        leaves: Vec<([u8; 32], Vec<u8>)>,
        done: bool,
    ) -> Result<(Option<Self>, ReceiverStep), DriverError> {
        if seq != self.expect_seq {
            // Out-of-order: re-ack the last chunk we have.
            let ack =
                Message::SnapshotAck { meta, seq: self.expect_seq - 1, done: false };
            return Ok((Some(self), ReceiverStep::Ack(ack)));
        }
        self.builder.add_leaves(leaves);
        self.expect_seq += 1;
        if !done {
            let ack = Message::SnapshotAck { meta, seq, done: false };
            return Ok((Some(self), ReceiverStep::Ack(ack)));
        }
        let restored = self
            .builder
            .finalize(self.root, self.ledger_version)
            .map_err(|e| DriverError::Ledger(crate::ledger::LedgerError::Store(e)))?;
        driver.install_snapshot_state(self.index, self.term, self.membership, restored)?;
        let ack = Message::SnapshotAck { meta, seq, done: true };
        Ok((None, ReceiverStep::Installed(ack)))
    }
}
