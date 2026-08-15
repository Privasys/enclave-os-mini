// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Attested Raft consensus core for Enclave OS (Mini) clusters.
//!
//! This crate is the sans-I/O heart of the cluster mode: a pure,
//! event-driven Raft state machine. It performs no I/O of any kind —
//! the caller feeds it peer messages ([`RaftCore::step`]) and time
//! ([`RaftCore::tick`]), and drains the resulting obligations from
//! [`RaftCore::ready`]: entries to persist, hard state to persist,
//! messages to send, committed entries to apply.
//!
//! # Driver contract
//!
//! For every [`Ready`] taken from the core, the driver MUST:
//! 1. delete persisted log entries at and above `truncate_from` (if set),
//! 2. persist `entries_to_persist` and `hard_state` durably,
//! 3. only then send `messages` to their destinations,
//! 4. apply `committed_entries` to the state machine (any time after 2).
//!
//! Sending before persisting can violate Raft safety (a vote or an
//! acknowledged append must survive a crash).
//!
//! # The trust model twist: incarnation-gated voting
//!
//! Plain Raft assumes disk state survives crashes. Our adversary is the
//! host, which can roll back the enclave's persisted vote and enable
//! double-voting within a term. The hardening: every enclave (re)start
//! draws a fresh random **incarnation**, and the replicated membership
//! records the incarnation under which each voter was admitted. A node
//! whose current incarnation differs from its recorded one behaves as a
//! learner — it does not vote and does not campaign — until the leader
//! commits a `RefreshIncarnation` config entry re-admitting it. A
//! rolled-back node therefore cannot repeat a vote: re-admission
//! requires a committed entry, which requires a leader, which means any
//! election it could influence has already moved past the stale term.
//!
//! Full-cluster restart would deadlock under that rule (nobody is
//! admitted, nobody votes), so an unadmitted voter regains election
//! rights after a long **recovery timeout** with no leader contact
//! (`Config::recovery_ticks`, default 10× the election timeout). A
//! single rolled-back node never reaches it — a live quorum refreshes
//! it long before — so exploiting the recovery path requires a quorum
//! of colluding hosts, consistent with the documented trust model.

pub mod types;
pub mod message;
pub mod core;
pub mod certs;
pub mod transaction;
pub mod ledger;
pub mod logstore;
pub mod driver;
pub mod transfer;

pub use crate::certs::{verify_sig, CertSigner, CommitCertificate};
pub use crate::core::{Config, LedgerRoot, ProposeError, RaftCore, RaftEvent, Ready};
pub use crate::driver::{DriverError, DriverOutput, RaftDriver};
pub use crate::ledger::{LedgerError, MerkleLedger};
pub use crate::logstore::{LogError, LogStore, RecoveredLog};
pub use crate::message::{Message, MsgMeta};
pub use crate::transaction::Transaction;
pub use crate::transfer::{
    ReceiverStep, SenderStep, SnapshotReceiver, SnapshotSender, SNAPSHOT_CHUNK_LEAVES,
};
pub use crate::types::{
    ConfigChange, Entry, EntryKind, HardState, Incarnation, Index, Membership, NodeId, Role, Term,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod driver_tests;
