// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Core Raft types: entries, membership, hard state.

use std::collections::{BTreeMap, BTreeSet};

/// Node identifier, unique within a cluster.
pub type NodeId = u64;
/// Raft term.
pub type Term = u64;
/// Log index (1-based; 0 means "before the log").
pub type Index = u64;
/// Boot incarnation: drawn fresh (randomly) at every enclave start.
pub type Incarnation = u64;

/// What a log entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    /// Application payload (a ledger transaction from WS3 onwards).
    App = 0,
    /// Empty entry appended by a new leader to commit its term.
    Noop = 1,
    /// Membership change ([`ConfigChange`] encoded in `data`).
    Config = 2,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::App),
            1 => Some(Self::Noop),
            2 => Some(Self::Config),
            _ => None,
        }
    }
}

/// A replicated log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub term: Term,
    pub index: Index,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

impl Entry {
    /// Persistence codec: `[term u64][index u64][kind u8][len u32][data]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(21 + self.data.len());
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.push(self.kind as u8);
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 21 {
            return None;
        }
        let term = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let index = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let kind = EntryKind::from_u8(data[16])?;
        let len = u32::from_le_bytes(data[17..21].try_into().ok()?) as usize;
        if data.len() != 21 + len {
            return None;
        }
        Some(Self { term, index, kind, data: data[21..].to_vec() })
    }
}

/// A single-server membership change, applied when the entry is
/// *appended* (not committed), per the Raft dissertation §4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigChange {
    /// Add a non-voting learner (replication target only).
    AddLearner { node: NodeId },
    /// Promote a learner to voter, recording the incarnation under
    /// which it is admitted.
    PromoteVoter { node: NodeId, incarnation: Incarnation },
    /// Remove a node entirely (voter or learner).
    RemoveNode { node: NodeId },
    /// Re-admit a restarted voter under its new incarnation.
    RefreshIncarnation { node: NodeId, incarnation: Incarnation },
    /// Register (or update) a node's commit-certificate signing key
    /// (compressed SEC1 P-256 point, 33 bytes).
    RegisterKey { node: NodeId, key: Vec<u8> },
}

impl ConfigChange {
    /// Encode: `[tag u8][node u64 LE][incarnation u64 LE (tags 2,4)]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        match self {
            Self::AddLearner { node } => {
                buf.push(1);
                buf.extend_from_slice(&node.to_le_bytes());
            }
            Self::PromoteVoter { node, incarnation } => {
                buf.push(2);
                buf.extend_from_slice(&node.to_le_bytes());
                buf.extend_from_slice(&incarnation.to_le_bytes());
            }
            Self::RemoveNode { node } => {
                buf.push(3);
                buf.extend_from_slice(&node.to_le_bytes());
            }
            Self::RefreshIncarnation { node, incarnation } => {
                buf.push(4);
                buf.extend_from_slice(&node.to_le_bytes());
                buf.extend_from_slice(&incarnation.to_le_bytes());
            }
            Self::RegisterKey { node, key } => {
                buf.push(5);
                buf.extend_from_slice(&node.to_le_bytes());
                buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
                buf.extend_from_slice(key);
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let tag = *data.first()?;
        let node = u64::from_le_bytes(data.get(1..9)?.try_into().ok()?);
        let inc = |d: &[u8]| -> Option<u64> {
            Some(u64::from_le_bytes(d.get(9..17)?.try_into().ok()?))
        };
        match tag {
            1 if data.len() == 9 => Some(Self::AddLearner { node }),
            2 if data.len() == 17 => Some(Self::PromoteVoter { node, incarnation: inc(data)? }),
            3 if data.len() == 9 => Some(Self::RemoveNode { node }),
            4 if data.len() == 17 => {
                Some(Self::RefreshIncarnation { node, incarnation: inc(data)? })
            }
            5 => {
                let len =
                    u32::from_le_bytes(data.get(9..13)?.try_into().ok()?) as usize;
                if len > 128 || data.len() != 13 + len {
                    return None;
                }
                Some(Self::RegisterKey { node, key: data[13..].to_vec() })
            }
            _ => None,
        }
    }
}

/// Cluster membership: voters (with their admitted incarnations) and
/// learners. Rebuilt deterministically from the log's config entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub voters: BTreeMap<NodeId, Incarnation>,
    pub learners: BTreeSet<NodeId>,
    /// Commit-certificate signing keys (compressed SEC1 P-256),
    /// registered via [`ConfigChange::RegisterKey`].
    pub keys: BTreeMap<NodeId, Vec<u8>>,
}

impl Membership {
    /// Genesis membership: the given nodes as voters, all admitted at
    /// incarnation 0 (the convention for first boot).
    pub fn bootstrap(voters: &[NodeId]) -> Self {
        Self {
            voters: voters.iter().map(|&id| (id, 0)).collect(),
            learners: BTreeSet::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Is this node a voter (by id, regardless of incarnation)?
    /// Governs candidate eligibility, vote counting and quorum size.
    pub fn is_voter(&self, id: NodeId) -> bool {
        self.voters.contains_key(&id)
    }

    /// Is this node a member at all?
    pub fn contains(&self, id: NodeId) -> bool {
        self.voters.contains_key(&id) || self.learners.contains(&id)
    }

    /// Votes needed to win an election / commit an entry.
    pub fn quorum(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    /// Persistence codec:
    /// `[voter_count u32][(id u64, incarnation u64)*][learner_count u32][id u64*]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.voters.len() * 16 + self.learners.len() * 8);
        buf.extend_from_slice(&(self.voters.len() as u32).to_le_bytes());
        for (id, inc) in &self.voters {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&inc.to_le_bytes());
        }
        buf.extend_from_slice(&(self.learners.len() as u32).to_le_bytes());
        for id in &self.learners {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf.extend_from_slice(&(self.keys.len() as u32).to_le_bytes());
        for (id, key) in &self.keys {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        let take_u32 = |d: &[u8], o: &mut usize| -> Option<u32> {
            let v = u32::from_le_bytes(d.get(*o..*o + 4)?.try_into().ok()?);
            *o += 4;
            Some(v)
        };
        let take_u64 = |d: &[u8], o: &mut usize| -> Option<u64> {
            let v = u64::from_le_bytes(d.get(*o..*o + 8)?.try_into().ok()?);
            *o += 8;
            Some(v)
        };
        let vc = take_u32(data, &mut off)? as usize;
        if vc > 4096 {
            return None;
        }
        let mut voters = BTreeMap::new();
        for _ in 0..vc {
            let id = take_u64(data, &mut off)?;
            let inc = take_u64(data, &mut off)?;
            voters.insert(id, inc);
        }
        let lc = take_u32(data, &mut off)? as usize;
        if lc > 4096 {
            return None;
        }
        let mut learners = BTreeSet::new();
        for _ in 0..lc {
            learners.insert(take_u64(data, &mut off)?);
        }
        let kc = take_u32(data, &mut off)? as usize;
        if kc > 4096 {
            return None;
        }
        let mut keys = BTreeMap::new();
        for _ in 0..kc {
            let id = take_u64(data, &mut off)?;
            let len = take_u32(data, &mut off)? as usize;
            if len > 128 {
                return None;
            }
            let key = data.get(off..off + len)?.to_vec();
            off += len;
            keys.insert(id, key);
        }
        if off != data.len() {
            return None;
        }
        Some(Self { voters, learners, keys })
    }

    /// Apply a single-server change.
    pub fn apply(&mut self, cc: &ConfigChange) {
        match cc {
            ConfigChange::AddLearner { node } => {
                if !self.voters.contains_key(node) {
                    self.learners.insert(*node);
                }
            }
            ConfigChange::PromoteVoter { node, incarnation } => {
                self.learners.remove(node);
                self.voters.insert(*node, *incarnation);
            }
            ConfigChange::RemoveNode { node } => {
                self.voters.remove(node);
                self.learners.remove(node);
                self.keys.remove(node);
            }
            ConfigChange::RefreshIncarnation { node, incarnation } => {
                if let Some(rec) = self.voters.get_mut(node) {
                    *rec = *incarnation;
                }
            }
            ConfigChange::RegisterKey { node, key } => {
                if self.contains(*node) {
                    self.keys.insert(*node, key.clone());
                }
            }
        }
    }
}

/// The durable per-node Raft state. Persisted before any message that
/// depends on it is sent (see the driver contract in the crate docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HardState {
    pub term: Term,
    pub voted_for: Option<NodeId>,
}

impl HardState {
    /// Persistence codec: `[term u64][voted_flag u8][voted_for u64]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.push(self.voted_for.is_some() as u8);
        buf.extend_from_slice(&self.voted_for.unwrap_or(0).to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != 17 {
            return None;
        }
        let term = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let voted_for = match data[8] {
            0 => None,
            1 => Some(u64::from_le_bytes(data[9..17].try_into().ok()?)),
            _ => return None,
        };
        Some(Self { term, voted_for })
    }
}

/// Volatile role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}
