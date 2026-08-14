// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Peer wire messages and their binary codec.
//!
//! The codec is the frozen peer-link wire format (WS1 carries these as
//! length-prefixed frames over mutual RA-TLS). Layout, all integers LE:
//!
//! ```text
//! [type u8] [from u64] [term u64] [incarnation u64] [variant fields]
//! ```
//!
//! `AppendResponse.applied_root` is reserved for the verified-commit
//! protocol (WS3): followers report the ledger root they computed for
//! their last applied entry; it rides in the wire format from day one
//! so the format does not churn.

use crate::types::{Entry, EntryKind, Incarnation, Index, NodeId, Term};

/// Sender metadata common to every message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgMeta {
    pub from: NodeId,
    pub term: Term,
    pub incarnation: Incarnation,
}

/// A peer-to-peer Raft message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    RequestVote {
        meta: MsgMeta,
        last_log_index: Index,
        last_log_term: Term,
    },
    VoteResponse {
        meta: MsgMeta,
        granted: bool,
    },
    AppendEntries {
        meta: MsgMeta,
        prev_log_index: Index,
        prev_log_term: Term,
        commit: Index,
        /// The leader's verified index: highest entry whose post-apply
        /// ledger root a quorum has confirmed (see `core` docs).
        verified: Index,
        entries: Vec<Entry>,
    },
    AppendResponse {
        meta: MsgMeta,
        success: bool,
        match_index: Index,
        /// On rejection: a hint for the leader's next probe.
        conflict_index: Index,
        /// Verified-commit report (WS3): `(applied_index, ledger_root)`.
        applied_root: Option<(Index, [u8; 32])>,
    },
}

/// Decode caps — a frame that exceeds these is rejected as corrupt.
const MAX_ENTRIES_PER_MSG: usize = 4096;
const MAX_ENTRY_DATA: usize = 4 * 1024 * 1024;

impl Message {
    pub fn meta(&self) -> MsgMeta {
        match self {
            Message::RequestVote { meta, .. }
            | Message::VoteResponse { meta, .. }
            | Message::AppendEntries { meta, .. }
            | Message::AppendResponse { meta, .. } => *meta,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        let (kind, meta) = match self {
            Message::RequestVote { meta, .. } => (1u8, meta),
            Message::VoteResponse { meta, .. } => (2, meta),
            Message::AppendEntries { meta, .. } => (3, meta),
            Message::AppendResponse { meta, .. } => (4, meta),
        };
        buf.push(kind);
        buf.extend_from_slice(&meta.from.to_le_bytes());
        buf.extend_from_slice(&meta.term.to_le_bytes());
        buf.extend_from_slice(&meta.incarnation.to_le_bytes());

        match self {
            Message::RequestVote { last_log_index, last_log_term, .. } => {
                buf.extend_from_slice(&last_log_index.to_le_bytes());
                buf.extend_from_slice(&last_log_term.to_le_bytes());
            }
            Message::VoteResponse { granted, .. } => {
                buf.push(*granted as u8);
            }
            Message::AppendEntries {
                prev_log_index, prev_log_term, commit, verified, entries, ..
            } => {
                buf.extend_from_slice(&prev_log_index.to_le_bytes());
                buf.extend_from_slice(&prev_log_term.to_le_bytes());
                buf.extend_from_slice(&commit.to_le_bytes());
                buf.extend_from_slice(&verified.to_le_bytes());
                buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                for e in entries {
                    buf.extend_from_slice(&e.term.to_le_bytes());
                    buf.extend_from_slice(&e.index.to_le_bytes());
                    buf.push(e.kind as u8);
                    buf.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&e.data);
                }
            }
            Message::AppendResponse {
                success, match_index, conflict_index, applied_root, ..
            } => {
                buf.push(*success as u8);
                buf.extend_from_slice(&match_index.to_le_bytes());
                buf.extend_from_slice(&conflict_index.to_le_bytes());
                match applied_root {
                    Some((idx, root)) => {
                        buf.push(1);
                        buf.extend_from_slice(&idx.to_le_bytes());
                        buf.extend_from_slice(root);
                    }
                    None => buf.push(0),
                }
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        let kind = get_u8(data, &mut off)?;
        let meta = MsgMeta {
            from: get_u64(data, &mut off)?,
            term: get_u64(data, &mut off)?,
            incarnation: get_u64(data, &mut off)?,
        };
        let msg = match kind {
            1 => Message::RequestVote {
                meta,
                last_log_index: get_u64(data, &mut off)?,
                last_log_term: get_u64(data, &mut off)?,
            },
            2 => Message::VoteResponse { meta, granted: get_u8(data, &mut off)? != 0 },
            3 => {
                let prev_log_index = get_u64(data, &mut off)?;
                let prev_log_term = get_u64(data, &mut off)?;
                let commit = get_u64(data, &mut off)?;
                let verified = get_u64(data, &mut off)?;
                let count = get_u32(data, &mut off)? as usize;
                if count > MAX_ENTRIES_PER_MSG {
                    return None;
                }
                let mut entries = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    let term = get_u64(data, &mut off)?;
                    let index = get_u64(data, &mut off)?;
                    let kind = EntryKind::from_u8(get_u8(data, &mut off)?)?;
                    let len = get_u32(data, &mut off)? as usize;
                    if len > MAX_ENTRY_DATA {
                        return None;
                    }
                    let data = get_bytes(data, &mut off, len)?.to_vec();
                    entries.push(Entry { term, index, kind, data });
                }
                Message::AppendEntries {
                    meta,
                    prev_log_index,
                    prev_log_term,
                    commit,
                    verified,
                    entries,
                }
            }
            4 => {
                let success = get_u8(data, &mut off)? != 0;
                let match_index = get_u64(data, &mut off)?;
                let conflict_index = get_u64(data, &mut off)?;
                let applied_root = match get_u8(data, &mut off)? {
                    0 => None,
                    1 => {
                        let idx = get_u64(data, &mut off)?;
                        let root: [u8; 32] = get_bytes(data, &mut off, 32)?.try_into().ok()?;
                        Some((idx, root))
                    }
                    _ => return None,
                };
                Message::AppendResponse { meta, success, match_index, conflict_index, applied_root }
            }
            _ => return None,
        };
        // Reject trailing garbage — frames are exact.
        if off != data.len() {
            return None;
        }
        Some(msg)
    }
}

fn get_u8(data: &[u8], off: &mut usize) -> Option<u8> {
    let v = *data.get(*off)?;
    *off += 1;
    Some(v)
}

fn get_u32(data: &[u8], off: &mut usize) -> Option<u32> {
    let v = u32::from_le_bytes(data.get(*off..*off + 4)?.try_into().ok()?);
    *off += 4;
    Some(v)
}

fn get_u64(data: &[u8], off: &mut usize) -> Option<u64> {
    let v = u64::from_le_bytes(data.get(*off..*off + 8)?.try_into().ok()?);
    *off += 8;
    Some(v)
}

fn get_bytes<'a>(data: &'a [u8], off: &mut usize, len: usize) -> Option<&'a [u8]> {
    let v = data.get(*off..*off + len)?;
    *off += len;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConfigChange;

    fn meta() -> MsgMeta {
        MsgMeta { from: 7, term: 42, incarnation: 0xDEAD_BEEF }
    }

    #[test]
    fn roundtrip_request_vote() {
        let m = Message::RequestVote { meta: meta(), last_log_index: 10, last_log_term: 3 };
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn roundtrip_vote_response() {
        for granted in [true, false] {
            let m = Message::VoteResponse { meta: meta(), granted };
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn roundtrip_append_entries() {
        let entries = vec![
            Entry { term: 2, index: 5, kind: EntryKind::App, data: b"tx1".to_vec() },
            Entry { term: 2, index: 6, kind: EntryKind::Noop, data: vec![] },
            Entry {
                term: 3,
                index: 7,
                kind: EntryKind::Config,
                data: ConfigChange::PromoteVoter { node: 9, incarnation: 4 }.encode(),
            },
        ];
        let m = Message::AppendEntries {
            meta: meta(),
            prev_log_index: 4,
            prev_log_term: 2,
            commit: 5,
            verified: 3,
            entries,
        };
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn roundtrip_append_response() {
        let m = Message::AppendResponse {
            meta: meta(),
            success: true,
            match_index: 12,
            conflict_index: 0,
            applied_root: Some((11, [0xAB; 32])),
        };
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        let m2 = Message::AppendResponse {
            meta: meta(),
            success: false,
            match_index: 0,
            conflict_index: 8,
            applied_root: None,
        };
        assert_eq!(Message::decode(&m2.encode()).unwrap(), m2);
    }

    #[test]
    fn rejects_trailing_garbage_and_truncation() {
        let m = Message::RequestVote { meta: meta(), last_log_index: 1, last_log_term: 1 };
        let mut enc = m.encode();
        enc.push(0);
        assert!(Message::decode(&enc).is_none());
        let enc = m.encode();
        assert!(Message::decode(&enc[..enc.len() - 1]).is_none());
        assert!(Message::decode(&[]).is_none());
        assert!(Message::decode(&[9]).is_none());
    }

    #[test]
    fn config_change_roundtrip() {
        for cc in [
            ConfigChange::AddLearner { node: 3 },
            ConfigChange::PromoteVoter { node: 3, incarnation: 77 },
            ConfigChange::RemoveNode { node: 1 },
            ConfigChange::RefreshIncarnation { node: 2, incarnation: u64::MAX },
        ] {
            assert_eq!(ConfigChange::decode(&cc.encode()).unwrap(), cc);
        }
        assert!(ConfigChange::decode(&[]).is_none());
        assert!(ConfigChange::decode(&[1, 0, 0]).is_none());
    }
}
