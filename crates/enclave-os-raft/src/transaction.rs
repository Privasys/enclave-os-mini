// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Apply-mode transactions: the payload of an [`crate::EntryKind::App`]
//! log entry.
//!
//! A transaction is a sealed state transition over the Merkle ledger:
//! `(root_before, write_set, root_after)`. Every node applies the
//! write-set and verifies the root transition; any mismatch is
//! divergence and fails closed (see the verified-commit protocol in
//! `core`). The write-set carries plaintext values — entries travel
//! only inside mutual RA-TLS peer links and rest in the node-local log
//! encrypted under a node key; each replica re-encrypts values with its
//! own storage key, and the commitment key makes the roots agree.

use crate::core::LedgerRoot;

/// Decode caps — a payload exceeding these is rejected as corrupt.
const MAX_OPS: usize = 65_536;
const MAX_KEY: usize = 64 * 1024;
const MAX_VALUE: usize = 4 * 1024 * 1024;

/// A sealed apply-mode transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Ledger root the transaction was sealed against.
    pub root_before: LedgerRoot,
    /// Ledger root the write-set must produce.
    pub root_after: LedgerRoot,
    /// Ledger version after applying (equals the version before + 1,
    /// or the unchanged version for a no-op write-set).
    pub version_after: u64,
    /// Deterministic (key-ordered) write-set: `Some` = put, `None` =
    /// delete.
    pub ops: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Transaction {
    /// Encode: `[root_before 32][root_after 32][version_after u64 LE]
    /// [count u32][per op: key_len u32, key, tag u8, (value_len u32,
    /// value)?]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(76 + self.ops.len() * 32);
        buf.extend_from_slice(&self.root_before);
        buf.extend_from_slice(&self.root_after);
        buf.extend_from_slice(&self.version_after.to_le_bytes());
        buf.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for (key, value) in &self.ops {
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            match value {
                Some(v) => {
                    buf.push(1);
                    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    buf.extend_from_slice(v);
                }
                None => buf.push(0),
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        let root_before: LedgerRoot = get_bytes(data, &mut off, 32)?.try_into().ok()?;
        let root_after: LedgerRoot = get_bytes(data, &mut off, 32)?.try_into().ok()?;
        let version_after = u64::from_le_bytes(get_bytes(data, &mut off, 8)?.try_into().ok()?);
        let count =
            u32::from_le_bytes(get_bytes(data, &mut off, 4)?.try_into().ok()?) as usize;
        if count > MAX_OPS {
            return None;
        }
        let mut ops = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let key_len =
                u32::from_le_bytes(get_bytes(data, &mut off, 4)?.try_into().ok()?) as usize;
            if key_len > MAX_KEY {
                return None;
            }
            let key = get_bytes(data, &mut off, key_len)?.to_vec();
            let value = match *data.get(off)? {
                0 => {
                    off += 1;
                    None
                }
                1 => {
                    off += 1;
                    let value_len =
                        u32::from_le_bytes(get_bytes(data, &mut off, 4)?.try_into().ok()?)
                            as usize;
                    if value_len > MAX_VALUE {
                        return None;
                    }
                    Some(get_bytes(data, &mut off, value_len)?.to_vec())
                }
                _ => return None,
            };
            ops.push((key, value));
        }
        if off != data.len() {
            return None;
        }
        Some(Self { root_before, root_after, version_after, ops })
    }
}

fn get_bytes<'a>(data: &'a [u8], off: &mut usize, len: usize) -> Option<&'a [u8]> {
    let v = data.get(*off..*off + len)?;
    *off += len;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let txn = Transaction {
            root_before: [1; 32],
            root_after: [2; 32],
            version_after: 9,
            ops: vec![
                (b"alice".to_vec(), Some(b"1000".to_vec())),
                (b"bob".to_vec(), None),
                (Vec::new(), Some(Vec::new())),
            ],
        };
        assert_eq!(Transaction::decode(&txn.encode()).unwrap(), txn);
    }

    #[test]
    fn rejects_corrupt() {
        let txn = Transaction {
            root_before: [0; 32],
            root_after: [0; 32],
            version_after: 1,
            ops: vec![(b"k".to_vec(), Some(b"v".to_vec()))],
        };
        let enc = txn.encode();
        assert!(Transaction::decode(&enc[..enc.len() - 1]).is_none());
        let mut trailing = enc.clone();
        trailing.push(0);
        assert!(Transaction::decode(&trailing).is_none());
        assert!(Transaction::decode(&[]).is_none());
    }
}
