// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Encrypted, host-backed persistence for the Raft log and hard state.
//!
//! One KV table (the module uses `raft:<name>` via the same OCALL
//! backend as the Merkle store) holds, all AES-256-GCM under a
//! node-local log key derived from the sealed master key:
//!
//! | key | value |
//! | --- | --- |
//! | `e` ‖ index u64 BE | encrypted [`Entry`] (AAD binds the index) |
//! | `h` | encrypted [`HardState`] |
//! | `g` | encrypted genesis [`Membership`] |
//! | `a` | encrypted applied floor (u64 LE) |
//!
//! Each [`Ready`] persists as ONE atomic `write_batch` (truncate
//! deletes + entry puts + hard state), honouring the driver contract:
//! the caller sends messages only after [`LogStore::persist`] returns.
//!
//! The applied floor (`a`) is written AFTER the ledger applied a batch,
//! so it can lag the ledger checkpoint by at most one batch; the driver
//! resolves that window by recognising a transaction whose `root_after`
//! equals the current ledger root as already applied.
//!
//! Rollback of this table by the host is exactly the attack the
//! incarnation gate and quorum root confirmation defend against — the
//! log store only needs confidentiality and integrity, both provided by
//! GCM with index-binding AAD.

use enclave_os_common::aead::AeadCipher;
use enclave_os_common::rpc::KvBatchOp;
use enclave_os_merkle::{KvBackend, MerkleError};

use crate::core::Ready;
use crate::types::{Entry, HardState, Index, Membership};

const KEY_HARD_STATE: &[u8] = b"h";
const KEY_GENESIS: &[u8] = b"g";
const KEY_APPLIED: &[u8] = b"a";
const ENTRY_PREFIX: u8 = b'e';

const AAD_ENTRY: &[u8] = b"enclave_os_raft_log_entry";
const AAD_HS: &[u8] = b"enclave_os_raft_hard_state";
const AAD_GENESIS: &[u8] = b"enclave_os_raft_genesis";
const AAD_APPLIED: &[u8] = b"enclave_os_raft_applied";

/// Log persistence failure.
#[derive(Debug)]
pub enum LogError {
    /// Backend I/O failure.
    Backend(MerkleError),
    /// A stored record failed authentication or decoding: the host
    /// tampered with the log table (or handed us a foreign table).
    Corrupted(&'static str),
}

impl From<MerkleError> for LogError {
    fn from(e: MerkleError) -> Self {
        Self::Backend(e)
    }
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "log backend: {e}"),
            Self::Corrupted(what) => write!(f, "log corrupted: {what}"),
        }
    }
}

fn entry_key(index: Index) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(ENTRY_PREFIX);
    k.extend_from_slice(&index.to_be_bytes());
    k
}

fn entry_aad(index: Index) -> Vec<u8> {
    let mut aad = AAD_ENTRY.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// The persisted state a [`LogStore::open`] recovers.
pub struct RecoveredLog {
    pub genesis: Membership,
    pub entries: Vec<Entry>,
    pub hard_state: HardState,
    pub applied_floor: Index,
}

/// Encrypted Raft log over a host KV table.
pub struct LogStore<B: KvBackend> {
    backend: B,
    cipher: AeadCipher,
    /// Last persisted entry index (0 = empty log).
    last_index: Index,
}

impl<B: KvBackend> LogStore<B> {
    /// Initialise a fresh log table with the genesis membership.
    pub fn create(backend: B, log_key: [u8; 32], genesis: &Membership) -> Result<Self, LogError> {
        let cipher = AeadCipher::from_key(log_key);
        let g = cipher
            .encrypt(&genesis.encode(), AAD_GENESIS)
            .map_err(|_| LogError::Corrupted("encrypt genesis"))?;
        backend.write_batch(vec![KvBatchOp::Put { key: KEY_GENESIS.to_vec(), value: g }])?;
        Ok(Self { backend, cipher, last_index: 0 })
    }

    /// Does a log exist in this table yet?
    pub fn exists(backend: &B) -> Result<bool, LogError> {
        Ok(backend.get(KEY_GENESIS)?.is_some())
    }

    /// Open an existing log: recover genesis, entries, hard state and
    /// the applied floor. Fails closed on any authentication failure.
    pub fn open(backend: B, log_key: [u8; 32]) -> Result<(Self, RecoveredLog), LogError> {
        let cipher = AeadCipher::from_key(log_key);

        let g = backend.get(KEY_GENESIS)?.ok_or(LogError::Corrupted("missing genesis"))?;
        let genesis = Membership::decode(
            &cipher.decrypt(&g, AAD_GENESIS).map_err(|_| LogError::Corrupted("genesis auth"))?,
        )
        .ok_or(LogError::Corrupted("genesis decode"))?;

        let hard_state = match backend.get(KEY_HARD_STATE)? {
            Some(ct) => HardState::decode(
                &cipher.decrypt(&ct, AAD_HS).map_err(|_| LogError::Corrupted("hard state auth"))?,
            )
            .ok_or(LogError::Corrupted("hard state decode"))?,
            None => HardState::default(),
        };

        let applied_floor = match backend.get(KEY_APPLIED)? {
            Some(ct) => {
                let pt = cipher
                    .decrypt(&ct, AAD_APPLIED)
                    .map_err(|_| LogError::Corrupted("applied auth"))?;
                let bytes: [u8; 8] =
                    pt.as_slice().try_into().map_err(|_| LogError::Corrupted("applied decode"))?;
                u64::from_le_bytes(bytes)
            }
            None => 0,
        };

        // Scan all entry records (chunked: the backend caps a scan).
        let mut entries: Vec<Entry> = Vec::new();
        let mut start = vec![ENTRY_PREFIX];
        let end = vec![ENTRY_PREFIX + 1];
        loop {
            let chunk = backend.scan(&start, &end, 4096)?;
            let n = chunk.len();
            for (key, ct) in &chunk {
                if key.len() != 9 || key[0] != ENTRY_PREFIX {
                    return Err(LogError::Corrupted("entry key shape"));
                }
                let index = u64::from_be_bytes(key[1..9].try_into().unwrap());
                let pt = cipher
                    .decrypt(ct, &entry_aad(index))
                    .map_err(|_| LogError::Corrupted("entry auth"))?;
                let entry = Entry::decode(&pt).ok_or(LogError::Corrupted("entry decode"))?;
                if entry.index != index {
                    return Err(LogError::Corrupted("entry index mismatch"));
                }
                entries.push(entry);
            }
            if n < 4096 {
                break;
            }
            // Resume after the last key seen.
            let mut next = chunk.last().unwrap().0.clone();
            next.push(0);
            start = next;
        }

        // BE index keys scan in index order; verify contiguity from 1.
        for (i, e) in entries.iter().enumerate() {
            if e.index != i as Index + 1 {
                return Err(LogError::Corrupted("entry gap"));
            }
        }
        let last_index = entries.last().map(|e| e.index).unwrap_or(0);

        Ok((
            Self { backend, cipher, last_index },
            RecoveredLog { genesis, entries, hard_state, applied_floor },
        ))
    }

    /// Persist one [`Ready`]'s durable obligations as a single atomic
    /// batch: truncation deletes, entry puts, hard state. Call BEFORE
    /// sending the Ready's messages.
    pub fn persist(&mut self, ready: &Ready) -> Result<(), LogError> {
        let mut ops: Vec<KvBatchOp> = Vec::new();
        let mut new_last = self.last_index;

        if let Some(t) = ready.truncate_from {
            for i in t..=self.last_index {
                ops.push(KvBatchOp::Delete { key: entry_key(i) });
            }
            new_last = t.saturating_sub(1);
        }
        for e in &ready.entries_to_persist {
            let ct = self
                .cipher
                .encrypt(&e.encode(), &entry_aad(e.index))
                .map_err(|_| LogError::Corrupted("encrypt entry"))?;
            ops.push(KvBatchOp::Put { key: entry_key(e.index), value: ct });
            new_last = new_last.max(e.index);
        }
        if let Some(hs) = ready.hard_state {
            let ct = self
                .cipher
                .encrypt(&hs.encode(), AAD_HS)
                .map_err(|_| LogError::Corrupted("encrypt hard state"))?;
            ops.push(KvBatchOp::Put { key: KEY_HARD_STATE.to_vec(), value: ct });
        }
        if ops.is_empty() {
            return Ok(());
        }
        self.backend.write_batch(ops)?;
        self.last_index = new_last;
        Ok(())
    }

    /// Record the applied floor (called after the ledger applied a
    /// committed batch; may lag the ledger by one batch on crash).
    pub fn set_applied_floor(&mut self, index: Index) -> Result<(), LogError> {
        let ct = self
            .cipher
            .encrypt(&index.to_le_bytes(), AAD_APPLIED)
            .map_err(|_| LogError::Corrupted("encrypt applied"))?;
        self.backend
            .write_batch(vec![KvBatchOp::Put { key: KEY_APPLIED.to_vec(), value: ct }])?;
        Ok(())
    }

    pub fn last_index(&self) -> Index {
        self.last_index
    }
}
