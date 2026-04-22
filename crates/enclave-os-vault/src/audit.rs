// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Per-key audit log.
//!
//! Each key gets a monotonic sequence of [`AuditEntry`]s, stored sealed
//! under `audit:<handle>:<seq>` in the KV store. The next sequence
//! number is kept on the [`KeyRecord`] (`audit_next_seq`) so reading
//! the log is a simple `seq` walk and writing is one KV put + one
//! record save.

use std::format;
use std::string::String;
use std::vec::Vec;

use enclave_os_kvstore::SealedKvStore;

use crate::types::{AuditDecision, AuditEntry, KeyRecord};

fn audit_key(handle: &str, seq: u64) -> Vec<u8> {
    format!("audit:{}:{:020}", handle, seq).into_bytes()
}

/// Append one entry to a key's audit log. Mutates `record.audit_next_seq`
/// but does not save the record — the surrounding handler is responsible
/// for that.
pub(crate) fn append(
    store: &SealedKvStore,
    record: &mut KeyRecord,
    op: &str,
    caller: &str,
    decision: AuditDecision,
    reason: &str,
) -> Result<(), String> {
    let now = enclave_os_common::ocall::get_current_time().unwrap_or(0);
    let entry = AuditEntry {
        seq: record.audit_next_seq,
        ts: now,
        op: op.to_string(),
        caller: caller.to_string(),
        decision,
        reason: reason.to_string(),
    };
    let bytes = serde_json::to_vec(&entry).map_err(|e| format!("audit serialise: {e}"))?;
    store
        .put(&audit_key(&record.handle, record.audit_next_seq), &bytes)
        .map_err(|e| format!("audit put: {e}"))?;
    record.audit_next_seq = record.audit_next_seq.saturating_add(1);
    Ok(())
}

/// Read entries with `seq > since_seq`, capped at `limit`. Returns the
/// fetched entries and the next-unread sequence number.
pub(crate) fn read(
    store: &SealedKvStore,
    handle: &str,
    next_seq: u64,
    since_seq: u64,
    limit: u32,
) -> Result<(Vec<AuditEntry>, u64), String> {
    let mut out = Vec::new();
    let limit = limit as u64;
    let start = since_seq;
    let mut seq = start;
    while seq < next_seq && (out.len() as u64) < limit {
        if let Some(bytes) = store
            .get(&audit_key(handle, seq))
            .map_err(|e| format!("audit get: {e}"))?
        {
            if let Ok(entry) = serde_json::from_slice::<AuditEntry>(&bytes) {
                out.push(entry);
            }
        }
        seq += 1;
    }
    Ok((out, seq))
}
