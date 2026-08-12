// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RocksDB-backed encrypted KV store with per-app table isolation.
//!
//! Each "table" maps to a RocksDB column family.  Tables are created
//! on first use and persisted across restarts.  The host stores opaque
//! ciphertext – all encryption/decryption happens inside the enclave.

use anyhow::{Context, Result};
use rocksdb::{ColumnFamilyDescriptor, Direction, IteratorMode, Options, WriteBatch, DB};
use std::sync::{Mutex, OnceLock};

/// Cap applied to scans when the caller passes `limit == 0`.
const DEFAULT_SCAN_LIMIT: usize = 10_000;

static DB_INSTANCE: OnceLock<Mutex<DB>> = OnceLock::new();

/// Shared options for column families.
fn cf_opts() -> Options {
    let mut opts = Options::default();
    opts.optimize_for_point_lookup(4); // 4 MiB block-cache per CF
    opts
}

/// Open (or create) the RocksDB database at `path`.
///
/// All existing column families are opened automatically so that tables
/// created in previous runs survive restarts.
pub fn init(path: &str) -> Result<()> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_max_open_files(256);
    opts.set_write_buffer_size(16 * 1024 * 1024); // 16 MiB

    // Discover existing column families (returns at least ["default"]).
    let cfs = DB::list_cf(&opts, path).unwrap_or_else(|_| vec!["default".to_string()]);

    let cf_descriptors: Vec<ColumnFamilyDescriptor> = cfs
        .iter()
        .map(|name| ColumnFamilyDescriptor::new(name, cf_opts()))
        .collect();

    let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
        .with_context(|| format!("Failed to open RocksDB at {}", path))?;

    DB_INSTANCE
        .set(Mutex::new(db))
        .map_err(|_| anyhow::anyhow!("KV store already initialised"))?;
    Ok(())
}

/// Get a lock on the shared DB handle.
fn db() -> std::sync::MutexGuard<'static, DB> {
    DB_INSTANCE
        .get()
        .expect("KV store not initialised")
        .lock()
        .expect("KV store lock poisoned")
}

/// Ensure a column family exists, creating it if necessary.
fn ensure_cf(db: &mut DB, table: &str) {
    if db.cf_handle(table).is_none() {
        let _ = db.create_cf(table, &cf_opts());
    }
}

/// Store an encrypted key-value pair in the given table.
pub fn put(table: &str, enc_key: &[u8], enc_val: &[u8]) -> Result<()> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    db.put_cf(&cf, enc_key, enc_val)
        .context("RocksDB put_cf failed")
}

/// Retrieve an encrypted value by encrypted key from the given table.
/// Returns `Ok(None)` if the key is not found.
pub fn get(table: &str, enc_key: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    db.get_cf(&cf, enc_key)
        .context("RocksDB get_cf failed")
}

/// Delete an entry by encrypted key from the given table.
/// Returns `Ok(true)` if the key existed.
pub fn delete(table: &str, enc_key: &[u8]) -> Result<bool> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    let existed = db
        .get_cf(&cf, enc_key)
        .context("RocksDB get_cf (before delete) failed")?
        .is_some();
    if existed {
        db.delete_cf(&cf, enc_key)
            .context("RocksDB delete_cf failed")?;
    }
    Ok(existed)
}

/// Apply a batch of operations atomically in the given table.
///
/// Each op is `(key, Some(value))` for a put or `(key, None)` for a
/// delete. RocksDB `WriteBatch` guarantees all-or-nothing.
pub fn write_batch(table: &str, ops: &[(&[u8], Option<&[u8]>)]) -> Result<()> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    let mut batch = WriteBatch::default();
    for (key, value) in ops {
        match value {
            Some(v) => batch.put_cf(&cf, key, v),
            None => batch.delete_cf(&cf, key),
        }
    }
    db.write(batch).context("RocksDB write batch failed")
}

/// Retrieve several encrypted values in one call. Results are in request
/// order; missing keys yield `None`.
pub fn multi_get(table: &str, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();
    db.multi_get_cf(keys.iter().map(|k| (cf, *k)))
        .into_iter()
        .map(|r| r.context("RocksDB multi_get_cf failed"))
        .collect()
}

/// Range scan `[start, end)` returning key-value pairs in ascending key
/// order. An empty `start` scans from the beginning; an empty `end` is
/// unbounded. `limit == 0` applies [`DEFAULT_SCAN_LIMIT`].
pub fn scan(table: &str, start: &[u8], end: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();

    scan_cf(&db, cf, start, end, limit)
}

/// Scan implementation over an already-resolved column family.
fn scan_cf(
    db: &DB,
    cf: &rocksdb::ColumnFamily,
    start: &[u8],
    end: &[u8],
    limit: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let limit = if limit == 0 { DEFAULT_SCAN_LIMIT } else { limit };
    let mode = if start.is_empty() {
        IteratorMode::Start
    } else {
        IteratorMode::From(start, Direction::Forward)
    };

    let mut entries = Vec::new();
    for item in db.iterator_cf(&cf, mode) {
        let (k, v) = item.context("RocksDB iterator failed")?;
        if !end.is_empty() && &*k >= end {
            break;
        }
        entries.push((k.to_vec(), v.to_vec()));
        if entries.len() >= limit {
            break;
        }
    }
    Ok(entries)
}

/// List all keys in a table, optionally filtered by a prefix.
///
/// Returns up to `limit` keys whose raw bytes start with `prefix`.
/// Pass an empty prefix to list all keys.
pub fn list_keys(table: &str, prefix: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
    let mut db = db();
    ensure_cf(&mut db, table);
    let cf = db.cf_handle(table).unwrap();

    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    let mut keys = Vec::new();
    for item in iter {
        let (k, _v) = item.context("RocksDB iterator failed")?;
        if prefix.is_empty() || k.starts_with(prefix) {
            keys.push(k.to_vec());
            if keys.len() >= limit {
                break;
            }
        } else if !prefix.is_empty() && &*k > prefix {
            // Keys are sorted — if we're past the prefix, stop early
            // (only works when prefix bytes form a valid range boundary).
            break;
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: open a fresh RocksDB in a temp dir for one test.
    fn open_tmp() -> (tempfile::TempDir, DB) {
        let tmp = tempfile::tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open(&opts, tmp.path()).unwrap();
        (tmp, db)
    }

    #[test]
    fn put_get_delete_default_cf() {
        let (_tmp, db) = open_tmp();

        let key = b"encrypted_key_123";
        let val = b"encrypted_value_456";

        db.put(key, val).unwrap();

        let retrieved = db.get(key).unwrap();
        assert_eq!(retrieved, Some(val.to_vec()));

        db.delete(key).unwrap();

        let after_delete = db.get(key).unwrap();
        assert_eq!(after_delete, None);
    }

    #[test]
    fn get_missing_returns_none() {
        let (_tmp, db) = open_tmp();
        assert_eq!(db.get(b"no_such_key").unwrap(), None);
    }

    #[test]
    fn overwrite_existing_key() {
        let (_tmp, db) = open_tmp();
        db.put(b"k", b"v1").unwrap();
        db.put(b"k", b"v2").unwrap();
        assert_eq!(db.get(b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn binary_keys_and_values() {
        let (_tmp, db) = open_tmp();
        let key = (0u8..=255).collect::<Vec<u8>>();
        let val = vec![0xFFu8; 64_000];
        db.put(&key, &val).unwrap();
        assert_eq!(db.get(&key).unwrap().unwrap(), val);
    }

    #[test]
    fn write_batch_atomic_put_and_delete() {
        let (_tmp, db) = open_tmp();
        db.put(b"old", b"v").unwrap();

        let mut batch = WriteBatch::default();
        let cf = db.cf_handle("default").unwrap();
        batch.put_cf(&cf, b"a", b"1");
        batch.put_cf(&cf, b"b", b"2");
        batch.delete_cf(&cf, b"old");
        db.write(batch).unwrap();

        assert_eq!(db.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(db.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(db.get(b"old").unwrap(), None);
    }

    #[test]
    fn multi_get_preserves_order_and_misses() {
        let (_tmp, db) = open_tmp();
        db.put(b"k1", b"v1").unwrap();
        db.put(b"k3", b"v3").unwrap();

        let cf = db.cf_handle("default").unwrap();
        let keys: Vec<&[u8]> = vec![b"k3", b"k2", b"k1"];
        let results: Vec<Option<Vec<u8>>> = db
            .multi_get_cf(keys.iter().map(|k| (cf, *k)))
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            results,
            vec![Some(b"v3".to_vec()), None, Some(b"v1".to_vec())]
        );
    }

    #[test]
    fn scan_range_semantics() {
        let (_tmp, db) = open_tmp();
        for (k, v) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3"), (b"d", b"4")] {
            db.put(k, v).unwrap();
        }
        let cf = db.cf_handle("default").unwrap();

        // [b, d) is half-open: includes b and c, excludes d.
        let entries = scan_cf(&db, cf, b"b", b"d", 100).unwrap();
        assert_eq!(
            entries,
            vec![(b"b".to_vec(), b"2".to_vec()), (b"c".to_vec(), b"3".to_vec())]
        );

        // Empty start scans from the beginning; empty end is unbounded.
        let entries = scan_cf(&db, cf, b"", b"", 100).unwrap();
        assert_eq!(entries.len(), 4);

        // Limit truncates.
        let entries = scan_cf(&db, cf, b"", b"", 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].0, b"c".to_vec());

        // Start between keys lands on the next key.
        let entries = scan_cf(&db, cf, b"bb", b"", 100).unwrap();
        assert_eq!(entries[0].0, b"c".to_vec());

        // Empty range.
        let entries = scan_cf(&db, cf, b"x", b"", 100).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn column_family_isolation() {
        let (_tmp, mut db) = open_tmp();

        // Create two column families.
        db.create_cf("app:alice", &cf_opts()).unwrap();
        db.create_cf("app:bob", &cf_opts()).unwrap();

        let cf_a = db.cf_handle("app:alice").unwrap();
        let cf_b = db.cf_handle("app:bob").unwrap();

        db.put_cf(&cf_a, b"key", b"alice_value").unwrap();
        db.put_cf(&cf_b, b"key", b"bob_value").unwrap();

        assert_eq!(
            db.get_cf(&cf_a, b"key").unwrap(),
            Some(b"alice_value".to_vec())
        );
        assert_eq!(
            db.get_cf(&cf_b, b"key").unwrap(),
            Some(b"bob_value".to_vec())
        );

        // Default CF should NOT have "key".
        assert_eq!(db.get(b"key").unwrap(), None);
    }
}
