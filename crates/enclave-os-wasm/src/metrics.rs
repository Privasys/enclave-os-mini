// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! In-memory fuel-metering metrics for WASM apps.
//!
//! Tracks per-app and per-function fuel consumption from wasmtime's fuel
//! metering.  Metrics live in memory and can be persisted to the sealed
//! KV store via [`WasmMetricsStore::save`] / [`WasmMetricsStore::load`].

use std::collections::BTreeMap;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use enclave_os_common::protocol::{WasmAppMetrics, WasmFunctionMetrics};

// ---------------------------------------------------------------------------
//  KV key for persistence
// ---------------------------------------------------------------------------

/// Key under which the metrics snapshot is stored in the sealed KV store.
const METRICS_KV_KEY: &[u8] = b"wasm:metrics:snapshot";

/// Schema version for the persisted metrics snapshot.
///
/// Bumped to `2` when the per-app SDK resource counters
/// (ledger / crypto / https) were added. Older (`0`/`1`) snapshots
/// deserialize cleanly because every new counter field is annotated
/// `#[serde(default)]` and therefore defaults to `0` on load.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
//  Per-function counters
// ---------------------------------------------------------------------------

/// Counters for a single exported function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FuncCounters {
    calls: i64,
    fuel_consumed: i64,
    errors: i64,
    fuel_min: i64,
    fuel_max: i64,
}

// ---------------------------------------------------------------------------
//  Per-call SDK resource usage accumulator
// ---------------------------------------------------------------------------

/// Billable Enclave-OS SDK resource usage accumulated **within a single
/// WASM call**.
///
/// One instance lives on each [`AppContext`](crate::wasi::AppContext),
/// which is freshly created per call (see
/// [`Engine::instantiate`](crate::engine::Engine::instantiate)). SDK host
/// functions (crypto / https / sealed filesystem) increment the relevant
/// fields as they execute; after the call returns, the dispatcher merges
/// the accumulator into the persistent [`WasmMetricsStore`] via
/// [`WasmMetricsStore::record_sdk_usage`].
#[derive(Debug, Clone, Default)]
pub struct SdkUsage {
    /// Sealed-KV ("ledger") read operations.
    pub ledger_read_calls: i64,
    /// Bytes read from the sealed KV store.
    pub ledger_read_bytes: i64,
    /// Sealed-KV ("ledger") write operations.
    pub ledger_write_calls: i64,
    /// Bytes written to the sealed KV store.
    pub ledger_write_bytes: i64,
    /// Bytes hashed via `crypto.digest` / `crypto.hmac-*`.
    pub crypto_digest_bytes: i64,
    /// Plaintext/ciphertext bytes processed via `crypto.encrypt` / `decrypt`.
    pub crypto_encdec_bytes: i64,
    /// Number of `crypto.sign` calls.
    pub crypto_sign_calls: i64,
    /// Number of `crypto.verify` calls.
    pub crypto_verify_calls: i64,
    /// Random bytes drawn via `crypto.get-random-bytes`.
    pub crypto_random_bytes: i64,
    /// Number of plain (non-RA-TLS) `https.fetch` calls.
    pub https_plain_calls: i64,
    /// Request+response bytes for plain `https.fetch` calls.
    pub https_plain_bytes: i64,
    /// Number of RA-TLS `https.fetch` calls.
    pub https_ratls_calls: i64,
    /// Request+response bytes for RA-TLS `https.fetch` calls.
    pub https_ratls_bytes: i64,
}

impl SdkUsage {
    /// Whether any billable resource was used during the call.
    pub fn is_empty(&self) -> bool {
        self.ledger_read_calls == 0
            && self.ledger_read_bytes == 0
            && self.ledger_write_calls == 0
            && self.ledger_write_bytes == 0
            && self.crypto_digest_bytes == 0
            && self.crypto_encdec_bytes == 0
            && self.crypto_sign_calls == 0
            && self.crypto_verify_calls == 0
            && self.crypto_random_bytes == 0
            && self.https_plain_calls == 0
            && self.https_plain_bytes == 0
            && self.https_ratls_calls == 0
            && self.https_ratls_bytes == 0
    }
}

// ---------------------------------------------------------------------------
//  Per-app counters
// ---------------------------------------------------------------------------

/// Counters for a single WASM app.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AppCounters {
    calls_total: i64,
    fuel_consumed_total: i64,
    errors_total: i64,
    functions: BTreeMap<String, FuncCounters>,

    // ── Billable SDK resource counters (schema v2) ──────────────────
    #[serde(default)]
    ledger_read_calls: i64,
    #[serde(default)]
    ledger_read_bytes: i64,
    #[serde(default)]
    ledger_write_calls: i64,
    #[serde(default)]
    ledger_write_bytes: i64,
    #[serde(default)]
    crypto_digest_bytes: i64,
    #[serde(default)]
    crypto_encdec_bytes: i64,
    #[serde(default)]
    crypto_sign_calls: i64,
    #[serde(default)]
    crypto_verify_calls: i64,
    #[serde(default)]
    crypto_random_bytes: i64,
    #[serde(default)]
    https_plain_calls: i64,
    #[serde(default)]
    https_plain_bytes: i64,
    #[serde(default)]
    https_ratls_calls: i64,
    #[serde(default)]
    https_ratls_bytes: i64,
}

// ---------------------------------------------------------------------------
//  WasmMetricsStore
// ---------------------------------------------------------------------------

/// Thread-safe (behind external Mutex) in-memory metrics store.
///
/// One instance lives inside [`WasmModule`](crate::WasmModule).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmMetricsStore {
    /// Persisted snapshot schema version (see [`SNAPSHOT_SCHEMA_VERSION`]).
    #[serde(default)]
    schema_version: u32,
    apps: BTreeMap<String, AppCounters>,
}

impl WasmMetricsStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record fuel consumed by a successful call.
    pub fn record_call(&mut self, app: &str, function: &str, fuel_consumed: i64) {
        let ac = self.apps.entry(app.to_string()).or_default();
        ac.calls_total += 1;
        ac.fuel_consumed_total += fuel_consumed;

        let fc = ac.functions.entry(function.to_string()).or_default();
        fc.calls += 1;
        fc.fuel_consumed += fuel_consumed;
        if fc.calls == 1 {
            fc.fuel_min = fuel_consumed;
            fc.fuel_max = fuel_consumed;
        } else {
            if fuel_consumed < fc.fuel_min {
                fc.fuel_min = fuel_consumed;
            }
            if fuel_consumed > fc.fuel_max {
                fc.fuel_max = fuel_consumed;
            }
        }
    }

    /// Merge a single call's billable SDK resource usage into the app's
    /// cumulative counters. No-op when nothing billable was used.
    pub fn record_sdk_usage(&mut self, app: &str, usage: &SdkUsage) {
        if usage.is_empty() {
            return;
        }
        let ac = self.apps.entry(app.to_string()).or_default();
        ac.ledger_read_calls += usage.ledger_read_calls;
        ac.ledger_read_bytes += usage.ledger_read_bytes;
        ac.ledger_write_calls += usage.ledger_write_calls;
        ac.ledger_write_bytes += usage.ledger_write_bytes;
        ac.crypto_digest_bytes += usage.crypto_digest_bytes;
        ac.crypto_encdec_bytes += usage.crypto_encdec_bytes;
        ac.crypto_sign_calls += usage.crypto_sign_calls;
        ac.crypto_verify_calls += usage.crypto_verify_calls;
        ac.crypto_random_bytes += usage.crypto_random_bytes;
        ac.https_plain_calls += usage.https_plain_calls;
        ac.https_plain_bytes += usage.https_plain_bytes;
        ac.https_ratls_calls += usage.https_ratls_calls;
        ac.https_ratls_bytes += usage.https_ratls_bytes;
    }

    /// Record a failed call (error).
    pub fn record_error(&mut self, app: &str, function: &str) {
        let ac = self.apps.entry(app.to_string()).or_default();
        ac.calls_total += 1;
        ac.errors_total += 1;

        let fc = ac.functions.entry(function.to_string()).or_default();
        fc.calls += 1;
        fc.errors += 1;
    }

    /// Remove metrics for an app (called on unload).
    pub fn remove_app(&mut self, app: &str) {
        self.apps.remove(app);
    }

    /// Export metrics in the wire protocol format.
    pub fn to_app_metrics(&self) -> Vec<WasmAppMetrics> {
        self.apps
            .iter()
            .map(|(name, ac)| WasmAppMetrics {
                name: name.clone(),
                calls_total: ac.calls_total,
                fuel_consumed_total: ac.fuel_consumed_total,
                errors_total: ac.errors_total,
                ledger_read_calls: ac.ledger_read_calls,
                ledger_read_bytes: ac.ledger_read_bytes,
                ledger_write_calls: ac.ledger_write_calls,
                ledger_write_bytes: ac.ledger_write_bytes,
                crypto_digest_bytes: ac.crypto_digest_bytes,
                crypto_encdec_bytes: ac.crypto_encdec_bytes,
                crypto_sign_calls: ac.crypto_sign_calls,
                crypto_verify_calls: ac.crypto_verify_calls,
                crypto_random_bytes: ac.crypto_random_bytes,
                https_plain_calls: ac.https_plain_calls,
                https_plain_bytes: ac.https_plain_bytes,
                https_ratls_calls: ac.https_ratls_calls,
                https_ratls_bytes: ac.https_ratls_bytes,
                functions: ac
                    .functions
                    .iter()
                    .map(|(fname, fc)| WasmFunctionMetrics {
                        name: fname.clone(),
                        calls: fc.calls,
                        fuel_consumed: fc.fuel_consumed,
                        errors: fc.errors,
                        fuel_min: fc.fuel_min,
                        fuel_max: fc.fuel_max,
                    })
                    .collect(),
            })
            .collect()
    }

    /// Serialize to JSON bytes for KV persistence.
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("metrics serialization failed: {e}"))
    }

    /// Deserialize from JSON bytes.
    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("metrics deserialization failed: {e}"))
    }

    /// Save the current metrics to the sealed KV store.
    pub fn save(&self) -> Result<(), String> {
        let kv =
            enclave_os_kvstore::kv_store().ok_or_else(|| "KV store not initialised".to_string())?;
        let kv = kv
            .lock()
            .map_err(|_| "KV store lock poisoned".to_string())?;
        let mut snapshot = self.clone();
        snapshot.schema_version = SNAPSHOT_SCHEMA_VERSION;
        let data = snapshot.to_bytes()?;
        kv.put(METRICS_KV_KEY, &data)
    }

    /// Load metrics from the sealed KV store, merging into the current
    /// counters (additive — preserves any calls recorded since boot).
    pub fn load(&mut self) -> Result<bool, String> {
        let kv =
            enclave_os_kvstore::kv_store().ok_or_else(|| "KV store not initialised".to_string())?;
        let kv = kv
            .lock()
            .map_err(|_| "KV store lock poisoned".to_string())?;

        match kv.get(METRICS_KV_KEY)? {
            Some(data) => {
                let saved = Self::from_bytes(&data)?;
                // Merge saved counters into current state.
                for (app_name, saved_ac) in saved.apps {
                    let ac = self.apps.entry(app_name).or_default();
                    ac.calls_total += saved_ac.calls_total;
                    ac.fuel_consumed_total += saved_ac.fuel_consumed_total;
                    ac.errors_total += saved_ac.errors_total;
                    ac.ledger_read_calls += saved_ac.ledger_read_calls;
                    ac.ledger_read_bytes += saved_ac.ledger_read_bytes;
                    ac.ledger_write_calls += saved_ac.ledger_write_calls;
                    ac.ledger_write_bytes += saved_ac.ledger_write_bytes;
                    ac.crypto_digest_bytes += saved_ac.crypto_digest_bytes;
                    ac.crypto_encdec_bytes += saved_ac.crypto_encdec_bytes;
                    ac.crypto_sign_calls += saved_ac.crypto_sign_calls;
                    ac.crypto_verify_calls += saved_ac.crypto_verify_calls;
                    ac.crypto_random_bytes += saved_ac.crypto_random_bytes;
                    ac.https_plain_calls += saved_ac.https_plain_calls;
                    ac.https_plain_bytes += saved_ac.https_plain_bytes;
                    ac.https_ratls_calls += saved_ac.https_ratls_calls;
                    ac.https_ratls_bytes += saved_ac.https_ratls_bytes;
                    for (func_name, saved_fc) in saved_ac.functions {
                        let fc = ac.functions.entry(func_name).or_default();
                        fc.calls += saved_fc.calls;
                        fc.fuel_consumed += saved_fc.fuel_consumed;
                        fc.errors += saved_fc.errors;
                        if fc.calls == saved_fc.calls {
                            // First data comes from saved — adopt min/max.
                            fc.fuel_min = saved_fc.fuel_min;
                            fc.fuel_max = saved_fc.fuel_max;
                        } else {
                            if saved_fc.fuel_min < fc.fuel_min || fc.fuel_min == 0 {
                                fc.fuel_min = saved_fc.fuel_min;
                            }
                            if saved_fc.fuel_max > fc.fuel_max {
                                fc.fuel_max = saved_fc.fuel_max;
                            }
                        }
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_export() {
        let mut store = WasmMetricsStore::new();
        store.record_call("app1", "hello", 5000);
        store.record_call("app1", "hello", 3000);
        store.record_call("app1", "process", 8000);
        store.record_error("app1", "hello");

        let metrics = store.to_app_metrics();
        assert_eq!(metrics.len(), 1);
        let app = &metrics[0];
        assert_eq!(app.name, "app1");
        assert_eq!(app.calls_total, 4);
        assert_eq!(app.fuel_consumed_total, 16000);
        assert_eq!(app.errors_total, 1);
        assert_eq!(app.functions.len(), 2);

        let hello = app.functions.iter().find(|f| f.name == "hello").unwrap();
        assert_eq!(hello.calls, 3);
        assert_eq!(hello.fuel_consumed, 8000);
        assert_eq!(hello.errors, 1);
        assert_eq!(hello.fuel_min, 3000);
        assert_eq!(hello.fuel_max, 5000);
    }

    #[test]
    fn serde_roundtrip() {
        let mut store = WasmMetricsStore::new();
        store.record_call("app1", "hello", 42000);
        let bytes = store.to_bytes().unwrap();
        let restored = WasmMetricsStore::from_bytes(&bytes).unwrap();
        let metrics = restored.to_app_metrics();
        assert_eq!(metrics[0].functions[0].fuel_consumed, 42000);
    }

    #[test]
    fn remove_app() {
        let mut store = WasmMetricsStore::new();
        store.record_call("app1", "hello", 100);
        store.record_call("app2", "world", 200);
        store.remove_app("app1");
        assert_eq!(store.to_app_metrics().len(), 1);
        assert_eq!(store.to_app_metrics()[0].name, "app2");
    }
}
