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
//  Per-app counters
// ---------------------------------------------------------------------------

/// Counters for a single WASM app.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AppCounters {
    calls_total: i64,
    fuel_consumed_total: i64,
    errors_total: i64,
    functions: BTreeMap<String, FuncCounters>,
}

// ---------------------------------------------------------------------------
//  WasmMetricsStore
// ---------------------------------------------------------------------------

/// Thread-safe (behind external Mutex) in-memory metrics store.
///
/// One instance lives inside [`WasmModule`](crate::WasmModule).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmMetricsStore {
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
        let kv = enclave_os_kvstore::kv_store()
            .ok_or_else(|| "KV store not initialised".to_string())?;
        let kv = kv.lock().map_err(|_| "KV store lock poisoned".to_string())?;
        let data = self.to_bytes()?;
        kv.put(METRICS_KV_KEY, &data)
    }

    /// Load metrics from the sealed KV store, merging into the current
    /// counters (additive — preserves any calls recorded since boot).
    pub fn load(&mut self) -> Result<bool, String> {
        let kv = enclave_os_kvstore::kv_store()
            .ok_or_else(|| "KV store not initialised".to_string())?;
        let kv = kv.lock().map_err(|_| "KV store lock poisoned".to_string())?;

        match kv.get(METRICS_KV_KEY)? {
            Some(data) => {
                let saved = Self::from_bytes(&data)?;
                // Merge saved counters into current state.
                for (app_name, saved_ac) in saved.apps {
                    let ac = self.apps.entry(app_name).or_default();
                    ac.calls_total += saved_ac.calls_total;
                    ac.fuel_consumed_total += saved_ac.fuel_consumed_total;
                    ac.errors_total += saved_ac.errors_total;
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
