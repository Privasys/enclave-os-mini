// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `MerkleModule` — the enclave module wrapper around [`MerkleStore`].
//!
//! ## Protocol
//!
//! Requests arrive as `Request::Data(json)` (`POST /data`) using a
//! field-presence envelope, wasm-style: exactly one `merkle_*` field
//! set; anything unrecognised declines so other modules can try. Keys,
//! values and proofs are hex-encoded.
//!
//! | field | role | reply |
//! |---|---|---|
//! | `{"merkle_root": {}}` | monitoring | `{"root": hex32, "version": n}` |
//! | `{"merkle_get": {"key": hex, "version"?: n}}` | monitoring | `{"value": hex \| null}` |
//! | `{"merkle_prove": {"key": hex, "version"?: n}}` | monitoring | `{"proof": hex, "root": hex32, "version": n}` |
//! | `{"merkle_put": {"ops": [{"key": hex, "value"?: hex}]}}` | manager | `{"root": hex32, "version": n}` (`value` absent = delete) |
//! | `{"merkle_prune": {"before_version"?: n, "retain_recent"?: n}}` | manager | `PruneStats` fields |
//!
//! ## Keys
//!
//! `sk` (per-machine storage key) and, for now, `ck` (commitment key)
//! are derived from the enclave master key with distinct labels. A
//! future BFT layer replaces the `ck` derivation with a
//! cluster-provisioned key so replicas share it — that swap touches
//! only [`MerkleModule::new`].
//!
//! ## Certificate OID
//!
//! `custom_oids` exposes `root ‖ version` under
//! `1.3.6.1.4.1.65230.2.6`, recomputed per certificate generation.

use std::sync::Mutex;

use enclave_os_common::hex::{hex_decode, hex_encode};
use enclave_os_common::modules::{ConfigLeaf, EnclaveModule, ModuleOid, RequestContext};
use enclave_os_common::oids::MERKLE_STATE_ROOT_OID;
use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::types::AEAD_KEY_SIZE;
use ring::hmac;
use serde::Deserialize;

use crate::backend::{KvBackend, OcallBackend};
use crate::error::MerkleError;
use crate::tree::MerkleStore;

const CK_LABEL: &[u8] = b"enclave-os-merkle:ck:v1:";
const SK_LABEL: &[u8] = b"enclave-os-merkle:sk:v1:";

/// Derive a store key from the enclave master key with a domain label.
fn derive_key(master_key: &[u8; AEAD_KEY_SIZE], label: &[u8], store_name: &str) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, master_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(label);
    ctx.update(store_name.as_bytes());
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub struct MerkleModule<B: KvBackend + Send> {
    store: Mutex<MerkleStore<B>>,
    store_name: String,
}

impl MerkleModule<OcallBackend> {
    /// Construct the module: derive keys, open the store at its
    /// checkpoint (or create it on first boot).
    pub fn new(
        master_key: [u8; AEAD_KEY_SIZE],
        store_name: &str,
    ) -> Result<Self, String> {
        let ck = derive_key(&master_key, CK_LABEL, store_name);
        let sk = derive_key(&master_key, SK_LABEL, store_name);
        let backend = OcallBackend::new(store_name);
        let store = MerkleStore::open_or_create(backend, ck, sk)
            .map_err(|e| format!("merkle store '{store_name}': {e}"))?;
        Ok(Self { store: Mutex::new(store), store_name: store_name.to_string() })
    }
}

impl<B: KvBackend + Send> MerkleModule<B> {
    /// Wrap an existing store (tests, custom compositions).
    pub fn with_store(store: MerkleStore<B>, store_name: &str) -> Self {
        Self { store: Mutex::new(store), store_name: store_name.to_string() }
    }
}

// ---------------------------------------------------------------------------
//  Envelope
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MerkleEnvelope {
    #[serde(default)]
    merkle_root: Option<serde_json::Value>,
    #[serde(default)]
    merkle_get: Option<KeyReq>,
    #[serde(default)]
    merkle_prove: Option<KeyReq>,
    #[serde(default)]
    merkle_put: Option<PutReq>,
    #[serde(default)]
    merkle_prune: Option<PruneReq>,
}

#[derive(Deserialize)]
struct KeyReq {
    key: String,
    #[serde(default)]
    version: Option<u64>,
}

#[derive(Deserialize)]
struct PutReq {
    ops: Vec<PutOp>,
}

#[derive(Deserialize)]
struct PutOp {
    key: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct PruneReq {
    #[serde(default)]
    before_version: Option<u64>,
    #[serde(default)]
    retain_recent: Option<u64>,
}

fn err_json(msg: &str) -> Response {
    Response::Error(
        serde_json::json!({ "error": msg }).to_string().into_bytes(),
    )
}

fn store_err(e: MerkleError) -> Response {
    err_json(&e.to_string())
}

fn ok_json(value: serde_json::Value) -> Response {
    Response::Data(value.to_string().into_bytes())
}

fn decode_key(hex: &str) -> Result<Vec<u8>, Response> {
    hex_decode(hex).ok_or_else(|| err_json("key must be hex"))
}

// ---------------------------------------------------------------------------
//  EnclaveModule
// ---------------------------------------------------------------------------

impl<B: KvBackend + Send> EnclaveModule for MerkleModule<B> {
    fn name(&self) -> &str {
        "merkle"
    }

    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };
        let env: MerkleEnvelope = match serde_json::from_slice(data) {
            Ok(e) => e,
            Err(_) => return None,
        };

        // Role gates, wasm convention: reads need monitoring, mutation
        // needs manager.
        let is_read = env.merkle_root.is_some() || env.merkle_get.is_some()
            || env.merkle_prove.is_some();
        let is_write = env.merkle_put.is_some() || env.merkle_prune.is_some();
        if !is_read && !is_write {
            return None; // no recognised field — decline
        }
        let claims = match &ctx.oidc_claims {
            Some(c) => c,
            None => return Some(err_json("authentication required")),
        };
        if is_write && !claims.has_manager() {
            return Some(err_json("manager role required"));
        }
        if !is_write && !claims.has_monitoring() {
            return Some(err_json("monitoring role required"));
        }

        let mut store = self.store.lock().expect("merkle store lock poisoned");

        if env.merkle_root.is_some() {
            let (root, version) = store.root();
            return Some(ok_json(serde_json::json!({
                "root": hex_encode(&root),
                "version": version,
            })));
        }

        if let Some(get) = env.merkle_get {
            let key = match decode_key(&get.key) {
                Ok(k) => k,
                Err(resp) => return Some(resp),
            };
            let result = match get.version {
                Some(v) => store.get_at(v, &key),
                None => store.get(&key),
            };
            return Some(match result {
                Ok(value) => ok_json(serde_json::json!({
                    "value": value.map(|v| hex_encode(&v)),
                })),
                Err(e) => store_err(e),
            });
        }

        if let Some(prove) = env.merkle_prove {
            let key = match decode_key(&prove.key) {
                Ok(k) => k,
                Err(resp) => return Some(resp),
            };
            // Report the root the proof verifies against.
            let result = match prove.version {
                Some(v) => store
                    .prove_at(v, &key)
                    .and_then(|p| store.root_at(v).map(|r| (p, r, v))),
                None => {
                    let (root, version) = store.root();
                    store.prove(&key).map(|p| (p, root, version))
                }
            };
            return Some(match result {
                Ok((proof, root, version)) => ok_json(serde_json::json!({
                    "proof": hex_encode(&proof.encode()),
                    "root": hex_encode(&root),
                    "version": version,
                })),
                Err(e) => store_err(e),
            });
        }

        if let Some(put) = env.merkle_put {
            let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(put.ops.len());
            for op in &put.ops {
                let key = match decode_key(&op.key) {
                    Ok(k) => k,
                    Err(resp) => return Some(resp),
                };
                let value = match &op.value {
                    Some(v) => match hex_decode(v) {
                        Some(v) => Some(v),
                        None => return Some(err_json("value must be hex")),
                    },
                    None => None,
                };
                ops.push((key, value));
            }
            return Some(match store.put_batch(&ops) {
                Ok((root, version)) => ok_json(serde_json::json!({
                    "root": hex_encode(&root),
                    "version": version,
                })),
                Err(e) => store_err(e),
            });
        }

        if let Some(prune) = env.merkle_prune {
            let result = match (prune.before_version, prune.retain_recent) {
                (Some(before), None) => store.prune(before),
                (None, Some(window)) => store.retain_recent(window),
                _ => return Some(err_json(
                    "exactly one of before_version / retain_recent required",
                )),
            };
            return Some(match result {
                Ok(stats) => ok_json(serde_json::json!({
                    "stale_entries": stats.stale_entries,
                    "records_deleted": stats.records_deleted,
                    "root_records_deleted": stats.root_records_deleted,
                })),
                Err(e) => store_err(e),
            });
        }

        None
    }

    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        vec![ConfigLeaf {
            name: "merkle.store_name".to_string(),
            data: Some(self.store_name.as_bytes().to_vec()),
        }]
    }

    fn custom_oids(&self) -> Vec<ModuleOid> {
        let store = self.store.lock().expect("merkle store lock poisoned");
        let (root, version) = store.root();
        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(&root);
        value.extend_from_slice(&version.to_be_bytes());
        vec![ModuleOid { oid: MERKLE_STATE_ROOT_OID, value }]
    }
}
