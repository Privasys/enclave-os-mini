// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-backed KEK lifecycle for WASM apps (Part 2 of the key-rotation work).
//!
//! The management-service is the **directory** (`GET /api/v1/vaults`) and the
//! authority that authors the owner-bound policy: at deploy it asks the IdP to
//! sign the policy into a **key-creation grant** (scoped to the app, bound to
//! this enclave's attested app-id) and delivers it in `wasm_load`. The enclave
//! holds the material; it never sees the directory's secrets and the directory
//! never learns which vaults hold the shares.
//!
//! - [`discover`] picks K vaults from the active constellation.
//! - [`resolve_or_provision`] — on first boot, generate the KEK, Shamir-split
//!   it, and `CreateKey` one share per vault presenting the grant; on later
//!   loads, dial each vault, `ExportKey`, and Shamir-combine the largest
//!   same-generation quorum. Fails CLOSED on a policy denial (the upgrade gate)
//!   so a stale measurement never splits the key's generations.
//!
//! The client certificate presented to each vault is minted by the OS-owned
//! [`enclave_os_egress::EnclaveClientCertSigner`]; the directory quote by the
//! OS-owned [`enclave_os_egress::EnclaveAttestationProvider`]. This module only
//! names the (OS-derived) identity; it never sees CA or quote material directly.

use std::format;
use std::string::String;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

use enclave_os_egress::{
    enclave_attestation_quote, https_fetch, mozilla_root_store, root_store_from_der,
    ClientCertIdentity, RaTlsPolicy, ReportDataBinding, RootCertStore, TeeType,
};

use enclave_os_common::hex::hex_decode;

use crate::kek_material::{
    best_group, decode_share, encode_share, new_generation, push_share, shamir_reconstruct,
    to_kek, KeyOrigin, Share,
};
pub use crate::kek_material::KEK_SIZE;

/// Cap on how many vaults a single key's shares are spread across. The active
/// constellation is small (N=4 today); this only bites if the directory ever
/// returns a very large enabled set. The directory already shuffles, so taking a
/// prefix is the random pick.
const MAX_SHARE_VAULTS: usize = 8;

// ===========================================================================
//  Sealed selection (persisted in AppMeta, MRENCLAVE-sealed)
// ===========================================================================

/// The enclave's *selection*: which K vaults hold this app's KEK shares, plus
/// what it takes to reconstruct from them. Sensitive (it names the vaults), so
/// it is MRENCLAVE-sealed in `AppMeta` — never on the host or the wire. The KEK
/// material itself lives only in the vaults (Shamir-split) and in TEE memory.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// The selected constellation endpoints, `"host:port"` each.
    pub endpoints: Vec<String>,
    /// Shamir k (any k of n shares reconstruct). Zero means 2.
    pub threshold: usize,
    /// Pins the vault enclave build (32-byte MRENCLAVE). On a later load, if the
    /// active constellation's mrenclave differs from this, the enclave migrates
    /// onto the new vaults (re-provision on vault upgrade).
    pub mrenclave: [u8; 32],
    /// Attestation server URLs that must each confirm a vault's quote.
    pub attestation_servers: Vec<String>,
    /// DER trust anchors the vault's RA-TLS leaf chains to (from the directory).
    pub ca_roots_der: Vec<Vec<u8>>,
    /// OIDC issuer the owner principal authenticates against (from the directory,
    /// e.g. `https://privasys.id`). Only needed to re-author on migration.
    #[serde(default)]
    pub oidc_issuer: String,
    /// Intel TCB statuses accepted (beyond the secure floor) when verifying the
    /// VAULTS' quotes on this leg — from the constellation's
    /// `acceptable_tcb_statuses`. Empty (incl. every pre-existing sealed
    /// selection) = no TCB acceptance check on the dial, matching the
    /// constellation-unset case; `Revoked` is rejected by the egress gate
    /// whenever enforcement is on.
    #[serde(default)]
    pub acceptable_tcb_statuses: Vec<String>,
}

impl VaultConfig {
    fn threshold(&self) -> usize {
        if self.threshold == 0 {
            2
        } else {
            self.threshold
        }
    }

    /// Build a config from caller-supplied constellation addressing (the
    /// cross-constellation migration path: management-service passes the
    /// TARGET constellation's coordinates inline, exactly like the container
    /// rotate request). Addressing is not trust: the vaults still have to
    /// pass RA-TLS against `mrenclave_hex` + the attestation server, and the
    /// key policy inside them stays the authorisation boundary.
    pub fn from_parts(
        endpoints: Vec<String>,
        mrenclave_hex: &str,
        attestation_server: &str,
        ca_roots_hex: &[String],
        threshold: usize,
        oidc_issuer: &str,
        acceptable_tcb_statuses: Vec<String>,
    ) -> Result<VaultConfig, String> {
        if endpoints.is_empty() {
            return Err("vaultkey: target constellation has no endpoints".into());
        }
        let mrenclave = parse_mrenclave(mrenclave_hex)?;
        if attestation_server.is_empty() {
            return Err("vaultkey: target constellation has no attestation server".into());
        }
        let ca_roots_der: Vec<Vec<u8>> = ca_roots_hex.iter().filter_map(|h| hex_decode(h)).collect();
        if ca_roots_der.is_empty() {
            return Err(
                "vaultkey: target constellation has no CA roots (cannot trust vault leaves)".into(),
            );
        }
        Ok(VaultConfig {
            endpoints,
            threshold: threshold.max(2),
            mrenclave,
            attestation_servers: std::vec![attestation_server.to_string()],
            ca_roots_der,
            oidc_issuer: oidc_issuer.to_string(),
            acceptable_tcb_statuses,
        })
    }
}

// ===========================================================================
//  Directory (GET /api/v1/vaults) — phonebook, fetched by the enclave itself
// ===========================================================================

/// What the enclave parses from the directory. Unknown fields are ignored.
#[derive(Deserialize)]
struct DirectoryResponse {
    constellation: Option<DirConstellation>,
    #[serde(default)]
    vaults: Vec<DirVault>,
}

#[derive(Deserialize)]
struct DirConstellation {
    /// Hex MRENCLAVE every vault in the constellation runs.
    mrenclave: String,
    attestation_server: String,
    #[serde(default)]
    oidc_issuer: String,
    #[serde(default)]
    threshold: Option<usize>,
    /// Hex DER trust anchors the vault leaves chain to. Added to the directory
    /// for the enclave-driven path (inc.4); empty on an older directory.
    #[serde(default)]
    ca_roots: Vec<String>,
    /// Constellation's acceptable Intel TCB statuses (empty on an older
    /// directory = no enforcement on the dial).
    #[serde(default)]
    acceptable_tcb_statuses: Vec<String>,
}

#[derive(Deserialize)]
struct DirVault {
    host: String,
    port: u16,
}

/// Fetch the active constellation + a shuffled vault list, authenticating to the
/// management-service by a fresh, timestamp-bound SGX quote. No challenge
/// round-trip: the directory is a read-only phonebook (the SDK re-verifies every
/// vault's own quote regardless), so binding a coarse timestamp — which lets the
/// server bound replay to a small window — is sufficient. The quote rides in a
/// request header, not the TLS layer, so it survives the TLS-terminating LB.
fn fetch_directory(
    mgmt_url: &str,
    environment: &str,
) -> Result<(DirConstellation, Vec<DirVault>), String> {
    let base = mgmt_url.trim_end_matches('/');
    // mgmt-service has a normal (publicly-trusted) TLS cert — verify it against
    // the Mozilla roots; no RA-TLS policy (it is not an attested peer).
    let roots = mozilla_root_store();

    // Bind the current time (big-endian u64) into the quote's ReportData; send
    // the same value in a header so the server can check freshness and confirm
    // the quote is not a replay of an older one.
    let ts = enclave_os_common::ocall::get_current_time()
        .map_err(|_| String::from("no trusted time to bind into the directory quote"))?;
    let quote = enclave_attestation_quote(&ts.to_be_bytes())
        .ok_or("no attestation provider registered (cannot authenticate to directory)")?;
    let quote_b64 = b64url_nopad_encode(&quote);

    let dir_url = format!("{base}/api/v1/vaults?environment={environment}");
    let headers = std::vec![
        (String::from("X-Attestation-Timestamp"), format!("{ts}")),
        (String::from("X-Attestation-Quote"), quote_b64),
    ];
    let resp = https_fetch("GET", &dir_url, &headers, None, roots, None)?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(format!("directory HTTP {}", resp.status));
    }
    let dir: DirectoryResponse =
        serde_json::from_slice(&resp.body).map_err(|e| format!("decode directory: {e}"))?;
    let con = dir
        .constellation
        .ok_or("directory has no active vault constellation")?;
    if dir.vaults.is_empty() {
        return Err("directory returned no vaults".into());
    }
    Ok((con, dir.vaults))
}

// ===========================================================================
//  Vault wire types (subset of the HSM protocol — POST /data, JSON)
// ===========================================================================

/// Externally-tagged to match the server's `VaultRequest` enum. The enclave
/// reconstructs (`ExportKey`) and, on first boot, creates the key in one call
/// (`CreateKey`) presenting the platform-minted grant, which carries the
/// owner-authored policy.
#[derive(Serialize)]
enum VaultRequest {
    ExportKey {
        handle: String,
    },
    CreateKey {
        handle: String,
        material_b64: String,
        grant: String,
    },
    GetPolicy {
        handle: String,
    },
}

/// Subset of the server's `VaultResponse` we care about.
#[derive(Deserialize, Default)]
struct VaultResponse {
    #[serde(rename = "KeyMaterial")]
    key_material: Option<KeyMaterialResp>,
    #[serde(rename = "KeyCreated")]
    key_created: Option<KeyCreatedResp>,
    #[serde(rename = "Policy")]
    policy: Option<PolicyResp>,
    #[serde(rename = "Error")]
    error: Option<String>,
}

/// `GetPolicy` response: the policy is walked generically (we only
/// need the Tees measurement set), so it stays a raw value.
#[derive(Deserialize)]
struct PolicyResp {
    policy: serde_json::Value,
}

#[derive(Deserialize)]
struct KeyMaterialResp {
    material: Vec<u8>,
}

#[derive(Deserialize)]
struct KeyCreatedResp {
    #[allow(dead_code)]
    handle: String,
}

// ===========================================================================
//  Public API — create (first load) and resolve (later loads)
// ===========================================================================

/// Discover the active constellation from the directory and build a candidate
/// [`VaultConfig`] (random pick of K vaults). No key operations — the caller
/// then [`resolve`]s an existing key against it or, if none exists yet,
/// [`create`]s one. Used on first load (no sealed selection) and on upgrade
/// (the sealed selection is unreadable under the new MRENCLAVE).
pub fn discover(mgmt_url: &str, environment: &str) -> Result<VaultConfig, String> {
    let (con, vaults) = fetch_directory(mgmt_url, environment)?;
    let mrenclave = parse_mrenclave(&con.mrenclave)?;
    let threshold = con.threshold.unwrap_or(2).max(2);

    let mut endpoints: Vec<String> = vaults
        .iter()
        .map(|v| format!("{}:{}", v.host, v.port))
        .collect();
    endpoints.truncate(MAX_SHARE_VAULTS);
    if endpoints.len() < threshold {
        return Err(format!(
            "vaultkey: only {} vaults available, need threshold {}",
            endpoints.len(),
            threshold
        ));
    }

    let ca_roots_der: Vec<Vec<u8>> = con.ca_roots.iter().filter_map(|h| hex_decode(h)).collect();
    if ca_roots_der.is_empty() {
        return Err("vaultkey: directory returned no CA roots (cannot trust vault leaves)".into());
    }

    Ok(VaultConfig {
        endpoints,
        threshold,
        mrenclave,
        attestation_servers: std::vec![con.attestation_server.clone()],
        ca_roots_der,
        oidc_issuer: con.oidc_issuer.clone(),
        acceptable_tcb_statuses: con.acceptable_tcb_statuses.clone(),
    })
}

/// Resolve the KEK from the constellation, CREATING it on first boot with the
/// platform-minted `grant` (which carries the owner-authored policy). Mirrors the
/// container `vaultkey.ResolveOrProvision`:
///   - a quorum of same-generation shares → reconstruct + return;
///   - any policy denial → fail CLOSED (the upgrade gate; never create, which
///     would split generations and corrupt the key);
///   - uniformly absent → generate a KEK, Shamir-split, `CreateKey` one share per
///     vault with the grant, return once ≥k acked;
///   - a partial/unreachable set → error (never create, could split generations).
///
/// `material`, when given, is the KEK a create splits instead of generating
/// one: a renewal re-creates the current KEK under the next handle, because a
/// vault key's lifetime is fixed at creation. It is ignored when the handle
/// already exists; the caller compares what comes back. The returned
/// [`KeyOrigin`] says which of the two happened.
pub fn resolve_or_provision(
    cfg: &VaultConfig,
    handle: &str,
    grant: &str,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
    material: Option<&[u8; KEK_SIZE]>,
) -> Result<([u8; KEK_SIZE], KeyOrigin), String> {
    if cfg.endpoints.is_empty() {
        return Err("vaultkey: sealed config has no vault endpoints".into());
    }
    let threshold = cfg.threshold();
    if threshold > cfg.endpoints.len() {
        return Err(format!(
            "vaultkey: threshold {} exceeds {} endpoints",
            threshold,
            cfg.endpoints.len()
        ));
    }
    let root_store = root_store_from_der(cfg.ca_roots_der.iter().cloned())
        .map_err(|e| format!("vaultkey: bad CA roots: {e}"))?;
    let policy = build_ratls_policy(cfg, code_hash, app_id)?;

    // ---- Phase 1: try to collect existing shares ------------------------
    let mut by_gen: Vec<(String, Vec<Share>)> = Vec::new();
    let mut not_found = 0usize;
    let mut denied = 0usize;
    let mut last_err: Option<String> = None;

    for ep in &cfg.endpoints {
        match call_vault(
            ep,
            &VaultRequest::ExportKey {
                handle: handle.into(),
            },
            &root_store,
            &policy,
        ) {
            Ok(material) => match decode_share(&material) {
                Ok((gen, share)) => push_share(&mut by_gen, gen, share),
                Err(e) => last_err = Some(format!("undecodable share from {ep}: {e}")),
            },
            Err(e) => {
                let s = e.to_lowercase();
                if s.contains("key not found") {
                    not_found += 1;
                } else if s.contains("policy.principals") {
                    denied += 1;
                } else {
                    last_err = Some(e);
                }
            }
        }
    }

    if let Some(best) = best_group(&by_gen, threshold) {
        return Ok((to_kek(shamir_reconstruct(best)?)?, KeyOrigin::Reconstructed));
    }

    // Fail CLOSED on the gate: the key exists but this measurement isn't
    // authorised. Never fall through to a create (would split generations).
    if denied > 0 {
        return Err(format!(
            "vaultkey: key {handle:?} exists but this measurement is not authorised to \
             reconstruct it ({denied}/{} vaults denied on policy) — the owner must promote \
             this version first",
            cfg.endpoints.len()
        ));
    }

    // First boot requires a clean slate: every vault must agree the handle is
    // absent. A partial set (shares below quorum, or an unreachable vault) is not
    // a first boot — creating a fresh generation could split the key.
    if not_found != cfg.endpoints.len() {
        return Err(format!(
            "vaultkey: cannot reconstruct {handle:?} (no share group meets threshold \
             {threshold}) and not every vault reports the handle absent; last error: {last_err:?}"
        ));
    }
    if grant.is_empty() {
        return Err(format!(
            "vaultkey: handle {handle:?} does not exist and no key-creation grant was supplied \
             (the platform must mint one at deploy)"
        ));
    }

    // ---- Phase 2: first boot — split the KEK + create the key -----------
    // A fresh KEK, or on a renewal the given material, under a fresh
    // generation tag either way.
    let fresh = new_generation(material, threshold, cfg.endpoints.len())?;
    let (kek, generation, shares) = (fresh.kek, fresh.generation, fresh.shares);
    let mut acks = 0usize;
    for (i, ep) in cfg.endpoints.iter().enumerate() {
        let payload = encode_share(&generation, &shares[i]);
        // One retry: transient dial failures are common right after a vault
        // restart. The payload is identical, so a retry never splits generations.
        for _ in 0..2 {
            match call_vault(
                ep,
                &VaultRequest::CreateKey {
                    handle: handle.into(),
                    material_b64: b64url_nopad_encode(&payload),
                    grant: grant.into(),
                },
                &root_store,
                &policy,
            ) {
                Ok(_) => {
                    acks += 1;
                    break;
                }
                Err(e) if e.to_lowercase().contains("already exists") => break,
                Err(_) => {}
            }
        }
    }
    if acks < threshold {
        return Err(format!(
            "vaultkey: only {acks} of {} vaults accepted a share (threshold {threshold}) — \
             refusing to use an unrecoverable KEK",
            cfg.endpoints.len()
        ));
    }
    Ok((kek, KeyOrigin::Created))
}

/// Read the Tees measurement set of a key's policy from the
/// constellation. The vault authorises `GetPolicy` by principal
/// resolution, so the running TEE can read its OWN credential's
/// policy — this is how a cluster node learns the admissible peer
/// measurement set from the policy instead of from configuration.
/// Returns the UNION over reachable vaults (mid-update the vaults may
/// briefly differ; the union opens an upgrade window as soon as any
/// vault carries the new measurement) and requires at least one vault
/// to answer.
pub fn read_policy_measurements(
    cfg: &VaultConfig,
    handle: &str,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<Vec<enclave_os_common::quote::TeeMeasurement>, String> {
    let root_store = root_store_from_der(cfg.ca_roots_der.iter().cloned())
        .map_err(|e| format!("vaultkey: bad CA roots: {e}"))?;
    let policy = build_ratls_policy(cfg, code_hash, app_id)?;
    let mut set: Vec<enclave_os_common::quote::TeeMeasurement> = Vec::new();
    let mut answered = 0usize;
    let mut last_err: Option<String> = None;
    for ep in &cfg.endpoints {
        let body = match serde_json::to_vec(&VaultRequest::GetPolicy { handle: handle.into() }) {
            Ok(b) => b,
            Err(e) => return Err(format!("marshal GetPolicy: {e}")),
        };
        let url = format!("https://{ep}/data");
        let resp = match https_fetch("POST", &url, &[], Some(&body), &root_store, Some(&policy)) {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let vr: VaultResponse = match serde_json::from_slice(&resp.body) {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(format!("decode GetPolicy response: {e}"));
                continue;
            }
        };
        if let Some(msg) = vr.error {
            last_err = Some(msg);
            continue;
        }
        let Some(p) = vr.policy else {
            last_err = Some("vault: GetPolicy returned no policy".into());
            continue;
        };
        answered += 1;
        collect_measurements(&p.policy, &mut set);
    }
    if answered == 0 {
        return Err(format!(
            "vaultkey: no vault answered GetPolicy for {handle:?}: {last_err:?}"
        ));
    }
    Ok(set)
}

/// Collect `principals.tees[].Tee.measurements[]` into `set`, TEE-typed
/// and deduplicated: `{"Mrenclave": <hex32>}` (SGX) and
/// `{"Tdx": {"mrtd", "rtmr1", "rtmr2"}}` (48-byte hex each) are both
/// recognised. Unknown shapes are skipped — the pin set only ever
/// narrows admission on top of the vault's own enforcement.
fn collect_measurements(
    policy: &serde_json::Value,
    set: &mut Vec<enclave_os_common::quote::TeeMeasurement>,
) {
    use enclave_os_common::quote::TeeMeasurement;
    let Some(tees) = policy
        .get("principals")
        .and_then(|p| p.get("tees"))
        .and_then(|t| t.as_array())
    else {
        return;
    };
    let hex48 = |v: Option<&serde_json::Value>| -> Option<[u8; 48]> {
        v.and_then(|v| v.as_str())
            .and_then(hex_decode)
            .and_then(|b| <[u8; 48]>::try_from(b).ok())
    };
    for tee in tees {
        let Some(measurements) = tee
            .get("Tee")
            .and_then(|t| t.get("measurements"))
            .and_then(|m| m.as_array())
        else {
            continue;
        };
        for m in measurements {
            let parsed = if let Some(mr) = m
                .get("Mrenclave")
                .and_then(|v| v.as_str())
                .and_then(hex_decode)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(TeeMeasurement::Sgx(mr))
            } else if let Some(tdx) = m.get("Tdx") {
                match (
                    hex48(tdx.get("mrtd")),
                    hex48(tdx.get("rtmr1")),
                    hex48(tdx.get("rtmr2")),
                ) {
                    (Some(mrtd), Some(rtmr1), Some(rtmr2)) => {
                        Some(TeeMeasurement::Tdx { mrtd, rtmr1, rtmr2 })
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Some(p) = parsed {
                if !set.contains(&p) {
                    set.push(p);
                }
            }
        }
    }
}

fn parse_mrenclave(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(hex).ok_or("vaultkey: constellation mrenclave is not hex")?;
    if bytes.len() != 32 {
        return Err(format!(
            "vaultkey: constellation mrenclave is {} bytes, want 32",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build the per-resolution RA-TLS policy: pin the vault MRENCLAVE, bind a fresh
/// challenge nonce, and present this app's mutually-attested client identity.
fn build_ratls_policy(
    cfg: &VaultConfig,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<RaTlsPolicy, String> {
    Ok(RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(cfg.mrenclave),
        mr_signer: None,
        mr_td: None,
        // Challenge mode: the vault's evidence is bound to this connection's
        // exporter value and a fresh context (RA-TLS v2).
        report_data: ReportDataBinding::ChallengeResponse,
        expected_oids: Vec::new(),
        attestation_servers: cfg.attestation_servers.clone(),
        // Enforce the constellation's acceptable-TCB set on the vault's quote
        // (empty set = legacy no-check, matching an unset constellation).
        acceptable_tcb_statuses: if cfg.acceptable_tcb_statuses.is_empty() {
            None
        } else {
            Some(cfg.acceptable_tcb_statuses.clone())
        },
        // Mutual RA-TLS: present this app's identity (OS signer mints the cert).
        client_identity: Some(ClientCertIdentity {
            code_hash: code_hash.to_vec(),
            app_id: app_id.map(|a| a.to_vec()),
        }),
        // The vault is platform infrastructure, not an app dependency.
        dependencies: None,
    })
}

// ===========================================================================
//  Vault RPC (POST /data over mutually-attested RA-TLS)
// ===========================================================================

/// Send one `VaultRequest` and return the exported key material (`ExportKey`) or
/// an empty vec (acked `CreateKey`). A vault `Error` is returned as `Err` so the
/// caller can classify it.
fn call_vault(
    endpoint: &str,
    req: &VaultRequest,
    root_store: &RootCertStore,
    policy: &RaTlsPolicy,
) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(req).map_err(|e| format!("marshal request: {e}"))?;
    let url = format!("https://{endpoint}/data");
    let resp = https_fetch("POST", &url, &[], Some(&body), root_store, Some(policy))?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(format!("vault HTTP {}", resp.status));
    }
    let vr: VaultResponse =
        serde_json::from_slice(&resp.body).map_err(|e| format!("decode response: {e}"))?;
    if let Some(msg) = vr.error {
        return Err(msg);
    }
    if let Some(km) = vr.key_material {
        return Ok(km.material);
    }
    if vr.key_created.is_some() {
        return Ok(Vec::new());
    }
    Err("vault: unexpected response (no KeyMaterial/KeyCreated/Error)".into())
}

// ===========================================================================
//  base64url (no padding) — for CreateKey.material_b64 + the directory
//  quote header (server decodes URL_SAFE_NO_PAD); dependency-free.
// ===========================================================================

fn b64url_nopad_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        }
    }
    out
}
