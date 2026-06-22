// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-backed KEK lifecycle for WASM apps (Part 2 of the key-rotation work).
//!
//! In the settled model the **app-enclave owns its vault key end-to-end**. The
//! management-service is only the **directory** (`GET /api/v1/vaults`); it never
//! reserves the key, names the handle, or learns which vaults hold the shares.
//!
//! - [`create`] — first load. Call the directory (authenticated by a
//!   challenge-bound SGX quote, NOT a host credential), randomly pick K vaults,
//!   **self-author the key policy** (owner = app owner OIDC; `Tee` = this
//!   enclave's own runtime MRENCLAVE + the per-app OIDs 3.2/3.6), `CreateKey`
//!   (two-phase reserve) + `ProvideMaterial` a Shamir share to each, and return
//!   the resulting [`VaultConfig`] (the *selection*) for the caller to seal in
//!   `AppMeta` (MRENCLAVE-sealed). The KEK is returned in TEE memory only.
//! - [`resolve`] — every later load on the same runtime. Reconstruct the KEK
//!   from the sealed selection: dial each vault, `ExportKey`, Shamir-combine the
//!   largest same-generation quorum. Fails CLOSED on a policy denial (the
//!   upgrade gate) so a stale measurement never splits the key's generations.
//!
//! The client certificate presented to each vault is minted by the OS-owned
//! [`enclave_os_egress::EnclaveClientCertSigner`]; the directory quote by the
//! OS-owned [`enclave_os_egress::EnclaveAttestationProvider`]. This module only
//! names the (OS-derived) identity; it never sees CA or quote material directly.

use std::format;
use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use enclave_os_egress::{
    enclave_attestation_quote, enclave_self_mrenclave, https_fetch, mozilla_root_store,
    root_store_from_der, ClientCertIdentity, RaTlsPolicy, ReportDataBinding, RootCertStore,
    TeeType,
};

use enclave_os_common::hex::{hex_decode, hex_encode};

/// Length of the per-generation tag prefixed to each share payload. A one-shot
/// `ProvideMaterial` retry must never split generations, so each share carries a
/// random 16-byte generation id; reconstruction groups by it.
const GENERATION_SIZE: usize = 16;

/// KEK length in bytes (256-bit).
pub const KEK_SIZE: usize = 32;

/// Cap on how many vaults a single key's shares are spread across. The active
/// constellation is small (N=4 today); this only bites if the directory ever
/// returns a very large enabled set. The directory already shuffles, so taking a
/// prefix is the random pick.
const MAX_SHARE_VAULTS: usize = 8;

/// Dotted OIDs the per-app key policy requires on the vault client cert. These
/// mirror `common/src/oids.rs` (`APP_CODE_HASH_OID` / `APP_ID_OID`); the values
/// are structurally immutable, so the dotted strings are pinned here to keep the
/// vault wire format dependency-free.
const OID_APP_CODE_HASH: &str = "1.3.6.1.4.1.65230.3.2";
const OID_APP_ID: &str = "1.3.6.1.4.1.65230.3.6";

/// Storage-DEK TTL the policy requests (90 days), matching the container path.
/// The running enclave re-provisions well inside this on its refresh cadence.
const STORAGE_KEK_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

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
}

impl VaultConfig {
    fn threshold(&self) -> usize {
        if self.threshold == 0 {
            2
        } else {
            self.threshold
        }
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
}

#[derive(Deserialize)]
struct DirVault {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    /// Hex nonce the enclave binds into its quote's ReportData.
    nonce: String,
}

/// Fetch the active constellation + a shuffled vault list, authenticating to the
/// management-service by a fresh challenge-bound SGX quote. Two round-trips: GET
/// a nonce, then GET the directory presenting the quote in a header (the quote
/// rides in the request, not the TLS layer, so it survives the LB).
fn fetch_directory(mgmt_url: &str, environment: &str) -> Result<(DirConstellation, Vec<DirVault>), String> {
    let base = mgmt_url.trim_end_matches('/');
    // mgmt-service has a normal (publicly-trusted) TLS cert — verify it against
    // the Mozilla roots; no RA-TLS policy (it is not an attested peer).
    let roots = mozilla_root_store();

    // 1. Challenge.
    let ch_url = format!("{base}/api/v1/enclave/vault-challenge");
    let ch_resp = https_fetch("GET", &ch_url, &[], None, roots, None)?;
    if ch_resp.status < 200 || ch_resp.status >= 300 {
        return Err(format!("vault-challenge HTTP {}", ch_resp.status));
    }
    let ch: ChallengeResponse =
        serde_json::from_slice(&ch_resp.body).map_err(|e| format!("decode challenge: {e}"))?;
    let nonce = hex_decode(&ch.nonce).ok_or("vault-challenge nonce is not hex")?;

    // 2. Quote bound to the nonce (produced by the OS attestation provider).
    let quote = enclave_attestation_quote(&nonce)
        .ok_or("no attestation provider registered (cannot authenticate to directory)")?;
    let quote_b64 = b64url_nopad_encode(&quote);

    // 3. Directory, presenting the quote.
    let dir_url = format!("{base}/api/v1/vaults?environment={environment}");
    let headers = std::vec![
        (String::from("X-Attestation-Nonce"), ch.nonce.clone()),
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
//  Vault key policy (serde-compatible port of the Go SDK / Rust vault types)
// ===========================================================================
//
//  Serialised exactly as the vault expects: struct fields are snake_case;
//  enum variants are externally-tagged PascalCase (e.g. `{"Tee": {...}}`,
//  `"ExportKey"`, `{"Mrenclave": "..."}`). Only the create path is needed, so
//  these are Serialize-only.

#[derive(Clone, Serialize)]
enum KeyType {
    RawShare,
}

#[derive(Clone, Serialize)]
enum Operation {
    ExportKey,
    ProvideMaterial,
    PromoteProfile,
    UpdatePolicy,
    DeleteKey,
}

#[derive(Clone, Serialize)]
enum PolicyField {
    Owner,
    Tees,
    PendingProfiles,
    Lifecycle,
}

/// Externally-tagged: `"Owner"` / `"AnyTee"` / `{"Tee": <u32>}`.
#[derive(Clone, Serialize)]
enum PrincipalRef {
    Owner,
    AnyTee,
}

#[derive(Clone, Serialize)]
struct OidcPrincipal {
    issuer: String,
    sub: String,
}

/// `{"Mrenclave": "<hex>"}` (vs `{"Mrtd": ...}` for TDX).
#[derive(Clone, Serialize)]
enum Measurement {
    Mrenclave(String),
}

#[derive(Clone, Serialize)]
struct AttestationServer {
    url: String,
}

#[derive(Clone, Serialize)]
struct OidRequirement {
    oid: String,
    value: String,
}

#[derive(Clone, Serialize)]
struct AttestationProfile {
    name: String,
    measurements: Vec<Measurement>,
    attestation_servers: Vec<AttestationServer>,
    required_oids: Vec<OidRequirement>,
}

/// `{"Oidc": {...}}` / `{"Tee": {...}}`.
#[derive(Clone, Serialize)]
enum Principal {
    Oidc(OidcPrincipal),
    Tee(AttestationProfile),
}

#[derive(Clone, Serialize)]
struct PrincipalSet {
    owner: Principal,
    tees: Vec<Principal>,
}

#[derive(Clone, Serialize)]
struct OperationRule {
    ops: Vec<Operation>,
    principals: Vec<PrincipalRef>,
}

#[derive(Clone, Serialize)]
struct Mutability {
    owner_can: Vec<PolicyField>,
    immutable: Vec<PolicyField>,
}

#[derive(Clone, Serialize)]
struct Lifecycle {
    ttl_seconds: u64,
}

#[derive(Clone, Serialize)]
struct KeyPolicy {
    version: u32,
    principals: PrincipalSet,
    operations: Vec<OperationRule>,
    mutability: Mutability,
    lifecycle: Lifecycle,
}

/// Mirror of the container `VaultProvisioner.EnsureReserved` policy, but with an
/// SGX MRENCLAVE measurement (not TDX MRTD): the running runtime + the per-app
/// OIDs 3.2/3.6 gate the data path; the app owner gates the control path.
fn build_app_key_policy(
    cfg: &VaultConfig,
    owner_sub: &str,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<KeyPolicy, String> {
    let self_mr = enclave_self_mrenclave()
        .ok_or("no attestation provider registered (self MRENCLAVE unavailable)")?;

    let mut required_oids = std::vec![OidRequirement {
        oid: OID_APP_CODE_HASH.into(),
        value: hex_encode(code_hash),
    }];
    if let Some(a) = app_id {
        required_oids.push(OidRequirement {
            oid: OID_APP_ID.into(),
            value: hex_encode(a),
        });
    }

    let profile = AttestationProfile {
        name: String::from("wasm app / SGX"),
        measurements: std::vec![Measurement::Mrenclave(hex_encode(&self_mr))],
        attestation_servers: cfg
            .attestation_servers
            .iter()
            .map(|u| AttestationServer { url: u.clone() })
            .collect(),
        required_oids,
    };

    Ok(KeyPolicy {
        version: 1,
        principals: PrincipalSet {
            // The app owner holds the key (privasys.id sub). The platform SA is
            // deliberately absent from every slot.
            owner: Principal::Oidc(OidcPrincipal {
                issuer: cfg.oidc_issuer.clone(),
                sub: owner_sub.into(),
            }),
            tees: std::vec![Principal::Tee(profile)],
        },
        operations: std::vec![
            // Data path: the running app TEE fills + reconstructs its own DEK.
            OperationRule {
                ops: std::vec![Operation::ProvideMaterial, Operation::ExportKey],
                principals: std::vec![PrincipalRef::AnyTee],
            },
            // Control path: only the owner promotes a new measurement (upgrade)
            // or mutates/deletes the key.
            OperationRule {
                ops: std::vec![
                    Operation::PromoteProfile,
                    Operation::UpdatePolicy,
                    Operation::DeleteKey
                ],
                principals: std::vec![PrincipalRef::Owner],
            },
        ],
        mutability: Mutability {
            owner_can: std::vec![
                PolicyField::Tees,
                PolicyField::PendingProfiles,
                PolicyField::Lifecycle
            ],
            immutable: std::vec![PolicyField::Owner],
        },
        lifecycle: Lifecycle {
            ttl_seconds: STORAGE_KEK_TTL_SECONDS,
        },
    })
}

// ===========================================================================
//  Vault wire types (subset of the HSM protocol — POST /data, JSON)
// ===========================================================================

/// Externally-tagged to match the server's `VaultRequest` enum.
#[derive(Serialize)]
enum VaultRequest {
    CreateKey {
        handle: String,
        key_type: KeyType,
        /// `None` = two-phase reserve (handle + policy, material later).
        #[serde(skip_serializing_if = "Option::is_none")]
        material_b64: Option<String>,
        exportable: bool,
        policy: KeyPolicy,
    },
    ExportKey {
        handle: String,
    },
    ProvideMaterial {
        handle: String,
        material_b64: String,
    },
}

/// Subset of the server's `VaultResponse` we care about.
#[derive(Deserialize, Default)]
struct VaultResponse {
    #[serde(rename = "KeyMaterial")]
    key_material: Option<KeyMaterialResp>,
    #[serde(rename = "MaterialProvided")]
    material_provided: Option<MaterialProvidedResp>,
    #[serde(rename = "KeyCreated")]
    key_created: Option<KeyCreatedResp>,
    #[serde(rename = "Error")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct KeyMaterialResp {
    material: Vec<u8>,
}

#[derive(Deserialize)]
struct MaterialProvidedResp {
    #[allow(dead_code)]
    handle: String,
}

#[derive(Deserialize)]
struct KeyCreatedResp {
    #[allow(dead_code)]
    #[serde(default)]
    expires_at: u64,
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
    })
}

/// Classifies a [`resolve`] error as "no key exists yet" (safe to [`create`]) vs
/// any other failure (a denial, a transport error — must NOT fall through to a
/// create, which could split generations or mask a real problem).
pub fn is_unprovisioned(err: &str) -> bool {
    let s = err.to_lowercase();
    s.contains("no share group meets threshold") && !s.contains("not authorised")
}

/// First-ever creation: self-author the policy, two-phase `CreateKey` (reserve)
/// + `ProvideMaterial` a Shamir share to each selected vault, returning the KEK.

/// Later loads: reconstruct the KEK from the sealed selection. Fails CLOSED on a
/// policy denial (the upgrade gate) — the owner must promote this measurement
/// first; a fill here would split generations and corrupt the key.
pub fn resolve(
    cfg: &VaultConfig,
    handle: &str,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<[u8; KEK_SIZE], String> {
    if cfg.endpoints.is_empty() {
        return Err("vaultkey: sealed config has no vault endpoints".into());
    }
    let threshold = cfg.threshold();
    let root_store = root_store_from_der(cfg.ca_roots_der.iter().cloned())
        .map_err(|e| format!("vaultkey: bad CA roots: {e}"))?;
    let policy = build_ratls_policy(cfg, code_hash, app_id)?;

    let mut by_gen: Vec<(String, Vec<Share>)> = Vec::new();
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
                if s.contains("policy.principals") {
                    denied += 1;
                } else {
                    last_err = Some(e);
                }
            }
        }
    }

    if let Some(best) = best_group(&by_gen, threshold) {
        let kek = shamir_reconstruct(best)?;
        return to_kek(kek);
    }

    if denied > 0 {
        return Err(format!(
            "vaultkey: key {handle:?} exists but this measurement is not authorised to \
             reconstruct it ({denied}/{} vaults denied on policy) — the owner must promote \
             this version first",
            cfg.endpoints.len()
        ));
    }
    Err(format!(
        "vaultkey: cannot reconstruct {handle:?} (no share group meets threshold {threshold}); \
         last error: {last_err:?}"
    ))
}

/// Reserve (two-phase `CreateKey`) the self-authored policy on each selected
/// vault, then generate a KEK, Shamir-split it, and `ProvideMaterial` one share
/// per vault. Returns the KEK once ≥k vaults hold a share. Call only after a
/// [`resolve`] reports the key [`is_unprovisioned`].
pub fn create(
    cfg: &VaultConfig,
    handle: &str,
    owner_sub: &str,
    code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<[u8; KEK_SIZE], String> {
    if owner_sub.is_empty() {
        return Err("vaultkey: no app-owner sub; refusing to author an owner-less key".into());
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
    let key_policy = build_app_key_policy(cfg, owner_sub, code_hash, app_id)?;

    // ---- Phase A: reserve handle + policy on each vault -------------------
    let mut reserved = 0usize;
    let mut last_err: Option<String> = None;
    for ep in &cfg.endpoints {
        match call_vault(
            ep,
            &VaultRequest::CreateKey {
                handle: handle.into(),
                key_type: KeyType::RawShare,
                material_b64: None,
                exportable: true,
                policy: key_policy.clone(),
            },
            &root_store,
            &policy,
        ) {
            Ok(_) => reserved += 1,
            Err(e) if e.to_lowercase().contains("already exists") => reserved += 1,
            Err(e) => last_err = Some(e),
        }
    }
    if reserved < threshold {
        return Err(format!(
            "vaultkey: reserved {handle:?} on only {reserved}/{} vaults (need {threshold}); \
             last error: {last_err:?}",
            cfg.endpoints.len()
        ));
    }

    // ---- Phase B: generate + fill ----------------------------------------
    let rng = SystemRandom::new();
    let mut kek = [0u8; KEK_SIZE];
    rng.fill(&mut kek).map_err(|_| "vaultkey: rng (kek)")?;
    let mut generation = [0u8; GENERATION_SIZE];
    rng.fill(&mut generation)
        .map_err(|_| "vaultkey: rng (generation)")?;

    let shares = shamir_split(&kek, threshold, cfg.endpoints.len())?;
    let mut acks = 0usize;
    for (i, ep) in cfg.endpoints.iter().enumerate() {
        let payload = encode_share(&generation, &shares[i]);
        // One retry: transient dial failures are common right after a vault
        // restart. The payload is identical, so a retry never splits generations.
        for _ in 0..2 {
            match call_vault(
                ep,
                &VaultRequest::ProvideMaterial {
                    handle: handle.into(),
                    material_b64: b64url_nopad_encode(&payload),
                },
                &root_store,
                &policy,
            ) {
                Ok(_) => {
                    acks += 1;
                    break;
                }
                Err(e) if e.to_lowercase().contains("already provided") => break,
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
    Ok(kek)
}

fn to_kek(v: Vec<u8>) -> Result<[u8; KEK_SIZE], String> {
    if v.len() != KEK_SIZE {
        return Err(format!(
            "vaultkey: reconstructed KEK has {} bytes, want {}",
            v.len(),
            KEK_SIZE
        ));
    }
    let mut out = [0u8; KEK_SIZE];
    out.copy_from_slice(&v);
    Ok(out)
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
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "vaultkey: rng (nonce)")?;
    Ok(RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(cfg.mrenclave),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse {
            nonce: nonce.to_vec(),
        },
        expected_oids: Vec::new(),
        attestation_servers: cfg.attestation_servers.clone(),
        // Mutual RA-TLS: present this app's identity (OS signer mints the cert).
        client_identity: Some(ClientCertIdentity {
            code_hash: code_hash.to_vec(),
            app_id: app_id.map(|a| a.to_vec()),
        }),
    })
}

// ===========================================================================
//  Vault RPC (POST /data over mutually-attested RA-TLS)
// ===========================================================================

/// Send one `VaultRequest` and return the exported key material (`ExportKey`) or
/// an empty vec (acked `CreateKey` / `ProvideMaterial`). A vault `Error` is
/// returned as `Err` so the caller can classify it.
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
    if vr.material_provided.is_some() || vr.key_created.is_some() {
        return Ok(Vec::new());
    }
    Err("vault: unexpected response (no KeyMaterial/MaterialProvided/KeyCreated/Error)".into())
}

// ===========================================================================
//  Share payload framing: generation(16) || X(1) || data
// ===========================================================================

fn encode_share(generation: &[u8; GENERATION_SIZE], s: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENERATION_SIZE + 1 + s.data.len());
    out.extend_from_slice(generation);
    out.push(s.x);
    out.extend_from_slice(&s.data);
    out
}

fn decode_share(payload: &[u8]) -> Result<(String, Share), String> {
    if payload.len() < GENERATION_SIZE + 2 {
        return Err(format!("share payload too short ({} bytes)", payload.len()));
    }
    let gen = hex_encode(&payload[..GENERATION_SIZE]);
    let x = payload[GENERATION_SIZE];
    if x == 0 {
        return Err("share X must be non-zero".into());
    }
    let data = payload[GENERATION_SIZE + 1..].to_vec();
    Ok((gen, Share { x, data }))
}

fn push_share(by_gen: &mut Vec<(String, Vec<Share>)>, gen: String, share: Share) {
    for (g, shares) in by_gen.iter_mut() {
        if *g == gen {
            shares.push(share);
            return;
        }
    }
    by_gen.push((gen, std::vec![share]));
}

/// Largest same-generation group meeting the threshold.
fn best_group(by_gen: &[(String, Vec<Share>)], threshold: usize) -> Option<&[Share]> {
    let mut best: Option<&[Share]> = None;
    for (_, shares) in by_gen {
        if shares.len() >= threshold && shares.len() > best.map_or(0, |b| b.len()) {
            best = Some(shares);
        }
    }
    best
}

// ===========================================================================
//  Shamir Secret Sharing over GF(2^8) — ported from the Go client so split
//  and reconstruct are self-consistent (the vault stores opaque shares).
// ===========================================================================

struct Share {
    x: u8,
    data: Vec<u8>,
}

/// `(gfExp, gfLog)` tables for GF(2^8) with generator g=3, modulus 0x11b.
fn gf_tables() -> &'static ([u8; 256], [u8; 256]) {
    static TABLES: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        let mut val: u16 = 1;
        for i in 0..255usize {
            exp[i] = val as u8;
            log[val as usize] = i as u8;
            let mut doubled = val << 1;
            if doubled & 0x100 != 0 {
                doubled ^= 0x11b;
            }
            val = doubled ^ val; // val *= 3
        }
        exp[255] = exp[0]; // g^255 = g^0 = 1
        (exp, log)
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = gf_tables();
    let log_sum = log[a as usize] as u16 + log[b as usize] as u16;
    exp[(log_sum % 255) as usize]
}

fn gf_inv(a: u8) -> u8 {
    let (exp, log) = gf_tables();
    exp[(255 - log[a as usize] as u16) as usize]
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn eval_poly(constant: u8, coeffs: &[u8], x: u8) -> u8 {
    let mut val = 0u8;
    for &c in coeffs.iter().rev() {
        val = gf_add(gf_mul(val, x), c);
    }
    gf_add(gf_mul(val, x), constant)
}

fn lagrange_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let n = xs.len();
    let mut result = 0u8;
    for i in 0..n {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            num = gf_mul(num, xs[j]); // 0 - xs[j] = xs[j] in GF(2^8)
            den = gf_mul(den, gf_add(xs[i], xs[j]));
        }
        let basis = gf_mul(num, gf_inv(den));
        result = gf_add(result, gf_mul(ys[i], basis));
    }
    result
}

fn shamir_split(secret: &[u8], threshold: usize, num_shares: usize) -> Result<Vec<Share>, String> {
    if threshold < 2 {
        return Err("threshold must be >= 2".into());
    }
    if num_shares < threshold {
        return Err("numShares must be >= threshold".into());
    }
    if num_shares > 255 {
        return Err("max 255 shares (GF(256))".into());
    }
    if secret.is_empty() {
        return Err("secret must not be empty".into());
    }
    let mut shares: Vec<Share> = (0..num_shares)
        .map(|i| Share {
            x: (i + 1) as u8,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();
    let rng = SystemRandom::new();
    let mut coeffs = std::vec![0u8; threshold - 1];
    for &b in secret {
        rng.fill(&mut coeffs).map_err(|_| "rng (shamir coeffs)")?;
        for share in shares.iter_mut() {
            let v = eval_poly(b, &coeffs, share.x);
            share.data.push(v);
        }
    }
    Ok(shares)
}

fn shamir_reconstruct(shares: &[Share]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("no shares provided".into());
    }
    let data_len = shares[0].data.len();
    for s in &shares[1..] {
        if s.data.len() != data_len {
            return Err("all shares must have the same data length".into());
        }
    }
    let mut seen = [false; 256];
    for s in shares {
        if seen[s.x as usize] {
            return Err(format!("duplicate share X={}", s.x));
        }
        seen[s.x as usize] = true;
    }
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    let mut secret = std::vec![0u8; data_len];
    let mut ys = std::vec![0u8; shares.len()];
    for (j, out) in secret.iter_mut().enumerate() {
        for (i, s) in shares.iter().enumerate() {
            ys[i] = s.data[j];
        }
        *out = lagrange_at_zero(&xs, &ys);
    }
    Ok(secret)
}

// ===========================================================================
//  base64url (no padding) — for ProvideMaterial.material_b64 + the directory
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
