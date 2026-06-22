// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault-backed KEK resolution for WASM apps (Part 2 of the key-rotation work).
//!
//! Reconstructs (or, on first boot, provisions) a per-app **key-encryption
//! key** from the Enclave Vault constellation over mutually-attested RA-TLS.
//! This is the WASM/SGX analog of the container path's `enclave-os-virtual`
//! `internal/vaultkey`:
//!
//! 1. **Reconstruct.** Dial every vault, `ExportKey` the handle. Each vault
//!    runs `tee_matches` against the key policy and returns this vault's share
//!    only if our measurement (cwasm code hash at OID 3.2, app-id at OID 3.6,
//!    carried in the RA-TLS client cert) is authorised. The largest
//!    same-generation quorum is Shamir-reconstructed into the KEK.
//! 2. **First-boot fill** (only when the handle is uniformly *pending*).
//!    Generate a 256-bit KEK + a 16-byte generation tag, Shamir-split, and
//!    `ProvideMaterial` one share per vault. Returns only once ≥k vaults ack.
//! 3. **Fail closed on a policy denial.** If any vault *denied* the export
//!    (the key exists but this measurement is not in policy = the upgrade
//!    gate), never fall through to a fill: that would split the key's
//!    generations and corrupt it. The owner must promote this version first.
//!
//! The client certificate presented to each vault is minted by the OS-owned
//! [`enclave_os_egress::EnclaveClientCertSigner`] registered at enclave init;
//! this module only sets the (OS-derived) app identity on the policy.
//!
//! The returned 32-byte KEK never leaves TEE memory and wraps the app's KV
//! `encryption_key` (see the load path in `registry.rs`).

use std::format;
use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use enclave_os_egress::{
    https_fetch, root_store_from_der, ClientCertIdentity, RaTlsPolicy, ReportDataBinding,
    RootCertStore, TeeType,
};

/// Length of the per-generation tag prefixed to each share payload. A
/// one-shot `ProvideMaterial` retry must never split generations, so each
/// share carries a random 16-byte generation id; reconstruction groups by it.
const GENERATION_SIZE: usize = 16;

/// KEK length in bytes (256-bit).
pub const KEK_SIZE: usize = 32;

// ===========================================================================
//  Config
// ===========================================================================

/// Addresses the vault constellation for a single key resolution. None of it
/// is secret or trusted: every vault is verified by attestation at dial time.
pub struct VaultConfig {
    /// Constellation endpoints, `"host:port"` each.
    pub endpoints: Vec<String>,
    /// Shamir k (any k of n shares reconstruct). Zero means 2.
    pub threshold: usize,
    /// Pins the vault enclave build (32-byte MRENCLAVE).
    pub mrenclave: [u8; 32],
    /// Attestation server URLs that must each confirm a vault's quote.
    pub attestation_servers: Vec<String>,
    /// DER trust anchors the vault's RA-TLS leaf chains to (the Privasys CA).
    pub ca_roots_der: Vec<Vec<u8>>,
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
//  Vault wire types (subset of the HSM protocol — POST /data, JSON)
// ===========================================================================

/// Externally-tagged to match the server's `VaultRequest` enum, e.g.
/// `{"ExportKey":{"handle":"…"}}`. `approvals` is `#[serde(default)]` on the
/// server, so we omit it (the RA-TLS Tee cert authorises the data path).
#[derive(Serialize)]
enum VaultRequest {
    ExportKey { handle: String },
    ProvideMaterial { handle: String, material_b64: String },
}

/// Subset of the server's `VaultResponse` we care about. `material` is a plain
/// `Vec<u8>` (serde_json round-trips it as a byte array, server↔enclave).
#[derive(Deserialize, Default)]
struct VaultResponse {
    #[serde(rename = "KeyMaterial")]
    key_material: Option<KeyMaterialResp>,
    #[serde(rename = "MaterialProvided")]
    material_provided: Option<MaterialProvidedResp>,
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

// ===========================================================================
//  Public API
// ===========================================================================

/// Reconstruct or first-boot-provision the KEK for `handle`.
///
/// `cwasm_code_hash` is the app's code hash (`sha256(cwasm)`, the OID 3.2
/// measurement); `app_id` is the raw app-id (OID 3.6) or `None` for the
/// MR_ENCLAVE shape. The mutually-attested client certificate is minted by the
/// OS-registered [`enclave_os_egress::EnclaveClientCertSigner`] from the
/// identity placed on the policy below.
pub fn resolve_or_provision(
    cfg: &VaultConfig,
    handle: &str,
    cwasm_code_hash: &[u8],
    app_id: Option<&[u8]>,
) -> Result<[u8; KEK_SIZE], String> {
    if cfg.endpoints.is_empty() {
        return Err("vaultkey: no vault endpoints configured".into());
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

    // One challenge nonce per resolution, bound into our ClientHello so the
    // vault binds its *server* quote to this connection.
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "vaultkey: rng (nonce)")?;
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some(cfg.mrenclave),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse {
            nonce: nonce.to_vec(),
        },
        expected_oids: Vec::new(),
        attestation_servers: cfg.attestation_servers.clone(),
        // Mutual RA-TLS: present this app's identity. The OS-registered signer
        // mints the cert (SGX quote bound to the vault's challenge, OID 3.2/3.6)
        // — egress never sees the CA, and nothing here is caller-injected.
        client_identity: Some(ClientCertIdentity {
            code_hash: cwasm_code_hash.to_vec(),
            app_id: app_id.map(|a| a.to_vec()),
        }),
    };

    // ---- Phase 1: collect existing shares ---------------------------------
    let mut by_gen: Vec<(String, Vec<Share>)> = Vec::new();
    let mut pending = 0usize;
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
                if s.contains("not yet provided") {
                    pending += 1;
                } else if s.contains("key not found") {
                    not_found += 1;
                } else if s.contains("policy.principals") {
                    // The key EXISTS but this measurement is not in policy: the
                    // upgrade gate. NOT pending — the vault holds material we
                    // are simply not authorised to export.
                    denied += 1;
                } else {
                    last_err = Some(e);
                }
            }
        }
    }

    if let Some(best) = best_group(&by_gen, threshold) {
        let kek = shamir_reconstruct(best)?;
        if kek.len() != KEK_SIZE {
            return Err(format!(
                "vaultkey: reconstructed KEK has {} bytes, want {}",
                kek.len(),
                KEK_SIZE
            ));
        }
        let mut out = [0u8; KEK_SIZE];
        out.copy_from_slice(&kek);
        return Ok(out);
    }

    // The key EXISTS (a vault denied us on policy grounds) but we could not
    // assemble an authorised quorum: the upgrade gate, NOT a first boot. Fail
    // CLOSED — a Phase-2 fill here would split generations and corrupt the key.
    if denied > 0 {
        return Err(format!(
            "vaultkey: key {handle:?} exists but this measurement is not authorised to \
             reconstruct it ({denied}/{} vaults denied on policy) — the owner must promote \
             this version first",
            cfg.endpoints.len()
        ));
    }

    if pending == 0 {
        if not_found == cfg.endpoints.len() {
            return Err(format!(
                "vaultkey: handle {handle:?} is not reserved on any vault (the platform must \
                 CreateKeyPending it before deploy)"
            ));
        }
        return Err(format!(
            "vaultkey: cannot reconstruct (no share group meets threshold {threshold}) and no \
             vault reports pending material; last error: {last_err:?}"
        ));
    }

    // ---- Phase 2: first boot — generate + fill ----------------------------
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

// ===========================================================================
//  Vault RPC (POST /data over mutually-attested RA-TLS)
// ===========================================================================

/// Send one `VaultRequest` to a vault and return the exported key material
/// (for `ExportKey`) or an empty vec (for an acked `ProvideMaterial`). On a
/// vault `Error` response, the message is returned as the `Err` so the caller
/// can classify it (pending / not-found / policy-denied).
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
    if vr.material_provided.is_some() {
        return Ok(Vec::new());
    }
    Err("vault: unexpected response (no KeyMaterial/MaterialProvided/Error)".into())
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
    let gen = enclave_os_common::hex::hex_encode(&payload[..GENERATION_SIZE]);
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
//  base64url (no padding) — for ProvideMaterial.material_b64 (server decodes
//  URL_SAFE_NO_PAD); dependency-free to keep the SGX build lean.
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
