// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Threshold Ed25519 keys (FROST, RFC 9591) on the vaults of a
//! constellation.
//!
//! The client drives the rounds, as it does for Shamir secrets: it calls each
//! vault directly, with its own credentials, and relays opaque messages
//! between them. The vaults never call each other. The protocol state and
//! the arithmetic live in `enclave-os-frost`; this module adds the vault's
//! rules:
//!
//! * **Creation** (`FrostDkgRound1`..`FrostDkgCommit`): each vault verifies the
//!   key-creation grant and binds it to the caller exactly as `CreateKey`
//!   does. Its round 1 message carries an attestation quote over the message
//!   and its X25519 key; every vault checks the other vaults' quotes (the
//!   attestation servers, and THIS enclave's MRENCLAVE) before it encrypts
//!   anything for them, so the client relays ciphertexts it cannot open.
//! * **Signing** (`FrostSignRound1`, `FrostSignRound2`, `FrostAggregate`): each
//!   signing vault authorises round 1 like `Sign` (the key's policy, the
//!   caller's own bearer, TEE identity and approvals) and audits it.
//! * **Sessions** belong to the caller that opened them: later rounds and
//!   aborts from anyone else are refused.
//! * **Nonces** stay in this enclave's memory (see `enclave-os-frost`).

use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use enclave_os_common::modules::RequestContext;
use enclave_os_frost as frost;
use frost::{Round1Msg, StoredShare};

use crate::grant::KeyCreationGrant;
use crate::policy::resolve_caller;
use crate::types::{
    ApprovalToken, AuditDecision, KeyRecord, KeyType, Operation, VaultRequest, VaultResponse,
};
use crate::{
    add_to_owner_index, audit_and_save, caller_str, check_grant_for_handle, expired, kv,
    load_record, normalise_policy, now_secs, record_key, require_op, NO_TRUSTED_TIME,
};

// ---------------------------------------------------------------------------
//  In-memory state
// ---------------------------------------------------------------------------

/// Most DKG + signing sessions one caller holds at once on this vault.
const MAX_SESSIONS_PER_CALLER: usize = 16;

/// A key being generated on this vault: what its record will hold.
struct PendingKey {
    handle: String,
    index: u16,
    threshold: u16,
    grant: KeyCreationGrant,
    vaults: Vec<String>,
}

struct State {
    dkg: frost::DkgStore,
    sign: frost::SignStore,
    pending: BTreeMap<String, PendingKey>,
    /// Who opened each session ("dkg:<id>" / "sign:<id>"), and when.
    owners: BTreeMap<String, (String, u64)>,
}

impl State {
    fn new() -> Self {
        State {
            dkg: frost::DkgStore::new(),
            sign: frost::SignStore::new(),
            pending: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        self.owners
            .retain(|_, (_, created)| now < created.saturating_add(frost::DKG_SESSION_TTL_SECS));
        let owners = &self.owners;
        self.pending
            .retain(|id, _| owners.contains_key(&format!("dkg:{id}")));
    }

    /// Record the caller that opens a session. One caller holds at most
    /// [`MAX_SESSIONS_PER_CALLER`] at once, so nobody can fill the vault's
    /// tables and lock everyone else out.
    fn open(&mut self, key: String, caller: &str, now: u64) -> Result<(), String> {
        self.prune(now);
        if self.owners.contains_key(&key) {
            return Err("session id already in use".into());
        }
        if self.owners.values().filter(|(c, _)| c == caller).count() >= MAX_SESSIONS_PER_CALLER {
            return Err("too many threshold sessions in progress for this caller; finish or abort some".into());
        }
        self.owners.insert(key, (caller.to_string(), now));
        Ok(())
    }

    /// The session must have been opened by this caller.
    fn check_owner(&mut self, key: &str, caller: &str, now: u64) -> Result<(), String> {
        self.prune(now);
        match self.owners.get(key) {
            Some((c, _)) if c == caller => Ok(()),
            Some(_) => Err("this session belongs to another caller".into()),
            None => Err("unknown or expired threshold session".into()),
        }
    }

    fn drop_dkg(&mut self, session: &str) {
        self.dkg.abort(session);
        self.pending.remove(session);
        self.owners.remove(&format!("dkg:{session}"));
    }
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::new()))
}

/// Run `f` on the state. The vault serves one request at a time, so holding
/// the lock across a round's attestation checks blocks nobody.
fn with_state<T>(f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
    let mut st = state()
        .lock()
        .map_err(|_| "threshold state lock poisoned".to_string())?;
    f(&mut st)
}

/// Who the caller is, for session ownership: its OIDC subject and its TLS
/// client certificate.
fn caller_id(ctx: &RequestContext) -> String {
    let sub = ctx.oidc_claims.as_ref().map(|c| c.sub.as_str()).unwrap_or("");
    let cert = ctx
        .peer_cert_der
        .as_deref()
        .map(|d| crate::quote::hex_encode(ring::digest::digest(&ring::digest::SHA256, d).as_ref()))
        .unwrap_or_default();
    format!("{sub}|{cert}")
}

fn now() -> Result<u64, String> {
    now_secs().ok_or_else(|| NO_TRUSTED_TIME.to_string())
}

fn unb64(s: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("{what} base64: {e}"))
}

fn map_unb64(m: &BTreeMap<u16, String>, what: &str) -> Result<BTreeMap<u16, Vec<u8>>, String> {
    m.iter().map(|(i, v)| Ok((*i, unb64(v, what)?))).collect()
}

fn response_error(r: VaultResponse) -> String {
    match r {
        VaultResponse::Error(e) => e,
        _ => "unexpected response".into(),
    }
}

// ---------------------------------------------------------------------------
//  Dispatch
// ---------------------------------------------------------------------------

pub(crate) fn handle(req: VaultRequest, ctx: &RequestContext) -> VaultResponse {
    run(req, ctx).unwrap_or_else(VaultResponse::Error)
}

fn run(req: VaultRequest, ctx: &RequestContext) -> Result<VaultResponse, String> {
    let caller = caller_id(ctx);
    match req {
        VaultRequest::FrostDkgRound1 {
            session,
            handle,
            grant,
            index,
            threshold,
            vaults,
        } => dkg_round1(&session, &handle, &grant, index, threshold, vaults, &caller, ctx),

        VaultRequest::FrostDkgRound2 {
            session,
            handle,
            round1,
        } => {
            let mut msgs = BTreeMap::new();
            for (i, m) in &round1 {
                msgs.insert(
                    *i,
                    Round1Msg {
                        package: unb64(&m.package_b64, "round 1 package")?,
                        dh_public: unb64(&m.dh_public_b64, "X25519 key")?,
                        quote: unb64(&m.quote_b64, "quote")?,
                    },
                );
            }
            let now = now()?;
            let packages = with_state(|st| {
                st.check_owner(&format!("dkg:{session}"), &caller, now)?;
                st.dkg
                    .round2(&session, &handle, &msgs, &verify_vault_quote, now)
            })?;
            Ok(VaultResponse::FrostDkgSealed { packages })
        }

        VaultRequest::FrostDkgRound3 {
            session,
            handle,
            packages_b64,
        } => {
            let packages = map_unb64(&packages_b64, "round 2 package")?;
            let now = now()?;
            let out = with_state(|st| {
                st.check_owner(&format!("dkg:{session}"), &caller, now)?;
                st.dkg.round3(&session, &handle, &packages, now)
            })?;
            Ok(VaultResponse::FrostDkgConfirm {
                public_key: out.group_public_key,
                confirmations: out.confirmations,
            })
        }

        VaultRequest::FrostDkgCommit {
            session,
            handle,
            confirmations_b64,
        } => {
            let confirmations = map_unb64(&confirmations_b64, "confirmation")?;
            let now = now()?;
            let (share, p) = with_state(|st| {
                st.check_owner(&format!("dkg:{session}"), &caller, now)?;
                let p = st
                    .pending
                    .remove(&session)
                    .ok_or("unknown or expired threshold session")?;
                let share = st.dkg.commit(&session, &handle, &confirmations, now);
                st.owners.remove(&format!("dkg:{session}"));
                Ok((share?, p))
            })?;
            if p.handle != handle {
                return Err("DKG session is for another key".into());
            }
            let (public_key, expires_at) = store_record(&p, &share, now, ctx)?;
            Ok(VaultResponse::ThresholdKeyCreated {
                handle,
                index: p.index,
                threshold: p.threshold,
                public_key,
                expires_at,
            })
        }

        VaultRequest::FrostDkgAbort { session } => {
            let now = now()?;
            with_state(|st| {
                st.check_owner(&format!("dkg:{session}"), &caller, now)?;
                st.drop_dkg(&session);
                Ok(())
            })?;
            Ok(VaultResponse::FrostDone)
        }

        VaultRequest::FrostSignRound1 {
            session,
            handle,
            message_b64,
            approvals,
        } => sign_round1(&session, &handle, &message_b64, &approvals, &caller, ctx),

        VaultRequest::FrostSignRound2 {
            session,
            handle,
            commitments_b64,
        } => {
            let commitments = map_unb64(&commitments_b64, "commitment")?;
            let now = now()?;
            // The session's owner first: nothing about the key is revealed to
            // anyone else.
            with_state(|st| st.check_owner(&format!("sign:{session}"), &caller, now))?;
            let record = threshold_record(&handle);
            let out = with_state(|st| {
                st.owners.remove(&format!("sign:{session}"));
                let record = match record {
                    Ok(r) => r,
                    Err(e) => {
                        st.sign.abort(&session);
                        return Err(e);
                    }
                };
                let share = StoredShare::from_bytes(&record.material)?;
                st.sign.sign(&session, &handle, &share, &commitments, now)
            })?;
            Ok(VaultResponse::FrostSignatureShare { share: out })
        }

        VaultRequest::FrostSignAbort { session } => {
            let now = now()?;
            with_state(|st| {
                st.check_owner(&format!("sign:{session}"), &caller, now)?;
                st.sign.abort(&session);
                st.owners.remove(&format!("sign:{session}"));
                Ok(())
            })?;
            Ok(VaultResponse::FrostDone)
        }

        VaultRequest::FrostAggregate {
            handle,
            message_b64,
            commitments_b64,
            shares_b64,
        } => {
            let record = load_record(&handle).map_err(response_error)?;
            if resolve_caller(&record.policy, ctx).is_none() {
                return Err("caller is not in policy.principals".into());
            }
            let record = threshold_record(&handle)?;
            let share = StoredShare::from_bytes(&record.material)?;
            let message = unb64(&message_b64, "message")?;
            let signature = frost::aggregate(
                &message,
                &map_unb64(&commitments_b64, "commitment")?,
                &map_unb64(&shares_b64, "signature share")?,
                &share,
            )?;
            Ok(VaultResponse::Signature {
                signature,
                alg: frost::ALG,
            })
        }

        _ => Err("not a threshold request".into()),
    }
}

fn threshold_record(handle: &str) -> Result<KeyRecord, String> {
    let record = load_record(handle).map_err(response_error)?;
    if record.key_type != KeyType::FrostEd25519 {
        return Err("not a threshold key".into());
    }
    if expired(&record) {
        return Err("key has expired".into());
    }
    Ok(record)
}

// ---------------------------------------------------------------------------
//  Attestation of the other vaults' round 1 messages
// ---------------------------------------------------------------------------

/// Byte offset of the low byte of the ATTRIBUTES flags in an SGX v3 quote.
const SGX_QUOTE_ATTRIBUTES_FLAGS: usize = 48 + 48;
/// SGX_FLAGS_DEBUG.
const SGX_FLAGS_DEBUG: u8 = 0x02;

/// A round 1 quote must come from a vault of THIS build (its MRENCLAVE),
/// not in DEBUG mode,
/// verified by the configured attestation servers, and its report data must
/// carry `binding` (the first 32 bytes; the rest zero).
fn verify_vault_quote(quote: &[u8], binding: &[u8; 32]) -> Result<(), String> {
    // A DEBUG enclave's memory is readable by its host: never a participant.
    // SGX quote v3: 48-byte header, then the report body, whose ATTRIBUTES
    // flags (u64 LE) sit at body offset 48; bit 1 is DEBUG.
    match quote.get(SGX_QUOTE_ATTRIBUTES_FLAGS) {
        Some(flags) if flags & SGX_FLAGS_DEBUG == 0 => {}
        Some(_) => return Err("the other vault runs in SGX DEBUG mode".into()),
        None => return Err("the quote is too short".into()),
    }
    let urls = enclave_os_common::attestation_servers::server_urls();
    if urls.is_empty() {
        return Err("no attestation server configured to verify the other vaults".into());
    }
    let verdicts = enclave_os_egress::attestation::verify_quote_statuses(quote, &urls)?;
    for v in &verdicts {
        if !enclave_os_egress::attestation::tcb_status_acceptable(&v.tcb_status, None) {
            return Err(format!("the other vault's platform TCB is {}", v.tcb_status));
        }
    }
    let identity = crate::quote::parse_quote(quote)?;
    let mine = enclave_os_egress::enclave_self_mrenclave()
        .ok_or("this enclave's MRENCLAVE is not available")?;
    if identity.tee != crate::quote::TeeType::Sgx
        || !identity
            .measurement
            .eq_ignore_ascii_case(&crate::quote::hex_encode(&mine))
    {
        return Err("the quote is not from a vault of this build".into());
    }
    let rd = crate::quote::extract_report_data(quote)?;
    if rd[..32] != binding[..] || rd[32..].iter().any(|b| *b != 0) {
        return Err("the quote does not bind this round 1 message".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
//  Creation
// ---------------------------------------------------------------------------

/// The DKG context every participant's quote binds: the participant list and
/// the threshold, so all vaults must have been given the same ones.
fn dkg_context(vaults: &[String], threshold: u16) -> [u8; 32] {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"privasys-vault-frost-dkg-context-v1");
    h.update(&threshold.to_be_bytes());
    h.update(&(vaults.len() as u64).to_be_bytes());
    for v in vaults {
        h.update(&(v.len() as u64).to_be_bytes());
        h.update(v.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finish().as_ref());
    out
}

/// The checks a vault makes before taking part in a key's DKG.
fn check_creation(
    handle: &str,
    grant: &KeyCreationGrant,
    vaults: &[String],
    threshold: u16,
    index: u16,
) -> Result<(), String> {
    check_grant_for_handle(handle, grant)?;
    if grant.key_type != KeyType::FrostEd25519 {
        return Err(format!(
            "the grant is for a {:?} key, not FrostEd25519",
            grant.key_type
        ));
    }
    if grant.exportable {
        return Err(
            "a threshold key is never exportable: the grant must say exportable=false".into(),
        );
    }
    let n = u16::try_from(vaults.len()).map_err(|_| "too many vaults".to_string())?;
    frost::check_threshold(threshold, n)?;
    if index == 0 || index > n {
        return Err(format!("participant index {index} is out of range 1..={n}"));
    }
    for (i, v) in vaults.iter().enumerate() {
        if v.is_empty() || v.len() > 256 || vaults[..i].contains(v) {
            return Err("vaults must be distinct, non-empty host:port endpoints".into());
        }
    }
    let kv = kv().map_err(response_error)?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
    match store.get(&record_key(handle)) {
        Ok(Some(_)) => Err("handle already exists".into()),
        Ok(None) => Ok(()),
        Err(e) => Err(format!("kv get failed: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn dkg_round1(
    session: &str,
    handle: &str,
    grant_jwt: &str,
    index: u16,
    threshold: u16,
    vaults: Vec<String>,
    caller: &str,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    let now = now()?;
    // Bound to the caller, as for CreateKey.
    let grant = crate::grant::verify_grant(grant_jwt, ctx, now)?;
    check_creation(handle, &grant, &vaults, threshold, index)?;
    let n = vaults.len() as u16;
    let out = with_state(|st| {
        st.open(format!("dkg:{session}"), caller, now)?;
        let out = st
            .dkg
            .round1(session, handle, &dkg_context(&vaults, threshold), index, threshold, n, now)
            .inspect_err(|_| {
                st.owners.remove(&format!("dkg:{session}"));
            })?;
        st.pending.insert(
            session.to_string(),
            PendingKey {
                handle: handle.to_string(),
                index,
                threshold,
                grant,
                vaults,
            },
        );
        Ok(out)
    })?;
    let Some(quote) = enclave_os_egress::enclave_attestation_quote(&out.binding) else {
        let _ = with_state(|st| {
            st.drop_dkg(session);
            Ok(())
        });
        return Err("this vault could not produce an attestation quote".into());
    };
    Ok(VaultResponse::FrostDkgRound1 {
        package: out.package,
        dh_public: out.dh_public,
        quote,
    })
}

fn store_record(
    p: &PendingKey,
    share: &StoredShare,
    now: u64,
    ctx: &RequestContext,
) -> Result<(Vec<u8>, u64), String> {
    let policy = normalise_policy(p.grant.policy.clone());
    let expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);
    let public_key = share.group_public_key()?;
    {
        let kv = kv().map_err(response_error)?;
        let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
        if let Ok(Some(_)) = store.get(&record_key(&p.handle)) {
            return Err("handle already exists".into());
        }
    }
    let mut record = KeyRecord {
        handle: p.handle.clone(),
        key_type: KeyType::FrostEd25519,
        exportable: false,
        material: share.to_bytes()?.to_vec(),
        public_key: Some(public_key.clone()),
        policy,
        policy_version: 1,
        created_at: now,
        expires_at,
        pending_profiles: Vec::new(),
        audit_next_seq: 0,
        next_pending_id: 0,
        threshold_vaults: p.vaults.clone(),
    };
    audit_and_save(
        &mut record,
        "CreateThresholdKey",
        &caller_str(ctx),
        AuditDecision::Allowed,
        &format!(
            "owner={} participant={}/{} threshold={}",
            p.grant.sub,
            p.index,
            p.vaults.len(),
            p.threshold
        ),
    )
    .map_err(response_error)?;
    let kv = kv().map_err(response_error)?;
    let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
    add_to_owner_index(&store, &p.grant.sub, &p.handle)
        .map_err(|e| format!("kv owner index: {e}"))?;
    Ok((public_key, expires_at))
}

// ---------------------------------------------------------------------------
//  Signing
// ---------------------------------------------------------------------------

fn sign_round1(
    session: &str,
    handle: &str,
    message_b64: &str,
    approvals: &[ApprovalToken],
    caller: &str,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    // Authorised and audited exactly like Sign on this vault.
    let record = require_op(handle, Operation::Sign, KeyType::FrostEd25519, approvals, ctx)
        .map_err(response_error)?;
    let share = StoredShare::from_bytes(&record.material)?;
    let message = unb64(message_b64, "message")?;
    let now = now()?;
    let commitment = with_state(|st| {
        st.open(format!("sign:{session}"), caller, now)?;
        st.sign
            .commit(session, handle, &share, &message, now)
            .inspect_err(|_| {
                st.owners.remove(&format!("sign:{session}"));
            })
    })?;
    Ok(VaultResponse::FrostCommitment {
        index: share.index,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(sub: Option<&str>, cert: Option<&[u8]>) -> RequestContext {
        RequestContext {
            peer_cert_der: cert.map(|c| c.to_vec()),
            peer_evidence: None,
            attestation: "none".into(),
            oidc_claims: sub.map(|s| {
                serde_json::from_value(serde_json::json!({
                    "sub": s, "roles": [], "is_manager": false, "is_monitoring": false
                }))
                .unwrap()
            }),
            fido2_user: None,
            app_name: None,
        }
    }

    #[test]
    fn caller_id_tells_callers_apart() {
        let a = caller_id(&ctx(Some("alice"), Some(b"cert-a")));
        assert_eq!(a, caller_id(&ctx(Some("alice"), Some(b"cert-a"))));
        assert_ne!(a, caller_id(&ctx(Some("bob"), Some(b"cert-a"))));
        assert_ne!(a, caller_id(&ctx(Some("alice"), Some(b"cert-b"))));
        assert_ne!(a, caller_id(&ctx(None, None)));
    }

    #[test]
    fn a_session_belongs_to_its_caller() {
        let mut st = State::new();
        st.open("sign:s".into(), "alice", 100).unwrap();
        assert!(st.open("sign:s".into(), "bob", 100).is_err());
        st.check_owner("sign:s", "alice", 101).unwrap();
        let e = st.check_owner("sign:s", "bob", 101).unwrap_err();
        assert!(e.contains("another caller"), "{e}");
        let e = st
            .check_owner("sign:s", "alice", 100 + frost::DKG_SESSION_TTL_SECS)
            .unwrap_err();
        assert!(e.contains("expired"), "{e}");
    }

    #[test]
    fn a_debug_enclave_never_takes_part() {
        let mut quote = vec![0u8; 600];
        quote[0] = 3;
        quote[SGX_QUOTE_ATTRIBUTES_FLAGS] = SGX_FLAGS_DEBUG | 0x01;
        let e = verify_vault_quote(&quote, &[0u8; 32]).unwrap_err();
        assert!(e.contains("DEBUG"), "{e}");
        assert!(verify_vault_quote(&quote[..50], &[0u8; 32]).unwrap_err().contains("too short"));
    }

    #[test]
    fn one_caller_cannot_fill_the_tables() {
        let mut st = State::new();
        for i in 0..MAX_SESSIONS_PER_CALLER {
            st.open(format!("sign:{i}"), "mallory", 100).unwrap();
        }
        let e = st.open("sign:x".into(), "mallory", 100).unwrap_err();
        assert!(e.contains("this caller"), "{e}");
        st.open("sign:y".into(), "alice", 100).unwrap();
    }

    #[test]
    fn the_context_binds_the_participants_and_threshold() {
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = dkg_context(&v(&["a:1", "b:2"]), 2);
        assert_eq!(a, dkg_context(&v(&["a:1", "b:2"]), 2));
        assert_ne!(a, dkg_context(&v(&["b:2", "a:1"]), 2));
        assert_ne!(a, dkg_context(&v(&["a:1", "b:2", "c:3"]), 2));
        assert_ne!(dkg_context(&v(&["a:1", "b:2", "c:3"]), 2), dkg_context(&v(&["a:1", "b:2", "c:3"]), 3));
        assert_ne!(dkg_context(&v(&["a:1b", ":2"]), 2), dkg_context(&v(&["a:1", "b:2"]), 2));
    }

    #[test]
    fn round1_messages_decode_from_the_wire() {
        let wire = serde_json::json!({
            "FrostDkgRound2": {
                "session": "0123456789abcdef",
                "handle": "users/s/k",
                "round1": {
                    "1": {"package_b64": "AQ", "dh_public_b64": "Ag", "quote_b64": "Aw"},
                    "2": {"package_b64": "BA", "dh_public_b64": "BQ", "quote_b64": "Bg"}
                }
            }
        });
        let req: VaultRequest = serde_json::from_value(wire).unwrap();
        match req {
            VaultRequest::FrostDkgRound2 { round1, .. } => {
                assert_eq!(round1.len(), 2);
                assert_eq!(round1[&2].quote_b64, "Bg");
            }
            _ => panic!("wrong variant"),
        }
    }
}
