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
use crate::policy::{resolve_caller, CallerRole};
use crate::types::{
    AuditDecision, FrostTargetMessage, KeyRecord, KeyType, Operation,
    ThresholdKeyInfo, VaultRequest, VaultResponse,
};
use crate::{
    add_to_owner_index, audit_and_save, caller_str, check_grant_for_handle, expired, kv,
    load_record, normalise_policy, now_secs, record_key, require_op, NO_TRUSTED_TIME,
};
use crate::types::{BindingV2Request, PendingCreation};

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
    /// Made with the owner's bound create approval (a re-created name).
    created_by_owner_approval: bool,
}

struct State {
    dkg: frost::DkgStore,
    sign: frost::SignStore,
    reshare: frost::reshare::ReshareStore,
    /// Keys being generated or reshared onto this vault, by session.
    pending: BTreeMap<String, PendingKey>,
    /// Who opened each session ("dkg:<id>" / "sign:<id>" / "reshare:<id>"),
    /// and when.
    owners: BTreeMap<String, (String, u64)>,
}

impl State {
    fn new() -> Self {
        State {
            dkg: frost::DkgStore::new(),
            sign: frost::SignStore::new(),
            reshare: frost::reshare::ReshareStore::new(),
            pending: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        self.owners
            .retain(|_, (_, created)| now < created.saturating_add(frost::DKG_SESSION_TTL_SECS));
        let owners = &self.owners;
        self.pending.retain(|id, _| {
            owners.contains_key(&format!("dkg:{id}")) || owners.contains_key(&format!("reshare:{id}"))
        });
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
pub(crate) fn caller_id(ctx: &RequestContext) -> String {
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
            binding,
        } => dkg_round1(&session, &handle, &grant, index, threshold, vaults, binding, &caller, ctx),

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
            let (public_key, expires_at) = store_record(&p, &share, now, &session, &caller, ctx)?;
            Ok(VaultResponse::ThresholdKeyCreated {
                handle,
                index: p.index,
                threshold: p.threshold,
                public_key,
                expires_at,
            })
        }

        VaultRequest::FrostDkgAbort { session, handle } => {
            let now = now()?;
            let open = with_state(|st| {
                if st.check_owner(&format!("dkg:{session}"), &caller, now).is_ok() {
                    st.drop_dkg(&session);
                    return Ok(true);
                }
                Ok(false)
            })?;
            abort_pending(open, &session, handle.as_deref(), &caller, now, ctx, "dkg")
        }

        VaultRequest::FrostSignRound1 {
            session,
            handle,
            message_b64,
        } => sign_round1(&session, &handle, &message_b64, &caller, ctx),

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
            let record = crate::load_for(&handle, ctx).map_err(response_error)?;
            if resolve_caller(&record.policy, ctx).is_none() {
                return Err(crate::tomb::NOT_A_PRINCIPAL.into());
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

        VaultRequest::FrostReshareTarget1 {
            session,
            handle,
            grant,
            index,
            threshold,
            vaults,
            helpers,
            old_public_key_package_b64,
            binding,
        } => reshare_target1(
            &session,
            &handle,
            &grant,
            index,
            threshold,
            vaults,
            helpers,
            &old_public_key_package_b64,
            binding,
            &caller,
            ctx,
        ),
        VaultRequest::FrostReshareDeal {
            session,
            handle,
            helpers,
            threshold,
            vaults,
            target_mrenclave,
            targets,
        } => reshare_deal(&session, &handle, &helpers, threshold, &vaults, &target_mrenclave, &targets, ctx),
        VaultRequest::FrostReshareTarget2 {
            session,
            handle,
            targets,
            deals,
        } => {
            let targets = decode_targets(&targets)?;
            let mut d = BTreeMap::new();
            for (i, m) in &deals {
                let commitment = m
                    .commitment_b64
                    .iter()
                    .map(|c| unb64(c, "commitment"))
                    .collect::<Result<Vec<_>, _>>()?;
                d.insert(*i, (commitment, unb64(&m.sealed_b64, "sealed piece")?));
            }
            let now = now()?;
            let out = with_state(|st| {
                st.check_owner(&format!("reshare:{session}"), &caller, now)?;
                st.reshare
                    .round2(&session, &handle, &targets, &d, &verify_vault_quote, now)
            })?;
            Ok(VaultResponse::FrostDkgConfirm {
                public_key: out.group_public_key,
                confirmations: out.confirmations,
            })
        }
        VaultRequest::FrostReshareCommit {
            session,
            handle,
            confirmations_b64,
        } => {
            let confirmations = map_unb64(&confirmations_b64, "confirmation")?;
            let now = now()?;
            let (share, p) = with_state(|st| {
                st.check_owner(&format!("reshare:{session}"), &caller, now)?;
                let p = st
                    .pending
                    .remove(&session)
                    .ok_or("unknown or expired threshold session")?;
                let share = st.reshare.commit(&session, &handle, &confirmations, now);
                st.owners.remove(&format!("reshare:{session}"));
                Ok((share?, p))
            })?;
            if p.handle != handle {
                return Err("resharing session is for another key".into());
            }
            let (public_key, expires_at) = store_reshared(&p, &share, now, &session, &caller, ctx)?;
            Ok(VaultResponse::ThresholdKeyCreated {
                handle,
                index: p.index,
                threshold: p.threshold,
                public_key,
                expires_at,
            })
        }
        VaultRequest::FrostReshareAbort { session, handle } => {
            let now = now()?;
            let open = with_state(|st| {
                if st.check_owner(&format!("reshare:{session}"), &caller, now).is_ok() {
                    st.reshare.abort(&session);
                    st.pending.remove(&session);
                    st.owners.remove(&format!("reshare:{session}"));
                    return Ok(true);
                }
                Ok(false)
            })?;
            abort_pending(open, &session, handle.as_deref(), &caller, now, ctx, "reshare")
        }
        VaultRequest::FrostReshareFinalize { handle } => reshare_finish(&handle, false, ctx),
        VaultRequest::FrostReshareRollback { handle } => reshare_finish(&handle, true, ctx),

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
    let mine = enclave_os_egress::enclave_self_mrenclave()
        .ok_or("this enclave's MRENCLAVE is not available")?;
    verify_quote_of(quote, binding, &mine)
}

/// The same checks against a named build: a quote from a vault whose
/// MRENCLAVE is `expected` (a resharing's target constellation).
fn verify_quote_of(quote: &[u8], binding: &[u8; 32], expected: &[u8; 32]) -> Result<(), String> {
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
    if identity.tee != crate::quote::TeeType::Sgx
        || !identity
            .measurement
            .eq_ignore_ascii_case(&crate::quote::hex_encode(expected))
    {
        return Err("the quote is not from a vault of the expected build".into());
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
    allow_existing: bool,
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
    if allow_existing {
        return Ok(());
    }
    crate::check_handle_free(handle)
}

/// A threshold key new on this vault under a re-created name needs the
/// owner's bound create approval (wire formats §9.3.1); beneath one, only a
/// linked renewal. `renewal` is whether this is a resharing.
fn check_threshold_name(
    handle: &str,
    grant: &KeyCreationGrant,
    renewal: bool,
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> Result<bool, String> {
    if !renewal && crate::is_generation_handle(handle) {
        return Err("a handle ending in gen-<n> is a generation and can only be created by a renewal".into());
    }
    match crate::check_name_rule(handle, renewal)? {
        crate::NameRule::ReCreated => {
            crate::check_stored_form(&grant.policy)?;
            crate::policy::require_owner_create(
                &normalise_policy(grant.policy.clone()),
                handle,
                binding.map(|b| b.members),
                ctx,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Abort a key this session committed here and that has served nothing yet
/// (wire formats §9.3.1). No tombstone: it never existed as a usable key. The
/// abort stays in the handle's audit log.
pub(crate) fn abort_pending(
    session_was_open: bool,
    session: &str,
    handle: Option<&str>,
    caller: &str,
    now: u64,
    ctx: &RequestContext,
    kind: &str,
) -> Result<VaultResponse, String> {
    let Some(handle) = handle else {
        if session_was_open {
            return Ok(VaultResponse::FrostDone);
        }
        return Err("unknown or expired threshold session".into());
    };
    let mut record = match crate::lookup(handle).map_err(response_error)? {
        crate::tomb::Lookup::Live(r) => r,
        // Nothing committed here (or long gone): nothing to undo.
        _ => return Ok(VaultResponse::FrostDone),
    };
    let ok = match &record.pending_creation {
        Some(p) => {
            p.session == session
                && p.caller == caller
                && now <= p.committed_at.saturating_add(frost::DKG_SESSION_TTL_SECS)
        }
        None => false,
    };
    if !ok {
        return Err(
            "only a key this session committed here, unused and within the session's time, \
             can be aborted; delete it instead"
                .into(),
        );
    }
    let owner = crate::owner_oidc_sub(&record.policy.principals.owner);
    audit_and_save(
        &mut record,
        "AbortPendingKey",
        &caller_str(ctx),
        AuditDecision::Allowed,
        &format!("{kind} session {session}"),
    )
    .map_err(response_error)?;
    let kv = kv().map_err(response_error)?;
    let mut store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
    store
        .delete(&record_key(handle))
        .map_err(|e| format!("kv delete failed: {e}"))?;
    if let Some(owner) = owner {
        let _ = crate::remove_from_owner_index(&store, &owner, handle);
    }
    Ok(VaultResponse::FrostDone)
}

#[allow(clippy::too_many_arguments)]
fn dkg_round1(
    session: &str,
    handle: &str,
    grant_jwt: &str,
    index: u16,
    threshold: u16,
    vaults: Vec<String>,
    binding: Option<BindingV2Request>,
    caller: &str,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    let now = now()?;
    // Bound to the caller, as for CreateKey.
    let grant = crate::grant::verify_grant(grant_jwt, ctx, now)?;
    check_creation(handle, &grant, &vaults, threshold, index, false)?;
    // A first creation, as for CreateKey: the grant's policy must ask for
    // approvals, or opt out explicitly. A resharing renews an existing key
    // and, like every renewal, is not checked again.
    crate::v2::check_approval_by_default(&normalise_policy(grant.policy.clone()), false)?;
    let created_by_owner_approval = check_threshold_name(handle, &grant, false, binding, ctx)?;
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
                created_by_owner_approval,
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
    session: &str,
    caller: &str,
    ctx: &RequestContext,
) -> Result<(Vec<u8>, u64), String> {
    let policy = normalise_policy(p.grant.policy.clone());
    let expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);
    let public_key = share.group_public_key()?;
    crate::check_handle_free(&p.handle)?;
    let audit_next_seq = {
        let kv = kv().map_err(response_error)?;
        let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
        crate::tomb::next_audit_seq(&store, &p.handle)
    };
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
        audit_next_seq,
        next_pending_id: 0,
        threshold_vaults: p.vaults.clone(),
        key_check: None,
        renewed_in_place_from: None,
        created_by_owner_approval: p.created_by_owner_approval,
        // Until it serves something, its own session may still abort it.
        pending_creation: Some(PendingCreation {
            session: session.to_string(),
            caller: caller.to_string(),
            committed_at: now,
        }),
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
    caller: &str,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    // Authorised and audited exactly like Sign on this vault.
    let record = require_op(handle, Operation::Sign, KeyType::FrostEd25519, ctx)
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

// ---------------------------------------------------------------------------
//  Resharing (renewal, and moving a key to another constellation)
// ---------------------------------------------------------------------------

/// KV key of the record a renewal in place keeps until it is finalized.
pub(crate) fn previous_key(handle: &str) -> Vec<u8> {
    format!("prev:{handle}").into_bytes()
}

/// A threshold key's public part on this vault, for `GetKeyInfo`.
pub(crate) fn key_info(record: &KeyRecord) -> Option<ThresholdKeyInfo> {
    if record.key_type != KeyType::FrostEd25519 {
        return None;
    }
    let share = StoredShare::from_bytes(&record.material).ok()?;
    Some(ThresholdKeyInfo {
        index: share.index,
        threshold: share.min_signers,
        participants: share.max_signers,
        vaults: record.threshold_vaults.clone(),
        public_key_package: share.public_key_package.clone(),
    })
}

/// What a resharing binds: the key (handle and group key), the helpers, the
/// new participants and threshold, and the new vaults' build. The new
/// vaults' quotes bind it, every helper recomputes it, and the owner's
/// wallet approval carries it (hex) in its measurement slot.
pub fn reshare_context(
    handle: &str,
    group_key: &[u8],
    helpers: &[u16],
    threshold: u16,
    vaults: &[String],
    target_mrenclave: &[u8; 32],
) -> [u8; 32] {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"privasys-vault-frost-reshare-v1");
    h.update(&(handle.len() as u64).to_be_bytes());
    h.update(handle.as_bytes());
    h.update(&(group_key.len() as u64).to_be_bytes());
    h.update(group_key);
    h.update(&(helpers.len() as u64).to_be_bytes());
    for i in helpers {
        h.update(&i.to_be_bytes());
    }
    h.update(&threshold.to_be_bytes());
    h.update(&(vaults.len() as u64).to_be_bytes());
    for v in vaults {
        h.update(&(v.len() as u64).to_be_bytes());
        h.update(v.as_bytes());
    }
    h.update(target_mrenclave);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finish().as_ref());
    out
}

/// What the new vaults' quotes bind: the resharing context and the key's
/// policy. A helper computes it from the policy it holds, a new vault from the
/// policy its creation grant carries: a renewal cannot change the key's
/// policy (its owner, principals, rules), whoever authored the grant.
fn quote_context(context: &[u8; 32], policy: &crate::types::KeyPolicy) -> Result<[u8; 32], String> {
    let bytes = serde_json::to_vec(policy).map_err(|e| format!("serialise policy: {e}"))?;
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"privasys-vault-frost-reshare-policy-v1");
    h.update(context);
    h.update(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finish().as_ref());
    Ok(out)
}

fn decode_targets(
    targets: &BTreeMap<u16, FrostTargetMessage>,
) -> Result<BTreeMap<u16, frost::reshare::TargetMsg>, String> {
    targets
        .iter()
        .map(|(j, m)| {
            Ok((
                *j,
                frost::reshare::TargetMsg {
                    dh_public: unb64(&m.dh_public_b64, "X25519 key")?,
                    quote: unb64(&m.quote_b64, "quote")?,
                },
            ))
        })
        .collect()
}

fn mrenclave_bytes(hex: &str) -> Result<[u8; 32], String> {
    enclave_os_common::hex::hex_decode(hex)
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| "target_mrenclave must be 32 bytes of hex".to_string())
}

#[allow(clippy::too_many_arguments)]
fn reshare_target1(
    session: &str,
    handle: &str,
    grant_jwt: &str,
    index: u16,
    threshold: u16,
    vaults: Vec<String>,
    helpers: Vec<u16>,
    old_pkp_b64: &str,
    binding: Option<BindingV2Request>,
    caller: &str,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    let now = now()?;
    // Bound to the caller, as for CreateKey.
    let grant = crate::grant::verify_grant(grant_jwt, ctx, now)?;
    let old_pkp = unb64(old_pkp_b64, "old public key package")?;
    let group = frost::reshare::group_key_of(&old_pkp)?;
    // The handle may hold the old key here already (renewal in place); then
    // the new key must be that key.
    let existing = load_record(handle).ok();
    if let Some(r) = &existing {
        if r.key_type != KeyType::FrostEd25519 || r.public_key.as_deref() != Some(&group[..]) {
            return Err("the handle holds another key on this vault".into());
        }
    }
    check_creation(handle, &grant, &vaults, threshold, index, existing.is_some())?;
    // New on this vault: the name rules of a re-created name apply.
    let created_by_owner_approval = match &existing {
        Some(r) => r.created_by_owner_approval,
        None => check_threshold_name(handle, &grant, true, binding, ctx)?,
    };
    let mine = enclave_os_egress::enclave_self_mrenclave()
        .ok_or("this enclave's MRENCLAVE is not available")?;
    let context = reshare_context(handle, &group, &helpers, threshold, &vaults, &mine);
    let context = quote_context(&context, &normalise_policy(grant.policy.clone()))?;
    if let Some(r) = &existing {
        let kv = kv().map_err(response_error)?;
        let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
        if let Ok(Some(_)) = store.get(&previous_key(&r.handle)) {
            return Err("a previous renewal of this key is not finalized: finalize or roll it back first".into());
        }
    }
    let n = vaults.len() as u16;
    let out = with_state(|st| {
        st.open(format!("reshare:{session}"), caller, now)?;
        let out = st
            .reshare
            .round1(session, handle, &context, index, threshold, n, &old_pkp, &helpers, now)
            .inspect_err(|_| {
                st.owners.remove(&format!("reshare:{session}"));
            })?;
        st.pending.insert(
            session.to_string(),
            PendingKey {
                handle: handle.to_string(),
                index,
                threshold,
                grant,
                vaults,
                created_by_owner_approval,
            },
        );
        Ok(out)
    })?;
    let Some(quote) = enclave_os_egress::enclave_attestation_quote(&out.binding) else {
        let _ = with_state(|st| {
            st.reshare.abort(session);
            st.pending.remove(session);
            st.owners.remove(&format!("reshare:{session}"));
            Ok(())
        });
        return Err("this vault could not produce an attestation quote".into());
    };
    Ok(VaultResponse::FrostReshareTarget {
        dh_public: out.dh_public,
        quote,
    })
}

#[allow(clippy::too_many_arguments)]
fn reshare_deal(
    session: &str,
    handle: &str,
    helpers: &[u16],
    threshold: u16,
    vaults: &[String],
    target_mrenclave: &str,
    targets: &BTreeMap<u16, FrostTargetMessage>,
    ctx: &RequestContext,
) -> Result<VaultResponse, String> {
    let mut record = threshold_record(handle)?;
    let share = StoredShare::from_bytes(&record.material)?;
    let target = mrenclave_bytes(target_mrenclave)?;
    let group = share.group_public_key()?;
    let n = u16::try_from(vaults.len()).map_err(|_| "too many vaults".to_string())?;
    let context = reshare_context(handle, &group, helpers, threshold, vaults, &target);
    let caller = caller_str(ctx);
    // As exporting a secret: the owner, with a wallet approval of exactly
    // this move.
    if let Err(e) = crate::policy::require_owner_step_up(
        &record.policy,
        record.policy_version,
        handle,
        &crate::quote::hex_encode(&context),
        ctx,
    ) {
        let _ = crate::audit_denial(ctx, &mut record, "ReshareDeal", &caller, AuditDecision::Denied, &e);
        return Err(e);
    }
    let targets = decode_targets(targets)?;
    let verify = |q: &[u8], b: &[u8; 32]| verify_quote_of(q, b, &target);
    let bound = quote_context(&context, &record.policy)?;
    let deal = frost::reshare::deal(&share, session, handle, &bound, helpers, threshold, n, &targets, &verify)
        .map_err(|e| {
            if e.contains("quote does not bind") {
                format!("{e} (or the renewal would change the key's policy)")
            } else {
                e
            }
        })?;
    // Having served, the key can no longer be aborted.
    record.pending_creation = None;
    audit_and_save(
        &mut record,
        "ReshareDeal",
        &caller,
        AuditDecision::Allowed,
        &format!(
            "to {n} vaults, threshold {threshold}, build {}",
            &target_mrenclave[..target_mrenclave.len().min(16)]
        ),
    )
    .map_err(response_error)?;
    Ok(VaultResponse::FrostReshareDealt {
        commitment: deal.commitment,
        sealed: deal.sealed,
    })
}

/// Store a reshared key. A renewal in place keeps the previous record (under
/// [`previous_key`]) until the owner finalizes, so a resharing that did not
/// commit everywhere can be rolled back.
fn store_reshared(
    p: &PendingKey,
    share: &StoredShare,
    now: u64,
    session: &str,
    caller: &str,
    ctx: &RequestContext,
) -> Result<(Vec<u8>, u64), String> {
    let Ok(mut old) = load_record(&p.handle) else {
        return store_record(p, share, now, session, caller, ctx);
    };
    let public_key = share.group_public_key()?;
    if old.public_key.as_deref() != Some(&public_key[..]) {
        return Err("the handle holds another key on this vault".into());
    }
    let kv = kv().map_err(response_error)?;
    {
        let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
        if let Ok(Some(_)) = store.get(&previous_key(&p.handle)) {
            return Err("a previous renewal of this key is not finalized yet".into());
        }
        let bytes = serde_json::to_vec(&old).map_err(|e| format!("serialise record: {e}"))?;
        store
            .put(&previous_key(&p.handle), &bytes)
            .map_err(|e| format!("kv put failed: {e}"))?;
    }
    let policy = normalise_policy(p.grant.policy.clone());
    old.expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);
    old.policy = policy;
    old.policy_version = old.policy_version.saturating_add(1);
    old.material = share.to_bytes()?.to_vec();
    old.threshold_vaults = p.vaults.clone();
    old.created_at = now;
    let expires_at = old.expires_at;
    audit_and_save(
        &mut old,
        "ReshareKey",
        &caller_str(ctx),
        AuditDecision::Allowed,
        &format!(
            "in place, participant={}/{} threshold={}",
            p.index,
            p.vaults.len(),
            p.threshold
        ),
    )
    .map_err(response_error)?;
    Ok((public_key, expires_at))
}

/// Owner: finalize (drop the kept previous record) or roll back (restore it).
fn reshare_finish(handle: &str, rollback: bool, ctx: &RequestContext) -> Result<VaultResponse, String> {
    let mut record = load_record(handle).map_err(response_error)?;
    match resolve_caller(&record.policy, ctx) {
        Some((_, CallerRole::Owner)) => {}
        _ => return Err("only the key's owner may finalize or roll back a renewal".into()),
    }
    let kv = kv().map_err(response_error)?;
    let previous = {
        let store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
        store
            .get(&previous_key(handle))
            .map_err(|e| format!("kv get failed: {e}"))?
    };
    let Some(previous) = previous else {
        return Ok(VaultResponse::FrostDone);
    };
    let op = if rollback { "ReshareRollback" } else { "ReshareFinalize" };
    if rollback {
        let mut restored: KeyRecord =
            serde_json::from_slice(&previous).map_err(|e| format!("corrupt previous record: {e}"))?;
        // Keep the audit log running on.
        restored.audit_next_seq = record.audit_next_seq;
        audit_and_save(&mut restored, op, &caller_str(ctx), AuditDecision::Allowed, "")
            .map_err(response_error)?;
    } else {
        audit_and_save(&mut record, op, &caller_str(ctx), AuditDecision::Allowed, "")
            .map_err(response_error)?;
    }
    let mut store = kv.lock().map_err(|_| "kv store lock poisoned".to_string())?;
    store
        .delete(&previous_key(handle))
        .map_err(|e| format!("kv delete failed: {e}"))?;
    Ok(VaultResponse::FrostDone)
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
        let e = verify_quote_of(&quote, &[0u8; 32], &[1u8; 32]).unwrap_err();
        assert!(e.contains("DEBUG"), "{e}");
        assert!(verify_quote_of(&quote[..50], &[0u8; 32], &[1u8; 32]).unwrap_err().contains("too short"));
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
    fn the_reshare_context_matches_the_go_client() {
        // The same vector is asserted by the Go client (frost_test.go), which
        // computes the step-up binding the owner approves.
        let v = vec!["a:1".to_string(), "b:2".to_string(), "c:3".to_string()];
        let c = reshare_context("vaults/x/k", &[1u8; 32], &[1, 3], 2, &v, &[9u8; 32]);
        assert_eq!(
            crate::quote::hex_encode(&c),
            "e6077b2adf28720e9348c478cc1668cf47604c8b4ede5d3def858bc65d7b6ea6"
        );
    }

    #[test]
    fn the_reshare_context_binds_every_input() {
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = reshare_context("h", &[1u8; 32], &[1, 2], 2, &v(&["a:1", "b:2"]), &[9u8; 32]);
        assert_ne!(base, reshare_context("h2", &[1u8; 32], &[1, 2], 2, &v(&["a:1", "b:2"]), &[9u8; 32]));
        assert_ne!(base, reshare_context("h", &[2u8; 32], &[1, 2], 2, &v(&["a:1", "b:2"]), &[9u8; 32]));
        assert_ne!(base, reshare_context("h", &[1u8; 32], &[1, 3], 2, &v(&["a:1", "b:2"]), &[9u8; 32]));
        assert_ne!(base, reshare_context("h", &[1u8; 32], &[1, 2], 3, &v(&["a:1", "b:2"]), &[9u8; 32]));
        assert_ne!(base, reshare_context("h", &[1u8; 32], &[1, 2], 2, &v(&["a:1", "c:3"]), &[9u8; 32]));
        assert_ne!(base, reshare_context("h", &[1u8; 32], &[1, 2], 2, &v(&["a:1", "b:2"]), &[8u8; 32]));
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
