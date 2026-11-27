// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Creating keys: first creations under a grant, renewals in place or with a carried policy, and re-created names (wire formats §9).

use super::*;

/// What a grant must satisfy for `handle`, whoever presents it: the handle is
/// not reserved and falls under the grant's scope, and the granted policy is
/// owned by the grant's subject.
pub(crate) fn check_grant_for_handle(
    handle: &str,
    grant: &crate::grant::KeyCreationGrant,
) -> Result<(), String> {
    if handle.is_empty() {
        return Err("handle must not be empty".into());
    }
    if handle.starts_with("__") {
        return Err("handles starting with '__' are reserved for internal use".into());
    }
    if handle != grant.scope && !handle.starts_with(&format!("{}/", grant.scope)) {
        return Err(format!(
            "handle '{handle}' is outside the grant scope '{}'",
            grant.scope
        ));
    }
    if owner_oidc_sub(&grant.policy.principals.owner).as_deref() != Some(grant.sub.as_str()) {
        return Err("grant policy owner does not match the grant subject".into());
    }
    Ok(())
}

/// What a `CreateKey` may carry beyond the grant (wire formats §9, §10.4).
pub(crate) struct CreateExtras {
    pub(crate) predecessor: Option<String>,
    pub(crate) policy: Option<Box<serde_json::value::RawValue>>,
    pub(crate) policy_version: Option<u32>,
    pub(crate) source_billing_id: Option<String>,
    pub(crate) key_check: Option<crate::types::KeyCheck>,
    pub(crate) carried_exportable: Option<bool>,
    pub(crate) carried_key_type: Option<KeyType>,
    pub(crate) binding: Option<BindingV2Request>,
}

/// The capability this build publishes in `GetVaultIdentity` for generation
/// links (wire formats §9.1).
pub const CAPABILITY_GENERATIONS: &str = "generations-v1";

/// The capability a build publishes when it accepts `update_policy_from`
/// (wire formats §5.3).
pub const CAPABILITY_UPDATE_FROM: &str = "update-policy-from-v1";

/// Whether a handle's last segment is a generation marker "gen-<digits>"
/// (wire formats §9.1): the suffix user-secret generations use, and nothing else.
pub(crate) fn is_generation_handle(handle: &str) -> bool {
    let last = handle.rsplit('/').next().unwrap_or(handle);
    match last.strip_prefix("gen-") {
        Some(n) => !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// What the handle's name allows (wire formats §9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameRule {
    /// No `new-<digits>` segment.
    Plain,
    /// The last segment is `new-<digits>`: a re-created name, made only with
    /// the owner's bound `create` approval.
    ReCreated,
    /// Beneath a `new-<digits>` segment: only a linked renewal, ending in
    /// `gen-<digits>`.
    BeneathReCreated,
}

pub(crate) fn is_new_segment(seg: &str) -> bool {
    match seg.strip_prefix("new-") {
        Some(n) => !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

pub(crate) fn name_rule(handle: &str) -> NameRule {
    let segs: Vec<&str> = handle.split('/').collect();
    let (last, rest) = segs.split_last().expect("split yields at least one segment");
    if is_new_segment(last) {
        NameRule::ReCreated
    } else if rest.iter().any(|s| is_new_segment(s)) {
        NameRule::BeneathReCreated
    } else {
        NameRule::Plain
    }
}

/// The checks a creation makes on the handle's name before anything else:
/// `renewal` is whether it is a renewal (a predecessor here or a carried
/// policy).
pub(crate) fn check_name_rule(handle: &str, renewal: bool) -> Result<NameRule, String> {
    let rule = name_rule(handle);
    if rule == NameRule::BeneathReCreated && !(renewal && is_generation_handle(handle)) {
        return Err(
            "beneath a re-created name (new-<k>) only a renewal ending in gen-<m> may be \
             created; to change the value, delete the key and re-create the name"
                .into(),
        );
    }
    Ok(rule)
}

/// A re-created name's policy is approved as the vault will store it: the
/// policy must already be in stored form (wire formats §9.3.1).
pub(crate) fn check_stored_form(policy: &KeyPolicy) -> Result<(), String> {
    let raw = serde_json::to_string(policy).map_err(|e| format!("serialise policy: {e}"))?;
    if v2::check_sent_in_stored_form(&raw).is_err() {
        return Err(
            "a re-created name's policy must be in the vault's stored form \
             (lower-case hex, a TTL within the vault's bounds), as CanonicalisePolicy returns it"
                .into(),
        );
    }
    Ok(())
}

/// Where a new key's policy comes from.
pub(crate) struct NewKeyPolicy {
    pub(crate) policy: KeyPolicy,
    pub(crate) policy_version: u32,
    pub(crate) exportable: bool,
    pub(crate) key_check: Option<crate::types::KeyCheck>,
    /// For the audit log.
    pub(crate) how: String,
    /// Set only for a renewal in place: the predecessor on this vault, and
    /// its material (a single-vault key must keep exactly the same value).
    pub(crate) in_place_from: Option<(String, Vec<u8>)>,
}

/// The caller of a renewal must be the key's owner or one of its enclaves,
/// under the policy being renewed.
pub(crate) fn check_renewal_caller(policy: &KeyPolicy, ctx: &RequestContext) -> Result<(), String> {
    match resolve_caller(policy, ctx) {
        Some((_, CallerRole::Owner)) | Some((_, CallerRole::Tee)) => Ok(()),
        _ => Err("a renewal must come from the key's owner or an enclave its policy names".into()),
    }
}

/// Decide the new key's policy (wire formats §9): copied from a predecessor on
/// this vault, carried by the app from another constellation, or the grant's
/// for a first creation.
pub(crate) fn new_key_policy(
    grant: &crate::grant::KeyCreationGrant,
    extras: CreateExtras,
    ctx: &RequestContext,
) -> Result<NewKeyPolicy, String> {
    if let Some(kc) = &extras.key_check {
        check_key_check(kc)?;
    }

    // Renewal in place: the predecessor is here.
    if let (Some(pred), None) = (&extras.predecessor, &extras.policy) {
        let rec = load_record(pred).map_err(|e| match e {
            VaultResponse::Error(m) => format!("predecessor: {m}"),
            _ => "predecessor not found".into(),
        })?;
        if expired(&rec) {
            return Err("predecessor has expired".into());
        }
        if rec.key_type != grant.key_type {
            return Err("predecessor is of another key type".into());
        }
        if rec.exportable != grant.exportable {
            return Err("the grant changes whether the key is exportable; a renewal keeps it".into());
        }
        check_renewal_caller(&rec.policy, ctx)?;
        return Ok(NewKeyPolicy {
            policy: rec.policy,
            policy_version: rec.policy_version,
            exportable: rec.exportable,
            key_check: rec.key_check.or(extras.key_check),
            how: format!("renewal in place from {pred}"),
            in_place_from: Some((pred.clone(), rec.material)),
        });
    }

    // Moved from another constellation, or rotated: the policy the app read
    // from the source vault, carried verbatim and parsed as the vault parses
    // its own records (not held to the strictness of a policy being approved).
    if let Some(raw) = &extras.policy {
        let policy: KeyPolicy = serde_json::from_str(raw.get())
            .map_err(|e| format!("carried policy does not parse: {e}"))?;
        let policy = normalise_policy(policy);
        let version = extras
            .policy_version
            .ok_or_else(|| "a carried policy needs its policy_version".to_string())?;
        if version == 0 {
            return Err("carried policy_version must be at least 1".into());
        }
        let (_, _, own_billing) = v2::own_identity()?;
        match extras.source_billing_id.as_deref() {
            Some(b) if b == own_billing => {}
            Some(_) => {
                return Err(
                    "the source is under another billing configuration: keys do not cross it"
                        .into(),
                )
            }
            None => return Err("a carried policy needs source_billing_id".into()),
        }
        // The key stays its owner's: a grant creates keys for its subject
        // only, carried or not, so the caller cannot name another owner.
        if owner_oidc_sub(&policy.principals.owner).as_deref() != Some(grant.sub.as_str()) {
            return Err("a carried policy must name the grant's subject as its owner".into());
        }
        check_renewal_caller(&policy, ctx)?;
        // The source key's exportable flag and type travel with its policy;
        // a grant may not change them on the way.
        let carried_exportable = extras
            .carried_exportable
            .ok_or_else(|| "a carried policy needs the source's carried_exportable".to_string())?;
        let carried_key_type = extras
            .carried_key_type
            .ok_or_else(|| "a carried policy needs the source's carried_key_type".to_string())?;
        if carried_exportable != grant.exportable || carried_key_type != grant.key_type {
            return Err(
                "the grant changes the key's type or whether it is exportable; a carried key keeps both"
                    .into(),
            );
        }
        return Ok(NewKeyPolicy {
            policy,
            policy_version: version,
            exportable: carried_exportable,
            key_check: extras.key_check,
            how: match &extras.predecessor {
                Some(p) => format!("carried from {p}"),
                None => "carried (rotation)".into(),
            },
            // A carried create never supersedes anything here.
            in_place_from: None,
        });
    }

    // A first creation: the grant's policy, which must ask for approvals.
    let policy = normalise_policy(grant.policy.clone());
    v2::check_approval_by_default(&policy, grant.exportable)?;
    Ok(NewKeyPolicy {
        policy,
        policy_version: 1,
        exportable: grant.exportable,
        key_check: extras.key_check,
        how: "created".into(),
        in_place_from: None,
    })
}

/// A renewal in place keeps the key's value. For every key type but a Shamir
/// share (whose share is fresh by design, the value being whole only across
/// the vaults), the vault holds the whole value and compares it.
pub(crate) fn check_same_value(key_type: KeyType, old: &[u8], new: &[u8]) -> Result<(), String> {
    if key_type == KeyType::RawShare {
        return Ok(());
    }
    let same = old.len() == new.len()
        && old.iter().zip(new).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if same {
        Ok(())
    } else {
        Err("a renewal must keep the key's value".into())
    }
}

/// Whether `succ` is a live renewal of `handle` made on this vault: the only
/// kind of successor that lets `RetireKey` delete `handle`.
pub(crate) fn superseded_in_place(handle: &str, succ: &KeyRecord) -> bool {
    superseded_in_place_at(handle, succ, now_secs())
}

pub(crate) fn superseded_in_place_at(handle: &str, succ: &KeyRecord, now: Option<u64>) -> bool {
    let live = now.is_some_and(|n| n <= succ.expires_at);
    live && succ.renewed_in_place_from.as_deref() == Some(handle)
}

/// A key check value is opaque to the vault, but must be well formed.
pub(crate) fn check_key_check(kc: &crate::types::KeyCheck) -> Result<(), String> {
    match URL_SAFE_NO_PAD.decode(&kc.salt_b64) {
        Ok(s) if s.len() == 16 => {}
        _ => return Err("key_check salt must be 16 bytes, base64url".into()),
    }
    if kc.digest_hex.len() != 64 || !kc.digest_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("key_check digest must be 64 lower-case hex digits".into());
    }
    Ok(())
}

pub(crate) fn handle_create(
    handle: &str,
    material_b64: &str,
    grant_jwt: &str,
    mut extras: CreateExtras,
    ctx: &RequestContext,
) -> VaultResponse {
    let Some(now) = now_secs() else {
        return VaultResponse::Error(NO_TRUSTED_TIME.into());
    };
    let grant = match crate::grant::verify_grant(grant_jwt, ctx, now) {
        Ok(g) => g,
        Err(e) => return VaultResponse::Error(e),
    };
    if let Err(e) = check_grant_for_handle(handle, &grant) {
        return VaultResponse::Error(e);
    }
    if grant.key_type == KeyType::FrostEd25519 {
        return VaultResponse::Error(
            "a FrostEd25519 key is created by the FrostDkg rounds, not CreateKey".into(),
        );
    }

    let key_type = grant.key_type;
    if extras.predecessor.as_deref() == Some(handle) {
        return VaultResponse::Error("a key cannot succeed itself".into());
    }
    // A generation ("<name>/gen-<n>") exists only through a renewal:
    // whoever mints grants must not be able to plant a newer generation with
    // a value of its choosing as a first creation. The marker is used by
    // nothing else, so first creations at ".../v<n>" are untouched.
    let first_creation = extras.predecessor.is_none() && extras.policy.is_none();
    if first_creation && is_generation_handle(handle) {
        return VaultResponse::Error(
            "a handle ending in gen-<n> is a generation and can only be created by a \
             renewal (a predecessor here, or the policy carried from the source)"
                .into(),
        );
    }
    let rule = match check_name_rule(handle, !first_creation) {
        Ok(r) => r,
        Err(e) => return VaultResponse::Error(e),
    };
    // Every creation path stops at a tombstone (wire formats §9.3).
    if let Err(e) = check_handle_free(handle) {
        return VaultResponse::Error(e);
    }
    // A re-created name: its policy as sent must be its stored form.
    if rule == NameRule::ReCreated {
        let sent = match &extras.policy {
            Some(raw) => match serde_json::from_str::<KeyPolicy>(raw.get()) {
                Ok(p) => p,
                Err(e) => return VaultResponse::Error(format!("carried policy does not parse: {e}")),
            },
            None if extras.predecessor.is_none() => grant.policy.clone(),
            None => {
                return VaultResponse::Error(
                    "a re-created name (new-<k>) is not a renewal in place".into(),
                )
            }
        };
        if let Err(e) = check_stored_form(&sent) {
            return VaultResponse::Error(e);
        }
    }
    let binding = extras.binding.take();
    let chosen = match new_key_policy(&grant, extras, ctx) {
        Ok(c) => c,
        Err(e) => return VaultResponse::Error(e),
    };
    // The owner's bound create approval, checked against exactly the policy
    // stored: never a grant alone.
    let created_by_owner_approval = rule == NameRule::ReCreated;
    if created_by_owner_approval {
        if let Err(e) = crate::policy::require_owner_create(
            &chosen.policy,
            handle,
            binding.map(|b| b.members),
            ctx,
        ) {
            return VaultResponse::Error(e);
        }
    }
    let exportable = chosen.exportable;
    let owner_sub = match owner_oidc_sub(&chosen.policy.principals.owner) {
        Some(s) => s,
        None => return VaultResponse::Error("the key's owner is not an OIDC subject".into()),
    };

    let material = match URL_SAFE_NO_PAD.decode(material_b64) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return VaultResponse::Error("material must not be empty".into()),
        Err(e) => return VaultResponse::Error(format!("bad base64: {e}")),
    };
    let public_key = match crypto::validate_material(key_type, &material) {
        Ok(p) => p,
        Err(e) => return VaultResponse::Error(e),
    };
    // A renewal keeps the value. A single-vault key holds the whole value
    // here, so the vault checks it; a split key's share is fresh by design.
    if let Some((_, old)) = &chosen.in_place_from {
        if let Err(e) = check_same_value(key_type, old, &material) {
            return VaultResponse::Error(e);
        }
    }
    let renewed_in_place_from = chosen.in_place_from.map(|(p, _)| p);

    let policy = chosen.policy;
    let expires_at = now.saturating_add(policy.lifecycle.ttl_seconds);

    let kv = match kv() {
        Ok(k) => k,
        Err(e) => return e,
    };
    let audit_next_seq = {
        let store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        match store.get(&record_key(handle)) {
            Ok(Some(_)) => return VaultResponse::Error("handle already exists".into()),
            Ok(None) => {}
            Err(e) => return VaultResponse::Error(format!("kv get failed: {e}")),
        }
        tomb::next_audit_seq(&store, handle)
    };

    let mut record = KeyRecord {
        handle: handle.to_string(),
        key_type,
        exportable,
        material,
        public_key,
        policy,
        policy_version: chosen.policy_version,
        created_at: now,
        expires_at,
        pending_profiles: Vec::new(),
        audit_next_seq,
        next_pending_id: 0,
        threshold_vaults: Vec::new(),
        key_check: chosen.key_check,
        renewed_in_place_from,
        created_by_owner_approval,
        pending_creation: None,
    };

    if let Err(e) = audit_and_save(
        &mut record,
        "CreateKey",
        &caller_str(ctx),
        AuditDecision::Allowed,
        &format!(
            "owner={owner_sub}; {}{}",
            chosen.how,
            if created_by_owner_approval { "; with the owner's create approval" } else { "" }
        ),
    ) {
        return e;
    }

    {
        let store = match kv.lock() {
            Ok(s) => s,
            Err(_) => return VaultResponse::Error("kv store lock poisoned".into()),
        };
        if let Err(e) = add_to_owner_index(&store, &owner_sub, handle) {
            return VaultResponse::Error(format!("kv owner index: {e}"));
        }
    }

    VaultResponse::KeyCreated {
        handle: handle.to_string(),
        expires_at,
    }
}
