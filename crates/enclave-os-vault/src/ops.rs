// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Operations that use a key: export, wrap, unwrap, sign and MAC, each gated by the key's policy.

use super::*;

pub(crate) fn handle_export(
    handle: &str,
    binding: Option<BindingV2Request>,
    ctx: &RequestContext,
) -> VaultResponse {
    let mut record = match load_for(handle, ctx) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if expired(&record) {
        return VaultResponse::Error("key has expired".into());
    }
    if !record.exportable {
        return VaultResponse::Error("key is not exportable".into());
    }
    let caller = caller_str(ctx);
    // Export has no canonical target measurement (unlike promote), so an
    // `OidcStepUp { operation_bound }` condition binds the empty measurement
    // slot: (handle, "", policy_version, nonce, exp). The empty measurement can
    // never collide with a promote binding (which always carries a non-empty
    // profile digest), so a captured promote approval cannot be replayed to
    // export the same handle, and vice versa.
    let op_binding = crate::policy::OpBinding {
        measurement_digest_hex: String::new(),
        policy_version: record.policy_version,
        v1: true,
        v2: Some(crate::policy::OpBindingV2 {
            op: "export",
            target: Ok("-".into()),
            members: binding.map(|b| b.members),
        }),
    };
    match evaluate_op(
        &record.policy,
        Operation::ExportKey,
        handle,
        ctx,
        Some(&op_binding),
    ) {
        Ok(()) => {
            let _ = audit_and_save(
                &mut record,
                "ExportKey",
                &caller,
                AuditDecision::Allowed,
                "",
            );
            VaultResponse::KeyMaterial {
                material: record.material,
                expires_at: record.expires_at,
            }
        }
        Err(e) => {
            let _ = audit_denial(ctx, &mut record, "ExportKey", &caller, AuditDecision::Denied, &e);
            VaultResponse::Error(e)
        }
    }
}
/// Shared prelude: load record, check not expired, check key_type matches,
/// run policy with conditions, audit, and on success return the record.
pub(crate) fn require_op(
    handle: &str,
    op: Operation,
    expect_type: KeyType,
    ctx: &RequestContext,
) -> Result<KeyRecord, VaultResponse> {
    let mut record = load_for(handle, ctx)?;
    if expired(&record) {
        let _ = audit_denial(ctx, 
            &mut record,
            op_name(op),
            &caller_str(ctx),
            AuditDecision::Denied,
            "key has expired",
        );
        return Err(VaultResponse::Error("key has expired".into()));
    }
    if record.key_type != expect_type {
        let msg = format!(
            "key {} has type {:?}, op {:?} requires {:?}",
            handle, record.key_type, op, expect_type
        );
        let _ = audit_denial(ctx, 
            &mut record,
            op_name(op),
            &caller_str(ctx),
            AuditDecision::Denied,
            &msg,
        );
        return Err(VaultResponse::Error(msg));
    }
    let caller = caller_str(ctx);
    if let Err(e) = evaluate_op(&record.policy, op, handle, ctx, None) {
        let _ = audit_denial(ctx, &mut record, op_name(op), &caller, AuditDecision::Denied, &e);
        return Err(VaultResponse::Error(e));
    }
    // Having served, a pending threshold key can no longer be aborted.
    record.pending_creation = None;
    if let Err(e) = audit_and_save(
        &mut record,
        op_name(op),
        &caller,
        AuditDecision::Allowed,
        "",
    ) {
        return Err(e);
    }
    Ok(record)
}

pub(crate) fn op_name(op: Operation) -> &'static str {
    match op {
        Operation::ExportKey => "ExportKey",
        Operation::DeleteKey => "DeleteKey",
        Operation::UpdatePolicy => "UpdatePolicy",
        Operation::Wrap => "Wrap",
        Operation::Unwrap => "Unwrap",
        Operation::Sign => "Sign",
        Operation::Mac => "Mac",
        Operation::PromoteProfile => "PromoteProfile",
    }
}

pub(crate) fn handle_wrap(
    handle: &str,
    plaintext_b64: &str,
    aad_b64: Option<&str>,
    iv_b64: Option<&str>,
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Wrap,
        KeyType::Aes256GcmKey,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let plaintext = match URL_SAFE_NO_PAD.decode(plaintext_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("plaintext base64: {e}")),
    };
    let aad = match aad_b64 {
        Some(s) => match URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("aad base64: {e}")),
        },
        None => Vec::new(),
    };
    // A caller-chosen nonce is refused: see the `Wrap` doc comment. Fail
    // loudly rather than ignoring the field, so a client that believes it is
    // fixing the nonce never receives a ciphertext under a different one.
    if iv_b64.is_some() {
        return VaultResponse::Error(
            "wrap does not accept a caller-supplied iv: the vault generates the nonce \
             and returns it (GCM nonce reuse breaks confidentiality and authenticity)"
                .to_string(),
        );
    }
    match crypto::aes_gcm_seal(&record.material, &plaintext, &aad) {
        Ok((ciphertext, iv)) => VaultResponse::Wrapped { ciphertext, iv },
        Err(e) => VaultResponse::Error(e),
    }
}

pub(crate) fn handle_unwrap(
    handle: &str,
    ciphertext_b64: &str,
    iv_b64: &str,
    aad_b64: Option<&str>,
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Unwrap,
        KeyType::Aes256GcmKey,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let ciphertext = match URL_SAFE_NO_PAD.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("ciphertext base64: {e}")),
    };
    let iv = match URL_SAFE_NO_PAD.decode(iv_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("iv base64: {e}")),
    };
    let aad = match aad_b64 {
        Some(s) => match URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => b,
            Err(e) => return VaultResponse::Error(format!("aad base64: {e}")),
        },
        None => Vec::new(),
    };
    match crypto::aes_gcm_open(&record.material, &ciphertext, &iv, &aad) {
        Ok(plaintext) => VaultResponse::Unwrapped { plaintext },
        Err(e) => VaultResponse::Error(e),
    }
}

pub(crate) fn handle_sign(
    handle: &str,
    message_b64: &str,
    prehashed: bool,
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Sign,
        KeyType::P256SigningKey,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let message = match URL_SAFE_NO_PAD.decode(message_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("message base64: {e}")),
    };
    // prehashed: `message` is a 32-byte SHA-256 digest, signed raw (CKM_ECDSA);
    // otherwise the vault hashes the message (ECDSA-P256-SHA256).
    let result = if prehashed {
        crypto::p256_sign_prehash(&record.material, &message)
    } else {
        crypto::p256_sign(&record.material, &message)
    };
    match result {
        Ok(signature) => VaultResponse::Signature {
            signature,
            alg: "ES256",
        },
        Err(e) => VaultResponse::Error(e),
    }
}

pub(crate) fn handle_mac(
    handle: &str,
    message_b64: &str,
    ctx: &RequestContext,
) -> VaultResponse {
    let record = match require_op(
        handle,
        Operation::Mac,
        KeyType::HmacSha256Key,
        ctx,
    ) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let message = match URL_SAFE_NO_PAD.decode(message_b64) {
        Ok(b) => b,
        Err(e) => return VaultResponse::Error(format!("message base64: {e}")),
    };
    let mac = crypto::hmac_sha256(&record.material, &message);
    VaultResponse::MacTag {
        mac,
        alg: "HMAC-SHA-256",
    }
}
