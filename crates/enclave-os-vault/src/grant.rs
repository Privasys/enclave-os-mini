// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Key-creation grants.
//!
//! A grant is an IdP-issued JWT (`aud = privasys-vault-keycreate`) presented in
//! [`crate::types::VaultRequest::CreateKey`]. It carries the key's owner, scope,
//! type, exportable flag and full policy, so a caller (an app TEE or CLI agent)
//! that holds the material but is not the owner can still create the key in a
//! single call. The caller cannot forge or alter the grant; the vault binds it
//! either to a holder-of-key `cnf`, or to a TEE the grant's own policy names
//! whose app-id (OID 3.6) equals the scope's. Either way the caller proves it:
//! the ingress server checks the handshake signature against the presented
//! certificate, and a TEE also presents evidence for that certificate's key on
//! this connection.

use std::string::String;
use std::vec::Vec;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use enclave_os_common::modules::RequestContext;
use enclave_os_common::oids::APP_ID_OID_STR;

use crate::policy::tee_matches;
use crate::types::{KeyPolicy, KeyType, Principal};

/// Dedicated audience: distinguishes a key-creation grant from an access token.
pub const GRANT_AUDIENCE: &str = "privasys-vault-keycreate";

/// Holder-of-key confirmation: the base64url SHA-256 thumbprint of the caller's
/// RA-TLS leaf certificate (DER).
#[derive(Debug, Clone, Deserialize)]
pub struct Cnf {
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

/// Claims of a verified key-creation grant.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyCreationGrant {
    pub iss: String,
    pub aud: String,
    /// The owner: the privasys.id `sub` that holds governance of the key.
    pub sub: String,
    /// Key namespace the grant authorises, e.g. `apps.privasys.org/<app-id>`
    /// or `users/<sub>`. The handle must fall under it.
    pub scope: String,
    pub key_type: KeyType,
    pub exportable: bool,
    pub policy: KeyPolicy,
    pub exp: u64,
    #[serde(default)]
    pub cnf: Option<Cnf>,
}

/// Verify a key-creation grant and bind it to the caller.
///
/// Verifies the JWT signature against the IdP JWKS, checks the issuer,
/// audience and expiry, then binds the grant to the caller (see [`bind_caller`]).
pub fn verify_grant(
    grant_jwt: &str,
    ctx: &RequestContext,
    now: u64,
) -> Result<KeyCreationGrant, String> {
    let cfg = enclave_os_common::oidc::global_oidc_config()
        .ok_or_else(|| "OIDC is not configured; cannot verify a key-creation grant".to_string())?;

    let grant: KeyCreationGrant =
        enclave_os_egress::jwks::verify_jwt_with_jwks(grant_jwt, &cfg.issuer, &cfg.jwks_uri)
            .map_err(|e| format!("key-creation grant verification failed: {e}"))?;

    if grant.iss != cfg.issuer {
        return Err(format!("grant issuer mismatch (got '{}')", grant.iss));
    }
    if grant.aud != GRANT_AUDIENCE {
        return Err(format!(
            "grant audience must be '{GRANT_AUDIENCE}' (got '{}')",
            grant.aud
        ));
    }
    if now >= grant.exp {
        return Err("key-creation grant has expired".into());
    }

    bind_caller(&grant, ctx)?;

    Ok(grant)
}

/// Bind the grant to the caller.
///
/// A grant is only as strong as this binding: whoever passes it creates the
/// key, with material of their choosing, under the grant's policy. Possession
/// of a certificate is not enough, since certificate bytes are not secret.
///
///   - **Holder-of-key** (`cnf`, e.g. an owner's CLI): the caller's certificate
///     thumbprint equals `cnf.x5t#S256`. The ingress server has verified the
///     handshake signature against that certificate's key, so the caller holds
///     the private key.
///   - **TEE**: the caller is a TEE that the grant's own policy names, proven by
///     evidence presented on this connection for this certificate's key, and the
///     certificate's app-id (OID 3.6) equals the scope's. These are the checks
///     export applies to the same policy later, so the TEE that will use the key
///     is the only one that can create it. The app-id is trustworthy once the
///     key is: the measured runtime is the only minter of its certificates.
fn bind_caller(grant: &KeyCreationGrant, ctx: &RequestContext) -> Result<(), String> {
    let peer_der = ctx
        .peer_cert_der
        .as_deref()
        .ok_or_else(|| "key creation requires a mutual-RA-TLS peer certificate".to_string())?;

    if let Some(cnf) = &grant.cnf {
        let thumb = URL_SAFE_NO_PAD.encode(sha256(peer_der));
        if thumb == cnf.x5t_s256 {
            return Ok(());
        }
        return Err(
            "grant cnf (holder-of-key) does not match the caller's RA-TLS certificate".into(),
        );
    }

    // The certificate's app-id against the scope first: cheap, and it needs no
    // network. The certificate is only parsed here; the TEE check below is what
    // makes its claims trustworthy.
    let evidence = crate::quote::dissect_peer_cert(peer_der, &[])?;
    let caller_app_id = evidence
        .oid_claims
        .iter()
        .find(|(oid, _)| oid == APP_ID_OID_STR)
        .map(|(_, value)| value.clone())
        .ok_or_else(|| {
            "caller RA-TLS certificate has no app-id (OID 3.6) and the grant has no cnf binding"
                .to_string()
        })?;
    let scope_app_id = scope_app_id(&grant.scope).ok_or_else(|| {
        format!(
            "grant scope '{}' carries no app-id and the grant has no cnf binding",
            grant.scope
        )
    })?;
    // Case-insensitive is safe here, and not a way for two apps to share one
    // grant: an app-id is a UUID rendered as canonical lowercase hex
    // ([0-9a-f]{32}, AppIDHex in the runtime, the same encoding the IdP pins
    // roles to), so no two distinct app-ids differ only by case. Folding case
    // only tolerates a mis-cased grant scope naming the same single app.
    if !caller_app_id.eq_ignore_ascii_case(scope_app_id) {
        return Err(format!(
            "caller app-id {caller_app_id} does not match grant scope app-id {scope_app_id}"
        ));
    }

    if ctx.peer_evidence.is_none() {
        return Err("key creation under a TEE grant requires evidence on this connection".into());
    }
    let policy = crate::normalise_policy(grant.policy.clone());
    let named_tee = policy.principals.tees.iter().any(|p| match p {
        Principal::Tee(profile) => tee_matches(profile, peer_der, ctx.peer_evidence.as_ref()),
        _ => false,
    });
    if !named_tee {
        return Err("the caller is not a TEE the grant's policy names".into());
    }
    Ok(())
}

/// The app-id segment of an `apps.privasys.org/<app-id>` scope, or `None`.
fn scope_app_id(scope: &str) -> Option<&str> {
    scope.strip_prefix("apps.privasys.org/")
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}
