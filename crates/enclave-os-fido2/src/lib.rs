// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! **FIDO2** — WebAuthn authenticator module for enclave-os.
//!
//! This module implements server-side FIDO2/WebAuthn registration and
//! authentication ceremonies inside the SGX enclave.  It pairs with the
//! Privasys Wallet mobile app, which acts as the FIDO2 authenticator.
//!
//! ## Architecture
//!
//! ```text
//! Phone (Privasys Wallet)
//!   ├─ RA-TLS connect + attestation verification
//!   ├─ POST /fido2/register/begin     → challenge
//!   ├─ POST /fido2/register/complete  → store credential
//!   ├─ POST /fido2/authenticate/begin → challenge
//!   └─ POST /fido2/authenticate/complete → verify signature
//!
//! Enclave (this module)
//!   ├─ Challenge generation (in-memory, TTL 5min)
//!   ├─ Credential storage (sealed KV, MRENCLAVE-bound)
//!   ├─ Session token issuance (in-memory, for browser auth)
//!   └─ AAGUID enforcement (only Privasys Wallet accepted)
//! ```
//!
//! ## Auth model
//!
//! After a successful FIDO2 ceremony:
//! - **Phone**: the RA-TLS session is marked as FIDO2-authenticated
//!   via `RaTlsSession.fido2_identity` (no token needed — TLS IS the
//!   authenticated channel)
//! - **Browser**: an opaque session token is issued and relayed to the
//!   browser via the auth broker. The browser sends it as
//!   `Authorization: Bearer <token>`.
//!
//! The existing OIDC JWT path remains unchanged. FIDO2 session tokens
//! and OIDC JWTs are parallel auth mechanisms.

pub mod challenge;
pub mod credentials;
pub mod sessions;
pub mod types;
pub mod webauthn;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};

use crate::challenge::Ceremony;
use crate::types::*;

// ---------------------------------------------------------------------------
//  Fido2Module
// ---------------------------------------------------------------------------

/// Enclave module implementing FIDO2/WebAuthn server-side ceremonies.
pub struct Fido2Module {
    /// Relying party ID (typically the app's SNI hostname).
    rp_id: String,
    /// Relying party display name.
    rp_name: String,
}

impl Fido2Module {
    /// Construct the FIDO2 module.
    ///
    /// `rp_id` is the relying party identifier (e.g. `"myapp.apps.privasys.org"`).
    /// `rp_name` is a human-readable name (e.g. `"My Application"`).
    pub fn new(rp_id: String, rp_name: String) -> Self {
        challenge::init();
        sessions::init();
        Self { rp_id, rp_name }
    }
}

impl EnclaveModule for Fido2Module {
    fn name(&self) -> &str {
        "fido2"
    }

    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response> {
        let data = match req {
            Request::Data(d) => d,
            _ => return None,
        };

        // Try to parse as Fido2Request — if it doesn't parse, this Data
        // isn't for us; let another module try.
        let fido2_req: Fido2Request = match serde_json::from_slice(data) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let fido2_resp = match fido2_req {
            Fido2Request::RegisterBegin {
                user_name,
                user_handle,
                browser_session_id,
            } => self.handle_register_begin(&user_name, &user_handle, browser_session_id),

            Fido2Request::RegisterComplete {
                challenge,
                attestation_object,
                client_data_json,
                credential_id,
                browser_session_id,
                push_token,
            } => self.handle_register_complete(
                &challenge,
                &attestation_object,
                &client_data_json,
                &credential_id,
                browser_session_id,
                push_token,
                ctx,
            ),

            Fido2Request::AuthenticateBegin {
                credential_id,
                browser_session_id,
            } => self.handle_authenticate_begin(credential_id.as_deref(), browser_session_id),

            Fido2Request::AuthenticateComplete {
                challenge,
                credential_id,
                authenticator_data,
                signature,
                client_data_json,
                browser_session_id,
            } => self.handle_authenticate_complete(
                &challenge,
                &credential_id,
                &authenticator_data,
                &signature,
                &client_data_json,
                browser_session_id,
                ctx,
            ),
        };

        match serde_json::to_vec(&fido2_resp) {
            Ok(bytes) => Some(Response::Data(bytes)),
            Err(e) => Some(Response::Error(
                format!("fido2: serialise response: {e}").into_bytes(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
//  Request handlers
// ---------------------------------------------------------------------------

impl Fido2Module {
    /// Handle `register_begin`: generate challenge + creation options.
    fn handle_register_begin(
        &self,
        user_name: &str,
        user_handle: &str,
        browser_session_id: Option<String>,
    ) -> Fido2Response {
        let now = current_time_secs();

        let challenge = match challenge::create_challenge(
            now,
            browser_session_id,
            Ceremony::Registration,
            Some(user_handle.to_string()),
            Some(user_name.to_string()),
        ) {
            Ok(c) => c,
            Err(e) => return Fido2Response::Error { error: e },
        };

        Fido2Response::RegisterOptions {
            challenge,
            rp: RelyingParty {
                id: self.rp_id.clone(),
                name: self.rp_name.clone(),
            },
            user: PublicKeyUser {
                id: user_handle.to_string(),
                name: user_name.to_string(),
                display_name: user_name.to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: COSE_ALG_ES256,
            }],
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: "platform".into(),
                resident_key: "required".into(),
                user_verification: "required".into(),
            },
            attestation: "direct".into(),
        }
    }

    /// Handle `register_complete`: verify attestation, store credential.
    fn handle_register_complete(
        &self,
        challenge_b64: &str,
        attestation_object_b64: &str,
        client_data_json_b64: &str,
        credential_id_b64: &str,
        browser_session_id: Option<String>,
        push_token: Option<String>,
        _ctx: &RequestContext,
    ) -> Fido2Response {
        let now = current_time_secs();

        // 1. Consume the challenge (one-time use)
        let consumed =
            match challenge::consume_challenge(challenge_b64, now, Ceremony::Registration) {
                Ok(c) => c,
                Err(e) => return Fido2Response::Error { error: e },
            };

        // Use the browser session ID from the challenge if the request didn't provide one
        let browser_session_id = browser_session_id.or(consumed.browser_session_id);
        let user_handle = consumed.user_handle.unwrap_or_default();
        let user_name = consumed.user_name.unwrap_or_default();

        // 2. Parse and verify clientDataJSON
        let (_client_data, _client_data_raw) = match webauthn::parse_client_data(
            client_data_json_b64,
            "webauthn.create",
            challenge_b64,
        ) {
            Ok(cd) => cd,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 3. Parse attestation object → extract authData
        let att_obj_bytes = match URL_SAFE_NO_PAD.decode(attestation_object_b64) {
            Ok(b) => b,
            Err(e) => return Fido2Response::Error { error: format!("attestation_object base64: {e}") },
        };

        let auth_data_bytes = match webauthn::parse_attestation_object(&att_obj_bytes) {
            Ok(ad) => ad,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 4. Parse authenticator data
        let auth_data = match webauthn::parse_authenticator_data(&auth_data_bytes) {
            Ok(ad) => ad,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 5. Verify flags: UP and UV must be set
        if !auth_data.user_present() {
            return Fido2Response::Error { error: "user not present".into() };
        }
        if !auth_data.user_verified() {
            return Fido2Response::Error { error: "user not verified".into() };
        }

        // 6. Extract attested credential data
        let attested = match auth_data.attested_credential {
            Some(ref ac) => ac,
            None => return Fido2Response::Error { error: "missing attested credential data".into() },
        };

        // 7. Verify rpIdHash
        let expected_rp_hash = webauthn::sha256(self.rp_id.as_bytes());
        if auth_data.rp_id_hash[..] != expected_rp_hash[..] {
            return Fido2Response::Error { error: "rpIdHash mismatch".into() };
        }

        // 8. Check AAGUID against allowlist
        match credentials::is_aaguid_allowed(&attested.aaguid) {
            Ok(true) => {}
            Ok(false) => {
                let hex: String = attested.aaguid.iter().map(|b| format!("{b:02x}")).collect();
                return Fido2Response::Error {
                    error: format!("authenticator AAGUID {hex} not in allowlist"),
                };
            }
            Err(e) => return Fido2Response::Error { error: e },
        }

        // 9. Extract P-256 public key from COSE key
        let public_key_raw = match webauthn::extract_p256_public_key(&attested.credential_public_key_cbor) {
            Ok(pk) => pk,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 10. Verify credential ID matches what the client reported
        let reported_cred_id = match URL_SAFE_NO_PAD.decode(credential_id_b64) {
            Ok(b) => b,
            Err(e) => return Fido2Response::Error { error: format!("credential_id base64: {e}") },
        };
        if attested.credential_id != reported_cred_id {
            return Fido2Response::Error { error: "credential ID mismatch".into() };
        }

        // 11. Store credential
        let aaguid_hex: String = attested.aaguid.iter().map(|b| format!("{b:02x}")).collect();
        let record = CredentialRecord {
            user_handle: user_handle.clone(),
            user_name,
            public_key_cose: URL_SAFE_NO_PAD.encode(&attested.credential_public_key_cbor),
            public_key_raw: URL_SAFE_NO_PAD.encode(&public_key_raw),
            aaguid: aaguid_hex,
            sign_count: auth_data.sign_count,
            created_at: now,
            rp_id: self.rp_id.clone(),
            push_token,
        };

        if let Err(e) = credentials::store_credential(&record, credential_id_b64) {
            return Fido2Response::Error { error: e };
        }

        // 12. Issue session token for browser (if browser_session_id provided)
        let session_token = match browser_session_id {
            Some(ref sid) => {
                match sessions::issue_token(now, &user_handle, credential_id_b64, sid) {
                    Ok(token) => Some(token),
                    Err(e) => return Fido2Response::Error { error: e },
                }
            }
            None => None,
        };

        Fido2Response::RegisterOk {
            status: "ok".into(),
            session_token,
        }
    }

    /// Handle `authenticate_begin`: generate challenge.
    fn handle_authenticate_begin(
        &self,
        credential_id_b64: Option<&str>,
        browser_session_id: Option<String>,
    ) -> Fido2Response {
        let now = current_time_secs();

        let challenge = match challenge::create_challenge(
            now,
            browser_session_id,
            Ceremony::Authentication,
            None,
            None,
        ) {
            Ok(c) => c,
            Err(e) => return Fido2Response::Error { error: e },
        };

        let allow_credentials = match credential_id_b64 {
            Some(cid) => vec![AllowCredential {
                cred_type: "public-key".into(),
                id: cid.to_string(),
            }],
            None => Vec::new(),
        };

        Fido2Response::AuthenticateOptions {
            challenge,
            allow_credentials,
            user_verification: "required".into(),
        }
    }

    /// Handle `authenticate_complete`: verify assertion.
    fn handle_authenticate_complete(
        &self,
        challenge_b64: &str,
        credential_id_b64: &str,
        authenticator_data_b64: &str,
        signature_b64: &str,
        client_data_json_b64: &str,
        browser_session_id: Option<String>,
        _ctx: &RequestContext,
    ) -> Fido2Response {
        let now = current_time_secs();

        // 1. Consume the challenge
        let consumed =
            match challenge::consume_challenge(challenge_b64, now, Ceremony::Authentication) {
                Ok(c) => c,
                Err(e) => return Fido2Response::Error { error: e },
            };

        let browser_session_id = browser_session_id.or(consumed.browser_session_id);

        // 2. Parse and verify clientDataJSON
        let (_client_data, client_data_raw) = match webauthn::parse_client_data(
            client_data_json_b64,
            "webauthn.get",
            challenge_b64,
        ) {
            Ok(cd) => cd,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 3. Load the stored credential
        let record = match credentials::load_credential(credential_id_b64) {
            Ok(Some(r)) => r,
            Ok(None) => return Fido2Response::Error { error: "unknown credential".into() },
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 4. Decode authenticator data
        let auth_data_bytes = match URL_SAFE_NO_PAD.decode(authenticator_data_b64) {
            Ok(b) => b,
            Err(e) => return Fido2Response::Error { error: format!("authenticator_data base64: {e}") },
        };

        let auth_data = match webauthn::parse_authenticator_data(&auth_data_bytes) {
            Ok(ad) => ad,
            Err(e) => return Fido2Response::Error { error: e },
        };

        // 5. Verify flags
        if !auth_data.user_present() {
            return Fido2Response::Error { error: "user not present".into() };
        }
        if !auth_data.user_verified() {
            return Fido2Response::Error { error: "user not verified".into() };
        }

        // 6. Verify rpIdHash
        let expected_rp_hash = webauthn::sha256(self.rp_id.as_bytes());
        if auth_data.rp_id_hash[..] != expected_rp_hash[..] {
            return Fido2Response::Error { error: "rpIdHash mismatch".into() };
        }

        // 7. Verify sign count (monotonically increasing)
        if auth_data.sign_count != 0 && auth_data.sign_count <= record.sign_count {
            return Fido2Response::Error {
                error: "sign count not increasing — possible cloned authenticator".into(),
            };
        }

        // 8. Verify signature
        //    signed_data = authenticator_data_bytes || SHA-256(clientDataJSON)
        let client_data_hash = webauthn::sha256(&client_data_raw);
        let mut signed_data = auth_data_bytes.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let sig_bytes = match URL_SAFE_NO_PAD.decode(signature_b64) {
            Ok(b) => b,
            Err(e) => return Fido2Response::Error { error: format!("signature base64: {e}") },
        };

        let public_key_bytes = match URL_SAFE_NO_PAD.decode(&record.public_key_raw) {
            Ok(b) => b,
            Err(e) => return Fido2Response::Error { error: format!("stored public key base64: {e}") },
        };

        if let Err(e) = webauthn::verify_signature(&public_key_bytes, &signed_data, &sig_bytes) {
            return Fido2Response::Error { error: e };
        }

        // 9. Update sign count
        if let Err(e) = credentials::update_credential(credential_id_b64, auth_data.sign_count, None) {
            // Log but don't fail — the auth succeeded
            let _ = e;
        }

        // 10. Issue session token for browser
        let session_token = match browser_session_id {
            Some(ref sid) => {
                match sessions::issue_token(now, &record.user_handle, credential_id_b64, sid) {
                    Ok(token) => Some(token),
                    Err(e) => return Fido2Response::Error { error: e },
                }
            }
            None => None,
        };

        Fido2Response::AuthenticateOk {
            status: "ok".into(),
            session_token,
        }
    }
}

// ---------------------------------------------------------------------------
//  Time helper
// ---------------------------------------------------------------------------

/// Get the current UNIX timestamp (seconds) via OCall.
fn current_time_secs() -> u64 {
    enclave_os_common::ocall::get_current_time().unwrap_or(0)
}
