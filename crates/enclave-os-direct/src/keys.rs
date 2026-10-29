// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The ACME account key.
//!
//! Derived in two steps, identical to the container runtime so the same
//! scheme holds on every enclave kind:
//!
//! 1. the direct-TLS branch of the app's vault-held key:
//!    HKDF-SHA256(secret, salt = `privasys-direct-tls/v1`, info = `branch`);
//! 2. the account key from the branch:
//!    HKDF-SHA256(branch, no salt, info = `privasys-acme-account/v1|<i>`) for
//!    i = 0, 1, ... until the 32 bytes are a valid P-256 scalar.
//!
//! Changing either label changes every app's ACME account, which breaks
//! every CAA record that pins one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdsa::SigningKey;
use p256::SecretKey;
use sha2::{Digest, Sha256};

/// HKDF salt of the direct-TLS branch.
pub const BRANCH_LABEL: &str = "privasys-direct-tls/v1";
/// HKDF info prefix of the account key.
pub const ACCOUNT_LABEL: &str = "privasys-acme-account/v1";

/// The direct-TLS branch of an app's vault-held key. One-way: the branch
/// never reveals the key.
pub fn direct_branch(secret: &[u8]) -> Result<[u8; 32], String> {
    if secret.is_empty() {
        return Err("direct: no app key (the app has no vault-held key)".into());
    }
    let hk = Hkdf::<Sha256>::new(Some(BRANCH_LABEL.as_bytes()), secret);
    let mut out = [0u8; 32];
    hk.expand(b"branch", &mut out).map_err(|_| "direct: hkdf expand".to_string())?;
    Ok(out)
}

/// The ACME account key from the direct-TLS branch.
pub fn account_key(branch: &[u8]) -> Result<AccountKey, String> {
    if branch.is_empty() {
        return Err("direct: no key branch".into());
    }
    let hk = Hkdf::<Sha256>::new(None, branch);
    for i in 0..16 {
        let mut raw = [0u8; 32];
        hk.expand(format!("{ACCOUNT_LABEL}|{i}").as_bytes(), &mut raw)
            .map_err(|_| "direct: hkdf expand".to_string())?;
        if let Ok(secret) = SecretKey::from_slice(&raw) {
            return Ok(AccountKey { signing: SigningKey::from(secret) });
        }
    }
    Err("direct: no valid account key derived".into())
}

/// An ACME account key.
#[derive(Clone)]
pub struct AccountKey {
    pub(crate) signing: SigningKey,
}

impl AccountKey {
    /// The uncompressed public point coordinates (x, y), 32 bytes each.
    pub fn coordinates(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.signing.verifying_key().to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().expect("uncompressed point"));
        y.copy_from_slice(point.y().expect("uncompressed point"));
        (x, y)
    }

    /// The public JWK, members in the lexicographic order RFC 7638 requires.
    pub fn jwk(&self) -> serde_json::Value {
        let (x, y) = self.coordinates();
        serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// The RFC 7638 JWK thumbprint, base64url: the second half of every key
    /// authorization.
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y)
        );
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// The key authorization of a challenge token (RFC 8555 section 8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_key_is_stable_per_app_key() {
        let a = account_key(&direct_branch(b"app-one-key-0000000000000000000").unwrap()).unwrap();
        let a2 = account_key(&direct_branch(b"app-one-key-0000000000000000000").unwrap()).unwrap();
        let b = account_key(&direct_branch(b"app-two-key-0000000000000000000").unwrap()).unwrap();
        assert_eq!(a.coordinates(), a2.coordinates(), "upgrades keep the account (CAA pins it)");
        assert_ne!(a.coordinates(), b.coordinates(), "two apps never share an account");
        assert!(direct_branch(b"").is_err(), "no app key, no account");
    }

    /// The same derivation as the container runtime (Go: crypto/hkdf), so a
    /// given app key yields the same account on either enclave kind. The
    /// vector was produced with the Go implementation.
    #[test]
    fn matches_the_container_runtime() {
        let branch = direct_branch(&[0x11u8; 32]).unwrap();
        let key = account_key(&branch).unwrap();
        let (x, _) = key.coordinates();
        assert_eq!(hex(&branch), GO_BRANCH);
        assert_eq!(hex(&x), GO_X);
    }

    const GO_BRANCH: &str = "62197995fca676a99c0d2598c1ed744907c7fe5e00b6c46e80a0068f37c51911";
    const GO_X: &str = "87d8038d04127a15a1a549849eb725694e04460696c8ec249e4c235029ea7bd2";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|v| format!("{v:02x}")).collect()
    }

    #[test]
    fn thumbprint_is_rfc7638() {
        let key = account_key(&[7u8; 32]).unwrap();
        let jwk = key.jwk();
        let canonical = serde_json::to_string(&jwk).unwrap();
        // serde_json keeps insertion order with preserve_order off by sorting
        // keys alphabetically, which is exactly RFC 7638's order here.
        assert_eq!(
            key.thumbprint(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
        );
        assert!(key.key_authorization("tok").starts_with("tok."));
    }
}
