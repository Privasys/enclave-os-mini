// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Guards the feature wiring that authentication depends on.
//!
//! This exists because of a real defect, not a hypothetical one. JWT signature
//! verification used to be gated on the `wasm` feature while the JWKS fetcher
//! actually lives behind `egress`. The `vault` composition enables `egress` but
//! not `wasm`, so it verified no signatures at all while authorizing key
//! operations from the claims — see the 2026-09-17 disclosure.
//!
//! No unit test of the crypto could have caught that: the verifier itself was
//! correct and well covered (`common/src/jwt.rs` rejects wrong keys, tampered
//! payloads and `alg:none`). It simply was never called. The invariant that was
//! broken is a property of `enclave/Cargo.toml`, so that is what is asserted
//! here.

#[cfg(test)]
mod tests {
    /// Features of the `enclave` crate that expose an OIDC-authenticated
    /// surface, and therefore MUST pull in a trusted key source.
    ///
    /// Adding a composition that authenticates users means adding it here.
    const AUTHENTICATING_FEATURES: &[&str] = &["vault", "wasm"];

    /// The feature carrying the JWKS fetcher (`enclave_os_egress::jwks`).
    const KEY_SOURCE_FEATURE: &str = "egress";

    fn feature_line(manifest: &str, feature: &str) -> Option<String> {
        manifest
            .lines()
            .map(str::trim)
            .find(|l| {
                l.starts_with(feature)
                    && l[feature.len()..].trim_start().starts_with('=')
            })
            .map(str::to_string)
    }

    #[test]
    fn every_authenticating_feature_enables_a_trusted_key_source() {
        let manifest = include_str!("../../../enclave/Cargo.toml");

        for feature in AUTHENTICATING_FEATURES {
            let line = feature_line(manifest, feature).unwrap_or_else(|| {
                panic!(
                    "enclave/Cargo.toml no longer defines the `{feature}` feature; \
                     if it was renamed, update AUTHENTICATING_FEATURES"
                )
            });

            assert!(
                line.contains(KEY_SOURCE_FEATURE),
                "feature `{feature}` does not enable `{KEY_SOURCE_FEATURE}`.\n\
                 Its line is: {line}\n\
                 A build that authenticates OIDC bearers without `{KEY_SOURCE_FEATURE}` \
                 has no trusted key source, so it cannot verify a token's signature. \
                 That is exactly the shape of the 2026-09-17 vault finding. Either \
                 enable `{KEY_SOURCE_FEATURE}`, or remove `{feature}` from \
                 AUTHENTICATING_FEATURES if it no longer authenticates anyone."
            );
        }
    }

    /// The refusing arm must stay reachable: if `egress` ever becomes
    /// unconditional, the `cfg(not(feature = "egress"))` branch in
    /// `verify_oidc_token` becomes dead and the guard above becomes vacuous.
    #[test]
    fn egress_is_still_an_optional_feature() {
        let manifest = include_str!("../../../enclave/Cargo.toml");
        assert!(
            feature_line(&manifest, KEY_SOURCE_FEATURE).is_some(),
            "`{KEY_SOURCE_FEATURE}` is no longer a declared feature of the enclave \
             crate; the cfg-gated refusal in verify_oidc_token needs revisiting"
        );
    }
}
