// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! JWKS-based JWT verification.
//!
//! The fetch+cache implementation lives in `enclave-os-egress` (it needs
//! `https_fetch`, and both this crate and the vault crate depend on egress).
//! Re-exported here so existing `crate::jwks_fetcher::…` call-sites keep working.

pub use enclave_os_egress::jwks::{idp_ec_p256_keys, verify_jwt_signature, verify_jwt_with_jwks};
