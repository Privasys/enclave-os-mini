// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Module trait and shared types.
//!
//! This module defines the [`EnclaveModule`] trait and its associated types.
//! Module crates implement this trait; the enclave core registers instances
//! at startup and dispatches incoming requests to them.
//!
//! These types live in `common` (rather than in the enclave crate) to
//! avoid a cyclic dependency: module crates implement the trait and
//! the enclave crate optionally pulls them in as feature-gated deps.

use crate::protocol::{Request, Response};

// ---------------------------------------------------------------------------
//  Config Merkle leaf
// ---------------------------------------------------------------------------

/// A named leaf for the configuration Merkle tree.
///
/// Each leaf is SHA-256 hashed and concatenated to produce the Merkle root
/// that gets embedded in every RA-TLS certificate.
pub struct ConfigLeaf {
    /// Stable, human-readable identifier (e.g. `"core.ca_cert"`).
    pub name: String,
    /// Raw bytes to hash. `None` means the input is absent (leaf = 32 zero bytes).
    pub data: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
//  Module OID
// ---------------------------------------------------------------------------

/// A custom X.509 OID extension registered by a module.
///
/// Each OID is embedded as a non-critical extension in every RA-TLS leaf
/// certificate, allowing clients to verify individual module properties
/// without computing the full config Merkle tree.
pub struct ModuleOid {
    /// OID arc sequence (e.g. `&[1, 3, 6, 1, 4, 1, 65230, 2, 1]`).
    pub oid: &'static [u64],
    /// Raw extension value bytes.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Per-app identity types
// ---------------------------------------------------------------------------

/// A configuration entry declared by a module or app at init time.
///
/// Each entry is SHA-256 hashed and included in the app's per-identity
/// Merkle tree. Entries flagged with an [`oid`](Self::oid) are also
/// embedded as direct X.509 extensions in the app's certificate for
/// fast-path verification.
pub struct ConfigEntry {
    /// Human-readable key (e.g. `"code_hash"`, `"policy_version"`).
    pub key: String,
    /// Raw value bytes (SHA-256 hashed into the Merkle tree).
    pub value: Vec<u8>,
    /// If `Some`, also embed this entry as a direct X.509 OID extension.
    pub oid: Option<&'static [u64]>,
}

/// Identity of an app endpoint that gets its own X.509 certificate.
///
/// Each identity is served via SNI-based TLS routing.
pub struct AppIdentity {
    /// SNI hostname this app responds to (e.g. `"payments.example.com"`).
    pub hostname: String,
    /// Configuration entries for this app's Merkle tree.
    pub config: Vec<ConfigEntry>,
}

// ---------------------------------------------------------------------------
//  Request context
// ---------------------------------------------------------------------------

/// Per-request context passed to [`EnclaveModule::handle()`].
///
/// Carries optional metadata extracted from the TLS session and OIDC auth.
pub struct RequestContext {
    /// DER-encoded leaf certificate presented by the TLS client.
    ///
    /// `Some(…)` when the client provided a certificate during the TLS
    /// handshake (mutual RA-TLS). `None` for regular browser clients.
    pub peer_cert_der: Option<Vec<u8>>,

    /// Random nonce sent to the client via the TLS CertificateRequest
    /// extension `0xFFBB` for bidirectional challenge-response attestation.
    pub client_challenge_nonce: Option<Vec<u8>>,

    /// Verified OIDC claims extracted from the `"auth"` field in the
    /// JSON envelope.  `None` when no bearer token was provided (e.g.
    /// healthz, or RA-TLS-only vault GetSecret).
    pub oidc_claims: Option<crate::oidc::OidcClaims>,
}

// ---------------------------------------------------------------------------
//  EnclaveModule trait
// ---------------------------------------------------------------------------

/// Trait for pluggable enclave business logic modules.
pub trait EnclaveModule: Send + Sync {
    /// Human-readable module name (used as config leaf prefix).
    fn name(&self) -> &str;

    /// Handle a client request. Returns `Some(response)` if handled.
    fn handle(&self, req: &Request, ctx: &RequestContext) -> Option<Response>;

    /// Config leaves to include in the configuration Merkle tree.
    ///
    /// Called once during enclave init.
    fn config_leaves(&self) -> Vec<ConfigLeaf> {
        Vec::new()
    }

    /// Custom X.509 OIDs to embed in RA-TLS certificates.
    fn custom_oids(&self) -> Vec<ModuleOid> {
        Vec::new()
    }

    /// App identities for per-app X.509 certificates.
    fn app_identities(&self) -> Vec<AppIdentity> {
        Vec::new()
    }

    /// Enrich enclave-level metrics with module-specific data.
    ///
    /// Called by the `Metrics` handler.  Modules can fill in their
    /// own fields (e.g. WASM fuel counters) and perform side-effects
    /// like snapshotting metrics to the sealed KV store.
    fn enrich_metrics(&self, _metrics: &mut crate::protocol::EnclaveMetrics) {}
}
