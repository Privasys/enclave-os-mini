// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Per-app certificate store with SNI-based resolution.
//!
//! Each registered app gets its own leaf X.509 certificate (signed by
//! the Enclave CA) containing:
//! - A per-app config Merkle root OID
//! - Any OID-flagged config entries as direct extensions
//! - An SGX quote (proving the enclave is genuine)
//!
//! Incoming TLS connections are routed to the correct certificate via
//! the SNI hostname in the ClientHello.
//!
//! ## Lifecycle
//!
//! 1. **Init** — [`init_cert_store()`] is called from `finalize_and_run()`
//!    after all modules are registered. Initial app identities are
//!    collected and registered.
//! 2. **Runtime** — Modules call [`cert_store().register()`] and
//!    [`cert_store().unregister()`] when apps are dynamically loaded
//!    or unloaded (e.g. WASM apps).
//! 3. **Connection** — The RA-TLS server calls [`cert_store().resolve()`]
//!    with the SNI hostname to get per-app certificate data for cert
//!    generation.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::{Arc, OnceLock, RwLock};
use std::vec::Vec;

use ring::digest;

use enclave_os_common::modules::{AppIdentity, ConfigEntry};
use crate::ratls::attestation::CaContext;

// ---------------------------------------------------------------------------
//  Global accessor
// ---------------------------------------------------------------------------

static CERT_STORE: OnceLock<CertStore> = OnceLock::new();

/// Get the global cert store.
///
/// # Panics
///
/// Panics if called before [`init_cert_store()`].
pub fn cert_store() -> &'static CertStore {
    CERT_STORE.get().expect("CertStore not initialised")
}

/// Initialise the global cert store. Called once from `finalize_and_run()`.
pub fn init_cert_store(store: CertStore) {
    let _ = CERT_STORE.set(store);
}

// ---------------------------------------------------------------------------
//  Per-app certificate data (snapshot for cert generation)
// ---------------------------------------------------------------------------

/// Snapshot of a registered app's certificate data.
///
/// Cloned from the store when the RA-TLS server needs to generate
/// a certificate for an incoming connection.
pub struct AppCertData {
    /// SNI hostname (used as Subject CN in the leaf certificate).
    pub hostname: String,
    /// Per-app config Merkle root (32-byte SHA-256).
    pub merkle_root: [u8; 32],
    /// Direct OID extensions extracted from config entries.
    ///
    /// Each tuple is `(OID arc sequence, raw value bytes)`.
    pub oid_extensions: Vec<(&'static [u64], Vec<u8>)>,
}

// ---------------------------------------------------------------------------
//  Registered app (internal)
// ---------------------------------------------------------------------------

/// A registered app with pre-computed Merkle tree data.
struct RegisteredApp {
    /// Per-app Merkle root.
    merkle_root: [u8; 32],
    /// Direct OID extensions from config entries.
    oid_extensions: Vec<(&'static [u64], Vec<u8>)>,
    /// Leaf manifest entries `(key, hash)` for auditing.
    #[allow(dead_code)]
    manifest: Vec<(String, [u8; 32])>,
}

// ---------------------------------------------------------------------------
//  CertStore
// ---------------------------------------------------------------------------

/// SNI-based certificate store for per-app RA-TLS certificates.
///
/// Thread-safe: uses an `RwLock` internally so that the RA-TLS server
/// can read while modules concurrently register/unregister apps.
pub struct CertStore {
    /// CA context for signing app leaf certificates.
    ca: Arc<CaContext>,
    /// Hostname → registered app data.
    inner: RwLock<BTreeMap<String, RegisteredApp>>,
}

impl CertStore {
    /// Create a new cert store with the given CA context.
    pub fn new(ca: Arc<CaContext>) -> Self {
        Self {
            ca,
            inner: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get the CA context (for cert generation).
    pub fn ca(&self) -> &Arc<CaContext> {
        &self.ca
    }

    /// Register an app identity.
    ///
    /// Computes the per-app Merkle tree from the identity's config
    /// entries and stores the result. If an app with the same hostname
    /// is already registered, it is replaced.
    pub fn register(&self, identity: AppIdentity) {
        let registered = Self::compute_app(&identity.config);
        if let Ok(mut inner) = self.inner.write() {
            inner.insert(identity.hostname, registered);
        }
    }

    /// Unregister an app by SNI hostname.
    ///
    /// Returns `true` if the app was found and removed.
    pub fn unregister(&self, hostname: &str) -> bool {
        if let Ok(mut inner) = self.inner.write() {
            inner.remove(hostname).is_some()
        } else {
            false
        }
    }

    /// Resolve an app by SNI hostname.
    ///
    /// Returns a cloned snapshot of the app's certificate data, or
    /// `None` if no app is registered for this hostname.
    pub fn resolve(&self, hostname: &str) -> Option<AppCertData> {
        let inner = self.inner.read().ok()?;
        let app = inner.get(hostname)?;
        Some(AppCertData {
            hostname: hostname.to_string(),
            merkle_root: app.merkle_root,
            oid_extensions: app.oid_extensions.clone(),
        })
    }

    /// List all registered hostnames.
    pub fn hostnames(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|inner| inner.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ---- Internal helpers -----------------------------------------------

    /// Compute per-app Merkle root + OID extensions from config entries.
    ///
    /// Merkle root = `SHA-256( SHA-256(e0.value) || SHA-256(e1.value) || … )`
    fn compute_app(config: &[ConfigEntry]) -> RegisteredApp {
        let mut leaf_hashes = Vec::with_capacity(config.len());
        let mut manifest = Vec::with_capacity(config.len());
        let mut oid_extensions = Vec::new();

        for entry in config {
            let d = digest::digest(&digest::SHA256, &entry.value);
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());

            manifest.push((entry.key.clone(), h));
            leaf_hashes.push(h);

            if let Some(oid) = entry.oid {
                oid_extensions.push((oid, entry.value.clone()));
            }
        }

        // Concatenate leaf hashes and compute root
        let merkle_root = if leaf_hashes.is_empty() {
            [0u8; 32]
        } else {
            let mut preimage = Vec::with_capacity(leaf_hashes.len() * 32);
            for h in &leaf_hashes {
                preimage.extend_from_slice(h);
            }
            let d = digest::digest(&digest::SHA256, &preimage);
            let mut root = [0u8; 32];
            root.copy_from_slice(d.as_ref());
            root
        };

        RegisteredApp {
            merkle_root,
            oid_extensions,
            manifest,
        }
    }
}
