// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Sealed Key-Value Store module for enclave-os.
//!
//! Both keys and values are encrypted inside the enclave using AES-256-GCM
//! before being stored on the host via OCALLs.  The encryption key is the
//! enclave-wide master key that lives in [`SealedConfig`] and is bound to
//! the enclave's code identity (MRENCLAVE).
//!
//! ## Usage
//!
//! In your custom `ecall_run`:
//!
//! ```rust,ignore
//! use enclave_os_kvstore::KvStoreModule;
//! use enclave_os_enclave::ecall::{init_enclave, finalize_and_run};
//! use enclave_os_enclave::modules::register_module;
//!
//! let (config, sealed_cfg) = init_enclave(config_json, config_len)?;
//!
//! let kvstore = KvStoreModule::new(sealed_cfg.master_key())?;
//! register_module(Box::new(kvstore));
//!
//! finalize_and_run(&config, &sealed_cfg);
//! ```

mod sealed;

use std::sync::{Mutex, OnceLock};

use enclave_os_common::modules::{EnclaveModule, RequestContext};
use enclave_os_common::protocol::{Request, Response};
use enclave_os_common::types::AEAD_KEY_SIZE;

pub use sealed::SealedKvStore;

// -------------------------------------------------------------------------
//  Global KV store
// -------------------------------------------------------------------------

static KV_STORE: OnceLock<Mutex<SealedKvStore>> = OnceLock::new();

/// Get the sealed KV store (returns `None` before module init).
pub fn kv_store() -> Option<&'static Mutex<SealedKvStore>> {
    KV_STORE.get()
}

// -------------------------------------------------------------------------
//  KvStoreModule
// -------------------------------------------------------------------------

pub struct KvStoreModule;

impl KvStoreModule {
    /// Construct the KV store module.
    ///
    /// Takes the enclave-wide master key from [`SealedConfig`] and creates
    /// the global [`SealedKvStore`] instance.
    pub fn new(master_key: [u8; AEAD_KEY_SIZE]) -> Result<Self, String> {
        let store = SealedKvStore::from_master_key(master_key);
        KV_STORE
            .set(Mutex::new(store))
            .map_err(|_| "KV store already initialised".to_string())?;

        Ok(KvStoreModule)
    }
}

impl EnclaveModule for KvStoreModule {
    fn name(&self) -> &str {
        "kvstore"
    }

    fn handle(&self, _req: &Request, _ctx: &RequestContext) -> Option<Response> {
        // KV is an internal service used by other modules.
        // Client-facing KV operations go through module-specific protocols.
        None
    }
}
