// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/sealing@0.1.0` — version-bound sovereign sealing
//! keys (the sovereign-data framework, Phase 1).
//!
//! | Function | Purpose |
//! |----------|---------|
//! | `get-seal-key()` | The calling app's CURRENT sealing key S_N and the code hash it is bound to. |
//!
//! S_N is derived from the MRENCLAVE-sealed runtime root and the calling
//! app's own code hash (OID 3.2), so a new wasm build receives a
//! DIFFERENT key. An app keeps each data owner's wallet-delivered key
//! element W wrapped under S_N: after an upgrade the wrap is unreadable
//! until the owner's wallet re-delivers W — an app upgrade is a consent
//! boundary for user-owned data. Apps should record the returned code
//! hash beside anything they seal, so a later version can name which S_N
//! a blob needs.
//!
//! Refused during ledger replay: raw key material must never be able to
//! leak into a replicated write-set on a replica that should not hold it.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use super::AppContext;
use crate::sovereign_seal;

// =========================================================================
//  privasys:enclave-os/sealing@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/sealing@0.1.0")?;

    // ── get-seal-key ───────────────────────────────────────────────
    inst.func_wrap(
        "get-seal-key",
        |store: StoreContextMut<'_, AppContext>,
         (): ()|
         -> wasmtime::Result<(Result<(Vec<u8>, Vec<u8>), String>,)> {
            if super::ledger::in_replay() {
                return Ok((Err("get-seal-key is not available during replay".into()),));
            }
            let app_name = store.data().app_name.clone();
            let module = match crate::global() {
                Some(m) => m,
                None => return Ok((Err("wasm module not initialised".into()),)),
            };
            let root = match crate::sovereign_root() {
                Some(r) => r,
                None => return Ok((Err("sovereign sealing root not initialised".into()),)),
            };
            let code_hash = match module.app_code_hash(&app_name) {
                Ok(h) => h,
                Err(e) => return Ok((Err(e),)),
            };
            let key = sovereign_seal::derive_seal_key(root, &code_hash);
            Ok((Ok((key.to_vec(), code_hash.to_vec())),))
        },
    )?;

    Ok(())
}
