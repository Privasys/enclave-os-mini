// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/attestation@0.1.0` — App-controlled attestation extensions.
//!
//! Two host functions support the **configure-then-freeze** pattern:
//!
//! | Function | Purpose |
//! |----------|---------|
//! | `set-attestation-extension(arc-suffix: u32, value: list<u8>)` | Install (or replace) a non-critical X.509 extension on the per-app RA-TLS leaf at OID `1.3.6.1.4.1.65230.3.5.{arc_suffix}`. Persisted across enclave restarts. |
//! | `set-config-complete()` | Lift the freeze gate so the app's other exports become callable. Must be called from the configure function (the function declared as `config_api` at load time). |
//!
//! ## Configure-then-freeze flow
//!
//! 1. App is loaded with `config_api = "configure"`. The runtime
//!    accepts only calls to `configure`; everything else returns an
//!    error.
//! 2. The deployer calls `configure(api_key)` over RA-TLS. The app:
//!    a. Stores the secret to its sealed KV store.
//!    b. Computes a SHA-256 of the secret.
//!    c. Calls `set-attestation-extension(1, hash)` so the per-app
//!       leaf advertises the configured-secret hash on its next
//!       handshake.
//!    d. Calls `set-config-complete()` to unfreeze.
//! 3. Subsequent client connections see the new extension in the
//!    leaf certificate and can prove they're talking to an enclave
//!    that saw exactly the secret they delivered.
//!
//! ## Restart behaviour
//!
//! On every enclave restart the app re-enters the frozen state.
//! Persisted extensions are still served on the leaf certificate
//! (so verifying clients keep working), but the secret material the
//! deployer originally supplied must be re-injected via `configure`
//! before any other export becomes callable.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use super::AppContext;

// =========================================================================
//  privasys:enclave-os/attestation@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/attestation@0.1.0")?;

    // ── set-attestation-extension ──────────────────────────────────
    inst.func_wrap(
        "set-attestation-extension",
        |store: StoreContextMut<'_, AppContext>,
         (arc_suffix, value): (u32, Vec<u8>)|
         -> wasmtime::Result<(Result<(), String>,)> {
            let app_name = store.data().app_name.clone();
            let module = match crate::global() {
                Some(m) => m,
                None => return Ok((Err("wasm module not initialised".into()),)),
            };
            // Bound the value size to keep the cert reasonable.
            // A 32-byte hash is the typical case; cap at 4 KiB to
            // prevent runaway certificate growth.
            if value.len() > 4096 {
                return Ok((Err("attestation extension value exceeds 4096 bytes".into()),));
            }
            match module.set_attestation_extension(&app_name, arc_suffix, value) {
                Ok(()) => Ok((Ok(()),)),
                Err(e) => Ok((Err(e),)),
            }
        },
    )?;

    // ── set-config-complete ────────────────────────────────────────
    inst.func_wrap(
        "set-config-complete",
        |store: StoreContextMut<'_, AppContext>, (): ()|
         -> wasmtime::Result<(Result<(), String>,)> {
            let app_name = store.data().app_name.clone();
            let module = match crate::global() {
                Some(m) => m,
                None => return Ok((Err("wasm module not initialised".into()),)),
            };
            match module.mark_configured(&app_name) {
                Ok(()) => Ok((Ok(()),)),
                Err(e) => Ok((Err(e),)),
            }
        },
    )?;

    Ok(())
}
