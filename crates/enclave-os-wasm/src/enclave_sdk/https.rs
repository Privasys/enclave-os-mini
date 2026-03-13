// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/https@0.1.0` — Secure HTTPS egress from WASM apps.
//!
//! Delegates to the egress crate ([`enclave_os_egress`]) which owns the
//! single TLS stack inside the enclave (Privasys rustls fork with RA-TLS
//! support). The host never sees request or response plaintext.
//!
//! ## Typed bindings
//!
//! Uses wasmtime's `func_wrap` API instead of the dynamic `func_new` / `Val`
//! API. This maps Component Model `list<u8>` directly to `Vec<u8>` via the
//! canonical ABI — no per-byte `Val::U8` wrapping (which previously caused
//! a ~24× memory amplification and OOM on large HTTPS responses).

use std::string::String;
use std::vec::Vec;

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use enclave_os_egress::client;

use super::AppContext;

// =========================================================================
//  privasys:enclave-os/https@0.1.0
// =========================================================================

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/https@0.1.0")?;

    // ── fetch ──────────────────────────────────────────────────────
    // func(method: u32, url: string, headers: list<tuple<string,string>>,
    //       body: option<list<u8>>)
    //      -> result<tuple<u16, list<tuple<string,string>>, list<u8>>, string>
    //
    //   method: 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=PATCH, 5=HEAD, 6=OPTIONS
    inst.func_wrap(
        "fetch",
        |_store: StoreContextMut<'_, AppContext>,
         (method, url, headers, body): (
            u32,
            String,
            Vec<(String, String)>,
            Option<Vec<u8>>,
        )|
         -> wasmtime::Result<(
            Result<(u16, Vec<(String, String)>, Vec<u8>), String>,
        )> {
            let method_str = match method {
                0 => "GET",
                1 => "POST",
                2 => "PUT",
                3 => "DELETE",
                4 => "PATCH",
                5 => "HEAD",
                6 => "OPTIONS",
                _ => return Ok((Err("unsupported HTTP method".into()),)),
            };

            let result = client::https_fetch(
                method_str,
                &url,
                &headers,
                body.as_deref(),
                client::mozilla_root_store(),
                None, // No RA-TLS for general WASM app egress
            );

            Ok((result.map(|r| (r.status, r.headers, r.body)),))
        },
    )?;

    Ok(())
}


