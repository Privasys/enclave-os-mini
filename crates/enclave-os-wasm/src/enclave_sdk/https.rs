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
use enclave_os_egress::client::{
    ExpectedOid, RaTlsPolicy, ReportDataBinding, RootCertStore, TeeType,
};

use super::AppContext;

// =========================================================================
//  privasys:enclave-os/https@0.1.0
// =========================================================================

/// Tuple shape matching the WIT `ratls-policy` record.
///
/// Field order (positional, canonical-ABI-equivalent):
///   0. tee:                 u32  (0=sgx, 1=tdx)
///   1. mr-enclave:          option<list<u8>>  (32 bytes when set)
///   2. mr-signer:           option<list<u8>>  (32 bytes when set)
///   3. mr-td:               option<list<u8>>  (48 bytes when set)
///   4. challenge-nonce:     option<list<u8>>
///   5. expected-oids:       list<expected-oid>  → list<(string, list<u8>)>
///   6. attestation-servers: list<string>
type RaTlsPolicyTuple = (
    u32,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<(String, Vec<u8>)>,
    Vec<String>,
);

/// Translate the WIT `ratls-policy` tuple into the egress crate's
/// [`RaTlsPolicy`].  Performs length checks on the measurement registers.
fn build_ratls_policy(t: RaTlsPolicyTuple) -> Result<RaTlsPolicy, String> {
    let (tee_u32, mr_enclave, mr_signer, mr_td, challenge_nonce, expected_oids, attestation_servers) =
        t;

    let tee = match tee_u32 {
        0 => TeeType::Sgx,
        1 => TeeType::Tdx,
        _ => return Err(format!("unknown tee-type discriminant: {}", tee_u32)),
    };

    let mr_enclave = match mr_enclave {
        None => None,
        Some(v) => {
            if v.len() != 32 {
                return Err(format!("mr-enclave must be 32 bytes, got {}", v.len()));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Some(a)
        }
    };
    let mr_signer = match mr_signer {
        None => None,
        Some(v) => {
            if v.len() != 32 {
                return Err(format!("mr-signer must be 32 bytes, got {}", v.len()));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Some(a)
        }
    };
    let mr_td = match mr_td {
        None => None,
        Some(v) => {
            if v.len() != 48 {
                return Err(format!("mr-td must be 48 bytes, got {}", v.len()));
            }
            let mut a = [0u8; 48];
            a.copy_from_slice(&v);
            Some(a)
        }
    };

    let report_data = match challenge_nonce {
        Some(nonce) => ReportDataBinding::ChallengeResponse { nonce },
        None => ReportDataBinding::Deterministic,
    };

    let expected_oids = expected_oids
        .into_iter()
        .map(|(oid, value)| ExpectedOid {
            oid,
            expected_value: value,
        })
        .collect();

    Ok(RaTlsPolicy {
        tee,
        mr_enclave,
        mr_signer,
        mr_td,
        report_data,
        expected_oids,
        attestation_servers,
    })
}

/// Build a custom root store from optional caller-supplied DER root certs.
/// Delegates to the egress crate so the WASM SDK shim does not need a
/// direct `rustls` dependency.
///
/// Returns `Ok(None)` when no custom roots were supplied (caller should
/// fall back to the default Mozilla store).
fn build_custom_root_store(
    ca_roots_der: Option<Vec<Vec<u8>>>,
) -> Result<Option<RootCertStore>, String> {
    let Some(ders) = ca_roots_der else {
        return Ok(None);
    };
    client::root_store_from_der(ders).map(Some)
}

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    let mut inst = linker.instance("privasys:enclave-os/https@0.1.0")?;

    // ── fetch ──────────────────────────────────────────────────────
    // WIT (positional / canonical ABI):
    //   record request {
    //       method:        method,                     // u32
    //       url:           string,
    //       headers:       list<tuple<string,string>>,
    //       body:          option<list<u8>>,
    //       ratls:         option<ratls-policy>,
    //       ca-roots-der:  option<list<list<u8>>>,
    //   }
    //
    //   method: 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=PATCH, 5=HEAD, 6=OPTIONS
    inst.func_wrap(
        "fetch",
        |_store: StoreContextMut<'_, AppContext>,
         (method, url, headers, body, ratls, ca_roots_der): (
            u32,
            String,
            Vec<(String, String)>,
            Option<Vec<u8>>,
            Option<RaTlsPolicyTuple>,
            Option<Vec<Vec<u8>>>,
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

            let ratls_policy = match ratls.map(build_ratls_policy).transpose() {
                Ok(p) => p,
                Err(e) => return Ok((Err(e),)),
            };

            let custom_store = match build_custom_root_store(ca_roots_der) {
                Ok(s) => s,
                Err(e) => return Ok((Err(e),)),
            };

            let root_store: &RootCertStore = match &custom_store {
                Some(s) => s,
                None => client::mozilla_root_store(),
            };

            let result = client::https_fetch(
                method_str,
                &url,
                &headers,
                body.as_deref(),
                root_store,
                ratls_policy.as_ref(),
            );

            Ok((result.map(|r| (r.status, r.headers, r.body)),))
        },
    )?;

    Ok(())
}


