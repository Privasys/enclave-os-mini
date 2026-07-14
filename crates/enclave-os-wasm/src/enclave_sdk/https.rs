// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! `privasys:enclave-os/https@0.1.0` — Secure HTTPS egress from WASM apps.
//!
//! Delegates to the egress crate ([`enclave_os_egress`]) which owns the
//! single TLS stack inside the enclave (Privasys rustls fork with RA-TLS
//! support). The host never sees request or response plaintext.
//!
//! ## Type-safe Component Model bindings
//!
//! Uses [`wasmtime::component::bindgen!`] to generate canonical-ABI
//! lowering directly from the WIT.  This avoids two earlier failure
//! modes:
//!
//! 1. The dynamic `func_new` / `Val` API caused ~24× memory amplification
//!    on large HTTPS responses (per-byte `Val::U8` boxing) → OOM.
//! 2. Manual `func_wrap` with positional tuples did not match the canonical
//!    ABI for `fetch: func(request: request)` (a single record-typed
//!    parameter, not flattened positional args), causing
//!    "matching implementation was not found in the linker" at instantiation.
//!
//! The generated bindings handle the record/option/list lowering correctly
//! and preserve the bulk-`Vec<u8>` mapping for `list<u8>` bodies.
//!
//! NOTE: The inline WIT below MUST stay in sync with the public SDK WIT
//! at `sdk/wit/enclave-os.wit`.  The two are consumed by different
//! tooling (cargo-component for adopters; bindgen! here for the host)
//! but describe the exact same ABI.

use std::string::String;
use std::vec::Vec;

use wasmtime::component::{HasSelf, Linker};

use enclave_os_egress::client;
use enclave_os_egress::client::{
    ExpectedOid, RaTlsPolicy, ReportDataBinding, RootCertStore, TeeType,
};

use super::AppContext;

// =========================================================================
//  privasys:enclave-os/https@0.1.0 — generated bindings
// =========================================================================

wasmtime::component::bindgen!({
    inline: r#"
        package privasys:enclave-os@0.1.0;

        interface https {
            enum method { get, post, put, delete, patch, head, options }

            enum tee-type { sgx, tdx }

            record expected-oid {
                oid: string,
                value: list<u8>,
            }

            record ratls-policy {
                tee: tee-type,
                mr-enclave: option<list<u8>>,
                mr-signer: option<list<u8>>,
                mr-td: option<list<u8>>,
                challenge-nonce: option<list<u8>>,
                expected-oids: list<expected-oid>,
                attestation-servers: list<string>,
            }

            record request {
                method: method,
                url: string,
                headers: list<tuple<string, string>>,
                body: option<list<u8>>,
                ratls: option<ratls-policy>,
                ca-roots-der: option<list<list<u8>>>,
            }

            record response {
                status: u16,
                headers: list<tuple<string, string>>,
                body: list<u8>,
            }

            fetch: func(request: request) -> result<response, string>;
        }

        world https-host {
            import https;
        }
    "#,
    world: "https-host",
});

use privasys::enclave_os::https as wit;

// =========================================================================
//  Conversion: WIT types → egress crate types
// =========================================================================

fn build_ratls_policy(p: wit::RatlsPolicy) -> Result<RaTlsPolicy, String> {
    let tee = match p.tee {
        wit::TeeType::Sgx => TeeType::Sgx,
        wit::TeeType::Tdx => TeeType::Tdx,
    };

    fn check_fixed(name: &str, v: Option<Vec<u8>>, want: usize) -> Result<Option<Vec<u8>>, String> {
        match v {
            None => Ok(None),
            Some(b) if b.len() == want => Ok(Some(b)),
            Some(b) => Err(format!("{name} must be {want} bytes, got {}", b.len())),
        }
    }

    let mr_enclave = check_fixed("mr-enclave", p.mr_enclave, 32)?.map(|v| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    });
    let mr_signer = check_fixed("mr-signer", p.mr_signer, 32)?.map(|v| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    });
    let mr_td = check_fixed("mr-td", p.mr_td, 48)?.map(|v| {
        let mut a = [0u8; 48];
        a.copy_from_slice(&v);
        a
    });

    let report_data = match p.challenge_nonce {
        Some(nonce) => ReportDataBinding::ChallengeResponse { nonce },
        None => ReportDataBinding::Deterministic,
    };

    Ok(RaTlsPolicy {
        tee,
        mr_enclave,
        mr_signer,
        mr_td,
        report_data,
        expected_oids: p
            .expected_oids
            .into_iter()
            .map(|e| ExpectedOid {
                oid: e.oid,
                expected_value: e.value,
            })
            .collect(),
        attestation_servers: p.attestation_servers,
        // App egress presents no client certificate (server attestation only).
        client_identity: None,
        // Set by the caller from the app's sealed metadata, not the app request.
        dependencies: None,
    })
}

fn build_custom_root_store(
    ca_roots_der: Option<Vec<Vec<u8>>>,
) -> Result<Option<RootCertStore>, String> {
    let Some(ders) = ca_roots_der else {
        return Ok(None);
    };
    client::root_store_from_der(ders).map(Some)
}

// =========================================================================
//  Host trait implementation
// =========================================================================

impl wit::Host for AppContext {
    fn fetch(&mut self, req: wit::Request) -> Result<wit::Response, String> {
        let method_str = match req.method {
            wit::Method::Get => "GET",
            wit::Method::Post => "POST",
            wit::Method::Put => "PUT",
            wit::Method::Delete => "DELETE",
            wit::Method::Patch => "PATCH",
            wit::Method::Head => "HEAD",
            wit::Method::Options => "OPTIONS",
        };

        // Capture billable metering inputs before `req` is consumed.
        let is_ratls = req.ratls.is_some();
        let req_body_len = req.body.as_deref().map(|b| b.len()).unwrap_or(0) as i64;

        // Inject the app's runtime-owned attested-dependency set (from sealed
        // metadata, never the app request) so a connection to a declared
        // dependency is verified fail-closed against its pinned identity.
        let ratls_policy = req.ratls.map(build_ratls_policy).transpose()?.map(|mut pol| {
            pol.dependencies = self.pinned_dependencies.clone();
            pol
        });
        let custom_store = build_custom_root_store(req.ca_roots_der)?;

        let root_store: &RootCertStore = match &custom_store {
            Some(s) => s,
            None => client::mozilla_root_store(),
        };

        let r = client::https_fetch(
            method_str,
            &req.url,
            &req.headers,
            req.body.as_deref(),
            root_store,
            ratls_policy.as_ref(),
        )?;

        // Record billable HTTPS egress (request + response body bytes),
        // split by transport (plain TLS vs RA-TLS).
        let total_bytes = req_body_len + r.body.len() as i64;
        if is_ratls {
            self.usage.https_ratls_calls += 1;
            self.usage.https_ratls_bytes += total_bytes;
        } else {
            self.usage.https_plain_calls += 1;
            self.usage.https_plain_bytes += total_bytes;
        }

        Ok(wit::Response {
            status: r.status,
            headers: r.headers,
            body: r.body,
        })
    }
}

pub fn add_to_linker(linker: &mut Linker<AppContext>) -> Result<(), wasmtime::Error> {
    wit::add_to_linker::<_, HasSelf<_>>(linker, |s| s)
}
