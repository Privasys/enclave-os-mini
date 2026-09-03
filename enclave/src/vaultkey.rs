// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! OS RA-TLS client identity and evidence for mutual attestation to the Enclave
//! Vault constellation and to attested dependencies (RA-TLS v2).
//!
//! Registered once at enclave init via [`register_client_cert_signer`]; it
//! holds the enclave intermediary CA and mints a measurement-bound client
//! identity via the attestation layer ([`mint_client_identity`]), and produces
//! the SGX quote of that identity for one connection ([`sgx_quote`]).
//!
//! The constellation client itself (the KEK resolve/provision flow, Shamir,
//! the vault RPC) lives in `enclave-os-wasm` (the WASM load path) because the
//! crate dependency runs enclave → wasm. The two halves connect only through
//! egress's global signer registration: no direct dependency in either
//! direction, and the CA never crosses the egress boundary.

use std::boxed::Box;
use std::vec::Vec;

use enclave_os_egress::{ClientCertIdentity, EnclaveAttestationProvider, EnclaveClientCertSigner};

use crate::ratls::attestation::{
    mint_client_identity, quote_binding_nonce, self_mrenclave, sgx_quote, CaContext,
};

/// The OS's RA-TLS client-identity signer: holds the enclave intermediary CA
/// and mints a client identity carrying the requested app identity (code
/// digest, app id), and quotes it per connection. egress invokes this via the
/// registered [`EnclaveClientCertSigner`] hook; the CA never leaves the OS and
/// the measurement comes from the policy the OS built, not from a caller.
struct OsClientCertSigner {
    ca_cert_der: Vec<u8>,
    ca_key_pkcs8: Vec<u8>,
}

impl EnclaveClientCertSigner for OsClientCertSigner {
    fn identity(&self, identity: &ClientCertIdentity, now: u64) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
        let ca = CaContext::from_parts(self.ca_cert_der.clone(), self.ca_key_pkcs8.clone()).ok()?;
        let (chain, pkcs8, _) = mint_client_identity(
            &ca,
            &identity.code_hash,
            identity.app_id.as_deref(),
            now,
        )
        .ok()?;
        Some((chain, pkcs8))
    }

    fn evidence(&self, report_data: &[u8; 64]) -> Option<Vec<u8>> {
        sgx_quote(report_data).ok()
    }
}

/// Register the OS client-identity signer once, at enclave init, from the
/// enclave CA (`SealedConfig.ca_cert_der` / `ca_key_pkcs8`). The signer is
/// leaked to obtain the `'static` egress requires; it lives for the enclave's
/// lifetime.
pub fn register_client_cert_signer(ca_cert_der: Vec<u8>, ca_key_pkcs8: Vec<u8>) {
    let signer: &'static OsClientCertSigner = Box::leak(Box::new(OsClientCertSigner {
        ca_cert_der,
        ca_key_pkcs8,
    }));
    enclave_os_egress::register_enclave_client_cert_signer(signer);
}

/// The OS's attestation provider: produces challenge-bound quotes (to
/// authenticate the enclave to the management-service vault directory over plain
/// TLS) and reports this enclave's own MRENCLAVE (so the wasm crate can pin the
/// running runtime when self-authoring a vault key policy).
struct OsAttestationProvider;

impl EnclaveAttestationProvider for OsAttestationProvider {
    fn quote(&self, nonce: &[u8]) -> Option<Vec<u8>> {
        quote_binding_nonce(nonce).ok()
    }

    fn self_mrenclave(&self) -> Option<[u8; 32]> {
        self_mrenclave().ok()
    }
}

/// Register the OS attestation provider once, at enclave init.
pub fn register_attestation_provider() {
    let provider: &'static OsAttestationProvider = Box::leak(Box::new(OsAttestationProvider));
    enclave_os_egress::register_enclave_attestation_provider(provider);
}
