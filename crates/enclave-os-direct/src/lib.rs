// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Direct domains for enclave-os.
//!
//! A direct domain is an adopter hostname whose TLS ends in the enclave with
//! a publicly trusted certificate. The platform gateway splices the name at
//! L4, so the only way a browser gets a certificate it trusts is for the
//! enclave to obtain one itself. This crate holds the pure half of that, with
//! no I/O, so it builds and tests on any host:
//!
//! - [`policy`]: the owner-signed app policy document and its `domains`, the
//!   only source of names the enclave will ever request, and the pin that
//!   keeps them across reloads.
//! - [`keys`]: the ACME account key, a P-256 scalar derived from the app's
//!   vault-held key. Only code the vault released the key to can hold the
//!   account, it survives upgrades, and an adopter's CAA record can pin
//!   issuance to it (RFC 8657 accounturi), the platform included.
//! - [`acme`]: an RFC 8555 client for TLS-ALPN-01 (RFC 8737) over an injected
//!   transport. One CA, one account: retries never move to a test CA.
//! - [`challenge`]: the acme-tls/1 challenge certificate, and the certificate
//!   key and CSR (the key is generated here and never leaves the enclave).
//! - [`binding`]: the OID 7.4 value binding each direct name to the key of
//!   its public certificate, and the status the control plane reads.
//! - [`dns`]: a readiness check, so no order is placed (and no failed
//!   validation spent) before the name resolves.

pub mod acme;
pub mod binding;
pub mod challenge;
pub mod dns;
pub mod jws;
pub mod keys;
pub mod policy;

/// The ALPN of the TLS-ALPN-01 challenge (RFC 8737).
pub const ACME_TLS_ALPN: &str = "acme-tls/1";

/// The ALPN an RA-TLS client offers. On a direct name it gets the RA-TLS
/// leaf; every other client gets the public certificate.
pub const RATLS_ALPN: &str = "privasys-ratls/1";

/// Let's Encrypt production. The only CA: a retry against a test CA with the
/// production account is refused by the test CA, and would never issue.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Which certificate a handshake on a direct name gets, from the ALPN the
/// client offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The acme-tls/1 challenge certificate (only when the client offers
    /// exactly that protocol, as RFC 8737 requires of the CA).
    Challenge,
    /// The RA-TLS leaf, minted for the direct name.
    RaTls,
    /// The publicly trusted certificate. The request is the direct leg.
    Public,
}

/// Chooses the certificate for a direct name.
pub fn select<'a, I>(offered: I) -> Selection
where
    I: IntoIterator<Item = &'a str>,
{
    let offered: Vec<&str> = offered.into_iter().collect();
    if offered.len() == 1 && offered[0] == ACME_TLS_ALPN {
        return Selection::Challenge;
    }
    if offered.iter().any(|p| *p == RATLS_ALPN) {
        return Selection::RaTls;
    }
    Selection::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_follows_the_offered_alpn() {
        assert_eq!(select(["acme-tls/1"]), Selection::Challenge);
        assert_eq!(select(["privasys-ratls/1", "http/1.1"]), Selection::RaTls);
        assert_eq!(select(["h2", "http/1.1"]), Selection::Public);
        assert_eq!(select([]), Selection::Public);
        // acme-tls/1 among others is not a CA validation.
        assert_eq!(select(["acme-tls/1", "h2"]), Selection::Public);
    }
}
