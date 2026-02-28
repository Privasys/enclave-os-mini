// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS (Remote Attestation - Transport Layer Security) module.
//!
//! Provides mutual attestation over TLS 1.3 using SGX quotes embedded
//! in X.509 certificates.

pub mod attestation;
pub mod cert_store;
pub mod server;
pub mod session;
