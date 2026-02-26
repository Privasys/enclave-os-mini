// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side encrypted KV store backend.
//!
//! Stores opaque encrypted blobs keyed by encrypted keys.
//! The host never sees plaintext – all encryption happens inside the enclave.

pub mod storage;

pub use storage::*;
