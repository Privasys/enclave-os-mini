// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Error type. Every integrity failure is `Corrupted` and fails closed:
//! the store never silently returns data that did not verify against
//! the in-memory root.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// The host backend returned an error code.
    Backend(i32),
    /// A record failed hash verification, decoding or decryption.
    /// Either the host tampered with storage or storage is damaged.
    Corrupted(String),
    /// A record that must exist is missing (e.g. a node referenced by
    /// its parent, or a root record for a requested version).
    Missing(String),
    /// Invalid input from the caller.
    Invalid(String),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::Backend(code) => write!(f, "backend error {code}"),
            MerkleError::Corrupted(m) => write!(f, "corrupted record: {m}"),
            MerkleError::Missing(m) => write!(f, "missing record: {m}"),
            MerkleError::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}
