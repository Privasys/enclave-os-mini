// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! SGX sealing – encrypt data bound to MRENCLAVE (code identity).
//!
//! Sealed data can only be unsealed by the exact same enclave binary
//! (same measurement / MRENCLAVE). This is used by [`SealedConfig`] to
//! persist all enclave state across restarts.
//!
//! Uses the Intel SGX SDK sealing API via teaclave-sgx-sdk bindings.

use std::vec::Vec;

#[cfg(not(feature = "mock"))]
use sgx_tseal::seal::SealedData;

/// Seal data using **MRENCLAVE** policy.
///
/// The sealed blob can only be unsealed by an enclave with the same MRENCLAVE.
///
/// NB: `SealedData::seal` uses SGX's *default* key policy, which the teaclave
/// SDK implements as **MRSIGNER** — that would let any same-signer enclave
/// unseal (weaker than this function's name implies) and, because our signing
/// key is generated per build, would also break unseal on every rebuild. We
/// therefore bind explicitly to MRENCLAVE with the crate's default masks
/// (`AttributesFlags::DEFAULT_MASK`, `xfrm = 0`, `TSEAL_DEFAULT_MISCMASK`).
/// Continuity across an MRENCLAVE change is provided by the vault (KEK-wrapped
/// per-app DEK), never by this seal.
#[cfg(not(feature = "mock"))]
pub fn seal_with_mrenclave(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    use sgx_types::types::{Attributes, AttributesFlags, KeyPolicy, TSEAL_DEFAULT_MISCMASK};

    let aad_opt = if aad.is_empty() { None } else { Some(aad) };
    let attribute_mask = Attributes {
        flags: AttributesFlags::DEFAULT_MASK,
        xfrm: 0,
    };
    let sealed = SealedData::<[u8]>::seal_with_key_policy(
        KeyPolicy::MRENCLAVE,
        attribute_mask,
        TSEAL_DEFAULT_MISCMASK,
        plaintext,
        aad_opt,
    )
    .map_err(|_| "sgx_seal_data failed")?;

    sealed.into_bytes().map_err(|_| "Failed to serialize sealed data")
}

/// Unseal data previously sealed with MRENCLAVE policy.
#[cfg(not(feature = "mock"))]
pub fn unseal_with_mrenclave(sealed_blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let sealed = SealedData::<[u8]>::from_slice(sealed_blob)
        .map_err(|_| "Invalid sealed data format")?;

    let unsealed = sealed.unseal().map_err(|_| "sgx_unseal_data failed")?;

    let plaintext = unsealed.to_plaintext().to_vec();
    let aad = unsealed.to_aad().to_vec();

    Ok((plaintext, aad))
}

// ---------------------------------------------------------------------------
//  Mock implementations for development / testing
// ---------------------------------------------------------------------------

#[cfg(feature = "mock")]
pub fn seal_with_mrenclave(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Mock: just prefix with a "sealed" marker + lengths, no real encryption
    let mut buf = Vec::new();
    buf.extend_from_slice(b"MOCK_SEALED:");
    buf.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    buf.extend_from_slice(plaintext);
    Ok(buf)
}

#[cfg(feature = "mock")]
pub fn unseal_with_mrenclave(sealed_blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let prefix = b"MOCK_SEALED:";
    if !sealed_blob.starts_with(prefix) {
        return Err("Not a mock-sealed blob");
    }
    let data = &sealed_blob[prefix.len()..];

    if data.len() < 4 { return Err("Invalid mock sealed data"); }
    let aad_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let data = &data[4..];
    if data.len() < aad_len + 4 { return Err("Invalid mock sealed data"); }
    let aad = data[..aad_len].to_vec();
    let data = &data[aad_len..];
    let pt_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let data = &data[4..];
    if data.len() < pt_len { return Err("Invalid mock sealed data"); }
    let plaintext = data[..pt_len].to_vec();

    Ok((plaintext, aad))
}


