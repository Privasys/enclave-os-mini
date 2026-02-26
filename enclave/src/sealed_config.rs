// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Unified sealed configuration.
//!
//! All operator-provided and enclave-generated persistent state is bundled
//! into a single [`SealedConfig`] struct, sealed with MRENCLAVE policy, and
//! stored as one blob on the host.
//!
//! The struct contains:
//! - A **master encryption key** (AES-256, generated on first boot) shared
//!   by all modules for KV store encryption.
//! - Intermediary CA certificate and private key.
//! - Module-specific opaque blobs in `module_data` for additional state.
//!
//! ## Binary layout (v3)
//!
//! ```text
//! [4 bytes: version (LE u32) = 3]
//! [32 bytes: master_key]
//! [4 bytes: ca_cert_der length (LE u32)]  [ca_cert_der]
//! [4 bytes: ca_key_pkcs8 length (LE u32)] [ca_key_pkcs8]
//! [4 bytes: num_entries (LE u32)]
//!   for each entry:
//!     [4 bytes: key_len (LE u32)] [key UTF-8]
//!     [4 bytes: val_len (LE u32)] [value]

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;
use crate::crypto::sealing;
use enclave_os_common::types::AEAD_KEY_SIZE;

const FORMAT_VERSION: u32 = 3;

/// KV tag under which the sealed config blob is stored on the host.
const SEALED_CONFIG_TAG: &[u8] = b"__enclave_os_sealed_config__";

/// KV table for system-level data (sealed config, etc.).
const SYSTEM_TABLE: &[u8] = b"system";

/// AAD for MRENCLAVE sealing of the unified config blob.
const SEALED_CONFIG_AAD: &[u8] = b"enclave_os_sealed_config_v3";

/// Unified sealed configuration.
///
/// Contains persistent enclave state:
/// - **Master encryption key** (AES-256, generated on first boot)
/// - Intermediary CA certificate and private key (core)
/// - Module-specific opaque blobs (extensible)
pub struct SealedConfig {
    /// AES-256 master encryption key (shared by all modules).
    ///
    /// Generated once on first boot; persisted via MRENCLAVE sealing.
    pub master_key: [u8; AEAD_KEY_SIZE],
    /// DER-encoded intermediary CA certificate.
    pub ca_cert_der: Vec<u8>,
    /// PKCS#8-encoded intermediary CA private key.
    pub ca_key_pkcs8: Vec<u8>,
    /// Module-specific sealed data, keyed by module name.
    ///
    /// Modules read their data during construction and write updated data
    /// before the config is re-sealed to disk.
    pub module_data: BTreeMap<String, Vec<u8>>,
}

impl SealedConfig {
    /// Get the master encryption key.
    pub fn master_key(&self) -> [u8; AEAD_KEY_SIZE] {
        self.master_key
    }

    /// Get module-specific sealed data by name.
    pub fn get_module_data(&self, key: &str) -> Option<&[u8]> {
        self.module_data.get(key).map(|v| v.as_slice())
    }

    /// Set module-specific sealed data.
    ///
    /// Call this during module init to persist data across restarts.
    /// The data is sealed to disk when [`seal_to_disk()`](Self::seal_to_disk) is
    /// called at the end of the init phase.
    pub fn set_module_data(&mut self, key: impl Into<String>, data: Vec<u8>) {
        self.module_data.insert(key.into(), data);
    }

    /// Serialize to the versioned binary format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());

        // Master encryption key (fixed 32 bytes)
        buf.extend_from_slice(&self.master_key);

        buf.extend_from_slice(&(self.ca_cert_der.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ca_cert_der);

        buf.extend_from_slice(&(self.ca_key_pkcs8.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ca_key_pkcs8);

        // Module data entries (sorted by BTreeMap key order)
        buf.extend_from_slice(&(self.module_data.len() as u32).to_le_bytes());
        for (key, value) in &self.module_data {
            let key_bytes = key.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(key_bytes);
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value);
        }

        buf
    }

    /// Deserialize from the versioned binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;

        // Version
        if data.len() < pos + 4 {
            return Err("Too short for version");
        }
        let version = u32::from_le_bytes(
            data[pos..pos + 4].try_into().map_err(|_| "bad version")?,
        );
        if version != FORMAT_VERSION {
            return Err("Unknown SealedConfig version");
        }
        pos += 4;

        // Master encryption key (fixed 32 bytes)
        if data.len() < pos + AEAD_KEY_SIZE {
            return Err("Too short for master_key");
        }
        let mut master_key = [0u8; AEAD_KEY_SIZE];
        master_key.copy_from_slice(&data[pos..pos + AEAD_KEY_SIZE]);
        pos += AEAD_KEY_SIZE;

        // CA cert
        if data.len() < pos + 4 {
            return Err("Too short for ca_cert_len");
        }
        let ca_cert_len = u32::from_le_bytes(
            data[pos..pos + 4].try_into().map_err(|_| "bad ca_cert_len")?,
        ) as usize;
        pos += 4;
        if data.len() < pos + ca_cert_len {
            return Err("Truncated ca_cert");
        }
        let ca_cert_der = data[pos..pos + ca_cert_len].to_vec();
        pos += ca_cert_len;

        // CA key
        if data.len() < pos + 4 {
            return Err("Too short for ca_key_len");
        }
        let ca_key_len = u32::from_le_bytes(
            data[pos..pos + 4].try_into().map_err(|_| "bad ca_key_len")?,
        ) as usize;
        pos += 4;
        if data.len() < pos + ca_key_len {
            return Err("Truncated ca_key");
        }
        let ca_key_pkcs8 = data[pos..pos + ca_key_len].to_vec();
        pos += ca_key_len;

        // Module data entries
        if data.len() < pos + 4 {
            return Err("Too short for num_entries");
        }
        let num_entries = u32::from_le_bytes(
            data[pos..pos + 4].try_into().map_err(|_| "bad num_entries")?,
        ) as usize;
        pos += 4;

        let mut module_data = BTreeMap::new();
        for _ in 0..num_entries {
            // Key
            if data.len() < pos + 4 {
                return Err("Too short for module key_len");
            }
            let key_len = u32::from_le_bytes(
                data[pos..pos + 4].try_into().map_err(|_| "bad key_len")?,
            ) as usize;
            pos += 4;
            if data.len() < pos + key_len {
                return Err("Truncated module key");
            }
            let key = std::str::from_utf8(&data[pos..pos + key_len])
                .map_err(|_| "Invalid UTF-8 in module key")?
                .to_string();
            pos += key_len;

            // Value
            if data.len() < pos + 4 {
                return Err("Too short for module val_len");
            }
            let val_len = u32::from_le_bytes(
                data[pos..pos + 4].try_into().map_err(|_| "bad val_len")?,
            ) as usize;
            pos += 4;
            if data.len() < pos + val_len {
                return Err("Truncated module value");
            }
            let value = data[pos..pos + val_len].to_vec();
            pos += val_len;

            module_data.insert(key, value);
        }

        Ok(Self {
            master_key,
            ca_cert_der,
            ca_key_pkcs8,
            module_data,
        })
    }

    /// Seal this config and store it on the host.
    pub fn seal_to_disk(&self) -> Result<(), String> {
        let plaintext = self.serialize();
        let sealed_blob = sealing::seal_with_mrenclave(&plaintext, SEALED_CONFIG_AAD)
            .map_err(|e| format!("SealedConfig seal failed: {}", e))?;

        let tag = config_storage_tag();
        crate::ocall::kv_store_put(SYSTEM_TABLE, &tag, &sealed_blob)
            .map_err(|e| format!("Host KV put (config) failed: {}", e))
    }

    /// Unseal a previously stored config from the host.
    pub fn unseal_from_disk() -> Result<Self, String> {
        let tag = config_storage_tag();

        let sealed_blob = crate::ocall::kv_store_get(SYSTEM_TABLE, &tag, 256 * 1024)
            .map_err(|e| format!("Host KV get (config) failed: {}", e))?
            .ok_or_else(|| String::from("No sealed config found on disk"))?;

        let (plaintext, _aad) = sealing::unseal_with_mrenclave(&sealed_blob)
            .map_err(|e| format!("SealedConfig unseal failed: {}", e))?;

        Self::deserialize(&plaintext)
            .map_err(|e| format!("SealedConfig deserialize failed: {}", e))
    }
}

/// Deterministic KV tag for the sealed config blob.
fn config_storage_tag() -> Vec<u8> {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, SEALED_CONFIG_TAG);
    hash.as_ref().to_vec()
}
