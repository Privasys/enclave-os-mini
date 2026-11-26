// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! App-defined attestation extensions (SDK `set-attestation-extension`).
//!
//! An app publishes up to [`MAX_APP_EXTENSIONS`] values on its own RA-TLS
//! leaf, each at `1.3.6.1.4.1.65230.5.4.{arc}` (the app-defined arc of the
//! OID registry, `APP_EXTENSION_ARC_OID`). The runtime appends exactly one
//! numeric arc, from 1: an app can never produce the root `5.4` or any
//! runtime-owned OID. The count is bounded because each value grows the
//! leaf and the app's sealed metadata, and the enclave heap is shared by
//! every app on the host.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

/// The most extensions one app may hold. Replacing an existing arc's value
/// is always allowed; a new arc beyond this count is refused.
pub const MAX_APP_EXTENSIONS: usize = 16;

/// Whether an app may set `arc` given the extensions it already holds.
pub fn check_new_extension(existing: &BTreeMap<u32, Vec<u8>>, arc: u32) -> Result<(), String> {
    if arc == 0 {
        return Err("attestation extension arc must be 1 or more".into());
    }
    if !existing.contains_key(&arc) && existing.len() >= MAX_APP_EXTENSIONS {
        return Err(format!(
            "an app may hold at most {MAX_APP_EXTENSIONS} attestation extensions"
        ));
    }
    Ok(())
}

/// Interned OIDs, one per arc ever stamped: the CertStore takes `'static`
/// OID slices, and an identity is rebuilt on every load and every change, so
/// a fresh allocation per rebuild would grow without end.
static OIDS: Mutex<BTreeMap<u32, &'static [u64]>> = Mutex::new(BTreeMap::new());

/// The OID for app-defined extension `arc`: `APP_EXTENSION_ARC_OID ++ [arc]`,
/// allocated once per arc for the life of the enclave.
pub fn extension_oid(arc: u32) -> &'static [u64] {
    let mut oids = match OIDS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(oid) = oids.get(&arc) {
        return oid;
    }
    let mut full: Vec<u64> = enclave_os_common::oids::APP_EXTENSION_ARC_OID.to_vec();
    full.push(arc as u64);
    let oid: &'static [u64] = Box::leak(full.into_boxed_slice());
    oids.insert(arc, oid);
    oid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding(n: u32) -> BTreeMap<u32, Vec<u8>> {
        (1..=n).map(|a| (a, vec![0u8; 32])).collect()
    }

    #[test]
    fn the_seventeenth_arc_is_refused() {
        let full = holding(MAX_APP_EXTENSIONS as u32);
        assert!(check_new_extension(&holding(15), 16).is_ok());
        assert!(check_new_extension(&full, 17).is_err());
        // Replacing a value the app already holds stays allowed at the cap.
        assert!(check_new_extension(&full, 3).is_ok());
    }

    #[test]
    fn arc_zero_is_refused() {
        assert!(check_new_extension(&BTreeMap::new(), 0).is_err());
    }

    #[test]
    fn oids_sit_under_the_app_defined_arc() {
        assert_eq!(extension_oid(7), &[1, 3, 6, 1, 4, 1, 65230, 5, 4, 7][..]);
    }

    #[test]
    fn rebuilding_an_identity_allocates_nothing_new() {
        let first = extension_oid(9);
        for _ in 0..1000 {
            assert!(core::ptr::eq(first, extension_oid(9)));
        }
        let interned = OIDS.lock().unwrap().len();
        for _ in 0..1000 {
            for arc in 1..=5 {
                let _ = extension_oid(arc);
            }
        }
        // Only the arcs not seen before were added, once each.
        assert!(OIDS.lock().unwrap().len() <= interned + 5);
    }
}
