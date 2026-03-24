// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Pure parsing helpers for WASM Component `package-docs` custom sections.
//!
//! The functions here are deliberately free of wasmtime / SGX dependencies
//! so that a lightweight test proxy crate (`tests/wasm-docs-unit/`) can
//! include this module via `#[path]` and run the `#[cfg(test)]` suite
//! without needing the full SGX toolchain.

use std::collections::BTreeMap;

/// Read a LEB128-encoded unsigned integer. Returns `(value, bytes_consumed)`.
pub fn read_leb128(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow protection.
        }
    }
    None
}

/// Walk a WASM binary looking for a custom section named `package-docs`.
///
/// The section payload is a JSON object mapping WIT paths (or flat names)
/// to doc-comment strings.  We normalise the keys into the `func:` /
/// `interface:` / `param:` convention used by the schema builder.
pub fn parse_package_docs(wasm_bytes: &[u8]) -> BTreeMap<String, String> {
    let mut docs = BTreeMap::new();
    if wasm_bytes.len() < 8 {
        return docs;
    }
    let mut pos = 8; // skip WASM header

    while pos < wasm_bytes.len() {
        let section_id = wasm_bytes[pos];
        pos += 1;
        let (section_size, consumed) = match read_leb128(&wasm_bytes[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += consumed;
        let section_end = pos + section_size;

        if section_id == 0 {
            // Custom section — first field is the section name.
            let name_start = pos;
            if let Some((name_len, name_leb_size)) = read_leb128(&wasm_bytes[name_start..]) {
                let name_bytes_start = name_start + name_leb_size;
                let name_bytes_end = name_bytes_start + name_len;
                if name_bytes_end <= wasm_bytes.len() {
                    if let Ok(name) = core::str::from_utf8(&wasm_bytes[name_bytes_start..name_bytes_end]) {
                        if name == "package-docs" {
                            let payload_start = name_bytes_end;
                            let payload_end = section_end;
                            if payload_end <= wasm_bytes.len() {
                                let payload = &wasm_bytes[payload_start..payload_end];
                                if let Ok(map) = serde_json::from_slice::<serde_json::Value>(payload) {
                                    normalise_package_docs(&map, &mut docs);
                                }
                            }
                            return docs;
                        }
                    }
                }
            }
        }

        pos = section_end;
    }

    docs
}

/// Normalise a `package-docs` JSON object into the keying convention
/// used by the schema builder.
///
/// The JSON from `package-docs` uses paths like:
/// - `"worlds/my-app/funcs/hello"` → function doc
/// - `"worlds/my-app/interfaces/my-api"` → interface doc
/// - `"interfaces/my-api/funcs/hello"` → interface function doc
///
/// We also accept the simpler flat format:
/// - `"hello"` → function doc
/// - `"hello.name"` → parameter doc
pub fn normalise_package_docs(
    val: &serde_json::Value,
    docs: &mut BTreeMap<String, String>,
) {
    let obj = match val.as_object() {
        Some(o) => o,
        None => return,
    };

    for (key, value) in obj {
        let desc = match value.as_str() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        if key.contains("/funcs/") {
            let func_name = key.rsplit("/funcs/").next().unwrap_or(key);
            docs.insert(format!("func:{}", func_name), desc.to_string());
        } else if key.contains("/interfaces/") {
            let iface_name = key.rsplit("/interfaces/").next().unwrap_or(key);
            docs.insert(format!("interface:{}", iface_name), desc.to_string());
        } else if key.contains('.') {
            docs.insert(format!("param:{}", key), desc.to_string());
        } else {
            docs.insert(format!("func:{}", key), desc.to_string());
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────
//
// These run via the lightweight proxy crate `tests/wasm-docs-unit/` which
// includes this file via `#[path]`, avoiding the full SGX dependency chain.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_single_byte() {
        assert_eq!(read_leb128(&[0x05]), Some((5, 1)));
        assert_eq!(read_leb128(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn leb128_multi_byte() {
        assert_eq!(read_leb128(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_leb128(&[0xE5, 0x8E, 0x26]), Some((624485, 3)));
    }

    #[test]
    fn leb128_empty() {
        assert_eq!(read_leb128(&[]), None);
    }

    #[test]
    fn normalise_func_path() {
        let json = serde_json::json!({
            "worlds/test-app/funcs/hello": "Return a greeting."
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.get("func:hello").unwrap(), "Return a greeting.");
    }

    #[test]
    fn normalise_interface_path() {
        let json = serde_json::json!({
            "worlds/my-world/interfaces/my-api": "My API interface."
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.get("interface:my-api").unwrap(), "My API interface.");
    }

    #[test]
    fn normalise_interface_func_path() {
        let json = serde_json::json!({
            "interfaces/my-api/funcs/process": "Process data."
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.get("func:process").unwrap(), "Process data.");
    }

    #[test]
    fn normalise_flat_param() {
        let json = serde_json::json!({
            "analyse-data.values": "The data points.",
            "analyse-data.config": "Output configuration."
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.get("param:analyse-data.values").unwrap(), "The data points.");
        assert_eq!(docs.get("param:analyse-data.config").unwrap(), "Output configuration.");
    }

    #[test]
    fn normalise_flat_func() {
        let json = serde_json::json!({
            "hello": "A greeting.",
            "analyse-data": "Analyse values."
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.get("func:hello").unwrap(), "A greeting.");
        assert_eq!(docs.get("func:analyse-data").unwrap(), "Analyse values.");
    }

    #[test]
    fn normalise_skips_empty_and_non_string() {
        let json = serde_json::json!({
            "good": "kept",
            "empty": "",
            "number": 42
        });
        let mut docs = BTreeMap::new();
        normalise_package_docs(&json, &mut docs);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs.get("func:good").unwrap(), "kept");
    }

    fn make_wasm_with_custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00]);
        buf.push(0x00); // custom section id

        let name_bytes = name.as_bytes();
        let mut name_len_leb = Vec::new();
        encode_leb128(name_bytes.len(), &mut name_len_leb);

        let section_body_len = name_len_leb.len() + name_bytes.len() + payload.len();
        let mut section_len_leb = Vec::new();
        encode_leb128(section_body_len, &mut section_len_leb);

        buf.extend_from_slice(&section_len_leb);
        buf.extend_from_slice(&name_len_leb);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(payload);
        buf
    }

    fn encode_leb128(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn parse_docs_from_wasm_binary() {
        let json = serde_json::json!({
            "worlds/test-app/funcs/hello": "Greet the caller.",
            "analyse-data.values": "Input data."
        });
        let payload = serde_json::to_vec(&json).unwrap();
        let wasm = make_wasm_with_custom_section("package-docs", &payload);

        let docs = parse_package_docs(&wasm);
        assert_eq!(docs.get("func:hello").unwrap(), "Greet the caller.");
        assert_eq!(docs.get("param:analyse-data.values").unwrap(), "Input data.");
    }

    #[test]
    fn parse_docs_ignores_other_sections() {
        let payload = b"not json but irrelevant";
        let wasm = make_wasm_with_custom_section("other-section", payload);
        let docs = parse_package_docs(&wasm);
        assert!(docs.is_empty());
    }

    #[test]
    fn parse_docs_too_short() {
        let docs = parse_package_docs(&[0x00, 0x61]);
        assert!(docs.is_empty());
    }
}
