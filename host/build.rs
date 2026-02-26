// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Build script for the host crate.
//!
//! On Linux (non-mock) this:
//!   1. Runs sgx_edger8r --untrusted to generate enclave_os_u.c / _u.h
//!   2. Compiles the generated C stub
//!   3. Links against the SGX untrusted runtime (libsgx_urts)
//!
//! On Windows or with the `mock` feature, this is a no-op.

use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let mock = env::var("CARGO_FEATURE_MOCK").is_ok();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SGX_SDK");
    println!("cargo:rerun-if-env-changed=SGX_SDK_PATH");
    println!("cargo:rerun-if-env-changed=TEACLAVE_SGX_SDK");

    // No SGX linking needed on non-Linux / mock mode
    if target_os != "linux" || mock {
        return;
    }

    let sgx_sdk = env::var("SGX_SDK")
        .or_else(|_| env::var("SGX_SDK_PATH"))
        .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // -----------------------------------------------------------------------
    //  Step 1: Locate the EDL file
    // -----------------------------------------------------------------------
    let edl_file = find_edl_file();
    println!("cargo:rerun-if-changed={}", edl_file.display());

    // -----------------------------------------------------------------------
    //  Step 2: Locate sgx_edger8r and the teaclave EDL search paths
    // -----------------------------------------------------------------------
    let edger8r = find_edger8r(&sgx_sdk);
    let teaclave_edl_dir = find_teaclave_edl_dir();

    // -----------------------------------------------------------------------
    //  Step 3: Run sgx_edger8r --untrusted
    // -----------------------------------------------------------------------
    let mut cmd = std::process::Command::new(&edger8r);
    cmd.arg("--untrusted")
        .arg(&edl_file)
        .arg("--untrusted-dir")
        .arg(&out_dir)
        .arg("--search-path")
        .arg(format!("{}/include", sgx_sdk));

    if let Some(ref dir) = teaclave_edl_dir {
        cmd.arg("--search-path").arg(dir);
    }

    eprintln!("cargo:warning=Running edger8r: {:?}", cmd);
    let output = cmd.output().expect("Failed to execute sgx_edger8r");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "sgx_edger8r failed (status {}):\nstdout: {}\nstderr: {}",
            output.status, stdout, stderr
        );
    }

    // -----------------------------------------------------------------------
    //  Step 4: Compile the generated untrusted bridge C code
    // -----------------------------------------------------------------------
    let u_c = out_dir.join("enclave_os_u.c");
    assert!(
        u_c.exists(),
        "sgx_edger8r did not generate {:?}",
        u_c
    );

    let mut build = cc::Build::new();
    build
        .file(&u_c)
        .include(&out_dir)
        .include(format!("{}/include", sgx_sdk));

    // The generated header may include files from the teaclave EDL directory
    // (e.g. "inc/stat.h" from sgx_tstd.edl / sgx_net.edl).
    if let Some(ref dir) = teaclave_edl_dir {
        build.include(dir);
        // Also include the common/inc directory for types used by EDL stubs
        let inc_dir = dir.parent().unwrap().parent().unwrap().join("common/inc");
        if inc_dir.is_dir() {
            build.include(&inc_dir);
        }
    }

    build.compile("enclave_os_u");

    // -----------------------------------------------------------------------
    //  Step 5: Link SGX SDK untrusted libraries
    // -----------------------------------------------------------------------
    println!("cargo:rustc-link-search=native={}/lib64", sgx_sdk);
    println!("cargo:rustc-link-lib=sgx_urts");
    // DCAP quoting libraries are dynamically loaded at runtime by AESM;
    // we don't need to link them into the host binary.
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Locate `edl/enclave_os.edl` relative to the workspace root.
fn find_edl_file() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // manifest_dir = <workspace>/host → parent = <workspace>
    let workspace = manifest_dir.parent().expect("Cannot find workspace root");
    let edl = workspace.join("edl/enclave_os.edl");
    assert!(
        edl.exists(),
        "Cannot find EDL file at {:?}",
        edl
    );
    edl
}

/// Locate `sgx_edger8r` inside the SGX SDK installation.
fn find_edger8r(sgx_sdk: &str) -> PathBuf {
    for sub in &["bin/x64/sgx_edger8r", "bin/sgx_edger8r"] {
        let p = PathBuf::from(sgx_sdk).join(sub);
        if p.exists() {
            return p;
        }
    }
    panic!(
        "Cannot find sgx_edger8r in SGX SDK at {}. \
         Make sure SGX SDK is installed and SGX_SDK or SGX_SDK_PATH is set.",
        sgx_sdk
    );
}

/// Find the teaclave-sgx-sdk `sgx_edl/edl` directory which contains the
/// standard EDL files (sgx_tstd.edl, sgx_net.edl, …).
///
/// Search order:
///   1. `TEACLAVE_SGX_SDK` env var (explicit checkout)
///   2. Cargo git checkouts (~/.cargo/git/checkouts/incubator-teaclave-sgx-sdk-*)
fn find_teaclave_edl_dir() -> Option<PathBuf> {
    // 1. Environment variable
    if let Ok(dir) = env::var("TEACLAVE_SGX_SDK") {
        let p = PathBuf::from(&dir).join("sgx_edl/edl");
        if p.is_dir() {
            return Some(p);
        }
    }

    // 2. Cargo git checkouts
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_default();
    let checkouts = PathBuf::from(&home).join(".cargo/git/checkouts");

    if checkouts.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&checkouts) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Match both the Apache fork and Privasys fork checkout names
                if name_str.starts_with("incubator-teaclave-sgx-sdk")
                    || name_str.starts_with("teaclave-sgx-sdk")
                {
                    // Each checkout has hash-named subdirectories
                    if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                        for sub in sub_entries.flatten() {
                            let edl_path = sub.path().join("sgx_edl/edl");
                            if edl_path.is_dir() {
                                return Some(edl_path);
                            }
                        }
                    }
                }
            }
        }
    }

    eprintln!(
        "cargo:warning=Could not find teaclave-sgx-sdk EDL directory. \
         Set TEACLAVE_SGX_SDK env var pointing to the repo checkout."
    );
    None
}
