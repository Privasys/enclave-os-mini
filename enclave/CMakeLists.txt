# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# enclave/CMakeLists.txt
# Build the enclave crate → link enclave.so → sign it.
#
# ── Composable module flags ─────────────────────────────────────────────
# Each module is independently enabled.  Combine freely:
#
#   cmake -DENABLE_VAULT=ON                    → vault + kvstore + egress
#   cmake -DENABLE_WASM=ON                     → wasm  + kvstore + egress
#   cmake -DENABLE_FIDO2=ON                    → fido2 + kvstore
#   cmake -DENABLE_EGRESS=ON                   → egress only
#   cmake -DENABLE_KVSTORE=ON                  → kvstore only
#   cmake -DENABLE_VAULT=ON -DENABLE_WASM=ON   → all four modules
#   cmake -DENABLE_WASM=ON -DENABLE_FIDO2=ON   → wasm + fido2 (full auth)
#
# Each flag maps to a Cargo feature on the enclave crate.  The default
# ecall_run (feature = "default-ecall") registers whichever modules are
# enabled.  With no flags → HelloWorld only.
#
# For a completely custom ecall_run, set CUSTOM_ENCLAVE_DIR to an external
# composition crate (disables default-ecall automatically).

# -- Step 2: Build enclave crate (staticlib) --
option(ENABLE_EGRESS  "Include the HTTPS egress module"                       OFF)
option(ENABLE_KVSTORE "Include the sealed KV store module"                    OFF)
option(ENABLE_VAULT   "Include the vault module (implies egress + kvstore)"   OFF)
option(ENABLE_WASM    "Include the WASM runtime module (implies egress + kvstore)" OFF)
option(ENABLE_FIDO2   "Include the FIDO2/WebAuthn authentication module (implies kvstore)" OFF)

set(CUSTOM_ENCLAVE_DIR "" CACHE PATH
    "Path to an external composition crate with a custom ecall_run. \
     When set, all ENABLE_* flags are ignored and this crate is built instead.")

# ── Resolve crate directory and feature list ────────────────────────────
if(NOT CUSTOM_ENCLAVE_DIR STREQUAL "")
    # Escape hatch: fully custom composition crate
    set(_ENCLAVE_CRATE_DIR  "${CUSTOM_ENCLAVE_DIR}")
    # Derive the crate name from the directory (convention: last component)
    get_filename_component(_dir_name "${CUSTOM_ENCLAVE_DIR}" NAME)
    string(REPLACE "-" "_" _ENCLAVE_CRATE_NAME "${_dir_name}")
    set(_ENCLAVE_FEATURES "")
    message(STATUS "Custom enclave crate — building ${_ENCLAVE_CRATE_DIR} (${_ENCLAVE_CRATE_NAME})")
else()
    # Default: build enclave-os-enclave with composable features
    set(_ENCLAVE_CRATE_DIR  "${CMAKE_CURRENT_SOURCE_DIR}")
    set(_ENCLAVE_CRATE_NAME "enclave_os_enclave")

    # Build the feature list from ENABLE_* flags
    set(_features "")
    if(ENABLE_EGRESS)
        list(APPEND _features "egress")
    endif()
    if(ENABLE_KVSTORE)
        list(APPEND _features "kvstore")
    endif()
    if(ENABLE_VAULT)
        list(APPEND _features "vault")
    endif()
    if(ENABLE_WASM)
        list(APPEND _features "wasm")
    endif()
    if(ENABLE_FIDO2)
        list(APPEND _features "fido2")
    endif()

    # Join into comma-separated string for Cargo
    string(REPLACE ";" "," _ENCLAVE_FEATURES "${_features}")

    if(_ENCLAVE_FEATURES)
        message(STATUS "Enclave modules: ${_ENCLAVE_FEATURES}")
    else()
        message(STATUS "Enclave modules: none (HelloWorld only)")
    endif()
endif()

rust_build_enclave("${_ENCLAVE_CRATE_DIR}" ${_ENCLAVE_CRATE_NAME} "${_ENCLAVE_FEATURES}")
add_dependencies(${_ENCLAVE_CRATE_NAME} sgx_sysroot)
set(ENCLAVE_STATIC_LIB "${${_ENCLAVE_CRATE_NAME}_STATIC_LIB}")

# -- Step 3+4: EDL stubs are built in edl/ --
# EDL_TRUSTED_OBJ is set by edl/CMakeLists.txt

# -- Step 5: Link enclave.so --
set(ENCLAVE_SO "${CMAKE_BINARY_DIR}/bin/enclave.so")
set(VERSION_SCRIPT "${CMAKE_SOURCE_DIR}/config/enclave.lds")

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

sgx_link_enclave(
    "${ENCLAVE_STATIC_LIB}"
    "${EDL_TRUSTED_OBJ}"
    "${VERSION_SCRIPT}"
    "${ENCLAVE_SO}"
)
add_custom_target(enclave_so ALL
    DEPENDS "${ENCLAVE_SO}"
)
add_dependencies(enclave_so ${_ENCLAVE_CRATE_NAME} edl_trusted_obj)

# -- Step 6: Sign enclave --
# Pick debug vs release enclave config
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(ENCLAVE_CONFIG "${CMAKE_SOURCE_DIR}/config/enclave.config.release.xml")
else()
    set(ENCLAVE_CONFIG "${CMAKE_SOURCE_DIR}/config/enclave.config.xml")
endif()

set(ENCLAVE_KEY     "${CMAKE_SOURCE_DIR}/config/enclave_private.pem")
set(ENCLAVE_SIGNED  "${CMAKE_BINARY_DIR}/bin/enclave.signed.so")

# Generate a development signing key if it doesn't exist
if(NOT EXISTS "${ENCLAVE_KEY}")
    execute_process(
        COMMAND openssl genrsa -out "${ENCLAVE_KEY}" -3 3072
    )
endif()

sgx_sign_enclave(
    "${ENCLAVE_SO}"
    "${ENCLAVE_CONFIG}"
    "${ENCLAVE_KEY}"
    "${ENCLAVE_SIGNED}"
)
add_custom_target(signed_enclave ALL DEPENDS "${ENCLAVE_SIGNED}")
add_dependencies(signed_enclave enclave_so)
