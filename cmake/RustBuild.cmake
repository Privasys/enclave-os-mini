# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# cmake/RustBuild.cmake
# Helpers for building Rust crates via Cargo from CMake.
#
# Toolchain: nightly-2025-12-01
# Enclave target: x86_64-unknown-linux-sgx (defined in Teaclave's rustlib/)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(RUST_ENCLAVE_TARGET "x86_64-unknown-linux-sgx" CACHE STRING
    "Rust target triple for SGX enclave builds")

set(RUST_ENCLAVE_TOOLCHAIN "nightly-2025-12-01" CACHE STRING
    "Rustup toolchain name for enclave builds")

# Build type mapping
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CARGO_BUILD_TYPE "--release")
    set(CARGO_OUT_DIR "release")
else()
    set(CARGO_BUILD_TYPE "")
    set(CARGO_OUT_DIR "debug")
endif()

# ---------------------------------------------------------------------------
# rust_build_host(CRATE_DIR OUTPUT_NAME)
#   Build a host-side Rust crate and produce a binary.
#   The host crate's build.rs handles EDL generation and C compilation itself.
#   NOTE: host is a workspace member → target dir is at the workspace root.
# ---------------------------------------------------------------------------
function(rust_build_host CRATE_DIR OUTPUT_NAME)
    add_custom_target(${OUTPUT_NAME} ALL
        COMMAND ${CMAKE_COMMAND} -E env
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            ${CARGO_EXECUTABLE} build
                ${CARGO_BUILD_TYPE}
                --manifest-path "${CRATE_DIR}/Cargo.toml"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Building host Rust crate: ${OUTPUT_NAME}"
    )

    # Workspace member: binary lands in workspace root target/
    set(${OUTPUT_NAME}_BINARY
        "${CMAKE_SOURCE_DIR}/target/${CARGO_OUT_DIR}/${OUTPUT_NAME}"
        PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# rust_build_enclave(CRATE_DIR OUTPUT_NAME [FEATURES])
#   Build an enclave-side Rust crate (staticlib) with the SGX sysroot.
#   Requires the sgx_sysroot target to have been built first (from the
#   Teaclave fork's CMakeLists.txt).
#
#   FEATURES (optional): comma-separated Cargo feature names to enable.
#     Passed as --no-default-features --features "sgx,default-ecall,<FEATURES>"
#     so that the caller controls exactly which modules are compiled in.
#     When empty, default features are used.
# ---------------------------------------------------------------------------
function(rust_build_enclave CRATE_DIR OUTPUT_NAME)
    # Optional 3rd argument: features
    set(_FEATURES "${ARGN}")

    if(NOT TEACLAVE_CHECKOUT)
        message(FATAL_ERROR "TEACLAVE_CHECKOUT not set. Run resolve_teaclave() first.")
    endif()

    set(TARGET_JSON "${TEACLAVE_CHECKOUT}/rustlib/${RUST_ENCLAVE_TARGET}.json")

    # Build the --features flag if modules were requested
    set(_FEATURES_ARGS "")
    if(_FEATURES)
        set(_FEATURES_ARGS --no-default-features --features "sgx,default-ecall,${_FEATURES}")
    endif()

    set(_BUILD_COMMENT "Building enclave Rust crate: ${OUTPUT_NAME}")
    if(_FEATURES)
        string(APPEND _BUILD_COMMENT " [${_FEATURES}]")
    endif()

    add_custom_target(${OUTPUT_NAME} ALL
        COMMAND ${CMAKE_COMMAND} -E env
            "SGX_SDK_PATH=${SGX_SDK_PATH}"
            "RUSTUP_TOOLCHAIN=${RUST_ENCLAVE_TOOLCHAIN}"
            "RUSTFLAGS=--sysroot ${SGX_SYSROOT_DIR} -C target-feature=+rdrand"
            ${CARGO_EXECUTABLE} build
                ${CARGO_BUILD_TYPE}
                --manifest-path "${CRATE_DIR}/Cargo.toml"
                --target "${TARGET_JSON}"
                ${_FEATURES_ARGS}
        WORKING_DIRECTORY "${CRATE_DIR}"
        COMMENT "${_BUILD_COMMENT}"
    )

    set(${OUTPUT_NAME}_STATIC_LIB
        "${CRATE_DIR}/target/${RUST_ENCLAVE_TARGET}/${CARGO_OUT_DIR}/lib${OUTPUT_NAME}.a"
        PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# sgx_link_enclave(STATIC_LIB EDL_OBJ ENCLAVE_SO)
#   Link the enclave static library + EDL trusted bridge into enclave.so.
#   Uses the Teaclave link recipe (no --whole-archive libsgx_trts).
# ---------------------------------------------------------------------------
function(sgx_link_enclave STATIC_LIB EDL_OBJ VERSION_SCRIPT ENCLAVE_SO)
    add_custom_command(
        OUTPUT "${ENCLAVE_SO}"
        COMMAND ${CMAKE_CXX_COMPILER}
            "${EDL_OBJ}"
            -o "${ENCLAVE_SO}"
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles
            -Wl,--start-group "${STATIC_LIB}" -Wl,--end-group
            -Wl,--version-script=${VERSION_SCRIPT}
            -Wl,-z,relro,-z,now,-z,noexecstack
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
            -Wl,-pie -Wl,--export-dynamic
            -Wl,--gc-sections
        DEPENDS "${STATIC_LIB}" "${EDL_OBJ}" "${VERSION_SCRIPT}"
        COMMENT "Linking enclave: ${ENCLAVE_SO}"
    )
endfunction()

# ---------------------------------------------------------------------------
# sgx_sign_enclave(ENCLAVE_SO CONFIG_XML KEY_PEM SIGNED_OUTPUT)
#   Sign an enclave shared object.
# ---------------------------------------------------------------------------
function(sgx_sign_enclave ENCLAVE_SO CONFIG_XML KEY_PEM SIGNED_OUTPUT)
    add_custom_command(
        OUTPUT "${SIGNED_OUTPUT}"
        COMMAND ${SGX_SIGN} sign
            -key "${KEY_PEM}"
            -enclave "${ENCLAVE_SO}"
            -out "${SIGNED_OUTPUT}"
            -config "${CONFIG_XML}"
        DEPENDS "${ENCLAVE_SO}" "${CONFIG_XML}" "${KEY_PEM}"
        COMMENT "Signing enclave: ${SIGNED_OUTPUT}"
    )
endfunction()
