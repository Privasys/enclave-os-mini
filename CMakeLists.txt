# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

cmake_minimum_required(VERSION 3.20)
project(enclave-os-mini LANGUAGES C CXX)

# =============================================================================
# Options
# =============================================================================
option(BUILD_HOST    "Build host-side binary"     ON)
option(BUILD_ENCLAVE "Build enclave-side targets" ON)

set(SGX_SDK_PATH "" CACHE PATH "Path to Intel SGX SDK (auto-detected if empty)")

# =============================================================================
# Detect platform
# =============================================================================
if(NOT (UNIX AND NOT APPLE))
    message(FATAL_ERROR "SGX enclaves require Linux. Use WSL or a Linux build host.")
endif()

# =============================================================================
# SGX SDK + Rust helpers
# =============================================================================
include(cmake/SgxConfig.cmake)
include(cmake/RustBuild.cmake)

# =============================================================================
# Resolve Teaclave checkout (same logic as build_all.sh's resolve_teaclave)
# =============================================================================
# The Cargo.lock in the workspace pins the teaclave-sgx-sdk commit hash.
# We parse it and find the matching checkout directory under ~/.cargo/git/checkouts.

# Find the teaclave-sgx-sdk base checkout directory
file(GLOB TEACLAVE_BASE "$ENV{HOME}/.cargo/git/checkouts/teaclave-sgx-sdk-*")
list(GET TEACLAVE_BASE 0 TEACLAVE_BASE)

# Extract the commit hash from the workspace Cargo.lock
file(READ "${CMAKE_SOURCE_DIR}/Cargo.lock" _CARGO_LOCK)
string(REGEX MATCH "teaclave-sgx-sdk[^\n]*#([0-9a-f]+)" _MATCH "${_CARGO_LOCK}")
set(TEACLAVE_FULL_REV "${CMAKE_MATCH_1}")
string(SUBSTRING "${TEACLAVE_FULL_REV}" 0 7 TEACLAVE_SHORT_REV)

set(TEACLAVE_CHECKOUT "${TEACLAVE_BASE}/${TEACLAVE_SHORT_REV}")
if(NOT EXISTS "${TEACLAVE_CHECKOUT}")
    message(FATAL_ERROR
        "Teaclave checkout not found at ${TEACLAVE_CHECKOUT}. "
        "Run 'cargo fetch' in the workspace first.")
endif()

message(STATUS "Teaclave SDK: ${TEACLAVE_CHECKOUT}")

# Paths derived from the Teaclave checkout
set(TEACLAVE_EDL_DIR  "${TEACLAVE_CHECKOUT}/sgx_edl/edl")
set(TEACLAVE_INC_DIR  "${TEACLAVE_CHECKOUT}/common/inc")
set(TEACLAVE_TLIBC    "${TEACLAVE_CHECKOUT}/common/inc/tlibc")
set(SGX_SYSROOT_DIR   "${CMAKE_SOURCE_DIR}/sysroot")

# =============================================================================
# Step 1: Build SGX sysroot (via the fork's CMake sgx_sysroot target)
# =============================================================================
if(BUILD_ENCLAVE)
    set(SYSROOT_BUILD_DIR "${TEACLAVE_CHECKOUT}/build_sysroot")

    # ExternalProject-like: configure + build the fork's sysroot target
    set(SYSROOT_STAMP "${CMAKE_BINARY_DIR}/sysroot.stamp")
    add_custom_command(
        OUTPUT "${SYSROOT_STAMP}"
        COMMENT "Building SGX sysroot via Teaclave fork CMake..."
        COMMAND ${CMAKE_COMMAND}
            -S "${TEACLAVE_CHECKOUT}"
            -B "${SYSROOT_BUILD_DIR}"
            -DBUILD_SYSROOT=ON
            -DBUILD_URTS=OFF
            -DSGX_SYSROOT_OUTPUT=${SGX_SYSROOT_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        COMMAND ${CMAKE_COMMAND}
            --build "${SYSROOT_BUILD_DIR}"
            --target sgx_sysroot
        COMMAND ${CMAKE_COMMAND} -E touch "${SYSROOT_STAMP}"
        VERBATIM
    )
    add_custom_target(sgx_sysroot DEPENDS "${SYSROOT_STAMP}")
endif()

# =============================================================================
# Subdirectories
# =============================================================================
if(BUILD_ENCLAVE)
    add_subdirectory(edl)
    add_subdirectory(enclave)
endif()

if(BUILD_HOST)
    add_subdirectory(host)
endif()

# =============================================================================
# Summary
# =============================================================================
message(STATUS "---------- enclave-os-mini ----------")
message(STATUS "  BUILD_HOST      = ${BUILD_HOST}")
message(STATUS "  BUILD_ENCLAVE   = ${BUILD_ENCLAVE}")
message(STATUS "  CMAKE_BUILD_TYPE= ${CMAKE_BUILD_TYPE}")
message(STATUS "  SGX_SDK_PATH    = ${SGX_SDK_PATH}")
message(STATUS "  TEACLAVE        = ${TEACLAVE_CHECKOUT}")
message(STATUS "  SYSROOT         = ${SGX_SYSROOT_DIR}")
message(STATUS "-------------------------------------")
