# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# enclave/CMakeLists.txt
# Build the enclave crate → link enclave.so → sign it.
#
# By default this builds enclave-os-enclave (HelloWorld only).
# Set -DENABLE_WASM=ON to build the wasm-enclave composition crate
# which registers the WASM runtime module alongside HelloWorld.

# -- Step 2: Build enclave crate (staticlib) --
option(ENABLE_WASM "Build with WASM runtime module" OFF)
set(WASM_ENCLAVE_DIR "" CACHE PATH "Path to the wasm-enclave composition crate (required when ENABLE_WASM=ON)")

if(ENABLE_WASM)
    if(WASM_ENCLAVE_DIR STREQUAL "")
        message(FATAL_ERROR
            "ENABLE_WASM=ON requires WASM_ENCLAVE_DIR to be set.\n"
            "Point it at your composition crate, e.g.:\n"
            "  cmake -DENABLE_WASM=ON -DWASM_ENCLAVE_DIR=/path/to/wasm-app-example/enclave ..")
    endif()
    set(_ENCLAVE_CRATE_DIR "${WASM_ENCLAVE_DIR}")
    set(_ENCLAVE_CRATE_NAME "enclave_os_wasm_app")
    message(STATUS "WASM runtime enabled — building ${_ENCLAVE_CRATE_DIR}")
else()
    set(_ENCLAVE_CRATE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    set(_ENCLAVE_CRATE_NAME "enclave_os_enclave")
endif()

rust_build_enclave("${_ENCLAVE_CRATE_DIR}" ${_ENCLAVE_CRATE_NAME})
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
