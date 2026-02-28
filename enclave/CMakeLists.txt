# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# enclave/CMakeLists.txt
# Build the enclave crate → link enclave.so → sign it.
#
# The enclave-os-enclave crate (this directory) provides the default
# ecall_run with the HelloWorld module. Adopters who need additional
# modules (e.g. WASM) create a separate project with a custom ecall_run
# and point CMake at it instead.

# -- Step 2: Build enclave crate (staticlib) --
rust_build_enclave("${CMAKE_CURRENT_SOURCE_DIR}" enclave_os_enclave)
add_dependencies(enclave_os_enclave sgx_sysroot)
set(ENCLAVE_STATIC_LIB "${enclave_os_enclave_STATIC_LIB}")

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
add_dependencies(enclave_so enclave_os_enclave edl_trusted_obj)

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
