# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# cmake/SgxConfig.cmake
# Detect and configure the Intel SGX SDK paths and compiler flags.

# ---- Auto-detect SGX SDK ----
if(NOT SGX_SDK_PATH)
    if(EXISTS "/opt/intel/sgxsdk")
        set(SGX_SDK_PATH "/opt/intel/sgxsdk")
    elseif(DEFINED ENV{SGX_SDK})
        set(SGX_SDK_PATH "$ENV{SGX_SDK}")
    endif()
endif()

if(NOT EXISTS "${SGX_SDK_PATH}")
    message(WARNING "SGX SDK not found at '${SGX_SDK_PATH}'. "
        "Set -DSGX_SDK_PATH=... or the SGX_SDK environment variable.")
endif()

# ---- Paths ----
set(SGX_INCLUDE_DIR "${SGX_SDK_PATH}/include")
set(SGX_EDGER8R     "${SGX_SDK_PATH}/bin/x64/sgx_edger8r")
set(SGX_SIGN        "${SGX_SDK_PATH}/bin/x64/sgx_sign")
set(SGX_LIBRARY_DIR "${SGX_SDK_PATH}/lib64")

# ---- Enclave C flags (for compiling EDL trusted stubs) ----
# Defined as a CMake list (no quotes) so each flag is a separate argument.
set(ENCLAVE_C_FLAGS
    -ffreestanding -nostdinc -fvisibility=hidden -fpie
    -fno-strict-overflow -fno-delete-null-pointer-checks -m64)

message(STATUS "SGX SDK: ${SGX_SDK_PATH}")
