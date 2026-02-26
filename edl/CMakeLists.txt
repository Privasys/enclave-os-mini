# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# edl/CMakeLists.txt
# Run sgx_edger8r to generate trusted/untrusted bridge code, then compile
# the trusted stub into an object file for linking into the enclave.

set(EDL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/enclave_os.edl")
set(EDL_OUTPUT_DIR "${CMAKE_BINARY_DIR}/edl")
file(MAKE_DIRECTORY "${EDL_OUTPUT_DIR}")

# Output files
set(EDL_T_C "${EDL_OUTPUT_DIR}/enclave_os_t.c")
set(EDL_T_H "${EDL_OUTPUT_DIR}/enclave_os_t.h")
set(EDL_U_C "${EDL_OUTPUT_DIR}/enclave_os_u.c")
set(EDL_U_H "${EDL_OUTPUT_DIR}/enclave_os_u.h")

# -- Generate trusted stubs --
add_custom_command(
    OUTPUT "${EDL_T_C}" "${EDL_T_H}"
    COMMAND ${SGX_EDGER8R} --trusted "${EDL_FILE}"
        --search-path "${TEACLAVE_EDL_DIR}"
        --search-path "${TEACLAVE_INC_DIR}"
        --trusted-dir "${EDL_OUTPUT_DIR}"
    DEPENDS "${EDL_FILE}"
    COMMENT "edger8r --trusted enclave_os.edl"
)

# -- Generate untrusted stubs --
add_custom_command(
    OUTPUT "${EDL_U_C}" "${EDL_U_H}"
    COMMAND ${SGX_EDGER8R} --untrusted "${EDL_FILE}"
        --search-path "${TEACLAVE_EDL_DIR}"
        --search-path "${TEACLAVE_INC_DIR}"
        --untrusted-dir "${EDL_OUTPUT_DIR}"
    DEPENDS "${EDL_FILE}"
    COMMENT "edger8r --untrusted enclave_os.edl"
)

# -- Compile the trusted C stub into an object file --
# This is the same gcc invocation that build_all.sh Step 4 performed.
set(EDL_T_O "${EDL_OUTPUT_DIR}/enclave_os_t.o")
add_custom_command(
    OUTPUT "${EDL_T_O}"
    COMMAND ${CMAKE_C_COMPILER}
        ${ENCLAVE_C_FLAGS}
        -I${TEACLAVE_EDL_DIR}
        -I${TEACLAVE_INC_DIR}
        -I${TEACLAVE_TLIBC}
        -I${SGX_INCLUDE_DIR}
        -I${SGX_INCLUDE_DIR}/tlibc
        -c "${EDL_T_C}"
        -o "${EDL_T_O}"
    DEPENDS "${EDL_T_C}" "${EDL_T_H}"
    COMMENT "CC => enclave_os_t.o"
)

# Convenience targets
add_custom_target(edl_trusted   DEPENDS "${EDL_T_C}" "${EDL_T_H}")
add_custom_target(edl_untrusted DEPENDS "${EDL_U_C}" "${EDL_U_H}")
add_custom_target(edl_trusted_obj DEPENDS "${EDL_T_O}")

# Export paths for use by enclave/CMakeLists.txt
set(EDL_TRUSTED_OBJ "${EDL_T_O}" PARENT_SCOPE)
