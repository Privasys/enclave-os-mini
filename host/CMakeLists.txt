# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

# host/CMakeLists.txt
# Build the host binary.
# host/build.rs handles EDL untrusted stub generation, C compilation, and sgx_urts linking.

rust_build_host("${CMAKE_CURRENT_SOURCE_DIR}" enclave-os-host)

# The host binary goes to build/bin/
set(HOST_BIN "${enclave-os-host_BINARY}")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Use add_custom_target (always runs) so the copy_if_different fires after every
# Cargo rebuild, even when CMake can't track the Rust binary's timestamp.
add_custom_target(host_binary ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${HOST_BIN}" "${CMAKE_BINARY_DIR}/bin/enclave-os-host"
    DEPENDS enclave-os-host
    COMMENT "Copying host binary to build/bin/"
)