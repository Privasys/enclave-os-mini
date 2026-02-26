# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

cmake_minimum_required(VERSION 3.24)

# Integration tests
if(BUILD_HOST)
    add_custom_target(run_tests
        COMMAND ${CARGO_EXECUTABLE} test
            --manifest-path "${CMAKE_SOURCE_DIR}/Cargo.toml"
            --target-dir "${CMAKE_BINARY_DIR}/rust-target"
            --workspace
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Running Rust workspace tests"
    )
endif()
