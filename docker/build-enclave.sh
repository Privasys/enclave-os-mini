#!/usr/bin/env bash
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.
#
# build-enclave.sh — Deterministic build of enclave-os-mini inside the Docker container.
#
# This script is the ENTRYPOINT for docker/Dockerfile.build.
# It expects the source tree to be mounted at /src.

set -euo pipefail

SRC=/src
BUILD_DIR="${SRC}/build"
BIN_DIR="${BUILD_DIR}/bin"

# ── Deterministic environment ────────────────────────────────────────────
export SOURCE_DATE_EPOCH=0
export CARGO_INCREMENTAL=0
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# SGX SDK environment (the script appends to vars that may not yet exist,
# so temporarily relax nounset).
set +u
source /opt/intel/sgxsdk/environment
set -u

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  enclave-os-mini — Reproducible Build                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  rustc : $(rustc --version)"
echo "  cargo : $(cargo --version)"
echo "  gcc   : $(gcc --version | head -1)"
echo "  cmake : $(cmake --version | head -1)"
echo "  sgx   : ${SGX_SDK:-/opt/intel/sgxsdk}"
echo ""

# ── Step 1: Fetch dependencies ──────────────────────────────────────────
echo "==> Fetching Cargo dependencies..."
cd "${SRC}"
cargo fetch --locked

# Also fetch the enclave crate (separate workspace)
cargo fetch --locked --manifest-path enclave/Cargo.toml

# ── Step 2: CMake configure ─────────────────────────────────────────────
echo "==> Configuring CMake build..."
cmake -S "${SRC}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_WASM=ON \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_CXX_COMPILER=g++

# ── Step 3: Build everything ────────────────────────────────────────────
echo "==> Building enclave + host..."
cmake --build "${BUILD_DIR}" -j"$(nproc)"

# ── Step 4: Extract MRENCLAVE ───────────────────────────────────────────
echo "==> Extracting MRENCLAVE..."
MRENCLAVE=$(bash "${SRC}/scripts/extract-mrenclave.sh" "${BIN_DIR}/enclave.signed.so")
echo "${MRENCLAVE}" > "${BUILD_DIR}/mrenclave.txt"

# ── Step 5: Build summary ──────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Build Complete                                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "  MRENCLAVE : ${MRENCLAVE}"
echo "  enclave   : ${BIN_DIR}/enclave.signed.so"
echo "  host      : $(ls "${SRC}"/target/release/enclave-os-host 2>/dev/null || echo 'N/A')"
echo "  sha256    : $(sha256sum "${BIN_DIR}/enclave.so" | cut -d' ' -f1)"
echo "╚══════════════════════════════════════════════════════════════╝"
