#!/usr/bin/env bash
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.
#
# extract-mrenclave.sh — Extract MRENCLAVE from a signed SGX enclave binary.
#
# Usage:
#   ./scripts/extract-mrenclave.sh build/bin/enclave.signed.so
#
# Output:  hex-encoded MRENCLAVE on stdout (lowercase, no spaces).
# Requires: sgx_sign from the Intel SGX SDK.

set -euo pipefail

SIGNED_ENCLAVE="${1:?Usage: $0 <path-to-enclave.signed.so>}"

SGX_SIGN="${SGX_SIGN:-/opt/intel/sgxsdk/bin/x64/sgx_sign}"
if [[ ! -x "$SGX_SIGN" ]]; then
    echo >&2 "ERROR: sgx_sign not found at $SGX_SIGN"
    echo >&2 "       Set SGX_SIGN= or install the Intel SGX SDK."
    exit 1
fi

TMPFILE=$(mktemp /tmp/mrenclave.XXXXXX)
trap 'rm -f "$TMPFILE"' EXIT

"$SGX_SIGN" dump -enclave "$SIGNED_ENCLAVE" -dumpfile "$TMPFILE" >/dev/null 2>&1

# Parse the two hex lines after "enclave_hash.m:"
MRENCLAVE=$(awk '/enclave_hash\.m:/{found=1; next} found && /^0x/{
    gsub(/0x/, ""); gsub(/ /, ""); printf "%s", $0; count++
    if(count>=2){exit}
}' "$TMPFILE")

if [[ -z "$MRENCLAVE" ]]; then
    echo >&2 "ERROR: Could not extract MRENCLAVE from $SIGNED_ENCLAVE"
    exit 1
fi

echo "$MRENCLAVE"
