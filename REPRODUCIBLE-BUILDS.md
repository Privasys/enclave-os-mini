# Reproducible Builds

enclave-os-mini uses Intel SGX to create a Trusted Execution Environment (TEE).
The cryptographic identity of the enclave — its **MRENCLAVE** — is a SHA-256 hash
of the enclave's code, data, and memory layout. Anyone who verifies an SGX DCAP
quote checks this value to trust the code running inside the enclave.

For this trust model to work, builds must be **reproducible**: the same source
code must always produce the same MRENCLAVE, regardless of where or when it is
built.

## Why Builds Can Differ

SGX MRENCLAVE depends on the exact bytes of `enclave.so`. Even tiny differences
in the binary — from a different compiler version, linker, or standard library —
produce a completely different MRENCLAVE.

| Factor | Impact on MRENCLAVE |
|--------|-------------------|
| Rust compiler version | Different codegen → **different** MRENCLAVE |
| SGX sysroot (Rust stdlib for SGX target) | **Primary cause** — built from source, non-deterministic across machines |
| Linker version (ld) | Layout differences → different MRENCLAVE |
| SGX SDK version | Enclave metadata/loader differences |
| Signing key | Changes MRSIGNER only, **not** MRENCLAVE |
| Enclave config (heap, stack, TCS) | Changes memory layout → different MRENCLAVE |
| Source code | Obviously |

### Key Insight

Cargo includes dependency version info in its `-C metadata=HASH` compiler flag,
which gets embedded in every symbol name. If even one transitive dependency
resolves to a different minor version, the entire binary changes.

This is why **both `Cargo.lock` files are committed** to this repository and
builds use `--locked` — ensuring every machine resolves the exact same
dependency tree.

## Solution: Docker Build Container

We solve this with a **pinned Docker build container** that freezes every tool
version and ensures byte-identical output.

### Quick Start

```bash
# Build the container (one-time)
docker build -f docker/Dockerfile.build -t privasys/enclave-os-build .

# Build the enclave
docker run --rm -v $(pwd):/src privasys/enclave-os-build

# Check MRENCLAVE
cat build/mrenclave.txt
```

### What's Pinned

| Component | Version | How |
|-----------|---------|-----|
| Base image | `ubuntu:24.04` | Docker image digest in Dockerfile |
| Rust | `nightly-2025-12-01` | `rust-toolchain.toml` + Dockerfile |
| rust-src | bundled with toolchain | `rust-toolchain.toml` |
| GCC | 13.3.0 | Ubuntu 24.04 default |
| Binutils/ld | 2.42 | Ubuntu 24.04 default |
| cmake | 3.28.x | Ubuntu 24.04 default |
| Intel SGX SDK | 2.27.100.1 | Pinned in Dockerfile |
| Teaclave SGX SDK | privasys-v0.1.0 | Pinned in `Cargo.lock` |
| All Cargo deps | exact versions | `Cargo.lock` (committed) |

### Deterministic Settings

The container also sets:
- `CARGO_INCREMENTAL=0` — disables incremental compilation
- `SOURCE_DATE_EPOCH=0` — zeroes embedded timestamps
- `LC_ALL=C.UTF-8` / `TZ=UTC` — locale and timezone normalization
- Fixed `CARGO_HOME` / `RUSTUP_HOME` paths — removes user-specific paths

## CI/CD

The GitHub Actions workflow (`.github/workflows/release.yml`) automates this:

1. **On tag push** (e.g., `v0.4.0`): Builds the Docker image, runs the build
   inside it, extracts MRENCLAVE, and creates a GitHub Release with:
   - `enclave.signed.so` — signed enclave binary
   - `enclave-os-host` — host binary
   - `mrenclave.txt` — hex MRENCLAVE
   - `build-manifest.json` — full build metadata

2. **Manual dispatch**: Can be triggered at any time for testing.

### Verify a Release

```bash
# Clone at the release tag
git clone --branch v0.4.0 https://github.com/Privasys/enclave-os-mini.git
cd enclave-os-mini

# Build in the same container
docker build -f docker/Dockerfile.build -t enclave-build .
docker run --rm -v $(pwd):/src enclave-build

# Compare MRENCLAVE with the release
cat build/mrenclave.txt
# Should match the MRENCLAVE listed in the GitHub release notes
```

## Signing Key and MRSIGNER

The **enclave signing key** (`config/enclave_private.pem`) is auto-generated at
build time if it doesn't exist. It is `.gitignored` — each build environment
gets its own key.

- **MRENCLAVE** (code identity): Determined by the binary. **Not affected** by
  the signing key. Reproducible builds guarantee the same MRENCLAVE.
- **MRSIGNER** (signer identity): Determined by the signing key. Different keys
  → different MRSIGNER.

For production deployments where MRSIGNER verification is also needed, use a
canonical signing key stored securely (e.g., in a hardware security module or
GitHub Secrets).

## Updating the Toolchain

When upgrading any build tool:

1. Update the version in `docker/Dockerfile.build`
2. Update `rust-toolchain.toml` if changing the Rust nightly
3. Rebuild the Docker image
4. Record the new MRENCLAVE — it **will** change
5. Update `ISVSVN` in `config/enclave.config.release.xml` to signal the change
6. Tag a new release

## Files

| File | Purpose |
|------|---------|
| `docker/Dockerfile.build` | Reproducible build container definition |
| `docker/build-enclave.sh` | Build script (container entrypoint) |
| `rust-toolchain.toml` | Pins Rust nightly + components |
| `scripts/extract-mrenclave.sh` | Extracts MRENCLAVE from signed enclave |
| `.github/workflows/release.yml` | CI/CD workflow for releases |
