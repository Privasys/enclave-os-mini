# Enclave OS (Mini)

A minimal OS layer for Intel SGX enclaves, written in Rust. It provides a
composable runtime for building confidential applications with built-in remote
attestation, encrypted storage, and optional WASM execution — all inside a
single SGX enclave.

## Features

| Feature | Description |
|---------|-------------|
| **RA-TLS Ingress** | TLS 1.3 with SGX DCAP quotes and config Merkle root embedded in X.509 certificates |
| **HTTPS Egress** | Outbound HTTPS from inside the enclave (TLS terminated in enclave, network I/O via host RPC) |
| **Sealed Key-Value Store** | Encrypted KV database — keys HMAC'd, values AES-256-GCM'd — master key sealed to MRENCLAVE |
| **WASM Runtime** | Execute WebAssembly apps inside SGX with WASI and Enclave OS SDK interfaces |
| **OIDC-Authenticated Vault** | Store and retrieve secrets gated by OIDC RBAC with dual-path GetSecret (OIDC owner + RA-TLS TEE) |
| **Sealed Config** | All persistent state stored as a single MRENCLAVE-bound blob |
| **Config Attestation** | Merkle root + per-module OIDs over all config inputs in every RA-TLS certificate |

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     Host (Untrusted)                       │
│                                                            │
│  ┌──────────────┐   ┌─────────────┐   ┌─────────────────┐  │
│  │ TCP Socket   │   │ KV Store    │   │ RPC Dispatcher  │  │
│  │ Table        │   │ Backend     │   │ (spin-polls     │  │
│  │ (net/)       │   │ (kvstore/)  │   │  enc_to_host)   │  │
│  └──────┬───────┘   └──────┬──────┘   └────────┬────────┘  │
│         │                  │                   │           │
│  ┌──────┴──────────────────┴───────────────────┴────────┐  │
│  │            Shared Memory SPSC Queues                 │  │
│  │  enc_to_host: [ring buf]  ← enclave writes requests  │  │
│  │  host_to_enc: [ring buf]  → host writes responses    │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                │
├───────────────────────────┼────────────────────────────────┤
│                           │     ← SGX boundary             │
│                           │       (4 ECALLs + 1 OCALL)     │
│  ┌────────────────────────┴─────────────────────────────┐  │
│  │                RPC Client                            │  │
│  │  (encodes requests → enc_to_host, reads responses)   │  │
│  └───┬──────────────┬──────────────┬────────────────────┘  │
│      │              │              │                       │
│  ┌───┴──────┐  ┌────┴───────┐  ┌───┴────────┐              │
│  │ RA-TLS   │  │ HTTPS      │  │ Sealed KV  │              │
│  │ Server   │  │ Egress     │  │ Store      │              │
│  │ (rustls) │  │ (rustls)   │  │ (AES-GCM)  │              │
│  └──────────┘  └────────────┘  └────────────┘              │
│                  Enclave (Trusted)                         │
└────────────────────────────────────────────────────────────┘
```

All host↔enclave communication flows through **lock-free SPSC ring buffers**
with a single OCALL for wake-up signalling. The enclave writes directly to
host memory — no context switch needed for data transfer.

## Modules

Business logic is implemented as **pluggable modules** conforming to the
`EnclaveModule` trait, each in its own crate:

| Module | Crate | Key OID |
|--------|-------|---------|
| **egress** | `crates/enclave-os-egress` | `1.3.6.1.4.1.65230.2.1` (Egress CA Hash) |
| **kvstore** | `crates/enclave-os-kvstore` | — |
| **wasm** | `crates/enclave-os-wasm` | `1.3.6.1.4.1.65230.2.5` (Combined Workloads Hash) |
| **vault** | `crates/enclave-os-vault` | — |

See [Architecture](docs/architecture.md) for the full module interface, composition model, and how to add your own.

## Quick Start

```bash
# Build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# First run — provision CA material
cd build/bin
./enclave-os-host \
    --port 8443 \
    --kv-path ./kvdata \
    --ca-cert /path/to/intermediary-ca.crt \
    --ca-key  /path/to/intermediary-ca.key

# Subsequent restarts — sealed config auto-loaded
./enclave-os-host --port 8443 --kv-path ./kvdata
```

See [Building and Usage](docs/building.md) for prerequisites, build options, WASM builds, and production deployment.

## Certificate Trust Chain

```
Root CA (your organization's root)
 └── Intermediary CA (sealed inside enclave)
      └── Leaf RA-TLS cert (per-connection, with SGX quote + config OIDs)
```

Every leaf certificate embeds:
- **SGX DCAP Quote** — proves code identity (MRENCLAVE)
- **Config Merkle Root** (`1.3.6.1.4.1.65230.1.1`) — proves operator-chosen configuration
- **Module OIDs** — per-module properties (e.g. egress CA hash, WASM code hash)

See [RA-TLS and Attestation](docs/ra-tls.md) for the full OID hierarchy, Merkle tree construction, verification strategies, and the honest reporter model.

## Security Model

| What | Where | How |
|------|-------|-----|
| TLS keys & plaintext | Enclave only | Generated per-connection, never leave enclave |
| CA material | Enclave only | Sealed to MRENCLAVE on first run |
| KV master key | Enclave only | RDRAND-generated, sealed in config |
| KV data at rest | Host (opaque) | Keys: HMAC-SHA256, Values: AES-256-GCM |
| Config attestation | X.509 cert | Merkle root + per-module OIDs in every RA-TLS cert |
| Network I/O | Host | Sees only ciphertext |

Clients verify: **MRENCLAVE** (code identity) + **Config Merkle Root** (config identity) + **Module OIDs** (individual property checks). The enclave is an honest reporter — no owner key or authorization gate.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Rust + SGX rationale, Teaclave fork, composable module design, SPSC queues, RPC protocol, sealed config |
| [RA-TLS and Attestation](docs/ra-tls.md) | Certificate trust chain, X.509 OID extensions, Config Merkle tree, verification strategies, per-app certificates |
| [WASM Runtime](docs/wasm-runtime.md) | Wasmtime fork for SGX, WASI + Enclave OS SDK interfaces, per-app isolation, building WASM apps |
| [Building and Usage](docs/building.md) | Prerequisites, build commands, running the enclave, WASM builds, client libraries, production deployment |
| [Layer 4 Proxy](docs/layer4-proxy.md) | Caddy (caddy-l4) and HAProxy configuration for TCP passthrough |

## Related Repositories

| Repository | Description |
|------------|-------------|
| [ra-tls-clients](https://github.com/Privasys/ra-tls-clients) | RA-TLS client libraries (Go, Python, Rust, TypeScript, C#) |
| [ra-tls-caddy](https://github.com/Privasys/ra-tls-caddy) | Caddy module for RA-TLS in Confidential VMs |
| [wasm-app-example](https://github.com/Privasys/wasm-app-example) | Example WASM app + composition crate for Enclave OS |
| [teaclave-sgx-sdk](https://github.com/Privasys/teaclave-sgx-sdk) | Privasys fork of Teaclave SGX SDK |
| [wasmtime](https://github.com/Privasys/wasmtime) | Privasys fork of Wasmtime (branch `sgx`, AOT-only) |

## Third-Party Dependencies

| Dependency | License | Usage |
|---|---|---|
| Teaclave SGX SDK (sgx_types, sgx_urts, sgx_tseal, sgx_tse) | Apache 2.0 | Intel SGX enclave SDK bindings (Privasys fork) |
| wasmtime | Apache 2.0 WITH LLVM-exception | WebAssembly runtime inside SGX (Privasys fork) |
| rocksdb | Apache 2.0 | Host-side key-value store |
| rustls | Apache 2.0 / MIT / ISC | TLS 1.3 implementation |
| ring | ISC | Cryptographic primitives (AES-GCM, ECDSA, SHA-256, HMAC) |
| rcgen | Apache 2.0 / MIT | X.509 certificate generation |
| serde / serde_json | Apache 2.0 / MIT | Serialization |
| getrandom | Apache 2.0 / MIT | RDRAND hardware RNG (enclave-wide via sgx_read_rand shim) |

Full dependency list and license texts in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).

## License

**GNU Affero General Public License v3.0** (AGPL-3.0)

Any modified versions or network services built on this software must make the complete source code available under the same license.

**Commercial licensing** is available for closed-source or proprietary use — contact **legal@privasys.org**.
