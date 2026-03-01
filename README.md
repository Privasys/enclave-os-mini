# Enclave OS (Mini)

A minimal OS layer for Intel SGX enclaves, written in Rust. Provides:

1. **RA-TLS Ingress**  Accept incoming TCP connections authenticated via Remote Attestation TLS (TLS 1.3 with SGX quotes embedded in X.509 certificates)
2. **HTTPS Egress**  Make outbound HTTPS requests from inside the enclave (TLS termination inside the enclave, network I/O via host RPC)  *egress module*
3. **Sealed Key-Value Store**  Encrypted KV database stored on the host, with both keys and values encrypted using a master key that is sealed to `MRENCLAVE`  *kvstore module*
4. **WASM Runtime**  Execute third-party WebAssembly bytecode inside SGX with WASI support (random, clocks, filesystem, sockets, IO/streams, CLI)  *wasm module*
5. **JWT-Authenticated Vault**  Store and retrieve secrets gated by ES256 JWT verification  *vault module*
6. **Sealed Config**  All persistent state (CA material, egress CA bundle, KV master key) stored as a single MRENCLAVE-bound blob
7. **Config Attestation**  A Merkle root and per-module OIDs over all config inputs are embedded as custom X.509 extensions in every RA-TLS certificate

## Modular Architecture

All business logic is implemented as **pluggable modules** that conform to the [`EnclaveModule`] trait and are registered at enclave startup. The core OS provides only:

- RA-TLS ingress server
- HTTPS egress client
- Sealed key-value store

Each module lives in its own crate under `crates/enclave-os-*`, keeping the core enclave small and each concern independently testable.

### Module Interface

Each module implements the following trait (see `enclave/src/modules/mod.rs`):

```rust
pub trait EnclaveModule: Send + Sync {
    /// Human-readable module name.
    fn name(&self) -> &str;
    /// Handle a client request.
    fn handle(&self, req: &Request) -> Option<Response>;
    /// Config leaves for the Merkle tree (default: none).
    fn config_leaves(&self) -> Vec<ConfigLeaf> { Vec::new() }
    /// Custom X.509 OIDs for RA-TLS certificates (default: none).
    fn custom_oids(&self) -> Vec<ModuleOid> { Vec::new() }
    /// Per-app identities for SNI-routed X.509 certificates (default: none).
    fn app_identities(&self) -> Vec<AppIdentity> { Vec::new() }
}
```

- `config_leaves()`  named inputs hashed into the config Merkle root OID.
- `custom_oids()`  individual X.509 OID extensions embedded in every RA-TLS certificate, allowing clients to verify specific module properties without full Merkle audit.
- `app_identities()`  per-app identities, each getting its own leaf cert (signed by the Enclave CA) with a dedicated Merkle tree and OID extensions, served via SNI routing.

### Module Crates

| Module | Crate | Description |
|--------|-------|-------------|
| **egress** | `crates/enclave-os-egress` | HTTPS egress client; owns egress root CA store; registers `egress.ca_bundle` leaf + OID `1.3.6.1.4.1.65230.2.1` |
| **kvstore** | `crates/enclave-os-kvstore` | Sealed (AES-256-GCM) KV store; owns master key from sealed config |
| **wasm** | `crates/enclave-os-wasm` | WASM runtime; registers `wasm.code_hash` leaf + OID `1.3.6.1.4.1.65230.2.3` |
| **vault** | `crates/enclave-os-vault` | JWT-authenticated (ES256) secret store/retrieval |
| **helloworld** | `enclave/src/modules/helloworld.rs` | Smoke-test module: responds `"world"` to `"hello"` (inline, used by `default-ecall` feature) |

Modules are registered at startup:

```rust
crate::modules::register_module(Box::new(MyModule));
```

The enclave dispatches all requests to registered modules. If a module returns `Some(response)`, that response is sent to the client.

#### Example: HelloWorld Module

See `enclave/src/modules/helloworld.rs` for a minimal example:

```rust
pub struct HelloWorldModule;
impl EnclaveModule for HelloWorldModule {
    fn name(&self) -> &str { "helloworld" }
    fn handle(&self, req: &Request) -> Option<Response> {
        match req {
            Request::Data(payload) if payload == b"hello" => {
                Some(Response::Data(b"world".to_vec()))
            }
            _ => None,
        }
    }
}
```

#### Adding Your Own Module

1. Create a new crate: `crates/enclave-os-mymodule/` with a `Cargo.toml` depending on `enclave-os-enclave` and `enclave-os-common`.
2. Implement the `EnclaveModule` trait (including `name()`, `handle()`, and optionally `config_leaves()` + `custom_oids()`).
3. Create a composition crate that depends on `enclave-os-enclave` (with `default-features = false, features = ["sgx"]`) and your module crate. Provide a custom `ecall_run` that registers your module.
4. Point CMake at your composition crate instead of `enclave/`.

See [wasm-app-example](https://github.com/Privasys/wasm-app-example) for a complete example.

---

## Architecture

All host↔enclave communication flows through **shared-memory SPSC queues**
with a **single OCALL** (`ocall_notify`) for wake-up signalling. The enclave
writes directly to host memory without context-switching.

```
┌────────────────────────────────────────────────────────────┐
│                     Host (Untrusted)                       │
│                                                            │
│  ┌──────────────┐   ┌─────────────┐   ┌────────────────┐   │
│  │ TCP Socket   │   │ KV Store    │   │ RPC Dispatcher │   │
│  │ Table        │   │ Backend     │   │ (spin-polls    │   │
│  │ (net/)       │   │ (kvstore/)  │   │  enc_to_host)  │   │
│  └──────┬───────┘   └──────┬──────┘   └────────┬───────┘   │
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
│  ┌────────────────────────┴────────────────────────────┐   │
│  │                RPC Client                           │   │
│  │  (encodes requests → enc_to_host, reads responses)  │   │
│  └───┬──────────────┬──────────────┬───────────────────┘   │
│      │              │              │                       │
│  ┌───┴──────┐  ┌────┴───────┐  ┌───┴────────┐              │
│  │ RA-TLS   │  │ HTTPS      │  │ Sealed KV  │              │
│  │ Server   │  │ Egress     │  │ Store      │              │
│  │ (rustls) │  │ (rustls)   │  │ (AES-GCM)  │              │
│  └──────────┘  └────────────┘  └────────────┘              │
│                  Enclave (Trusted)                         │
└────────────────────────────────────────────────────────────┘
```


### SPSC Queue Design

- Lock-free ring buffers with `AtomicU64` head/tail pointers
- Cache-line (64-byte) padding to prevent false sharing
- Capacity must be power-of-2 (default: 2 MiB per queue)
- Messages framed as `[u32 LE length][payload]`
- Allocated in host memory; enclave accesses via raw pointers (`[user_check]` EDL)

### RPC Protocol

Compact binary format over the SPSC queues:

| Field | Request | Response |
|-------|---------|----------|
| Correlation ID | u64 | u64 |
| Method / Status | u16 (method enum) | i32 (status code) |
| Payload length | u32 | u32 |
| Payload | variable | variable |

**Request header**: 14 bytes. **Response header**: 16 bytes.

### EDL Interface (Minimal)

```c
trusted {
    public int ecall_init_channel(
        [user_check] void* enc_to_host_header,
        [user_check] void* enc_to_host_buf,
        [user_check] void* host_to_enc_header,
        [user_check] void* host_to_enc_buf,
        uint64_t capacity
    );
    public int ecall_init_data_channel(
        [user_check] void* enc_to_host_header,
        [user_check] void* enc_to_host_buf,
        [user_check] void* host_to_enc_header,
        [user_check] void* host_to_enc_buf,
        uint64_t capacity
    );
    public int ecall_run([user_check] const void* config_json, uint64_t config_len);
    public int ecall_shutdown();
};
untrusted {
    void ocall_notify();  // the ONLY OCALL
};
```

## Dependencies

- **Intel SGX SDK** (Linux) — for `sgx_edger8r`, `sgx_sign`, and SGX runtime libraries
- **[teaclave-sgx-sdk](https://github.com/privasys/teaclave-sgx-sdk)** (branch `main`) — Privasys fork of the Teaclave SGX SDK with Rust 1.84 + SGX 2.25 patches
- **[rustls](https://github.com/rustls/rustls)** — Lightweight, pure-Rust TLS 1.3 library (no OpenSSL dependency)
- **[ring](https://github.com/briansmith/ring)** — Cryptographic primitives (AES-GCM, ECDSA, SHA-256, HMAC)
- **[rcgen](https://github.com/rustls/rcgen)** — X.509 certificate generation for RA-TLS

## Randomness and AEAD

- **Randomness:** Inside the enclave, all randomness comes from Intel SGX's hardware RNG (`RDRAND`). On the host, the system RNG is used.
- **AEAD:** All AES-256-GCM operations happen inside the enclave via `ring`. The host only stores opaque ciphertext.

### Teaclave SGX SDK Crates Used


The [Teaclave SGX SDK fork by Privasys](https://github.com/privasys/teaclave-sgx-sdk) is used for enclave integration and hardware-backed randomness. The following Teaclave crates are included as dependencies:

- **enclave**: `sgx_tseal`, `sgx_tse`
- **host**: `sgx_types`, `sgx_urts`

These crates provide the necessary SGX APIs for sealing, attestation, and enclave runtime support. All cryptographic and randomness operations are delegated to upstream crates as listed above.

## Building

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Intel SGX SDK (Linux)
# See: https://download.01.org/intel-sgx/latest/linux-latest/docs/

# Clone Privasys teaclave-sgx-sdk fork
git clone https://github.com/privasys/teaclave-sgx-sdk.git
```

### Build (Linux with SGX)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Build (Host only / Development on Windows)

```bash
# From the workspace root, build the host crate in mock mode
cargo build --manifest-path host/Cargo.toml
```

### Run tests

```bash
cargo test --workspace
```

## Usage

### Starting the Server

On **first run**, provide the intermediary CA certificate and key (and optionally
an egress CA bundle) so the enclave can seal everything to disk:

```bash
./enclave-os-host \
    --enclave-path ./build/bin/enclave.signed.so \
    --port 443 \
    --kv-path ./kvdata \
    --ca-cert tests/certificates/privasys.intermediate-ca.dev.crt \
    --ca-key  tests/certificates/privasys.intermediate-ca.dev.key \
    --egress-ca-bundle /etc/ssl/certs/ca-certificates.crt \
    --debug
```

On **subsequent restarts**, all flags can be omitted  the enclave unseals the
unified `SealedConfig` blob from disk automatically:

```bash
./enclave-os-host \
    --enclave-path ./build/bin/enclave.signed.so \
    --port 443 \
    --kv-path ./kvdata \
    --debug
```

Passing parameters on restart **updates** the sealed config (e.g. rotate the CA or change the egress bundle). A new KV master key is only generated on first run.

> **Note:** The `.key` files are excluded from git (see `.gitignore`).
> You must generate or obtain them separately.

### Testing with Client Libraries

Client libraries were moved to a dedicated repository:

- https://github.com/Privasys/ra-tls-clients/tree/main

Use the root CA from `tests/certificates/privasys.root-ca.dev.crt` when running client examples.

### Certificate Trust Chain

```
Root CA (privasys.root-ca.dev.crt)
 └── Intermediary CA (privasys.intermediate-ca.dev.crt + .key)  ← sealed inside enclave
      └── Leaf RA-TLS certificate (generated per-connection inside enclave)
               ├── Extension: SGX Quote             (OID 1.2.840.113741.1.13.1.0)
               ├── Extension: Config Merkle Root    (OID 1.3.6.1.4.1.65230.1.1)
               ├── Extension: Egress CA Hash        (OID 1.3.6.1.4.1.65230.2.1)  ← module
               └── Extension: WASM Code Hash       (OID 1.3.6.1.4.1.65230.2.3)  ← module
```

- The **intermediary CA** cert + key are passed to the enclave at init time,
  sealed to disk as part of the unified `SealedConfig` (MRENCLAVE policy),
  and kept only in encrypted enclave memory.
- The **leaf certificate** is generated per-connection with an embedded SGX
  quote and signed by the intermediary CA.
- **Module OIDs** are registered by each module via `custom_oids()` and
  embedded as non-critical extensions. Clients can verify specific ← module
  properties (e.g. "the egress CA bundle hash matches my expectation")
  with a single OID check  no Merkle tree computation needed.

  | OID | Module | Value |
  |-----|--------|-------|
  | `1.3.6.1.4.1.65230.1.1` | core | Config Merkle root (32 bytes) |
  | `1.3.6.1.4.1.65230.2.1` | egress | SHA-256 of egress CA bundle (32 bytes) |
  | `1.3.6.1.4.1.65230.2.3` | wasm | SHA-256 of WASM bytecode (32 bytes) |

- The **Config Merkle Root** extension is a 32-byte SHA-256 hash tree over
  all operator-chosen and module-contributed configuration inputs. The leaf
  order is deterministic and append-only:

  | Index | Name | Input |
  |-------|------|-------|
  | 0 | `core.ca_cert` | Intermediary CA certificate (DER) |
  | 1 | `egress.ca_bundle` | Egress CA bundle (PEM)  from egress module |
  | 2 | `<module>.<key>` | Module-specific inputs |

  `root = SHA-256( H(leaf_0) || H(leaf_1) ||  || H(leaf_N) )` where
  `H(leaf) = SHA-256(data)` or 32 zero bytes if the input is absent.

  **Auditability:** The enclave stores a full **config manifest**  a list
  of `(name, leaf_hash)` pairs alongside the root. Clients can request the
  manifest (binary serialization via `ConfigManifest::to_bytes()`) and
  independently recompute the root to verify which inputs were used.
  Individual leaf hashes are also logged at startup for operator visibility.

  Clients can pin the Merkle root to verify the enclave's runtime
  configuration without trusting the operator, or pin individual leaf
  hashes to audit specific inputs.
- Clients verify the chain using the **root CA** certificate.

## Security Model

| Component | Trust Boundary | Details |
|-----------|---------------|---------|
| **RA-TLS certificate** | Enclave | Generated inside enclave with SGX quote + config Merkle root + module OIDs |
| **TLS termination** | Enclave | All TLS keys and plaintext stay in enclave |
| **Sealed config** | Enclave | Single MRENCLAVE-bound blob: CA + egress bundle + KV key |
| **Config Merkle root** | Enclave | SHA-256 tree of config inputs, embedded as X.509 OID |
| **Module OIDs** | Enclave | Per-module X.509 OID extensions for fast client verification |
| **KV encryption key** | Enclave | Generated in enclave on first run, sealed in config |
| **KV key encryption** | Enclave | HMAC-SHA256 (deterministic for lookups) |
| **KV value encryption** | Enclave | AES-256-GCM with random nonces |
| **Network I/O** | Host | Host handles TCP sockets, sees only ciphertext |
| **KV storage** | Host | Host stores opaque encrypted blobs |

### Client Verification

The enclave is an **honest reporter** — it computes and publishes the config
Merkle root in every RA-TLS certificate. There is no owner key or authorization
gate. Clients verify:

1. **MRENCLAVE** (via SGX quote) → correct enclave code
2. **Config Merkle root** (via X.509 OID `1.3.6.1.4.1.65230.1.1`)  correct operator-chosen inputs
3. **Module OIDs** (e.g. `1.3.6.1.4.1.65230.2.1`)  fast-path verification of individual module properties without Merkle audit
4. **Config manifest** (optional) → request the full `(name, leaf_hash)` list from the enclave and recompute the root to audit individual inputs

Anyone with host access can change the config, but the Merkle root in the
certificate will change accordingly, and clients pinning a known-good value
will detect it. Modules can contribute their own config leaves via the
`EnclaveModule::config_leaves()` trait method, making the tree extensible
without modifying core code.

## Design Decisions

1. **SPSC queues over traditional OCALLs**: Shared-memory ring buffers eliminate ~12 individual OCALLs (each ~5-10μs context switch). The enclave writes directly to host memory  no OCALL needed for data transfer. Only a single `ocall_notify()` for wake-up signalling.
2. **Lock-free design**: `AtomicU64` head/tail with cache-line padding. No mutexes in the hot path. Producer reads tail with Acquire, writes head with Release; consumer does the inverse.
3. **Custom binary RPC**: Hand-rolled 14-byte request / 16-byte response headers. No protobuf/gRPC overhead, no extra dependencies inside the enclave TCB.
4. **rustls over OpenSSL**: Pure Rust, no C dependencies inside the enclave, smaller TCB, TLS 1.3 by default
5. **ring for crypto**: Well-audited, SGX-compatible via teaclave, covers AEAD + signatures + hashing
6. **Deterministic key encryption**: HMAC-SHA256 for KV keys enables lookups without decrypting all keys
7. **Per-connection RA-TLS certificates**: Fresh key pair + SGX quote generated per connection, with optional challenge-response via TLS extension `0xFFBB`
8. **RocksDB host KV store**: Host stores opaque encrypted blobs in RocksDB, tuned for point lookups
9. **Crate-per-module**: Each module is an independent crate under `crates/`, keeping the core enclave TCB small and enabling independent compilation/testing

## Third-party dependencies

Enclave OS (Mini) uses the following third-party Rust crates:

| Dependency | License | Usage |
|---|---|---|
| Teaclave SGX SDK (sgx_types, sgx_urts, sgx_tseal, sgx_tse) | Apache 2.0 | Intel SGX enclave SDK bindings (Privasys fork) |
| wasmtime | Apache 2.0 WITH LLVM-exception | WebAssembly runtime inside SGX (Privasys fork) |
| rocksdb | Apache 2.0 | Host-side key-value store |
| rustls | Apache 2.0 / MIT / ISC | TLS 1.3 implementation |
| rustls-pemfile | Apache 2.0 / MIT / ISC | PEM file parsing |
| ring | ISC | Cryptographic primitives |
| rustls-webpki (webpki) | ISC | WebPKI certificate validation |
| webpki-roots | MPL 2.0 | Mozilla root CA certificates |
| serde / serde_json | Apache 2.0 / MIT | Serialization |
| base64 | Apache 2.0 / MIT | Base64 encoding |
| rcgen | Apache 2.0 / MIT | X.509 certificate generation |
| x509-parser | Apache 2.0 / MIT | X.509 certificate parsing |
| anyhow | Apache 2.0 / MIT | Error handling |
| clap | Apache 2.0 / MIT | CLI argument parsing |
| log / env_logger | Apache 2.0 / MIT | Logging |
| hex | Apache 2.0 / MIT | Hex encoding |
| cc | Apache 2.0 / MIT | C compiler build helper |
| getrandom | Apache 2.0 / MIT | RDRAND hardware RNG (enclave-wide via sgx_read_rand shim) |
| tokio | MIT | Async runtime (tests only) |

Full license texts are available in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).

## License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

You are free to use, modify, and distribute this software under the terms of the AGPL-3.0. Any modified versions or services built on this software that are accessible over a network **must** make the complete source code available under the same license.

### Commercial Licensing

For commercial, closed-source, or proprietary use that is not compatible with the AGPL-3.0, a separate **commercial license** is available.

Please contact **legal@privasys.org** for licensing enquiries.
