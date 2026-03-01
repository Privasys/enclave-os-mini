# WASM Runtime

## Why WebAssembly Inside SGX?

Intel SGX protects code and data from the host OS, hypervisor, and physical
access.  But compiling application logic directly into the enclave has
significant drawbacks:

- **Rebuild the enclave** for every application change → new MRENCLAVE
- **Large TCB** — application code, dependencies, and business logic all
  inside the trusted boundary
- **No multi-tenancy** — one application per enclave binary

WebAssembly solves these problems by providing a **sandboxed execution
environment inside the enclave**:

| Concern | Without WASM | With WASM |
|---------|-------------|-----------|
| Deploy new logic | Rebuild enclave, re-sign, re-attest | Load `.cwasm` at runtime over RA-TLS |
| TCB size | Application + all deps | Wasmtime runtime only (stable, audited) |
| Multi-tenancy | One app per enclave | Many apps, isolated by WASM sandbox |
| Attestation | MRENCLAVE changes per app version | MRENCLAVE stays stable; app identity via code hash OID |
| Language support | Rust only (SGX target) | Any language that compiles to WASM |

The WASM sandbox provides a second layer of isolation **inside** the already-
isolated SGX enclave: even if a WASM app has a vulnerability, it cannot
access enclave memory, other apps' data, or the enclave's private keys.

---

## Wasmtime

Enclave OS uses [Wasmtime](https://wasmtime.dev/) as the WASM runtime,
specifically a [Privasys fork](https://github.com/Privasys/wasmtime) on the
`sgx` branch.

### Why Wasmtime?

- **Component Model** — first-class support for WIT interfaces, typed imports/exports
- **AOT compilation** — pre-compile outside SGX, deserialize inside (no Cranelift in the TCB)
- **Fuel metering** — bounded execution prevents infinite loops
- **Memory safety** — Rust implementation, no C runtime
- **Configurable platform** — `custom-virtual-memory` + `custom-native-signals` features
  allow plugging in SGX-specific memory and signal handling

### SGX Configuration

The Wasmtime engine inside the enclave is configured for the SGX constraints:

| Setting | Value | Rationale |
|---------|-------|-----------|
| Component Model | enabled | WIT-based typed interfaces |
| SIMD | enabled | Leverage SGX2 SSE/AVX |
| Multi-memory | enabled | Component Model requires it |
| Memory reservation | 4 MiB | Conserves SGX EPC (Enclave Page Cache) |
| Memory guard size | 64 KiB | No virtual memory overcommit in SGX |
| Copy-on-write | disabled | No disk-backed memory images in SGX |
| Cranelift | excluded | AOT only — no compiler in the TCB |
| Async | excluded | Synchronous execution model |
| Pooling allocator | excluded | Not needed for single-threaded model |

### SGX Platform Layer

The fork includes a custom platform layer (`sgx_platform.rs`) that provides
the C-ABI symbols Wasmtime needs:

| Capability | SGX Implementation |
|------------|-------------------|
| Code memory | 16 MiB RWX pool (`.wasm_code` ELF section, bump allocator) |
| Data memory | Standard heap allocation |
| Memory protection | No-op (code pool = RWX, heap = RW) |
| Trap handling | `sgx_register_exception_handler` (vectored exception) |
| Thread-local storage | `AtomicPtr` (single-threaded per TCS) |
| Stack unwinding | Stub (no-op) |

### AOT Compilation

WASM components must be pre-compiled **outside the enclave** using Wasmtime's
`compile` command (or `Engine::precompile_component()`).  The resulting
`.cwasm` artifact contains native x86_64 code that can be deserialized
directly inside the enclave without invoking Cranelift.

```bash
wasmtime compile my_app.wasm -o my_app.cwasm
```

**Important:** The `.cwasm` must be produced with matching engine settings
(same Wasmtime version, same feature flags).

---

## WASI Support

The WASM runtime implements a subset of the [WASI](https://wasi.dev/)
(WebAssembly System Interface) standard, adapted for the SGX environment.

### Standard WASI Interfaces

| Interface | Enclave OS Backing |
|-----------|-------------------|
| `wasi:random/random@0.2.0` | RDRAND hardware RNG (no OCALL) |
| `wasi:random/insecure@0.2.0` | Same (RDRAND) — stub for compatibility |
| `wasi:random/insecure-seed@0.2.0` | Same (RDRAND) |
| `wasi:clocks/wall-clock@0.2.0` | OCALL to host for current UNIX time |
| `wasi:clocks/monotonic-clock@0.2.0` | OCALL to host (best-effort) |
| `wasi:cli/environment@0.2.0` | Enclave-controlled environment variables |
| `wasi:cli/stdout@0.2.0` | Line-buffered → enclave log |
| `wasi:cli/stderr@0.2.0` | Line-buffered → enclave error log |
| `wasi:cli/stdin@0.2.0` | In-memory buffer |
| `wasi:cli/exit@0.2.0` | Trap (terminates WASM instance) |
| `wasi:io/error@0.2.0` | Error resource with debug string |
| `wasi:io/poll@0.2.0` | Synchronous (always-ready) pollables |
| `wasi:io/streams@0.2.0` | Resource-backed stream I/O |
| `wasi:sockets/tcp@0.2.0` | OCALL-backed TCP (sync model) |
| `wasi:sockets/tcp-create-socket@0.2.0` | Socket state tracking |
| `wasi:sockets/network@0.2.0` | Network resource stub |
| `wasi:filesystem/types@0.2.0` | Sealed KV store (AES-256-GCM encrypted) |
| `wasi:filesystem/preopens@0.2.0` | Single root `/` descriptor |

### Enclave OS SDK Interfaces

In addition to standard WASI, Enclave OS provides custom Component Model
interfaces under the `privasys:enclave-os@0.1.0` namespace:

#### `privasys:enclave-os/https@0.1.0`

HTTPS egress — make outbound HTTPS requests from inside the enclave.

```
fetch(method: u32, url: string, headers: list<(string, string)>, body: option<list<u8>>)
  → result<(status: u16, headers: list<(string, string)>, body: list<u8>), string>
```

Methods: 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=PATCH, 5=HEAD, 6=OPTIONS.

TLS terminates **inside the enclave** using `rustls` + Mozilla root CAs.
The host only transports encrypted TCP bytes via OCALLs — it never sees
request URLs, headers, or response bodies in plaintext.

Only `https://` URLs are accepted; `http://` is rejected.

#### `privasys:enclave-os/crypto@0.1.0`

Cryptographic operations using keys managed inside the enclave.

| Function | Description |
|----------|-------------|
| `digest(algorithm, data)` | SHA-256, SHA-384, or SHA-512 |
| `encrypt(key-name, iv, aad, plaintext)` | AES-256-GCM encryption |
| `decrypt(key-name, iv, aad, ciphertext)` | AES-256-GCM decryption |
| `sign(key-name, algorithm, data)` | ECDSA P-256 or P-384 |
| `verify(key-name, algorithm, data, signature)` | ECDSA verification |
| `hmac-sign(key-name, algorithm, data)` | HMAC-SHA-256/384/512 |
| `hmac-verify(key-name, algorithm, data, tag)` | HMAC verification |
| `get-random-bytes(len)` | RDRAND hardware random |

#### `privasys:enclave-os/keystore@0.1.0`

Key lifecycle management with optional persistence via sealed storage.

| Function | Description |
|----------|-------------|
| `generate-symmetric-key(name)` | 32 random bytes (AES-256) via RDRAND |
| `generate-signing-key(name, algorithm)` | ECDSA PKCS#8 (P-256 or P-384) |
| `generate-hmac-key(name, algorithm)` | 32/48/64 random bytes |
| `import-symmetric-key(name, bytes)` | Import raw key material |
| `export-public-key(name)` | Export ECDSA public key (DER) |
| `delete-key(name)` | Remove from in-memory store |
| `key-exists(name)` | Check existence |
| `persist-key(name)` | Seal to host KV store (`app:<name>/key:<key-name>`) |
| `load-key(name)` | Unseal from host KV store |

Persisted keys are sealed with the app's AES-256 encryption key and stored
in the host KV under `app:<app-name>/key:<key-name>`.

---

## The `enclave-os-wasm` Crate

The WASM module (`crates/enclave-os-wasm`) implements the `EnclaveModule`
trait and provides:

| Responsibility | Implementation |
|----------------|----------------|
| Wire protocol | `WasmEnvelope` — JSON discriminator for `wasm_load`, `wasm_call`, `wasm_list`, `wasm_unload` |
| App registry | `WasmRegistry` — stores loaded apps, handles export introspection |
| Execution | Fresh `Store` + `Instance` per call (stateless), 10M fuel budget |
| File system | `SealedKvStore` — AES-256-GCM encrypted, per-app isolated (`app:<name>/fs:<path>`) |
| Attestation | Per-app config leaves + OIDs via `EnclaveModule` trait methods |

### Wire Protocol

All management commands are JSON messages inside `Request::Data` frames:

| Command | Request | Response |
|---------|---------|----------|
| Load | `{"wasm_load": {"name": "...", "bytes": [...]}}` | `{"status": "loaded", "app": {...}}` |
| Call | `{"wasm_call": {"app": "...", "function": "...", "params": [...]}}` | `{"status": "ok", "returns": [...]}` |
| List | `{"wasm_list": {}}` | `{"status": "apps", "apps": [...]}` |
| Unload | `{"wasm_unload": {"name": "..."}}` | `{"status": "unloaded", "name": "..."}` |

See the [wasm-app-example](https://github.com/Privasys/wasm-app-example)
README for detailed request/response examples including BYOK, per-app
hostnames, and the complete Python loading example.

### App Lifecycle

1. **Load** — client sends `.cwasm` bytes over RA-TLS.  The enclave:
   - Computes SHA-256 code hash
   - Deserializes the AOT artifact (no compilation)
   - Introspects exports (function names, parameter/result counts)
   - Generates AES-256 encryption key (RDRAND) or accepts BYOK
   - Registers the app in the `WasmRegistry`
   - Registers an `AppIdentity` with the `CertStore` for SNI routing
   - Re-derives RA-TLS certificate with updated config Merkle tree

2. **Call** — client sends function name + typed parameters.  The enclave:
   - Looks up the app in the registry
   - Creates a fresh `Store` with 10M fuel and a new `Instance`
   - Sets up WASI + SDK host imports with per-app `AppContext`
   - Invokes the exported function
   - Returns typed results or error message
   - Drops the instance (stateless — no carry-over between calls)

3. **List** — returns metadata for all loaded apps (name, hostname,
   code hash, key source, exported functions)

4. **Unload** — removes the app from the registry and `CertStore`.
   The in-memory encryption key is dropped — if it was generated
   (not BYOK), all KV data becomes permanently unrecoverable.

---

## Per-App X.509 Certificates

Each loaded WASM app can register a **hostname** for SNI-based certificate
routing.  When a client connects via that hostname, they receive an
app-specific X.509 certificate containing:

| Extension | OID | Value |
|-----------|-----|-------|
| SGX Quote | `1.2.840.113741.1.13.1.0` | Same enclave quote (proves enclave identity) |
| App Config Merkle Root | `1.3.6.1.4.1.65230.3.1` | SHA-256 tree of app-specific config |
| App Code Hash | `1.3.6.1.4.1.65230.3.2` | SHA-256 of the WASM bytecode |

The per-app Merkle tree contains:

| Leaf | Value |
|------|-------|
| `wasm.<name>.code_hash` | SHA-256 of the `.cwasm` bytecode |
| `wasm.<name>.key_source` | `"byok"` or `"generated"` |

This means a client can verify **exactly which WASM code is running** for
a specific app without knowing about other apps in the same enclave.

### Example

Load an app with a custom hostname:

```json
{
  "wasm_load": {
    "name": "my-app",
    "bytes": [0, 97, 115, 109, ...],
    "hostname": "my-app.enclave.example.com"
  }
}
```

A client connecting to `my-app.enclave.example.com` receives a certificate
with `APP_CODE_HASH_OID` containing the SHA-256 of `my-app`'s bytecode.

---

## Per-App Data Isolation

Each app gets its own:

- **AES-256 encryption key** — generated via RDRAND or supplied via BYOK
- **KV namespace** — all file system operations are prefixed with `app:<name>/fs:<path>`
- **Key namespace** — all keystore operations use `app:<name>/key:<key-name>`

Apps cannot access each other's data, keys, or file system entries. The
encryption key is different for each app, so even at the host KV storage
layer, one app's ciphertext is meaningless to another.

---

## Building a WASM App

### Prerequisites

| Tool | Install |
|------|---------|
| Rust stable 1.82+ | `rustup update stable` |
| WASI target | `rustup target add wasm32-wasip2` |
| cargo-component | `cargo install cargo-component` |

### WIT Interfaces

WASM apps declare their imports and exports using
[WIT (WebAssembly Interface Types)](https://component-model.bytecodealliance.org/design/wit.html).
Place WIT files under `wit/` in your crate:

```wit
// wit/world.wit
package my-org:my-app@0.1.0;

world my-app {
    // Standard WASI imports
    import wasi:random/random@0.2.0;
    import wasi:clocks/wall-clock@0.2.0;
    import wasi:filesystem/types@0.2.0;

    // Enclave OS SDK imports
    import privasys:enclave-os/https@0.1.0;
    import privasys:enclave-os/crypto@0.1.0;
    import privasys:enclave-os/keystore@0.1.0;

    // Your exported functions
    export hello: func() -> string;
    export process: func(input: string) -> string;
}
```

WIT interface definitions are available in the
[Enclave OS WASM SDK](https://github.com/Privasys/enclave-os-mini/tree/main/crates/enclave-os-wasm/sdk).

### Build and Pre-compile

```bash
# Build the WASM component
cargo component build --release

# AOT compile for the enclave's Wasmtime engine
wasmtime compile target/wasm32-wasip1/release/my_app.wasm -o my_app.cwasm
```

### Example: wasm-app-example

The [wasm-app-example](https://github.com/Privasys/wasm-app-example) repository
is a complete reference implementation that exercises all WASM capabilities:

| Function | WASI Interface | What it demonstrates |
|----------|---------------|---------------------|
| `hello` | *(none)* | Pure guest code, no host imports |
| `get-random` | `wasi:random` | RDRAND hardware RNG |
| `get-time` | `wasi:clocks/wall-clock` | Wall clock via OCALL |
| `kv-store` | `wasi:filesystem` | Write to sealed KV store |
| `kv-read` | `wasi:filesystem` | Read from sealed KV store |
| `fetch-headlines` | `privasys:enclave-os/https` | HTTPS egress from inside SGX |

---

## Execution Model

### Stateless Calls

Each `wasm_call` creates a **fresh WASM instance** — a new `Store`, new
`Instance`, new linear memory.  There is no state carried between calls.

Persistent data must go through the file system interface (`wasi:filesystem`),
which maps to the sealed KV store.  Data written via `sync-data()` persists
across calls and enclave restarts (same MRENCLAVE required to unseal).

### Fuel Metering

Each call gets a budget of **10 million fuel units** (~a few hundred
milliseconds of compute).  Instructions consume fuel; when the budget is
exhausted, the WASM instance traps.

This prevents infinite loops and ensures fair resource sharing when multiple
apps are loaded.

### Memory Limits

| Resource | Limit |
|----------|-------|
| Linear memory per instance | 4 MiB |
| Code memory pool (shared) | 16 MiB |
| Memory guard pages | 64 KiB |
| Fuel budget per call | 10,000,000 |
