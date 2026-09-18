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
specifically a [Privasys fork](https://github.com/Privasys/wasmtime), pinned
by release tag (`privasys-v0.3.0` = upstream v48.0.2 plus one SGX commit, see
[wasmtime-fork.md](wasmtime-fork.md)).

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
| Async | enabled | Every call runs on a fiber, so a host import can suspend the guest (see [Concurrency](#concurrency)) |
| Fiber stack | 1 MiB (`max_wasm_stack` 512 KiB) | Guest frames plus the host code a guest calls into; heap-allocated, registered with the SGX runtime |
| Fuel yield interval | 1,000,000 | A long call gives the event loop back every few milliseconds |
| Pooling allocator | excluded | Not needed for single-threaded model |

### SGX Platform Layer

The fork includes a custom platform layer (`sgx_platform.rs`) that provides
the C-ABI symbols Wasmtime needs:

| Capability | SGX Implementation |
|------------|-------------------|
| Code memory | 16 MiB RWX pool (`.wasm_code` ELF section); pages are reclaimed when an app is unloaded or evicted, and a load that does not fit is refused |
| Data memory | Standard heap allocation |
| Memory protection | No-op (code pool = RWX, heap = RW); making memory outside the pool executable is refused |
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
| `wasi:clocks/wall-clock@0.2.0` | The enclave's trusted time (see [Trusted Time](trusted-time.md)); traps when there is none |
| `wasi:clocks/monotonic-clock@0.2.0` | The same trusted time in nanoseconds; never goes back |
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
The host only transports encrypted TCP bytes: it never sees request URLs,
headers, or response bodies in plaintext. Plain HTTPS offers TLS 1.3 and
1.2; an RA-TLS request is TLS 1.3 only.

The guest sees a blocking call, but the enclave does not block: while the
request waits on the network, the guest is suspended and the enclave serves
other requests (see [Concurrency](#concurrency)).

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
| Wire protocol | `WasmEnvelope` — JSON discriminator for `wasm_load`, `wasm_call`, `wasm_list`, `wasm_unload`, `wasm_schema`, `connect_call`, `mcp_tools` |
| App registry | `WasmRegistry` — stores loaded apps, handles export introspection |
| Execution | Fresh `Store` + `Instance` per call (stateless), per-app fuel budget |
| File system | `SealedKvStore` — AES-256-GCM encrypted, per-app isolated (`app:<name>/fs:<path>`) |
| Attestation | Per-app config leaves + OIDs via `EnclaveModule` trait methods |
| MCP | `mcp_tools` generates MCP-compatible tool manifests from WIT types + `package-docs` comments |

### Wire Protocol

All management commands are JSON messages inside `Request::Data` frames:

| Command | Request | Response |
|---------|---------|----------|
| Load | `{"wasm_load": {"name": "...", "bytes": [...]}}` | `{"status": "loaded", "app": {...}}` |
| Call | `{"wasm_call": {"app": "...", "function": "...", "params": [...]}}` | `{"status": "ok", "returns": [...]}` |
| List | `{"wasm_list": {}}` | `{"status": "apps", "apps": [...]}` |
| Unload | `{"wasm_unload": {"name": "..."}}` | `{"status": "unloaded", "name": "..."}` |
| Schema | `{"wasm_schema": {"app": "..."}}` | `{"status": "schema", "schema": {...}}` |
| MCP Tools | `{"mcp_tools": {"app": "..."}}` | `{"status": "mcp_tools", "manifest": {...}}` |
| Connect | `{"connect_call": {"app": "...", "function": "...", "body": {...}}}` | `{"status": "ok", "returns": [...]}` |

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
   - Creates a fresh `Store` with the app's fuel budget and a new `Instance`
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
| App Key Source | `1.3.6.1.4.1.65230.3.4` | `"generated"` or `"byok:<fingerprint>"` |

The per-app Merkle tree contains:

| Leaf | Value |
|------|-------|
| `wasm.<name>.code_hash` | SHA-256 of the `.cwasm` bytecode |
| `wasm.<name>.key_source` | `"generated"` or `"byok:<fingerprint>"` |

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
| `get-time` | `wasi:clocks/wall-clock` | Trusted wall clock |
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

Each call gets a fuel budget that limits computation.  The default is
**1 billion fuel units** (about a second or two of compute; decoding a
typical web page after `https.fetch` takes 25 to 45 million).  Managers can
set a custom `max_fuel` per app at load time.  When the budget is
exhausted, the WASM instance traps and the call fails with
`wasm trap: all fuel consumed by WebAssembly`.

The budget ends a runaway call. Fairness between calls comes from the fuel
yield interval: every 1 million fuel units the guest gives the event loop
back, so a long computation does not hold up other requests (see
[Concurrency](#concurrency)). Billing counts the fuel consumed, not the
budget.

#### Fuel Metrics

The runtime tracks cumulative fuel consumption **per app** and **per
function**.  Counters are i64 to accommodate large cumulative values.

| Counter | Scope | Description |
|---------|-------|-------------|
| `calls_total` | App | Total calls (successful + errored) |
| `fuel_consumed_total` | App | Sum of fuel consumed across all calls |
| `errors_total` | App | Calls that returned an error |
| `calls` | Function | Calls to this specific export |
| `fuel_consumed` | Function | Fuel consumed by this export |
| `errors` | Function | Error count for this export |
| `fuel_min` | Function | Minimum fuel consumed in a single call |
| `fuel_max` | Function | Maximum fuel consumed in a single call |

Retrieve counters via the core `Metrics` API (Monitoring+ role) — they
appear in the `wasm_app_metrics` array of the `MetricsReport`.

#### Metric Persistence

Every `Metrics` call automatically persists the current counters to the
sealed KV store under the key `wasm:metrics:snapshot` (AES-256-GCM
encrypted, same sealing as app data).

On enclave startup, previously-snapshotted metrics are automatically loaded
and additively merged with the in-memory counters.  This means counters
survive enclave restarts as long as the operator polls `Metrics` before
shutdown.

When an app is unloaded via `wasm_unload`, its counters are removed from
the in-memory store.  The next `Metrics` call will persist the
remaining apps' counters (effectively garbage-collecting the old app).

### Concurrency

The enclave has one event loop, on one SGX thread, for every app it hosts.
Requests still never wait for each other's network I/O or long computations:

- **Requests run as tasks.** Each ingress request runs its handler on its
  own fiber (1 MiB, pooled). When the handler has to wait, the task
  suspends and the event loop goes on serving other connections; the task
  resumes when its waker fires. A connection has at most one suspended
  request at a time (HTTP/1.1 answers in order, the next requests stay
  buffered), and at most 8 requests are suspended at once; past that, a
  request runs to completion inline.
- **Guest calls run on fibers.** wasmtime runs each call on a fiber of its
  own, so an async host import suspends the guest in the middle of a call.
  The guest cannot tell: `https.fetch` still looks like a blocking call.
- **Egress waits suspend, not block.** Inside a request task,
  `https.fetch` does its TLS and HTTP exchange over sockets the host TCP
  proxy drives (`TcpConnect` / `TcpData` / `TcpClose` on the data channel,
  connection ids from `0xC000_0000` up). A read with no data suspends the
  guest and its task; the proxy's next message wakes them. Outside a task
  (e.g. a raft replay) the call uses the blocking RPC sockets.
- **Long computations yield.** Every 1 million fuel units a guest call
  yields, and the event loop serves other requests before resuming it.
- **Bounded waits.** The proxy closes an egress connection 60 s after it
  opened, so a server that never answers, or trickles one byte at a time,
  fails the request instead of holding its slot.

Measured on SGX hardware: while fetches of a 1.3 MB page ran back to back,
a concurrent `hello` answered in 15 ms median (56 ms worst) instead of
~245 ms; during a fetch to a server that accepts the connection and never
answers, 1,472 `hello` calls answered in 15 ms median and the fetch failed
after 60 s.

Two rules keep this sound. Code running in a task must not hold a lock
another request may take when it waits (every task shares the one thread,
so the second request would block the thread for good). And a wait inside
a guest call's synchronous host function blocks rather than suspends, so
wasmtime's frames are never switched out from under another guest call.

Fiber stacks live on the enclave heap. The SGX runtime only accepts an
exception (such as the `CPUID` the enclave emulates) raised on a stack it
knows, so every fiber stack is registered with it
(`sgx_register_alt_stack`, Privasys Teaclave SDK `privasys-v0.5.0`).

### Memory Limits

| Resource | Limit |
|----------|-------|
| Linear memory per instance | 4 MiB |
| Code memory pool (shared) | 16 MiB |
| Memory guard pages | 64 KiB |
| Default fuel budget per call | 1,000,000,000 (configurable via `max_fuel`) |
| Fiber stack per call | 1 MiB |
| Requests suspended at once | 8 (further requests run to completion inline) |
