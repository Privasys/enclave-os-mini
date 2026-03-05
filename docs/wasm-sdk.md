# WASM SDK — API Reference

The complete API surface available to WebAssembly Components running inside an Enclave OS SGX enclave.

WASM apps are sandboxed guests — they can **only** call the host functions defined in this SDK. There is no direct access to the hardware, the operating system, or the network. Everything goes through the enclave runtime.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    WASM Component (guest)                       │
│                                                                 │
│  Your app code                                                  │
│    │                                                            │
│    ├── import privasys:enclave-os/crypto     ─── ring / RDRAND  │
│    ├── import privasys:enclave-os/keystore   ─── sealed keys    │
│    ├── import privasys:enclave-os/https      ─── rustls egress  │
│    ├── import wasi:random/*                  ─── RDRAND         │
│    ├── import wasi:clocks/*                  ─── OCALL time     │
│    ├── import wasi:filesystem/*              ─── sealed KV      │
│    ├── import wasi:io/*                      ─── in-memory      │
│    ├── import wasi:cli/*                     ─── controlled env │
│    └── import wasi:sockets/tcp*              ─── OCALL tunnel   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│             Enclave OS Runtime (host functions)                 │
│                 Inside SGX enclave boundary                     │
├─────────────────────────────────────────────────────────────────┤
│               Untrusted Host (OCALLs only)                      │
│        Only sees: encrypted KV blobs, TLS ciphertext,           │
│        TCP bytes, timestamps                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Platform APIs — `privasys:enclave-os@0.1.0`

These are Enclave OS exclusive capabilities — they exist because the code runs inside SGX.

### Crypto (`privasys:enclave-os/crypto@0.1.0`)

| Function | Description |
|----------|-------------|
| `digest(algorithm, data)` | SHA-256 / SHA-384 / SHA-512 |
| `encrypt(key-name, iv, aad, plaintext)` | AES-256-GCM encryption |
| `decrypt(key-name, iv, aad, ciphertext)` | AES-256-GCM decryption |
| `sign(key-name, algorithm, data)` | ECDSA P-256 / P-384 signing |
| `verify(key-name, algorithm, data, signature)` | ECDSA signature verification |
| `hmac-sign(key-name, algorithm, data)` | HMAC-SHA-256 / 384 / 512 |
| `hmac-verify(key-name, algorithm, data, tag)` | HMAC tag verification |
| `get-random-bytes(len)` | Cryptographic random bytes (RDRAND) |

All operations use `ring` inside the SGX enclave. Keys are referenced by name from the keystore — raw key material is never exposed.

### Keystore (`privasys:enclave-os/keystore@0.1.0`)

| Function | Description |
|----------|-------------|
| `generate-symmetric-key(name)` | Generate AES-256 key (32 random bytes) |
| `generate-signing-key(name, algorithm)` | Generate ECDSA key pair (PKCS#8) |
| `generate-hmac-key(name, algorithm)` | Generate HMAC key |
| `import-symmetric-key(name, raw-key)` | Import a 256-bit symmetric key |
| `export-public-key(name)` | Export signing key's public component (DER) |
| `delete-key(name)` | Remove key from memory |
| `key-exists(name)` | Check if a key is loaded |
| `persist-key(name)` | Seal and store key to host KV (MRENCLAVE-bound) |
| `load-key(name)` | Unseal a previously persisted key |

Keys are generated inside SGX using RDRAND, stored in enclave memory, and optionally persisted via MRENCLAVE-sealed encryption. **Keys never leave the enclave in plaintext.**

Each app's keys are namespace-isolated: `app:<app-name>/key:<key-name>`.

### HTTPS (`privasys:enclave-os/https@0.1.0`)

| Function | Description |
|----------|-------------|
| `fetch(request)` | Perform an HTTPS request |

TLS terminates **inside the enclave** using rustls + Mozilla root CAs. The host only transports encrypted bytes — it never sees request URLs, headers, bodies, or responses.

**Plain HTTP is not supported.** Only `https://` URLs are accepted — requests to `http://` are rejected. Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.

---

## WASI Interfaces (enclave-implemented)

Standard WASI Preview 2 interfaces, re-implemented by the enclave runtime. These are **not** backed by the host OS.

### Random (`wasi:random@0.2.0`)

All random bytes come from Intel RDRAND (hardware RNG inside SGX). There is no difference between "secure" and "insecure" variants — all are hardware RNG.

| Interface | Functions |
|-----------|-----------|
| `random` | `get-random-bytes(len)`, `get-random-u64()` |
| `insecure` | `get-insecure-random-bytes(len)`, `get-insecure-random-u64()` |
| `insecure-seed` | `insecure-seed() → (u64, u64)` |

### Clocks (`wasi:clocks@0.2.0`)

| Interface | Functions | Notes |
|-----------|-----------|-------|
| `wall-clock` | `now()`, `resolution()` | UNIX timestamp via OCALL. 1-second resolution |
| `monotonic-clock` | `now()`, `resolution()`, `subscribe-instant()`, `subscribe-duration()` | Derived from wall clock. 1-second resolution |

### Filesystem (`wasi:filesystem@0.2.0`)

Backed by a sealed key-value store. Each "file" is a KV entry encrypted with AES-256-GCM and sealed to MRENCLAVE.

| Operation | Supported | Notes |
|-----------|-----------|-------|
| `open-at` (create/truncate) | Yes | Loads from / creates in sealed KV |
| `read` / `read-via-stream` | Yes | From in-memory buffer |
| `write` / `write-via-stream` | Yes | To in-memory buffer |
| `sync-data` / `sync` | Yes | **Flushes encrypted data to host KV** |
| `stat` / `stat-at` | Yes | Size from buffer |
| `get-type` / `get-flags` | Yes | |
| `read-directory` | Partial | Returns empty (no KV listing) |
| Links, symlinks, rename, unlink | No | Returns `unsupported` |

**Important**: Call `sync-data()` after writing to persist data. Without it, data only exists in the ephemeral instance memory and is lost when the call returns.

Key namespace: `app:<app-name>/fs:<path>`.

### I/O (`wasi:io@0.2.0`)

Synchronous model — all pollables are always ready.

| Interface | Notes |
|-----------|-------|
| `error` | Error resources with debug strings |
| `poll` | All pollables return ready immediately |
| `streams` | Backed by in-memory buffers, TCP OCALLs, or null sinks |

### CLI (`wasi:cli@0.2.0`)

| Interface | Notes |
|-----------|-------|
| `environment` | Operator-configured env vars and args |
| `stdin` | In-memory input buffer |
| `stdout` / `stderr` | Captured to enclave log (line-buffered) |
| `exit` | Always traps — enclave manages its own lifecycle |

### Sockets (`wasi:sockets@0.2.0`)

TCP sockets tunnelled through host OCALLs.

> **Warning**: Raw TCP sockets expose plaintext to the untrusted host. For secure outbound communication, use `privasys:enclave-os/https` instead.

| Interface | Notes |
|-----------|-------|
| `tcp` | connect, bind, listen, accept, shutdown |
| `tcp-create-socket` | Creates socket via host OCALL |
| `network` / `instance-network` | Opaque handles |

---

## Execution Model

| Property | Value |
|----------|-------|
| **Isolation** | Each call creates a fresh `Store` + `Instance` (stateless) |
| **Fuel budget** | 10,000,000 instructions per call |
| **Persistence** | Via `wasi:filesystem` → `sync-data()` → sealed KV store |
| **Key persistence** | Via `keystore/persist-key()` → sealed KV store |
| **Max WASM memory** | 4 MiB static allocation |
| **Namespace isolation** | `app:<name>/*` — apps cannot access each other's data |
| **Attestation** | SHA-256 of WASM bytecode embedded in RA-TLS certificates |

---

## Using the SDK

### 1. Copy the WIT files

Copy the `sdk/wit/` directory into your WASM project:

```
your-wasm-app/
├── Cargo.toml
├── src/
│   └── lib.rs
└── wit/
    ├── world.wit              ← your world (imports from SDK)
    └── deps/
        ├── enclave-os/        ← from sdk/wit/enclave-os.wit
        ├── io/                ← from sdk/wit/deps/io/
        ├── clocks/            ← from sdk/wit/deps/clocks/
        ├── random/            ← from sdk/wit/deps/random/
        ├── filesystem/        ← from sdk/wit/deps/filesystem/
        ├── cli/               ← from sdk/wit/deps/cli/
        └── sockets/           ← from sdk/wit/deps/sockets/
```

### 2. Define your world

Create `wit/world.wit` importing only what you need:

```wit
package my-org:my-app;

world my-app {
    // Import the platform APIs you need
    import privasys:enclave-os/crypto@0.1.0;
    import privasys:enclave-os/https@0.1.0;

    // Import WASI interfaces you need
    import wasi:random/random@0.2.0;
    import wasi:clocks/wall-clock@0.2.0;

    // Export your functions
    export process: func(input: string) -> string;
}
```

### 3. Build

```bash
cargo component build --release
```

Output: `target/wasm32-wasip1/release/your_app.wasm`

### 4. Load into the enclave

Connect to the running enclave over RA-TLS and upload the compiled WASM component:

```json
{
    "wasm_load": {
        "name": "my-app",
        "bytes": [0, 97, 115, 109, ...]
    }
}
```

### 5. Call over RA-TLS

```json
{
    "wasm_call": {
        "app": "my-app",
        "function": "process",
        "params": [{"type": "string", "value": "hello"}]
    }
}
```

---

## SDK File Structure

```
sdk/
├── README.md              ← this file
├── README.wit             ← overview comment (not parsed)
└── wit/
    ├── world.wit          ← reference world (all imports)
    ├── enclave-os.wit     ← privasys:enclave-os@0.1.0 (crypto, keystore, https)
    └── deps/
        ├── io/            ← wasi:io@0.2.0
        ├── clocks/        ← wasi:clocks@0.2.0
        ├── random/        ← wasi:random@0.2.0
        ├── filesystem/    ← wasi:filesystem@0.2.0
        ├── cli/           ← wasi:cli@0.2.0
        └── sockets/       ← wasi:sockets@0.2.0
```

## Version Compatibility

| SDK version | Enclave OS | WASI | Component Model |
|-------------|-----------|------|-----------------|
| 0.1.0 | Mini 0.1.x | Preview 2 (0.2.0) | Yes |

> **Note**: The standard `cargo-component` toolchain bundles a WASI adapter that stamps interfaces at `@0.2.3`. The enclave host currently registers them at `@0.2.0`. Before integration, update the host's version strings in `crates/enclave-os-wasm/src/wasi/` — the API surface is identical.
