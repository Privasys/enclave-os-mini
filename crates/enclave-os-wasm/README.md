# enclave-os-wasm

WebAssembly Component runtime for Enclave OS (Mini). Executes third-party WASM
bytecode inside an Intel SGX enclave with WASI support (random, clocks,
filesystem, sockets) and Enclave OS platform APIs (crypto, keystore, HTTPS
egress).

## Wasmtime fork — rationale

This crate depends on a [Privasys fork of wasmtime](https://github.com/Privasys/wasmtime)
(branch `sgx`). The fork introduces **two commits** on top of upstream
`main` (`2b7715886`). Every change is gated behind
`#[cfg(target_vendor = "teaclave")]` so that non-SGX builds are completely
unaffected.

### Commit 1 — `16f076a45` — Route Teaclave target to `sys::custom`

Wasmtime supports a `sys::custom` backend with C-ABI hooks for memory
management, trap handling, and TLS. This backend is intended for `no_std`
environments. SGX enclaves link against Teaclave's `sgx_tstd` (a partial
`std` re-implementation), so `cfg(unix)` and `cfg(feature = "std")` are
both true — which means the default build would route to `sys::unix` and
try to call `mmap`, `mprotect`, `sigaction`, etc., all of which are
unavailable inside an enclave.

This commit makes wasmtime recognize `target_vendor = "teaclave"` and
route to `sys::custom` instead, where our `sgx_platform.rs` provides the
required `extern "C"` symbols.

#### Files changed

**`crates/wasmtime/Cargo.toml`** — New `sgx` feature

```toml
sgx = ["runtime", "custom-virtual-memory", "custom-native-signals"]
```

The feature enables the two `custom-*` features that activate the C API
backend. Additionally, two platform-gated dependency blocks are updated:

- `memfd` (Linux memory-mapped file descriptors) — excluded for Teaclave
  because SGX has no `/proc/self/fd` or `memfd_create`.
- `rustix` (low-level POSIX bindings) — excluded for Teaclave because
  system calls are not available inside an enclave.

**`crates/wasmtime/build.rs`** — Exclude Teaclave from `supported_os`

The build script sets `supported_os = true` for unix + std, which
activates the `sys::unix` module. The fix adds `&& !teaclave` so that
Teaclave targets are treated like an unsupported OS, falling through to
`sys::custom`.

**`crates/wasmtime/src/runtime.rs`** — Skip unix extensions for Teaclave

The `cfg_if!` chain that conditionally exposes `pub mod unix` (Unix-specific
extensions like `PoolingAllocationConfig::create_memfd_image`) now has a
`target_vendor = "teaclave"` branch above the `unix` branch, so those
extensions are not compiled.

**`crates/wasmtime/src/runtime/vm/sys/mod.rs`** — Route to `sys::custom`

The core routing change. The `cfg_if!` chain that selects the system
backend (`unix`, `windows`, `custom`) now matches Teaclave before `unix`:

```rust
} else if #[cfg(target_vendor = "teaclave")] {
    mod custom;
    pub use custom::*;
} else if #[cfg(windows)] {
```

This is the fundamental change that makes wasmtime compile for SGX. Our
crate's `sgx_platform.rs` then provides the `extern "C"` symbols that
`sys::custom::capi` declares — memory allocation via an RWX code pool,
a VEH-based trap handler, and AtomicPtr-based thread-local storage.

---

### Commit 2 — `d7d53bb99` — De-activate incompatible subsystems

With `sys::custom` routing in place, the runtime compiles but several
subsystems still assume a full POSIX environment. This commit fixes four
files:

#### 1. Serialization — skip ISA flag and OS triple checks

**File:** `crates/wasmtime/src/engine/serialization.rs`

When loading a pre-compiled `.cwasm` module, wasmtime's `check_compatible`
function validates that the module's metadata matches the host. Two checks
fail in the SGX cross-compilation scenario:

**OS triple mismatch.** The AOT compiler (`enclave-os-wasm-compile`) runs
on `x86_64-unknown-linux-gnu` and embeds that triple in the `.cwasm`
metadata. The enclave runtime reports `x86_64-unknown-teaclave-sgx`.
Without the skip, loading fails with:

> *"Module was compiled for operating system 'linux'"*

This is a hard blocker — no AOT module can load without this change.

**ISA flags mismatch.** This is the more subtle issue (cf. [wasmtime
#3897](https://github.com/bytecodealliance/wasmtime/issues/3897)).
When Cranelift compiles a `.cwasm`, it queries CPUID on the host to
detect CPU features (SSE4.2, AVX2, BMI2, POPCNT, etc.) and enables
corresponding optimizations. These feature flags are embedded in the
`.cwasm` metadata. At load time, wasmtime runs `check_isa_flags` which
calls `std::is_x86_feature_detected!()` — which internally calls CPUID —
to verify the host CPU actually supports the features the module was
compiled for.

The problem: **Intel SGX filters CPUID results.** The `CPUID` instruction
inside an enclave doesn't trap to the OS, but the SGX microcode masks
certain feature bits depending on the SGX version and enclave attributes.
A feature like AVX2 may be physically present and fully functional, but
SGX-filtered CPUID reports it as absent. The AOT compiler, running
**outside** SGX on the same physical CPU, sees the real CPUID and enables
the optimization. The enclave, running on the **same CPU**, gets a
filtered CPUID and thinks the feature is missing. Result:

> *"compilation settings of module incompatible with native host:
> compilation setting "has_avx2" is enabled, but not available on the
> host"*

This check exists to prevent loading a `.cwasm` compiled for a more
capable CPU onto a less capable one. In our case:

1. **Same physical CPU** — the compiler and enclave always run on the
   same machine (or at least the same CPU model, verified by
   MRENCLAVE/MRSIGNER attestation).
2. **MRENCLAVE integrity** — the `.cwasm` is compiled from WASM bytecode
   whose SHA-256 hash is attested in the RA-TLS certificate. Nobody
   can substitute a differently-compiled module without the hash
   changing.
3. **Feature flags are additive** — if Cranelift emitted AVX2
   instructions, the CPU supports them. The issue is purely a reporting
   discrepancy.

Skipping the check is therefore safe. Both guards are:

```rust
#[cfg(not(target_vendor = "teaclave"))]
```

This means outside SGX (normal Linux/Windows/macOS), the checks still run
at full strictness. Only the SGX enclave build skips them.

> **Alternative considered:** Providing a custom `detect_host_feature`
> callback via `Config::detect_host_feature()` that returns `Some(true)`
> for all features. This would avoid patching wasmtime source but requires
> hardcoding the host's feature set inside the enclave. Since we control
> the compilation pipeline end-to-end and MRENCLAVE guarantees integrity,
> the compile-time `#[cfg]` skip is simpler and equally correct.

#### 2. Profiling agent — disable perfmap

**File:** `crates/wasmtime/src/profiling_agent.rs`

The `perfmap` profiling agent writes JIT symbol maps to `/tmp/perf-<pid>.map`
for Linux `perf` integration. This requires filesystem access (`std::fs`)
and `/tmp` — neither exists inside SGX. The fix adds
`not(target_vendor = "teaclave")` to the `cfg` gate:

```rust
if #[cfg(all(unix, feature = "std", not(target_vendor = "teaclave")))] {
    mod perfmap;
```

Without this, compilation fails because `std::fs::File::create` resolves
to Teaclave's stub which either panics or returns an error.

#### 3. Debug — replace `std::process::abort` with `panic!`

**File:** `crates/wasmtime/src/runtime/debug.rs`

The `abort_on_republish_error` function is called when re-publishing
executable code (after GDB breakpoint editing) fails. It calls
`std::process::abort()` as a last resort. In SGX, `abort()` is not
available — the enclave does not own the process. The fix provides a
Teaclave-specific version that calls `panic!()` instead:

```rust
#[cfg(all(feature = "std", target_vendor = "teaclave"))]
fn abort_on_republish_error(e: crate::Error) -> ! {
    panic!("abort: failed to re-publish executable code");
}
```

This is safe because:
- The enclave is single-threaded per TCS (no stack unwinding race).
- Teaclave's panic handler terminates the enclave thread cleanly.
- This code path should never be hit in production (it relates to GDB
  breakpoint editing, which doesn't happen inside SGX).

#### 4. Store — replace `std::process::abort` with `panic!`

**File:** `crates/wasmtime/src/runtime/store.rs`

`StoreOpaque` handles invalid trap faults by printing a diagnostic to
stderr and calling `std::process::abort()`. Same issue as above —
`abort()` and `eprintln!` are not available in SGX. The fix adds a
Teaclave-specific branch that panics with the PC and address:

```rust
if #[cfg(target_vendor = "teaclave")] {
    let _ = pc;
    panic!("wasmtime: invalid fault at pc=0x{:x}, addr=0x{:x}", pc, addr);
}
```

---

### Summary of all changes

| File | Commit | Change | Reason |
|------|--------|--------|--------|
| `Cargo.toml` | 1 | Add `sgx` feature; exclude `memfd`/`rustix` for Teaclave | No `memfd_create` or syscalls in SGX |
| `build.rs` | 1 | Exclude Teaclave from `supported_os` | Prevent `sys::unix` module selection |
| `runtime.rs` | 1 | Skip `pub mod unix` for Teaclave | Unix extensions use unavailable APIs |
| `sys/mod.rs` | 1 | Route Teaclave to `sys::custom` | Core change: use C API backend |
| `serialization.rs` | 2 | Skip OS triple check | Compiler=linux-gnu, enclave=teaclave |
| `serialization.rs` | 2 | Skip ISA flags check | SGX CPUID filtering hides real CPU features |
| `profiling_agent.rs` | 2 | Disable perfmap | No filesystem in SGX |
| `debug.rs` | 2 | `abort` → `panic` | No `std::process::abort` in SGX |
| `store.rs` | 2 | `abort` → `panic` | No `std::process::abort` in SGX |

### Platform integration (`sgx_platform.rs`)

On the enclave side, `src/sgx_platform.rs` in this crate provides the
`extern "C"` symbols that wasmtime's `sys::custom::capi` module expects.
Key design choices:

- **RWX code pool**: A 16 MiB `.wasm_code` ELF section allocated via
  `global_asm!` with `"awx"` flags. `sgx_sign` creates EADD entries with
  RWX permissions for these pages. Wasmtime gets code memory from this
  pool (bump allocator) and data memory from the regular heap.

- **No-op `mprotect`**: Code pages are already RWX; heap pages are RW.
  No permission changes are needed or possible.

- **VEH trap handler**: `sgx_register_exception_handler` is used to catch
  hardware exceptions (illegal instruction, access violation) and convert
  them to wasmtime traps.

- **AtomicPtr TLS**: Wasmtime's thread-local storage uses an `AtomicPtr`
  since each TCS runs single-threaded.

- **Disabled memory images**: CoW / memfd-based memory images are not
  available in SGX (no `/proc`, no `memfd_create`).

## Wire protocol — dynamic WASM loading

WASM apps are loaded, unloaded, and called over the RA-TLS wire protocol.
The protocol uses a `WasmEnvelope` JSON payload inside the core
`Request::Data` / `Response::Data` framing.

### Management commands

| Command | Envelope field | Payload | Response |
|---------|---------------|---------|----------|
| **Load app** | `wasm_load` | `{ name, bytes }` | `WasmManagementResult::Loaded { app }` |
| **Unload app** | `wasm_unload` | `{ name }` | `Unloaded { name }` or `NotFound { name }` |
| **List apps** | `wasm_list` | `{}` | `Apps { apps: [...] }` |
| **Call function** | `wasm_call` | `{ app, function, params }` | `WasmResult { values }` or `{ error }` |

Only one field should be set per envelope. The module dispatches in order:
`wasm_call` → `wasm_load` → `wasm_unload` → `wasm_list`.

### Example: load and call

```json
// 1. Upload the WASM component
{"wasm_load": {"name": "my-app", "bytes": [0, 97, 115, 109, ...]}}

// 2. Call a function
{"wasm_call": {"app": "my-app", "function": "hello", "params": [{"type": "string", "value": "world"}]}}

// 3. List loaded apps
{"wasm_list": {}}

// 4. Unload when done
{"wasm_unload": {"name": "my-app"}}
```

### Attestation

Each loaded app's SHA-256 code hash is automatically included in subsequent
RA-TLS certificate renewals (OID `1.3.6.1.4.1.65230.2.3`). Clients can
verify exactly which WASM code is running without trusting the operator.

## Directory structure

```
enclave-os-wasm/
├── Cargo.toml                  # Crate manifest (wasmtime fork dep)
├── README.md                   # This file
├── sdk/                        # WASM SDK — WIT definitions + docs
│   ├── README.md               # Full API surface documentation
│   ├── README.wit              # Overview comment
│   └── wit/                    # WIT interface definitions
│       ├── world.wit           # Reference world (all imports)
│       ├── enclave-os.wit      # privasys:enclave-os@0.1.0
│       └── deps/               # Standard WASI interfaces
├── tools/
│   └── wasm-compile/           # AOT compiler for .cwasm artifacts
│       ├── Cargo.toml          # Same wasmtime fork, no sgx feature
│       └── src/main.rs
└── src/
    ├── lib.rs                  # WasmModule — public API
    ├── engine.rs               # Wasmtime Engine + Component setup
    ├── protocol.rs             # WasmCall / WasmResult wire format
    ├── registry.rs             # App registry (load/unload/list)
    ├── sgx_platform.rs         # Platform layer (RWX pool, VEH, TLS)
    ├── enclave_sdk.wit         # WIT for privasys:enclave-os
    ├── enclave_sdk/            # Host-side SDK implementations
    │   ├── mod.rs
    │   ├── crypto.rs           # ring-based crypto (AES-GCM, ECDSA, HMAC)
    │   ├── https.rs            # rustls HTTPS egress
    │   └── keystore.rs         # In-memory + sealed key management
    └── wasi/                   # WASI interface implementations
        ├── mod.rs
        ├── cli.rs              # random, clocks, env, stdin/stdout, exit
        ├── filesystem.rs       # Sealed KV-backed filesystem
        ├── io.rs               # In-memory streams + poll
        └── sockets.rs          # TCP via host OCALLs
```

## License

GNU Affero General Public License v3.0 — see [LICENSE](../../LICENSE).
