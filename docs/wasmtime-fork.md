# Wasmtime Fork: SGX Port

The WASM runtime (`enclave-os-wasm`) and the two AOT compiler tools
(`tools/wasm-precompile`, `crates/enclave-os-wasm/tools/wasm-compile`) depend
on the [Privasys fork of wasmtime](https://github.com/Privasys/wasmtime),
pinned by release **tag** (not a moving branch):

```toml
wasmtime = { git = "https://github.com/Privasys/wasmtime", tag = "privasys-v0.3.0", ... }
wasmtime-internal-fiber = { git = "https://github.com/Privasys/wasmtime", tag = "privasys-v0.3.0", features = ["std"] }
```

- **`privasys-v0.3.0`** = upstream **v48.0.2** + a single squashed
  Teaclave/SGX port commit on top (the `sgx` branch head).
- The full rationale for every change lives in
  [`SGX_FORK.md`](https://github.com/Privasys/wasmtime/blob/sgx/SGX_FORK.md)
  in the fork. In short: route `target_vendor = "teaclave"` to
  `sys::custom`, de-activate the subsystems that assume a full POSIX
  environment (perfmap, `std::process::abort`, the `.cwasm` ISA-flags /
  OS-triple compatibility checks, `avxvnni` host detection), and route the
  fiber crate to its heap-backed `nostd` backend (`cfg(unix)` is true under
  Teaclave, and the Unix backend needs `mmap`). Every change is gated
  behind `#[cfg(target_vendor = "teaclave")]`, so non-SGX builds are
  unaffected.

The enclave links wasmtime with `default-features = false` and the
`async`, `component-model`, `runtime`, `std`, `sgx` and `gc-drc` features.
The AOT tools add `cranelift`. `sgx_platform.rs` provides the `extern "C"`
symbols that wasmtime's `sys::custom::capi` declares (RWX code pool, VEH
trap handler, TLS slots).

## Fibers

With `async`, every guest call runs on a wasmtime fiber (see
[wasm-runtime.md](wasm-runtime.md#concurrency)); the enclave also runs its
request tasks on the same fiber crate (`wasmtime-internal-fiber`). Three
things are specific to SGX:

- **Stacks come from the heap.** `executor::FiberStacks` (a wasmtime
  `StackCreator`) allocates them; the `nostd` backend has no guard page, so
  `async_stack_size` (1 MiB) leaves ample room above `max_wasm_stack`
  (512 KiB) for host code (a TLS handshake measured 86 KiB).
- **Stacks are registered with the SGX runtime.** Teaclave's exception
  entry refuses an exception whose stack pointer is outside the thread
  stack and marks the enclave crashed. The enclave's CPUID emulation is
  such an exception, so each fiber stack is declared with
  `sgx_register_alt_stack` (Privasys Teaclave SDK `privasys-v0.5.0`).
- **Wasm traps are not exceptions.** With `signals_based_traps(false)`,
  Cranelift compiles traps as calls into the runtime, so a trap on a fiber
  never goes through the exception path.

From wasmtime 48, async is implied: once one async host function is linked,
every entry point must be `*_async` (`instantiate_async`, `call_async`).

## Updating to a new upstream release

The fork is maintained as one commit on top of an upstream release tag,
never a merge. To move it forward: rebase the SGX commit onto the new
upstream tag, GPG-sign, force-push `sgx`, cut the next `privasys-vX.Y.Z`
tag; the exact steps are in the fork's `SGX_FORK.md`. Then in this repo:

1. Bump the `tag = "privasys-vX.Y.Z"` in the `wasmtime` and
   `wasmtime-internal-fiber` entries and regenerate the lockfiles.
2. Adapt any call sites to wasmtime API changes. (v47 example: the
   component-type `exports()` iterator now yields `ComponentExtern` whose
   `.ty` field carries the `ComponentItem`, see `engine.rs`. v48: the
   crates moved from `cfg_if!` to `cfg_select!`, so every SGX gate in the
   fork is rewritten, and `is_x86_feature_detected!("avxvnni")` does not
   exist in the Teaclave sysroot.)
3. Diff `sys/custom/capi.rs` against `sgx_platform.rs`: a signature change
   there corrupts wasmtime's state at runtime without a compile error.
4. Keep the AOT compilers' `Config` in step with `WasmEngine::new` (fuel,
   proposals, `signals_based_traps`), and rebuild every app's `.cwasm`: a
   runtime refuses artefacts from another wasmtime version.
5. Rebuild the enclave and **re-pin its MRENCLAVE**.

> **MRENCLAVE depends on the Cargo source-id, not just the source code.**
> Switching the pin from `branch = "sgx"` to `tag = "privasys-v0.2.0"` (or any
> change to the git URL/ref/rev) changes each wasmtime crate's canonical
> source string, which feeds Rust's `-C metadata` symbol hashes, which
> changes the compiled bytes: the MRENCLAVE changes even when the compiled
> source is byte-identical. Always rebuild and re-pin after touching the
> pin, and deploy the exact artefact whose MRENCLAVE you pinned.
