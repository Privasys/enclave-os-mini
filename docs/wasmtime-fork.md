# Wasmtime Fork — SGX Port

The WASM runtime (`enclave-os-wasm`) and the two AOT compiler tools
(`tools/wasm-precompile`, `crates/enclave-os-wasm/tools/wasm-compile`) depend
on the [Privasys fork of wasmtime](https://github.com/Privasys/wasmtime),
pinned by release **tag** (not a moving branch):

```toml
wasmtime = { git = "https://github.com/Privasys/wasmtime", tag = "privasys-v0.2.0", ... }
```

- **`privasys-v0.2.0`** = upstream **v47.0.1** + a single squashed
  Teaclave/SGX port commit on top (the `sgx` branch head).
- The full rationale for every change lives in
  [`SGX_FORK.md`](https://github.com/Privasys/wasmtime/blob/sgx/SGX_FORK.md)
  in the fork. In short: route `target_vendor = "teaclave"` to
  `sys::custom`, and de-activate the subsystems that assume a full POSIX
  environment (perfmap, `std::process::abort`, and the `.cwasm`
  ISA-flags / OS-triple compatibility checks). Every change is gated behind
  `#[cfg(target_vendor = "teaclave")]`, so non-SGX builds are unaffected.

The enclave links wasmtime with `default-features = false` and the
`component-model`, `runtime`, `std`, and `sgx` features. The AOT tools add
`cranelift`. `sgx_platform.rs` provides the `extern "C"` symbols that
wasmtime's `sys::custom::capi` declares (RWX code pool, VEH trap handler,
AtomicPtr TLS).

## Updating to a new upstream release

The fork is maintained as one commit on top of an upstream release tag,
never a merge. To move it forward: rebase the SGX commit onto the new
upstream tag, GPG-sign, force-push `sgx`, cut the next `privasys-vX.Y.Z`
tag — the exact steps are in the fork's `SGX_FORK.md`. Then in this repo:

1. Bump the `tag = "privasys-vX.Y.Z"` in the three `wasmtime = { git = ... }`
   entries and regenerate the lockfiles (`cargo update -p wasmtime`).
2. Adapt any call sites to wasmtime API changes. (v47 example: the
   component-type `exports()` iterator now yields `ComponentExtern` whose
   `.ty` field carries the `ComponentItem` — see `engine.rs`.)
3. Rebuild the enclave and **re-pin its MRENCLAVE**.

> **MRENCLAVE depends on the Cargo source-id, not just the source code.**
> Switching the pin from `branch = "sgx"` to `tag = "privasys-v0.2.0"` (or any
> change to the git URL/ref/rev) changes each wasmtime crate's canonical
> source string, which feeds Rust's `-C metadata` symbol hashes, which
> changes the compiled bytes — so the MRENCLAVE changes even when the
> compiled source is byte-identical. Always rebuild and re-pin after
> touching the pin, and deploy the exact artifact whose MRENCLAVE you pinned.
