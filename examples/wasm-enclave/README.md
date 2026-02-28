# Enclave OS + WASM Example

This example shows how to compose Enclave OS (Mini) with the WASM runtime
module. The result is an enclave that accepts dynamic WASM app loading over
RA-TLS.

## What this does

The [default `ecall_run`](../../enclave/src/ecall.rs) in `enclave-os-enclave`
registers only the HelloWorld diagnostic module, keeping the enclave binary
minimal.

This example provides a custom `ecall_run` that also registers the
[`WasmModule`](../../crates/enclave-os-wasm/) — enabling clients to
dynamically load, call, list, and unload WASM Components over the RA-TLS
wire protocol.

## Building

### Option A: Modify CMake to point at this crate

In `enclave/CMakeLists.txt`, change:

```cmake
rust_build_enclave("${CMAKE_CURRENT_SOURCE_DIR}" enclave_os_enclave)
```

to:

```cmake
rust_build_enclave("${CMAKE_SOURCE_DIR}/examples/wasm-enclave" enclave_os_wasm_app)
```

And update the corresponding `add_dependencies` and `set(ENCLAVE_STATIC_LIB ...)` lines.

### Option B: Copy to your own project

Copy this directory as a starting point for your own enclave composition.
Update the `path = "..."` entries in `Cargo.toml` to point at your local
checkout of `enclave-os-mini`.

## Usage

Once built and deployed, connect over RA-TLS:

```json
{"wasm_load": {"name": "my-app", "bytes": [0, 97, 115, 109, ...]}}
{"wasm_call": {"app": "my-app", "function": "process", "params": [{"type": "string", "value": "hello"}]}}
{"wasm_list": {}}
{"wasm_unload": {"name": "my-app"}}
```

## Project structure

```
examples/wasm-enclave/
├── Cargo.toml     # Depends on enclave-os-enclave + enclave-os-wasm
├── README.md      # This file
└── src/
    └── lib.rs     # Custom ecall_run (~40 lines)
```
