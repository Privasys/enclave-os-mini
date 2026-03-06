# Building and Usage

## Prerequisites

### Host machine (build + run)

| Dependency | Purpose | Install |
|------------|---------|---------|
| Rust nightly-2025-12-01 | Enclave compilation | `rustup install nightly-2025-12-01` |
| `rust-src` component | SGX sysroot build | `rustup component add rust-src --toolchain nightly-2025-12-01` |
| Intel SGX SDK 2.25 | `sgx_edger8r`, `sgx_sign`, runtime libs | [Intel SGX SDK](https://download.01.org/intel-sgx/latest/linux-latest/docs/) |
| Intel SGX PSW | AESM service (quoting) | `apt install sgx-aesm-service libsgx-dcap-ql` |
| CMake 3.20+ | Build system | `apt install cmake` |
| GCC / build-essential | C compiler (EDL glue, RocksDB) | `apt install build-essential` |
| pkg-config | Library discovery | `apt install pkg-config` |

### WASM development (optional)

| Dependency | Purpose | Install |
|------------|---------|---------|
| Rust stable 1.82+ | WASM app compilation | `rustup update stable` |
| `wasm32-wasip2` target | WASI Component Model | `rustup target add wasm32-wasip2` |
| cargo-component | WIT-based WASM builds | `cargo install cargo-component` |
| Wasmtime CLI | AOT pre-compilation | `cargo install wasmtime-cli` |

---

## Building the Enclave

### Standard build (no WASM)

```bash
git clone https://github.com/Privasys/enclave-os-mini.git
cd enclave-os-mini

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Outputs in `build/bin/`:
- `enclave-os-host` — untrusted host binary
- `enclave.signed.so` — signed SGX enclave

### Build with WASM runtime

The WASM runtime requires a **composition crate** that combines the base
enclave with the WASM module.  The
[wasm-app-example](https://github.com/Privasys/wasm-app-example) repository
provides one:

```bash
# Clone the composition crate
git clone https://github.com/Privasys/wasm-app-example.git

# Build enclave-os-mini with WASM enabled
cd enclave-os-mini
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_WASM=ON \
    -DWASM_ENCLAVE_DIR=/path/to/wasm-app-example/enclave
cmake --build build -j$(nproc)
```

The `-DWASM_ENCLAVE_DIR` flag is **required** when `-DENABLE_WASM=ON` — it
points CMake at the composition crate that registers the WASM module.

### Build options

| CMake flag | Default | Description |
|------------|---------|-------------|
| `CMAKE_BUILD_TYPE` | `Debug` | `Release` for production (LTO, no debug symbols) |
| `ENABLE_WASM` | `OFF` | Enable the WASM runtime module |
| `WASM_ENCLAVE_DIR` | *(none)* | Path to the WASM composition crate (required when `ENABLE_WASM=ON`) |

### Host-only build (development on Windows/macOS)

For local development without SGX hardware, build only the host crate in
mock mode:

```bash
cargo build --manifest-path host/Cargo.toml
```

### Running tests

```bash
cargo test --workspace
```

---

## Running the Enclave

### First run — provision CA material

On the first run, provide the intermediary CA certificate and private key
so the enclave can seal them:

```bash
cd build/bin

./enclave-os-host \
    --port 8443 \
    --kv-path ./kvdata \
    --ca-cert /path/to/intermediary-ca.crt \
    --ca-key  /path/to/intermediary-ca.key \
    --egress-ca-bundle /etc/ssl/certs/ca-certificates.crt \
    --debug
```

| Flag | Required | Description |
|------|----------|-------------|
| `--port` | yes | TLS listen port |
| `--kv-path` | yes | Directory for RocksDB encrypted KV store |
| `--ca-cert` | first run | PEM or DER intermediary CA certificate |
| `--ca-key` | first run | PEM or PKCS#8 CA private key (ECDSA P-256) |
| `--egress-ca-bundle` | optional | Root CA bundle for HTTPS egress |
| `--debug` | optional | Enable debug logging |

The enclave will:

1. Generate an AES-256 master key via RDRAND
2. Seal everything into a unified `SealedConfig` (MRENCLAVE policy)
3. Store the sealed blob in the KV store
4. Start the RA-TLS server

### Subsequent restarts

The enclave automatically unseals the config — no flags needed beyond
port and KV path:

```bash
./enclave-os-host \
    --port 8443 \
    --kv-path ./kvdata
```

Providing `--ca-cert` or `--ca-key` on restart **updates** the sealed
config (e.g. CA rotation).  The master key is preserved.

### Production deployment

For production, run the enclave behind a **Layer 4 (TCP passthrough)** proxy.
The enclave terminates TLS internally — the proxy must NOT terminate TLS.

See:
- [Layer 4 Proxy Guide](layer4-proxy.md) — Caddy (caddy-l4) and HAProxy
- [OVH Bare Metal (SGX)](https://github.com/Privasys/wasm-app-example/blob/main/install/ovh-sgx.md) — Full deployment walkthrough

---

## Loading WASM Apps

The enclave starts **empty** — no WASM apps are compiled in.  Apps are loaded
at runtime over the RA-TLS connection.

### 1. Build the WASM app

```bash
cd wasm-app-example
cargo component build --release
```

### 2. Pre-compile to `.cwasm`

```bash
wasmtime compile target/wasm32-wasip1/release/wasm_example.wasm -o wasm_example.cwasm
```

### 3. Load into the enclave

Using the test script:

```bash
python tests/test_wasm_functions.py wasm_example.cwasm
```

Or programmatically via any [RA-TLS client](https://github.com/Privasys/ra-tls-clients):

```python
import json, socket, ssl, struct

def frame(data):
    return struct.pack(">I", len(data)) + data

# Connect
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = ctx.wrap_socket(
    socket.create_connection(("127.0.0.1", 8443)),
    server_hostname="127.0.0.1",
)

# Load the WASM app
with open("wasm_example.cwasm", "rb") as f:
    wasm_bytes = list(f.read())

load_req = json.dumps({
    "wasm_load": {"name": "my-app", "bytes": wasm_bytes}
}).encode()
sock.sendall(frame(json.dumps({"Data": list(load_req)}).encode()))

# Read response
buf = sock.recv(65536)
length = struct.unpack(">I", buf[:4])[0]
resp = json.loads(buf[4:4+length])
inner = json.loads(bytes(resp["Data"]))
print("Loaded:", json.dumps(inner, indent=2))
```

---

## Client Libraries

Use [ra-tls-clients](https://github.com/Privasys/ra-tls-clients) to connect
to the enclave with RA-TLS verification:

| Language | Path |
|----------|------|
| Go | `ra-tls-clients/go/` |
| Python | `ra-tls-clients/python/` |
| Rust | `ra-tls-clients/rust/` |
| TypeScript | `ra-tls-clients/typescript/` |
| C# (.NET) | `ra-tls-clients/dotnet/` |

The Go CLI provides an interactive session:

```bash
cd ra-tls-clients/go
go run . --host enclave.example.com --port 443
```

---

## Certificate Trust Chain

```
Root CA (your organization's root)
 └── Intermediary CA (provisioned at first run, sealed inside enclave)
      └── Leaf RA-TLS cert (per-connection, with SGX quote + config OIDs)
```

Use the root CA when configuring client libraries:

```bash
# Go client
go run . --host server --port 443 --ca-cert /path/to/root-ca.crt

# Python
from ratls_client import RaTlsClient
client = RaTlsClient("server", 443, ca_cert="/path/to/root-ca.crt")
```

### Verifying the RA-TLS certificate

```bash
# View certificate extensions
openssl s_client -connect enclave.example.com:443 </dev/null 2>&1 | \
    openssl x509 -text -noout | grep -A2 "1.3.6.1.4.1.65230"
```

Expected OIDs:
- `1.3.6.1.4.1.65230.1.1` — Config Merkle Root
- `1.3.6.1.4.1.65230.2.1` — Egress CA Hash
- `1.3.6.1.4.1.65230.2.5` — Combined Workloads Hash (WASM apps)
- `1.3.6.1.4.1.65230.2.7` — Attestation Servers Hash

---

## Project Structure

```
enclave-os-mini/
├── CMakeLists.txt               # Top-level CMake build
├── cmake/
│   ├── RustBuild.cmake          # Rust/Cargo integration for CMake
│   └── SgxConfig.cmake          # SGX SDK paths and signing config
├── common/                      # Shared types (host + enclave)
│   └── src/
│       ├── channel.rs           # SPSC queue implementation
│       ├── oids.rs              # X.509 OID constants
│       └── ...
├── enclave/                     # Enclave crate (trusted code)
│   ├── CMakeLists.txt           # Enclave build + SGX signing
│   ├── src/
│   │   ├── ecall.rs             # ECALL entry points
│   │   ├── config_merkle.rs     # Merkle tree construction
│   │   ├── sealed_config.rs     # Sealed config serialization
│   │   ├── crypto/
│   │   │   └── sealing.rs       # SGX seal/unseal wrappers
│   │   ├── modules/
│   │   │   ├── mod.rs           # EnclaveModule trait
│   │   │   └── helloworld.rs    # Example module
│   │   └── ratls/
│   │       ├── attestation.rs   # RA-TLS cert generation + SGX quotes
│   │       ├── cert_store.rs    # Per-app SNI certificate routing
│   │       ├── server.rs        # TLS server (data channel)
│   │       └── session.rs       # TLS session byte I/O
│   └── build.rs                 # Build script (getrandom shim)
├── host/                        # Host crate (untrusted code)
│   └── src/
│       ├── dispatcher.rs        # RPC dispatcher (polls SPSC queues)
│       └── net/
│           └── listener.rs      # TCP socket management
├── crates/
│   ├── enclave-os-egress/       # HTTPS egress module
│   ├── enclave-os-kvstore/      # Sealed KV store module
│   ├── enclave-os-vault/        # JWT-authenticated vault module
│   └── enclave-os-wasm/         # WASM runtime module
│       └── src/
│           ├── lib.rs           # EnclaveModule impl
│           ├── engine.rs        # Wasmtime engine config
│           ├── registry.rs      # App registry + call dispatch
│           ├── protocol.rs      # Wire protocol types
│           ├── sgx_platform.rs  # Custom Wasmtime platform layer
│           ├── wasi/            # WASI interface implementations
│           ├── enclave_sdk/     # Enclave OS SDK interfaces
│           └── sdk/             # WIT interface definitions
├── edl/
│   └── enclave_os.edl           # SGX EDL (ECALLs + OCALLs)
├── config/
│   ├── enclave.config.xml       # Debug enclave config
│   └── enclave.config.release.xml # Release enclave config
├── install/
│   └── layer4-proxy.md          # L4 proxy setup guide
├── docs/                        # Documentation
│   ├── architecture.md          # Architecture and design
│   ├── ra-tls.md                # RA-TLS and attestation
│   ├── wasm-runtime.md          # WASM runtime
│   └── building.md              # This file
└── tests/
    ├── certificates/            # Dev CA certificates
    └── integration/             # Integration test suite
```
