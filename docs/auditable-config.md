# Auditable Configuration

Enclave OS uses a **configuration Merkle tree** to ensure that every
operator-chosen input is committed to a tamper-evident hash.  The resulting
Merkle root is embedded in every RA-TLS certificate as X.509 OID
`1.3.6.1.4.1.65230.1.1`, making the enclave's configuration auditable by
any external verifier with no trust requirements beyond the attestation
itself.

---

## How It Works

During enclave initialisation, each module registers **named leaves** with
the `ConfigMerkleTree`:

```text
┌────────────────────────────────────────────────────────┐
│  Config Merkle Root (OID 1.3.6.1.4.1.65230.1.1)        │
│  root = SHA-256( leaf₀_hash || leaf₁_hash || … )       │
├────────────────────────────────────────────────────────┤
│  core.ca_cert                 → CA certificate DER     │
│  egress.ca_bundle             → PEM CA bundle          │
│  egress.attestation_servers   → sorted URLs (newline)  │
│  wasm.code_hash               → WASM bytecode hash     │
│  …any custom module leaves…                            │
└────────────────────────────────────────────────────────┘
```

**Leaf hashing**: Each leaf's raw data is `SHA-256` hashed (absent inputs
produce a 32-byte zero hash).

**Root computation**: `SHA-256( leaf_hash₀ || leaf_hash₁ || … || leaf_hashₙ )`

**Determinism**: Leaf order is fixed (core → egress → wasm → …) and names
are included in the manifest, so the same inputs always produce the same
root.

---

## Fast-Path OIDs

In addition to the Merkle root, individual leaf hashes are embedded as
dedicated X.509 OIDs.  This lets verifiers check a specific config property
without requesting the full manifest:

| OID | Constant | What it proves |
|-----|----------|----------------|
| `1.3.6.1.4.1.65230.1.1` | `CONFIG_MERKLE_ROOT_OID` | All config inputs (Merkle root) |
| `1.3.6.1.4.1.65230.2.1` | `EGRESS_CA_HASH_OID` | Egress CA bundle identity |
| `1.3.6.1.4.1.65230.2.3` | `WASM_APPS_HASH_OID` | WASM application code identity |
| `1.3.6.1.4.1.65230.2.4` | `ATTESTATION_SERVERS_HASH_OID` | Attestation server URL list |
| `1.3.6.1.4.1.65230.3.1` | `APP_CONFIG_MERKLE_ROOT_OID` | Per-app config Merkle root |
| `1.3.6.1.4.1.65230.3.2` | `APP_CODE_HASH_OID` | Per-app code hash |

All OID constants are defined in `common/src/oids.rs` (single source of
truth).

---

## Config Inputs Reference

### `egress.ca_bundle` — Egress CA Bundle

The PEM-encoded root CA bundle that the enclave trusts for outbound HTTPS
connections.  Without one, the enclave cannot make HTTPS requests.

**How to set:**

```bash
enclave-os-host \
  --enclave-path enclave.signed.so \
  --egress-ca-bundle /etc/ssl/certs/ca-certificates.crt
```

The host reads the PEM file, hex-encodes it, and passes it to the enclave
as `egress_ca_bundle_hex` in the config JSON.  Inside the enclave, the
`EgressModule` hashes the raw PEM bytes to produce:

- Merkle leaf `egress.ca_bundle` (included in the root)
- OID `1.3.6.1.4.1.65230.2.1` (individual fast-path)

**How to update:**

1. Prepare the new PEM bundle file.
2. Restart the host with `--egress-ca-bundle /path/to/new-bundle.pem`.
3. The enclave rebuilds the Merkle tree on startup — the root and OID `2.1`
   change to reflect the new bundle.
4. Remote verifiers that pin the Merkle root or the CA hash OID will
   detect the change and must update their expected values.

---

### `egress.attestation_servers` — Attestation Server URLs

The list of attestation server URLs trusted by the enclave for remote quote
verification.  The vault module (and any other consumer) reads this list at
runtime via `enclave_os_egress::attestation_servers()`.

The attestation server is **TEE-agnostic** — it supports Intel SGX,
Intel TDX, AMD SEV-SNP, NVIDIA Confidential Computing, and ARM CCA.

**How to set:**

```bash
enclave-os-host \
  --enclave-path enclave.signed.so \
  --egress-ca-bundle /etc/ssl/certs/ca-certificates.crt \
  --attestation-servers https://as.privasys.org/verify,https://as.customer-corp.com/verify
```

The `--attestation-servers` flag accepts a comma-separated list.  The host
passes it as a JSON array (`attestation_servers`) in the config JSON.

Inside the enclave, the `EgressModule` canonicalises the URL list (sorted,
newline-joined) and hashes it to produce:

- Merkle leaf `egress.attestation_servers` (included in the root)
- OID `1.3.6.1.4.1.65230.2.4` (individual fast-path)

**How to update:**

1. Restart the host with the new `--attestation-servers` value.
2. The Merkle root and OID `2.4` reflect the updated server list.
3. Remote verifiers that pin either value will detect the change.

**Multi-party trust**: by specifying multiple URLs, the enclave operator and
the secret owner can each run independent attestation infrastructure.  The
enclave sends the raw quote to **every** configured server; **all** must
confirm the quote before measurements are trusted.

**Omitting attestation servers**: if `--attestation-servers` is not set, the
leaf is absent (zero hash) and quote verification via attestation servers is
disabled.  This is suitable for development but **not recommended** for
production — without attestation server verification, the enclave relies
solely on local measurement matching.

---

## Verification Workflow (Remote Verifier)

A remote client connecting to the enclave sees the RA-TLS certificate
containing:

1. The SGX/TDX attestation quote (proves hardware identity)
2. `CONFIG_MERKLE_ROOT_OID` (`1.3.6.1.4.1.65230.1.1`) — the root hash
3. Individual OIDs for each config property

To verify:

```text
1. Extract the attestation quote → verify via attestation server
2. Extract OID 1.3.6.1.4.1.65230.1.1 → compare against known-good root
   (OR)
   Extract individual OIDs (2.1, 2.3, 2.4, …) → compare specific values
3. (Optional) Request the full manifest from the enclave → recompute
   root from leaf hashes → confirm it matches the cert OID
```

### Computing Expected Hashes Locally

**CA bundle hash** (OID `2.1`):

```bash
sha256sum /path/to/ca-bundle.pem
```

**Attestation servers hash** (OID `2.4`):

```bash
# Sort URLs, join with newlines, SHA-256
printf '%s\n' "https://as.customer-corp.com/verify" "https://as.privasys.org/verify" | \
  tr -d '\n' | sed 's|$||' | head -c -1 | sha256sum
```

Or in Python:

```python
import hashlib
urls = ["https://as.privasys.org/verify", "https://as.customer-corp.com/verify"]
canonical = "\n".join(sorted(urls))
print(hashlib.sha256(canonical.encode()).hexdigest())
```

---

## Rust API

### Setting config from a composition crate

```rust
use enclave_os_egress::EgressModule;
use enclave_os_enclave::ecall::{init_enclave, finalize_and_run, hex_decode};
use enclave_os_enclave::modules::register_module;

let (config, sealed_cfg) = init_enclave(config_json, config_len)?;

// Load egress CA bundle from config
let pem = config.extra.get("egress_ca_bundle_hex")
    .and_then(|v| v.as_str())
    .and_then(|hex| hex_decode(hex));

// Load attestation server URLs from config
let attestation_servers = config.extra.get("attestation_servers")
    .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok());

let (egress, cert_count) = EgressModule::new(pem, attestation_servers)?;
register_module(Box::new(egress));

finalize_and_run(&config, &sealed_cfg);
```

### Reading attestation servers at runtime (e.g. vault module)

```rust
let servers = enclave_os_egress::attestation_servers()
    .expect("EgressModule not initialised");
enclave_os_egress::attestation::verify_quote(&raw_quote, servers)?;
```

### Building an `RaTlsPolicy` with attestation servers

```rust
use enclave_os_egress::client::{RaTlsPolicy, TeeType, ReportDataBinding};

let servers = enclave_os_egress::attestation_servers()
    .cloned()
    .unwrap_or_default();

let policy = RaTlsPolicy {
    tee: TeeType::Sgx,
    mr_enclave: Some(expected_mrenclave),
    mr_signer: None,
    mr_td: None,
    report_data: ReportDataBinding::Deterministic,
    expected_oids: vec![],
    attestation_servers: servers,
};
```
