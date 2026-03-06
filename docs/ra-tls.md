# Remote Attestation TLS (RA-TLS)

## Why RA-TLS?

Standard TLS proves that a client is talking to the holder of a private key.
But it says nothing about **what software** is running on the other end, or
**what configuration** it is using.

RA-TLS solves this by embedding an **Intel SGX attestation quote** directly
in the X.509 certificate.  When a client connects, it receives cryptographic
proof of:

1. **What code is running** — the `MRENCLAVE` measurement (SHA-256 of the
   enclave binary)
2. **Who signed the code** — the `MRSIGNER` identity (the enclave author's
   signing key)
3. **What the enclave reports** — the `ReportData` field (64 bytes chosen
   by the enclave, binding the TLS key to the quote)
4. **What configuration the enclave is using** — custom X.509 OID extensions
   with config hashes and Merkle roots

All of this is verified **before the TLS handshake completes**.  The client
can reject connections to enclaves running unknown code, wrong versions, or
unexpected configurations — without trusting the server operator.

---

## Certificate Trust Chain

```
Root CA (operator-provisioned)
 └── Intermediary CA (sealed inside the enclave)
      └── Leaf RA-TLS certificate (generated per-connection)
               ├── SGX Quote           (OID 1.2.840.113741.1.13.1.0)
               ├── Config Merkle Root  (OID 1.3.6.1.4.1.65230.1.1)
               ├── Module OIDs         (OID 1.3.6.1.4.1.65230.2.*)
               └── [Per-App OIDs]      (OID 1.3.6.1.4.1.65230.3.*)
```

### Intermediary CA

The CA certificate and private key (ECDSA P-256) are provisioned by the
operator at first run via `--ca-cert` and `--ca-key`.  They are:

- Sealed to disk using `sgx_tseal` with **MRENCLAVE policy** — only the
  exact same enclave binary can unseal them
- Kept only in encrypted enclave memory at runtime
- Used to sign every leaf certificate the enclave generates

The operator never needs to provide them again — the enclave unseals them
automatically on restart.

### Leaf Certificate

A fresh leaf certificate is generated for each TLS connection (or cached
for up to 24 hours in deterministic mode).  The process:

1. Generate a fresh **ECDSA P-256 key pair** inside the enclave
2. Compute `ReportData`:
   ```
   report_data = SHA-512( SHA-256(leaf_public_key_DER) || binding )
   ```
   - **Challenge mode**: `binding` = nonce from ClientHello extension `0xFFBB`
   - **Deterministic mode**: `binding` = creation timestamp (8 bytes LE)
3. Create an **SGX report** binding the public key to the enclave identity
4. Get a **DCAP quote** from the quoting enclave
5. Build the X.509 certificate with the quote and config extensions
6. Sign with the intermediary CA key

### Client Verification

Clients verify the chain in three steps:

1. **Standard TLS** — verify the certificate chain against the root CA
2. **SGX quote** — extract the quote from OID `1.2.840.113741.1.13.1.0`,
   verify the DCAP signature, check MRENCLAVE and MRSIGNER
3. **Config attestation** — check the Merkle root, module OIDs, or
   per-app hashes against known-good values

---

## X.509 OID Extensions

Every RA-TLS certificate contains custom non-critical X.509 extensions
that encode the enclave's attestation data and configuration state.

### OID Hierarchy

```
1.2.840.113741.1.13.1.0              Intel SGX DCAP Quote
1.2.840.113741.1.5.5.1.6             Intel TDX DCAP Quote

1.3.6.1.4.1.65230                    Privasys arc
├── 1.1                              Config Merkle root (enclave-wide)
├── 2.*                              Module OIDs (enclave-wide)
│   ├── 2.1                          Egress CA bundle hash
│   ├── 2.5                          Combined workloads hash (WASM apps)
│   └── 2.7                          Attestation servers hash
└── 3.*                              Per-app OIDs
    ├── 3.1                          App config Merkle root
    ├── 3.2                          App code hash
    └── 3.4                          App key source
```

### Enclave-Wide OIDs

| OID | Name | Value | Size |
|-----|------|-------|------|
| `1.2.840.113741.1.13.1.0` | SGX Quote | Raw DCAP quote bytes | ~4 KB |
| `1.3.6.1.4.1.65230.1.1` | Config Merkle Root | SHA-256 hash | 32 bytes |
| `1.3.6.1.4.1.65230.2.1` | Egress CA Hash | SHA-256 of CA bundle PEM | 32 bytes |
| `1.3.6.1.4.1.65230.2.5` | Combined Workloads Hash | SHA-256 of all app hashes | 32 bytes |
| `1.3.6.1.4.1.65230.2.7` | Attestation Servers Hash | SHA-256 of server URL list | 32 bytes |

### Per-App OIDs

When a client connects via SNI to an app-specific hostname, they receive
a dedicated certificate with app-level OIDs:

| OID | Name | Value | Size |
|-----|------|-------|------|
| `1.3.6.1.4.1.65230.3.1` | App Config Merkle Root | SHA-256 tree of app config | 32 bytes |
| `1.3.6.1.4.1.65230.3.2` | App Code Hash | SHA-256 of WASM bytecode | 32 bytes |
| `1.3.6.1.4.1.65230.3.4` | App Key Source | `"generated"` or `"byok:<fingerprint>"` | variable |

### Module OID Registration

Each module registers its OIDs via the `EnclaveModule::custom_oids()` trait
method.  At certificate generation time, all module OIDs are collected and
added as non-critical X.509 extensions.

For example, the WASM module computes a combined hash of all loaded apps:

```
combined = SHA-256( name_1 || code_hash_1 || name_2 || code_hash_2 || … )
```

(Apps sorted by name for determinism.)

This means clients can verify **which set of WASM apps is loaded** with a
single OID check, without enumerating individual apps.

---

## Building Trust: Enclave Measurement and Configuration

### The Two Pillars of Trust

**Pillar 1: Code identity (MRENCLAVE)**

The SGX quote contains `MRENCLAVE` — a SHA-256 measurement of every page
loaded into the enclave at initialization.  This proves the exact binary
that is running.  Clients pin a known-good `MRENCLAVE` value to ensure
they are talking to the correct enclave code.

**Pillar 2: Configuration identity (Merkle root)**

Knowing the code is correct is necessary but not sufficient.  The same
enclave binary can be configured differently:

- Different CA certificates (→ different trust chains)
- Different egress CA bundles (→ different outbound trust)
- Different WASM apps loaded (→ different application logic)
- Different KV encryption keys (→ different data access)

The **Config Merkle Root** (OID `1.3.6.1.4.1.65230.1.1`) captures all of
these inputs in a single 32-byte hash, allowing clients to verify the
complete configuration state.

### Config Merkle Tree

The Merkle tree is constructed deterministically from all configuration inputs:

```
                    root = SHA-256(H₀ || H₁ || … || Hₙ)
                   ╱                                    ╲
         H₀ = SHA-256(ca_cert_der)          H₁ = SHA-256(egress_ca_pem)
                                      H₂ = SHA-256(wasm.app1.code_hash)
                                      H₃ = SHA-256(wasm.app1.key_source)
                                                    …
```

**Leaf ordering** is deterministic and append-only:

| Index | Name | Input |
|-------|------|-------|
| 0 | `core.ca_cert` | Intermediary CA certificate (DER bytes) |
| 1 | `egress.ca_bundle` | Egress CA bundle (PEM bytes) |
| 2+ | `<module>.<key>` | Module-contributed leaves |

Each leaf hash is `SHA-256(data)`, or 32 zero bytes if the input is absent.

The root is:
```
root = SHA-256( leaf_hash_0 || leaf_hash_1 || … || leaf_hash_N )
```

### Config Manifest

For full auditability, the enclave stores a **config manifest** alongside
the Merkle root — a list of `(name, leaf_hash)` pairs.  Clients can request
the manifest and independently recompute the root to verify which inputs
were used:

```
Manifest format:
  [4 bytes: num_entries (u32 LE)]
  For each entry:
    [2 bytes: name_len (u16 LE)]
    [name_len bytes: name (UTF-8)]
    [32 bytes: leaf_hash]
  [32 bytes: root]
```

### Verification Strategies

Clients can choose their verification depth:

| Strategy | What to check | Trust level |
|----------|--------------|-------------|
| **MRENCLAVE only** | SGX quote → MRENCLAVE matches known value | Code is correct, but config unknown |
| **MRENCLAVE + Merkle root** | + OID `1.3.6.1.4.1.65230.1.1` | Code and full configuration verified |
| **Fast-path module OIDs** | + OID `1.3.6.1.4.1.65230.2.*` | Verify specific properties without Merkle audit |
| **Full manifest audit** | + request manifest, recompute root | Complete transparency of all inputs |
| **Per-app verification** | + OID `1.3.6.1.4.1.65230.3.*` | Verify specific WASM app code + config |

### The Honest Reporter Model

The enclave is an **honest reporter** — it computes and publishes its
configuration state in every certificate.  There is no owner key, no
authorization gate, no way to suppress information.

Anyone with host access can change the configuration (load different WASM
apps, swap the CA, etc.), but the Merkle root in the certificate will change
accordingly.  Clients pinning a known-good root will immediately detect
the change.

---

## Challenge-Response vs. Deterministic Mode

### Challenge Mode (Client → Server)

The client sends a random nonce in a TLS ClientHello extension (`0xFFBB`).
The enclave binds this nonce into the SGX quote's `ReportData`:

```
report_data = SHA-512( SHA-256(pubkey) || nonce )
```

This proves the certificate was generated **in response to this specific
connection**.  The certificate is valid for 5 minutes and is never cached.

**Use case:** High-security scenarios where certificate freshness is critical.

### Deterministic Mode

When no nonce is present, the enclave uses the creation timestamp as binding:

```
report_data = SHA-512( SHA-256(pubkey) || timestamp_le_bytes )
```

The certificate is cached per hostname for up to 24 hours.

**Use case:** Standard operation — avoids re-generating quotes for every
connection while still providing time-bound freshness.

### Bidirectional Challenge-Response (Server → Client)

When the client requests challenge mode (via `0xFFBB`), the server **also**
challenges the client by generating a random 32-byte **client challenge nonce**
and sending it in the TLS **CertificateRequest** message via extension `0xFFBB`.

The client's `GetClientCertificate` callback reads this nonce from
`CertificateRequestInfo.RATLSChallenge` and generates a fresh RA-TLS
certificate with:

```
client_report_data = SHA-512( SHA-256(client_pubkey) || server_nonce )
```

The server stores the nonce and, when processing `GetSecret`, verifies that
the client's quote `report_data` matches the expected binding.  This proves
the client generated its certificate **specifically for this TLS connection**.

**Protocol flow (single TLS handshake):**

```
 Client                                            Server (SGX Enclave)
 ───────                                            ────────────────
 1. ClientHello + ext 0xFFBB(client_nonce)
    ────────────────────────────────────────▶

                                                    2. Generate fresh ECDSA key pair
                                                    3. report_data = SHA-512(
                                                         SHA-256(server_pubkey) || client_nonce )
                                                    4. Get SGX quote with report_data
                                                    5. Generate random server_nonce (32 bytes)
                                                    6. Build cert with:
                                                         - SGX quote (OID 1.2.840...)
                                                    7. Store server_nonce for this connection

    ServerHello + Certificate (RA-TLS)
    + CertificateRequest { ext 0xFFBB(server_nonce) }
    + Finished
    ◀────────────────────────────────────────

 8. GetClientCertificate callback fires
 9. Read server_nonce from CertificateRequestInfo.RATLSChallenge
10. Generate fresh client ECDSA key pair
11. client_report_data = SHA-512(
      SHA-256(client_pubkey) || server_nonce )
12. Get TDX/SGX quote with client_report_data
13. Build client RA-TLS cert

    Client Certificate + CertificateVerify
    ────────────────────────────────────────▶

    ─────── TLS 1.3 established ───────

14. GetSecret { name, bearer_token? }
    ────────────────────────────────────────▶

                                                   15. Extract client cert from peer
                                                   16. Parse SGX/TDX quote from cert
                                                   17. Extract actual report_data
                                                   18. Compute expected = SHA-512(
                                                         SHA-256(client_pubkey) || stored_nonce )
                                                   19. Verify actual == expected
                                                   20. Check measurement, token, OIDs

    SecretValue { secret, expires_at }
    ◀────────────────────────────────────────
```

This achieves **full bidirectional challenge-response** in a single TLS
handshake:

| Direction | Challenge | Binding |
|-----------|-----------|----------|
| Client → Server | `0xFFBB nonce` in ClientHello | `server_report_data = SHA-512(SHA-256(server_pk) \|\| client_nonce)` |
| Server → Client | `0xFFBB nonce` in CertificateRequest | `client_report_data = SHA-512(SHA-256(client_pk) \|\| server_nonce)` |

**Use case:** Vault `GetSecret` — the strongest possible guarantee that both
parties generated fresh certificates specifically for this connection.

---

## Per-App Certificates and SNI Routing

### Why per-app certificates?

A single enclave can host many WASM apps simultaneously.  Per-app certificates
solve two important requirements:

1. **Tenant isolation** — each client only sees the code hash and configuration
   of the app it connects to.  A client connecting to `app-A` learns
   nothing about `app-B` or any other app in the same enclave.
2. **Independent lifecycle** — adding, removing, or updating one app does not
   affect any other app's certificate.  Clients only need to re-verify when
   *their* app changes.

Enclave OS achieves this with a **two-tier certificate hierarchy** where each
WASM app gets its own leaf certificate, signed by the enclave's attested CA:

```
Root CA (operator-provisioned)
 └── Intermediary CA (sealed inside enclave)
      └── Enclave CA Cert (attested — SGX quote lives here)
            ├── OID: MRENCLAVE / MRSIGNER
            ├── OID: Enclave Config Merkle Root (core config only)
            │
            ├── App Leaf: "payments-api"
            │     ├── OID 1.3.6.1.4.1.65230.3.2  App Code Hash
            │     ├── OID 1.3.6.1.4.1.65230.3.1  App Config Merkle Root
            │     ├── OID 1.3.6.1.4.1.65230.3.4  App Key Source
            │     └── OID 1.3.6.1.4.1.65230.3.*   App-specific custom OIDs
            │
            ├── App Leaf: "analytics-api"
            │     ├── OID 1.3.6.1.4.1.65230.3.2  App Code Hash
            │     ├── OID 1.3.6.1.4.1.65230.3.1  App Config Merkle Root
            │     ├── OID 1.3.6.1.4.1.65230.3.4  App Key Source
            │     └── ...
            │
            └── ... (scales to thousands of apps)
```

### How it works

1. **SGX quote generated once** — at enclave boot the quote is bound to the
   Enclave CA's public key via `ReportData`.  No new quote per app — that
   would be prohibitively expensive at 1 000+ apps.
2. **App leaf certs are cheap** — each is signed by the Enclave CA inside the
   enclave using `ring` ECDSA P-256.  No round-trip to the quoting enclave.
3. **SNI-based selection** — the client TLS `ClientHello` includes the app
   hostname (e.g. `payments-api.enclave.example.com`).  The enclave's
   `CertStore` looks up the matching leaf cert + chain and presents it.
4. **Independent lifecycle** — adding an app = generate a leaf cert.  Removing
   an app = drop it.  No certificate regeneration for other apps.
5. **Tenant isolation** — a client connecting for `payments-api` sees only
   that app's code hash and config Merkle root.  It learns nothing about
   `analytics-api` or any other app in the same enclave.

### Per-app Merkle tree

Each app gets its own Config Merkle tree, independent of the enclave-wide
tree.  Typical leaves:

| Leaf name | Input |
|-----------|-------|
| `app.code_hash` | SHA-256 of the WASM `.cwasm` bytecode |
| `app.key_source` | `"generated"` or `"byok:<fingerprint>"` |
| `app.name` | App name string |

The root of this per-app tree is embedded as OID `1.3.6.1.4.1.65230.3.1`
in the app's leaf certificate.

### Client verification flow

Clients verify a per-app certificate in four steps:

```
1. Root CA  →  chain signature  →  Intermediary CA  →  Enclave CA
2. Enclave CA cert  →  extract SGX quote  →  verify DCAP signature
3. SGX quote  →  check MRENCLAVE / MRSIGNER (correct enclave code)
4. App leaf cert  →  check OID 3.2 (app code hash)
                  →  check OID 3.1 (app config Merkle root)
```

No need to inspect other apps' certificates or parse a combined hash.

### Enclave-wide vs. per-app: what goes where

| Scope | Certificate | OIDs present |
|-------|-------------|-------------|
| **Enclave-wide** | Enclave CA cert (or default leaf if no SNI) | SGX Quote, Config Merkle Root (`1.1`), Module OIDs (`2.*`) |
| **Per-app** | App leaf cert (via SNI) | App Code Hash (`3.2`), App Config Merkle Root (`3.1`), app-specific (`3.*`) |

The enclave-wide certificate still contains the **combined workloads hash**
(OID `1.3.6.1.4.1.65230.2.5`) for clients that want a single check covering
all loaded apps without SNI routing.

### SNI routing in `CertStore`

The `CertStore` (in `enclave/src/ratls/cert_store.rs`) maintains a map of
`hostname → (cert_chain, private_key)`.  During the TLS handshake:

1. rustls calls the `ResolvesServerCert` implementation
2. `CertStore` extracts the SNI from the `ClientHello`
3. If a matching app entry exists → return the app's leaf cert + Enclave CA chain
4. Otherwise → return the default enclave-wide leaf cert

Apps register their hostname when loaded via `EnclaveModule::app_identities()`:

```rust
fn app_identities(&self) -> Vec<AppIdentity> {
    vec![AppIdentity {
        hostname: "payments-api.enclave.example.com".into(),
        code_hash: sha256_of_wasm_bytes,
        config_leaves: vec![
            ConfigLeaf { name: "app.code_hash".into(), data: wasm_bytes },
            ConfigLeaf { name: "app.key_source".into(), data: b"generated" },
        ],
        custom_oids: vec![],
    }]
}
```

See [WASM Runtime — Per-App X.509 Certificates](wasm-runtime.md#per-app-x509-certificates)
for the full implementation details.

---

## Mutual RA-TLS

Standard RA-TLS is **server-side only**: the server presents an attested
certificate and the client verifies it.  **Mutual RA-TLS** extends this so
that the *client* also presents an RA-TLS certificate, allowing the server
to verify the client's TEE identity.

### When It's Used

Mutual RA-TLS is **optional at the server level** — the TLS server offers
client certificate authentication but does not require it.  This allows
browsers and non-TEE clients to connect without a certificate.

It is **mandatory for the vault module**: the `GetSecret` operation requires
the caller to present an RA-TLS client certificate so the vault can extract
the attestation evidence from the peer cert's X.509 extensions rather than
relying on self-reported data in the JSON request body.

### How It Works

1. The server's `ClientCertVerifier` (`PermissiveClientAuth`) is configured
   to *offer* client auth on every connection but not *require* it.  Any
   presented certificate is accepted at the TLS layer — quote verification
   happens at the application layer.

2. After the TLS handshake, the server extracts the peer certificate DER
   (if present) and passes it to the module dispatch chain via
   `RequestContext { peer_cert_der, client_challenge_nonce }`.

3. The vault module parses the peer certificate using `x509-parser` and
   extracts:
   - The SGX/TDX quote from OID `1.2.840.113741.1.13.1.0` or
     `1.2.840.113741.1.5.5.1.6`
   - OID claims from the Privasys OID hierarchy (`1.3.6.1.4.1.65230.*`)

4. **Bidirectional challenge-response verification** (when
   `client_challenge_nonce` is present):
   - Extract `report_data` from the client's attestation quote
   - Extract the client's raw public key from the peer certificate
   - Compute expected `report_data = SHA-512(SHA-256(client_pubkey) || nonce)`
   - Verify the actual report_data matches the expected value

5. The extracted attestation evidence is verified against the secret's
   policy — identical checks to before, but the data source is now the
   cryptographically-bound peer certificate rather than the request body.

### Client Configuration

The RA-TLS client libraries support mutual RA-TLS via:

| Language | API | Description |
|----------|-----|-------------|
| Rust | `RaTlsClient::connect_mutual(host, port, cert_chain, key)` | Connect with a static client certificate |
| Go | `Options.ClientCert = &tls.Certificate{...}` | Set static client cert in connection options |
| Go | `Options.GetClientCertificate = func(...)` | Dynamic cert generation with challenge nonce (bidirectional) |

Both vault client libraries (`rust/vault/` and `go/vault/`) automatically
use mutual RA-TLS for `GetSecret` when `client_cert_der` / `ClientCert` is
configured.

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Bidirectional attestation** | Both sides prove their TEE identity via attested certificates |
| **No self-reported attestation** | The server extracts evidence from the peer cert, not the request body |
| **Backward compatible** | Clients without certificates can still connect for non-vault operations |
| **Quote verification at app layer** | The TLS layer accepts any cert; the vault module verifies the quote against policy |

---

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Key binding** | The TLS public key is cryptographically bound to the SGX quote via ReportData |
| **Code identity** | MRENCLAVE in the quote proves the exact enclave binary |
| **Config identity** | Merkle root proves all operator-chosen and module-contributed inputs |
| **Freshness** | Challenge nonce or timestamp prevents replay of old certificates |
| **Bidirectional freshness** | Server→client challenge nonce prevents replay of client certificates |
| **CA isolation** | The CA private key is sealed to MRENCLAVE — only this enclave can sign leaf certs |
| **No suppression** | The enclave is an honest reporter — it cannot hide its configuration |
| **Per-app isolation** | Each WASM app gets its own certificate, Merkle tree, and OID extensions |
