# Vault — OIDC-Authenticated Secret Store

## Purpose

The vault module (`enclave-os-vault`) provides policy-gated secret storage
inside an SGX enclave.  Secrets are sealed to the enclave's code identity
(MRENCLAVE) and protected by OIDC-based access control.

The vault currently supports two retrieval paths:

1. **OIDC owner** — the secret creator retrieves their own secrets using
   their OIDC bearer token.
2. **Mutual RA-TLS** — a remote TEE retrieves secrets by presenting
   attestation evidence that matches the secret's access policy.

This makes the vault well-suited for holding secrets on behalf of enclaves
running on other machines (e.g. a TDX VM storing an encryption key in an
SGX vault), but the architecture is generic and designed to be extended
with additional retrieval and policy mechanisms in the future.

---

## Actors

There are three actors in the vault model.  Understanding the distinction
is critical.

### Secret Owner (= Creator)

The owner is the entity that creates, deletes, manages, and lists secrets.

- Authenticates via **OIDC bearer token** (Zitadel or any OIDC provider)
- Must hold the **`enclave-vault:secret-owner`** role
- The owner's OIDC `sub` (subject) claim is stored in each `SecretRecord`,
  so only the original creator can delete, update, or list their secrets
- Operations: `StoreSecret`, `DeleteSecret`, `UpdateSecretPolicy`,
  `ListSecrets`

The Secret Owner can always retrieve their own secrets via the OIDC path
(no RA-TLS required).

In production, the Secret Owner is typically a remote TEE application
(SGX enclave, TDX VM, or SEV-SNP VM).  When it needs to let **other TEEs**
retrieve the secret, those TEEs use the RA-TLS path (see below).

### Remote TEE (GetSecret via RA-TLS)

A remote TEE that needs to retrieve a secret authenticates via
**mutual RA-TLS**:

- Presents its own RA-TLS certificate during the mTLS handshake
- The vault extracts the SGX/TDX quote and OID claims directly from the
  peer certificate's X.509 extensions
- The vault parses the quote, extracts the measurement (MRENCLAVE or MRTD),
  and checks it against the secret's policy whitelist
- OID claims are extracted from the peer cert's X.509 extensions and checked
  against the policy's `required_oids`
- Operation: `GetSecret` (RA-TLS path)

### Secret Manager (Bearer Token Issuer)

The secret manager is a **separate actor** whose sole role is to issue
bearer tokens at `GetSecret` time as defence-in-depth.

- Authenticates via **OIDC bearer token**
- Must hold the **`enclave-vault:secret-manager`** role
- **Cannot** read, write, or delete secrets, and **cannot** update policies
- **Only** provides a bearer token that the remote TEE presents alongside
  its attestation evidence
- The vault verifies the bearer token's OIDC `sub` against the
  `manager_sub` stored in the secret's policy

This is optional: if a secret's policy has no `manager_sub`, no bearer
token is required.

#### Why a Secret Manager?

Remote attestation proves what code is running, but if the attestation
infrastructure is compromised (e.g. a firmware bug allows forged quotes),
an attacker could present a fake measurement.  Requiring a fresh bearer
token from the secret manager means the attacker needs **two independent
things** — a valid quote **and** a token from the manager — to retrieve
the secret.

```
 Threat model:

   RA compromised alone              → blocked (no manager token)
   Manager compromised alone          → blocked (no valid quote)
   Both compromised                   → secret exposed (defence-in-depth breached)
```

---

## Architecture

```
                            OIDC + RA-TLS
  Secret Owner          ──────────────────►  ┌───────────────────────────┐
  (OIDC: secret-owner)                       │     enclave-os-vault      │
                                             │     (SGX enclave)         │
                                             │                           │
  Remote TEE            ══════════════════►  │  ┌─────────────────────┐  │
  (mutual RA-TLS                             │  │   SecretPolicy      │  │
   + manager token?)                         │  │  ─────────────      │  │
                                             │  │  MRENCLAVE list     │  │
  The remote TEE presents its                │  │  MRTD list          │  │
  own RA-TLS cert; the vault                 │  │  Manager sub        │  │
  extracts the SGX/TDX quote                 │  │  OID requirements   │  │
  and OID claims from the                    │  │  TTL                │  │
  peer certificate.                          │  └─────────────────────┘  │
                                             │             │             │
                                             │             ▼             │
                                             │  ┌─────────────────────┐  │
                                             │  │  enclave-os-kvstore │  │
                                             │  │  (sealed storage)   │  │
                                             │  └─────────────────────┘  │
                                             └───────────────────────────┘
```

### Multi-Instance Deployment

In production the vault is deployed as **multiple instances** (typically 3
or 5).  The secret owner uses the vault client library to:

1. Split the secret into M shares using **Shamir Secret Sharing** (threshold N)
2. Store one share in each vault instance

To reconstruct the secret, any N-of-M vault instances must return their
share.  No single vault ever holds the complete secret.

```
 ┌──────────────┐       RA-TLS         ┌─────────────┐
 │              │──── share 1 ────────►│  Vault #1   │
 │  VaultClient │──── share 2 ────────►│  Vault #2   │
 │  (Shamir)    │──── share 3 ────────►│  Vault #3   │
 │              │       ...            │    ...      │
 │              │──── share M ────────►│  Vault #M   │
 └──────────────┘                      └─────────────┘

 Reconstruction: any N-of-M shares → original secret
```

---

## GetSecret Dual-Path Auth

`GetSecret` supports two authentication paths:

### Path 1 — OIDC Owner

The secret owner retrieves their own secrets using their OIDC token.  No
RA-TLS required.  The vault checks that `ctx.oidc_claims.sub` matches the
secret's `owner_sub`.

### Path 2 — RA-TLS TEE

A remote TEE retrieves secrets via mutual RA-TLS.  The vault:

1. Requires a TLS client certificate (mutual RA-TLS)
2. Extracts the attestation quote from the peer cert
3. Verifies the quote via attestation server(s)
4. Checks the measurement against the policy whitelist
5. Verifies bidirectional challenge-response binding (if nonce present)
6. Checks the optional bearer token from the secret manager
7. Checks required OID claims

```
 Remote TEE                                    Vault Enclave
 ──────────                                    ─────────────
                   ClientHello + ext 0xFFBB(nonce)
    ────────────────────────────────────────────►
                   ServerHello + server cert (RA-TLS)
                   + CertificateRequest { ext 0xFFBB(server_nonce) }
    ◄────────────────────────────────────────────

                   Client reads server_nonce from
                   CertificateRequestInfo.RATLSChallenge,
                   generates fresh RA-TLS cert with
                   report_data bound to that nonce

                   Client cert (RA-TLS, bound to server nonce)
    ────────────────────────────────────────────►
                   ───── TLS 1.3 established ─────

    GetSecret { name, bearer_token? }
    ────────────────────────────────────────────►

    Vault extracts from peer cert:
      1. SGX/TDX quote  (OID 1.2.840.113741.1.13.1.0 or 1.2.840.113741.1.5.5.1.6)
      2. OID claims      (OID 1.3.6.1.4.1.65230.*)

    Vault verifies bidirectional challenge:
      3. Extract report_data from client's quote
      4. Compute expected = SHA-512(SHA-256(client_pubkey) || stored_nonce)
      5. Verify actual == expected

    SecretValue { secret, expires_at }
    ◄────────────────────────────────────────────
```

### Server Configuration

The RA-TLS server is configured with a **permissive client certificate
verifier** — it *offers* client auth to every connection but does not
*require* it.  This allows browsers and non-TEE clients to connect for
other modules (WASM, healthz, etc.) without presenting a certificate.

The vault module itself enforces the requirement per-path: OIDC owner path
needs a valid OIDC token, RA-TLS path needs a peer certificate.

---

## Protocol

All requests arrive as JSON inside the enclave-os length-delimited framing
(`4-byte big-endian length || payload`).  OIDC tokens are passed in the
JSON `"auth"` field (stripped by the auth layer before reaching the vault).

### Requests

| Request | Auth | Role | Description |
|---------|------|------|-------------|
| `StoreSecret { name, secret, policy }` | OIDC | secret-owner | Store a secret. `secret` is base64url-encoded. |
| `GetSecret { name, bearer_token? }` | OIDC owner **or** mutual RA-TLS | — | Retrieve a secret. |
| `DeleteSecret { name }` | OIDC | secret-owner | Delete a secret (owner only). |
| `UpdateSecretPolicy { name, policy }` | OIDC | secret-owner | Update a secret's policy (owner only). |
| `ListSecrets` | OIDC | secret-owner | List all secrets owned by the caller (metadata only). |

### Responses

| Response | Description |
|----------|-------------|
| `SecretStored { name, expires_at }` | Secret stored successfully. |
| `SecretValue { secret, expires_at }` | Secret data returned (typically a Shamir share). |
| `SecretDeleted` | Secret removed. |
| `PolicyUpdated` | Policy replaced. |
| `SecretList { secrets }` | List of `{ name, expires_at }` entries for the caller's secrets. |
| `Error(String)` | Human-readable error message. |

---

## Access Policy

Each secret carries a `SecretPolicy` that is evaluated on every `GetSecret`
request via the RA-TLS path.  (OIDC owner path bypasses policy evaluation.)

| Field | Type | Description |
|-------|------|-------------|
| `allowed_mrenclave` | `Vec<String>` | SGX MRENCLAVE values (hex) allowed to retrieve the secret. |
| `allowed_mrtd` | `Vec<String>` | TDX MRTD values (hex) allowed to retrieve the secret. |
| `manager_sub` | `Option<String>` | OIDC `sub` of the secret manager. When set, `GetSecret` via RA-TLS requires a bearer token whose OIDC `sub` matches and who has the `secret-manager` role. |
| `required_oids` | `Vec<OidRequirement>` | OID/value pairs the caller's RA-TLS certificate must contain. |
| `ttl_seconds` | `u64` | Time-to-live in seconds. Capped at 90 days, defaults to 30 days. |

### Policy Evaluation Order (RA-TLS path)

1. **Mutual RA-TLS** — the vault requires the caller to present a TLS client
   certificate.  If no peer certificate is present the request is rejected.
2. **Attestation extraction** — the vault parses the peer certificate's X.509
   extensions to extract the SGX/TDX quote and Privasys OID claims.
3. **Expiry** — the secret's `expires_at` timestamp is checked.
4. **Attestation server verification** — the quote is forwarded to the
   configured attestation servers for cryptographic verification (signature
   chain, TCB status, platform identity).
5. **Attestation identity** — the extracted quote is parsed and its
   measurement (MRENCLAVE or MRTD) is checked against the whitelist.
5b. **Bidirectional challenge-response** — when a `client_challenge_nonce`
   is present, the vault verifies the client's report_data binding.
6. **Manager bearer token** — if `manager_sub` is set, the bearer token
   must be a valid OIDC JWT whose `sub` matches the policy's `manager_sub`
   and the holder must have the `secret-manager` role.
7. **OID claims** — each `required_oids` entry must have a matching claim
   extracted from the peer certificate.

---

## OIDC Authentication

### OIDC Roles

| Role | Claim value | Operations |
|------|------------|------------|
| `secret-owner` | `enclave-vault:secret-owner` | Store, Delete, Update, List, Get (own secrets) |
| `secret-manager` | `enclave-vault:secret-manager` | Issue bearer tokens for RA-TLS GetSecret |

### Token Delivery

Since enclave-os-mini uses a frame protocol (not HTTP), the OIDC bearer
token is passed inside the JSON envelope as an `"auth"` field:

```json
{
  "auth": "eyJhbGciOiJSUzI1NiIs...",
  "StoreSecret": {
    "name": "customer-123-dek",
    "secret": "base64url-encoded-bytes",
    "policy": { "allowed_mrenclave": ["abcd1234..."], "ttl_seconds": 604800 }
  }
}
```

The auth layer strips `"auth"`, verifies it via JWKS, and populates
`OidcClaims` in the `RequestContext`.  The vault reads `ctx.oidc_claims.sub`
for ownership checks and `ctx.oidc_claims.roles` for role verification.

### Owner Identity

The OIDC `sub` claim uniquely identifies the secret owner.  No more
`OpenVault` / `CloseVault` ceremony — the OIDC subject *is* the vault
namespace.  KV keys use the format `secret:{owner_sub}:{name}` for
namespace isolation between owners.

---

## Storage

Secrets are persisted using `enclave-os-kvstore`, which seals data with an
**MRENCLAVE-bound key** (AES-256-GCM).  The KV store uses HMAC-SHA256 for
key encryption, so keys are opaque on the host — no prefix or suffix
queries are possible.

### KV Key Layout

| Key | Value | Purpose |
|-----|-------|---------|
| `secret:{owner_sub}:{name}` | JSON `SecretRecord` | The actual secret data |
| `lookup:{name}` | `owner_sub` (UTF-8) | Reverse index for RA-TLS GetSecret (name → owner) |
| `index:{owner_sub}` | JSON `Vec<String>` | Owner index for ListSecrets (owner → [name, ...]) |

The reverse lookup index (`lookup:`) enables the RA-TLS GetSecret path
where the caller knows the secret name but not the owner's OIDC subject.
The owner index (`index:`) enables ListSecrets without scanning all keys.

Both indexes are maintained atomically with secret creation and deletion.

### SecretRecord

```rust
struct SecretRecord {
    secret: Vec<u8>,          // the Shamir share (opaque bytes)
    policy: SecretPolicy,     // access control
    created_at: u64,          // Unix timestamp
    expires_at: u64,          // Unix timestamp
    owner_sub: String,        // OIDC subject of the secret owner
}
```

Because sealing uses MRENCLAVE policy, only the exact same enclave binary
can unseal the data.  An enclave upgrade (new MRENCLAVE) requires the owner
to re-store secrets.

---

## Quote Parsing

The vault parses raw DCAP attestation quotes to extract TEE measurements:

| Quote Version | TEE | Measurement | Offset | Size |
|---------------|-----|-------------|--------|------|
| 3 | SGX | MRENCLAVE | 112–144 | 32 bytes |
| 4 | TDX | MRTD | 184–232 | 48 bytes |

The version field is a little-endian `u16` at bytes 0–1.  Unknown versions
are rejected.  Measurements are hex-encoded and compared case-insensitively
against the policy whitelist.

---

## Client Libraries

The [ra-tls-clients](https://github.com/Privasys/ra-tls-clients) repository
provides vault client libraries with built-in Shamir Secret Sharing:

| Language | Directory | Import |
|----------|-----------|--------|
| Rust | `rust/vault/` | `vault_client` |
| Go | `go/vault/` | `enclave-os-mini/clients/go/vault` |

Both clients handle Shamir splitting/reconstruction, OIDC token management,
and RA-TLS transport to the vault enclaves.

### Example (Rust)

```rust
use vault_client::client::{VaultClient, VaultClientConfig, VaultEndpoint, SecretPolicy};

let client = VaultClient::new(VaultClientConfig {
    endpoints: vec![
        VaultEndpoint { host: "vault1.example.com".into(), port: 443 },
        VaultEndpoint { host: "vault2.example.com".into(), port: 443 },
        VaultEndpoint { host: "vault3.example.com".into(), port: 443 },
    ],
    threshold: 2,
    // OIDC bearer token (secret-owner role)
    oidc_token: Some("eyJhbGciOi...".into()),
    ca_cert_pem: Some("vault-ca.pem".into()),
    vault_policy: None,
    // Mutual RA-TLS: the client's own RA-TLS certificate + private key.
    // Required for GetSecret via RA-TLS path.
    client_cert_der: Some(vec![my_ratls_cert_der]),
    client_key_pkcs8: Some(my_ratls_key_pkcs8),
}).unwrap();

// Store — secret owner Shamir-splits and distributes
let policy = SecretPolicy::new()
    .allow_mrenclave("abcd1234...")     // remote TEE's measurement
    .manager_sub("manager-oidc-sub")    // optional: secret manager's OIDC sub
    .ttl(86400 * 7);                    // 7 days
client.store_secret("customer-123-dek", &secret_bytes, &policy).unwrap();

// Retrieve (OIDC owner path) — owner collects shares and reconstructs.
let reconstructed = client.get_secret_oidc("customer-123-dek").unwrap();

// Retrieve (RA-TLS TEE path) — remote TEE collects shares via mutual
// RA-TLS and reconstructs.  The TEE's attestation evidence is extracted
// from its RA-TLS client certificate.
let reconstructed = client.get_secret_ratls(
    "customer-123-dek",
    Some(&manager_bearer_token),  // bearer token (if manager_sub set)
).unwrap();
```

---

## Source Files

| File | Description |
|------|-------------|
| [`src/lib.rs`](../crates/enclave-os-vault/src/lib.rs) | `VaultModule` — request dispatch and handlers |
| [`src/types.rs`](../crates/enclave-os-vault/src/types.rs) | Wire types, `SecretPolicy`, `SecretRecord` |
| [`src/quote.rs`](../crates/enclave-os-vault/src/quote.rs) | SGX v3 / TDX v4 quote parsing and policy matching |
