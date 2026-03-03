# Vault — Secret Store for Remote Enclaves

## Purpose

The vault module (`enclave-os-vault`) provides policy-gated secret storage
inside an SGX enclave.  It is designed to hold secrets **from other enclaves
running on other machines** — for example, a TDX VM in one data centre
storing an encryption key in an SGX vault in another.

The core guarantee: a secret stored in the vault can only be retrieved by a
remote TEE whose attestation evidence matches the policy set by the secret
owner at creation time.

---

## Actors

There are three actors in the vault model.  Understanding the distinction
is critical.

### Secret Owner (= Creator)

The owner is the entity that creates, deletes, and manages a secret's access
policy.

- Authenticates via **ES256 JWTs** signed with their P-256 private key
- The vault verifies JWTs using the owner's public key (configured at vault
  startup)
- The SHA-256 hash of the owner's public key is stored in each
  `SecretRecord`, so only the original creator can delete or update a
  secret's policy
- Operations: `StoreSecret`, `DeleteSecret`, `UpdateSecretPolicy`

In most cases the Secret Onwer will be a remote TEE application (SGX enclave, TDX VM, or SEV-SNP VM).
When it needs to retrieve the secret, it will need to:

- Authenticates via **mutual RA-TLS** — the remote TEE presents its own
  RA-TLS certificate during the mTLS handshake.  The vault extracts the
  SGX/TDX quote and OID claims directly from the peer certificate's X.509
  extensions.
- The vault parses the quote from the peer cert, extracts the measurement
  (MRENCLAVE or MRTD), and checks it against the secret's policy whitelist
- OID claims are extracted from the peer cert's X.509 extensions and checked
  against the policy's `required_oids`
- Operation: `GetSecret`

### Manager (Bearer Token Issuer)

The manager is a **separate actor** whose sole role is to issue bearer tokens
at `GetSecret` time as defence-in-depth.  The manager:

- **Cannot** read, write, or delete a secret, and **Cannot** update policies
- **Only** signs ES256 JWTs (bearer tokens) that the remote TEE presents
  alongside its attestation evidence
- The bearer token payload is `{ "name": "<secret-name>" }`, binding the
  token to a specific secret
- The vault verifies the bearer token's signature against the
  `manager_pubkey` stored in the secret's policy

This is optional: if a secret's policy has no `manager_pubkey`, no bearer
token is required.

#### Why a Manager?

Remote attestation proves what code is running, but if the attestation
infrastructure itself is compromised (e.g. a firmware bug allows forged
quotes), an attacker could present a fake measurement.  Requiring a fresh
bearer token from the manager means the attacker needs **two independent
things** — a valid quote **and** a signed token from the manager — to
retrieve the secret.

```
 Threat model:

   RA compromised alone         → blocked (no manager JWT)
   Manager compromised alone    → blocked (no valid quote)
   Both compromised             → secret exposed (defence-in-depth breached)
```

---

## Architecture

```
                         RA-TLS
  Secret Owner     ──────────────────►  ┌───────────────────────────┐
  (ES256 JWT)                           │     enclave-os-vault      │
                                        │     (SGX enclave)         │
                                        │                           │
  Remote TEE       ══════════════════►  │  ┌─────────────────────┐  │
  (mutual RA-TLS                        │  │   SecretPolicy      │  │
   + manager JWT)                       │  │  ─────────────      │  │
                                        │  │  MRENCLAVE list     │  │
  The remote TEE presents its           │  │  MRTD list          │  │
  own RA-TLS cert; the vault            │  │  Manager pubkey     │  │
  extracts the SGX/TDX quote            │  │  OID requirements   │  │
  and OID claims from the               │  │  TTL                │  │
  peer certificate.                     │  └─────────────────────┘  │
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

## Mutual RA-TLS

The vault uses **mutual RA-TLS** for `GetSecret`: both sides of the TLS
connection present attestation certificates.

### Why Mutual?

In standard RA-TLS the *server* presents an attested certificate so clients
can verify the enclave.  But when a remote TEE fetches a secret the vault
also needs to verify *the caller*.  Mutual RA-TLS achieves this: the remote
TEE presents its own RA-TLS client certificate during the TLS handshake,
and the vault extracts attestation evidence directly from the peer cert.

### How It Works

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
other modules (WASM, KV store, etc.) without presenting a certificate.

The vault module itself enforces the requirement: if `peer_cert_der` is
absent in the `RequestContext`, `GetSecret` returns an error.

### What Changed

Previously, `GetSecret` accepted attestation evidence and OID claims as
JSON fields in the request body.  This was a **self-reported attestation**
model — the caller could claim to be any enclave.  With mutual RA-TLS the
attestation is extracted from the cryptographically-bound peer certificate,
which eliminates the possibility of spoofed attestation data.

| Before (self-reported) | After (mutual RA-TLS) |
|------------------------|----------------------|
| `GetSecret { name, bearer_token?, attestation_evidence, oid_claims? }` | `GetSecret { name, bearer_token? }` |
| Attestation in JSON body — caller can forge | Attestation in peer cert — cryptographically bound |
| No TLS-layer identity verification | Peer cert binds TEE identity to TLS session |

---

## Protocol

All requests arrive as JSON inside the enclave-os length-delimited framing
(`4-byte big-endian length || payload`).

### Requests

| Request | Auth | Description |
|---------|------|-------------|
| `StoreSecret { jwt }` | ES256 JWT (owner key) | Store a secret. JWT payload: `{ name, secret (base64url), policy }` |
| `GetSecret { name, bearer_token? }` | Mutual RA-TLS + optional manager JWT | Retrieve a secret. Attestation evidence is extracted from the peer's RA-TLS certificate (mutual TLS). |
| `DeleteSecret { jwt }` | ES256 JWT (owner key) | Delete a secret. JWT payload: `{ name }` |
| `UpdateSecretPolicy { jwt }` | ES256 JWT (owner key) | Update a secret's policy. JWT payload: `{ name, policy }` |

### Responses

| Response | Description |
|----------|-------------|
| `SecretStored { name, expires_at }` | Secret stored successfully. |
| `SecretValue { secret, expires_at }` | Secret data returned (typically a Shamir share). |
| `SecretDeleted` | Secret removed. |
| `PolicyUpdated` | Policy replaced. |
| `Error(String)` | Human-readable error message. |

---

## Access Policy

Each secret carries a `SecretPolicy` that is evaluated on every `GetSecret`
request.

| Field | Type | Description |
|-------|------|-------------|
| `allowed_mrenclave` | `Vec<String>` | SGX MRENCLAVE values (hex) allowed to retrieve the secret. |
| `allowed_mrtd` | `Vec<String>` | TDX MRTD values (hex) allowed to retrieve the secret. |
| `manager_pubkey` | `Option<String>` | Hex-encoded uncompressed P-256 public key (65 bytes: `04 \|\| x \|\| y`) of the manager. When set, `GetSecret` requires a bearer token signed by this key. |
| `required_oids` | `Vec<OidRequirement>` | OID/value pairs the caller's RA-TLS certificate must contain. |
| `ttl_seconds` | `u64` | Time-to-live in seconds. Capped at 90 days, defaults to 30 days. |

### Policy Evaluation Order

1. **Mutual RA-TLS** — the vault requires the caller to present a TLS client
   certificate.  If no peer certificate is present the request is rejected.
2. **Attestation extraction** — the vault parses the peer certificate's X.509
   extensions to extract the SGX/TDX quote (OID `1.2.840.113741.1.13.1.0` or
   `1.2.840.113741.1.5.5.1.6`) and any Privasys OID claims.
3. **Expiry** — the secret's `expires_at` timestamp is checked.
4. **Attestation identity** — the extracted quote is parsed and its
   measurement (MRENCLAVE or MRTD) is checked against the whitelist.
4b. **Bidirectional challenge-response** — when a `client_challenge_nonce`
   is present (challenge mode), the vault extracts `report_data` from the
   client's quote, computes the expected binding
   `SHA-512(SHA-256(client_pubkey) || nonce)`, and verifies they match.
   This proves the client generated its certificate specifically for this
   connection, preventing replay of previously captured client certificates.
5. **Manager bearer token** — if `manager_pubkey` is set, the bearer token
   must be a valid ES256 JWT signed by the manager, with
   `{ "name": "<secret-name>" }` matching the requested secret.
6. **OID claims** — each `required_oids` entry must have a matching claim
   extracted from the peer certificate (case-insensitive).

---

## JWT Authentication

### Owner JWTs (Store / Delete / UpdatePolicy)

The secret owner signs JWTs with their P-256 private key.  The vault is
configured at startup with the owner's public key:

```rust
let vault = VaultModule::new(owner_pubkey_hex)?;
```

The first `StoreSecret` call stores the SHA-256 hash of the owner's public
key inside the `SecretRecord`.  Subsequent `DeleteSecret` and
`UpdateSecretPolicy` calls verify that the JWT signer matches the stored
hash — only the original creator can modify or remove a secret.

### Manager Bearer Tokens (GetSecret)

When a policy includes `manager_pubkey`, the `GetSecret` caller must provide
a bearer token: an ES256 JWT signed by the manager's private key.

```json
// Bearer token JWT payload
{ "name": "customer-123-dek" }
```

The vault:
1. Hex-decodes the `manager_pubkey` from the stored policy
2. Creates a `JwtVerifier` from the manager's public key bytes
3. Verifies the bearer token's signature
4. Checks that `claims.name` matches the requested secret name

The manager's key is entirely separate from the owner's key.

---

## Storage

Secrets are persisted using `enclave-os-kvstore`, which seals data with an
**MRENCLAVE-bound key** (AES-256-GCM).  The KV key is the secret name
(UTF-8 bytes).  The value is a JSON-serialised `SecretRecord`:

```rust
struct SecretRecord {
    secret: Vec<u8>,          // the Shamir share (opaque bytes)
    policy: SecretPolicy,     // access control
    created_at: u64,          // Unix timestamp
    expires_at: u64,          // Unix timestamp
    owner_pubkey_hash: String, // SHA-256(owner public key), hex
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

Both clients handle Shamir splitting/reconstruction, ES256 JWT signing (for
the owner), and RA-TLS transport to the vault enclaves.

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
    signing_key_pkcs8: std::fs::read("owner-key.p8").unwrap(),
    ca_cert_pem: Some("vault-ca.pem".into()),
    vault_policy: None,
    // Mutual RA-TLS: the client's own RA-TLS certificate + private key.
    // Required for GetSecret — the vault extracts attestation from this cert.
    client_cert_der: Some(vec![my_ratls_cert_der]),
    client_key_pkcs8: Some(my_ratls_key_pkcs8),
}).unwrap();

// Store — secret owner Shamir-splits and distributes
let policy = SecretPolicy::new()
    .allow_mrenclave("abcd1234...")     // remote TEE's measurement
    .manager_pubkey("04aabb...")         // optional: manager's P-256 pubkey
    .ttl(86400 * 7);                    // 7 days
client.store_secret("customer-123-dek", &secret_bytes, &policy).unwrap();

// Retrieve — remote TEE collects shares via mutual RA-TLS and reconstructs.
// The TEE's attestation evidence (quote + OIDs) is extracted from its
// RA-TLS client certificate — no attestation data in the request body.
let reconstructed = client.get_secret(
    "customer-123-dek",
    Some(&manager_signed_jwt),  // bearer token (if manager_pubkey set)
).unwrap();
```

---

## Source Files

| File | Description |
|------|-------------|
| [`src/lib.rs`](../crates/enclave-os-vault/src/lib.rs) | `VaultModule` — request dispatch and handlers |
| [`src/types.rs`](../crates/enclave-os-vault/src/types.rs) | Wire types, `SecretPolicy`, `SecretRecord`, JWT claims |
| [`src/quote.rs`](../crates/enclave-os-vault/src/quote.rs) | SGX v3 / TDX v4 quote parsing and policy matching |
