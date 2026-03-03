# enclave-os-vault

Secret management module for [enclave-os-mini](../../README.md). Provides JWT-authenticated,
policy-gated secret storage backed by a sealed KV store.

## Architecture

```
                        RA-TLS
  Secret Owner    ──────────────────►  ┌───────────────────────────┐
  (ES256 JWT)                          │     enclave-os-vault      │
                                       │                           │
  TEE Application ══════════════════►  │  ┌─────────────────────┐  │
  (mutual RA-TLS + manager JWT)        │  │   SecretPolicy      │  │
                                       │  │  ─────────────      │  │
  The remote TEE presents its          │  │  MRENCLAVE list     │  │
  own RA-TLS cert; the vault           │  │  MRTD list          │  │
  extracts the SGX/TDX quote           │  │  Manager pubkey     │  │
  and OID claims from the              │  │  OID requirements   │  │
  peer certificate.                    │  │  TTL                │  │
                                       │  └─────────────────────┘  │
                                       │             │             │
                                       │             ▼             │
                                       │  ┌─────────────────────┐  │
                                       │  │  enclave-os-kvstore │  │
                                       │  │  (sealed storage)   │  │
                                       │  └─────────────────────┘  │
                                       └───────────────────────────┘
```

The vault is designed to be deployed as **multiple instances** behind an
RA-TLS transport. A secret owner uses the
[vault client](../../../ra-tls-clients/README.md) to Shamir-split secrets and
distribute one share to each vault instance. TEE applications on **other
machines** retrieve shares using their attestation evidence (SGX, TDX, or
SEV-SNP quotes).

## Protocol

All requests arrive as JSON inside the enclave-os length-delimited framing
(`4-byte big-endian length || payload`).

| Request | Auth | Description |
|---------|------|-------------|
| `StoreSecret { jwt }` | ES256 JWT (owner key) | Store a secret with an access policy. The JWT payload contains the secret name, base64url-encoded value, and `SecretPolicy`. |
| `GetSecret { name, bearer_token? }` | Mutual RA-TLS + optional manager JWT | Retrieve a secret. Attestation evidence is extracted from the peer's RA-TLS client certificate (mutual TLS), not from the JSON body. |
| `DeleteSecret { jwt }` | ES256 JWT (owner key) | Remove a stored secret. |
| `UpdateSecretPolicy { jwt }` | ES256 JWT (owner key) | Replace the access policy for an existing secret. |

### Responses

| Response | Description |
|----------|-------------|
| `SecretStored { name, expires_at }` | Secret stored successfully. |
| `SecretValue { secret, expires_at }` | Secret value (the Shamir share bytes). |
| `SecretDeleted` | Secret removed. |
| `PolicyUpdated` | Policy replaced. |
| `Error(String)` | Human-readable error message. |

## Access Policy Model

Each secret carries a `SecretPolicy` that is evaluated on every `GetSecret`
request:

| Field | Type | Description |
|-------|------|-------------|
| `allowed_mrenclave` | `Vec<String>` | Hex-encoded SGX MRENCLAVE values permitted to read the secret. |
| `allowed_mrtd` | `Vec<String>` | Hex-encoded TDX MRTD values permitted to read the secret. |
| `manager_pubkey` | `Option<String>` | Hex-encoded uncompressed P-256 public key (65 bytes: `04 \|\| x \|\| y`) of the manager authorised to issue bearer tokens. When set, `GetSecret` requires a valid ES256 JWT signed by this key. |
| `required_oids` | `Vec<OidRequirement>` | OID/value pairs that must appear in the caller's RA-TLS certificate. |
| `ttl_seconds` | `u64` | Time-to-live. Capped at **90 days** (7 776 000 s); defaults to **30 days** (2 592 000 s) if zero. |

### Policy Evaluation

1. **Mutual RA-TLS** — the vault requires the caller to present a TLS client
   certificate.  The SGX/TDX quote and OID claims are extracted from the peer
   certificate's X.509 extensions.  If no peer certificate is present the
   request is rejected.

2. **Attestation identity** — the extracted quote is parsed and the measurement
   (`MRENCLAVE` for SGX v3 quotes, `MRTD` for TDX v4 quotes) is checked
   against the policy's whitelist.  At least one of `allowed_mrenclave` or
   `allowed_mrtd` must match.

3. **Bearer token (manager verification)** — if `manager_pubkey` is set, the
   request must include a bearer token that is a valid ES256 JWT signed by the
   manager's private key.  The JWT payload must contain
   `{ "name": "<secret-name>" }` matching the requested secret.  This provides
   defence-in-depth: even if remote attestation is compromised, the attacker
   still needs the manager to issue a fresh bearer token.

4. **OID claims** — each entry in `required_oids` must be present in the
   peer certificate's X.509 extensions with a matching value (case-insensitive).

5. **TTL** — expired secrets are rejected.

## Quote Parsing

The module parses raw DCAP attestation quotes to extract TEE measurements:

| Quote Version | TEE | Measurement | Offset | Size |
|---------------|-----|-------------|--------|------|
| 3 | SGX | `MRENCLAVE` | 112–144 | 32 bytes |
| 4 | TDX | `MRTD` | 184–232 | 48 bytes |

The version field is a little-endian `u16` at bytes 0–1. Unknown versions are
rejected. The parsed measurement is hex-encoded and compared against the
policy's whitelist (case-insensitive).

## Storage

Secrets are persisted using `enclave-os-kvstore`, which seals data with an
MRENCLAVE-bound key. Each secret is stored as a `SecretRecord` containing:

- The secret value (opaque bytes — typically a Shamir share)
- The `SecretPolicy`
- An `expires_at` Unix timestamp

## JWT Authentication

Write operations (`StoreSecret`, `DeleteSecret`, `UpdateSecretPolicy`) are
authenticated via **ES256** (ECDSA P-256 + SHA-256) JWTs in compact JWS format.
The **secret owner** — the entity that creates and manages the secret — signs
these JWTs with their P-256 private key.  The vault verifies the signature
using the owner's public key, which is configured at enclave startup and
stored (as a SHA-256 hash) in each `SecretRecord` so that only the original
creator can delete or update a secret's policy.

### Manager Bearer Tokens

The **manager** is a separate actor whose sole role is to provide bearer tokens
at `GetSecret` time as defence-in-depth against remote attestation compromise.
The manager cannot read, write, delete, or update policies — they only
authorise secret fetches.

When a secret's policy includes a `manager_pubkey`, the `GetSecret` caller must
provide a bearer token that is an ES256 JWT signed by the manager's private key.
The JWT payload is `{ "name": "<secret-name>" }`, binding the token to a
specific secret.

## Crate Dependencies

| Dependency | Purpose |
|------------|---------|
| `enclave-os-enclave` | Core enclave module trait (`EnclaveModule`) |
| `enclave-os-common` (jwt feature) | JWT verification (ES256) |
| `enclave-os-kvstore` | Sealed KV store (MRENCLAVE-bound) |
| `ring` 0.17 | Cryptographic primitives |
| `serde` / `serde_json` | JSON serialisation of requests, responses, and policies |
| `base64` 0.21 | Base64url decoding of secret payloads in JWTs |
| `x509-parser` 0.16 | X.509 certificate parsing (extract quote + OID claims from peer certs) |

## Source Files

| File | Description |
|------|-------------|
| [src/lib.rs](src/lib.rs) | `VaultModule` implementing `EnclaveModule` — request dispatch and handlers |
| [src/types.rs](src/types.rs) | Wire types (`VaultRequest`, `VaultResponse`, `SecretPolicy`, `SecretRecord`) |
| [src/quote.rs](src/quote.rs) | SGX v3 and TDX v4 quote parsing and policy matching |

## License

AGPL-3.0 — see [LICENSE](../../LICENSE).
