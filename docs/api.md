# API Reference

The enclave-os-mini API is exposed over RA-TLS using a binary
length-delimited frame protocol.  Every request and response is a JSON
payload wrapped in a 4-byte big-endian length prefix:

```
[4 bytes: payload length (BE u32)] [JSON payload]
```

Maximum frame size: 16 MiB.

All operations except `Healthz` require an OIDC bearer token when OIDC is
configured.  The token is passed inside the JSON envelope as an `"auth"`
field (not an HTTP header — enclave-os-mini does not use HTTP).

See [vault.md](vault.md) for vault-specific details and
[wasm-runtime.md](wasm-runtime.md) for WASM runtime details.

---

## Operations Summary

### Core

| Operation | Auth | Role | Description |
|-----------|------|------|-------------|
| `Healthz` | None | — | Liveness probe |
| `Readyz` | Bearer | Monitoring+ | Readiness probe |
| `Status` | Bearer | Monitoring+ | Per-module status |
| `Metrics` | Bearer | Monitoring+ | Enclave counters |
| `Shutdown` | — | — | Graceful shutdown (internal) |

### WASM

| Operation | Auth | Role | Description |
|-----------|------|------|-------------|
| `wasm_load` | Bearer | Manager | Load a WASM component |
| `wasm_unload` | Bearer | Manager | Unload a WASM component |
| `wasm_call` | Bearer | Any authenticated | Call an exported function |
| `wasm_list` | Bearer | Monitoring+ | List loaded WASM apps |

### Vault

| Operation | Auth | Role | Description |
|-----------|------|------|-------------|
| `StoreSecret` | Bearer | Secret Owner | Store a named secret |
| `GetSecret` | Bearer **or** mutual RA-TLS | — | Retrieve a secret (dual-path) |
| `DeleteSecret` | Bearer | Secret Owner | Delete a secret |
| `UpdateSecretPolicy` | Bearer | Secret Owner | Update a secret's access policy |
| `ListSecrets` | Bearer | Secret Owner | List caller's secrets (metadata only) |

"Monitoring+" means the `enclave-os-mini:monitoring` role or any higher
role (manager implies monitoring).

---

## Authentication

### OIDC Bearer Token

When OIDC is configured, the bearer token is passed in the `"auth"` field
of the JSON envelope.  The auth layer strips `"auth"` before dispatching
to the module.

```json
{
  "auth": "eyJhbGciOiJSUzI1NiIs...",
  "Readyz": null
}
```

### Roles

| Role | Claim value | Scope |
|------|------------|-------|
| Manager | `enclave-os-mini:manager` | WASM load/unload |
| Monitoring | `enclave-os-mini:monitoring` | Readyz, Status, Metrics, WASM list |
| Secret Owner | `enclave-os-mini:secret-owner` | Vault store/delete/update/list/get (own) |
| Secret Manager | `enclave-os-mini:secret-manager` | Issue bearer tokens for RA-TLS GetSecret |

Role claims are extracted from (checked in order):
1. `urn:zitadel:iam:org:project:roles` (Zitadel map format)
2. `roles` (string array)
3. `realm_access.roles` (Keycloak format)

---

## Core Operations

### Healthz

Liveness probe.  Always succeeds, no authentication required.

**Request**

```json
"Healthz"
```

**Response**

```json
{ "Healthz": { "status": "ok" } }
```

---

### Readyz

Readiness probe.  Returns whether modules are registered and the enclave
is ready to serve.

**Request**

```json
{ "auth": "<token>", "Readyz": null }
```

**Response** (ready)

```json
{ "Readyz": { "status": "ready", "modules": 3 } }
```

**Response** (not ready)

```json
{ "Readyz": { "status": "not_ready", "modules": 0 } }
```

---

### Status

Returns the status of all registered modules.

**Request**

```json
{ "auth": "<token>", "Status": null }
```

**Response**

```json
{
  "StatusReport": [
    { "name": "kvstore", "details": {} },
    { "name": "wasm", "details": {} },
    { "name": "vault", "details": {} }
  ]
}
```

---

### Metrics

Returns enclave-level counters.

**Request**

```json
{ "auth": "<token>", "Metrics": null }
```

**Response**

```json
{
  "MetricsReport": {
    "connections_total": 142,
    "frames_total": 1024,
    "wasm_calls_total": 87,
    "secrets_stored_total": 12,
    "secrets_retrieved_total": 5,
    "attestation_verifications_total": 23,
    "uptime_seconds": 86400
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `connections_total` | u64 | Total TLS connections served |
| `frames_total` | u64 | Total application frames processed |
| `wasm_calls_total` | u64 | Total WASM calls executed |
| `secrets_stored_total` | u64 | Total secrets stored |
| `secrets_retrieved_total` | u64 | Total secrets retrieved |
| `attestation_verifications_total` | u64 | Total attestation verifications |
| `uptime_seconds` | u64 | Enclave uptime in seconds |

---

## WASM Operations

WASM operations are carried inside `Data` frames.  The JSON payload is a
`WasmEnvelope` with exactly one field set.

### wasm_load

Load (or replace) a WASM component.  Requires **Manager** role.

**Request**

```json
{
  "auth": "<token>",
  "wasm_load": {
    "name": "my-app",
    "bytes": [0, 97, 115, 109, ...],
    "hostname": "my-app.example.com",
    "encryption_key": "hex-encoded-32-byte-aes-key"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | App identifier |
| `bytes` | byte[] | yes | Raw WASM component bytecode |
| `hostname` | string | no | SNI hostname for per-app TLS certificate (defaults to `name`) |
| `encryption_key` | string | no | Hex-encoded 32-byte AES-256 key for per-app KV encryption. If omitted, a random key is generated inside the enclave via RDRAND |

**Response** (success)

```json
{
  "status": "loaded",
  "app": {
    "name": "my-app",
    "hostname": "my-app.example.com",
    "code_hash": "a1b2c3d4...",
    "key_source": "generated",
    "exports": [
      { "name": "process", "param_count": 1, "result_count": 1 }
    ]
  }
}
```

**Response** (error)

```json
{ "status": "error", "message": "description" }
```

---

### wasm_unload

Unload a WASM component by name.  Requires **Manager** role.

**Request**

```json
{
  "auth": "<token>",
  "wasm_unload": { "name": "my-app" }
}
```

**Response** (success)

```json
{ "status": "unloaded", "name": "my-app" }
```

**Response** (not found)

```json
{ "status": "not_found", "name": "my-app" }
```

---

### wasm_call

Call an exported function on a loaded WASM component.  Requires a valid
OIDC token (any authenticated user) — no specific role needed.

**Request**

```json
{
  "auth": "<token>",
  "wasm_call": {
    "app": "my-app",
    "function": "process",
    "params": [
      { "type": "string", "value": "hello" },
      { "type": "u32", "value": 42 }
    ]
  }
}
```

**Parameter types**: `bool`, `s32`, `s64`, `u32`, `u64`, `f32`, `f64`,
`string`, `bytes`.

**Response** (success)

```json
{
  "status": "ok",
  "returns": [
    { "type": "string", "value": "processed: hello" }
  ]
}
```

**Response** (error)

```json
{ "status": "error", "message": "function not found: process" }
```

---

### wasm_list

List all loaded WASM components.  Requires **Monitoring+** role.

**Request**

```json
{
  "auth": "<token>",
  "wasm_list": {}
}
```

**Response**

```json
{
  "status": "apps",
  "apps": [
    {
      "name": "my-app",
      "hostname": "my-app.example.com",
      "code_hash": "a1b2c3d4...",
      "key_source": "byok:e5f6a7b8...",
      "exports": [
        { "name": "process", "param_count": 1, "result_count": 1 },
        { "name": "init", "param_count": 0, "result_count": 0 }
      ]
    }
  ]
}
```

| AppInfo field | Type | Description |
|---------------|------|-------------|
| `name` | string | App identifier |
| `hostname` | string | SNI hostname for per-app TLS certificate |
| `code_hash` | string | SHA-256 of WASM component bytecode (hex) |
| `key_source` | string | `"generated"` or `"byok:<fingerprint>"` |
| `exports` | array | Discovered exported function signatures |

---

## Vault Operations

Vault operations are carried inside `Data` frames.  The JSON payload is a
`VaultRequest` enum variant.  See [vault.md](vault.md) for the full access
policy model and dual-path authentication details.

### StoreSecret

Store a named secret with an access policy.  Requires **Secret Owner**
role.

**Request**

```json
{
  "auth": "<token>",
  "StoreSecret": {
    "name": "customer-123-dek",
    "secret": "base64url-encoded-bytes",
    "policy": {
      "allowed_mrenclave": ["abcd1234..."],
      "allowed_mrtd": [],
      "manager_sub": "manager-oidc-subject",
      "required_oids": [],
      "ttl_seconds": 604800
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable secret name |
| `secret` | string | yes | Base64url-encoded secret bytes |
| `policy` | SecretPolicy | yes | Access policy (see below) |

**SecretPolicy fields**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_mrenclave` | string[] | `[]` | SGX MRENCLAVE values (hex) permitted to retrieve |
| `allowed_mrtd` | string[] | `[]` | TDX MRTD values (hex) permitted to retrieve |
| `manager_sub` | string? | `null` | OIDC `sub` of the secret manager (defence-in-depth) |
| `required_oids` | OidRequirement[] | `[]` | OID/value pairs the caller's RA-TLS cert must contain |
| `ttl_seconds` | u64 | 30 days | Time-to-live (capped at 90 days) |

**Response**

```json
{ "SecretStored": { "name": "customer-123-dek", "expires_at": 1741564800 } }
```

---

### GetSecret

Retrieve a secret.  Supports two authentication paths:

**Path 1 — OIDC owner**: the caller's OIDC `sub` matches the stored
`owner_sub`.  No RA-TLS required.

**Path 2 — Mutual RA-TLS TEE**: the caller presents an RA-TLS client
certificate.  The vault extracts attestation from the peer cert and
evaluates it against the secret's policy.  Optionally requires a bearer
token from the secret manager.

**Request** (OIDC owner path)

```json
{
  "auth": "<owner-oidc-token>",
  "GetSecret": { "name": "customer-123-dek" }
}
```

**Request** (RA-TLS TEE path, with manager bearer token)

```json
{
  "GetSecret": {
    "name": "customer-123-dek",
    "bearer_token": [101, 121, 74, ...]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Secret name |
| `bearer_token` | byte[] | no | OIDC bearer token from the secret manager (required if policy has `manager_sub`) |

**Response**

```json
{
  "SecretValue": {
    "secret": [72, 101, 108, 108, 111],
    "expires_at": 1741564800
  }
}
```

**Error responses**

| Condition | Error message |
|-----------|---------------|
| No auth provided | `"authentication required: provide OIDC token or mutual RA-TLS client certificate"` |
| Secret not found | `"secret not found"` |
| Secret expired | `"secret has expired"` |
| Measurement mismatch | `"measurement not permitted by policy"` |
| Missing bearer token | `"bearer token required (manager_sub set in policy)"` |
| Bearer sub mismatch | `"bearer token sub '...' != policy manager_sub"` |
| OID not satisfied | `"required OID ... not satisfied"` |

---

### DeleteSecret

Delete a secret.  Only the original OIDC owner can delete.  Requires
**Secret Owner** role.

**Request**

```json
{
  "auth": "<token>",
  "DeleteSecret": { "name": "customer-123-dek" }
}
```

**Response**

```json
"SecretDeleted"
```

---

### UpdateSecretPolicy

Update the access policy for an existing secret.  Only the original OIDC
owner can update.  Requires **Secret Owner** role.

**Request**

```json
{
  "auth": "<token>",
  "UpdateSecretPolicy": {
    "name": "customer-123-dek",
    "policy": {
      "allowed_mrenclave": ["abcd1234...", "ef567890..."],
      "allowed_mrtd": [],
      "manager_sub": null,
      "required_oids": [
        { "oid": "1.3.6.1.4.1.65230.2.1", "value": "a1b2c3..." }
      ],
      "ttl_seconds": 2592000
    }
  }
}
```

**Response**

```json
"PolicyUpdated"
```

---

### ListSecrets

List all secrets owned by the caller (metadata only, never the secret
values).  Requires **Secret Owner** role.

**Request**

```json
{
  "auth": "<token>",
  "ListSecrets": null
}
```

**Response**

```json
{
  "SecretList": {
    "secrets": [
      { "name": "customer-123-dek", "expires_at": 1741564800 },
      { "name": "signing-key", "expires_at": 1742169600 }
    ]
  }
}
```

---

## Error Format

All error responses use one of two formats depending on the layer:

**Protocol-level errors** (auth failures, unknown requests):

```json
{ "Error": [98, 97, 100, 32, ...] }
```

The `Error` variant contains a UTF-8 byte array with a human-readable
message.

**Module-level errors** (vault, WASM):

```json
{ "Error": "description of the problem" }
```

or

```json
{ "status": "error", "message": "description" }
```

The format depends on the module: vault uses `VaultResponse::Error(String)`,
WASM uses `WasmManagementResult::Error { message }` or
`WasmResult::Error { message }`.
