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
| `Metrics` | Bearer | Monitoring+ | Enclave counters + WASM fuel metrics |
| `SetAttestationServers` | Bearer | Manager | Update attestation servers (URLs + tokens) |
| `Shutdown` | — | — | Graceful shutdown (internal) |

### WASM

| Operation | Auth | Role | Description |
|-----------|------|------|-------------|
| `wasm_load` | Bearer | Manager | Load a WASM component |
| `wasm_unload` | Bearer | Manager | Unload a WASM component |
| `wasm_call` | App-level or none | Per-function | Call an exported function |
| `wasm_list` | Bearer | Monitoring+ | List loaded WASM apps |

### Egress

The egress module provides outbound HTTPS from inside the enclave.  It
has no module-level management operations — attestation server management
is handled at the core level (see `SetAttestationServers` above).

### Vault

| Operation | Auth | Role | Description |
|-----------|------|------|-------------|
| `StoreSecret` | Bearer | Secret Owner | Store a named secret |
| `GetSecret` | Bearer **or** mutual RA-TLS | — | Retrieve a secret (dual-path) |
| `DeleteSecret` | Bearer | Secret Owner | Delete a secret |
| `UpdateSecretPolicy` | Bearer | Secret Owner | Update a secret's access policy |
| `ListSecrets` | Bearer | Secret Owner | List caller's secrets (metadata only) |

"Monitoring+" means the `privasys-platform:monitoring` role or any higher
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
| Manager | `privasys-platform:manager` | WASM load/unload |
| Monitoring | `privasys-platform:monitoring` | Readyz, Status, Metrics, WASM list |
| Secret Owner | `privasys-platform:secret-owner` | Vault store/delete/update/list/get (own) |
| Secret Manager | `privasys-platform:secret-manager` | Issue bearer tokens for RA-TLS GetSecret |

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
    "uptime_seconds": 86400,
    "wasm_app_metrics": [
      {
        "name": "my-app",
        "calls_total": 142,
        "fuel_consumed_total": 8523410,
        "errors_total": 3,
        "functions": [
          {
            "name": "process",
            "calls": 140,
            "fuel_consumed": 8500000,
            "errors": 1,
            "fuel_min": 50000,
            "fuel_max": 75000
          }
        ]
      }
    ]
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
| `wasm_app_metrics` | array | Per-app WASM fuel metrics (omitted when empty) |

**`wasm_app_metrics` fields:**

| WasmAppMetrics field | Type | Description |
|----------------------|------|-------------|
| `name` | string | App identifier |
| `calls_total` | i64 | Total successful + errored calls |
| `fuel_consumed_total` | i64 | Total fuel consumed across all calls |
| `errors_total` | i64 | Total calls that returned an error |
| `functions` | array | Per-function breakdown |

| WasmFunctionMetrics field | Type | Description |
|---------------------------|------|-------------|
| `name` | string | Exported function name |
| `calls` | i64 | Number of calls to this function |
| `fuel_consumed` | i64 | Total fuel consumed by this function |
| `errors` | i64 | Calls that returned an error |
| `fuel_min` | i64 | Minimum fuel consumed in a single call |
| `fuel_max` | i64 | Maximum fuel consumed in a single call |

Each `Metrics` call also persists the current fuel counters to the sealed
KV store (key `wasm:metrics:snapshot`).  On enclave restart, previously-
snapshotted metrics are automatically loaded and merged.

---

### SetAttestationServers

Update the attestation server list (URLs, optional bearer tokens, and
optional OIDC bootstrap configuration).
This is a **core** operation — it is handled at the same level as Readyz,
Status, and Metrics, not inside a module.

Changes take effect immediately: the attestation servers hash OID
(`1.3.6.1.4.1.65230.2.7`) in subsequent RA-TLS certificates will
reflect the new canonical URL list.

The enclave sends bearer tokens as `Authorization: Bearer <token>` when
verifying quotes against authenticated attestation servers.

**Role:** Manager

**Request:**

```json
{
  "auth": "eyJhbGciOiJSUzI1NiIs...",
  "SetAttestationServers": {
    "servers": [
      {
        "url": "https://as.privasys.org/",
        "oidc_bootstrap": {
          "issuer": "https://auth.privasys.org",
          "service_account_id": "363552322535555076",
          "project_id": "363481202289541124"
        }
      },
      { "url": "https://as.customer.com/", "token": "eyJhbGciOiJSUzI1NiIs..." }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Attestation server URL |
| `token` | string? | Pre-existing bearer token (optional, mutually exclusive with `oidc_bootstrap`) |
| `oidc_bootstrap` | object? | OIDC bootstrap config (optional, see below) |

**OIDC bootstrap** (`oidc_bootstrap`):

| Field | Type | Description |
|-------|------|-------------|
| `issuer` | string | OIDC issuer URL |
| `service_account_id` | string | Service account user ID on the OIDC provider |
| `project_id` | string? | OIDC project ID for audience-scoped tokens |

When `oidc_bootstrap` is present and the request includes an `auth` token
with `privasys-platform:manager` + `ORG_USER_MANAGER` roles, the enclave:

1. Generates an ECDSA P-256 keypair inside the enclave.
2. Registers the public key with the OIDC provider's key registration API
   (e.g. Zitadel `POST /v2/users/{service_account_id}/keys`) using the
   manager JWT.
3. Exchanges a signed JWT assertion (ES256, jwt-bearer grant) for an
   access token scoped to the project audience.
4. Stores the token and keypair — subsequent attestation calls use the
   token automatically, with lazy refresh at 75% of token lifetime.

**Response:**

```json
{
  "AttestationServersUpdated": {
    "server_count": 2,
    "hash": "a1b2c3d4..."
  }
}
```

| Field          | Type   | Description                                      |
|----------------|--------|--------------------------------------------------|
| `server_count` | int    | Number of attestation servers now configured      |
| `hash`         | string | Hex-encoded SHA-256 of the canonical URL list     |

**Startup configuration:**

Attestation servers can also be configured at startup via CLI flags.
When `--manager-token` is provided alongside `--oidc-service-account-id`,
the enclave runs OIDC bootstrap at startup for each attestation server.

```bash
./enclave-os-host \
  --attestation-servers https://as.privasys.org/verify \
  --oidc-issuer https://auth.privasys.org \
  --oidc-audience 363481202289541124 \
  --manager-token "eyJhbGciOiJSUzI1NiIs..." \
  --oidc-service-account-id 363552322535555076 \
  --oidc-project-id 363481202289541124
```

| CLI Flag | Description |
|----------|-------------|
| `--attestation-servers` | Comma-separated list of attestation server URLs |
| `--manager-token` | Manager JWT for OIDC bootstrap at startup |
| `--oidc-service-account-id` | Service account user ID for key registration |
| `--oidc-project-id` | (optional) OIDC project ID for audience-scoped tokens |
| `--oidc-issuer` | OIDC issuer URL |
| `--oidc-audience` | OIDC audience claim (project ID) |

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
    "encryption_key": "hex-encoded-32-byte-aes-key",
    "max_fuel": 20000000,
    "permissions": {
      "version": 1,
      "oidc": {
        "issuer": "https://auth.app-owner.com",
        "jwks_uri": "https://auth.app-owner.com/.well-known/jwks.json",
        "audience": "my-app"
      },
      "default_policy": "public",
      "functions": {
        "transfer": { "policy": "role", "roles": ["finance-admin"] },
        "admin/reset": { "policy": "role", "roles": ["super-admin"] }
      }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | App identifier |
| `bytes` | byte[] | yes | Raw WASM component bytecode |
| `hostname` | string | no | SNI hostname for per-app TLS certificate (defaults to `name`) |
| `encryption_key` | string | no | Hex-encoded 32-byte AES-256 key for per-app KV encryption. If omitted, a random key is generated inside the enclave via RDRAND |
| `max_fuel` | u64 | no | Maximum fuel budget per call. Defaults to 10 000 000 (~a few hundred ms of compute) |
| `permissions` | AppPermissions | no | Per-function access policy with app-developer OIDC. If omitted, all functions are public (no auth) |

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
    ],
    "permissions_hash": "e5f6a7b8...",
    "max_fuel": 20000000
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

Call an exported function on a loaded WASM component.

When the app has a `permissions` policy, access is controlled per-function
using the app developer's own OIDC provider and roles.  When the app has
no permissions, all functions are callable without authentication.

See [App Permissions](#app-permissions) for the full model.

**Request** (app with no permissions — public)

```json
{
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

**Request** (app with permissions — app-level auth)

```json
{
  "wasm_call": {
    "app": "my-app",
    "function": "transfer",
    "params": [
      { "type": "string", "value": "from-account" },
      { "type": "u64", "value": 1000 }
    ],
    "app_auth": "eyJhbGciOiJSUzI1NiIs..."
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
      ],
      "max_fuel": 10000000
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
| `permissions_hash` | string? | SHA-256 of the permissions JSON (hex), or absent if no permissions |
| `max_fuel` | u64 | Fuel budget per call for this app |



---

## App Permissions

WASM app developers can define per-function access control via a
`permissions` object supplied at load time.  This allows the app developer
to bring their own OIDC provider — the enclave verifies caller tokens
against the app's JWKS, not the platform's.

### Behaviour

| App has permissions? | Auth on `wasm_call` |
|---------------------|---------------------|
| No | **Public** — no authentication required |
| Yes | Enforced per-function using the app's OIDC provider |

### Permission Schema

```json
{
  "version": 1,
  "oidc": {
    "issuer": "https://auth.app-owner.com",
    "jwks_uri": "https://auth.app-owner.com/.well-known/jwks.json",
    "audience": "my-app",
    "roles_claim": "roles"
  },
  "default_policy": "public",
  "default_roles": [],
  "functions": {
    "get-balance": { "policy": "authenticated" },
    "transfer":    { "policy": "role", "roles": ["finance-admin"] },
    "admin/reset": { "policy": "role", "roles": ["super-admin"] },
    "public/info": { "policy": "public" }
  }
}
```

**Top-level fields**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | u32 | yes | Schema version (must be `1`) |
| `oidc` | AppOidcConfig | yes | App developer's OIDC provider |
| `default_policy` | string | no | Policy for unlisted functions: `"public"` (default), `"authenticated"`, or `"role"` |
| `default_roles` | string[] | no | Roles required when `default_policy` is `"role"` |
| `functions` | map | no | Per-function policy overrides |

**AppOidcConfig fields**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string | yes | OIDC issuer URL |
| `jwks_uri` | string | yes | JWKS endpoint for token signature verification |
| `audience` | string | yes | Expected `aud` claim in app user tokens |
| `roles_claim` | string | no | Claim path for roles (default: `"roles"`) |

**FunctionPermission fields**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy` | string | yes | `"public"`, `"authenticated"`, or `"role"` |
| `roles` | string[] | no | Required roles (when policy is `"role"`; caller needs at least one) |

### Policy types

| Policy | `app_auth` required? | Behaviour |
|--------|---------------------|-----------|
| `public` | No | Anyone can call, no token needed |
| `authenticated` | Yes | Valid token from the app's OIDC provider, any role |
| `role` | Yes | Valid token with at least one of the specified roles |

### Token delivery

The app-level token is passed in the `app_auth` field inside the
`wasm_call` object (not the top-level `"auth"` field, which is reserved
for the platform OIDC):

```json
{
  "wasm_call": {
    "app": "my-app",
    "function": "transfer",
    "params": [...],
    "app_auth": "eyJhbGciOiJSUzI1NiIs..."
  }
}
```

### Attestation

The SHA-256 hash of the permissions JSON is included in the per-app
RA-TLS certificate as OID `1.3.6.1.4.1.65230.3.5` (App Permissions
Hash).  Clients connecting via the app's SNI hostname can verify exactly
which permission policy is active — without trusting the host.

| Per-app OID | Value |
|-------------|-------|
| `3.2` | Code hash (WASM bytecode SHA-256) |
| `3.4` | Key source (`"generated"` or `"byok:<fingerprint>"`) |
| `3.5` | Permissions hash (SHA-256 of permissions JSON) |

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
