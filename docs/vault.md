# Vault — Policy-Gated Key Store (vHSM)

The vault module (`enclave-os-vault`) is an SGX-enclave-resident key store
shaped after PKCS#11 / KMIP. Callers manipulate **keys** with handles,
types, usage flags and per-key access policies — not opaque "secrets".

A vault enclave has **no policy of its own**: it is a verifiable,
tamper-proof SGX binary that faithfully enforces the per-key policy the
secret owner attached at `CreateKey` / `PutShare` time. Trust comes from
the attested enclave measurement; trust does not come from any role the
vault plays in a quorum, and there is no cross-vault coordination.

> **Trust boundary**
>
> The Enclave Vaults **registry** (`platform/enclave-vaults/registry`) is a
> phonebook: it returns `(endpoint, measurement)` tuples and nothing else.
> It never sees keys, shares, policies, pending profiles, approval tokens,
> or audit data, and is treated as untrusted by the client.
>
> The **client** (`platform/enclave-vaults-client`) does its own RA-TLS
> handshake to each vault and verifies each vault's attestation quote
> itself. All fan-out across the constellation — Shamir distribution,
> pending-profile staging, promotion, revocation, approval-token delivery
> — happens in the client.
>
> Each **vault** enforces only the per-key policy supplied at creation.

---

## 1. Object model

```text
KeyRecord
  handle:        stable string ("tenant42/master-kek")
  key_type:      KeyType              (RawShare | Aes256GcmKey | P256SigningKey | HmacSha256Key)
  exportable:    bool                  (gates ExportKey)
  public_key:    Option<Vec<u8>>       (for asymmetric keys, raw EC point)
  created_at, expires_at, policy_version
  policy:        KeyPolicy             (see section 3)
  pending_profiles: Vec<PendingProfile>  (for the enclave-upgrade flow)
  material:      sealed bytes          (KV value, AES-256-GCM under MRENCLAVE-bound key)
```

`KeyMaterial` is sealed at rest using `enclave-os-kvstore` (AES-256-GCM
under an MRENCLAVE-bound key). Public components (e.g. an EC point) are
stored alongside in unsealed metadata so `GetKeyInfo` does not need a
sealing round-trip.

### 1.1 Key types

| `KeyType` | Operations | Notes |
|---|---|---|
| `RawShare` | `ExportKey` | A Shamir share of an external secret. The client reconstructs after retrieving K-of-N shares. Default for legacy `PutShare`/`GetShare`. |
| `Aes256GcmKey` | `Wrap`, `Unwrap`, optional `ExportKey` | 32-byte AES-256 KEK / DEK. |
| `P256SigningKey` | `Sign`, optional `ExportKey` | PKCS#8 v1 ECDSA-P256 private key. Returns IEEE-P1363 fixed-length 64-byte signatures. |
| `HmacSha256Key` | `Mac`, optional `ExportKey` | 32-64 byte HMAC key. |

`exportable` is opt-in per key. Default for non-`RawShare` types is
**non-exportable**: the enclave performs the operation; the raw private
key never leaves. This matches HSM semantics and removes whole categories
of misuse.

---

## 2. Operations (RPCs)

All requests are JSON inside the enclave-os length-delimited frame
(`4-byte big-endian length || payload`). OIDC bearer tokens travel in
the JSON `"auth"` field; the auth layer strips them before the vault sees
the request.

### 2.1 Key management

| RPC | Auth | Description |
|---|---|---|
| `CreateKey { handle, key_type, material_b64, exportable, policy }` | OIDC: must equal `policy.principals.owner` | Create a key with caller-supplied material. |
| `ExportKey { handle, approvals? }` | per-key `Operation::ExportKey` rule | Returns raw material. Requires `exportable == true`. |
| `DeleteKey { handle, approvals? }` | per-key `Operation::DeleteKey` rule | Removes the key and all audit/pending state. |
| `UpdatePolicy { handle, new_policy, approvals? }` | per-field `Mutability` (see section 3.4) | Replace the policy. |
| `GetPolicy { handle }` | owner / auditor | Returns the current policy and `policy_version`. |
| `GetKeyInfo { handle }` | owner / auditor | Metadata only; never material. |
| `ListKeys` | OIDC | Lists handles whose owner is the caller. |

### 2.2 In-enclave crypto

| RPC | Key type | Output |
|---|---|---|
| `Wrap { handle, plaintext_b64, aad_b64?, iv_b64?, approvals? }` | `Aes256GcmKey` | `{ ciphertext, iv }` (vault generates 12-byte IV if absent) |
| `Unwrap { handle, ciphertext_b64, iv_b64, aad_b64?, approvals? }` | `Aes256GcmKey` | `{ plaintext }` |
| `Sign { handle, message_b64, approvals? }` | `P256SigningKey` | `{ signature, alg: "ECDSA-P256-SHA256" }` |
| `Mac { handle, message_b64, approvals? }` | `HmacSha256Key` | `{ mac, alg: "HMAC-SHA-256" }` |

### 2.3 Approvals

| RPC | Description |
|---|---|
| `IssueApprovalToken { handle, op, ttl_seconds }` | Caller must be one of `policy.principals.managers`. Returns a short-lived ES256 JWT signed by the vault. The token can be carried inside subsequent requests to satisfy `Condition::ManagerApproval`. TTL capped at one hour; default 5 minutes. |

### 2.4 Audit

| RPC | Description |
|---|---|
| `ReadAuditLog { handle, since_seq, limit }` | Owner or auditors. Returns sealed append-only entries with `(ts, op, caller, decision, reason, seq)`. |

Audit entries are stored under `audit:<handle>:<020d-seq>` in the sealed
KV. Every mutating or denied request appends one entry.

### 2.5 Pending attestation profiles (enclave upgrade)

| RPC | Description |
|---|---|
| `StagePendingProfile { handle, profile, source }` | Owner; or manager iff `mutability.manager_can` includes `PendingProfiles`. Stages a new `AttestationProfile` for later promotion. |
| `ListPendingProfiles { handle }` | Owner / auditor / managers. |
| `PromotePendingProfile { handle, pending_id, approvals? }` | Subject to `Mutability` for `PolicyField::Tees` — typically requires the configured threshold of fresh `ApprovalToken`s. Promotes the profile into `policy.principals.tees`. |
| `RevokePendingProfile { handle, pending_id }` | Owner / managers. Drops without promoting. |

---

## 3. Policy

### 3.1 `KeyPolicy`

```text
KeyPolicy {
    version:    u32,                       // currently 1
    principals: PrincipalSet,
    operations: Vec<OperationRule>,
    mutability: Mutability,
    lifecycle:  Lifecycle,
}

PrincipalSet {
    owner:    Principal,
    managers: Vec<Principal>,              // 0..n approvers (was manager_sub)
    auditors: Vec<Principal>,              // 0..n read-only on metadata + audit log
    tees:     Vec<Principal>,              // RA-TLS clients allowed at runtime
}
```

### 3.2 `Principal`

| Variant | Match | Use case |
|---|---|---|
| `Oidc { issuer, sub, required_roles }` | Caller's verified `OidcClaims.sub` matches AND every required role is present. | Owner / manager / auditor identities (humans, CI, service accounts). |
| `Tee(AttestationProfile)` | RA-TLS peer cert satisfies the profile (measurement + OIDs + bidirectional challenge). | Runtime callers — the running app TEE doing `Wrap` / `Unwrap` / `Sign` / `ExportKey` on its own share. |
| `Fido2 { rp_id, credential_id_b64 }` | (Schema-only in Phase 3; rejected at evaluation until the wallet relay path is wired up.) | Future: hardware-bound human approvals. |

Bidirectional RA-TLS challenge-response is **always** required for
`Principal::Tee` — there is no opt-out flag.

### 3.3 `OperationRule` and `Condition`

```text
OperationRule {
    ops:        Vec<Operation>,            // ExportKey | DeleteKey | UpdatePolicy
                                           // | Wrap | Unwrap | Sign | Mac | PromoteProfile
    principals: Vec<PrincipalRef>,         // Owner | Manager(i) | Auditor(i) | Tee(i) | AnyTee
    requires:   Vec<Condition>,            // AND-conjunctive; empty == no extra condition
}

Condition {
    AttestationMatches(AttestationProfile)
  | ManagerApproval { manager: u32, fresh_for_seconds: u64 }
  | TimeWindow { not_before: u64, not_after: u64 }
}
```

A request is allowed iff there is at least one rule whose `ops` contains
the requested op AND whose `principals` contains the caller's resolved
principal AND every condition in `requires` evaluates true.

`AttestationProfile` carries `name`, `measurements: Vec<Measurement>`
(`Mrenclave(hex)` or `Mrtd(hex)`), `attestation_servers` (URLs with
optional pinned-SPKI hash), and `required_oids`.

### 3.4 `Mutability` — who can change what on `UpdatePolicy`

```text
Mutability {
    owner_can:   Vec<PolicyField>,         // default: Managers, Auditors, Tees, Operations,
                                           //          Lifecycle, PendingProfiles
    manager_can: Vec<PolicyField>,         // default: empty
    immutable:   Vec<PolicyField>,         // default: Owner, Mutability
}
```

`UpdatePolicy` evaluation:

1. Compute the diff between `new_policy` and the stored policy.
2. For every touched `PolicyField`:
   - in `immutable` -> reject.
   - only in `manager_can` -> caller must authenticate as a manager AND
     carry the configured threshold of fresh `ApprovalToken`s.
   - in `owner_can` -> caller must authenticate as `principals.owner`.
3. Re-validate the new policy as a whole (e.g. you cannot remove the last
   rule that grants the operations the key needs).
4. On success, seal, increment `policy_version`, append an audit entry.

The default makes the owner field and the mutability rules themselves
immutable for the lifetime of the key. Adopters loosen this explicitly
when they want a manager to be able to (for example) add a new TEE
measurement to authorise an enclave upgrade.

### 3.5 `Lifecycle`

```text
Lifecycle {
    ttl_seconds: u64,                      // default 30 days, capped at 90 days
}
```

---

## 4. Approval tokens

`IssueApprovalToken { handle, op, ttl_seconds }` returns an `ApprovalToken
{ jwt }`. The JWT is ES256, signed by a vault-resident P-256 key created
on first use and sealed under `__vault_signing_key_pkcs8__`.

```text
ApprovalClaims {
    iss:     "enclave-os-vault",
    handle:  String,
    op:      Operation,
    manager: u32,                          // index into principals.managers
    iat:     u64,
    exp:     u64,
}
```

The vault that verifies a token is the same vault that issued it
(single-vault path) or one configured with the same signing key
(constellation-wide manager governance is a future deployment option;
today, approvals are vault-local).

`Condition::ManagerApproval { manager, fresh_for_seconds }` succeeds iff
the request carries an `ApprovalToken` whose claims match `(handle, op,
manager)` and whose age is within `fresh_for_seconds` at verification time.

---

## 5. Worked policy examples

### 5.1 "Running app TEE can `Unwrap` its own DEK"

```text
OperationRule {
  ops:        [Unwrap],
  principals: [Tee(0)],
  requires:   [],                          // RA-TLS already proved the measurement
}
```

with `principals.tees[0] = Principal::Tee(profile_v_n)`.

### 5.2 "Manager may add a new TEE for an enclave upgrade, owner cannot"

`Mutability::manager_can = [PolicyField::PendingProfiles, PolicyField::Tees]`
with one of:

```text
OperationRule {
  ops:        [PromoteProfile],
  principals: [Manager(0)],
  requires:   [ManagerApproval { manager: 1, fresh_for_seconds: 3600 }],
}
```

so promoting requires both managers (#0 issues the request, #1's fresh
token is attached).

### 5.3 "Auditor reads the audit log, nothing else"

No operation rule is needed: `ReadAuditLog` admits owner OR any auditor
by name; everything else falls through to the operation table.

### 5.4 "Two-of-three managers must co-sign an export"

```text
OperationRule {
  ops:        [ExportKey],
  principals: [Manager(0), Manager(1), Manager(2)],
  requires: [
    ManagerApproval { manager: 0, fresh_for_seconds: 3600 },
    ManagerApproval { manager: 1, fresh_for_seconds: 3600 },
  ],
}
```

The caller must be one of the three managers AND carry fresh tokens from
the two designated co-signers.

---

## 6. Enclave upgrade flow (vN -> v(N+1))

The vault enforces a strict separation: a platform-driven enclave upgrade
**never** automatically authorises the new MRENCLAVE to read a customer
key. The new measurement enters the policy only via the explicit pending
/ promote pair, gated by the policy's `Mutability` and `ManagerApproval`
rules.

```text
[v(N) running]
   |  developer builds v(N+1); MRENCLAVE captured
   v
[v(N+1) staged]   StagePendingProfile{ handle, profile=v(N+1), source }
   |              -> vault appends to KeyRecord.pending_profiles
   |              -> optional manager approvals collected (IssueApprovalToken)
   v
[v(N+1) live]     PromotePendingProfile{ handle, pending_id, approvals }
                  -> vault checks Mutability for PolicyField::Tees
                  -> pending profile becomes principals.tees[k]
                  -> policy_version incremented; audit entry written
                  -> v(N+1) presents its quote on RA-TLS and gets its share
```

The fan-out across the K-of-N constellation lives entirely in
`enclave-vaults-client`. Each vault evaluates its own per-key policy
against its own share, independently. Partial outcomes (e.g. 3 of 4
vaults accept the promote) are surfaced verbatim to the caller; the
client does not attempt to roll back, because each vault is the sole
authority over the share it holds.

---

## 7. Storage layout

| KV key | Value | Purpose |
|---|---|---|
| `key:<handle>` | sealed `KeyRecord` | The key, its policy, its sealed material. |
| `index:<owner_sub>` | JSON `Vec<String>` | Owner's handle list, used by `ListKeys`. |
| `audit:<handle>:<020d-seq>` | sealed `AuditEntry` | Append-only audit log. |
| `__vault_signing_key_pkcs8__` | sealed P-256 PKCS#8 | Vault's approval-token signer. |

KV keys are HMAC-SHA-256-encrypted on disk by `enclave-os-kvstore`, so
the host sees opaque blobs only — no prefix scans, no enumeration.

---

## 8. Authentication summary

| Caller | Transport | Identifies as | Typical operations |
|---|---|---|---|
| Service / TEE | mutual RA-TLS | `Principal::Tee` | `Wrap` / `Unwrap` / `Sign` / `Mac` / `ExportKey` on a `RawShare`. |
| Operator (CI, CLI, human) | OIDC bearer over TLS | `Principal::Oidc` | `CreateKey`, `UpdatePolicy`, `IssueApprovalToken`, `ReadAuditLog`, pending-profile staging. |
| Hardware-bound approver | OIDC + FIDO2 (Phase 4+) | `Principal::Fido2` | High-risk approvals; schema only today. |

Default OIDC role names (Privasys IdP; configurable per deployment):
`vault:owner`, `vault:manager`, `vault:auditor`. Adopters can point
`oidc_issuer_url` and `vault_*_role` at any OIDC provider.

---

## 9. Migration from the legacy `SecretRecord` API

The previous wire protocol (`StoreSecret` / `GetSecret` / etc.) is gone.
Adopters using the old shape need to:

1. Replace `StoreSecret` with `CreateKey { key_type: RawShare, exportable: true, ... }`.
2. Replace `GetSecret` (OIDC owner path) with `ExportKey`.
3. Replace `GetSecret` (RA-TLS path) with `ExportKey` carrying
   appropriate `principals.tees` + `OperationRule { ops: [ExportKey],
   principals: [AnyTee] }`.
4. Replace `manager_sub` with `principals.managers[i]` plus a
   `Condition::ManagerApproval` on the relevant operation rule (and use
   `IssueApprovalToken` to mint approvals at the call site).

This is a breaking change — there is no compatibility shim. Keeping the
TCB minimal is more important than a deprecation window for an API with
no production deployments.
# Vault â€” Policy-Gated Key Store (vHSM)

The vault module (`enclave-os-vault`) is an SGX-enclave-resident key store
shaped after PKCS#11 / KMIP. Callers manipulate **keys** with handles,
types, usage flags and per-key access policies â€” not opaque "secrets".

A vault enclave has **no policy of its own**: it is a verifiable,
tamper-proof SGX binary that faithfully enforces the per-key policy the
secret owner attached at `CreateKey` / `PutShare` time. Trust comes from
the attested enclave measurement; trust does not come from any role the
vault plays in a quorum, and there is no cross-vault coordination.

> **Trust boundary**
>
> The Enclave Vaults **registry** (`platform/enclave-vaults/registry`) is a
> phonebook: it returns `(endpoint, measurement)` tuples and nothing else.
> It never sees keys, shares, policies, pending profiles, approval tokens,
> or audit data, and is treated as untrusted by the client.
>
> The **client** (`platform/enclave-vaults-client`) does its own RA-TLS
> handshake to each vault and verifies each vault's attestation quote
> itself. All fan-out across the constellation â€” Shamir distribution,
> pending-profile staging, promotion, revocation, approval-token delivery
> â€” happens in the client.
>
> Each **vault** enforces only the per-key policy supplied at creation.

---

## 1. Object model

```text
KeyRecord
â”œâ”€â”€ handle:        stable string ("tenant42/master-kek")
â”œâ”€â”€ key_type:      KeyType            // RawShare | Aes256GcmKey | P256SigningKey | HmacSha256Key
â”œâ”€â”€ exportable:    bool                // gates ExportKey
â”œâ”€â”€ public_key:    Option<Vec<u8>>     // for asymmetric keys, raw EC point
â”œâ”€â”€ created_at, expires_at, policy_version
â”œâ”€â”€ policy:        KeyPolicy           // see Â§3
â”œâ”€â”€ pending_profiles: Vec<PendingProfile>   // for the enclave-upgrade flow
â””â”€â”€ material:      sealed bytes        // KV value, AES-256-GCM under MRENCLAVE-bound key
```

`KeyMaterial` is sealed at rest using `enclave-os-kvstore` (AES-256-GCM
under an MRENCLAVE-bound key). Public components (e.g. an EC point) are
stored alongside in unsealed metadata so `GetKeyInfo` does not need a
sealing round-trip.

### 1.1 Key types

| `KeyType` | Operations | Notes |
|---|---|---|
| `RawShare` | `ExportKey` | A Shamir share of an external secret. The client reconstructs after retrieving K-of-N shares. Default for legacy `PutShare`/`GetShare`. |
| `Aes256GcmKey` | `Wrap`, `Unwrap`, optional `ExportKey` | 32-byte AES-256 KEK / DEK. |
| `P256SigningKey` | `Sign`, optional `ExportKey` | PKCS#8 v1 ECDSA-P256 private key. Returns IEEE-P1363 fixed-length 64-byte signatures. |
| `HmacSha256Key` | `Mac`, optional `ExportKey` | 32â€“64-byte HMAC key. |

`exportable` is opt-in per key. Default for non-`RawShare` types is
**non-exportable**: the enclave performs the operation; the raw private
key never leaves. This matches HSM semantics and removes whole categories
of misuse.

---

## 2. Operations (RPCs)

All requests are JSON inside the enclave-os length-delimited frame
(`4-byte big-endian length || payload`). OIDC bearer tokens travel in
the JSON `"auth"` field; the auth layer strips them before the vault sees
the request.

### 2.1 Key management

| RPC | Auth | Description |
|---|---|---|
| `CreateKey { handle, key_type, material_b64, exportable, policy }` | OIDC: must equal `policy.principals.owner` | Create a key with caller-supplied material. |
| `ExportKey { handle, approvals? }` | per-key `Operation::ExportKey` rule | Returns raw material. Requires `exportable == true`. |
| `DeleteKey { handle, approvals? }` | per-key `Operation::DeleteKey` rule | Removes the key and all audit/pending state. |
| `UpdatePolicy { handle, new_policy, approvals? }` | per-field `Mutability` (see Â§3.4) | Replace the policy. |
| `GetPolicy { handle }` | owner / auditor | Returns the current policy and `policy_version`. |
| `GetKeyInfo { handle }` | owner / auditor | Metadata only; never material. |
| `ListKeys` | OIDC | Lists handles whose owner is the caller. |

### 2.2 In-enclave crypto

| RPC | Key type | Output |
|---|---|---|
| `Wrap { handle, plaintext_b64, aad_b64?, iv_b64?, approvals? }` | `Aes256GcmKey` | `{ ciphertext, iv }` (vault generates 12-byte IV if absent) |
| `Unwrap { handle, ciphertext_b64, iv_b64, aad_b64?, approvals? }` | `Aes256GcmKey` | `{ plaintext }` |
| `Sign { handle, message_b64, approvals? }` | `P256SigningKey` | `{ signature, alg: "ECDSA-P256-SHA256" }` |
| `Mac { handle, message_b64, approvals? }` | `HmacSha256Key` | `{ mac, alg: "HMAC-SHA-256" }` |

### 2.3 Approvals

| RPC | Description |
|---|---|
| `IssueApprovalToken { handle, op, ttl_seconds }` | Caller must be one of `policy.principals.managers`. Returns a short-lived ES256 JWT signed by the vault. The token can be carried inside subsequent requests to satisfy `Condition::ManagerApproval`. TTL capped at one hour; default 5 minutes. |

### 2.4 Audit

| RPC | Description |
|---|---|
| `ReadAuditLog { handle, since_seq, limit }` | Owner or auditors. Returns sealed append-only entries with `(ts, op, caller, decision, reason, seq)`. |

Audit entries are stored under `audit:<handle>:<020d-seq>` in the sealed
KV. Every mutating or denied request appends one entry.

### 2.5 Pending attestation profiles (enclave upgrade)

| RPC | Description |
|---|---|
| `StagePendingProfile { handle, profile, source }` | Owner; or manager iff `mutability.manager_can` includes `PendingProfiles`. Stages a new `AttestationProfile` for later promotion. |
| `ListPendingProfiles { handle }` | Owner / auditor / managers. |
| `PromotePendingProfile { handle, pending_id, approvals? }` | Subject to `Mutability` for `PolicyField::Tees` â€” typically requires the configured threshold of fresh `ApprovalToken`s. Promotes the profile into `policy.principals.tees`. |
| `RevokePendingProfile { handle, pending_id }` | Owner / managers. Drops without promoting. |

---

## 3. Policy

### 3.1 `KeyPolicy`

```text
KeyPolicy {
    version:    u32,                       // currently 1
    principals: PrincipalSet,
    operations: Vec<OperationRule>,
    mutability: Mutability,
    lifecycle:  Lifecycle,
}

PrincipalSet {
    owner:    Principal,
    managers: Vec<Principal>,              // 0..n approvers (was manager_sub)
    auditors: Vec<Principal>,              // 0..n read-only on metadata + audit log
    tees:     Vec<Principal>,              // RA-TLS clients allowed at runtime
}
```

### 3.2 `Principal`

| Variant | Match | Use case |
|---|---|---|
| `Oidc { issuer, sub, required_roles }` | Caller's verified `OidcClaims.sub` matches AND every required role is present. | Owner / manager / auditor identities (humans, CI, service accounts). |
| `Tee(AttestationProfile)` | RA-TLS peer cert satisfies the profile (measurement + OIDs + bidirectional challenge). | Runtime callers â€” the running app TEE doing `Wrap` / `Unwrap` / `Sign` / `ExportKey` on its own share. |
| `Fido2 { rp_id, credential_id_b64 }` | (Schema-only in Phase 3; rejected at evaluation until the wallet relay path is wired up.) | Future: hardware-bound human approvals. |

Bidirectional RA-TLS challenge-response is **always** required for
`Principal::Tee` â€” there is no opt-out flag.

### 3.3 `OperationRule` and `Condition`

```text
OperationRule {
    ops:        Vec<Operation>,            // ExportKey | DeleteKey | UpdatePolicy
                                           // | Wrap | Unwrap | Sign | Mac | PromoteProfile
    principals: Vec<PrincipalRef>,         // Owner | Manager(i) | Auditor(i) | Tee(i) | AnyTee
    requires:   Vec<Condition>,            // AND-conjunctive; empty == no extra condition
}

Condition {
    AttestationMatches(AttestationProfile)
  | ManagerApproval { manager: u32, fresh_for_seconds: u64 }
  | TimeWindow { not_before: u64, not_after: u64 }
}
```

A request is allowed iff there is at least one rule whose `ops` contains
the requested op AND whose `principals` contains the caller's resolved
principal AND every condition in `requires` evaluates true.

`AttestationProfile` carries `name`, `measurements: Vec<Measurement>`
(`Mrenclave(hex)` or `Mrtd(hex)`), `attestation_servers` (URLs with
optional pinned-SPKI hash), and `required_oids`.

### 3.4 `Mutability` â€” who can change what on `UpdatePolicy`

```text
Mutability {
    owner_can:   Vec<PolicyField>,         // default: Managers, Auditors, Tees, Operations,
                                           //          Lifecycle, PendingProfiles
    manager_can: Vec<PolicyField>,         // default: empty
    immutable:   Vec<PolicyField>,         // default: Owner, Mutability
}
```

`UpdatePolicy` evaluation:

1. Compute the diff between `new_policy` and the stored policy.
2. For every touched `PolicyField`:
   - in `immutable` â†’ reject.
   - only in `manager_can` â†’ caller must authenticate as a manager AND
     carry the configured threshold of fresh `ApprovalToken`s.
   - in `owner_can` â†’ caller must authenticate as `principals.owner`.
3. Re-validate the new policy as a whole (e.g. you cannot remove the last
   rule that grants the operations the key needs).
4. On success, seal, increment `policy_version`, append an audit entry.

The default makes the owner field and the mutability rules themselves
immutable for the lifetime of the key. Adopters loosen this explicitly
when they want a manager to be able to (for example) add a new TEE
measurement to authorise an enclave upgrade.

### 3.5 `Lifecycle`

```text
Lifecycle {
    ttl_seconds: u64,                      // default 30 days, capped at 90 days
}
```

---

## 4. Approval tokens

`IssueApprovalToken { handle, op, ttl_seconds }` returns an `ApprovalToken
{ jwt }`. The JWT is ES256, signed by a vault-resident P-256 key created
on first use and sealed under `__vault_signing_key_pkcs8__`.

```text
ApprovalClaims {
    iss:     "enclave-os-vault",
    handle:  String,
    op:      Operation,
    manager: u32,                          // index into principals.managers
    iat:     u64,
    exp:     u64,
}
```

The vault that verifies a token is the same vault that issued it
(single-vault path) or one configured with the same signing key
(constellation-wide manager governance is a future deployment option;
today, approvals are vault-local).

`Condition::ManagerApproval { manager, fresh_for_seconds }` succeeds iff
the request carries an `ApprovalToken` whose claims match (handle, op,
manager) and whose age is within `fresh_for_seconds` at verification time.

---

## 5. Worked policy examples

### 5.1 "Running app TEE can `Unwrap` its own DEK"

```text
OperationRule {
  ops:        [Unwrap],
  principals: [Tee(0)],
  requires:   [],                          // RA-TLS already proved the measurement
}
```

with `principals.tees[0] = Principal::Tee(profile_v_n)`.

### 5.2 "Manager may add a new TEE for an enclave upgrade, owner cannot"

`Mutability::manager_can = [PolicyField::PendingProfiles, PolicyField::Tees]`
with one of:

```text
OperationRule {
  ops:        [PromoteProfile],
  principals: [Manager(0)],
  requires:   [ManagerApproval { manager: 1, fresh_for_seconds: 3600 }],
}
```

so promoting requires both managers (#0 issues the request, #1's fresh
token is attached).

### 5.3 "Auditor reads the audit log, nothing else"

No operation rule is needed: `ReadAuditLog` admits owner OR any auditor
by name; everything else falls through to the operation table.

### 5.4 "Two-of-three managers must co-sign an export"

```text
OperationRule {
  ops:        [ExportKey],
  principals: [Manager(0), Manager(1), Manager(2)],
  requires: [
    ManagerApproval { manager: 0, fresh_for_seconds: 3600 },
    ManagerApproval { manager: 1, fresh_for_seconds: 3600 },
  ],
}
```

The caller must be one of the three managers AND carry fresh tokens from
the two designated co-signers.

---

## 6. Enclave upgrade flow (vN â†’ v(N+1))

The vault enforces a strict separation: a platform-driven enclave upgrade
**never** automatically authorises the new MRENCLAVE to read a customer
key. The new measurement enters the policy only via the explicit pending /
promote pair, gated by the policy's `Mutability` and `ManagerApproval`
rules.

```
[v(N) running]
   â”‚ developer builds v(N+1); MRENCLAVE captured
   â–¼
[v(N+1) staged]   StagePendingProfile{ handle, profile=v(N+1), source }
   â”‚              â†³ vault appends to KeyRecord.pending_profiles
   â”‚              â†³ optional manager approvals collected (IssueApprovalToken)
   â–¼
[v(N+1) live]     PromotePendingProfile{ handle, pending_id, approvals }
                  â†³ vault checks Mutability for PolicyField::Tees
                  â†³ pending profile becomes principals.tees[k]
                  â†³ policy_version incremented; audit entry written
                  â†³ v(N+1) presents its quote on RA-TLS and gets its share
```

The fan-out across the K-of-N constellation lives entirely in
`enclave-vaults-client`. Each vault evaluates its own per-key policy
against its own share, independently. Partial outcomes (e.g. 3 of 4
vaults accept the promote) are surfaced verbatim to the caller; the
client does not attempt to roll back, because each vault is the sole
authority over the share it holds.

---

## 7. Storage layout

| KV key | Value | Purpose |
|---|---|---|
| `key:<handle>` | sealed `KeyRecord` | The key, its policy, its sealed material. |
| `index:<owner_sub>` | JSON `Vec<String>` | Owner's handle list, used by `ListKeys`. |
| `audit:<handle>:<020d-seq>` | sealed `AuditEntry` | Append-only audit log. |
| `__vault_signing_key_pkcs8__` | sealed P-256 PKCS#8 | Vault's approval-token signer. |

KV keys are HMAC-SHA-256-encrypted on disk by `enclave-os-kvstore`, so
the host sees opaque blobs only â€” no prefix scans, no enumeration.

---

## 8. Authentication summary

| Caller | Transport | Identifies as | Typical operations |
|---|---|---|---|
| Service / TEE | mutual RA-TLS | `Principal::Tee` | `Wrap` / `Unwrap` / `Sign` / `Mac` / `ExportKey` on a `RawShare`. |
| Operator (CI, CLI, human) | OIDC bearer over TLS | `Principal::Oidc` | `CreateKey`, `UpdatePolicy`, `IssueApprovalToken`, `ReadAuditLog`, pending-profile staging. |
| Hardware-bound approver | OIDC + FIDO2 (Phase 4+) | `Principal::Fido2` | High-risk approvals; schema only today. |

OIDC role names (defaults in the Privasys IdP, configurable per
deployment): `vault:owner`, `vault:manager`, `vault:auditor`. Adopters
can point `oidc_issuer_url` and `secret_*_role` at any OIDC provider.

---

## 9. Migration from the legacy `SecretRecord` API

The previous wire protocol (`StoreSecret` / `GetSecret` / etc.) is gone.
Adopters using the old shape need to:

1. Replace `StoreSecret` with `CreateKey { key_type: RawShare, exportable: true, ... }`.
2. Replace `GetSecret` (OIDC owner path) with `ExportKey`.
3. Replace `GetSecret` (RA-TLS path) with `ExportKey` carrying
   appropriate `principals.tees` + `OperationRule { ops: [ExportKey],
   principals: [AnyTee] }`.
4. Replace `manager_sub` with `principals.managers[i]` plus a
   `Condition::ManagerApproval` on the relevant operation rule (and use
   `IssueApprovalToken` to mint approvals at the call site).

This is a breaking change â€” there is no compatibility shim. Keeping the
TCB minimal is more important than a deprecation window for an API with
no production deployments.
