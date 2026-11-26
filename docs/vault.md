# Vault: Policy-Gated Key Store (vHSM)

The vault module (`enclave-os-vault`) is an SGX-enclave-resident key store shaped after PKCS#11 / KMIP. Callers manipulate **keys** with handles, types, an exportable flag and per-key access policies, not opaque "secrets".

A vault enclave has **no policy of its own**: it is a verifiable, tamper-proof SGX binary that faithfully enforces the per-key policy the key's owner attached when the key was created. Trust comes from the attested enclave measurement; trust does not come from any role the vault plays in a quorum, and the vaults never call each other.

> **Trust boundary**
>
> The **vault directory** (the control plane's list of constellations and their member vaults) is a phonebook: it returns `(endpoint, measurement)` tuples and nothing else. It never sees keys, shares, policies, pending profiles, approvals or audit data, and the client treats it as untrusted.
>
> The **client** ([enclave-vaults-client](https://github.com/Privasys/enclave-vaults-client)) does its own RA-TLS handshake to each vault and verifies each vault's attestation quote itself. All fan-out across the constellation happens in the client: Shamir distribution, threshold-key rounds, pending-profile staging, promotion, revocation, renewals and approval delivery.
>
> Each **vault** enforces only the per-key policy supplied at creation, as later changed through the policy's own rules.

The exact formats of vault identity, approvals, policy digests, renewals and tombstones are in [vault-wire-formats.md](vault-wire-formats.md).

---

## 1. Object model

```text
KeyRecord
  handle:        stable string ("tenant42/master-kek")
  key_type:      KeyType              (RawShare | Aes256GcmKey | P256SigningKey | HmacSha256Key | FrostEd25519)
  exportable:    bool                  (gates ExportKey)
  public_key:    Option<Vec<u8>>       (for asymmetric keys: raw EC point, or the Ed25519 group key)
  created_at, expires_at, policy_version
  policy:        KeyPolicy             (see section 3)
  pending_profiles: Vec<PendingProfile>  (for the enclave-upgrade flow, at most 16)
  threshold_vaults: Vec<String>        (threshold keys: participant i at index i - 1)
  key_check:     Option<KeyCheck>      (key check value of the whole key, never returned)
  renewed_in_place_from: Option<String> (set by the vault on a renewal in place, section 7)
  created_by_owner_approval: bool      (set by the vault for a re-created name, section 8.3)
  pending_creation: Option<...>        (a threshold key not yet used, section 2.6)
  material:      sealed bytes          (KV value, AES-256-GCM under MRENCLAVE-bound key)
```

`KeyMaterial` is sealed at rest using `enclave-os-kvstore` (AES-256-GCM under an MRENCLAVE-bound key). Public components (for example an EC point) are kept in the record so `GetKeyInfo` returns them without exposing material.

### 1.1 Key types

| `KeyType` | Operations | Notes |
|---|---|---|
| `RawShare` | `ExportKey` | A Shamir share of an external secret. The client reconstructs after retrieving K-of-N shares. |
| `Aes256GcmKey` | `Wrap`, `Unwrap`, optional `ExportKey` | 32-byte AES-256 KEK / DEK. The vault always generates the 12-byte IV and refuses a caller-supplied one. |
| `P256SigningKey` | `Sign`, optional `ExportKey` | PKCS#8 v1 ECDSA-P256 private key. Returns IEEE-P1363 fixed-length 64-byte signatures, over a message the vault hashes or over a 32-byte SHA-256 digest (`prehashed`). |
| `HmacSha256Key` | `Mac`, optional `ExportKey` | 32-64 byte HMAC key. |
| `FrostEd25519` | threshold signing and resharing (section 2.6) | One vault's share of a threshold Ed25519 key (FROST(Ed25519, SHA-512), RFC 9591, crate `enclave-os-frost`). Created by distributed key generation; never exportable. |

`exportable` is a per-key flag set at creation. Keys are non-exportable unless the creation grant says otherwise: the enclave performs the operation and the raw private key stays inside it. This matches HSM semantics and removes whole categories of misuse. A threshold key is always non-exportable.

### 1.2 Key lifetime

Every key expires. `lifecycle.ttl_seconds` sets its lifetime from creation: the default is 30 days (2,592,000 s, also used when the field is 0) and the maximum is 90 days (7,776,000 s); a longer value is capped at the maximum. An expired key serves no operation. A key lives on past its expiry only by renewal (section 7), which creates the next generation under the same policy.

---

## 2. Operations (RPCs)

All requests are JSON inside the enclave-os length-delimited frame (`4-byte big-endian length || payload`). OIDC bearer tokens travel in the JSON `"auth"` field; the auth layer verifies them and strips them before the vault sees the request.

Any caller that is not a principal of a key gets the same answer, `caller is not in policy.principals`, for a live key and a deleted one, before any check of expiry, type or exportability.

### 2.1 Key management

| RPC | Auth | Description |
|---|---|---|
| `CreateKey { handle, material_b64, grant, predecessor?, policy?, policy_version?, source_billing_id?, key_check?, carried_exportable?, carried_key_type?, binding? }` | IdP-issued grant bound to the caller (see below) | Create a key in a single call. The grant carries the owner, scope, key type, exportable flag and full policy; the caller supplies the material. The optional fields create a renewal (section 7) or a re-created name (section 8.3). Returns `KeyCreated { handle, expires_at }`. |
| `ExportKey { handle, approvals?, binding? }` | per-key `ExportKey` rule | Returns raw material. Requires `exportable == true`. |
| `DeleteKey { handle, approvals?, binding?, after? }` | per-key `DeleteKey` rule | Deletes the key's material and record and leaves a tombstone (section 8). With `after`, the delete is bound to a successor (`delete_after`, section 7.3). |
| `RetireKey { handle, successor, successor_members }` | an enclave the key's policy names | Deletes the previous generation after a renewal in place, with no approval (section 7.2). Returns `KeyRetired { was_present }`. |
| `UpdatePolicy { handle, new_policy, approvals?, binding? }` | per-key `UpdatePolicy` rule and per-field `Mutability` (section 3.4) | Replace the policy. `new_policy` is kept as sent; a binding v2 approval covers the digest of exactly this JSON (section 5). |
| `GetPolicy { handle }` | key principals | Returns the current policy, in the vault's stored form, and `policy_version`. |
| `GetKeyInfo { handle }` | key principals | Metadata only; never material. Reports `threshold`, `renewed_in_place_from` and `created_by_owner_approval` where set. On a deleted key, returns its tombstone (section 8). |
| `ListKeys` | OIDC | Lists live handles whose owner is the caller. |
| `GetVaultIdentity` | none | This vault's member id, member key, billing id, MRENCLAVE, a quote binding them, and its capabilities (section 6). |
| `CanonicalisePolicy { policy }` | none | Checks a policy against the canonical rules of section 5.1 and returns `CanonicalPolicy { policy, pd }`: the policy in the vault's stored form and its digest. Stores nothing. |

**Grant-based create.** A caller that holds the material but is not the owner (an app TEE, or a CLI agent acting for a user) creates a key in one call by presenting an IdP-issued **key-creation grant** (a JWT, `aud = privasys-vault-keycreate`). The grant carries the owner, the scope, the key type, the exportable flag and the full policy; the vault verifies it against the IdP JWKS and binds it to the caller. Either a holder-of-key `cnf` (`x5t#S256`) matches the caller's leaf, whose private key the caller proved by signing the handshake; or the caller is a TEE that the grant's own policy names, proven by evidence presented on the connection for its leaf key, and its app-id (OID 3.6) equals the scope's. The handle must fall under the grant's scope, must not start with `__`, and the policy's owner must equal the grant subject. A first creation's policy must ask for approvals (section 4). This is the basis of the developer-platform key flow: the platform authors the owner-bound policy and mints the grant; the key materialises inside the app enclave, which never has to be the owner.

### 2.2 In-enclave crypto

| RPC | Key type | Output |
|---|---|---|
| `Wrap { handle, plaintext_b64, aad_b64?, approvals? }` | `Aes256GcmKey` | `{ ciphertext, iv }` (the vault generates the 12-byte IV; a request carrying `iv_b64` is refused, so a nonce is never reused) |
| `Unwrap { handle, ciphertext_b64, iv_b64, aad_b64?, approvals? }` | `Aes256GcmKey` | `{ plaintext }` |
| `Sign { handle, message_b64, prehashed?, approvals? }` | `P256SigningKey` | `{ signature, alg: "ECDSA-P256-SHA256" }`; with `prehashed`, `message_b64` is a 32-byte SHA-256 digest signed directly |
| `Mac { handle, message_b64, approvals? }` | `HmacSha256Key` | `{ mac, alg: "HMAC-SHA-256" }` |

### 2.3 Manager approval tokens

| RPC | Description |
|---|---|
| `IssueApprovalToken { handle, op, ttl_seconds }` | Caller must match one of `policy.principals.managers`. Returns a short-lived ES256 JWT signed by the vault. The token can be carried inside subsequent requests to satisfy `Condition::ManagerApproval`. TTL capped at one hour; default 5 minutes. |

Owner approvals from a wallet are passkey step-ups, carried in the bearer itself (section 5); they need no RPC of their own.

### 2.4 Audit

| RPC | Description |
|---|---|
| `ReadAuditLog { handle, since_seq, limit }` | Owner or auditors. Returns sealed append-only entries with `(ts, op, caller, decision, reason, seq)`. Works on a deleted key until its tombstone is purged. |

Audit entries are stored under `audit:<handle>:<020d-seq>` in the sealed KV. Every mutating or denied request appends one entry. A strict tightening of the approval rules is recorded as `TightenApprovals`, naming the rules that changed.

### 2.5 Pending attestation profiles (enclave upgrade)

| RPC | Description |
|---|---|
| `StagePendingProfile { handle, profile, source }` | Owner; or manager iff `mutability.manager_can` includes `PendingProfiles`; or the platform's manager-role bearer, unless `PendingProfiles` is immutable on the key. Stages a new `AttestationProfile` for later promotion. Staging authorises nothing. |
| `ListPendingProfiles { handle }` | Key principals. |
| `PromotePendingProfile { handle, pending_id, approvals?, binding? }` | Subject to the key's `PromoteProfile` rule and to `Mutability` for `PolicyField::Tees`. Promotes the profile into `policy.principals.tees`. |
| `RevokePendingProfile { handle, pending_id }` | Owner / managers. Drops without promoting. |

### 2.6 Threshold Ed25519 keys (FROST)

A threshold key (`FrostEd25519`) is generated by the vaults together and used by a threshold `t` of them together: no vault, and not the client, ever holds the whole key, and the signature verifies under one ordinary Ed25519 public key.

The client drives every round across the constellation, calling each vault directly with its own credentials and relaying opaque messages between them; the vaults never call each other. Each vault's first message carries an SGX quote over the round binding, and every vault verifies the others' quotes against this enclave's own MRENCLAVE before encrypting anything for them (a DEBUG enclave is refused). Sessions belong to their caller (OIDC subject and client certificate), a caller holds at most 16 at once on a vault, and a session ends on any failed round. Signing nonces live in enclave memory only and are single-use. Bytes travel as base64url without padding.

| RPC | Description |
|---|---|
| `FrostDkgRound1` / `FrostDkgRound2` / `FrostDkgRound3` / `FrostDkgCommit` | Distributed key generation under a key-creation grant (`key_type = FrostEd25519`, `exportable = false`), bound to the caller as for `CreateKey`: round 1 packages plus an X25519 key, round 2 packages sealed (AES-GCM) to each peer, round 3 HMAC confirmations, then commit. The context binds the participant list and the threshold. Round 1 takes `binding` for a re-created name (section 8.3). |
| `FrostSignRound1` / `FrostSignRound2` / `FrostAggregate` | Signing: commitments (the policy's `Sign` rule is checked and audited here), signature shares over the message the vault kept, aggregation into one EdDSA signature verified under the group key (key principals only). |
| `FrostReshareTarget1` / `FrostReshareDeal` / `FrostReshareTarget2` / `FrostReshareCommit` | Resharing (renewal or move to other vaults, same handle and same public key; the threshold may change): the target vaults quote their key and the policy, each helper deals λᵢ·sᵢ with a Feldman VSS sealed to the target, the targets verify and sum, then confirm. A helper deals only to the key's owner, under a passkey step-up fresh within 300 s and bound (binding v1, section 5.4) to the resharing context in the measurement slot: handle, group key, helpers, threshold, target vaults and target MRENCLAVE. |
| `FrostReshareFinalize` / `FrostReshareRollback` | Owner. A renewal in place keeps the previous share as `prev:<handle>` until finalize; rollback restores it. A new resharing of the key waits until the previous one is finalized or rolled back. |
| `FrostDkgAbort { session, handle? }` / `FrostReshareAbort { session, handle? }` / `FrostSignAbort { session }` | End a session. With `handle`, also remove the key that session committed on this vault while it is still pending (see below). |

**Pending threshold keys.** A key committed by a DKG or resharing session is pending until it first serves an operation (a signing round, a crypto operation, or a deal of a resharing). While pending, and within 300 s of its commit, the same session and the same caller may abort it with `FrostDkgAbort` / `FrostReshareAbort` and its `handle`. The abort leaves no tombstone, since the key never served anything, and is recorded in the handle's audit log as `AbortPendingKey`; a later creation of the handle continues that log. Once a key has served, it is removed only by `DeleteKey`.

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
    approval:   Option<String>,            // "none" opts out of approval by default (section 4)
}

PrincipalSet {
    owner:    Principal,
    managers: Vec<Principal>,              // 0..n approvers
    auditors: Vec<Principal>,              // 0..n read-only on metadata + audit log
    tees:     Vec<Principal>,              // RA-TLS clients allowed at runtime
}
```

`approval` is absent on keys created before approval by default, and the vault's serialisation leaves it out when absent.

### 3.2 `Principal`

| Variant | Match | Use case |
|---|---|---|
| `Oidc { issuer, sub, required_roles }` | Caller's verified `OidcClaims.sub` matches AND every required role is present. An empty `sub` makes the principal role-only: it matches any subject holding all `required_roles` (which must then be non-empty). | Owner / manager / auditor identities (humans, CI, service accounts), or a team named by role. |
| `Tee(AttestationProfile)` | RA-TLS peer cert satisfies the profile (measurement + OIDs + bidirectional challenge). | Runtime callers: the running app TEE doing `Wrap` / `Unwrap` / `Sign` / `ExportKey` on its own key or share. |
| `Fido2 { rp_id, credential_id_b64 }` | Declared in the schema; no caller resolves to it. | Hardware-bound human approvals are expressed with `OidcStepUp` (section 3.3), a passkey step-up through the IdP. |

Bidirectional RA-TLS challenge-response is **always** required for `Principal::Tee`; there is no opt-out flag.

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
  | OidcStepUp { required_amr: Vec<String>, operation_bound: bool,
                 fresh_for_seconds: u64, binding: u8 }
}
```

A request is allowed iff there is at least one rule whose `ops` contains the requested op AND whose `principals` contains the caller's resolved principal AND every condition in `requires` evaluates true.

`OidcStepUp` asks the caller's own bearer to prove a fresh step-up: its `amr` claim contains every method in `required_amr`, and its `iat` is within `fresh_for_seconds`. With `"binding": 2` the token must also carry a binding v2 of this exact operation (section 5); with `binding` absent and `operation_bound: true`, a binding v1 (section 5.4). A condition takes only the binding version it names. The canonical owner approval, which the vault's approval-by-default and tightening rules recognise, is:

```json
{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}
```

The IdP (Privasys ID by default) issues such a token after a WebAuthn assertion from the owner's passkey in their wallet, with the operation's `vault_op` and `nonce` as claims.

`AttestationProfile` carries `name`, `measurements: Vec<Measurement>` (`Mrenclave(hex)` or `Tdx { mrtd, rtmr1, rtmr2 }`), `attestation_servers` (URLs with optional pinned-SPKI hash), `required_oids`, and the optional `acceptable_tcb_statuses`.

### 3.4 `Mutability`: who can change what on `UpdatePolicy`

```text
Mutability {
    owner_can:   Vec<PolicyField>,         // default: Managers, Auditors, Tees, Operations,
                                           //          Lifecycle, PendingProfiles
    manager_can: Vec<PolicyField>,         // default: empty
    immutable:   Vec<PolicyField>,         // default: Owner, Mutability
}
```

`UpdatePolicy` evaluation:

1. The caller must satisfy the key's `UpdatePolicy` rule, with its conditions (section 5).
2. Compute the diff between `new_policy` and the stored policy.
3. For every touched `PolicyField`: in `immutable`, reject; otherwise the caller's role (owner or manager) must list it in `owner_can` or `manager_can`. A strict tightening by the owner is the one exception (section 4.1).
4. The new policy keeps every required OID the key already enforces, only the owner changes `lifecycle.auto_migrate_to_next_attestation_profile`, and a key that asks for approvals keeps asking for them (section 4).
5. On success, store, increment `policy_version`, append an audit entry.

The default makes the owner field and the mutability rules themselves immutable for the lifetime of the key. Adopters loosen this explicitly when they want a manager to be able to (for example) add a new TEE measurement to authorise an enclave upgrade.

### 3.5 `Lifecycle`

```text
Lifecycle {
    ttl_seconds: u64,                                  // default 30 days, capped at 90 days (section 1.2)
    auto_migrate_to_next_attestation_profile: bool,    // default false; only the owner changes it
}
```

With `auto_migrate_to_next_attestation_profile`, a profile staged by the platform that differs from an accepted profile only in the platform-runtime measurement (SGX MRENCLAVE, or the TDX MRTD/RTMR set) is promoted at once. The app-code digest, the app id and every other required OID must be identical, so app-code changes always wait for the owner.

---

## 4. Approval by default

A new key's policy asks for the owner's wallet approval on the operations that govern the key. At a first creation (`CreateKey` without `predecessor` or a carried `policy`, and `FrostDkgRound1`), the vault refuses a policy in which a rule that a person can use lets `PromoteProfile`, `UpdatePolicy` or `DeleteKey` happen without an approval, or `ExportKey` too when the key is exportable.

- **Rules a person can use** are rules naming `Owner`, a `Manager` or an `Auditor`. A rule for the app's own enclaves only (`Tee`, `AnyTee`), such as an app fetching its own key, is exempt.
- **An approval** is an `OidcStepUp` with `webauthn` in `required_amr` that is bound to the operation: `"binding": 2`, or `operation_bound: true` (binding v1). A fresh token alone, or a `ManagerApproval` co-sign alone, does not count.
- **Opting out** is explicit: `"approval": "none"` in the policy. Any other value is refused.
- **Updates** keep what a key has: when the current policy passes these rules and does not opt out, the new policy must pass them too and may not add `"approval": "none"`. A key created before approval by default may still be updated, and an update may add approvals.
- **Renewals** (section 7) copy or carry the key's existing policy, so the check does not apply to them.

### 4.1 Adding approvals to an existing key (tightening)

An owner may add the canonical bound step-up (section 3.3) to an existing key's rules, even when `Operations` is not in `owner_can`. The vault accepts the change as a tightening when the new policy differs from the current one only like this:

- every rule is kept, in the same order, with the same `ops` and `principals`;
- some rules gain exactly one condition, appended at the end: the canonical step-up `{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}`; every existing condition stays as it was;
- each rule that gains it names only persons (`Owner`, `Manager(i)`, `Auditor(i)`), grants at least one of `PromoteProfile`, `UpdatePolicy`, `DeleteKey`, `ExportKey`, and does not already ask for a wallet approval. A rule that names an enclave, even beside a person, keeps working for that enclave unchanged;
- everything outside `operations` (principals, mutability, lifecycle, `approval`) is identical.

Only the owner may tighten, through the key's `UpdatePolicy` rule as for any update, and a frozen `Operations` (listed in `immutable`) stays frozen. `policy_version` moves on by one and the audit log records `TightenApprovals`. `v2::tightening_rules` in the crate implements the check.

---

## 5. Owner approvals: binding v2

An owner approval is the owner's bearer itself: a token from the IdP with `amr` containing `webauthn`, a `nonce`, an `exp`, and a `vault_op` claim that names exactly one operation. With binding v2, `vault_op = base64url(SHA-256(text))` where the text is these lines joined by `\n`, with no trailing newline:

```text
privasys-vault-approval/v2
<member count>
<member_id>              one line each, sorted ascending
<op>
<handle>
<target>
<policy_version>
<approver>
-
<nonce>
<exp>
```

- **Members.** The request carries `"binding": { "members": [...] }`: the member ids of the vaults the approval is for, 64 lower-case hex digits each, sorted ascending and unique. A vault refuses an approval whose member set does not include its own member id (section 6), which keeps an approval for one constellation from being spent on another.
- **`approver`** is `oidc:0:<sub>`, the bearer's subject. The line after it is always `-` in this version.
- **The target and policy version** are computed by the vault from its own state and the request, never taken from the caller:

| `op` | `handle` | `target` | `policy_version` |
| --- | --- | --- | --- |
| `create` | the new handle | `PD` of the new key's policy in the vault's stored form | `0` |
| `promote` | key | `profile_binding_digest` of the staged profile | current |
| `export` | key | `-` | current |
| `update_policy` | key | `PD(new_policy as sent)` | current (the version replaced) |
| `update_policy_from` | key | hex `SHA-256("privasys-update-policy-from-v1\n" PD(current) "\n" PD(new))` | current |
| `delete` | key | `-` | current |
| `delete_after` | the old key | hex `SHA-256("privasys-delete-after-v1\n" successor "\n" successor_target)` | current |

- **Expiry.** The vault requires `now <= exp <= now + 600` on its trusted clock; a `delete_after` may live up to 24 hours (`now + 86400`), since it is presented only once a migration or upgrade has finished. The canonical condition's `fresh_for_seconds: 300` further requires the token to have been issued within the last 300 s.
- **Single use.** Each vault records `SHA-256(text)` until `exp` and refuses a second use. The short expiry and the policy version are the primary guarantee: any change to the policy moves `policy_version` and retires every approval made before it.
- **Which version a key takes** is in its policy: a condition with `"binding": 2` takes binding v2 and only v2. A client reads it with `GetPolicy`.

`profile_binding_digest` is the hex SHA-256 of the profile's measurements and required OIDs, each rendered as a lower-case `kind:value` line (`mrenclave:<hex>`, `mrtd:<hex>`, `rtmr1:<hex>`, `rtmr2:<hex>`, `oid:<oid>=<value>`), sorted and joined with `\n`.

### 5.1 The policy digest (`PD`)

`PD` is the hex SHA-256 of the RFC 8785 (JCS) serialisation of the policy JSON **exactly as the request carries it**, not of a re-serialisation. A policy is accepted for a digest only when:

- object member names are ASCII and unique (a duplicate is refused, never resolved); numbers are integers with absolute value at most 2^53; there are no floats;
- it names no field the vault does not know, at any depth. A known field sent at the default the vault's own serialisation omits is accepted: exactly `"approval": null` and `"binding": 0`;
- it is already normalised: lower-case hex in measurements, OID values and SPKI pins, and a non-zero `lifecycle.ttl_seconds` within the maximum. What the owner approves is what is stored.

`CanonicalisePolicy { policy }` applies these checks and returns the policy in the vault's **stored form** (every field written out, as `GetPolicy` returns it) with its `pd`. `PD(current)` in `update_policy_from` is the digest of the key's current policy in that stored form.

### 5.2 Policy updates on a binding v2 key

For a key whose `UpdatePolicy` rule takes binding 2, `new_policy` must be sent exactly in the vault's stored form, as `CanonicalisePolicy` returns it (key order and whitespace are free). The vault checks this before evaluating or spending any approval, and otherwise answers `new_policy is not in the vault's stored form (first difference at <json-pointer>): send the policy exactly as CanonicalisePolicy returns it`. The owner then approves the JSON the vault stores and returns, and the next update can name it as replaced with no re-canonicalising.

**`update_policy_from`.** A request may also bind the policy it replaces: `"binding": { "members": [...], "replaced_pd": "<hex PD(current)>" }`. The vault refuses unless `replaced_pd` equals the digest of its own current policy, and the approval's target covers both digests. A wallet can then show the owner a before-and-after diff that the vault itself checks. A vault that supports it lists `update-policy-from-v1` among its capabilities; a request without `replaced_pd` is a plain `update_policy`.

### 5.3 Test vectors

[`crates/enclave-os-vault/testdata/v2_vectors.json`](../crates/enclave-os-vault/testdata/v2_vectors.json) holds vectors produced by the vault's own code: a policy digest (with its JCS form), a member id, a billing id, the identity report data, a binding v2 `update_policy`, a binding v2 `update_policy_from`, and the stored-form refusal. A crate test asserts that the code still produces exactly that file, so client implementations can check their own code against it.

### 5.4 Binding v1

Keys created before binding v2 carry `OidcStepUp` conditions without `binding`. With `operation_bound: true`, such a condition takes a binding v1: `vault_op = base64url(SHA-256("privasys-vault-approval/v1\n" handle "\n" measurement_hex "\n" policy_version "\n" nonce "\n" exp))`, where the measurement slot is the staged profile's `profile_binding_digest` for a promote and empty for an export. Binding v1 has no form for update or delete, so an operation-bound v1 condition on those operations is never satisfied. Resharing a threshold key uses binding v1 with the resharing context in the measurement slot (section 2.6).

### 5.5 Manager approval tokens

`IssueApprovalToken { handle, op, ttl_seconds }` returns an `ApprovalToken { jwt }`. The JWT is ES256, signed by a vault-resident P-256 key created on first use and sealed under `__vault_signing_key_pkcs8__`.

```text
ApprovalClaims {
    iss:     "enclave-os-vault",
    handle:  String,
    op:      Operation,
    manager: u32,                          // index into principals.managers
    approver_sub:   String,                // the approver's OIDC sub
    policy_version: u32,                   // the key's policy_version at issuance
    iat:     u64,
    exp:     u64,
}
```

Approval tokens are vault-local: the vault that verifies a token is the vault that issued it.

`Condition::ManagerApproval { manager, fresh_for_seconds }` succeeds iff the request carries an `ApprovalToken` whose claims match `(handle, op, manager)` and whose age is within `fresh_for_seconds` at verification time. For a subject-bound manager, the token's `approver_sub` must be the `sub` of the manager now at that index; for a role-based manager, the approver must be a different person from the caller. The token is accepted only while the key's `policy_version` equals the one it carries.

---

## 6. Vault identity

`GetVaultIdentity` returns `VaultIdentity { member_id, member_public_key, billing_id, mrenclave, quote_b64, capabilities }`:

- `member_public_key` is the vault's sealed P-256 key (SEC1 uncompressed, hex), and `member_id` = hex `SHA-256("privasys-vault-member-v1\n" || member_public_key)`. Binding v2 approvals name vaults by member id.
- `billing_id` identifies the vault's OIDC configuration: hex `SHA-256("privasys-billing-implicit-v0\n" issuer "\n" audience)`. A carried renewal is accepted only from a source vault with the same billing id (section 7.1).
- `quote_b64` is an SGX quote whose report data starts with `SHA-256("privasys-vault-identity-v1\n" member_id "\n" billing_id)`.
- `capabilities` names what this build enforces: `generations-v1` (generation handles and links, section 7), `update-policy-from-v1` (section 5.2) and `tombstones-v1` (tombstones, re-created names and pending threshold keys, section 8).

The call is unauthenticated. A client trusts the answer only over an RA-TLS connection that pinned the vault's expected MRENCLAVE, and checks that the identity names that MRENCLAVE; the capabilities are outside the quote, so they are believed only as read over that pinned connection.

---

## 7. Renewals

A key renews before it expires by creating its next generation under the same policy. The app that uses the key (its runtime) renews it, reading the policy fresh from the vault over its attested connection. A renewal needs no approval: it copies or carries the key's own policy and never writes a new one.

**Generations** of a name use the handle `<base>/gen-<n>` (n >= 2). A first creation of a handle whose last segment is `gen-<digits>` is refused: a generation exists only through a renewal.

### 7.1 `CreateKey` renewal fields

| Field | Meaning |
|---|---|
| `predecessor` | Renewal in place: the handle of the key this one succeeds, on this vault. The vault copies its policy, `policy_version` and key check value, and ignores the grant's policy. The predecessor must be live, unexpired and of the same key type, the grant must keep its exportable flag, and the caller must be the key's owner or an enclave its policy names. A single-vault key must keep exactly the same value (the vault compares it); a Shamir share is fresh by design. The vault records `renewed_in_place_from`, and `GetKeyInfo` reports it. |
| `policy`, `policy_version` | Renewal onto another constellation, or rotation: the key's current policy as `GetPolicy` returned it from the source vault, carried byte for byte, and its version (at least 1). It takes the place of the grant's policy. The caller must be the owner or an enclave the carried policy names. `predecessor`, if given, names the old handle for the audit log only. |
| `source_billing_id` | Required with a carried policy: the source vault's billing id, which must equal this vault's (section 6). |
| `carried_exportable`, `carried_key_type` | Required with a carried policy: the source key's flag and type from its `GetKeyInfo`. The vault refuses a grant that differs, so a carried key keeps its shape. |
| `key_check` | The key check value of the whole key: `{ salt_b64, digest_hex }`, an Argon2id digest under a random 16-byte salt. The vault checks its form, stores it and never returns it. |
| `binding` | The members of the owner's `create` approval, for a re-created name (section 8.3). |

A carried create never sets `renewed_in_place_from`, so it cannot claim to supersede a key on the target vault.

### 7.2 Retiring the previous generation

`RetireKey { handle, successor, successor_members }` deletes the previous generation after a renewal in place, with no approval. The caller must be an enclave the key's policy names. The vault retires the key only when the successor is on this vault (`successor_members`, sorted and unique, include this vault's member id), is unexpired, and records `handle` as its `renewed_in_place_from`: the live generation is never reachable this way. Threshold keys renew by resharing and are not retired. The call is idempotent (`was_present: false` when the key is already gone) and leaves a tombstone with op `retire`. After a move to another constellation, the old generation stays until its own expiry.

### 7.3 Deleting the old key of a migration or upgrade (`delete_after`)

On a migration or an upgrade, the owner approves the old key's deletion together with its successor, and the delete is presented once the successor works. `DeleteKey { handle, after: { successor, successor_target }, binding }` binds the delete to that successor: `successor_target` is the profile digest of the successor's promote, or `-` when the successor was created rather than promoted. The vault refuses:

- a key named as its own successor;
- a successor deleted on this vault;
- where the successor is on this vault: one that is expired, belongs to another owner, or was not created after the key it replaces, or, with a profile digest, one whose policy does not yet list that profile.

Where the successor is on another constellation, the client presents the delete only after confirming the new key works, and the binding confines the approval to that successor.

---

## 8. Deletion and tombstones

### 8.1 Tombstones

`DeleteKey` (plain or `delete_after`) and `RetireKey` remove the key's record and material and leave a tombstone at `tomb:<handle>`. The tombstone is written first, then the record, its `prev:` share and its place in the owner's index are deleted; any later touch of the handle, and the housekeeping, finish a deletion that was cut short, so material never survives a tombstone. A tombstone holds no material:

```text
Tombstone {
    handle, key_type,
    final_policy, final_pd, final_policy_version,
    op:        "delete" | "delete_after" | "retire",
    approver:  "oidc:0:<sub>" | "tee:<caller id>",
    vault_op:  the binding's vault_op, or "-",
    successor: the successor's handle, or "-",
    deleted_at,
    expires_at,                            // the key's original expiry
    audit_next_seq,
}
```

- **Who learns of it.** The principals of the final policy: `GetKeyInfo` returns `KeyTombstone { handle, key_type, op, deleted_at, successor, expires_at }`, `ReadAuditLog` keeps working, and every other operation answers `key deleted at <deleted_at> (<op>); successor <successor>; the handle is reusable after <expires_at>`. Any other caller gets the answer it would get for a live key it is not a principal of. `ListKeys` lists live keys only.
- **The name is remembered.** Every creation path (first creation, carried create, renewal in place, threshold creation) refuses the handle while the tombstone exists: `handle deleted at <deleted_at>; reusable after <expires_at>: choose another name`.
- **Retention.** At the key's original expiry the tombstone and the key's audit log are purged, and the handle is free again. Purging needs the vault's trusted clock; without it, the tombstone is kept.
- **Housekeeping** runs on the back of ordinary requests at most every 300 s, over an index of tombstoned handles (`__tombs`), and visits at most 100 tombstones a pass from a rotating cursor.

### 8.2 Deleting

`DeleteKey` is evaluated against the key's `DeleteKey` rule. On a binding v2 key, the owner's approval names op `delete` (or `delete_after`, section 7.3), the handle and the current policy version.

### 8.3 Re-creating a deleted name

A deleted name comes back as a new key under a fresh handle `<base>/new-<k>` (k = 2, 3, ...). A first creation of a handle whose last segment is `new-<digits>` requires the owner's bound `create` approval: the bearer is the policy's owner, with the canonical step-up (section 3.3) and a binding v2 whose op is `create`, whose target is `PD` of the new key's policy in the vault's stored form, at policy version 0, with the members in the request's `binding`. The policy must be sent in stored form. The vault records `created_by_owner_approval: true`, and `GetKeyInfo` reports it. Beneath `<base>/new-<k>`, only renewals ending in `gen-<m>` may be created.

---

## 9. Worked policy examples

### 9.1 "Running app TEE can `Unwrap` its own DEK; the owner governs it"

```text
OperationRule {
  ops:        [Unwrap],
  principals: [Tee(0)],
  requires:   [],                          // RA-TLS already proved the measurement
}
OperationRule {
  ops:        [PromoteProfile, UpdatePolicy, DeleteKey],
  principals: [Owner],
  requires:   [OidcStepUp { required_amr: ["webauthn"], operation_bound: true,
                            fresh_for_seconds: 300, binding: 2 }],
}
```

with `principals.tees[0] = Principal::Tee(profile_v_n)`. The enclave rule needs no approval; the owner's rule carries the canonical step-up, so the policy passes approval by default.

### 9.2 "Manager may add a new TEE for an enclave upgrade, with a co-signer"

`Mutability::manager_can = [PolicyField::PendingProfiles, PolicyField::Tees]` with:

```text
OperationRule {
  ops:        [PromoteProfile],
  principals: [Manager(0)],
  requires:   [ManagerApproval { manager: 1, fresh_for_seconds: 3600 },
               OidcStepUp { required_amr: ["webauthn"], operation_bound: true,
                            fresh_for_seconds: 300, binding: 2 }],
}
```

so promoting requires manager #0's own bound passkey step-up and a fresh token from manager #1.

### 9.3 "Auditor reads the audit log, nothing else"

No operation rule is needed: `ReadAuditLog` admits owner OR any auditor by name; everything else falls through to the operation table.

---

## 10. Enclave upgrade flow (vN -> v(N+1))

The vault enforces a strict separation: a platform-driven enclave upgrade **never** automatically authorises a new app measurement to read a customer key. The new measurement enters the policy only via the explicit pending / promote pair, gated by the policy's rules and `Mutability`, or through the owner's own `auto_migrate_to_next_attestation_profile` opt-in for platform-runtime changes (section 3.5).

```text
[v(N) running]
   |  developer builds v(N+1); MRENCLAVE captured
   v
[v(N+1) staged]   StagePendingProfile{ handle, profile=v(N+1), source }
   |              -> vault appends to KeyRecord.pending_profiles
   |              -> the owner approves the promote in their wallet
   v
[v(N+1) live]     PromotePendingProfile{ handle, pending_id, binding }
                  -> vault checks the PromoteProfile rule (op "promote", target = profile digest)
                  -> vault checks Mutability for PolicyField::Tees
                  -> pending profile becomes principals.tees[k]
                  -> policy_version incremented; audit entry written
                  -> v(N+1) presents its quote on RA-TLS and gets its key
```

The fan-out across the constellation lives entirely in `enclave-vaults-client`. Each vault evaluates its own per-key policy against its own state, independently. Partial outcomes (for example 3 of 4 vaults accept the promote) are surfaced verbatim to the caller; each vault is the sole authority over what it holds.

---

## 11. Storage layout

| KV key | Value | Purpose |
|---|---|---|
| `key:<handle>` | sealed `KeyRecord` | The key, its policy, its sealed material. |
| `index:<owner_sub>` | JSON `Vec<String>` | Owner's handle list, used by `ListKeys`. |
| `audit:<handle>:<020d-seq>` | sealed `AuditEntry` | Append-only audit log, kept until a deleted key's original expiry. |
| `tomb:<handle>` | sealed `Tombstone` | What a deleted key leaves, until its original expiry (section 8). |
| `__tombs` | JSON `Vec<String>` | Handles that have a tombstone, for the housekeeping. |
| `prev:<handle>` | sealed `KeyRecord` | A threshold key's previous share during a renewal in place, until finalize or rollback. |
| `__vault_signing_key_pkcs8__` | sealed P-256 PKCS#8 | The vault's member key: signs manager approval tokens and defines the member id. |

KV keys are HMAC-SHA-256-encrypted on disk by `enclave-os-kvstore`, so the host sees opaque blobs only: no prefix scans, no enumeration. Handles starting with `__` are reserved.

---

## 12. Authentication summary

| Caller | Transport | Identifies as | Typical operations |
|---|---|---|---|
| Service / TEE | mutual RA-TLS | `Principal::Tee` | `Wrap` / `Unwrap` / `Sign` / `Mac` / `ExportKey`, renewals, `RetireKey`. |
| Operator (CI, CLI, human) | OIDC bearer over RA-TLS | `Principal::Oidc` | `GetPolicy`, `GetKeyInfo`, `ListKeys`, `ReadAuditLog`, `IssueApprovalToken`, pending-profile staging. |
| Owner approving in their wallet | OIDC bearer with a passkey step-up | `Principal::Oidc` + `OidcStepUp` | Promote, update, delete, export, re-creating a name. |

The vault matches OIDC callers against the subjects and `required_roles` its key policies name; it gives no built-in meaning to any role name. A role-only principal (empty `sub`) names a set of callers by role, for example an app's team. Adopters can point `oidc_issuer_url` at any OIDC provider and name its issuer in `Principal::Oidc`.

---

## 13. Migration from the legacy `SecretRecord` API

The previous wire protocol (`StoreSecret` / `GetSecret` / etc.) is gone. Adopters using the old shape need to:

1. Replace `StoreSecret` with `CreateKey` under a grant for `key_type: RawShare` (or a typed key).
2. Replace `GetSecret` (OIDC owner path) with `ExportKey`.
3. Replace `GetSecret` (RA-TLS path) with `ExportKey` carrying appropriate `principals.tees` + `OperationRule { ops: [ExportKey], principals: [AnyTee] }`.
4. Replace `manager_sub` with `principals.managers[i]` plus a `Condition::ManagerApproval` on the relevant operation rule (and use `IssueApprovalToken` to mint approvals at the call site), or with the owner's `OidcStepUp`.

There is no compatibility shim: keeping the TCB minimal comes first.
