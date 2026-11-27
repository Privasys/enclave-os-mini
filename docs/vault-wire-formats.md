# Enclave Vaults: wire formats

The exact formats the vault (`crates/enclave-os-vault`) computes and checks for vault identity, owner approvals, policy digests, renewals and deletions. Section numbers are stable, so code comments cite them as "vault wire formats §N"; numbers without a section here are not used. [vault.md](vault.md) describes the vault as a whole.

## 0. Conventions

- `H(x)` is SHA-256. `b64u` is base64url without padding. Hex is lower-case.
- Every hashed text form is UTF-8, lines joined by `\n`, with no trailing newline, so every party computes the same bytes. A value that contains `\n`, or is empty, is refused. Integers are decimal without leading zeros. A missing value is the single character `-`.
- A list is a count line followed by one item per line. Sets (member ids) are sorted ascending by byte value.
- Every form starts with a versioned domain line, so no form can be mistaken for another.
- JSON policies are hashed as `H(JCS(doc))`, JCS being RFC 8785. `PD(policy)` is the hex of that (§5.1 says exactly over which JSON).
- The vault recomputes every bound value from its own state or from the request's actual content. It never takes a digest from a request.

## 1. What a vault fixes at first boot

- **The member key.** The vault's own P-256 key, generated in the enclave on first use and sealed under `__vault_signing_key_pkcs8__` (`signing.rs`).
- `member_id` = hex `H("privasys-vault-member-v1\n" || P)`, with `P` the SEC1 uncompressed public key of the member key. Stable across restarts, new with every vault. Different vaults have different member ids, and every approval names the members it is for (§5), which is what keeps one constellation's approvals from being spent on another.
- `billing_id` = hex `H("privasys-billing-implicit-v0\n" issuer "\n" audience)`, from the vault's OIDC issuer and audience, which are fixed in its sealed configuration.
- **`GetVaultIdentity`** (unauthenticated) returns `VaultIdentity { member_id, member_public_key, billing_id, mrenclave, quote_b64, capabilities }`. `member_public_key` is hex; `quote_b64` is an SGX quote (b64u) whose report data starts with `H("privasys-vault-identity-v1\n" member_id "\n" billing_id)`. `capabilities` lists what the build enforces: `generations-v1` (§9), `update-policy-from-v1` (§5.3) and `tombstones-v1` (§9.3, §9.3.1).
- **Trust.** A client takes a vault's identity only over an RA-TLS connection that pinned the vault's expected MRENCLAVE, and checks that the identity names that MRENCLAVE and that `member_id` and the quote's report data agree with the stated key and billing id. The capabilities are outside the quote, so they are believed only as read over that pinned connection.

## 4. Approval rules

**Approval by default.** A policy without an approval rule on promote, update, delete and export is refused unless it says so explicitly (`"approval": "none"`; any other value is refused). Precisely:

- only rules a person can use count: rules naming `Owner`, a `Manager` or an `Auditor`. A rule for the app's own enclaves only (`Tee`, `AnyTee`), such as an app fetching its key, needs no approval;
- the operations checked are `PromoteProfile`, `UpdatePolicy` and `DeleteKey`, and `ExportKey` when the key is exportable;
- an approval is an `OidcStepUp` with `webauthn` in `required_amr`, which the vault always checks bound to the operation (§5). A step-up without a passkey is not;
- checked at first creation (`CreateKey` without a predecessor or carried policy, and `FrostDkgRound1`), and at update only against a downgrade: when the current policy passes and does not opt out, the new one must pass and may not add `"approval": "none"`. A key without approvals may still be updated, and an update may add them. Renewals are exempt: their policy is copied or carried, not written (§9).

### 4.1 Adding approvals to an existing key

An owner may change an existing key's operation rules to ADD bound approvals, even when `Operations` is not in `owner_can`: a strict tightening (`v2::tightening_rules`).

- **What counts as a tightening, exactly.** The new policy equals the current one except that some rules gain ONE condition, appended at the end, the canonical bound passkey step-up:

  `{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}`

  and only rules that:
  - have ONLY persons as principals (`Owner`, `Manager(i)`, `Auditor(i)`). A rule naming `Tee` or `AnyTee`, even beside a person, keeps working for that enclave unchanged; a request adding a condition to it is refused ("split the rule first");
  - grant one or more of `PromoteProfile`, `UpdatePolicy`, `DeleteKey`, `ExportKey`;
  - do not already carry a wallet approval (§4).

  Nothing else may differ: the same principals, the same rule list and order, the same ops per rule, every existing condition kept as it is, the same lifecycle and mutability, and the same `approval`. The fixed shape keeps a key's owners able to meet every rule: the canonical step-up asks only for a wallet tap.
- **How the vault recognises it.** Inside `UpdatePolicy`, before the `Mutability` check: if the diff is exactly a tightening, the `Operations` field may change for the owner even though `owner_can` does not list it. Any other change to `Operations` still needs `Operations` in `owner_can` (or `manager_can`).
- **Who may do it:** the owner only.
- **`immutable`.** If `Operations` is in `mutability.immutable`, the tightening is refused like any change.
- **Which approval the change needs:** the key's current `UpdatePolicy` rule, evaluated as for any update.
- **After it:** `policy_version` moves on by one, approval by default is re-checked on the result, and the audit records the decision as `TightenApprovals`, naming the rules that changed. Callers add the condition to every eligible rule in one update, so the result passes approval by default.

## 5. Binding v2

```
privasys-vault-approval/v2
<member count>
<member_id>              one line each, sorted
<op>
<handle>
<target>
<policy_version>
<approver>
-
<nonce>
<exp>
```

- An owner approval is a bearer from the IdP whose `vault_op` claim is `b64u(H(text))`, built with the token's own `nonce` and `exp`.
- `approver` is `oidc:0:<sub>`, the bearer's subject. The line after it is always `-`.
- The request carries `"binding": { "members": [...] }` (and `replaced_pd` for §5.3). Every other value comes from the vault's state, the operation, or the token.

| `op` | `handle` | `target` (computed by the vault) | `policy_version` |
| --- | --- | --- | --- |
| `create` | the new handle | `PD(policy of the new key)`, in the vault's stored form | `0` |
| `promote` | key | `profile_binding_digest` of the staged profile | current |
| `export` | key | `-` | current |
| `update_policy_from` | key | hex `H("privasys-update-policy-from-v1\n" PD(current policy) "\n" PD(new policy))` (§5.3) | current (the version replaced) |
| `delete` | key | `-` | current |
| `delete_after` | the old key | hex `H("privasys-delete-after-v1\n" successor_handle "\n" successor_target)` (§9.2) | current |
| `reshare` | key | the hex resharing context of the threshold key (§9) | current |

- **Members.** 64 lower-case hex digits each, sorted ascending and unique. The vault refuses unless its own `member_id` is in the set.
- **Expiry and nonce.** `now <= exp <= now + 600` on the vault's trusted clock, refused when the clock is not trusted. The one exception is `delete_after`, which may live up to 24 hours (`now + 86400`), because it is presented only once a migration or upgrade has finished (§9.2). Each vault keeps `H(text)` until `exp` and refuses a second use; the real guarantee is the short expiry plus `policy_version`.
- **Freshness.** The condition's `fresh_for_seconds` bounds the token's age by its `iat` (300 s in the canonical step-up).
- **Every step-up is binding v2.** Keys written before v2 carry `OidcStepUp` without `binding` (and `operation_bound` true or false); the vault keeps those bytes, so their `PD` never changes, and checks every step-up as binding v2. `binding` other than absent or `2` is refused. A rule checks its binding once.
- `profile_binding_digest` is the hex `H` of the profile's measurements and required OIDs rendered as lower-case `kind:value` lines (`mrenclave:`, `mrtd:`, `rtmr1:`, `rtmr2:`, `oid:<oid>=<value>`), sorted and joined by `\n`.

### 5.1 The policy digest, exactly

`PD` is computed over the policy JSON **exactly as the request carries it**, not over any re-serialisation.

- **Canonical JSON** is RFC 8785 with these restrictions, and the vault refuses a policy outside them: object member names are ASCII and unique (a duplicate name is refused, not resolved); numbers are integers with absolute value at most 2^53; no floats.
- **Unknown fields are refused**, at any depth, so nothing inside the digest is ignored by the vault.
- **Already normalised.** The vault refuses a policy its normalisation would change: lower-case hex in measurements, OID values and SPKI pins; a non-zero `lifecycle.ttl_seconds` within the vault's maximum. What the owner approved is what is stored.
- **A known field sent at its default** is accepted even where the vault's own serialisation leaves it out: exactly `"approval": null` and `"binding": 0`. Any other name the vault does not know is refused, whatever its value.
- **Omitted fields** take their defaults, and the digest covers the omission.
- `GetPolicy` returns the vault's own serialisation (the stored form). `PD(current)` is the digest of that.
- **`CanonicalisePolicy { policy }`** (unauthenticated, stores nothing): returns `{ policy, pd }`, the policy in the vault's stored form and the digest of the JSON as sent.
- **A policy update sends the stored form.** Every policy update (`update_policy_from`, including the §4.1 tightening) must send `new_policy` exactly in the vault's stored form, as `CanonicalisePolicy` returns it (key order and whitespace free). Otherwise it is refused before any approval is evaluated or spent, with `new_policy is not in the vault's stored form (first difference at <json-pointer>): send the policy exactly as CanonicalisePolicy returns it`. Then `PD(new as sent)` is the stored `PD`, and the next `update_policy_from` names it as `replaced_pd`. A re-created name's policy (§9.3.1) is likewise sent in stored form.
- **The stored form, field by field:**
  - policy: `version`, `principals`, `operations`, `mutability` (absent means the default: `owner_can` `[Managers, Auditors, Tees, Operations, Lifecycle, PendingProfiles]`, `manager_can` `[]`, `immutable` `[Owner, Mutability]`; a partial object gets `[]` for each list it leaves out), `lifecycle` (`ttl_seconds`, default 2592000, 0 means the default, capped at 7776000; `auto_migrate_to_next_attestation_profile`, default false). `approval` is omitted when absent, never `null`.
  - principals: `owner`, `managers`, `auditors`, `tees` (each `[]` when empty). `Oidc`: `issuer`, `sub`, `required_roles` (`[]`).
  - TEE profile (`Tee`): `name`, `measurements` (`{"Mrenclave": hex}` or `{"Tdx": {"mrtd", "rtmr1", "rtmr2"}}`), `attestation_servers` (each `url` and `pinned_spki_sha256_hex`, `null` when absent), `required_oids` (`[]`), `acceptable_tcb_statuses` (`null` when absent). Hex is lower-case.
  - operation rule: `ops`, `principals`, `requires` (`[]`).
  - conditions: `OidcStepUp` writes `required_amr`, `operation_bound`, `fresh_for_seconds`, and `binding` only when non-zero.

### 5.2 Test vector, binding v2

Inputs: members `1111...1111` and `2222...2222` (64 hex digits each); `op` `update_policy`; `handle` `apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2`; `target` `3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b`; `policy_version` 3; `approver` `oidc:0:test-subject-1`; `nonce` `AAECAwQFBgcICQoLDA0ODw`; `exp` 1764000600.

Text (356 bytes, no trailing newline):

```
privasys-vault-approval/v2
2
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
update_policy
apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2
3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
3
oidc:0:test-subject-1
-
AAECAwQFBgcICQoLDA0ODw
1764000600
```

`H(text)` = `f4fe5392066464c3e92ca26c442af4f53d2009e87532a398923cea5f95f31b23`; `vault_op` = `9P5TkgZkZMPpLKJsRCr09T0gCeh1MqOYkjzqX5XzGyM`.

**Vectors from the vault's code** are in [`crates/enclave-os-vault/testdata/v2_vectors.json`](../crates/enclave-os-vault/testdata/v2_vectors.json). A crate test asserts that the code still produces exactly that file, so it is the reference for client implementations: a policy digest (the policy as sent and its JCS form), a member id, the billing id of `https://privasys.id` / `privasys-platform-test`, the identity report data, a binding v2 `update_policy` whose target is that `PD`, a binding v2 `update_policy_from`, and the stored-form refusal (`stored_form_for_v2_updates`).

### 5.3 Binding the policy being replaced

An approval of a policy update may also bind the digest of the policy it replaces, so a wallet can show a diff it can trust: the "before" is checked against the vault's own current policy, the "after" against the new policy, and both are in what the owner signs.

- **The binding** keeps the §5 layout. Only the op and its target differ: `op` = `update_policy_from`, `target` = hex `H("privasys-update-policy-from-v1\n" || PD(current) || "\n" || PD(new))`, `policy_version` = the current version.
- **`PD(current)`** is the digest of the key's current policy as `GetPolicy` returns it (the stored form, §5.1).
- **The request** carries `"binding": { "members": [...], "replaced_pd": "<hex PD(current)>" }` on `UpdatePolicy`. The vault refuses unless `replaced_pd` equals its own `PD(current)`. Like `policy_version`, that stops an approval made against one "before" being spent on another.
- **Required.** A request without `replaced_pd` is refused. The vault still lists capability `update-policy-from-v1` in `GetVaultIdentity` for older clients; nothing needs to read it.

## 9. Renewals and moves

The app (its runtime) renews its own key before it expires. It holds the secret and carries the policy, read fresh from the source vault over its attested connection. A renewal needs no approval: the policy it carries is the key's own.

- **In place.** `CreateKey { handle: successor, predecessor, grant, ... }`: the vault copies the predecessor's policy, `policy_version` and key check value, and ignores the grant's policy. It refuses if the predecessor is missing, expired or of another key type, if the grant changes `exportable`, or if the caller is not the key's owner or an enclave its policy names.
- **To another constellation, or a rotation.** The app reads `GetPolicy` (the policy and `policy_version`) and `GetVaultIdentity` (the source's `billing_id`) from the source vault, then calls `CreateKey { handle: successor, policy, policy_version, source_billing_id, carried_exportable, carried_key_type, grant, ... }` on each target vault. `predecessor` may name the old handle for the audit log.
- **The target vault checks:** the caller is the owner or an enclave the carried policy names; `policy_version` is at least 1; `source_billing_id` equals its own `billing_id` (keys do not cross billing configurations); `carried_exportable` and `carried_key_type` equal the grant's, so a carried key keeps its shape. It creates the successor with that policy and `policy_version`.
- **An in-place renewal records its predecessor; nothing else does.** The vault sets `renewed_in_place_from` only when it copied the policy from a predecessor on this vault, never from a request, so a carried create cannot claim to supersede a key. A renewal in place of a single-vault key must keep exactly the same value (the vault compares it); a Shamir share is fresh by design.
- **Generations exist only through renewals.** A generation is named `<base>/gen-<n>` (n >= 2), a marker nothing else uses. A first creation (no predecessor, no carried policy) of any handle whose last segment is `gen-<digits>` is refused. `GetKeyInfo` reports `renewed_in_place_from`. A client that takes a name's newest generation should accept generation n > 1 only when it names generation n - 1, or, for a carried move (no link), only when no older generation of that name exists.
- **Capability `generations-v1`.** A build that enforces the rules above, reports the link and keeps a carried key's shape lists `generations-v1`. A field's absence proves nothing, so a client trusts a link only from a vault listing the capability, over a connection pinned to its build.
- **Threshold keys** renew by resharing: same handle, same public key, under the owner's approval of the resharing context.

### 9.1 Deleting the previous generation after a renewal

After a successful automatic renewal in place, the app deletes the previous generation itself, with no approval.

`RetireKey { handle, successor, successor_members }` -> `KeyRetired { was_present }`:
- The caller is an enclave the predecessor's policy names (a `Tee` principal). This is a request of its own, not the owner's `DeleteKey` rule.
- **Only a generation the vault knows is superseded:** the successor is on this vault, unexpired, and its record's `renewed_in_place_from` is `handle`; `successor_members` (sorted, unique, non-empty) include this vault. The live generation is never reachable this way, whatever the caller claims.
- **After a move, the old generation is not retired by the app.** The old vault cannot see the successor; the old generation goes when it expires.
- Idempotent: a predecessor already gone returns `was_present: false`.
- Refused for threshold keys.
- Leaves a tombstone with op `retire` (§9.3).

### 9.2 Deleting the old key of a migration or upgrade

On a migration or an upgrade, the owner approves the old key's delete together with the promote (or creation) of its successor. The delete is presented only after the migration or upgrade has succeeded.

- **The approval** is a binding v2 with `op` `delete_after`, `handle` = the old key, and `target` = hex `H("privasys-delete-after-v1\n" successor_handle "\n" successor_target)`. `successor_target` is the target of the successor's `promote` (its profile digest), or `-` when the successor is created, not promoted.
- **The request** is `DeleteKey { handle, after: { successor, successor_target }, binding }`; the vault recomputes the target from `after`.
- **Lifetime:** up to 24 hours, for this op only (§5).
- **A key is never its own successor:** the vault refuses a `delete_after` whose successor is the key being deleted.
- **The vault refuses the delete until the successor has succeeded, where it can see it.** If the successor is on this vault, it must be live and unexpired, its policy must have the same owner principal as the key being deleted, and it must have been created later. When `successor_target` is a profile digest, the successor's policy must already list a TEE profile with that digest, which means the promote was applied. A successor tombstoned on this vault is refused.
- **Where the successor is on another constellation**, the old vault cannot see it. There the client presents the delete only after confirming the new key works. The binding still confines the approval to that successor.
- Spent once, like every binding.

### 9.3 Tombstones

A deleted key leaves a tombstone, so the deletion and the key's history can still be read, and its handle is not reused, until the key would have expired anyway.

- **When.** `DeleteKey` (plain or `delete_after`) and `RetireKey`. The key record is removed with its material; in its place the vault writes `tomb:<handle>`.
- **Material never survives a tombstone.** The sealed store has no multi-key transaction, so the order makes it safe: the tombstone is written first, then the key record (with its material), its `prev:` share and its place in the owner's index are deleted. Any later touch of the handle finds the tombstone and completes the deletion before answering. The housekeeping also completes half-done deletions: it runs on the back of ordinary requests at most every 300 s, over an index of tombstoned handles (`__tombs`), visiting at most 100 per pass from a rotating cursor.
- **What it holds, never material:**

  ```json
  {
    "handle": "...", "key_type": "...",
    "final_policy": { ... }, "final_pd": "<hex>", "final_policy_version": 7,
    "op": "delete | delete_after | retire",
    "approver": "oidc:0:<sub> | tee:<caller>",
    "vault_op": "<the binding's vault_op, or ->",
    "successor": "<handle, or ->",
    "deleted_at": 1764000000,
    "expires_at": 1771776000,
    "audit_next_seq": 12
  }
  ```

  The final policy is kept whole because it decides who may read the tombstone and the log. `expires_at` is the key's original expiry.
- **The audit log is kept.** Entries at `audit:<handle>:<seq>` stay, with the deletion as the last entry, and `ReadAuditLog` works on a tombstoned handle for the principals the final policy resolves.
- **`GetKeyInfo`** on a tombstoned handle returns `{"KeyTombstone":{"handle","key_type","op","deleted_at","successor","expires_at"}}` to the same principals (`KeyDeleted` stays the plain answer to a successful `DeleteKey`). Every other operation on it is refused with exactly `key deleted at <deleted_at> (<op>); successor <successor>; the handle is reusable after <expires_at>`. Clients match the prefix "key deleted" (Go: `IsKeyDeleted`). The platform's manager bearer is told as the principals are. `RetireKey` of a tombstoned handle answers `KeyRetired { was_present: false }` to a principal.
- **The handle cannot be created again** while the tombstone exists. Every creation path is refused: a first creation, a carried create, an in-place renewal and a threshold creation alike, with `handle deleted at <deleted_at>; reusable after <expires_at>: choose another name` (Go: `IsHandleTombstoned`).
- **Purge.** After `expires_at` the tombstone and the key's audit entries are deleted, lazily whenever the handle is touched and by the housekeeping. Never without trusted time. After the purge the handle is "not found" again and may be created.
- **Not listed.** `ListKeys` lists live keys only.
- **No existence oracle.** Handles can name a person, so only the principals the final policy resolves learn that a handle was deleted. Any other caller gets exactly the answer it would get for a live key it is not a principal of (`caller is not in policy.principals`), never "key deleted" and never `KeyTombstone`.
- **Retention.** A tombstone keeps the owner's subject, the approver and the final policy until the key's original expiry, at most 90 days after the key was created, and is then purged with the key's audit log.

#### 9.3.1 Re-created names and pending keys

**Re-created names.** A deleted name comes back as a NEW key (new value, its own creation and approvals) under a fresh handle `<base>/new-<k>` (k = 2, 3, ...), never as a generation of the deleted one.

- **The vault** accepts a first creation of a handle whose last segment is `new-<digits>` ONLY with the owner's bound `create` approval (§5: `op` `create`, the binding names the handle, `target` = `PD` of the new key's policy in the vault's stored form, as `CanonicalisePolicy` returns it, `policy_version` 0; the bearer must be the policy's owner, with the canonical step-up), never on a grant alone. The policy must be sent in stored form. A re-created name is not a renewal in place. The vault records `created_by_owner_approval: true` on the key, set by the vault, and `GetKeyInfo` reports it. The build lists it under `tombstones-v1`.
- **Clients** can rely on `created_by_owner_approval`, read from the pinned vaults, to confirm that a re-created name was made by its owner, and treat a `new-<k>` without it as unresolved. `gen-<m>` beneath `new-<k>` follows the generation rules of §9, with `new-<k>` playing generation 1.
- **Beneath `new-<k>`, only linked renewals.** Any handle with a `new-<digits>` segment that is not its last may only be created by a renewal (a predecessor here, or a carried policy) and must end in `gen-<m>`; the vault refuses any other child. Rotating a re-created key to a new value is a delete and a further re-creation (`new-<k+1>`).

**Pending threshold keys.**
- A threshold key created by a DKG or resharing session is pending on a vault from its commit until it first serves an operation (a signing round, a crypto operation, or a deal of a resharing). The vault records the session id and the creating caller.
- `FrostDkgAbort` / `FrostReshareAbort` take an optional `handle` and remove a pending key, accepted only for a key in that state, within its own session (same session id, same caller), at most 300 s after its commit, and never once the key has served any operation.
- An aborted pending key leaves no tombstone: it never existed as a usable key. The abort is audited (`AbortPendingKey`), the aborted key's audit entries stay, and a later creation of the same handle continues that log.
- A key that has served is deleted only through `DeleteKey`, with a tombstone, like any other.

## 10. Key check value

### 10.4 The key check value of a whole key

- At creation, the creator, who holds the whole key, may send `key_check` = `{ salt_b64, digest_hex }` in `CreateKey`: `digest_hex` = hex `Argon2id(password = key, salt = "privasys-key-check-v1" || salt, t = 3, m = 64 MiB, p = 1, length = 32)`, with `salt` 16 random bytes (b64u in `salt_b64`). For a split key, every vault receives the same pair beside its share. A slow function, not a hash, so a single vault's sealed state does not make a low-entropy secret cheap to guess.
- The vault checks the form (a 16-byte salt, 64 lower-case hex digits), stores it and never returns it from any call.
- A renewal in place copies it with the policy. A renewal onto another constellation, or a rotation, sends a fresh one, with a new salt, as any creator does.
- A vault cannot check `key_check` against a share. Split keys are meant for high-entropy secrets.
