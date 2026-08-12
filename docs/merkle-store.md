# Merkle Store (`enclave-os-merkle`)

Authenticated key-value store for enclave-os: a versioned sparse Merkle
tree over the host KV store. One 32-byte root attests the entire logical
data state; reads fail closed against an in-memory root the host cannot
roll back.

## Why

The sealed KV store (`enclave-os-kvstore`) hides *content* from the host
but cannot detect a host that serves stale data or selectively drops
records. The merkle store adds integrity and freshness on top of the
same host RocksDB: every read verifies a hash chain up to a root held in
enclave memory, every commit produces a new root, and one `(version,
root)` pair summarises everything.

## Commitments: the root is encryption-independent

Two independent 32-byte keys, never mixed:

| key | scope | used for |
| --- | --- | --- |
| `ck` commitment key | logical dataset (shared across future BFT replicas) | `path = HMAC-SHA256(ck, "p" ‖ key)`, `vh = HMAC-SHA256(ck, "v" ‖ path ‖ plaintext)` |
| `sk` storage key | this enclave instance only | AES-256-GCM of value bytes at rest |

The tree commits to `(path, vh)` pairs only, so the root is a pure
function of the logical state and `ck`. Two replicas sharing `ck` but
holding different storage keys produce **identical roots** and compare
state by comparing `(version, root)` — the property a future BFT-Raft
layer builds on. Ciphertexts are free to be non-deterministic (random
GCM nonces) and per-machine.

Keyed hashing means the host cannot dictionary-attack low-entropy keys
or values; including `path` in the `vh` preimage hides value equality
across different keys.

## Structure

- 256-bit paths, walked one nibble per level: **16-ary storage** (one
  node record per level, depth ≈ log16 N) with **binary hashing** (an
  internal node's hash is a 4-level binary merkle over its 16 child
  slots, empty ranges standing in as a placeholder constant, single-leaf
  ranges collapsing to the leaf hash). I/O stays logarithmic while
  proofs stay compact binary sibling lists.
- A leaf terminates the path at any depth: a subtree with one key is
  one leaf node.
- Node records are addressed `(version, nibble prefix)` and are
  **immutable**: commits copy-on-write the touched path under the new
  version. Value records are addressed `(vh, value_version)` and are
  equally written-once (the leaf carries `value_version` as routing
  metadata, excluded from the hash).

## Storage records (host RocksDB, one table `merkle:<name>`)

| prefix | key | value |
| --- | --- | --- |
| `n` | NodeKey | node encoding (plaintext: hashes/versions only) |
| `v` | `vh ‖ value_version` | AES-256-GCM ciphertext |
| `s` | `stale_since ‖ target record key` | empty |
| `r` | `version` | root hash |

Nodes are deliberately host-readable: they contain nothing but hashes
and offsets, and host visibility is what allows host-side proving and
host-executed pruning later. A commit lands all records in **one atomic
`kv_store_write_batch`**; the in-memory `(root, version)` swings only
after the host confirms.

## API sketch

```rust
let backend = OcallBackend::new("mystore");
let mut store = MerkleStore::create(backend, ck, sk)?;   // or ::open(.., root, version)

let (root, version) = store.put_batch(&[
    (b"alice".to_vec(), Some(b"1000".to_vec())),
    (b"bob".to_vec(),   None),                            // delete
])?;                                                      // one atomic commit
store.get(b"alice")?;                                     // verified read
store.get_at(version - 1, b"alice")?;                     // historical read

let proof = store.prove(b"alice")?;                       // inclusion/absence
store.verify_value(&root, b"alice", b"1000", &proof)?;    // bound to key+plaintext

store.retain_recent(128)?;                                // prune old versions
```

Seal `(root, version)` after every commit; hand it back to `open()` at
restart, which verifies the backend actually holds that root before
serving traffic.

## Reads fail closed

A read returns plaintext only after: every node on the path hashes to
its parent's expectation (up to the in-memory root), the GCM tag
verifies, and the plaintext re-derives the committed `vh`. Any mismatch
is an error, never data. The node cache (default 1024 records) removes
host I/O, not verification — cached nodes are re-verified against the
parent's expected hash on every use.

## Proofs

Every proof is a plain binary sparse-Merkle proof: terminal evidence
(the leaf found, or nothing for an empty subtree) plus bottom-up sibling
hashes. `proof::verify(root, path, proof)` is a pure function returning
the established statement — `Present(vh)` or `Absent` — and compiles on
any target. Absence proofs come free from the placeholder structure
(empty-slot terminal) or as a divergent leaf covering the proven
position. Without `ck`, statements are about opaque `(path, vh)` pairs
by design.

## Pruning

Commits append stale-index entries for every record they supersede.
`prune(before_version)` (or `retain_recent(window)`) range-deletes the
stale entries at or below the horizon together with their targets, plus
root records below the horizon — chunked atomic batches, idempotent,
cost proportional to garbage. Versions at or above the horizon stay
fully readable and provable; older ones fail with `Missing`. Because
node and value records are written-once, deletion is blind: no liveness
checks, no refcounts.

## Freshness model, stated precisely

- **Live reads (`get`, `prove`)**: bound to the in-memory root. A host
  serving stale or forged records produces hash mismatches, never wrong
  data. Rollback of the live state is not possible while the enclave
  runs.
- **Restart**: `open()` takes the sealed `(root, version)` checkpoint
  and refuses to start if the backend does not verify against it. A
  host replaying a matched old checkpoint + old store across a restart
  is not locally detectable (sealing has no freshness source);
  client-side root-continuity pinning and, later, BFT quorum close
  this.
- **History (`get_at`, `prove_at`)**: content is authenticated against
  the stored root record for that version; the version→root binding for
  history is host-held until a sealed root-history lands.

## Performance (measured, in-memory backend, 100k keys)

- Warm-cache random `get`: ~4.1 backend reads (≈3 node + 1 value),
  ~36µs dominated by SHA-256 verification.
- Batch commits write shared prefix nodes once; a 1000-op batch is one
  host round trip.
- A host-prover OCALL (host walks, enclave verifies one returned proof)
  would cut ~3 node round trips ≈ a few µs per get on the SPSC queues —
  deferred until a real workload shows it matters.
