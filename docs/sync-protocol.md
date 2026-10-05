# Keyorra Sync Protocol

Version: 1 (draft). Status: sections 1–8 are defined and implemented in `crates/keyorra-sync`
(plan A1a), section 9 by plan A1b, section 10 by plan A1c-1 (headers, snapshots and clone
handling follow in plan A1c-2); later sections are placeholders filled by later plans. The design rationale is in
`docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`; this document is the normative
description. Any change to bytes on the wire changes this file in the same commit.

Test vectors: `docs/sync-test-vectors/a1a.json` (fixed inputs → exact outputs). An
implementation is conforming for this part when it reproduces every value in that file.

## 1. Notation

- `‖` concatenation; `x:N` a field of N bytes; integers in headers are unsigned big-endian
  (`u32` = 4 bytes, `u64` = 8 bytes).
- `SHA-256`, `HKDF-SHA256` (RFC 5869), `Ed25519` (RFC 8032, verification with the strict
  rules of `ed25519-dalek` `verify_strict`), `XChaCha20-Poly1305` (draft-irtf-cfrg-xchacha;
  sealed output is `nonce:24 ‖ ciphertext ‖ tag:16`).
- `Argon2id` (RFC 9106, version 0x13).
- `canonical(v)`: the deterministic CBOR encoding of section 3.
- Hex in this document and in the vectors is lowercase.

## 2. Labels

Every label is used as `label ‖ 0x00 ‖ parts…`, so no label is a prefix of another.

| Label | Used for |
|---|---|
| `keyorra/sync/v1/kek` | HKDF info for `KEK_sync` |
| `keyorra/sync/v1/server-auth` | HKDF info for `AUTH` |
| `keyorra/sync/v1/segment-key` | HKDF info for `K_seg` |
| `keyorra/sync/v1/account-key` | AAD of the wrapped account key |
| `keyorra/sync/v1/header` | header signature |
| `keyorra/sync/v1/body` | AAD of record bodies |
| `keyorra/sync/v1/version` | version hash |
| `keyorra/sync/v1/chunk` | AAD of attachment chunks |
| `keyorra/sync/v1/segment` | segment signature |
| `keyorra/sync/v1/snapshot` | snapshot signature |
| `keyorra/sync/v1/chain-genesis` | first link of a stream's hash chain |
| `keyorra/sync/v1/chain` | every further link |
| `keyorra/sync/v1/conflict-copy` | ids of conflict copies and of their attachment records |
| `keyorra/sync/v1/endorse` | endorsement and self-join statements |

## 3. Canonical CBOR

A subset of RFC 8949: major types 0 (unsigned integer), 2 (byte string), 3 (UTF-8 text),
4 (array), 5 (map) and the simple values `false` (0xf4), `true` (0xf5), `null` (0xf6).

Encoding: the shortest head for every length or integer; definite lengths only; map entries
sorted by the bytewise order of their encoded keys, no duplicate keys.

Decoding is strict and rejects: non-shortest heads, indefinite lengths, reserved
additional-information values, negative integers, tags, floats and other simple values,
unsorted or duplicate map keys, invalid UTF-8, lengths beyond the input, nesting deeper
than 32, and trailing bytes. Structures are maps with text keys and exactly the listed
fields.

## 4. Padding

`pad(data) = data ‖ 0x80 ‖ 0x00…` up to `max(1024, padme(len(data) + 1))` bytes, where
`padme(L)` (Padmé, PURBs paper, PETS 2019) is: for `L < 2`, `L`; otherwise
`E = floor(log2 L)`, `S = floor(log2 E) + 1`, `mask = 2^(E−S) − 1`,
`padme(L) = (L + mask) & ~mask`. Unpadding strips trailing zeros, requires the last
non-zero byte to be `0x80` and the total length to equal the formula. Applied to segment
payloads, snapshot payloads and attachment chunks.

## 5. Secret Key and keys

**Secret Key.** 16 random bytes `SK` and an independent 4-character id (random digits of
the alphabet below). Display: `ID-ddddd-ddddd-ddddd-ddddd-ddddd-dc` where the 26 `d` are the
big-endian base32 digits of `SK` as a 128-bit integer (Crockford alphabet
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`; the first digit is at most 7) and `c` is
`"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"[SK mod 37]`. Parsing ignores case, hyphens and
whitespace and maps `I`, `L` → `1` and `O` → `0`.

**Derivation.**

```
U        = Argon2id(password, salt, m, t, p, 32 bytes)        salt, m, t, p from the account header
M        = HKDF-Extract(salt = SK, ikm = U)
KEK_sync = HKDF-Expand(M, "keyorra/sync/v1/kek\0" ‖ account_id, 32)
AUTH     = HKDF-Expand(M, "keyorra/sync/v1/server-auth\0" ‖ account_id, 32)
K_seg    = HKDF(salt = account_id, ikm = AK, info = "keyorra/sync/v1/segment-key\0", 32)
```

KDF parameters read from a header must satisfy, before Argon2 runs: `m ≤ 1048576` KiB,
`1 ≤ p ≤ 4`, `t ≤ 10`, and (floor) `m ≥ 65536` KiB and `t ≥ 2`, the app's own minimum:
weaker parameters would let whoever writes the folder or server brute-force the password offline
from the public wrapped key. Argon2's own minimum `m ≥ 8p` also applies. The ceiling is checked
whenever keys are derived; the floor when a header read from storage is unlocked.

## 6. Account header

```
Header = { "keyorra_sync": 1, "account_id": bytes16, "epoch": uint32, "generation": uint32,
           "root_device": bytes16, "kdf": { "m_kib", "t", "p" }, "salt": bytes16,
           "secret_key_id": text(4), "wrapped_account_key": bytes }
wrapped_account_key = XChaCha20-Poly1305(KEK_sync, nonce, AK,
                        aad = "keyorra/sync/v1/account-key\0" ‖ binding)       exactly 72 bytes
binding    = SHA-256(canonical(Header with wrapped_account_key = empty bytes))
HeaderFile = { "header": Header, "author": bytes16, "sig": bytes64 }
sig        = Ed25519(author key, "keyorra/sync/v1/header\0" ‖ author:16 ‖ canonical(Header))
file name  = hex8(epoch) ‖ "-" ‖ hex(author) ‖ ".hdr"
```

`binding` ties the wrapped key to account, epoch, generation, root device, KDF parameters, salt
and Secret Key id, so a header cannot be recombined from parts. `secret_key_id` is 4 characters
of the Secret Key alphabet. A header read from storage is untrusted until its signature has been
verified with a key the trust rules (section 10) accept; unlocking it first is allowed but its
result must not be used before that. A header file is at most 16 KiB.

A `keyorra_sync` value other than 1 is "unsupported", not "malformed". Which header counts
(highest epoch, matching log entry, tie-breaks) is defined in section 10.

## 7. Record envelopes, versions and bodies

```
Version  = { "vector": { bytes16 → uint ≥ 1 }, "hlc": uint, "author": bytes16 }
Envelope = { "format": 1, "kind": "vault" | "item" | "attachment", "record_id": bytes16,
             "vault_id": bytes16 | null, "schema": uint32, "version": Version,
             "tombstone": bool, "body": bytes | null }
version_hash = SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, version]))
header_hash  = SHA-256(canonical(envelope with "body" = null))
body (item, attachment) = XChaCha20-Poly1305(vault key, nonce, payload,
                            aad = "keyorra/sync/v1/body\0" ‖ account_id ‖ header_hash)
body (vault) = the plaintext payload (protected by the segment layer)
```

Rules: `tombstone` is true exactly when `body` is null; `item` and `attachment` envelopes
have a `vault_id`, `vault` envelopes have none (`vault_id` is null). Unknown `format` or `kind`: unsupported (kept, not interpreted). The
payload contents and the merge rules are defined in section 9.

## 8. Framing: chunks, segments, snapshots

**Attachment chunk** (at most 4 MiB of data):

```
chunk = "KYC1" ‖ XChaCha20-Poly1305(attachment key, nonce, pad(data),
          aad = "keyorra/sync/v1/chunk\0" ‖ account_id ‖ attachment_id:16 ‖ index:u32 ‖ count:u32)
name  = hex(SHA-256(chunk))
```

In the formats below, `XChaCha20-Poly1305(...)` denotes the sealed output of section 1, which
begins with the 24-byte nonce; there is no separate nonce field. Nonces are drawn fresh from a
CSPRNG for every seal.

**Segment.**

```
header  = "KYS1" ‖ collection:u8 (= 0) ‖ device_id:16 ‖ first_seq:u64 ‖ last_seq:u64 ‖ prev_hash:32 ‖ last_hash:32
segment = header ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload = { "entries": [entry, …], "sig": Ed25519(device key, "keyorra/sync/v1/segment\0" ‖ header ‖ canonical(entries)) }
chain_0 = SHA-256("keyorra/sync/v1/chain-genesis\0" ‖ account_id ‖ device_id)
chain_n = SHA-256("keyorra/sync/v1/chain\0" ‖ chain_{n−1} ‖ canonical(entry_n))
```

`first_seq ≥ 1`; the entry count equals `last_seq − first_seq + 1`; `last_hash` is the chain
over the entries starting from `prev_hash`; the canonical entries are at most 4 MiB and the
whole segment at most the padded size of that plus framing (checked before parsing or
decrypting); `first_seq + count − 1` must not overflow. That the first segment of a stream
starts from `chain_0` is checked by the stream rules (section 10), not by the framing. A
non-zero collection is unsupported in version 1 (reserved for shared vaults).

**Snapshot.**

```
header   = "KYP1" ‖ collection:u8 (= 0) ‖ author:16
snapshot = header ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload  = { "body": …, "sig": Ed25519(author key, "keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body)) }
name     = hex(SHA-256(snapshot))
```

The canonical snapshot body is at most 64 MiB; the sealed snapshot is length-checked before
decryption. A chunk longer than the padded size of 4 MiB is rejected before decryption.

## 9. Payloads, versions, fold and presentation

### 9.1 Payloads

The opened body of an envelope (section 7) is the canonical CBOR of:

```
item       = { "item": bytes, "deleted_at": uint | null, "content_from": { bytes16 → uint ≥ 1 } }
vault      = { "name": text, "wrapped_key": bytes, "deleted": bool }
attachment = { "item_id": bytes16, "name": text, "size": uint, "key": bytes32,
               "chunk_size": uint, "chunks": [bytes32, …] }
```

`item` is the item's JSON object exactly as the local store serializes it; `deleted_at` is
unix seconds (in Recently Deleted when set); `content_from` (never empty) is the version
vector of the write that last changed `item`. `wrapped_key` is the vault key sealed by the
account key (`keyorra-core` `wrap_vault_key`). `key` is the attachment's own key; `chunks`
are chunk names (section 8). A tombstone envelope has no payload. Vaults are never
tombstoned; they are deleted with `deleted = true`.

### 9.2 Clocks and new versions

`hlc = unix_ms << 16 | counter`. A new local write takes `max(wall_ms << 16, last + 1)`. A
received version whose physical part is more than 300 000 ms ahead of the local wall clock
is accepted but does not move the local clock (and is logged).

A new version of record `r` by device `D`: `vector = join(vectors of r's siblings)` with
`vector[D] = max(that, D's previous counter for r) + 1`. An edit sets the item's
`content_from` to the new vector; trashing and restoring keep the previous `content_from`
(an empty one, from a first copy, becomes the vector of the version being trashed or
restored).

### 9.3 Validation

A segment's versions are accepted together or not at all. For each version carried by the
stream of device `S`: `version.author = S`; `vector[S]` is exactly one more than the
highest `vector[S]` among `S`'s versions of the same record already accepted (or in the same
segment), or 1; the payload decodes as the envelope's kind; a vault is never a tombstone; an
item's `content_from` is covered by its own vector. A version already accepted (same version
hash) is ignored if its payload and `vault_id` are identical and is an equivocation
otherwise. A violation rejects the segment and stops reading that stream (an alarm). A
segment containing a version whose `vector[X]` (X ≠ `S`) exceeds X's highest accepted counter
for that record waits until X's earlier versions have been applied.

### 9.4 Sibling sets and the fold

For every record, the sibling set is the set of accepted, admitted versions that no other
accepted, admitted version dominates (vector ≥ in every entry and different). Equal vectors
count as the same version. The set depends only on which versions were accepted, not on
their order. Every accepted version is retained so the sets can be rebuilt when admission
changes (section 10).

### 9.5 Presentation

Ranks: `(hlc, author)` compared as `(u64, bytes16)`, higher wins.

**Items.** A sibling is *live* (no `deleted_at`), *trashed* (`deleted_at` set) or *purged*
(tombstone). A *first copy* (item payload with an empty `content_from`) is left out when the
record has any other sibling. Among the rest, a sibling is *stale* when another sibling that
is a tombstone or has a different `content_from` has a vector covering (≥ in every entry) its
`content_from`. Siblings are ordered fresh before stale, then by rank. Shown: the first live
sibling if any; else the first purged one; else the first trashed one. Every other sibling
becomes a conflict copy unless it is stale, its content equals content already shown (the
shown sibling's or an earlier copy's; JSON values compared without `updated_at`), or (with a
purge shown) it is trashed. A trashed sibling's copy keeps its `deleted_at`.

**Vaults.** Shown: the highest-ranked sibling's payload. It counts as deleted only if it is
`deleted` and no live item has this vault; otherwise a `deleted` vault is shown as revived.
Siblings with different `wrapped_key` raise an alarm.

**Attachments.** Removed if any sibling is a tombstone; otherwise the highest-ranked payload.

### 9.6 Conflict copies

For a copied sibling `s` of item `r`:

```
copy_id            = UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ r ‖ version_hash(s))[0..16])
copy attachment id = UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ copy_id ‖ attachment_id)[0..16])
```

(UUIDv8: the first 16 bytes with the version nibble set to 8 and the RFC 4122 variant.) The
copy's JSON is `s`'s JSON with `"id"` = `copy_id`, `"conflict"` = `{ "of": r, "version":
hex(version_hash(s)), "from_device": hex(s.author) }`, and every attachment reference's `"id"`
replaced by its copy attachment id with `"copied_from"` = the original id. The title is not
changed.

A device whose fold shows a copy that does not exist as a record writes, before its next user
edit: each missing copy (a new record; empty `content_from`), then a version of `r` with the
shown sibling's content and `content_from` (an empty one replaced by the shown sibling's
vector), or a tombstone if `r` is purged.
For each attachment reference with `copied_from` in a shown copy whose record does not exist,
a device that has accepted a version of the original attachment with content writes it: the
payload of the newest such version (highest rank), even if the original was removed since,
with `item_id` = the copy.

## 10. Streams, entries and trust

### 10.1 Entries

```
entry = { "put": Envelope }
      | { "checkpoint": { bytes16 → [seq, hash] } }
      | { "genesis": { "account_id": bytes16, "key": bytes32, "name": text } }
      | { "self_join": { "key": bytes32, "name": text, "sig": bytes64 } }
      | { "endorse": { "device": bytes16, "key": bytes32, "name": text, "sig": bytes64 } }
      | { "revoke": { "device": bytes16, "last_valid_seq": uint } }
statement = "keyorra/sync/v1/endorse\0" ‖ account_id ‖ device ‖ key
```

An entry is a map with exactly one key; an unknown key is "unsupported" (a newer app wrote
it: the stream waits, nothing is rejected). `endorse.sig` is the endorsing device's Ed25519
signature over the statement for the endorsed device; `self_join.sig` the joining device's
own signature over the statement for itself. `checkpoint` lists, for other streams, the
position (the last entry of a segment: sequence number and chain hash) that the writer had
received when it wrote the entries that follow. A writer adds a checkpoint before the first
entry it writes after what it has received changed, and a device that only reads writes one
at least every hour while its received positions change. `put.version.author` must be the
stream's device.

### 10.2 Trust

The account header names the **root** device. Trust is derived from all accepted `genesis`,
`self_join`, `endorse` and `revoke` entries, ordered by `(stream, seq)`, so it does not depend
on arrival order:

1. `genesis` is valid only as entry 1 of the root's stream, with this account's id and the
   key that signs the stream. `self_join` is valid only as entry 1 of its own stream, with
   the key that signs the stream and a valid signature. An `endorse` must verify with the key
   of the stream that carries it; a device id endorsed with two different keys is a
   rejection.
2. **Introduced devices**: the root (by `genesis`), self-joined devices, and, repeatedly, every
   device endorsed by an introduced device at a position not after that device's cut.
3. **Cuts**: a `revoke` counts if the revoker is the revoked device itself, or is introduced
   without the revoked device (step 2 with that device and everything only it introduced left
   out), and if its position is not after the revoker's own cut, where that cut ignores
   revocations made by the device being revoked now (so mutual revocations both apply). A
   device's cut is the smallest `last_valid_seq` among the revocations of it that count.
4. A stream position `(device, seq)` **counts** (is admitted) iff the device is introduced and
   `seq` is not after its cut. The fold (§9.4) builds sibling sets from admitted versions
   only and is rebuilt whenever trust changes.

A device that is not introduced yet can read but does not write. A device whose own cut is
set does not write any more. Other devices report a self-joined device once (an alarm).

### 10.3 Reading streams

A device keeps, per other stream, the last received position (initially `(0, chain_0)`)
and the chain hash at the end of every received segment. It receives the segment whose
`first_seq` is the next one, verified with the stream device's key from §10.2, or, for
entry 1 of the root's stream or of a self-joining stream, with the key in that entry. A
segment that does not open is retried later. A received segment whose `prev_hash` is not the
known hash is a **fork**. A `put` whose author is not the stream's device rejects the stream.

Received entries are then applied with per-record buffering: an entry waits only for what it
needs, and entries of one stream keep their order within their lane (per record for `put`,
one lane for trust entries):

- an item or attachment `put` waits for the key of its vault (from any stream's vault record);
- a `put` whose `vector[X]` (X ≠ author) exceeds X's highest applied counter for that record
  waits for X's earlier versions (§9.3);
- a trust entry waits until the stream's device is introduced.

Checkpoints are compared on receipt: a listed position that this device has received with a
different chain hash is a **fork**; a listed position of this device's own stream beyond what
the store confirmed is a fork, unless it is exactly the segment whose append outcome was lost
(then it counts as confirmed); a listed position not received yet is a **claim**, settled
when the position arrives (a different hash then is a fork). A claim unmet for 24 hours is
reported as withheld (a warning, not a pause).

**Rollback**: before reading, a device compares each stream's stored head (`Transport::head`)
with its own received position, and before writing, the stored head of its own stream with
its last confirmed position; a stored head behind is a rollback. A stored head of its own
stream ahead of its confirmed position means another copy of the device wrote there: the
device stops writing (clone handling: plan A1c-2).

A fork or a rollback pauses syncing until the user decides; the round reports it as an error.

### 10.4 Conflict copies after a revocation

A conflict copy whose versions were all written by a device that is no longer admitted, of a
source version that is still admitted, is written again (same content) by a device that may
write, so that the copied content does not disappear with the revocation (§9.6).

## 11. Folder transport

To be defined by plan A2.

## 12. Server API

To be defined by plans B1 and B2.
