# Keyorra Sync — Design

Date: 2026-10-05
Status: revised after an independent cryptography/distributed-systems review (2026-10-05);
the user's decisions on the open questions are recorded in §13. Awaiting final review.
Expands roadmap item 1 of `2026-10-02-lockbox-mvp-design.md`.

## Goal

Keep one Keyorra account in step across several Macs (later also an iPhone), without
giving up what Keyorra is today: free, local-first, and readable only by its owner.

Two phases, one sync engine:

- **Phase A — folder sync.** Any folder that some other program keeps in sync: iCloud
  Drive, Dropbox, Google Drive, OneDrive, Syncthing, a NAS share. One implementation, the
  *folder transport*. iCloud Drive is only the suggested default location
  (`~/Library/Mobile Documents/com~apple~CloudDocs/Keyorra`).
- **Phase B — self-hosted server.** A small Keyorra server for Linux, shipped both as a
  Docker image and as a single static (musl) binary. Same engine, another transport. It
  adds push updates, enforced device approval, and is the base for vault sharing later.

Two non-negotiables, set by the user:

1. **Secure.** A folder or a server only ever holds ciphertext. Whoever controls it can
   delete or withhold data, but cannot read it, cannot change it unnoticed, and cannot roll
   it back or fork it unnoticed by devices that saw a newer state.
2. **Transparent.** The user can see what is stored where, which devices take part, what
   happened during each sync, and what the folder or server can see. The protocol is a
   public document with test vectors, so anyone can audit or re-implement it.

### Non-goals (for this design)

- Sharing vaults between different people (roadmap 3). The format reserves room for it.
- WebDAV and S3 transports (roadmap 1d). They fit the same transport trait later.
- Syncing per-device settings: Touch ID, browser pairings, auto-lock, window state.
- Field-level automatic merging of concurrent edits. Conflicts keep every version.
- Garbage collection and key rotation in phase A (both arrive in C1, after phase B).

## Summary of decisions

| Topic | Decision |
|---|---|
| Unit of sync | One record per vault, item, attachment; device identity and account headers are signed log entries |
| Storage | Per-device append-only streams of immutable, hash-chained, signed, padded segments; record versions travel **inline** in segments; snapshots are self-contained packs; separate blobs only for attachment chunks. No file is ever modified, so no locks and no sync-client conflicts |
| Concurrency | Version vector per version; per-record **sibling set** (antichain of non-dominated versions); hybrid logical clock (HLC) picks the visible sibling |
| Local state | A deterministic **fold** over accepted entries; independent of delivery order |
| Conflicts | Keep all: the visible sibling stays, every other differing sibling becomes a copy "X (conflict from <device>)" whose id derives from that sibling's own version |
| Edit vs delete | Edit wins (decided) |
| Device trust | A device counts only if endorsed by a live device (first device = root). Server approval *is* that endorsement. Self-join with the Emergency Kit works but raises an alarm on every other device |
| Secret Key | Required for sync (decided). Mixed into the key that wraps the account key in the folder/server; the local vault keeps unlocking with the master password alone |
| Server auth | Token derived from master password + Secret Key + account id under its own HKDF label; server stores only its hash. No SRP/OPAQUE (§6.3) |
| Rollback / fork | Hash chains + Ed25519 signatures + cross-checkpoints; clone detection on every append |
| Server | Rust, axum, SQLite + blob directory; single owner + invites (decided), multi-account schema |
| TLS | Own cert files, a reverse proxy, or a self-signed cert pinned through the setup code. No built-in ACME |
| Push | Server-Sent Events |
| Sync while locked | No (decided) |
| Key rotation | After phase B, in C1 together with GC (decided) |

## 1. What exists today (grounding)

From `crates/keyorra-core`:

- `crypto::keys`: master password → Argon2id (64 MiB, t=3, p=1, 16-byte salt) → KEK; the
  KEK seals a random 32-byte **account key** (AK) in a `Header { format, kdf, salt,
  wrapped_account_key }` with AAD `lockbox/account-key/v1`. AK wraps one random **vault
  key** per vault (AAD `lockbox/vault-key/v1\0 ‖ vault_id`).
- `crypto::aead`: XChaCha20-Poly1305, `nonce(24) ‖ ciphertext ‖ tag`.
- Items are sealed with their vault key, AAD `lockbox/item/v1\0 ‖ vault_id ‖ item_id ‖
  schema(be32)`; attachments with `lockbox/attachment/v1\0 ‖ vault_id ‖ item_id ‖ att_id`.
  Vault metadata (name) is sealed with AK.
- `store`: SQLite tables `meta`, `vaults(id, wrapped_key, meta, revision, deleted)`,
  `items(id, vault_id, data, revision, updated_at, deleted_at, schema)`,
  `attachments(id, item_id, data, revision, deleted, schema)`. `revision` is a per-row
  counter. Item deletion is two-stage: `deleted_at` (Recently Deleted, 30 days), then purge
  empties `data` and keeps a tombstone row. Vault deletion keeps a tombstone row and the
  key. A row that fails to decrypt is shown as `Damaged`. `KdfParams::validate` allows up
  to 4 GiB of Argon2 memory.
- `Store::sealed_meta` keeps small per-device secrets sealed with AK.
- `keyorra-session::touchid`: AK wrapped to a Secure Enclave key; a `Keyring` trait already
  abstracts the macOS Keychain.

Reused by sync: the key hierarchy (unchanged), tombstones, `Damaged` handling,
`sealed_meta`, the `Keyring` abstraction. Not reusable as is: the local `revision` (a
single counter cannot tell "newer" from "concurrent") and the at-rest blobs (their AAD
binds no version). Sync defines its own wire format and converts at the boundary; the
local SQLite format stays the local format.

## 2. Architecture

```
crates/
  keyorra-core/      store migration v2 (sync tables, single change path, unknown-field keeping)
  keyorra-sync/      NEW: formats, fold/merge, streams, endorsement, Transport trait,
                     memory + fault-injecting transports, test vectors. No OS APIs.
  keyorra-sync-fs/   NEW: folder transport (std fs + notify; macOS iCloud/File Provider bits behind cfg)
  keyorra-server/    NEW (phase B): axum server binary + admin CLI
  keyorra-session/   sync scheduling, Keychain-held device key, Sync screen DTOs, flows
app/src-tauri        commands, background sync thread, FSEvents/SSE wake-ups
app/src              Sync screen, onboarding, conflict UI
```

- The engine is synchronous and deterministic: given local state, transport contents, a
  clock and an RNG (all injected), it produces the same result. It runs on its own thread;
  every transport call has a deadline (default 30 s) so a hung provider never blocks the
  UI or the lock.
- `keyorra-server` depends on `keyorra-sync` only for framing types (segment header, name
  rules, signature verification of plaintext statements). It never links decryption code.
- One account syncs through exactly one transport at a time.

```rust
pub trait Transport {
    fn headers(&self) -> Result<Vec<RawHeader>>;
    fn put_header(&self, h: &RawHeader) -> Result<()>;
    fn delete_header(&self, name: &HeaderName) -> Result<()>;
    fn streams(&self) -> Result<Vec<StreamInfo>>;                  // one per device
    fn segments(&self, stream: DeviceId, after_seq: u64) -> Result<Vec<Fetched<RawSegment>>>;
    fn append(&self, seg: &RawSegment) -> Result<AppendOutcome>;   // Ok | Conflict(remote head)
    fn snapshots(&self) -> Result<Vec<SnapshotInfo>>;
    fn get_snapshot(&self, s: &SnapshotName) -> Result<Fetched<Vec<u8>>>;
    fn put_snapshot(&self, s: &SnapshotName, bytes: &[u8]) -> Result<()>;
    fn delete_own_snapshot(&self, s: &SnapshotName) -> Result<()>;
    fn get_chunk(&self, name: &ChunkName) -> Result<Fetched<Vec<u8>>>;
    fn put_chunk(&self, name: &ChunkName, bytes: &[u8]) -> Result<()>;
    fn listing(&self) -> Result<Vec<RawEntry>>;                     // "what the transport sees"
}
pub enum Fetched<T> { Ready(T), Pending /* not downloaded yet */, Missing }
```

`Pending` is a first-class answer: an iCloud placeholder, a dataless File Provider file or
a half-synced segment all mean "try again later", never "error".

## 3. Data model

### 3.1 What is synced

| Record kind | Content (inside encryption) | Inner key |
|---|---|---|
| `vault` | name, icon, the vault key wrapped by AK (existing AAD), `deleted: bool` | none (segment layer only) |
| `item` | the `Item` JSON exactly as stored today, plus `deleted_at` | vault key |
| `attachment` | `item_id`, name, size, random attachment key, chunk names, chunk size | vault key |

Plus, as signed stream entries (§4): device introductions and endorsements, revocations,
account headers, checkpoints, snapshot references. Plus, as separate blobs: attachment
chunks (§3.6).

Not synced: Touch ID records, browser pairings, the local header, settings, sync state
tables, Watchtower's HIBP cache.

### 3.2 Keys and labels

Every sync label is `keyorra/sync/v1/<name>`; every label is followed by `\0` when used as
a prefix, so no label is a prefix of another.

| Name | Derivation | Use |
|---|---|---|
| `account_id` | 16 random bytes, fixed when sync is first enabled | binds everything to one account |
| Secret Key `SK` | 128 random bits (§7.6) | second factor for the synced header |
| `U` | Argon2id(master password, remote salt, remote kdf) | |
| `M` | HKDF-Extract(salt = SK, ikm = U) | |
| `KEK_sync` | HKDF-Expand(M, `keyorra/sync/v1/kek\0 ‖ account_id`, 32) | unwraps AK from the synced header |
| `AUTH` | HKDF-Expand(M, `keyorra/sync/v1/server-auth\0 ‖ account_id`, 32) | server login (§6.3) |
| `K_seg` | HKDF-SHA256(ikm = AK, salt = account_id, info = `keyorra/sync/v1/segment-key\0`) | segments and snapshots |

KDF parameters read from a synced header are bounded on both sides before Argon2 runs: at most
1 GiB, t = 10, p = 4, and at least the app's own minimum (64 MiB, t = 2); a weaker header would let
whoever writes the folder or server brute-force the password offline.
| vault key | existing, per vault | inner layer of item and attachment records |
| attachment key | 32 random bytes per attachment | chunk blobs (§3.6) |
| device key | Ed25519, per device, in the Keychain (§4.2) | signs segments, snapshots, headers, endorsements |

The inner vault-key layer is kept although segments are already encrypted with `K_seg`:
it preserves the MVP promise that vault content needs that vault's key, and it is what a
future shared vault will rely on (its segments will be sealed with a key derived from the
vault key; the segment header reserves a `collection` byte, `0` in v1).

### 3.3 Versions

Every record version carries:

```rust
struct Version {
    vector: BTreeMap<DeviceId, u64>, // how many writes of each device this version includes
    hlc: u64,                        // hybrid logical clock: 48-bit unix ms | 16-bit counter
    author: DeviceId,                // device that wrote this version; equals the stream's device
}
version_hash(v) = SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, v]))
```

- **Write** on device D to a record with sibling set S (§3.4):
  `vector = join(vectors of S); vector[D] += 1`;
  `hlc = max(wall_ms << 16, local_hlc + 1)`. The new version dominates every sibling, so a
  write always collapses the set.
- **Dominance**: `a` dominates `b` if every entry of `a` ≥ the entry of `b` (missing = 0)
  and they differ. Neither dominates → concurrent.
- **Receiving** a version: `local_hlc = max(local_hlc, v.hlc)` **unless** the physical part
  of `v.hlc` is more than 5 minutes ahead of the local wall clock. Then the local clock is
  not advanced, the version is still accepted (refusing would lose data), and the Sync log
  says "MacBook Air's clock is 3 h ahead; its edits win conflicts until that is fixed".
- **Validation** of a Put from stream D (rejecting the whole segment with an alarm if it
  fails, since a live device signed it): `v.author == D`; `v.vector[D]` equals
  `1 + (D's previous accepted version of this record).vector[D]` (or 1); for every other
  device X, `v.vector[X]` ≤ the number of X's versions of this record already applied
  (guaranteed checkable by causal delivery, §4.4).

Vectors stay small (one entry per device that ever edited the record). Entries of revoked
devices are never removed.

### 3.4 Sibling sets and the fold

For each record the engine keeps its **sibling set**: the versions that no other accepted
version dominates (an antichain, in the spirit of dotted version vectors).

Adding an accepted version `v` to set `S`: if some sibling equals or dominates `v`, drop
`v`; otherwise remove the siblings `v` dominates and add `v`.

The result depends only on the *set* of accepted versions, not on the order they arrive,
so devices that have accepted the same entries hold the same sibling sets. Local state is
therefore defined as a **fold**: `state = presentation(sibling sets(accepted versions))`,
where "accepted" is the acceptance rule of §4.4. The SQLite tables `vaults`, `items` and
`attachments` are a materialised view of that fold, updated in place.

Because a revocation can remove versions from the accepted set (§4.6), dominated versions
are not thrown away when they leave the sibling set:

- the local index (`sync_versions`: kind, id, vector, hlc, author, stream position) keeps
  every accepted version;
- the local copy of a dominated version's ciphertext is kept for 90 days; after that it is
  re-fetched from its segment on the transport if a re-fold needs it (phase A has no GC,
  so segments stay available).

### 3.5 Presentation: what the user sees

**Items.** Classify the siblings of an item: *live* (no `deleted_at`), *trashed*
(`deleted_at` set), *purged* (tombstone, no body). "Same content" compares the item's JSON
values without `updated_at` (`deleted_at` is outside the JSON).

Every item version also carries `content_from`: the version vector of the write that last
changed its content. An edit sets it to its own vector; trashing and restoring keep it. A
sibling is **stale** when another sibling with a different `content_from` (or a tombstone)
has a version that covers its `content_from`: it only trashed or restored content that the
other side then replaced or deleted. Siblings with the same `content_from` never make each
other stale (two devices that collapsed the same conflict would otherwise hide each other
next to a third concurrent edit; found by review of A1b). (Revised while
planning A1b: comparing a trashed sibling's content with the *concurrent* edit cannot tell a
pure delete from an edit-then-delete, because a pure delete carries the old content.)

1. Any purged sibling: the item stays purged (ids never come back). Every live sibling that
   is not stale becomes a live copy. Trashed siblings are dropped (the user meant to delete
   them).
2. Else any live sibling: the visible item is the best live sibling, where "best" prefers
   fresh over stale, then the higher `(hlc, author)`. So an edit beats a concurrent delete
   and a concurrent pure restore. Every other sibling that is not stale and whose content is
   not already shown becomes a copy: live siblings as live copies, trashed ones (edited, then
   trashed, concurrently with an edit elsewhere) as copies **in Recently Deleted**, so the
   edit is not lost and the delete is still honoured.
3. Else all trashed: the visible item is the best trashed sibling; others that are not stale
   and have different content become trashed copies.

A copy of sibling `s`: id = `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ record_id
‖ version_hash(s))[0..16])`, item field `conflict = { of: record_id, version:
version_hash(s), from_device: s.author }`, same vault. The stored title is unchanged; the app
shows "(conflict from <device name>)" from the marker, because device names can differ
between devices at the moment of writing and the copy must be byte-identical everywhere.
Its attachment references point to new ids `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0"
‖ copy_id ‖ attachment_id)[0..16])` and keep `copied_from = attachment_id`; any device that
knows the original attachment record writes the copy's attachment record (same key and
chunks, `item_id` = the copy), so a copy never waits for an attachment. Each copy derives
from its sibling's *own* version, so the result is the same on every device and there is no
invented "join author".

**Materialising copies.** Any device whose fold yields a copy id that does not yet exist as
a record writes, at the end of every pull (also when the pull failed part of the way) and
again before any item edit (which is refused if the copies cannot be written): each such copy as a
new record (its `content_from` is its own version), then a collapsing write of the original
(content and `content_from` of the visible sibling, vector = join + 1). Two devices doing
this concurrently produce copies with equal content and collapsing versions that are stale
against each other, which yield no further copies, so no more writes follow: the process
terminates. A copy that the user later deletes stays deleted (a record with that id exists,
so it is not materialised again).

Conflict copies show a badge in the item list; Watchtower gets a **Sync conflicts**
section; the item detail offers "Keep this version" (copies content into the original,
deletes the copy) and "Delete this copy", both ordinary syncing edits.

**Vaults.** A vault version carries name, icon, the wrapped vault key and `deleted`, so a
deleted vault still has everything needed to show or revive it. Visible version = sibling
with the highest `(hlc, author)`. If it is deleted but the fold holds live items in that
vault, the vault is shown live (with that version's name) and the Sync log says "'Work'
was kept: MacBook Air added items to it". All versions of one vault must carry the same
wrapped key until key rotation; a mismatch is an alarm.

**Attachments.** Created, moved (re-sealed under another vault key) or tombstoned; never
edited otherwise. A tombstone sibling wins.

**Purge and trash.** Moving to Recently Deleted and restoring are ordinary edits. Purge
(30 days after `deleted_at`, or "Delete permanently") writes a tombstone version. Every
device purges on its own schedule; concurrent purges are content-equal.

### 3.6 Formats

**Canonical encoding.** Deterministic CBOR (RFC 8949 §4.2.1: definite lengths, shortest
integers, map keys sorted by their encoded bytes), restricted to unsigned integers, byte and
text strings, arrays, maps, booleans and null. Decoding is strict: anything non-canonical
(longer heads, unsorted or duplicate keys, indefinite lengths, floats, tags, negative
integers) is rejected, so every value has exactly one encoding. Implemented as a small
codec in `keyorra-sync` rather than a crate (none is in the lockfile, and the common ones
neither guarantee canonical output nor reject non-canonical input). Everything that is
hashed, signed or authenticated is canonical CBOR. The `Item` JSON is carried as a CBOR byte string, so item serialisation
does not change.

**Record version (inline in a Put entry).**

```
Envelope  = { format: 1, kind, record_id, vault_id?, schema, version, tombstone: bool, body: bytes? }
body      = XChaCha20-Poly1305(vault_key, nonce, payload, body_aad)       // item, attachment; sealed output = nonce:24 ‖ ciphertext ‖ tag
body_aad  = "keyorra/sync/v1/body\0" ‖ account_id ‖ SHA-256(canonical(Envelope with body = null))
```

For `vault` records the payload is inline (protected by the segment layer; the vault key
inside is wrapped by AK as today). `body_aad` binds the ciphertext to kind, ids, vault,
schema and full version: a body cannot be moved to another record, vault or version, even
by a holder of only the vault key.

**Attachment chunks** (the only per-object blobs):

```
chunk      = "KYC1" ‖ XChaCha20-Poly1305(att_key, nonce, pad(bytes), chunk_aad)   // sealed output starts with the nonce
chunk_aad  = "keyorra/sync/v1/chunk\0" ‖ account_id ‖ attachment_id ‖ index:u32 ‖ count:u32
name       = hex SHA-256(chunk)
```

Chunks are ≤ 4 MiB of plaintext. Because the attachment key lives in the small attachment
record (sealed with the vault key), moving an item to another vault or making a conflict
copy rewrites only that record; chunks are never re-uploaded.

**Padding** (`pad`): append `0x80`, then zeros up to the Padmé length (at most ~12%
overhead), minimum 1 KiB. Applied to segment plaintexts, snapshot plaintexts and chunks.

**Forward compatibility.** `format` and `schema` are inside the authenticated data. A
device that meets a higher `format` or `schema` keeps the version in the fold, does not
write to that record, and shows "Update Keyorra to see N items". `Item` gains
`#[serde(flatten)] extra` so an older app never drops fields a newer one wrote.

## 4. Streams, trust and integrity

### 4.1 Entries and segments

Each device appends only to its own **stream**. Entries:

```
Put        { envelope }                                      // a record version, inline
Checkpoint { heads: {DeviceId -> (seq, hash)}, header_epoch }  // first entry of every segment
Genesis    { account_id, device_pk }                         // root device only, seq 1
Endorse    { device_id, device_pk, statement_sig }           // by a live device (§4.3)
SelfJoin   { device_pk, statement_sig }                      // Emergency-Kit join, own stream
Revoke     { device_id, last_valid_seq, reason }
Retire     { }                                               // this device id is done (§4.2)
Header     { header }                                        // account header (§4.7)
Snapshot   { name, sha256, frontier }                        // chains snapshots into the log
Moved      { sealed new location }                           // phase B2 (§7.5)

chain_0 = SHA-256("keyorra/sync/v1/chain-genesis\0" ‖ account_id ‖ device_id)
chain_n = SHA-256("keyorra/sync/v1/chain\0" ‖ chain_{n-1} ‖ canonical(entry_n))
```

```
segment = "KYS1" ‖ collection:u8 ‖ device_id:16 ‖ first_seq:u64 ‖ last_seq:u64
          ‖ prev_hash:32 ‖ last_hash:32
          ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical({entries, sig})), aad = header ‖ nonce)
          // the sealed output starts with the 24-byte nonce (no separate nonce field)
sig     = Ed25519(device_sk, "keyorra/sync/v1/segment\0" ‖ all plaintext header bytes ‖ canonical(entries))
```

The plaintext header carries only random ids, counters and hashes, so a server can enforce
"append-only, contiguous, chained" per stream without reading anything. A sync round
writes one segment; segments are capped at 4 MiB of plaintext (a large import becomes
several).

### 4.2 Device identity, and cloned or restored Macs

A device has a random `device_id` and an Ed25519 key pair. The private key lives in the
macOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (through the existing
`Keyring` abstraction), so it does not travel with Time Machine restores, Migration
Assistant or a copied home directory, while the SQLite database does.

Before **every** append the device compares its local head of its own stream with the
remote head:

| Situation | Meaning | Action |
|---|---|---|
| equal | normal | append |
| remote behind local | rollback of the store (§4.5) | alarm, offer restore |
| remote ahead, or same seq with another hash | another copy of this device (clone, restored backup) wrote to the stream | **retire**: never write with this id again |
| device key missing from the Keychain | database restored or copied to another Mac | **retire** |

Retiring: local unsynced edits are kept in the outbox; the device generates a new id and
key and rejoins (§7.3: approval by a live device, or self-join with alarm); its first
entries are `Revoke {old id, last_valid_seq = last remote head}` (if the old id is still
live) and then the queued edits as new versions. Nothing written under the old id after
the cut is accepted.

### 4.3 Endorsement and liveness

- The **root** is the first device: its stream starts with `Genesis`, and every account
  header names `root_device`.
- **Endorse**: an approving device writes `Endorse {device_id, device_pk, statement_sig}`
  with `statement_sig = Ed25519(approver_sk, "keyorra/sync/v1/endorse\0" ‖ account_id ‖
  device_id ‖ device_pk)`. The same signature is what the server checks when a device is
  approved (§6.4): server approval and log endorsement are one act.
- **SelfJoin**: a device that joins with the Emergency Kit and no approver writes
  `SelfJoin` as the first entry of its own stream, signed by itself. It proves knowledge
  of AK (the segment is sealed with `K_seg`) and nothing more. Every other live device
  shows a red alarm: "New device 'MacBook Air' joined with the Emergency Kit and was not
  approved by any of your devices. If this wasn't you: Remove it and rotate keys." The user
  can mark it as expected, which writes an `Endorse` for it.
- **Live**: a device is live if it is the root or has an accepted `Endorse`/`SelfJoin`,
  and no accepted `Revoke` names it. An endorsement made before the endorser's revocation
  cut stays valid (revoking one device does not cascade).

Stated plainly, in the protocol doc and in the UI: every device holds AK. Endorsements and
signatures let devices attribute changes and reject *writes* from revoked or unendorsed
devices; they cannot stop anyone who holds AK from *reading* data they can reach. Real
lock-out needs key rotation (C1).

### 4.4 Acceptance rule

An entry `e` at position `(D, seq)` is **accepted** iff:

1. its segment verifies: shape, AEAD under `K_seg`, chain linkage from the previous
   accepted head (or a snapshot frontier, §4.8), Ed25519 signature with D's key;
2. D's introduction (`Genesis`, `Endorse` or `SelfJoin`) is accepted;
3. if D is revoked, `seq ≤ last_valid_seq` of the earliest accepted revocation of D;
4. **causal delivery**: the heads in the segment's leading `Checkpoint` (what D had
   applied when it wrote these entries) are already applied locally. Segments that are
   not yet deliverable are buffered; references that cannot be resolved yet (an
   attachment record whose item has not arrived, a chunk still `Pending`) are buffered too;
5. the validations of §3.3 pass for every `Put`.

When a `Revoke` is accepted, the records with versions from the revoked stream after its
cut are **re-folded** from the retained versions (§3.4). A segment that cannot be
delivered for 24 h produces a warning naming the device whose changes are missing.

### 4.5 Rollback, fork and withholding detection

For every stream a device stores the newest accepted `(seq, hash)` (`sync_heads`) and the
heads that other devices' checkpoints claim to have seen.

| Attack by folder/server | Detected by | Reaction |
|---|---|---|
| Tamper with a segment, snapshot, header or chunk | AEAD, signature, chunk hash | Ignore, red Sync log entry |
| Inject versions or devices | Needs AK **and** a live device key | Impossible without them |
| Replay an old version as current | Version vectors + `body_aad` | Dominated, no effect |
| Roll a stream back | Head regression vs `sync_heads` | Sync paused, alarm |
| Fork (different segment n to different readers) | Same seq, other hash, seen directly or via a checkpoint | Sync paused, alarm |
| Withhold a stream | Checkpoints claim heads we cannot fetch; causal buffer stalls | Warning after 24 h, names the device |
| Roll back the account header | Epoch regression | Ignored, warning |
| Restore an old copy of a device's database | Own-stream check before append (§4.2) | Device retires and rejoins |

Alarm UI: sync pauses with a plain explanation and two actions: **Restore from this Mac**
and **Stop syncing**. Nothing is silently "fixed".

**Restore** (after a rollback): the device publishes a fresh snapshot (§4.8) of its full
fold with its frontier (including its own stream at the local head), then continues its
stream with new entries. Readers that lack the rolled-back segments accept the snapshot
(signed by a live device) as the anchor for every stream it covers and continue from
there. Other devices whose own streams were rolled back do the same when they notice.

Limits, documented: a device that never saw the newer state cannot detect a rollback (a
fresh device joining a folder restored from an old backup). Two devices can be kept on
forked views only while every exchange between them passes through the hostile store; the
first honest crossing exposes it. Withholding cannot be prevented, only reported.

### 4.6 Revocation

`Revoke {device_id, last_valid_seq}` by any live device; `last_valid_seq` is the newest
head of that device the revoker has seen. Entries after the cut are not accepted; affected
records are re-folded. The server additionally disables the device's token. If two devices
revoke each other concurrently, both revocations apply and the user gets an alarm pointing
to key rotation (rare; deliberately not automated).

### 4.7 Account headers

A joining device needs the wrapped AK before it has any key, so headers are also published
as standalone files, but they count only as signed log entries:

```
Header       = { keyorra_sync: 1, account_id, epoch: u32, generation: u32, root_device,
                 kdf, salt, secret_key_id, wrapped_account_key }
wrapped_account_key = seal(KEK_sync, AK, "keyorra/sync/v1/account-key\0" ‖ SHA-256(canonical(header with empty wrapped_account_key)))
                      // binds account_id, epoch, generation, root_device, kdf, salt and secret_key_id
header file  = canonical({ header, author: DeviceId, sig })     // named <epoch:08x>-<author hex>.hdr
sig          = Ed25519(author_sk, "keyorra/sync/v1/header\0" ‖ author ‖ canonical(header))
```

- The same `Header` must appear as an accepted `Header` entry in the author's stream; a
  header file without that is ignored after unlock and reported.
- **Joining** uses only the highest epoch present. If several files share it, they are
  tried in ascending author order. There is no fallback to lower epochs, even if the
  password fails: an old password must not open the account. (Consequence: someone with
  write access to the folder can block joining by planting a bogus high epoch; they can
  block sync anyway by deleting files. The error says "wrong password, or the account
  header was tampered with".)
- **Concurrent changes** of the same epoch on two devices: the accepted entry with the
  higher `(hlc, author)` wins; the other device is told its password change lost and the
  password set on the other Mac is now the current one for new devices.
- **KDF bounds** for remote headers, checked before running Argon2: m ≤ 1 GiB, t ≤ 10,
  p ≤ 4 (stricter than the local 4 GiB bound).
- **Cleanup**: once the checkpoints of every live device report `header_epoch ≥ n`, any
  device deletes header files with epoch < n. This is the one deletion phase A performs,
  because an old header still opens the account with the old password.

### 4.8 Snapshots

A snapshot is a self-contained pack: `{account_id, author, frontier: {D -> (seq, hash)},
floor: {D -> seq}, devices (introductions, endorsements, revocations with their original
signatures), current header, every sibling set (envelopes inline)}`, signed by the author
(`keyorra/sync/v1/snapshot`), sealed with `K_seg`, padded, and referenced by a `Snapshot`
entry in the author's stream so snapshots are themselves chained.
Framing: `"KYP1" ‖ collection:u8 ‖ author:16 ‖ XChaCha20-Poly1305(K_seg, nonce,
pad(canonical({body, sig})), aad = header ‖ nonce)`, `sig = Ed25519(author_sk,
"keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body))`; the name is the SHA-256 of the
bytes.

- Written after ~500 new entries or 7 days, after a restore, and after accepting a Revoke.
- **Bootstrap**: a joining device takes the newest snapshot that verifies against a live
  device and whose frontier respects every revocation cut it later learns of (otherwise it
  falls back to an older snapshot or one written after the revocation), then reads all
  segments after the frontier.
- `floor` is the per-stream point below which segments are no longer needed by this
  snapshot. Phase A records it but deletes nothing except a device's own snapshots older
  than its newest two. Real GC (segments, chunks, revoked devices' data, tombstones) is
  part of C1.

## 5. Folder transport (phase A)

### 5.1 Layout

```
Keyorra/
  README-KEYORRA.txt                 plaintext: what this folder is, "don't edit", link to the protocol doc
  account/<epoch:08x>-<device>.hdr   account headers
  streams/<device hex>/<first_seq:016x>.seg
  snapshots/<device hex>/<sha256 hex>.snap
  chunks/<2 hex>/<64 hex>            attachment chunks, 256-way fan-out
  join/<random>.<step>               approval messages of §6.4 (write-once, one file per step,
                                     deleted by the joining device when done or after 1 hour)
```

Readers count a file only if its name matches the exact pattern of its directory and its
content verifies. Everything else is ignored and listed as "unknown files" on the Sync
screen. Since every Keyorra file is write-once and written by one device, this makes the
transport immune to sync-client conflict copies (`x (1).seg`, `x (conflicted copy …)`),
torn files (treated as `Pending`, reported if still broken after 24 h), reordering
(buffered, §4.4) and user-deleted files (`Missing`).

### 5.2 iCloud Drive and File Provider folders

- Before reading any file, the transport checks its download state:
  `NSURLUbiquitousItemDownloadingStatusKey` for iCloud Drive and for File Provider domains
  (Dropbox, OneDrive, Google Drive under `~/Library/CloudStorage`), plus `SF_DATALESS` in
  `st_flags`. A file that is not downloaded is never opened (opening a dataless file can
  block for minutes): the transport calls `startDownloadingUbiquitousItemAtURL` (or the
  File Provider equivalent) and returns `Pending`. An iCloud placeholder `.X.icloud` means
  "X exists, Pending". No dependency on `brctl`.
- Reads and writes in these folders go through `NSFileCoordinator` (via `objc2`).
- The Sync screen recommends "Keep Downloaded" for the folder; it works without it.
- The iPhone app (later) reaches the same folder through the Files picker and a
  security-scoped bookmark.

### 5.3 Writing

1. Write the file into a temp directory **outside the synced tree on the same volume**:
   `~/Library/Application Support/app.keyorra.mac/sync-tmp/` (checked by comparing
   `st_dev`). If the folder is on another volume (external disk, network share), use
   `<folder>/.keyorra-tmp.nosync/` instead (`.nosync` is skipped by iCloud; other clients
   may upload it, and readers ignore it).
2. `fsync`, then `rename` into the final name (atomic), `fsync` the directory.
3. Chunks first, then the segment; a snapshot before the segment that references it.

### 5.4 Noticing changes

FSEvents (`notify`) on the folder, debounced 2 s; plus a poll every 60 s while unlocked,
and on unlock, wake and "Sync now". Streams are read from the known head; chunks are
fetched by name; no directory is listed in full on every round.

### 5.5 What someone with folder access learns

Can see: the number of devices (stream directories), the number, timing (mtimes) and
Padmé-bucketed sizes of segments (roughly how much changed per sync round), snapshot sizes
(roughly the size of the whole account), the number and bucketed sizes of attachment
chunks (roughly how many attachments of which size), the KDF parameters, the salt and the
Secret Key id (random, independent of the key). Cannot see: item or vault counts, which
changes were edits or deletions, names, URLs, device names, who edited what. The provider
also sees the IP addresses and cloud account that sync the folder; that is outside
Keyorra.

## 6. Server (phase B)

### 6.1 Shape

`keyorra-server`: one binary, `axum` + `tokio`, `rustls`, `rusqlite` (bundled), `tracing`.
Data directory (`/var/lib/keyorra`, or the Docker volume `/data`):

```
keyorra.db       SQLite: accounts, devices, segments, snapshots, headers, chunk metadata,
                 invites, per-account change cursors, audit of admin actions
blobs/<account>/<2>/<64>   chunks, keyed by (account_id, sha256)
server.toml      optional; env vars KEYORRA_* override
server.secret    32 random bytes, created on init (fake login params, §6.5)
```

The server holds no key that decrypts anything; it stores what a folder would hold, plus
authentication data.

### 6.2 Scope

Single owner plus invites (decided). The schema is multi-account from day one (every row
has `account_id`, chunks are namespaced per account) because sharing later needs it.
`keyorra-server init` prints a one-time invite for the owner; `invite create` makes more.
No open registration. Quota per account (default 1 GiB).

### 6.3 Authentication

The client derives `AUTH` (§3.2) from the master password, the Secret Key and the account
id; the server stores `SHA-256(AUTH)` and compares in constant time.

Why not SRP or OPAQUE:

- They exist to stop the server (or a leak of its database) from mounting an offline
  dictionary attack on the password. `AUTH` contains the 128-bit Secret Key, so its hash is
  not brute-forceable whatever the password.
- The server must hold the wrapped AK anyway (new devices download it), which is already an
  offline target of exactly the same strength. A PAKE would guard a door next to an open
  window.
- A PAKE adds a protocol, a younger crate (`opaque-ke`) and more to audit and re-implement
  on iOS, for no gain here. This argument depends on the Secret Key being mandatory, which
  the user decided.
- `AUTH` and `KEK_sync` are separate HKDF outputs; the server never learns anything that
  unwraps AK.

Residual risk, documented: pointing a client at a malicious server hands that server
`AUTH`, which lets it log in to the real server as the user. It still needs approval
(§6.4) and still cannot read anything.

**Device tokens.** Login exchanges `AUTH` + the device's Ed25519 public key for a random
256-bit token (stored hashed), sent as `Authorization: Bearer`. Tokens are independent of
the password: a master password change does **not** rotate them; only revocation ends a
token. Replacing the stored `SHA-256(AUTH)` (password change) requires a valid device
token **and** the current `AUTH`.

### 6.4 Device approval

The first device of an account is approved on creation. A later login creates a
**pending** device that can only read its own status. Approval is a short-authentication-
string exchange with commitments, so neither side (nor a server in the middle) can choose
its randomness after seeing the other's:

1. New device N, at login: picks `r_N` (32 bytes), sends `pk_N` and
   `c_N = SHA-256("keyorra/sync/v1/approve-commit\0" ‖ account_id ‖ pk_N ‖ r_N)`.
2. Approver A sees the pending device (name, `pk_N`, `c_N`), picks `r_A`, posts it.
3. N, only after receiving `r_A`, reveals `r_N`. A checks it against `c_N`.
4. Both display `code = BE-u32(SHA-256("keyorra/sync/v1/approve-code\0" ‖ account_id ‖ pk_N
   ‖ pk_A ‖ r_N ‖ r_A)[0..4]) mod 10^6`. The user confirms the codes match on A.
5. A posts `statement_sig` (§4.3); the server verifies it against A's registered key and
   activates N's token; A writes the matching `Endorse` entry in its stream.

A server substituting its own key for `pk_N` must commit before seeing `r_A`, so each
attempt matches with probability 10⁻⁶, and every attempt is a visible pending device. At
most 5 pending devices per account at a time; more are refused until the user approves or
denies. With no other device available, `keyorra-server device approve <id>` activates the
token, and the device writes `SelfJoin` (alarm on every other device, §4.3).

### 6.5 API (v1)

JSON bodies, except segment/snapshot/chunk bytes (`application/octet-stream`); max body
8 MiB.

| Method & path | Who | Purpose |
|---|---|---|
| `POST /v1/accounts` | invite | create account: id, first header, `SHA-256(AUTH)`, root device |
| `GET /v1/accounts/{id}/login-params` | anyone | salt, kdf, secret_key_id. Unknown ids get fake params derived as `HMAC-SHA256(server.secret, account_id)`, stable and indistinguishable |
| `POST /v1/accounts/{id}/login` | anyone | `AUTH`, `pk`, `c_N` → token (pending or approved) |
| `PUT /v1/auth` | device + current `AUTH` | replace `SHA-256(AUTH)` |
| `GET /v1/devices`, `POST /v1/devices/{id}/approval` (steps 2–5), `DELETE /v1/devices/{id}` | device | list, approve, revoke |
| `GET/PUT /v1/headers[/{name}]`, `DELETE` older epochs | device | account headers |
| `POST /v1/streams/{device}/segments` | that device | append; `409` with the current head if `prev_hash` ≠ head or seq not contiguous |
| `GET /v1/changes?cursor=N` | device | segments, snapshots, headers since a **per-account** cursor |
| `GET/PUT /v1/snapshots/{name}`, `DELETE` own | device | snapshots |
| `GET/PUT /v1/chunks/{sha256}` | device | server verifies the hash on PUT |
| `GET /v1/events` | device | Server-Sent Events: `changed {cursor}` |
| `GET /v1/listing` | device | everything stored for this account (§9.2) |
| `GET /healthz`, `/readyz` | anyone | liveness/readiness, no data |

Push uses SSE: one-way is all that is needed, it passes every reverse proxy, and clients
reconnect automatically. Clients also poll `/v1/changes` every 5 minutes. The iPhone
(later) uses background app refresh.

### 6.6 TLS

`[tls] mode =`
- `"files"`: certificate and key paths, reloaded on SIGHUP.
- `"self-signed"`: generated on first start; the server prints its SPKI SHA-256
  fingerprint, which the setup code carries and the client pins. For home servers without
  a domain.
- `"off"`: plain HTTP, only with `behind_proxy = true`; for running behind Caddy, nginx or
  Traefik, which handle certificates (including automatic Let's Encrypt). The server warns
  on every start in this mode.

Built-in ACME is not offered: it needs port 443 or 80 on the server itself, which clashes
with the common reverse-proxy setups, and a proxy already does it well. Clients refuse
`http://` except for `localhost`; the pinned fingerprint is shown on the Sync screen.

### 6.7 Abuse limits

- `login-params` and `login`: token bucket **per IP** (10/min, burst 20). No per-account
  lockout: `AUTH` cannot be guessed, and a lockout would only let a stranger lock the owner
  out.
- Authenticated requests: per-device rate limit (20 req/s, burst 100), per-account quota,
  body size cap, idle timeouts, SSE connections per account capped.

### 6.8 Backups and restore

Everything on the server is ciphertext or a hash, so backups can live anywhere.

- `keyorra-server backup <file.tar.zst>`: SQLite online backup API + blobs, consistent
  while running; or stop the service and copy the data directory.
- `keyorra-server restore <file>`: into an empty data directory.
- Restoring an old backup is a rollback. Devices detect it (§4.5) and offer "Restore from
  this Mac", which publishes a fresh snapshot. The self-hosting doc says this alarm is
  expected after a restore.
- `keyorra-server check`: verifies chunk hashes, stream contiguity and chain linkage (all
  checkable from plaintext headers) without any key.

### 6.9 Observability

`tracing`, JSON or pretty. Per request: request id, route template (not the raw path),
status, duration, account id shortened to 8 hex characters. Never logged: bodies,
`Authorization`, `AUTH`, tokens, full chunk names, and IP addresses unless `log_ips = true`
(off by default). No metrics endpoint in v1.

### 6.10 Admin CLI

`keyorra-server serve | init | invite create | account list | account delete <id> |
device list <account> | device approve <id> | device revoke <id> | backup | restore |
check | healthcheck | version`. Admin actions go to the `audit` table and are shown to the
account owner in the app ("Device revoked by the server admin on …").

## 7. Local changes and flows

### 7.1 Store migration v2

```
sync_config   one row: account_id, transport, location, state, root_device
sync_versions every accepted version: kind, id, vector, hlc, author, stream position,
              ciphertext (dominated ones kept 90 days, §3.4)
sync_heads    per stream: seq, hash, last_seen_hlc, claimed heads from checkpoints
sync_devices  device_id, name, pk, introduced_by, live/revoked, cut
sync_outbox   record kind, id, queued_at
sync_log      at, level, text (last 1000 events; local and encrypted like everything else)
```

**Single change path.** Every mutating `Store` method (`save_item`, `delete_item`,
`restore_item`, `purge_expired`, attachment add/remove, vault create/rename/delete,
`apply_import`) calls one private function, `record_change(tx, RecordRef)`, inside its
transaction; it enqueues into `sync_outbox` when sync is on. A test asserts that each
public mutating method produces an outbox row.

The Ed25519 device key is in the Keychain (§4.2). The Secret Key is sealed under AK in
`sealed_meta("sync-secret-key")`.

### 7.2 Enabling sync (first device)

1. Choose transport: a folder (iCloud Drive suggested) that is empty or new, or a server
   URL plus invite.
2. Re-enter the master password.
3. Generate `account_id`, Secret Key, Secret Key id, device id and key.
4. Emergency Kit (§7.6). The user confirms by typing the last 4 characters of the Secret
   Key.
5. Write `Genesis`, header epoch 1, every vault, item and attachment as versions
   `{this_device: 1}`, then a snapshot. Progress bar; the vault stays usable.

### 7.3 Joining (another Mac)

1. "Join a synced account": pick the folder or enter the server URL, then paste the
   **setup code** (`KY1-<account_id>-<secret key>[-<pin>]`) shown by a device that is
   already set up, or type account id and Secret Key from the Emergency Kit.
2. Master password → `KEK_sync` → AK from the highest-epoch header (§4.7).
3. Approval: with another live device available, the commitment exchange of §6.4 runs
   through the transport (server) or through `join/` request files in the folder (same
   messages, same code). Without one: SelfJoin with alarm.
4. Local data:
   - no local vault → build it from the fold; a local header is created from the same
     master password with a fresh salt;
   - a local vault of a **different** account → **Merge** (default: re-encrypted under the
     synced keys as new records; Watchtower's duplicate check helps afterwards) or
     **Replace**;
   - a local vault of the **same** account (it left sync earlier, or is rejoining after
     retirement) → merged **by record id**: a record with the same content as the fold
     writes nothing; one that differs is written as a new version by the new device
     (concurrent with the remote ones, so it shows up as a conflict copy if it really
     differs). No duplicates.
   Either way the old database is kept as `keyorra.db.pre-sync-YYYYMMDD` until the user
   deletes it in Settings.

### 7.4 Leaving

- **Turn off sync on this Mac**: writes a self-`Revoke`, keeps the local vault as a normal
  local vault, drops the sync tables except the record ids (so a later rejoin merges by
  id).
- **Delete synced data**: offered only on the last live device, after typing the account
  id. Folder: removes the Keyorra folder contents. Server: deletes the account.

### 7.5 Switching transport (phase B2)

The device publishes its full fold as a snapshot to the new transport (same account id,
keys and device ids; streams continue from that snapshot as anchor), then appends
`Moved { new location sealed with K_seg }` to its stream in the old one. Other devices
show "This account moved to https://vault.example.com. Switch now?" and follow after
confirmation (server: login + approval). Not in phase A.

### 7.6 Secret Key and Emergency Kit

**Decided: required for sync.** 128 random bits, shown as `<id>-XXXXX-XXXXX-XXXXX-XXXXX-
XXXXX-XC`: 26 Crockford base32 digits carry the 128 bits (big-endian; the first digit is
at most 7) and one Crockford check character (the key as an integer mod 37) follows;
parsing ignores case and hyphens and reads I/L as 1 and O as 0.
The 4-character `id` is separate random data, not derived from the key, so publishing it
in the header reveals nothing.

Why: with sync, the wrapped AK sits with a cloud provider or on a VPS, where it can leak in
ways a local disk does not. With the Secret Key, a leaked folder or server database is
useless without a device or the Emergency Kit. Cost: one more thing to keep, and data loss
if all devices and the kit are lost; the app says so at setup.

Where it is used: only in the synced header (`KEK_sync`, `AUTH`). The local header stays
password-only (format 1, unchanged), so unlocking a Mac never depends on the Keychain or
the kit, and a stolen Mac is protected exactly as today.

**Emergency Kit**: account id, Secret Key, location, a blank line for the master password.
"Print" is the primary action. "Save as PDF" is secondary and warns, at the save dialog
and again if the chosen path is inside iCloud Drive, `~/Library/CloudStorage`, Dropbox or
the sync folder, that a kit stored next to the encrypted data defeats its purpose.

**Setup code** on the clipboard: written with the `org.nspasteboard.ConcealedType` and
`TransientType` markers (clipboard managers skip it) and cleared after 90 s like other
secrets. Shown only after re-entering the master password.

## 8. Key changes

### 8.1 Master password change

On device A: re-wrap AK in the local header (as today), write header epoch `n+1` (new salt,
same AK and Secret Key) as a `Header` entry and file, and replace `SHA-256(AUTH)` on the
server (§6.3). Device tokens stay valid. Other devices adopt the new header after checking
its entry, keep accepting the old password locally until the user unlocks with the new one
(the Sync screen says "Master password changed on MacBook Pro"), and then re-wrap their
local header. Touch ID keeps working (AK did not change). Old header files are deleted per
§4.7.

Stated limit: a password change does not lock out someone who already has the old
password, the Secret Key and a copy of the folder. That takes key rotation.

### 8.2 Vault deletion

A vault version with `deleted = true` that still carries name, icon and wrapped key (§3.5);
items inside are purged first, as today. Concurrent additions undo it.

### 8.3 Device removal

Sync screen → device → **Remove**: writes `Revoke`, disables the server token. The dialog
says what it does and does not do (§4.3) and, once C1 exists, offers **Remove and rotate
keys**.

### 8.4 Key rotation (C1, after phase B — decided)

New AK, new vault keys, optionally a new Secret Key; every live record re-written into a
new `generation`; header epoch bumps; the old generation is garbage-collected once every
live device has moved. Other devices need the master password on their next unlock (Touch
ID records become invalid), and the new setup code if the Secret Key changed. A revoked
device keeps what it had but cannot read anything written afterwards. The `generation`
field exists in v1 so no format change is needed.

### 8.5 Touch ID

Unchanged and per device; never synced.

## 9. Transparency

### 9.1 Sync screen (Settings → Sync)

- **Status**: Up to date · Syncing · Paused: locked · Waiting for iCloud to download 3
  files · Waiting for changes from MacBook Air · Offline · Alarm (red, with explanation
  and actions).
- **Last sync** and "Sync now".
- **Location**: folder path with "Show in Finder", or server URL with TLS mode and pinned
  fingerprint; "Keep Downloaded" hint for iCloud.
- **This device**: name (editable), device id, key fingerprint.
- **Devices**: name, introduced by (or "Emergency Kit"), last seen (newest checkpoint),
  status (live, pending, revoked, retired); Remove; Approve.
- **Conflicts**: count and list linking to the copies.
- **What the folder/server sees** (§9.2).
- **Sync log**: last 1000 events: pulled 5 changes from MacBook Air, pushed 2, kept 'GitHub'
  after a concurrent delete, conflict copy created, clock skew, waiting for files, alarms.
  Item titles appear only in this local encrypted log, never on the wire.
- **Verify everything**: re-reads all streams, snapshots, headers and chunks, checks
  hashes, signatures, chains and endorsements, and re-folds to confirm the local state
  equals the fold. Per-file results.
- **Emergency Kit / setup code** (after re-entering the master password).

### 9.2 "What the folder/server sees"

An in-app table of every file or blob for this account exactly as stored: name, kind as
visible from outside (header, segment, snapshot, chunk, unknown), size, created time, and
for segments the plaintext header fields. Next to it, one paragraph on what each column
reveals (§5.5). Export to CSV/zip is left out of v1.

### 9.3 Public protocol and test vectors

- `docs/sync-protocol.md`: normative description of keys, labels, canonical CBOR, padding,
  envelopes, chunks, segments, snapshots, headers, entries, the acceptance rule, the fold
  and presentation rules, endorsement, the folder layout and the server API. Versioned; any
  wire change updates it in the same commit.
- `docs/sync-test-vectors/*.json`: fixed password, Secret Key, account id, AK, nonces and
  device keys → expected `KEK_sync`, `AUTH`, `K_seg`, envelope, chunk, segment, header and
  snapshot bytes, chain hashes, version hashes, conflict-copy ids, approval codes, and fold
  results for scripted scenarios. `keyorra-sync` tests load them with an injected RNG.
- `keyorra-inspect` (example binary): given a folder, the master password and the Secret
  Key, it verifies and dumps everything readably, so an auditor can check the protocol
  without the app.

### 9.4 Threat model

| Adversary | Can | Cannot | Notes |
|---|---|---|---|
| Passive folder/provider reader | See device count, segment/snapshot/chunk counts, bucketed sizes, timing, KDF params, salt, Secret Key id | Read anything; brute-force the password offline (needs Secret Key) | §5.5 |
| Active folder writer | Delete, withhold, restore old files, show devices different files, block joining with a bogus header | Inject or alter data; roll back or fork unnoticed by a device that saw newer state | §4.5, §4.7 |
| Malicious server operator | As active writer; see IPs, timing, account id, `SHA-256(AUTH)`; learn `AUTH` at login | Read data; unwrap AK; add a device without winning a 10⁻⁶ code match the user sees | §6.3, §6.4 |
| Server database/backup leak | Get ciphertext, headers, token hashes | Anything useful | |
| Network attacker | Block traffic | Read/alter (TLS; pinning for self-signed) | |
| Stolen locked Mac | Get the local database | Unlock without the master password (Argon2 as today); use its device key (Keychain, this device only) | |
| Restored/cloned Mac database | Hold an old copy | Write under the old device id | §4.2 |
| Stolen unlocked Mac / malware | Everything that device can see | — | Remove device, rotate keys (C1) |
| Holder of AK + Secret Key + password (e.g. Emergency Kit thief) | Read everything they can reach; self-join | Join silently: every device raises an alarm | §4.3 |
| Revoked device | Read data it can still reach until rotation | Have new writes accepted; use the server | §4.6 |
| Lost all devices **and** the Emergency Kit | — | — | Unrecoverable; stated at setup |
| Older app version | Read records of its format | Damage newer records (read-only on them, unknown fields kept) | §3.6 |
| Clock skew | Make its edits win concurrent conflicts | Lose an edit (loser kept as copy); push others' clocks forward | §3.3 |

## 10. Browser extensions and other clients

Unaffected. The extensions talk only to the local app over the existing bridge; synced
items appear once merged, and logins saved from the browser are local edits that sync like
any other. Browser pairings stay per device.

The iPhone app (roadmap 2) uses the same `keyorra-sync` crate (via UniFFI), both
transports (folder through the Files picker; server over HTTPS) and the same join flow
(setup code scanned with the camera). Its AutoFill extension reads the local store; sync
runs in the app and in background refresh.

## 11. Testing strategy

TDD as in the MVP. In order of importance:

1. **Formats and crypto**: test vectors; every AAD and signature component matters;
   tampering any byte fails; bodies cannot move between records, vaults or versions;
   canonical CBOR is byte-stable; padding round-trips; remote KDF bounds enforced before
   Argon2.
2. **Fold and presentation**: one test per rule of §3.4–3.5 (including edit+trash vs edit,
   purge vs edit, vault deletion undone); copy ids depend only on the sibling's version;
   materialisation terminates; forward compatibility.
3. **Streams and trust**: endorsement chains, SelfJoin alarm, revocation cut and re-fold,
   mutual revocation, causal buffering, version validation (§3.3), clock skew, header
   epochs (highest only, concurrent epochs, cleanup), clone detection and retirement,
   restore via snapshot.
4. **Engine against `MemoryTransport`**: 2, 3 and 5 simulated devices with injected
   clocks; offline periods; join, leave, rejoin by id.
5. **Fault-injecting transports**: drop, delay, duplicate, reorder, truncate, bit-flip,
   late `Pending`, `(1)` conflict-copy files, rollback of one stream, fork per reader,
   withheld streams, bogus header, crash between chunk upload and append, crash mid-fold.
6. **Property tests** (`proptest`): random edits/deletes/moves/purges/revocations on N
   devices with random delivery and faults. After full delivery: identical state on every
   device (convergence); the same state for any delivery order of the same accepted set;
   no written content lost (present as the item or a copy, unless superseded by a purge
   or a revocation cut); every detectable attack detected.
7. **Folder transport**: on a temp dir; plus a macOS-only, ignored-by-default suite on a
   real iCloud Drive folder (eviction forced with `brctl evict`, in tests only); dataless
   File Provider files never opened; temp files never appear in the synced tree. Dropbox
   as a manual checklist.
8. **Server**: in-process axum tests: auth, `AUTH` replacement rules, per-IP limits,
   approval exchange (commit/reveal order enforced), `409` on chain mismatch, per-account
   cursors, chunk namespacing, quotas, SSE, fake login params stable and indistinguishable,
   backup/restore/check round-trip, captured logs contain no secrets.
9. **Server transport**: suites 4–5 rerun against an in-process server.
10. **End to end**: two app instances (two data dirs, two Keychain namespaces) on one Mac
    sharing a temp folder, driven through Tauri commands: enable, join with approval, edit
    on both, conflict on both, resolve, remove device, clone a data dir and check that it
    retires. Same against a local server in Docker in CI.
11. **Store**: migration v2; single change path; leaving sync keeps a working vault.

## 12. Phasing

Each line becomes one implementation plan in `docs/superpowers/plans/`.

| Plan | Content | Done when |
|---|---|---|
| **A1a** Keys and formats | HKDF derivations, labels, canonical CBOR, Padmé, envelopes, chunks, segment/snapshot/header framing, test vectors, `docs/sync-protocol.md` draft | Suite 1 green; protocol draft reviewed |
| **A1b** Fold | Versions/HLC, validation, payloads, sibling sets, presentation, conflict copies and materialisation, the fold with an admission hook, a first engine (`Put` entries only, fixed device directory), `MemoryTransport`, fault-injecting transport, property tests | Suites 2, 4 (trust stubbed), 5 (transient faults), 6 green |
| **A1c** Streams and trust | Entry types, Keychain device key, endorsement, SelfJoin, revocation and re-fold, acceptance rule, causal delivery, headers, snapshots (bootstrap, restore), clone detection, rollback/fork faults | Suites 3, 5, 6 green |
| **A1d** Store integration | Store migration v2, single change path, `Item.extra` and the `conflict` field, the engine reading from and writing to the local store | Suite 11 green; a vault survives enable → edit → sync → restart |
| **A2** Folder transport | `keyorra-sync-fs`: layout, temp-outside-tree writes, strict reading, iCloud/File Provider download state, `NSFileCoordinator`, FSEvents + poll, deadlines, `keyorra-inspect` | Suite 7 green; two processes on one folder converge |
| **A3** UI | Enable/join/leave, Emergency Kit, setup code, folder-based approval, Sync screen, conflicts in list/detail/Watchtower, alarms | Suite 10 (folder) green; manual two-Mac iCloud test |
| **B1** Server | Schema, API, auth, approval exchange, SSE, limits, quotas, TLS modes, logs, admin CLI, backup/restore/check | Suite 8 green |
| **B2** Server transport | HTTP transport, login/approval UI, pinning, transport switch with `Moved` | Suite 9 + E2E against server green |
| **B3** Packaging | Multi-arch Docker image, static musl binaries, systemd unit, signed releases, `docs/self-hosting.md` | Image runs on amd64 and arm64 (Raspberry Pi) from the docs alone |
| **C1** Rotation + GC | Key rotation, generations, GC of segments/chunks/snapshots/tombstones and revoked devices' data by live devices using snapshot floors, 90-day inactive-device prompt | — |

Phase A ships without GC: storage grows with history; snapshots exist only for bootstrap
and restore, and only header files and a device's older snapshots are ever deleted.

### 12.1 B3 details

- **Docker**: multi-stage; build `x86_64`/`aarch64-unknown-linux-musl`; final stage
  `gcr.io/distroless/static-debian12:nonroot` (UID 65532); `VOLUME /data`;
  `EXPOSE 8443`; `HEALTHCHECK CMD ["/keyorra-server", "healthcheck"]`; works with a
  read-only root filesystem. Published to `ghcr.io/skensell201/keyorra-server` with cosign
  signatures and an SBOM. Docs include `docker-compose.yml` examples with Caddy in front
  and with a self-signed certificate.
- **Binary**: `keyorra-server-<version>-<arch>-linux-musl.tar.gz` on GitHub Releases with
  `SHA256SUMS` and a signature. Example unit:

```ini
[Unit]
Description=Keyorra sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/keyorra-server serve --config /etc/keyorra/server.toml
DynamicUser=yes
StateDirectory=keyorra
ConfigurationDirectory=keyorra
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
MemoryDenyWriteExecute=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

- **Config** (`server.toml`; each key also `KEYORRA_<SECTION>_<KEY>`):

```toml
data_dir = "/var/lib/keyorra"
bind = "0.0.0.0:8443"
public_url = "https://vault.example.com"
require_approval = true
quota_bytes = 1073741824

[tls]
mode = "files"                 # files | self-signed | off (requires behind_proxy)
cert = "/etc/keyorra/tls/fullchain.pem"
key = "/etc/keyorra/tls/privkey.pem"
# behind_proxy = true

[log]
format = "json"
log_ips = false
```

- `docs/self-hosting.md`: install (Docker, binary), TLS choices, first account, backups and
  the alarm a restore triggers, upgrades, reverse proxy examples (Caddy, nginx with SSE
  buffering off), what the server can and cannot see.

## 13. Decisions (user, 2026-10-05)

1. **Secret Key is required for sync.** No password-only synced accounts; hence no OPAQUE.
2. **A concurrent edit beats a delete** (§3.5), with the edit+trash case kept as a copy in
   Recently Deleted.
3. **Sync runs only while the app is unlocked.** Changes from other devices arrive at the
   next unlock; no key is kept for background sync while locked.
4. **Server: single owner plus invites**, no open registration.
5. **Key rotation comes after phase B** (C1, together with GC). Until then the UI states
   that removing a device stops its writes but not its reading of data it can reach.

## 14. Notes on the review

All review points are adopted. Where the spec goes beyond or slightly differs from the
review's wording:

- **Dominated versions "until GC"** (C3): with no GC in phase A, keeping every dominated
  version's ciphertext locally would grow without bound. The local index keeps every
  version; ciphertext of dominated versions is kept 90 days and re-fetched from the
  (never-collected) remote segments if a re-fold needs it.
- **Copy materialisation** (C2): the review fixes the copy ids; the spec adds *when* copies
  become real records (first observer writes them plus a collapsing version) and why that
  terminates.
- **Deletions in phase A**: despite "no GC in phase A", old header epochs are deleted (an
  old header opens the account with the old password) and a device prunes its own
  snapshots beyond the newest two (each is a full copy of the account).
- **Per-IP limits only** (I9) applies to login. The spec keeps one per-account bound: at
  most 5 pending devices, which caps code-guessing attempts in the approval exchange and is
  not a lockout of the owner's logins.
