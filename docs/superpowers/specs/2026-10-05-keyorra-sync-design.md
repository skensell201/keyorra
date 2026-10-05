# Keyorra Sync — Design

Date: 2026-10-05
Status: draft, awaiting review
Supersedes: nothing. Expands roadmap item 1 of `2026-10-02-lockbox-mvp-design.md`.

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
  adds push updates, device approval, and is the base for vault sharing later.

Two non-negotiables, set by the user:

1. **Secure.** A folder or a server only ever holds ciphertext. Whoever controls it can
   delete or withhold data, but cannot read it, cannot change it unnoticed, and cannot roll
   it back or fork it unnoticed by devices that saw a newer state.
2. **Transparent.** The user can see what is stored where, which devices take part, what
   happened during each sync, and what the folder or server can see. The protocol is a
   public document with test vectors, so anyone can audit or re-implement it.

### Non-goals (for this design)

- Sharing vaults between different people (roadmap 3). The format reserves room for it;
  nothing more.
- WebDAV and S3 transports (roadmap 1d). They fit the same transport trait later.
- Syncing per-device settings: Touch ID, browser pairings, auto-lock, window state. These
  stay local on purpose.
- Field-level automatic merging of concurrent edits. Conflicts keep both versions.

## Summary of decisions

| Topic | Decision |
|---|---|
| Unit of sync | One encrypted record per vault, item, attachment, device; account header separate |
| Concurrency | Version vector per record; hybrid logical clock (HLC) for a deterministic winner |
| Conflicts | Keep both: winner stays, loser becomes "X (conflict from <device>)"; deterministic, so all devices agree without talking |
| Storage layout | Immutable, content-addressed objects + per-device append-only, hash-chained, signed log segments. No file is ever modified, so no sync-client conflicts and no locks |
| Metadata | Everything but object sizes (padded), counts and timestamps is encrypted; file names are hashes or random ids |
| Secret Key | Yes, for synced accounts: a 128-bit Secret Key is mixed into the key that wraps the account key *in the folder/server*. The local vault keeps working with the master password alone |
| Server auth | Token derived from master password + Secret Key via a separate HKDF label; server stores only its hash. No SRP/OPAQUE (justified in §6.3) |
| Rollback / fork | Per-device hash chains, signed with a per-device Ed25519 key, plus cross-checkpoints of everyone's heads |
| Server | Rust, axum, SQLite + blob directory, multi-account capable, single-account by default |
| TLS | Built-in rustls: own cert, ACME (optional), or self-signed with a fingerprint pinned through the setup code; plain HTTP only behind an explicit reverse-proxy flag |
| Push | Server-Sent Events |
| Sync while locked | No. Sync runs only while the app is unlocked (see open questions) |

## 1. What exists today (grounding)

From `crates/keyorra-core`:

- `crypto::keys`: master password → Argon2id (64 MiB, t=3, p=1, 16-byte salt) → KEK; the
  KEK seals a random 32-byte **account key** in a `Header { format, kdf, salt,
  wrapped_account_key }` with AAD `lockbox/account-key/v1`. The account key wraps one random
  **vault key** per vault (AAD `lockbox/vault-key/v1\0 ‖ vault_id`).
- `crypto::aead`: XChaCha20-Poly1305, `nonce(24) ‖ ciphertext ‖ tag`.
- Items are sealed with their vault key, AAD `lockbox/item/v1\0 ‖ vault_id ‖ item_id ‖
  schema(be32)`; attachments with `lockbox/attachment/v1\0 ‖ vault_id ‖ item_id ‖ att_id`.
  Vault metadata (name) is sealed with the account key.
- `store`: SQLite tables `meta`, `vaults(id, wrapped_key, meta, revision, deleted)`,
  `items(id, vault_id, data, revision, updated_at, deleted_at, schema)`,
  `attachments(id, item_id, data, revision, deleted, schema)`. `revision` is a per-row
  counter. Item deletion is two-stage: `deleted_at` set (Recently Deleted, 30 days), then
  purge empties `data` and keeps the row as a tombstone. Vault deletion purges and keeps a
  tombstone row and the key. A row that fails to decrypt is shown as `Damaged`.
- `Store::sealed_meta` keeps small per-device secrets (browser pairings) sealed with the
  account key.
- `keyorra-session::touchid`: the account key wrapped to a Secure Enclave key, master
  password due every 14 days. Per device, never leaves it.

What sync can reuse: the key hierarchy (unchanged), tombstones, per-row revision (becomes
the local half of a version vector), `Damaged` handling, `sealed_meta`. What sync cannot
reuse as is: the local `revision` (a single counter cannot tell "newer" from "concurrent"),
and the at-rest blobs (their AAD binds no version, so a stale blob could be replayed as
current). Sync therefore defines its own wire format and converts at the boundary; the
local SQLite format stays the local format.

## 2. Architecture

```
crates/
  keyorra-core/      unchanged API + store migration v2 (sync tables, unknown-field keeping)
  keyorra-sync/      NEW: record format, engine, merge/conflict rules, Transport trait,
                     in-memory + fault-injecting transports, test vectors. No OS APIs.
  keyorra-sync-fs/   NEW: folder transport (std fs + notify; macOS iCloud bits behind cfg)
  keyorra-server/    NEW (phase B): axum server binary + admin CLI
  keyorra-session/   sync scheduling, Sync screen DTOs, enable/join/leave flows
app/src-tauri        commands, background sync thread, FSEvents/SSE wake-ups
app/src              Sync screen, onboarding, conflict UI
```

- The engine is synchronous and deterministic: given the local state, the transport's
  contents, a clock and an RNG (all injected), it produces the same result. Transports do
  the I/O; the server transport wraps its async HTTP client behind a blocking adapter on
  the sync thread.
- `keyorra-server` depends on `keyorra-sync` only for the framing types (segment header,
  object name rules) so it can validate shape. It never links code that could decrypt.
- One account syncs through exactly one transport at a time.

```rust
pub trait Transport {
    fn headers(&self) -> Result<Vec<RawHeader>>;                 // account headers by epoch
    fn put_header(&self, h: &RawHeader) -> Result<()>;
    fn streams(&self) -> Result<Vec<StreamInfo>>;                // one per device
    fn segments(&self, stream: DeviceId, from_seq: u64) -> Result<Vec<Fetched<RawSegment>>>;
    fn append(&self, seg: &RawSegment) -> Result<AppendOutcome>; // Ok | Conflict(head)
    fn snapshots(&self) -> Result<Vec<SnapshotInfo>>;
    fn put_snapshot(&self, s: &RawSnapshot) -> Result<()>;
    fn get_object(&self, name: &ObjectName) -> Result<Fetched<Vec<u8>>>;
    fn put_object(&self, name: &ObjectName, bytes: &[u8]) -> Result<()>;
    fn delete(&self, what: Garbage) -> Result<()>;               // own objects/segments only
    fn listing(&self) -> Result<Vec<RawEntry>>;                   // "what the transport sees"
}
pub enum Fetched<T> { Ready(T), Pending /* not downloaded yet */, Missing }
```

`Pending` is a first-class answer: an iCloud placeholder, a half-synced Dropbox file or a
segment that names an object not yet arrived all mean "try again later", never "error".

## 3. Sync model

### 3.1 What is synced

| Record kind | Content (plaintext, inside encryption) | Sealed with |
|---|---|---|
| `vault` | `VaultInfo` (name, icon) + the vault key wrapped by the account key (existing AAD) | object key |
| `item` | the `Item` JSON exactly as stored today + `deleted_at` | object key, then vault key |
| `attachment` | name, size, list of chunk object names | object key, then vault key |
| `chunk` | ≤ 4 MiB of attachment bytes | object key, then vault key |
| `device` | device id, name, model, Ed25519 public key, added at, added by | object key |

Plus, outside the record set:

- **Account header** (§3.6): KDF params, salt, the account key wrapped by the *sync KEK*
  (master password + Secret Key), epoch. Needed by a joining device before it has any key.
- **Log segments** and **snapshots** (§4): the ordering and integrity layer.

Not synced: Touch ID records, browser pairings (`sealed_meta`), the local `meta.header`,
settings, the sync state tables, the clipboard, Watchtower's HIBP cache.

### 3.2 Keys used by sync

All derived with HKDF-SHA256 from the account key `AK`, salt = `account_id` (16 random
bytes, fixed when sync is first enabled):

| Name | info label | Use |
|---|---|---|
| `K_obj` | `keyorra/sync/v1/object` | outer layer of every object |
| `K_seg` | `keyorra/sync/v1/segment` | log segments and snapshots |
| `K_hdr` | `keyorra/sync/v1/header-mac` | authenticates the account header |

Two layers for vault content (outer `K_obj`, inner vault key) look redundant for one user.
They exist so that the outer layer hides *everything* (kind, ids, vault, versions) from the
folder, while the inner layer keeps the property the MVP spec promises: vault content is
readable only with that vault's key. When vault sharing arrives, a shared vault's records
move to a collection whose outer key derives from the vault key; the format reserves a
`collection` byte for it (`0` = account collection, the only value in v1).

### 3.3 Versions: version vectors + HLC

Every record version carries:

```rust
struct Version {
    vector: BTreeMap<DeviceId, u64>, // how many writes of each device this version includes
    hlc: u64,                        // hybrid logical clock: 48-bit ms | 16-bit counter
    author: DeviceId,                // device that wrote this version
}
```

- **Write** on device D: `vector = merged_vector_seen_for_this_record; vector[D] += 1`;
  `hlc = max(wall_ms << 16, last_hlc + 1, max_hlc_seen + 1)`.
- **Compare** two versions a, b of one record: `a` dominates `b` if every entry of `a` ≥ the
  entry of `b` (missing = 0) and they differ. Neither dominates → **concurrent**.
- **Winner** among concurrent versions (deterministic, same on every device):
  higher `(hlc, author)` wins, compared as `(u64, 16 bytes)`. HLC follows wall time
  closely when clocks are sane ("the later edit wins", as a user expects) and still orders
  correctly when a clock is wrong.
- **Join** of versions: element-wise max of vectors, max of HLC.

Vectors stay small: one entry per device that ever edited the record (a person has a
handful of devices). Entries of revoked devices are never removed; they cost 24 bytes.

The local `revision` column stays as is (it drives local UI caching); the vector lives in
the new `sync_versions` table (§7.1).

### 3.4 Merge rules

Given the current local version `L` and an incoming version `R` of the same record:

1. `R` equal to or dominated by `L` → ignore.
2. `R` dominates `L` → apply `R`.
3. Concurrent → resolve by kind:

| Kind | Concurrent rule |
|---|---|
| `item` (both live, contents differ) | **Keep both.** Winner keeps the item id with version `join(L, R)`. Loser becomes a new item: id = `conflict_copy_id(record_id, loser)`, title `"<title> (conflict from <device name>)"`, `conflict = { of: record_id, from_device, at_hlc }`, same vault, version = loser's vector re-keyed to the copy id. |
| `item` (both live, contents equal) | No conflict; join. |
| `item`: edit vs trash (`deleted_at` set on one side) | **Edit wins**; item stays live with the edited content. Sync log: "Kept 'X': deleted on A, edited on B". |
| `item`: edit vs purge tombstone | Tombstone is final (ids never come back). The edit survives as a conflict copy, so no edit is lost. |
| `item`: tombstone vs tombstone / trash vs trash | Join; earliest `deleted_at` kept. |
| `vault` meta (rename) | Winner by `(hlc, author)`; loser name only in the sync log. |
| `vault` delete vs anything live inside it | A vault is deleted only if, after merging, it holds no live item. Otherwise the deletion is undone and logged ("'Work' was kept: MacBook Air added items to it"). |
| `attachment`, `chunk` | Immutable after creation; only create and tombstone. Tombstone wins. |
| `device` | Winner by `(hlc, author)` (only the name can change). Revocation is a log entry, not a record edit (§4.5). |

`conflict_copy_id(id, v) = UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ id ‖
version_hash(v))[0..16])`. Because the winner, the copy's id, its content and its version
are pure functions of the two versions, every device that sees the conflict computes the
same result. Resolution writes nothing new to the log except the copy itself, and two
devices materialising the same copy produce identical versions (deduplicated). This is
what makes "keep both" converge instead of ping-ponging.

Conflict copies are ordinary items with a `conflict` marker. The item list shows a badge;
Watchtower gets a **Sync conflicts** section; the item detail offers "Keep this version"
(copies content into the original, deletes the copy) and "Delete this copy". Both are
normal edits that sync.

### 3.5 Deletes and trash

- Moving to Recently Deleted (setting `deleted_at`) and restoring are ordinary edits.
- Purge (30 days after `deleted_at`, or "Delete permanently") writes a **tombstone**
  version: header only, no body. Every device purges on its own; concurrent purges join.
- Attachment removal writes an attachment tombstone; its chunks become garbage (§4.6).
- Tombstones are kept for as long as any live device might still hold the old item
  (§4.6 GC rule). A device that comes back after its tombstone horizon must re-join
  (§7.4), which prevents resurrecting purged items.

### 3.6 Object format

An **object** is one record version (or one chunk). File/blob name = lowercase hex
SHA-256 of the object bytes, so integrity is checked before any decryption.

```
object      = "KYO1" | collection:u8 (=0) | nonce:24 | XChaCha20-Poly1305(K_obj, nonce, plain, aad)
aad         = "keyorra/sync/v1/object\0" | account_id:16 | collection:u8
plain       = pad( canonical(Envelope) )
Envelope    = { format: 1, kind, record_id, vault_id?, schema, version, tombstone: bool,
                body: bytes? }
body        = nonce:24 | XChaCha20-Poly1305(inner_key, nonce, payload, body_aad)
body_aad    = "keyorra/sync/v1/body\0" | SHA-256(canonical(Envelope with body = null))
inner_key   = the vault key for item/attachment/chunk; absent (payload inline) for vault/device
```

- `canonical()` is deterministic CBOR (RFC 8949 §4.2.1: definite lengths, sorted map
  keys). JSON is not used on the wire because float/escape/ordering rules make test vectors
  fragile. Payloads that are JSON today (the `Item`) are carried as a CBOR byte string of
  the same JSON, so item serialization does not change.
- `body_aad` binds the inner ciphertext to its kind, ids, vault, schema and full version.
  A body cannot be moved to another record, another vault or replayed under a newer
  version, even by someone who has only the vault key (the future sharing case).
- **Padding** (`pad`): append `0x80` then zeros up to the next bucket. Buckets: 512 B,
  1 KiB, 2 KiB, 4 KiB, then the Padmé scheme (at most 12% overhead) up to the 4 MiB chunk
  size. A typical login and a secure note with a paragraph are indistinguishable by size.
- **Forward compatibility**: `format` and `schema` are inside the AEAD. A device that meets
  a higher `format` or `schema` keeps the object, does not touch that record, and shows
  "Update Keyorra to see N items". The `Item` struct gains `#[serde(flatten)] extra` so an
  older app never drops fields written by a newer one when it re-saves an item.

**Account header** (one immutable file per epoch, plaintext JSON because a joining device
must read it before it has any key):

```json
{ "keyorra_sync": 1, "account_id": "…", "epoch": 3, "generation": 1,
  "kdf": {"m_kib": 65536, "t": 3, "p": 1}, "salt": "…", "secret_key_id": "A3K7",
  "wrapped_account_key": "…", "mac": "…" }
```

`wrapped_account_key` = seal(`KEK_sync`, AK, `"keyorra/sync/v1/account-key\0" ‖
account_id ‖ epoch ‖ generation`). `mac` = seal(`K_hdr`, empty, canonical(all other
fields)): only a holder of AK can produce a header that devices accept as a successor.
Devices adopt the highest epoch whose `mac` verifies and never go back to a lower one.

## 4. Logs, snapshots and integrity

### 4.1 Per-device streams

Each device writes only its own **stream**: an append-only sequence of entries, each
linked to the previous by hash and grouped into immutable **segments** (one per sync
round). Objects are immutable and content-addressed. Together this means no file is ever
modified or written by two devices, which is what makes folder sync safe without locks.

```
Entry      = { seq: u64, kind: Put | Revoke | Checkpoint | Moved, ... }
  Put        { record_kind, record_id, version_hash, object: ObjectName, size }
  Revoke     { device, last_valid_seq, reason }
  Checkpoint { heads: { DeviceId -> (seq, hash) }, hlc }   // what this device has seen
  Moved      { transport_hint (sealed), at_hlc }            // §7.3
chain_0    = SHA-256("keyorra/sync/v1/chain-genesis\0" | account_id | device_id)
chain_n    = SHA-256("keyorra/sync/v1/chain\0" | chain_{n-1} | canonical(entry_n))
```

Segment layout:

```
segment = "KYS1" | device_id:16 | first_seq:u64 | last_seq:u64 | prev_hash:32 | last_hash:32
          | nonce:24 | XChaCha20-Poly1305(K_seg, nonce, canonical(SignedEntries), aad = all preceding bytes)
SignedEntries = { entries, sig: Ed25519(device_sk, "keyorra/sync/v1/segment\0" | header bytes | canonical(entries)) }
```

The plaintext header carries only random ids, counters and hashes, so a server can enforce
"append-only, contiguous, chained" per stream without being able to read anything.

### 4.2 Device keys

Each device has a random `device_id` (16 bytes) and an Ed25519 key pair, generated when it
joins. The secret key is stored sealed in the local store (`sealed_meta("sync-device")`).
The public key is published in the device's own `device` record, written as the first
entry of its own stream.

What the signatures buy, honestly stated: every device holds AK, so AK alone cannot tell
devices apart. Signatures let devices (a) attribute every change to a device for the Sync
log, and (b) reject writes from a **revoked** device even though it still knows AK (§4.5).

### 4.3 Reading

For every stream, a device keeps `(seq, hash)` of the newest entry it has verified (table
`sync_heads`). On each round:

1. Fetch segments after the known head. Verify: header shape, AEAD, signature against the
   device record's key, `prev_hash` = known head, chain recomputation, contiguous seqs.
2. For each `Put`, fetch the object, check its SHA-256 and that the decrypted envelope's
   kind/id/version hash match the entry. A `Pending`/`Missing` object pauses that stream at
   that entry (later entries of the same stream wait, other streams continue).
3. Merge (§3.4) into the local store in one SQLite transaction per segment.
4. Advance the head only after the transaction commits. A crash re-applies idempotently.

### 4.4 Writing

Local edits are recorded in `sync_outbox` in the same transaction as the edit. A round
seals the outbox into objects, uploads objects first, then appends one segment (which ends
with a `Checkpoint` of all heads this device has seen). Folder: segment written last, by
atomic rename (§5.3), so a reader never sees a segment before its objects exist on the
writer's side. Server: `append` is compare-and-swap on `prev_hash`.

### 4.5 Rollback, fork and withholding detection

| Attack by folder/server | Detected by | Reaction |
|---|---|---|
| Tamper with an object/segment | SHA-256 name, AEAD, signature | Ignore the file, red entry in Sync log, "Verify" offers re-upload from a device that has it |
| Inject a record | Needs AK and a live device key | Impossible without them |
| Replay an old object as current | `body_aad` + version in the log entry | Ignored |
| Roll a stream back (serve fewer segments) | Head regression vs `sync_heads` | Sync paused, alarm |
| Fork (show A and B different segment n) | Same seq, different hash, seen directly or via another device's `Checkpoint` | Sync paused, alarm |
| Withhold a device's updates | Other devices' checkpoints claim a head we cannot fetch; or a device's last segment ages | "Changes from MacBook Air are missing (last seen 3 days ago)" warning after 24 h |
| Roll back the account header | Epoch regression | Ignored; warning |

Alarm UI: sync pauses with a plain explanation and two actions: **Restore from this Mac**
(re-upload this device's own segments and objects, which it keeps until GC confirms) and
**Stop syncing**. Nothing is silently "fixed".

Limits, documented: a device that has never seen the newer state cannot detect a rollback
(e.g. a fresh device joining a folder that was restored from an old backup). Two devices
that never exchange data through anything but the hostile store can be forked
indefinitely only if the attacker keeps them strictly partitioned; the first honest
crossing exposes it.

**Revocation.** `Revoke { device, last_valid_seq }` written by any live device. Entries of
the revoked stream after `last_valid_seq` are ignored by everyone; its earlier writes stay.
The server (phase B) additionally disables the device's token. Revocation stops a device
from *writing*; it does not stop it from *reading* new objects in a folder it can still
access, because it still knows AK. Full lock-out needs key rotation (§8.4); the UI says so.
If two devices revoke each other concurrently, both revocations apply and the user gets an
alarm that points to rotation (rare, deliberately not automated).

### 4.6 Snapshots and garbage collection

Logs grow; snapshots bound them.

- A **snapshot** = the full merged state (record id → version + object name) as of a
  frontier (heads of all streams), signed by its device and sealed with `K_seg`. A device
  writes one after ~500 new entries or 7 days, whichever is first.
- **Bootstrap** of a joining device: newest snapshot that verifies against a live device,
  then all segments after its frontier.
- **GC**: a device deletes only *its own* segments and objects, only when (a) the newest
  snapshot of every live device covers them, and (b) the object is no longer referenced by
  any of those snapshots. A device unseen for 90 days blocks GC; the Sync screen then asks
  "MacBook Air hasn't synced since June. Remove it?" Tombstones go away the same way: once
  every live device's snapshot includes the purge.

## 5. Folder transport (phase A)

### 5.1 Layout

```
Keyorra/
  README-KEYORRA.txt            plaintext: what this folder is, "don't edit", link to docs/sync-protocol.md
  account/00000001.hdr          account headers, one per epoch (immutable)
  streams/<device_id hex>/<first_seq:016x>.seg
  snapshots/<device_id hex>/<frontier_seq:016x>.snap
  objects/<2 hex>/<64 hex>      content-addressed objects, 256-way fan-out
  .keyorra-tmp/                 temp files during writes; ignored by readers
```

Rules for readers: a file counts only if its name matches the exact pattern for its
directory and its content verifies. Everything else is ignored and listed under "unknown
files" on the Sync screen. That makes the transport immune to:

- **Sync-client conflict copies** (`x (1).seg`, `x (conflicted copy 2026-…).seg`,
  `x 2.seg`): never match the pattern. Since our files are write-once, a copy can only be
  an identical duplicate or a torn one.
- **Partial/torn files**: hash/AEAD/signature fails → treated as `Pending`, retried, and
  reported only if it stays broken for 24 h.
- **Reordering** (segment arrives before its objects, objects before their segment):
  `Pending` until complete.
- **Deleted-by-user files**: `Missing`; the author re-uploads on "Verify".

### 5.2 iCloud Drive specifics

- Files can be **evicted** (replaced by a placeholder `.name.icloud` or a dataless file).
  The transport asks `NSURLUbiquitousItemDownloadingStatusKey`; if not current it calls
  `NSFileManager.startDownloadingUbiquitousItemAtURL` and returns `Pending`. It also treats
  a `.X.icloud` placeholder as "X exists, Pending". No dependency on `brctl` (a diagnostics
  tool, not an API).
- Reads and writes in the iCloud folder go through `NSFileCoordinator` (via `objc2`), as
  Apple requires for ubiquitous files. Other providers get plain POSIX I/O; coordination
  there is harmless and also used when the folder is inside a File Provider domain
  (Dropbox, OneDrive and Google Drive on current macOS).
- Recommend "Keep Downloaded" for the Keyorra folder (Finder option on macOS 15+); the
  transport works without it, only slower.
- The iPhone app (later) reaches the same folder through the Files document picker and a
  security-scoped bookmark; iCloud Drive and Dropbox both work this way.

### 5.3 Writing

1. Write to `.keyorra-tmp/<random>.part` with mode 0600, `fsync`.
2. `rename` into its final name (same volume, atomic), `fsync` the directory.
3. Objects first, segment last; snapshot after its segment.

If the final name already exists with the same hash (objects), skip. Segments never
collide: only one device writes its stream, and a device's seq is stored locally before
the write.

### 5.4 Noticing changes

- FSEvents (`notify` crate) on the folder, debounced 2 s.
- Poll every 60 s while unlocked, plus on unlock, on wake and on "Sync now". Some providers
  update files without FSEvents firing reliably; polling covers that.
- Listing cost stays small: streams are read from the known head, objects are fetched by
  name, never by listing `objects/`.

### 5.5 What someone with folder access learns

Can see: number of objects and their padded size buckets, number of devices (stream
directories), number and timing of sync rounds (segments, file mtimes), total size, the
KDF parameters and salt, and the 4-character Secret Key id. Cannot see: item count per
vault, number of vaults, which object is which kind, names, URLs, device names, who edited
what. Deletions and edits are indistinguishable from additions. The cloud provider also
sees the IP addresses and account that sync the folder; that is outside Keyorra.

## 6. Server (phase B)

### 6.1 Shape

`keyorra-server`: one binary, `axum` + `tokio`, `rustls`, `rusqlite` (bundled), `tracing`.
Data directory (`/var/lib/keyorra` or the Docker volume `/data`):

```
keyorra.db      SQLite: accounts, devices, streams, segments (metadata), objects (metadata),
                headers, invites, audit (admin actions)
blobs/<2>/<64>  object bytes, content-addressed; segments and snapshots stored inline in SQLite
server.toml     optional; env vars KEYORRA_* override
tls/            certs, ACME state
```

The server never holds a key that decrypts anything. It stores what the folder would
hold, plus authentication data.

### 6.2 Scope: single-user default, multi-account capable

The schema is multi-account from day one (every row has `account_id`), because sharing
later needs several accounts on one server. Defaults: `registration = "invite"`; `keyorra-
server init` creates the first invite and prints it. Admins can issue more invites. Open
registration exists as a config option, off by default. Quotas per account (default 1 GiB).

### 6.3 Authentication

Derivation on the client, for the synced header (salt and KDF params come from the server,
unauthenticated, via `GET /v1/accounts/{account_id}/login-params`):

```
U        = Argon2id(master_password, remote_salt, kdf)       // 32 bytes
M        = HKDF-Extract(salt = secret_key, ikm = U)
KEK_sync = HKDF-Expand(M, "keyorra/kek/v2", 32)              // unwraps AK from the header
AUTH     = HKDF-Expand(M, "keyorra/server-auth/v1", 32)      // proves knowledge to the server
```

The server stores `SHA-256(AUTH)` (constant-time compare). Why not SRP or OPAQUE:

- Both exist to stop a server (or a leak of its database) from mounting an offline
  dictionary attack on the password. Here `AUTH` contains the 128-bit Secret Key, so its
  hash is not brute-forceable whatever the password.
- The server must hold the wrapped account key anyway (new devices download it), and that
  is already an offline-attack target with exactly the same strength. A PAKE would protect
  a door next to an open window.
- The cost of a PAKE is real: an extra protocol, a younger crate (`opaque-ke`), more to
  audit and to re-implement on iOS. Not worth it for no gain.
- `AUTH` is a separate HKDF output from `KEK_sync`, so the server never learns anything
  that unwraps AK.

Residual risk, documented: a user who points a client at a malicious server hands it
`AUTH`, which lets it log into the *real* server as that user. It still needs device
approval (§6.4) and still cannot read anything. If the Secret Key policy becomes optional
(open question 1), accounts without a Secret Key must use OPAQUE instead; this is the
reason the Secret Key is recommended mandatory.

Sessions: login exchanges `AUTH` + the device's Ed25519 public key for a random 256-bit
**device token** (stored hashed), sent as `Authorization: Bearer`. Tokens do not expire
while the device is approved and not revoked; they rotate on master password change.

### 6.4 Device registration and approval

- The first device of an account is approved automatically.
- Any later login creates a **pending** device: it can read `login-params` and its own
  status, nothing else.
- An approved device shows "New device 'MacBook Air' wants to join. Code 482 913"; the
  same 6-digit code shows on the new device: `code = BE-u32(SHA-256("keyorra/sync/v1/
  approve\0" ‖ new_device_pk ‖ approver_pk ‖ account_id)[0..4]) mod 10^6`. The approver
  signs `{account_id, new_device_id, new_device_pk}`; the server checks the signature
  against the approver's registered key and enables the token. (Commit-then-reveal, as in
  the browser bridge, so a relay cannot grind the code.)
- No other device available: `keyorra-server device approve <id>` on the server.
- `require_approval = true` by default; can be turned off for a single-user home server.

### 6.5 API (v1)

All bodies JSON except object/segment bytes (`application/octet-stream`). Max request
body 8 MiB (objects are ≤ 4 MiB + overhead).

| Method & path | Who | Purpose |
|---|---|---|
| `POST /v1/accounts` | invite | create account: `account_id`, first header, `SHA-256(AUTH)` |
| `GET /v1/accounts/{id}/login-params` | anyone (rate-limited) | salt, kdf, secret_key_id; unknown ids get deterministic fake params (no enumeration) |
| `POST /v1/accounts/{id}/login` | anyone (rate-limited) | `AUTH`, device pk → device token (pending/approved) |
| `GET/PUT /v1/headers[/{epoch}]` | device | account headers; PUT only `epoch = current + 1` |
| `GET /v1/devices`, `POST /v1/devices/{id}/approve`, `DELETE /v1/devices/{id}` | device | list/approve/revoke |
| `PUT/GET /v1/objects/{sha256}` | device | server verifies the hash on PUT |
| `POST /v1/streams/{device}/segments` | that device | append; `409` with the current head if `prev_hash` ≠ head or seq not contiguous |
| `GET /v1/changes?cursor=N` | device | segments/snapshots appended after a server-global cursor |
| `PUT/GET /v1/snapshots/...` | device | snapshots |
| `DELETE /v1/garbage` | device | own segments/objects (§4.6) |
| `GET /v1/events` | device | Server-Sent Events: `changed {cursor}` |
| `GET /v1/listing` | device | everything the server stores for this account (§9.2) |
| `GET /healthz`, `/readyz` | anyone | liveness/readiness, no data |

Push: SSE over the same HTTPS connection (works through every reverse proxy, simple in
axum, auto-reconnect in clients). A WebSocket adds nothing here: the client never sends
over the push channel. Clients also poll `/v1/changes` every 5 minutes as a fallback. The
iPhone (later) cannot hold SSE in the background and uses background app refresh.

### 6.6 TLS

`[tls] mode =`
- `"files"`: cert + key paths (reloaded on SIGHUP).
- `"acme"`: Let's Encrypt via `rustls-acme` (TLS-ALPN-01, port 443), cache in `tls/`.
- `"self-signed"`: generated on first start; the server prints its SPKI SHA-256
  fingerprint, and the setup code carries it; the client pins it. For home servers without
  a domain.
- `"off"`: plain HTTP, accepted only together with `behind_proxy = true` and a loopback or
  explicitly configured bind address; the server logs a warning on every start.

Clients refuse `http://` except for `localhost`. Pinned fingerprints are shown on the Sync
screen.

### 6.7 Abuse limits

- `login-params` and `login`: token bucket per IP (10/min) and per account (20/hour),
  exponential lockout per account after failures, logged.
- Per-device request rate (default 20 req/s burst 100), per-account quota, max body size,
  max segments per request, idle timeouts, SSE connection cap per account.

### 6.8 Backups and restore

Everything on the server is ciphertext or a hash, so backups can live anywhere.

- `keyorra-server backup <file.tar.zst>`: SQLite online backup API + blobs, consistent,
  while running. Or stop the service and copy the data directory.
- `keyorra-server restore <file>`: into an empty data directory.
- Restoring an old backup **is a rollback**. Devices detect it (§4.5) and offer "Restore
  from this Mac", which re-uploads their newer segments and objects. The ops docs say this
  explicitly, so an admin knows the alarm after a restore is expected.
- `keyorra-server check`: verifies blob hashes, stream contiguity and chain linkage (which
  it can check from plaintext headers) without any keys.

### 6.9 Observability

- `tracing` with JSON output (`--log-format json|pretty`). Every request: request id,
  route template (not the raw path), status, duration, account id shortened to 8 hex chars.
- Never logged: request/response bodies, `Authorization`, `AUTH`, tokens, object names in
  full, IP addresses beyond what `log_ips = true` enables (off by default).
- Optional Prometheus `/metrics` on a separate bind address (off by default): request
  counts, latencies, storage size, SSE connections. No per-account labels.

### 6.10 Admin CLI

`keyorra-server serve | init | invite create | account list | account delete <id> |
device list <account> | device approve <id> | device revoke <id> | backup | restore |
check | healthcheck | version`. Admin actions are written to the `audit` table and are
visible to the account owner in the app ("Device revoked by server admin on …").

## 7. Local changes, migration, switching

### 7.1 Store migration v2

New tables (migration v2, backup made automatically as today):

```
sync_config   (one row: account_id, transport kind, location, sealed device secret, state)
sync_versions (record_kind, record_id, vector BLOB, hlc, author, object, PRIMARY KEY(kind,id))
sync_heads    (device_id, seq, hash, last_seen_hlc)
sync_devices  (device_id, name, model, pk, added_at, revoked_at_seq)
sync_outbox   (record_kind, record_id, queued_at)
sync_log      (at, level, text)   -- last 1000 events, shown in the UI
```

`sync_versions` is keyed by record, not by local row, so a local re-encryption (item moved
between vaults) does not lose its version. Every store write path (`save_item`,
`delete_item`, `restore_item`, `purge_expired`, attachment add/remove, vault create/
rename/delete, import) also enqueues into `sync_outbox` in the same transaction when sync
is on. A test enumerates the public mutating `Store` methods and asserts each one
enqueues, so a future method cannot forget.

### 7.2 Enabling sync (first device)

1. Choose transport: folder (iCloud Drive suggested; any folder via picker) or server URL.
   The folder must be empty or not exist.
2. Re-enter the master password (needed to derive `KEK_sync`).
3. Generate `account_id`, the **Secret Key** (§7.5), this device's id and Ed25519 key.
4. Show the **Emergency Kit**: account id, Secret Key, location, blank line for the master
   password, as a printable page / PDF. The user confirms by typing the last 4 characters
   of the Secret Key.
5. Write header epoch 1, export every vault, item, attachment as records with vector
   `{this_device: 1}`, then one snapshot. Progress bar; the local vault stays usable.

### 7.3 Joining (second Mac)

1. "Join a synced account": pick the folder or enter the server URL, then paste/scan the
   **setup code** (`KY1-<account_id>-<secret key>[-<pin>]`) shown by another device, or
   type account id and Secret Key from the Emergency Kit.
2. Master password → `KEK_sync` → AK from the newest header whose `mac` verifies.
3. Server: login, wait for approval (§6.4).
4. Local data:
   - no local vault → create one from the synced state (local header from the same master
     password, Argon2 with a fresh salt);
   - an existing local vault (different AK) → choose **Merge** (default: local vaults and
     items are re-encrypted under the synced keys and written as new records; no attempt
     to deduplicate, Watchtower's duplicate check helps afterwards) or **Replace**. Either
     way the old database is kept as `keyorra.db.pre-sync-YYYYMMDD` until the user deletes
     it from Settings.
5. Existing devices see "MacBook Air joined" in their Sync log and Devices list.

### 7.4 Disabling, leaving, switching

- **Turn off sync on this Mac**: writes a self-`Revoke`, keeps the full local vault as a
  normal local vault, deletes sync tables. Remote data untouched.
- **Delete synced data**: only offered on the last live device; requires typing the
  account id. Folder: deletes the Keyorra folder contents. Server: `DELETE /v1/accounts/{id}`.
- **Switch transport** (e.g. iCloud Drive → own server): the device publishes the full
  state as a snapshot to the new transport (same account id, keys and device ids, streams
  restart at a new seq base), then appends `Moved { sealed new location }` to its stream in
  the old transport. Other devices read `Moved`, show "This account moved to
  https://vault.example.com. Switch now?", and switch after confirmation (server: needs
  login + approval). The old location is cleaned by the last device to leave it.
- A device returning after its tombstone horizon (§4.6) is told to re-join; its local
  unsynced edits are kept as a "Recovered" vault and then merged as new records.

### 7.5 The Secret Key

**Decision: yes, for synced accounts.** 128 random bits, shown as
`A3K7-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (base32 Crockford, 4-char public id + 26 chars + 1
check char).

Why: with sync, the wrapped account key sits on iCloud/Dropbox/Google or a VPS, where it
can leak in ways a local disk does not (provider breach, shared links, backups, a
compromised server). Without a Secret Key, everything then rests on the master password
surviving an offline Argon2 attack. With it, a leaked folder or server database is
useless without a device or the Emergency Kit.

Costs: one more thing to keep (Emergency Kit), one more step when adding a device (setup
code or typing), data loss if all devices and the kit are lost. These are the same costs
1Password users accept, and the setup code makes the common case (another device at hand)
a paste.

Where it lives:
- In the **synced header** only: `KEK_sync` mixes it in. The **local** header stays
  password-only (format 1, unchanged), so unlocking this Mac never depends on the Keychain
  or the kit. A stolen Mac is protected exactly as today.
- On each device, sealed under AK in `sealed_meta("sync-secret-key")`, so the app can
  re-wrap the synced header on password change and show the setup code (after re-entering
  the master password).

## 8. Key changes

### 8.1 Master password change

On device A: re-wrap AK in the local header (as today) **and** write synced header epoch
`n+1` (new salt, same AK, same Secret Key). Server: also uploads the new `SHA-256(AUTH)`
with the device token; other device tokens stay valid. Other devices verify the new
header's `mac` with their AK, adopt it, and re-wrap their *local* header the next time the
user unlocks with the new password: until then they still accept the old one locally,
and the Sync screen shows "Master password changed on MacBook Pro. Unlock with the new
password." Touch ID keeps working (it wraps AK, which did not change), but its 14-day
password check now needs the new password.

Stated limit: changing the password does not lock out someone who already has both the old
password and the Secret Key and a copy of the folder; for that, rotate keys (§8.4).

### 8.2 Vault deletion

As today locally (vault must be empty; trashed items purged). Sync: tombstones for the
items and the vault record; vault key is kept in the vault record's last live version
until GC, so old tombstones still verify. Concurrent additions undo the deletion (§3.4).

### 8.3 Device removal

Sync screen → device → **Remove**: writes `Revoke`, disables the server token. The dialog
says plainly what it does and does not do (§4.5) and offers **Remove and rotate keys**.

### 8.4 Key rotation (phase C, format ready now)

New AK, new vault keys, optionally a new Secret Key; every live record re-encrypted into a
new **generation** (header field `generation`, objects under the new keys); header epoch
bumps; old generation objects deleted after all live devices have moved. Other devices
need the master password on their next unlock (their Touch ID record is invalidated), and
with a new Secret Key, the new setup code. A revoked device keeps what it had but cannot
read anything written after rotation. Scheduled after phase B (open question 5).

### 8.5 Touch ID

Unchanged and per device. Never synced. A device joining sync can turn it on after its
first password unlock, as today.

## 9. Transparency

### 9.1 Sync screen (Settings → Sync)

- **Status line**: Up to date · Syncing (n of m) · Paused: locked · Waiting for iCloud to
  download 3 files · Offline · Alarm (red, with explanation and actions).
- **Last sync**: time of last successful round; "Sync now".
- **Location**: folder path with "Show in Finder", or server URL with TLS mode and pinned
  fingerprint; transport-specific hints (iCloud "Keep Downloaded").
- **This device**: name (editable), device id, public key fingerprint.
- **Devices**: name, model, added on/by, last seen (from its newest checkpoint), status
  (approved/pending/revoked); Remove; Approve (server).
- **Conflicts**: count, list linking to the conflict copies.
- **What the folder/server sees** (§9.2).
- **Sync log**: last 1000 events, filterable: pulled 5 changes from MacBook Air, pushed 2,
  kept 'GitHub' after concurrent delete, conflict copy created, object pending, alarms.
  Item titles appear only in this local, encrypted log; never on the wire.
- **Verify everything**: re-reads every stream, object and snapshot, checks hashes,
  signatures, chains and that the local state equals the merged remote state. Reports
  per-file results.
- **Emergency Kit / setup code** (after re-entering the master password).

### 9.2 "What the folder/server sees"

A table of every file/blob for this account exactly as stored: name, kind as visible from
outside (header / stream segment / snapshot / object / unknown file), size, created time,
and for segments the plaintext header fields (device id, seq range, hashes). Export as
CSV, or "Export raw files" (zip of the bytes). Next to it, a one-paragraph explanation of
what each column reveals. Purpose: the user can confirm, without trusting us, that nothing
readable leaves the Mac.

### 9.3 Public protocol and test vectors

- `docs/sync-protocol.md`: normative description of keys, labels, object/segment/snapshot/
  header formats, canonical CBOR rules, padding, merge rules, conflict-copy derivation,
  chain and signature rules, folder layout, server API. Versioned; any change to the wire
  format bumps a version and updates this file in the same commit.
- `docs/sync-test-vectors/*.json`: fixed AK, Secret Key, password, salts, nonces, device
  keys → expected KEKs, AUTH, object bytes, segment bytes, chain hashes, conflict-copy ids,
  merge outcomes. `keyorra-sync` tests load them (deterministic RNG injected), so code and
  document cannot drift.
- `keyorra-inspect` (example binary in `keyorra-sync`): given a folder (or a server
  listing export), the master password and the Secret Key, it verifies and dumps
  everything in readable form. An auditor can check the protocol end to end without the
  app.

### 9.4 Threat model

| Adversary | Can | Cannot | Notes |
|---|---|---|---|
| Passive folder/provider reader | See sizes (bucketed), counts, device count, timing, KDF params, salt, Secret Key id | Read anything; brute-force the password offline (needs Secret Key) | §5.5 |
| Active folder writer | Delete, withhold, restore old files, show devices different files | Inject or alter data; roll back or fork unnoticed by a device that saw newer state | §4.5 |
| Malicious server operator | As active writer; see IPs, request timing, account id, `SHA-256(AUTH)`; learn `AUTH` at login | Read data; unwrap AK; brute-force password (Secret Key) | TLS hides content from the network, not from the operator |
| Server database/backup leak | Get ciphertext, header, token hashes | Anything useful | Tokens stored hashed |
| Network attacker | Block traffic | Read/alter (TLS; pinning for self-signed) | |
| Stolen locked Mac | Get local store | Unlock without the master password (Argon2 as today) | Secret Key sealed under AK, adds nothing to the thief |
| Stolen unlocked Mac / malware on a device | Everything that device can see | — | Remove device + rotate keys |
| Revoked device | Read objects it can still reach (folder) until rotation | Write accepted changes; use the server | §4.5, §8.4 |
| Lost all devices **and** Emergency Kit | — | — | Data is unrecoverable; said at setup |
| Older app version | Read records of its format | Corrupt newer records (it stays read-only on them; unknown fields preserved) | §3.6 |
| Clock skew/manipulation | Influence which concurrent edit wins | Lose an edit (loser kept as copy) | HLC, §3.3 |

## 10. Browser extensions and other clients

Unaffected. The extensions talk only to the local app over the existing bridge; they see
synced items once the app has merged them, and logins saved from the browser are local
edits that sync like any other. Browser pairings stay per device. The bridge protocol does
not change.

iPhone (roadmap 2) uses the same `keyorra-sync` crate (via UniFFI), both transports
(folder through the Files picker; server over HTTPS), and the same join flow (setup code
scanned with the camera). Its AutoFill extension reads the local store; sync runs in the
app and background refresh.

## 11. Testing strategy

TDD as in the MVP. In order of importance:

1. **Format and crypto** (`keyorra-sync`): known-answer tests from the test vectors; every
   AAD component changes the result; tampering any byte of an object/segment/header fails;
   body moved between records/vaults/versions fails; padding round-trips and hides sizes
   within a bucket; canonical CBOR is byte-stable.
2. **Merge rules**: one test per row of the table in §3.4; conflict copy determinism (two
   independent resolvers produce byte-identical logical state); edit-vs-delete; vault
   deletion undone by a concurrent add; forward-compat (unknown schema stays untouched,
   unknown item fields survive a re-save).
3. **Engine against `MemoryTransport`**: two, three and five simulated devices with
   injected clocks; offline periods; join/leave; snapshots and GC; revocation.
4. **Fault-injecting transports** wrapping the memory transport: drop, delay, duplicate,
   reorder, truncate (partial files), bit-flip, `Pending` placeholders that resolve late,
   `(1)` conflict-copy files, rollback of one stream, fork per reader, withheld streams,
   crash between object upload and segment append, crash mid-merge.
5. **Property tests** (`proptest`): random sequences of edits/deletes/moves/purges on N
   devices with random delivery schedules and faults; after delivering everything, all
   devices reach identical state (convergence), no edit is lost (each written plaintext is
   present as the item or a conflict copy, unless purged by a dominating tombstone), and
   every detectable attack is detected.
6. **Folder transport**: on a temp dir; plus a macOS-only, ignored-by-default suite on a
   real iCloud Drive folder (eviction via `brctl evict` used *only in tests*), Dropbox
   smoke test documented as a manual checklist.
7. **Server**: axum handlers with an in-process server (no network); auth, rate limits,
   approval, `409` on chain mismatch, quotas, SSE; `keyorra-server check`/backup/restore
   round-trip; a test that greps captured logs for secrets.
8. **Server transport**: the engine suite from (3)–(5) rerun against a live in-process
   server (same test bodies, transport parameterized).
9. **End to end**: two app instances (two data dirs) on one Mac sharing a temp folder,
   driven through Tauri commands: enable, join, edit on both, conflict appears in both,
   resolve, remove device. Same with a local server in Docker in CI (Linux).
10. **Store**: migration v2; every mutating method enqueues to the outbox (enumeration
    test); turning sync off leaves a normal working vault.

## 12. Phasing

Each line becomes one implementation plan in `docs/superpowers/plans/`.

| Plan | Content | Done when |
|---|---|---|
| **A1** Engine + format | `keyorra-sync`: keys, object/segment/snapshot/header formats, CBOR, padding, versions/HLC, merge rules, conflict copies, chains, signatures, snapshots/GC, `MemoryTransport` + fault transports, property tests, test vectors, `docs/sync-protocol.md` draft; store migration v2 + outbox; `Item.extra` | Suites 1–5, 10 green; protocol doc reviewed |
| **A2** Folder transport | `keyorra-sync-fs`: layout, atomic writes, pattern-strict reading, iCloud downloading status + `NSFileCoordinator`, placeholders, FSEvents + poll, `keyorra-inspect` | Suite 6 green; two processes on one temp folder converge |
| **A3** UI | Enable/join/leave flows, Secret Key + Emergency Kit + setup code, Sync screen (§9.1–9.2), conflicts in list/detail/Watchtower, alarms, background sync thread | E2E suite 9 (folder) green; manual iCloud test with two Macs |
| **B1** Server | `keyorra-server`: schema, API, auth, approvals, SSE, rate limits, quotas, TLS modes, logs, admin CLI, backup/restore/check | Suite 7 green |
| **B2** Server transport | HTTP client transport, login/approval UI, pinning, switch transport + `Moved` | Suite 8 + E2E against server green |
| **B3** Packaging | Multi-arch Docker image, static musl binaries, systemd unit, signed releases, `docs/self-hosting.md` | Image runs on amd64/arm64 (Raspberry Pi) from the docs alone |
| **C1** (later) Key rotation | Generations, rotation flow | — |

### 12.1 B3 details

- **Docker**: multi-stage; build `x86_64`/`aarch64-unknown-linux-musl`, final stage
  `gcr.io/distroless/static-debian12:nonroot` (UID 65532), `VOLUME /data`, `EXPOSE 8443`,
  `HEALTHCHECK CMD ["/keyorra-server", "healthcheck"]` (no curl in the image), read-only
  root filesystem friendly. Published to `ghcr.io/skensell201/keyorra-server` with cosign
  signatures and an SBOM. `docker-compose.yml` example in the docs (with and without
  Caddy as reverse proxy).
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
AmbientCapabilities=CAP_NET_BIND_SERVICE
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

- **Config** (`server.toml`, every key also `KEYORRA_<SECTION>_<KEY>`):

```toml
data_dir = "/var/lib/keyorra"
bind = "0.0.0.0:8443"
public_url = "https://vault.example.com"
registration = "invite"        # invite | open | closed
require_approval = true
quota_bytes = 1073741824

[tls]
mode = "acme"                  # files | acme | self-signed | off
domains = ["vault.example.com"]
contact = "mailto:me@example.com"
# behind_proxy = true           # required for mode = "off"

[log]
format = "json"
log_ips = false
```

- `docs/self-hosting.md`: install (Docker / binary), TLS choices, first account, backups and
  what a restore triggers, upgrading, reverse proxy examples (Caddy, nginx: SSE needs
  buffering off), what the server can and cannot see.

## 13. Open questions for the user

1. **Secret Key mandatory for sync?** Recommended: yes (the server-auth design and the
   folder threat model rely on it). The alternative, optional, would need OPAQUE on the
   server and weaker folder guarantees for those accounts.
2. **Concurrent edit vs delete: edit wins?** Recommended: yes (no data loss; the deletion
   is logged and easy to redo). Alternative: delete wins and the edit goes to Recently
   Deleted.
3. **Sync only while unlocked?** Recommended: yes; changes from other devices arrive at
   the next unlock. Pulling while locked would need a sync-only key kept in the Keychain
   without the master password, which weakens the "locked means nothing is decryptable"
   rule.
4. **Server registration default**: invite-only single user (recommended), or open
   registration for a family server?
5. **When to build key rotation (C1)?** Recommended: right after phase B. Without it,
   removing a device in folder mode stops its writes but not its reading of new data;
   building it before shipping A3 delays phase A by roughly one plan.
