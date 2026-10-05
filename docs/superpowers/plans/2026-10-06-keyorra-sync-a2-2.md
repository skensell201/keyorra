# Keyorra Sync A2-2 Implementation Plan (attachment contents, file coordination, per-account folders, macOS)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync runs for real on a Mac. Attachment contents travel as encrypted chunks next to the streams (written before the record that names them; a device that has the record but not yet the chunks waits and says so); a conflict copy's attachment opens the original's chunks. Every read, write and delete in the folder goes through the provider's coordination (`NSFileCoordinator`). Each account has its own folder `<place>/Keyorra/<account id hex>/`; turning sync on makes a new one, joining finds the folder whose header names the Secret Key. The app syncs over iCloud Drive by default: it reads iCloud's download state, asks for missing files, notices changes with FSEvents and polls every minute while unlocked, and keeps device keys sealed to the Secure Enclave.

**Builds on:** A2-1 (`docs/superpowers/plans/2026-10-06-keyorra-sync-a2-1.md`) on `feat/sync-design`.

**Verified:** every task was applied in order in a scratch worktree on top of A2-1; the workspace suite passes after every task (666 tests, 4 ignored at the end), clippy is clean (it compiles the Swift files), and the adversary and convergence property tests pass at 2000 cases in release. The app's tests run the FSEvents watcher and `NSFileCoordinator` on temp folders; nothing touches the keychain or the Secure Enclave.

**Architecture:**

- `keyorra-sync`: the attachment payload names the id its chunks are sealed for (`chunks_for`); `Engine::seal_attachment` (new key, chunks), `write_attachment`, `open_attachment`.
- `keyorra-core`: `Store::attachment_state`, `attachment_content`, `attachment_ids`, `apply_remote_attachment`, `apply_remote_attachment_removed`.
- `keyorra-session::sync`: attachment changes are written as chunks then records; a round shows attachment contents (fetching chunks) and removals; existing attachments are written when sync is turned on or a vault rejoins. `enable` and `start_new_account` take the new account's id; `holds_account` finds the folder to join.
- `keyorra-sync-fs`: `Availability::coordinate` wraps every file access.
- `keyorra-session::session`: `SyncLink::transport(account)`, `new_account_transport(account)`, `join_candidates()`.
- App: `swift/SyncFolder.swift` (download state and requests, `NSFileCoordinator`, FSEvents, computer name), `src/syncfolder.rs` (`MacCloud`, `FolderLink`, `Watcher`, `Schedule`), wiring in `lib.rs` and the housekeeping loop.

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`:

1. **§3.5, conflict copies**: after "same key and chunks, `item_id` = the copy": "and `chunks_for` = the original's (the id its chunks are sealed for)".
2. **§5.2**: "Reads, writes and deletes of files go through `NSFileCoordinator` (a Swift helper; directory listings are not coordinated). Download state: `NSURLUbiquitousItemDownloadingStatusKey` (current or downloaded is ready), plus `SF_DATALESS`."
3. **§5.4**: "FSEvents on the account folders' parent (latency 2 s, started at launch if the folder exists; after sync is first turned on, polling covers it until the next launch); a round every 60 s while unlocked and on any change. A round runs on the app's housekeeping thread holding the session (10 s budget)."
4. **§7.2 step 5 and §7.3**: "Attachment contents are written through the change path: chunks first, then the record; existing attachments when sync is turned on or a vault rejoins."
5. **§7.3 step 1**: "Joining looks at every account folder in the sync place and picks the one whose header names the Secret Key id (setup code or Emergency Kit); none is an error."

And to `docs/sync-protocol.md` §9.1: `attachment = { …, "chunks": [bytes32, …], "chunks_for": bytes16 }` with "`chunks_for` is the attachment id bound into every chunk's associated data (§8): the record's own id, or for a conflict copy's attachment the original's".

## Decisions

Visible to the user (to confirm):

- **iCloud Drive is the default place** (`~/Library/Mobile Documents/com~apple~CloudDocs/Keyorra/`); nothing is created there before sync is turned on. Choosing another synced folder is A3.
- **A round holds the session for up to 10 s** (the window waits meanwhile). Moving rounds off the session lock (an engine thread) is a later step if it is felt.
- **A missing account folder is an error shown on the Sync screen**, never silently recreated (it may be an iCloud problem, or the user deleted it).
- **Attachments are read whole into memory** (in 4 MiB chunks): fine for documents and photos; very large files wait for a streaming version.
- **Waiting attachments** (record here, chunks not yet) are listed in the round's notices until their chunks arrive.

Internal:

- **`chunks_for` in the attachment payload** (a format change before any release): chunks stay bound to one attachment id, and copies share them without re-upload.
- **Coordination wraps the access, not the transport call**: Swift calls back into Rust inside the coordinated block, so Rust does the I/O.
- **Joining matches the header's Secret Key id** before trying the password, so only one account folder costs a key derivation.

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings` clean; the touched crates' tests green.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against the state after the previous task; apply them with `git apply` (or by hand), in task order. New files are given in full.
- Never run `--ignored` tests and never touch the real keychain or Secure Enclave from tests.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-sync/src/payload.rs, fold.rs, present.rs   chunks_for
crates/keyorra-sync/src/engine.rs                         seal_attachment, write_attachment, open_attachment
crates/keyorra-sync/src/engine/attachment_tests.rs        NEW
crates/keyorra-sync/src/transport.rs                      MemoryTransport::take_chunks (tests)
crates/keyorra-core/src/store/{mod,sync,sync_tests}.rs    attachment state, content, remote applies
crates/keyorra-session/Cargo.toml                         dev: keyorra-sync-fs
crates/keyorra-session/src/sync/{mod,merge,tests}.rs      attachments, account ids, holds_account
crates/keyorra-session/src/session/{sync,sync_tests}.rs   per-account SyncLink
crates/keyorra-sync-fs/src/{avail,lib,tests}.rs           coordination
app/src-tauri/swift/SyncFolder.swift                      NEW
app/src-tauri/src/syncfolder.rs                           NEW
app/src-tauri/{build.rs,Cargo.toml,src/lib.rs,src/touchid.rs}
```

---

### Task 1: Attachment contents in the engine

**Files:** Create `crates/keyorra-sync/src/engine/attachment_tests.rs`; modify `crates/keyorra-sync/src/payload.rs`, `fold.rs`, `present.rs`, `engine.rs`.

- [ ] **Step 1: Failing tests.**

Create `crates/keyorra-sync/src/engine/attachment_tests.rs` (an attachment travels as chunks and opens elsewhere; chunks out of place are refused; a conflict copy opens the original's chunks):

```rust
//! Plan A2-2: attachment contents as chunks next to the streams.

use uuid::Uuid;

use super::*;
use crate::faults::Faults;
use crate::testkit::{Cluster, START_MS};

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);
const ATT: Uuid = Uuid::from_bytes([0x61; 16]);

/// Device 0 attaches `bytes` to ITEM (chunks of `chunk_size`) and uploads the chunks.
fn attach(c: &mut Cluster, vault: Uuid, bytes: &[u8], chunk_size: usize) {
    let (payload, chunks) = c.devices[0]
        .seal_attachment(ATT, ITEM, "scan.pdf", bytes, chunk_size)
        .unwrap();
    for chunk in &chunks {
        c.store.put_chunk(chunk).unwrap();
    }
    c.devices[0]
        .write_attachment(vault, ATT, payload, START_MS)
        .unwrap();
    let json = Cluster::item_json(ITEM, "with a file", &[ATT]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
}

fn chunks_of(c: &Cluster, payload: &AttachmentPayload) -> Vec<Vec<u8>> {
    payload
        .chunks
        .iter()
        .map(|h| {
            match c
                .store
                .get_chunk(&data_encoding::HEXLOWER.encode(h))
                .unwrap()
            {
                Fetched::Ready(b) => b,
                other => panic!("chunk {other:?}"),
            }
        })
        .collect()
}

fn shared() -> (Cluster, Uuid) {
    let mut c = Cluster::new(2, 31, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    (c, vault)
}

#[test]
fn an_attachment_travels_as_chunks_and_opens_elsewhere() {
    let (mut c, vault) = shared();
    let bytes: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    attach(&mut c, vault, &bytes, 300);
    let view = c.devices[1].view();
    let payload = view.attachments[&ATT].clone();
    assert_eq!(payload.chunks.len(), 4);
    assert_eq!(payload.chunks_for, ATT);
    let opened = c.devices[1]
        .open_attachment(&payload, &chunks_of(&c, &payload))
        .unwrap();
    assert_eq!(&opened[..], &bytes[..]);
}

#[test]
fn chunks_out_of_place_are_refused() {
    let (mut c, vault) = shared();
    attach(&mut c, vault, b"0123456789", 4);
    let payload = c.devices[1].view().attachments[&ATT].clone();
    let mut chunks = chunks_of(&c, &payload);
    chunks.swap(0, 1);
    assert!(c.devices[1].open_attachment(&payload, &chunks).is_err());
    let chunks = chunks_of(&c, &payload);
    assert!(c.devices[1]
        .open_attachment(&payload, &chunks[..2])
        .is_err());
    // The same chunks under another attachment's id do not open.
    let mut moved = payload.clone();
    moved.chunks_for = Uuid::from_bytes([0x62; 16]);
    assert!(c.devices[1].open_attachment(&moved, &chunks).is_err());
}

#[test]
fn a_conflict_copy_opens_the_original_chunks() {
    let (mut c, vault) = shared();
    attach(&mut c, vault, b"shared bytes", 5);
    for (i, title) in [(0, "edit 0"), (1, "edit 1")] {
        let json = Cluster::item_json(ITEM, title, &[ATT]);
        c.devices[i]
            .save_item(vault, ITEM, &json, c.clocks[i])
            .unwrap();
    }
    c.heal();
    let view = c.devices[0].view();
    let copy = view
        .attachments
        .iter()
        .find(|(id, _)| **id != ATT)
        .map(|(_, p)| p.clone())
        .expect("the copy's attachment");
    assert_eq!(copy.chunks_for, ATT);
    assert_ne!(copy.item_id, ITEM);
    let opened = c.devices[1]
        .open_attachment(&copy, &chunks_of(&c, &copy))
        .unwrap();
    assert_eq!(&opened[..], b"shared bytes");
}
```

- [ ] **Step 2: The payload names the id its chunks are sealed for.**

Apply:

````diff
diff --git a/crates/keyorra-sync/src/fold.rs b/crates/keyorra-sync/src/fold.rs
index 3120c2e..d6c600e 100644
--- a/crates/keyorra-sync/src/fold.rs
+++ b/crates/keyorra-sync/src/fold.rs
@@ -734,6 +734,7 @@ mod tests {
                 key: Zeroizing::new([7; 32]),
                 chunk_size: 3,
                 chunks: vec![[8; 32]],
+                chunks_for: Uuid::from_bytes([9; 16]),
             }),
         }
     }
diff --git a/crates/keyorra-sync/src/payload.rs b/crates/keyorra-sync/src/payload.rs
index 8c33254..bc03113 100644
--- a/crates/keyorra-sync/src/payload.rs
+++ b/crates/keyorra-sync/src/payload.rs
@@ -5,7 +5,7 @@
 //!                "content_from": { bytes16 → uint } }
 //! vault      = { "name": text, "wrapped_key": bytes, "deleted": bool }
 //! attachment = { "item_id": bytes16, "name": text, "size": uint, "key": bytes32,
-//!                "chunk_size": uint, "chunks": [bytes32, …] }
+//!                "chunk_size": uint, "chunks": [bytes32, …], "chunks_for": bytes16 }
 //! ```
 
 use std::fmt;
@@ -48,6 +48,9 @@ pub struct AttachmentPayload {
     pub key: Zeroizing<[u8; 32]>,
     pub chunk_size: u32,
     pub chunks: Vec<[u8; 32]>,
+    /// The attachment id the chunks are sealed for (bound into each chunk): the record's own
+    /// id, or for a conflict copy's attachment the original's, whose chunks it shares.
+    pub chunks_for: Uuid,
 }
 
 /// The decoded content of one record version.
@@ -129,6 +132,7 @@ impl Doc {
                     "chunks",
                     Value::Array(p.chunks.iter().map(Value::bytes).collect()),
                 ),
+                ("chunks_for", Value::bytes(p.chunks_for.as_bytes())),
             ]),
             Doc::Tombstone => return Zeroizing::new(Vec::new()),
         };
@@ -172,8 +176,15 @@ impl Doc {
                 })
             }
             RecordKind::Attachment => {
-                let f =
-                    value.fields(&["item_id", "name", "size", "key", "chunk_size", "chunks"])?;
+                let f = value.fields(&[
+                    "item_id",
+                    "name",
+                    "size",
+                    "key",
+                    "chunk_size",
+                    "chunks",
+                    "chunks_for",
+                ])?;
                 Doc::Attachment(AttachmentPayload {
                     item_id: Uuid::from_bytes(f.get("item_id")?.as_array_of()?),
                     name: f.get("name")?.as_text()?.to_owned(),
@@ -186,6 +197,7 @@ impl Doc {
                         .iter()
                         .map(|c| c.as_array_of())
                         .collect::<Result<_>>()?,
+                    chunks_for: Uuid::from_bytes(f.get("chunks_for")?.as_array_of()?),
                 })
             }
         })
@@ -328,6 +340,7 @@ mod tests {
             key: Zeroizing::new([2; 32]),
             chunk_size: 4 * 1024 * 1024,
             chunks: vec![[3; 32]],
+            chunks_for: Uuid::from_bytes([4; 16]),
         }
     }
 
diff --git a/crates/keyorra-sync/src/present.rs b/crates/keyorra-sync/src/present.rs
index f2c5e82..dba2af6 100644
--- a/crates/keyorra-sync/src/present.rs
+++ b/crates/keyorra-sync/src/present.rs
@@ -541,6 +541,7 @@ mod tests {
             key: Zeroizing::new([0; 32]),
             chunk_size: 1,
             chunks: vec![],
+            chunks_for: ID,
         });
         let s = set(vec![sib(A, 9, &[(A, 1)], att.clone())]);
         assert!(present_attachment(&s).is_some());
````

- [ ] **Step 3: Engine.**

Apply (`seal_attachment`, `write_attachment`, `open_attachment`, the test module):

```diff
diff --git a/crates/keyorra-sync/src/engine.rs b/crates/keyorra-sync/src/engine.rs
index 92dc1f0..534db0b 100644
--- a/crates/keyorra-sync/src/engine.rs
+++ b/crates/keyorra-sync/src/engine.rs
@@ -1150,11 +1150,112 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             key,
             chunk_size: crate::chunk::MAX_CHUNK as u32,
             chunks: Vec::new(),
+            chunks_for: id,
         });
         self.write(RecordKind::Attachment, id, Some(vault_id), doc, wall_ms)?;
         Ok(id)
     }
 
+    /// An attachment's content as chunks (plan A2): a new random key, the bytes cut into
+    /// `chunk_size` pieces (at most [`crate::chunk::MAX_CHUNK`]), each sealed for this
+    /// attachment id. The caller stores the chunks first, then writes the record with
+    /// [`Engine::write_attachment`] (a reader must never see a record whose chunks are not
+    /// there yet, spec §5.3).
+    pub fn seal_attachment(
+        &mut self,
+        id: Uuid,
+        item_id: Uuid,
+        name: &str,
+        bytes: &[u8],
+        chunk_size: usize,
+    ) -> Result<(AttachmentPayload, Vec<Vec<u8>>)> {
+        let chunk_size = chunk_size.clamp(1, crate::chunk::MAX_CHUNK);
+        let mut key = Zeroizing::new([0u8; 32]);
+        self.rng.fill_bytes(&mut key[..]);
+        let pieces: Vec<&[u8]> = if bytes.is_empty() {
+            vec![&[][..]]
+        } else {
+            bytes.chunks(chunk_size).collect()
+        };
+        let count = u32::try_from(pieces.len())
+            .map_err(|_| crate::error::malformed("attachment too large"))?;
+        let attachment_key = Key::from_bytes(*key);
+        let mut sealed = Vec::with_capacity(pieces.len());
+        let mut names = Vec::with_capacity(pieces.len());
+        for (index, piece) in pieces.into_iter().enumerate() {
+            let place = crate::chunk::ChunkPlace {
+                account_id: self.account_id,
+                attachment_id: id,
+                index: index as u32,
+                count,
+            };
+            let chunk = crate::chunk::seal_chunk(&attachment_key, &place, piece, &mut self.rng)?;
+            let mut name = [0u8; 32];
+            name.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(&chunk));
+            names.push(name);
+            sealed.push(chunk);
+        }
+        let payload = AttachmentPayload {
+            item_id,
+            name: name.to_owned(),
+            size: bytes.len() as u64,
+            key,
+            chunk_size: chunk_size as u32,
+            chunks: names,
+            chunks_for: id,
+        };
+        Ok((payload, sealed))
+    }
+
+    /// Writes an attachment record whose chunks are stored ([`Engine::seal_attachment`]).
+    pub fn write_attachment(
+        &mut self,
+        vault_id: Uuid,
+        id: Uuid,
+        payload: AttachmentPayload,
+        wall_ms: u64,
+    ) -> Result<()> {
+        self.write(
+            RecordKind::Attachment,
+            id,
+            Some(vault_id),
+            Doc::Attachment(payload),
+            wall_ms,
+        )
+    }
+
+    /// The content of an attachment from its chunks, in order (as named by `payload`).
+    /// Each chunk must have its name and open for its place; the total must be the size.
+    pub fn open_attachment(
+        &self,
+        payload: &AttachmentPayload,
+        chunks: &[Vec<u8>],
+    ) -> Result<Zeroizing<Vec<u8>>> {
+        if chunks.len() != payload.chunks.len() {
+            return Err(crate::error::malformed("attachment chunk count"));
+        }
+        let count =
+            u32::try_from(chunks.len()).map_err(|_| crate::error::malformed("chunk count"))?;
+        let key = Key::from_bytes(*payload.key);
+        let mut out = Zeroizing::new(Vec::with_capacity(payload.size.min(1 << 30) as usize));
+        for (index, (chunk, name)) in chunks.iter().zip(&payload.chunks).enumerate() {
+            if <sha2::Sha256 as sha2::Digest>::digest(chunk).as_slice() != name {
+                return Err(crate::error::malformed("chunk does not match its name"));
+            }
+            let place = crate::chunk::ChunkPlace {
+                account_id: self.account_id,
+                attachment_id: payload.chunks_for,
+                index: index as u32,
+                count,
+            };
+            out.extend_from_slice(&crate::chunk::open_chunk(&key, &place, chunk)?);
+        }
+        if out.len() as u64 != payload.size {
+            return Err(crate::error::malformed("attachment size"));
+        }
+        Ok(out)
+    }
+
     pub fn remove_attachment(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
         let vault_id = self
             .fold
@@ -2503,6 +2604,8 @@ fn is_trust_entry(entry: &Entry) -> bool {
 #[cfg(test)]
 mod adversary_tests;
 #[cfg(test)]
+mod attachment_tests;
+#[cfg(test)]
 mod attack_tests;
 #[cfg(test)]
 mod recovery_tests;
```

- [ ] **Step 4: Run and commit.**

`cargo test -p keyorra-sync` green. Commit: `Sync A2-2: attachment contents as chunks`.

---

### Task 2: Attachment contents in the store

**Files:** Modify `crates/keyorra-core/src/store/sync.rs`, `mod.rs`, `sync_tests.rs`.

- [ ] **Step 1: Failing test.**

`attachments_from_sync_are_stored_and_removed` is in this patch:

```diff
diff --git a/crates/keyorra-core/src/store/sync_tests.rs b/crates/keyorra-core/src/store/sync_tests.rs
index 65526e2..0f08482 100644
--- a/crates/keyorra-core/src/store/sync_tests.rs
+++ b/crates/keyorra-core/src/store/sync_tests.rs
@@ -398,3 +398,42 @@ fn rotation_stops_on_an_unreadable_item_and_changes_nothing() {
     store.unlock(PW).unwrap();
     assert_eq!(store.get_item(good.id).unwrap().title, "good");
 }
+
+/// Plan A2-2: attachment contents from sync, and what the sync layer reads of local ones.
+#[test]
+fn attachments_from_sync_are_stored_and_removed() {
+    let (_dir, _path, mut store) = new_store();
+    store.set_sync_tracking(true).unwrap();
+    let v = store.create_vault("Personal").unwrap();
+    let mut item = Item::new(v.id, ItemKind::Login, "x", 1);
+    store.save_item(&item).unwrap();
+    store.clear_changes(&changes(&store)).unwrap();
+    let att = Uuid::from_bytes([9; 16]);
+    item.attachments.push(crate::model::AttachmentRef {
+        id: att,
+        name: "a.txt".into(),
+        size: 5,
+        extra: Default::default(),
+    });
+    store.apply_remote_item(&item, None).unwrap();
+    assert_eq!(store.attachment_state(att).unwrap(), None);
+    store
+        .apply_remote_attachment(att, item.id, b"bytes")
+        .unwrap();
+    store
+        .apply_remote_attachment(att, item.id, b"bytes")
+        .unwrap();
+    assert_eq!(&store.get_attachment(att).unwrap()[..], b"bytes");
+    let state = store.attachment_state(att).unwrap().unwrap();
+    assert_eq!((state.item_id, state.live), (item.id, true));
+    assert_eq!(&store.attachment_content(att).unwrap()[..], b"bytes");
+    assert_eq!(store.attachment_ids().unwrap(), vec![att]);
+    store.apply_remote_attachment_removed(att).unwrap();
+    assert!(store.get_attachment(att).is_err());
+    assert!(!store.attachment_state(att).unwrap().unwrap().live);
+    assert!(store.attachment_ids().unwrap().is_empty());
+    assert!(changes(&store).is_empty(), "nothing recorded");
+    // A local attachment reads the same way.
+    let local = store.add_attachment(item.id, "b.txt", b"local", 3).unwrap();
+    assert_eq!(&store.attachment_content(local.id).unwrap()[..], b"local");
+}
```

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/crates/keyorra-core/src/store/mod.rs b/crates/keyorra-core/src/store/mod.rs
index 4eaecf9..fe23be0 100644
--- a/crates/keyorra-core/src/store/mod.rs
+++ b/crates/keyorra-core/src/store/mod.rs
@@ -21,7 +21,7 @@ mod sync_tests;
 mod tests;
 
 use sync::record_change;
-pub use sync::{Change, ChangeKind, MetaWriter};
+pub use sync::{AttachmentState, Change, ChangeKind, MetaWriter};
 
 const DB_VERSION: i64 = MIGRATIONS.len() as i64;
 // Format label from the Lockbox days; kept so existing vaults and pairings stay readable.
diff --git a/crates/keyorra-core/src/store/sync.rs b/crates/keyorra-core/src/store/sync.rs
index 79da4e8..db67b4e 100644
--- a/crates/keyorra-core/src/store/sync.rs
+++ b/crates/keyorra-core/src/store/sync.rs
@@ -10,13 +10,14 @@ use std::collections::BTreeMap;
 
 use rusqlite::{params, Connection, OptionalExtension};
 use uuid::Uuid;
+use zeroize::Zeroizing;
 
 use super::{
     configure, insert_vault, parse_id, reencrypt_attachments, sealed_meta_aad, sealed_meta_key,
     upsert_item, vault_meta_aad, Store,
 };
 use crate::crypto::{self, Key};
-use crate::model::{Item, VaultInfo};
+use crate::model::{Item, VaultInfo, SCHEMA_VERSION};
 use crate::{Error, Result};
 
 const TRACKING_KEY: &str = "sync_tracking";
@@ -251,6 +252,103 @@ impl Store {
         Ok(())
     }
 
+    /// An attachment row as the sync layer needs it, without decrypting: its item and
+    /// whether it is live (`None` when there is no row).
+    pub fn attachment_state(&self, id: Uuid) -> Result<Option<AttachmentState>> {
+        self.account_key()?;
+        let row: Option<(String, i64, i64)> = self
+            .conn
+            .query_row(
+                "SELECT item_id, deleted, length(data) FROM attachments WHERE id = ?1",
+                [id.to_string()],
+                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
+            )
+            .optional()?;
+        Ok(match row {
+            None => None,
+            Some((item_id, deleted, len)) => Some(AttachmentState {
+                item_id: parse_id(&item_id)?,
+                live: deleted == 0 && len > 0,
+            }),
+        })
+    }
+
+    /// The content of a live attachment row, whatever state its item is in.
+    pub fn attachment_content(&self, id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
+        self.account_key()?;
+        let row: Option<(Vec<u8>, String, String)> = self
+            .conn
+            .query_row(
+                "SELECT a.data, a.item_id, i.vault_id FROM attachments a
+                 JOIN items i ON i.id = a.item_id
+                 WHERE a.id = ?1 AND a.deleted = 0 AND length(a.data) > 0",
+                [id.to_string()],
+                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
+            )
+            .optional()?;
+        let (data, item_id, vault_id) =
+            row.ok_or_else(|| Error::NotFound(format!("attachment {id}")))?;
+        let (item_id, vault_id) = (parse_id(&item_id)?, parse_id(&vault_id)?);
+        crypto::open(
+            self.vault_key(vault_id)?,
+            &data,
+            &crypto::attachment_aad(vault_id, item_id, id),
+        )
+    }
+
+    /// Ids of the live attachment rows.
+    pub fn attachment_ids(&self) -> Result<Vec<Uuid>> {
+        let mut stmt = self.conn.prepare(
+            "SELECT id FROM attachments WHERE deleted = 0 AND length(data) > 0 ORDER BY rowid",
+        )?;
+        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
+        rows.map(|r| parse_id(&r?)).collect()
+    }
+
+    /// An attachment's content from sync, for an item the store has. Records nothing;
+    /// writes nothing when the same content is there.
+    pub fn apply_remote_attachment(&mut self, id: Uuid, item_id: Uuid, bytes: &[u8]) -> Result<()> {
+        if let Some(state) = self.attachment_state(id)? {
+            // Attachments never change content: a live row of that item is the same.
+            if state.item_id == item_id && state.live {
+                return Ok(());
+            }
+        }
+        let vault_id: String = self
+            .conn
+            .query_row(
+                "SELECT vault_id FROM items WHERE id = ?1",
+                [item_id.to_string()],
+                |r| r.get(0),
+            )
+            .optional()?
+            .ok_or_else(|| Error::NotFound(format!("item {item_id}")))?;
+        let vault_id = parse_id(&vault_id)?;
+        let data = crypto::seal(
+            self.vault_key(vault_id)?,
+            bytes,
+            &crypto::attachment_aad(vault_id, item_id, id),
+        );
+        self.conn.execute(
+            "INSERT INTO attachments (id, item_id, data, schema) VALUES (?1, ?2, ?3, ?4)
+             ON CONFLICT(id) DO UPDATE SET item_id = excluded.item_id, data = excluded.data,
+                 deleted = 0, revision = attachments.revision + 1",
+            params![id.to_string(), item_id.to_string(), data, SCHEMA_VERSION],
+        )?;
+        Ok(())
+    }
+
+    /// An attachment sync shows as removed. Records nothing.
+    pub fn apply_remote_attachment_removed(&mut self, id: Uuid) -> Result<()> {
+        self.account_key()?;
+        self.conn.execute(
+            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
+             WHERE id = ?1 AND deleted = 0",
+            [id.to_string()],
+        )?;
+        Ok(())
+    }
+
     /// An item the sync engine shows as purged: its data goes, the row stays a tombstone.
     pub fn apply_remote_purge(&mut self, id: Uuid) -> Result<()> {
         self.account_key()?;
@@ -419,3 +517,11 @@ impl MetaWriter {
         Ok(())
     }
 }
+
+/// What [`Store::attachment_state`] returns.
+#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+pub struct AttachmentState {
+    pub item_id: Uuid,
+    /// `false`: removed.
+    pub live: bool,
+}
```

- [ ] **Step 3: Run and commit.**

Commit: `Core A2-2: attachment rows for sync`.

---

### Task 3: Attachments through the session bridge

**Files:** Modify `crates/keyorra-session/src/sync/mod.rs`, `crates/keyorra-session/src/sync/tests.rs`, `crates/keyorra-session/Cargo.toml`, `crates/keyorra-sync/src/transport.rs`.

- [ ] **Step 1: Failing tests.**

Apply (attachment contents travel and removals follow; an attachment whose chunks are not there yet waits and is reported; a conflict copy keeps the content; **two vault stores sync an item with an attachment through a real folder**):

```diff
diff --git a/crates/keyorra-session/Cargo.toml b/crates/keyorra-session/Cargo.toml
index 00607b0..5f3d458 100644
--- a/crates/keyorra-session/Cargo.toml
+++ b/crates/keyorra-session/Cargo.toml
@@ -25,4 +25,5 @@ zeroize = { version = "1", features = ["serde"] }
 [dev-dependencies]
 keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
 keyorra-sync = { path = "../keyorra-sync", features = ["test-utils"] }
+keyorra-sync-fs = { path = "../keyorra-sync-fs" }
 tempfile = "3"
diff --git a/crates/keyorra-session/src/sync/tests.rs b/crates/keyorra-session/src/sync/tests.rs
index 4496ed9..cee5f48 100644
--- a/crates/keyorra-session/src/sync/tests.rs
+++ b/crates/keyorra-session/src/sync/tests.rs
@@ -1086,3 +1086,175 @@ fn review_a1d2_i7_a_refused_new_account_changes_nothing() {
     }
     round(&mut main, NOW_MS + 161);
 }
+
+// ---- attachment contents (plan A2-2) ----
+
+#[test]
+fn attachment_contents_travel_and_removals_follow() {
+    let (_t, mut main, mut laptop) = pair();
+    let item = find(&laptop.store, "before sync");
+    let att = laptop
+        .store
+        .add_attachment(item.id, "scan.pdf", b"%PDF bytes", 200)
+        .unwrap();
+    for t in 200..204 {
+        round(&mut laptop, NOW_MS + t);
+        round(&mut main, NOW_MS + t);
+    }
+    assert_eq!(
+        &main.store.get_attachment(att.id).unwrap()[..],
+        b"%PDF bytes"
+    );
+    let shown = main.store.get_item(item.id).unwrap();
+    assert_eq!(shown.attachments.len(), 1);
+    main.store.remove_attachment(item.id, att.id, 210).unwrap();
+    for t in 210..214 {
+        round(&mut main, NOW_MS + t);
+        round(&mut laptop, NOW_MS + t);
+    }
+    assert!(laptop.store.get_attachment(att.id).is_err());
+    assert!(laptop
+        .store
+        .get_item(item.id)
+        .unwrap()
+        .attachments
+        .is_empty());
+}
+
+#[test]
+fn an_attachment_whose_chunks_are_not_there_yet_waits_and_is_reported() {
+    let (transport, mut main, mut laptop) = pair();
+    let item = find(&laptop.store, "before sync");
+    let att = laptop
+        .store
+        .add_attachment(item.id, "a.bin", b"payload", 220)
+        .unwrap();
+    round(&mut laptop, NOW_MS + 220);
+    // The chunks have not reached this store yet.
+    let chunks = transport.take_chunks();
+    assert!(!chunks.is_empty());
+    let report = main.synced.round(&mut main.store, NOW_MS + 221).unwrap();
+    assert!(
+        report.failed.iter().any(|(id, _)| *id == att.id),
+        "{report:?}"
+    );
+    assert!(main.store.get_attachment(att.id).is_err());
+    for c in chunks {
+        transport.put_chunk(&c).unwrap();
+    }
+    round(&mut main, NOW_MS + 222);
+    assert_eq!(&main.store.get_attachment(att.id).unwrap()[..], b"payload");
+}
+
+#[test]
+fn a_conflict_copy_keeps_the_attachment_content() {
+    let (_t, mut main, mut laptop) = pair();
+    let item = find(&laptop.store, "before sync");
+    let att = laptop
+        .store
+        .add_attachment(item.id, "a.txt", b"shared", 230)
+        .unwrap();
+    for t in 230..233 {
+        round(&mut laptop, NOW_MS + t);
+        round(&mut main, NOW_MS + t);
+    }
+    retitle(&mut main.store, "before sync", "edited on main");
+    retitle(&mut laptop.store, "before sync", "edited on laptop");
+    for t in 233..240 {
+        round(&mut main, NOW_MS + t);
+        round(&mut laptop, NOW_MS + t);
+    }
+    for store in [&main.store, &laptop.store] {
+        let copies: Vec<_> = store
+            .list_items(None)
+            .unwrap()
+            .into_iter()
+            .filter_map(|e| match e {
+                keyorra_core::store::ItemEntry::Ok(i) if i.conflict.is_some() => Some(i),
+                _ => None,
+            })
+            .collect();
+        assert_eq!(copies.len(), 1);
+        let copy_att = copies[0].attachments[0].id;
+        assert_ne!(copy_att, att.id);
+        assert_eq!(&store.get_attachment(copy_att).unwrap()[..], b"shared");
+    }
+}
+
+/// Two vault stores sync through a real folder (plan A2): enable, join, approve, an item
+/// with an attachment, and an edit back.
+#[test]
+fn two_stores_sync_through_a_folder() {
+    use keyorra_sync_fs::{FolderTransport, LocalDisk};
+    let folder = tempfile::tempdir().unwrap();
+    let open =
+        || FolderTransport::open(folder.path(), None, std::sync::Arc::new(LocalDisk)).unwrap();
+    let dir = tempfile::tempdir().unwrap();
+    let mut main_store =
+        Store::create(&dir.path().join("m.db"), PW, KdfParams::INSECURE_FAST).unwrap();
+    let vault = main_store.create_vault("Personal").unwrap();
+    let item = Item::new(vault.id, ItemKind::Login, "in the folder", 1);
+    main_store.save_item(&item).unwrap();
+    main_store
+        .add_attachment(item.id, "f.txt", b"file bytes", 2)
+        .unwrap();
+    let mut main_keys = MemoryDeviceKeys::default();
+    let Enabled {
+        mut synced, kit, ..
+    } = enable(
+        &mut main_store,
+        open(),
+        &mut main_keys,
+        "Main",
+        PW,
+        KdfParams::INSECURE_FAST,
+        NOW_MS,
+    )
+    .unwrap();
+    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
+    let mut laptop_keys = MemoryDeviceKeys::default();
+    let Joined {
+        store: mut laptop_store,
+        synced: mut laptop,
+        ..
+    } = join(
+        &dir.path().join("l.db"),
+        PW,
+        KdfParams::INSECURE_FAST,
+        &sk,
+        &id,
+        Some(&synced.root_pin()),
+        open(),
+        &mut laptop_keys,
+        "Laptop",
+        cheap_unlock(PW, *sk.as_bytes()),
+        NOW_MS,
+    )
+    .unwrap();
+    synced.round(&mut main_store, NOW_MS + 1).unwrap();
+    let code = laptop.key_code();
+    synced
+        .approve(laptop.engine().device(), &code, NOW_MS + 2)
+        .unwrap();
+    for t in 3..8 {
+        synced.round(&mut main_store, NOW_MS + t).unwrap();
+        laptop.round(&mut laptop_store, NOW_MS + t).unwrap();
+    }
+    let got = laptop_store.get_item(item.id).unwrap();
+    assert_eq!(got.title, "in the folder");
+    assert_eq!(
+        &laptop_store.get_attachment(got.attachments[0].id).unwrap()[..],
+        b"file bytes"
+    );
+    let mut edited = got;
+    edited.title = "edited on the laptop".into();
+    laptop_store.save_item(&edited).unwrap();
+    for t in 8..12 {
+        laptop.round(&mut laptop_store, NOW_MS + t).unwrap();
+        synced.round(&mut main_store, NOW_MS + t).unwrap();
+    }
+    assert_eq!(
+        main_store.get_item(item.id).unwrap().title,
+        "edited on the laptop"
+    );
+}
diff --git a/crates/keyorra-sync/src/transport.rs b/crates/keyorra-sync/src/transport.rs
index 9f155d5..e2d2e88 100644
--- a/crates/keyorra-sync/src/transport.rs
+++ b/crates/keyorra-sync/src/transport.rs
@@ -156,6 +156,13 @@ impl MemoryTransport {
         }
     }
 
+    /// Removes and returns every attachment chunk (tests: chunks not arrived yet).
+    pub fn take_chunks(&self) -> Vec<Vec<u8>> {
+        std::mem::take(&mut self.files.lock().unwrap().chunks)
+            .into_values()
+            .collect()
+    }
+
     /// An independent copy of everything stored now (tests: one side of a fork).
     pub fn deep_copy(&self) -> MemoryTransport {
         MemoryTransport {
```

- [ ] **Step 2: Implement.**

Apply (attachment changes: chunks then record, a chunk that cannot be stored keeps the change; `show_attachments`; existing attachments recorded as changes when sync is turned on or a vault rejoins):

```diff
diff --git a/crates/keyorra-session/src/sync/mod.rs b/crates/keyorra-session/src/sync/mod.rs
index 6a7267f..4683a0c 100644
--- a/crates/keyorra-session/src/sync/mod.rs
+++ b/crates/keyorra-session/src/sync/mod.rs
@@ -237,6 +237,18 @@ fn item_json(item: &Item) -> Result<Zeroizing<Vec<u8>>> {
         .map_err(|e| Error::Malformed(e.to_string()))
 }
 
+/// Every live attachment of the store, as changes (written unless sync has them).
+fn attachment_changes(store: &Store) -> Result<Vec<Change>> {
+    Ok(store
+        .attachment_ids()?
+        .into_iter()
+        .map(|id| Change {
+            kind: ChangeKind::Attachment,
+            id,
+        })
+        .collect())
+}
+
 /// Whether this store is the main device of its synced account (from its configuration, so
 /// also while sync is not running).
 pub fn is_main(store: &Store) -> Result<bool> {
@@ -334,6 +346,8 @@ pub fn enable<T: Transport>(
         caught_up: false,
     };
     synced.commit(store)?;
+    // Attachment contents go through the normal path (chunks first, then the record).
+    store.record_changes(&attachment_changes(store)?)?;
     let first_round = synced.round(store, wall_ms);
     Ok(Enabled {
         synced,
@@ -539,7 +553,8 @@ fn join_store<T: Transport>(
         };
         if let Some(base) = &synced.base {
             // What changed here while sync was off is written once the device may write.
-            let changed = merge::changed_since(store, base)?;
+            let mut changed = merge::changed_since(store, base)?;
+            changed.extend(attachment_changes(store)?);
             synced.commit(store)?;
             store.record_changes(&changed)?;
         } else {
@@ -700,6 +715,11 @@ impl<T: Transport> Synced<T> {
                     report.reverted.push((change, reason));
                 }
                 Err(Error::Refused(_)) => all = false,
+                // The store of files did not take a chunk: tried again next round.
+                Err(Error::Transport(reason)) => {
+                    all = false;
+                    report.failed.push((change.id, reason));
+                }
                 Err(Error::NotFound(reason)) => {
                     if still_here(store, change)? {
                         all = false;
@@ -825,8 +845,112 @@ impl<T: Transport> Synced<T> {
                 Ok(Outcome::Written)
             }
             // Attachment contents travel with the folder transport (plan A2).
-            ChangeKind::Attachment => Ok(Outcome::Written),
+            // Its content as chunks, stored before the record is written (spec §5.3).
+            // Attachments never change: an id sync has is the same content.
+            ChangeKind::Attachment => {
+                let Some(state) = store.attachment_state(change.id)? else {
+                    return Ok(Outcome::Written);
+                };
+                let in_sync = view.attachments.contains_key(&change.id);
+                if state.live && !in_sync {
+                    let Some((item, _)) = store.item_state(state.item_id)? else {
+                        return Ok(Outcome::Written);
+                    };
+                    let name = item
+                        .attachments
+                        .iter()
+                        .find(|a| a.id == change.id)
+                        .map(|a| a.name.clone())
+                        .unwrap_or_default();
+                    let bytes = store.attachment_content(change.id)?;
+                    let (payload, chunks) = self.engine.seal_attachment(
+                        change.id,
+                        item.id,
+                        &name,
+                        &bytes,
+                        keyorra_sync::chunk::MAX_CHUNK,
+                    )?;
+                    for chunk in &chunks {
+                        self.transport.put_chunk(chunk)?;
+                    }
+                    self.engine
+                        .write_attachment(item.vault_id, change.id, payload, wall_ms)?;
+                } else if !state.live && in_sync {
+                    self.engine.remove_attachment(change.id, wall_ms)?;
+                }
+                Ok(Outcome::Written)
+            }
+        }
+    }
+
+    /// Attachment contents sync shows: fetched as chunks and stored; removed ones removed.
+    /// Content whose chunks are not here yet waits (reported), and is tried every round.
+    fn show_attachments(
+        &mut self,
+        store: &mut Store,
+        view: &View,
+        pending: &BTreeSet<Uuid>,
+    ) -> Result<Vec<(Uuid, String)>> {
+        let mut failed = Vec::new();
+        for (id, payload) in &view.attachments {
+            if pending.contains(id) {
+                continue;
+            }
+            let here = store.attachment_state(*id)?;
+            if here.is_some_and(|h| h.live && h.item_id == payload.item_id) {
+                continue;
+            }
+            if store.item_state(payload.item_id)?.is_none() {
+                continue;
+            }
+            let mut chunks = Vec::with_capacity(payload.chunks.len());
+            let mut waiting = false;
+            for name in &payload.chunks {
+                match self
+                    .transport
+                    .get_chunk(&data_encoding::HEXLOWER.encode(name))
+                {
+                    Ok(Fetched::Ready(bytes)) => chunks.push(bytes),
+                    Ok(_) => {
+                        waiting = true;
+                        break;
+                    }
+                    Err(e) => {
+                        failed.push((*id, e.to_string()));
+                        waiting = true;
+                        break;
+                    }
+                }
+            }
+            if waiting {
+                if !failed.iter().any(|(f, _)| f == id) {
+                    failed.push((*id, "waiting for the attachment's content".to_owned()));
+                }
+                continue;
+            }
+            match self.engine.open_attachment(payload, &chunks) {
+                Ok(bytes) => {
+                    if let Err(e) = store.apply_remote_attachment(*id, payload.item_id, &bytes) {
+                        failed.push((*id, e.to_string()));
+                    }
+                }
+                Err(e) => failed.push((*id, e.to_string())),
+            }
         }
+        // Removed in sync: an attachment record the account has that is no longer live.
+        for id in store.attachment_ids()? {
+            if pending.contains(&id) || view.attachments.contains_key(&id) {
+                continue;
+            }
+            if self
+                .engine
+                .fold()
+                .contains(keyorra_sync::envelope::RecordKind::Attachment, id)
+            {
+                store.apply_remote_attachment_removed(id)?;
+            }
+        }
+        Ok(failed)
     }
 
     /// What sync shows, in the store. Records with local changes not yet written are left as
@@ -837,13 +961,15 @@ impl<T: Transport> Synced<T> {
         let pending: BTreeSet<Uuid> = store.pending_changes()?.into_iter().map(|c| c.id).collect();
         let view = self.engine.view();
         let engine = &self.engine;
-        Ok(show_view(
+        let mut failed = show_view(
             store,
             &view,
             &pending,
             |v| engine.vault_key(v),
             wall_ms / 1000,
-        ))
+        );
+        failed.extend(self.show_attachments(store, &view, &pending)?);
+        Ok(failed)
     }
     /// Everything the engine cannot read again from the streams.
     /// Sync is on: the configuration, the change tracking and the engine's state, saved.
```

- [ ] **Step 3: Run and commit.**

`cargo test -p keyorra-session` green. Commit: `Session A2-2: attachment contents sync`.

---

### Task 4: File coordination in the folder transport

**Files:** Modify `crates/keyorra-sync-fs/src/avail.rs`, `lib.rs`, `tests.rs`.

- [ ] **Step 1: Failing test.**

`every_file_access_is_coordinated` is in this patch:

```diff
diff --git a/crates/keyorra-sync-fs/src/tests.rs b/crates/keyorra-sync-fs/src/tests.rs
index 0c1b21c..882cf1b 100644
--- a/crates/keyorra-sync-fs/src/tests.rs
+++ b/crates/keyorra-sync-fs/src/tests.rs
@@ -351,3 +351,44 @@ fn devices_converge_despite_conflict_copies_and_evicted_files() {
     assert_eq!(c.devices[0].view(), c.devices[1].view());
     assert!(c.devices[1].view().items.contains_key(&id));
 }
+
+/// Plan A2-2: every read, write and delete of a file goes through the provider's
+/// coordination (`NSFileCoordinator` in the app).
+#[test]
+fn every_file_access_is_coordinated() {
+    #[derive(Default)]
+    struct Recorder(Mutex<Vec<(Access, PathBuf)>>);
+    impl Availability for Recorder {
+        fn coordinate(
+            &self,
+            path: &Path,
+            access: Access,
+            f: &mut dyn FnMut() -> std::io::Result<()>,
+        ) -> std::io::Result<()> {
+            self.0.lock().unwrap().push((access, path.to_path_buf()));
+            f()
+        }
+    }
+    let dir = tempfile::tempdir().unwrap();
+    let rec = Arc::new(Recorder::default());
+    let t = FolderTransport::open(dir.path(), None, rec.clone()).unwrap();
+    rec.0.lock().unwrap().clear();
+    let segs = some_segments();
+    t.append(&segs[0]).unwrap();
+    t.segments(&device_id(0), 0).unwrap();
+    t.delete_segment(&device_id(0), 1).unwrap();
+    let seg = dir
+        .path()
+        .join("streams")
+        .join("01".repeat(16))
+        .join(names::segment_file(1));
+    let log = rec.0.lock().unwrap().clone();
+    assert_eq!(
+        log,
+        vec![
+            (Access::Write, seg.clone()),
+            (Access::Read, seg.clone()),
+            (Access::Delete, seg),
+        ]
+    );
+}
```

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/crates/keyorra-sync-fs/src/avail.rs b/crates/keyorra-sync-fs/src/avail.rs
index 36d8736..b1f3255 100644
--- a/crates/keyorra-sync-fs/src/avail.rs
+++ b/crates/keyorra-sync-fs/src/avail.rs
@@ -4,6 +4,15 @@
 
 use std::path::Path;
 
+/// How a coordinated access touches a file.
+#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+pub enum Access {
+    Read,
+    /// The file is created or replaced (the temp file is renamed onto it).
+    Write,
+    Delete,
+}
+
 /// What a file is, without opening it.
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum FileState {
@@ -24,6 +33,18 @@ pub trait Availability: Send + Sync {
     fn request_download(&self, path: &Path) {
         let _ = path;
     }
+    /// Runs `f`, which reads, writes or deletes `path`, the way the provider wants file
+    /// access coordinated with its sync client (`NSFileCoordinator` in the app). Directory
+    /// listings are not coordinated.
+    fn coordinate(
+        &self,
+        path: &Path,
+        access: Access,
+        f: &mut dyn FnMut() -> std::io::Result<()>,
+    ) -> std::io::Result<()> {
+        let _ = (path, access);
+        f()
+    }
 }
 
 /// A plain folder: only `SF_DATALESS` is looked at (no download requests).
diff --git a/crates/keyorra-sync-fs/src/lib.rs b/crates/keyorra-sync-fs/src/lib.rs
index e5a6f41..9244367 100644
--- a/crates/keyorra-sync-fs/src/lib.rs
+++ b/crates/keyorra-sync-fs/src/lib.rs
@@ -23,7 +23,7 @@ use keyorra_sync::snapshot::{snapshot_name, SnapshotHeader};
 use keyorra_sync::transport::{AppendOutcome, Fetched, Transport};
 use keyorra_sync::{DeviceId, Error, Result};
 
-pub use avail::{Availability, FileState, LocalDisk};
+pub use avail::{Access, Availability, FileState, LocalDisk};
 use names::*;
 use write::{choose_temp_dir, write_file, Mode};
 
@@ -137,9 +137,14 @@ impl FolderTransport {
                 return Ok(Fetched::Missing);
             }
         }
-        match std::fs::read(path) {
-            Ok(bytes) if bytes.is_empty() => Ok(Fetched::Pending),
-            Ok(bytes) => Ok(Fetched::Ready(bytes)),
+        let mut bytes = Vec::new();
+        let read = self.availability.coordinate(path, Access::Read, &mut || {
+            bytes = std::fs::read(path)?;
+            Ok(())
+        });
+        match read {
+            Ok(()) if bytes.is_empty() => Ok(Fetched::Pending),
+            Ok(()) => Ok(Fetched::Ready(bytes)),
             Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fetched::Missing),
             Err(e) => Err(io("reading the folder", e)),
         }
@@ -162,7 +167,9 @@ impl FolderTransport {
     }
 
     fn write(&self, dest: &Path, bytes: &[u8], mode: Mode) -> std::io::Result<()> {
-        write_file(&self.tmp, dest, bytes, mode)
+        self.availability.coordinate(dest, Access::Write, &mut || {
+            write_file(&self.tmp, dest, bytes, mode)
+        })
     }
 
     fn remove(&self, path: &Path) -> Result<()> {
@@ -174,7 +181,13 @@ impl FolderTransport {
                     .unwrap_or_default(),
             )),
         ] {
-            match std::fs::remove_file(&p) {
+            if p.symlink_metadata().is_err() {
+                continue;
+            }
+            let removed = self
+                .availability
+                .coordinate(&p, Access::Delete, &mut || std::fs::remove_file(&p));
+            match removed {
                 Ok(()) => {}
                 Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                 Err(e) => return Err(io("deleting from the folder", e)),
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A2-2: every file access in the folder is coordinated`.

---

### Task 5: One folder per account in the session

**Files:** Modify `crates/keyorra-session/src/session/sync.rs`, `sync_tests.rs`, `crates/keyorra-session/src/sync/mod.rs`, `merge.rs`, `tests.rs`.

- [ ] **Step 1: Failing tests.**

The session tests share a `Place` (one folder per account) instead of one transport; each account gets its own folder; starting a new account leaves the old folder; turning sync on refuses a folder that holds an account (bridge test):

```diff
diff --git a/crates/keyorra-session/src/session/sync_tests.rs b/crates/keyorra-session/src/session/sync_tests.rs
index 7264371..0b9f09a 100644
--- a/crates/keyorra-session/src/session/sync_tests.rs
+++ b/crates/keyorra-session/src/session/sync_tests.rs
@@ -5,16 +5,27 @@ use keyorra_core::model::ItemKind;
 use keyorra_sync::header::Header;
 use keyorra_sync::keys::derive_sync_keys;
 use keyorra_sync::secret_key::SecretKey;
+use std::collections::BTreeMap;
+use std::sync::{Arc, Mutex};
+
 use keyorra_sync::transport::MemoryTransport;
 
 use super::tests::{new_session, unlocked_session, PW};
 use super::*;
 use crate::sync::{DeviceKeyStore, MemoryDeviceKeys};
 
+/// The sync place the test Macs share: one folder (in memory) per account.
+#[derive(Clone, Default)]
+struct Place(Arc<Mutex<BTreeMap<keyorra_sync::AccountId, MemoryTransport>>>);
+
+impl Place {
+    fn folders(&self) -> usize {
+        self.0.lock().unwrap().len()
+    }
+}
+
 struct TestLink {
-    transport: MemoryTransport,
-    /// Where a new account goes (its own location).
-    fresh: MemoryTransport,
+    place: Place,
     keys: MemoryDeviceKeys,
     name: &'static str,
 }
@@ -25,14 +36,32 @@ thread_local! {
 }
 
 impl SyncLink for TestLink {
-    fn transport(&self) -> Result<BoxedTransport, String> {
+    fn transport(&self, account: &keyorra_sync::AccountId) -> Result<BoxedTransport, String> {
         if OFFLINE.get() {
             return Err("the folder is not available".into());
         }
-        Ok(Box::new(self.transport.clone()))
+        match self.place.0.lock().unwrap().get(account) {
+            Some(t) => Ok(Box::new(t.clone())),
+            None => Err("no folder for this account".into()),
+        }
+    }
+    fn new_account_transport(
+        &self,
+        account: &keyorra_sync::AccountId,
+    ) -> Result<BoxedTransport, String> {
+        let t = MemoryTransport::new();
+        self.place.0.lock().unwrap().insert(*account, t.clone());
+        Ok(Box::new(t))
     }
-    fn fresh_transport(&self) -> Result<BoxedTransport, String> {
-        Ok(Box::new(self.fresh.clone()))
+    fn join_candidates(&self) -> Result<Vec<BoxedTransport>, String> {
+        Ok(self
+            .place
+            .0
+            .lock()
+            .unwrap()
+            .values()
+            .map(|t| Box::new(t.clone()) as BoxedTransport)
+            .collect())
     }
     fn device_keys(&self) -> Box<dyn DeviceKeyStore> {
         Box::new(self.keys.clone())
@@ -58,10 +87,9 @@ impl SyncLink for TestLink {
     }
 }
 
-fn link(s: &mut Session, transport: &MemoryTransport, name: &'static str) {
+fn link(s: &mut Session, place: &Place, name: &'static str) {
     s.set_sync_link(Box::new(TestLink {
-        transport: transport.clone(),
-        fresh: transport.clone(),
+        place: place.clone(),
         keys: MemoryDeviceKeys::default(),
         name,
     }));
@@ -94,11 +122,11 @@ fn rounds(a: &mut Session, b: &mut Session, from: u64) {
 
 /// The main Mac with sync on, and a second Mac joined with the setup code and approved.
 fn two_macs() -> (
-    MemoryTransport,
+    Place,
     (tempfile::TempDir, Session),
     (tempfile::TempDir, Session),
 ) {
-    let transport = MemoryTransport::new();
+    let transport = Place::default();
     let (d1, mut main) = unlocked_session();
     link(&mut main, &transport, "Main");
     add(&mut main, "before sync", 1_000);
@@ -288,29 +316,22 @@ fn review_a1d2_i11_the_kit_needs_a_recent_password() {
     assert!(main.emergency_kit(Some(PW), 5_002).is_ok());
 }
 
-/// Review A1d-2 I12: a location that holds another account is not used for a new one.
+/// Review A1d-2 I12 with plan A2: each account gets its own folder; a vault of another
+/// account turning sync on does not touch the first account's folder.
 #[test]
-fn review_a1d2_i12_enable_refuses_a_location_with_an_account() {
-    let (transport, _main, _laptop) = two_macs();
+fn review_a1d2_i12_each_account_gets_its_own_folder() {
+    let (place, _main, _laptop) = two_macs();
     let (_d, mut other) = unlocked_session();
-    other.set_sync_link(Box::new(TestLink {
-        transport: transport.clone(),
-        fresh: transport.clone(),
-        keys: MemoryDeviceKeys::default(),
-        name: "Other",
-    }));
-    assert_eq!(
-        other.enable_sync(PW, 1_130).unwrap_err().kind,
-        ErrorKind::Invalid
-    );
-    assert!(!other.sync_status().unwrap().enabled);
+    link(&mut other, &place, "Other");
+    other.enable_sync(PW, 1_130).unwrap();
+    assert_eq!(place.folders(), 2);
 }
 
 /// Review A1d-2 I7: a wrong password leaves sync running on the old account; a right one
-/// moves to a new account in its own location and drops the Touch ID record.
+/// moves to a new account in its own folder.
 #[test]
 fn review_a1d2_i7_starting_a_new_account() {
-    let (t, (_d1, mut main), _laptop) = two_macs();
+    let (place, (_d1, mut main), _laptop) = two_macs();
     assert_eq!(
         main.start_new_sync_account("wrong password!", 1_140)
             .unwrap_err()
@@ -318,29 +339,18 @@ fn review_a1d2_i7_starting_a_new_account() {
         ErrorKind::WrongPassword
     );
     assert!(main.synced.is_some());
-    // The same location holds the old account: refused, nothing changes.
-    assert_eq!(
-        main.start_new_sync_account(PW, 1_141).unwrap_err().kind,
-        ErrorKind::Invalid
-    );
-    assert!(main.synced.is_some());
-    // A location of its own.
-    main.set_sync_link(Box::new(TestLink {
-        transport: t.clone(),
-        fresh: MemoryTransport::new(),
-        keys: MemoryDeviceKeys::default(),
-        name: "Main",
-    }));
+    assert_eq!(place.folders(), 1);
     let kit = main.start_new_sync_account(PW, 1_142).unwrap();
     assert!(kit.setup_code.starts_with("KEYORRA-SETUP-1-"));
     assert!(main.sync_status().unwrap().enabled);
+    assert_eq!(place.folders(), 2, "the old account's folder stays");
 }
 
 /// Wrong passwords given to turn sync on count towards the unlock throttle.
 #[test]
 fn wrong_passwords_for_sync_are_throttled() {
     let (_d, mut s) = unlocked_session();
-    link(&mut s, &MemoryTransport::new(), "Main");
+    link(&mut s, &Place::default(), "Main");
     let mut kinds = Vec::new();
     for t in 0..8 {
         kinds.push(
diff --git a/crates/keyorra-session/src/sync/tests.rs b/crates/keyorra-session/src/sync/tests.rs
index cee5f48..6cc92ee 100644
--- a/crates/keyorra-session/src/sync/tests.rs
+++ b/crates/keyorra-session/src/sync/tests.rs
@@ -66,6 +66,7 @@ fn main_device(transport: &MemoryTransport) -> (Device, EmergencyKit) {
         ..
     } = enable(
         &mut store,
+        new_account_id(),
         transport.clone(),
         &mut keys,
         "Main",
@@ -490,6 +491,7 @@ fn review_a1d_i5_enable_succeeds_when_the_first_round_fails() {
     let mut keys = MemoryDeviceKeys::default();
     let enabled = enable(
         &mut store,
+        new_account_id(),
         faulty,
         &mut keys,
         "Main",
@@ -792,6 +794,7 @@ fn the_main_device_starts_a_new_account_with_new_keys() {
     let fresh = MemoryTransport::new();
     let Enabled { synced, kit, .. } = start_new_account(
         &mut main.store,
+        new_account_id(),
         fresh.clone(),
         &mut main.keys,
         "Main",
@@ -965,6 +968,7 @@ fn review_a1d2_i6_enabling_again_forgets_the_old_rejoin_base() {
     let fresh = MemoryTransport::new();
     let enabled = enable(
         &mut store,
+        new_account_id(),
         fresh.clone(),
         &mut keys,
         "Laptop",
@@ -1070,6 +1074,7 @@ fn review_a1d2_i7_a_refused_new_account_changes_nothing() {
     for (password, location) in [("wrong password!", MemoryTransport::new()), (PW, transport)] {
         assert!(start_new_account(
             &mut main.store,
+            new_account_id(),
             location,
             &mut main.keys,
             "Main",
@@ -1203,6 +1208,7 @@ fn two_stores_sync_through_a_folder() {
         mut synced, kit, ..
     } = enable(
         &mut main_store,
+        new_account_id(),
         open(),
         &mut main_keys,
         "Main",
@@ -1258,3 +1264,23 @@ fn two_stores_sync_through_a_folder() {
         "edited on the laptop"
     );
 }
+
+/// Review A1d-2 I12: a folder that already holds an account is not used for a new one.
+#[test]
+fn enabling_refuses_a_folder_that_holds_an_account() {
+    let (transport, _main, _laptop) = pair();
+    let dir = tempfile::tempdir().unwrap();
+    let mut store = Store::create(&dir.path().join("o.db"), PW, KdfParams::INSECURE_FAST).unwrap();
+    let result = enable(
+        &mut store,
+        new_account_id(),
+        transport,
+        &mut MemoryDeviceKeys::default(),
+        "Other",
+        PW,
+        KdfParams::INSECURE_FAST,
+        NOW_MS + 300,
+    );
+    assert!(matches!(result, Err(Error::Refused(_))));
+    assert!(!is_enabled(&store).unwrap());
+}
```

- [ ] **Step 2: Implement.**

Apply (`new_account_id`, `account_id`, `holds_account`; `enable` and `start_new_account` take the account id; the `SyncLink` methods; joining picks the folder by the Secret Key id):

```diff
diff --git a/crates/keyorra-session/src/session/sync.rs b/crates/keyorra-session/src/session/sync.rs
index 2707152..df029f3 100644
--- a/crates/keyorra-session/src/session/sync.rs
+++ b/crates/keyorra-session/src/session/sync.rs
@@ -7,6 +7,7 @@ use keyorra_core::store::Store;
 use keyorra_sync::header::Header;
 use keyorra_sync::secret_key::SecretKey;
 use keyorra_sync::transport::Transport;
+use keyorra_sync::AccountId;
 use serde::Serialize;
 
 use super::{locked, move_aside, sibling, Session, Status, DB_SIBLINGS, MIN_PASSWORD_LEN};
@@ -18,14 +19,17 @@ pub type BoxedTransport = Box<dyn Transport + Send>;
 
 /// What the app gives the session for sync.
 pub trait SyncLink: Send {
-    /// The store of files the account lives in (opened per use).
-    fn transport(&self) -> Result<BoxedTransport, String>;
-    fn device_keys(&self) -> Box<dyn DeviceKeyStore>;
-    /// A location for a new account (each account has its own; plan A2 makes a new folder).
-    /// Turning sync on and starting a new account use it; it must hold no account yet.
-    fn fresh_transport(&self) -> Result<BoxedTransport, String> {
-        self.transport()
+    /// The folder of `account` (opened per use; plan A2: `<place>/Keyorra/<account hex>/`).
+    fn transport(&self, account: &AccountId) -> Result<BoxedTransport, String>;
+    /// Makes the folder of a new account (turning sync on, starting a new account); it must
+    /// hold no account yet.
+    fn new_account_transport(&self, account: &AccountId) -> Result<BoxedTransport, String> {
+        self.transport(account)
     }
+    /// Every account folder in the sync place: joining picks the one whose header names the
+    /// Secret Key.
+    fn join_candidates(&self) -> Result<Vec<BoxedTransport>, String>;
+    fn device_keys(&self) -> Box<dyn DeviceKeyStore>;
     /// This Mac's name, shown to the other devices.
     fn device_name(&self) -> String;
     /// Opens an account header with the master password and Secret Key (tests replace the
@@ -111,9 +115,25 @@ pub(super) fn recover_interrupted_join(path: &std::path::Path) {
     }
 }
 
-fn open_transport(link: &dyn SyncLink) -> CmdResult<BoxedTransport> {
-    link.transport()
-        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Sync folder: {e}")))
+fn folder_error(e: String) -> CmdError {
+    CmdError::new(ErrorKind::Other, format!("Sync folder: {e}"))
+}
+
+fn open_transport(link: &dyn SyncLink, account: &AccountId) -> CmdResult<BoxedTransport> {
+    link.transport(account).map_err(folder_error)
+}
+
+/// The account folder to join with this Secret Key (its header names the key's id).
+fn join_transport(link: &dyn SyncLink, secret_key_id: &str) -> CmdResult<BoxedTransport> {
+    for candidate in link.join_candidates().map_err(folder_error)? {
+        if s::holds_account(&candidate, secret_key_id).unwrap_or(false) {
+            return Ok(candidate);
+        }
+    }
+    Err(CmdError::new(
+        ErrorKind::NotFound,
+        "No account for this Secret Key in the sync folder",
+    ))
 }
 
 /// Where the old database goes when the vault joins another account (spec §7.3):
@@ -158,8 +178,10 @@ impl Session {
         self.sync_link.as_deref().ok_or_else(no_link)
     }
 
+    /// The folder of the account this vault syncs with.
     fn transport(&self) -> CmdResult<BoxedTransport> {
-        open_transport(self.link()?)
+        let account = s::account_id(self.store()?).map_err(sync_error)?;
+        open_transport(self.link()?, &account)
     }
 
     /// Runs `f` with the link taken out of the session (so `f` may change the session).
@@ -244,9 +266,9 @@ impl Session {
         self.touch(now);
         self.check_password_throttled(password, now)?;
         let link = self.link()?;
+        let account = s::new_account_id();
         let (transport, mut keys, name) = (
-            link.fresh_transport()
-                .map_err(|e| CmdError::new(ErrorKind::Other, format!("Sync folder: {e}")))?,
+            link.new_account_transport(&account).map_err(folder_error)?,
             link.device_keys(),
             link.device_name(),
         );
@@ -259,6 +281,7 @@ impl Session {
             ..
         } = s::enable(
             store,
+            account,
             transport,
             keys.as_mut(),
             &name,
@@ -367,7 +390,7 @@ impl Session {
         now: u64,
     ) -> CmdResult<()> {
         let (transport, mut keys, name) = (
-            open_transport(link)?,
+            join_transport(link, sk_id)?,
             link.device_keys(),
             link.device_name(),
         );
@@ -444,7 +467,7 @@ impl Session {
         now: u64,
     ) -> CmdResult<()> {
         let (transport, mut keys, name) = (
-            open_transport(link)?,
+            join_transport(link, sk_id)?,
             link.device_keys(),
             link.device_name(),
         );
@@ -515,14 +538,14 @@ impl Session {
             )];
         }
         // The new vault is in place: sync that cannot start now starts on the next round.
-        let resumed = s::resume(
-            self.store.as_ref().ok_or_else(locked)?,
-            open_transport(link)?,
-            link.device_keys().as_ref(),
-        );
+        let store = self.store.as_ref().ok_or_else(locked)?;
+        let resumed = s::account_id(store)
+            .map_err(sync_error)
+            .and_then(|account| open_transport(link, &account))
+            .and_then(|t| s::resume(store, t, link.device_keys().as_ref()).map_err(sync_error));
         match resumed {
             Ok(synced) => self.synced = Some(synced),
-            Err(e) => self.sync_error = Some(sync_error(e).message),
+            Err(e) => self.sync_error = Some(e.message),
         }
         Ok(())
     }
@@ -566,9 +589,9 @@ impl Session {
         self.touch(now);
         self.check_password_throttled(password, now)?;
         let link = self.link()?;
+        let account = s::new_account_id();
         let (transport, mut keys, name) = (
-            link.fresh_transport()
-                .map_err(|e| CmdError::new(ErrorKind::Other, format!("Sync folder: {e}")))?,
+            link.new_account_transport(&account).map_err(folder_error)?,
             link.device_keys(),
             link.device_name(),
         );
@@ -577,6 +600,7 @@ impl Session {
         let before = store.account_key_copy()?;
         let started = s::start_new_account(
             store,
+            account,
             transport,
             keys.as_mut(),
             &name,
diff --git a/crates/keyorra-session/src/sync/merge.rs b/crates/keyorra-session/src/sync/merge.rs
index 11f6f28..63826b1 100644
--- a/crates/keyorra-session/src/sync/merge.rs
+++ b/crates/keyorra-session/src/sync/merge.rs
@@ -23,7 +23,7 @@ use keyorra_sync::fold::View;
 use keyorra_sync::header::Header;
 use keyorra_sync::secret_key::SecretKey;
 use keyorra_sync::transport::Transport;
-use keyorra_sync::{DeviceId, Error, Result};
+use keyorra_sync::{AccountId, DeviceId, Error, Result};
 use sha2::{Digest, Sha256};
 use uuid::Uuid;
 
@@ -356,6 +356,7 @@ pub fn carry_over(from: &Store, to: &mut Store) -> Result<CarryReport> {
 #[allow(clippy::too_many_arguments)]
 pub fn start_new_account<T: Transport>(
     store: &mut Store,
+    account_id: AccountId,
     transport: T,
     keys: &mut dyn DeviceKeyStore,
     device_name: &str,
@@ -375,5 +376,14 @@ pub fn start_new_account<T: Transport>(
     if let Some(device) = device {
         keys.forget(&device);
     }
-    enable(store, transport, keys, device_name, password, kdf, wall_ms)
+    enable(
+        store,
+        account_id,
+        transport,
+        keys,
+        device_name,
+        password,
+        kdf,
+        wall_ms,
+    )
 }
diff --git a/crates/keyorra-session/src/sync/mod.rs b/crates/keyorra-session/src/sync/mod.rs
index 4683a0c..538e007 100644
--- a/crates/keyorra-session/src/sync/mod.rs
+++ b/crates/keyorra-session/src/sync/mod.rs
@@ -237,6 +237,26 @@ fn item_json(item: &Item) -> Result<Zeroizing<Vec<u8>>> {
         .map_err(|e| Error::Malformed(e.to_string()))
 }
 
+/// A new account's id (its folder is named after it, plan A2).
+pub fn new_account_id() -> AccountId {
+    random_id()
+}
+
+/// The account this store syncs with.
+pub fn account_id(store: &Store) -> Result<AccountId> {
+    Ok(load_config(store)?.account_id)
+}
+
+/// Whether `transport` holds an account whose header names this Secret Key id (choosing the
+/// account folder to join without trying the password on each, plan A2).
+pub fn holds_account<T: Transport>(transport: &T, secret_key_id: &str) -> Result<bool> {
+    Ok(transport.headers()?.into_iter().any(|(_, f)| match f {
+        Fetched::Ready(bytes) => keyorra_sync::header::HeaderFile::decode(&bytes)
+            .is_ok_and(|h| h.header.secret_key_id == secret_key_id),
+        _ => false,
+    }))
+}
+
 /// Every live attachment of the store, as changes (written unless sync has them).
 fn attachment_changes(store: &Store) -> Result<Vec<Change>> {
     Ok(store
@@ -296,6 +316,7 @@ pub struct RoundReport {
 #[allow(clippy::too_many_arguments)]
 pub fn enable<T: Transport>(
     store: &mut Store,
+    account_id: AccountId,
     transport: T,
     keys: &mut dyn DeviceKeyStore,
     device_name: &str,
@@ -313,7 +334,6 @@ pub fn enable<T: Transport>(
             "this location already holds a Keyorra account; choose an empty one".into(),
         ));
     }
-    let account_id = random_id();
     let device = random_id();
     let signer = new_signer();
     keys.store(device, &signer).map_err(Error::Refused)?;
```

- [ ] **Step 3: Run and commit.**

Commit: `Session A2-2: one sync folder per account`.

---

### Task 6: The Mac side: iCloud Drive, coordination, FSEvents

**Files:** Create `app/src-tauri/swift/SyncFolder.swift`, `app/src-tauri/src/syncfolder.rs`; modify `app/src-tauri/build.rs`, `Cargo.toml`, `src/lib.rs`, `src/touchid.rs`.

- [ ] **Step 1: Swift.**

Create `app/src-tauri/swift/SyncFolder.swift`:

```swift
// The sync folder for Keyorra (plan A2-2): iCloud Drive / File Provider download state,
// file coordination with the sync client, and change notifications. Called from Rust
// (src/syncfolder.rs) through C. Nothing here touches the keychain.

import CoreServices
import Foundation

// Status codes; keep in sync with src/syncfolder.rs.
private let SF_READY: Int32 = 0
private let SF_NOT_DOWNLOADED: Int32 = 1
private let SF_MISSING: Int32 = 2
private let SF_FAILED: Int32 = 6

/// Whether a file's content is on this Mac. Not an iCloud / File Provider item: ready.
@_cdecl("ks_ubiquity_state")
public func ks_ubiquity_state(_ path: UnsafePointer<CChar>) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    guard let values = try? url.resourceValues(forKeys: [
        .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey,
    ]) else { return SF_MISSING }
    if values.isUbiquitousItem != true { return SF_READY }
    switch values.ubiquitousItemDownloadingStatus {
    case .some(.current), .some(.downloaded): return SF_READY
    default: return SF_NOT_DOWNLOADED
    }
}

/// Asks the provider to download a file; returns at once.
@_cdecl("ks_ubiquity_download")
public func ks_ubiquity_download(_ path: UnsafePointer<CChar>) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    do {
        try FileManager.default.startDownloadingUbiquitousItem(at: url)
        return SF_READY
    } catch {
        return SF_FAILED
    }
}

/// Runs `body(ctx)` inside an `NSFileCoordinator` block for `path`: access 0 = read,
/// 1 = write (replace), 2 = delete. Returns what `body` returned, or FAILED if coordination
/// failed.
@_cdecl("ks_coordinate")
public func ks_coordinate(
    _ path: UnsafePointer<CChar>, _ access: Int32, _ ctx: UnsafeMutableRawPointer?,
    _ body: @convention(c) (UnsafeMutableRawPointer?) -> Int32
) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    let coordinator = NSFileCoordinator(filePresenter: nil)
    var error: NSError?
    var rc: Int32 = SF_FAILED
    switch access {
    case 0:
        coordinator.coordinate(readingItemAt: url, options: [.withoutChanges], error: &error) { _ in
            rc = body(ctx)
        }
    case 1:
        coordinator.coordinate(writingItemAt: url, options: [.forReplacing], error: &error) { _ in
            rc = body(ctx)
        }
    default:
        coordinator.coordinate(writingItemAt: url, options: [.forDeleting], error: &error) { _ in
            rc = body(ctx)
        }
    }
    return error == nil ? rc : SF_FAILED
}

private final class Watch {
    let notify: @convention(c) (UnsafeMutableRawPointer?) -> Void
    let ctx: UnsafeMutableRawPointer?
    var stream: FSEventStreamRef?
    init(notify: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void, ctx: UnsafeMutableRawPointer?) {
        self.notify = notify
        self.ctx = ctx
    }
}

/// Calls `notify(ctx)` (on a background queue, at most every 2 s) when anything under `path`
/// changes. Returns a handle for `ks_watch_stop`, or null.
@_cdecl("ks_watch_start")
public func ks_watch_start(
    _ path: UnsafePointer<CChar>, _ ctx: UnsafeMutableRawPointer?,
    _ notify: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void
) -> UnsafeMutableRawPointer? {
    let watch = Watch(notify: notify, ctx: ctx)
    let info = Unmanaged.passRetained(watch).toOpaque()
    var context = FSEventStreamContext(
        version: 0, info: info, retain: nil, release: nil, copyDescription: nil)
    let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
        guard let info = info else { return }
        let watch = Unmanaged<Watch>.fromOpaque(info).takeUnretainedValue()
        watch.notify(watch.ctx)
    }
    let paths = [String(cString: path)] as CFArray
    guard let stream = FSEventStreamCreate(
        nil, callback, &context, paths, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 2.0,
        FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents))
    else {
        Unmanaged<Watch>.fromOpaque(info).release()
        return nil
    }
    watch.stream = stream
    FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
    FSEventStreamStart(stream)
    return info
}

@_cdecl("ks_watch_stop")
public func ks_watch_stop(_ handle: UnsafeMutableRawPointer?) {
    guard let handle = handle else { return }
    let watch = Unmanaged<Watch>.fromOpaque(handle).takeRetainedValue()
    if let stream = watch.stream {
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
    }
}

/// This Mac's name as the user set it (System Settings → General → Sharing).
@_cdecl("ks_computer_name")
public func ks_computer_name(_ out: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let name = Array((Host.current().localizedName ?? "Mac").utf8.prefix(cap))
    name.withUnsafeBufferPointer { out.update(from: $0.baseAddress!, count: name.count) }
    return name.count
}
```

Compile it with Touch ID's file and link CoreServices:

```diff
diff --git a/app/src-tauri/Cargo.toml b/app/src-tauri/Cargo.toml
index 8611552..a81db62 100644
--- a/app/src-tauri/Cargo.toml
+++ b/app/src-tauri/Cargo.toml
@@ -20,6 +20,8 @@ tauri-plugin-clipboard-manager = "2"
 tauri-plugin-global-shortcut = "2"
 keyorra-core = { path = "../../crates/keyorra-core" }
 keyorra-session = { path = "../../crates/keyorra-session" }
+keyorra-sync = { path = "../../crates/keyorra-sync" }
+keyorra-sync-fs = { path = "../../crates/keyorra-sync-fs" }
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
 uuid = { version = "1", features = ["serde"] }
@@ -30,3 +32,4 @@ core-foundation = "0.10"
 
 [dev-dependencies]
 ed25519-dalek = "2"
+tempfile = "3"
diff --git a/app/src-tauri/build.rs b/app/src-tauri/build.rs
index 1540dde..47a7848 100644
--- a/app/src-tauri/build.rs
+++ b/app/src-tauri/build.rs
@@ -8,10 +8,13 @@ fn main() {
     tauri_build::build()
 }
 
-/// Compiles swift/TouchId.swift into a static library and links the Swift runtime from the OS.
+/// Compiles the Swift helpers (Touch ID, the sync folder) into a static library and links
+/// the Swift runtime from the OS.
 fn build_touch_id() {
-    let source = "swift/TouchId.swift";
-    println!("cargo:rerun-if-changed={source}");
+    let sources = ["swift/TouchId.swift", "swift/SyncFolder.swift"];
+    for source in sources {
+        println!("cargo:rerun-if-changed={source}");
+    }
     let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
     let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
         "aarch64" => "arm64",
@@ -29,14 +32,15 @@ fn build_touch_id() {
         ])
         .args(["-module-name", "KeyorraTouchId", "-target"])
         .arg(format!("{arch}-apple-macosx13.0"))
-        .arg(source)
+        .args(sources)
         .arg("-o")
         .arg(&lib)
         .status()
         .expect("xcrun swiftc (install Xcode or the Command Line Tools)");
-    assert!(status.success(), "compiling {source} failed");
+    assert!(status.success(), "compiling {sources:?} failed");
     println!("cargo:rustc-link-search=native={}", out.display());
     println!("cargo:rustc-link-lib=static=keyorra_touchid");
+    println!("cargo:rustc-link-lib=framework=CoreServices");
     let swiftc = xcrun(&["--find", "swiftc"]);
     let toolchain = Path::new(&swiftc).parent().unwrap().parent().unwrap();
     println!(
```

- [ ] **Step 2: Rust (tests in the file).**

Create `app/src-tauri/src/syncfolder.rs` (tests: each account has its own folder and joining lists them; coordinated access runs the body and returns its result; a round is due on a change or every minute; the FSEvents watcher notices a new file; all on temp folders):

```rust
//! The sync folder on this Mac (plan A2-2): safe wrappers over swift/SyncFolder.swift, the
//! folder transport's view of iCloud Drive and File Provider folders, the session's
//! [`SyncLink`], and change notifications.
//!
//! Accounts live in `<place>/Keyorra/<account id hex>/`; the place is iCloud Drive unless the
//! user picks another synced folder (plan A3).

use std::ffi::{c_void, CString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use keyorra_session::session::{BoxedTransport, SyncLink};
use keyorra_session::sync::DeviceKeyStore;
use keyorra_sync::AccountId;
use keyorra_sync_fs::avail::local_state;
use keyorra_sync_fs::{Access, Availability, FileState, FolderTransport};

/// How long one sync round may spend in the folder: the session is locked meanwhile.
pub const ROUND_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::c_void;
    use std::os::raw::c_char;

    pub type Body = extern "C" fn(*mut c_void) -> i32;
    pub type Notify = extern "C" fn(*mut c_void);

    extern "C" {
        pub fn ks_ubiquity_state(path: *const c_char) -> i32;
        pub fn ks_ubiquity_download(path: *const c_char) -> i32;
        pub fn ks_coordinate(path: *const c_char, access: i32, ctx: *mut c_void, body: Body)
            -> i32;
        pub fn ks_watch_start(path: *const c_char, ctx: *mut c_void, notify: Notify)
            -> *mut c_void;
        pub fn ks_watch_stop(handle: *mut c_void);
        pub fn ks_computer_name(out: *mut u8, cap: usize) -> usize;
    }
}

/// Elsewhere: plain files, no notifications.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
mod ffi {
    use std::ffi::c_void;
    use std::os::raw::c_char;

    pub type Body = extern "C" fn(*mut c_void) -> i32;
    pub type Notify = extern "C" fn(*mut c_void);

    pub unsafe fn ks_ubiquity_state(_: *const c_char) -> i32 {
        0
    }
    pub unsafe fn ks_ubiquity_download(_: *const c_char) -> i32 {
        0
    }
    pub unsafe fn ks_coordinate(_: *const c_char, _: i32, ctx: *mut c_void, body: Body) -> i32 {
        body(ctx)
    }
    pub unsafe fn ks_watch_start(_: *const c_char, _: *mut c_void, _: Notify) -> *mut c_void {
        std::ptr::null_mut()
    }
    pub unsafe fn ks_watch_stop(_: *mut c_void) {}
    pub unsafe fn ks_computer_name(_: *mut u8, _: usize) -> usize {
        0
    }
}

fn c_path(path: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).ok()
}

/// iCloud Drive and File Provider folders as the folder transport needs them.
pub struct MacCloud;

impl Availability for MacCloud {
    fn state(&self, path: &Path) -> FileState {
        match local_state(path) {
            FileState::Ready => {}
            other => return other,
        }
        let Some(p) = c_path(path) else {
            return FileState::Missing;
        };
        // SAFETY: a live C string.
        match unsafe { ffi::ks_ubiquity_state(p.as_ptr()) } {
            0 => FileState::Ready,
            1 => FileState::NotDownloaded,
            _ => FileState::Missing,
        }
    }

    fn request_download(&self, path: &Path) {
        if let Some(p) = c_path(path) {
            // SAFETY: a live C string.
            let _ = unsafe { ffi::ks_ubiquity_download(p.as_ptr()) };
        }
    }

    fn coordinate(
        &self,
        path: &Path,
        access: Access,
        f: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        struct Call<'a> {
            f: &'a mut dyn FnMut() -> std::io::Result<()>,
            result: Option<std::io::Result<()>>,
        }
        extern "C" fn body(ctx: *mut c_void) -> i32 {
            // SAFETY: `ctx` is the `Call` below, alive for the whole coordinated call.
            let call = unsafe { &mut *(ctx as *mut Call<'_>) };
            let r = (call.f)();
            let ok = r.is_ok();
            call.result = Some(r);
            if ok {
                0
            } else {
                6
            }
        }
        let p = c_path(path)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        let access = match access {
            Access::Read => 0,
            Access::Write => 1,
            Access::Delete => 2,
        };
        let mut call = Call { f, result: None };
        // SAFETY: a live C string; `call` outlives the synchronous call that uses it.
        let rc = unsafe {
            ffi::ks_coordinate(
                p.as_ptr(),
                access,
                &mut call as *mut Call<'_> as *mut c_void,
                body,
            )
        };
        match call.result {
            Some(r) => r,
            None if rc == 0 => Ok(()),
            None => Err(std::io::Error::other("the file could not be coordinated")),
        }
    }
}

/// `~/Library/Mobile Documents/com~apple~CloudDocs/Keyorra` (iCloud Drive), if iCloud Drive
/// is set up on this Mac.
pub fn icloud_place() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let drive = home.join("Library/Mobile Documents/com~apple~CloudDocs");
    drive.is_dir().then(|| drive.join("Keyorra"))
}

/// This Mac's name for the other devices.
pub fn computer_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: Swift writes at most `cap` bytes.
    let n = unsafe { ffi::ks_computer_name(buf.as_mut_ptr(), buf.len()) };
    match std::str::from_utf8(&buf[..n.min(buf.len())]) {
        Ok(s) if !s.trim().is_empty() => s.to_owned(),
        _ => "Mac".to_owned(),
    }
}

/// The session's link to the sync place: one folder per account.
pub struct FolderLink {
    place: PathBuf,
    temp: PathBuf,
    availability: Arc<dyn Availability>,
    keys: Box<dyn Fn() -> Box<dyn DeviceKeyStore> + Send>,
    name: String,
}

impl FolderLink {
    pub fn new(
        place: PathBuf,
        temp: PathBuf,
        availability: Arc<dyn Availability>,
        keys: Box<dyn Fn() -> Box<dyn DeviceKeyStore> + Send>,
        name: String,
    ) -> Self {
        Self {
            place,
            temp,
            availability,
            keys,
            name,
        }
    }

    fn folder(&self, account: &AccountId) -> PathBuf {
        self.place.join(data_encoding_hex(account))
    }

    fn open(&self, folder: &Path) -> Result<BoxedTransport, String> {
        FolderTransport::open(folder, Some(&self.temp), self.availability.clone())
            .map(|t| Box::new(t.with_round_budget(ROUND_BUDGET)) as BoxedTransport)
            .map_err(|e| e.to_string())
    }
}

fn data_encoding_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_account_folder(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl SyncLink for FolderLink {
    fn transport(&self, account: &AccountId) -> Result<BoxedTransport, String> {
        let folder = self.folder(account);
        if !folder.is_dir() {
            return Err(format!(
                "the account folder {} is not there (moved, deleted, or not synced yet)",
                folder.display()
            ));
        }
        self.open(&folder)
    }

    fn new_account_transport(&self, account: &AccountId) -> Result<BoxedTransport, String> {
        let folder = self.folder(account);
        if folder.exists() {
            return Err(format!("{} already exists", folder.display()));
        }
        std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        self.open(&folder)
    }

    fn join_candidates(&self) -> Result<Vec<BoxedTransport>, String> {
        let entries = match std::fs::read_dir(&self.place) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_str().is_some_and(is_account_folder) && entry.path().is_dir() {
                out.push(self.open(&entry.path())?);
            }
        }
        Ok(out)
    }

    fn device_keys(&self) -> Box<dyn DeviceKeyStore> {
        (self.keys)()
    }

    fn device_name(&self) -> String {
        self.name.clone()
    }
}

/// Notes that something changed in the sync place (FSEvents); the housekeeping loop runs a
/// round when it sees the flag (and every 60 s while unlocked).
pub struct Watcher {
    handle: *mut c_void,
    flag: *const AtomicBool,
}

// SAFETY: the handle is only passed back to Swift (`ks_watch_stop`), which is thread-safe.
unsafe impl Send for Watcher {}

impl Watcher {
    pub fn start(path: &Path, flag: Arc<AtomicBool>) -> Option<Watcher> {
        extern "C" fn notify(ctx: *mut c_void) {
            // SAFETY: `ctx` is the `Arc<AtomicBool>` kept alive by the `Watcher`.
            let flag = unsafe { &*(ctx as *const AtomicBool) };
            flag.store(true, Ordering::SeqCst);
        }
        let p = c_path(path)?;
        let raw = Arc::into_raw(flag);
        // SAFETY: a live C string; `raw` stays alive until `Drop`.
        let handle = unsafe { ffi::ks_watch_start(p.as_ptr(), raw as *mut c_void, notify) };
        if handle.is_null() {
            // SAFETY: from `Arc::into_raw` above, not used by Swift.
            drop(unsafe { Arc::from_raw(raw) });
            return None;
        }
        Some(Watcher { handle, flag: raw })
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: the handle from `ks_watch_start`; after it stops, nothing uses the flag.
        unsafe {
            ffi::ks_watch_stop(self.handle);
            drop(Arc::from_raw(self.flag));
        }
    }
}

/// When the housekeeping loop runs a sync round.
pub struct Schedule {
    pub changed: Arc<AtomicBool>,
    last_round: Option<u64>,
}

/// A round at least this often while unlocked, even without notifications.
pub const POLL_SECS: u64 = 60;

impl Schedule {
    pub fn new(changed: Arc<AtomicBool>) -> Self {
        Self {
            changed,
            last_round: None,
        }
    }

    /// Whether a round is due now (and if so, notes it).
    pub fn due(&mut self, now: u64) -> bool {
        let changed = self.changed.swap(false, Ordering::SeqCst);
        let polled = self
            .last_round
            .is_none_or(|t| now.saturating_sub(t) >= POLL_SECS);
        if changed || polled {
            self.last_round = Some(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyorra_session::sync::MemoryDeviceKeys;

    fn link(place: &Path, temp: &Path) -> FolderLink {
        FolderLink::new(
            place.to_path_buf(),
            temp.to_path_buf(),
            Arc::new(MacCloud),
            Box::new(|| Box::new(MemoryDeviceKeys::default())),
            "Test Mac".into(),
        )
    }

    #[test]
    fn each_account_has_its_own_folder_and_joining_lists_them() {
        let base = tempfile::tempdir().unwrap();
        let place = base.path().join("Keyorra");
        let link = link(&place, &base.path().join("tmp"));
        assert!(link.join_candidates().unwrap().is_empty());
        let a = [1u8; 16];
        link.new_account_transport(&a).unwrap();
        assert!(place.join("01".repeat(16)).join("streams").is_dir());
        assert!(link.new_account_transport(&a).is_err(), "never reused");
        assert!(link.transport(&a).is_ok());
        assert!(
            link.transport(&[2u8; 16]).is_err(),
            "a missing folder is an error"
        );
        std::fs::create_dir_all(place.join("not an account")).unwrap();
        assert_eq!(link.join_candidates().unwrap().len(), 1);
    }

    #[test]
    fn coordinated_access_runs_the_body_and_returns_its_result() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let mut ran = false;
        MacCloud
            .coordinate(&file, Access::Read, &mut || {
                ran = true;
                Ok(())
            })
            .unwrap();
        assert!(ran);
        let err = MacCloud
            .coordinate(&file, Access::Write, &mut || {
                Err(std::io::Error::other("disk full"))
            })
            .unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert_eq!(MacCloud.state(&file), FileState::Ready);
        assert_eq!(MacCloud.state(&dir.path().join("none")), FileState::Missing);
    }

    #[test]
    fn a_round_is_due_on_a_change_or_every_minute() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut s = Schedule::new(flag.clone());
        assert!(s.due(1_000), "first round at once");
        assert!(!s.due(1_010));
        flag.store(true, Ordering::SeqCst);
        assert!(s.due(1_011));
        assert!(!s.due(1_020));
        assert!(s.due(1_071));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_watcher_notices_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let watcher = Watcher::start(dir.path(), flag.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        std::fs::write(dir.path().join("new.seg"), b"x").unwrap();
        let mut seen = false;
        for _ in 0..80 {
            if flag.load(Ordering::SeqCst) {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        drop(watcher);
        assert!(seen, "FSEvents reported the change");
    }
}
```

- [ ] **Step 3: Wiring.**

Apply (the link over iCloud Drive with the enclave device keys; the watcher; rounds in the housekeeping loop; `device_keys()` is used now):

```diff
diff --git a/app/src-tauri/src/lib.rs b/app/src-tauri/src/lib.rs
index 86e050f..7731dcf 100644
--- a/app/src-tauri/src/lib.rs
+++ b/app/src-tauri/src/lib.rs
@@ -3,10 +3,12 @@ mod commands;
 pub mod native_host;
 mod quick;
 mod screen;
+mod syncfolder;
 mod touchid;
 mod tray;
 
-use std::sync::{Mutex, MutexGuard};
+use std::sync::atomic::AtomicBool;
+use std::sync::{Arc, Mutex, MutexGuard};
 use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
 
 use keyorra_core::crypto::KdfParams;
@@ -39,6 +41,24 @@ pub fn run() {
             let path = app.path().app_data_dir()?.join("keyorra.db");
             let mut session = Session::new(path, KdfParams::DEFAULT, now());
             session.set_keyring(Box::new(touchid::MacKeyring));
+            // Sync over iCloud Drive (plan A2; A3 lets the user pick another synced folder).
+            let changed = Arc::new(AtomicBool::new(false));
+            let mut watcher = None;
+            if let Some(place) = syncfolder::icloud_place() {
+                let temp = app.path().app_data_dir()?.join("sync-tmp");
+                // Nothing is created in iCloud Drive before sync is turned on; once the
+                // folder exists, changes are noticed from the next launch (and polled).
+                if place.is_dir() {
+                    watcher = syncfolder::Watcher::start(&place, changed.clone());
+                }
+                session.set_sync_link(Box::new(syncfolder::FolderLink::new(
+                    place,
+                    temp,
+                    Arc::new(syncfolder::MacCloud),
+                    Box::new(|| Box::new(touchid::device_keys())),
+                    syncfolder::computer_name(),
+                )));
+            }
             app.manage(AppState(Mutex::new(session)));
             // After `manage`: both call commands that need the session. Neither is essential;
             // without them Keyorra still works from its main window.
@@ -49,7 +69,7 @@ pub fn run() {
                 eprintln!("keyorra: quick search unavailable: {e}");
             }
             let handle = app.handle().clone();
-            std::thread::spawn(move || housekeeping(handle));
+            std::thread::spawn(move || housekeeping(handle, changed, watcher));
             if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                 let socket = keyorra_session::bridge::wire::socket_path(&home);
                 let bridge_app = app.handle().clone();
@@ -121,9 +141,10 @@ pub fn run() {
 
 /// Every two seconds: lock when idle (and tell the window), clear the clipboard once our copy
 /// has expired — but only if it still holds our copy.
-fn housekeeping(app: AppHandle) {
+fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, _watcher: Option<syncfolder::Watcher>) {
     // `Instant` does not advance while the Mac sleeps (CLOCK_UPTIME_RAW), unlike wall time.
     let start = Instant::now();
+    let mut schedule = syncfolder::Schedule::new(changed);
     loop {
         std::thread::sleep(Duration::from_secs(2));
         let state = app.state::<AppState>();
@@ -142,9 +163,20 @@ fn housekeeping(app: AppHandle) {
                 let _ = app.clipboard().clear();
             }
         }
+        // Sync while unlocked: on a change in the folder, and every minute.
+        let mut synced = false;
+        if session.status() == keyorra_session::session::Status::Unlocked
+            && session.sync_status().is_ok_and(|s| s.enabled)
+            && schedule.due(t)
+        {
+            synced = session.sync_now(t).is_ok();
+        }
         drop(session);
         if locked {
             let _ = app.emit("locked", ());
         }
+        if synced {
+            let _ = app.emit("synced", ());
+        }
     }
 }
diff --git a/app/src-tauri/src/touchid.rs b/app/src-tauri/src/touchid.rs
index aa1d8fb..f99ff5b 100644
--- a/app/src-tauri/src/touchid.rs
+++ b/app/src-tauri/src/touchid.rs
@@ -258,9 +258,7 @@ impl keyorra_session::sync::Enclave for MacEnclave {
     }
 }
 
-/// Sync device keys sealed to this Mac (plan A1d; the app hands them to sync with the
-/// transport in plan A2).
-#[allow(dead_code)]
+/// Sync device keys sealed to this Mac (plan A1d), handed to sync by the folder link.
 pub fn device_keys() -> keyorra_session::sync::EnclaveDeviceKeys {
     keyorra_session::sync::EnclaveDeviceKeys::new(
         std::sync::Arc::new(DeviceKeysKeyring),
```

- [ ] **Step 4: Run and commit.**

`cargo clippy --workspace --all-targets -- -D warnings`; `cargo test -p keyorra-app` (8 passed, 3 ignored; do not run the ignored ones). Commit: `App A2-2: sync over iCloud Drive`.

---

### Task 7: Spec and protocol

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`, `docs/sync-protocol.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Commit: `docs: A2-2 attachment chunks, coordination, per-account folders`.

- [ ] **Step 2: By hand, on two Macs with one iCloud account (not automated).**

Turn sync on on one Mac, join on the other with the setup code (A3 adds the UI; until then through a debug command), add an item with an attachment, watch it arrive; evict the folder ("Remove Download") and check that sync waits and recovers.

---

### Task 8: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (666 passed, 4 ignored when verified); `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

