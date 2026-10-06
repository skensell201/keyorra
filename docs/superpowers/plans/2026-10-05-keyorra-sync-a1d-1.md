# Keyorra Sync A1d-1 Implementation Plan (store integration: engine resume, migration v2, the sync bridge)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local vault store and the sync engine work together. Every local change goes through one path into sync; what sync shows is written back into the store; the engine continues after a restart from what the store keeps. At the end, two vault stores (two "Macs") converge through an in-memory store of files: one turns sync on (becoming the main device of a new account, with all its existing data), the other joins with the Secret Key and the main device's pin, is approved, edits travel both ways, concurrent edits become a conflict copy in both stores, and a restart resumes with nothing lost or doubled.

**Builds on:** `feat/sync-design` at `2820941` (A1c-2 with all trust reviews through G1).

**Verified:** every task was applied in order in a scratch worktree from `2820941`; the full workspace suite passes (584 tests, 3 ignored), `cargo clippy --workspace --all-targets -- -D warnings` is clean, and `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence` passes.

**Architecture:**

- `keyorra-sync` (still pure, no I/O) gains `Engine::resume` (rebuild after a restart: the engine reads every stream again from the transport, its own stream only up to the confirmed position, re-queues what was sealed or queued but not confirmed, then compares the heads with the ones it remembered), `EngineMemo` (the small part of the engine's state the streams cannot tell it again: accepted alarms, acknowledged rollbacks, blocked streams, remembered heads, the root's advertised head and time, how far its own segments are covered), `Engine::adopt_vault` (an existing local vault, with its id and key, as a first version) and byte encodings for `OutboxState` and `EngineMemo`.
- `keyorra-core` gains database version 2 (`sync_changes`, `sync_segments`), the **single change path** (`record_change` inside every mutating method's transaction, only while sync is on), **remote applies** that record nothing (`apply_remote_vault`, `apply_remote_item`, `apply_remote_purge`), `Store::create_with_account_key` (a joining device keeps the account's key), a `MetaWriter` (a second connection the engine's outbox hook saves through), and `Item.conflict` / `Item.extra`.
- `keyorra-session` gains `sync`: `enable`, `join`, `resume` and `Synced::round` (write the recorded changes as versions, sync, show the view in the store, persist), with a `DeviceKeyStore` trait (in memory here; A1d-2 seals the keys to the Secure Enclave).

**The account key `AK` is the store's account key.** Vault keys are wrapped the same way locally and in sync, so vault rows and sync payloads carry the same wrapped keys, and a joining device creates its store with the account's key under its own local header (password-only, format 1 unchanged, spec §7.6).

**Tech Stack:** unchanged (Rust, rusqlite, ed25519-dalek, serde_json). `keyorra-session` now depends on `keyorra-sync` and `ed25519-dalek`.

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`:

1. **§7.1**, replace the table block and the paragraph after it with:

   > ```
   > sync_changes   kind, id: records changed locally, not yet written as versions
   > sync_segments  first_seq, data: this device's own confirmed segments (already encrypted)
   > sealed meta    sync:config  account id, device id and name, main device id and key,
   >                             Secret Key and its id
   >                sync:outbox  the engine's outbox (sealed segment, queued entries, sent head)
   >                sync:memo    accepted alarms, acknowledged rollbacks, blocked streams,
   >                             remembered heads, the main device's advertised head and time
   > ```
   >
   > Nothing else of sync is stored locally. After a restart the engine reads every stream
   > again from the transport (its own up to the confirmed position, verified with its own
   > key), then compares the heads with the remembered ones: a stream that now holds
   > something else is a fork. Snapshots (§4.8) bound this reading. This trades start-up
   > work for a much smaller local schema and one source of truth.
   >
   > **Single change path.** Every mutating `Store` method (`save_item`, `delete_item`,
   > `restore_item`, `purge_expired`, attachment add/remove, vault create/rename/delete,
   > `apply_import`) calls one private function, `record_change(tx, kind, id)`, inside its
   > transaction; it records into `sync_changes` when sync is on. A test asserts that each
   > public mutating method records its records. What sync shows is written with
   > `apply_remote_*` methods that record nothing.

2. **§7.1**, the sentence on the Secret Key: "The Secret Key is sealed under AK in `sync:config`."

3. **§7.2 step 5**: "Write `Genesis`, header epoch 1, every vault (with its existing id and key: `adopt_vault`; its id does not commit to its key, §4.4, so the earliest admitted version whose key unwraps decides) and every item as versions. Attachment contents travel with the folder transport (A2). A snapshot follows when due (§4.8)."

4. **§12**, the A1d line becomes two lines:

   > | **A1d-1** Store integration | Engine resume and memo, migration v2, single change path, remote applies, `Item.extra` and `conflict`, the session-side bridge (`enable`, `join`, `resume`, rounds) over `MemoryTransport` | Two stores converge; restart resumes; enable keeps existing data |
   > | **A1d-2** Sync in the session | Session wiring (sync only while unlocked), setup code, device keys sealed to the Secure Enclave, turning sync off, rejoining (merge by record id), carrying another account's vault over, starting a new account | Two sessions converge through enable/join/approve/lock/unlock/disable/rejoin |

## Decisions

- **Rebuild from the transport instead of persisted sync tables** (deviates from spec §7.1, see "Spec changes"). The engine's state is mostly a function of the streams; keeping it locally would be a second source of truth with its own migration and consistency problems. Only what the streams cannot say again is persisted: the outbox (so a restart retries the same sealed bytes), the device's own confirmed segments (for self-repair, A1c-2), and the memo. A restart re-reads everything; snapshots bound this later.
- **During the rebuild the engine does not write.** `can_write()` is false until its own stream has been read to the confirmed position; then the unsent segment and queued entries are applied again as its own lanes (`finish_rebuild`). Local changes made meanwhile wait in `sync_changes`.
- **A record with a local change waiting is not overwritten** by what sync shows (`show` skips it); once written, the engine's view includes it.
- **The outbox is saved through a second connection** (`MetaWriter`), because the engine saves it before every append while the session holds the `Store`. It is the same file and the same sealing.
- **Remote applies are idempotent**: `apply_remote_item` decrypts the current row and writes nothing when it is the same item in the same state.
- **Purged items stay as tombstone rows** (empty data), as locally purged items do today.
- **Conflict copies** carry `Item.conflict = { of, version, from_device }` (hex), the shape the fold writes (A1b `copy_item_json`); unknown fields written by a newer app survive in `Item.extra` (`#[serde(flatten)]`).
- **Not here:** Session wiring, the setup code, device keys in the Keychain, disable/rejoin/carry over/start over (A1d-2); attachment contents (A2); UI (A3).

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings` clean; the crate's tests green.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against the state after the previous task (the first against `2820941`); apply them with `git apply` (or by hand), in task order. New files are given in full.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-sync/src/engine/resume.rs        NEW EngineMemo, Resumed, Engine::resume, finish_rebuild
crates/keyorra-sync/src/engine/resume_tests.rs  NEW
crates/keyorra-sync/src/engine.rs               rebuilding flag, own stream re-read, adopt_vault
crates/keyorra-sync/src/engine/snapshots.rs     bootstrap never loads the own stream from a snapshot
crates/keyorra-sync/src/engine/outbox.rs        OutboxState::to_bytes / from_bytes
crates/keyorra-core/src/crypto/{keys,mod}.rs    + header_for_account
crates/keyorra-core/src/store/mod.rs            migration v2, record_change in every mutator, create_with_account_key
crates/keyorra-core/src/store/sync.rs           NEW changes, remote applies, kept segments, MetaWriter
crates/keyorra-core/src/store/sync_tests.rs     NEW
crates/keyorra-core/src/model.rs                Item.conflict, Item.extra
crates/keyorra-session/Cargo.toml               + keyorra-sync, ed25519-dalek
crates/keyorra-session/src/lib.rs               + pub mod sync
crates/keyorra-session/src/sync/mod.rs          NEW enable, join, resume, Synced::round
crates/keyorra-session/src/sync/keys.rs         NEW DeviceKeyStore, MemoryDeviceKeys
crates/keyorra-session/src/sync/tests.rs        NEW two stores through MemoryTransport
```

---

### Task 1: The engine resumes after a restart, and adopts existing vaults

**Files:** Create `crates/keyorra-sync/src/engine/resume.rs`, `crates/keyorra-sync/src/engine/resume_tests.rs`; modify `crates/keyorra-sync/src/engine.rs`, `crates/keyorra-sync/src/engine/snapshots.rs`.

- [ ] **Step 1: Failing tests.**

Create `crates/keyorra-sync/src/engine/resume_tests.rs`:

```rust
//! Plan A1d: an engine continues after a restart from its outbox, kept segments and memo.

use rand::SeedableRng;
use uuid::Uuid;

use super::*;
use crate::faults::Faults;
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);

fn title(view: &View, id: Uuid) -> String {
    let p = view.items[&id].payload.as_ref().expect("item has content");
    let v: serde_json::Value = serde_json::from_slice(&p.item_json).unwrap();
    v["title"].as_str().unwrap().to_owned()
}

/// What the app would persist, and a fresh engine continuing from it.
fn restart(c: &mut Cluster, i: usize) {
    let e = &c.devices[i];
    let saved = Resumed {
        outbox: e.outbox_state(),
        own_segments: e.own_segments().clone(),
        memo: EngineMemo::from_bytes(&e.memo().to_bytes()).unwrap(),
    };
    let fresh = Engine::resume(
        device_id(i),
        signer(i),
        &device_name(i),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(1000 + i as u64),
        saved,
    )
    .unwrap();
    c.devices[i] = fresh;
}

fn shared(n: usize) -> (Cluster, Uuid) {
    let mut c = Cluster::new(n, 21, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "base", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
    (c, vault)
}

#[test]
fn a_restarted_device_reads_everything_again_and_goes_on() {
    let (mut c, vault) = shared(3);
    let json = Cluster::item_json(ITEM, "by 1", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    c.heal();
    let before = c.devices[1].view();
    restart(&mut c, 1);
    assert!(
        !c.devices[1].can_write(),
        "nothing new before its own stream is read"
    );
    c.sync(1).unwrap();
    assert!(!c.devices[1].is_rebuilding());
    assert_eq!(c.devices[1].view(), before);
    // It goes on writing where it left off: no conflict with its own earlier edit.
    let json = Cluster::item_json(ITEM, "after restart", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(title(&c.devices[0].view(), ITEM), "after restart");
    assert!(c.devices[0].view().conflict_copies().is_empty());
}

#[test]
fn queued_changes_survive_a_restart_and_land_once() {
    let (mut c, vault) = shared(2);
    // Offline: the change is queued and its segment sealed, but never confirmed.
    c.links[1].set_faults(Faults {
        fail_before_append: 100,
        ..Faults::NONE
    });
    let json = Cluster::item_json(ITEM, "offline", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    let _ = c.sync(1);
    let other = Uuid::from_bytes([0x61; 16]);
    let json = Cluster::item_json(other, "queued", &[]);
    c.devices[1]
        .save_item(vault, other, &json, c.clocks[1])
        .unwrap();
    restart(&mut c, 1);
    assert!(
        c.devices[1].view().items.is_empty(),
        "nothing read back yet"
    );
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(title(&view, ITEM), "offline");
    assert_eq!(title(&view, other), "queued");
    assert!(view.conflict_copies().is_empty());
}

#[test]
fn the_main_device_restarts_with_its_trust() {
    let (mut c, vault) = shared(3);
    c.devices[0].revoke(device_id(2), c.clocks[0]).unwrap();
    c.heal();
    restart(&mut c, 0);
    c.sync(0).unwrap();
    assert!(c.devices[0].is_root());
    assert!(c.devices[0]
        .trust()
        .device(&device_id(2))
        .unwrap()
        .cut
        .is_some());
    let json = Cluster::item_json(ITEM, "root again", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, c.clocks[0])
        .unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(title(&c.devices[1].view(), ITEM), "root again");
}

#[test]
fn a_history_that_changed_while_the_app_was_closed_is_a_fork() {
    let (mut c, vault) = shared(3);
    let e = &c.devices[2];
    let mut memo = e.memo();
    // Pretend device 2 had received another history of device 1 before the restart.
    let h = memo.heads.get_mut(&device_id(1)).unwrap();
    h.hash = [9; 32];
    let saved = Resumed {
        outbox: e.outbox_state(),
        own_segments: e.own_segments().clone(),
        memo,
    };
    c.devices[2] = Engine::resume(
        device_id(2),
        signer(2),
        &device_name(2),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(7),
        saved,
    )
    .unwrap();
    let _ = vault;
    c.sync(2).unwrap();
    assert!(c.devices[2]
        .alarms()
        .iter()
        .any(|a| matches!(a, Alarm::Fork { stream, .. } if *stream == device_id(1))));
}

#[test]
fn the_memo_round_trips() {
    let memo = EngineMemo {
        accepted_alarms: vec![
            Alarm::Fork {
                stream: [1; 16],
                seq: 3,
            },
            Alarm::Disputed {
                stream: [2; 16],
                seq: 4,
                by: [3; 16],
            },
            Alarm::Rollback {
                stream: [4; 16],
                received: 9,
                stored: 2,
            },
            Alarm::ForeignHeader {
                epoch: 7,
                root: [5; 16],
            },
        ],
        acknowledged_rollbacks: vec![([4; 16], 2)],
        blocked: vec![[1; 16]],
        unapproved_seen: 2,
        heads: [(
            [6; 16],
            Head {
                seq: 11,
                hash: [7; 32],
            },
        )]
        .into_iter()
        .collect(),
        root_head_advertised: Some(Head {
            seq: 12,
            hash: [8; 32],
        }),
        root_time: Some((100, 200)),
        own_covered: 5,
    };
    assert_eq!(EngineMemo::from_bytes(&memo.to_bytes()).unwrap(), memo);
}

#[test]
fn an_existing_vault_is_adopted_with_its_id_and_key() {
    let mut c = Cluster::new(2, 3, Faults::NONE);
    let id = Uuid::from_bytes([0x44; 16]);
    let key = Key::from_bytes([0x55; 32]);
    c.devices[0].adopt_vault(id, "Old", &key, START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "kept", &[]);
    c.devices[0].save_item(id, ITEM, &json, START_MS).unwrap();
    assert!(c.devices[0]
        .adopt_vault(id, "Again", &key, START_MS)
        .is_err());
    c.heal();
    let view = c.devices[1].view();
    assert_eq!(view.vaults[&id].name, "Old");
    assert_eq!(title(&view, ITEM), "kept");
    let wrapped = &view.vaults[&id].wrapped_key;
    let unwrapped = crypto::unwrap_vault_key(&Key::from_bytes(ACCOUNT_KEY), id, wrapped).unwrap();
    assert_eq!(unwrapped.as_bytes(), key.as_bytes());
}
```

Run `cargo test -p keyorra-sync resume`: it does not compile (`Engine::resume`, `EngineMemo`, `Resumed`, `adopt_vault` do not exist; the module is not declared yet, so declare it with the engine patch below).

- [ ] **Step 2: Engine.**

Apply (the `rebuilding` flag and `remembered_heads`; `pull` reads the own stream again while rebuilding and calls `finish_rebuild`; `receive_stream` verifies the own stream with the own key and stops at the confirmed position, skips own checkpoints, and marks the own `SelfJoin` pending; `can_write` is false while rebuilding; `adopt_vault`):

```diff
diff --git a/crates/keyorra-sync/src/engine.rs b/crates/keyorra-sync/src/engine.rs
index 2b2fe1c..025013f 100644
--- a/crates/keyorra-sync/src/engine.rs
+++ b/crates/keyorra-sync/src/engine.rs
@@ -55,10 +55,12 @@ use crate::{AccountId, DeviceId};
 
 mod headers;
 mod outbox;
+mod resume;
 mod retire;
 mod snapshots;
 
 pub use outbox::{NoOutboxStore, OutboxState, OutboxStore};
+pub use resume::{EngineMemo, Resumed};
 pub use retire::{DeviceKeys, KeepKeys, RetireReason};
 pub use snapshots::{SNAPSHOT_EVERY_ENTRIES, SNAPSHOT_EVERY_MS};
 
@@ -436,6 +438,11 @@ pub struct Engine<R> {
     /// The main device's snapshots cover the own stream up to here: kept segments up to it
     /// are dropped once the store is seen holding them.
     own_covered: u64,
+    /// After a restart: the own stream is read again (up to the confirmed position) before
+    /// the queued own entries are applied and before anything new is written.
+    rebuilding: bool,
+    /// Heads received before a restart, compared once the streams are read again.
+    remembered_heads: Heads,
     /// The last outbox save failed: nothing is appended until one succeeds.
     outbox_unsaved: bool,
     bootstrap_tried: bool,
@@ -557,6 +564,8 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             revoked_since_snapshot: false,
             own_segments: BTreeMap::new(),
             outbox_unsaved: false,
+            rebuilding: false,
+            remembered_heads: Heads::new(),
             own_covered: 0,
             bootstrap_tried: false,
             root_head_written: (0, 0, 0, 0),
@@ -656,7 +665,9 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     /// Whether this device's next entry would count: approved and not removed, or
     /// self-joined and not (yet) decided on (then it counts only here until approved).
     pub fn can_write(&self) -> bool {
-        self.trust.admits(&self.device, self.next_seq) && !self.approved_with_another_key()
+        !self.rebuilding
+            && self.trust.admits(&self.device, self.next_seq)
+            && !self.approved_with_another_key()
     }
 
     fn approved_with_another_key(&self) -> bool {
@@ -1019,6 +1030,24 @@ impl<R: RngCore + CryptoRng> Engine<R> {
         Ok(id)
     }
 
+    /// Brings a vault of the local store into sync with its existing id and key (enabling
+    /// sync on a vault that already has data, plan A1d). Its id does not commit to its key
+    /// (spec §4.4), so the earliest admitted version whose key unwraps decides; new vaults
+    /// should be created with [`Engine::create_vault`].
+    pub fn adopt_vault(&mut self, id: Uuid, name: &str, key: &Key, wall_ms: u64) -> Result<()> {
+        if self.fold.contains(RecordKind::Vault, id) {
+            return Err(Error::Refused(format!("vault {id} is already synced")));
+        }
+        let wrapped_key = crypto::wrap_vault_key(&self.account_key, id, key);
+        self.unwrapped.insert(wrapped_key.clone(), key.clone());
+        let doc = Doc::Vault(VaultPayload {
+            name: name.to_owned(),
+            wrapped_key,
+            deleted: false,
+        });
+        self.write(RecordKind::Vault, id, None, doc, wall_ms)
+    }
+
     pub fn rename_vault(&mut self, id: Uuid, name: &str, wall_ms: u64) -> Result<()> {
         let mut p = self.vault_payload(id)?;
         p.name = name.to_owned();
@@ -1359,7 +1388,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     }
 
     fn pull(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
-        let streams: Vec<DeviceId> = transport
+        let mut streams: Vec<DeviceId> = transport
             .streams()?
             .into_iter()
             .filter(|d| *d != self.device && !self.blocked.contains(d))
@@ -1368,6 +1397,9 @@ impl<R: RngCore + CryptoRng> Engine<R> {
         for stream in &streams {
             self.check_stored_head(transport, stream);
         }
+        if self.rebuilding {
+            streams.push(self.device);
+        }
         loop {
             let mut progress = false;
             for stream in &streams {
@@ -1390,6 +1422,9 @@ impl<R: RngCore + CryptoRng> Engine<R> {
         }
         self.report_withheld(wall_ms);
         self.check_root_head();
+        if self.rebuilding {
+            self.finish_rebuild(wall_ms);
+        }
         Ok(())
     }
 
@@ -1492,7 +1527,17 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             })
             .collect();
         candidates.sort_by_key(|(seq, _)| *seq);
-        let Some(key) = self.trust.key(stream) else {
+        // The own stream (read again after a restart) verifies with the own key.
+        let own = *stream == self.device;
+        if own && head.seq >= self.sent.seq {
+            return Ok(false);
+        }
+        let key = if own {
+            Some(self.signer.verifying_key())
+        } else {
+            self.trust.key(stream)
+        };
+        let Some(key) = key else {
             if head.seq == 0 && !self.peeked.contains(stream) {
                 if let Some((_, first)) = candidates.iter().find(|(s, _)| *s == 1) {
                     let first = first.clone();
@@ -1595,6 +1640,11 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             self.confirm_snapshot_ref(stream, segment.header.first_seq, &entries);
             for (seq, entry) in entries {
                 match entry {
+                    // Own checkpoints read again after a restart say nothing new.
+                    Entry::Checkpoint(_) if own => {}
+                    Entry::SelfJoin { .. } if own && seq == 1 && !is_root => {
+                        self.trust.set_pending_self(self.device)
+                    }
                     Entry::Checkpoint(heads) => {
                         let bounds = self.checkpoint_bounds.entry(*stream).or_default();
                         for (d, h) in &heads {
@@ -2428,4 +2478,6 @@ mod attack_tests;
 #[cfg(test)]
 mod recovery_tests;
 #[cfg(test)]
+mod resume_tests;
+#[cfg(test)]
 mod tests;
```

- [ ] **Step 3: Snapshots.**

A snapshot never stands in for the own stream (the device reads it itself):

```diff
diff --git a/crates/keyorra-sync/src/engine/snapshots.rs b/crates/keyorra-sync/src/engine/snapshots.rs
index a18e8aa..0df15cb 100644
--- a/crates/keyorra-sync/src/engine/snapshots.rs
+++ b/crates/keyorra-sync/src/engine/snapshots.rs
@@ -322,10 +322,16 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     ) {
         let root = self.trust.root();
         let from_root = author == root;
-        let wanted = |d: &DeviceId| match only {
-            Some(s) => *d == s,
-            None => true,
-        } && (from_root || *d == author);
+        let own = self.device;
+        // The own stream is never taken from a snapshot: it is read itself (after a restart).
+        let wanted = |d: &DeviceId| {
+            *d != own
+                && match only {
+                    Some(s) => *d == s,
+                    None => true,
+                }
+                && (from_root || *d == author)
+        };
         if from_root {
             for (stream, seq, entry) in &body.entries {
                 match entry {
```

- [ ] **Step 4: Resume.**

Create `crates/keyorra-sync/src/engine/resume.rs`:

```rust
//! Continuing after a restart (plan A1d). The engine keeps no database of its own: the store
//! holds the streams, so a restarted engine reads them again, its own stream included (the
//! fold, trust and headers are rebuilt from them, from the main device's newest snapshot if
//! there is one). What cannot be read again is persisted by the app next to the vault:
//! - the outbox ([`OutboxState`]: positions, chain hashes, the unsent segment, queued entries),
//! - the own confirmed segments kept for repairs ([`Engine::own_segments`]),
//! - a small memo of decisions and observations ([`EngineMemo`]): accepted alarms,
//!   acknowledged rollbacks, streams no longer read, the devices awaiting approval already
//!   shown, the heads last received (a different history after the restart is a fork), the
//!   main device's advertised head and time, and how far its snapshots cover the own stream.
//!
//! Until the own stream is read again up to the confirmed position, nothing new is written;
//! then the queued own entries are applied again and the engine goes on as before.

use crate::cbor::Value;
use crate::entry::{heads_from, heads_value};
use crate::error::malformed;

use super::*;

/// What an engine remembers across restarts besides the streams and its outbox.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineMemo {
    pub accepted_alarms: Vec<Alarm>,
    pub acknowledged_rollbacks: Vec<(DeviceId, u64)>,
    pub blocked: Vec<DeviceId>,
    pub unapproved_seen: u64,
    /// The heads last received from other streams.
    pub heads: Heads,
    pub root_head_advertised: Option<Head>,
    /// The main device's time in its head file, and the local time it last advanced.
    pub root_time: Option<(u64, u64)>,
    pub own_covered: u64,
}

fn alarm_value(a: &Alarm) -> Option<Value> {
    Some(match a {
        Alarm::Rollback {
            stream,
            received,
            stored,
        } => Value::Array(vec![
            Value::text("rollback"),
            Value::bytes(stream),
            Value::Uint(*received),
            Value::Uint(*stored),
        ]),
        Alarm::Fork { stream, seq } => Value::Array(vec![
            Value::text("fork"),
            Value::bytes(stream),
            Value::Uint(*seq),
        ]),
        Alarm::Disputed { stream, seq, by } => Value::Array(vec![
            Value::text("disputed"),
            Value::bytes(stream),
            Value::Uint(*seq),
            Value::bytes(by),
        ]),
        Alarm::ForeignHeader { epoch, root } => Value::Array(vec![
            Value::text("foreign_header"),
            Value::Uint((*epoch).into()),
            Value::bytes(root),
        ]),
        // Computed from state, or noted by count: nothing to remember.
        Alarm::OwnStreamTampered { .. }
        | Alarm::Unapproved { .. }
        | Alarm::RootBehind { .. }
        | Alarm::ApprovedWithAnotherKey => return None,
    })
}

fn alarm_from(v: &Value) -> Result<Alarm> {
    let list = v.as_list()?;
    let tag = list.first().ok_or_else(|| malformed("alarm"))?.as_text()?;
    Ok(match (tag, list) {
        ("rollback", [_, s, r, t]) => Alarm::Rollback {
            stream: s.as_array_of()?,
            received: r.as_uint()?,
            stored: t.as_uint()?,
        },
        ("fork", [_, s, q]) => Alarm::Fork {
            stream: s.as_array_of()?,
            seq: q.as_uint()?,
        },
        ("disputed", [_, s, q, b]) => Alarm::Disputed {
            stream: s.as_array_of()?,
            seq: q.as_uint()?,
            by: b.as_array_of()?,
        },
        ("foreign_header", [_, e, r]) => Alarm::ForeignHeader {
            epoch: e.as_u32()?,
            root: r.as_array_of()?,
        },
        _ => return Err(malformed("alarm")),
    })
}

fn opt_head(h: &Option<Head>) -> Value {
    match h {
        Some(h) => Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
        None => Value::Null,
    }
}

impl EngineMemo {
    /// Canonical CBOR; the app seals it with the account key.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::cbor::encode(&Value::map(vec![
            (
                "accepted_alarms",
                Value::Array(
                    self.accepted_alarms
                        .iter()
                        .filter_map(alarm_value)
                        .collect(),
                ),
            ),
            (
                "acknowledged_rollbacks",
                Value::Array(
                    self.acknowledged_rollbacks
                        .iter()
                        .map(|(d, s)| Value::Array(vec![Value::bytes(d), Value::Uint(*s)]))
                        .collect(),
                ),
            ),
            (
                "blocked",
                Value::Array(self.blocked.iter().map(Value::bytes).collect()),
            ),
            ("unapproved_seen", Value::Uint(self.unapproved_seen)),
            ("heads", heads_value(&self.heads)),
            ("root_head", opt_head(&self.root_head_advertised)),
            (
                "root_time",
                match self.root_time {
                    Some((r, l)) => Value::Array(vec![Value::Uint(r), Value::Uint(l)]),
                    None => Value::Null,
                },
            ),
            ("own_covered", Value::Uint(self.own_covered)),
        ]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<EngineMemo> {
        let v = crate::cbor::decode(bytes)?;
        let f = v.fields(&[
            "accepted_alarms",
            "acknowledged_rollbacks",
            "blocked",
            "unapproved_seen",
            "heads",
            "root_head",
            "root_time",
            "own_covered",
        ])?;
        let pair = |v: &Value| -> Result<(u64, Value)> {
            let [a, b] = v.as_list()? else {
                return Err(malformed("pair"));
            };
            Ok((a.as_uint()?, b.clone()))
        };
        Ok(EngineMemo {
            accepted_alarms: f
                .get("accepted_alarms")?
                .as_list()?
                .iter()
                .map(alarm_from)
                .collect::<Result<_>>()?,
            acknowledged_rollbacks: f
                .get("acknowledged_rollbacks")?
                .as_list()?
                .iter()
                .map(|v| {
                    let [d, s] = v.as_list()? else {
                        return Err(malformed("rollback"));
                    };
                    Ok((d.as_array_of()?, s.as_uint()?))
                })
                .collect::<Result<_>>()?,
            blocked: f
                .get("blocked")?
                .as_list()?
                .iter()
                .map(|v| v.as_array_of())
                .collect::<Result<_>>()?,
            unapproved_seen: f.get("unapproved_seen")?.as_uint()?,
            heads: heads_from(f.get("heads")?)?,
            root_head_advertised: match f.get("root_head")? {
                Value::Null => None,
                v => {
                    let (seq, hash) = pair(v)?;
                    Some(Head {
                        seq,
                        hash: hash.as_array_of()?,
                    })
                }
            },
            root_time: match f.get("root_time")? {
                Value::Null => None,
                v => {
                    let [r, l] = v.as_list()? else {
                        return Err(malformed("root time"));
                    };
                    Some((r.as_uint()?, l.as_uint()?))
                }
            },
            own_covered: f.get("own_covered")?.as_uint()?,
        })
    }
}

/// What an engine needs to continue after a restart.
pub struct Resumed {
    pub outbox: OutboxState,
    /// Own confirmed segments kept for repairs, by first position.
    pub own_segments: BTreeMap<u64, Vec<u8>>,
    pub memo: EngineMemo,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    /// Continues a device after a restart: an engine like [`Engine::join`] that knows its
    /// outbox, its kept segments and its memo, and reads the streams (its own included)
    /// again on its next sync.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        root: DeviceId,
        root_key: VerifyingKey,
        rng: R,
        state: Resumed,
    ) -> Result<Self> {
        let mut e = Self::join(
            device,
            signer,
            name,
            account_id,
            account_key,
            root,
            root_key,
            rng,
        );
        e.restore_outbox(state.outbox)?;
        e.own_segments = state.own_segments;
        let m = state.memo;
        e.accepted_alarms = m.accepted_alarms.into_iter().collect();
        e.acknowledged_rollbacks = m.acknowledged_rollbacks.into_iter().collect();
        e.blocked = m.blocked.into_iter().collect();
        e.unapproved_seen = m.unapproved_seen as usize;
        e.remembered_heads = m.heads;
        e.root_head_advertised = m.root_head_advertised;
        e.root_time = m.root_time.map(|(root_ms, since_ms)| RootTime {
            root_ms,
            since_ms,
            reported: false,
        });
        e.own_covered = m.own_covered;
        e.rebuilding = e.sent.seq > 0 || e.unsent.is_some() || !e.outbox.is_empty();
        // A fresh device that only queued its first entries has nothing to read back.
        if e.sent.seq == 0 {
            e.finish_rebuild_now();
        }
        Ok(e)
    }

    /// The memo to persist (after every sync round).
    pub fn memo(&self) -> EngineMemo {
        let mut heads = self.heads.clone();
        heads.remove(&self.device);
        EngineMemo {
            accepted_alarms: self.accepted_alarms.iter().cloned().collect(),
            acknowledged_rollbacks: self.acknowledged_rollbacks.iter().copied().collect(),
            blocked: self.blocked.iter().copied().collect(),
            unapproved_seen: self.unapproved_seen as u64,
            heads,
            root_head_advertised: self.root_head_advertised,
            root_time: self.root_time.map(|t| (t.root_ms, t.since_ms)),
            own_covered: self.own_covered,
        }
    }

    /// The own confirmed segments kept for repairs (to persist with the outbox).
    pub fn own_segments(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.own_segments
    }

    /// Whether the engine is still reading its own stream again after a restart.
    pub fn is_rebuilding(&self) -> bool {
        self.rebuilding
    }

    /// Called after each pull while rebuilding: once the own stream is read up to the
    /// confirmed position, the queued own entries are applied again.
    pub(super) fn finish_rebuild(&mut self, wall_ms: u64) {
        let read = self.heads.get(&self.device).map_or(0, |h| h.seq);
        if read < self.sent.seq {
            return;
        }
        self.finish_rebuild_now();
        self.apply_pending(wall_ms);
        // A history that differs from what was received before the restart is a fork.
        let remembered = std::mem::take(&mut self.remembered_heads);
        for (stream, h) in remembered {
            let known = self.hashes.get(&stream).and_then(|x| x.get(&h.seq));
            if known.is_some_and(|k| *k != h.hash) {
                self.raise(Alarm::Fork { stream, seq: h.seq });
            }
        }
    }

    fn finish_rebuild_now(&mut self) {
        self.heads.remove(&self.device);
        self.rebuilding = false;
        // The unsent segment and the queued entries, at their positions.
        let mut queued: Vec<Value> = Vec::new();
        if let Some(u) = &self.unsent {
            if let Ok(seg) = decrypt_segment(&self.segment_key, &u.bytes)
                .and_then(|x| x.verify(&self.signer.verifying_key()))
            {
                queued.extend(seg.entries);
            }
        }
        queued.extend(self.outbox.iter().cloned());
        let first = self.sent.seq + 1;
        for (i, value) in queued.iter().enumerate() {
            let seq = first + i as u64;
            let Ok(entry) = Entry::from_value(value) else {
                continue;
            };
            match entry {
                Entry::Put(env) => {
                    self.lanes
                        .entry((self.device, (env.kind, env.record_id)))
                        .or_default()
                        .push_back(Pending {
                            seq,
                            env,
                            doc: None,
                        });
                }
                Entry::SelfJoin { .. } if seq == 1 && !self.is_root() => {
                    self.trust.set_pending_self(self.device)
                }
                Entry::Header(_) | Entry::HeaderSeen { .. } => {
                    self.note_header_entry(self.device, seq, &entry)
                }
                Entry::Genesis { .. } | Entry::Endorse { .. } | Entry::Revoke { .. }
                    if self.is_root() =>
                {
                    self.apply_root_entry(seq, &entry)
                }
                _ => {}
            }
        }
    }
}
```

- [ ] **Step 5: Run and commit.**

`cargo test -p keyorra-sync` green (247 passed, 1 ignored when verified). Commit: `Sync A1d-1: the engine resumes after a restart and adopts existing vaults`.

---

### Task 2: The outbox as bytes

**Files:** Modify `crates/keyorra-sync/src/engine/outbox.rs`, `crates/keyorra-sync/src/engine/resume_tests.rs`.

- [ ] **Step 1: Failing test.**

In `resume_tests.rs`, the restart helper round-trips the outbox through bytes (part of the patch below); it fails to compile without `to_bytes`/`from_bytes`.

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/crates/keyorra-sync/src/engine/outbox.rs b/crates/keyorra-sync/src/engine/outbox.rs
index 8774c8d..30755d9 100644
--- a/crates/keyorra-sync/src/engine/outbox.rs
+++ b/crates/keyorra-sync/src/engine/outbox.rs
@@ -17,6 +17,95 @@ pub struct OutboxState {
     pub outbox: Vec<Vec<u8>>,
 }
 
+impl OutboxState {
+    /// Canonical CBOR (the app seals it with the account key).
+    pub fn to_bytes(&self) -> Vec<u8> {
+        let head = |h: &Head| Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]);
+        crate::cbor::encode(&Value::map(vec![
+            ("device", Value::bytes(self.device)),
+            ("next_seq", Value::Uint(self.next_seq)),
+            ("sent", head(&self.sent)),
+            (
+                "own_hashes",
+                Value::Array(
+                    self.own_hashes
+                        .iter()
+                        .map(|(s, h)| Value::Array(vec![Value::Uint(*s), Value::bytes(h)]))
+                        .collect(),
+                ),
+            ),
+            (
+                "unsent",
+                match &self.unsent {
+                    None => Value::Null,
+                    Some(u) => Value::Array(vec![
+                        Value::bytes(&u.bytes),
+                        Value::Uint(u.versions as u64),
+                        Value::Uint(u.last_seq),
+                        Value::bytes(u.last_hash),
+                    ]),
+                },
+            ),
+            (
+                "outbox",
+                Value::Array(self.outbox.iter().map(Value::bytes).collect()),
+            ),
+        ]))
+    }
+
+    pub fn from_bytes(bytes: &[u8]) -> Result<OutboxState> {
+        let v = crate::cbor::decode(bytes)?;
+        let f = v.fields(&[
+            "device",
+            "next_seq",
+            "sent",
+            "own_hashes",
+            "unsent",
+            "outbox",
+        ])?;
+        let head = |v: &Value| -> Result<Head> {
+            let [s, h] = v.as_list()? else {
+                return Err(crate::error::malformed("head"));
+            };
+            Ok(Head {
+                seq: s.as_uint()?,
+                hash: h.as_array_of()?,
+            })
+        };
+        Ok(OutboxState {
+            device: f.get("device")?.as_array_of()?,
+            next_seq: f.get("next_seq")?.as_uint()?,
+            sent: head(f.get("sent")?)?,
+            own_hashes: f
+                .get("own_hashes")?
+                .as_list()?
+                .iter()
+                .map(|p| head(p).map(|h| (h.seq, h.hash)))
+                .collect::<Result<_>>()?,
+            unsent: match f.get("unsent")? {
+                Value::Null => None,
+                u => {
+                    let [b, n, s, h] = u.as_list()? else {
+                        return Err(crate::error::malformed("unsent"));
+                    };
+                    Some(SealedSegment {
+                        bytes: b.as_bytes()?.to_vec(),
+                        versions: n.as_uint()? as usize,
+                        last_seq: s.as_uint()?,
+                        last_hash: h.as_array_of()?,
+                    })
+                }
+            },
+            outbox: f
+                .get("outbox")?
+                .as_list()?
+                .iter()
+                .map(|b| b.as_bytes().map(<[u8]>::to_vec))
+                .collect::<Result<_>>()?,
+        })
+    }
+}
+
 /// Where A1d keeps [`OutboxState`] (in the same transaction as the local change).
 pub trait OutboxStore: Send {
     /// Persists `state`. On an error the engine appends nothing until a save succeeds, so it
diff --git a/crates/keyorra-sync/src/engine/resume_tests.rs b/crates/keyorra-sync/src/engine/resume_tests.rs
index 484882c..c5c5a02 100644
--- a/crates/keyorra-sync/src/engine/resume_tests.rs
+++ b/crates/keyorra-sync/src/engine/resume_tests.rs
@@ -19,7 +19,7 @@ fn title(view: &View, id: Uuid) -> String {
 fn restart(c: &mut Cluster, i: usize) {
     let e = &c.devices[i];
     let saved = Resumed {
-        outbox: e.outbox_state(),
+        outbox: OutboxState::from_bytes(&e.outbox_state().to_bytes()).unwrap(),
         own_segments: e.own_segments().clone(),
         memo: EngineMemo::from_bytes(&e.memo().to_bytes()).unwrap(),
     };
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1d-1: OutboxState encodes to canonical CBOR`.

---

### Task 3: Store migration v2, the single change path, remote applies

**Files:** Create `crates/keyorra-core/src/store/sync.rs`, `crates/keyorra-core/src/store/sync_tests.rs`; modify `crates/keyorra-core/src/store/mod.rs`, `crates/keyorra-core/src/crypto/keys.rs`, `crates/keyorra-core/src/crypto/mod.rs`.

- [ ] **Step 1: Failing tests.**

Create `crates/keyorra-core/src/store/sync_tests.rs` (migration from version 1 with a backup; nothing recorded while sync is off; **every mutating method records its records**; remote applies record nothing and round-trip, including trash and purge; kept segments and sealed blobs persist; a joining device's store keeps the account key):

```rust
//! Plan A1d: the store's side of sync (migration v2, the single change path, remote applies).

use std::collections::BTreeMap;

use super::tests::{new_store, PW};
use super::*;
use crate::model::ItemKind;

fn changes(store: &Store) -> Vec<Change> {
    store.pending_changes().unwrap()
}

fn item_change(id: Uuid) -> Change {
    Change {
        kind: ChangeKind::Item,
        id,
    }
}

fn vault_change(id: Uuid) -> Change {
    Change {
        kind: ChangeKind::Vault,
        id,
    }
}

#[test]
fn version_1_databases_migrate_to_2_with_sync_tables() {
    let (_dir, path, store) = new_store();
    drop(store);
    // Downgrade the file to version 1 as an older app left it.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE sync_changes; DROP TABLE sync_segments;")
        .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    store.set_sync_tracking(true).unwrap();
    let v = store.create_vault("Personal").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    assert!(sibling(&path, ".bak-v1").exists());
}

#[test]
fn nothing_is_recorded_while_sync_is_off() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    store
        .save_item(&Item::new(v.id, ItemKind::Login, "x", 1))
        .unwrap();
    assert!(changes(&store).is_empty());
    assert!(!store.sync_tracking().unwrap());
}

#[test]
fn every_mutating_method_records_its_records() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let v = store.create_vault("Personal").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.rename_vault(v.id, "Home").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let item = Item::new(v.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let att = store.add_attachment(item.id, "f.txt", b"hi", 2).unwrap();
    let mut got = changes(&store);
    got.sort();
    let mut want = vec![
        item_change(item.id),
        Change {
            kind: ChangeKind::Attachment,
            id: att.id,
        },
    ];
    want.sort();
    assert_eq!(got, want);
    store.clear_changes(&changes(&store)).unwrap();

    store.remove_attachment(item.id, att.id, 3).unwrap();
    assert_eq!(changes(&store).len(), 2);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_item(item.id, 4).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.restore_item(item.id).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_item(item.id, 5).unwrap();
    store.clear_changes(&changes(&store)).unwrap();
    assert_eq!(store.purge_expired(5 + DELETED_RETENTION_SECS).unwrap(), 1);
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_vault(v.id, 6).unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let plan = crate::import::ImportPlan {
        vaults: vec![crate::import::ImportedVault {
            name: "Imported".into(),
            items: vec![crate::import::ImportedItem {
                item: Item::new(Uuid::nil(), ItemKind::SecureNote, "n", 1),
                attachments: vec![],
            }],
        }],
        ..Default::default()
    };
    store.apply_import(&plan).unwrap();
    let kinds: Vec<ChangeKind> = changes(&store).into_iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&ChangeKind::Vault) && kinds.contains(&ChangeKind::Item));
}

#[test]
fn remote_applies_record_nothing_and_round_trip() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let vault = Uuid::from_bytes([1; 16]);
    let key = Key::random();
    let wrapped = crypto::wrap_vault_key(store.account_key().unwrap(), vault, &key);
    store
        .apply_remote_vault(vault, "Shared", &wrapped, false)
        .unwrap();
    let mut item = Item::new(vault, ItemKind::Login, "from elsewhere", 1);
    store.apply_remote_item(&item, None).unwrap();
    assert!(changes(&store).is_empty());
    assert_eq!(store.get_item(item.id).unwrap(), item);
    // Trashed remotely, then restored, then edited.
    store.apply_remote_item(&item, Some(9)).unwrap();
    assert!(store.get_item(item.id).is_err());
    assert_eq!(store.deleted_items().unwrap().len(), 1);
    item.title = "edited".into();
    store.apply_remote_item(&item, None).unwrap();
    assert_eq!(store.get_item(item.id).unwrap().title, "edited");
    store.apply_remote_purge(item.id).unwrap();
    assert!(store.get_item(item.id).is_err());
    assert!(store.deleted_items().unwrap().is_empty());
    store
        .apply_remote_vault(vault, "Shared", &wrapped, true)
        .unwrap();
    assert!(store.vaults().unwrap().is_empty());
    assert!(changes(&store).is_empty());
}

#[test]
fn kept_segments_and_sync_blobs_persist() {
    let (_dir, path, mut store) = new_store();
    let segs: BTreeMap<u64, Vec<u8>> = [(1, vec![1, 2]), (4, vec![3])].into_iter().collect();
    store.set_own_segments(&segs).unwrap();
    store.set_sealed_meta("sync:memo", b"memo").unwrap();
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.own_segments().unwrap(), segs);
    assert_eq!(
        &store.sealed_meta("sync:memo").unwrap().unwrap()[..],
        b"memo"
    );
}

#[test]
fn a_joining_device_creates_its_store_with_the_accounts_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let account = Key::from_bytes([7; 32]);
    let store =
        Store::create_with_account_key(&path, PW, KdfParams::INSECURE_FAST, account).unwrap();
    assert_eq!(store.account_key().unwrap().as_bytes(), &[7; 32]);
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.account_key().unwrap().as_bytes(), &[7; 32]);
}
```

It fails to compile.

- [ ] **Step 2: Account key header.**

Apply:

```diff
diff --git a/crates/keyorra-core/src/crypto/keys.rs b/crates/keyorra-core/src/crypto/keys.rs
index 9aa22b4..878fb6b 100644
--- a/crates/keyorra-core/src/crypto/keys.rs
+++ b/crates/keyorra-core/src/crypto/keys.rs
@@ -28,6 +28,12 @@ pub fn create_header(password: &str, kdf: KdfParams) -> Result<(Header, Key)> {
     Ok((header, account))
 }
 
+/// A header for an existing account key (a device joining a synced account keeps the
+/// account's key, plan A1d).
+pub fn header_for_account(account: &Key, password: &str, kdf: KdfParams) -> Result<Header> {
+    wrap_account_key(account, password, kdf)
+}
+
 /// Recovers the account key. A wrong password fails AEAD authentication.
 pub fn unlock(header: &Header, password: &str) -> Result<Key> {
     if header.format != FORMAT_VERSION {
diff --git a/crates/keyorra-core/src/crypto/mod.rs b/crates/keyorra-core/src/crypto/mod.rs
index 46d9620..1395cab 100644
--- a/crates/keyorra-core/src/crypto/mod.rs
+++ b/crates/keyorra-core/src/crypto/mod.rs
@@ -9,6 +9,6 @@ pub use aead::{open, seal, seal_with_rng, NONCE_LEN};
 pub use kdf::{derive_kek, KdfParams};
 pub use key::Key;
 pub use keys::{
-    attachment_aad, change_password, create_header, item_aad, unlock, unwrap_vault_key,
-    wrap_vault_key, Header, FORMAT_VERSION,
+    attachment_aad, change_password, create_header, header_for_account, item_aad, unlock,
+    unwrap_vault_key, wrap_vault_key, Header, FORMAT_VERSION,
 };
```

- [ ] **Step 3: Store.**

Apply (migration `SCHEMA_V2`; `create_with_account_key`; every mutator records inside its transaction: `create_vault`, `rename_vault`, `delete_vault`, `apply_import`, `save_item`, `add_attachment`, `remove_attachment`, `delete_item`, `restore_item`, `purge_expired`):

```diff
diff --git a/crates/keyorra-core/src/store/mod.rs b/crates/keyorra-core/src/store/mod.rs
index 4cecbb5..3bd4bc5 100644
--- a/crates/keyorra-core/src/store/mod.rs
+++ b/crates/keyorra-core/src/store/mod.rs
@@ -13,9 +13,15 @@ use crate::import::{ImportPlan, ImportReport};
 use crate::model::{AttachmentRef, Item, VaultInfo, SCHEMA_VERSION};
 use crate::{Error, Result};
 
+mod sync;
+#[cfg(test)]
+mod sync_tests;
 #[cfg(test)]
 mod tests;
 
+use sync::record_change;
+pub use sync::{Change, ChangeKind};
+
 const DB_VERSION: i64 = MIGRATIONS.len() as i64;
 // Format label from the Lockbox days; kept so existing vaults and pairings stay readable.
 const CHECK_AAD: &[u8] = b"lockbox/check/v1";
@@ -65,8 +71,16 @@ CREATE TABLE attachments (
 );
 ";
 
+/// Version 2 (plan A1d): sync bookkeeping. Records changed locally wait in `sync_changes`
+/// until the sync engine has written them; the device's own confirmed segments are kept in
+/// `sync_segments` (already encrypted) for repairs. Everything else of sync is sealed meta.
+const SCHEMA_V2: &str = "
+CREATE TABLE sync_changes (kind TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (kind, id));
+CREATE TABLE sync_segments (first_seq INTEGER PRIMARY KEY, data BLOB NOT NULL);
+";
+
 /// `MIGRATIONS[i]` upgrades database version `i` to `i + 1`.
-const MIGRATIONS: &[&str] = &[SCHEMA_V1];
+const MIGRATIONS: &[&str] = &[SCHEMA_V1, SCHEMA_V2];
 
 /// The encrypted vault database. Locked until `unlock`/`unlock_with_key`.
 pub struct Store {
@@ -89,6 +103,22 @@ impl Store {
     pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Store> {
         // Argon2 can fail on bad params; do it before touching the filesystem.
         let (header, account) = crypto::create_header(password, kdf)?;
+        Self::create_with(path, header, account)
+    }
+
+    /// Creates a new database for an existing account key (a device joining a synced
+    /// account, plan A1d), unlocked.
+    pub fn create_with_account_key(
+        path: &Path,
+        password: &str,
+        kdf: KdfParams,
+        account: Key,
+    ) -> Result<Store> {
+        let header = crypto::header_for_account(&account, password, kdf)?;
+        Self::create_with(path, header, account)
+    }
+
+    fn create_with(path: &Path, header: Header, account: Key) -> Result<Store> {
         claim_path(path)?;
         match Self::init_file(path, &header, &account) {
             Ok(conn) => Ok(Store {
@@ -221,7 +251,10 @@ impl Store {
             name: name.to_owned(),
         };
         let key = Key::random();
-        insert_vault(&self.conn, account, &info, &key)?;
+        let tx = self.conn.unchecked_transaction()?;
+        insert_vault(&tx, account, &info, &key)?;
+        record_change(&tx, ChangeKind::Vault, info.id)?;
+        tx.commit()?;
         self.vault_keys.insert(info.id, key);
         Ok(info)
     }
@@ -233,13 +266,16 @@ impl Store {
             name: name.to_owned(),
         };
         let meta = crypto::seal(account, &serde_json::to_vec(&info)?, &vault_meta_aad(id));
-        let n = self.conn.execute(
+        let tx = self.conn.unchecked_transaction()?;
+        let n = tx.execute(
             "UPDATE vaults SET meta = ?2, revision = revision + 1 WHERE id = ?1 AND deleted = 0",
             params![id.to_string(), meta],
         )?;
         if n == 0 {
             return Err(Error::NotFound(format!("vault {id}")));
         }
+        record_change(&tx, ChangeKind::Vault, id)?;
+        tx.commit()?;
         Ok(info)
     }
 
@@ -273,6 +309,9 @@ impl Store {
         if n == 0 {
             return Err(Error::NotFound(format!("vault {id}")));
         }
+        // The purged items of the vault travel as part of deleting it (the engine purges
+        // what is in Recently Deleted before deleting the vault).
+        record_change(&tx, ChangeKind::Vault, id)?;
         tx.commit()?;
         Ok(())
     }
@@ -290,6 +329,7 @@ impl Store {
             };
             let key = Key::random();
             insert_vault(&tx, account, &info, &key)?;
+            record_change(&tx, ChangeKind::Vault, info.id)?;
             report.vaults += 1;
             for imported in &vault.items {
                 let mut item = imported.item.clone();
@@ -303,10 +343,12 @@ impl Store {
                         size: bytes.len() as u64,
                     };
                     insert_attachment(&tx, &key, &item, &att, bytes)?;
+                    record_change(&tx, ChangeKind::Attachment, att.id)?;
                     item.attachments.push(att);
                     report.attachments += 1;
                 }
                 upsert_item(&tx, &key, &item)?;
+                record_change(&tx, ChangeKind::Item, item.id)?;
                 report.items += 1;
             }
             new_keys.push((info.id, key));
@@ -384,6 +426,7 @@ impl Store {
             None => item.attachments.clear(),
         }
         upsert_item(&tx, new_key, &item)?;
+        record_change(&tx, ChangeKind::Item, item.id)?;
         tx.commit()?;
         Ok(())
     }
@@ -407,6 +450,8 @@ impl Store {
         item.attachments.push(att.clone());
         item.updated_at = now;
         upsert_item(&tx, key, &item)?;
+        record_change(&tx, ChangeKind::Attachment, att.id)?;
+        record_change(&tx, ChangeKind::Item, item.id)?;
         tx.commit()?;
         Ok(att)
     }
@@ -436,6 +481,8 @@ impl Store {
             params![attachment_id.to_string(), item_id.to_string()],
         )?;
         upsert_item(&tx, key, &item)?;
+        record_change(&tx, ChangeKind::Attachment, attachment_id)?;
+        record_change(&tx, ChangeKind::Item, item_id)?;
         tx.commit()?;
         Ok(())
     }
@@ -487,7 +534,8 @@ impl Store {
 
     pub fn delete_item(&mut self, id: Uuid, now: i64) -> Result<()> {
         self.account_key()?;
-        let n = self.conn.execute(
+        let tx = self.conn.unchecked_transaction()?;
+        let n = tx.execute(
             "UPDATE items SET deleted_at = ?2, revision = revision + 1
              WHERE id = ?1 AND deleted_at IS NULL",
             params![id.to_string(), now],
@@ -495,12 +543,15 @@ impl Store {
         if n == 0 {
             return Err(Error::NotFound(format!("item {id}")));
         }
+        record_change(&tx, ChangeKind::Item, id)?;
+        tx.commit()?;
         Ok(())
     }
 
     pub fn restore_item(&mut self, id: Uuid) -> Result<()> {
         self.account_key()?;
-        let n = self.conn.execute(
+        let tx = self.conn.unchecked_transaction()?;
+        let n = tx.execute(
             "UPDATE items SET deleted_at = NULL, revision = revision + 1
              WHERE id = ?1 AND deleted_at IS NOT NULL AND length(data) > 0",
             [id.to_string()],
@@ -508,6 +559,8 @@ impl Store {
         if n == 0 {
             return Err(Error::NotFound(format!("deleted item {id}")));
         }
+        record_change(&tx, ChangeKind::Item, id)?;
+        tx.commit()?;
         Ok(())
     }
 
@@ -515,6 +568,17 @@ impl Store {
     pub fn purge_expired(&mut self, now: i64) -> Result<usize> {
         let cutoff = now - DELETED_RETENTION_SECS;
         let tx = self.conn.unchecked_transaction()?;
+        let purged: Vec<String> = {
+            let mut stmt = tx.prepare(
+                "SELECT id FROM items
+                 WHERE deleted_at IS NOT NULL AND deleted_at <= ?1 AND length(data) > 0",
+            )?;
+            let rows = stmt.query_map([cutoff], |r| r.get(0))?;
+            rows.collect::<rusqlite::Result<_>>()?
+        };
+        for id in &purged {
+            record_change(&tx, ChangeKind::Item, parse_id(id)?)?;
+        }
         tx.execute(
             "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
              WHERE item_id IN (SELECT id FROM items
```

- [ ] **Step 4: Sync side of the store.**

Create `crates/keyorra-core/src/store/sync.rs`:

```rust
//! The store's side of sync (plan A1d, spec §7.1).
//!
//! **Single change path.** Every mutating method records the records it changed in
//! `sync_changes` inside its own transaction, when sync is on (`record_change`); the sync
//! layer turns them into versions and clears them. **Remote applies** write what the sync
//! engine shows without recording anything. Sync's own state is kept as sealed meta and, for
//! the device's own confirmed segments (already encrypted), in `sync_segments`.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use super::{insert_vault, parse_id, upsert_item, vault_meta_aad, Store};
use crate::crypto::{self, Key};
use crate::model::{Item, VaultInfo};
use crate::{Error, Result};

const TRACKING_KEY: &str = "sync_tracking";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    Vault,
    Item,
    Attachment,
}

impl ChangeKind {
    fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Vault => "vault",
            ChangeKind::Item => "item",
            ChangeKind::Attachment => "attachment",
        }
    }

    fn parse(s: &str) -> Result<ChangeKind> {
        Ok(match s {
            "vault" => ChangeKind::Vault,
            "item" => ChangeKind::Item,
            "attachment" => ChangeKind::Attachment,
            other => return Err(Error::Invalid(format!("bad change kind {other}"))),
        })
    }
}

/// A record changed locally, waiting to be written by the sync engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Change {
    pub kind: ChangeKind,
    pub id: Uuid,
}

/// Records a change if sync is on. Called by every mutating method inside its transaction.
pub(super) fn record_change(conn: &Connection, kind: ChangeKind, id: Uuid) -> Result<()> {
    let on: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [TRACKING_KEY],
            |r| r.get(0),
        )
        .optional()?;
    if on.as_deref() == Some(b"1") {
        conn.execute(
            "INSERT OR IGNORE INTO sync_changes (kind, id) VALUES (?1, ?2)",
            params![kind.as_str(), id.to_string()],
        )?;
    }
    Ok(())
}

impl Store {
    /// Turns recording of local changes on or off (sync enabled or disabled).
    pub fn set_sync_tracking(&mut self, on: bool) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![TRACKING_KEY, if on { &b"1"[..] } else { &b"0"[..] }],
        )?;
        if !on {
            self.conn.execute("DELETE FROM sync_changes", [])?;
        }
        Ok(())
    }

    pub fn sync_tracking(&self) -> Result<bool> {
        let on: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [TRACKING_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(on.as_deref() == Some(b"1"))
    }

    /// The records changed locally and not yet written by the sync engine, in a stable order.
    pub fn pending_changes(&self) -> Result<Vec<Change>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, id FROM sync_changes ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id) = row?;
            out.push(Change {
                kind: ChangeKind::parse(&kind)?,
                id: parse_id(&id)?,
            });
        }
        Ok(out)
    }

    /// The sync engine wrote these.
    pub fn clear_changes(&mut self, changes: &[Change]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for c in changes {
            tx.execute(
                "DELETE FROM sync_changes WHERE kind = ?1 AND id = ?2",
                params![c.kind.as_str(), c.id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// A vault as the sync engine shows it (its key wrapped under the account key, as
    /// locally). Records nothing.
    pub fn apply_remote_vault(
        &mut self,
        id: Uuid,
        name: &str,
        wrapped_key: &[u8],
        deleted: bool,
    ) -> Result<()> {
        let account = self.account_key()?.clone();
        let key = crypto::unwrap_vault_key(&account, id, wrapped_key)?;
        let info = VaultInfo {
            id,
            name: name.to_owned(),
        };
        let exists = self
            .conn
            .query_row(
                "SELECT 1 FROM vaults WHERE id = ?1",
                [id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            let meta = crypto::seal(&account, &serde_json::to_vec(&info)?, &vault_meta_aad(id));
            self.conn.execute(
                "UPDATE vaults SET meta = ?2, wrapped_key = ?3, deleted = ?4,
                     revision = revision + 1 WHERE id = ?1",
                params![id.to_string(), meta, wrapped_key, deleted as i64],
            )?;
        } else {
            insert_vault(&self.conn, &account, &info, &key)?;
            self.conn.execute(
                "UPDATE vaults SET deleted = ?2 WHERE id = ?1",
                params![id.to_string(), deleted as i64],
            )?;
        }
        self.vault_keys.insert(id, key);
        Ok(())
    }

    /// An item as the sync engine shows it, live or in Recently Deleted (`deleted_at`). Its
    /// attachment list is taken as is. Records nothing; rewrites nothing that is the same.
    pub fn apply_remote_item(&mut self, item: &Item, deleted_at: Option<i64>) -> Result<()> {
        let key = self.vault_key(item.vault_id)?.clone();
        let current: Option<(String, Vec<u8>, i64, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT vault_id, data, schema, deleted_at FROM items WHERE id = ?1",
                [item.id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((vault, data, schema, was_deleted)) = &current {
            let same = !data.is_empty()
                && was_deleted == &deleted_at
                && parse_id(vault).ok() == Some(item.vault_id)
                && u32::try_from(*schema)
                    .ok()
                    .and_then(|s| self.decrypt_item(item.id, item.vault_id, s, data).ok())
                    .as_ref()
                    == Some(item);
            if same {
                return Ok(());
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        upsert_item(&tx, &key, item)?;
        tx.execute(
            "UPDATE items SET deleted_at = ?2 WHERE id = ?1",
            params![item.id.to_string(), deleted_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// An item the sync engine shows as purged: its data goes, the row stays a tombstone.
    pub fn apply_remote_purge(&mut self, id: Uuid) -> Result<()> {
        self.account_key()?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE item_id = ?1 AND deleted = 0",
            [id.to_string()],
        )?;
        tx.execute(
            "UPDATE items SET data = X'', deleted_at = COALESCE(deleted_at, 0),
                 revision = revision + 1
             WHERE id = ?1 AND length(data) > 0",
            [id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Every vault row with its key as stored (wrapped under the account key) and whether it
    /// is deleted: what enabling sync writes as the first versions.
    pub fn vault_rows(&self) -> Result<Vec<(VaultInfo, Key, bool)>> {
        let account = self.account_key()?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta, deleted FROM vaults ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, meta, deleted) = row?;
            let id = parse_id(&id)?;
            let plain = crypto::open(account, &meta, &vault_meta_aad(id))?;
            let info: VaultInfo = serde_json::from_slice(&plain)?;
            out.push((info, self.vault_key(id)?.clone(), deleted != 0));
        }
        Ok(out)
    }

    /// An item with its deletion time, if it is live or in Recently Deleted (not purged).
    pub fn item_state(&self, id: Uuid) -> Result<Option<(Item, Option<i64>)>> {
        let row: Option<(String, Vec<u8>, i64, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT vault_id, data, schema, deleted_at FROM items WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((vault, data, schema, deleted_at)) = row else {
            return Ok(None);
        };
        if data.is_empty() {
            return Ok(None);
        }
        let schema = u32::try_from(schema).map_err(|_| Error::Invalid("bad item schema".into()))?;
        let item = self.decrypt_item(id, parse_id(&vault)?, schema, &data)?;
        Ok(Some((item, deleted_at)))
    }

    /// Whether the item row exists as a purged tombstone.
    pub fn item_purged(&self, id: Uuid) -> Result<bool> {
        let row: Option<i64> = self
            .conn
            .query_row(
                "SELECT length(data) FROM items WHERE id = ?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row == Some(0))
    }

    pub fn own_segments(&self) -> Result<BTreeMap<u64, Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT first_seq, data FROM sync_segments ORDER BY first_seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (seq, data) = row?;
            out.insert(seq as u64, data);
        }
        Ok(out)
    }

    /// Replaces the kept own segments (they are already encrypted and signed).
    pub fn set_own_segments(&mut self, segments: &BTreeMap<u64, Vec<u8>>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sync_segments", [])?;
        for (seq, data) in segments {
            tx.execute(
                "INSERT INTO sync_segments (first_seq, data) VALUES (?1, ?2)",
                params![*seq as i64, data],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The account key itself, for the sync engine (which uses it as the account key `AK`).
    pub fn account_key_copy(&self) -> Result<Key> {
        Ok(self.account_key()?.clone())
    }
}
```

- [ ] **Step 5: Run and commit.**

`cargo test -p keyorra-core` green. Commit: `Core A1d-1: migration v2, single change path, remote applies`.

---

### Task 4: Conflict marker and unknown fields on items

**Files:** Modify `crates/keyorra-core/src/model.rs`.

- [ ] **Step 1: Test first, then implement.**

The test `unknown_fields_and_the_conflict_marker_survive_a_round_trip` is in the patch; add it first and see it fail to compile, then apply the rest:

```diff
diff --git a/crates/keyorra-core/src/model.rs b/crates/keyorra-core/src/model.rs
index 4c2e41f..1a1b851 100644
--- a/crates/keyorra-core/src/model.rs
+++ b/crates/keyorra-core/src/model.rs
@@ -1,3 +1,5 @@
+use std::collections::BTreeMap;
+
 use serde::{Deserialize, Serialize};
 use uuid::Uuid;
 
@@ -109,6 +111,22 @@ pub struct Item {
     pub attachments: Vec<AttachmentRef>,
     pub created_at: i64,
     pub updated_at: i64,
+    /// Set on a conflict copy (sync, spec §3.5): which item and version it was copied from.
+    #[serde(default, skip_serializing_if = "Option::is_none")]
+    pub conflict: Option<ConflictInfo>,
+    /// Fields written by a newer app: kept as they are, so an older one does not drop them
+    /// when it saves the item (sync, spec §3.6).
+    #[serde(flatten)]
+    pub extra: BTreeMap<String, serde_json::Value>,
+}
+
+/// Where a conflict copy comes from: the original item, the version copied (hex of its
+/// version hash) and the device that wrote that version (hex id).
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct ConflictInfo {
+    pub of: Uuid,
+    pub version: String,
+    pub from_device: String,
 }
 
 impl Item {
@@ -128,6 +146,8 @@ impl Item {
             attachments: Vec::new(),
             created_at: now,
             updated_at: now,
+            conflict: None,
+            extra: BTreeMap::new(),
         }
     }
 
@@ -267,6 +287,24 @@ mod tests {
         item
     }
 
+    #[test]
+    fn unknown_fields_and_the_conflict_marker_survive_a_round_trip() {
+        let mut json = serde_json::to_value(login()).unwrap();
+        json["future_field"] = serde_json::json!({"x": 1});
+        json["conflict"] = serde_json::json!({
+            "of": "60606060-6060-6060-6060-606060606060",
+            "version": "abcd",
+            "from_device": "0101",
+        });
+        let item: Item = serde_json::from_value(json.clone()).unwrap();
+        assert_eq!(item.conflict.as_ref().unwrap().version, "abcd");
+        assert_eq!(item.extra["future_field"], serde_json::json!({"x": 1}));
+        assert_eq!(serde_json::to_value(&item).unwrap(), json);
+        // Without them, the JSON is as before.
+        let plain = serde_json::to_value(login()).unwrap();
+        assert!(plain.get("conflict").is_none());
+    }
+
     #[test]
     fn accessors_find_purpose_fields_and_totp_in_sections() {
         let item = login();
```

Without a conflict marker or unknown fields the JSON is byte-for-byte what it was (no new keys), so stored items and the browser bridge are unaffected.

- [ ] **Step 2: Run and commit.**

`cargo test --workspace` green. Commit: `Core A1d-1: items keep a conflict marker and unknown fields`.

---

### Task 5: A second connection for the outbox hook

**Files:** Modify `crates/keyorra-core/src/store/sync.rs`, `crates/keyorra-core/src/store/mod.rs`, `crates/keyorra-core/src/store/sync_tests.rs`.

- [ ] **Step 1: Test first, then implement.**

`the_meta_writer_writes_what_the_store_reads` is in the patch:

```diff
diff --git a/crates/keyorra-core/src/store/mod.rs b/crates/keyorra-core/src/store/mod.rs
index 3bd4bc5..9dad7de 100644
--- a/crates/keyorra-core/src/store/mod.rs
+++ b/crates/keyorra-core/src/store/mod.rs
@@ -20,7 +20,7 @@ mod sync_tests;
 mod tests;
 
 use sync::record_change;
-pub use sync::{Change, ChangeKind};
+pub use sync::{Change, ChangeKind, MetaWriter};
 
 const DB_VERSION: i64 = MIGRATIONS.len() as i64;
 // Format label from the Lockbox days; kept so existing vaults and pairings stay readable.
diff --git a/crates/keyorra-core/src/store/sync.rs b/crates/keyorra-core/src/store/sync.rs
index 5c12a8b..5d2c5f4 100644
--- a/crates/keyorra-core/src/store/sync.rs
+++ b/crates/keyorra-core/src/store/sync.rs
@@ -11,7 +11,10 @@ use std::collections::BTreeMap;
 use rusqlite::{params, Connection, OptionalExtension};
 use uuid::Uuid;
 
-use super::{insert_vault, parse_id, upsert_item, vault_meta_aad, Store};
+use super::{
+    configure, insert_vault, parse_id, sealed_meta_aad, sealed_meta_key, upsert_item,
+    vault_meta_aad, Store,
+};
 use crate::crypto::{self, Key};
 use crate::model::{Item, VaultInfo};
 use crate::{Error, Result};
@@ -307,8 +310,42 @@ impl Store {
         Ok(())
     }
 
+    /// A second connection to the same database that writes sealed meta (the sync engine's
+    /// outbox is saved through it before every append, while the session holds the store).
+    pub fn meta_writer(&self) -> Result<MetaWriter> {
+        let path = self
+            .conn
+            .path()
+            .filter(|p| !p.is_empty())
+            .ok_or_else(|| Error::Invalid("the store has no file".into()))?;
+        let conn = Connection::open(path)?;
+        configure(&conn)?;
+        Ok(MetaWriter {
+            conn,
+            key: self.account_key()?.clone(),
+        })
+    }
+
     /// The account key itself, for the sync engine (which uses it as the account key `AK`).
     pub fn account_key_copy(&self) -> Result<Key> {
         Ok(self.account_key()?.clone())
     }
 }
+
+/// Writes sealed meta of one store through its own connection ([`Store::meta_writer`]).
+pub struct MetaWriter {
+    conn: Connection,
+    key: Key,
+}
+
+impl MetaWriter {
+    pub fn set_sealed_meta(&self, name: &str, value: &[u8]) -> Result<()> {
+        let data = crypto::seal(&self.key, value, &sealed_meta_aad(name));
+        self.conn.execute(
+            "INSERT INTO meta (key, value) VALUES (?1, ?2)
+             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
+            params![sealed_meta_key(name), data],
+        )?;
+        Ok(())
+    }
+}
diff --git a/crates/keyorra-core/src/store/sync_tests.rs b/crates/keyorra-core/src/store/sync_tests.rs
index 270de25..a93c504 100644
--- a/crates/keyorra-core/src/store/sync_tests.rs
+++ b/crates/keyorra-core/src/store/sync_tests.rs
@@ -181,3 +181,14 @@ fn a_joining_device_creates_its_store_with_the_accounts_key() {
     store.unlock(PW).unwrap();
     assert_eq!(store.account_key().unwrap().as_bytes(), &[7; 32]);
 }
+
+#[test]
+fn the_meta_writer_writes_what_the_store_reads() {
+    let (_dir, _path, store) = new_store();
+    let writer = store.meta_writer().unwrap();
+    writer.set_sealed_meta("sync:outbox", b"state").unwrap();
+    assert_eq!(
+        &store.sealed_meta("sync:outbox").unwrap().unwrap()[..],
+        b"state"
+    );
+}
```

- [ ] **Step 2: Run and commit.**

Commit: `Core A1d-1: MetaWriter saves sealed meta through its own connection`.

---

### Task 6: The sync bridge in the session

**Files:** Modify `crates/keyorra-session/Cargo.toml`, `crates/keyorra-session/src/lib.rs`; create `crates/keyorra-session/src/sync/mod.rs`, `crates/keyorra-session/src/sync/keys.rs`, `crates/keyorra-session/src/sync/tests.rs`.

- [ ] **Step 1: Dependencies.**

Apply (Cargo updates `Cargo.lock`):

```diff
diff --git a/crates/keyorra-session/Cargo.toml b/crates/keyorra-session/Cargo.toml
index f704d0c..00607b0 100644
--- a/crates/keyorra-session/Cargo.toml
+++ b/crates/keyorra-session/Cargo.toml
@@ -8,7 +8,9 @@ publish = false
 [dependencies]
 chacha20poly1305 = "0.10"
 data-encoding = "2"
+ed25519-dalek = { version = "2", features = ["zeroize"] }
 keyorra-core = { path = "../keyorra-core" }
+keyorra-sync = { path = "../keyorra-sync" }
 p256 = { version = "0.13", features = ["ecdh"] }
 psl = "2"
 rand = "0.8"
@@ -22,4 +24,5 @@ zeroize = { version = "1", features = ["serde"] }
 
 [dev-dependencies]
 keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
+keyorra-sync = { path = "../keyorra-sync", features = ["test-utils"] }
 tempfile = "3"
diff --git a/crates/keyorra-session/src/lib.rs b/crates/keyorra-session/src/lib.rs
index 41c689a..6343e7e 100644
--- a/crates/keyorra-session/src/lib.rs
+++ b/crates/keyorra-session/src/lib.rs
@@ -8,6 +8,7 @@ pub mod error;
 pub mod session;
 pub mod settings;
 pub mod sleep;
+pub mod sync;
 pub mod throttle;
 pub mod touchid;
 pub mod watchtower;
```

- [ ] **Step 2: Failing tests.**

Create `crates/keyorra-session/src/sync/tests.rs` (enable then join and see the data; changes travel both ways, including trash; concurrent edits become one conflict copy in both stores; a restart resumes from the store, with a change made during the rebuild; vaults created through sync get committed ids):

```rust
//! Plan A1d: two vault stores synced through an in-memory store of files.

use std::collections::BTreeSet;

use keyorra_core::crypto::KdfParams;
use keyorra_core::model::{Item, ItemKind};
use keyorra_core::store::Store;
use keyorra_sync::header::Header;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::MemoryTransport;

use super::*;

const PW: &str = "correct horse battery";
const NOW_MS: u64 = 1_790_000_000_000;

struct Device {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
    synced: Synced<MemoryTransport>,
    keys: MemoryDeviceKeys,
}

fn titles(store: &Store) -> BTreeSet<String> {
    store
        .vaults()
        .unwrap()
        .iter()
        .flat_map(|v| store.list_items(Some(v.id)).unwrap())
        .filter_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) => Some(i.title),
            _ => None,
        })
        .collect()
}

/// The test header unlock: the real one refuses the cheap KDF parameters used here.
fn cheap_unlock(password: &'static str, sk: [u8; 16]) -> impl FnMut(&Header) -> Result<Key> {
    move |h: &Header| {
        let keys = derive_sync_keys(
            password,
            &h.salt,
            h.kdf,
            &SecretKey::from_bytes(sk),
            &h.account_id,
        )?;
        h.unwrap_account_key(&keys.kek)
    }
}

/// A store with a vault and an item, made the main device of a new account.
fn main_device(transport: &MemoryTransport) -> (Device, EmergencyKit) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    let mut store = Store::create(&path, PW, KdfParams::INSECURE_FAST).unwrap();
    let vault = store.create_vault("Personal").unwrap();
    store
        .save_item(&Item::new(vault.id, ItemKind::Login, "before sync", 1))
        .unwrap();
    let mut keys = MemoryDeviceKeys::default();
    let (synced, kit) = enable(
        &mut store,
        transport.clone(),
        &mut keys,
        "Main",
        PW,
        KdfParams::INSECURE_FAST,
        NOW_MS,
    )
    .unwrap();
    (
        Device {
            _dir: dir,
            path,
            store,
            synced,
            keys,
        },
        kit,
    )
}

fn joiner(transport: &MemoryTransport, kit: &EmergencyKit, pin: Option<RootPin>) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("join.db");
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let mut keys = MemoryDeviceKeys::default();
    let (store, synced) = join(
        &path,
        PW,
        KdfParams::INSECURE_FAST,
        &sk,
        &id,
        pin.as_ref(),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS,
    )
    .unwrap();
    Device {
        _dir: dir,
        path,
        store,
        synced,
        keys,
    }
}

fn round(d: &mut Device, at: u64) {
    d.synced.round(&mut d.store, at).unwrap();
}

/// Main device and an approved second device, in step.
fn pair() -> (MemoryTransport, Device, Device) {
    let transport = MemoryTransport::new();
    let (mut main, kit) = main_device(&transport);
    let pin = main.synced.root_pin();
    let mut laptop = joiner(&transport, &kit, Some(pin));
    round(&mut main, NOW_MS + 1);
    let code = laptop.synced.key_code();
    let id = laptop.synced.engine().device();
    main.synced.approve(id, &code, NOW_MS + 2).unwrap();
    for t in 3..6 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    (transport, main, laptop)
}

#[test]
fn enabling_writes_the_vault_and_a_new_device_joins_and_sees_it() {
    let (_t, main, laptop) = pair();
    assert!(is_enabled(&main.store).unwrap());
    assert!(is_enabled(&laptop.store).unwrap());
    assert_eq!(titles(&laptop.store), titles(&main.store));
    assert!(titles(&laptop.store).contains("before sync"));
    assert!(laptop.synced.engine().can_write());
}

#[test]
fn local_changes_travel_both_ways() {
    let (_t, mut main, mut laptop) = pair();
    let vault = laptop.store.vaults().unwrap()[0].id;
    let item = Item::new(vault, ItemKind::SecureNote, "from the laptop", 10);
    laptop.store.save_item(&item).unwrap();
    round(&mut laptop, NOW_MS + 10);
    round(&mut main, NOW_MS + 11);
    assert!(titles(&main.store).contains("from the laptop"));
    main.store.delete_item(item.id, 12).unwrap();
    round(&mut main, NOW_MS + 12);
    round(&mut laptop, NOW_MS + 13);
    assert!(!titles(&laptop.store).contains("from the laptop"));
    assert_eq!(laptop.store.deleted_items().unwrap().len(), 1);
    assert!(laptop.store.pending_changes().unwrap().is_empty());
}

#[test]
fn concurrent_edits_become_a_conflict_copy_in_both_stores() {
    let (_t, mut main, mut laptop) = pair();
    let vault = main.store.vaults().unwrap()[0].id;
    let id = main
        .store
        .list_items(Some(vault))
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) => Some(i.id),
            _ => None,
        })
        .unwrap();
    let mut a = main.store.get_item(id).unwrap();
    a.title = "edited on main".into();
    main.store.save_item(&a).unwrap();
    let mut b = laptop.store.get_item(id).unwrap();
    b.title = "edited on laptop".into();
    laptop.store.save_item(&b).unwrap();
    for t in 20..26 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    let seen = titles(&main.store);
    assert!(
        seen.contains("edited on main") && seen.contains("edited on laptop"),
        "{seen:?}"
    );
    assert_eq!(titles(&laptop.store), seen);
    let copies = main
        .store
        .list_items(Some(vault))
        .unwrap()
        .into_iter()
        .filter(|e| matches!(e, keyorra_core::store::ItemEntry::Ok(i) if i.conflict.is_some()))
        .count();
    assert_eq!(copies, 1);
}

#[test]
fn a_restart_resumes_from_the_store() {
    let (transport, mut main, mut laptop) = pair();
    let vault = laptop.store.vaults().unwrap()[0].id;
    laptop
        .store
        .save_item(&Item::new(vault, ItemKind::Login, "before restart", 30))
        .unwrap();
    round(&mut laptop, NOW_MS + 30);
    // The app quits; the store is opened again and unlocked.
    let Device {
        _dir, path, keys, ..
    } = laptop;
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    let synced = resume(&store, transport.clone(), &keys).unwrap();
    let mut laptop = Device {
        _dir,
        path,
        store,
        synced,
        keys,
    };
    // A change made right after unlock, while the engine reads its streams again.
    laptop
        .store
        .save_item(&Item::new(vault, ItemKind::Login, "after restart", 31))
        .unwrap();
    for t in 31..35 {
        round(&mut laptop, NOW_MS + t);
        round(&mut main, NOW_MS + t);
    }
    let seen = titles(&main.store);
    assert!(seen.contains("before restart") && seen.contains("after restart"));
    assert_eq!(titles(&laptop.store), seen);
    assert!(main
        .store
        .list_items(None)
        .unwrap()
        .iter()
        .all(|e| !matches!(e, keyorra_core::store::ItemEntry::Ok(i) if i.conflict.is_some())));
}

#[test]
fn vaults_created_while_synced_get_committed_ids() {
    let (_t, mut main, mut laptop) = pair();
    let id = main
        .synced
        .create_vault(&mut main.store, "Work", NOW_MS + 40)
        .unwrap();
    round(&mut main, NOW_MS + 41);
    round(&mut laptop, NOW_MS + 42);
    let names: BTreeSet<String> = laptop
        .store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert!(names.contains("Work"));
    assert!(laptop.store.vaults().unwrap().iter().any(|v| v.id == id));
}
```

- [ ] **Step 3: Device keys.**

Create `crates/keyorra-session/src/sync/keys.rs`:

```rust
//! Device signing keys. A1d-2 keeps them in the macOS Keychain with
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (a Swift helper, like Touch ID), so a
//! database restored or copied to another Mac finds no key and the device retires its id.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use keyorra_sync::engine::DeviceKeys;
use keyorra_sync::DeviceId;
use zeroize::Zeroizing;

pub trait DeviceKeyStore: Send {
    fn load(&self, device: &DeviceId) -> Option<SigningKey>;
    fn store(&mut self, device: DeviceId, key: &SigningKey);
    /// Another handle to the same keys (the engine keeps one to store a new id's key when it
    /// retires the old one).
    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore>;
}

/// In memory (tests, and until the Keychain helper exists); clones share the keys.
#[derive(Clone, Default)]
pub struct MemoryDeviceKeys(pub Arc<Mutex<BTreeMap<DeviceId, Zeroizing<[u8; 32]>>>>);

impl DeviceKeyStore for MemoryDeviceKeys {
    fn load(&self, device: &DeviceId) -> Option<SigningKey> {
        self.0
            .lock()
            .unwrap()
            .get(device)
            .map(|k| SigningKey::from_bytes(k))
    }

    fn store(&mut self, device: DeviceId, key: &SigningKey) {
        self.0
            .lock()
            .unwrap()
            .insert(device, Zeroizing::new(key.to_bytes()));
    }

    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.clone())
    }
}

/// The engine's view of the key store: whether a key is held, and storing a new id's key.
pub(super) struct EngineKeys(pub Box<dyn DeviceKeyStore>);

impl DeviceKeys for EngineKeys {
    fn holds(&self, device: &DeviceId) -> bool {
        self.0.load(device).is_some()
    }
    fn store(&mut self, device: DeviceId, key: &SigningKey) {
        self.0.store(device, key);
    }
}
```

- [ ] **Step 4: The bridge.**

Create `crates/keyorra-session/src/sync/mod.rs`:

```rust
//! Sync for a vault store (plan A1d): the bridge between the local [`Store`] and the sync
//! [`Engine`].
//!
//! - **Enabling** turns a store into the main device of a new synced account: Secret Key,
//!   account header, every vault and item written as first versions.
//! - **Joining** creates a store on a new device from the account header in the store
//!   (password + Secret Key, optionally pinned to the main device by a setup code); the
//!   device then self-joins and waits for the main device's approval.
//! - **Resuming** continues after a restart (the engine reads the streams again).
//! - **A round** writes the local changes the store recorded, syncs, shows what sync shows in
//!   the store, and persists the engine's state.
//!
//! The account key `AK` is the store's own account key: vault keys are wrapped the same way
//! locally and in sync. The engine's state that cannot be read again from the store's streams
//! is kept as sealed meta of the store (`sync:config`, `sync:outbox`, `sync:memo`) and in its
//! `sync_segments` table. Attachment contents travel with the folder transport (plan A2).

mod keys;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{KdfParams, Key};
use keyorra_core::model::Item;
use keyorra_core::store::{Change, ChangeKind, MetaWriter, Store};
use keyorra_sync::account::{unlock_join_with, RootPin};
use keyorra_sync::engine::{Engine, EngineMemo, Event, OutboxState, OutboxStore, Resumed};
use keyorra_sync::header::{wrap_account_key, Header};
use keyorra_sync::keys::derive_sync_keys;
use keyorra_sync::present::ItemState;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::{Fetched, Transport};
use keyorra_sync::{AccountId, DeviceId, Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use keys::{DeviceKeyStore, MemoryDeviceKeys};

const CONFIG: &str = "sync:config";
const OUTBOX: &str = "sync:outbox";
const MEMO: &str = "sync:memo";

/// What this device knows about its synced account (sealed meta `sync:config`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SyncConfig {
    account_id: AccountId,
    device: DeviceId,
    device_name: String,
    root: DeviceId,
    root_key: [u8; 32],
    secret_key: [u8; 16],
    secret_key_id: String,
}

/// What the user writes down when sync is enabled (spec §7.6). The location is the
/// transport's (plan A2/A3 add it).
pub struct EmergencyKit {
    pub account_id: String,
    pub secret_key: Zeroizing<String>,
}

/// Saves the engine's outbox through a second connection, before every append.
struct StoreOutbox(MetaWriter);

impl OutboxStore for StoreOutbox {
    fn save(&mut self, state: &OutboxState) -> Result<()> {
        self.0
            .set_sealed_meta(OUTBOX, &state.to_bytes())
            .map_err(Error::from)
    }
}

/// Sync of one store over one transport.
pub struct Synced<T: Transport> {
    engine: Engine<OsRng>,
    transport: T,
    config: SyncConfig,
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

fn new_signer() -> SigningKey {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut secret[..]);
    SigningKey::from_bytes(&secret)
}

fn save_config(store: &mut Store, config: &SyncConfig) -> Result<()> {
    let bytes = serde_json::to_vec(config).map_err(|e| Error::Malformed(e.to_string()))?;
    store.set_sealed_meta(CONFIG, &bytes)?;
    Ok(())
}

fn load_config(store: &Store) -> Result<SyncConfig> {
    let raw = store
        .sealed_meta(CONFIG)?
        .ok_or_else(|| Error::NotFound("sync is not set up on this vault".into()))?;
    serde_json::from_slice(&raw).map_err(|e| Error::Malformed(e.to_string()))
}

fn item_json(item: &Item) -> Result<Vec<u8>> {
    serde_json::to_vec(item).map_err(|e| Error::Malformed(e.to_string()))
}

/// Whether sync is set up on this store.
pub fn is_enabled(store: &Store) -> Result<bool> {
    Ok(store.sync_tracking()? && store.sealed_meta(CONFIG)?.is_some())
}

/// Turns `store` into the main device of a new synced account, writing everything it holds
/// as first versions. The synced header uses `kdf` (the remote floor applies when joining).
#[allow(clippy::too_many_arguments)]
pub fn enable<T: Transport>(
    store: &mut Store,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<(Synced<T>, EmergencyKit)> {
    if is_enabled(store)? {
        return Err(Error::Refused("sync is already on".into()));
    }
    let account_id = random_id();
    let device = random_id();
    let signer = new_signer();
    keys.store(device, &signer);
    let (secret_key, secret_key_id) = SecretKey::generate(&mut OsRng);
    let account_key = store.account_key_copy()?;
    let root_key = signer.verifying_key();
    let mut engine = Engine::create_account(
        device,
        signer,
        device_name,
        account_id,
        account_key.clone(),
        OsRng,
        wall_ms,
    );
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let sync_keys = derive_sync_keys(password, &salt, kdf, &secret_key, &account_id)?;
    let mut header = Header {
        account_id,
        epoch: 1,
        generation: 1,
        root_device: device,
        root_key: root_key.to_bytes(),
        kdf,
        salt,
        secret_key_id: secret_key_id.clone(),
        wrapped_account_key: Vec::new(),
    };
    header.wrapped_account_key =
        wrap_account_key(&sync_keys.kek, &account_key, &header, &mut OsRng);
    engine.publish_header(header, wall_ms)?;
    // Everything the store holds: vaults with their ids and keys, then items.
    for (info, key, deleted) in store.vault_rows()? {
        if !deleted {
            engine.adopt_vault(info.id, &info.name, &key, wall_ms)?;
        }
    }
    for vault in store.vaults()? {
        for entry in store.list_items(Some(vault.id))? {
            if let keyorra_core::store::ItemEntry::Ok(item) = entry {
                engine.save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)?;
            }
        }
    }
    for entry in store.deleted_items()? {
        if let keyorra_core::store::ItemEntry::Ok(item) = entry {
            if let Some((_, Some(at))) = store.item_state(item.id)? {
                engine.save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)?;
                engine.trash_item(item.id, at.max(0) as u64, wall_ms)?;
            }
        }
    }
    let config = SyncConfig {
        account_id,
        device,
        device_name: device_name.to_owned(),
        root: device,
        root_key: root_key.to_bytes(),
        secret_key: *secret_key.as_bytes(),
        secret_key_id: secret_key_id.clone(),
    };
    save_config(store, &config)?;
    store.set_sync_tracking(true)?;
    let kit = EmergencyKit {
        account_id: data_encoding::HEXLOWER.encode(&account_id),
        secret_key: secret_key.display(&secret_key_id),
    };
    let mut synced = Synced {
        engine,
        transport,
        config,
    };
    synced.round(store, wall_ms)?;
    Ok((synced, kit))
}

/// A new device joins a synced account it has no local vault for: a store is created at
/// `path` with the account's key (unlocked with the local `password`), and the device
/// self-joins; it waits for the main device's approval (comparing [`Synced::key_code`]).
/// `unlock` opens a header with the master password and the Secret Key (the app passes
/// `Header::unlock`, which refuses KDF parameters below the remote floor).
#[allow(clippy::too_many_arguments)]
pub fn join<T: Transport>(
    path: &std::path::Path,
    password: &str,
    local_kdf: KdfParams,
    secret_key: &SecretKey,
    secret_key_id: &str,
    pin: Option<&RootPin>,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    unlock: impl FnMut(&Header) -> Result<Key>,
    wall_ms: u64,
) -> Result<(Store, Synced<T>)> {
    let files = transport.headers()?;
    let root_head = match transport.root_head_file()? {
        Fetched::Ready(b) => Some(b),
        _ => None,
    };
    let joined = unlock_join_with(&files, root_head.as_deref(), pin, unlock)?;
    let header = joined.file.header.clone();
    let mut store =
        Store::create_with_account_key(path, password, local_kdf, joined.account_key.clone())?;
    let device = random_id();
    let signer = new_signer();
    keys.store(device, &signer);
    let root_key = VerifyingKey::from_bytes(&header.root_key)
        .map_err(|_| Error::Malformed("main device key".into()))?;
    let mut engine = Engine::join(
        device,
        signer,
        device_name,
        header.account_id,
        joined.account_key,
        header.root_device,
        root_key,
        OsRng,
    );
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    engine.self_join(wall_ms)?;
    let config = SyncConfig {
        account_id: header.account_id,
        device,
        device_name: device_name.to_owned(),
        root: header.root_device,
        root_key: header.root_key,
        secret_key: *secret_key.as_bytes(),
        secret_key_id: secret_key_id.to_owned(),
    };
    save_config(&mut store, &config)?;
    store.set_sync_tracking(true)?;
    let mut synced = Synced {
        engine,
        transport,
        config,
    };
    synced.round(&mut store, wall_ms)?;
    Ok((store, synced))
}

/// Continues sync after a restart (the store unlocked). The device key comes from `keys`; if
/// it is gone, the engine retires the id on its first round (spec §4.2).
pub fn resume<T: Transport>(
    store: &Store,
    transport: T,
    keys: &dyn DeviceKeyStore,
) -> Result<Synced<T>> {
    let config = load_config(store)?;
    let outbox = match store.sealed_meta(OUTBOX)? {
        Some(b) => OutboxState::from_bytes(&b)?,
        None => return Err(Error::NotFound("sync outbox".into())),
    };
    let memo = match store.sealed_meta(MEMO)? {
        Some(b) => EngineMemo::from_bytes(&b)?,
        None => EngineMemo::default(),
    };
    let signer = keys.load(&config.device).unwrap_or_else(new_signer);
    let root_key = VerifyingKey::from_bytes(&config.root_key)
        .map_err(|_| Error::Malformed("main device key".into()))?;
    let mut engine = Engine::resume(
        config.device,
        signer,
        &config.device_name,
        config.account_id,
        store.account_key_copy()?,
        config.root,
        root_key,
        OsRng,
        Resumed {
            outbox,
            own_segments: store.own_segments()?,
            memo,
        },
    )?;
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    engine.set_device_keys(Box::new(keys::EngineKeys(keys.boxed_clone())));
    Ok(Synced {
        engine,
        transport,
        config,
    })
}

impl<T: Transport> Synced<T> {
    pub fn engine(&self) -> &Engine<OsRng> {
        &self.engine
    }

    /// The code to compare on the main device before it approves this one.
    pub fn key_code(&self) -> String {
        self.engine.key_fingerprint()
    }

    /// The main device approves a device that self-joined, after the user compared codes.
    pub fn approve(&mut self, device: DeviceId, code: &str, wall_ms: u64) -> Result<()> {
        self.engine.approve(device, code, wall_ms)
    }

    /// A new vault, created through sync so its id commits to its key (spec §4.4), then
    /// shown in the store.
    pub fn create_vault(&mut self, store: &mut Store, name: &str, wall_ms: u64) -> Result<Uuid> {
        let id = self.engine.create_vault(name, wall_ms)?;
        self.show(store)?;
        Ok(id)
    }

    /// One round: write the local changes, sync, show the result in the store, persist.
    /// Returns the engine's events.
    pub fn round(&mut self, store: &mut Store, wall_ms: u64) -> Result<Vec<Event>> {
        self.write_changes(store, wall_ms)?;
        let synced = self.engine.sync(&self.transport, wall_ms);
        // What could not be written before (the engine was still reading its own stream).
        self.write_changes(store, wall_ms)?;
        self.show(store)?;
        self.persist(store)?;
        synced?;
        Ok(self.engine.take_events())
    }

    /// The store's recorded changes, as versions. A change the engine cannot take yet (it
    /// is still reading its own stream after a restart, or conflict copies are owed) stays.
    fn write_changes(&mut self, store: &mut Store, wall_ms: u64) -> Result<()> {
        if !self.engine.can_write() {
            return Ok(());
        }
        let mut done = Vec::new();
        for change in store.pending_changes()? {
            match self.write_change(store, change, wall_ms) {
                Ok(()) | Err(Error::NotFound(_)) => done.push(change),
                Err(Error::Refused(_)) => {}
                Err(e) => return Err(e),
            }
        }
        store.clear_changes(&done)?;
        Ok(())
    }

    fn write_change(&mut self, store: &Store, change: Change, wall_ms: u64) -> Result<()> {
        let view = self.engine.view();
        match change.kind {
            ChangeKind::Vault => {
                let Some((info, key, deleted)) = store
                    .vault_rows()?
                    .into_iter()
                    .find(|(i, _, _)| i.id == change.id)
                else {
                    return Ok(());
                };
                match view.vaults.get(&change.id) {
                    None if !deleted => self.engine.adopt_vault(info.id, &info.name, &key, wall_ms),
                    None => Ok(()),
                    Some(v) if deleted && !v.deleted => {
                        self.engine.delete_vault(change.id, wall_ms)
                    }
                    Some(v) if !deleted && v.name != info.name => {
                        self.engine.rename_vault(change.id, &info.name, wall_ms)
                    }
                    Some(_) => Ok(()),
                }
            }
            ChangeKind::Item => {
                let synced = view.items.get(&change.id);
                match store.item_state(change.id)? {
                    Some((item, None)) => {
                        self.engine
                            .save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)
                    }
                    Some((item, Some(at))) => {
                        let live_same = synced.is_some_and(|v| {
                            v.state == ItemState::Live
                                && v.payload
                                    .as_ref()
                                    .and_then(|p| serde_json::from_slice::<Item>(&p.item_json).ok())
                                    == Some(item.clone())
                        });
                        if !live_same && synced.is_none_or(|v| v.state != ItemState::Trashed) {
                            self.engine.save_item(
                                item.vault_id,
                                item.id,
                                &item_json(&item)?,
                                wall_ms,
                            )?;
                        }
                        match self.engine.view().items.get(&change.id).map(|v| v.state) {
                            Some(ItemState::Live) => {
                                self.engine.trash_item(change.id, at.max(0) as u64, wall_ms)
                            }
                            _ => Ok(()),
                        }
                    }
                    None if store.item_purged(change.id)? => {
                        if synced.is_some_and(|v| v.state == ItemState::Live) {
                            self.engine.trash_item(change.id, 0, wall_ms)?;
                        }
                        match self.engine.view().items.get(&change.id).map(|v| v.state) {
                            Some(ItemState::Trashed) => self.engine.purge_item(change.id, wall_ms),
                            _ => Ok(()),
                        }
                    }
                    None => Ok(()),
                }
            }
            // Attachment contents travel with the folder transport (plan A2).
            ChangeKind::Attachment => Ok(()),
        }
    }

    /// What sync shows, in the store. Records with local changes not yet written are left as
    /// they are (they will be written, then shown).
    fn show(&mut self, store: &mut Store) -> Result<()> {
        let pending: BTreeSet<Uuid> = store.pending_changes()?.into_iter().map(|c| c.id).collect();
        let view = self.engine.view();
        for (id, v) in &view.vaults {
            if !pending.contains(id) {
                store.apply_remote_vault(*id, &v.name, &v.wrapped_key, v.deleted)?;
            }
        }
        for (id, v) in &view.items {
            if pending.contains(id) {
                continue;
            }
            match (v.state, &v.payload, v.vault_id) {
                (ItemState::Purged, _, _) => store.apply_remote_purge(*id)?,
                (_, Some(p), Some(vault)) => {
                    let Ok(mut item) = serde_json::from_slice::<Item>(&p.item_json) else {
                        continue;
                    };
                    item.id = *id;
                    item.vault_id = vault;
                    let deleted_at = match v.state {
                        ItemState::Trashed => Some(p.deleted_at.unwrap_or(0) as i64),
                        _ => None,
                    };
                    store.apply_remote_item(&item, deleted_at)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Everything the engine cannot read again from the streams.
    fn persist(&mut self, store: &mut Store) -> Result<()> {
        // A retired id: the device goes on under its new one.
        if self.engine.device() != self.config.device {
            self.config.device = self.engine.device();
            save_config(store, &self.config)?;
        }
        store.set_sealed_meta(OUTBOX, &self.engine.outbox_state().to_bytes())?;
        store.set_sealed_meta(MEMO, &self.engine.memo().to_bytes())?;
        store.set_own_segments(self.engine.own_segments())?;
        Ok(())
    }

    /// The account id and Secret Key, for the Emergency Kit or a setup code.
    pub fn emergency_kit(&self) -> EmergencyKit {
        let sk = SecretKey::from_bytes(self.config.secret_key);
        EmergencyKit {
            account_id: data_encoding::HEXLOWER.encode(&self.config.account_id),
            secret_key: sk.display(&self.config.secret_key_id),
        }
    }

    /// The pin a setup code shown on this device carries (the main device's id and key code).
    pub fn root_pin(&self) -> RootPin {
        RootPin {
            device: self.config.root,
            key_fingerprint: keyorra_sync::trust::key_fingerprint(
                &VerifyingKey::from_bytes(&self.config.root_key).expect("checked when saved"),
            ),
        }
    }
}
```

- [ ] **Step 5: Run and commit.**

`cargo test -p keyorra-session sync::` green (5 tests), then the workspace. Commit: `Session A1d-1: enable, join, resume and sync rounds for a vault store`.

---

### Task 7: Spec

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

- [ ] **Step 2: Commit.**

`docs: A1d-1 local sync state, single change path`.

---

### Task 8: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (584 passed, 3 ignored when verified); `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

