# Keyorra Sync A3-1 Implementation Plan (the Sync screen's backend: status, alarms, actions, tools, commands)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everything the Sync screen (A3-2) shows and does, as session methods and Tauri commands: one call for the whole screen (on/off, running, location, last round, devices, alarms with explanations and the actions that fit, notices, a log of this unlock), alarm actions (accept, restore from this Mac, remove device, continue as a new device), removing a device, "Verify everything" (the local copy decrypts and matches what sync shows), "What the folder sees" (every file with its size, unknown files marked, nothing read), the database's backup copies with delete, joining that reports what happened and the code to compare, choosing the sync folder (iCloud Drive or another, with what to keep in mind), and copying the setup code concealed from clipboard managers.

**Builds on:** `feat/sync-design` at `5c4dd87` (A2 with its review fixes).

**Verified:** every task was applied in order in a scratch worktree from `5c4dd87`; the workspace suite passes (687 tests, 4 ignored), clippy is clean (it compiles the Swift files), and the adversary and convergence property tests pass at 2000 cases in release.

**Architecture:** `Transport::inventory` (names and sizes; the folder transport marks names it does not read). `keyorra-session::sync::screen`: `AlarmView` (id, kind, title, explanation, actions), `Synced::alarm_action`, `remove_device`, `verify` (`VerifyReport`), `inventory`, `describe` (log lines). `keyorra-session::session::sync_screen`: `SyncScreenDto`, `sync_alarm_action`, `remove_sync_device`, `verify_sync`, `sync_folder_files`, `backups`, `delete_backup`; the session keeps the log (200 lines, until it locks) and the last round's time; `join_sync` returns a `JoinOutcome`. App: `SyncPlace` (iCloud Drive or a chosen folder, kept in `sync-place`), `describe_place`, `copy_concealed` (Swift: `org.nspasteboard.ConcealedType`, `TransientType`), the commands, the watcher follows the place, `sync-approval` events.

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md` §9.1 (Sync screen):

> The Sync screen is one call (`sync_screen`): on/off, running, location, last round (time, went through), this Mac's role and key code, devices (approved, waiting, removed, main, this Mac), alarms with a plain title, an explanation and the actions that fit (accept; restore from this Mac — own stream, or any stream on the main Mac; remove device — the main Mac, for a forked device; continue as a new device), notices of the last round, and the log of this unlock (200 lines, in memory). "Unconfirmed" is shown for the account (the main Mac's newest changes are not all here), not per item. Tools: Emergency Kit (master password unless entered in the last 5 minutes), Verify everything (every item and attachment decrypts; every live item matches what sync shows), What the folder sees (names and sizes; unknown files marked), the database's backup copies (`.bak-v*`, `.pre-sync-*`) with delete. The sync folder is chosen only while sync is off (iCloud Drive by default; another folder with a note on what to keep in mind: cloud storage folders kept downloaded, network drives connected). The setup code is copied concealed from clipboard managers and cleared after 90 seconds.

## Decisions

See the A3-2 plan for the user-visible ones; internal:

- **Alarm ids** are a hash of the alarm, stable while it stands; an action is checked against the actions offered for it.
- **The log is not persisted**: it would be a record of activity on disk; the alarms that matter persist in the engine's memo.
- **Backups** are found by name next to the database (`<db>.bak-v*`, `<db>.pre-sync-*`), deleted with their SQLite companions; nothing else can be deleted through the command.
- **The sync folder choice** lives in the app (`sync-place` next to the vault), not in `Settings` (which the UI saves whole).

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root: `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings`; the touched crates' tests. Frontend from `app/`: `pnpm exec tsc --noEmit`; `pnpm exec vitest run`.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw (use it for vitest: the proxy otherwise writes `app/.vitest/`). Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against the state after the previous task; apply them with `git apply` (or by hand), in task order. New files are given in full.
- Never run `--ignored` tests; never touch the real keychain, Secure Enclave or iCloud from tests.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-sync/src/transport.rs, faults.rs           Transport::inventory, InventoryEntry
crates/keyorra-sync-fs/src/lib.rs, tests.rs               the folder's inventory
crates/keyorra-session/src/sync/screen.rs                 NEW alarm views and actions, verify, log lines
crates/keyorra-session/src/sync/mod.rs                    status: root_confirmed, removed devices
crates/keyorra-session/src/session/sync_screen.rs         NEW the screen and its commands, backups
crates/keyorra-session/src/session/{mod,sync,sync_tests}.rs   log, last round, join outcome, location
app/src-tauri/src/syncfolder.rs                           SyncPlace, describe_place, copy_concealed
app/src-tauri/src/{commands,lib}.rs                       commands, watcher follows the place, sync-approval
app/src-tauri/swift/SyncFolder.swift                      the concealed pasteboard
```

---

### Task 1: What the folder holds

**Files:** Modify `crates/keyorra-sync/src/transport.rs`, `faults.rs`, `crates/keyorra-sync-fs/src/lib.rs`, `tests.rs`.

- [ ] **Step 1: Failing test.**

`the_inventory_lists_files_and_marks_strangers` is in this patch:

```diff
diff --git a/crates/keyorra-sync-fs/src/tests.rs b/crates/keyorra-sync-fs/src/tests.rs
index 016d3ae..22b77aa 100644
--- a/crates/keyorra-sync-fs/src/tests.rs
+++ b/crates/keyorra-sync-fs/src/tests.rs
@@ -571,3 +571,38 @@ fn review_a2_i6_chunk_state_does_not_read() {
     assert_eq!(*a.1.lock().unwrap(), 0, "nothing read");
     assert!(a.0.requested.lock().unwrap().contains(&away_path));
 }
+
+/// Plan A3: "what the folder sees": every file with its size, unknown ones marked, nothing
+/// read, symlinks and temp files left out.
+#[test]
+fn the_inventory_lists_files_and_marks_strangers() {
+    let dir = tempfile::tempdir().unwrap();
+    let t = folder(dir.path());
+    let segs = some_segments();
+    t.append(&segs[0]).unwrap();
+    let chunk = t.put_chunk(b"KYC1 abc").unwrap();
+    std::fs::write(
+        dir.path()
+            .join("streams")
+            .join("01".repeat(16))
+            .join("x (1).seg"),
+        b"x",
+    )
+    .unwrap();
+    let inv = t.inventory().unwrap();
+    let find = |p: &str| inv.iter().find(|e| e.path == p).cloned();
+    let seg = find(&format!("streams/{}/0000000000000001.seg", "01".repeat(16))).unwrap();
+    assert!(seg.counted);
+    assert_eq!(seg.size, segs[0].len() as u64);
+    assert!(
+        find(&format!("chunks/{}/{chunk}", &chunk[..2]))
+            .unwrap()
+            .counted
+    );
+    assert!(
+        !find(&format!("streams/{}/x (1).seg", "01".repeat(16)))
+            .unwrap()
+            .counted
+    );
+    assert!(find("README-KEYORRA.txt").is_some());
+}
```

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/crates/keyorra-sync-fs/src/lib.rs b/crates/keyorra-sync-fs/src/lib.rs
index fbf7134..3ddc5eb 100644
--- a/crates/keyorra-sync-fs/src/lib.rs
+++ b/crates/keyorra-sync-fs/src/lib.rs
@@ -22,7 +22,7 @@ use keyorra_sync::chunk::chunk_name;
 use keyorra_sync::header::MAX_HEADER_FILE_LEN;
 use keyorra_sync::segment::{max_segment_len, SegmentHeader, HEADER_LEN};
 use keyorra_sync::snapshot::{max_snapshot_len, snapshot_name, SnapshotHeader};
-use keyorra_sync::transport::{AppendOutcome, Fetched, Transport};
+use keyorra_sync::transport::{AppendOutcome, Fetched, InventoryEntry, Transport};
 use keyorra_sync::{DeviceId, Error, Result};
 
 pub use avail::{Access, Availability, FileState, LocalDisk};
@@ -331,6 +331,45 @@ impl FolderTransport {
         Ok(None)
     }
 
+    /// Files under `rel` (at most three levels: `streams/<device>/<file>`), without
+    /// following symlinks or reading anything; the temp directory is left out.
+    fn inventory_dir(&self, rel: &Path, depth: usize, out: &mut Vec<InventoryEntry>) -> Result<()> {
+        self.check_time()?;
+        let dir = self.root.join(rel);
+        let entries = match std::fs::read_dir(&dir) {
+            Ok(e) => e,
+            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
+            Err(e) => return Err(io("listing the folder", e)),
+        };
+        for entry in entries.flatten() {
+            if out.len() >= self.max_entries {
+                return Err(Error::Transport("the folder holds too many files".into()));
+            }
+            let Ok(kind) = entry.file_type() else {
+                continue;
+            };
+            let name = entry.file_name().to_string_lossy().into_owned();
+            if kind.is_symlink() || (depth == 0 && name == NOSYNC_TMP) {
+                continue;
+            }
+            let path = rel.join(&name);
+            if kind.is_dir() {
+                if depth < 2 {
+                    self.inventory_dir(&path, depth + 1, out)?;
+                }
+                continue;
+            }
+            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
+            let text = path.to_string_lossy().replace('\\', "/");
+            out.push(InventoryEntry {
+                counted: counted(&text),
+                path: text,
+                size,
+            });
+        }
+        Ok(())
+    }
+
     fn chunk_path(&self, name: &str) -> PathBuf {
         self.root.join(CHUNKS).join(&name[..2]).join(name)
     }
@@ -526,6 +565,13 @@ impl Transport for FolderTransport {
         self.fetch(&self.chunk_path(name), max_chunk_len())
     }
 
+    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
+        let mut out = Vec::new();
+        self.inventory_dir(Path::new(""), 0, &mut out)?;
+        out.sort_by(|a, b| a.path.cmp(&b.path));
+        Ok(out)
+    }
+
     fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
         if !is_chunk_name(name) {
             return Ok(Fetched::Missing);
@@ -533,3 +579,16 @@ impl Transport for FolderTransport {
         self.state(&self.chunk_path(name))
     }
 }
+
+/// Whether a path (relative to the account folder) is a name Keyorra reads.
+fn counted(path: &str) -> bool {
+    let parts: Vec<&str> = path.split('/').collect();
+    match parts.as_slice() {
+        [README] => true,
+        [ACCOUNT, f] => *f == ROOT_HEAD || is_header_file(f),
+        [STREAMS, d, f] => parse_device_dir(d).is_some() && parse_segment_file(f).is_some(),
+        [SNAPSHOTS, d, f] => parse_device_dir(d).is_some() && parse_snapshot_file(f).is_some(),
+        [CHUNKS, p, f] => is_chunk_name(f) && f.starts_with(p) && p.len() == 2,
+        _ => false,
+    }
+}
diff --git a/crates/keyorra-sync/src/faults.rs b/crates/keyorra-sync/src/faults.rs
index 14d8c48..900089e 100644
--- a/crates/keyorra-sync/src/faults.rs
+++ b/crates/keyorra-sync/src/faults.rs
@@ -206,6 +206,10 @@ impl<T: Transport> Transport for Faulty<T> {
         self.inner.end_round()
     }
 
+    fn inventory(&self) -> Result<Vec<crate::transport::InventoryEntry>> {
+        self.inner.inventory()
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let f = self.faults();
         if self.roll(f.fail_before_append) {
@@ -319,6 +323,10 @@ impl<T: Transport> Transport for Rollback<T> {
     fn end_round(&self) {
         self.inner.end_round()
     }
+
+    fn inventory(&self) -> Result<Vec<crate::transport::InventoryEntry>> {
+        self.inner.inventory()
+    }
 }
 
 /// A store that shows one stream from another store: one side of a fork (two histories of
@@ -416,6 +424,10 @@ impl<T: Transport, U: Transport> Transport for Overlay<T, U> {
     fn end_round(&self) {
         self.base.end_round()
     }
+
+    fn inventory(&self) -> Result<Vec<crate::transport::InventoryEntry>> {
+        self.base.inventory()
+    }
 }
 
 #[cfg(test)]
diff --git a/crates/keyorra-sync/src/transport.rs b/crates/keyorra-sync/src/transport.rs
index bef7c89..ccfbe47 100644
--- a/crates/keyorra-sync/src/transport.rs
+++ b/crates/keyorra-sync/src/transport.rs
@@ -19,6 +19,16 @@ pub enum Fetched<T> {
     Missing,
 }
 
+/// One file as the store holds it, for "what the folder sees" (spec §9.2).
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct InventoryEntry {
+    /// Relative to the account's place (`streams/<device>/<seq>.seg`, …).
+    pub path: String,
+    pub size: u64,
+    /// The name is one Keyorra reads; `false`: an unknown file, ignored.
+    pub counted: bool,
+}
+
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum AppendOutcome {
     Appended,
@@ -81,6 +91,10 @@ pub trait Transport {
     fn begin_round(&self) {}
     /// The round is over: calls until the next round have no round budget (review A2 I1).
     fn end_round(&self) {}
+    /// Every file of the account as stored (names and sizes only, nothing is read).
+    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
+        Ok(Vec::new())
+    }
 }
 
 /// A boxed transport (the app picks the transport at run time).
@@ -142,6 +156,9 @@ impl<T: Transport + ?Sized> Transport for Box<T> {
     fn end_round(&self) {
         (**self).end_round()
     }
+    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
+        (**self).inventory()
+    }
 }
 
 #[derive(Clone, Debug, Default)]
@@ -314,6 +331,42 @@ impl Transport for MemoryTransport {
             .map_or(Fetched::Missing, |b| Fetched::Ready(b.clone())))
     }
 
+    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
+        let entry = |path: String, size: usize| InventoryEntry {
+            path,
+            size: size as u64,
+            counted: true,
+        };
+        let hex = |d: &DeviceId| data_encoding::HEXLOWER.encode(d);
+        let mut out = Vec::new();
+        for (device, segs) in self.streams.lock().unwrap().iter() {
+            for (seq, b) in segs {
+                out.push(entry(
+                    format!("streams/{}/{seq:016x}.seg", hex(device)),
+                    b.len(),
+                ));
+            }
+        }
+        let files = self.files.lock().unwrap();
+        for (name, b) in &files.headers {
+            out.push(entry(format!("account/{name}"), b.len()));
+        }
+        if let Some(b) = &files.root_head {
+            out.push(entry("account/root.head".into(), b.len()));
+        }
+        for (name, b) in &files.snapshots {
+            let author = SnapshotHeader::parse(b)
+                .map(|h| hex(&h.author))
+                .unwrap_or_default();
+            out.push(entry(format!("snapshots/{author}/{name}.snap"), b.len()));
+        }
+        for (name, b) in &files.chunks {
+            out.push(entry(format!("chunks/{}/{name}", &name[..2]), b.len()));
+        }
+        out.sort_by(|a, b| a.path.cmp(&b.path));
+        Ok(out)
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let header = SegmentHeader::parse(segment)?;
         let mut streams = self.streams.lock().unwrap();
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A3-1: what the folder holds (Transport::inventory)`.

---

### Task 2: The Sync screen in the session

**Files:** Create `crates/keyorra-session/src/sync/screen.rs`, `crates/keyorra-session/src/session/sync_screen.rs`; modify `crates/keyorra-session/src/sync/mod.rs`, `crates/keyorra-session/src/session/mod.rs`, `crates/keyorra-session/src/session/sync.rs`, `crates/keyorra-session/src/session/sync_tests.rs`.

- [ ] **Step 1: Failing tests.**

Apply (the screen shows the account; an alarm is explained and accepted, and only offered actions run; removing a device and verifying; backup copies are listed and deleted, nothing else):

```diff
diff --git a/crates/keyorra-session/src/session/sync_tests.rs b/crates/keyorra-session/src/session/sync_tests.rs
index 47e2c71..768ff1b 100644
--- a/crates/keyorra-session/src/session/sync_tests.rs
+++ b/crates/keyorra-session/src/session/sync_tests.rs
@@ -54,6 +54,9 @@ impl SyncLink for TestLink {
         self.place.0.lock().unwrap().insert(*account, t.clone());
         Ok(Box::new(t))
     }
+    fn location(&self, account: &keyorra_sync::AccountId) -> Option<String> {
+        Some(format!("place/{}", data_encoding::HEXLOWER.encode(account)))
+    }
     fn join_candidates(&self) -> Result<Vec<(String, BoxedTransport)>, String> {
         Ok(self
             .place
@@ -491,3 +494,151 @@ fn review_a2_i4_a_folder_still_downloading_says_so() {
         .unwrap();
     assert!(err.message.contains("still downloading"), "{}", err.message);
 }
+
+// ---- the Sync screen (plan A3) ----
+
+/// The Sync screen in one call: location, last round, devices, log; joining tells what
+/// happened and the code to compare.
+#[test]
+fn the_sync_screen_shows_the_account() {
+    let (place, (_d1, mut main), _laptop) = two_macs();
+    let (_d3, mut third) = new_session();
+    link(&mut third, &place, "Third");
+    let kit = main.emergency_kit(None, 1_005).unwrap();
+    let joined = third.join_sync(PW, &kit.setup_code, 1_400).unwrap();
+    assert_eq!(joined.mode, "new");
+    assert_eq!(
+        joined.key_code,
+        third.sync_status().unwrap().status.unwrap().key_code
+    );
+    main.sync_now(1_401).unwrap();
+    let screen = main.sync_screen().unwrap();
+    assert!(screen.enabled && screen.running);
+    assert!(screen.location.unwrap().starts_with("place/"));
+    assert_eq!(screen.last_round_at, Some(1_401));
+    assert_eq!(screen.last_round_ok, Some(true));
+    let status = screen.status.unwrap();
+    assert!(status.main_device && status.root_confirmed);
+    assert!(status
+        .devices
+        .iter()
+        .any(|d| d.name == "Third" && !d.approved));
+    assert!(
+        screen.log.iter().any(|l| l.text.starts_with("Received")),
+        "{:?}",
+        screen.log
+    );
+    let files = main.sync_folder_files().unwrap();
+    assert!(files
+        .iter()
+        .any(|f| f.path.starts_with("streams/") && f.counted));
+    main.lock();
+    main.unlock(PW, 1_402).unwrap();
+    assert!(
+        main.sync_screen().unwrap().log.is_empty(),
+        "the log is per unlock"
+    );
+}
+
+/// An alarm with its explanation and the actions that fit; accepting clears it.
+#[test]
+fn an_alarm_is_explained_and_accepted() {
+    let (place, (_d1, mut main), (_d2, mut laptop)) = two_macs();
+    add(&mut main, "one more", 1_410);
+    rounds(&mut main, &mut laptop, 1_411);
+    // The folder loses the main Mac's newest changes.
+    let folder = place.0.lock().unwrap().values().next().unwrap().clone();
+    let main_id = main.synced.as_ref().unwrap().engine().device();
+    let newest = folder
+        .dump()
+        .into_iter()
+        .filter(|(d, _, _)| *d == main_id)
+        .map(|(_, seq, _)| seq)
+        .max()
+        .unwrap();
+    folder.remove_segment(&main_id, newest);
+    laptop.sync_now(1_420).unwrap();
+    let alarms = laptop.sync_screen().unwrap().alarms;
+    let rollback = alarms
+        .iter()
+        .find(|a| a.kind == "rollback")
+        .expect("an alarm");
+    assert!(rollback.title.contains("Main"), "{}", rollback.title);
+    assert_eq!(
+        rollback.actions,
+        vec!["accept"],
+        "only the main Mac restores"
+    );
+    assert_eq!(
+        laptop
+            .sync_alarm_action(&rollback.id, "restore", 1_421)
+            .unwrap_err()
+            .kind,
+        ErrorKind::Invalid
+    );
+    laptop
+        .sync_alarm_action(&rollback.id, "accept", 1_422)
+        .unwrap();
+    assert!(laptop
+        .sync_screen()
+        .unwrap()
+        .alarms
+        .iter()
+        .all(|a| a.id != rollback.id));
+}
+
+/// The main Mac removes a device; "Verify everything" checks the local copy.
+#[test]
+fn removing_a_device_and_verifying() {
+    let (_place, (_d1, mut main), (_d2, mut laptop)) = two_macs();
+    let report = laptop.verify_sync().unwrap();
+    assert_eq!(report.items, 1);
+    assert_eq!((report.damaged, report.missing), (0, 0));
+    assert!(report.differing.is_empty());
+    let laptop_id = laptop
+        .sync_status()
+        .unwrap()
+        .status
+        .unwrap()
+        .devices
+        .into_iter()
+        .find(|d| d.this_device)
+        .unwrap()
+        .id;
+    assert_eq!(
+        laptop
+            .remove_sync_device(&laptop_id, 1_430)
+            .unwrap_err()
+            .kind,
+        ErrorKind::Invalid,
+        "only the main Mac removes devices"
+    );
+    main.remove_sync_device(&laptop_id, 1_431).unwrap();
+    main.sync_now(1_432).unwrap();
+    let devices = main.sync_status().unwrap().status.unwrap().devices;
+    assert!(devices.iter().any(|d| d.id == laptop_id && d.removed));
+}
+
+/// The database's backup copies are listed and can be deleted; nothing else can.
+#[test]
+fn backup_copies_are_listed_and_deleted() {
+    let (dir, mut s) = unlocked_session();
+    let base = dir.path().join("Application Support");
+    std::fs::write(base.join("keyorra.db.bak-v1"), b"old").unwrap();
+    std::fs::write(base.join("keyorra.db.pre-sync-20261006"), b"older").unwrap();
+    std::fs::write(base.join("keyorra.db.pre-sync-20261006-journal"), b"x").unwrap();
+    std::fs::write(base.join("settings.json"), b"{}").unwrap();
+    let backups = s.backups().unwrap();
+    let names: Vec<&str> = backups.iter().map(|b| b.name.as_str()).collect();
+    assert_eq!(names, ["keyorra.db.bak-v1", "keyorra.db.pre-sync-20261006"]);
+    assert_eq!(backups[0].kind, "migration");
+    assert_eq!(backups[1].size, 5);
+    assert_eq!(
+        s.delete_backup("settings.json", 1_440).unwrap_err().kind,
+        ErrorKind::NotFound
+    );
+    s.delete_backup("keyorra.db.pre-sync-20261006", 1_441)
+        .unwrap();
+    assert!(!base.join("keyorra.db.pre-sync-20261006-journal").exists());
+    assert_eq!(s.backups().unwrap().len(), 1);
+}
```

- [ ] **Step 2: Alarms, actions, verify, log lines.**

Create `crates/keyorra-session/src/sync/screen.rs`:

```rust
//! What the Sync screen shows and does (plan A3): alarms with their explanations and the
//! actions that fit, the log, a check of the local copy against sync, and the files as the
//! folder holds them.

use keyorra_core::model::Item;
use keyorra_core::store::{ItemEntry, Store};
use keyorra_sync::engine::{Alarm, Event, RetireReason};
use keyorra_sync::present::ItemState;
use keyorra_sync::transport::{InventoryEntry, Transport};
use keyorra_sync::{DeviceId, Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::Synced;

/// One alarm as the Sync screen shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlarmView {
    /// Stable while the alarm stands; actions name it.
    pub id: String,
    pub kind: &'static str,
    pub title: String,
    pub explanation: String,
    /// What the user can do: "accept", "restore", "remove", "leave".
    pub actions: Vec<&'static str>,
}

/// The result of "Verify everything".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub items: usize,
    /// Items here that cannot be decrypted.
    pub damaged: usize,
    pub attachments: usize,
    /// Attachments here whose content cannot be decrypted.
    pub damaged_attachments: usize,
    /// Items whose content here differs from what sync shows (and that wait for no local
    /// change): titles, for the user.
    pub differing: Vec<String>,
    /// Sync has them, this vault does not.
    pub missing: usize,
}

fn alarm_id(alarm: &Alarm) -> String {
    let digest = Sha256::digest(format!("{alarm:?}").as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..8])
}

impl<T: Transport> Synced<T> {
    /// A device's name as the account knows it, or the start of its id.
    pub fn device_label(&self, device: &DeviceId) -> String {
        let trust = self.engine.trust();
        if *device == self.engine.device() {
            return "This Mac".to_owned();
        }
        trust
            .device(device)
            .map(|d| d.name.clone())
            .or_else(|| trust.unapproved().get(device).map(|d| d.name.clone()))
            .unwrap_or_else(|| format!("device {}", data_encoding::HEXLOWER.encode(&device[..4])))
    }

    pub fn alarm_views(&self) -> Vec<AlarmView> {
        let main = self.engine.is_root();
        let me = self.engine.device();
        self.engine
            .alarms()
            .iter()
            .map(|alarm| {
                let (kind, title, explanation, actions): (_, String, String, Vec<&'static str>) =
                    match alarm {
                        Alarm::Rollback { stream, .. } if *stream == me => (
                            "rollback",
                            "This Mac's changes are missing from the sync folder".into(),
                            "The folder holds fewer of this Mac's changes than it wrote: an \
                             old copy of the folder was restored, or files were deleted. \
                             Restore puts them back from this Mac."
                                .into(),
                            vec!["restore", "accept"],
                        ),
                        Alarm::Rollback { stream, .. } => (
                            "rollback",
                            format!(
                                "Changes of {} went missing from the sync folder",
                                self.device_label(stream)
                            ),
                            "The folder holds fewer of that device's changes than this Mac \
                             already has: an old copy of the folder was restored, or files \
                             were deleted. Its newer changes are paused here."
                                .into(),
                            if main {
                                vec!["restore", "accept"]
                            } else {
                                vec!["accept"]
                            },
                        ),
                        Alarm::Fork { stream, .. } => (
                            "fork",
                            format!("Two different histories of {}", self.device_label(stream)),
                            "The folder shows that device's changes in two versions: a copy of \
                             that Mac (a restored backup) wrote too, or the files were tampered \
                             with. Its changes are paused here. If you do not recognise this, \
                             remove the device on your main Mac."
                                .into(),
                            if main && *stream != me {
                                vec!["remove", "accept"]
                            } else {
                                vec!["accept"]
                            },
                        ),
                        Alarm::OwnStreamTampered { .. } => (
                            "ownStreamTampered",
                            "Something occupies this Mac's place in the sync folder".into(),
                            "A file that is not this Mac's sits where its next changes go. \
                             Remove it from the folder and try again, or let this Mac continue \
                             under a new identity (the main Mac approves it again)."
                                .into(),
                            vec!["accept", "leave"],
                        ),
                        Alarm::Disputed { stream, by, .. } => (
                            "disputed",
                            format!(
                                "{} reports another history of {}",
                                self.device_label(by),
                                self.device_label(stream)
                            ),
                            "One of the two is wrong or tampered with. Nothing is paused; if it \
                             repeats, remove the device you do not trust."
                                .into(),
                            vec!["accept"],
                        ),
                        Alarm::RootBehind { .. } => (
                            "rootBehind",
                            "Not all of the main Mac's changes are here yet".into(),
                            "Until they are, changes of other devices count as unconfirmed. \
                             This clears by itself once the folder catches up."
                                .into(),
                            vec![],
                        ),
                        Alarm::ForeignHeader { .. } => (
                            "foreignHeader",
                            "An account file names another main Mac".into(),
                            "Someone with your master password and Secret Key wrote it. Devices \
                             that join with the Emergency Kit alone could trust it. Consider \
                             starting a new account from your main Mac."
                                .into(),
                            vec!["accept"],
                        ),
                        Alarm::ApprovedWithAnotherKey => (
                            "approvedWithAnotherKey",
                            "The main Mac approved this Mac with another key".into(),
                            "This Mac's request to join was replaced on the way. It writes \
                             nothing. Join again and compare the code carefully."
                                .into(),
                            vec!["leave"],
                        ),
                        Alarm::Unapproved { count } => (
                            "unapproved",
                            format!("{count} device(s) wait for the main Mac's approval"),
                            "They joined with the Emergency Kit. Their changes count for nobody \
                             until the main Mac approves them."
                                .into(),
                            vec![],
                        ),
                    };
                AlarmView {
                    id: alarm_id(alarm),
                    kind,
                    title,
                    explanation,
                    actions,
                }
            })
            .collect()
    }

    /// Does `action` for the alarm named `id`.
    pub fn alarm_action(&mut self, id: &str, action: &str, wall_ms: u64) -> Result<()> {
        let alarm = self
            .engine
            .alarms()
            .into_iter()
            .find(|a| alarm_id(a) == id)
            .ok_or_else(|| Error::NotFound("that alarm is gone".into()))?;
        let offered = self
            .alarm_views()
            .into_iter()
            .find(|v| v.id == id)
            .is_some_and(|v| v.actions.contains(&action));
        if !offered {
            return Err(Error::Refused(format!(
                "{action} is not offered for this alarm"
            )));
        }
        match (action, &alarm) {
            ("accept", _) => {
                self.engine.accept_alarm(&alarm);
                Ok(())
            }
            ("restore", Alarm::Rollback { stream, .. }) => {
                self.engine.restore(&self.transport, *stream, wall_ms)
            }
            ("remove", Alarm::Fork { stream, .. }) => self.engine.revoke(*stream, wall_ms),
            ("leave", _) => self.engine.leave_id(wall_ms),
            _ => Err(Error::Refused(format!("{action} does not fit this alarm"))),
        }
    }

    /// The main Mac removes a device (it can no longer read what is written from now on;
    /// what it had stays with it).
    pub fn remove_device(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        self.engine.revoke(device, wall_ms)
    }

    /// Whether other devices' changes are confirmed by the main Mac's newest decisions.
    pub fn root_confirmed(&self) -> bool {
        self.engine.root_confirmed()
    }

    /// The files of the account as the store holds them.
    pub fn inventory(&self) -> Result<Vec<InventoryEntry>> {
        self.transport.inventory()
    }

    /// Checks the local copy: everything decrypts, and every live item matches what sync
    /// shows (records with local changes waiting are left out).
    pub fn verify(&self, store: &Store) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        let pending: std::collections::BTreeSet<uuid::Uuid> =
            store.pending_changes()?.into_iter().map(|c| c.id).collect();
        let mut entries = store.list_items(None)?;
        entries.extend(store.deleted_items()?);
        for entry in &entries {
            report.items += 1;
            if matches!(entry, ItemEntry::Damaged { .. }) {
                report.damaged += 1;
            }
        }
        for id in store.attachment_ids()? {
            report.attachments += 1;
            if store.attachment_content(id).is_err() {
                report.damaged_attachments += 1;
            }
        }
        let view = self.engine.view();
        for (id, v) in &view.items {
            if pending.contains(id) || v.state != ItemState::Live {
                continue;
            }
            let (Some(p), Some(vault)) = (&v.payload, v.vault_id) else {
                continue;
            };
            let Ok(mut synced) = serde_json::from_slice::<Item>(&p.item_json) else {
                continue;
            };
            synced.id = *id;
            synced.vault_id = vault;
            match store.item_state(*id)? {
                Some((local, None)) if local == synced => {}
                Some((local, _)) => report.differing.push(local.title),
                None => report.missing += 1,
            }
        }
        Ok(report)
    }

    /// A line for the Sync log, for the events worth a line.
    pub fn describe(&self, event: &Event) -> Option<String> {
        Some(match event {
            Event::Pulled { from, versions } => format!(
                "Received {versions} change(s) from {}",
                self.device_label(from)
            ),
            Event::Pushed { versions } => format!("Sent {versions} change(s)"),
            Event::PushFailed(e) => format!("Sending failed: {e}"),
            Event::Unreadable { from, .. } => format!(
                "A file of {} could not be read yet; trying again",
                self.device_label(from)
            ),
            Event::Rejected { from, reason, .. } => format!(
                "Changes of {} were refused: {reason}",
                self.device_label(from)
            ),
            Event::Alarm(a) => format!("Alarm: {a}"),
            Event::Resolved { copies, .. } => format!("Made {copies} conflict copy(ies)"),
            Event::Retired { reason, .. } => format!(
                "This Mac continues under a new identity ({}); the main Mac approves it again",
                match reason {
                    RetireReason::OtherCopyWrote => "another copy of it wrote",
                    RetireReason::KeyMissing => "its device key is gone",
                }
            ),
            Event::RootMustStartOver { .. } => {
                "The main Mac's identity was copied or lost: start a new account from it".into()
            }
            Event::HeaderAdopted { epoch } => {
                format!("The master password was changed on the main Mac (epoch {epoch})")
            }
            Event::RootSilent { .. } => "The main Mac has not synced for a week".into(),
            Event::OwnStreamCleaned { seq } => {
                format!("Removed a stray file at this Mac's position {seq}")
            }
            Event::OutboxNotSaved(e) => format!("Could not save what is waiting to be sent: {e}"),
            Event::RollbackRepaired { stream } => format!(
                "Changes of {} missing from the folder are covered by a snapshot",
                self.device_label(stream)
            ),
            Event::Removed => "This Mac was removed from the account".into(),
            _ => return None,
        })
    }
}
```

Apply:

```diff
diff --git a/crates/keyorra-session/src/sync/mod.rs b/crates/keyorra-session/src/sync/mod.rs
index 0ce50af..a3e92b9 100644
--- a/crates/keyorra-session/src/sync/mod.rs
+++ b/crates/keyorra-session/src/sync/mod.rs
@@ -18,6 +18,7 @@
 mod enclave_keys;
 mod keys;
 mod merge;
+mod screen;
 mod setup;
 #[cfg(test)]
 mod tests;
@@ -46,6 +47,7 @@ use zeroize::Zeroizing;
 pub use enclave_keys::{Enclave, EnclaveDeviceKeys, EnclaveError};
 pub use keys::{DeviceKeyStore, MemoryDeviceKeys};
 pub use merge::{carry_over, disable, rejoin, start_new_account, CarryReport, Rejoined};
+pub use screen::{AlarmView, VerifyReport};
 pub use setup::SetupCode;
 
 const CONFIG: &str = "sync:config";
@@ -94,6 +96,9 @@ pub struct SyncStatus {
     pub key_code: String,
     pub devices: Vec<SyncDevice>,
     pub alarms: usize,
+    /// Other devices' changes are confirmed by the main Mac's newest decisions (false while
+    /// its newest changes are not all here).
+    pub root_confirmed: bool,
 }
 
 #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
@@ -104,6 +109,8 @@ pub struct SyncDevice {
     pub approved: bool,
     pub main: bool,
     pub this_device: bool,
+    /// Removed by the main Mac.
+    pub removed: bool,
 }
 
 /// What the user writes down when sync is enabled (spec §7.6). The location is the
@@ -1155,6 +1162,7 @@ impl<T: Transport> Synced<T> {
                 approved: true,
                 main: *id == trust.root(),
                 this_device: *id == self.engine.device(),
+                removed: d.cut.is_some(),
             })
             .collect();
         devices.extend(trust.unapproved().iter().map(|(id, d)| SyncDevice {
@@ -1163,6 +1171,7 @@ impl<T: Transport> Synced<T> {
             approved: false,
             main: false,
             this_device: *id == self.engine.device(),
+            removed: false,
         }));
         SyncStatus {
             main_device: self.engine.is_root(),
@@ -1170,6 +1179,7 @@ impl<T: Transport> Synced<T> {
             key_code: self.engine.key_fingerprint(),
             devices,
             alarms: self.engine.alarms().len(),
+            root_confirmed: self.engine.root_confirmed(),
         }
     }
 
```

- [ ] **Step 3: The screen's commands.**

Create `crates/keyorra-session/src/session/sync_screen.rs`:

```rust
//! The Sync screen's commands (plan A3): everything it shows in one call, and what it does
//! (alarm actions, removing a device, checking the local copy, the files in the folder, the
//! backup copies of the database).

use serde::Serialize;

use super::sync::{sync_error, LogLine};
use super::{locked, sibling, Session, DB_SIBLINGS};
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::sync::{self as s, AlarmView, SyncStatus, VerifyReport};

/// The Sync screen in one call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncScreenDto {
    pub enabled: bool,
    /// On and running this unlock.
    pub running: bool,
    pub error: Option<String>,
    /// Where the account lives (a folder path).
    pub location: Option<String>,
    pub last_round_at: Option<u64>,
    pub last_round_ok: Option<bool>,
    pub status: Option<SyncStatus>,
    pub alarms: Vec<AlarmView>,
    pub notices: Vec<String>,
    pub log: Vec<LogLine>,
}

/// A copy of the database kept next to it: before a migration (`.bak-v1`) or the vault a
/// join replaced (`.pre-sync-YYYYMMDD`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupFile {
    pub name: String,
    pub size: u64,
    /// Unix seconds.
    pub modified: u64,
    /// "migration" or "preSync".
    pub kind: &'static str,
}

/// One file of the account as the folder holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderFile {
    pub path: String,
    pub size: u64,
    pub counted: bool,
}

fn not_synced() -> CmdError {
    CmdError::new(ErrorKind::Invalid, "Sync is not running")
}

fn wall_ms(now: u64) -> u64 {
    now.saturating_mul(1000)
}

impl Session {
    pub fn sync_screen(&self) -> CmdResult<SyncScreenDto> {
        let store = self.store()?;
        let enabled = s::is_enabled(store).map_err(sync_error)?;
        let location = if enabled {
            s::account_id(store)
                .ok()
                .and_then(|a| self.sync_link.as_ref().and_then(|l| l.location(&a)))
        } else {
            None
        };
        Ok(SyncScreenDto {
            enabled,
            running: self.synced.is_some(),
            error: self.sync_error.clone(),
            location,
            last_round_at: self.last_round.map(|(at, _)| at),
            last_round_ok: self.last_round.map(|(_, ok)| ok),
            status: self.synced.as_ref().map(|x| x.status()),
            alarms: self
                .synced
                .as_ref()
                .map(|x| x.alarm_views())
                .unwrap_or_default(),
            notices: self.sync_notices.clone(),
            log: self.sync_log.iter().cloned().collect(),
        })
    }

    /// Accept, restore, remove or leave, as the alarm offers.
    pub fn sync_alarm_action(&mut self, id: &str, action: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        let synced = self.synced.as_mut().ok_or_else(not_synced)?;
        synced
            .alarm_action(id, action, wall_ms(now))
            .map_err(sync_error)
    }

    /// The main Mac removes a device.
    pub fn remove_sync_device(&mut self, id: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        let device: [u8; 16] = data_encoding::HEXLOWER
            .decode(id.as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Unknown device"))?;
        let synced = self.synced.as_mut().ok_or_else(not_synced)?;
        synced
            .remove_device(device, wall_ms(now))
            .map_err(sync_error)
    }

    /// "Verify everything": the local copy decrypts and matches what sync shows.
    pub fn verify_sync(&self) -> CmdResult<VerifyReport> {
        let store = self.store()?;
        let synced = self.synced.as_ref().ok_or_else(not_synced)?;
        synced.verify(store).map_err(sync_error)
    }

    /// "What the folder sees": names and sizes only.
    pub fn sync_folder_files(&self) -> CmdResult<Vec<FolderFile>> {
        self.store()?;
        let synced = self.synced.as_ref().ok_or_else(not_synced)?;
        Ok(synced
            .inventory()
            .map_err(sync_error)?
            .into_iter()
            .map(|e| FolderFile {
                path: e.path,
                size: e.size,
                counted: e.counted,
            })
            .collect())
    }

    /// The backup copies of the database next to it.
    pub fn backups(&self) -> CmdResult<Vec<BackupFile>> {
        self.store()?;
        let Some(dir) = self.path.parent() else {
            return Ok(Vec::new());
        };
        let Some(base) = self.path.file_name().and_then(|n| n.to_str()) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(out);
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(rest) = name.strip_prefix(base) else {
                continue;
            };
            if DB_SIBLINGS.iter().any(|s| rest.ends_with(s)) {
                continue;
            }
            let kind = if rest.starts_with(".bak-v") {
                "migration"
            } else if rest.starts_with(".pre-sync-") {
                "preSync"
            } else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            out.push(BackupFile {
                size: meta.len(),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs()),
                name,
                kind,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes one backup copy (with SQLite's companions); only a name `backups` lists.
    pub fn delete_backup(&mut self, name: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        if !self.backups()?.iter().any(|b| b.name == name) {
            return Err(CmdError::new(ErrorKind::NotFound, "No such backup"));
        }
        let dir = self.path.parent().ok_or_else(locked)?;
        let path = dir.join(name);
        std::fs::remove_file(&path)
            .map_err(|e| CmdError::new(ErrorKind::Other, format!("Can't delete it: {e}")))?;
        for suffix in DB_SIBLINGS {
            let _ = std::fs::remove_file(sibling(&path, suffix));
        }
        Ok(())
    }
}
```

Apply (the log and last round, `JoinOutcome`, `SyncLink::location`):

```diff
diff --git a/crates/keyorra-session/src/session/mod.rs b/crates/keyorra-session/src/session/mod.rs
index 2d17ae5..10f26ae 100644
--- a/crates/keyorra-session/src/session/mod.rs
+++ b/crates/keyorra-session/src/session/mod.rs
@@ -26,6 +26,7 @@ mod bridge_tests;
 #[cfg(test)]
 mod polish_tests;
 mod sync;
+mod sync_screen;
 #[cfg(test)]
 mod sync_tests;
 #[cfg(test)]
@@ -95,9 +96,14 @@ pub struct Session {
     sync_error: Option<String>,
     /// What the last round undid or could not show.
     sync_notices: Vec<String>,
+    /// The Sync log of this unlock (newest last, at most `SYNC_LOG_LINES`).
+    sync_log: std::collections::VecDeque<sync::LogLine>,
+    /// When the last round ran and whether it went through.
+    last_round: Option<(u64, bool)>,
 }
 
-pub use sync::{BoxedTransport, EmergencyKitDto, SyncLink, SyncStatusDto};
+pub use sync::{BoxedTransport, EmergencyKitDto, JoinOutcome, LogLine, SyncLink, SyncStatusDto};
+pub use sync_screen::{BackupFile, SyncScreenDto};
 
 impl Session {
     /// `kdf` is `KdfParams::DEFAULT` in the app; tests pass cheap parameters.
@@ -132,6 +138,8 @@ impl Session {
             synced: None,
             sync_error: None,
             sync_notices: Vec::new(),
+            sync_log: std::collections::VecDeque::new(),
+            last_round: None,
         }
     }
 
@@ -352,6 +360,8 @@ impl Session {
         // Sync runs only while unlocked; its state is in the store.
         self.synced = None;
         self.sync_notices.clear();
+        self.sync_log.clear();
+        self.last_round = None;
         self.store = None;
         self.breaches.clear();
         self.watchtower_count = None;
diff --git a/crates/keyorra-session/src/session/sync.rs b/crates/keyorra-session/src/session/sync.rs
index b0928b9..b848510 100644
--- a/crates/keyorra-session/src/session/sync.rs
+++ b/crates/keyorra-session/src/session/sync.rs
@@ -26,6 +26,11 @@ pub trait SyncLink: Send {
     fn new_account_transport(&self, account: &AccountId) -> Result<BoxedTransport, String> {
         self.transport(account)
     }
+    /// Where the account lives, for the Sync screen (a folder path).
+    fn location(&self, account: &AccountId) -> Option<String> {
+        let _ = account;
+        None
+    }
     /// Every account folder in the sync place, by folder name, opened read-only (nothing is
     /// created in them): joining picks the one named after the account whose header names
     /// the Secret Key.
@@ -54,6 +59,33 @@ pub struct EmergencyKitDto {
     pub setup_code: String,
 }
 
+/// One line of the Sync log.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
+#[serde(rename_all = "camelCase")]
+pub struct LogLine {
+    pub at: u64,
+    pub text: String,
+}
+
+/// The Sync log keeps this many lines (in memory, until the vault locks).
+pub const SYNC_LOG_LINES: usize = 200;
+
+/// How joining went.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
+#[serde(rename_all = "camelCase")]
+pub struct JoinOutcome {
+    /// "new": a vault was made for the account; "rejoined": this vault joined its account
+    /// again; "carriedOver": this vault's items were copied into a new vault for the account.
+    pub mode: &'static str,
+    /// Compare it on the main Mac before it approves this Mac.
+    pub key_code: String,
+    pub copied: usize,
+    /// Items in Recently Deleted that stayed in the old file.
+    pub trashed_left: usize,
+    /// Items that could not be read and stayed in the old file.
+    pub damaged: usize,
+}
+
 /// The sync part of the settings screen.
 #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
 #[serde(rename_all = "camelCase")]
@@ -67,7 +99,7 @@ pub struct SyncStatusDto {
     pub notices: Vec<String>,
 }
 
-fn sync_error(e: keyorra_sync::Error) -> CmdError {
+pub(super) fn sync_error(e: keyorra_sync::Error) -> CmdError {
     match e {
         keyorra_sync::Error::Core(core) => core.into(),
         keyorra_sync::Error::WrongPassword => CmdError::new(
@@ -263,11 +295,22 @@ impl Session {
         }
     }
 
-    /// Keeps what the UI shows about the last round.
-    fn note_round(&mut self, round: keyorra_sync::Result<s::RoundReport>) {
+    /// Keeps what the UI shows about the last round, and its lines for the Sync log.
+    fn note_round(&mut self, round: keyorra_sync::Result<s::RoundReport>, now: u64) {
+        let mut lines = Vec::new();
         match round {
             Ok(report) => {
                 self.sync_error = None;
+                self.last_round = Some((now, true));
+                if let Some(synced) = self.synced.as_ref() {
+                    lines.extend(report.events.iter().filter_map(|e| synced.describe(e)));
+                }
+                lines.extend(
+                    report
+                        .reverted
+                        .iter()
+                        .map(|(_, why)| format!("Undone: {why}")),
+                );
                 self.sync_notices = report
                     .reverted
                     .iter()
@@ -275,7 +318,18 @@ impl Session {
                     .chain(report.failed.iter().map(|(id, why)| format!("{id}: {why}")))
                     .collect();
             }
-            Err(e) => self.sync_error = Some(sync_error(e).message),
+            Err(e) => {
+                let message = sync_error(e).message;
+                lines.push(format!("Sync failed: {message}"));
+                self.last_round = Some((now, false));
+                self.sync_error = Some(message);
+            }
+        }
+        for text in lines {
+            if self.sync_log.len() == SYNC_LOG_LINES {
+                self.sync_log.pop_front();
+            }
+            self.sync_log.push_back(LogLine { at: now, text });
         }
     }
 
@@ -300,7 +354,7 @@ impl Session {
         let store = self.store.as_mut().ok_or_else(locked)?;
         if let Some(synced) = self.synced.as_mut() {
             let round = synced.round(store, wall_ms(now));
-            self.note_round(round);
+            self.note_round(round, now);
             self.watchtower_count = None;
         }
         self.sync_status()
@@ -342,7 +396,7 @@ impl Session {
             setup_code: synced.setup_code().to_text().to_string(),
         };
         self.synced = Some(synced);
-        self.note_round(first_round);
+        self.note_round(first_round, now);
         Ok(dto)
     }
 
@@ -407,7 +461,7 @@ impl Session {
     ///   merge by id.
     /// - It belongs to another account: a vault is made for the account and this vault's
     ///   items are carried over into it; the old file is kept aside.
-    pub fn join_sync(&mut self, password: &str, code: &str, now: u64) -> CmdResult<()> {
+    pub fn join_sync(&mut self, password: &str, code: &str, now: u64) -> CmdResult<JoinOutcome> {
         self.touch(now);
         let (sk_id, sk, pin) = match SetupCode::parse(code) {
             Ok(c) => (c.secret_key_id, c.secret_key, Some(c.pin)),
@@ -434,13 +488,20 @@ impl Session {
         (sk, sk_id): (&SecretKey, &str),
         pin: Option<keyorra_sync::account::RootPin>,
         now: u64,
-    ) -> CmdResult<()> {
+    ) -> CmdResult<JoinOutcome> {
         let (transport, mut keys, name) = (
             join_transport(link, password, (sk, sk_id), pin.as_ref())?,
             link.device_keys(),
             link.device_name(),
         );
         let unlock = |h: &Header| link.unlock_header(h, password, sk);
+        let outcome = |mode: &'static str, synced: &Synced<BoxedTransport>| JoinOutcome {
+            mode,
+            key_code: synced.key_code(),
+            copied: 0,
+            trashed_left: 0,
+            damaged: 0,
+        };
         match self.status() {
             Status::Locked => Err(locked()),
             Status::New => {
@@ -466,12 +527,13 @@ impl Session {
                     wall_ms(now),
                 )
                 .map_err(sync_error)?;
+                let joined = outcome("new", &synced);
                 self.store = Some(store);
                 self.synced = Some(synced);
-                self.note_round(first_round);
+                self.note_round(first_round, now);
                 self.password_verified_at = Some(now);
                 self.keyring.delete();
-                Ok(())
+                Ok(joined)
             }
             Status::Unlocked => {
                 let store = self.store.as_mut().ok_or_else(locked)?;
@@ -491,9 +553,10 @@ impl Session {
                 );
                 match result {
                     Ok(rejoined) => {
+                        let joined = outcome("rejoined", &rejoined.synced);
                         self.synced = Some(rejoined.synced);
-                        self.note_round(rejoined.first_round);
-                        Ok(())
+                        self.note_round(rejoined.first_round, now);
+                        Ok(joined)
                     }
                     Err(keyorra_sync::Error::AnotherAccount) => {
                         self.join_carrying_over(link, password, (sk, sk_id), pin, now)
@@ -511,7 +574,7 @@ impl Session {
         (sk, sk_id): (&SecretKey, &str),
         pin: Option<keyorra_sync::account::RootPin>,
         now: u64,
-    ) -> CmdResult<()> {
+    ) -> CmdResult<JoinOutcome> {
         let (transport, mut keys, name) = (
             join_transport(link, password, (sk, sk_id), pin.as_ref())?,
             link.device_keys(),
@@ -537,6 +600,7 @@ impl Session {
             wall_ms(now),
         )
         .map_err(sync_error)?;
+        let key_code = synced.key_code();
         let old = self.store.take().ok_or_else(locked)?;
         let carried = s::carry_over(&old, &mut new_store);
         drop(new_store);
@@ -593,7 +657,13 @@ impl Session {
             Ok(synced) => self.synced = Some(synced),
             Err(e) => self.sync_error = Some(e.message),
         }
-        Ok(())
+        Ok(JoinOutcome {
+            mode: "carriedOver",
+            key_code,
+            copied: report.copied,
+            trashed_left: report.trashed_left,
+            damaged: report.damaged,
+        })
     }
 
     /// Turns sync off on this Mac; everything stays in the vault.
@@ -679,7 +749,7 @@ impl Session {
             setup_code: synced.setup_code().to_text().to_string(),
         };
         self.synced = Some(synced);
-        self.note_round(first_round);
+        self.note_round(first_round, now);
         Ok(dto)
     }
 
```

- [ ] **Step 4: Run and commit.**

`cargo test -p keyorra-session` green. Commit: `Session A3-1: the Sync screen (alarms and actions, devices, verify, folder files, backups, log)`.

---

### Task 3: Commands, the sync folder choice, the concealed clipboard

**Files:** Modify `app/src-tauri/src/syncfolder.rs`, `commands.rs`, `lib.rs`, `app/src-tauri/swift/SyncFolder.swift`, `crates/keyorra-session/src/session/mod.rs`.

- [ ] **Step 1: Failing tests.**

In `syncfolder.rs` (in the patch below): `places_are_described_by_where_they_are`, `the_chosen_place_is_kept` (temp folders only).

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/app/src-tauri/src/syncfolder.rs b/app/src-tauri/src/syncfolder.rs
index 05532a9..7198402 100644
--- a/app/src-tauri/src/syncfolder.rs
+++ b/app/src-tauri/src/syncfolder.rs
@@ -36,6 +36,7 @@ mod ffi {
             -> *mut c_void;
         pub fn ks_watch_stop(handle: *mut c_void);
         pub fn ks_computer_name(out: *mut u8, cap: usize) -> usize;
+        pub fn ks_pasteboard_set_concealed(text: *const c_char) -> i32;
     }
 }
 
@@ -65,6 +66,9 @@ mod ffi {
     pub unsafe fn ks_computer_name(_: *mut u8, _: usize) -> usize {
         0
     }
+    pub unsafe fn ks_pasteboard_set_concealed(_: *const c_char) -> i32 {
+        6
+    }
 }
 
 fn c_path(path: &Path) -> Option<CString> {
@@ -156,6 +160,130 @@ pub fn icloud_place() -> Option<PathBuf> {
     drive.is_dir().then(|| drive.join("Keyorra"))
 }
 
+/// Where accounts live and what the Sync screen says about it.
+#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
+#[serde(rename_all = "camelCase")]
+pub struct PlaceInfo {
+    /// `<chosen folder>/Keyorra`.
+    pub path: String,
+    /// "icloud", "cloudStorage" (Dropbox, OneDrive, Google Drive), "network" or "local".
+    pub kind: &'static str,
+    /// What to keep in mind with this kind of folder.
+    pub warning: Option<String>,
+}
+
+/// What kind of place `path` is (by where it is; nothing is read).
+pub fn describe_place(path: &Path) -> PlaceInfo {
+    let text = path.to_string_lossy().into_owned();
+    let (kind, warning) = if text.contains("/Library/Mobile Documents/com~apple~CloudDocs") {
+        ("icloud", None)
+    } else if text.contains("/Library/CloudStorage/") {
+        (
+            "cloudStorage",
+            Some(
+                "Set this folder to stay downloaded (\"Available offline\" or \"Make available \
+                 offline\") so Keyorra does not wait for files."
+                    .to_owned(),
+            ),
+        )
+    } else if text.starts_with("/Volumes/") {
+        (
+            "network",
+            Some(
+                "A network or external drive: sync works only while it is connected. Other \
+                 devices must reach the same folder."
+                    .to_owned(),
+            ),
+        )
+    } else {
+        (
+            "local",
+            Some(
+                "This folder is on this Mac only. Other devices see it only if a sync app \
+                 keeps it in step."
+                    .to_owned(),
+            ),
+        )
+    };
+    PlaceInfo {
+        path: text,
+        kind,
+        warning,
+    }
+}
+
+/// Where accounts live (`<chosen folder>/Keyorra`): iCloud Drive unless the user chose
+/// another folder, which is kept in `sync-place` next to the vault.
+pub struct SyncPlace {
+    file: PathBuf,
+    temp: PathBuf,
+    current: std::sync::Mutex<Option<PathBuf>>,
+}
+
+impl SyncPlace {
+    pub fn load(app_data: &Path) -> SyncPlace {
+        let file = app_data.join("sync-place");
+        let chosen = std::fs::read_to_string(&file)
+            .ok()
+            .map(|t| PathBuf::from(t.trim()))
+            .filter(|p| p.is_absolute());
+        SyncPlace {
+            file,
+            temp: app_data.join("sync-tmp"),
+            current: std::sync::Mutex::new(chosen.or_else(icloud_place)),
+        }
+    }
+
+    pub fn current(&self) -> Option<PathBuf> {
+        self.current.lock().unwrap().clone()
+    }
+
+    /// Chooses the folder accounts go in (`None`: iCloud Drive). The folder must exist.
+    pub fn set(&self, chosen: Option<&Path>) -> Result<PathBuf, String> {
+        let place = match chosen {
+            None => {
+                let _ = std::fs::remove_file(&self.file);
+                icloud_place().ok_or("iCloud Drive is not set up on this Mac")?
+            }
+            Some(dir) => {
+                let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
+                if !meta.is_dir() {
+                    return Err(format!("{} is not a folder", dir.display()));
+                }
+                let place = dir.join("Keyorra");
+                std::fs::write(&self.file, place.to_string_lossy().as_bytes())
+                    .map_err(|e| e.to_string())?;
+                place
+            }
+        };
+        *self.current.lock().unwrap() = Some(place.clone());
+        Ok(place)
+    }
+
+    /// The session's link to the current place.
+    pub fn link(&self) -> Option<FolderLink> {
+        let place = self.current()?;
+        Some(FolderLink::new(
+            place,
+            self.temp.clone(),
+            Arc::new(MacCloud),
+            Box::new(|| Box::new(crate::touchid::device_keys())),
+            computer_name(),
+        ))
+    }
+}
+
+/// Puts a secret on the clipboard marked concealed and transient (clipboard managers skip
+/// it, spec §7.6).
+pub fn copy_concealed(text: &str) -> Result<(), String> {
+    let c = CString::new(text).map_err(|_| "NUL in text".to_owned())?;
+    // SAFETY: a live C string.
+    match unsafe { ffi::ks_pasteboard_set_concealed(c.as_ptr()) } {
+        0 => Ok(()),
+        _ => Err("the clipboard did not take it".into()),
+    }
+}
+
 /// This Mac's name for the other devices.
 pub fn computer_name() -> String {
     let mut buf = [0u8; 256];
@@ -414,6 +542,37 @@ mod tests {
         assert_eq!(MacCloud.state(&dir.path().join("none")), FileState::Missing);
     }
 
+    #[test]
+    fn places_are_described_by_where_they_are() {
+        let icloud = describe_place(Path::new(
+            "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Keyorra",
+        ));
+        assert_eq!((icloud.kind, icloud.warning.is_none()), ("icloud", true));
+        let dropbox = describe_place(Path::new("/Users/a/Library/CloudStorage/Dropbox/Keyorra"));
+        assert_eq!(dropbox.kind, "cloudStorage");
+        assert!(dropbox.warning.unwrap().contains("offline"));
+        assert_eq!(
+            describe_place(Path::new("/Volumes/nas/Keyorra")).kind,
+            "network"
+        );
+        assert_eq!(
+            describe_place(Path::new("/Users/a/Sync/Keyorra")).kind,
+            "local"
+        );
+    }
+
+    #[test]
+    fn the_chosen_place_is_kept() {
+        let data = tempfile::tempdir().unwrap();
+        let chosen = tempfile::tempdir().unwrap();
+        let places = SyncPlace::load(data.path());
+        let place = places.set(Some(chosen.path())).unwrap();
+        assert_eq!(place, chosen.path().join("Keyorra"));
+        assert!(places.set(Some(&chosen.path().join("missing"))).is_err());
+        let again = SyncPlace::load(data.path());
+        assert_eq!(again.current(), Some(chosen.path().join("Keyorra")));
+    }
+
     #[test]
     fn a_panic_in_a_coordinated_access_is_an_error() {
         let dir = tempfile::tempdir().unwrap();
diff --git a/app/src-tauri/swift/SyncFolder.swift b/app/src-tauri/swift/SyncFolder.swift
index b766a8d..092ec25 100644
--- a/app/src-tauri/swift/SyncFolder.swift
+++ b/app/src-tauri/swift/SyncFolder.swift
@@ -2,6 +2,7 @@
 // file coordination with the sync client, and change notifications. Called from Rust
 // (src/syncfolder.rs) through C. Nothing here touches the keychain.
 
+import AppKit
 import CoreServices
 import Foundation
 import SystemConfiguration
@@ -136,3 +137,16 @@ public func ks_computer_name(_ out: UnsafeMutablePointer<UInt8>, _ cap: Int) ->
     }
     return bytes.count
 }
+
+/// Puts `text` on the general pasteboard marked concealed and transient, so clipboard
+/// managers skip it (nspasteboard.org markers).
+@_cdecl("ks_pasteboard_set_concealed")
+public func ks_pasteboard_set_concealed(_ text: UnsafePointer<CChar>) -> Int32 {
+    let pasteboard = NSPasteboard.general
+    pasteboard.clearContents()
+    let item = NSPasteboardItem()
+    item.setString(String(cString: text), forType: .string)
+    item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
+    item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
+    return pasteboard.writeObjects([item]) ? SF_READY : SF_FAILED
+}
diff --git a/crates/keyorra-session/src/session/mod.rs b/crates/keyorra-session/src/session/mod.rs
index 10f26ae..e6fb639 100644
--- a/crates/keyorra-session/src/session/mod.rs
+++ b/crates/keyorra-session/src/session/mod.rs
@@ -103,7 +103,7 @@ pub struct Session {
 }
 
 pub use sync::{BoxedTransport, EmergencyKitDto, JoinOutcome, LogLine, SyncLink, SyncStatusDto};
-pub use sync_screen::{BackupFile, SyncScreenDto};
+pub use sync_screen::{BackupFile, FolderFile, SyncScreenDto};
 
 impl Session {
     /// `kdf` is `KdfParams::DEFAULT` in the app; tests pass cheap parameters.
@@ -451,6 +451,14 @@ impl Session {
         }
     }
 
+    /// A secret the app just put on the clipboard (the setup code): cleared after 90 s at
+    /// most, like other secrets (spec §7.6).
+    pub fn copied_secret(&mut self, text: &str, now: u64) {
+        self.touch(now);
+        self.clipboard
+            .copied(text, now, self.settings.clipboard_seconds.min(90));
+    }
+
     pub fn clipboard_pending(&self) -> bool {
         self.clipboard.is_pending()
     }
```

```diff
diff --git a/app/src-tauri/src/commands.rs b/app/src-tauri/src/commands.rs
index ad8563a..59c3915 100644
--- a/app/src-tauri/src/commands.rs
+++ b/app/src-tauri/src/commands.rs
@@ -336,3 +336,138 @@ pub fn unlock_with_touch_id(app: AppHandle, state: State<'_, AppState>) -> CmdRe
     let _ = app.emit("unlocked", ());
     Ok(())
 }
+
+// ---- sync (plan A3) ----
+
+use crate::syncfolder::{describe_place, PlaceInfo, SyncPlace};
+use keyorra_session::session::{BackupFile, EmergencyKitDto, JoinOutcome, SyncScreenDto};
+use keyorra_session::sync::VerifyReport;
+use std::sync::Arc;
+
+#[tauri::command(async)]
+pub fn sync_screen(state: State<'_, AppState>) -> CmdResult<SyncScreenDto> {
+    lock_session(&state).sync_screen()
+}
+
+#[tauri::command(async)]
+pub fn sync_now(app: AppHandle, state: State<'_, AppState>) -> CmdResult<SyncScreenDto> {
+    let mut session = lock_session(&state);
+    session.sync_now(now())?;
+    let screen = session.sync_screen();
+    drop(session);
+    let _ = app.emit("synced", ());
+    screen
+}
+
+#[tauri::command(async)]
+pub fn enable_sync(state: State<'_, AppState>, password: String) -> CmdResult<EmergencyKitDto> {
+    lock_session(&state).enable_sync(&password, now())
+}
+
+#[tauri::command(async)]
+pub fn join_sync(
+    app: AppHandle,
+    state: State<'_, AppState>,
+    password: String,
+    code: String,
+) -> CmdResult<JoinOutcome> {
+    let outcome = lock_session(&state).join_sync(&password, &code, now())?;
+    let _ = app.emit("synced", ());
+    Ok(outcome)
+}
+
+#[tauri::command(async)]
+pub fn disable_sync(state: State<'_, AppState>) -> CmdResult<()> {
+    lock_session(&state).disable_sync(now())
+}
+
+#[tauri::command(async)]
+pub fn approve_device(state: State<'_, AppState>, id: String, code: String) -> CmdResult<()> {
+    lock_session(&state).approve_device(&id, &code, now())
+}
+
+#[tauri::command(async)]
+pub fn sync_alarm_action(state: State<'_, AppState>, id: String, action: String) -> CmdResult<()> {
+    lock_session(&state).sync_alarm_action(&id, &action, now())
+}
+
+#[tauri::command(async)]
+pub fn remove_sync_device(state: State<'_, AppState>, id: String) -> CmdResult<()> {
+    lock_session(&state).remove_sync_device(&id, now())
+}
+
+#[tauri::command(async)]
+pub fn verify_sync(state: State<'_, AppState>) -> CmdResult<VerifyReport> {
+    lock_session(&state).verify_sync()
+}
+
+#[tauri::command(async)]
+pub fn sync_folder_files(
+    state: State<'_, AppState>,
+) -> CmdResult<Vec<keyorra_session::session::FolderFile>> {
+    lock_session(&state).sync_folder_files()
+}
+
+#[tauri::command(async)]
+pub fn emergency_kit(
+    state: State<'_, AppState>,
+    password: Option<String>,
+) -> CmdResult<EmergencyKitDto> {
+    lock_session(&state).emergency_kit(password.as_deref(), now())
+}
+
+#[tauri::command(async)]
+pub fn start_new_sync_account(
+    state: State<'_, AppState>,
+    password: String,
+) -> CmdResult<EmergencyKitDto> {
+    lock_session(&state).start_new_sync_account(&password, now())
+}
+
+#[tauri::command(async)]
+pub fn backups(state: State<'_, AppState>) -> CmdResult<Vec<BackupFile>> {
+    lock_session(&state).backups()
+}
+
+#[tauri::command(async)]
+pub fn delete_backup(state: State<'_, AppState>, name: String) -> CmdResult<()> {
+    lock_session(&state).delete_backup(&name, now())
+}
+
+#[tauri::command(async)]
+pub fn sync_place(places: State<'_, Arc<SyncPlace>>) -> Option<PlaceInfo> {
+    places.current().map(|p| describe_place(&p))
+}
+
+/// Chooses where accounts go (`None`: iCloud Drive); only while sync is off.
+#[tauri::command(async)]
+pub fn set_sync_place(
+    state: State<'_, AppState>,
+    places: State<'_, Arc<SyncPlace>>,
+    path: Option<String>,
+) -> CmdResult<PlaceInfo> {
+    let mut session = lock_session(&state);
+    if session.sync_status().is_ok_and(|s| s.enabled) {
+        return Err(CmdError::new(
+            ErrorKind::Invalid,
+            "Turn sync off before choosing another folder",
+        ));
+    }
+    let place = places
+        .set(path.as_deref().map(std::path::Path::new))
+        .map_err(|e| CmdError::new(ErrorKind::Invalid, e))?;
+    if let Some(link) = places.link() {
+        session.set_sync_link(Box::new(link));
+    }
+    Ok(describe_place(&place))
+}
+
+/// A secret (the setup code) on the clipboard, concealed from clipboard managers and
+/// cleared after 90 seconds at most.
+#[tauri::command(async)]
+pub fn copy_secret(state: State<'_, AppState>, text: String) -> CmdResult<()> {
+    let mut session = lock_session(&state);
+    crate::syncfolder::copy_concealed(&text).map_err(|e| CmdError::new(ErrorKind::Other, e))?;
+    session.copied_secret(&text, now());
+    Ok(())
+}
diff --git a/app/src-tauri/src/lib.rs b/app/src-tauri/src/lib.rs
index 809549c..ba090aa 100644
--- a/app/src-tauri/src/lib.rs
+++ b/app/src-tauri/src/lib.rs
@@ -41,22 +41,16 @@ pub fn run() {
             let path = app.path().app_data_dir()?.join("keyorra.db");
             let mut session = Session::new(path, KdfParams::DEFAULT, now());
             session.set_keyring(Box::new(touchid::MacKeyring));
-            // Sync over iCloud Drive (plan A2; A3 lets the user pick another synced folder).
+            // Sync over iCloud Drive, or the folder the user chose (plan A3). Nothing is
+            // created there before sync is turned on; the watcher starts once the folder
+            // exists (housekeeping).
             let changed = Arc::new(AtomicBool::new(false));
-            let place = syncfolder::icloud_place();
-            if let Some(place) = place.clone() {
-                let temp = app.path().app_data_dir()?.join("sync-tmp");
-                // Nothing is created in iCloud Drive before sync is turned on; the watcher
-                // starts once the folder exists (housekeeping, review A2 M3).
-                session.set_sync_link(Box::new(syncfolder::FolderLink::new(
-                    place,
-                    temp,
-                    Arc::new(syncfolder::MacCloud),
-                    Box::new(|| Box::new(touchid::device_keys())),
-                    syncfolder::computer_name(),
-                )));
+            let places = Arc::new(syncfolder::SyncPlace::load(&app.path().app_data_dir()?));
+            if let Some(link) = places.link() {
+                session.set_sync_link(Box::new(link));
             }
             app.manage(AppState(Mutex::new(session)));
+            app.manage(places.clone());
             // After `manage`: both call commands that need the session. Neither is essential;
             // without them Keyorra still works from its main window.
             if let Err(e) = tray::install(app.handle()) {
@@ -66,7 +60,7 @@ pub fn run() {
                 eprintln!("keyorra: quick search unavailable: {e}");
             }
             let handle = app.handle().clone();
-            std::thread::spawn(move || housekeeping(handle, changed, place));
+            std::thread::spawn(move || housekeeping(handle, changed, places));
             if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                 let socket = keyorra_session::bridge::wire::socket_path(&home);
                 let bridge_app = app.handle().clone();
@@ -113,6 +107,23 @@ pub fn run() {
             commands::deny_pairing,
             commands::paired_browsers,
             commands::remove_paired_browser,
+            commands::sync_screen,
+            commands::sync_now,
+            commands::enable_sync,
+            commands::join_sync,
+            commands::disable_sync,
+            commands::approve_device,
+            commands::sync_alarm_action,
+            commands::remove_sync_device,
+            commands::verify_sync,
+            commands::sync_folder_files,
+            commands::emergency_kit,
+            commands::start_new_sync_account,
+            commands::backups,
+            commands::delete_backup,
+            commands::sync_place,
+            commands::set_sync_place,
+            commands::copy_secret,
         ])
         .on_window_event(|window, event| {
             // Closing the main window keeps Keyorra in the menu bar; Quit is in the tray menu.
@@ -138,19 +149,20 @@ pub fn run() {
 
 /// Every two seconds: lock when idle (and tell the window), clear the clipboard once our copy
 /// has expired — but only if it still holds our copy.
-fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, place: Option<std::path::PathBuf>) {
+fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, places: Arc<syncfolder::SyncPlace>) {
     // `Instant` does not advance while the Mac sleeps (CLOCK_UPTIME_RAW), unlike wall time.
     let start = Instant::now();
     let mut schedule = syncfolder::Schedule::new(changed.clone());
-    let mut watcher: Option<syncfolder::Watcher> = None;
+    let mut watcher: Option<(std::path::PathBuf, syncfolder::Watcher)> = None;
+    let mut approvals_shown = 0;
     loop {
         std::thread::sleep(Duration::from_secs(2));
         // Changes are watched as soon as the sync place exists (sync turned on here or on
-        // another Mac), not only from the next launch.
-        if watcher.is_none() {
-            if let Some(p) = place.as_ref().filter(|p| p.is_dir()) {
-                watcher = syncfolder::Watcher::start(p, changed.clone());
-            }
+        // another Mac), and the watch follows the place when the user picks another one.
+        let want = places.current().filter(|p| p.is_dir());
+        if watcher.as_ref().map(|(p, _)| p) != want.as_ref() {
+            watcher =
+                want.and_then(|p| syncfolder::Watcher::start(&p, changed.clone()).map(|w| (p, w)));
         }
         let state = app.state::<AppState>();
         // Read the flag before taking the lock. Sleep is detected from wall time vs the
@@ -170,11 +182,23 @@ fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, place: Option<std::pat
         }
         // Sync while unlocked: on a change in the folder, and every minute.
         let mut synced = false;
+        let mut approvals = None;
         if session.status() == keyorra_session::session::Status::Unlocked
             && session.sync_status().is_ok_and(|s| s.enabled)
             && schedule.due(t)
         {
-            synced = session.sync_now(t).is_ok();
+            if let Ok(status) = session.sync_now(t) {
+                synced = true;
+                // Devices that ask the main Mac to approve them: told once per change.
+                let waiting = status
+                    .status
+                    .filter(|s| s.main_device)
+                    .map_or(0, |s| s.devices.iter().filter(|d| !d.approved).count());
+                if waiting != approvals_shown {
+                    approvals_shown = waiting;
+                    approvals = Some(waiting);
+                }
+            }
         }
         drop(session);
         if locked {
@@ -183,5 +207,8 @@ fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, place: Option<std::pat
         if synced {
             let _ = app.emit("synced", ());
         }
+        if let Some(waiting) = approvals {
+            let _ = app.emit("sync-approval", waiting);
+        }
     }
 }
```

- [ ] **Step 3: Run and commit.**

`cargo clippy --workspace --all-targets -- -D warnings`; `cargo test -p keyorra-app` (12 passed, 3 ignored; do not run the ignored ones). Commit: `App A3-1: sync commands, the sync folder choice, concealed setup code`.

---

### Task 4: Spec

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Commit: `docs: A3-1 the Sync screen`.

---

### Task 5: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (687 passed, 4 ignored when verified); `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

