# Keyorra Sync A2-1 Implementation Plan (the folder transport)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync can run over a folder: iCloud Drive by default, or any folder a sync client keeps in step (Dropbox, OneDrive, Google Drive through File Provider, a NAS share). A new crate, `keyorra-sync-fs`, implements the engine's `Transport` over one account folder with the layout of spec §5.1: exact file names (a sync client's conflict copies and strangers are ignored), write-once files written in a temp directory outside the synced tree and renamed into place without ever replacing an existing name, files that are not on this Mac (placeholders, `SF_DATALESS`) never opened but reported `Pending` and asked for, empty (half-written) files `Pending`, and a time budget per sync round. The `Transport` trait gains attachment chunks and a round start. Two engines converge through a real temp folder, also with conflict copies and files that arrive late.

**Builds on:** `feat/sync-design` at `f295915` (A1d-1, A1d-2 and both data-safety reviews).

**Verified:** every task was applied in order in a scratch worktree from `f295915`; the workspace suite passes after every task (652 tests, 4 ignored at the end), clippy is clean, and the adversary and convergence property tests pass at 2000 cases in release.

**Architecture:** `keyorra-sync-fs` depends on `keyorra-sync` only (no app code): `names` (the exact names), `avail` (`Availability`: whether a file is on this Mac and how to ask for it; `LocalDisk` looks at `SF_DATALESS` only, the app's implementation comes in A2-2), `write` (temp directory choice and the write-then-rename), and `FolderTransport`. Plan A2-2 adds attachment contents, file coordination, per-account folders in the session and the macOS side.

**Tech Stack:** Rust; `libc` for `renamex_np(RENAME_EXCL)` (macOS) and `renameat2(RENAME_NOREPLACE)` (Linux).

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`:

1. **§5.3 Writing**, step 2: "`fsync`, then rename into the final name, `fsync` the directory. Write-once names (segments, snapshots, chunks) use a rename that fails if the name exists (`renamex_np(RENAME_EXCL)` on macOS): a name is never replaced, and a taken name is compared byte for byte (same: already there; different: conflict). Header files and `root.head` are replaced by a plain rename."
2. **§5.3**, new step 4: "An empty file is a write still in progress: `Pending`. `README-KEYORRA.txt` is written when the folder is created."
3. **§5.4**, add: "Every sync round has a time budget (30 s by default; the app uses 10 s): once it is spent, the remaining file operations fail as transport errors and the round goes on next time. A device learns a stream's head from the header of its newest segment file only; if that file is not on this Mac, the rollback check of that stream waits for a later round (`HeadUnknown`)."
4. **§12**, the A2 line becomes: "**A2-1** Folder transport: `keyorra-sync-fs` (layout, strict names, temp outside the synced tree, exclusive renames, download state, round budget), chunks in the transport trait | two engines converge through a temp folder with conflict copies and late files" and "**A2-2** Attachments and macOS: attachment contents as chunks, file coordination, per-account folders in the session, iCloud Drive link, FSEvents and polling | two vault stores sync an item with an attachment through a folder".

And to `docs/sync-protocol.md` §11 (folder transport): the exact names of §5.1 with "anything else is ignored", and that chunks are stored under `chunks/<first 2 hex>/<64 hex>`.

## Decisions

- **One crate per transport.** `keyorra-sync` stays free of I/O; the folder transport is `keyorra-sync-fs` (the server transport, B2, will be another crate).
- **Never replace a write-once name**, even within this device: the exclusive rename makes "someone else wrote this position" (a clone, a squatter) visible as a conflict, exactly as in memory.
- **Not on this Mac is `Pending`, never a blocking read.** The placeholder `.<name>.icloud` counts as the file; a download is requested and the next round tries again.
- **The head comes from the newest file's header** (101 bytes of it are needed, the file is read whole): no extra index file to keep in step.
- **Per-round time budget** instead of per-call timeouts: a hanging network share cannot hold a round (and the session) for long; reads of single files are not interrupted (they are only started for files that are on this Mac).
- **Not here:** attachment contents, file coordination, the app (A2-2).

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
crates/keyorra-sync/src/transport.rs     Transport::put_chunk, get_chunk, begin_round; MemoryTransport chunks
crates/keyorra-sync/src/faults.rs        the test transports pass them through
crates/keyorra-sync/src/engine.rs        sync() starts the transport's round
Cargo.toml                               + crates/keyorra-sync-fs
crates/keyorra-sync-fs/Cargo.toml        NEW
crates/keyorra-sync-fs/src/lib.rs        NEW FolderTransport
crates/keyorra-sync-fs/src/names.rs      NEW exact names
crates/keyorra-sync-fs/src/avail.rs      NEW Availability, FileState, LocalDisk
crates/keyorra-sync-fs/src/write.rs      NEW temp directory, write and exclusive rename
crates/keyorra-sync-fs/src/tests.rs      NEW
```

---

### Task 1: Chunks and the round start in the transport trait

**Files:** Modify `crates/keyorra-sync/src/transport.rs`, `crates/keyorra-sync/src/faults.rs`, `crates/keyorra-sync/src/engine.rs`.

- [ ] **Step 1: Failing test.**

`chunks_are_stored_under_their_hash` (in the patch below, `transport.rs` tests) fails to compile.

- [ ] **Step 2: Implement.**

Default methods keep other transports compiling; `MemoryTransport` keeps chunks, the wrappers and `Box<T>` pass them through, and `Engine::sync` starts the transport's round:

```diff
diff --git a/crates/keyorra-sync/src/engine.rs b/crates/keyorra-sync/src/engine.rs
index e0c79e8..92dc1f0 100644
--- a/crates/keyorra-sync/src/engine.rs
+++ b/crates/keyorra-sync/src/engine.rs
@@ -1354,6 +1354,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     /// returned afterwards. Alarms do not make a round fail: a rollback or fork pauses only
     /// its stream (the own stream: nothing is pushed), see [`Engine::alarms`].
     pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
+        transport.begin_round();
         if self.sent.seq > 0 && !self.keys.holds(&self.device) {
             self.retire(RetireReason::KeyMissing, wall_ms)?;
         }
diff --git a/crates/keyorra-sync/src/faults.rs b/crates/keyorra-sync/src/faults.rs
index 4fccd73..8ab8a0c 100644
--- a/crates/keyorra-sync/src/faults.rs
+++ b/crates/keyorra-sync/src/faults.rs
@@ -186,6 +186,18 @@ impl<T: Transport> Transport for Faulty<T> {
         self.inner.put_root_head_file(bytes)
     }
 
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_chunk(bytes)
+    }
+
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_chunk(name)
+    }
+
+    fn begin_round(&self) {
+        self.inner.begin_round()
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let f = self.faults();
         if self.roll(f.fail_before_append) {
@@ -279,6 +291,18 @@ impl<T: Transport> Transport for Rollback<T> {
     fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
         self.inner.put_root_head_file(bytes)
     }
+
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_chunk(bytes)
+    }
+
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_chunk(name)
+    }
+
+    fn begin_round(&self) {
+        self.inner.begin_round()
+    }
 }
 
 /// A store that shows one stream from another store: one side of a fork (two histories of
@@ -356,6 +380,18 @@ impl<T: Transport, U: Transport> Transport for Overlay<T, U> {
     fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
         self.base.put_root_head_file(bytes)
     }
+
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        self.base.put_chunk(bytes)
+    }
+
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.base.get_chunk(name)
+    }
+
+    fn begin_round(&self) {
+        self.base.begin_round()
+    }
 }
 
 #[cfg(test)]
diff --git a/crates/keyorra-sync/src/transport.rs b/crates/keyorra-sync/src/transport.rs
index 3345d29..9f155d5 100644
--- a/crates/keyorra-sync/src/transport.rs
+++ b/crates/keyorra-sync/src/transport.rs
@@ -54,6 +54,21 @@ pub trait Transport {
     /// The main device's advertised head file ([`crate::root_head`]).
     fn root_head_file(&self) -> Result<Fetched<Vec<u8>>>;
     fn put_root_head_file(&self, bytes: &[u8]) -> Result<()>;
+    /// Stores an attachment chunk under its name, the lowercase hex SHA-256 of the bytes
+    /// ([`crate::chunk::chunk_name`]), which it returns. Chunks are write-once: storing the
+    /// same bytes again is a no-op (plan A2).
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        let _ = bytes;
+        Err(crate::Error::Transport(
+            "this store keeps no attachment chunks".into(),
+        ))
+    }
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        let _ = name;
+        Ok(Fetched::Missing)
+    }
+    /// A sync round starts (a folder transport starts its time budget, plan A2).
+    fn begin_round(&self) {}
 }
 
 /// A boxed transport (the app picks the transport at run time).
@@ -100,6 +115,15 @@ impl<T: Transport + ?Sized> Transport for Box<T> {
     fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
         (**self).put_root_head_file(bytes)
     }
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        (**self).put_chunk(bytes)
+    }
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        (**self).get_chunk(name)
+    }
+    fn begin_round(&self) {
+        (**self).begin_round()
+    }
 }
 
 #[derive(Clone, Debug, Default)]
@@ -107,6 +131,7 @@ struct Files {
     headers: BTreeMap<String, Vec<u8>>,
     snapshots: BTreeMap<String, Vec<u8>>,
     root_head: Option<Vec<u8>>,
+    chunks: BTreeMap<String, Vec<u8>>,
 }
 
 /// One stream: segment bytes by first sequence number.
@@ -245,6 +270,25 @@ impl Transport for MemoryTransport {
         Ok(())
     }
 
+    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
+        let name = crate::chunk::chunk_name(bytes);
+        self.files
+            .lock()
+            .unwrap()
+            .chunks
+            .entry(name.clone())
+            .or_insert_with(|| bytes.to_vec());
+        Ok(name)
+    }
+
+    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        let files = self.files.lock().unwrap();
+        Ok(files
+            .chunks
+            .get(name)
+            .map_or(Fetched::Missing, |b| Fetched::Ready(b.clone())))
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let header = SegmentHeader::parse(segment)?;
         let mut streams = self.streams.lock().unwrap();
@@ -323,6 +367,28 @@ mod tests {
         assert!(t.append(b"junk").is_err());
     }
 
+    #[test]
+    fn chunks_are_stored_under_their_hash() {
+        let t = MemoryTransport::new();
+        let name = t.put_chunk(b"KYC1 chunk bytes").unwrap();
+        assert_eq!(name, crate::chunk::chunk_name(b"KYC1 chunk bytes"));
+        assert_eq!(
+            t.put_chunk(b"KYC1 chunk bytes").unwrap(),
+            name,
+            "write-once, same name"
+        );
+        assert_eq!(
+            t.get_chunk(&name).unwrap(),
+            Fetched::Ready(b"KYC1 chunk bytes".to_vec())
+        );
+        assert_eq!(t.get_chunk(&"0".repeat(64)).unwrap(), Fetched::Missing);
+        let boxed: Box<dyn Transport> = Box::new(t.clone());
+        assert_eq!(
+            boxed.get_chunk(&name).unwrap(),
+            Fetched::Ready(b"KYC1 chunk bytes".to_vec())
+        );
+    }
+
     #[test]
     fn headers_and_snapshots_are_stored_by_name() {
         let t = MemoryTransport::new();
```

- [ ] **Step 3: Run and commit.**

`cargo test -p keyorra-sync` green. Commit: `Sync A2-1: attachment chunks and the round start in the transport`.

---

### Task 2: The folder transport

**Files:** Create the files of `crates/keyorra-sync-fs/`; modify the workspace `Cargo.toml`.

- [ ] **Step 1: Workspace.**

Apply:

```diff
diff --git a/Cargo.toml b/Cargo.toml
index 2e16fad..9c5df4d 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,6 +1,17 @@
 [workspace]
-members = ["crates/keyorra-core", "crates/keyorra-session", "crates/keyorra-sync", "app/src-tauri"]
-default-members = ["crates/keyorra-core", "crates/keyorra-session", "crates/keyorra-sync"]
+members = [
+    "crates/keyorra-core",
+    "crates/keyorra-session",
+    "crates/keyorra-sync",
+    "crates/keyorra-sync-fs",
+    "app/src-tauri",
+]
+default-members = [
+    "crates/keyorra-core",
+    "crates/keyorra-session",
+    "crates/keyorra-sync",
+    "crates/keyorra-sync-fs",
+]
 resolver = "2"
 
 # Argon2 with 64 MiB is painfully slow unoptimized; keep debug builds usable.
```

Create `crates/keyorra-sync-fs/Cargo.toml`:

```toml
[package]
name = "keyorra-sync-fs"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
description = "Keyorra sync over a folder (iCloud Drive or any synced folder)"

[dependencies]
data-encoding = "2"
keyorra-sync = { path = "../keyorra-sync" }
libc = "0.2"
rand = "0.8"

[dev-dependencies]
keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
keyorra-sync = { path = "../keyorra-sync", features = ["test-utils"] }
tempfile = "3"
uuid = "1"
```

- [ ] **Step 2: Failing tests.**

Create `crates/keyorra-sync-fs/src/tests.rs` (a new folder has the layout and the README; segments are write-once and leave no temp files; conflict copies and strangers are ignored; files not on this Mac are `Pending` and asked for, also as iCloud placeholders; an empty file is a write in progress; headers, snapshots, the root head and chunks round-trip; the temp directory is outside the folder when on the same volume, else `.keyorra-tmp.nosync`; a round that runs out of time stops; two engines converge through a folder, also with conflict copies and files that arrive late):

```rust
//! Plan A2-1: the folder transport on temp directories, with what sync clients do to files.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyorra_sync::faults::Faults;
use keyorra_sync::testkit::{device_id, Cluster, START_MS};
use keyorra_sync::transport::{AppendOutcome, Fetched, MemoryTransport, Transport};
use uuid::Uuid;

use super::*;

/// A folder whose provider has some files only in the cloud.
#[derive(Default)]
struct Cloud {
    evicted: Mutex<BTreeSet<PathBuf>>,
    requested: Mutex<Vec<PathBuf>>,
}

impl Availability for Cloud {
    fn state(&self, path: &Path) -> FileState {
        if self.evicted.lock().unwrap().contains(path) {
            return FileState::NotDownloaded;
        }
        avail::local_state(path)
    }
    fn request_download(&self, path: &Path) {
        self.requested.lock().unwrap().push(path.to_path_buf());
    }
}

fn folder(dir: &Path) -> FolderTransport {
    FolderTransport::open(dir, None, Arc::new(LocalDisk)).unwrap()
}

/// A real segment of device 0 (from a cluster's store).
fn some_segments() -> Vec<Vec<u8>> {
    let c = Cluster::new(2, 7, Faults::NONE);
    let mut out = Vec::new();
    for f in c.store.segments(&device_id(0), 0).unwrap() {
        if let Fetched::Ready(b) = f {
            out.push(b);
        }
    }
    out
}

/// Everything a memory store holds, written into a folder.
fn mirror(from: &MemoryTransport, to: &FolderTransport) {
    for stream in from.streams().unwrap() {
        for f in from.segments(&stream, 0).unwrap() {
            if let Fetched::Ready(b) = f {
                to.append(&b).unwrap();
            }
        }
    }
    for (name, f) in from.headers().unwrap() {
        if let Fetched::Ready(b) = f {
            to.put_header(&name, &b).unwrap();
        }
    }
    if let Fetched::Ready(b) = from.root_head_file().unwrap() {
        to.put_root_head_file(&b).unwrap();
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn a_new_folder_has_the_layout_and_a_readme() {
    let dir = tempfile::tempdir().unwrap();
    let _t = folder(dir.path());
    for d in ["account", "streams", "snapshots", "chunks"] {
        assert!(dir.path().join(d).is_dir(), "{d}");
    }
    let readme = std::fs::read_to_string(dir.path().join("README-KEYORRA.txt")).unwrap();
    assert!(readme.contains("Do not edit"));
}

#[test]
fn segments_are_write_once_and_leave_no_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let t = folder(dir.path());
    let segs = some_segments();
    assert_eq!(t.append(&segs[0]).unwrap(), AppendOutcome::Appended);
    assert_eq!(t.append(&segs[0]).unwrap(), AppendOutcome::AlreadyThere);
    // Other bytes at the same position.
    let mut other = segs[0].clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    assert_eq!(t.append(&other).unwrap(), AppendOutcome::Conflict);
    assert_eq!(t.streams().unwrap(), vec![device_id(0)]);
    assert_eq!(
        t.segments(&device_id(0), 0).unwrap(),
        vec![Fetched::Ready(segs[0].clone())]
    );
    let stray: Vec<PathBuf> = files_under(dir.path())
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "tmp"))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

#[test]
fn conflict_copies_and_strangers_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let t = folder(dir.path());
    let segs = some_segments();
    t.append(&segs[0]).unwrap();
    let stream = dir.path().join("streams").join("01".repeat(16));
    let seg_name = names::segment_file(1);
    std::fs::copy(
        stream.join(&seg_name),
        stream.join("0000000000000001 (1).seg"),
    )
    .unwrap();
    std::fs::write(stream.join(".DS_Store"), b"x").unwrap();
    std::fs::write(dir.path().join("streams").join("not a device"), b"x").unwrap();
    std::fs::write(
        dir.path().join("account").join(format!(
            "00000001-{} (conflicted copy).hdr",
            "01".repeat(16)
        )),
        b"x",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("chunks").join("ab")).unwrap();
    std::fs::write(dir.path().join("chunks").join("ab").join("abc"), b"x").unwrap();
    assert_eq!(t.streams().unwrap(), vec![device_id(0)]);
    assert_eq!(t.segments(&device_id(0), 0).unwrap().len(), 1);
    assert!(t.headers().unwrap().is_empty());
    assert_eq!(t.get_chunk("abc").unwrap(), Fetched::Missing);
}

#[test]
fn files_not_on_this_mac_are_pending_and_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let cloud = Arc::new(Cloud::default());
    let t = FolderTransport::open(dir.path(), None, cloud.clone()).unwrap();
    let segs = some_segments();
    t.append(&segs[0]).unwrap();
    let path = dir
        .path()
        .join("streams")
        .join("01".repeat(16))
        .join(names::segment_file(1));
    cloud.evicted.lock().unwrap().insert(path.clone());
    assert_eq!(
        t.segments(&device_id(0), 0).unwrap(),
        vec![Fetched::Pending]
    );
    assert!(
        t.head(&device_id(0)).is_err(),
        "the head is unknown, not empty"
    );
    assert!(
        t.append(&segs[0]).is_err(),
        "cannot say yet whether it is the same"
    );
    assert!(cloud.requested.lock().unwrap().contains(&path));
    // An iCloud placeholder instead of the file.
    std::fs::rename(
        &path,
        path.with_file_name(names::placeholder_name(&names::segment_file(1))),
    )
    .unwrap();
    cloud.evicted.lock().unwrap().clear();
    assert_eq!(
        t.segments(&device_id(0), 0).unwrap(),
        vec![Fetched::Pending]
    );
    // Downloaded.
    std::fs::rename(
        path.with_file_name(names::placeholder_name(&names::segment_file(1))),
        &path,
    )
    .unwrap();
    assert_eq!(
        t.segments(&device_id(0), 0).unwrap(),
        vec![Fetched::Ready(segs[0].clone())]
    );
}

#[test]
fn an_empty_file_is_a_write_in_progress() {
    let dir = tempfile::tempdir().unwrap();
    let t = folder(dir.path());
    let stream = dir.path().join("streams").join("01".repeat(16));
    std::fs::create_dir_all(&stream).unwrap();
    std::fs::write(stream.join(names::segment_file(1)), b"").unwrap();
    assert_eq!(
        t.segments(&device_id(0), 0).unwrap(),
        vec![Fetched::Pending]
    );
}

#[test]
fn headers_snapshots_root_head_and_chunks_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let t = folder(dir.path());
    let header = format!("00000001-{}.hdr", "01".repeat(16));
    t.put_header(&header, b"header").unwrap();
    t.put_header(&header, b"header v2").unwrap();
    assert_eq!(
        t.headers().unwrap(),
        vec![(header.clone(), Fetched::Ready(b"header v2".to_vec()))]
    );
    assert!(t.put_header("../escape.hdr", b"x").is_err());
    t.delete_header(&header).unwrap();
    assert!(t.headers().unwrap().is_empty());

    t.put_root_head_file(b"head").unwrap();
    assert_eq!(
        t.root_head_file().unwrap(),
        Fetched::Ready(b"head".to_vec())
    );

    let name = t.put_chunk(b"KYC1 bytes").unwrap();
    assert_eq!(t.put_chunk(b"KYC1 bytes").unwrap(), name);
    assert_eq!(
        t.get_chunk(&name).unwrap(),
        Fetched::Ready(b"KYC1 bytes".to_vec())
    );
    assert!(dir
        .path()
        .join("chunks")
        .join(&name[..2])
        .join(&name)
        .is_file());

    let mut c = Cluster::new(2, 9, Faults::NONE);
    let snap = c.devices[0]
        .write_snapshot(&c.store.clone(), START_MS)
        .unwrap();
    let Fetched::Ready(bytes) = c.store.get_snapshot(&snap).unwrap() else {
        panic!("snapshot");
    };
    assert_eq!(t.put_snapshot(&bytes).unwrap(), snap);
    assert_eq!(t.snapshots().unwrap(), vec![(snap.clone(), device_id(0))]);
    assert_eq!(t.get_snapshot(&snap).unwrap(), Fetched::Ready(bytes));
    t.delete_snapshot(&snap).unwrap();
    assert!(t.snapshots().unwrap().is_empty());
}

#[test]
fn the_temp_directory_is_outside_the_folder_when_on_the_same_volume() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("Keyorra").join("acct");
    std::fs::create_dir_all(&root).unwrap();
    let app_tmp = base.path().join("app-tmp");
    let t = FolderTransport::open(&root, Some(&app_tmp), Arc::new(LocalDisk)).unwrap();
    assert_eq!(t.tmp, app_tmp);
    assert!(!root.join(names::NOSYNC_TMP).exists());
    // Without an app temp directory (or on another volume): `.nosync` inside.
    let t = FolderTransport::open(&root, None, Arc::new(LocalDisk)).unwrap();
    assert_eq!(t.tmp, root.join(names::NOSYNC_TMP));
}

#[test]
fn a_round_that_runs_out_of_time_stops() {
    let dir = tempfile::tempdir().unwrap();
    let t = folder(dir.path()).with_round_budget(Duration::ZERO);
    assert!(t.streams().is_ok(), "no round started: no limit");
    t.begin_round();
    assert!(t.streams().is_err());
    let t = t.with_round_budget(Duration::from_secs(60));
    t.begin_round();
    assert!(t.streams().is_ok());
}

/// Two devices, each with its own view of the same folder, converge through it.
#[test]
fn devices_converge_through_a_folder() {
    let mut c = Cluster::new(2, 11, Faults::NONE);
    let dir = tempfile::tempdir().unwrap();
    let folders = [folder(dir.path()), folder(dir.path())];
    mirror(&c.store, &folders[0]);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    for n in 0..3u8 {
        let id = Uuid::from_bytes([0x70 + n; 16]);
        let json = Cluster::item_json(id, &format!("item {n}"), &[]);
        c.devices[(n % 2) as usize]
            .save_item(vault, id, &json, START_MS)
            .ok();
        for _ in 0..3 {
            for (i, f) in folders.iter().enumerate() {
                c.devices[i].sync(f, c.clocks[i]).unwrap();
            }
            c.tick(1_000);
        }
    }
    let views: Vec<_> = c.devices.iter().map(|d| d.view()).collect();
    assert_eq!(views[0], views[1]);
    assert!(views[0].items.len() >= 2, "{}", views[0].items.len());
}

/// What sync clients do (conflict copies, evicted files that come back later) does not stop
/// two devices from converging.
#[test]
fn devices_converge_despite_conflict_copies_and_evicted_files() {
    let mut c = Cluster::new(2, 12, Faults::NONE);
    let dir = tempfile::tempdir().unwrap();
    let cloud = Arc::new(Cloud::default());
    let folders = [
        folder(dir.path()),
        FolderTransport::open(dir.path(), None, cloud.clone()).unwrap(),
    ];
    mirror(&c.store, &folders[0]);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let id = Uuid::from_bytes([0x71; 16]);
    c.devices[0]
        .save_item(vault, id, &Cluster::item_json(id, "from 0", &[]), START_MS)
        .unwrap();
    c.devices[0].sync(&folders[0], c.clocks[0]).unwrap();
    // The client made conflict copies of everything and has not downloaded device 0's files
    // for device 1 yet.
    for p in files_under(dir.path()) {
        if p.extension().is_some_and(|e| e == "seg") {
            let copy = p.with_file_name(format!(
                "{} (1).seg",
                p.file_stem().unwrap().to_str().unwrap()
            ));
            std::fs::copy(&p, copy).unwrap();
            if p.to_string_lossy().contains(&"01".repeat(16)) {
                cloud.evicted.lock().unwrap().insert(p);
            }
        }
    }
    c.devices[1].sync(&folders[1], c.clocks[1]).unwrap();
    assert!(!c.devices[1].view().items.contains_key(&id));
    cloud.evicted.lock().unwrap().clear();
    for _ in 0..3 {
        for (i, f) in folders.iter().enumerate() {
            c.devices[i].sync(f, c.clocks[i]).unwrap();
        }
        c.tick(1_000);
    }
    assert_eq!(c.devices[0].view(), c.devices[1].view());
    assert!(c.devices[1].view().items.contains_key(&id));
}
```

- [ ] **Step 3: Names.**

Create `crates/keyorra-sync-fs/src/names.rs`:

```rust
//! The exact file names of the account folder (spec §5.1). A file counts only if its name
//! matches its directory's pattern; anything else (a sync client's conflict copy
//! `x (1).seg`, `.DS_Store`, a half-written temp file) is ignored.

use keyorra_sync::DeviceId;

pub const ACCOUNT: &str = "account";
pub const STREAMS: &str = "streams";
pub const SNAPSHOTS: &str = "snapshots";
pub const CHUNKS: &str = "chunks";
pub const ROOT_HEAD: &str = "root.head";
pub const README: &str = "README-KEYORRA.txt";
/// Temp files when the app's temp directory is on another volume: inside the folder, under
/// a name iCloud does not upload and readers ignore.
pub const NOSYNC_TMP: &str = ".keyorra-tmp.nosync";

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn device_dir(device: &DeviceId) -> String {
    data_encoding::HEXLOWER.encode(device)
}

pub fn parse_device_dir(name: &str) -> Option<DeviceId> {
    if !is_hex(name, 32) {
        return None;
    }
    data_encoding::HEXLOWER
        .decode(name.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

pub fn segment_file(first_seq: u64) -> String {
    format!("{first_seq:016x}.seg")
}

pub fn parse_segment_file(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".seg")?;
    is_hex(stem, 16).then(|| u64::from_str_radix(stem, 16).ok())?
}

/// `<epoch:08x>-<device hex>.hdr`, as `HeaderFile::file_name` makes it.
pub fn is_header_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".hdr") else {
        return false;
    };
    let mut parts = stem.splitn(2, '-');
    matches!((parts.next(), parts.next()), (Some(e), Some(d)) if is_hex(e, 8) && is_hex(d, 32))
}

pub fn is_snapshot_name(name: &str) -> bool {
    is_hex(name, 64)
}

pub fn snapshot_file(name: &str) -> String {
    format!("{name}.snap")
}

pub fn parse_snapshot_file(file: &str) -> Option<&str> {
    file.strip_suffix(".snap").filter(|n| is_snapshot_name(n))
}

pub fn is_chunk_name(name: &str) -> bool {
    is_hex(name, 64)
}

/// An evicted iCloud file shows as `.<name>.icloud`: the file exists but is not on this Mac.
pub fn placeholder_of(file: &str) -> Option<&str> {
    file.strip_prefix('.')?.strip_suffix(".icloud")
}

pub fn placeholder_name(file: &str) -> String {
    format!(".{file}.icloud")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_names_count() {
        assert_eq!(parse_segment_file("000000000000002a.seg"), Some(42));
        for bad in [
            "000000000000002a (1).seg",
            "000000000000002A.seg",
            "2a.seg",
            "000000000000002a.seg.tmp",
            ".000000000000002a.seg",
        ] {
            assert_eq!(parse_segment_file(bad), None, "{bad}");
        }
        assert!(is_header_file(&format!("00000001-{}.hdr", "ab".repeat(16))));
        assert!(!is_header_file(&format!(
            "00000001-{} (1).hdr",
            "ab".repeat(16)
        )));
        assert!(!is_header_file("root.head"));
        assert_eq!(parse_device_dir(&"0f".repeat(16)), Some([0x0f; 16]));
        assert_eq!(parse_device_dir(".DS_Store"), None);
        assert_eq!(
            parse_snapshot_file(&format!("{}.snap", "1".repeat(64))),
            Some(&*"1".repeat(64))
        );
        assert_eq!(
            parse_snapshot_file(&format!("{} 2.snap", "1".repeat(64))),
            None
        );
        assert_eq!(
            placeholder_of(".000000000000002a.seg.icloud"),
            Some("000000000000002a.seg")
        );
        assert_eq!(placeholder_of("000000000000002a.seg"), None);
    }
}
```

- [ ] **Step 4: Availability.**

Create `crates/keyorra-sync-fs/src/avail.rs`:

```rust
//! Whether a file in the folder can be read now (spec §5.2). A file that is not on this Mac
//! (an iCloud or File Provider placeholder, `SF_DATALESS`) is never opened: opening it can
//! block until it is downloaded. The transport asks for a download and reports `Pending`.

use std::path::Path;

/// What a file is, without opening it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Ready,
    /// Exists, but its content is not on this Mac yet.
    NotDownloaded,
    Missing,
}

/// The folder's provider, as far as reading needs it. The app's implementation (plan A2-2)
/// asks iCloud or File Provider through a Swift helper (`NSURLUbiquitousItemDownloadingStatusKey`,
/// `startDownloadingUbiquitousItemAtURL`, `NSFileCoordinator`).
pub trait Availability: Send + Sync {
    fn state(&self, path: &Path) -> FileState {
        local_state(path)
    }
    /// Starts downloading a file that is not on this Mac; returns at once.
    fn request_download(&self, path: &Path) {
        let _ = path;
    }
}

/// A plain folder: only `SF_DATALESS` is looked at (no download requests).
pub struct LocalDisk;

impl Availability for LocalDisk {}

/// `st_flags` bit of a dataless (cloud-only) file on macOS.
pub const SF_DATALESS: u32 = 0x4000_0000;

/// The state from the file system alone: missing, dataless, or ready.
pub fn local_state(path: &Path) -> FileState {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return FileState::Missing;
    };
    if !meta.is_file() {
        return FileState::Missing;
    }
    if is_dataless(&meta) {
        return FileState::NotDownloaded;
    }
    FileState::Ready
}

#[cfg(target_os = "macos")]
fn is_dataless(meta: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    meta.st_flags() & SF_DATALESS != 0
}

#[cfg(not(target_os = "macos"))]
fn is_dataless(_: &std::fs::Metadata) -> bool {
    false
}
```

- [ ] **Step 5: Writing.**

Create `crates/keyorra-sync-fs/src/write.rs`:

```rust
//! Writing a file into the folder (spec §5.3): written and synced to disk in a temp
//! directory outside the synced tree on the same volume, then renamed into place in one
//! step, and the directory synced. Write-once names are never replaced: the rename fails if
//! the name exists.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::names::NOSYNC_TMP;

/// Where temp files go: the app's own temp directory when it is on the same volume as the
/// folder (a rename across volumes is not atomic), otherwise `<folder>/.keyorra-tmp.nosync`.
pub fn choose_temp_dir(folder: &Path, app_temp: Option<&Path>) -> std::io::Result<PathBuf> {
    if let Some(app) = app_temp {
        std::fs::create_dir_all(app)?;
        if same_volume(folder, app)? {
            return Ok(app.to_path_buf());
        }
    }
    let inside = folder.join(NOSYNC_TMP);
    std::fs::create_dir_all(&inside)?;
    Ok(inside)
}

#[cfg(unix)]
fn same_volume(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(a)?.dev() == std::fs::metadata(b)?.dev())
}

#[cfg(not(unix))]
fn same_volume(_: &Path, _: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// Whether a write replaces an existing file of that name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Write-once (segments, snapshots, chunks): `AlreadyExists` if the name is taken.
    New,
    /// The file is replaced as a whole (headers by name, the root head).
    Replace,
}

/// Writes `bytes` to `dest` through `tmp_dir`.
pub fn write_file(tmp_dir: &Path, dest: &Path, bytes: &[u8], mode: Mode) -> std::io::Result<()> {
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let tmp = tmp_dir.join(format!("{}.tmp", data_encoding::HEXLOWER.encode(&suffix)));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir)?;
        }
        match mode {
            Mode::New => rename_new(&tmp, dest)?,
            Mode::Replace => std::fs::rename(&tmp, dest)?,
        }
        if let Some(dir) = dest.parent() {
            // Makes the rename durable; not every file system can sync a directory.
            let _ = File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A rename that fails with `AlreadyExists` instead of replacing `to`.
fn rename_new(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| {
        CString::new(p.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))
    };
    let (f, t) = (c(from)?, c(to)?);
    #[cfg(target_os = "macos")]
    // SAFETY: two live NUL-terminated paths.
    let rc = unsafe { libc::renamex_np(f.as_ptr(), t.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(target_os = "linux")]
    // SAFETY: two live NUL-terminated paths, relative to the current directory.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            f.as_ptr(),
            libc::AT_FDCWD,
            t.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let rc = {
        if to.symlink_metadata().is_ok() {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        std::fs::rename(from, to).map(|()| 0)?
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
```

- [ ] **Step 6: The transport.**

Create `crates/keyorra-sync-fs/src/lib.rs`:

```rust
//! Keyorra sync over a folder (plan A2, spec §5): iCloud Drive by default, or any folder a
//! sync client keeps in step (Dropbox, OneDrive, Google Drive, a NAS share).
//!
//! One account per folder (`<place>/Keyorra/<account id hex>/`). Every file is write-once
//! and written by one device, so a sync client's conflict copies, torn files and files that
//! arrive in any order do no harm: names that do not match exactly are ignored, content is
//! verified by the engine, and anything not readable yet is `Pending`.

pub mod avail;
pub mod names;
pub mod write;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keyorra_sync::chunk::chunk_name;
use keyorra_sync::segment::{SegmentHeader, HEADER_LEN};
use keyorra_sync::snapshot::{snapshot_name, SnapshotHeader};
use keyorra_sync::transport::{AppendOutcome, Fetched, Transport};
use keyorra_sync::{DeviceId, Error, Result};

pub use avail::{Availability, FileState, LocalDisk};
use names::*;
use write::{choose_temp_dir, write_file, Mode};

const README_TEXT: &str = "This folder holds a Keyorra account, end-to-end encrypted.\n\
Do not edit, move or rename the files in it: Keyorra on your devices reads and writes them.\n\
The format is public: docs/sync-protocol.md in Keyorra's source code.\n";

/// How long one sync round may spend in the folder by default.
pub const ROUND_BUDGET: Duration = Duration::from_secs(30);

/// One account's folder.
pub struct FolderTransport {
    root: PathBuf,
    tmp: PathBuf,
    availability: Arc<dyn Availability>,
    budget: Duration,
    deadline: Mutex<Option<Instant>>,
}

fn io(context: &str, e: std::io::Error) -> Error {
    Error::Transport(format!("{context}: {e}"))
}

impl FolderTransport {
    /// Opens the account folder `root`, creating its directories (and the README) when
    /// missing. `app_temp` is the app's temp directory (used when on the same volume).
    pub fn open(
        root: &Path,
        app_temp: Option<&Path>,
        availability: Arc<dyn Availability>,
    ) -> Result<FolderTransport> {
        for dir in [ACCOUNT, STREAMS, SNAPSHOTS, CHUNKS] {
            std::fs::create_dir_all(root.join(dir)).map_err(|e| io("creating the folder", e))?;
        }
        let tmp = choose_temp_dir(root, app_temp).map_err(|e| io("temp directory", e))?;
        let t = FolderTransport {
            root: root.to_path_buf(),
            tmp,
            availability,
            budget: ROUND_BUDGET,
            deadline: Mutex::new(None),
        };
        let readme = root.join(README);
        if readme.symlink_metadata().is_err() {
            let _ = write_file(&t.tmp, &readme, README_TEXT.as_bytes(), Mode::New);
        }
        Ok(t)
    }

    /// A shorter or longer time budget per round (tests, slow network shares).
    pub fn with_round_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Fails once the round's time is up: a slow or hanging folder must not hold the app.
    fn check_time(&self) -> Result<()> {
        match *self.deadline.lock().unwrap() {
            Some(d) if Instant::now() >= d => Err(Error::Transport(
                "the sync folder is too slow; trying again later".into(),
            )),
            _ => Ok(()),
        }
    }

    /// The file names in `dir` (missing directory: none), with evicted placeholders mapped to
    /// the names they stand for (`true` = placeholder).
    fn list(&self, dir: &Path) -> Result<Vec<(String, bool)>> {
        self.check_time()?;
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io("listing the folder", e)),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            match placeholder_of(&name) {
                Some(real) => out.push((real.to_owned(), true)),
                None => out.push((name, false)),
            }
        }
        Ok(out)
    }

    /// Reads a file if it is on this Mac; otherwise asks for it and says `Pending`. An empty
    /// file is a write still in progress (`Pending`).
    fn fetch(&self, path: &Path) -> Result<Fetched<Vec<u8>>> {
        self.check_time()?;
        let placeholder = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| path.with_file_name(placeholder_name(n)));
        match self.availability.state(path) {
            FileState::Ready => {}
            FileState::NotDownloaded => {
                self.availability.request_download(path);
                return Ok(Fetched::Pending);
            }
            FileState::Missing => {
                if placeholder.is_some_and(|p| p.symlink_metadata().is_ok()) {
                    self.availability.request_download(path);
                    return Ok(Fetched::Pending);
                }
                return Ok(Fetched::Missing);
            }
        }
        match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => Ok(Fetched::Pending),
            Ok(bytes) => Ok(Fetched::Ready(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fetched::Missing),
            Err(e) => Err(io("reading the folder", e)),
        }
    }

    fn stream_dir(&self, stream: &DeviceId) -> PathBuf {
        self.root.join(STREAMS).join(device_dir(stream))
    }

    /// Strict segment files of a stream, by first position.
    fn segment_files(&self, stream: &DeviceId) -> Result<Vec<u64>> {
        let mut seqs: Vec<u64> = self
            .list(&self.stream_dir(stream))?
            .into_iter()
            .filter_map(|(n, _)| parse_segment_file(&n))
            .collect();
        seqs.sort_unstable();
        seqs.dedup();
        Ok(seqs)
    }

    fn write(&self, dest: &Path, bytes: &[u8], mode: Mode) -> std::io::Result<()> {
        write_file(&self.tmp, dest, bytes, mode)
    }

    fn remove(&self, path: &Path) -> Result<()> {
        for p in [
            path.to_path_buf(),
            path.with_file_name(placeholder_name(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default(),
            )),
        ] {
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io("deleting from the folder", e)),
            }
        }
        Ok(())
    }

    fn snapshot_path(&self, name: &str) -> Result<Option<PathBuf>> {
        if !is_snapshot_name(name) {
            return Ok(None);
        }
        for (dir, _) in self.list(&self.root.join(SNAPSHOTS))? {
            if parse_device_dir(&dir).is_some() {
                let p = self
                    .root
                    .join(SNAPSHOTS)
                    .join(dir)
                    .join(snapshot_file(name));
                if p.symlink_metadata().is_ok()
                    || p.with_file_name(placeholder_name(&snapshot_file(name)))
                        .symlink_metadata()
                        .is_ok()
                {
                    return Ok(Some(p));
                }
            }
        }
        Ok(None)
    }

    fn chunk_path(&self, name: &str) -> PathBuf {
        self.root.join(CHUNKS).join(&name[..2]).join(name)
    }
}

impl Transport for FolderTransport {
    fn begin_round(&self) {
        *self.deadline.lock().unwrap() = Some(Instant::now() + self.budget);
    }

    fn streams(&self) -> Result<Vec<DeviceId>> {
        Ok(self
            .list(&self.root.join(STREAMS))?
            .into_iter()
            .filter_map(|(n, _)| parse_device_dir(&n))
            .collect())
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let dir = self.stream_dir(stream);
        let mut out = Vec::new();
        for seq in self.segment_files(stream)? {
            if seq > after_seq {
                out.push(self.fetch(&dir.join(segment_file(seq)))?);
            }
        }
        Ok(out)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        // The newest file's header says where the stream ends (its first bytes only).
        let Some(newest) = self.segment_files(stream)?.last().copied() else {
            return Ok(None);
        };
        match self.fetch(&self.stream_dir(stream).join(segment_file(newest)))? {
            Fetched::Ready(bytes) if bytes.len() >= HEADER_LEN => {
                Ok(Some(SegmentHeader::parse(&bytes)?.last_seq))
            }
            Fetched::Missing => Ok(None),
            _ => Err(Error::Transport(
                "the newest segment is not downloaded yet".into(),
            )),
        }
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        let header = SegmentHeader::parse(segment)?;
        let path = self
            .stream_dir(&header.device_id)
            .join(segment_file(header.first_seq));
        self.check_time()?;
        let compare = |this: &Self| -> Result<AppendOutcome> {
            match this.fetch(&path)? {
                Fetched::Ready(existing) if existing == segment => Ok(AppendOutcome::AlreadyThere),
                Fetched::Ready(_) => Ok(AppendOutcome::Conflict),
                Fetched::Missing => Err(Error::Transport("the segment went away".into())),
                Fetched::Pending => Err(Error::Transport(
                    "a segment at this position is not downloaded yet".into(),
                )),
            }
        };
        if self.availability.state(&path) != FileState::Missing
            || path
                .with_file_name(placeholder_name(&segment_file(header.first_seq)))
                .symlink_metadata()
                .is_ok()
        {
            return compare(self);
        }
        match self.write(&path, segment, Mode::New) {
            Ok(()) => Ok(AppendOutcome::Appended),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => compare(self),
            Err(e) => Err(io("writing a segment", e)),
        }
    }

    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        self.remove(&self.stream_dir(stream).join(segment_file(first_seq)))
    }

    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        let dir = self.root.join(ACCOUNT);
        let mut names: Vec<String> = self
            .list(&dir)?
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| is_header_file(n))
            .collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(|n| {
                let f = self.fetch(&dir.join(&n))?;
                Ok((n, f))
            })
            .collect()
    }

    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        if !is_header_file(name) {
            return Err(Error::Transport(format!("bad header file name {name}")));
        }
        self.check_time()?;
        self.write(&self.root.join(ACCOUNT).join(name), bytes, Mode::Replace)
            .map_err(|e| io("writing a header", e))
    }

    fn delete_header(&self, name: &str) -> Result<()> {
        if !is_header_file(name) {
            return Ok(());
        }
        self.remove(&self.root.join(ACCOUNT).join(name))
    }

    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        let base = self.root.join(SNAPSHOTS);
        let mut out = Vec::new();
        for (dir, _) in self.list(&base)? {
            let Some(author) = parse_device_dir(&dir) else {
                continue;
            };
            for (file, _) in self.list(&base.join(&dir))? {
                if let Some(name) = parse_snapshot_file(&file) {
                    out.push((name.to_owned(), author));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        match self.snapshot_path(name)? {
            Some(p) => self.fetch(&p),
            None => Ok(Fetched::Missing),
        }
    }

    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        let author = SnapshotHeader::parse(bytes)?.author;
        let name = snapshot_name(bytes);
        self.check_time()?;
        let path = self
            .root
            .join(SNAPSHOTS)
            .join(device_dir(&author))
            .join(snapshot_file(&name));
        match self.write(&path, bytes, Mode::New) {
            Ok(()) => Ok(name),
            // Content-addressed: the same name is the same bytes.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(name),
            Err(e) => Err(io("writing a snapshot", e)),
        }
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        match self.snapshot_path(name)? {
            Some(p) => self.remove(&p),
            None => Ok(()),
        }
    }

    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        self.fetch(&self.root.join(ACCOUNT).join(ROOT_HEAD))
    }

    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.check_time()?;
        self.write(
            &self.root.join(ACCOUNT).join(ROOT_HEAD),
            bytes,
            Mode::Replace,
        )
        .map_err(|e| io("writing the root head", e))
    }

    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        let name = chunk_name(bytes);
        self.check_time()?;
        match self.write(&self.chunk_path(&name), bytes, Mode::New) {
            Ok(()) => Ok(name),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(name),
            Err(e) => Err(io("writing a chunk", e)),
        }
    }

    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        if !is_chunk_name(name) {
            return Ok(Fetched::Missing);
        }
        self.fetch(&self.chunk_path(name))
    }
}
```

- [ ] **Step 7: Run and commit.**

`cargo test -p keyorra-sync-fs` green (11 tests); the workspace too. Commit: `Sync A2-1: the folder transport (keyorra-sync-fs)`.

---

### Task 3: Spec and protocol

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`, `docs/sync-protocol.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Commit: `docs: A2-1 folder transport`.

---

### Task 4: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (652 passed, 4 ignored when verified); `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

