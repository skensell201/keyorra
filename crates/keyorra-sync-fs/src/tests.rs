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

/// Plan A2-2: every read, write and delete of a file goes through the provider's
/// coordination (`NSFileCoordinator` in the app).
#[test]
fn every_file_access_is_coordinated() {
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(Access, PathBuf)>>);
    impl Availability for Recorder {
        fn coordinate(
            &self,
            path: &Path,
            access: Access,
            f: &mut dyn FnMut() -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.0.lock().unwrap().push((access, path.to_path_buf()));
            f()
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let rec = Arc::new(Recorder::default());
    let t = FolderTransport::open(dir.path(), None, rec.clone()).unwrap();
    rec.0.lock().unwrap().clear();
    let segs = some_segments();
    t.append(&segs[0]).unwrap();
    t.segments(&device_id(0), 0).unwrap();
    t.delete_segment(&device_id(0), 1).unwrap();
    let seg = dir
        .path()
        .join("streams")
        .join("01".repeat(16))
        .join(names::segment_file(1));
    let log = rec.0.lock().unwrap().clone();
    assert_eq!(
        log,
        vec![
            (Access::Write, seg.clone()),
            (Access::Read, seg.clone()),
            (Access::Delete, seg),
        ]
    );
}
