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
            // A panic must not unwind into Swift (review A2 M10).
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (call.f)()))
                .unwrap_or_else(|_| Err(std::io::Error::other("the file access panicked")));
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

    fn join_candidates(&self) -> Result<Vec<(String, BoxedTransport)>, String> {
        let entries = match std::fs::read_dir(&self.place) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // Plain folders named like an account only; looking creates nothing in them, and
            // one that cannot be opened does not hide the others (review A2 I4, M5).
            let plain = entry
                .file_type()
                .is_ok_and(|t| t.is_dir() && !t.is_symlink());
            if !is_account_folder(&name) || !plain {
                continue;
            }
            if let Ok(t) =
                FolderTransport::probe(&entry.path(), Some(&self.temp), self.availability.clone())
            {
                out.push((
                    name,
                    Box::new(t.with_round_budget(ROUND_BUDGET)) as BoxedTransport,
                ));
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
        std::fs::create_dir_all(place.join("02".repeat(16))).unwrap();
        let probed = link.join_candidates().unwrap();
        assert_eq!(probed.len(), 1);
        assert_eq!(probed[0].0, "02".repeat(16));
        assert_eq!(
            std::fs::read_dir(place.join("02".repeat(16)))
                .unwrap()
                .count(),
            0,
            "looking created nothing"
        );
        std::fs::remove_dir(place.join("02".repeat(16))).unwrap();
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
    fn a_panic_in_a_coordinated_access_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = MacCloud
            .coordinate(dir.path(), Access::Read, &mut || panic!("boom"))
            .unwrap_err();
        assert!(err.to_string().contains("panicked"));
    }

    /// Review A2 I5: no command runs on the main thread (a sync round may hold the session).
    #[test]
    fn every_command_runs_off_the_main_thread() {
        let source = include_str!("commands.rs");
        assert_eq!(
            source.matches("#[tauri::command]").count(),
            0,
            "commands are #[tauri::command(async)]"
        );
        assert!(include_str!("tray.rs").contains("std::thread::spawn"));
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
