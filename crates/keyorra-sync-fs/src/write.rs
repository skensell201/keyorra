//! Writing a file into the folder (spec §5.3): written and synced to disk in a temp
//! directory outside the synced tree on the same volume, then renamed into place in one
//! step, and the directory synced. Write-once names are never replaced: the rename fails if
//! the name exists.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rand::RngCore;

use crate::names::NOSYNC_TMP;
use crate::safe::ensure_dir;

/// Temp files older than this are left over from a crash and removed when a folder opens.
pub const STALE_TMP: Duration = Duration::from_secs(3600);

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
    ensure_dir(folder, &inside)?;
    Ok(inside)
}

/// Removes `*.tmp` files older than [`STALE_TMP`] from a temp directory (review A2 M6).
pub fn clean_temp_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > STALE_TMP);
        if stale && path.extension().is_some_and(|e| e == "tmp") {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn same_volume(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(a)?.dev() == std::fs::metadata(b)?.dev())
}

/// Whether a write replaces an existing file of that name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Write-once (segments, snapshots, chunks): `AlreadyExists` if the name is taken.
    New,
    /// The file is replaced as a whole (headers by name, the root head).
    Replace,
}

/// Writes `bytes` to `dest` (inside `root`) through `tmp_dir`. The directories on the way
/// are created as plain directories; a symlink among them is an error.
pub fn write_file(
    tmp_dir: &Path,
    root: &Path,
    dest: &Path,
    bytes: &[u8],
    mode: Mode,
) -> std::io::Result<()> {
    let dir = dest
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no directory"))?;
    ensure_dir(root, dir)?;
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let tmp = tmp_dir.join(format!("{}.tmp", data_encoding::HEXLOWER.encode(&suffix)));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        match mode {
            Mode::New => rename_new(&tmp, dest)?,
            Mode::Replace => std::fs::rename(&tmp, dest)?,
        }
        // Makes the rename durable; not every file system can sync a directory.
        let _ = File::open(dir).and_then(|d| d.sync_all());
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A rename that fails with `AlreadyExists` instead of replacing `to`. Where the file system
/// cannot do that in one step (SMB, NFS: `ENOTSUP`), a hard link (which fails if the name
/// exists) and an unlink of the temp file do the same (review A2 M6).
fn rename_new(from: &Path, to: &Path) -> std::io::Result<()> {
    match rename_excl(from, to) {
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::ENOSYS)
            ) =>
        {
            std::fs::hard_link(from, to)?;
            let _ = std::fs::remove_file(from);
            Ok(())
        }
        other => other,
    }
}

fn rename_excl(from: &Path, to: &Path) -> std::io::Result<()> {
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
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
