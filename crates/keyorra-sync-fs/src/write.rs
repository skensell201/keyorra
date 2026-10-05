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
