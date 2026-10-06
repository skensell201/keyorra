//! File access that stays inside the account folder (review A2 I2, I3): no symlinked
//! directory below the folder's root is ever followed, a symlinked file is never read, and a
//! file is read only up to the largest valid size of its kind.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

fn not_inside(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} is not a plain directory inside the sync folder",
            path.display()
        ),
    )
}

/// The directories from `root` (exclusive) down to `dir` (inclusive).
fn steps<'a>(root: &'a Path, dir: &'a Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let rel = dir.strip_prefix(root).map_err(|_| not_inside(dir))?;
    let mut cur = root.to_path_buf();
    let mut out = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(name) => {
                cur.push(name);
                out.push(cur.clone());
            }
            _ => return Err(not_inside(dir)),
        }
    }
    Ok(out)
}

/// Whether `dir` (inside `root`) exists as plain directories all the way down: `Ok(false)`
/// when a part is missing, an error when a part is a symlink or not a directory.
pub fn dir_is_plain(root: &Path, dir: &Path) -> std::io::Result<bool> {
    for step in steps(root, dir)? {
        match std::fs::symlink_metadata(&step) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err(not_inside(&step)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Creates `dir` inside `root` one plain directory at a time; a symlink on the way is an
/// error (nothing is created through it).
pub fn ensure_dir(root: &Path, dir: &Path) -> std::io::Result<()> {
    for step in steps(root, dir)? {
        match std::fs::create_dir(&step) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let m = std::fs::symlink_metadata(&step)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(not_inside(&step));
        }
    }
    Ok(())
}

/// Reads a regular file without following a symlink in its last part, and without waiting
/// on a FIFO, at most `limit + 1` bytes (a longer file is cut there, so its reader rejects
/// it as too long). `NotFound` also for a symlink.
pub fn read_limited(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                std::io::Error::from(std::io::ErrorKind::NotFound)
            } else {
                e
            }
        })?;
    if !file.metadata()?.is_file() {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}
