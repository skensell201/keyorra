//! Whether a file in the folder can be read now (spec §5.2). A file that is not on this Mac
//! (an iCloud or File Provider placeholder, `SF_DATALESS`) is never opened: opening it can
//! block until it is downloaded. The transport asks for a download and reports `Pending`.

use std::path::Path;

/// How a coordinated access touches a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    /// The file is created or replaced (the temp file is renamed onto it).
    Write,
    Delete,
}

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
    /// Runs `f`, which reads, writes or deletes `path`, the way the provider wants file
    /// access coordinated with its sync client (`NSFileCoordinator` in the app). Directory
    /// listings are not coordinated.
    fn coordinate(
        &self,
        path: &Path,
        access: Access,
        f: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let _ = (path, access);
        f()
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
