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

pub use avail::{Access, Availability, FileState, LocalDisk};
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
        let mut bytes = Vec::new();
        let read = self.availability.coordinate(path, Access::Read, &mut || {
            bytes = std::fs::read(path)?;
            Ok(())
        });
        match read {
            Ok(()) if bytes.is_empty() => Ok(Fetched::Pending),
            Ok(()) => Ok(Fetched::Ready(bytes)),
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
        self.availability.coordinate(dest, Access::Write, &mut || {
            write_file(&self.tmp, dest, bytes, mode)
        })
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
            if p.symlink_metadata().is_err() {
                continue;
            }
            let removed = self
                .availability
                .coordinate(&p, Access::Delete, &mut || std::fs::remove_file(&p));
            match removed {
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
