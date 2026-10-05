//! Where segments live: the transport trait, and an in-memory transport for tests and for the
//! engine's own test suites. Folder (A2) and server (B2) transports implement the same trait;
//! headers, snapshots and chunks are added to it by the plans that need them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::segment::SegmentHeader;
use crate::snapshot::{snapshot_name, SnapshotHeader};
use crate::DeviceId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched<T> {
    Ready(T),
    /// Exists but cannot be read yet (not downloaded, half-synced): try again later.
    Pending,
    /// Listed but gone.
    Missing,
}

/// One file as the store holds it, for "what the folder sees" (spec §9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Relative to the account's place (`streams/<device>/<seq>.seg`, …).
    pub path: String,
    pub size: u64,
    /// The name is one Keyorra reads; `false`: an unknown file, ignored.
    pub counted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// The same bytes were already there (a retried append that had succeeded).
    AlreadyThere,
    /// Different bytes already occupy this position of the stream.
    Conflict,
}

pub trait Transport {
    /// Devices that have a stream.
    fn streams(&self) -> Result<Vec<DeviceId>>;
    /// Segments of `stream` that start after `after_seq`, in no particular order.
    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>>;
    /// Stores a segment under its device and first sequence number (from its header).
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome>;
    /// The highest `last_seq` stored for `stream` (from file names or server metadata, without
    /// reading segments): how a device notices that a stream went backwards (spec §4.5).
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>>;
    /// Account header files as (file name, content) (spec §4.7).
    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>>;
    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()>;
    fn delete_header(&self, name: &str) -> Result<()>;
    /// Snapshots as (name = lowercase hex SHA-256 of the file, author) (spec §4.8).
    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>>;
    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>>;
    /// Stores a snapshot under its name, which it returns.
    fn put_snapshot(&self, bytes: &[u8]) -> Result<String>;
    fn delete_snapshot(&self, name: &str) -> Result<()>;
    /// Deletes the segment file of `stream` starting at `first_seq` (a device removing
    /// something that occupies its own stream but is not its segment).
    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()>;
    /// The main device's advertised head file ([`crate::root_head`]).
    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>>;
    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()>;
    /// Stores an attachment chunk under its name, the lowercase hex SHA-256 of the bytes
    /// ([`crate::chunk::chunk_name`]), which it returns. Chunks are write-once: storing the
    /// same bytes again is a no-op (plan A2).
    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        let _ = bytes;
        Err(crate::Error::Transport(
            "this store keeps no attachment chunks".into(),
        ))
    }
    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        let _ = name;
        Ok(Fetched::Missing)
    }
    /// Whether a chunk is here, without reading it (`Pending`: not on this device yet, and
    /// asked for). Review A2 I6.
    fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
        Ok(match self.get_chunk(name)? {
            Fetched::Ready(_) => Fetched::Ready(()),
            Fetched::Pending => Fetched::Pending,
            Fetched::Missing => Fetched::Missing,
        })
    }
    /// A sync round starts (a folder transport starts its time budget, plan A2). The caller
    /// that runs rounds calls it, and [`Transport::end_round`] when the round is over.
    fn begin_round(&self) {}
    /// The round is over: calls until the next round have no round budget (review A2 I1).
    fn end_round(&self) {}
    /// Every file of the account as stored (names and sizes only, nothing is read).
    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
        Ok(Vec::new())
    }
}

/// A boxed transport (the app picks the transport at run time).
impl<T: Transport + ?Sized> Transport for Box<T> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        (**self).streams()
    }
    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        (**self).segments(stream, after_seq)
    }
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        (**self).append(segment)
    }
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        (**self).head(stream)
    }
    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        (**self).headers()
    }
    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        (**self).put_header(name, bytes)
    }
    fn delete_header(&self, name: &str) -> Result<()> {
        (**self).delete_header(name)
    }
    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        (**self).snapshots()
    }
    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        (**self).get_snapshot(name)
    }
    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        (**self).put_snapshot(bytes)
    }
    fn delete_snapshot(&self, name: &str) -> Result<()> {
        (**self).delete_snapshot(name)
    }
    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        (**self).delete_segment(stream, first_seq)
    }
    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        (**self).root_head_file()
    }
    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        (**self).put_root_head_file(bytes)
    }
    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        (**self).put_chunk(bytes)
    }
    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        (**self).get_chunk(name)
    }
    fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
        (**self).chunk_state(name)
    }
    fn begin_round(&self) {
        (**self).begin_round()
    }
    fn end_round(&self) {
        (**self).end_round()
    }
    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
        (**self).inventory()
    }
}

#[derive(Clone, Debug, Default)]
struct Files {
    headers: BTreeMap<String, Vec<u8>>,
    snapshots: BTreeMap<String, Vec<u8>>,
    root_head: Option<Vec<u8>>,
    chunks: BTreeMap<String, Vec<u8>>,
}

/// One stream: segment bytes by first sequence number.
type Stream = BTreeMap<u64, Vec<u8>>;

/// Segments in memory, shared by every clone (one clone per simulated device).
#[derive(Clone, Debug, Default)]
pub struct MemoryTransport {
    streams: Arc<Mutex<BTreeMap<DeviceId, Stream>>>,
    files: Arc<Mutex<Files>>,
}

impl MemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes one segment file (tests: the user deleting what a tamperer put there).
    pub fn remove_segment(&self, device: &DeviceId, first_seq: u64) {
        if let Some(stream) = self.streams.lock().unwrap().get_mut(device) {
            stream.remove(&first_seq);
        }
    }

    /// Removes and returns every attachment chunk (tests: chunks not arrived yet).
    pub fn take_chunks(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.files.lock().unwrap().chunks)
            .into_values()
            .collect()
    }

    /// An independent copy of everything stored now (tests: one side of a fork).
    pub fn deep_copy(&self) -> MemoryTransport {
        MemoryTransport {
            streams: Arc::new(Mutex::new(self.streams.lock().unwrap().clone())),
            files: Arc::new(Mutex::new(self.files.lock().unwrap().clone())),
        }
    }

    /// Every stored segment, for "what the transport sees" and for tests.
    pub fn dump(&self) -> Vec<(DeviceId, u64, usize)> {
        let streams = self.streams.lock().unwrap();
        streams
            .iter()
            .flat_map(|(d, segs)| segs.iter().map(move |(seq, b)| (*d, *seq, b.len())))
            .collect()
    }
}

impl Transport for MemoryTransport {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        Ok(self.streams.lock().unwrap().keys().copied().collect())
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let streams = self.streams.lock().unwrap();
        Ok(streams
            .get(stream)
            .map(|segs| {
                segs.range(after_seq + 1..)
                    .map(|(_, b)| Fetched::Ready(b.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        let streams = self.streams.lock().unwrap();
        // The highest last position named by any file (as a folder listing would).
        Ok(streams.get(stream).and_then(|segs| {
            segs.values()
                .filter_map(|b| SegmentHeader::parse(b).ok())
                .map(|h| h.last_seq)
                .max()
        }))
    }

    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .headers
            .iter()
            .map(|(n, b)| (n.clone(), Fetched::Ready(b.clone())))
            .collect())
    }

    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        files.headers.insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn delete_header(&self, name: &str) -> Result<()> {
        self.files.lock().unwrap().headers.remove(name);
        Ok(())
    }

    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .snapshots
            .iter()
            .filter_map(|(n, b)| Some((n.clone(), SnapshotHeader::parse(b).ok()?.author)))
            .collect())
    }

    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .snapshots
            .get(name)
            .map_or(Fetched::Missing, |b| Fetched::Ready(b.clone())))
    }

    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        SnapshotHeader::parse(bytes)?;
        let name = snapshot_name(bytes);
        let mut files = self.files.lock().unwrap();
        files.snapshots.insert(name.clone(), bytes.to_vec());
        Ok(name)
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        self.files.lock().unwrap().snapshots.remove(name);
        Ok(())
    }

    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        self.remove_segment(stream, first_seq);
        Ok(())
    }

    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .root_head
            .clone()
            .map_or(Fetched::Missing, Fetched::Ready))
    }

    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.files.lock().unwrap().root_head = Some(bytes.to_vec());
        Ok(())
    }

    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        let name = crate::chunk::chunk_name(bytes);
        self.files
            .lock()
            .unwrap()
            .chunks
            .entry(name.clone())
            .or_insert_with(|| bytes.to_vec());
        Ok(name)
    }

    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .chunks
            .get(name)
            .map_or(Fetched::Missing, |b| Fetched::Ready(b.clone())))
    }

    fn inventory(&self) -> Result<Vec<InventoryEntry>> {
        let entry = |path: String, size: usize| InventoryEntry {
            path,
            size: size as u64,
            counted: true,
        };
        let hex = |d: &DeviceId| data_encoding::HEXLOWER.encode(d);
        let mut out = Vec::new();
        for (device, segs) in self.streams.lock().unwrap().iter() {
            for (seq, b) in segs {
                out.push(entry(
                    format!("streams/{}/{seq:016x}.seg", hex(device)),
                    b.len(),
                ));
            }
        }
        let files = self.files.lock().unwrap();
        for (name, b) in &files.headers {
            out.push(entry(format!("account/{name}"), b.len()));
        }
        if let Some(b) = &files.root_head {
            out.push(entry("account/root.head".into(), b.len()));
        }
        for (name, b) in &files.snapshots {
            let author = SnapshotHeader::parse(b)
                .map(|h| hex(&h.author))
                .unwrap_or_default();
            out.push(entry(format!("snapshots/{author}/{name}.snap"), b.len()));
        }
        for (name, b) in &files.chunks {
            out.push(entry(format!("chunks/{}/{name}", &name[..2]), b.len()));
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        let header = SegmentHeader::parse(segment)?;
        let mut streams = self.streams.lock().unwrap();
        let stream = streams.entry(header.device_id).or_default();
        match stream.get(&header.first_seq) {
            Some(existing) if existing == segment => Ok(AppendOutcome::AlreadyThere),
            Some(_) => Ok(AppendOutcome::Conflict),
            None => {
                stream.insert(header.first_seq, segment.to_vec());
                Ok(AppendOutcome::Appended)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::segment::{chain_genesis, seal_segment, StreamPosition};
    use ed25519_dalek::SigningKey;
    use keyorra_core::crypto::Key;

    fn segment(device: DeviceId, first_seq: u64, entry: u64) -> Vec<u8> {
        let at = StreamPosition {
            device_id: device,
            first_seq,
            prev_hash: chain_genesis(&[0; 16], &device),
        };
        let mut rng = rand::rngs::OsRng;
        seal_segment(
            &Key::from_bytes([1; 32]),
            &SigningKey::from_bytes(&[2; 32]),
            &at,
            vec![Value::Uint(entry)],
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn stores_by_device_and_first_seq() {
        let t = MemoryTransport::new();
        let (a, b) = ([1; 16], [2; 16]);
        assert_eq!(
            t.append(&segment(a, 1, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            t.append(&segment(a, 2, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            t.append(&segment(b, 1, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(t.streams().unwrap(), vec![a, b]);
        assert_eq!(t.segments(&a, 0).unwrap().len(), 2);
        assert_eq!(t.segments(&a, 1).unwrap().len(), 1);
        assert_eq!(t.segments(&[9; 16], 0).unwrap(), vec![]);
        assert_eq!(t.head(&a).unwrap(), Some(2));
        assert_eq!(t.head(&[9; 16]).unwrap(), None);
        assert_eq!(t.dump().len(), 3);
    }

    #[test]
    fn retries_are_idempotent_and_overwrites_conflict() {
        let t = MemoryTransport::new();
        let seg = segment([1; 16], 1, 0);
        t.append(&seg).unwrap();
        assert_eq!(t.append(&seg).unwrap(), AppendOutcome::AlreadyThere);
        assert_eq!(
            t.append(&segment([1; 16], 1, 5)).unwrap(),
            AppendOutcome::Conflict
        );
        assert!(t.append(b"junk").is_err());
    }

    #[test]
    fn chunks_are_stored_under_their_hash() {
        let t = MemoryTransport::new();
        let name = t.put_chunk(b"KYC1 chunk bytes").unwrap();
        assert_eq!(name, crate::chunk::chunk_name(b"KYC1 chunk bytes"));
        assert_eq!(
            t.put_chunk(b"KYC1 chunk bytes").unwrap(),
            name,
            "write-once, same name"
        );
        assert_eq!(
            t.get_chunk(&name).unwrap(),
            Fetched::Ready(b"KYC1 chunk bytes".to_vec())
        );
        assert_eq!(t.get_chunk(&"0".repeat(64)).unwrap(), Fetched::Missing);
        let boxed: Box<dyn Transport> = Box::new(t.clone());
        assert_eq!(
            boxed.get_chunk(&name).unwrap(),
            Fetched::Ready(b"KYC1 chunk bytes".to_vec())
        );
    }

    #[test]
    fn headers_and_snapshots_are_stored_by_name() {
        let t = MemoryTransport::new();
        t.put_header("00000001-aa.hdr", b"h1").unwrap();
        assert_eq!(
            t.headers().unwrap(),
            vec![("00000001-aa.hdr".to_owned(), Fetched::Ready(b"h1".to_vec()))]
        );
        t.delete_header("00000001-aa.hdr").unwrap();
        assert!(t.headers().unwrap().is_empty());
        let snap = crate::snapshot::seal_snapshot(
            &Key::from_bytes([1; 32]),
            &SigningKey::from_bytes(&[2; 32]),
            [7; 16],
            Value::Null,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let name = t.put_snapshot(&snap).unwrap();
        assert_eq!(t.snapshots().unwrap(), vec![(name.clone(), [7; 16])]);
        assert_eq!(t.get_snapshot(&name).unwrap(), Fetched::Ready(snap));
        t.delete_snapshot(&name).unwrap();
        assert_eq!(t.get_snapshot(&name).unwrap(), Fetched::Missing);
        assert!(t.put_snapshot(b"junk").is_err());
    }

    #[test]
    fn a_deep_copy_does_not_share_storage() {
        let t = MemoryTransport::new();
        let u = t.deep_copy();
        t.append(&segment([1; 16], 1, 0)).unwrap();
        assert!(u.streams().unwrap().is_empty());
    }

    #[test]
    fn clones_share_storage() {
        let t = MemoryTransport::new();
        let u = t.clone();
        t.append(&segment([1; 16], 1, 0)).unwrap();
        assert_eq!(u.streams().unwrap().len(), 1);
    }
}
