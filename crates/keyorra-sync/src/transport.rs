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
    /// The main device's advertised head file ([`crate::root_head`]).
    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>>;
    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
struct Files {
    headers: BTreeMap<String, Vec<u8>>,
    snapshots: BTreeMap<String, Vec<u8>>,
    root_head: Option<Vec<u8>>,
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
        Ok(streams
            .get(stream)
            .and_then(|segs| segs.values().next_back())
            .and_then(|b| SegmentHeader::parse(b).ok())
            .map(|h| h.last_seq))
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
