//! Where segments live: the transport trait, and an in-memory transport for tests and for the
//! engine's own test suites. Folder (A2) and server (B2) transports implement the same trait;
//! headers, snapshots and chunks are added to it by the plans that need them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::segment::SegmentHeader;
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
}

/// One stream: segment bytes by first sequence number.
type Stream = BTreeMap<u64, Vec<u8>>;

/// Segments in memory, shared by every clone (one clone per simulated device).
#[derive(Clone, Debug, Default)]
pub struct MemoryTransport {
    streams: Arc<Mutex<BTreeMap<DeviceId, Stream>>>,
}

impl MemoryTransport {
    pub fn new() -> Self {
        Self::default()
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
    fn clones_share_storage() {
        let t = MemoryTransport::new();
        let u = t.clone();
        t.append(&segment([1; 16], 1, 0)).unwrap();
        assert_eq!(u.streams().unwrap().len(), 1);
    }
}
