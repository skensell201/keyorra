//! A transport that misbehaves the way synced folders and networks do (spec §11, suite 5):
//! files not downloaded yet, half-synced files, bit rot, sync-client duplicates, any listing
//! order, streams that show up late, writes that fail before or after they land.
//! Every fault is transient and drawn from a seeded generator, so a failing case replays.

use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::DeviceId;

/// Probabilities in percent, per segment read or per append.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// A stream is left out of the listing.
    pub hide_stream: u8,
    /// A segment is reported as `Pending`.
    pub pending: u8,
    /// A segment is left out of the listing.
    pub omit: u8,
    /// A segment is returned cut short (half-synced).
    pub truncate: u8,
    /// One bit of a segment is flipped.
    pub flip: u8,
    /// A segment is listed twice.
    pub duplicate: u8,
    /// The listing comes back shuffled.
    pub shuffle: u8,
    /// An append fails without storing anything.
    pub fail_before_append: u8,
    /// An append stores the segment, then reports a failure.
    pub fail_after_append: u8,
}

impl Faults {
    pub const NONE: Faults = Faults {
        hide_stream: 0,
        pending: 0,
        omit: 0,
        truncate: 0,
        flip: 0,
        duplicate: 0,
        shuffle: 0,
        fail_before_append: 0,
        fail_after_append: 0,
    };

    /// Everything at once, often enough to matter.
    pub const CHAOS: Faults = Faults {
        hide_stream: 10,
        pending: 15,
        omit: 10,
        truncate: 10,
        flip: 5,
        duplicate: 15,
        shuffle: 50,
        fail_before_append: 15,
        fail_after_append: 15,
    };
}

pub struct Faulty<T> {
    inner: T,
    faults: Mutex<Faults>,
    state: Mutex<u64>,
}

impl<T: Transport> Faulty<T> {
    pub fn new(inner: T, faults: Faults, seed: u64) -> Self {
        Faulty {
            inner,
            faults: Mutex::new(faults),
            state: Mutex::new(seed),
        }
    }

    /// Changes the fault rates (e.g. `Faults::NONE` to let everything heal).
    pub fn set_faults(&self, faults: Faults) {
        *self.faults.lock().unwrap() = faults;
    }

    /// SplitMix64.
    fn next(&self) -> u64 {
        let mut s = self.state.lock().unwrap();
        *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn roll(&self, percent: u8) -> bool {
        percent > 0 && self.next() % 100 < u64::from(percent)
    }

    fn faults(&self) -> Faults {
        *self.faults.lock().unwrap()
    }
}

impl<T: Transport> Transport for Faulty<T> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        let f = self.faults();
        let mut out = self.inner.streams()?;
        out.retain(|_| !self.roll(f.hide_stream));
        Ok(out)
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let f = self.faults();
        let mut out = Vec::new();
        for fetched in self.inner.segments(stream, after_seq)? {
            let Fetched::Ready(mut bytes) = fetched else {
                out.push(fetched);
                continue;
            };
            if self.roll(f.omit) {
                continue;
            }
            if self.roll(f.pending) {
                out.push(Fetched::Pending);
                continue;
            }
            if self.roll(f.truncate) {
                let keep = (self.next() as usize) % bytes.len();
                bytes.truncate(keep);
            } else if self.roll(f.flip) {
                let bit = (self.next() as usize) % (bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
            if self.roll(f.duplicate) {
                out.push(Fetched::Ready(bytes.clone()));
            }
            out.push(Fetched::Ready(bytes));
        }
        if self.roll(f.shuffle) {
            for i in (1..out.len()).rev() {
                let j = (self.next() as usize) % (i + 1);
                out.swap(i, j);
            }
        }
        Ok(out)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        self.inner.head(stream)
    }

    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        self.inner.headers()
    }

    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put_header(name, bytes)
    }

    fn delete_header(&self, name: &str) -> Result<()> {
        self.inner.delete_header(name)
    }

    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        self.inner.snapshots()
    }

    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.inner.get_snapshot(name)
    }

    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        self.inner.put_snapshot(bytes)
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        self.inner.delete_snapshot(name)
    }

    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        self.inner.delete_segment(stream, first_seq)
    }

    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        self.inner.root_head_file()
    }

    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.inner.put_root_head_file(bytes)
    }

    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        self.inner.put_chunk(bytes)
    }

    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.inner.get_chunk(name)
    }

    fn begin_round(&self) {
        self.inner.begin_round()
    }

    fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
        self.inner.chunk_state(name)
    }

    fn end_round(&self) {
        self.inner.end_round()
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        let f = self.faults();
        if self.roll(f.fail_before_append) {
            return Err(Error::Transport("append failed".into()));
        }
        let outcome = self.inner.append(segment)?;
        if self.roll(f.fail_after_append) {
            return Err(Error::Transport("append outcome lost".into()));
        }
        Ok(outcome)
    }
}

/// A store that went back in time for one stream: segments after `keep_through` are gone
/// (a restored backup, a sync client that lost files). Appends still go through.
pub struct Rollback<T> {
    pub inner: T,
    pub stream: DeviceId,
    pub keep_through: u64,
}

impl<T: Transport> Transport for Rollback<T> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        self.inner.streams()
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let all = self.inner.segments(stream, after_seq)?;
        if *stream != self.stream {
            return Ok(all);
        }
        Ok(all
            .into_iter()
            .filter(|f| match f {
                Fetched::Ready(b) => crate::segment::SegmentHeader::parse(b)
                    .is_ok_and(|h| h.last_seq <= self.keep_through),
                _ => true,
            })
            .collect())
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.inner.append(segment)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        let head = self.inner.head(stream)?;
        Ok(if *stream == self.stream {
            head.map(|h| h.min(self.keep_through)).filter(|h| *h > 0)
        } else {
            head
        })
    }

    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        self.inner.headers()
    }

    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put_header(name, bytes)
    }

    fn delete_header(&self, name: &str) -> Result<()> {
        self.inner.delete_header(name)
    }

    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        self.inner.snapshots()
    }

    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.inner.get_snapshot(name)
    }

    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        self.inner.put_snapshot(bytes)
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        self.inner.delete_snapshot(name)
    }

    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        self.inner.delete_segment(stream, first_seq)
    }

    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        self.inner.root_head_file()
    }

    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.inner.put_root_head_file(bytes)
    }

    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        self.inner.put_chunk(bytes)
    }

    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.inner.get_chunk(name)
    }

    fn begin_round(&self) {
        self.inner.begin_round()
    }

    fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
        self.inner.chunk_state(name)
    }

    fn end_round(&self) {
        self.inner.end_round()
    }
}

/// A store that shows one stream from another store: one side of a fork (two histories of
/// one device, e.g. a cloned Mac), as a store that keeps devices partitioned would.
pub struct Overlay<T, U> {
    pub base: T,
    pub overlay: U,
    pub stream: DeviceId,
}

impl<T: Transport, U: Transport> Transport for Overlay<T, U> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        let mut streams = self.base.streams()?;
        if !streams.contains(&self.stream) {
            streams.push(self.stream);
        }
        Ok(streams)
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        if *stream == self.stream {
            self.overlay.segments(stream, after_seq)
        } else {
            self.base.segments(stream, after_seq)
        }
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.base.append(segment)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        if *stream == self.stream {
            self.overlay.head(stream)
        } else {
            self.base.head(stream)
        }
    }
    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        self.base.headers()
    }

    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.base.put_header(name, bytes)
    }

    fn delete_header(&self, name: &str) -> Result<()> {
        self.base.delete_header(name)
    }

    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        self.base.snapshots()
    }

    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.base.get_snapshot(name)
    }

    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        self.base.put_snapshot(bytes)
    }

    fn delete_snapshot(&self, name: &str) -> Result<()> {
        self.base.delete_snapshot(name)
    }

    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
        self.base.delete_segment(stream, first_seq)
    }

    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        self.base.root_head_file()
    }

    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.base.put_root_head_file(bytes)
    }

    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        self.base.put_chunk(bytes)
    }

    fn get_chunk(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.base.get_chunk(name)
    }

    fn begin_round(&self) {
        self.base.begin_round()
    }

    fn chunk_state(&self, name: &str) -> Result<Fetched<()>> {
        self.base.chunk_state(name)
    }

    fn end_round(&self) {
        self.base.end_round()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::segment::{chain_genesis, seal_segment, StreamPosition};
    use crate::transport::MemoryTransport;
    use ed25519_dalek::SigningKey;
    use keyorra_core::crypto::Key;

    const D: DeviceId = [1; 16];

    fn store(n: u64) -> MemoryTransport {
        let t = MemoryTransport::new();
        let mut rng = rand::rngs::OsRng;
        for seq in 1..=n {
            let at = StreamPosition {
                device_id: D,
                first_seq: seq,
                prev_hash: chain_genesis(&[0; 16], &D),
            };
            let seg = seal_segment(
                &Key::from_bytes([1; 32]),
                &SigningKey::from_bytes(&[2; 32]),
                &at,
                vec![Value::Uint(seq)],
                &mut rng,
            )
            .unwrap();
            t.append(&seg).unwrap();
        }
        t
    }

    #[test]
    fn no_faults_is_transparent() {
        let t = store(5);
        let f = Faulty::new(t.clone(), Faults::NONE, 1);
        assert_eq!(f.segments(&D, 0).unwrap(), t.segments(&D, 0).unwrap());
        assert_eq!(f.streams().unwrap(), vec![D]);
    }

    #[test]
    fn same_seed_same_faults() {
        let t = store(20);
        let a = Faulty::new(t.clone(), Faults::CHAOS, 42);
        let b = Faulty::new(t, Faults::CHAOS, 42);
        for _ in 0..5 {
            assert_eq!(a.segments(&D, 0).unwrap(), b.segments(&D, 0).unwrap());
        }
    }

    #[test]
    fn chaos_produces_every_kind_of_damage() {
        let t = store(20);
        let clean = t.segments(&D, 0).unwrap();
        let f = Faulty::new(t, Faults::CHAOS, 7);
        let (mut pending, mut damaged, mut duplicated, mut short) = (0, 0, 0, 0);
        for _ in 0..50 {
            let got = f.segments(&D, 0).unwrap();
            short += usize::from(got.len() < clean.len());
            duplicated += usize::from(got.len() > clean.len());
            for g in &got {
                match g {
                    Fetched::Pending => pending += 1,
                    Fetched::Ready(b) if !clean.contains(&Fetched::Ready(b.clone())) => {
                        damaged += 1
                    }
                    _ => {}
                }
            }
        }
        assert!(pending > 0 && damaged > 0 && duplicated > 0 && short > 0);
    }

    #[test]
    fn rollback_hides_later_segments_and_lowers_the_head() {
        let r = Rollback {
            inner: store(5),
            stream: D,
            keep_through: 3,
        };
        assert_eq!(r.segments(&D, 0).unwrap().len(), 3);
        assert_eq!(r.head(&D).unwrap(), Some(3));
    }

    #[test]
    fn overlay_shows_one_stream_from_elsewhere() {
        let o = Overlay {
            base: MemoryTransport::new(),
            overlay: store(2),
            stream: D,
        };
        assert_eq!(o.streams().unwrap(), vec![D]);
        assert_eq!(o.segments(&D, 0).unwrap().len(), 2);
        assert_eq!(o.head(&D).unwrap(), Some(2));
    }

    #[test]
    fn appends_can_fail_before_or_after_landing() {
        let t = MemoryTransport::new();
        let seg = store(1).segments(&D, 0).unwrap().remove(0);
        let Fetched::Ready(seg) = seg else { panic!() };
        let before = Faulty::new(
            t.clone(),
            Faults {
                fail_before_append: 100,
                ..Faults::NONE
            },
            1,
        );
        assert!(before.append(&seg).is_err());
        assert!(t.streams().unwrap().is_empty());
        let after = Faulty::new(
            t.clone(),
            Faults {
                fail_after_append: 100,
                ..Faults::NONE
            },
            1,
        );
        assert!(after.append(&seg).is_err());
        assert_eq!(t.streams().unwrap(), vec![D]);
    }
}
