//! Stub until Task 9 (snapshots).

use super::*;

pub const SNAPSHOT_EVERY_ENTRIES: u64 = 500;
pub const SNAPSHOT_EVERY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub(super) struct SnapshotRef;

impl<R: RngCore + CryptoRng> Engine<R> {
    pub(super) fn snapshot_due(&mut self, _: u64) -> bool {
        false
    }
    pub fn write_snapshot(&mut self, _: &impl Transport, _: u64) -> Result<String> {
        Err(Error::Refused("snapshots come with Task 9".into()))
    }
    pub fn bootstrap(&mut self, _: &impl Transport, _: u64) -> Result<bool> {
        Ok(false)
    }
    pub(super) fn anchor_stream(&mut self, _: &impl Transport, _: &DeviceId, _: u64) -> bool {
        false
    }
    pub(super) fn snapshot_covers(&self, _: &impl Transport, _: &DeviceId, _: u64) -> bool {
        false
    }
    pub(super) fn confirm_snapshot_ref(&mut self, _: &DeviceId, _: u64, _: &[(u64, Entry)]) {}
}
