//! Stub until Task 8 (account headers and the main device's head file).

use super::*;

impl<R: RngCore + CryptoRng> Engine<R> {
    pub(super) fn note_header_entry(&mut self, _: DeviceId, _: u64, _: &Entry) {}
    pub(super) fn adopt_header(&mut self, _: u64) {}
    pub(super) fn delete_old_headers(&mut self, _: &impl Transport) {}
    pub(super) fn upload_header_files(&mut self, _: &impl Transport) {}
    pub(super) fn write_root_head_file(&mut self, _: &impl Transport) {}
    pub(super) fn read_root_head_file(&mut self, _: &impl Transport) {}
}
