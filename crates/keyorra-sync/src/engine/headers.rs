//! Account headers as signed entries of the main device's stream (spec §4.7), and the main
//! device's advertised head.
//!
//! Only the main device publishes headers (a master password change happens there): a header
//! counts only as a `Header` entry of the root's stream, and must name the root and its key.
//! The header file in the store is what a joining device reads before it has any key; it is
//! uploaded once the entry's segment is confirmed. The header in force is the highest epoch.
//! Once every approved device has adopted an epoch (`HeaderSeen`, or the root's own `Header`),
//! older header files are deleted, because an old header still opens the account with the old
//! password.

use crate::root_head::{open_root_head, seal_root_head, RootHead, ROOT_HEAD_FILE};

use super::*;

impl<R: RngCore + CryptoRng> Engine<R> {
    /// The account header in force.
    pub fn current_header(&self) -> Option<&Header> {
        self.header_entries
            .iter()
            .map(|(_, h)| h)
            .max_by_key(|h| h.epoch)
    }

    pub fn header_epoch(&self) -> u32 {
        self.current_header().map_or(0, |h| h.epoch)
    }

    /// Publishes the next account header (creating the account, changing the master
    /// password). Main device only; its epoch must be one more than the current one.
    pub fn publish_header(&mut self, header: Header, wall_ms: u64) -> Result<()> {
        if !self.is_root() {
            return Err(Error::Refused(
                "only the main device publishes account headers".into(),
            ));
        }
        self.require_writable()?;
        self.check_header(&header).map_err(Error::Refused)?;
        let next = self.header_epoch() + 1;
        if header.epoch != next {
            return Err(Error::Refused(format!("the next header epoch is {next}")));
        }
        self.write_entry(Entry::Header(header.clone()), wall_ms)?;
        let seq = self.next_seq - 1;
        self.adopted_epoch = header.epoch;
        let file = HeaderFile::sign(header, self.device, &self.signer);
        self.header_files_out.push((seq, file));
        Ok(())
    }

    pub(super) fn check_header(&self, header: &Header) -> std::result::Result<(), String> {
        if header.account_id != self.account_id {
            return Err("header of another account".into());
        }
        if header.root_device != self.trust.root() {
            return Err("header names another main device".into());
        }
        if header.root_key != self.trust.root_key().to_bytes() {
            return Err("header names another key of the main device".into());
        }
        if header.generation != 1 {
            return Err("key generations other than 1 need key rotation (C1)".into());
        }
        if header.epoch == 0 {
            return Err("header epoch 0".into());
        }
        Ok(())
    }

    /// Keeps track of the root's `Header` entries and everyone's `HeaderSeen` entries,
    /// written or received.
    pub(super) fn note_header_entry(&mut self, stream: DeviceId, seq: u64, entry: &Entry) {
        match entry {
            Entry::Header(h) if stream == self.trust.root() => {
                if let Err(reason) = self.check_header(h) {
                    self.events.push(Event::TrustEntryIgnored {
                        from: stream,
                        seq,
                        reason,
                    });
                    return;
                }
                if !self.header_entries.iter().any(|(s, _)| *s == seq) {
                    self.header_entries.push((seq, h.clone()));
                }
            }
            Entry::HeaderSeen { epoch }
                if !self
                    .header_seen
                    .iter()
                    .any(|(d, s, _)| *d == stream && *s == seq) =>
            {
                self.header_seen.push((stream, seq, *epoch));
            }
            _ => {}
        }
    }

    /// Adopts a newer header epoch and tells the main device.
    pub(super) fn adopt_header(&mut self, wall_ms: u64) {
        let epoch = self.header_epoch();
        if epoch <= self.adopted_epoch || !self.can_write() {
            return;
        }
        self.adopted_epoch = epoch;
        if !self.is_root() {
            self.events.push(Event::HeaderAdopted { epoch });
            let _ = self.write_entry(Entry::HeaderSeen { epoch }, wall_ms);
        }
    }

    /// The highest epoch every approved device (not removed) has adopted.
    fn epoch_adopted_by_all(&self) -> u32 {
        let adopted = |device: &DeviceId| {
            if *device == self.trust.root() {
                return self.header_epoch();
            }
            self.header_seen
                .iter()
                .filter(|(d, s, _)| d == device && self.trust.admits(d, *s))
                .map(|(_, _, e)| *e)
                .max()
                .unwrap_or(0)
        };
        self.trust
            .devices()
            .iter()
            .filter(|(_, info)| info.cut.is_none())
            .map(|(d, _)| adopted(d))
            .min()
            .unwrap_or(0)
    }

    /// Header files naming another main device raise an alarm (at most a few are listed).
    pub(super) fn check_header_files(&mut self, transport: &impl Transport) {
        const MAX_FOREIGN: usize = 8;
        let Ok(files) = transport.headers() else {
            return;
        };
        let root = self.trust.root();
        let root_key = self.trust.root_key().to_bytes();
        for (_, f) in files {
            let Fetched::Ready(bytes) = f else { continue };
            let Ok(file) = HeaderFile::decode(&bytes) else {
                continue;
            };
            let h = &file.header;
            if h.account_id != self.account_id || (h.root_device == root && h.root_key == root_key)
            {
                continue;
            }
            let alarm = Alarm::ForeignHeader {
                epoch: h.epoch,
                root: h.root_device,
            };
            let open = self
                .alarms
                .iter()
                .filter(|a| matches!(a, Alarm::ForeignHeader { .. }))
                .count();
            if open < MAX_FOREIGN
                && !self.alarms.contains(&alarm)
                && !self.accepted_alarms.contains(&alarm)
            {
                self.events.push(Event::Alarm(alarm.clone()));
                self.alarms.push(alarm);
            }
        }
    }

    /// Deletes header files of epochs that every approved device has moved past.
    pub(super) fn delete_old_headers(&mut self, transport: &impl Transport) {
        let all = self.epoch_adopted_by_all();
        if all <= 1 || all <= self.deleted_below {
            return;
        }
        let Ok(files) = transport.headers() else {
            return;
        };
        for (name, file) in files {
            if let Fetched::Ready(bytes) = file {
                if HeaderFile::decode(&bytes).is_ok_and(|h| h.header.epoch < all) {
                    let _ = transport.delete_header(&name);
                }
            }
        }
        self.deleted_below = all;
    }

    /// Uploads own header files whose entries the store has confirmed.
    pub(super) fn upload_header_files(&mut self, transport: &impl Transport) {
        let confirmed = self.sent.seq;
        let mut waiting = Vec::new();
        for (seq, file) in std::mem::take(&mut self.header_files_out) {
            let uploaded = seq <= confirmed
                && transport
                    .put_header(&file.file_name(), &file.encode())
                    .is_ok();
            if !uploaded {
                waiting.push((seq, file));
            }
        }
        self.header_files_out = waiting;
    }

    /// Whether the header file this device joined with is backed by the root's log entry:
    /// `None` while that is not known yet, `Some(false)` for a forged or mismatching file (an
    /// alarm for A3).
    pub fn header_confirmed(&self, file: &HeaderFile) -> Option<bool> {
        if file.author != self.trust.root() || file.verify(&self.trust.root_key()).is_err() {
            return Some(false);
        }
        let entries: Vec<&Header> = self.header_entries.iter().map(|(_, h)| h).collect();
        if entries.iter().any(|h| **h == file.header) {
            Some(true)
        } else if entries.iter().any(|h| h.epoch == file.header.epoch) {
            Some(false)
        } else {
            None
        }
    }

    /// The main device writes its confirmed head for everyone to compare with: when it moved
    /// or its pending removals changed, and at least daily while online (a heartbeat,
    /// review I1). Every removal travels in it too (reviews F1, G1): a short list.
    pub(super) fn write_root_head_file(&mut self, transport: &impl Transport, wall_ms: u64) {
        if !self.is_root() || self.sent.seq == 0 {
            return;
        }
        let pending: Vec<(u64, Entry)> = self
            .root_log
            .iter()
            // Every removal, not only unconfirmed ones: a keyless deleter who removes the
            // main device's segments from a Revoke on must not hide it (review G1).
            .filter(|(_, e)| matches!(e, Entry::Revoke { .. }))
            .cloned()
            .collect();

        let devices = self
            .trust
            .devices()
            .iter()
            .filter(|(d, info)| **d != self.device && info.cut.is_none())
            .count() as u64;
        let file = RootHead {
            head: self.sent,
            at_ms: wall_ms,
            devices,
            pending,
        };
        let (seq, at, count, approved) = self.root_head_written;
        if seq == self.sent.seq
            && count == file.pending.len()
            && approved == devices
            && wall_ms < at + ROOT_HEARTBEAT_MS
        {
            return;
        }
        let bytes = seal_root_head(&self.account_id, &file, &self.signer);
        if transport.put_root_head_file(&bytes).is_ok() {
            self.root_head_written = (self.sent.seq, wall_ms, file.pending.len(), devices);
        }
    }

    /// Other devices read it (only forward; a bad file is ignored). Pending removals are
    /// applied at once (provisionally; the stream's own entry settles them). If the main
    /// device's time in it has not advanced for a week, a mild warning: it may be switched
    /// off, or the store may be freezing the file (review F3).
    pub(super) fn read_root_head_file(&mut self, transport: &impl Transport, wall_ms: u64) {
        if self.is_root() {
            return;
        }
        let opened = match transport.root_head_file() {
            Ok(Fetched::Ready(bytes)) => {
                open_root_head(&self.account_id, &self.trust.root_key(), &bytes).ok()
            }
            _ => None,
        };
        if let Some(file) = opened {
            self.set_root_head(file.head);
            let received = self.heads.get(&self.trust.root()).map_or(0, |h| h.seq);
            let mut changed = false;
            for (seq, entry) in &file.pending {
                if *seq <= received {
                    continue;
                }
                if let Entry::Revoke {
                    device,
                    last_valid_seq,
                    ..
                } = entry
                {
                    changed |= self.trust.provisional_revoke(*device, *last_valid_seq);
                }
            }
            if changed {
                self.trust_changed();
            }
            if self.root_time.is_none_or(|t| file.at_ms > t.root_ms) {
                self.root_time = Some(RootTime {
                    root_ms: file.at_ms,
                    since_ms: wall_ms,
                    reported: false,
                });
                return;
            }
        }
        let t = self.root_time.get_or_insert(RootTime {
            root_ms: 0,
            since_ms: wall_ms,
            reported: false,
        });
        if !t.reported && wall_ms >= t.since_ms + ROOT_SILENT_AFTER_MS {
            t.reported = true;
            let since_ms = t.since_ms;
            self.events.push(Event::RootSilent { since_ms });
        }
    }

    /// The name of the root head file, for transports that list files.
    pub fn root_head_file_name() -> &'static str {
        ROOT_HEAD_FILE
    }
}
