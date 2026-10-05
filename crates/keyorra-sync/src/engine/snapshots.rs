//! Snapshots (spec §4.8): written after many entries, after a week, after a removal, and on
//! restore; used to bootstrap a device that has nothing yet, and to anchor a stream whose
//! segments the store lost (a rollback that someone restored).
//!
//! Under root-only authority (spec §4.3) what a snapshot may vouch for depends on its author:
//! - a device bootstraps only from a snapshot of the **main device** (verified with the root
//!   key from the account header), since only the root's word covers trust and other devices'
//!   records;
//! - a snapshot of the main device anchors any stream it covers; a snapshot of another
//!   (approved) device anchors only that device's own stream ("Restore from this Mac" of a
//!   rolled-back own stream).
//!
//! A snapshot is chained into its author's log by a `Snapshot` entry written right after it.
//! A device that started from a snapshot checks that entry in the author's next segments; a
//! snapshot that its author's log never mentions is treated as a fork.

use crate::pack::{check_entries, SnapshotBody};
use crate::snapshot::{decrypt_snapshot, seal_snapshot};

use super::*;

/// A snapshot is due after this many new entries…
pub const SNAPSHOT_EVERY_ENTRIES: u64 = 500;
/// …or this long after the last one.
pub const SNAPSHOT_EVERY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Own snapshots kept in the store (older ones are deleted).
const KEEP_OWN_SNAPSHOTS: usize = 2;
/// The author's `Snapshot` entry must appear within this many segments after the frontier.
const SNAPSHOT_ENTRY_WITHIN: u64 = 3;

/// The snapshot this device started from (or anchored on), until its author's log confirms it.
#[derive(Clone, Debug)]
pub(super) struct SnapshotRef {
    author: DeviceId,
    name: [u8; 32],
    after_seq: u64,
    segments: u64,
}

fn name_bytes(name: &str) -> Option<[u8; 32]> {
    data_encoding::HEXLOWER
        .decode(name.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub(super) fn snapshot_due(&mut self, wall_ms: u64) -> bool {
        let Some(last) = self.last_snapshot_ms else {
            self.last_snapshot_ms = Some(wall_ms);
            return false;
        };
        self.entries_since_snapshot >= SNAPSHOT_EVERY_ENTRIES
            || self.revoked_since_snapshot
            || wall_ms >= last + SNAPSHOT_EVERY_MS
    }

    /// Writes a snapshot of everything this device has received and confirmed, stores it,
    /// and chains it into the own stream. Returns its name.
    pub fn write_snapshot(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<String> {
        self.require_writable()?;
        let mut frontier = self.heads.clone();
        frontier.insert(self.device, self.sent);
        let within = |d: &DeviceId, s: u64| frontier.get(d).is_some_and(|h| s <= h.seq);
        let root = self.trust.root();
        let mut entries: Vec<(DeviceId, u64, Entry)> = self
            .root_log
            .iter()
            .filter(|(s, _)| within(&root, *s))
            .map(|(s, e)| (root, *s, e.clone()))
            .collect();
        entries.extend(
            self.header_entries
                .iter()
                .filter(|(s, _)| within(&root, *s))
                .map(|(s, h)| (root, *s, Entry::Header(h.clone()))),
        );
        entries.extend(
            self.header_seen
                .iter()
                .filter(|(d, s, _)| within(d, *s))
                .map(|(d, s, e)| (*d, *s, Entry::HeaderSeen { epoch: *e })),
        );
        entries.sort_by_key(|(d, s, _)| (*d, *s));
        let admitted: Vec<Accepted> = self
            .fold
            .retained()
            .filter(|a| self.trust.admits(&a.stream, a.seq) && within(&a.stream, a.seq))
            .cloned()
            .collect();
        let mut versions = Vec::with_capacity(admitted.len());
        for a in admitted {
            versions.push((a.stream, a.seq, self.reseal(&a)?));
        }
        let body = SnapshotBody {
            account_id: self.account_id,
            floors: frontier.iter().map(|(d, h)| (*d, h.seq)).collect(),
            frontier: frontier.clone(),
            entries,
            versions,
        };
        let bytes = seal_snapshot(
            &self.segment_key,
            &self.signer,
            self.device,
            body.to_value(),
            &mut self.rng,
        )?;
        let name = transport.put_snapshot(&bytes)?;
        let name_raw =
            name_bytes(&name).ok_or_else(|| Error::Transport("bad snapshot name".into()))?;
        self.write_entry(
            Entry::Snapshot {
                name: name_raw,
                frontier,
            },
            wall_ms,
        )?;
        self.own_snapshots.push(name.clone());
        while self.own_snapshots.len() > KEEP_OWN_SNAPSHOTS {
            let old = self.own_snapshots.remove(0);
            let _ = transport.delete_snapshot(&old);
        }
        self.entries_since_snapshot = 0;
        self.last_snapshot_ms = Some(wall_ms);
        self.revoked_since_snapshot = false;
        self.events
            .push(Event::SnapshotWritten { name: name.clone() });
        Ok(name)
    }

    /// An accepted version as an envelope again (the body re-sealed with a fresh nonce under
    /// the vault's key: the version and its content are what count, not the ciphertext).
    pub(super) fn reseal(&mut self, a: &Accepted) -> Result<Envelope> {
        let mut envelope = Envelope {
            kind: a.kind,
            record_id: a.record_id,
            vault_id: a.vault_id,
            schema: SCHEMA_VERSION,
            version: a.version.clone(),
            tombstone: a.doc == Doc::Tombstone,
            body: None,
        };
        match &a.doc {
            Doc::Tombstone => {}
            Doc::Vault(_) => envelope.body = Some(a.doc.encode().to_vec()),
            Doc::Item(_) | Doc::Attachment(_) => {
                let vault = a
                    .vault_id
                    .ok_or_else(|| Error::NotFound("vault id".into()))?;
                let key = self
                    .writer_vault_key(vault)
                    .ok_or_else(|| Error::NotFound(format!("key of vault {vault}")))?;
                envelope.seal_body(&key, &self.account_id, &a.doc.encode(), &mut self.rng);
            }
        }
        Ok(envelope)
    }

    /// Opens and checks a snapshot: this account, entries of the right kinds, signed by its
    /// author with the key this device knows for it, the author admitted at its own frontier
    /// position. Returns the body and the author.
    fn check_snapshot(&self, bytes: &[u8]) -> Option<(SnapshotBody, DeviceId)> {
        let unverified = decrypt_snapshot(&self.segment_key, bytes).ok()?;
        let body = SnapshotBody::from_value(&unverified.body).ok()?;
        if body.account_id != self.account_id || check_entries(&body).is_err() {
            return None;
        }
        let author = unverified.header.author;
        let at = body.frontier.get(&author)?.seq;
        if !self.trust.admits(&author, at) {
            return None;
        }
        let key = self.trust.key(&author)?;
        unverified.verify(&key).ok()?;
        Some((body, author))
    }

    /// The streams a snapshot by `author` may vouch for.
    fn vouches_for(&self, author: &DeviceId, _stream: &DeviceId) -> bool {
        // Only the main device's word covers records of streams other readers rely on: a
        // snapshot of another device could say anything about its own past (review S1).
        *author == self.trust.root()
    }

    /// A device with nothing yet starts from the newest snapshot of the main device it can
    /// verify (the one covering the most). Returns whether it did.
    pub fn bootstrap(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<bool> {
        if !self.heads.is_empty() || self.fold.retained().next().is_some() || self.is_root() {
            return Ok(false);
        }
        let root = self.trust.root();
        let mut best: Option<(u64, String, SnapshotBody)> = None;
        for (name, author) in transport.snapshots()? {
            if author != root {
                continue;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                continue;
            };
            let Some((body, _)) = self.check_snapshot(&bytes) else {
                continue;
            };
            let score = body.frontier.values().map(|h| h.seq).sum::<u64>();
            if best.as_ref().is_none_or(|(s, ..)| score > *s) {
                best = Some((score, name, body));
            }
        }
        let Some((_, name, body)) = best else {
            return Ok(false);
        };
        self.load_snapshot(root, &name, body, None, wall_ms);
        Ok(true)
    }

    /// Fills a gap in `stream` from the snapshot (one that may vouch for it) that covers it
    /// furthest. Returns whether the stream's head moved.
    pub(super) fn anchor_stream(
        &mut self,
        transport: &impl Transport,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> bool {
        let head = self.heads.get(stream).map_or(0, |h| h.seq);
        let Ok(listing) = transport.snapshots() else {
            return false;
        };
        let mut best: Option<(u64, String, DeviceId, SnapshotBody)> = None;
        for (name, author) in listing {
            if !self.vouches_for(&author, stream) {
                continue;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                continue;
            };
            let Some((body, author)) = self.check_snapshot(&bytes) else {
                continue;
            };
            let cover = body.covers(stream).map_or(0, |h| h.seq);
            if cover > head && best.as_ref().is_none_or(|(c, ..)| cover > *c) {
                best = Some((cover, name, author, body));
            }
        }
        let Some((cover, name, author, body)) = best else {
            return false;
        };
        self.load_snapshot(author, &name, body, Some(*stream), wall_ms);
        self.events.push(Event::Anchored {
            stream: *stream,
            seq: cover,
            by: author,
        });
        true
    }

    /// Whether a snapshot that may vouch for `stream` covers it up to `seq` (a rollback of it
    /// loses nothing).
    pub(super) fn snapshot_covers(
        &self,
        transport: &impl Transport,
        stream: &DeviceId,
        seq: u64,
    ) -> bool {
        let Ok(listing) = transport.snapshots() else {
            return false;
        };
        listing.into_iter().any(|(name, author)| {
            if !self.vouches_for(&author, stream) {
                return false;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                return false;
            };
            self.check_snapshot(&bytes)
                .and_then(|(body, _)| body.covers(stream))
                .is_some_and(|h| h.seq >= seq)
        })
    }

    /// Applies a snapshot: the main device's trust and header entries in order, everyone's
    /// header-seen entries, and the versions of the streams it may vouch for (`only`: just
    /// that one stream), whose heads move to its frontier.
    fn load_snapshot(
        &mut self,
        author: DeviceId,
        name: &str,
        body: SnapshotBody,
        only: Option<DeviceId>,
        wall_ms: u64,
    ) {
        let root = self.trust.root();
        let from_root = author == root;
        let wanted = |d: &DeviceId| match only {
            Some(s) => *d == s,
            None => true,
        } && (from_root || *d == author);
        if from_root {
            for (stream, seq, entry) in &body.entries {
                match entry {
                    Entry::Header(_) | Entry::HeaderSeen { .. } => {
                        self.note_header_entry(*stream, *seq, entry)
                    }
                    _ if *stream == root && !self.root_log.iter().any(|(s, _)| s == seq) => {
                        self.apply_root_entry(*seq, entry)
                    }
                    _ => {}
                }
            }
        }
        for (stream, seq, env) in body.versions {
            if !wanted(&stream) {
                continue;
            }
            let known = self.heads.get(&stream).map_or(0, |h| h.seq);
            if seq <= known {
                continue;
            }
            self.lanes
                .entry((stream, (env.kind, env.record_id)))
                .or_default()
                .push_back(Pending {
                    seq,
                    env,
                    doc: None,
                });
            *self.pending_count.entry(stream).or_insert(0) += 1;
        }
        for (device, head) in &body.frontier {
            if *device == self.device || !wanted(device) {
                continue;
            }
            let known = self.heads.get(device).map_or(0, |h| h.seq);
            if head.seq > known {
                self.heads.insert(*device, *head);
                self.hashes
                    .entry(*device)
                    .or_default()
                    .insert(head.seq, head.hash);
            }
        }
        self.apply_pending(wall_ms);
        if author != self.device {
            if let (Some(raw), Some(at)) = (name_bytes(name), body.frontier.get(&author)) {
                self.snapshot_ref = Some(SnapshotRef {
                    author,
                    name: raw,
                    after_seq: at.seq,
                    segments: 0,
                });
            }
        }
    }

    /// Checks a received segment of the author of the snapshot this device started from.
    pub(super) fn confirm_snapshot_ref(
        &mut self,
        stream: &DeviceId,
        first_seq: u64,
        entries: &[(u64, Entry)],
    ) {
        let Some(r) = &mut self.snapshot_ref else {
            return;
        };
        if r.author != *stream || first_seq <= r.after_seq {
            return;
        }
        let name = r.name;
        if entries
            .iter()
            .any(|(_, e)| matches!(e, Entry::Snapshot { name: n, .. } if *n == name))
        {
            self.snapshot_ref = None;
            return;
        }
        r.segments += 1;
        if r.segments >= SNAPSHOT_ENTRY_WITHIN {
            let seq = r.after_seq + 1;
            self.snapshot_ref = None;
            self.raise(Alarm::Fork {
                stream: *stream,
                seq,
            });
        }
    }

    /// "Restore from this Mac" after a rollback alarm about `stream`. The own stream is
    /// restored by appending its lost segments again, byte for byte, so every reader checks
    /// them like any other (signature, chain). Another device's stream is restored only by
    /// the main device, with a snapshot (its word covers other devices' records).
    pub fn restore(
        &mut self,
        transport: &impl Transport,
        stream: DeviceId,
        wall_ms: u64,
    ) -> Result<()> {
        let Some(alarm) = self
            .alarms
            .iter()
            .find(|a| matches!(a, Alarm::Rollback { stream: s, .. } if *s == stream))
            .cloned()
        else {
            return Err(Error::Refused(
                "there is no rollback of that stream to restore".into(),
            ));
        };
        let Alarm::Rollback { stored, .. } = alarm else {
            unreachable!("filtered above")
        };
        if stream == self.device {
            let lost: Vec<Vec<u8>> = self
                .own_segments
                .range(stored + 1..)
                .map(|(_, b)| b.clone())
                .collect();
            // Positions are segment ends: the first lost segment starts right after `stored`.
            let have_all = self.own_segments.contains_key(&(stored + 1));
            if !have_all {
                return Err(Error::Refused(
                    "this device no longer has its lost changes; restore on the main device".into(),
                ));
            }
            for bytes in lost {
                transport.append(&bytes)?;
            }
            self.alarms.retain(|a| *a != alarm);
            self.push(transport);
            return Ok(());
        }
        if !self.is_root() {
            return Err(Error::Refused(
                "only the main device can restore another device's changes".into(),
            ));
        }
        self.alarms.retain(|a| *a != alarm);
        self.acknowledged_rollbacks.insert((stream, stored));
        self.write_snapshot(transport, wall_ms)?;
        self.push(transport);
        Ok(())
    }
}
