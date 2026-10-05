//! The sync engine of one device: local writes, pulling other devices' streams into the fold,
//! materialising conflict copies, and pushing its own stream (spec §4.1–4.4, without the trust
//! layer). Plan A1c adds endorsement and revocation (through [`Directory`] and
//! [`Admission`](crate::fold::Admission)), checkpoints, causal delivery, headers, snapshots
//! and clone detection.
//!
//! Deliberate A1b limitations (each with its successor):
//! - A segment that has to wait (a vault key from another stream, another device's earlier
//!   writes) stalls its whole stream. A1c: causal delivery buffers per record, so independent
//!   records keep flowing.
//! - A sealed segment that is not yet confirmed lives only in memory; after a crash the
//!   engine would reseal with a new nonce and the transport would answer `Conflict`. A1d
//!   persists the outbox and the sealed bytes in the store before calling `append`, and
//!   retries the same bytes after a restart.
//! - After `OwnStreamConflict` the engine stops pushing and keeps its unsent writes (it never
//!   becomes idle). A1c's clone detection retires the device id, rejoins under a new one and
//!   re-queues those writes.
//! - A rejected stream is blocked for this engine's lifetime only. A1c makes rejections
//!   persistent alarms tied to the device's trust state.
//! - Item writes do not carry the version the user started editing from; an edit replaces
//!   whatever is visible at that moment. A3's editor passes its base and asks before
//!   overwriting a change that arrived meanwhile.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key};
use keyorra_core::model::SCHEMA_VERSION;
use rand::{CryptoRng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::clock::{Hlc, Observed};
use crate::envelope::{Envelope, RecordKind};
use crate::error::{Error, Result};
use crate::fold::{Accepted, Admission, AdmitAll, Fold, View};
use crate::keys::segment_key;
use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::present::{present_item, present_vault, ItemState};
use crate::segment::{
    chain, chain_genesis, open_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::{AccountId, DeviceId};

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;

/// Whose signatures count. Plan A1c derives it from endorsements; tests use a fixed map.
pub trait Directory {
    fn verifying_key(&self, device: &DeviceId) -> Option<VerifyingKey>;
}

#[derive(Clone, Debug, Default)]
pub struct StaticDirectory(pub BTreeMap<DeviceId, VerifyingKey>);

impl Directory for StaticDirectory {
    fn verifying_key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.0.get(device).copied()
    }
}

/// What happened, for the Sync log (spec §9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Pulled {
        from: DeviceId,
        versions: usize,
    },
    Pushed {
        versions: usize,
    },
    PushFailed(String),
    /// A segment could not be read (half-synced, damaged); retried next round.
    Unreadable {
        from: DeviceId,
        first_seq: u64,
    },
    /// A segment waits for something (a vault key from another stream, a newer app).
    Waiting {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    /// Listing a stream's segments failed; the other streams are still read.
    ListingFailed {
        from: DeviceId,
        reason: String,
    },
    /// Conflict copies are still owed after materialising (or writing them failed); item
    /// edits are refused until a later round writes them. An alarm.
    MaterializeIncomplete(String),
    /// A signed segment broke the rules; the stream is no longer read. An alarm.
    Rejected {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    ClockAhead {
        from: DeviceId,
        ahead_ms: u64,
    },
    Resolved {
        record: Uuid,
        copies: usize,
    },
    /// Someone else wrote at this device's next position (clone detection is plan A1c).
    OwnStreamConflict,
}

struct Unsent {
    bytes: Vec<u8>,
    versions: usize,
    last_seq: u64,
    last_hash: [u8; 32],
}

enum Stop {
    Wait(String),
    Reject(String),
}

pub struct Engine<R> {
    device: DeviceId,
    signer: SigningKey,
    account_id: AccountId,
    account_key: Key,
    segment_key: Key,
    rng: R,
    hlc: Hlc,
    fold: Fold,
    vault_keys: BTreeMap<Uuid, Key>,
    /// Per other device: last applied (seq, chain hash).
    heads: BTreeMap<DeviceId, (u64, [u8; 32])>,
    blocked: BTreeSet<DeviceId>,
    /// Last own (seq, chain hash) confirmed by the transport.
    sent: (u64, [u8; 32]),
    unsent: Option<Unsent>,
    outbox: Vec<Value>,
    next_seq: u64,
    events: Vec<Event>,
    /// Which stream positions count (plan A1c: endorsement and revocation cuts).
    admission: Box<dyn Admission + Send>,
    /// Set after `OwnStreamConflict`: this device stops pushing (plan A1c retires it).
    halted: bool,
    /// Devices already reported as `ClockAhead`.
    clock_reported: BTreeSet<DeviceId>,
    /// The last stall reported per stream (`Waiting`/`Unreadable`), to report changes only.
    stalls: BTreeMap<DeviceId, Event>,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn new(
        device: DeviceId,
        signer: SigningKey,
        account_id: AccountId,
        account_key: Key,
        rng: R,
    ) -> Self {
        Engine {
            device,
            signer,
            account_id,
            segment_key: segment_key(&account_key, &account_id),
            account_key,
            rng,
            hlc: Hlc::default(),
            fold: Fold::default(),
            vault_keys: BTreeMap::new(),
            heads: BTreeMap::new(),
            blocked: BTreeSet::new(),
            sent: (0, chain_genesis(&account_id, &device)),
            unsent: None,
            outbox: Vec::new(),
            admission: Box::new(AdmitAll),
            halted: false,
            clock_reported: BTreeSet::new(),
            stalls: BTreeMap::new(),
            next_seq: 1,
            events: Vec::new(),
        }
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn view(&self) -> View {
        self.fold.view()
    }

    pub fn fold(&self) -> &Fold {
        &self.fold
    }

    /// Nothing waiting to be pushed.
    pub fn is_idle(&self) -> bool {
        self.outbox.is_empty() && self.unsent.is_none()
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Replaces the admission policy and rebuilds the fold under it (plan A1c calls this when
    /// endorsements or revocations change).
    pub fn set_admission(&mut self, admission: Box<dyn Admission + Send>) {
        self.admission = admission;
        self.fold.refold(&*self.admission);
    }

    /// Reports a stall of `from`'s stream unless the same one was reported last.
    fn stall(&mut self, from: DeviceId, event: Event) {
        if self.stalls.get(&from) != Some(&event) {
            self.stalls.insert(from, event.clone());
            self.events.push(event);
        }
    }

    // ---- local writes ----

    pub fn create_vault(&mut self, name: &str, wall_ms: u64) -> Result<Uuid> {
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let id = uuid::Builder::from_random_bytes(id).into_uuid();
        let mut raw = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut raw[..]);
        let key = Key::from_bytes(*raw);
        let wrapped_key = crypto::wrap_vault_key(&self.account_key, id, &key);
        self.vault_keys.insert(id, key);
        let doc = Doc::Vault(VaultPayload {
            name: name.to_owned(),
            wrapped_key,
            deleted: false,
        });
        self.write(RecordKind::Vault, id, None, doc, wall_ms)?;
        Ok(id)
    }

    pub fn rename_vault(&mut self, id: Uuid, name: &str, wall_ms: u64) -> Result<()> {
        let mut p = self.vault_payload(id)?;
        p.name = name.to_owned();
        self.write(RecordKind::Vault, id, None, Doc::Vault(p), wall_ms)
    }

    /// Deletes an empty vault (as the local store does): refused while it has live items;
    /// items of it in Recently Deleted are purged first.
    pub fn delete_vault(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let mut p = self.vault_payload(id)?;
        let view = self.fold.view();
        let in_vault = |state: ItemState| {
            view.items
                .iter()
                .filter(move |(_, v)| v.state == state && v.vault_id == Some(id))
                .map(|(item, _)| *item)
                .collect::<Vec<_>>()
        };
        let live = in_vault(ItemState::Live);
        if !live.is_empty() {
            return Err(Error::Refused(format!("vault has {} items", live.len())));
        }
        for item in in_vault(ItemState::Trashed) {
            self.write(RecordKind::Item, item, Some(id), Doc::Tombstone, wall_ms)?;
        }
        p.deleted = true;
        self.write(RecordKind::Vault, id, None, Doc::Vault(p), wall_ms)
    }

    /// Creates or edits an item (and makes it live again if it was trashed).
    pub fn save_item(
        &mut self,
        vault_id: Uuid,
        id: Uuid,
        item_json: &[u8],
        wall_ms: u64,
    ) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let doc = Doc::Item(ItemPayload {
            item_json: Zeroizing::new(item_json.to_vec()),
            deleted_at: None,
            content_from: Default::default(), // this write: set by `write_with`
        });
        self.write_with(RecordKind::Item, id, Some(vault_id), doc, wall_ms, true)
    }

    pub fn trash_item(&mut self, id: Uuid, at_secs: u64, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Live)?;
        p.deleted_at = Some(at_secs);
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    pub fn restore_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Trashed)?;
        p.deleted_at = None;
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    /// Permanently deletes an item in Recently Deleted.
    pub fn purge_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, _) = self.item_in_state(id, ItemState::Trashed)?;
        self.write(RecordKind::Item, id, vault_id, Doc::Tombstone, wall_ms)
    }

    /// Adds an attachment record (its chunks are uploaded by the transports' plans).
    /// The caller also saves the item with the new reference.
    pub fn add_attachment(
        &mut self,
        vault_id: Uuid,
        item_id: Uuid,
        name: &str,
        size: u64,
        wall_ms: u64,
    ) -> Result<Uuid> {
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let id = uuid::Builder::from_random_bytes(id).into_uuid();
        let mut key = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut key[..]);
        let doc = Doc::Attachment(AttachmentPayload {
            item_id,
            name: name.to_owned(),
            size,
            key,
            chunk_size: crate::chunk::MAX_CHUNK as u32,
            chunks: Vec::new(),
        });
        self.write(RecordKind::Attachment, id, Some(vault_id), doc, wall_ms)?;
        Ok(id)
    }

    pub fn remove_attachment(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        let vault_id = self
            .fold
            .set(RecordKind::Attachment, id)
            .and_then(|s| s.top())
            .and_then(|s| s.vault_id)
            .ok_or_else(|| Error::NotFound(format!("attachment {id}")))?;
        self.write(
            RecordKind::Attachment,
            id,
            Some(vault_id),
            Doc::Tombstone,
            wall_ms,
        )
    }

    fn vault_payload(&self, id: Uuid) -> Result<VaultPayload> {
        self.fold
            .set(RecordKind::Vault, id)
            .and_then(|s| present_vault(s, false))
            .map(|p| p.payload.clone())
            .ok_or_else(|| Error::NotFound(format!("vault {id}")))
    }

    fn item_in_state(&self, id: Uuid, want: ItemState) -> Result<(Option<Uuid>, ItemPayload)> {
        let set = self
            .fold
            .set(RecordKind::Item, id)
            .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
        let p = present_item(id, set);
        match (p.state == want, p.visible) {
            (true, Some(v)) => match &v.doc {
                Doc::Item(payload) => {
                    let mut payload = payload.clone();
                    if payload.content_from.is_empty() {
                        // A copy as first written: its content originates in that version.
                        payload.content_from = v.version.vector.clone();
                    }
                    Ok((v.vault_id, payload))
                }
                _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
            },
            _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
        }
    }

    /// A write that keeps the payload's `content_from` (trash, restore, collapse, and copies
    /// as first written, whose empty `content_from` marks them; spec §3.5).
    fn write(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
    ) -> Result<()> {
        self.write_with(kind, id, vault_id, doc, wall_ms, false)
    }

    /// `edit`: the item's content changes here, so `content_from` becomes the new version.
    fn write_with(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
        edit: bool,
    ) -> Result<()> {
        let hlc = self.hlc.tick(wall_ms);
        let version = self.fold.next_version(kind, id, self.device, hlc);
        let mut doc = doc;
        if let Doc::Item(p) = &mut doc {
            if edit {
                p.content_from = version.vector.clone();
            }
        }
        let mut envelope = Envelope {
            kind,
            record_id: id,
            vault_id,
            schema: SCHEMA_VERSION,
            version: version.clone(),
            tombstone: doc == Doc::Tombstone,
            body: None,
        };
        match &doc {
            Doc::Tombstone => {}
            Doc::Vault(_) => envelope.body = Some(doc.encode().to_vec()),
            Doc::Item(_) | Doc::Attachment(_) => {
                let vault = vault_id.ok_or_else(|| Error::NotFound("vault id".into()))?;
                let key = self
                    .vault_keys
                    .get(&vault)
                    .ok_or_else(|| Error::NotFound(format!("key of vault {vault}")))?;
                envelope.seal_body(key, &self.account_id, &doc.encode(), &mut self.rng);
            }
        }
        envelope.check()?;
        let accepted = Accepted {
            stream: self.device,
            seq: self.next_seq,
            kind,
            record_id: id,
            vault_id,
            version,
            doc,
        };
        self.fold
            .accept(accepted, &*self.admission)
            .expect("a local write always follows the rules");
        self.outbox
            .push(Value::map(vec![("put", envelope.to_value())]));
        self.next_seq += 1;
        debug_assert_eq!(
            self.next_seq,
            self.unsent.as_ref().map_or(self.sent.0, |u| u.last_seq) + self.outbox.len() as u64 + 1,
            "own sequence numbers out of step"
        );
        Ok(())
    }

    // ---- sync ----

    /// One round: pull everything readable, materialise conflict copies, push. Whatever the
    /// pull managed to apply is always materialised and pushed, even if the transport failed
    /// part of the way (a failed stream listing is only an event); the pull error, if any, is
    /// returned afterwards. Push failures are logged and retried.
    pub fn sync(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        wall_ms: u64,
    ) -> Result<()> {
        let pulled = self.pull(transport, directory, wall_ms);
        self.materialize(wall_ms)?;
        self.push(transport);
        pulled
    }

    fn pull(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        wall_ms: u64,
    ) -> Result<()> {
        let streams: Vec<DeviceId> = transport
            .streams()?
            .into_iter()
            .filter(|d| *d != self.device && !self.blocked.contains(d))
            .collect();
        loop {
            let mut progress = false;
            for stream in &streams {
                match self.pull_stream(transport, directory, stream, wall_ms) {
                    Ok(p) => progress |= p,
                    Err(e) => self.events.push(Event::ListingFailed {
                        from: *stream,
                        reason: e.to_string(),
                    }),
                }
            }
            if !progress {
                return Ok(());
            }
        }
    }

    /// Applies every segment of `stream` that is next in line. Returns whether any was applied.
    fn pull_stream(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> Result<bool> {
        if self.blocked.contains(stream) {
            return Ok(false);
        }
        let Some(author) = directory.verifying_key(stream) else {
            return Ok(false);
        };
        let (mut head_seq, mut head_hash) = self
            .heads
            .get(stream)
            .copied()
            .unwrap_or((0, chain_genesis(&self.account_id, stream)));
        let mut candidates: Vec<(u64, Vec<u8>)> = transport
            .segments(stream, head_seq)?
            .into_iter()
            .filter_map(|f| match f {
                Fetched::Ready(b) => Some(b),
                Fetched::Pending | Fetched::Missing => None,
            })
            .filter_map(|b| {
                let h = SegmentHeader::parse(&b).ok()?;
                (h.device_id == *stream && h.first_seq > head_seq).then_some((h.first_seq, b))
            })
            .collect();
        candidates.sort_by_key(|(seq, _)| *seq);
        let mut applied = false;
        loop {
            let want = head_seq + 1;
            let mut opened = None;
            let mut tried = false;
            for (_, bytes) in candidates.iter().filter(|(s, _)| *s == want) {
                tried = true;
                if let Ok(seg) = open_segment(&self.segment_key, &author, bytes) {
                    opened = Some(seg);
                    break;
                }
            }
            let Some(segment) = opened else {
                if tried {
                    self.stall(
                        *stream,
                        Event::Unreadable {
                            from: *stream,
                            first_seq: want,
                        },
                    );
                }
                return Ok(applied);
            };
            if segment.header.prev_hash != head_hash {
                self.stall(
                    *stream,
                    Event::Waiting {
                        from: *stream,
                        first_seq: want,
                        reason: "chain does not continue from the known head".into(),
                    },
                );
                return Ok(applied);
            }
            match self.decode_segment(stream, &segment.header, &segment.entries) {
                Ok((batch, keys)) => {
                    let ready = match self.fold.missing_dependency(&batch) {
                        Ok(ready) => ready,
                        Err(rejection) => {
                            self.reject(stream, want, rejection.to_string());
                            return Ok(applied);
                        }
                    };
                    if let Some(device) = ready {
                        self.stall(
                            *stream,
                            Event::Waiting {
                                from: *stream,
                                first_seq: want,
                                reason: format!(
                                    "needs earlier changes from {}",
                                    data_encoding::HEXLOWER.encode(&device[..4])
                                ),
                            },
                        );
                        return Ok(applied);
                    }
                    let observed: Vec<u64> = batch.iter().map(|a| a.version.hlc).collect();
                    match self.fold.accept_batch(batch, &*self.admission) {
                        Ok(n) => {
                            self.vault_keys.extend(keys);
                            for hlc in observed {
                                if let Observed::TooFarAhead { ahead_ms } =
                                    self.hlc.observe(hlc, wall_ms)
                                {
                                    if self.clock_reported.insert(*stream) {
                                        self.events.push(Event::ClockAhead {
                                            from: *stream,
                                            ahead_ms,
                                        });
                                    }
                                }
                            }
                            self.events.push(Event::Pulled {
                                from: *stream,
                                versions: n,
                            });
                        }
                        Err(rejection) => {
                            self.reject(stream, want, rejection.to_string());
                            return Ok(applied);
                        }
                    }
                }
                Err(Stop::Wait(reason)) => {
                    self.stall(
                        *stream,
                        Event::Waiting {
                            from: *stream,
                            first_seq: want,
                            reason,
                        },
                    );
                    return Ok(applied);
                }
                Err(Stop::Reject(reason)) => {
                    self.reject(stream, want, reason);
                    return Ok(applied);
                }
            }
            head_seq = segment.header.last_seq;
            head_hash = segment.header.last_hash;
            self.heads.insert(*stream, (head_seq, head_hash));
            self.stalls.remove(stream);
            applied = true;
        }
    }

    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        self.events.push(Event::Rejected {
            from: *stream,
            first_seq,
            reason,
        });
    }

    /// Decodes a segment's entries; vault keys learned on the way are returned, not stored, so
    /// nothing changes unless the whole segment is accepted.
    #[allow(clippy::type_complexity)]
    fn decode_segment(
        &self,
        stream: &DeviceId,
        header: &SegmentHeader,
        entries: &[Value],
    ) -> std::result::Result<(Vec<Accepted>, Vec<(Uuid, Key)>), Stop> {
        let mut batch = Vec::new();
        let mut keys: Vec<(Uuid, Key)> = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            let put = entry
                .fields(&["put"])
                .and_then(|f| f.get("put").cloned())
                .map_err(|_| Stop::Reject("unknown entry".into()))?;
            let env = match Envelope::from_value(&put) {
                Ok(env) => env,
                Err(Error::Unsupported(what)) => {
                    return Err(Stop::Wait(format!("needs a newer app: {what}")))
                }
                Err(e) => return Err(Stop::Reject(e.to_string())),
            };
            let doc = if env.tombstone {
                Doc::Tombstone
            } else if env.kind == RecordKind::Vault {
                let body = env.body.as_deref().unwrap_or_default();
                let doc = Doc::decode(RecordKind::Vault, body)
                    .map_err(|e| Stop::Reject(e.to_string()))?;
                if let Doc::Vault(p) = &doc {
                    let key =
                        crypto::unwrap_vault_key(&self.account_key, env.record_id, &p.wrapped_key)
                            .map_err(|_| Stop::Reject("vault key does not unwrap".into()))?;
                    keys.push((env.record_id, key));
                }
                doc
            } else {
                let vault = env.vault_id.expect("checked by Envelope::from_value");
                let key = keys
                    .iter()
                    .rev()
                    .find(|(id, _)| *id == vault)
                    .map(|(_, k)| k)
                    .or_else(|| self.vault_keys.get(&vault))
                    .ok_or_else(|| Stop::Wait(format!("key of vault {vault} not known yet")))?;
                let plain = env
                    .open_body(key, &self.account_id)
                    .map_err(|_| Stop::Reject("body does not open".into()))?;
                Doc::decode(env.kind, &plain).map_err(|e| Stop::Reject(e.to_string()))?
            };
            batch.push(Accepted {
                stream: *stream,
                seq: header.first_seq + i as u64,
                kind: env.kind,
                record_id: env.record_id,
                vault_id: env.vault_id,
                version: env.version,
                doc,
            });
        }
        Ok((batch, keys))
    }

    /// Writes the conflict copies, and the attachment records they need, that the fold asks
    /// for (spec §3.5). Each pass removes what it wrote from the next view. If copies are still
    /// owed afterwards, or a write fails, `Event::MaterializeIncomplete` is raised and item
    /// edits are refused until a later round succeeds.
    fn materialize(&mut self, wall_ms: u64) -> Result<()> {
        let result = self.materialize_passes(wall_ms);
        match &result {
            Ok(true) => {}
            Ok(false) => self.events.push(Event::MaterializeIncomplete(
                "conflict copies still owed after materialising".into(),
            )),
            Err(e) => self
                .events
                .push(Event::MaterializeIncomplete(e.to_string())),
        }
        result.map(|_| ())
    }

    /// Returns whether nothing is owed any more.
    fn materialize_passes(&mut self, wall_ms: u64) -> Result<bool> {
        for _ in 0..4 {
            let view = self.fold.view();
            if !view.owes_copies() {
                return Ok(true);
            }
            for copy in view.orphan_copies {
                let doc = Doc::Item(copy.payload);
                self.write(RecordKind::Item, copy.copy_id, copy.vault_id, doc, wall_ms)?;
            }
            for r in view.resolutions {
                for copy in &r.copies {
                    let doc = Doc::Item(copy.payload.clone());
                    self.write(RecordKind::Item, copy.copy_id, copy.vault_id, doc, wall_ms)?;
                }
                self.write(
                    RecordKind::Item,
                    r.record_id,
                    r.vault_id,
                    r.collapse,
                    wall_ms,
                )?;
                self.events.push(Event::Resolved {
                    record: r.record_id,
                    copies: r.copies.len(),
                });
            }
            for a in view.attachment_copies {
                let doc = Doc::Attachment(a.payload);
                self.write(RecordKind::Attachment, a.id, a.vault_id, doc, wall_ms)?;
            }
        }
        let view = self.fold.view();
        Ok(!view.owes_copies())
    }

    /// Item edits first write any conflict copies the fold owes, so an edit can never
    /// collapse a conflict whose losing side has no copy yet; if that fails, the edit is
    /// refused.
    fn settle_before_edit(&mut self, wall_ms: u64) -> Result<()> {
        if self.materialize_passes(wall_ms)? {
            Ok(())
        } else {
            Err(Error::Refused(
                "conflict copies are still being written; try again".into(),
            ))
        }
    }

    fn push(&mut self, transport: &impl Transport) {
        if self.halted {
            return;
        }
        loop {
            if self.unsent.is_none() {
                if self.outbox.is_empty() {
                    return;
                }
                let take = self.outbox.len().min(MAX_ENTRIES_PER_SEGMENT);
                let entries: Vec<Value> = self.outbox.drain(..take).collect();
                let at = StreamPosition {
                    device_id: self.device,
                    first_seq: self.sent.0 + 1,
                    prev_hash: self.sent.1,
                };
                let last_hash = chain(&at.prev_hash, &entries);
                let versions = entries.len();
                let bytes =
                    seal_segment(&self.segment_key, &self.signer, &at, entries, &mut self.rng)
                        .expect("own entries fit a segment");
                self.unsent = Some(Unsent {
                    bytes,
                    versions,
                    last_seq: at.first_seq + versions as u64 - 1,
                    last_hash,
                });
            }
            let unsent = self.unsent.as_ref().expect("set above");
            match transport.append(&unsent.bytes) {
                Ok(AppendOutcome::Appended | AppendOutcome::AlreadyThere) => {
                    self.sent = (unsent.last_seq, unsent.last_hash);
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                }
                Ok(AppendOutcome::Conflict) => {
                    // Someone else wrote at this device's next position: a clone or a
                    // restored copy of this device. Stop writing; plan A1c retires the id.
                    self.halted = true;
                    self.events.push(Event::OwnStreamConflict);
                    return;
                }
                Err(e) => {
                    self.events.push(Event::PushFailed(e.to_string()));
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
