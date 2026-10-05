//! The sync engine of one device: local writes, pulling other devices' streams into the fold,
//! materialising conflict copies, and pushing its own stream (spec §4.1–4.4, without the trust
//! layer). Plan A1c adds endorsement and revocation (through [`Directory`] and
//! [`Admission`](crate::fold::Admission)), checkpoints, causal delivery, headers, snapshots
//! and clone detection.

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
use crate::fold::{Accepted, AdmitAll, Fold, View};
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

    pub fn delete_vault(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        let mut p = self.vault_payload(id)?;
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
            content_from: Default::default(), // this write: filled in by `write`
        });
        self.write(RecordKind::Item, id, Some(vault_id), doc, wall_ms)
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
        match (p.state == want, p.visible.map(|v| (&v.doc, v.vault_id))) {
            (true, Some((Doc::Item(payload), vault_id))) => Ok((vault_id, payload.clone())),
            _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
        }
    }

    fn write(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
    ) -> Result<()> {
        let hlc = self.hlc.tick(wall_ms);
        let version = self.fold.next_version(kind, id, self.device, hlc);
        let mut doc = doc;
        if let Doc::Item(p) = &mut doc {
            if p.content_from.is_empty() {
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
            .accept(accepted, &AdmitAll)
            .expect("a local write always follows the rules");
        self.outbox
            .push(Value::map(vec![("put", envelope.to_value())]));
        self.next_seq += 1;
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
                    self.events.push(Event::Unreadable {
                        from: *stream,
                        first_seq: want,
                    });
                }
                return Ok(applied);
            };
            if segment.header.prev_hash != head_hash {
                self.events.push(Event::Waiting {
                    from: *stream,
                    first_seq: want,
                    reason: "chain does not continue from the known head".into(),
                });
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
                        self.events.push(Event::Waiting {
                            from: *stream,
                            first_seq: want,
                            reason: format!(
                                "needs earlier changes from {}",
                                data_encoding::HEXLOWER.encode(&device[..4])
                            ),
                        });
                        return Ok(applied);
                    }
                    let observed: Vec<u64> = batch.iter().map(|a| a.version.hlc).collect();
                    match self.fold.accept_batch(batch, &AdmitAll) {
                        Ok(n) => {
                            self.vault_keys.extend(keys);
                            for hlc in observed {
                                if let Observed::TooFarAhead { ahead_ms } =
                                    self.hlc.observe(hlc, wall_ms)
                                {
                                    self.events.push(Event::ClockAhead {
                                        from: *stream,
                                        ahead_ms,
                                    });
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
                    self.events.push(Event::Waiting {
                        from: *stream,
                        first_seq: want,
                        reason,
                    });
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
            if view.resolutions.is_empty() && view.attachment_copies.is_empty() {
                return Ok(true);
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
        Ok(view.resolutions.is_empty() && view.attachment_copies.is_empty())
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
