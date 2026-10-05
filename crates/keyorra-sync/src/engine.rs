//! The sync engine of one device (spec §4): local writes, reading every other device's
//! stream, applying what it carries, materialising conflict copies, and writing its own stream.
//!
//! Reading has two layers. The **log** layer receives segments strictly in order per stream:
//! signature (the key comes from [`Trust`], or from the stream's own first entry for the root
//! and for self-joined devices), chain continuity, checkpoint claims; a segment that does not
//! continue the known head is a fork. The **apply** layer then applies the received entries
//! with per-record buffering: an entry waits only for what it needs (the vault key of its
//! vault, earlier writes of other devices to the same record, earlier entries of its own
//! stream for the same record), so independent records keep flowing (causal delivery).
//!
//! Trust entries (`Genesis`, `SelfJoin`, `Endorse`, `Revoke`) feed [`Trust`], which is also
//! the fold's admission policy: a revocation's cut refolds the state.
//!
//! Rollback (a stream's stored head behind what this device already received) and forks (a
//! segment or a checkpoint that contradicts a received position) raise an [`Alarm`] and pause
//! syncing until the user decides. Checkpoint claims that stay unmet for a day raise
//! [`Event::Withheld`].
//!
//! Deliberate limitations, picked up later: clone detection and retiring the device id,
//! account headers, snapshots, restore after a rollback (plan A1c-2); a persisted outbox and
//! persisted sealed bytes (`OutboxStore` hook, plan A1d); the editor's base version (A3).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key};
use keyorra_core::model::SCHEMA_VERSION;
use rand::{CryptoRng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::clock::{Hlc, Observed};
use crate::entry::{sign_endorsement, Entry, Head, Heads};
use crate::envelope::{Envelope, RecordKind};
use crate::error::{Error, Result};
use crate::fold::{Accepted, Admission, Fold, RecordKey, View};
use crate::keys::segment_key;
use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::present::{present_item, present_vault, ItemState};
use crate::segment::{
    chain, chain_genesis, decrypt_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::trust::Trust;
use crate::{AccountId, DeviceId};

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;
/// A device that only reads still writes a checkpoint this often when its heads moved.
pub const CHECKPOINT_EVERY_MS: u64 = 60 * 60 * 1000;
/// Checkpoint claims unmet for this long are reported as withheld (spec §4.5).
pub const WITHHELD_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// Something that pauses syncing until the user decides (spec §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alarm {
    /// The store holds fewer segments of `stream` than this device already received.
    Rollback {
        stream: DeviceId,
        received: u64,
        stored: u64,
    },
    /// Two different histories of `stream` at `seq`: a segment that does not continue the
    /// received chain, or a checkpoint that disagrees with it.
    Fork { stream: DeviceId, seq: u64 },
}

impl fmt::Display for Alarm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |d: &DeviceId| data_encoding::HEXLOWER.encode(&d[..4]);
        match self {
            Alarm::Rollback {
                stream,
                received,
                stored,
            } => write!(
                f,
                "changes of {} were rolled back: received up to {received}, stored up to {stored}",
                short(stream)
            ),
            Alarm::Fork { stream, seq } => {
                write!(f, "two different histories of {} at {seq}", short(stream))
            }
        }
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
    /// An entry waits for something (a vault key, earlier changes, a newer app).
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
    /// A signed entry broke the rules; the stream is no longer read. An alarm.
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
    /// A device joined with the Emergency Kit, approved by no other device (spec §4.3).
    SelfJoined {
        device: DeviceId,
        name: String,
    },
    /// Other devices claim changes of `from` up to `claimed_seq` that the store has not
    /// delivered for a day.
    Withheld {
        from: DeviceId,
        claimed_seq: u64,
    },
    /// Syncing paused.
    Alarm(Alarm),
    /// Someone else wrote at this device's next position (retiring the id: plan A1c-2).
    OwnStreamConflict,
}

struct Unsent {
    bytes: Vec<u8>,
    versions: usize,
    last_seq: u64,
    last_hash: [u8; 32],
}

/// A received entry that has not been applied yet.
#[derive(Clone, Debug)]
struct Pending {
    stream: DeviceId,
    seq: u64,
    entry: Entry,
}

/// Entries of one stream apply in order within a lane: per record for `Put`, all trust
/// entries together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Record(RecordKey),
    Trust,
}

impl Pending {
    fn lane(&self) -> Lane {
        match &self.entry {
            Entry::Put(env) => Lane::Record((env.kind, env.record_id)),
            _ => Lane::Trust,
        }
    }
}

enum Applied {
    Done,
    Wait(String),
    Reject(String),
}

/// A checkpoint claim of a position not received yet.
#[derive(Clone, Copy, Debug)]
struct Claim {
    head: Head,
    since_ms: u64,
}

pub struct Engine<R> {
    device: DeviceId,
    signer: SigningKey,
    name: String,
    account_id: AccountId,
    account_key: Key,
    segment_key: Key,
    rng: R,
    hlc: Hlc,
    fold: Fold,
    trust: Trust,
    vault_keys: BTreeMap<Uuid, Key>,
    /// Per other device: the last received position.
    heads: Heads,
    /// Per other device: chain hash at the end of every received segment.
    ends: BTreeMap<DeviceId, BTreeMap<u64, [u8; 32]>>,
    /// Received entries waiting to be applied.
    pending: Vec<Pending>,
    claims: BTreeMap<DeviceId, Claim>,
    withheld_reported: BTreeSet<DeviceId>,
    blocked: BTreeSet<DeviceId>,
    /// Last own position confirmed by the transport.
    sent: Head,
    /// Chain hash at the end of every own segment confirmed by the transport.
    own_ends: BTreeMap<u64, [u8; 32]>,
    unsent: Option<Unsent>,
    outbox: Vec<Value>,
    next_seq: u64,
    /// Heads in the last checkpoint this device wrote, and when.
    last_checkpoint: Option<(Heads, u64)>,
    events: Vec<Event>,
    alarm: Option<Alarm>,
    /// Set after `OwnStreamConflict`: this device stops pushing (plan A1c-2 retires it).
    halted: bool,
    clock_reported: BTreeSet<DeviceId>,
    self_join_reported: BTreeSet<DeviceId>,
    /// The last stall reported per stream (`Waiting`/`Unreadable`), to report changes only.
    stalls: BTreeMap<DeviceId, Event>,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    /// The first device of a new account: its stream starts with `Genesis`.
    pub fn create_account(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        rng: R,
        wall_ms: u64,
    ) -> Self {
        let mut engine = Self::join(device, signer, name, account_id, account_key, device, rng);
        let genesis = Entry::Genesis {
            account_id,
            key: engine.signer.verifying_key().to_bytes(),
            name: name.to_owned(),
        };
        engine
            .write_entry(genesis, wall_ms)
            .expect("the first entry of a new account");
        engine
    }

    /// A further device of an existing account (`root` comes from the account header). It
    /// reads what it can, and can write once another device endorses it or after
    /// [`self_join`](Self::self_join).
    pub fn join(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        root: DeviceId,
        rng: R,
    ) -> Self {
        Engine {
            device,
            signer,
            name: name.to_owned(),
            account_id,
            segment_key: segment_key(&account_key, &account_id),
            account_key,
            rng,
            hlc: Hlc::default(),
            fold: Fold::default(),
            trust: Trust::new(account_id, root),
            vault_keys: BTreeMap::new(),
            heads: Heads::new(),
            ends: BTreeMap::new(),
            pending: Vec::new(),
            claims: BTreeMap::new(),
            withheld_reported: BTreeSet::new(),
            blocked: BTreeSet::new(),
            sent: Head {
                seq: 0,
                hash: chain_genesis(&account_id, &device),
            },
            own_ends: BTreeMap::new(),
            unsent: None,
            outbox: Vec::new(),
            next_seq: 1,
            last_checkpoint: None,
            events: Vec::new(),
            alarm: None,
            halted: false,
            clock_reported: BTreeSet::new(),
            self_join_reported: BTreeSet::new(),
            stalls: BTreeMap::new(),
        }
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    pub fn view(&self) -> View {
        self.fold.view()
    }

    pub fn fold(&self) -> &Fold {
        &self.fold
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    /// Nothing waiting to be pushed.
    pub fn is_idle(&self) -> bool {
        self.outbox.is_empty() && self.unsent.is_none()
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Why syncing is paused, if it is.
    pub fn alarm(&self) -> Option<&Alarm> {
        self.alarm.as_ref()
    }

    /// The user looked at the alarm and chose to continue (A3; restoring is plan A1c-2).
    pub fn clear_alarm(&mut self) {
        self.alarm = None;
    }

    /// Whether this device's next entry would count (introduced and not revoked).
    pub fn can_write(&self) -> bool {
        self.trust.admits(&self.device, self.next_seq)
    }

    /// Reports a stall of `from`'s stream unless the same one was reported last.
    fn stall(&mut self, from: DeviceId, event: Event) {
        if self.stalls.get(&from) != Some(&event) {
            self.stalls.insert(from, event.clone());
            self.events.push(event);
        }
    }

    fn raise(&mut self, alarm: Alarm) {
        if self.alarm.is_none() {
            self.events.push(Event::Alarm(alarm.clone()));
            self.alarm = Some(alarm);
        }
    }

    // ---- trust ----

    /// Joins without approval, with the Emergency Kit: the stream's first entry is a
    /// `SelfJoin`, and every other device raises an alarm (spec §4.3).
    pub fn self_join(&mut self, wall_ms: u64) -> Result<()> {
        if self.next_seq != 1 {
            return Err(Error::Refused("self-join must be the first entry".into()));
        }
        let key = self.signer.verifying_key().to_bytes();
        let sig = sign_endorsement(&self.signer, &self.account_id, &self.device, &key);
        let entry = Entry::SelfJoin {
            key,
            name: self.name.clone(),
            sig,
        };
        self.write_entry(entry, wall_ms)
    }

    /// Approves another device (after the code comparison of spec §6.4).
    pub fn endorse(
        &mut self,
        device: DeviceId,
        key: &VerifyingKey,
        name: &str,
        wall_ms: u64,
    ) -> Result<()> {
        self.require_writable()?;
        let key = key.to_bytes();
        let sig = sign_endorsement(&self.signer, &self.account_id, &device, &key);
        let entry = Entry::Endorse {
            device,
            key,
            name: name.to_owned(),
            sig,
        };
        self.write_entry(entry, wall_ms)
    }

    /// Removes a device: its entries after the last position this device received stop
    /// counting everywhere. Revoking this device itself ends its participation.
    pub fn revoke(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        self.require_writable()?;
        let last_valid_seq = if device == self.device {
            self.next_seq - 1
        } else {
            self.heads.get(&device).map_or(0, |h| h.seq)
        };
        let entry = Entry::Revoke {
            device,
            last_valid_seq,
        };
        self.write_entry(entry, wall_ms)
    }

    fn require_writable(&self) -> Result<()> {
        if self.can_write() {
            Ok(())
        } else {
            Err(Error::Refused(
                "this device is not approved, or was removed".into(),
            ))
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
        self.require_writable()?;
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
        let seq = self.reserve_seq(wall_ms);
        let accepted = Accepted {
            stream: self.device,
            seq,
            kind,
            record_id: id,
            vault_id,
            version,
            doc,
        };
        self.fold
            .accept(accepted, &self.trust)
            .expect("a local write always follows the rules");
        self.queue(Entry::Put(envelope));
        Ok(())
    }

    /// Writes a trust entry (recorded at once) or a checkpoint.
    fn write_entry(&mut self, entry: Entry, wall_ms: u64) -> Result<()> {
        // `Genesis` and `SelfJoin` must be the stream's first entry: no checkpoint before them.
        let introduction = matches!(entry, Entry::Genesis { .. } | Entry::SelfJoin { .. });
        let seq = if introduction {
            self.next_seq
        } else {
            self.reserve_seq(wall_ms)
        };
        let key = self.signer.verifying_key();
        let changed = self
            .trust
            .record(self.device, &key, seq, &entry)
            .map_err(|e| Error::Refused(e.to_string()))?;
        if changed {
            self.fold.refold(&self.trust);
        }
        self.queue(entry);
        Ok(())
    }

    /// The sequence number of the next entry, after writing a checkpoint first if what this
    /// device has received changed since its last one: readers learn which heads the entries
    /// that follow were written against.
    fn reserve_seq(&mut self, wall_ms: u64) -> u64 {
        let due = self
            .last_checkpoint
            .as_ref()
            .is_none_or(|(heads, _)| *heads != self.heads);
        if due && !self.heads.is_empty() {
            self.last_checkpoint = Some((self.heads.clone(), wall_ms));
            self.queue(Entry::Checkpoint(self.heads.clone()));
        }
        self.next_seq
    }

    fn queue(&mut self, entry: Entry) {
        self.outbox.push(entry.to_value());
        self.next_seq += 1;
        debug_assert_eq!(
            self.next_seq,
            self.unsent.as_ref().map_or(self.sent.seq, |u| u.last_seq)
                + self.outbox.len() as u64
                + 1,
            "own sequence numbers out of step"
        );
    }

    // ---- sync ----

    /// One round: receive and apply everything readable, materialise conflict copies, push.
    /// Whatever was applied is always materialised and pushed, even if the transport failed
    /// part of the way (a failed stream listing is only an event); the error, if any, is
    /// returned afterwards. While an [`Alarm`] is raised, nothing happens.
    pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        if let Some(alarm) = &self.alarm {
            return Err(Error::Refused(format!("sync paused: {alarm}")));
        }
        let pulled = self.pull(transport, wall_ms);
        if self.alarm.is_none() {
            if self.can_write() {
                self.materialize(wall_ms)?;
                self.checkpoint_if_stale(wall_ms);
            }
            self.push(transport);
        }
        match &self.alarm {
            Some(alarm) => Err(Error::Refused(format!("sync paused: {alarm}"))),
            None => pulled,
        }
    }

    fn checkpoint_if_stale(&mut self, wall_ms: u64) {
        let stale = match &self.last_checkpoint {
            None => true,
            Some((heads, at)) => *heads != self.heads && wall_ms >= at + CHECKPOINT_EVERY_MS,
        };
        if stale && self.outbox.is_empty() && !self.heads.is_empty() {
            self.last_checkpoint = Some((self.heads.clone(), wall_ms));
            self.queue(Entry::Checkpoint(self.heads.clone()));
        }
    }

    fn pull(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        let streams: Vec<DeviceId> = transport
            .streams()?
            .into_iter()
            .filter(|d| *d != self.device && !self.blocked.contains(d))
            .collect();
        for stream in &streams {
            self.check_stored_head(transport, stream);
        }
        loop {
            let mut progress = false;
            for stream in &streams {
                if self.alarm.is_some() {
                    return Ok(());
                }
                match self.receive_stream(transport, stream, wall_ms) {
                    Ok(p) => progress |= p,
                    Err(e) => self.events.push(Event::ListingFailed {
                        from: *stream,
                        reason: e.to_string(),
                    }),
                }
            }
            progress |= self.apply_pending(wall_ms);
            if !progress || self.alarm.is_some() {
                break;
            }
        }
        self.report_withheld(wall_ms);
        Ok(())
    }

    /// Rollback: the store's head of a stream is behind what this device received.
    fn check_stored_head(&mut self, transport: &impl Transport, stream: &DeviceId) {
        let received = self.heads.get(stream).map_or(0, |h| h.seq);
        if received == 0 {
            return;
        }
        if let Ok(stored) = transport.head(stream) {
            let stored = stored.unwrap_or(0);
            if stored < received {
                self.raise(Alarm::Rollback {
                    stream: *stream,
                    received,
                    stored,
                });
            }
        }
    }

    /// Receives every segment of `stream` that continues its chain. Returns whether any was.
    fn receive_stream(
        &mut self,
        transport: &impl Transport,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> Result<bool> {
        let mut head = self.heads.get(stream).copied().unwrap_or(Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, stream),
        });
        let mut candidates: Vec<(u64, Vec<u8>)> = transport
            .segments(stream, head.seq)?
            .into_iter()
            .filter_map(|f| match f {
                Fetched::Ready(b) => Some(b),
                Fetched::Pending | Fetched::Missing => None,
            })
            .filter_map(|b| {
                let h = SegmentHeader::parse(&b).ok()?;
                (h.device_id == *stream && h.first_seq > head.seq).then_some((h.first_seq, b))
            })
            .collect();
        candidates.sort_by_key(|(seq, _)| *seq);
        let mut received = false;
        loop {
            let want = head.seq + 1;
            let mut opened = None;
            let mut tried = false;
            for (_, bytes) in candidates.iter().filter(|(s, _)| *s == want) {
                tried = true;
                let Ok(unverified) = decrypt_segment(&self.segment_key, bytes) else {
                    continue;
                };
                let key = self.trust.key(stream).or_else(|| {
                    // The root and self-joined devices carry their key in their first entry.
                    let first = unverified.entries.first()?;
                    let entry = Entry::from_value(first).ok()?;
                    let own = match &entry {
                        Entry::Genesis { .. } if *stream == self.trust.root() => entry.own_key(),
                        Entry::SelfJoin { .. } => entry.own_key(),
                        _ => None,
                    };
                    (want == 1).then_some(own).flatten()?;
                    VerifyingKey::from_bytes(&own?).ok()
                });
                let Some(key) = key else { continue };
                if let Ok(segment) = unverified.verify(&key) {
                    opened = Some((segment, key));
                    break;
                }
            }
            let Some((segment, key)) = opened else {
                if tried {
                    self.stall(
                        *stream,
                        Event::Unreadable {
                            from: *stream,
                            first_seq: want,
                        },
                    );
                }
                return Ok(received);
            };
            if segment.header.prev_hash != head.hash {
                self.raise(Alarm::Fork {
                    stream: *stream,
                    seq: want,
                });
                return Ok(received);
            }
            let mut entries = Vec::new();
            for (i, value) in segment.entries.iter().enumerate() {
                let seq = segment.header.first_seq + i as u64;
                match Entry::from_value(value) {
                    Ok(Entry::Put(env)) if env.version.author != *stream => {
                        self.reject(
                            stream,
                            seq,
                            "version author is not the stream's device".into(),
                        );
                        return Ok(received);
                    }
                    Ok(entry) => entries.push(Pending {
                        stream: *stream,
                        seq,
                        entry,
                    }),
                    Err(Error::Unsupported(what)) => {
                        self.stall(
                            *stream,
                            Event::Waiting {
                                from: *stream,
                                first_seq: seq,
                                reason: format!("needs a newer app: {what}"),
                            },
                        );
                        return Ok(received);
                    }
                    Err(e) => {
                        self.reject(stream, seq, e.to_string());
                        return Ok(received);
                    }
                }
            }
            for p in &entries {
                if let Entry::Checkpoint(heads) = &p.entry {
                    self.check_claims(heads, wall_ms);
                }
            }
            // Trust entries of a self-certified first segment are recorded right away, so the
            // rest of the stream can be verified.
            for p in &entries {
                if matches!(p.entry, Entry::Genesis { .. } | Entry::SelfJoin { .. }) {
                    if let Err(e) = self.trust.record(*stream, &key, p.seq, &p.entry) {
                        self.reject(stream, p.seq, e.to_string());
                        return Ok(received);
                    }
                    self.fold.refold(&self.trust);
                    self.report_self_joins();
                }
            }
            head = Head {
                seq: segment.header.last_seq,
                hash: segment.header.last_hash,
            };
            self.heads.insert(*stream, head);
            self.ends
                .entry(*stream)
                .or_default()
                .insert(head.seq, head.hash);
            self.settle_claim(stream);
            self.events.push(Event::Pulled {
                from: *stream,
                versions: entries.len(),
            });
            self.pending.extend(entries.into_iter().filter(|p| {
                !matches!(
                    p.entry,
                    Entry::Checkpoint(_) | Entry::Genesis { .. } | Entry::SelfJoin { .. }
                )
            }));
            self.stalls.remove(stream);
            received = true;
        }
    }

    /// Compares a checkpoint's heads with what this device knows: a different hash at a known
    /// position is a fork; a position not received yet becomes a claim.
    fn check_claims(&mut self, heads: &Heads, wall_ms: u64) {
        for (device, claimed) in heads {
            if *device == self.device {
                self.check_own_claim(claimed);
                continue;
            }
            let ends = self.ends.get(device);
            if let Some(hash) = ends.and_then(|e| e.get(&claimed.seq)) {
                if *hash != claimed.hash {
                    self.raise(Alarm::Fork {
                        stream: *device,
                        seq: claimed.seq,
                    });
                }
                continue;
            }
            let received = self.heads.get(device).map_or(0, |h| h.seq);
            if claimed.seq > received {
                let claim = self.claims.entry(*device).or_insert(Claim {
                    head: *claimed,
                    since_ms: wall_ms,
                });
                if claimed.seq > claim.head.seq {
                    claim.head = *claimed;
                }
            }
        }
    }

    /// Another device claims a position of this device's own stream.
    fn check_own_claim(&mut self, claimed: &Head) {
        if claimed.seq <= self.sent.seq {
            if self
                .own_ends
                .get(&claimed.seq)
                .is_some_and(|h| *h != claimed.hash)
            {
                self.raise(Alarm::Fork {
                    stream: self.device,
                    seq: claimed.seq,
                });
            }
            return;
        }
        // Beyond what the store confirmed: it may be the segment whose append outcome was
        // lost; anything else was written by another copy of this device.
        match &self.unsent {
            Some(u) if u.last_seq == claimed.seq && u.last_hash == claimed.hash => {
                self.sent = *claimed;
                self.own_ends.insert(claimed.seq, claimed.hash);
                self.unsent = None;
            }
            _ => self.raise(Alarm::Fork {
                stream: self.device,
                seq: claimed.seq,
            }),
        }
    }

    /// After receiving more of `stream`: a claim it reached is settled, or a fork.
    fn settle_claim(&mut self, stream: &DeviceId) {
        let Some(claim) = self.claims.get(stream).copied() else {
            return;
        };
        let received = self.heads.get(stream).map_or(0, |h| h.seq);
        if claim.head.seq > received {
            return;
        }
        self.claims.remove(stream);
        self.withheld_reported.remove(stream);
        if let Some(hash) = self.ends.get(stream).and_then(|e| e.get(&claim.head.seq)) {
            if *hash != claim.head.hash {
                self.raise(Alarm::Fork {
                    stream: *stream,
                    seq: claim.head.seq,
                });
            }
        }
    }

    fn report_withheld(&mut self, wall_ms: u64) {
        let overdue: Vec<(DeviceId, u64)> = self
            .claims
            .iter()
            .filter(|(d, c)| {
                wall_ms >= c.since_ms + WITHHELD_AFTER_MS && !self.withheld_reported.contains(*d)
            })
            .map(|(d, c)| (*d, c.head.seq))
            .collect();
        for (from, claimed_seq) in overdue {
            self.withheld_reported.insert(from);
            self.events.push(Event::Withheld { from, claimed_seq });
        }
    }

    /// Applies every pending entry whose needs are met, repeatedly. Returns whether any was.
    fn apply_pending(&mut self, wall_ms: u64) -> bool {
        let mut any = false;
        loop {
            let mut applied = false;
            let mut i = 0;
            while i < self.pending.len() {
                let p = self.pending[i].clone();
                let blocked_lane = self.blocked.contains(&p.stream)
                    || self.pending[..i]
                        .iter()
                        .any(|q| q.stream == p.stream && q.lane() == p.lane());
                if blocked_lane {
                    i += 1;
                    continue;
                }
                match self.apply(&p, wall_ms) {
                    Applied::Done => {
                        self.pending.remove(i);
                        applied = true;
                    }
                    Applied::Wait(reason) => {
                        self.stall(
                            p.stream,
                            Event::Waiting {
                                from: p.stream,
                                first_seq: p.seq,
                                reason,
                            },
                        );
                        i += 1;
                    }
                    Applied::Reject(reason) => {
                        self.reject(&p.stream, p.seq, reason);
                        i = 0;
                    }
                }
            }
            if !applied {
                return any;
            }
            any = true;
        }
    }

    fn apply(&mut self, p: &Pending, wall_ms: u64) -> Applied {
        let env = match &p.entry {
            Entry::Put(env) => env,
            entry => {
                let Some(key) = self.trust.key(&p.stream) else {
                    return Applied::Wait("device not introduced yet".into());
                };
                return match self.trust.record(p.stream, &key, p.seq, entry) {
                    Ok(changed) => {
                        if changed {
                            self.fold.refold(&self.trust);
                            self.report_self_joins();
                        }
                        Applied::Done
                    }
                    Err(e) => Applied::Reject(e.to_string()),
                };
            }
        };
        let mut new_key = None;
        let doc = if env.tombstone {
            Doc::Tombstone
        } else if env.kind == RecordKind::Vault {
            let body = env.body.as_deref().unwrap_or_default();
            let doc = match Doc::decode(RecordKind::Vault, body) {
                Ok(doc) => doc,
                Err(e) => return Applied::Reject(e.to_string()),
            };
            if let Doc::Vault(v) = &doc {
                match crypto::unwrap_vault_key(&self.account_key, env.record_id, &v.wrapped_key) {
                    Ok(key) => new_key = Some(key),
                    Err(_) => return Applied::Reject("vault key does not unwrap".into()),
                }
            }
            doc
        } else {
            let vault = env.vault_id.expect("checked by Envelope::from_value");
            let Some(key) = self.vault_keys.get(&vault) else {
                return Applied::Wait(format!("key of vault {vault} not known yet"));
            };
            let Ok(plain) = env.open_body(key, &self.account_id) else {
                return Applied::Reject("body does not open".into());
            };
            match Doc::decode(env.kind, &plain) {
                Ok(doc) => doc,
                Err(e) => return Applied::Reject(e.to_string()),
            }
        };
        let accepted = Accepted {
            stream: p.stream,
            seq: p.seq,
            kind: env.kind,
            record_id: env.record_id,
            vault_id: env.vault_id,
            version: env.version.clone(),
            doc,
        };
        match self
            .fold
            .missing_dependency(std::slice::from_ref(&accepted))
        {
            Err(rejection) => return Applied::Reject(rejection.to_string()),
            Ok(Some(device)) => {
                return Applied::Wait(format!(
                    "needs earlier changes from {}",
                    data_encoding::HEXLOWER.encode(&device[..4])
                ))
            }
            Ok(None) => {}
        }
        let hlc = accepted.version.hlc;
        if let Err(rejection) = self.fold.accept(accepted, &self.trust) {
            return Applied::Reject(rejection.to_string());
        }
        if let Some(key) = new_key {
            self.vault_keys.insert(env.record_id, key);
        }
        if let Observed::TooFarAhead { ahead_ms } = self.hlc.observe(hlc, wall_ms) {
            if self.clock_reported.insert(p.stream) {
                self.events.push(Event::ClockAhead {
                    from: p.stream,
                    ahead_ms,
                });
            }
        }
        Applied::Done
    }

    fn report_self_joins(&mut self) {
        let new: Vec<(DeviceId, String)> = self
            .trust
            .self_joined()
            .filter(|(d, _)| **d != self.device && !self.self_join_reported.contains(*d))
            .map(|(d, info)| (*d, info.name.clone()))
            .collect();
        for (device, name) in new {
            self.self_join_reported.insert(device);
            self.events.push(Event::SelfJoined { device, name });
        }
    }

    /// A rule-breaking entry: its stream is no longer read and its pending entries dropped.
    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        self.pending.retain(|p| p.stream != *stream);
        self.events.push(Event::Rejected {
            from: *stream,
            first_seq,
            reason,
        });
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
        if self.halted || (self.unsent.is_none() && self.outbox.is_empty()) {
            return;
        }
        // The store's head of this device's own stream must be where this device left it.
        if let Ok(stored) = transport.head(&self.device) {
            let stored = stored.unwrap_or(0);
            if stored < self.sent.seq {
                self.raise(Alarm::Rollback {
                    stream: self.device,
                    received: self.sent.seq,
                    stored,
                });
                return;
            }
            if stored > self.sent.seq && self.unsent.is_none() {
                self.halted = true;
                self.events.push(Event::OwnStreamConflict);
                return;
            }
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
                    first_seq: self.sent.seq + 1,
                    prev_hash: self.sent.hash,
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
                    self.sent = Head {
                        seq: unsent.last_seq,
                        hash: unsent.last_hash,
                    };
                    self.own_ends.insert(unsent.last_seq, unsent.last_hash);
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                }
                Ok(AppendOutcome::Conflict) => {
                    // Someone else wrote at this device's next position: a clone or a
                    // restored copy of this device. Stop writing; plan A1c-2 retires the id.
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
