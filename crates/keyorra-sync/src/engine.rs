//! The sync engine of one device (spec §4): local writes, reading every other device's
//! stream, applying what it carries, materialising conflict copies, and writing its own stream.
//!
//! Reading has two layers. The **log** layer receives segments strictly in order per stream:
//! signature (the key comes from [`Trust`]: an introduced device's key, or the pinned root key;
//! a self-joining device's first segment carries its own key, used only when no trust entry of
//! any stream is still waiting), chain continuity (every entry's chain hash is kept, so a fork
//! is noticed at any position). Past a stream's cut only trust entries and checkpoints are
//! kept (a later revocation can still change which cuts count); records there are skipped,
//! and read again if the cut moves. The **apply** layer applies
//! received entries with per-record buffering: each lane (one record of one stream, or one
//! stream's trust entries) applies in order, an entry waits only for what it needs, and only
//! lane heads are looked at.
//!
//! Only admitted positions affect anything: checkpoints are evaluated once their position is
//! known to count; vault keys come only from admitted vault versions (a body that opens under
//! none of them waits, it never rejects the stream).
//!
//! Alarms (rollback, fork, a self-joined device, an id endorsed with two keys) form a queue;
//! while any is open, syncing is paused. Each is accepted one by one ([`Engine::accept_alarm`]),
//! or resolves itself (a self-joined device approved or removed). Checkpoint claims unmet for a
//! day raise [`Event::Withheld`] (a warning).
//!
//! Plan A1c-2 adds account headers, snapshots, restore, retiring the device id and the outbox
//! persistence hook; A3 the editor's base version; C1 key rotation and GC.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
    chain, chain_genesis, chain_next, decrypt_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::trust::Trust;
use crate::{AccountId, DeviceId};

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;
/// Received entries waiting to be applied, per stream; beyond this a stream is not read further
/// until some apply (bounded memory against a stream full of entries that never can).
pub const MAX_PENDING_PER_STREAM: usize = 20_000;
/// A device that only reads still writes a checkpoint this often when its heads moved.
pub const CHECKPOINT_EVERY_MS: u64 = 60 * 60 * 1000;
/// Checkpoint claims unmet for this long are reported as withheld (spec §4.5).
pub const WITHHELD_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// Something that pauses syncing until the user decides (spec §4.3, §4.5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Alarm {
    /// The store holds fewer segments of `stream` than this device already received.
    Rollback {
        stream: DeviceId,
        received: u64,
        stored: u64,
    },
    /// Two different histories of `stream` at `seq`.
    Fork { stream: DeviceId, seq: u64 },
    /// A device joined with the Emergency Kit, approved by no device. Resolved by approving
    /// or removing it, or by accepting the alarm (it keeps writing records, without powers).
    SelfJoined { device: DeviceId, name: String },
    /// One device id was endorsed with two different keys; the id is in quarantine.
    KeyConflict { device: DeviceId },
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
            Alarm::SelfJoined { device, name } => write!(
                f,
                "\"{name}\" ({}) joined without approval by any of your devices",
                short(device)
            ),
            Alarm::KeyConflict { device } => {
                write!(
                    f,
                    "device {} was approved with two different keys",
                    short(device)
                )
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
    /// An entry waits for something (a vault key, earlier changes, a newer app, room).
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
    /// The store could not say how far a stream goes, so a rollback check was skipped.
    HeadUnknown {
        stream: DeviceId,
        reason: String,
    },
    /// Conflict copies are still owed after materialising (or writing them failed); item
    /// edits are refused until a later round writes them. An alarm.
    MaterializeIncomplete(String),
    /// A signed entry broke the protocol (not a trust question); the stream is no longer read.
    Rejected {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    /// A trust entry that does not hold (bad signature, out of place); it is ignored.
    TrustEntryIgnored {
        from: DeviceId,
        seq: u64,
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
    /// Other devices claim changes of `from` up to `claimed_seq` that the store has not
    /// delivered for a day.
    Withheld {
        from: DeviceId,
        claimed_seq: u64,
    },
    /// A new alarm; syncing is paused until it is accepted or resolves.
    Alarm(Alarm),
    /// Another device removed this one: it reads but no longer writes. A3 offers to rejoin.
    Removed,
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
    seq: u64,
    entry: Entry,
    /// For a trust entry: what the stream's device had received before it, by its own
    /// earlier checkpoints.
    seen: Heads,
    /// The opened content of a `Put`, once known (so waiting does not decrypt again).
    doc: Option<Doc>,
}

/// Entries of one stream apply in order within a lane: per record for `Put`, all trust
/// entries together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Lane {
    Trust,
    Record(RecordKey),
}

fn lane_of(entry: &Entry) -> Lane {
    match entry {
        Entry::Put(env) => Lane::Record((env.kind, env.record_id)),
        _ => Lane::Trust,
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

/// A checkpoint received at `(from, at)`, evaluated once its position is known to count.
#[derive(Clone, Debug)]
struct Observation {
    from: DeviceId,
    at: u64,
    heads: Heads,
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
    /// Vault keys unwrapped so far, by wrapped bytes.
    unwrapped: BTreeMap<Vec<u8>, Key>,
    /// Per other device: the last received position.
    heads: Heads,
    /// Per other device: the chain hash of every received entry.
    hashes: BTreeMap<DeviceId, BTreeMap<u64, [u8; 32]>>,
    /// Received entries waiting to be applied, per stream and lane.
    lanes: BTreeMap<(DeviceId, Lane), VecDeque<Pending>>,
    pending_count: BTreeMap<DeviceId, usize>,
    /// Per stream: the highest position of every device listed in its checkpoints so far.
    checkpoint_bounds: BTreeMap<DeviceId, Heads>,
    observations: Vec<Observation>,
    claims: BTreeMap<DeviceId, Vec<Claim>>,
    withheld_reported: BTreeSet<DeviceId>,
    /// Streams no longer read: a protocol violation, or a fork the user accepted.
    blocked: BTreeSet<DeviceId>,
    /// Per stream: the first position of a segment whose records were skipped past the cut.
    skipped_from: BTreeMap<DeviceId, u64>,
    /// Per rewound stream: how far it had been received. Up to there only records are taken
    /// again; everything else was handled the first time.
    rewound_through: BTreeMap<DeviceId, u64>,
    /// Last own position confirmed by the transport.
    sent: Head,
    /// Chain hash of every own entry, confirmed or queued.
    own_hashes: BTreeMap<u64, [u8; 32]>,
    unsent: Option<Unsent>,
    outbox: Vec<Value>,
    next_seq: u64,
    /// Heads in the last checkpoint this device wrote, and when.
    last_checkpoint: Option<(Heads, u64)>,
    events: Vec<Event>,
    alarms: Vec<Alarm>,
    accepted_alarms: BTreeSet<Alarm>,
    acknowledged_rollbacks: BTreeSet<(DeviceId, u64)>,
    removed_reported: bool,
    /// Set after `OwnStreamConflict`: nothing more is written (plan A1c-2 retires the id).
    halted: bool,
    /// Tests only: an attacker's copy of the engine, which writes whatever it is told,
    /// removed or not.
    #[cfg(test)]
    pub(crate) forging: bool,
    clock_reported: BTreeSet<DeviceId>,
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
        let key = engine.signer.verifying_key();
        engine.trust.pin_root(key);
        let genesis = Entry::Genesis {
            account_id,
            key: key.to_bytes(),
            name: name.to_owned(),
        };
        engine
            .write_entry(genesis, wall_ms)
            .expect("the first entry of a new account");
        engine
    }

    /// A further device of an existing account (`root` comes from the account header; pin its
    /// key with [`pin_root_key`](Self::pin_root_key) when pairing provides it). It reads what
    /// it can, and can write once another device endorses it or after
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
            unwrapped: BTreeMap::new(),
            heads: Heads::new(),
            hashes: BTreeMap::new(),
            lanes: BTreeMap::new(),
            pending_count: BTreeMap::new(),
            checkpoint_bounds: BTreeMap::new(),
            observations: Vec::new(),
            claims: BTreeMap::new(),
            withheld_reported: BTreeSet::new(),
            blocked: BTreeSet::new(),
            skipped_from: BTreeMap::new(),
            rewound_through: BTreeMap::new(),
            sent: Head {
                seq: 0,
                hash: chain_genesis(&account_id, &device),
            },
            own_hashes: BTreeMap::new(),
            unsent: None,
            outbox: Vec::new(),
            next_seq: 1,
            last_checkpoint: None,
            events: Vec::new(),
            alarms: Vec::new(),
            accepted_alarms: BTreeSet::new(),
            acknowledged_rollbacks: BTreeSet::new(),
            removed_reported: false,
            halted: false,
            #[cfg(test)]
            forging: false,
            clock_reported: BTreeSet::new(),
            stalls: BTreeMap::new(),
        }
    }

    /// Pins the root's key (from pairing; plan A1c-2 binds it into the account header).
    pub fn pin_root_key(&mut self, key: VerifyingKey) {
        self.trust.pin_root(key);
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

    /// Open alarms; syncing is paused while there is any.
    pub fn alarms(&self) -> &[Alarm] {
        &self.alarms
    }

    /// The user accepted `alarm`: a fork stops reading that stream, a rollback is taken as
    /// is, a self-joined device keeps writing records without powers, a quarantined id stays
    /// so. Returns whether it was open.
    pub fn accept_alarm(&mut self, alarm: &Alarm) -> bool {
        let Some(i) = self.alarms.iter().position(|a| a == alarm) else {
            return false;
        };
        let alarm = self.alarms.remove(i);
        match &alarm {
            Alarm::Fork { stream, .. } if *stream != self.device => {
                self.blocked.insert(*stream);
                self.drop_pending(stream);
            }
            Alarm::Rollback { stream, stored, .. } => {
                self.acknowledged_rollbacks.insert((*stream, *stored));
            }
            _ => {}
        }
        self.accepted_alarms.insert(alarm);
        true
    }

    /// Whether this device's next entry would count (introduced and not removed).
    pub fn can_write(&self) -> bool {
        self.trust.admits(&self.device, self.next_seq)
    }

    /// Whether this device may approve and remove others.
    pub fn has_powers(&self) -> bool {
        self.can_write() && self.trust.device(&self.device).is_some_and(|d| d.powers)
    }

    /// Reports a stall of `from`'s stream unless the same one was reported last.
    fn stall(&mut self, from: DeviceId, event: Event) {
        if self.stalls.get(&from) != Some(&event) {
            self.stalls.insert(from, event.clone());
            self.events.push(event);
        }
    }

    fn raise(&mut self, alarm: Alarm) {
        // Two histories past a removed device's cut: neither counts, so nothing to decide
        // (reading that stream simply stops at the fork).
        if let Alarm::Fork { stream, seq } = &alarm {
            let past_cut = self
                .trust
                .device(stream)
                .and_then(|d| d.cut)
                .is_some_and(|c| *seq > c);
            if past_cut {
                return;
            }
        }
        if !self.alarms.contains(&alarm) && !self.accepted_alarms.contains(&alarm) {
            self.events.push(Event::Alarm(alarm.clone()));
            self.alarms.push(alarm);
        }
    }

    fn drop_pending(&mut self, stream: &DeviceId) {
        self.lanes.retain(|(s, _), _| s != stream);
        self.pending_count.remove(stream);
    }

    // ---- trust ----

    /// Joins without approval, with the Emergency Kit: the stream's first entry is a
    /// `SelfJoin`. The device may write records but has no powers, and every other device
    /// pauses with an alarm until the user approves or removes it (spec §4.3).
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

    /// Approves another device (after the code comparison of spec §6.4). Needs powers.
    pub fn endorse(
        &mut self,
        device: DeviceId,
        key: &VerifyingKey,
        name: &str,
        wall_ms: u64,
    ) -> Result<()> {
        self.require_powers()?;
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
    /// counting everywhere. Needs powers, except for removing this device itself.
    pub fn revoke(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        if device == self.device {
            self.require_writable()?;
        } else {
            self.require_powers()?;
        }
        let (last_valid_seq, last_valid_hash) = if device == self.device {
            let seq = self.next_seq - 1;
            (seq, self.own_hashes.get(&seq).copied().unwrap_or([0; 32]))
        } else {
            let seq = self.heads.get(&device).map_or(0, |h| h.seq);
            let hash = self
                .hashes
                .get(&device)
                .and_then(|h| h.get(&seq))
                .copied()
                .unwrap_or([0; 32]);
            (seq, hash)
        };
        let entry = Entry::Revoke {
            device,
            last_valid_seq,
            last_valid_hash,
        };
        self.write_entry(entry, wall_ms)
    }

    fn forging(&self) -> bool {
        #[cfg(test)]
        return self.forging;
        #[cfg(not(test))]
        false
    }

    fn require_writable(&self) -> Result<()> {
        if self.can_write() || self.forging() {
            Ok(())
        } else {
            Err(Error::Refused(
                "this device is not approved, or was removed".into(),
            ))
        }
    }

    fn require_powers(&self) -> Result<()> {
        if self.has_powers() || self.forging() {
            Ok(())
        } else {
            Err(Error::Refused(
                "only an approved device can approve or remove others".into(),
            ))
        }
    }

    /// The keys of `vault` from its admitted versions (more than one only around a mismatch,
    /// which the fold reports).
    fn vault_keys_for(&mut self, vault: Uuid) -> Vec<Key> {
        let wrapped: Vec<Vec<u8>> = self
            .fold
            .retained()
            .filter(|a| a.kind == RecordKind::Vault && a.record_id == vault)
            .filter(|a| self.trust.admits(&a.stream, a.seq))
            .filter_map(|a| match &a.doc {
                Doc::Vault(v) => Some(v.wrapped_key.clone()),
                _ => None,
            })
            .collect();
        let mut keys: Vec<Key> = Vec::new();
        for w in wrapped {
            if let Some(k) = self.unwrap_vault_key(vault, &w) {
                if !keys.iter().any(|x| x.as_bytes() == k.as_bytes()) {
                    keys.push(k);
                }
            }
        }
        keys
    }

    /// The key to write into `vault` with: the one of its visible version.
    fn writer_vault_key(&mut self, vault: Uuid) -> Option<Key> {
        let wrapped = self
            .fold
            .set(RecordKind::Vault, vault)
            .and_then(|s| present_vault(s, false))
            .map(|p| p.payload.wrapped_key.clone())?;
        self.unwrap_vault_key(vault, &wrapped)
    }

    fn unwrap_vault_key(&mut self, vault: Uuid, wrapped: &[u8]) -> Option<Key> {
        if let Some(k) = self.unwrapped.get(wrapped) {
            return Some(k.clone());
        }
        let key = crypto::unwrap_vault_key(&self.account_key, vault, wrapped).ok()?;
        self.unwrapped.insert(wrapped.to_vec(), key.clone());
        Some(key)
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
        self.unwrapped.insert(wrapped_key.clone(), key);
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
                    .writer_vault_key(vault)
                    .ok_or_else(|| Error::NotFound(format!("key of vault {vault}")))?;
                envelope.seal_body(&key, &self.account_id, &doc.encode(), &mut self.rng);
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
            .accept_own(accepted, &self.trust)
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
        // What readers will see in this device's last checkpoint before the entry.
        let seen = self
            .last_checkpoint
            .as_ref()
            .map(|(h, _)| h.clone())
            .unwrap_or_default();
        let changed = self
            .trust
            .record(self.device, &key, seq, &entry, &seen)
            .map_err(|e| Error::Refused(e.to_string()))?;
        self.queue(entry);
        if changed {
            self.trust_changed();
        }
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
        let value = entry.to_value();
        let prev = self
            .own_hashes
            .get(&(self.next_seq - 1))
            .copied()
            .unwrap_or(self.sent.hash);
        self.own_hashes
            .insert(self.next_seq, chain_next(&prev, &value));
        self.outbox.push(value);
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
    /// returned afterwards. While an [`Alarm`] is open only trust entries are applied (so an
    /// alarm resolved on another device, by approving or removing, resolves here too) and
    /// nothing is materialised; what the user did on this device is still pushed, unless the
    /// alarm is about this device's own stream.
    pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        let pulled = self.pull(transport, wall_ms);
        if self.alarms.is_empty() && self.can_write() {
            self.materialize(wall_ms)?;
            self.checkpoint_if_stale(wall_ms);
        }
        let own_alarm = self.alarms.iter().any(|a| match a {
            Alarm::Rollback { stream, .. } | Alarm::Fork { stream, .. } => *stream == self.device,
            _ => false,
        });
        if !own_alarm {
            self.push(transport);
        }
        match self.alarms.first() {
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
                match self.receive_stream(transport, stream) {
                    Ok(p) => progress |= p,
                    Err(e) => self.events.push(Event::ListingFailed {
                        from: *stream,
                        reason: e.to_string(),
                    }),
                }
            }
            progress |= self.apply_pending(wall_ms);
            self.evaluate_observations(wall_ms);
            if !progress {
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
        match transport.head(stream) {
            Ok(stored) => {
                let stored = stored.unwrap_or(0);
                if stored < received && !self.acknowledged_rollbacks.contains(&(*stream, stored)) {
                    self.raise(Alarm::Rollback {
                        stream: *stream,
                        received,
                        stored,
                    });
                }
            }
            Err(e) => self.events.push(Event::HeadUnknown {
                stream: *stream,
                reason: e.to_string(),
            }),
        }
    }

    /// The key that verifies `stream`'s segment at `want`: the stream's key from trust, or
    /// the key a self-joining device's first entry carries, but only while no trust entry of
    /// an introduced stream is still waiting to be applied (one of them could endorse this id
    /// with another key).
    fn stream_key(
        &self,
        stream: &DeviceId,
        want: u64,
        first: Option<&Value>,
    ) -> Option<VerifyingKey> {
        if let Some(key) = self.trust.key(stream) {
            return Some(key);
        }
        let trust_waiting = self
            .lanes
            .keys()
            .any(|(d, lane)| *lane == Lane::Trust && self.trust.device(d).is_some());
        if want != 1 || trust_waiting {
            return None;
        }
        let entry = Entry::from_value(first?).ok()?;
        let own = match &entry {
            // An unpinned root (a device joined without pairing): its Genesis key.
            Entry::Genesis { .. } if *stream == self.trust.root() => entry.own_key(),
            Entry::SelfJoin { .. } if *stream != self.trust.root() => entry.own_key(),
            _ => None,
        }?;
        VerifyingKey::from_bytes(&own).ok()
    }

    /// Receives every segment of `stream` that continues its chain, up to its cut. Returns
    /// whether any was received.
    fn receive_stream(&mut self, transport: &impl Transport, stream: &DeviceId) -> Result<bool> {
        let mut head = self.heads.get(stream).copied().unwrap_or(Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, stream),
        });
        if self.pending_count.get(stream).copied().unwrap_or(0) >= MAX_PENDING_PER_STREAM {
            self.stall(
                *stream,
                Event::Waiting {
                    from: *stream,
                    first_seq: head.seq + 1,
                    reason: "too many entries waiting".into(),
                },
            );
            return Ok(false);
        }
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
                let Some(key) = self.stream_key(stream, want, unverified.entries.first()) else {
                    continue;
                };
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
            let cut = self.trust.device(stream).and_then(|d| d.cut);
            let mut hash = head.hash;
            let mut entries = Vec::new();
            for (i, value) in segment.entries.iter().enumerate() {
                let seq = segment.header.first_seq + i as u64;
                hash = chain_next(&hash, value);
                self.hashes.entry(*stream).or_default().insert(seq, hash);
                match Entry::from_value(value) {
                    // Records past a cut do not count; they are read again if the cut moves.
                    // Only the record id is kept: it can name a conflict copy owed again.
                    Ok(Entry::Put(env)) if cut.is_some_and(|c| seq > c) => {
                        self.fold.note_skipped(env.kind, env.record_id);
                        self.skipped_from
                            .entry(*stream)
                            .or_insert(segment.header.first_seq);
                    }
                    Ok(Entry::Put(env)) if env.version.author != *stream => {
                        self.reject(
                            stream,
                            seq,
                            "version author is not the stream's device".into(),
                        );
                        return Ok(received);
                    }
                    Ok(entry) => entries.push((seq, entry)),
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
            let count = entries.len();
            let rewound = self.rewound_through.get(stream).copied().unwrap_or(0);
            for (seq, entry) in entries {
                if seq <= rewound && !matches!(entry, Entry::Put(_)) {
                    continue; // handled when first received
                }
                match &entry {
                    Entry::Checkpoint(heads) => {
                        let bounds = self.checkpoint_bounds.entry(*stream).or_default();
                        for (d, h) in heads {
                            let e = bounds.entry(*d).or_insert(*h);
                            if h.seq > e.seq {
                                *e = *h;
                            }
                        }
                        self.observations.push(Observation {
                            from: *stream,
                            at: seq,
                            heads: heads.clone(),
                        });
                    }
                    // A self-certified introduction is recorded at once, so the rest of the
                    // stream can be verified.
                    Entry::Genesis { .. } | Entry::SelfJoin { .. } => {
                        match self.trust.record(*stream, &key, seq, &entry, &Heads::new()) {
                            Ok(true) => self.trust_changed(),
                            Ok(false) => {}
                            Err(e) => self.events.push(Event::TrustEntryIgnored {
                                from: *stream,
                                seq,
                                reason: e.to_string(),
                            }),
                        }
                    }
                    _ => {
                        let seen = match &entry {
                            Entry::Put(_) => Heads::new(),
                            _ => self
                                .checkpoint_bounds
                                .get(stream)
                                .cloned()
                                .unwrap_or_default(),
                        };
                        self.lanes
                            .entry((*stream, lane_of(&entry)))
                            .or_default()
                            .push_back(Pending {
                                seq,
                                entry,
                                seen,
                                doc: None,
                            });
                        *self.pending_count.entry(*stream).or_insert(0) += 1;
                    }
                }
            }
            head = Head {
                seq: segment.header.last_seq,
                hash: segment.header.last_hash,
            };
            if rewound <= head.seq {
                self.rewound_through.remove(stream);
            }
            self.heads.insert(*stream, head);
            self.settle_claims(stream);
            self.events.push(Event::Pulled {
                from: *stream,
                versions: count,
            });
            self.stalls.remove(stream);
            received = true;
        }
    }

    /// Checkpoints whose position counts are compared with what this device knows: a
    /// different hash at a known position is a fork; a position not received yet a claim.
    /// Checkpoints at positions that do not count are dropped.
    fn evaluate_observations(&mut self, wall_ms: u64) {
        let observations = std::mem::take(&mut self.observations);
        for o in observations {
            if !self.trust.device(&o.from).is_some() {
                self.observations.push(o); // the writer is not introduced yet
                continue;
            }
            if !self.trust.admits(&o.from, o.at) {
                continue;
            }
            for (device, claimed) in &o.heads {
                if *device == self.device {
                    self.check_own_claim(claimed);
                    continue;
                }
                if let Some(hash) = self.hashes.get(device).and_then(|h| h.get(&claimed.seq)) {
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
                    let list = self.claims.entry(*device).or_default();
                    if !list.iter().any(|c| c.head == *claimed) {
                        list.push(Claim {
                            head: *claimed,
                            since_ms: wall_ms,
                        });
                    }
                }
            }
        }
    }

    /// Another device claims a position of this device's own stream.
    fn check_own_claim(&mut self, claimed: &Head) {
        let known = self.own_hashes.get(&claimed.seq);
        if known.is_some_and(|h| *h != claimed.hash) {
            self.raise(Alarm::Fork {
                stream: self.device,
                seq: claimed.seq,
            });
            return;
        }
        if claimed.seq <= self.sent.seq {
            return;
        }
        // Beyond what the store confirmed: the segment whose append outcome was lost counts as
        // confirmed; a position this device never wrote was written by another copy of it.
        match &self.unsent {
            Some(u) if u.last_seq == claimed.seq && u.last_hash == claimed.hash => {
                self.sent = *claimed;
                self.unsent = None;
            }
            _ if known.is_some() => {}
            _ => self.raise(Alarm::Fork {
                stream: self.device,
                seq: claimed.seq,
            }),
        }
    }

    /// After receiving more of `stream`: claims it reached are settled, or forks.
    fn settle_claims(&mut self, stream: &DeviceId) {
        let received = self.heads.get(stream).map_or(0, |h| h.seq);
        let Some(list) = self.claims.get_mut(stream) else {
            return;
        };
        let reached: Vec<Claim> = list
            .iter()
            .copied()
            .filter(|c| c.head.seq <= received)
            .collect();
        list.retain(|c| c.head.seq > received);
        if list.is_empty() {
            self.claims.remove(stream);
            self.withheld_reported.remove(stream);
        }
        for c in reached {
            let known = self.hashes.get(stream).and_then(|h| h.get(&c.head.seq));
            if known.is_some_and(|h| *h != c.head.hash) {
                self.raise(Alarm::Fork {
                    stream: *stream,
                    seq: c.head.seq,
                });
            }
        }
    }

    /// The oldest unmet claim of a stream, if older than a day, is reported once.
    fn report_withheld(&mut self, wall_ms: u64) {
        let overdue: Vec<(DeviceId, u64)> = self
            .claims
            .iter()
            .filter(|(d, list)| {
                !self.withheld_reported.contains(*d)
                    && list
                        .iter()
                        .map(|c| c.since_ms)
                        .min()
                        .is_some_and(|since| wall_ms >= since + WITHHELD_AFTER_MS)
            })
            .map(|(d, list)| (*d, list.iter().map(|c| c.head.seq).max().unwrap_or(0)))
            .collect();
        for (from, claimed_seq) in overdue {
            self.withheld_reported.insert(from);
            self.events.push(Event::Withheld { from, claimed_seq });
        }
    }

    /// Applies lane heads whose needs are met, repeatedly. Returns whether any was applied.
    fn apply_pending(&mut self, wall_ms: u64) -> bool {
        let mut any = false;
        loop {
            let mut applied = false;
            let keys: Vec<(DeviceId, Lane)> = self.lanes.keys().copied().collect();
            for key in keys {
                if !self.alarms.is_empty() && key.1 != Lane::Trust {
                    continue; // paused: records wait
                }
                let Some(mut p) = self.lanes.get_mut(&key).and_then(|q| q.pop_front()) else {
                    continue;
                };
                let (stream, _) = key;
                match self.apply(stream, &mut p, wall_ms) {
                    Applied::Done => {
                        applied = true;
                        if let Some(n) = self.pending_count.get_mut(&stream) {
                            *n = n.saturating_sub(1);
                        }
                        if self.lanes.get(&key).is_some_and(|q| q.is_empty()) {
                            self.lanes.remove(&key);
                        }
                    }
                    Applied::Wait(reason) => {
                        let first_seq = p.seq;
                        if let Some(q) = self.lanes.get_mut(&key) {
                            q.push_front(p);
                        }
                        self.stall(
                            stream,
                            Event::Waiting {
                                from: stream,
                                first_seq,
                                reason,
                            },
                        );
                    }
                    Applied::Reject(reason) => self.reject(&stream, p.seq, reason),
                }
            }
            if !applied {
                return any;
            }
            any = true;
        }
    }

    fn apply(&mut self, stream: DeviceId, p: &mut Pending, wall_ms: u64) -> Applied {
        let env = match &p.entry {
            Entry::Put(env) => env.clone(),
            Entry::Checkpoint(_) => return Applied::Done,
            entry => {
                let Some(key) = self.trust.key(&stream) else {
                    return Applied::Wait("device not introduced yet".into());
                };
                if let Entry::Revoke {
                    device,
                    last_valid_seq,
                    last_valid_hash,
                } = entry
                {
                    // Only a counting revocation's claim about history is checked.
                    let known = self.hashes.get(device).and_then(|h| h.get(last_valid_seq));
                    if self.trust.admits(&stream, p.seq)
                        && known.is_some_and(|h| h != last_valid_hash)
                    {
                        self.raise(Alarm::Fork {
                            stream: *device,
                            seq: *last_valid_seq,
                        });
                    }
                }
                match self.trust.record(stream, &key, p.seq, entry, &p.seen) {
                    Ok(true) => self.trust_changed(),
                    Ok(false) => {}
                    Err(e) => self.events.push(Event::TrustEntryIgnored {
                        from: stream,
                        seq: p.seq,
                        reason: e.to_string(),
                    }),
                }
                return Applied::Done;
            }
        };
        let doc = match p.doc.clone() {
            Some(doc) => doc,
            None => {
                let doc = if env.tombstone {
                    Doc::Tombstone
                } else if env.kind == RecordKind::Vault {
                    let body = env.body.as_deref().unwrap_or_default();
                    match Doc::decode(RecordKind::Vault, body) {
                        Ok(doc) => doc,
                        Err(e) => return Applied::Reject(e.to_string()),
                    }
                } else {
                    let vault = env.vault_id.expect("checked by Envelope::from_value");
                    let keys = self.vault_keys_for(vault);
                    let Some(plain) = keys
                        .iter()
                        .find_map(|k| env.open_body(k, &self.account_id).ok())
                    else {
                        return Applied::Wait(format!(
                            "no known key of vault {vault} opens this record"
                        ));
                    };
                    match Doc::decode(env.kind, &plain) {
                        Ok(doc) => doc,
                        Err(e) => return Applied::Reject(e.to_string()),
                    }
                };
                p.doc = Some(doc.clone());
                doc
            }
        };
        let accepted = Accepted {
            stream,
            seq: p.seq,
            kind: env.kind,
            record_id: env.record_id,
            vault_id: env.vault_id,
            version: env.version.clone(),
            doc,
        };
        match self
            .fold
            .missing_dependency(std::slice::from_ref(&accepted), &self.trust)
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
        if let Observed::TooFarAhead { ahead_ms } = self.hlc.observe(hlc, wall_ms) {
            if self.clock_reported.insert(stream) {
                self.events.push(Event::ClockAhead {
                    from: stream,
                    ahead_ms,
                });
            }
        }
        Applied::Done
    }

    /// After any change of trust: refold, update the trust alarms, report this device's
    /// removal.
    fn trust_changed(&mut self) {
        self.fold.refold(&self.trust);
        // A cut that moved past skipped records: read those segments again.
        let rewind: Vec<(DeviceId, u64)> = self
            .skipped_from
            .iter()
            .filter(|(d, from)| {
                self.trust
                    .device(d)
                    .and_then(|i| i.cut)
                    .is_none_or(|c| c >= **from)
            })
            .map(|(d, from)| (*d, *from))
            .collect();
        for (stream, from) in rewind {
            self.skipped_from.remove(&stream);
            self.rewind(stream, from);
        }
        let self_joined: Vec<Alarm> = self
            .trust
            .self_joined()
            .filter(|(d, info)| **d != self.device && info.cut.is_none())
            .map(|(d, info)| Alarm::SelfJoined {
                device: *d,
                name: info.name.clone(),
            })
            .collect();
        let conflicts: Vec<Alarm> = self
            .trust
            .quarantined()
            .iter()
            .map(|d| Alarm::KeyConflict { device: *d })
            .collect();
        // Trust alarms that no longer hold resolve themselves.
        self.alarms.retain(|a| match a {
            Alarm::SelfJoined { .. } => self_joined.contains(a),
            Alarm::KeyConflict { .. } => conflicts.contains(a),
            _ => true,
        });
        for alarm in self_joined.into_iter().chain(conflicts) {
            self.raise(alarm);
        }
        let removed = self
            .trust
            .device(&self.device)
            .is_some_and(|d| d.cut.is_some());
        if removed && !self.removed_reported {
            self.removed_reported = true;
            self.events.push(Event::Removed);
        }
    }

    /// Receives `stream` again from position `from` on (its records there were skipped).
    /// Entries of the stream still waiting are dropped: they are received again.
    fn rewind(&mut self, stream: DeviceId, from: u64) {
        let hash = if from <= 1 {
            chain_genesis(&self.account_id, &stream)
        } else {
            self.hashes
                .get(&stream)
                .and_then(|h| h.get(&(from - 1)))
                .copied()
                .expect("hashes of received entries are kept")
        };
        // Records waiting from the skipped segments on are received again; nothing else.
        let mut dropped = 0;
        for ((s, lane), queue) in self.lanes.iter_mut() {
            if *s == stream && *lane != Lane::Trust {
                let before = queue.len();
                queue.retain(|p| p.seq < from);
                dropped += before - queue.len();
            }
        }
        self.lanes.retain(|_, q| !q.is_empty());
        if let Some(n) = self.pending_count.get_mut(&stream) {
            *n = n.saturating_sub(dropped);
        }
        let received = self.heads.get(&stream).map_or(0, |h| h.seq);
        let through = self.rewound_through.entry(stream).or_insert(0);
        *through = (*through).max(received);
        self.heads.insert(
            stream,
            Head {
                seq: from - 1,
                hash,
            },
        );
    }

    /// A protocol violation (not a trust question): the stream is no longer read.
    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        self.drop_pending(stream);
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
        match transport.head(&self.device) {
            Ok(stored) => {
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
            Err(e) => self.events.push(Event::HeadUnknown {
                stream: self.device,
                reason: e.to_string(),
            }),
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
                let last_seq = at.first_seq + versions as u64 - 1;
                debug_assert_eq!(self.own_hashes.get(&last_seq), Some(&last_hash));
                let bytes =
                    seal_segment(&self.segment_key, &self.signer, &at, entries, &mut self.rng)
                        .expect("own entries fit a segment");
                self.unsent = Some(Unsent {
                    bytes,
                    versions,
                    last_seq,
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
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                }
                Ok(AppendOutcome::Conflict) => {
                    // Someone else wrote at this device's next position: another copy of this
                    // device (plan A1c-2 retires the id). Nothing more is written meanwhile.
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
mod adversary_tests;
#[cfg(test)]
mod attack_tests;
#[cfg(test)]
mod tests;
