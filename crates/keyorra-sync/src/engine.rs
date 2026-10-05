//! The sync engine of one device (spec §4): local writes, reading every other device's
//! stream, applying what it carries, materialising conflict copies, and writing its own stream.
//!
//! Reading has two layers. The **log** layer receives segments strictly in order per stream:
//! signature (the key is the root's, known from the account header or the setup code, or one
//! the root gave in an `Endorse`; never a key a stream certifies for itself), chain continuity
//! (every entry's chain hash is kept and compared when seen again, so a fork is noticed at any
//! position). Trust entries of the root's stream are applied at once, in stream order; trust
//! entries of other streams are ignored. Past a stream's cut, records are skipped (only their
//! ids are noted). The **apply** layer applies records with per-record buffering: each lane
//! (one record of one stream) applies in order, an entry waits only for what it needs, and
//! only lane heads are looked at.
//!
//! Only admitted positions affect anything: checkpoints are evaluated once their position is
//! known to count; vault keys come only from admitted vault versions (a body that opens under
//! none of them waits, it never rejects the stream).
//!
//! Alarms are scoped: a rollback or fork pauses only the stream concerned (the own stream:
//! no pushing); devices that self-joined and await the root's decision raise one aggregated
//! alarm that pauses nothing (their records count for nobody anyway). Checkpoint claims unmet
//! for a day raise [`Event::Withheld`] (a warning).
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

/// Something the user must decide on (spec §4.3, §4.5). Rollbacks and forks pause the stream
/// concerned until accepted; nothing else is paused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Alarm {
    /// The store holds fewer segments of `stream` than this device already received.
    Rollback {
        stream: DeviceId,
        received: u64,
        stored: u64,
    },
    /// Two different histories of `stream` at `seq`: seen directly, or claimed by the main
    /// device's checkpoint or removal.
    Fork { stream: DeviceId, seq: u64 },
    /// Another (non-main) device's checkpoint claims a different history of `stream` at
    /// `seq`: either `stream` forked or `by` lies. Pauses nothing.
    Disputed {
        stream: DeviceId,
        seq: u64,
        by: DeviceId,
    },
    /// `count` devices joined with the Emergency Kit and await the main device's decision
    /// ([`Trust::unapproved`]). Their records count for nobody meanwhile.
    Unapproved { count: usize },
}

impl Alarm {
    /// The stream this alarm pauses, if any.
    pub fn stream(&self) -> Option<DeviceId> {
        match self {
            Alarm::Rollback { stream, .. } | Alarm::Fork { stream, .. } => Some(*stream),
            Alarm::Unapproved { .. } | Alarm::Disputed { .. } => None,
        }
    }
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
            Alarm::Disputed { stream, seq, by } => write!(
                f,
                "{} claims another history of {} at {seq}",
                short(by),
                short(stream)
            ),
            Alarm::Unapproved { count } => write!(
                f,
                "{count} device(s) joined with the Emergency Kit and were not approved by the \
                 main device"
            ),
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
    /// A trust entry that does not count (not from the main device, bad signature, out of
    /// place, already decided); it is ignored.
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
    /// A new alarm.
    Alarm(Alarm),
    /// The main device removed this one: it reads but no longer writes. A3 offers to rejoin.
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

/// A received record that has not been applied yet.
#[derive(Clone, Debug)]
struct Pending {
    seq: u64,
    env: Envelope,
    /// The opened content, once known (so waiting does not decrypt again).
    doc: Option<Doc>,
}

/// Records of one stream apply in order per record.
type Lane = (DeviceId, RecordKey);

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
    by: DeviceId,
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
    /// Received records waiting to be applied, per stream and record.
    lanes: BTreeMap<Lane, VecDeque<Pending>>,
    pending_count: BTreeMap<DeviceId, usize>,
    /// Per stream: the highest position of every device listed in its checkpoints so far.
    checkpoint_bounds: BTreeMap<DeviceId, Heads>,
    observations: Vec<Observation>,
    claims: BTreeMap<DeviceId, Vec<Claim>>,
    withheld_reported: BTreeSet<DeviceId>,
    /// Streams no longer read: a protocol violation, or a fork the user accepted.
    blocked: BTreeSet<DeviceId>,
    /// Streams without a key whose start was looked at for a `SelfJoin`.
    peeked: BTreeSet<DeviceId>,
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
    /// Open rollback and fork alarms (one per stream and kind).
    alarms: Vec<Alarm>,
    accepted_alarms: BTreeSet<Alarm>,
    acknowledged_rollbacks: BTreeSet<(DeviceId, u64)>,
    /// How many unapproved devices the user has already seen in an alarm.
    unapproved_seen: usize,
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
    /// The first device of a new account, the main device (root): its stream starts with
    /// `Genesis`, and it alone approves and removes devices.
    pub fn create_account(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        rng: R,
        wall_ms: u64,
    ) -> Self {
        let key = signer.verifying_key();
        let mut engine = Self::join(
            device,
            signer,
            name,
            account_id,
            account_key,
            device,
            key,
            rng,
        );
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

    /// A further device of an existing account. `root` and `root_key` come from the account
    /// header or the setup code (never from the store's streams). It reads what it can, and
    /// writes once the main device approves it, or pending after
    /// [`self_join`](Self::self_join).
    #[allow(clippy::too_many_arguments)]
    pub fn join(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        root: DeviceId,
        root_key: VerifyingKey,
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
            trust: Trust::new(account_id, root, root_key),
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
            peeked: BTreeSet::new(),
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
            unapproved_seen: 0,
            removed_reported: false,
            halted: false,
            #[cfg(test)]
            forging: false,
            clock_reported: BTreeSet::new(),
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

    /// Open alarms: rollbacks and forks (each pausing its stream), and the aggregated alarm
    /// about devices awaiting approval if it lists more than the user has seen.
    pub fn alarms(&self) -> Vec<Alarm> {
        let mut alarms = self.alarms.clone();
        let count = self.trust.unapproved().len();
        if count > self.unapproved_seen {
            alarms.push(Alarm::Unapproved { count });
        }
        alarms
    }

    /// The user accepted `alarm`: a fork stops reading that stream further, a rollback is taken as
    /// is, the unapproved devices listed are noted (a new one raises it again). Returns
    /// whether it was open.
    pub fn accept_alarm(&mut self, alarm: &Alarm) -> bool {
        if let Alarm::Unapproved { count } = alarm {
            let open = self.alarms().contains(alarm);
            if open {
                self.unapproved_seen = *count;
            }
            return open;
        }
        let Some(i) = self.alarms.iter().position(|a| a == alarm) else {
            return false;
        };
        let alarm = self.alarms.remove(i);
        match &alarm {
            // What was received before the fork is a verified history: it still applies.
            Alarm::Fork { stream, .. } if *stream != self.device => {
                self.blocked.insert(*stream);
            }
            Alarm::Rollback { stream, stored, .. } => {
                self.acknowledged_rollbacks.insert((*stream, *stored));
            }
            _ => {}
        }
        self.accepted_alarms.insert(alarm);
        true
    }

    /// Whether this device's next entry would count: approved and not removed, or
    /// self-joined and not (yet) decided on (then it counts only here until approved).
    pub fn can_write(&self) -> bool {
        self.trust.admits(&self.device, self.next_seq)
    }

    /// Whether this is the main device, the one that approves and removes devices.
    pub fn is_root(&self) -> bool {
        self.device == self.trust.root()
    }

    /// Whether `stream` is paused by an open rollback or fork alarm.
    fn paused(&self, stream: &DeviceId) -> bool {
        self.alarms.iter().any(|a| a.stream() == Some(*stream))
    }

    /// Reports a stall of `from`'s stream unless the same one was reported last.
    fn stall(&mut self, from: DeviceId, event: Event) {
        if self.stalls.get(&from) != Some(&event) {
            self.stalls.insert(from, event.clone());
            self.events.push(event);
        }
    }

    fn raise(&mut self, alarm: Alarm) {
        if let Alarm::Disputed { by, stream, seq } = &alarm {
            let past_cut = self.trust.is_removed(stream)
                || self
                    .trust
                    .device(stream)
                    .and_then(|d| d.cut)
                    .is_some_and(|c| seq > &c);
            if past_cut {
                return;
            }
            // One open dispute per claimant.
            let open = self
                .alarms
                .iter()
                .any(|a| matches!(a, Alarm::Disputed { by: b, .. } if b == by));
            if !open && !self.accepted_alarms.contains(&alarm) {
                self.events.push(Event::Alarm(alarm.clone()));
                self.alarms.push(alarm);
            }
            return;
        }
        let Some(stream) = alarm.stream() else {
            return;
        };
        // Two histories past a removed device's cut: neither counts, so nothing to decide
        // (reading that stream simply stops at the fork).
        if let Alarm::Fork { seq, .. } = &alarm {
            let past_cut = self.trust.is_removed(&stream)
                || self
                    .trust
                    .device(&stream)
                    .and_then(|d| d.cut)
                    .is_some_and(|c| *seq > c);
            if past_cut {
                return;
            }
        }
        if self.accepted_alarms.contains(&alarm) {
            return;
        }
        // One alarm per stream and kind: a repeated rollback replaces the earlier one.
        let same_kind = |a: &Alarm| {
            a.stream() == Some(stream)
                && std::mem::discriminant(a) == std::mem::discriminant(&alarm)
        };
        if let Some(i) = self.alarms.iter().position(same_kind) {
            if matches!(alarm, Alarm::Rollback { .. }) && self.alarms[i] != alarm {
                self.alarms[i] = alarm;
            }
            return;
        }
        self.events.push(Event::Alarm(alarm.clone()));
        self.alarms.push(alarm);
    }

    fn drop_pending(&mut self, stream: &DeviceId) {
        self.lanes.retain(|(s, _), _| s != stream);
        self.pending_count.remove(stream);
    }

    // ---- trust ----

    /// Joins without approval, with the Emergency Kit: the stream's first entry is a
    /// `SelfJoin`. The device may write, but its records count for nobody else until the main
    /// device approves it; others see an alarm (spec §4.3).
    pub fn self_join(&mut self, wall_ms: u64) -> Result<()> {
        if self.next_seq != 1 || self.is_root() {
            return Err(Error::Refused("self-join must be the first entry".into()));
        }
        let key = self.signer.verifying_key().to_bytes();
        let sig = sign_endorsement(&self.signer, &self.account_id, &self.device, &key);
        let entry = Entry::SelfJoin {
            key,
            name: self.name.clone(),
            sig,
        };
        self.trust.set_pending_self(self.device);
        self.write_entry(entry, wall_ms)
    }

    /// Approves another device (after the code comparison of spec §6.4). Main device only.
    pub fn endorse(
        &mut self,
        device: DeviceId,
        key: &VerifyingKey,
        name: &str,
        wall_ms: u64,
    ) -> Result<()> {
        self.require_root()?;
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

    /// Approves a device that self-joined, with the key its `SelfJoin` carries.
    pub fn approve(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        let Some(u) = self.trust.unapproved().get(&device).cloned() else {
            return Err(Error::NotFound("no such device awaiting approval".into()));
        };
        self.endorse(device, &u.key, &u.name, wall_ms)
    }

    /// Removes a device: its entries after the last position this device received stop
    /// counting everywhere (for a device never approved: all of them). Main device only; the
    /// main device itself cannot be removed.
    pub fn revoke(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        self.require_root()?;
        if device == self.trust.root() && !self.forging() {
            return Err(Error::Refused("the main device cannot be removed".into()));
        }
        let seq = self.heads.get(&device).map_or(0, |h| h.seq);
        let last_valid_hash = self
            .hashes
            .get(&device)
            .and_then(|h| h.get(&seq))
            .copied()
            .unwrap_or([0; 32]);
        let entry = Entry::Revoke {
            device,
            last_valid_seq: seq,
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

    fn require_root(&self) -> Result<()> {
        if (self.is_root() && self.can_write()) || self.forging() {
            Ok(())
        } else {
            Err(Error::Refused(
                "only the main device approves or removes devices".into(),
            ))
        }
    }

    /// The keys a body of `vault` may open with: those of its admitted versions first, then
    /// those of versions that no longer count. Opening is safe with any key: what a record
    /// says is vouched for by the signature of the stream that carries it, not by the vault
    /// key. (A device may have sealed records with the key of a version that counted when it
    /// wrote them and was cut later; those records must stay readable.) Which key new records
    /// are sealed with comes only from the visible version.
    fn vault_keys_for(&mut self, vault: Uuid) -> Vec<Key> {
        let mut versions: Vec<(bool, Vec<u8>)> = self
            .fold
            .retained()
            .filter(|a| a.kind == RecordKind::Vault && a.record_id == vault)
            .filter_map(|a| match &a.doc {
                Doc::Vault(v) => {
                    Some((!self.trust.admits(&a.stream, a.seq), v.wrapped_key.clone()))
                }
                _ => None,
            })
            .collect();
        versions.sort_by_key(|(not_admitted, _)| *not_admitted);
        let wrapped: Vec<Vec<u8>> = versions.into_iter().map(|(_, w)| w).collect();
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
        let wrapped = self.vault_wrapped_key(vault)?;
        self.unwrap_vault_key(vault, &wrapped)
    }

    /// A vault's key is fixed when the vault is created (until key rotation, C1): the one of
    /// its earliest admitted version, the ancestor of all others. Later versions carrying
    /// another key (a removed device's, written before readers knew) are never written with
    /// and never copied into new versions.
    fn vault_wrapped_key(&self, vault: Uuid) -> Option<Vec<u8>> {
        self.fold
            .retained()
            .filter(|a| a.kind == RecordKind::Vault && a.record_id == vault)
            .filter(|a| self.trust.admits(&a.stream, a.seq))
            .filter_map(|a| match &a.doc {
                Doc::Vault(v) => {
                    let total: u64 = a.version.vector.values().sum();
                    Some((
                        (total, a.version.hlc, a.version.author),
                        v.wrapped_key.clone(),
                    ))
                }
                _ => None,
            })
            .min_by(|x, y| x.0.cmp(&y.0))
            .map(|(_, w)| w)
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
        let mut p = self
            .fold
            .set(RecordKind::Vault, id)
            .and_then(|s| present_vault(s, false))
            .map(|p| p.payload.clone())
            .ok_or_else(|| Error::NotFound(format!("vault {id}")))?;
        if let Some(w) = self.vault_wrapped_key(id) {
            p.wrapped_key = w;
        }
        Ok(p)
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

    /// Writes a trust entry (applied at once on the main device; on others it counts for
    /// nobody, which only an attacker's copy would do).
    fn write_entry(&mut self, entry: Entry, wall_ms: u64) -> Result<()> {
        // `Genesis` and `SelfJoin` must be the stream's first entry: no checkpoint before them.
        let introduction = matches!(entry, Entry::Genesis { .. } | Entry::SelfJoin { .. });
        let seq = if introduction {
            self.next_seq
        } else {
            self.reserve_seq(wall_ms)
        };
        let mut changed = false;
        if self.is_root() {
            let seen = self.last_checkpoint.as_ref().map(|(h, _)| h.clone());
            let result = self.trust.apply_root(seq, &entry, |d| {
                seen.as_ref().and_then(|h| h.get(d)).map_or(0, |h| h.seq)
            });
            match result {
                Ok(c) => changed = c,
                Err(e) if !self.forging() => return Err(Error::Refused(e.to_string())),
                Err(_) => {}
            }
        }
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
    /// returned afterwards. Alarms do not make a round fail: a rollback or fork pauses only
    /// its stream (the own stream: nothing is pushed), see [`Engine::alarms`].
    pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        let pulled = self.pull(transport, wall_ms);
        if self.can_write() {
            self.materialize(wall_ms)?;
            self.checkpoint_if_stale(wall_ms);
        }
        if !self.paused(&self.device) {
            self.push(transport);
        }
        pulled
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
            .filter(|d| !self.trust.is_removed(d))
            .collect();
        for stream in &streams {
            self.check_stored_head(transport, stream);
        }
        loop {
            let mut progress = false;
            for stream in &streams {
                if self.paused(stream) {
                    continue;
                }
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

    /// A stream the main device has not given a key: if its first segment is a valid
    /// `SelfJoin` (signed by the key it carries), the device is noted as awaiting approval.
    /// Nothing else of it is read or credited.
    fn peek_self_join(&mut self, stream: &DeviceId, first: &[u8]) {
        let Ok(unverified) = decrypt_segment(&self.segment_key, first) else {
            return;
        };
        let Some(Ok(Entry::SelfJoin { key, name, sig })) =
            unverified.entries.first().map(Entry::from_value)
        else {
            return;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&key) else {
            return;
        };
        if !crate::entry::verify_endorsement(&vk, &self.account_id, stream, &key, &sig) {
            return;
        }
        if unverified.verify(&vk).is_err() {
            return;
        }
        self.peeked.insert(*stream);
        if self.trust.note_self_join(*stream, vk, &name) {
            let count = self.trust.unapproved().len();
            self.events.push(Event::Alarm(Alarm::Unapproved { count }));
        }
    }

    /// Receives every segment of `stream` that continues its chain, up to its cut. Returns
    /// whether any was received.
    fn receive_stream(&mut self, transport: &impl Transport, stream: &DeviceId) -> Result<bool> {
        let mut head = self.heads.get(stream).copied().unwrap_or(Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, stream),
        });
        let is_root = *stream == self.trust.root();
        // The root's stream carries trust: never held back (its records are capped by the
        // root itself, which is trusted anyway).
        if !is_root
            && self.pending_count.get(stream).copied().unwrap_or(0) >= MAX_PENDING_PER_STREAM
        {
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
        let Some(key) = self.trust.key(stream) else {
            if head.seq == 0 && !self.peeked.contains(stream) {
                if let Some((_, first)) = candidates.iter().find(|(s, _)| *s == 1) {
                    let first = first.clone();
                    self.peek_self_join(stream, &first);
                }
            }
            return Ok(false);
        };
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
                if let Ok(segment) = unverified.verify(&key) {
                    opened = Some(segment);
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
                // A position seen before with another hash: two histories.
                let known = self.hashes.entry(*stream).or_default();
                if known.get(&seq).is_some_and(|h| *h != hash) {
                    self.raise(Alarm::Fork {
                        stream: *stream,
                        seq,
                    });
                    return Ok(received);
                }
                known.insert(seq, hash);
                match Entry::from_value(value) {
                    // Records past a cut never count (a cut never moves); only the record id
                    // is kept: it can name a conflict copy owed again.
                    Ok(Entry::Put(env)) if cut.is_some_and(|c| seq > c) => {
                        self.fold.note_skipped(env.kind, env.record_id);
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
            for (seq, entry) in entries {
                match entry {
                    Entry::Checkpoint(heads) => {
                        let bounds = self.checkpoint_bounds.entry(*stream).or_default();
                        for (d, h) in &heads {
                            let e = bounds.entry(*d).or_insert(*h);
                            if h.seq > e.seq {
                                *e = *h;
                            }
                        }
                        self.observations.push(Observation {
                            from: *stream,
                            at: seq,
                            heads,
                        });
                    }
                    Entry::Put(env) => {
                        self.lanes
                            .entry((*stream, (env.kind, env.record_id)))
                            .or_default()
                            .push_back(Pending {
                                seq,
                                env,
                                doc: None,
                            });
                        *self.pending_count.entry(*stream).or_insert(0) += 1;
                    }
                    // The first entry of an approved self-joined stream: nothing to do.
                    Entry::SelfJoin { .. } if seq == 1 && !is_root => {}
                    entry if is_root => self.apply_root_entry(seq, &entry),
                    _ => self.events.push(Event::TrustEntryIgnored {
                        from: *stream,
                        seq,
                        reason: crate::trust::TrustError::NotFromRoot.to_string(),
                    }),
                }
            }
            head = Head {
                seq: segment.header.last_seq,
                hash: segment.header.last_hash,
            };
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
            if !self.trust.admits(&o.from, o.at) {
                continue;
            }
            for (device, claimed) in &o.heads {
                if *device == self.device {
                    self.check_own_claim(claimed, o.from);
                    continue;
                }
                if let Some(hash) = self.hashes.get(device).and_then(|h| h.get(&claimed.seq)) {
                    if *hash != claimed.hash {
                        self.claim_mismatch(*device, claimed.seq, o.from);
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
                            by: o.from,
                        });
                    }
                }
            }
        }
    }

    /// A checkpoint of `by` claims another hash at `stream`'s `seq` than this device has:
    /// a fork if the main device says so, otherwise a dispute (pausing nothing).
    fn claim_mismatch(&mut self, stream: DeviceId, seq: u64, by: DeviceId) {
        if by == self.trust.root() {
            self.raise(Alarm::Fork { stream, seq });
        } else {
            self.raise(Alarm::Disputed { stream, seq, by });
        }
    }

    /// Another device claims a position of this device's own stream.
    fn check_own_claim(&mut self, claimed: &Head, by: DeviceId) {
        let known = self.own_hashes.get(&claimed.seq);
        if known.is_some_and(|h| *h != claimed.hash) {
            self.claim_mismatch(self.device, claimed.seq, by);
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
            _ => self.claim_mismatch(self.device, claimed.seq, by),
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
                self.claim_mismatch(*stream, c.head.seq, c.by);
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
            let keys: Vec<Lane> = self.lanes.keys().copied().collect();
            for key in keys {
                if self.paused(&key.0) {
                    continue; // paused: its records wait
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

    /// An approval or removal by the main device, in its stream's order.
    fn apply_root_entry(&mut self, seq: u64, entry: &Entry) {
        if let Entry::Revoke {
            device,
            last_valid_seq,
            last_valid_hash,
        } = entry
        {
            // The root's statement about history is checked against this device's chain.
            let known = self.hashes.get(device).and_then(|h| h.get(last_valid_seq));
            if *last_valid_seq > 0 && known.is_some_and(|h| h != last_valid_hash) {
                self.raise(Alarm::Fork {
                    stream: *device,
                    seq: *last_valid_seq,
                });
            }
        }
        // What the root had seen counts only where it matches this device's chain.
        let root = self.trust.root();
        let bounds = self
            .checkpoint_bounds
            .get(&root)
            .cloned()
            .unwrap_or_default();
        let hashes = &self.hashes;
        let seen = |d: &DeviceId| {
            bounds
                .get(d)
                .filter(|h| hashes.get(d).and_then(|x| x.get(&h.seq)) == Some(&h.hash))
                .map_or(0, |h| h.seq)
        };
        match self.trust.apply_root(seq, entry, seen) {
            Ok(true) => self.trust_changed(),
            Ok(false) => {}
            Err(e) => self.events.push(Event::TrustEntryIgnored {
                from: root,
                seq,
                reason: e.to_string(),
            }),
        }
    }

    fn apply(&mut self, stream: DeviceId, p: &mut Pending, wall_ms: u64) -> Applied {
        let env = p.env.clone();
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

    /// After any change of trust: refold, drop what removed devices still have waiting,
    /// report this device's removal.
    fn trust_changed(&mut self) {
        self.fold.refold(&self.trust);
        let removed: Vec<DeviceId> = self
            .lanes
            .keys()
            .map(|(d, _)| *d)
            .filter(|d| self.trust.is_removed(d))
            .collect();
        for d in removed {
            self.drop_pending(&d);
        }
        if self.unapproved_seen > self.trust.unapproved().len() {
            self.unapproved_seen = self.trust.unapproved().len();
        }
        if self.trust.is_cut(&self.device) && !self.removed_reported {
            self.removed_reported = true;
            self.events.push(Event::Removed);
        }
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
