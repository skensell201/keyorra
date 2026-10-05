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
//! Plan A1c-2 adds, in submodules: account headers as signed entries of the main device's
//! stream and its advertised head (`headers`), snapshots for bootstrap, anchoring and restore
//! (`snapshots`), retiring the device id when another copy of this device wrote or its key is
//! gone (`retire`), and the outbox persistence hook for A1d (`outbox`). Still later: the
//! editor's base version (A3), key rotation and GC (C1).

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
use crate::header::{Header, HeaderFile};
use crate::keys::segment_key;
use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::present::{present_item, present_vault, ItemState};
use crate::segment::{
    chain, chain_genesis, chain_next, decrypt_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::trust::Trust;
use crate::{AccountId, DeviceId};

mod headers;
mod outbox;
mod resume;
mod retire;
mod snapshots;

pub use outbox::{NoOutboxStore, OutboxState, OutboxStore};
pub use resume::{EngineMemo, Resumed};
pub use retire::{DeviceKeys, KeepKeys, RetireReason};
pub use snapshots::{SNAPSHOT_EVERY_ENTRIES, SNAPSHOT_EVERY_MS};

/// Own confirmed segments kept for "Restore from this Mac" at most (older ones are covered
/// by the main device's snapshots in practice).
pub const MAX_OWN_SEGMENTS_KEPT: usize = 10_000;
/// The main device rewrites its head file at least this often while online.
pub const ROOT_HEARTBEAT_MS: u64 = 24 * 60 * 60 * 1000;
/// The main device's head file not advancing for this long, while other streams move on,
/// is reported ([`Event::RootSilent`]).
pub const ROOT_SILENT_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// What a device last saw of the main device's head file.
#[derive(Clone, Copy, Debug)]
struct RootTime {
    root_ms: u64,
    /// Local wall time when it last advanced.
    since_ms: u64,
    reported: bool,
}

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;
/// Received entries waiting to be applied, per stream; beyond this a stream is not read further
/// until some apply (bounded memory against a stream full of entries that never can).
pub const MAX_PENDING_PER_STREAM: usize = 20_000;
/// A device that only reads still writes a checkpoint this often when its heads moved.
pub const CHECKPOINT_EVERY_MS: u64 = 60 * 60 * 1000;
/// A claimed position more than this far past what was received is not plausible: ignored.
pub const MAX_CLAIM_AHEAD: u64 = 100_000;
/// Unmet claims kept per claimant; further ones are ignored until some are met.
pub const MAX_CLAIMS_PER_CLAIMANT: usize = 64;
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
    /// Something that is not a segment of this device (unsigned, unreadable) occupies its
    /// own stream at `seq` (review K1): a store or someone with folder access tampered with
    /// it. This device keeps its id and pushes nothing until the user looks into it: remove
    /// the file and accept (retry), or leave the id ([`Engine::leave_id`]).
    OwnStreamTampered { seq: u64 },
    /// Another (non-main) device's checkpoint claims a different history of `stream` at
    /// `seq`: either `stream` forked or `by` lies. Pauses nothing.
    Disputed {
        stream: DeviceId,
        seq: u64,
        by: DeviceId,
    },
    /// The main device's stream, as received, is behind the head the account header (or the
    /// setup code) advertises: its newest decisions (a removal) may be withheld. Records of
    /// other devices are unconfirmed meanwhile ([`Engine::root_confirmed`]). Pauses nothing;
    /// resolves itself when the stream catches up.
    RootBehind { advertised: u64, received: u64 },
    /// A header file in the store names another main device (review I2): someone with the
    /// master password and Secret Key published it. Pauses nothing; devices joining with the
    /// Emergency Kit alone would trust it, so the user should look (and rotate keys, C1).
    ForeignHeader { epoch: u32, root: DeviceId },
    /// The main device approved this device's id with a key that is not this device's: the
    /// joining segment was replaced on the way. This device does not write.
    ApprovedWithAnotherKey,
    /// `count` devices joined with the Emergency Kit and await the main device's decision
    /// ([`Trust::unapproved`]). Their records count for nobody meanwhile.
    Unapproved { count: usize },
}

impl Alarm {
    /// The stream this alarm pauses, if any.
    pub fn stream(&self) -> Option<DeviceId> {
        match self {
            Alarm::Rollback { stream, .. } | Alarm::Fork { stream, .. } => Some(*stream),
            Alarm::OwnStreamTampered { .. } => None,
            Alarm::Unapproved { .. }
            | Alarm::Disputed { .. }
            | Alarm::ApprovedWithAnotherKey
            | Alarm::RootBehind { .. }
            | Alarm::ForeignHeader { .. } => None,
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
            Alarm::OwnStreamTampered { seq } => write!(
                f,
                "this device's changes cannot be stored: something else occupies position {seq}"
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
            Alarm::ForeignHeader { epoch, root } => write!(
                f,
                "an account header (epoch {epoch}) names another main device ({})",
                short(root)
            ),
            Alarm::RootBehind {
                advertised,
                received,
            } => write!(
                f,
                "the main device's changes are not all here (up to {received} of {advertised}); \
                 other devices' changes are unconfirmed"
            ),
            Alarm::ApprovedWithAnotherKey => f.write_str(
                "the main device approved this device with another key: its joining request \
                 was replaced; join again and compare the code",
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
    /// Someone else wrote at this device's next position: another copy of this device.
    OwnStreamConflict,
    /// This device continues under a new id (spec §4.2), pending the main device's approval.
    Retired {
        old: DeviceId,
        new: DeviceId,
        reason: RetireReason,
    },
    /// The main device itself would have to retire (another copy of it wrote, or its key is
    /// gone): it stops writing; the user starts a new account from a device and carries the
    /// data over (A1d/A3).
    RootMustStartOver {
        reason: RetireReason,
    },
    /// A newer account header (a master password change on the main device).
    HeaderAdopted {
        epoch: u32,
    },
    SnapshotWritten {
        name: String,
    },
    /// Positions of `stream` up to `seq` were taken from a snapshot by `by` (restore).
    Anchored {
        stream: DeviceId,
        seq: u64,
        by: DeviceId,
    },
    /// The main device's head file has not advanced since `since_ms` (a week): the main
    /// device may be switched off, or the store may be freezing the file while hiding its
    /// newest entries. A mild warning.
    RootSilent {
        since_ms: u64,
    },
    /// Something at this device's own position `seq` was not its segment (a keyless writer's
    /// junk, a squatter): deleted, and the device went on (review F1).
    OwnStreamCleaned {
        seq: u64,
    },
    /// The outbox could not be persisted; nothing is appended until it can.
    OutboxNotSaved(String),
    /// A rollback of `stream` that a snapshot already covers: nothing is lost, no alarm.
    RollbackRepaired {
        stream: DeviceId,
    },
}

/// A sealed segment that the store has not confirmed yet: retried byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSegment {
    pub bytes: Vec<u8>,
    pub versions: usize,
    pub last_seq: u64,
    pub last_hash: [u8; 32],
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
    /// Position of the checkpoint in `by`'s stream.
    at: u64,
    reported: bool,
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
    /// Per other device: the last position of every received segment (snapshot frontiers
    /// must be segment ends, since readers read whole segments).
    segment_ends: BTreeMap<DeviceId, BTreeSet<u64>>,
    /// Per other device: the chain hash of every received entry.
    hashes: BTreeMap<DeviceId, BTreeMap<u64, [u8; 32]>>,
    /// Received records waiting to be applied, per stream and record.
    lanes: BTreeMap<Lane, VecDeque<Pending>>,
    pending_count: BTreeMap<DeviceId, usize>,
    /// Per stream: the highest position of every device listed in its checkpoints so far.
    checkpoint_bounds: BTreeMap<DeviceId, Heads>,
    observations: Vec<Observation>,
    claims: BTreeMap<DeviceId, Vec<Claim>>,
    /// Streams no longer read: a protocol violation, or a fork the user accepted.
    blocked: BTreeSet<DeviceId>,
    /// Streams without a key whose start was looked at for a `SelfJoin`.
    peeked: BTreeSet<DeviceId>,
    /// Last own position confirmed by the transport.
    sent: Head,
    /// Chain hash of every own entry, confirmed or queued.
    own_hashes: BTreeMap<u64, [u8; 32]>,
    unsent: Option<SealedSegment>,
    outbox: Vec<Value>,
    next_seq: u64,
    /// Heads in the last checkpoint this device wrote, and when.
    last_checkpoint: Option<(Heads, u64)>,
    events: Vec<Event>,
    /// Open rollback and fork alarms (one per stream and kind).
    alarms: Vec<Alarm>,
    accepted_alarms: BTreeSet<Alarm>,
    acknowledged_rollbacks: BTreeSet<(DeviceId, u64)>,
    /// The main device's head as advertised by the account header or the setup code.
    root_head_advertised: Option<Head>,
    /// How many unapproved devices the user has already seen in an alarm.
    unapproved_seen: usize,
    removed_reported: bool,
    /// Set when the main device would have to retire: nothing more is written.
    halted: bool,
    keys: Box<dyn DeviceKeys>,
    outbox_store: Box<dyn OutboxStore>,
    /// Set when another copy of this device was noticed; handled at the end of the round.
    retire_due: Option<RetireReason>,
    /// The main device's `Header` entries `(seq, header)` and everyone's `HeaderSeen`.
    header_entries: Vec<(u64, Header)>,
    header_seen: Vec<(DeviceId, u64, u32)>,
    adopted_epoch: u32,
    /// Own header files waiting for their entry's segment to be confirmed.
    header_files_out: Vec<(u64, HeaderFile)>,
    /// Header files below this epoch were deleted.
    deleted_below: u32,
    snapshot_ref: Option<snapshots::SnapshotRef>,
    own_snapshots: Vec<String>,
    entries_since_snapshot: u64,
    last_snapshot_ms: Option<u64>,
    revoked_since_snapshot: bool,
    /// Own confirmed segments, byte for byte, by first position: what "Restore from this
    /// Mac" appends again after the store lost them (A1d persists them with the outbox).
    own_segments: BTreeMap<u64, Vec<u8>>,
    /// The main device's snapshots cover the own stream up to here: kept segments up to it
    /// are dropped once the store is seen holding them.
    own_covered: u64,
    /// After a restart: the own stream is read again (up to the confirmed position) before
    /// the queued own entries are applied and before anything new is written.
    rebuilding: bool,
    /// Heads received before a restart, compared once the streams are read again.
    remembered_heads: Heads,
    /// The last outbox save failed: nothing is appended until one succeeds.
    outbox_unsaved: bool,
    bootstrap_tried: bool,
    /// The own head and wall time last written to the root head file (main device).
    root_head_written: (u64, u64, usize, u64),
    /// The main device's time in its head file, as last seen advancing (other devices).
    root_time: Option<RootTime>,
    /// The main device's trust entries applied so far, in its stream's order (for snapshots).
    root_log: Vec<(u64, Entry)>,
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
            segment_ends: BTreeMap::new(),
            lanes: BTreeMap::new(),
            pending_count: BTreeMap::new(),
            checkpoint_bounds: BTreeMap::new(),
            observations: Vec::new(),
            claims: BTreeMap::new(),
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
            root_head_advertised: None,
            removed_reported: false,
            halted: false,
            keys: Box::new(KeepKeys),
            outbox_store: Box::new(NoOutboxStore),
            retire_due: None,
            header_entries: Vec::new(),
            header_seen: Vec::new(),
            adopted_epoch: 0,
            header_files_out: Vec::new(),
            deleted_below: 0,
            snapshot_ref: None,
            own_snapshots: Vec::new(),
            entries_since_snapshot: 0,
            last_snapshot_ms: None,
            revoked_since_snapshot: false,
            own_segments: BTreeMap::new(),
            outbox_unsaved: false,
            rebuilding: false,
            remembered_heads: Heads::new(),
            own_covered: 0,
            bootstrap_tried: false,
            root_head_written: (0, 0, 0, 0),
            root_time: None,
            root_log: Vec::new(),
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
        if self.approved_with_another_key() {
            alarms.push(Alarm::ApprovedWithAnotherKey);
        }
        if let Some(advertised) = self.root_head_advertised {
            let received = self.root_received().seq;
            if advertised.seq > received {
                alarms.push(Alarm::RootBehind {
                    advertised: advertised.seq,
                    received,
                });
            }
        }
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
            // Accepting retries (the user removed what occupied the position); if it is
            // still there, the alarm comes back. Leaving the id is `leave_id`.
            Alarm::OwnStreamTampered { .. } => return true,
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
        !self.rebuilding
            && self.trust.admits(&self.device, self.next_seq)
            && !self.approved_with_another_key()
    }

    fn approved_with_another_key(&self) -> bool {
        self.trust
            .key(&self.device)
            .is_some_and(|k| k != self.signer.verifying_key())
    }

    /// The code to show on this device while it waits for approval
    /// ([`crate::trust::key_fingerprint`]).
    pub fn key_fingerprint(&self) -> String {
        crate::trust::key_fingerprint(&self.signer.verifying_key())
    }

    /// The main device's own head, for it to advertise in the account header (A1c-2) and the
    /// setup code.
    pub fn root_head(&self) -> Head {
        self.root_received()
    }

    /// The main device's head from the account header or the setup code (only moves
    /// forward). Compared with the main device's stream as received.
    pub fn set_root_head(&mut self, head: Head) {
        if self.root_head_advertised.is_none_or(|h| head.seq >= h.seq) {
            self.root_head_advertised = Some(head);
        }
        self.check_root_head();
    }

    /// Whether the main device's stream is received up to its advertised head. Until then
    /// other devices' records are shown as unconfirmed: a removal could still be withheld.
    pub fn root_confirmed(&self) -> bool {
        self.root_head_advertised
            .is_none_or(|h| h.seq <= self.root_received().seq)
    }

    fn root_received(&self) -> Head {
        if self.is_root() {
            return self.sent;
        }
        let root = self.trust.root();
        self.heads.get(&root).copied().unwrap_or(Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, &root),
        })
    }

    /// The advertised head against the received chain: another hash there is a fork.
    fn check_root_head(&mut self) {
        let Some(h) = self.root_head_advertised else {
            return;
        };
        if self.is_root() || h.seq == 0 {
            return;
        }
        let root = self.trust.root();
        let known = self.hashes.get(&root).and_then(|x| x.get(&h.seq));
        if known.is_some_and(|k| *k != h.hash) {
            self.raise(Alarm::Fork {
                stream: root,
                seq: h.seq,
            });
        }
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

    /// Approves a device that self-joined, with the key its `SelfJoin` carries, once the user
    /// confirmed that `expected_fingerprint` is the code shown on the joining device (the
    /// store could have replaced its joining segment).
    pub fn approve(
        &mut self,
        device: DeviceId,
        expected_fingerprint: &str,
        wall_ms: u64,
    ) -> Result<()> {
        let Some(u) = self.trust.unapproved().get(&device).cloned() else {
            return Err(Error::NotFound("no such device awaiting approval".into()));
        };
        if crate::trust::key_fingerprint(&u.key) != expected_fingerprint {
            return Err(Error::Refused(
                "the code does not match the one shown on the joining device; its request may \
                 have been replaced"
                    .into(),
            ));
        }
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

    /// The wrapped key of `vault` as the engine uses it ([`Self::vault_wrapped_key`]): what
    /// the local store must keep, not the view's top sibling (review A1d C3).
    pub fn vault_key(&self, vault: Uuid) -> Option<Vec<u8>> {
        self.vault_wrapped_key(vault)
    }

    /// The last outbox save failed: changes written since are not safe from a crash yet
    /// (review A1d I3); the app keeps them recorded until a save succeeds.
    pub fn outbox_unsaved(&self) -> bool {
        self.outbox_unsaved
    }

    /// The key to write into `vault` with: the one of its visible version.
    fn writer_vault_key(&mut self, vault: Uuid) -> Option<Key> {
        let wrapped = self.vault_wrapped_key(vault)?;
        self.unwrap_vault_key(vault, &wrapped)
    }

    /// A vault's key is fixed when the vault is created (until key rotation, C1): the key the
    /// vault id commits to, together with the creating device ([`crate::present::vault_id`]),
    /// carried by any admitted version. Without such a version (a vault created before ids
    /// committed), the key of the earliest admitted version whose key unwraps. A key that
    /// does not unwrap never counts, and new records and vault versions use only this key,
    /// so a device that is later removed cannot take the vault over.
    fn vault_wrapped_key(&self, vault: Uuid) -> Option<Vec<u8>> {
        let versions: Vec<&Accepted> = self
            .fold
            .retained()
            .filter(|a| a.kind == RecordKind::Vault && a.record_id == vault)
            .filter(|a| self.trust.admits(&a.stream, a.seq))
            .collect();
        let authors: BTreeSet<DeviceId> = versions.iter().map(|a| a.version.author).collect();
        let mut committed = Vec::new();
        let mut unwrapping = Vec::new();
        for a in &versions {
            let Doc::Vault(v) = &a.doc else { continue };
            let Ok(key) = crypto::unwrap_vault_key(&self.account_key, vault, &v.wrapped_key) else {
                continue;
            };
            let total: u64 = a.version.vector.values().sum();
            let order = (total, a.version.hlc, a.version.author);
            let commits = authors
                .iter()
                .any(|d| crate::present::vault_id(d, key.as_bytes()) == vault);
            if commits {
                committed.push((order, v.wrapped_key.clone()));
            } else {
                unwrapping.push((order, v.wrapped_key.clone()));
            }
        }
        let pick = if committed.is_empty() {
            unwrapping
        } else {
            committed
        };
        pick.into_iter()
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
        let mut raw = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut raw[..]);
        let id = crate::present::vault_id(&self.device, &raw);
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

    /// Brings a vault of the local store into sync with its existing id and key (enabling
    /// sync on a vault that already has data, plan A1d). Its id does not commit to its key
    /// (spec §4.4), so the earliest admitted version whose key unwraps decides; new vaults
    /// should be created with [`Engine::create_vault`].
    pub fn adopt_vault(&mut self, id: Uuid, name: &str, key: &Key, wall_ms: u64) -> Result<()> {
        if self.fold.contains(RecordKind::Vault, id) {
            return Err(Error::Refused(format!("vault {id} is already synced")));
        }
        let wrapped_key = crypto::wrap_vault_key(&self.account_key, id, key);
        self.unwrapped.insert(wrapped_key.clone(), key.clone());
        let doc = Doc::Vault(VaultPayload {
            name: name.to_owned(),
            wrapped_key,
            deleted: false,
        });
        self.write(RecordKind::Vault, id, None, doc, wall_ms)
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
            chunks_for: id,
        });
        self.write(RecordKind::Attachment, id, Some(vault_id), doc, wall_ms)?;
        Ok(id)
    }

    /// An attachment's content as chunks (plan A2): a new random key, the bytes cut into
    /// `chunk_size` pieces (at most [`crate::chunk::MAX_CHUNK`]), each sealed for this
    /// attachment id. The caller stores the chunks first, then writes the record with
    /// [`Engine::write_attachment`] (a reader must never see a record whose chunks are not
    /// there yet, spec §5.3).
    pub fn seal_attachment(
        &mut self,
        id: Uuid,
        item_id: Uuid,
        name: &str,
        bytes: &[u8],
        chunk_size: usize,
    ) -> Result<(AttachmentPayload, Vec<Vec<u8>>)> {
        let chunk_size = chunk_size.clamp(1, crate::chunk::MAX_CHUNK);
        let mut key = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut key[..]);
        let pieces: Vec<&[u8]> = if bytes.is_empty() {
            vec![&[][..]]
        } else {
            bytes.chunks(chunk_size).collect()
        };
        let count = u32::try_from(pieces.len())
            .map_err(|_| crate::error::malformed("attachment too large"))?;
        let attachment_key = Key::from_bytes(*key);
        let mut sealed = Vec::with_capacity(pieces.len());
        let mut names = Vec::with_capacity(pieces.len());
        for (index, piece) in pieces.into_iter().enumerate() {
            let place = crate::chunk::ChunkPlace {
                account_id: self.account_id,
                attachment_id: id,
                index: index as u32,
                count,
            };
            let chunk = crate::chunk::seal_chunk(&attachment_key, &place, piece, &mut self.rng)?;
            let mut name = [0u8; 32];
            name.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(&chunk));
            names.push(name);
            sealed.push(chunk);
        }
        let payload = AttachmentPayload {
            item_id,
            name: name.to_owned(),
            size: bytes.len() as u64,
            key,
            chunk_size: chunk_size as u32,
            chunks: names,
            chunks_for: id,
        };
        Ok((payload, sealed))
    }

    /// Writes an attachment record whose chunks are stored ([`Engine::seal_attachment`]).
    pub fn write_attachment(
        &mut self,
        vault_id: Uuid,
        id: Uuid,
        payload: AttachmentPayload,
        wall_ms: u64,
    ) -> Result<()> {
        self.write(
            RecordKind::Attachment,
            id,
            Some(vault_id),
            Doc::Attachment(payload),
            wall_ms,
        )
    }

    /// The content of an attachment from its chunks, in order (as named by `payload`).
    /// Each chunk must have its name and open for its place; the total must be the size.
    pub fn open_attachment(
        &self,
        payload: &AttachmentPayload,
        chunks: &[Vec<u8>],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if chunks.len() != payload.chunks.len() {
            return Err(crate::error::malformed("attachment chunk count"));
        }
        let count =
            u32::try_from(chunks.len()).map_err(|_| crate::error::malformed("chunk count"))?;
        let key = Key::from_bytes(*payload.key);
        let mut out = Zeroizing::new(Vec::with_capacity(payload.size.min(1 << 30) as usize));
        for (index, (chunk, name)) in chunks.iter().zip(&payload.chunks).enumerate() {
            if <sha2::Sha256 as sha2::Digest>::digest(chunk).as_slice() != name {
                return Err(crate::error::malformed("chunk does not match its name"));
            }
            let place = crate::chunk::ChunkPlace {
                account_id: self.account_id,
                attachment_id: payload.chunks_for,
                index: index as u32,
                count,
            };
            out.extend_from_slice(&crate::chunk::open_chunk(&key, &place, chunk)?);
        }
        if out.len() as u64 != payload.size {
            return Err(crate::error::malformed("attachment size"));
        }
        Ok(out)
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
            if result.is_ok() && is_trust_entry(&entry) {
                self.root_log.push((seq, entry.clone()));
            }
            match result {
                Ok(c) => changed = c,
                Err(e) if !self.forging() => return Err(Error::Refused(e.to_string())),
                Err(_) => {}
            }
        }
        self.note_header_entry(self.device, seq, &entry);
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
        self.entries_since_snapshot += 1;
        debug_assert_eq!(
            self.next_seq,
            self.unsent.as_ref().map_or(self.sent.seq, |u| u.last_seq)
                + self.outbox.len() as u64
                + 1,
            "own sequence numbers out of step"
        );
        self.save_outbox();
    }

    // ---- sync ----

    /// One round: receive and apply everything readable, materialise conflict copies, push.
    /// Whatever was applied is always materialised and pushed, even if the transport failed
    /// part of the way (a failed stream listing is only an event); the error, if any, is
    /// returned afterwards. Alarms do not make a round fail: a rollback or fork pauses only
    /// its stream (the own stream: nothing is pushed), see [`Engine::alarms`].
    pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        transport.begin_round();
        if self.sent.seq > 0 && !self.keys.holds(&self.device) {
            self.retire(RetireReason::KeyMissing, wall_ms)?;
        }
        if !self.bootstrap_tried {
            self.bootstrap_tried = true;
            self.bootstrap(transport, wall_ms)?;
        }
        self.read_root_head_file(transport, wall_ms);
        let pulled = self.pull(transport, wall_ms);
        if let Some(reason) = self.retire_due.take() {
            self.retire(reason, wall_ms)?;
        }
        self.adopt_header(wall_ms);
        self.check_header_files(transport);
        self.delete_old_headers(transport);
        if self.can_write() {
            self.materialize(wall_ms)?;
            self.checkpoint_if_stale(wall_ms);
        }
        if !self.paused(&self.device) {
            self.push(transport);
            if let Some(reason) = self.retire_due.take() {
                self.retire(reason, wall_ms)?;
                self.push(transport);
            }
            if self.can_write() && self.is_idle() && self.snapshot_due(wall_ms) {
                self.write_snapshot(transport, wall_ms)?;
                self.push(transport);
            }
        }
        self.write_root_head_file(transport, wall_ms);
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
        let mut streams: Vec<DeviceId> = transport
            .streams()?
            .into_iter()
            .filter(|d| *d != self.device && !self.blocked.contains(d))
            .filter(|d| !self.trust.is_removed(d))
            .collect();
        for stream in &streams {
            self.check_stored_head(transport, stream);
        }
        if self.rebuilding {
            streams.push(self.device);
        }
        loop {
            let mut progress = false;
            for stream in &streams {
                if self.paused(stream) {
                    continue;
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
            self.evaluate_observations(wall_ms);
            if !progress {
                break;
            }
        }
        self.report_withheld(wall_ms);
        self.check_root_head();
        if self.rebuilding {
            self.finish_rebuild(wall_ms);
        }
        self.check_remembered();
        Ok(())
    }

    /// Rollback: the store's head of a stream is behind what this device received.
    fn check_stored_head(&mut self, transport: &impl Transport, stream: &DeviceId) {
        // After a restart, what was received before counts until the stream is read again.
        let received = self
            .heads
            .get(stream)
            .map_or(0, |h| h.seq)
            .max(self.remembered_heads.get(stream).map_or(0, |h| h.seq));
        if received == 0 {
            return;
        }
        match transport.head(stream) {
            Ok(stored) => {
                let stored = stored.unwrap_or(0);
                if stored < received && !self.acknowledged_rollbacks.contains(&(*stream, stored)) {
                    if self.snapshot_covers(transport, stream, received) {
                        self.acknowledged_rollbacks.insert((*stream, stored));
                        self.events
                            .push(Event::RollbackRepaired { stream: *stream });
                    } else {
                        self.raise(Alarm::Rollback {
                            stream: *stream,
                            received,
                            stored,
                        });
                    }
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
        // The own stream (read again after a restart) verifies with the own key.
        let own = *stream == self.device;
        if own && head.seq >= self.sent.seq {
            return Ok(false);
        }
        let key = if own {
            Some(self.signer.verifying_key())
        } else {
            self.trust.key(stream)
        };
        let Some(key) = key else {
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
                } else if candidates.iter().any(|(s, _)| *s > want)
                    && self.anchor_stream(transport, stream, wall_ms)
                {
                    // A gap the store cannot fill (a restored rollback): a snapshot covers it.
                    head = self.heads.get(stream).copied().unwrap_or(head);
                    received = true;
                    continue;
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
            self.entries_since_snapshot += count as u64;
            self.confirm_snapshot_ref(stream, segment.header.first_seq, &entries);
            for (seq, entry) in entries {
                match entry {
                    // Own checkpoints read again after a restart say nothing new.
                    Entry::Checkpoint(_) if own => {}
                    Entry::SelfJoin { .. } if own && seq == 1 && !is_root => {
                        self.trust.set_pending_self(self.device)
                    }
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
                    // The main device's snapshot covers this device's own segments up to its
                    // frontier: restoring them is the main device's job from now on.
                    Entry::Snapshot { frontier, .. } => {
                        if is_root {
                            if let Some(h) = frontier.get(&self.device) {
                                self.own_covered = self.own_covered.max(h.seq);
                            }
                        }
                    }
                    Entry::HeaderSeen { .. } => self.note_header_entry(*stream, seq, &entry),
                    Entry::Header(_) if is_root => self.note_header_entry(*stream, seq, &entry),
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
            self.segment_ends
                .entry(*stream)
                .or_default()
                .insert(head.seq);
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
                let plausible = claimed.seq <= received.saturating_add(MAX_CLAIM_AHEAD);
                let by_claimant = self
                    .claims
                    .values()
                    .flatten()
                    .filter(|c| c.by == o.from)
                    .count();
                if claimed.seq > received && plausible && by_claimant < MAX_CLAIMS_PER_CLAIMANT {
                    let list = self.claims.entry(*device).or_default();
                    if !list.iter().any(|c| c.head == *claimed) {
                        list.push(Claim {
                            head: *claimed,
                            since_ms: wall_ms,
                            by: o.from,
                            at: o.at,
                            reported: false,
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
            self.own_claim_mismatch(claimed.seq, by);
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
            _ => self.own_claim_mismatch(claimed.seq, by),
        }
    }

    /// Another history of this device's own stream: if the main device says so, another
    /// copy of this device wrote there and this one retires; anyone else's word is a dispute.
    fn own_claim_mismatch(&mut self, seq: u64, by: DeviceId) {
        if by == self.trust.root() {
            self.events.push(Event::OwnStreamConflict);
            self.retire_due = Some(RetireReason::OtherCopyWrote);
        } else {
            self.claim_mismatch(self.device, seq, by);
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
        }
        for c in reached {
            let known = self.hashes.get(stream).and_then(|h| h.get(&c.head.seq));
            if known.is_some_and(|h| *h != c.head.hash) {
                self.claim_mismatch(*stream, c.head.seq, c.by);
            }
        }
    }

    /// Every unmet claim older than a day is reported once (a bogus claim cannot hide a
    /// later real one).
    fn report_withheld(&mut self, wall_ms: u64) {
        let mut overdue = Vec::new();
        for (from, list) in self.claims.iter_mut() {
            for c in list.iter_mut() {
                if !c.reported && wall_ms >= c.since_ms + WITHHELD_AFTER_MS {
                    c.reported = true;
                    overdue.push((*from, c.head.seq));
                }
            }
        }
        for (from, claimed_seq) in overdue {
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
        // A provisional cut (from the head file) the stream's Revoke may raise: the records
        // skipped past it are read again (review G1).
        let before = match entry {
            Entry::Revoke { device, .. } => self
                .trust
                .device(device)
                .and_then(|d| d.cut)
                .map(|c| (*device, c)),
            _ => None,
        };
        let result = self.trust.apply_root(seq, entry, seen);
        if let (Ok(true), Some((device, old))) = (&result, before) {
            if self
                .trust
                .device(&device)
                .and_then(|d| d.cut)
                .is_some_and(|c| c > old)
            {
                self.reread_after(device, old);
            }
        }
        if result.is_ok() && is_trust_entry(entry) && !self.root_log.iter().any(|(s, _)| *s == seq)
        {
            self.root_log.push((seq, entry.clone()));
        }
        match result {
            Ok(true) => {
                if matches!(entry, Entry::Revoke { .. }) {
                    self.revoked_since_snapshot = true;
                }
                self.trust_changed()
            }
            Ok(false) => {}
            Err(e) => self.events.push(Event::TrustEntryIgnored {
                from: root,
                seq,
                reason: e.to_string(),
            }),
        }
    }

    /// Receives `stream` again after position `seq` (a cut rose above records skipped past
    /// it): what is waiting from there is dropped and read anew.
    fn reread_after(&mut self, stream: DeviceId, seq: u64) {
        let hash = if seq == 0 {
            Some(chain_genesis(&self.account_id, &stream))
        } else {
            self.hashes.get(&stream).and_then(|h| h.get(&seq)).copied()
        };
        let Some(hash) = hash else {
            return;
        };
        for ((s, _), queue) in self.lanes.iter_mut() {
            if *s == stream {
                queue.retain(|p| p.seq <= seq);
            }
        }
        self.lanes.retain(|_, q| !q.is_empty());
        let left = self
            .lanes
            .iter()
            .filter(|((s, _), _)| *s == stream)
            .map(|(_, q)| q.len())
            .sum();
        self.pending_count.insert(stream, left);
        if self.heads.get(&stream).is_some_and(|h| h.seq > seq) {
            self.heads.insert(stream, Head { seq, hash });
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
        // Claims made at positions that no longer count are dropped.
        let trust = &self.trust;
        for list in self.claims.values_mut() {
            list.retain(|c| trust.admits(&c.by, c.at));
        }
        self.claims.retain(|_, l| !l.is_empty());
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
    /// The stream is valid only up to `first_seq - 1`: whatever was applied of it from there
    /// on (records of other lanes) stops counting, so every reader ends with the same prefix.
    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        for queue in self
            .lanes
            .iter_mut()
            .filter(|((s, _), _)| s == stream)
            .map(|(_, q)| q)
        {
            queue.retain(|p| p.seq < first_seq);
        }
        self.lanes.retain(|_, q| !q.is_empty());
        let left = self
            .lanes
            .iter()
            .filter(|((s, _), _)| s == stream)
            .map(|(_, q)| q.len())
            .sum();
        self.pending_count.insert(*stream, left);
        if self.trust.invalidate_from(*stream, first_seq) {
            self.trust_changed();
        }
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

    /// Something occupies this device's own stream beyond its confirmed position. Only a
    /// segment that verifies with this device's own key proves another copy of it (a clone,
    /// a restored backup): then it retires. Anything else (a keyless writer's junk, a squatter)
    /// is deleted and the device goes on by itself (review F1); only if deleting fails is it
    /// an alarm. Returns whether the way is clear again.
    fn own_stream_occupied(&mut self, transport: &impl Transport) -> bool {
        let own_key = self.signer.verifying_key();
        let unsent = self.unsent.as_ref().map(|u| u.bytes.clone());
        let mut junk = Vec::new();
        let mut copy = false;
        if let Ok(found) = transport.segments(&self.device, self.sent.seq) {
            for f in found {
                let Fetched::Ready(bytes) = f else { continue };
                if Some(&bytes) == unsent.as_ref() {
                    continue;
                }
                let Ok(header) = SegmentHeader::parse(&bytes) else {
                    continue;
                };
                if header.device_id != self.device || header.first_seq <= self.sent.seq {
                    continue;
                }
                let verified = decrypt_segment(&self.segment_key, &bytes)
                    .ok()
                    .and_then(|u| u.verify(&own_key).ok())
                    .is_some();
                if verified {
                    copy = true;
                } else {
                    junk.push(header.first_seq);
                }
            }
        }
        if copy {
            self.events.push(Event::OwnStreamConflict);
            self.retire_due = Some(RetireReason::OtherCopyWrote);
            return false;
        }
        // Nothing found (the store did not list it this time): try again next round.
        let mut cleared = !junk.is_empty();
        for seq in junk {
            if transport.delete_segment(&self.device, seq).is_ok() {
                self.events.push(Event::OwnStreamCleaned { seq });
            } else {
                cleared = false;
                self.raise_own_tampered(seq);
            }
        }
        cleared
    }

    /// Makes the store hold this device's kept segments byte for byte: a missing one is
    /// appended again (a rollback of the store, or a partitioned view, repaired by itself), and
    /// something else at its position is deleted first, unless it is signed with the own key
    /// (another copy of this device: retire). Returns whether the stream is whole again.
    fn heal_own_stream(&mut self, transport: &impl Transport) -> bool {
        let Some(lowest) = self.own_segments.keys().next().copied() else {
            return true;
        };
        let Ok(found) = transport.segments(&self.device, lowest - 1) else {
            return true;
        };
        let stored: BTreeMap<u64, Vec<u8>> = found
            .into_iter()
            .filter_map(|f| match f {
                Fetched::Ready(b) => Some(b),
                _ => None,
            })
            .filter_map(|b| Some((SegmentHeader::parse(&b).ok()?.first_seq, b)))
            .collect();
        // Segments the store holds and the main device's snapshot covers need not be kept.
        let covered = self.own_covered;
        self.own_segments
            .retain(|f, b| *f > covered || stored.get(f) != Some(b));
        let own_key = self.signer.verifying_key();
        let kept: Vec<(u64, Vec<u8>)> = self
            .own_segments
            .iter()
            .filter(|(f, b)| stored.get(f) != Some(b))
            .map(|(f, b)| (*f, b.clone()))
            .collect();
        let mut repaired = false;
        for (first, bytes) in kept {
            // Appending says for sure whether something else is there (a listing may lie).
            match transport.append(&bytes) {
                Ok(AppendOutcome::Appended) => {
                    repaired = true;
                    continue;
                }
                Ok(AppendOutcome::AlreadyThere) => continue,
                Ok(AppendOutcome::Conflict) => {}
                Err(_) => return false,
            }
            let occupant = transport
                .segments(&self.device, first - 1)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|f| match f {
                    Fetched::Ready(b) => Some(b),
                    _ => None,
                })
                .find(|b| SegmentHeader::parse(b).is_ok_and(|h| h.first_seq == first));
            let Some(occupant) = occupant else {
                return false;
            };
            let ours = decrypt_segment(&self.segment_key, &occupant)
                .ok()
                .and_then(|u| u.verify(&own_key).ok())
                .is_some();
            if ours {
                self.events.push(Event::OwnStreamConflict);
                self.retire_due = Some(RetireReason::OtherCopyWrote);
                return false;
            }
            if transport.delete_segment(&self.device, first).is_err() {
                self.raise_own_tampered(first);
                return false;
            }
            self.events.push(Event::OwnStreamCleaned { seq: first });
            match transport.append(&bytes) {
                Ok(AppendOutcome::Appended | AppendOutcome::AlreadyThere) => repaired = true,
                _ => return false,
            }
        }
        if repaired {
            self.events.push(Event::RollbackRepaired {
                stream: self.device,
            });
        }
        true
    }

    /// The user chose to leave this device's id behind (its stream is occupied for good):
    /// it continues under a new id, pending approval. The main device cannot; it asks to start
    /// over instead.
    pub fn leave_id(&mut self, wall_ms: u64) -> Result<()> {
        if self.is_root() {
            return Err(Error::Refused(
                "the main device cannot leave its id (that would stop the account)".into(),
            ));
        }
        self.alarms
            .retain(|a| !matches!(a, Alarm::OwnStreamTampered { .. }));
        self.retire(RetireReason::OtherCopyWrote, wall_ms)
    }

    fn raise_own_tampered(&mut self, seq: u64) {
        let alarm = Alarm::OwnStreamTampered { seq };
        if !self.alarms.contains(&alarm) {
            self.events.push(Event::Alarm(alarm.clone()));
            self.alarms.push(alarm);
        }
    }

    fn push(&mut self, transport: &impl Transport) {
        if self.halted || self.retire_due.is_some() {
            return;
        }
        if self
            .alarms
            .iter()
            .any(|a| matches!(a, Alarm::OwnStreamTampered { .. }))
        {
            return;
        }
        self.upload_header_files(transport);
        if !self.heal_own_stream(transport) {
            return;
        }
        // The store's head of this device's own stream must be where this device left it
        // (checked every round, not only before writing: an idle device's lost segments
        // matter to every reader).
        for _ in 0..2 {
            match transport.head(&self.device) {
                Ok(stored) => {
                    let stored = stored.unwrap_or(0);
                    if stored > self.sent.seq && self.unsent.is_none() {
                        // Something beyond what this device wrote: cleaned up if it is not
                        // this device's, then the head is looked at again.
                        if !self.own_stream_occupied(transport) {
                            return;
                        }
                        continue;
                    }
                    let acknowledged = self.acknowledged_rollbacks.contains(&(self.device, stored));
                    if stored < self.sent.seq
                        && !acknowledged
                        && self.snapshot_covers(transport, &self.device, self.sent.seq)
                    {
                        // The main device's snapshot covers what the store lost.
                        self.acknowledged_rollbacks.insert((self.device, stored));
                        self.events.push(Event::RollbackRepaired {
                            stream: self.device,
                        });
                    } else if stored < self.sent.seq && !acknowledged {
                        self.raise(Alarm::Rollback {
                            stream: self.device,
                            received: self.sent.seq,
                            stored,
                        });
                        return;
                    }
                }
                Err(e) => self.events.push(Event::HeadUnknown {
                    stream: self.device,
                    reason: e.to_string(),
                }),
            }
            break;
        }
        if self.unsent.is_none() && self.outbox.is_empty() {
            return;
        }
        if self.outbox_unsaved && !self.save_outbox() {
            return;
        }
        let mut retries = 0;
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
                self.unsent = Some(SealedSegment {
                    bytes,
                    versions,
                    last_seq,
                    last_hash,
                });
                // Persisted before the append, so a restart retries these exact bytes.
                if !self.save_outbox() {
                    return;
                }
            }
            let unsent = self.unsent.as_ref().expect("set above");
            match transport.append(&unsent.bytes) {
                Ok(AppendOutcome::Appended | AppendOutcome::AlreadyThere) => {
                    let first = self.sent.seq + 1;
                    self.own_segments.insert(first, unsent.bytes.clone());
                    while self.own_segments.len() > MAX_OWN_SEGMENTS_KEPT {
                        self.own_segments.pop_first();
                    }
                    self.sent = Head {
                        seq: unsent.last_seq,
                        hash: unsent.last_hash,
                    };
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                    self.save_outbox();
                    self.upload_header_files(transport);
                }
                Ok(AppendOutcome::Conflict) => {
                    retries += 1;
                    if retries > 3 || !self.own_stream_occupied(transport) {
                        return;
                    }
                    // Appending again only continues the stream if the store still holds
                    // everything before this position (no gap).
                    let stored = transport.head(&self.device).ok().flatten().unwrap_or(0);
                    if stored < self.sent.seq
                        && !self.acknowledged_rollbacks.contains(&(self.device, stored))
                    {
                        return;
                    }
                }
                Err(e) => {
                    self.events.push(Event::PushFailed(e.to_string()));
                    return;
                }
            }
        }
    }
}

/// The main device's trust log (what its snapshots carry as entries) holds only trust
/// entries: a snapshot entry in it made every later snapshot unusable (`check_entries`).
fn is_trust_entry(entry: &Entry) -> bool {
    matches!(
        entry,
        Entry::Genesis { .. } | Entry::Endorse { .. } | Entry::Revoke { .. }
    )
}

#[cfg(test)]
mod adversary_tests;
#[cfg(test)]
mod attachment_tests;
#[cfg(test)]
mod attack_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod resume_tests;
#[cfg(test)]
mod tests;
