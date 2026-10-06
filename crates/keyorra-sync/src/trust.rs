//! Which devices count (spec §4.3, §4.6): **root-only authority**.
//!
//! The root (the device where sync was turned on, named by the account header, its key known
//! from the header or the setup code, never from the store) is the only device that approves
//! (`Endorse`) or removes (`Revoke`) devices. Trust is the root's stream read in order: no
//! other stream's trust entries count (they are ignored and reported), so there is nothing to
//! resolve between devices, no fixpoint and no order to depend on.
//!
//! - A device approved by the root counts with the key the root gave it, from its first entry
//!   until its cut. The first decision about an id is final: a second `Endorse` of it, or an
//!   `Endorse` after its removal, is ignored.
//! - The root removing an approved device cuts its stream at `last_valid_seq` (never below the
//!   device's position in the root's own earlier checkpoints); removing a device it never
//!   approved (a self-joined one) means nothing of it ever counts.
//! - A device that joined with the Emergency Kit (`SelfJoin`, first entry of its own stream)
//!   counts for nobody until the root approves it; it reads, and its own writes stay pending
//!   (visible only on itself).
//! - The root cannot be removed: a stolen root is answered by starting a new account (key
//!   rotation, after phase B).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::entry::{verify_endorsement, Entry};
use crate::fold::Admission;
use crate::{AccountId, DeviceId};

/// The short code of a device key that the user compares on the main device and on the
/// joining device before approving: 48 bits of `SHA-256("keyorra/sync/v1/key-fingerprint\0"
/// ‖ key)`, as `xxxx-xxxx-xxxx`.
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(crate::labels::tagged(
        crate::labels::KEY_FINGERPRINT,
        &[key.as_bytes()],
    ));
    let hex = data_encoding::HEXLOWER.encode(&digest[..6]);
    format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Introduction {
    Root,
    /// Approved by the root at this position of the root's stream.
    Endorsed {
        at_seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub key: VerifyingKey,
    pub name: String,
    pub introduced: Introduction,
    /// Entries after this sequence number do not count.
    pub cut: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// An approval or removal outside the root's stream.
    NotFromRoot,
    /// `Genesis` anywhere but at the root's sequence 1, `SelfJoin` in the root's stream.
    Misplaced,
    WrongAccount,
    BadSignature,
    /// The root's `Genesis` carries another key than the known one.
    RootKeyMismatch,
    /// The root already approved or removed this id.
    AlreadyDecided,
    /// The root cannot be removed (a stolen root: start a new account).
    RootCannotBeRemoved,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TrustError::NotFromRoot => "only the main device approves or removes devices",
            TrustError::Misplaced => "introduction entry out of place",
            TrustError::WrongAccount => "genesis of another account",
            TrustError::BadSignature => "endorsement signature does not verify",
            TrustError::RootKeyMismatch => "the root's genesis key is not the known one",
            TrustError::AlreadyDecided => "this device was already approved or removed",
            TrustError::RootCannotBeRemoved => "the main device cannot be removed",
        })
    }
}

impl std::error::Error for TrustError {}

/// Self-joined devices listed at most; further ones are ignored until some are decided on
/// (an AK holder could otherwise create any number).
pub const MAX_UNAPPROVED: usize = 64;

/// A device that joined with the Emergency Kit and awaits the root's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unapproved {
    pub key: VerifyingKey,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Trust {
    account_id: AccountId,
    root: DeviceId,
    /// Approved devices, the root included.
    devices: BTreeMap<DeviceId, DeviceInfo>,
    /// Removed by the root without ever being approved: nothing of them counts.
    removed: BTreeSet<DeviceId>,
    unapproved: BTreeMap<DeviceId, Unapproved>,
    /// This device, if it self-joined: its own writes count for itself while pending.
    pending_self: Option<DeviceId>,
    /// Streams that broke the protocol: nothing from this position on counts (local, not a
    /// trust decision; every reader finds the same first violation).
    invalid_from: BTreeMap<DeviceId, u64>,
    /// Cuts taken from the main device's head file before its stream delivered the
    /// `Revoke`; the stream's entry settles them.
    provisional: BTreeSet<DeviceId>,
}

impl Trust {
    pub fn new(account_id: AccountId, root: DeviceId, root_key: VerifyingKey) -> Trust {
        let mut devices = BTreeMap::new();
        devices.insert(
            root,
            DeviceInfo {
                key: root_key,
                name: String::new(),
                introduced: Introduction::Root,
                cut: None,
            },
        );
        Trust {
            account_id,
            root,
            devices,
            removed: BTreeSet::new(),
            unapproved: BTreeMap::new(),
            pending_self: None,
            invalid_from: BTreeMap::new(),
            provisional: BTreeSet::new(),
        }
    }

    pub fn root(&self) -> DeviceId {
        self.root
    }

    pub fn root_key(&self) -> VerifyingKey {
        self.devices[&self.root].key
    }

    /// Approved devices, the root included.
    pub fn devices(&self) -> &BTreeMap<DeviceId, DeviceInfo> {
        &self.devices
    }

    pub fn device(&self, device: &DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(device)
    }

    /// The key a stream is verified with: only ever the root's, or one the root gave.
    pub fn key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.devices.get(device).map(|d| d.key)
    }

    /// Self-joined devices awaiting the root's decision.
    pub fn unapproved(&self) -> &BTreeMap<DeviceId, Unapproved> {
        &self.unapproved
    }

    /// Removed before it was approved: nothing of it ever counts.
    pub fn is_removed(&self, device: &DeviceId) -> bool {
        self.removed.contains(device)
    }

    /// A removal the main device announced in its signed head file before its stream
    /// delivered it (review F1): an approved device is cut at once at `last_valid_seq`. Its
    /// `Revoke` in the stream settles the cut later. Returns whether anything changed.
    pub fn provisional_revoke(&mut self, device: DeviceId, last_valid_seq: u64) -> bool {
        match self.devices.get_mut(&device) {
            Some(d) if d.cut.is_none() && device != self.root => {
                d.cut = Some(last_valid_seq);
                self.provisional.insert(device);
                true
            }
            _ => false,
        }
    }

    /// `device`'s entry at `seq` broke the protocol: from there on nothing of it counts.
    /// Returns whether that changed anything.
    pub fn invalidate_from(&mut self, device: DeviceId, seq: u64) -> bool {
        let e = self.invalid_from.entry(device).or_insert(u64::MAX);
        if seq < *e {
            *e = seq;
            true
        } else {
            false
        }
    }

    /// This device self-joined: its own writes count for itself until the root decides.
    pub fn set_pending_self(&mut self, device: DeviceId) {
        self.pending_self = Some(device);
    }

    /// A valid `SelfJoin` was seen at the start of `device`'s stream. Returns whether it is
    /// new (it is ignored for an id the root already decided on).
    pub fn note_self_join(&mut self, device: DeviceId, key: VerifyingKey, name: &str) -> bool {
        if device == self.root
            || self.devices.contains_key(&device)
            || self.removed.contains(&device)
            || self.unapproved.contains_key(&device)
            || self.unapproved.len() >= MAX_UNAPPROVED
        {
            return false;
        }
        self.unapproved.insert(
            device,
            Unapproved {
                key,
                name: name.to_owned(),
            },
        );
        true
    }

    /// Applies an entry of the root's stream at `seq`, in stream order. `seen(d)` is `d`'s
    /// position in the root's latest checkpoint before the entry (counted only where it
    /// matches the reader's chain). Other entries are ignored. Returns whether trust changed;
    /// an error means the entry is ignored.
    pub fn apply_root(
        &mut self,
        seq: u64,
        entry: &Entry,
        seen: impl Fn(&DeviceId) -> u64,
    ) -> Result<bool, TrustError> {
        let root_key = self.root_key();
        match entry {
            Entry::Genesis {
                account_id,
                key,
                name,
            } => {
                if seq != 1 {
                    return Err(TrustError::Misplaced);
                }
                if *account_id != self.account_id {
                    return Err(TrustError::WrongAccount);
                }
                if key != root_key.as_bytes() {
                    return Err(TrustError::RootKeyMismatch);
                }
                let root = self.devices.get_mut(&self.root).expect("root");
                root.name = name.clone();
                Ok(true)
            }
            Entry::SelfJoin { .. } => Err(TrustError::Misplaced),
            Entry::Endorse {
                device,
                key,
                name,
                sig,
            } => {
                if !verify_endorsement(&root_key, &self.account_id, device, key, sig) {
                    return Err(TrustError::BadSignature);
                }
                if *device == self.root {
                    return Err(TrustError::Misplaced);
                }
                if self.devices.contains_key(device) || self.removed.contains(device) {
                    return Err(TrustError::AlreadyDecided);
                }
                let key = VerifyingKey::from_bytes(key).map_err(|_| TrustError::BadSignature)?;
                self.unapproved.remove(device);
                self.devices.insert(
                    *device,
                    DeviceInfo {
                        key,
                        name: name.clone(),
                        introduced: Introduction::Endorsed { at_seq: seq },
                        cut: None,
                    },
                );
                Ok(true)
            }
            Entry::Revoke {
                device,
                last_valid_seq,
                ..
            } => {
                if *device == self.root {
                    return Err(TrustError::RootCannotBeRemoved);
                }
                if self.removed.contains(device) {
                    return Err(TrustError::AlreadyDecided);
                }
                if self.provisional.remove(device) {
                    let d = self
                        .devices
                        .get_mut(device)
                        .expect("provisional cuts are of devices");
                    let cut = (*last_valid_seq).max(seen(device));
                    let changed = d.cut != Some(cut);
                    d.cut = Some(cut);
                    return Ok(changed);
                }
                match self.devices.get_mut(device) {
                    Some(d) if d.cut.is_some() => Err(TrustError::AlreadyDecided),
                    Some(d) => {
                        d.cut = Some((*last_valid_seq).max(seen(device)));
                        Ok(true)
                    }
                    None => {
                        self.unapproved.remove(device);
                        self.removed.insert(*device);
                        Ok(true)
                    }
                }
            }
            Entry::Put(_)
            | Entry::Checkpoint(_)
            | Entry::Header(_)
            | Entry::HeaderSeen { .. }
            | Entry::Snapshot { .. } => Ok(false),
        }
    }
}

impl Admission for Trust {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
        if self
            .invalid_from
            .get(stream)
            .is_some_and(|from| seq >= *from)
        {
            return false;
        }
        if let Some(d) = self.devices.get(stream) {
            return d.cut.is_none_or(|c| seq <= c);
        }
        self.pending_self == Some(*stream) && !self.removed.contains(stream)
    }

    fn is_cut(&self, device: &DeviceId) -> bool {
        self.removed.contains(device)
            || self.invalid_from.contains_key(device)
            || self.devices.get(device).is_some_and(|d| d.cut.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::sign_endorsement;
    use ed25519_dalek::SigningKey;

    const ACCOUNT: AccountId = [0x10; 16];
    const ROOT: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];
    const C: DeviceId = [3; 16];
    const D: DeviceId = [4; 16];

    fn signer(d: &DeviceId) -> SigningKey {
        SigningKey::from_bytes(&[0x40 + d[0]; 32])
    }

    fn pk(d: &DeviceId) -> VerifyingKey {
        signer(d).verifying_key()
    }

    fn base() -> Trust {
        let mut t = Trust::new(ACCOUNT, ROOT, pk(&ROOT));
        t.apply_root(1, &genesis(&pk(&ROOT)), |_| 0).unwrap();
        t.apply_root(2, &endorse_by(&ROOT, &B, &pk(&B)), |_| 0)
            .unwrap();
        t.apply_root(3, &endorse_by(&ROOT, &C, &pk(&C)), |_| 0)
            .unwrap();
        t
    }

    fn genesis(key: &VerifyingKey) -> Entry {
        Entry::Genesis {
            account_id: ACCOUNT,
            key: key.to_bytes(),
            name: "root".into(),
        }
    }

    fn endorse_by(by: &DeviceId, device: &DeviceId, key: &VerifyingKey) -> Entry {
        let key = key.to_bytes();
        Entry::Endorse {
            device: *device,
            key,
            name: "dev".into(),
            sig: sign_endorsement(&signer(by), &ACCOUNT, device, &key),
        }
    }

    fn revoke(device: &DeviceId, last_valid_seq: u64) -> Entry {
        Entry::Revoke {
            device: *device,
            last_valid_seq,
            last_valid_hash: [0; 32],
        }
    }

    fn cut(t: &Trust, d: &DeviceId) -> Option<u64> {
        t.device(d).and_then(|i| i.cut)
    }

    #[test]
    fn the_root_approves_and_removes() {
        let mut t = base();
        assert!(t.admits(&B, 100));
        assert_eq!(t.key(&B), Some(pk(&B)));
        t.apply_root(4, &revoke(&B, 7), |_| 0).unwrap();
        assert_eq!(cut(&t, &B), Some(7));
        assert!(t.admits(&B, 7) && !t.admits(&B, 8));
        assert!(t.admits(&ROOT, u64::MAX));
    }

    #[test]
    fn a_cut_is_never_below_what_the_root_had_seen() {
        let mut t = base();
        t.apply_root(4, &revoke(&B, 2), |d| if *d == B { 9 } else { 0 })
            .unwrap();
        assert_eq!(cut(&t, &B), Some(9));
    }

    #[test]
    fn the_first_decision_about_an_id_is_final() {
        let mut t = base();
        // Another key for an approved id: ignored (review C7a, N2: no quarantine to abuse).
        assert_eq!(
            t.apply_root(4, &endorse_by(&ROOT, &B, &pk(&D)), |_| 0),
            Err(TrustError::AlreadyDecided)
        );
        assert_eq!(t.key(&B), Some(pk(&B)));
        t.apply_root(5, &revoke(&B, 3), |_| 0).unwrap();
        assert_eq!(
            t.apply_root(6, &revoke(&B, 30), |_| 0),
            Err(TrustError::AlreadyDecided)
        );
        assert_eq!(cut(&t, &B), Some(3));
        // Removed without approval: never approved afterwards.
        t.apply_root(7, &revoke(&D, 0), |_| 0).unwrap();
        assert_eq!(
            t.apply_root(8, &endorse_by(&ROOT, &D, &pk(&D)), |_| 0),
            Err(TrustError::AlreadyDecided)
        );
        assert!(!t.admits(&D, 1));
    }

    #[test]
    fn the_root_cannot_be_removed() {
        let mut t = base();
        assert_eq!(
            t.apply_root(4, &revoke(&ROOT, 0), |_| 0),
            Err(TrustError::RootCannotBeRemoved)
        );
        assert!(t.admits(&ROOT, 1));
    }

    #[test]
    fn introductions_are_checked() {
        let mut t = Trust::new(ACCOUNT, ROOT, pk(&ROOT));
        assert_eq!(
            t.apply_root(1, &genesis(&pk(&D)), |_| 0),
            Err(TrustError::RootKeyMismatch)
        );
        assert_eq!(
            t.apply_root(2, &genesis(&pk(&ROOT)), |_| 0),
            Err(TrustError::Misplaced)
        );
        // An endorsement signed by anyone but the root does not verify.
        assert_eq!(
            t.apply_root(3, &endorse_by(&B, &D, &pk(&D)), |_| 0),
            Err(TrustError::BadSignature)
        );
        let key = pk(&ROOT).to_bytes();
        let self_join = Entry::SelfJoin {
            key,
            name: "kit".into(),
            sig: sign_endorsement(&signer(&ROOT), &ACCOUNT, &ROOT, &key),
        };
        assert_eq!(
            t.apply_root(1, &self_join, |_| 0),
            Err(TrustError::Misplaced)
        );
    }

    #[test]
    fn a_self_joined_device_counts_for_nobody_until_approved() {
        let mut t = base();
        assert!(t.note_self_join(D, pk(&D), "kit"));
        assert!(!t.admits(&D, 1));
        assert!(t.key(&D).is_none());
        assert!(t.unapproved().contains_key(&D));
        // On itself, its own writes count while pending.
        let mut own = t.clone();
        own.set_pending_self(D);
        assert!(own.admits(&D, 5));
        t.apply_root(4, &endorse_by(&ROOT, &D, &pk(&D)), |_| 0)
            .unwrap();
        assert!(t.admits(&D, 1));
        assert!(t.unapproved().is_empty());
    }

    #[test]
    fn the_unapproved_list_is_capped() {
        let mut t = base();
        for k in 0..(MAX_UNAPPROVED as u8 + 10) {
            let id: DeviceId = [0x80, k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            t.note_self_join(id, pk(&D), "kit");
        }
        assert_eq!(t.unapproved().len(), MAX_UNAPPROVED);
    }

    #[test]
    fn review_n6_removing_a_self_joined_device_hides_everything_it_wrote() {
        let mut t = base();
        t.note_self_join(D, pk(&D), "thief");
        t.set_pending_self(D);
        t.apply_root(4, &revoke(&D, 50), |_| 0).unwrap();
        assert!(t.is_removed(&D));
        assert!(!t.admits(&D, 1));
        assert!(t.is_cut(&D));
        assert!(!t.note_self_join(D, pk(&D), "again"));
    }
}
