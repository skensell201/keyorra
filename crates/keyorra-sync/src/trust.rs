//! Which devices count (spec §4.3, §4.6): derived from the trust entries of all streams.
//!
//! - The **root** (named by the account header) is introduced by `Genesis`, the first entry
//!   of its own stream. A **self-joined** device by `SelfJoin`, the first entry of its own
//!   stream (an alarm on every other device). Any other device by an `Endorse` from an
//!   introduced device, made at a position that device may still write at.
//! - `Revoke { device, last_valid_seq }` cuts `device`'s stream: later positions stop
//!   counting. It counts if the revoker is introduced without relying on the revoked device
//!   (so a device endorsed after its endorser's cut cannot revoke it back) or revokes itself,
//!   and if it was written before the revoker's own cut, unless that cut came from the device
//!   being revoked (mutual revocations both apply). Several revocations of one device: the
//!   earliest cut wins.
//!
//! Everything is recomputed from the recorded entries in `(stream, seq)` order, so the result
//! does not depend on the order in which entries arrived.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::entry::{verify_endorsement, Entry};
use crate::fold::Admission;
use crate::{AccountId, DeviceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Introduction {
    Root,
    /// Joined with the Emergency Kit, approved by no other device.
    SelfJoined,
    Endorsed {
        by: DeviceId,
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
    /// `Genesis`/`SelfJoin` anywhere but at sequence 1, or `Genesis` outside the root stream.
    Misplaced,
    WrongAccount,
    BadSignature,
    /// A device id endorsed with two different keys.
    KeyConflict(DeviceId),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::Misplaced => f.write_str("introduction entry out of place"),
            TrustError::WrongAccount => f.write_str("genesis of another account"),
            TrustError::BadSignature => f.write_str("endorsement signature does not verify"),
            TrustError::KeyConflict(d) => write!(
                f,
                "device {} endorsed with two keys",
                data_encoding::HEXLOWER.encode(&d[..4])
            ),
        }
    }
}

#[derive(Clone, Debug)]
struct Recorded {
    stream: DeviceId,
    seq: u64,
    entry: Entry,
}

#[derive(Clone, Debug)]
pub struct Trust {
    account_id: AccountId,
    root: DeviceId,
    recorded: Vec<Recorded>,
    devices: BTreeMap<DeviceId, DeviceInfo>,
}

type Known = BTreeMap<DeviceId, (VerifyingKey, String, Introduction)>;

impl Trust {
    pub fn new(account_id: AccountId, root: DeviceId) -> Trust {
        Trust {
            account_id,
            root,
            recorded: Vec::new(),
            devices: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> DeviceId {
        self.root
    }

    pub fn devices(&self) -> &BTreeMap<DeviceId, DeviceInfo> {
        &self.devices
    }

    pub fn device(&self, device: &DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(device)
    }

    pub fn key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.devices.get(device).map(|d| d.key)
    }

    /// Checks and records a trust entry found at `(stream, seq)`, whose segment verified with
    /// `stream_key`. Other entries are ignored. Returns whether the derived state changed.
    pub fn record(
        &mut self,
        stream: DeviceId,
        stream_key: &VerifyingKey,
        seq: u64,
        entry: &Entry,
    ) -> Result<bool, TrustError> {
        match entry {
            Entry::Genesis {
                account_id, key, ..
            } => {
                if seq != 1 || stream != self.root || key != stream_key.as_bytes() {
                    return Err(TrustError::Misplaced);
                }
                if *account_id != self.account_id {
                    return Err(TrustError::WrongAccount);
                }
            }
            Entry::SelfJoin { key, sig, .. } => {
                if seq != 1 || key != stream_key.as_bytes() {
                    return Err(TrustError::Misplaced);
                }
                if !verify_endorsement(stream_key, &self.account_id, &stream, key, sig) {
                    return Err(TrustError::BadSignature);
                }
            }
            Entry::Endorse {
                device, key, sig, ..
            } => {
                if !verify_endorsement(stream_key, &self.account_id, device, key, sig) {
                    return Err(TrustError::BadSignature);
                }
                let conflicting = self.recorded.iter().any(|r| match &r.entry {
                    Entry::Endorse {
                        device: d, key: k, ..
                    } => d == device && k != key,
                    Entry::SelfJoin { key: k, .. } => r.stream == *device && k != key,
                    Entry::Genesis { key: k, .. } => r.stream == *device && k != key,
                    _ => false,
                });
                if conflicting {
                    return Err(TrustError::KeyConflict(*device));
                }
            }
            Entry::Revoke { .. } => {}
            Entry::Put(_) | Entry::Checkpoint(_) => return Ok(false),
        }
        if self
            .recorded
            .iter()
            .any(|r| r.stream == stream && r.seq == seq)
        {
            return Ok(false);
        }
        let at = self
            .recorded
            .partition_point(|r| (r.stream, r.seq) < (stream, seq));
        self.recorded.insert(
            at,
            Recorded {
                stream,
                seq,
                entry: entry.clone(),
            },
        );
        let derived = self.derive();
        let changed = derived != self.devices;
        self.devices = derived;
        Ok(changed)
    }

    /// Devices introduced through `SelfJoin`.
    pub fn self_joined(&self) -> impl Iterator<Item = (&DeviceId, &DeviceInfo)> {
        self.devices
            .iter()
            .filter(|(_, d)| d.introduced == Introduction::SelfJoined)
    }

    fn derive(&self) -> BTreeMap<DeviceId, DeviceInfo> {
        let no_cuts = BTreeMap::new();
        // Candidates: revocations by a device introduced without the revoked one (or by the
        // device itself), as (revoker, revoker's seq, target, cut).
        let candidates: Vec<(DeviceId, u64, DeviceId, u64)> = self
            .recorded
            .iter()
            .filter_map(|r| match &r.entry {
                Entry::Revoke {
                    device,
                    last_valid_seq,
                } if r.stream == *device
                    || self.closure(&no_cuts, Some(device)).contains_key(&r.stream) =>
                {
                    Some((r.stream, r.seq, *device, *last_valid_seq))
                }
                _ => None,
            })
            .collect();
        // A revocation written after its author was itself cut does not count, except when
        // that cut came from the device being revoked now (mutual revocations both apply).
        let cut_of = |device: &DeviceId, ignoring: &DeviceId| {
            candidates
                .iter()
                .filter(|(by, _, target, _)| target == device && by != ignoring)
                .map(|(_, _, _, cut)| *cut)
                .min()
        };
        let mut cuts: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (by, at, target, cut) in &candidates {
            if by == target || cut_of(by, target).is_none_or(|c| *at <= c) {
                let e = cuts.entry(*target).or_insert(*cut);
                *e = (*e).min(*cut);
            }
        }
        self.closure(&cuts, None)
            .into_iter()
            .map(|(id, (key, name, introduced))| {
                (
                    id,
                    DeviceInfo {
                        key,
                        name,
                        introduced,
                        cut: cuts.get(&id).copied(),
                    },
                )
            })
            .collect()
    }

    /// Devices introduced when `cuts` apply, leaving out `excluded` and everything that
    /// depends on it.
    fn closure(&self, cuts: &BTreeMap<DeviceId, u64>, excluded: Option<&DeviceId>) -> Known {
        let mut known = Known::new();
        for r in &self.recorded {
            if Some(&r.stream) == excluded {
                continue;
            }
            match &r.entry {
                Entry::Genesis { key, name, .. } => {
                    if let Ok(k) = VerifyingKey::from_bytes(key) {
                        known.insert(r.stream, (k, name.clone(), Introduction::Root));
                    }
                }
                Entry::SelfJoin { key, name, .. } => {
                    if let Ok(k) = VerifyingKey::from_bytes(key) {
                        known.entry(r.stream).or_insert((
                            k,
                            name.clone(),
                            Introduction::SelfJoined,
                        ));
                    }
                }
                _ => {}
            }
        }
        loop {
            let mut changed = false;
            for r in &self.recorded {
                let Entry::Endorse {
                    device, key, name, ..
                } = &r.entry
                else {
                    continue;
                };
                if Some(device) == excluded
                    || known.contains_key(device)
                    || !known.contains_key(&r.stream)
                    || cuts.get(&r.stream).is_some_and(|c| r.seq > *c)
                {
                    continue;
                }
                if let Ok(k) = VerifyingKey::from_bytes(key) {
                    known.insert(
                        *device,
                        (
                            k,
                            name.clone(),
                            Introduction::Endorsed {
                                by: r.stream,
                                at_seq: r.seq,
                            },
                        ),
                    );
                    changed = true;
                }
            }
            if !changed {
                return known;
            }
        }
    }
}

impl Admission for Trust {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
        self.devices
            .get(stream)
            .is_some_and(|d| d.cut.is_none_or(|c| seq <= c))
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

    fn genesis() -> Entry {
        Entry::Genesis {
            account_id: ACCOUNT,
            key: pk(&ROOT).to_bytes(),
            name: "root".into(),
        }
    }

    fn endorse(by: &DeviceId, device: &DeviceId) -> Entry {
        let key = pk(device).to_bytes();
        Entry::Endorse {
            device: *device,
            key,
            name: "dev".into(),
            sig: sign_endorsement(&signer(by), &ACCOUNT, device, &key),
        }
    }

    fn self_join(device: &DeviceId) -> Entry {
        let key = pk(device).to_bytes();
        Entry::SelfJoin {
            key,
            name: "kit".into(),
            sig: sign_endorsement(&signer(device), &ACCOUNT, device, &key),
        }
    }

    fn revoke(device: &DeviceId, last_valid_seq: u64) -> Entry {
        Entry::Revoke {
            device: *device,
            last_valid_seq,
        }
    }

    fn rec(t: &mut Trust, stream: DeviceId, seq: u64, e: Entry) -> Result<bool, TrustError> {
        t.record(stream, &pk(&stream), seq, &e)
    }

    fn base() -> Trust {
        let mut t = Trust::new(ACCOUNT, ROOT);
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        rec(&mut t, ROOT, 2, endorse(&ROOT, &B)).unwrap();
        t
    }

    #[test]
    fn root_and_endorsed_devices_are_admitted() {
        let t = base();
        assert_eq!(t.device(&ROOT).unwrap().introduced, Introduction::Root);
        assert_eq!(
            t.device(&B).unwrap().introduced,
            Introduction::Endorsed {
                by: ROOT,
                at_seq: 2
            }
        );
        assert!(t.admits(&B, 1_000));
        assert!(!t.admits(&C, 1));
        assert_eq!(t.key(&B), Some(pk(&B)));
    }

    #[test]
    fn introductions_are_checked() {
        let mut t = Trust::new(ACCOUNT, ROOT);
        assert_eq!(rec(&mut t, ROOT, 2, genesis()), Err(TrustError::Misplaced));
        assert_eq!(rec(&mut t, B, 1, genesis()), Err(TrustError::Misplaced));
        let other = Entry::Genesis {
            account_id: [0x11; 16],
            key: pk(&ROOT).to_bytes(),
            name: "x".into(),
        };
        assert_eq!(rec(&mut t, ROOT, 1, other), Err(TrustError::WrongAccount));
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        let mut forged = endorse(&ROOT, &B);
        if let Entry::Endorse { sig, .. } = &mut forged {
            sig[0] ^= 1;
        }
        assert_eq!(rec(&mut t, ROOT, 2, forged), Err(TrustError::BadSignature));
        assert_eq!(rec(&mut t, C, 2, self_join(&C)), Err(TrustError::Misplaced));
    }

    #[test]
    fn a_device_cannot_get_two_keys() {
        let mut t = base();
        let key = pk(&C).to_bytes();
        let twisted = Entry::Endorse {
            device: B,
            key,
            name: "evil".into(),
            sig: sign_endorsement(&signer(&ROOT), &ACCOUNT, &B, &key),
        };
        assert_eq!(
            rec(&mut t, ROOT, 3, twisted),
            Err(TrustError::KeyConflict(B))
        );
    }

    #[test]
    fn self_joined_devices_count_and_are_listed() {
        let mut t = base();
        assert!(rec(&mut t, C, 1, self_join(&C)).unwrap());
        assert_eq!(t.device(&C).unwrap().introduced, Introduction::SelfJoined);
        assert_eq!(
            t.self_joined().map(|(d, _)| *d).collect::<Vec<_>>(),
            vec![C]
        );
    }

    #[test]
    fn a_revocation_cuts_the_stream_and_its_later_endorsements() {
        let mut t = base();
        rec(&mut t, B, 5, endorse(&B, &C)).unwrap();
        rec(&mut t, B, 9, endorse(&B, &D)).unwrap();
        assert!(t.device(&D).is_some());
        rec(&mut t, ROOT, 3, revoke(&B, 7)).unwrap();
        assert_eq!(t.device(&B).unwrap().cut, Some(7));
        assert!(t.admits(&B, 7) && !t.admits(&B, 8));
        assert!(t.device(&C).is_some(), "endorsed before the cut");
        assert!(t.device(&D).is_none(), "endorsed after the cut");
    }

    #[test]
    fn a_device_endorsed_after_the_cut_cannot_revoke_its_endorser_back() {
        let mut t = base();
        rec(&mut t, B, 5, endorse(&B, &C)).unwrap();
        rec(&mut t, ROOT, 3, revoke(&B, 4)).unwrap();
        // C exists only through B's post-cut endorsement; its revocation of the root is void.
        rec(&mut t, C, 1, revoke(&ROOT, 1)).unwrap();
        assert!(t.device(&C).is_none());
        assert_eq!(t.device(&ROOT).unwrap().cut, None);
        assert_eq!(t.device(&B).unwrap().cut, Some(4));
    }

    #[test]
    fn mutual_revocations_both_apply_and_self_revocation_counts() {
        let mut t = base();
        rec(&mut t, C, 1, self_join(&C)).unwrap();
        rec(&mut t, B, 3, revoke(&C, 2)).unwrap();
        rec(&mut t, C, 3, revoke(&B, 1)).unwrap();
        assert_eq!(t.device(&B).unwrap().cut, Some(1));
        assert_eq!(t.device(&C).unwrap().cut, Some(2));
        let mut u = base();
        rec(&mut u, B, 4, revoke(&B, 3)).unwrap();
        assert_eq!(u.device(&B).unwrap().cut, Some(3));
        // The earliest cut wins.
        rec(&mut u, ROOT, 3, revoke(&B, 1)).unwrap();
        assert_eq!(u.device(&B).unwrap().cut, Some(1));
    }

    #[test]
    fn a_revoked_device_cannot_revoke_others_after_its_cut() {
        let mut t = base();
        rec(&mut t, ROOT, 3, endorse(&ROOT, &C)).unwrap();
        rec(&mut t, ROOT, 4, revoke(&B, 2)).unwrap();
        rec(&mut t, B, 6, revoke(&C, 1)).unwrap();
        assert_eq!(t.device(&C).unwrap().cut, None);
        assert_eq!(t.device(&B).unwrap().cut, Some(2));
    }

    #[test]
    fn arrival_order_does_not_matter() {
        let entries = [
            (ROOT, 1, genesis()),
            (ROOT, 2, endorse(&ROOT, &B)),
            (B, 5, endorse(&B, &C)),
            (C, 1, revoke(&ROOT, 9)),
            (ROOT, 3, revoke(&B, 4)),
            (D, 1, self_join(&D)),
        ];
        let mut reference = Trust::new(ACCOUNT, ROOT);
        for (s, q, e) in entries.iter().cloned() {
            rec(&mut reference, s, q, e).unwrap();
        }
        for rotation in 0..entries.len() {
            let mut t = Trust::new(ACCOUNT, ROOT);
            for (s, q, e) in entries
                .iter()
                .cycle()
                .skip(rotation)
                .take(entries.len())
                .cloned()
            {
                rec(&mut t, s, q, e).unwrap();
            }
            assert_eq!(t.devices(), reference.devices(), "rotation {rotation}");
        }
    }
}
