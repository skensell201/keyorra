//! Which devices count, and what they may do (spec §4.3, §4.6), derived from the trust entries
//! of all streams. The result depends only on the set of recorded entries, never on the order
//! in which they arrived.
//!
//! **Introductions.** The root (named by the account header, its key optionally pinned) is
//! introduced by `Genesis`, the first entry of its own stream. A device endorsed by a device
//! *with powers*, at a position that endorser may still write at, is introduced *with powers*.
//! Powers are not retroactive: a device's endorsement or revocation of others counts only if,
//! by its own checkpoints, it had already received an endorsement of itself (the root needs
//! none). So a device that self-joined and was approved later cannot revive what it wrote
//! before.
//! A device that only self-joined (`SelfJoin`, the first entry of its own stream, never the
//! root's) is introduced *without powers*: its records count, its endorsements and its
//! revocations of others do not, and other devices raise an alarm until the user approves or
//! removes it. Two different keys endorsed for one id, at counting positions, put the id in
//! quarantine (not introduced; an alarm); an endorsement beats a `SelfJoin` with another key.
//!
//! **Revocations.** `Revoke { device, last_valid_seq }` cuts `device`'s stream: later positions
//! stop counting. The effective cut is never below the target's position that the revoker had
//! already listed in its own checkpoints, so a revocation cannot erase history the revoker had
//! seen. A revocation of another device counts only if its author has powers and
//! wrote it before its own cut. A self-revocation always cuts at the position before it and
//! never lowers a cut someone else set.
//!
//! Whether a revocation counts depends on cuts, which depend on revocations. This is resolved
//! by a fixpoint: revocations that count under the most cuts certainly count; for those left
//! open (devices removing each other at the same time), the revocations by devices closer to
//! the root are decided first, and revocations by equally close devices both apply.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::entry::{verify_endorsement, Entry, Heads};
use crate::fold::Admission;
use crate::{AccountId, DeviceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Introduction {
    Root,
    /// Joined with the Emergency Kit, approved by no other device: no powers.
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
    /// May endorse and revoke others.
    pub powers: bool,
    /// Entries after this sequence number do not count.
    pub cut: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// `Genesis`/`SelfJoin` anywhere but at sequence 1, `Genesis` outside the root stream, or
    /// `SelfJoin` in the root stream.
    Misplaced,
    WrongAccount,
    BadSignature,
    /// The root's `Genesis` carries another key than the pinned one.
    RootKeyMismatch,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TrustError::Misplaced => "introduction entry out of place",
            TrustError::WrongAccount => "genesis of another account",
            TrustError::BadSignature => "endorsement signature does not verify",
            TrustError::RootKeyMismatch => "the root's genesis key is not the pinned one",
        })
    }
}

#[derive(Clone, Debug)]
struct Recorded {
    stream: DeviceId,
    seq: u64,
    entry: Entry,
    /// What the author had received before this entry, by its own checkpoints.
    seen: Heads,
}

impl Recorded {
    fn seen(&self, device: &DeviceId) -> u64 {
        self.seen.get(device).map_or(0, |h| h.seq)
    }
}

/// An endorsement that counts: the entry, the key it gives, the name.
type Candidate<'a> = (&'a Recorded, [u8; 32], &'a String);

/// A revocation, as the derivation sees it.
#[derive(Clone, Copy, Debug)]
struct Rev {
    by: DeviceId,
    at: u64,
    target: DeviceId,
    cut: u64,
    /// Index of the entry in `recorded`.
    entry: usize,
}

type Cuts = BTreeMap<DeviceId, u64>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Derived {
    devices: BTreeMap<DeviceId, DeviceInfo>,
    quarantined: BTreeSet<DeviceId>,
    /// Per endorsed device: the counting endorsements of it, as (endorser, position).
    endorsements: BTreeMap<DeviceId, Vec<(DeviceId, u64)>>,
}

#[derive(Clone, Debug)]
pub struct Trust {
    account_id: AccountId,
    root: DeviceId,
    pinned_root: Option<VerifyingKey>,
    recorded: Vec<Recorded>,
    derived: Derived,
}

impl Trust {
    pub fn new(account_id: AccountId, root: DeviceId) -> Trust {
        Trust {
            account_id,
            root,
            pinned_root: None,
            recorded: Vec::new(),
            derived: Derived::default(),
        }
    }

    /// Pins the root's key (from pairing; plan A1c-2 binds it into the account header): the
    /// root's stream verifies only with it, and a `Genesis` with another key is refused.
    pub fn pin_root(&mut self, key: VerifyingKey) {
        self.pinned_root = Some(key);
    }

    pub fn root(&self) -> DeviceId {
        self.root
    }

    pub fn devices(&self) -> &BTreeMap<DeviceId, DeviceInfo> {
        &self.derived.devices
    }

    pub fn device(&self, device: &DeviceId) -> Option<&DeviceInfo> {
        self.derived.devices.get(device)
    }

    /// The key that signs `device`'s stream: of an introduced device, or the pinned root key.
    pub fn key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.derived
            .devices
            .get(device)
            .map(|d| d.key)
            .or_else(|| (*device == self.root).then_some(self.pinned_root).flatten())
    }

    /// Ids endorsed with two different keys at counting positions.
    pub fn quarantined(&self) -> &BTreeSet<DeviceId> {
        &self.derived.quarantined
    }

    /// Devices introduced only through `SelfJoin` (no powers).
    pub fn self_joined(&self) -> impl Iterator<Item = (&DeviceId, &DeviceInfo)> {
        self.derived
            .devices
            .iter()
            .filter(|(_, d)| d.introduced == Introduction::SelfJoined)
    }

    /// Checks and records a trust entry found at `(stream, seq)`, whose segment verified with
    /// `stream_key`; `seen` is what the author had received before it, by its own earlier
    /// checkpoints (the highest position per device). Other entries are ignored. Returns
    /// whether the outcome changed. An error means the entry is ignored; it never makes the
    /// stream unreadable.
    pub fn record(
        &mut self,
        stream: DeviceId,
        stream_key: &VerifyingKey,
        seq: u64,
        entry: &Entry,
        seen: &Heads,
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
                if self.pinned_root.is_some_and(|p| p.as_bytes() != key) {
                    return Err(TrustError::RootKeyMismatch);
                }
            }
            Entry::SelfJoin { key, sig, .. } => {
                if seq != 1 || stream == self.root || key != stream_key.as_bytes() {
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
            }
            Entry::Revoke { .. } => {}
            _ => return Ok(false),
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
                seen: seen.clone(),
            },
        );
        let derived = self.derive();
        let changed = derived != self.derived;
        self.derived = derived;
        Ok(changed)
    }

    /// Every recorded trust entry with its position and what its author had seen, in
    /// `(stream, seq)` order.
    pub fn entries(&self) -> impl Iterator<Item = (DeviceId, u64, &Entry, &Heads)> {
        self.recorded
            .iter()
            .map(|r| (r.stream, r.seq, &r.entry, &r.seen))
    }

    fn revocations(&self) -> Vec<Rev> {
        self.recorded
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &r.entry {
                Entry::Revoke {
                    device,
                    last_valid_seq,
                    ..
                } => Some(Rev {
                    by: r.stream,
                    at: r.seq,
                    target: *device,
                    cut: if *device == r.stream {
                        r.seq - 1
                    } else {
                        (*last_valid_seq).max(r.seen(device))
                    },
                    entry: i,
                }),
                _ => None,
            })
            .collect()
    }

    /// Whether the author of `recorded[i]` had powers when it wrote it: the root, or a device
    /// that had received a counting endorsement of itself (by its own checkpoints).
    fn had_powers(&self, i: usize, intro: &Derived) -> bool {
        let r = &self.recorded[i];
        match intro.devices.get(&r.stream) {
            Some(d) if d.introduced == Introduction::Root => true,
            Some(d) if d.powers => intro
                .endorsements
                .get(&r.stream)
                .is_some_and(|list| list.iter().any(|(by, at)| r.seen(by) >= *at)),
            _ => false,
        }
    }

    fn derive(&self) -> Derived {
        let revs = self.revocations();
        let depth = self.depths();
        let valid_under = |counting: &BTreeSet<usize>| -> BTreeSet<usize> {
            let cuts = cuts_of(&revs, counting, None);
            let intro = self.introduce(&cuts);
            (0..revs.len())
                .filter(|i| self.valid(&revs, *i, counting, &intro))
                .collect()
        };
        // Alternating fixpoint: `upper` shrinks to what counts when only certain revocations
        // apply; `lower` grows to what counts under every candidate cut.
        let mut upper: BTreeSet<usize> = (0..revs.len()).collect();
        let lower = loop {
            let lower = valid_under(&upper);
            let next = valid_under(&lower);
            if next == upper {
                break lower;
            }
            upper = next;
        };
        // Open cases, closest to the root first; equally close ones together.
        let mut counting = lower.clone();
        let mut open: Vec<usize> = upper.difference(&lower).copied().collect();
        open.sort_by_key(|i| depth.get(&revs[*i].by).copied().unwrap_or(u32::MAX));
        let mut k = 0;
        while k < open.len() {
            let d = depth.get(&revs[open[k]].by).copied().unwrap_or(u32::MAX);
            let group: Vec<usize> = open[k..]
                .iter()
                .copied()
                .take_while(|i| depth.get(&revs[*i].by).copied().unwrap_or(u32::MAX) == d)
                .collect();
            k += group.len();
            let cuts = cuts_of(&revs, &counting, None);
            let intro = self.introduce(&cuts);
            let ok: Vec<usize> = group
                .into_iter()
                .filter(|i| self.valid(&revs, *i, &counting, &intro))
                .collect();
            counting.extend(ok);
        }
        let cuts = cuts_of(&revs, &counting, None);
        let mut intro = self.introduce(&cuts);
        for (id, info) in intro.devices.iter_mut() {
            info.cut = cuts.get(id).copied();
        }
        intro
    }

    /// Whether revocation `i` counts, given the counting set (for the author's own cut) and the
    /// introductions under it.
    fn valid(&self, revs: &[Rev], i: usize, counting: &BTreeSet<usize>, intro: &Derived) -> bool {
        let r = revs[i];
        if !intro.devices.contains_key(&r.by) {
            return false;
        }
        if r.by != r.target && !self.had_powers(r.entry, intro) {
            return false;
        }
        // A self-revocation is judged against cuts set by others only.
        let own_cut = cuts_of(revs, counting, (r.by == r.target).then_some(i))
            .get(&r.by)
            .copied();
        own_cut.is_none_or(|c| r.at <= c)
    }

    /// Introductions under `cuts`.
    fn introduce(&self, cuts: &Cuts) -> Derived {
        let counts = |d: &DeviceId, seq: u64| cuts.get(d).is_none_or(|c| seq <= *c);
        let mut devices: BTreeMap<DeviceId, DeviceInfo> = BTreeMap::new();
        for r in &self.recorded {
            if let Entry::Genesis { key, name, .. } = &r.entry {
                if let Ok(k) = VerifyingKey::from_bytes(key) {
                    devices.insert(
                        r.stream,
                        DeviceInfo {
                            key: k,
                            name: name.clone(),
                            introduced: Introduction::Root,
                            powers: true,
                            cut: None,
                        },
                    );
                }
            }
        }
        let mut quarantined = BTreeSet::new();
        let mut endorsements: BTreeMap<DeviceId, Vec<(DeviceId, u64)>> = BTreeMap::new();
        // Endorsed devices: repeat until stable (bounded, deterministic).
        for _ in 0..=self.recorded.len() {
            let current = Derived {
                devices: devices.clone(),
                quarantined: BTreeSet::new(),
                endorsements: endorsements.clone(),
            };
            let mut candidates: BTreeMap<DeviceId, Vec<Candidate>> = BTreeMap::new();
            for (i, r) in self.recorded.iter().enumerate() {
                let Entry::Endorse {
                    device, key, name, ..
                } = &r.entry
                else {
                    continue;
                };
                if *device != self.root && counts(&r.stream, r.seq) && self.had_powers(i, &current)
                {
                    candidates.entry(*device).or_default().push((r, *key, name));
                }
            }
            let mut next: BTreeMap<DeviceId, DeviceInfo> = devices
                .iter()
                .filter(|(_, d)| d.introduced == Introduction::Root)
                .map(|(id, d)| (*id, d.clone()))
                .collect();
            let mut next_endorsements = BTreeMap::new();
            quarantined.clear();
            for (device, list) in &candidates {
                let keys: BTreeSet<[u8; 32]> = list.iter().map(|(_, k, _)| *k).collect();
                if keys.len() > 1 {
                    quarantined.insert(*device);
                    continue;
                }
                let (first, key, name) = list[0];
                if let Ok(k) = VerifyingKey::from_bytes(&key) {
                    next_endorsements.insert(
                        *device,
                        list.iter().map(|(r, _, _)| (r.stream, r.seq)).collect(),
                    );
                    next.insert(
                        *device,
                        DeviceInfo {
                            key: k,
                            name: name.clone(),
                            introduced: Introduction::Endorsed {
                                by: first.stream,
                                at_seq: first.seq,
                            },
                            powers: true,
                            cut: None,
                        },
                    );
                }
            }
            if next == devices && next_endorsements == endorsements {
                break;
            }
            devices = next;
            endorsements = next_endorsements;
        }
        for r in &self.recorded {
            if let Entry::SelfJoin { key, name, .. } = &r.entry {
                if devices.contains_key(&r.stream) || quarantined.contains(&r.stream) {
                    continue; // an endorsement (or a conflict) wins over a self-join
                }
                if let Ok(k) = VerifyingKey::from_bytes(key) {
                    devices.insert(
                        r.stream,
                        DeviceInfo {
                            key: k,
                            name: name.clone(),
                            introduced: Introduction::SelfJoined,
                            powers: false,
                            cut: None,
                        },
                    );
                }
            }
        }
        Derived {
            devices,
            quarantined,
            endorsements,
        }
    }

    /// Distance from the root along endorsements, ignoring cuts (for ordering open cases).
    fn depths(&self) -> BTreeMap<DeviceId, u32> {
        let mut depth = BTreeMap::new();
        if self
            .recorded
            .iter()
            .any(|r| matches!(r.entry, Entry::Genesis { .. }))
        {
            depth.insert(self.root, 0);
        }
        loop {
            let mut changed = false;
            for r in &self.recorded {
                if let Entry::Endorse { device, .. } = &r.entry {
                    if let Some(d) = depth.get(&r.stream).copied() {
                        let e = depth.entry(*device).or_insert(u32::MAX);
                        if d + 1 < *e {
                            *e = d + 1;
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                return depth;
            }
        }
    }
}

/// Cuts from the counting revocations, leaving out `skip`: per device, the lowest cut set by
/// others; a self-revocation's cut only if nobody else cut the device.
fn cuts_of(revs: &[Rev], counting: &BTreeSet<usize>, skip: Option<usize>) -> Cuts {
    let mut others: Cuts = BTreeMap::new();
    let mut own: Cuts = BTreeMap::new();
    for i in counting {
        if Some(*i) == skip {
            continue;
        }
        let r = revs[*i];
        let map = if r.by == r.target {
            &mut own
        } else {
            &mut others
        };
        let e = map.entry(r.target).or_insert(r.cut);
        *e = (*e).min(r.cut);
    }
    for (d, c) in own {
        others.entry(d).or_insert(c);
    }
    others
}

impl Admission for Trust {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
        self.derived
            .devices
            .get(stream)
            .is_some_and(|d| d.cut.is_none_or(|c| seq <= c))
    }

    fn is_cut(&self, device: &DeviceId) -> bool {
        self.derived
            .devices
            .get(device)
            .is_some_and(|d| d.cut.is_some())
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
    const E: DeviceId = [5; 16];

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
        endorse_key(by, device, &pk(device))
    }

    fn endorse_key(by: &DeviceId, device: &DeviceId, key: &VerifyingKey) -> Entry {
        let key = key.to_bytes();
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
            last_valid_hash: [0; 32],
        }
    }

    fn heads(list: &[(DeviceId, u64)]) -> Heads {
        list.iter()
            .map(|(d, seq)| {
                (
                    *d,
                    crate::entry::Head {
                        seq: *seq,
                        hash: [0; 32],
                    },
                )
            })
            .collect()
    }

    /// Records as if the author had seen the root's stream (so it knows the root's
    /// endorsements of it) and nothing else.
    fn rec(t: &mut Trust, stream: DeviceId, seq: u64, e: Entry) -> Result<bool, TrustError> {
        t.record(stream, &pk(&stream), seq, &e, &heads(&[(ROOT, 100)]))
    }

    fn cut(t: &Trust, d: &DeviceId) -> Option<u64> {
        t.device(d).and_then(|i| i.cut)
    }

    /// Root, and B, C endorsed by the root.
    fn base() -> Trust {
        let mut t = Trust::new(ACCOUNT, ROOT);
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        rec(&mut t, ROOT, 2, endorse(&ROOT, &B)).unwrap();
        rec(&mut t, ROOT, 3, endorse(&ROOT, &C)).unwrap();
        t
    }

    #[test]
    fn root_and_endorsed_devices_have_powers() {
        let t = base();
        assert_eq!(t.device(&ROOT).unwrap().introduced, Introduction::Root);
        let b = t.device(&B).unwrap();
        assert_eq!(
            b.introduced,
            Introduction::Endorsed {
                by: ROOT,
                at_seq: 2
            }
        );
        assert!(b.powers);
        assert!(t.admits(&B, 1_000));
        assert!(!t.admits(&D, 1));
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
        // A self-join in the root's stream is refused.
        assert_eq!(
            rec(&mut t, ROOT, 1, self_join(&ROOT)),
            Err(TrustError::Misplaced)
        );
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        let mut forged = endorse(&ROOT, &B);
        if let Entry::Endorse { sig, .. } = &mut forged {
            sig[0] ^= 1;
        }
        assert_eq!(rec(&mut t, ROOT, 2, forged), Err(TrustError::BadSignature));
        assert_eq!(rec(&mut t, C, 2, self_join(&C)), Err(TrustError::Misplaced));
    }

    #[test]
    fn a_pinned_root_key_refuses_another_genesis() {
        let mut t = Trust::new(ACCOUNT, ROOT);
        t.pin_root(pk(&B));
        assert_eq!(
            t.key(&ROOT),
            Some(pk(&B)),
            "the root stream verifies with the pin"
        );
        let impostor = Entry::Genesis {
            account_id: ACCOUNT,
            key: pk(&ROOT).to_bytes(),
            name: "root".into(),
        };
        assert_eq!(
            rec(&mut t, ROOT, 1, impostor),
            Err(TrustError::RootKeyMismatch)
        );
        assert!(t.device(&ROOT).is_none());
    }

    #[test]
    fn a_self_joined_device_has_no_powers() {
        let mut t = base();
        rec(&mut t, D, 1, self_join(&D)).unwrap();
        let d = t.device(&D).unwrap();
        assert_eq!(d.introduced, Introduction::SelfJoined);
        assert!(!d.powers);
        assert!(t.admits(&D, 5), "its records count");
        // Its endorsements and its revocations of others do not count.
        rec(&mut t, D, 2, endorse(&D, &E)).unwrap();
        assert!(t.device(&E).is_none());
        rec(&mut t, D, 3, revoke(&ROOT, 0)).unwrap();
        assert_eq!(cut(&t, &ROOT), None);
        // Approving it gives it powers.
        rec(&mut t, ROOT, 4, endorse(&ROOT, &D)).unwrap();
        assert!(t.device(&D).unwrap().powers);
        assert_eq!(t.self_joined().count(), 0);
    }

    #[test]
    fn an_endorsement_beats_a_self_join_with_another_key() {
        let mut t = base();
        // D self-joined with its own key; the root endorses id D with E's key.
        rec(&mut t, D, 1, self_join(&D)).unwrap();
        rec(&mut t, ROOT, 4, endorse_key(&ROOT, &D, &pk(&E))).unwrap();
        let d = t.device(&D).unwrap();
        assert_eq!(d.key, pk(&E));
        assert!(d.powers);
        assert!(t.quarantined().is_empty());
    }

    #[test]
    fn two_keys_for_one_id_quarantine_it_without_rejecting_anyone() {
        let mut t = base();
        rec(&mut t, ROOT, 4, endorse(&ROOT, &D)).unwrap();
        rec(&mut t, B, 1, endorse_key(&B, &D, &pk(&E))).unwrap();
        assert!(t.device(&D).is_none());
        assert_eq!(t.quarantined().iter().copied().collect::<Vec<_>>(), vec![D]);
        assert!(t.device(&B).is_some() && t.device(&ROOT).is_some());
    }

    #[test]
    fn a_removed_device_cannot_quarantine_others_after_its_cut() {
        let mut t = base();
        rec(&mut t, ROOT, 4, revoke(&B, 2)).unwrap();
        // B, after its cut, endorses C's id with another key.
        rec(&mut t, B, 3, endorse_key(&B, &C, &pk(&E))).unwrap();
        assert!(t.quarantined().is_empty());
        assert_eq!(t.device(&C).unwrap().key, pk(&C));
    }

    #[test]
    fn a_revocation_cuts_the_stream_and_its_later_endorsements() {
        let mut t = base();
        rec(&mut t, B, 5, endorse(&B, &D)).unwrap();
        rec(&mut t, B, 9, endorse(&B, &E)).unwrap();
        rec(&mut t, ROOT, 4, revoke(&B, 7)).unwrap();
        assert_eq!(cut(&t, &B), Some(7));
        assert!(t.admits(&B, 7) && !t.admits(&B, 8));
        assert!(t.device(&D).is_some(), "endorsed before the cut");
        assert!(t.device(&E).is_none(), "endorsed after the cut");
    }

    #[test]
    fn review_c1_a_puppet_endorsed_after_the_cut_cannot_revoke_anyone() {
        let mut t = base();
        rec(&mut t, ROOT, 4, revoke(&B, 3)).unwrap();
        rec(&mut t, B, 4, endorse(&B, &D)).unwrap(); // after B's cut
        rec(&mut t, D, 1, revoke(&C, 0)).unwrap();
        rec(&mut t, D, 2, revoke(&ROOT, 0)).unwrap();
        assert!(t.device(&D).is_none());
        assert_eq!(cut(&t, &C), None);
        assert_eq!(cut(&t, &ROOT), None);
    }

    #[test]
    fn review_c2_a_void_revocation_does_not_disarm_a_real_one() {
        let mut t = base();
        // C removes B; B's puppet D (endorsed after B's cut) tries to remove C first.
        rec(&mut t, C, 1, revoke(&B, 3)).unwrap();
        rec(&mut t, B, 4, endorse(&B, &D)).unwrap();
        rec(&mut t, D, 1, revoke(&C, 0)).unwrap();
        assert_eq!(cut(&t, &B), Some(3));
        assert_eq!(cut(&t, &C), None);
        assert!(t.device(&D).is_none());
    }

    #[test]
    fn review_c3_a_removed_device_cannot_self_revoke_lower_or_erase_history() {
        let mut t = base();
        rec(&mut t, B, 3, endorse(&B, &D)).unwrap();
        rec(&mut t, ROOT, 4, revoke(&B, 5)).unwrap();
        // After its cut, B "revokes itself" at 0 to erase its endorsement of D.
        rec(&mut t, B, 9, revoke(&B, 0)).unwrap();
        assert_eq!(cut(&t, &B), Some(5));
        assert!(t.device(&D).is_some());
        // A self-revocation cuts at the position before it, whatever it claims…
        let mut u = base();
        rec(&mut u, C, 6, revoke(&C, 0)).unwrap();
        assert_eq!(cut(&u, &C), Some(5));
        // …and never lowers a cut someone else set.
        rec(&mut u, ROOT, 4, revoke(&C, 5)).unwrap();
        rec(&mut u, C, 4, revoke(&C, 1)).unwrap();
        assert_eq!(cut(&u, &C), Some(5));
    }

    #[test]
    fn review_c4_a_self_joiner_cannot_remove_the_root() {
        let mut t = base();
        rec(&mut t, D, 1, self_join(&D)).unwrap();
        rec(&mut t, D, 2, revoke(&ROOT, 0)).unwrap();
        rec(&mut t, D, 3, revoke(&B, 0)).unwrap();
        assert_eq!(cut(&t, &ROOT), None);
        assert_eq!(cut(&t, &B), None);
    }

    #[test]
    fn a_cut_never_goes_below_what_the_revoker_had_seen() {
        let mut t = base();
        let e = revoke(&B, 0);
        t.record(ROOT, &pk(&ROOT), 4, &e, &heads(&[(B, 7)]))
            .unwrap();
        assert_eq!(cut(&t, &B), Some(7));
    }

    #[test]
    fn powers_are_not_retroactive() {
        // D self-joined and, still without powers, revoked the root; later the root approved
        // it. The early revocation stays void: D had not seen its approval when writing it.
        let mut t = base();
        rec(&mut t, D, 1, self_join(&D)).unwrap();
        t.record(D, &pk(&D), 2, &revoke(&ROOT, 0), &heads(&[(ROOT, 3)]))
            .unwrap();
        rec(&mut t, ROOT, 4, endorse(&ROOT, &D)).unwrap();
        assert!(t.device(&D).unwrap().powers);
        assert_eq!(cut(&t, &ROOT), None);
        // Once it has seen its approval, its revocations count.
        t.record(D, &pk(&D), 3, &revoke(&B, 2), &heads(&[(ROOT, 4)]))
            .unwrap();
        assert_eq!(cut(&t, &B), Some(2));
    }

    #[test]
    fn devices_removing_each_other_at_once() {
        // Equally close to the root: both removals apply.
        let mut t = base();
        rec(&mut t, B, 5, revoke(&C, 2)).unwrap();
        rec(&mut t, C, 5, revoke(&B, 2)).unwrap();
        assert_eq!((cut(&t, &B), cut(&t, &C)), (Some(2), Some(2)));
        // The one closer to the root wins over one it approved.
        let mut u = base();
        rec(&mut u, B, 4, endorse(&B, &D)).unwrap();
        rec(&mut u, B, 6, revoke(&D, 1)).unwrap();
        rec(&mut u, D, 3, revoke(&B, 4)).unwrap();
        assert_eq!(cut(&u, &D), Some(1));
        assert_eq!(cut(&u, &B), None);
    }

    #[test]
    fn a_revocation_written_after_seeing_the_other_wins() {
        // B revoked C (cut 2). C saw that revocation (C's cut on B includes B's revoke at 5)
        // and revoked B after it: B's revocation stays valid, C's comes after its own cut.
        let mut t = base();
        rec(&mut t, B, 5, revoke(&C, 2)).unwrap();
        rec(&mut t, C, 4, revoke(&B, 5)).unwrap();
        assert_eq!(cut(&t, &C), Some(2));
        assert_eq!(cut(&t, &B), None);
    }

    #[test]
    fn arrival_order_does_not_matter() {
        let entries = [
            (ROOT, 1, genesis()),
            (ROOT, 2, endorse(&ROOT, &B)),
            (ROOT, 3, endorse(&ROOT, &C)),
            (B, 4, endorse(&B, &D)),
            (C, 1, revoke(&B, 3)),
            (D, 1, revoke(&C, 0)),
            (E, 1, self_join(&E)),
            (E, 2, revoke(&ROOT, 0)),
            (B, 6, revoke(&C, 2)),
        ];
        let mut reference = Trust::new(ACCOUNT, ROOT);
        for (s, q, e) in entries.iter().cloned() {
            let _ = rec(&mut reference, s, q, e);
        }
        for rotation in 0..entries.len() {
            for reversed in [false, true] {
                let mut order: Vec<_> = entries
                    .iter()
                    .cycle()
                    .skip(rotation)
                    .take(entries.len())
                    .collect();
                if reversed {
                    order.reverse();
                }
                let mut t = Trust::new(ACCOUNT, ROOT);
                for (s, q, e) in order {
                    let _ = rec(&mut t, *s, *q, e.clone());
                }
                assert_eq!(t.devices(), reference.devices(), "{rotation} {reversed}");
            }
        }
    }
}
