//! The fold: local state as a deterministic function of the accepted versions (spec §3.4).
//!
//! Every accepted version is retained; the sibling sets are built from the retained versions
//! that the [`Admission`] policy admits. Plan A1c supplies the real policy (endorsement and
//! revocation cuts) and calls [`Fold::refold`] when it changes; until then [`AdmitAll`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use uuid::Uuid;

use crate::envelope::{version_hash, RecordKind, Version};
use crate::payload::{
    attachment_refs, copied_attachment_refs, copy_item_json, AttachmentPayload, ConflictMarker,
    Doc, ItemPayload,
};
use crate::present::{
    copy_attachment_id, present_attachment, present_item, present_vault, ItemState,
};
use crate::siblings::{Sibling, SiblingSet};
use crate::vv::{compare, join, Causality, Vector};
use crate::DeviceId;

pub type RecordKey = (RecordKind, Uuid);

/// A version that passed the stream checks, with its decoded content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The device whose stream carried it.
    pub stream: DeviceId,
    /// Its position in that stream.
    pub seq: u64,
    pub kind: RecordKind,
    pub record_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub version: Version,
    pub doc: Doc,
}

impl Accepted {
    pub fn key(&self) -> RecordKey {
        (self.kind, self.record_id)
    }

    pub fn hash(&self) -> [u8; 32] {
        version_hash(self.kind, self.record_id, &self.version)
    }

    fn sibling(&self) -> Sibling {
        Sibling {
            version: self.version.clone(),
            hash: self.hash(),
            vault_id: self.vault_id,
            doc: self.doc.clone(),
        }
    }
}

/// Which stream positions count. A1c: endorsed devices, up to their revocation cut.
pub trait Admission {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool;
    /// Whether `device`'s stream has a cut. Versions may count writes of a cut device that
    /// this device never receives (it does not read past a cut), so such counts are not
    /// waited for.
    fn is_cut(&self, _device: &DeviceId) -> bool {
        false
    }
}

/// Every position counts (until A1c).
pub struct AdmitAll;

impl Admission for AdmitAll {
    fn admits(&self, _: &DeviceId, _: u64) -> bool {
        true
    }
}

/// Why a version was refused (spec §3.3). A live device signed it, so this is an alarm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// `version.author` is not the device whose stream carried the version.
    WrongAuthor,
    /// `vector[author]` must be one more than the author's previous version of the record.
    CounterNotNext { expected: u64, got: u64 },
    /// The payload does not match the envelope kind.
    KindMismatch,
    /// Vaults are deleted with a flag, never purged.
    VaultTombstone,
    /// The same version (same version hash) arrived with different content or vault: the
    /// author signed two different things under one version. An alarm, never first-wins.
    Equivocation,
    /// An item's `content_from` is not covered by its own version.
    ContentFromAhead,
    /// The version claims more writes of `device` to this record than have been applied.
    /// Not a rejection when reading: the engine waits (see [`Fold::missing_dependency`]).
    AheadOfApplied { device: DeviceId },
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::WrongAuthor => f.write_str("version author is not the stream's device"),
            Rejection::CounterNotNext { expected, got } => {
                write!(f, "version counter {got}, expected {expected}")
            }
            Rejection::KindMismatch => f.write_str("payload does not match the record kind"),
            Rejection::VaultTombstone => f.write_str("vault tombstone"),
            Rejection::Equivocation => f.write_str("one version with two different contents"),
            Rejection::ContentFromAhead => f.write_str("content_from is ahead of the version"),
            Rejection::AheadOfApplied { device } => write!(
                f,
                "depends on changes of {} not applied yet",
                data_encoding::HEXLOWER.encode(&device[..4])
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accept {
    New,
    /// Already accepted (same version hash); nothing changed.
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemView {
    pub state: ItemState,
    pub vault_id: Option<Uuid>,
    /// `None` when purged.
    pub payload: Option<ItemPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultView {
    pub name: String,
    pub wrapped_key: Vec<u8>,
    pub deleted: bool,
    pub revived: bool,
    pub key_mismatch: bool,
}

/// A conflict copy that does not exist yet as a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCopy {
    pub copy_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub payload: ItemPayload,
}

/// An attachment record a conflict copy refers to but nobody has written yet: the original's
/// attachment, re-pointed at the copy (same key, same chunks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentCopy {
    pub id: Uuid,
    pub vault_id: Option<Uuid>,
    pub payload: AttachmentPayload,
}

/// What the first device to see a conflict writes (spec §3.5, "Materialising copies"):
/// the copies, then a version of the original that collapses its sibling set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub record_id: Uuid,
    pub copies: Vec<PendingCopy>,
    /// The visible content, rewritten as a new version (an item payload or a tombstone).
    pub collapse: Doc,
    pub vault_id: Option<Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub vaults: BTreeMap<Uuid, VaultView>,
    pub items: BTreeMap<Uuid, ItemView>,
    /// Live attachments only.
    pub attachments: BTreeMap<Uuid, AttachmentPayload>,
    pub resolutions: Vec<Resolution>,
    pub attachment_copies: Vec<AttachmentCopy>,
    /// Conflict copies whose only versions no longer count (written by a device that was
    /// revoked since), of a source version that still counts: written again by a device
    /// that may write, so the copied content does not disappear with the revocation.
    pub orphan_copies: Vec<PendingCopy>,
}

impl View {
    /// Whether conflict copies or their attachment records are still owed.
    pub fn owes_copies(&self) -> bool {
        !self.resolutions.is_empty()
            || !self.attachment_copies.is_empty()
            || !self.orphan_copies.is_empty()
    }

    /// Items that are conflict copies (live or in Recently Deleted).
    pub fn conflict_copies(&self) -> Vec<Uuid> {
        self.items
            .iter()
            .filter(|(_, v)| {
                v.payload
                    .as_ref()
                    .is_some_and(|p| crate::payload::conflict_marker(p).is_some())
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Fold {
    /// Every accepted version, with whether the current admission policy admits it.
    retained: BTreeMap<RecordKey, Vec<(Accepted, bool)>>,
    /// Built from the admitted versions only; a record is "known" iff it has a set.
    sets: BTreeMap<RecordKey, SiblingSet>,
    /// Ids of item records written past a cut and not read further (their content does not
    /// count; the id alone tells a conflict copy that disappeared with the cut).
    skipped_items: BTreeSet<Uuid>,
}

impl Fold {
    /// Validates and retains `a`; it joins the sibling set if `admission` admits its position.
    /// Nothing is stored when it is rejected.
    /// Accepts this device's own new version. Its vector was built from sibling sets, which
    /// may count versions of another device that are not held right now (skipped past a cut
    /// that has since moved, and not read again yet): nothing to wait for.
    pub fn accept_own(
        &mut self,
        a: Accepted,
        admission: &dyn Admission,
    ) -> Result<Accept, Rejection> {
        struct Own<'a>(&'a dyn Admission);
        impl Admission for Own<'_> {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                self.0.admits(stream, seq)
            }
            fn is_cut(&self, _: &DeviceId) -> bool {
                true
            }
        }
        self.accept(a, &Own(admission))
    }

    pub fn accept(&mut self, a: Accepted, admission: &dyn Admission) -> Result<Accept, Rejection> {
        let expected = {
            let retained = self.retained_of(&a.key());
            check_version(&a, &retained, admission)?;
            if let Some(existing) = retained.iter().find(|v| v.hash() == a.hash()) {
                return same_or_equivocation(existing, &a).map(|_| Accept::Duplicate);
            }
            own_counter(&retained, &a.stream) + 1
        };
        let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
        if got != expected {
            return Err(Rejection::CounterNotNext { expected, got });
        }
        let admitted = admission.admits(&a.stream, a.seq);
        if admitted {
            self.sets.entry(a.key()).or_default().insert(a.sibling());
        }
        self.retained
            .entry(a.key())
            .or_default()
            .push((a, admitted));
        Ok(Accept::New)
    }

    /// Accepts a whole segment's versions, or none of them: everything is validated first.
    /// Returns how many were new.
    pub fn accept_batch(
        &mut self,
        batch: Vec<Accepted>,
        admission: &dyn Admission,
    ) -> Result<usize, Rejection> {
        let mut counters: BTreeMap<(RecordKey, DeviceId), u64> = BTreeMap::new();
        let mut seen: BTreeMap<[u8; 32], &Accepted> = BTreeMap::new();
        for a in &batch {
            let retained = self.retained_of(&a.key());
            check_version(a, &retained, admission)?;
            let hash = a.hash();
            if let Some(existing) = retained.iter().find(|v| v.hash() == hash) {
                same_or_equivocation(existing, a)?;
                continue;
            }
            if let Some(earlier) = seen.get(&hash) {
                same_or_equivocation(earlier, a)?;
                continue;
            }
            let counter = counters
                .entry((a.key(), a.stream))
                .or_insert_with(|| own_counter(&retained, &a.stream));
            let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
            if got != *counter + 1 {
                return Err(Rejection::CounterNotNext {
                    expected: *counter + 1,
                    got,
                });
            }
            *counter = got;
            seen.insert(hash, a);
        }
        let mut new = 0;
        for a in batch {
            if self.accept(a, admission)? == Accept::New {
                new += 1;
            }
        }
        Ok(new)
    }

    /// Checks a batch before it is accepted: a rule violation is a rejection; otherwise the
    /// first device whose earlier writes the batch depends on but which are not applied yet
    /// (spec §3.3: `vector[X]` may not exceed X's applied versions of the record). The engine
    /// waits for those instead of rejecting; plan A1c replaces this with causal delivery.
    pub fn missing_dependency(
        &self,
        batch: &[Accepted],
        admission: &dyn Admission,
    ) -> Result<Option<DeviceId>, Rejection> {
        for a in batch {
            check_shape(a)?;
        }
        Ok(batch.iter().find_map(|a| {
            let retained = self.retained_of(&a.key());
            a.version
                .vector
                .iter()
                .filter(|(d, _)| **d != a.stream && !admission.is_cut(d))
                .find(|(d, n)| **n > own_counter(&retained, d))
                .map(|(d, _)| *d)
        }))
    }

    /// Rebuilds every sibling set from the retained versions under a new admission policy.
    /// Notes an item record written past its stream's cut, which is not read further.
    pub fn note_skipped(&mut self, kind: RecordKind, record_id: Uuid) {
        if kind == RecordKind::Item {
            self.skipped_items.insert(record_id);
        }
    }

    /// Item records noted with [`Fold::note_skipped`].
    pub fn skipped_items(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.skipped_items.iter().copied()
    }

    pub fn refold(&mut self, admission: &dyn Admission) {
        self.sets.clear();
        for (key, versions) in &mut self.retained {
            for (v, admitted) in versions.iter_mut() {
                *admitted = admission.admits(&v.stream, v.seq);
                if *admitted {
                    self.sets.entry(*key).or_default().insert(v.sibling());
                }
            }
        }
    }

    /// Conflict copies that disappeared with a cut (written only past their device's cut)
    /// although their source still counts: owed again, so the copied content survives.
    /// Only the record id is taken from what was written past the cut: it must be the copy
    /// id of an admitted version; the content is made again from that version. (So a removed
    /// device can at worst make old content of the account reappear as a copy, never bring
    /// in content of its own.)
    fn orphan_copies(&self) -> Vec<PendingCopy> {
        let mut wanted: BTreeSet<Uuid> = self
            .retained
            .iter()
            .filter(|((kind, _), versions)| {
                *kind == RecordKind::Item && versions.iter().any(|(_, admitted)| !admitted)
            })
            .map(|((_, id), _)| *id)
            .chain(self.skipped_items.iter().copied())
            .collect();
        wanted.retain(|id| !self.contains(RecordKind::Item, *id));
        if wanted.is_empty() {
            return Vec::new();
        }
        let mut copies = Vec::new();
        for ((kind, item), versions) in &self.retained {
            if *kind != RecordKind::Item {
                continue;
            }
            let admitted: Vec<&Accepted> = versions
                .iter()
                .filter(|(_, admitted)| *admitted)
                .map(|(a, _)| a)
                .collect();
            for source in &admitted {
                let hash = source.hash();
                let copy_id = crate::present::conflict_copy_id(*item, &hash);
                if !wanted.contains(&copy_id) {
                    continue;
                }
                let Doc::Item(p) = &source.doc else { continue };
                let trashed = p.deleted_at.is_some();
                copies.push(copy_of(*item, &source.sibling(), copy_id, trashed));
            }
        }
        copies.sort_by_key(|c| c.copy_id);
        copies
    }

    /// The newest admitted content of an attachment, even if it was removed since: a conflict
    /// copy keeps the attachments its version referred to.
    fn newest_attachment_content(&self, id: Uuid) -> Option<&AttachmentPayload> {
        self.retained
            .get(&(RecordKind::Attachment, id))?
            .iter()
            .filter(|(_, admitted)| *admitted)
            .filter_map(|(a, _)| match &a.doc {
                Doc::Attachment(p) => Some((a.version.hlc, a.version.author, p)),
                _ => None,
            })
            .max_by_key(|(hlc, author, _)| (*hlc, *author))
            .map(|(_, _, p)| p)
    }

    fn retained_of(&self, key: &RecordKey) -> Vec<&Accepted> {
        self.retained
            .get(key)
            .map(|v| v.iter().map(|(a, _)| a).collect())
            .unwrap_or_default()
    }

    pub fn set(&self, kind: RecordKind, id: Uuid) -> Option<&SiblingSet> {
        self.sets.get(&(kind, id))
    }

    pub fn sets(&self) -> impl Iterator<Item = (&RecordKey, &SiblingSet)> {
        self.sets.iter()
    }

    pub fn retained(&self) -> impl Iterator<Item = &Accepted> {
        self.retained.values().flatten().map(|(a, _)| a)
    }

    /// Whether the record has an admitted version.
    pub fn contains(&self, kind: RecordKind, id: Uuid) -> bool {
        self.sets.contains_key(&(kind, id))
    }

    /// The version a new local write by `author` gets: it dominates every sibling.
    pub fn next_version(&self, kind: RecordKind, id: Uuid, author: DeviceId, hlc: u64) -> Version {
        let key = (kind, id);
        let mut vector = self
            .sets
            .get(&key)
            .map(|s| join(s.siblings().iter().map(|x| &x.version.vector)))
            .unwrap_or_default();
        let own = own_counter(&self.retained_of(&key), &author);
        let counter = vector.get(&author).copied().unwrap_or(0).max(own) + 1;
        vector.insert(author, counter);
        Version {
            vector,
            hlc,
            author,
        }
    }

    pub fn view(&self) -> View {
        let mut view = View::default();
        for ((kind, id), set) in &self.sets {
            if *kind == RecordKind::Attachment {
                if let Some((_, p)) = present_attachment(set) {
                    view.attachments.insert(*id, p.clone());
                }
            }
        }
        for ((kind, id), set) in &self.sets {
            if *kind != RecordKind::Item {
                continue;
            }
            let p = present_item(*id, set);
            let Some(visible) = p.visible else { continue };
            let payload = match &visible.doc {
                Doc::Item(x) => Some(x.clone()),
                _ => None,
            };
            view.items.insert(
                *id,
                ItemView {
                    state: p.state,
                    vault_id: visible.vault_id,
                    payload: payload.clone(),
                },
            );
            let copies: Vec<PendingCopy> = p
                .copies
                .iter()
                .filter(|c| !self.contains(RecordKind::Item, c.copy_id))
                .map(|c| copy_of(*id, c.source, c.copy_id, c.trashed))
                .collect();
            if !copies.is_empty() {
                let mut collapse = visible.doc.clone();
                if let Doc::Item(p) = &mut collapse {
                    if p.content_from.is_empty() {
                        // A copy as first written: its content originates in that version.
                        p.content_from = visible.version.vector.clone();
                    }
                }
                view.resolutions.push(Resolution {
                    record_id: *id,
                    copies,
                    collapse,
                    vault_id: visible.vault_id,
                });
            }
            if let Some(payload) = &payload {
                for (copy_att, original) in copied_attachment_refs(payload) {
                    if self.contains(RecordKind::Attachment, copy_att) {
                        continue;
                    }
                    if let Some(source) = self.newest_attachment_content(original) {
                        let mut a = source.clone();
                        a.item_id = *id;
                        view.attachment_copies.push(AttachmentCopy {
                            id: copy_att,
                            vault_id: visible.vault_id,
                            payload: a,
                        });
                    }
                }
            }
        }
        view.orphan_copies = self.orphan_copies();
        for ((kind, id), set) in &self.sets {
            if *kind != RecordKind::Vault {
                continue;
            }
            let has_live = view
                .items
                .values()
                .any(|i| i.state == ItemState::Live && i.vault_id == Some(*id));
            if let Some(p) = present_vault(set, has_live) {
                view.vaults.insert(
                    *id,
                    VaultView {
                        name: p.payload.name.clone(),
                        wrapped_key: p.payload.wrapped_key.clone(),
                        deleted: p.deleted,
                        revived: p.revived,
                        key_mismatch: p.key_mismatch,
                    },
                );
            }
        }
        view
    }
}

/// Spec §3.3: the shape checks, and no claim beyond the applied versions of other devices.
fn check_version(
    a: &Accepted,
    retained: &[&Accepted],
    admission: &dyn Admission,
) -> Result<(), Rejection> {
    check_shape(a)?;
    for (device, n) in &a.version.vector {
        if *device != a.stream && !admission.is_cut(device) && *n > own_counter(retained, device) {
            return Err(Rejection::AheadOfApplied { device: *device });
        }
    }
    Ok(())
}

fn check_shape(a: &Accepted) -> Result<(), Rejection> {
    if a.version.author != a.stream {
        return Err(Rejection::WrongAuthor);
    }
    match a.doc.kind() {
        Some(k) if k != a.kind => return Err(Rejection::KindMismatch),
        None if a.kind == RecordKind::Vault => return Err(Rejection::VaultTombstone),
        _ => {}
    }
    if let Doc::Item(p) = &a.doc {
        if !matches!(
            compare(&p.content_from, &a.version.vector),
            Causality::Equal | Causality::Before
        ) {
            return Err(Rejection::ContentFromAhead);
        }
    }
    Ok(())
}

fn same_or_equivocation(existing: &Accepted, a: &Accepted) -> Result<(), Rejection> {
    if existing.doc == a.doc && existing.vault_id == a.vault_id {
        Ok(())
    } else {
        Err(Rejection::Equivocation)
    }
}

fn own_counter(versions: &[&Accepted], author: &DeviceId) -> u64 {
    versions
        .iter()
        .filter(|v| &v.version.author == author)
        .filter_map(|v| v.version.vector.get(author).copied())
        .max()
        .unwrap_or(0)
}

/// The conflict copy `copy_id` of `source` (a version of item `of`), as first written.
fn copy_of(of: Uuid, source: &Sibling, copy_id: Uuid, trashed: bool) -> PendingCopy {
    let Doc::Item(item) = &source.doc else {
        unreachable!("copies are made of items")
    };
    let map: Vec<(Uuid, Uuid)> = attachment_refs(item)
        .into_iter()
        .map(|r| (r, copy_attachment_id(copy_id, r)))
        .collect();
    let marker = ConflictMarker {
        of,
        version: source.hash,
        from_device: source.version.author,
    };
    PendingCopy {
        copy_id,
        vault_id: source.vault_id,
        payload: ItemPayload {
            item_json: copy_item_json(item, copy_id, &marker, &map)
                .expect("item payloads are JSON objects"),
            deleted_at: if trashed { item.deleted_at } else { None },
            // Empty: marks the copy as first written (spec §3.5).
            content_from: Vector::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{conflict_marker, VaultPayload};
    use crate::present::conflict_copy_id;
    use zeroize::Zeroizing;

    const A: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];
    const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);
    const VAULT: Uuid = Uuid::from_bytes([0x61; 16]);
    const ATT: Uuid = Uuid::from_bytes([0x62; 16]);

    fn json(title: &str, attachments: &[Uuid]) -> Doc {
        let atts: Vec<String> = attachments
            .iter()
            .map(|a| format!(r#"{{"id":"{a}"}}"#))
            .collect();
        Doc::Item(ItemPayload {
            item_json: Zeroizing::new(
                format!(
                    r#"{{"title":"{title}","attachments":[{}]}}"#,
                    atts.join(",")
                )
                .into_bytes(),
            ),
            deleted_at: None,
            // Set to the version's own vector by `item`.
            content_from: Vector::new(),
        })
    }

    fn item(
        stream: DeviceId,
        seq: u64,
        vector: &[(DeviceId, u64)],
        hlc: u64,
        doc: Doc,
    ) -> Accepted {
        let vector: Vector = vector.iter().copied().collect();
        let mut doc = doc;
        if let Doc::Item(p) = &mut doc {
            // Every test version is a fresh edit.
            p.content_from = vector.clone();
        }
        Accepted {
            stream,
            seq,
            kind: RecordKind::Item,
            record_id: ITEM,
            vault_id: Some(VAULT),
            version: Version {
                vector,
                hlc,
                author: stream,
            },
            doc,
        }
    }

    fn vault(stream: DeviceId, seq: u64, n: u64, hlc: u64, deleted: bool) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Vault,
            record_id: VAULT,
            vault_id: None,
            version: Version {
                vector: [(stream, n)].into_iter().collect(),
                hlc,
                author: stream,
            },
            doc: Doc::Vault(VaultPayload {
                name: "Work".into(),
                wrapped_key: vec![1],
                deleted,
            }),
        }
    }

    fn attachment(stream: DeviceId, seq: u64) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Attachment,
            record_id: ATT,
            vault_id: Some(VAULT),
            version: Version {
                vector: [(stream, 1)].into_iter().collect(),
                hlc: 1,
                author: stream,
            },
            doc: Doc::Attachment(AttachmentPayload {
                item_id: ITEM,
                name: "scan.pdf".into(),
                size: 3,
                key: Zeroizing::new([7; 32]),
                chunk_size: 3,
                chunks: vec![[8; 32]],
            }),
        }
    }

    #[test]
    fn validation_rules() {
        let mut f = Fold::default();
        let mut wrong_author = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        wrong_author.version.author = B;
        assert_eq!(
            f.accept(wrong_author, &AdmitAll),
            Err(Rejection::WrongAuthor)
        );
        assert_eq!(
            f.accept(item(A, 1, &[(A, 2)], 1, json("a", &[])), &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 1,
                got: 2
            })
        );
        let mut mismatch = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        mismatch.kind = RecordKind::Attachment;
        assert_eq!(f.accept(mismatch, &AdmitAll), Err(Rejection::KindMismatch));
        let mut tomb = vault(A, 1, 1, 1, false);
        tomb.doc = Doc::Tombstone;
        assert_eq!(f.accept(tomb, &AdmitAll), Err(Rejection::VaultTombstone));
        assert_eq!(
            f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll),
            Ok(Accept::New)
        );
        assert_eq!(
            f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll),
            Ok(Accept::Duplicate)
        );
        // A second, different version with the same counter is a replay or a bug.
        assert_eq!(
            f.accept(item(A, 2, &[(A, 1)], 2, json("b", &[])), &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            f.accept(item(A, 2, &[(A, 2)], 2, json("b", &[])), &AdmitAll),
            Ok(Accept::New)
        );
    }

    #[test]
    fn one_version_with_two_contents_is_an_equivocation() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll)
            .unwrap();
        let same = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        assert_eq!(f.accept(same, &AdmitAll), Ok(Accept::Duplicate));
        let forked = item(A, 1, &[(A, 1)], 1, json("b", &[]));
        assert_eq!(
            f.accept(forked.clone(), &AdmitAll),
            Err(Rejection::Equivocation)
        );
        let mut moved = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        moved.vault_id = Some(Uuid::from_bytes([0x63; 16]));
        assert_eq!(f.accept(moved, &AdmitAll), Err(Rejection::Equivocation));
        // Inside one batch, too.
        let mut g = Fold::default();
        let first = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        assert_eq!(
            g.accept_batch(vec![first, forked], &AdmitAll),
            Err(Rejection::Equivocation)
        );
        assert_eq!(g.retained().count(), 0);
    }

    #[test]
    fn rejected_versions_leave_no_trace_and_contains_follows_admission() {
        let mut f = Fold::default();
        let skipped = item(A, 1, &[(A, 2)], 1, json("a", &[]));
        assert!(f.accept(skipped, &AdmitAll).is_err());
        assert!(!f.contains(RecordKind::Item, ITEM));
        assert_eq!(f.retained().count(), 0);
        f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll)
            .unwrap();
        assert!(f.contains(RecordKind::Item, ITEM));
        struct Nothing;
        impl Admission for Nothing {
            fn admits(&self, _: &DeviceId, _: u64) -> bool {
                false
            }
        }
        f.refold(&Nothing);
        assert!(!f.contains(RecordKind::Item, ITEM));
        assert_eq!(f.retained().count(), 1);
    }

    #[test]
    fn content_from_may_not_run_ahead_of_the_version() {
        let mut f = Fold::default();
        let mut a = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        if let Doc::Item(p) = &mut a.doc {
            p.content_from = [(A, 2)].into_iter().collect();
        }
        assert_eq!(f.accept(a, &AdmitAll), Err(Rejection::ContentFromAhead));
    }

    #[test]
    fn a_version_may_not_claim_writes_that_were_not_applied() {
        let mut f = Fold::default();
        let early = item(B, 1, &[(A, 1), (B, 1)], 2, json("b", &[]));
        assert_eq!(
            f.missing_dependency(std::slice::from_ref(&early), &AdmitAll),
            Ok(Some(A))
        );
        assert_eq!(
            f.accept(early.clone(), &AdmitAll),
            Err(Rejection::AheadOfApplied { device: A })
        );
        f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll)
            .unwrap();
        assert_eq!(
            f.missing_dependency(std::slice::from_ref(&early), &AdmitAll),
            Ok(None)
        );
        assert_eq!(f.accept(early, &AdmitAll), Ok(Accept::New));
        // Shape violations are reported before dependencies.
        let mut wrong = item(B, 2, &[(A, 5), (B, 2)], 3, json("x", &[]));
        wrong.version.author = A;
        assert_eq!(
            f.missing_dependency(std::slice::from_ref(&wrong), &AdmitAll),
            Err(Rejection::WrongAuthor)
        );
    }

    #[test]
    fn a_batch_is_all_or_nothing() {
        let mut f = Fold::default();
        let good = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        let next = item(A, 2, &[(A, 2)], 2, json("b", &[]));
        let skip = item(A, 3, &[(A, 4)], 3, json("c", &[]));
        assert_eq!(
            f.accept_batch(vec![good.clone(), next.clone(), skip], &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 3,
                got: 4
            })
        );
        assert_eq!(f.retained().count(), 0);
        assert_eq!(
            f.accept_batch(vec![good.clone(), next, good], &AdmitAll),
            Ok(2)
        );
    }

    #[test]
    fn concurrent_edits_produce_one_resolution_with_a_copy() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 1, json("base", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(A, 2, &[(A, 2)], 5, json("from A", &[])), &AdmitAll)
            .unwrap();
        f.accept(
            item(B, 1, &[(A, 1), (B, 1)], 9, json("from B", &[])),
            &AdmitAll,
        )
        .unwrap();
        let view = f.view();
        let shown = view.items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("from B"));
        assert_eq!(view.resolutions.len(), 1);
        let r = &view.resolutions[0];
        assert_eq!(r.record_id, ITEM);
        assert_eq!(r.collapse, Doc::Item(shown));
        let copy = &r.copies[0];
        let loser_hash = version_hash(
            RecordKind::Item,
            ITEM,
            &item(A, 2, &[(A, 2)], 5, json("", &[])).version,
        );
        assert_eq!(copy.copy_id, conflict_copy_id(ITEM, &loser_hash));
        let marker = conflict_marker(&copy.payload).unwrap();
        assert_eq!((marker.of, marker.from_device), (ITEM, A));
    }

    #[test]
    fn a_materialised_copy_is_not_proposed_again() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        let copy = f.view().resolutions[0].copies[0].clone();
        let mut written = copy.payload.clone();
        written.content_from = [(B, 1)].into_iter().collect();
        f.accept(
            Accepted {
                stream: B,
                seq: 2,
                kind: RecordKind::Item,
                record_id: copy.copy_id,
                vault_id: copy.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(written),
            },
            &AdmitAll,
        )
        .unwrap();
        assert!(f.view().resolutions.is_empty());
        assert_eq!(f.view().conflict_copies().len(), 1);
    }

    #[test]
    fn a_copy_gets_its_attachment_records_once_the_original_is_known() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[ATT])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        // The copy does not wait for the attachment record.
        let copy = f.view().resolutions[0].copies[0].clone();
        let new_att = copy_attachment_id(copy.copy_id, ATT);
        assert_eq!(
            crate::payload::copied_attachment_refs(&copy.payload),
            vec![(new_att, ATT)]
        );
        let mut written = copy.payload.clone();
        written.content_from = [(B, 1)].into_iter().collect();
        f.accept(
            Accepted {
                stream: B,
                seq: 2,
                kind: RecordKind::Item,
                record_id: copy.copy_id,
                vault_id: copy.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(written),
            },
            &AdmitAll,
        )
        .unwrap();
        assert!(
            f.view().attachment_copies.is_empty(),
            "original not known yet"
        );
        f.accept(attachment(A, 2), &AdmitAll).unwrap();
        let proposed = f.view().attachment_copies;
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].id, new_att);
        assert_eq!(proposed[0].payload.item_id, copy.copy_id);
        assert_eq!(proposed[0].payload.key, Zeroizing::new([7; 32]));
    }

    #[test]
    fn a_copy_keeps_an_attachment_that_was_removed_meanwhile() {
        let mut f = Fold::default();
        f.accept(attachment(A, 1), &AdmitAll).unwrap();
        f.accept(item(A, 2, &[(A, 1)], 5, json("a", &[ATT])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        let copy = f.view().resolutions[0].copies[0].clone();
        f.accept(
            Accepted {
                stream: B,
                seq: 2,
                kind: RecordKind::Item,
                record_id: copy.copy_id,
                vault_id: copy.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(copy.payload.clone()),
            },
            &AdmitAll,
        )
        .unwrap();
        // The original attachment is removed before anyone writes the copy's record.
        let mut removed = attachment(A, 3);
        removed.version.vector.insert(A, 2);
        removed.doc = Doc::Tombstone;
        f.accept(removed, &AdmitAll).unwrap();
        assert!(!f.view().attachments.contains_key(&ATT));
        let proposed = f.view().attachment_copies;
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].payload.item_id, copy.copy_id);
    }

    #[test]
    fn a_copy_written_only_by_a_removed_device_is_owed_again() {
        struct CutB;
        impl Admission for CutB {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                *stream != B || seq <= 1
            }
        }
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &CutB)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &CutB)
            .unwrap();
        let copy = f.view().resolutions[0].copies[0].clone();
        // B wrote the copy (of A's version) after its cut: it does not count.
        f.accept(
            Accepted {
                stream: B,
                seq: 2,
                kind: RecordKind::Item,
                record_id: copy.copy_id,
                vault_id: copy.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(copy.payload.clone()),
            },
            &CutB,
        )
        .unwrap();
        let view = f.view();
        assert_eq!(view.orphan_copies.len(), 1);
        assert_eq!(view.orphan_copies[0].copy_id, copy.copy_id);
        assert!(view.owes_copies());
        // With B fully admitted the copy counts and nothing is owed for it.
        f.refold(&AdmitAll);
        assert!(f.view().orphan_copies.is_empty());
    }

    #[test]
    fn review_c5_orphan_copies_cannot_launder_content() {
        struct CutB;
        impl Admission for CutB {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                *stream != B || seq <= 1
            }
        }
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &CutB)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &CutB)
            .unwrap();
        let honest = f.view().resolutions[0].copies[0].clone();
        // B, after its cut, writes "copies" with forged content: one under the right id, one
        // under an id of its choosing.
        let forged = |copy_id: Uuid, seq: u64| {
            let Doc::Item(mut p) = json("forged", &[]) else {
                unreachable!()
            };
            let mut obj: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&honest.payload.item_json).unwrap();
            obj.insert("title".into(), "forged".into());
            obj.insert("id".into(), copy_id.to_string().into());
            p.item_json = Zeroizing::new(serde_json::to_vec(&obj).unwrap());
            p.content_from = Vector::new();
            Accepted {
                stream: B,
                seq,
                kind: RecordKind::Item,
                record_id: copy_id,
                vault_id: honest.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(p),
            }
        };
        f.accept(forged(honest.copy_id, 2), &CutB).unwrap();
        f.accept(forged(Uuid::from_bytes([0x77; 16]), 3), &CutB)
            .unwrap();
        let view = f.view();
        // Only the copy that is owed, with the content regenerated from the admitted source.
        assert_eq!(view.orphan_copies, vec![honest]);
    }

    #[test]
    fn vault_deletion_is_undone_by_live_items() {
        let mut f = Fold::default();
        f.accept(vault(A, 1, 1, 1, false), &AdmitAll).unwrap();
        f.accept(vault(A, 2, 2, 2, true), &AdmitAll).unwrap();
        assert!(f.view().vaults[&VAULT].deleted);
        f.accept(item(B, 1, &[(B, 1)], 3, json("new", &[])), &AdmitAll)
            .unwrap();
        let v = &f.view().vaults[&VAULT];
        assert!(!v.deleted && v.revived);
    }

    #[test]
    fn refold_applies_a_cut_and_resurfaces_dominated_versions() {
        struct Cut(DeviceId, u64);
        impl Admission for Cut {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                stream != &self.0 || seq <= self.1
            }
        }
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 1, json("by A", &[])), &AdmitAll)
            .unwrap();
        f.accept(
            item(B, 7, &[(A, 1), (B, 1)], 2, json("by B", &[])),
            &AdmitAll,
        )
        .unwrap();
        assert_eq!(f.set(RecordKind::Item, ITEM).unwrap().siblings().len(), 1);
        f.refold(&Cut(B, 6));
        let shown = f.view().items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("by A"));
        f.refold(&AdmitAll);
        let shown = f.view().items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("by B"));
    }

    #[test]
    fn next_version_dominates_all_siblings_and_counts_own_writes() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        let v = f.next_version(RecordKind::Item, ITEM, A, 10);
        assert_eq!(v.vector, [(A, 2), (B, 1)].into_iter().collect());
        let fresh = f.next_version(RecordKind::Item, Uuid::from_bytes([9; 16]), B, 11);
        assert_eq!(fresh.vector, [(B, 1)].into_iter().collect());
    }

    #[test]
    fn the_view_does_not_depend_on_arrival_order() {
        let versions = vec![
            vault(A, 1, 1, 1, false),
            item(A, 2, &[(A, 1)], 2, json("base", &[ATT])),
            attachment(A, 3),
            item(B, 1, &[(A, 1), (B, 1)], 6, json("B", &[ATT])),
            item(A, 4, &[(A, 2)], 7, json("A", &[ATT])),
        ];
        let reference = {
            let mut f = Fold::default();
            for v in &versions {
                f.accept(v.clone(), &AdmitAll).unwrap();
            }
            f.view()
        };
        // Any causal order (B's version needs A's first; each stream keeps its own order).
        let orders: [&[usize]; 3] = [&[0, 1, 3, 2, 4], &[1, 3, 0, 4, 2], &[1, 2, 4, 3, 0]];
        for order in orders {
            let mut f = Fold::default();
            for &i in order {
                f.accept(versions[i].clone(), &AdmitAll).unwrap();
            }
            assert_eq!(f.view(), reference, "{order:?}");
        }
    }
}
