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
use crate::vv::{join, Vector};
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
}

impl View {
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
    retained: BTreeMap<RecordKey, Vec<Accepted>>,
    sets: BTreeMap<RecordKey, SiblingSet>,
}

impl Fold {
    /// Validates and retains `a`; it joins the sibling set if `admission` admits its position.
    pub fn accept(&mut self, a: Accepted, admission: &impl Admission) -> Result<Accept, Rejection> {
        check_shape(&a)?;
        let hash = a.hash();
        let versions = self.retained.entry(a.key()).or_default();
        if versions.iter().any(|v| v.hash() == hash) {
            return Ok(Accept::Duplicate);
        }
        let expected = own_counter(versions, &a.stream) + 1;
        let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
        if got != expected {
            return Err(Rejection::CounterNotNext { expected, got });
        }
        if admission.admits(&a.stream, a.seq) {
            self.sets.entry(a.key()).or_default().insert(a.sibling());
        }
        versions.push(a);
        Ok(Accept::New)
    }

    /// Accepts a whole segment's versions, or none of them: everything is validated first.
    /// Returns how many were new.
    pub fn accept_batch(
        &mut self,
        batch: Vec<Accepted>,
        admission: &impl Admission,
    ) -> Result<usize, Rejection> {
        let mut counters: BTreeMap<(RecordKey, DeviceId), u64> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for a in &batch {
            check_shape(a)?;
            let hash = a.hash();
            let retained = self.retained.get(&a.key()).map_or(&[][..], |v| v);
            if seen.contains(&hash) || retained.iter().any(|v| v.hash() == hash) {
                continue;
            }
            let counter = counters
                .entry((a.key(), a.stream))
                .or_insert_with(|| own_counter(retained, &a.stream));
            let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
            if got != *counter + 1 {
                return Err(Rejection::CounterNotNext {
                    expected: *counter + 1,
                    got,
                });
            }
            *counter = got;
            seen.insert(hash);
        }
        let mut new = 0;
        for a in batch {
            if self.accept(a, admission)? == Accept::New {
                new += 1;
            }
        }
        Ok(new)
    }

    /// Rebuilds every sibling set from the retained versions under a new admission policy.
    pub fn refold(&mut self, admission: &impl Admission) {
        self.sets.clear();
        for (key, versions) in &self.retained {
            for v in versions {
                if admission.admits(&v.stream, v.seq) {
                    self.sets.entry(*key).or_default().insert(v.sibling());
                }
            }
        }
    }

    pub fn set(&self, kind: RecordKind, id: Uuid) -> Option<&SiblingSet> {
        self.sets.get(&(kind, id))
    }

    pub fn sets(&self) -> impl Iterator<Item = (&RecordKey, &SiblingSet)> {
        self.sets.iter()
    }

    pub fn retained(&self) -> impl Iterator<Item = &Accepted> {
        self.retained.values().flatten()
    }

    pub fn contains(&self, kind: RecordKind, id: Uuid) -> bool {
        self.retained.contains_key(&(kind, id))
    }

    /// The version a new local write by `author` gets: it dominates every sibling.
    pub fn next_version(&self, kind: RecordKind, id: Uuid, author: DeviceId, hlc: u64) -> Version {
        let key = (kind, id);
        let mut vector = self
            .sets
            .get(&key)
            .map(|s| join(s.siblings().iter().map(|x| &x.version.vector)))
            .unwrap_or_default();
        let own = own_counter(self.retained.get(&key).map_or(&[][..], |v| v), &author);
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
                .map(|c| {
                    let Doc::Item(source) = &c.source.doc else {
                        unreachable!("copies are made of items")
                    };
                    let map: Vec<(Uuid, Uuid)> = attachment_refs(source)
                        .into_iter()
                        .map(|r| (r, copy_attachment_id(c.copy_id, r)))
                        .collect();
                    let marker = ConflictMarker {
                        of: *id,
                        version: c.source.hash,
                        from_device: c.source.version.author,
                    };
                    PendingCopy {
                        copy_id: c.copy_id,
                        vault_id: c.source.vault_id,
                        payload: ItemPayload {
                            item_json: copy_item_json(source, c.copy_id, &marker, &map)
                                .expect("item payloads are JSON objects"),
                            deleted_at: if c.trashed { source.deleted_at } else { None },
                            // Filled with the copy's own version when it is written.
                            content_from: Vector::new(),
                        },
                    }
                })
                .collect();
            if !copies.is_empty() {
                view.resolutions.push(Resolution {
                    record_id: *id,
                    copies,
                    collapse: visible.doc.clone(),
                    vault_id: visible.vault_id,
                });
            }
            if let Some(payload) = &payload {
                for (copy_att, original) in copied_attachment_refs(payload) {
                    if self.contains(RecordKind::Attachment, copy_att) {
                        continue;
                    }
                    if let Some(source) = view.attachments.get(&original) {
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

fn check_shape(a: &Accepted) -> Result<(), Rejection> {
    if a.version.author != a.stream {
        return Err(Rejection::WrongAuthor);
    }
    match a.doc.kind() {
        Some(k) if k != a.kind => Err(Rejection::KindMismatch),
        None if a.kind == RecordKind::Vault => Err(Rejection::VaultTombstone),
        _ => Ok(()),
    }
}

fn own_counter(versions: &[Accepted], author: &DeviceId) -> u64 {
    versions
        .iter()
        .filter(|v| &v.version.author == author)
        .filter_map(|v| v.version.vector.get(author).copied())
        .max()
        .unwrap_or(0)
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
            // A device that never writes here: every test version counts as a fresh edit.
            content_from: [([9; 16], 1)].into_iter().collect(),
        })
    }

    fn item(
        stream: DeviceId,
        seq: u64,
        vector: &[(DeviceId, u64)],
        hlc: u64,
        doc: Doc,
    ) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Item,
            record_id: ITEM,
            vault_id: Some(VAULT),
            version: Version {
                vector: vector.iter().copied().collect(),
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
        // Any order that keeps each stream's own order.
        let orders: [&[usize]; 3] = [&[3, 0, 1, 2, 4], &[0, 3, 1, 4, 2], &[3, 0, 1, 4, 2]];
        for order in orders {
            let mut f = Fold::default();
            for &i in order {
                f.accept(versions[i].clone(), &AdmitAll).unwrap();
            }
            assert_eq!(f.view(), reference, "{order:?}");
        }
    }
}
