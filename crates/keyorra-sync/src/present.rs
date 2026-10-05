//! Presentation: what the user sees for a record, given its sibling set (spec §3.5).
//! Everything here is a pure function of the set, so every device shows the same thing.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::labels::{self, tagged};
use crate::payload::{item_content_eq, AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::siblings::{Sibling, SiblingSet};
use crate::vv::{compare, Causality};

fn uuid_v8(digest: &[u8]) -> Uuid {
    Uuid::new_v8(digest[..16].try_into().expect("SHA-256 has 32 bytes"))
}

/// Id of the conflict copy made from sibling `version_hash` of record `record_id`:
/// `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ record_id ‖ version_hash)[0..16])`.
pub fn conflict_copy_id(record_id: Uuid, version_hash: &[u8; 32]) -> Uuid {
    uuid_v8(&Sha256::digest(tagged(
        labels::CONFLICT_COPY,
        &[record_id.as_bytes(), version_hash],
    )))
}

/// Id of the attachment record a conflict copy gets for one of the original's attachments:
/// `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ copy_id ‖ attachment_id)[0..16])`
/// (32 input bytes after the label, against 48 for an item copy, so the two never collide).
pub fn copy_attachment_id(copy_id: Uuid, attachment_id: Uuid) -> Uuid {
    uuid_v8(&Sha256::digest(tagged(
        labels::CONFLICT_COPY,
        &[copy_id.as_bytes(), attachment_id.as_bytes()],
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemState {
    Live,
    Trashed,
    Purged,
}

/// One sibling that must become a conflict copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyOf<'a> {
    pub copy_id: Uuid,
    pub source: &'a Sibling,
    /// The copy goes to Recently Deleted (an edited-then-trashed sibling).
    pub trashed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemPresentation<'a> {
    pub state: ItemState,
    /// The sibling shown; `None` only for an empty set.
    pub visible: Option<&'a Sibling>,
    pub copies: Vec<CopyOf<'a>>,
}

fn payload(s: &Sibling) -> Option<&ItemPayload> {
    match &s.doc {
        Doc::Item(p) => Some(p),
        _ => None,
    }
}

fn state(s: &Sibling) -> ItemState {
    match payload(s) {
        None => ItemState::Purged,
        Some(p) if p.deleted_at.is_some() => ItemState::Trashed,
        Some(_) => ItemState::Live,
    }
}

/// Spec §3.5 for items. A sibling is *stale* when another sibling has seen its content (its
/// `content_from` is covered by that sibling's version): it only trashed or restored content
/// that the other side then kept or replaced.
///
/// Shown: a purge if there is one (purge is final), else the best live sibling (an edit beats a
/// delete), else the best trashed one, where "best" prefers fresh over stale siblings, then the
/// higher HLC, then the higher author id. Every other sibling becomes a copy unless it is stale
/// or its content is already shown. With a purge, only live siblings can become copies.
pub fn present_item(record_id: Uuid, set: &SiblingSet) -> ItemPresentation<'_> {
    let stale = |s: &Sibling| {
        payload(s).is_some_and(|p| {
            set.siblings().iter().any(|o| {
                !std::ptr::eq(o, s)
                    && matches!(
                        compare(&p.content_from, &o.version.vector),
                        Causality::Equal | Causality::Before
                    )
            })
        })
    };
    let mut by_rank: Vec<&Sibling> = set.siblings().iter().collect();
    by_rank.sort_by_key(|s| std::cmp::Reverse((!stale(s), s.rank())));
    let first = |st: ItemState| by_rank.iter().copied().find(|s| state(s) == st);
    let (shown_state, visible) = match (
        first(ItemState::Purged),
        first(ItemState::Live),
        first(ItemState::Trashed),
    ) {
        (Some(p), _, _) => (ItemState::Purged, p),
        (None, Some(l), _) => (ItemState::Live, l),
        (None, None, Some(t)) => (ItemState::Trashed, t),
        (None, None, None) => {
            return ItemPresentation {
                state: ItemState::Purged,
                visible: None,
                copies: vec![],
            }
        }
    };
    let mut shown: Vec<&ItemPayload> = payload(visible).into_iter().collect();
    let mut copies = Vec::new();
    for s in by_rank {
        if std::ptr::eq(s, visible) {
            continue;
        }
        let Some(p) = payload(s) else { continue };
        if shown_state == ItemState::Purged && p.deleted_at.is_some() {
            continue;
        }
        if stale(s) || shown.iter().any(|x| item_content_eq(x, p)) {
            continue;
        }
        shown.push(p);
        copies.push(CopyOf {
            copy_id: conflict_copy_id(record_id, &s.hash),
            source: s,
            trashed: p.deleted_at.is_some(),
        });
    }
    ItemPresentation {
        state: shown_state,
        visible: Some(visible),
        copies,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPresentation<'a> {
    pub payload: &'a VaultPayload,
    /// Shown as deleted: the visible version is deleted and no live item remains in it.
    pub deleted: bool,
    /// The visible version is deleted but live items keep the vault (spec §3.5).
    pub revived: bool,
    /// Siblings disagree on the wrapped vault key: an alarm, never expected before rotation.
    pub key_mismatch: bool,
}

pub fn present_vault(set: &SiblingSet, has_live_items: bool) -> Option<VaultPresentation<'_>> {
    let vaults: Vec<(&Sibling, &VaultPayload)> = set
        .siblings()
        .iter()
        .filter_map(|s| match &s.doc {
            Doc::Vault(p) => Some((s, p)),
            _ => None,
        })
        .collect();
    let (_, top) = vaults.iter().max_by_key(|(s, _)| s.rank())?;
    let key_mismatch = vaults.iter().any(|(_, p)| p.wrapped_key != top.wrapped_key);
    Some(VaultPresentation {
        payload: top,
        deleted: top.deleted && !has_live_items,
        revived: top.deleted && has_live_items,
        key_mismatch,
    })
}

/// A tombstone sibling wins; otherwise the top-ranked version. `None` = removed.
pub fn present_attachment(set: &SiblingSet) -> Option<(&Sibling, &AttachmentPayload)> {
    if set.siblings().iter().any(|s| s.doc == Doc::Tombstone) {
        return None;
    }
    let top = set.top()?;
    match &top.doc {
        Doc::Attachment(p) => Some((top, p)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Version;
    use crate::vv::Vector;
    use zeroize::Zeroizing;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const C: [u8; 16] = [3; 16];
    const ID: Uuid = Uuid::from_bytes([0x60; 16]);

    fn vector(entries: &[([u8; 16], u64)]) -> Vector {
        entries.iter().copied().collect()
    }

    fn sib(author: [u8; 16], hlc: u64, version: &[([u8; 16], u64)], doc: Doc) -> Sibling {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(&author);
        hash[16..24].copy_from_slice(&hlc.to_be_bytes());
        Sibling {
            version: Version {
                vector: vector(version),
                hlc,
                author,
            },
            hash,
            vault_id: Some(Uuid::from_bytes([0x61; 16])),
            doc,
        }
    }

    /// An item whose content was last changed at `content_from`.
    fn item(title: &str, deleted_at: Option<u64>, content_from: &[([u8; 16], u64)]) -> Doc {
        Doc::Item(ItemPayload {
            item_json: Zeroizing::new(format!(r#"{{"title":"{title}"}}"#).into_bytes()),
            deleted_at,
            content_from: vector(content_from),
        })
    }

    /// A fresh edit: the content was changed by this very version.
    fn edit(author: [u8; 16], hlc: u64, version: &[([u8; 16], u64)], title: &str) -> Sibling {
        sib(author, hlc, version, item(title, None, version))
    }

    fn set(siblings: Vec<Sibling>) -> SiblingSet {
        let mut s = SiblingSet::default();
        for x in siblings {
            assert!(s.insert(x));
        }
        s
    }

    /// (state, author of the visible sibling, [(author of a copied sibling, trashed)]).
    type Summary = (ItemState, Option<[u8; 16]>, Vec<([u8; 16], bool)>);

    fn summary(p: &ItemPresentation) -> Summary {
        (
            p.state,
            p.visible.map(|v| v.version.author),
            p.copies
                .iter()
                .map(|c| (c.source.version.author, c.trashed))
                .collect(),
        )
    }

    #[test]
    fn copy_ids_are_deterministic_v8_and_distinct() {
        let a = conflict_copy_id(ID, &[1; 32]);
        assert_eq!(a, conflict_copy_id(ID, &[1; 32]));
        assert_eq!(a.get_version_num(), 8);
        assert_ne!(a, conflict_copy_id(ID, &[2; 32]));
        assert_ne!(a, conflict_copy_id(Uuid::from_bytes([0x62; 16]), &[1; 32]));
        assert_ne!(
            copy_attachment_id(a, ID),
            copy_attachment_id(a, Uuid::from_bytes([0x62; 16]))
        );
        // Pinned (cross-checked with Python hashlib).
        assert_eq!(a.to_string(), "fa11d85b-0a1a-8caa-8441-ad95ab1ee22b");
    }

    #[test]
    fn single_live_version_has_no_copies() {
        let s = set(vec![edit(A, 1, &[(A, 1)], "a")]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(A), vec![])
        );
    }

    #[test]
    fn concurrent_edits_keep_the_top_and_copy_the_rest() {
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "a"),
            edit(B, 9, &[(B, 1)], "b"),
            edit(C, 7, &[(C, 1)], "c"),
        ]);
        let p = present_item(ID, &s);
        assert_eq!(
            summary(&p),
            (ItemState::Live, Some(B), vec![(C, false), (A, false)])
        );
        assert_eq!(
            p.copies[0].copy_id,
            conflict_copy_id(ID, &p.copies[0].source.hash)
        );
    }

    #[test]
    fn equal_content_makes_no_copy() {
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "same"),
            edit(B, 9, &[(B, 1)], "same"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
        // Two losers with the same content make one copy.
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "x"),
            edit(B, 9, &[(B, 1)], "y"),
            edit(C, 7, &[(C, 1)], "x"),
        ]);
        assert_eq!(summary(&present_item(ID, &s)).2, vec![(C, false)]);
    }

    #[test]
    fn a_pure_delete_loses_to_a_concurrent_edit_without_a_copy() {
        // C wrote "base"; A trashed it unchanged while B edited it. A ranks higher.
        let s = set(vec![
            sib(A, 9, &[(C, 1), (A, 1)], item("base", Some(100), &[(C, 1)])),
            edit(B, 5, &[(C, 1), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
    }

    #[test]
    fn an_edit_then_trash_survives_in_recently_deleted() {
        // A edited "base" to "mine" (A:1) and then trashed it (A:2), concurrently with B's edit.
        let s = set(vec![
            sib(
                A,
                9,
                &[(C, 1), (A, 2)],
                item("mine", Some(100), &[(C, 1), (A, 1)]),
            ),
            edit(B, 5, &[(C, 1), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![(A, true)])
        );
    }

    #[test]
    fn a_pure_restore_loses_to_a_concurrent_edit_without_a_copy() {
        // "base" was trashed by C; A restored it unchanged while B edited and restored it.
        // The edit shows even when the restore ranks higher.
        let s = set(vec![
            sib(A, 9, &[(C, 2), (A, 1)], item("base", None, &[(C, 1)])),
            edit(B, 5, &[(C, 2), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
        let s = set(vec![
            sib(A, 3, &[(C, 2), (A, 1)], item("base", None, &[(C, 1)])),
            edit(B, 5, &[(C, 2), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
    }

    #[test]
    fn purge_is_final_and_live_edits_become_copies() {
        let s = set(vec![
            sib(A, 1, &[(C, 2), (A, 1)], Doc::Tombstone),
            edit(B, 9, &[(C, 2), (B, 1)], "b"),
            sib(C, 5, &[(C, 3)], item("c", Some(3), &[(C, 3)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Purged, Some(A), vec![(B, false)])
        );
        // A restore without an edit, concurrent with the purge, leaves nothing to keep.
        let s = set(vec![
            sib(A, 1, &[(C, 2), (A, 1)], Doc::Tombstone),
            sib(B, 9, &[(C, 2), (B, 1)], item("base", None, &[(C, 1)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Purged, Some(A), vec![])
        );
    }

    #[test]
    fn all_trashed_shows_the_top_trashed_and_copies_differing_edits() {
        let s = set(vec![
            sib(A, 1, &[(A, 2)], item("a", Some(1), &[(A, 1)])),
            sib(B, 9, &[(B, 2)], item("b", Some(2), &[(B, 1)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Trashed, Some(B), vec![(A, true)])
        );
    }

    #[test]
    fn deleted_vault_is_revived_by_live_items() {
        let vault = |name: &str, deleted: bool| {
            Doc::Vault(VaultPayload {
                name: name.into(),
                wrapped_key: vec![1, 2, 3],
                deleted,
            })
        };
        let s = set(vec![
            sib(A, 9, &[(A, 1)], vault("Work", true)),
            sib(B, 5, &[(B, 1)], vault("Job", false)),
        ]);
        let p = present_vault(&s, false).unwrap();
        assert!(p.deleted && !p.revived && !p.key_mismatch);
        assert_eq!(p.payload.name, "Work");
        let p = present_vault(&s, true).unwrap();
        assert!(!p.deleted && p.revived);
        let odd = Doc::Vault(VaultPayload {
            name: "Job".into(),
            wrapped_key: vec![9],
            deleted: false,
        });
        let s = set(vec![
            sib(A, 9, &[(A, 1)], vault("Work", false)),
            sib(B, 5, &[(B, 1)], odd),
        ]);
        assert!(present_vault(&s, false).unwrap().key_mismatch);
    }

    #[test]
    fn attachment_tombstone_wins() {
        let att = Doc::Attachment(AttachmentPayload {
            item_id: ID,
            name: "a".into(),
            size: 1,
            key: Zeroizing::new([0; 32]),
            chunk_size: 1,
            chunks: vec![],
        });
        let s = set(vec![sib(A, 9, &[(A, 1)], att.clone())]);
        assert!(present_attachment(&s).is_some());
        let s = set(vec![
            sib(A, 9, &[(A, 1)], att),
            sib(B, 1, &[(B, 1)], Doc::Tombstone),
        ]);
        assert!(present_attachment(&s).is_none());
    }
}
