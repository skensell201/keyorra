//! Sibling sets: per record, the accepted versions that no other accepted version dominates
//! (an antichain, in the spirit of dotted version vectors). The set depends only on which
//! versions were added, never on the order, which is what makes devices converge.

use uuid::Uuid;

use crate::envelope::Version;
use crate::payload::Doc;
use crate::vv::{compare, Causality};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sibling {
    pub version: Version,
    /// `version_hash` of the version; also its identity.
    pub hash: [u8; 32],
    /// The envelope's `vault_id` (items and attachments).
    pub vault_id: Option<Uuid>,
    pub doc: Doc,
}

impl Sibling {
    /// The order that picks the visible sibling: higher HLC, then higher author id.
    pub fn rank(&self) -> (u64, [u8; 16]) {
        (self.version.hlc, self.version.author)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiblingSet {
    /// Kept sorted by `hash`, so equal sets are equal values.
    siblings: Vec<Sibling>,
}

impl SiblingSet {
    pub fn siblings(&self) -> &[Sibling] {
        &self.siblings
    }

    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Adds `s` unless an existing sibling equals or dominates it; drops the siblings it
    /// dominates. Returns whether `s` was added.
    pub fn insert(&mut self, s: Sibling) -> bool {
        let mut dominated = Vec::new();
        for (i, existing) in self.siblings.iter().enumerate() {
            match compare(&s.version.vector, &existing.version.vector) {
                Causality::Equal | Causality::Before => return false,
                Causality::After => dominated.push(i),
                Causality::Concurrent => {}
            }
        }
        for i in dominated.into_iter().rev() {
            self.siblings.remove(i);
        }
        let at = self.siblings.partition_point(|x| x.hash < s.hash);
        self.siblings.insert(at, s);
        true
    }

    /// The sibling with the highest rank.
    pub fn top(&self) -> Option<&Sibling> {
        self.siblings.iter().max_by_key(|s| s.rank())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const C: [u8; 16] = [3; 16];

    fn sib(author: [u8; 16], hlc: u64, vector: &[([u8; 16], u64)]) -> Sibling {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(&author);
        hash[16..24].copy_from_slice(&hlc.to_be_bytes());
        Sibling {
            version: Version {
                vector: vector.iter().copied().collect::<BTreeMap<_, _>>(),
                hlc,
                author,
            },
            hash,
            vault_id: None,
            doc: Doc::Tombstone,
        }
    }

    #[test]
    fn newer_replaces_older_and_older_is_ignored() {
        let mut s = SiblingSet::default();
        assert!(s.insert(sib(A, 1, &[(A, 1)])));
        assert!(s.insert(sib(A, 2, &[(A, 2)])));
        assert!(!s.insert(sib(A, 1, &[(A, 1)])));
        assert_eq!(s.siblings().len(), 1);
        assert_eq!(s.top().unwrap().version.hlc, 2);
    }

    #[test]
    fn concurrent_versions_are_kept_and_a_join_collapses_them() {
        let mut s = SiblingSet::default();
        s.insert(sib(A, 5, &[(A, 1)]));
        s.insert(sib(B, 3, &[(B, 1)]));
        assert_eq!(s.siblings().len(), 2);
        assert_eq!(s.top().unwrap().version.author, A);
        assert!(s.insert(sib(C, 9, &[(A, 1), (B, 1), (C, 1)])));
        assert_eq!(s.siblings().len(), 1);
    }

    #[test]
    fn rank_breaks_hlc_ties_by_author() {
        let mut s = SiblingSet::default();
        s.insert(sib(A, 5, &[(A, 1)]));
        s.insert(sib(B, 5, &[(B, 1)]));
        assert_eq!(s.top().unwrap().version.author, B);
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let versions = [
            sib(A, 1, &[(A, 1)]),
            sib(B, 2, &[(B, 1)]),
            sib(A, 3, &[(A, 2)]),
            sib(C, 4, &[(A, 1), (C, 1)]),
            sib(B, 5, &[(A, 2), (B, 2)]),
        ];
        let mut reference = SiblingSet::default();
        for v in versions.iter().cloned() {
            reference.insert(v);
        }
        for rotation in 0..versions.len() {
            for reversed in [false, true] {
                let mut order: Vec<_> = versions
                    .iter()
                    .cycle()
                    .skip(rotation)
                    .take(versions.len())
                    .collect();
                if reversed {
                    order.reverse();
                }
                let mut s = SiblingSet::default();
                for v in order {
                    s.insert(v.clone());
                }
                assert_eq!(s, reference, "rotation {rotation}, reversed {reversed}");
            }
        }
    }
}
