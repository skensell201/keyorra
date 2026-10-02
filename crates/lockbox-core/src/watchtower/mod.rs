pub mod hibp;

use std::collections::HashMap;

use uuid::Uuid;

use crate::model::Item;

pub use hibp::{breached, Hibp};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub item_id: Uuid,
    pub kind: FindingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// zxcvbn score 0-2 (of 4).
    Weak { score: u8 },
    /// The same password is used by `count` items.
    Reused { count: usize },
    /// Seen `count` times in known breaches.
    Breached { count: u64 },
}

/// Passwords with a zxcvbn score below 3.
pub fn weak(items: &[Item]) -> Vec<Finding> {
    items
        .iter()
        .filter_map(|item| {
            let password = item.password().filter(|p| !p.is_empty())?;
            let score = u8::from(zxcvbn::zxcvbn(password, &[]).score());
            (score < 3).then(|| Finding {
                item_id: item.id,
                kind: FindingKind::Weak { score },
            })
        })
        .collect()
}

/// Every item whose password is shared with another item, sorted by item id.
pub fn reused(items: &[Item]) -> Vec<Finding> {
    let mut groups: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for item in items {
        if let Some(password) = item.password().filter(|p| !p.is_empty()) {
            groups.entry(password).or_default().push(item.id);
        }
    }
    let mut out: Vec<Finding> = groups
        .values()
        .filter(|ids| ids.len() > 1)
        .flat_map(|ids| {
            ids.iter().map(|id| Finding {
                item_id: *id,
                kind: FindingKind::Reused { count: ids.len() },
            })
        })
        .collect();
    out.sort_by_key(|f| f.item_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ItemKind;

    pub(super) fn with_password(pw: &str) -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, pw, 0);
        if !pw.is_empty() {
            item.set_password(pw, 0);
        }
        item
    }

    #[test]
    fn weak_flags_guessable_passwords_only() {
        let items = [
            with_password("password"),
            with_password("correct-horse-battery-staple-91!"),
            with_password(""),
        ];
        let findings = weak(&items);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].item_id, items[0].id);
        assert!(matches!(findings[0].kind, FindingKind::Weak { score } if score < 3));
    }

    #[test]
    fn reused_groups_identical_passwords() {
        let items = [
            with_password("same-Pass-123!"),
            with_password("unique-Pass-456!"),
            with_password("same-Pass-123!"),
            with_password("same-Pass-123!"),
            with_password(""),
            with_password(""),
        ];
        let findings = reused(&items);
        let mut expected: Vec<_> = [&items[0], &items[2], &items[3]]
            .iter()
            .map(|i| Finding {
                item_id: i.id,
                kind: FindingKind::Reused { count: 3 },
            })
            .collect();
        expected.sort_by_key(|f| f.item_id);
        assert_eq!(findings, expected);
    }
}
