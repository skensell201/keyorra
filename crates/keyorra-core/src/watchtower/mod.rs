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
            let inputs = user_inputs(item);
            let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
            let score = u8::from(zxcvbn::zxcvbn(password, &inputs).score());
            (score < 3).then_some(Finding {
                item_id: item.id,
                kind: FindingKind::Weak { score },
            })
        })
        .collect()
}

/// What an attacker who knows the item would try first: its title, username and site.
fn user_inputs(item: &Item) -> Vec<String> {
    let mut out = vec![item.title.clone()];
    out.extend(item.username().map(str::to_owned));
    for raw in &item.urls {
        let with_scheme = if raw.contains("://") {
            raw.clone()
        } else {
            format!("https://{raw}")
        };
        if let Some(host) = url::Url::parse(&with_scheme)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
        {
            // The labels too: "github" in a password is as guessable as "github.com".
            out.extend(host.split('.').filter(|l| l.len() >= 3).map(str::to_owned));
            out.push(host);
        }
    }
    out.retain(|s| !s.is_empty());
    out
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
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, "Item", 0);
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
    fn weak_counts_the_items_own_title_username_and_host_as_guessable() {
        let password = "quixotrelzembulak";
        let mut plain = Item::new(Uuid::new_v4(), ItemKind::Login, "Bank", 0);
        plain.set_password(password, 0);
        assert!(weak(&[plain]).is_empty(), "strong without context");

        let mut by_title = Item::new(Uuid::new_v4(), ItemKind::Login, "Quixotrel", 0);
        by_title.set_password(password, 0);
        by_title.urls.push("https://zembulak.example/login".into());
        assert_eq!(weak(&[by_title]).len(), 1, "title + host");

        let mut by_user = Item::new(Uuid::new_v4(), ItemKind::Login, "Bank", 0);
        by_user.fields.push(crate::model::Field {
            id: "username".into(),
            label: "username".into(),
            value: crate::model::FieldValue::Text("quixotrel".into()),
            purpose: Some(crate::model::Purpose::Username),
            extra: Default::default(),
        });
        by_user.urls.push("zembulak.example".into());
        by_user.set_password(password, 0);
        assert_eq!(weak(&[by_user]).len(), 1, "username + bare host");
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
