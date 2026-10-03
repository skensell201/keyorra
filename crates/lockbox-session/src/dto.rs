//! Data shapes the UI sends and receives (camelCase JSON). Items themselves travel as
//! `lockbox_core::model::Item` (snake_case, as stored).

use lockbox_core::model::ItemKind;
use lockbox_core::store::ItemEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDto {
    pub id: Uuid,
    pub name: String,
    pub item_count: usize,
}

/// One row of the item list. `kind` is `None` for a damaged item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: Option<ItemKind>,
    pub title: String,
    pub subtitle: String,
    pub favorite: bool,
    pub has_totp: bool,
    pub updated_at: i64,
    pub damaged: bool,
}

impl ItemSummary {
    pub fn from_entry(entry: &ItemEntry) -> Self {
        match entry {
            ItemEntry::Ok(item) => Self {
                id: item.id,
                vault_id: item.vault_id,
                kind: Some(item.kind),
                title: item.title.clone(),
                subtitle: item.username().unwrap_or_default().to_owned(),
                favorite: item.favorite,
                has_totp: item.totp().is_some(),
                updated_at: item.updated_at,
                damaged: false,
            },
            ItemEntry::Damaged { id, vault_id } => Self {
                id: *id,
                vault_id: *vault_id,
                kind: None,
                title: "Damaged item".into(),
                subtitle: "This item can't be decrypted".into(),
                favorite: false,
                has_totp: false,
                updated_at: 0,
                damaged: true,
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ItemFilter {
    pub vault_id: Option<Uuid>,
    pub query: String,
    pub favorites: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_entries_become_placeholders() {
        let (id, vault_id) = (Uuid::new_v4(), Uuid::new_v4());
        let s = ItemSummary::from_entry(&ItemEntry::Damaged { id, vault_id });
        assert!(s.damaged);
        assert_eq!(s.kind, None);
        assert_eq!((s.id, s.vault_id), (id, vault_id));
    }

    #[test]
    fn filter_fields_are_optional_camel_case() {
        let f: ItemFilter = serde_json::from_str(r#"{"query":"git"}"#).unwrap();
        assert_eq!(
            f,
            ItemFilter {
                query: "git".into(),
                ..ItemFilter::default()
            }
        );
        let id = Uuid::new_v4();
        let f: ItemFilter =
            serde_json::from_str(&format!(r#"{{"vaultId":"{id}","favorites":true}}"#)).unwrap();
        assert_eq!((f.vault_id, f.favorites), (Some(id), true));
    }
}
