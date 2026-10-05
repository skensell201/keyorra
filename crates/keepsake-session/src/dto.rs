//! Data shapes the UI sends and receives (camelCase JSON). Items themselves travel as
//! `keepsake_core::model::Item` (snake_case, as stored).

use keepsake_core::generator::{self, PassphraseOptions, PasswordOptions};
use keepsake_core::import::{ImportPlan, ImportReport};
use keepsake_core::model::ItemKind;
use keepsake_core::store::ItemEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CmdResult;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_left: u64,
    pub period: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GeneratorKind {
    Password,
    Passphrase,
}

/// Generator settings from the UI; omitted fields take the core defaults.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GeneratorRequest {
    pub kind: GeneratorKind,
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for GeneratorRequest {
    fn default() -> Self {
        let p = PasswordOptions::default();
        let q = PassphraseOptions::default();
        Self {
            kind: GeneratorKind::Password,
            length: p.length,
            lowercase: p.lowercase,
            uppercase: p.uppercase,
            digits: p.digits,
            symbols: p.symbols,
            avoid_ambiguous: p.avoid_ambiguous,
            words: q.words,
            separator: q.separator,
            capitalize: q.capitalize,
            include_number: q.include_number,
        }
    }
}

impl GeneratorRequest {
    pub fn generate(&self) -> CmdResult<String> {
        Ok(match self.kind {
            GeneratorKind::Password => generator::password(&PasswordOptions {
                length: self.length,
                lowercase: self.lowercase,
                uppercase: self.uppercase,
                digits: self.digits,
                symbols: self.symbols,
                avoid_ambiguous: self.avoid_ambiguous,
            })?,
            GeneratorKind::Passphrase => generator::passphrase(&PassphraseOptions {
                words: self.words,
                separator: self.separator.clone(),
                capitalize: self.capitalize,
                include_number: self.include_number,
            })?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub vaults: Vec<ImportVaultPreview>,
    pub skipped: Vec<SkippedDto>,
    pub total_items: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportVaultPreview {
    pub name: String,
    pub items: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedDto {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub vaults: usize,
    pub items: usize,
    pub attachments: usize,
}

impl ImportPreview {
    /// Empty vaults are not created by `apply_import`, so they are not shown either.
    pub fn of(plan: &ImportPlan) -> Self {
        Self {
            vaults: plan
                .vaults
                .iter()
                .filter(|v| !v.items.is_empty())
                .map(|v| ImportVaultPreview {
                    name: v.name.clone(),
                    items: v.items.len(),
                })
                .collect(),
            skipped: plan
                .skipped
                .iter()
                .map(|s| SkippedDto {
                    title: s.title.clone(),
                    reason: s.reason.clone(),
                })
                .collect(),
            total_items: plan.item_count(),
        }
    }
}

impl From<ImportReport> for ImportResult {
    fn from(r: ImportReport) -> Self {
        Self {
            vaults: r.vaults,
            items: r.items,
            attachments: r.attachments,
        }
    }
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

    #[test]
    fn generator_defaults_and_partial_json() {
        assert_eq!(
            GeneratorRequest::default()
                .generate()
                .unwrap()
                .chars()
                .count(),
            20
        );
        let req: GeneratorRequest =
            serde_json::from_str(r#"{"kind":"passphrase","words":4,"separator":"."}"#).unwrap();
        assert_eq!(req.generate().unwrap().split('.').count(), 4);
        let bad = GeneratorRequest {
            length: 7,
            ..GeneratorRequest::default()
        };
        assert_eq!(bad.generate().unwrap_err().kind, crate::ErrorKind::Invalid);
    }
}
