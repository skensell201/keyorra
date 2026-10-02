//! Parsing other managers' exports into an [`ImportPlan`] the user previews
//! before `Store::apply_import` writes it in one transaction.

pub mod csv;
pub mod onepux;

use crate::model::Item;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImportPlan {
    pub vaults: Vec<ImportedVault>,
    pub skipped: Vec<Skipped>,
}

impl ImportPlan {
    pub fn item_count(&self) -> usize {
        self.vaults.iter().map(|v| v.items.len()).sum()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImportedVault {
    pub name: String,
    pub items: Vec<ImportedItem>,
}

/// `item.id` and `item.vault_id` are placeholders; `apply_import` assigns real ones.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedItem {
    pub item: Item,
    /// (file name, bytes)
    pub attachments: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub vaults: usize,
    pub items: usize,
    pub attachments: usize,
}
