use std::path::PathBuf;

use lockbox_core::crypto::KdfParams;
use lockbox_core::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose};
use lockbox_core::store::ItemEntry;
use lockbox_core::store::Store;
use serde::Serialize;
use uuid::Uuid;

use crate::dto::{ItemFilter, ItemSummary, VaultDto};

use crate::autolock::AutoLock;
use crate::clipboard::ClipboardGuard;
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::throttle::UnlockThrottle;

#[cfg(test)]
mod tests;

pub const MIN_PASSWORD_LEN: usize = 10;
pub const DEFAULT_VAULT: &str = "Personal";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    /// No vault file yet: show first-run setup.
    New,
    Locked,
    Unlocked,
}

/// Everything the desktop app keeps between commands. Times are Unix seconds from the caller.
pub struct Session {
    path: PathBuf,
    kdf: KdfParams,
    store: Option<Store>,
    autolock: AutoLock,
    throttle: UnlockThrottle,
    clipboard: ClipboardGuard,
}

impl Session {
    /// `kdf` is `KdfParams::DEFAULT` in the app; tests pass cheap parameters.
    pub fn new(path: PathBuf, kdf: KdfParams, now: u64) -> Self {
        Self {
            path,
            kdf,
            store: None,
            autolock: AutoLock::new(AutoLock::DEFAULT_TIMEOUT_SECS, now),
            throttle: UnlockThrottle::default(),
            clipboard: ClipboardGuard::default(),
        }
    }

    pub fn status(&self) -> Status {
        if self.store.is_some() {
            Status::Unlocked
        } else if self.path.exists() {
            Status::Locked
        } else {
            Status::New
        }
    }

    /// First run: creates the database with a "Personal" vault and leaves it unlocked.
    pub fn create(&mut self, password: &str, now: u64) -> CmdResult<()> {
        if self.status() != Status::New {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "A vault already exists on this Mac",
            ));
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                format!("Use at least {MIN_PASSWORD_LEN} characters"),
            ));
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
        }
        let mut store = Store::create(&self.path, password, self.kdf)?;
        store.create_vault(DEFAULT_VAULT)?;
        self.store = Some(store);
        self.autolock.touch(now);
        Ok(())
    }

    pub fn unlock(&mut self, password: &str, now: u64) -> CmdResult<()> {
        if self.store.is_some() {
            return Ok(());
        }
        self.throttle.check(now).map_err(CmdError::throttled)?;
        let mut store = Store::open(&self.path)?;
        match store.unlock(password) {
            Ok(()) => {
                self.throttle.record_success();
                self.autolock.touch(now);
                self.store = Some(store);
                Ok(())
            }
            Err(lockbox_core::Error::WrongPassword) => {
                self.throttle.record_failure(now);
                Err(lockbox_core::Error::WrongPassword.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Drops the store; its keys are wiped on drop.
    pub fn lock(&mut self) {
        self.store = None;
    }

    /// Records user activity for the auto-lock timer.
    pub fn touch(&mut self, now: u64) {
        self.autolock.touch(now);
    }

    /// Periodic housekeeping; returns `true` if it just locked the vault.
    pub fn tick(&mut self, now: u64) -> bool {
        if self.store.is_some() && self.autolock.is_due(now) {
            self.lock();
            true
        } else {
            false
        }
    }

    pub fn clipboard_pending(&self) -> bool {
        self.clipboard.is_pending()
    }

    pub fn clipboard_should_clear(&mut self, now: u64, current: Option<&str>) -> bool {
        self.clipboard.should_clear(now, current)
    }

    pub fn vaults(&mut self, now: u64) -> CmdResult<Vec<VaultDto>> {
        self.touch(now);
        let store = self.store()?;
        let entries = store.list_items(None)?;
        Ok(store
            .vaults()?
            .into_iter()
            .map(|v| VaultDto {
                item_count: entries.iter().filter(|e| entry_vault(e) == v.id).count(),
                id: v.id,
                name: v.name,
            })
            .collect())
    }

    pub fn create_vault(&mut self, name: &str, now: u64) -> CmdResult<VaultDto> {
        self.touch(now);
        let name = name.trim();
        if name.is_empty() {
            return Err(CmdError::new(ErrorKind::Invalid, "Vault name is required"));
        }
        let info = self.store_mut()?.create_vault(name)?;
        Ok(VaultDto {
            id: info.id,
            name: info.name,
            item_count: 0,
        })
    }

    /// Summaries sorted by title (case-insensitive). Damaged rows show only in unfiltered lists.
    pub fn items(&mut self, filter: &ItemFilter, now: u64) -> CmdResult<Vec<ItemSummary>> {
        self.touch(now);
        let entries = self.store()?.list_items(filter.vault_id)?;
        let unfiltered = filter.query.trim().is_empty() && !filter.favorites;
        let mut out: Vec<ItemSummary> = entries
            .iter()
            .filter(|e| match e {
                ItemEntry::Ok(item) => {
                    item.overview().matches(&filter.query) && (!filter.favorites || item.favorite)
                }
                ItemEntry::Damaged { .. } => unfiltered,
            })
            .map(ItemSummary::from_entry)
            .collect();
        out.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    pub fn item(&mut self, id: Uuid, now: u64) -> CmdResult<Item> {
        self.touch(now);
        Ok(self.store()?.get_item(id)?)
    }

    /// An unsaved item with the built-in fields its kind needs.
    pub fn new_item(&mut self, vault_id: Uuid, kind: ItemKind, now: u64) -> CmdResult<Item> {
        self.touch(now);
        if !self.store()?.vaults()?.iter().any(|v| v.id == vault_id) {
            return Err(CmdError::new(
                ErrorKind::NotFound,
                format!("vault {vault_id}"),
            ));
        }
        let mut item = Item::new(vault_id, kind, "", now as i64);
        match kind {
            ItemKind::Login => {
                item.fields.push(purpose_field(Purpose::Username));
                item.fields.push(purpose_field(Purpose::Password));
            }
            ItemKind::Password => item.fields.push(purpose_field(Purpose::Password)),
            _ => {}
        }
        Ok(item)
    }

    /// Saves an edited or new item. Keeps `created_at` and the stored password history, and
    /// records the old password when it changed.
    pub fn save_item(&mut self, mut item: Item, now: u64) -> CmdResult<Item> {
        self.touch(now);
        item.title = item.title.trim().to_owned();
        if item.title.is_empty() {
            return Err(CmdError::new(ErrorKind::Invalid, "Title is required"));
        }
        let now = now as i64;
        let store = self.store_mut()?;
        match store.get_item(item.id) {
            Ok(old) => {
                item.created_at = old.created_at;
                item.password_history = old.password_history.clone();
                if let Some(old_pw) = old.password().filter(|p| !p.is_empty()) {
                    if item.password() != Some(old_pw) {
                        item.password_history.insert(
                            0,
                            HistoryEntry {
                                value: old_pw.to_owned(),
                                changed_at: now,
                            },
                        );
                    }
                }
            }
            Err(lockbox_core::Error::NotFound(_)) => {
                item.created_at = now;
                item.password_history.clear();
            }
            Err(e) => return Err(e.into()),
        }
        item.updated_at = now;
        store.save_item(&item)?;
        Ok(store.get_item(item.id)?)
    }

    pub fn delete_item(&mut self, id: Uuid, now: u64) -> CmdResult<()> {
        self.touch(now);
        Ok(self.store_mut()?.delete_item(id, now as i64)?)
    }

    fn store(&self) -> CmdResult<&Store> {
        self.store.as_ref().ok_or_else(locked)
    }

    fn store_mut(&mut self) -> CmdResult<&mut Store> {
        self.store.as_mut().ok_or_else(locked)
    }
}

fn locked() -> CmdError {
    lockbox_core::Error::Locked.into()
}

fn entry_vault(entry: &ItemEntry) -> Uuid {
    match entry {
        ItemEntry::Ok(item) => item.vault_id,
        ItemEntry::Damaged { vault_id, .. } => *vault_id,
    }
}

fn purpose_field(purpose: Purpose) -> Field {
    let (id, value) = match purpose {
        Purpose::Username => ("username", FieldValue::Text(String::new())),
        Purpose::Password => ("password", FieldValue::Concealed(String::new())),
    };
    Field {
        id: id.into(),
        label: id.into(),
        value,
        purpose: Some(purpose),
    }
}
