use std::path::{Path, PathBuf};

use keepsake_core::crypto::KdfParams;
use keepsake_core::import::{self, onepux, ImportPlan};
use keepsake_core::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose};
use keepsake_core::store::ItemEntry;
use keepsake_core::store::Store;
use keepsake_core::totp::Totp;
use serde::Serialize;
use uuid::Uuid;

use crate::dto::{ImportPreview, ImportResult, ItemFilter, ItemSummary, TotpCode, VaultDto};

use crate::autolock::AutoLock;
use crate::clipboard::ClipboardGuard;
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::settings::Settings;
use crate::sleep::SleepDetector;
use crate::throttle::UnlockThrottle;
use crate::touchid::{self, Keyring, NoKeyring, TouchIdState, UnlockRequest};
use crate::watchtower;

mod bridge;
#[cfg(test)]
mod bridge_tests;
#[cfg(test)]
mod polish_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod touchid_tests;
#[cfg(test)]
mod watchtower_tests;

pub use bridge::{BridgeEvent, PairedBrowser, PairingRequest};

pub const MIN_PASSWORD_LEN: usize = 10;
const MAX_IMPORT_BYTES: u64 = 1 << 30;
pub const DEFAULT_VAULT: &str = "Personal";

/// What the quick-search window copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuickCopy {
    Username,
    Password,
    Totp,
}

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
    pending_import: Option<ImportPlan>,
    settings: Settings,
    settings_path: PathBuf,
    sleep: SleepDetector,
    pending: Option<bridge::PendingPairing>,
    pair_failures: u32,
    pair_blocked_until: u64,
    guard_path: PathBuf,
    /// Recent `lookup` times per paired browser, for rate limiting.
    lookups: std::collections::HashMap<String, Vec<u64>>,
    /// Set while serving a bridge call that saved an item.
    items_changed: bool,
    /// Have I Been Pwned answers by password SHA-1 (upper-case hex); forgotten on lock.
    breaches: std::collections::HashMap<String, u64>,
    /// Holds the Touch ID record (the macOS login keychain in the app).
    keyring: Box<dyn Keyring>,
    /// When the master password was last entered (or the Touch ID record says so).
    password_verified_at: Option<u64>,
}

impl Session {
    /// `kdf` is `KdfParams::DEFAULT` in the app; tests pass cheap parameters.
    pub fn new(path: PathBuf, kdf: KdfParams, now: u64) -> Self {
        let settings_path = path.with_file_name("settings.json");
        let settings = Settings::load(&settings_path);
        let guard_path = path.with_file_name(bridge::GUARD_FILE);
        let guard = bridge::PairGuard::load(&guard_path);
        Self {
            path,
            kdf,
            store: None,
            autolock: AutoLock::new(settings.auto_lock_minutes * 60, now),
            throttle: UnlockThrottle::default(),
            clipboard: ClipboardGuard::default(),
            pending_import: None,
            settings,
            settings_path,
            sleep: SleepDetector::default(),
            pending: None,
            pair_failures: guard.failures,
            pair_blocked_until: guard.blocked_until,
            guard_path,
            lookups: std::collections::HashMap::new(),
            items_changed: false,
            breaches: std::collections::HashMap::new(),
            keyring: Box::new(NoKeyring),
            password_verified_at: None,
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
        if let Err(e) = store.create_vault(DEFAULT_VAULT) {
            drop(store);
            let _ = std::fs::remove_file(&self.path);
            let mut journal = self.path.clone().into_os_string();
            journal.push("-journal");
            let _ = std::fs::remove_file(journal);
            return Err(e.into());
        }
        self.store = Some(store);
        self.autolock.touch(now);
        // A Touch ID record left from an earlier vault would only ever fail.
        self.keyring.delete();
        self.password_verified_at = Some(now);
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
                // Housekeeping, not part of unlocking: a failure here must not lock the user out.
                let _ = store.purge_expired(now as i64);
                self.store = Some(store);
                self.password_verified_at = Some(now);
                self.rearm_touch_id(now);
                Ok(())
            }
            Err(keepsake_core::Error::WrongPassword) => {
                self.throttle.record_failure(now);
                Err(keepsake_core::Error::WrongPassword.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Lets the app plug in the macOS keychain.
    pub fn set_keyring(&mut self, keyring: Box<dyn Keyring>) {
        self.keyring = keyring;
    }

    fn touch_id_record(&self) -> Option<touchid::Record> {
        self.keyring
            .load()
            .and_then(|bytes| touchid::Record::from_bytes(&bytes))
    }

    pub fn touch_id_state(&self, available: bool, now: u64) -> TouchIdState {
        let record = self.touch_id_record();
        TouchIdState {
            available,
            enabled: record.is_some(),
            password_due: record.is_some_and(|r| r.is_expired(now)),
        }
    }

    /// Turns Touch ID on with a fresh enclave key (made by the app, no prompt). Only while
    /// unlocked; the 14 days run from the last master-password entry.
    pub fn enable_touch_id(
        &mut self,
        enclave_key: Vec<u8>,
        enclave_public: &[u8],
        now: u64,
    ) -> CmdResult<()> {
        self.touch(now);
        let verified_at = self.password_verified_at.ok_or_else(|| {
            CmdError::new(
                ErrorKind::PasswordRequired,
                "Unlock with your master password first",
            )
        })?;
        let record = touchid::wrap(
            self.store()?.account_key()?,
            enclave_key,
            enclave_public,
            verified_at,
        )?;
        self.keyring
            .save(&record.to_bytes())
            .map_err(|e| CmdError::new(ErrorKind::Other, format!("Keychain: {e}")))
    }

    pub fn disable_touch_id(&mut self) {
        self.keyring.delete();
    }

    /// First half of a Touch ID unlock: what the enclave needs. The app then shows the prompt
    /// without holding the session and calls `unlock_with_touch_id`.
    pub fn touch_id_request(&self, now: u64) -> CmdResult<UnlockRequest> {
        let record = self
            .touch_id_record()
            .ok_or_else(|| CmdError::new(ErrorKind::PasswordRequired, "Touch ID is off"))?;
        if record.is_expired(now) {
            return Err(password_due());
        }
        Ok(UnlockRequest {
            enclave_key: record.enclave_key,
            ephemeral_public: record.ephemeral_public,
        })
    }

    /// Second half: `shared` is the enclave's ECDH result after Touch ID.
    pub fn unlock_with_touch_id(&mut self, shared: &[u8; 32], now: u64) -> CmdResult<()> {
        if self.store.is_some() {
            return Ok(());
        }
        let record = self
            .touch_id_record()
            .ok_or_else(|| CmdError::new(ErrorKind::PasswordRequired, "Touch ID is off"))?;
        if record.is_expired(now) {
            return Err(password_due());
        }
        let forget = |s: &mut Self, e: CmdError| {
            s.keyring.delete();
            e
        };
        let account = match touchid::unwrap(&record, shared) {
            Ok(key) => key,
            Err(e) => return Err(forget(self, e)),
        };
        let mut store = Store::open(&self.path)?;
        match store.unlock_with_key(account) {
            Ok(()) => {}
            // The record belongs to another vault (e.g. after "Start over").
            Err(keepsake_core::Error::WrongPassword) => {
                let e = CmdError::new(
                    ErrorKind::PasswordRequired,
                    "Touch ID needs to be set up again. Unlock with your master password.",
                );
                return Err(forget(self, e));
            }
            Err(e) => return Err(e.into()),
        }
        self.autolock.touch(now);
        let _ = store.purge_expired(now as i64);
        self.store = Some(store);
        self.password_verified_at = Some(record.verified_at);
        Ok(())
    }

    /// After a master-password entry: re-wrap the record so the 14 days start again. Reuses
    /// the enclave key, so no prompt. Failures leave the old record.
    fn rearm_touch_id(&mut self, now: u64) {
        let Some(record) = self.touch_id_record() else {
            return;
        };
        let Ok(account) = self.store().and_then(|s| Ok(s.account_key()?.clone())) else {
            return;
        };
        if let Ok(new) = touchid::wrap(&account, record.enclave_key, &record.enclave_public, now) {
            let _ = self.keyring.save(&new.to_bytes());
        }
    }

    /// Drops the store; its keys are wiped on drop.
    pub fn lock(&mut self) {
        self.store = None;
        self.breaches.clear();
        self.pending_import = None;
        self.drop_pending_pairing();
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

    pub fn settings(&self) -> Settings {
        self.settings
    }

    /// Validates, persists and applies new settings. Only while unlocked, so the lock screen
    /// can't be used to weaken them.
    pub fn update_settings(&mut self, settings: Settings, now: u64) -> CmdResult<Settings> {
        self.touch(now);
        self.store()?;
        settings.validate()?;
        settings.save(&self.settings_path)?;
        self.settings = settings;
        self.autolock.set_timeout(settings.auto_lock_minutes * 60);
        Ok(settings)
    }

    /// Re-wraps the account key under a new master password. Wrong guesses count towards the
    /// unlock throttle, so this form can't be used to brute-force the password.
    pub fn change_password(&mut self, current: &str, new: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        self.throttle.check(now).map_err(CmdError::throttled)?;
        if new.chars().count() < MIN_PASSWORD_LEN {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                format!("Use at least {MIN_PASSWORD_LEN} characters"),
            ));
        }
        if new == current {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "The new password must be different",
            ));
        }
        let result = self.store_mut()?.change_password(current, new);
        match result {
            Ok(()) => {
                self.throttle.record_success();
                self.password_verified_at = Some(now);
                // Replace the Touch ID record, like 1Password does after a password change.
                self.rearm_touch_id(now);
                Ok(())
            }
            Err(keepsake_core::Error::WrongPassword) => {
                self.throttle.record_failure(now);
                Err(keepsake_core::Error::WrongPassword.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Housekeeping tick from the app: also locks when the screen is locked or the Mac slept.
    /// `awake` is seconds of a monotonic clock that does not advance during sleep.
    pub fn tick_with(&mut self, now: u64, awake: u64, screen_locked: bool) -> bool {
        let slept = self.sleep.observe(now, awake);
        if self.store.is_some() && (screen_locked || slept || self.autolock.is_due(now)) {
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

    pub fn rename_vault(&mut self, id: Uuid, name: &str, now: u64) -> CmdResult<VaultDto> {
        self.touch(now);
        let name = name.trim();
        if name.is_empty() {
            return Err(CmdError::new(ErrorKind::Invalid, "Vault name is required"));
        }
        self.store_mut()?.rename_vault(id, name)?;
        self.vaults(now)?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(|| CmdError::new(ErrorKind::NotFound, format!("vault {id}")))
    }

    /// Deletes an empty vault (never the last one). Its items in Recently Deleted go with it.
    pub fn delete_vault(&mut self, id: Uuid, now: u64) -> CmdResult<()> {
        let vaults = self.vaults(now)?;
        let vault = vaults
            .iter()
            .find(|v| v.id == id)
            .ok_or_else(|| CmdError::new(ErrorKind::NotFound, format!("vault {id}")))?;
        if vaults.len() == 1 {
            return Err(CmdError::new(ErrorKind::Invalid, "Keep at least one vault"));
        }
        if vault.item_count > 0 {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                format!(
                    "\"{}\" still has {} item(s). Delete them first.",
                    vault.name, vault.item_count
                ),
            ));
        }
        Ok(self.store_mut()?.delete_vault(id, now as i64)?)
    }

    /// Moves an unreadable database aside (never deletes it) so setup can start fresh.
    /// Refuses when the file opens fine: a working vault is never moved.
    pub fn start_over(&mut self, now: u64) -> CmdResult<PathBuf> {
        if self.store.is_some() {
            return Err(CmdError::new(ErrorKind::Invalid, "Lock Keepsake first"));
        }
        match Store::open(&self.path) {
            Err(keepsake_core::Error::NotADatabase(_)) => {}
            Ok(_) => {
                return Err(CmdError::new(
                    ErrorKind::Invalid,
                    "This is a working Keepsake database; it was not moved",
                ))
            }
            Err(e) => return Err(e.into()),
        }
        self.keyring.delete();
        let aside = sibling(&self.path, &format!(".unreadable-{now}"));
        std::fs::rename(&self.path, &aside)
            .map_err(|e| CmdError::new(ErrorKind::Other, format!("Can't move the file: {e}")))?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let extra = sibling(&self.path, suffix);
            if extra.exists() {
                let _ = std::fs::rename(&extra, sibling(&aside, suffix));
            }
        }
        Ok(aside)
    }

    /// Watchtower over live items. Breach results only come from `record_breaches`.
    pub fn watchtower(&mut self, now: u64) -> CmdResult<watchtower::Report> {
        self.touch(now);
        let items = self.live_items()?;
        Ok(watchtower::report(&items, &self.breaches))
    }

    /// SHA-1 hashes (upper-case hex) of passwords not checked against HIBP in this session.
    /// The caller queries HIBP without holding the session, then calls `record_breaches`.
    pub fn breach_hashes_to_check(&mut self, now: u64) -> CmdResult<Vec<String>> {
        self.touch(now);
        let items = self.live_items()?;
        Ok(watchtower::unchecked_hashes(&items, &self.breaches))
    }

    /// Remembers HIBP answers until the vault locks. Ignored while locked.
    pub fn record_breaches(&mut self, results: impl IntoIterator<Item = (String, u64)>) {
        if self.store.is_some() {
            self.breaches.extend(results);
        }
    }

    fn live_items(&self) -> CmdResult<Vec<Item>> {
        Ok(self
            .store()?
            .list_items(None)?
            .into_iter()
            .filter_map(|e| match e {
                ItemEntry::Ok(item) => Some(item),
                ItemEntry::Damaged { .. } => None,
            })
            .collect())
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
        item.fields = template_fields(kind);
        Ok(item)
    }

    /// Saves an edited or new item. Keeps `created_at` and the stored password history, and
    /// records the old password when it changed.
    pub fn save_item(&mut self, mut item: Item, now: u64) -> CmdResult<Item> {
        self.touch(now);
        item.title = item.title.trim().to_owned();
        // An empty one-time-password field would make every code request fail.
        item.fields
            .retain(|f| !matches!(&f.value, FieldValue::Totp(s) if s.trim().is_empty()));
        // Only new or changed secrets are validated: imported items may carry values we can't
        // generate codes for, and those must not block unrelated edits.
        let known: Vec<String> = match self.store()?.get_item(item.id) {
            Ok(old) => old
                .fields
                .iter()
                .chain(old.sections.iter().flat_map(|s| s.fields.iter()))
                .filter_map(|f| match &f.value {
                    FieldValue::Totp(raw) => Some(raw.clone()),
                    _ => None,
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        for field in item
            .fields
            .iter()
            .chain(item.sections.iter().flat_map(|s| s.fields.iter()))
        {
            if let FieldValue::Totp(raw) = &field.value {
                if known.contains(raw) {
                    continue;
                }
                Totp::parse(raw).map_err(|_| {
                    let name = if field.label.is_empty() {
                        "one-time password"
                    } else {
                        &field.label
                    };
                    CmdError::new(
                        ErrorKind::Invalid,
                        format!(
                            "\"{name}\" isn't a valid one-time password: paste the secret key \
                             or the otpauth:// link from the site's 2FA setup"
                        ),
                    )
                })?;
            }
        }
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
            Err(keepsake_core::Error::NotFound(_)) => {
                let is_deleted = store.deleted_items()?.iter().any(|e| match e {
                    ItemEntry::Ok(i) => i.id == item.id,
                    ItemEntry::Damaged { id, .. } => *id == item.id,
                });
                if is_deleted {
                    return Err(CmdError::new(ErrorKind::NotFound, "This item was deleted"));
                }
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

    /// Items in Recently Deleted, sorted by title.
    pub fn deleted_items(&mut self, now: u64) -> CmdResult<Vec<ItemSummary>> {
        self.touch(now);
        let mut out: Vec<ItemSummary> = self
            .store()?
            .deleted_items()?
            .iter()
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

    pub fn restore_item(&mut self, id: Uuid, now: u64) -> CmdResult<()> {
        self.touch(now);
        Ok(self.store_mut()?.restore_item(id)?)
    }

    fn store(&self) -> CmdResult<&Store> {
        self.store.as_ref().ok_or_else(locked)
    }

    fn store_mut(&mut self) -> CmdResult<&mut Store> {
        self.store.as_mut().ok_or_else(locked)
    }

    /// Current code of the item's first TOTP field. Not activity: the UI polls it every second,
    /// which must not keep the vault unlocked.
    pub fn totp(&self, id: Uuid, now: u64) -> CmdResult<Option<TotpCode>> {
        let item = self.store()?.get_item(id)?;
        let Some(raw) = item.totp() else {
            return Ok(None);
        };
        let totp = Totp::parse(raw)?;
        Ok(Some(TotpCode {
            code: totp.code_at(now),
            seconds_left: totp.seconds_left(now),
            period: totp.period(),
        }))
    }

    /// Text to put on the clipboard for one field (`"totp"` = the current one-time code), and
    /// arms clearing it after the configured clipboard timeout.
    pub fn copy_value(&mut self, id: Uuid, field_id: &str, now: u64) -> CmdResult<String> {
        self.touch(now);
        let item = self.store()?.get_item(id)?;
        let text = if field_id == "totp" {
            let raw = item.totp().ok_or_else(|| {
                CmdError::new(ErrorKind::NotFound, "This item has no one-time password")
            })?;
            Totp::parse(raw)?.code_at(now)
        } else {
            let field = item
                .fields
                .iter()
                .chain(item.sections.iter().flat_map(|s| s.fields.iter()))
                .find(|f| f.id == field_id)
                .ok_or_else(|| CmdError::new(ErrorKind::NotFound, format!("field {field_id}")))?;
            copy_text(&field.value, now)?
        };
        if text.is_empty() {
            return Err(CmdError::new(ErrorKind::Invalid, "Nothing to copy"));
        }
        self.clipboard
            .copied(&text, now, self.settings.clipboard_seconds);
        Ok(text)
    }

    /// Quick search: copies the login's username, password or current one-time code. Fields
    /// are found by purpose, so imported items with other field ids work too.
    pub fn copy_quick(&mut self, id: Uuid, what: QuickCopy, now: u64) -> CmdResult<String> {
        let (purpose, name) = match what {
            QuickCopy::Totp => return self.copy_value(id, "totp", now),
            QuickCopy::Username => (Purpose::Username, "username"),
            QuickCopy::Password => (Purpose::Password, "password"),
        };
        let item = self.store()?.get_item(id)?;
        let field_id = item
            .fields
            .iter()
            .find(|f| f.purpose == Some(purpose))
            .map(|f| f.id.clone())
            .ok_or_else(|| {
                CmdError::new(ErrorKind::NotFound, format!("This item has no {name}"))
            })?;
        self.copy_value(id, &field_id, now)
    }

    /// Parses a 1Password export (.1pux or .csv) and keeps the plan until `import_apply`.
    pub fn import_preview(&mut self, path: &Path, now: u64) -> CmdResult<ImportPreview> {
        self.touch(now);
        self.store()?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        let too_large = std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_IMPORT_BYTES);
        if too_large {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "The export file is too large (over 1 GiB)",
            ));
        }
        let bytes = std::fs::read(path).map_err(|e| {
            CmdError::new(
                ErrorKind::Other,
                format!("Can't read {}: {e}", path.display()),
            )
        })?;
        let plan = match ext.as_deref() {
            Some("1pux") => onepux::parse(&bytes, now as i64)?,
            Some("csv") => {
                let text = String::from_utf8(bytes).map_err(|_| {
                    CmdError::new(ErrorKind::Invalid, "The CSV file is not UTF-8 text")
                })?;
                import::csv::parse(&text, "Imported", now as i64)?
            }
            _ => {
                return Err(CmdError::new(
                    ErrorKind::Invalid,
                    "Choose a .1pux or .csv export from 1Password",
                ))
            }
        };
        let preview = ImportPreview::of(&plan);
        self.pending_import = Some(plan);
        Ok(preview)
    }

    /// Writes the previewed import in one transaction.
    pub fn import_apply(&mut self, now: u64) -> CmdResult<ImportResult> {
        self.touch(now);
        let plan = self
            .pending_import
            .take()
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Choose an export file first"))?;
        Ok(self.store_mut()?.apply_import(&plan)?.into())
    }
}

/// `path` with `suffix` appended to the whole file name (`keepsake.db` -> `keepsake.db-journal`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn locked() -> CmdError {
    keepsake_core::Error::Locked.into()
}

fn password_due() -> CmdError {
    CmdError::new(
        ErrorKind::PasswordRequired,
        "Enter your master password. Keepsake asks for it every 14 days.",
    )
}

fn entry_vault(entry: &ItemEntry) -> Uuid {
    match entry {
        ItemEntry::Ok(item) => item.vault_id,
        ItemEntry::Damaged { vault_id, .. } => *vault_id,
    }
}

fn field(id: &str, label: &str, value: FieldValue) -> Field {
    Field {
        id: id.into(),
        label: label.into(),
        value,
        purpose: None,
    }
}

/// Built-in fields a new item of this kind starts with.
fn template_fields(kind: ItemKind) -> Vec<Field> {
    let text = |id: &str, label: &str| field(id, label, FieldValue::Text(String::new()));
    let hidden = |id: &str, label: &str| field(id, label, FieldValue::Concealed(String::new()));
    match kind {
        ItemKind::Login => vec![
            purpose_field(Purpose::Username),
            purpose_field(Purpose::Password),
        ],
        ItemKind::Password => vec![purpose_field(Purpose::Password)],
        ItemKind::CreditCard => vec![
            text("cardholder", "cardholder name"),
            hidden("number", "number"),
            text("expiry", "expiry date"),
            hidden("cvv", "verification number"),
        ],
        ItemKind::Identity => vec![
            text("first-name", "first name"),
            text("last-name", "last name"),
            field("email", "email", FieldValue::Email(String::new())),
            field("phone", "phone", FieldValue::Phone(String::new())),
        ],
        ItemKind::ApiCredential => vec![
            text("username", "username"),
            hidden("credential", "credential"),
            text("hostname", "hostname"),
        ],
        ItemKind::SecureNote => Vec::new(),
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

fn copy_text(value: &FieldValue, now: u64) -> CmdResult<String> {
    Ok(match value {
        FieldValue::Totp(raw) => Totp::parse(raw)?.code_at(now),
        FieldValue::Date(secs) => format_date(*secs),
        FieldValue::MonthYear(ym) => format!("{:02}/{}", ym % 100, ym / 100),
        other => other.as_str().unwrap_or_default().to_owned(),
    })
}

/// Unix seconds → `YYYY-MM-DD` (UTC), Howard Hinnant's civil-from-days algorithm.
fn format_date(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
