use std::path::PathBuf;

use lockbox_core::crypto::KdfParams;
use lockbox_core::store::Store;
use serde::Serialize;

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
}
