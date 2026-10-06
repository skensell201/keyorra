//! Sync in the session (plan A1d): turned on, joined, run and turned off here; it runs only
//! while the vault is unlocked. The app supplies the transport and the device key store
//! through a [`SyncLink`] (the folder transport is plan A2; the UI is plan A3).

use keyorra_core::crypto::Key;
use keyorra_core::store::Store;
use keyorra_sync::header::Header;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::Transport;
use keyorra_sync::AccountId;
use serde::Serialize;

use super::{locked, move_aside, sibling, Session, Status, DB_SIBLINGS, MIN_PASSWORD_LEN};
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::sync::{self as s, DeviceKeyStore, SetupCode, SyncStatus, Synced};

/// The transport sync runs over, boxed.
pub type BoxedTransport = Box<dyn Transport + Send>;

/// What the app gives the session for sync.
pub trait SyncLink: Send {
    /// The folder of `account` (opened per use; plan A2: `<place>/Keyorra/<account hex>/`).
    fn transport(&self, account: &AccountId) -> Result<BoxedTransport, String>;
    /// Makes the folder of a new account (turning sync on, starting a new account); it must
    /// hold no account yet.
    fn new_account_transport(&self, account: &AccountId) -> Result<BoxedTransport, String> {
        self.transport(account)
    }
    /// Where the account lives, for the Sync screen (a folder path).
    fn location(&self, account: &AccountId) -> Option<String> {
        let _ = account;
        None
    }
    /// Every account folder in the sync place, by folder name, opened read-only (nothing is
    /// created in them): joining picks the one named after the account whose header names
    /// the Secret Key.
    fn join_candidates(&self) -> Result<Vec<(String, BoxedTransport)>, String>;
    fn device_keys(&self) -> Box<dyn DeviceKeyStore>;
    /// This Mac's name, shown to the other devices.
    fn device_name(&self) -> String;
    /// Opens an account header with the master password and Secret Key (tests replace the
    /// remote KDF floor).
    fn unlock_header(
        &self,
        header: &Header,
        password: &str,
        secret_key: &SecretKey,
    ) -> keyorra_sync::Result<Key> {
        header.unlock(password, secret_key).map(|(key, _)| key)
    }
}

/// Shown once when sync is turned on (and again from settings while unlocked).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyKitDto {
    pub account_id: String,
    pub secret_key: String,
    /// Kept in Rust: the app copies it to the clipboard itself (review A3), so it never
    /// reaches the web view.
    #[serde(skip_serializing)]
    pub setup_code: String,
    /// Where the account lives (the folder path), when the link knows it.
    pub location: Option<String>,
}

/// One line of the Sync log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    pub at: u64,
    pub text: String,
}

/// The Sync log keeps this many lines (in memory, until the vault locks).
pub const SYNC_LOG_LINES: usize = 200;

/// How joining went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinOutcome {
    /// "new": a vault was made for the account; "rejoined": this vault joined its account
    /// again; "carriedOver": this vault's items were copied into a new vault for the account.
    pub mode: &'static str,
    /// Compare it on the main Mac before it approves this Mac.
    pub key_code: String,
    pub copied: usize,
    /// Items in Recently Deleted that stayed in the old file.
    pub trashed_left: usize,
    /// Items that could not be read and stayed in the old file.
    pub damaged: usize,
}

/// The sync part of the settings screen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub enabled: bool,
    /// Set but not running (e.g. the transport could not be opened); shown with a retry.
    pub error: Option<String>,
    pub status: Option<SyncStatus>,
    /// From the last round: local changes sync could not take and undid (shown once), and
    /// records that wait or could not be shown.
    pub notices: Vec<String>,
}

pub(super) fn sync_error(e: keyorra_sync::Error) -> CmdError {
    match e {
        keyorra_sync::Error::Core(core) => core.into(),
        keyorra_sync::Error::WrongPassword => CmdError::new(
            ErrorKind::WrongPassword,
            "Wrong master password or Secret Key",
        ),
        keyorra_sync::Error::NotFound(m) => CmdError::new(ErrorKind::NotFound, m),
        keyorra_sync::Error::Refused(m) => CmdError::new(ErrorKind::Invalid, m),
        other => CmdError::new(ErrorKind::Other, other.to_string()),
    }
}

fn no_link() -> CmdError {
    CmdError::new(ErrorKind::Invalid, "Sync isn't available in this build")
}

/// How long after a master-password entry the Emergency Kit is shown without asking again.
pub const KIT_PASSWORD_SECS: u64 = 5 * 60;

/// Removes a database file and SQLite's companions.
pub(super) fn remove_database(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    for suffix in DB_SIBLINGS {
        let _ = std::fs::remove_file(sibling(path, suffix));
    }
}

/// The file a join that carries another account's vault over builds before moving it into
/// place.
pub(super) fn joining_path(path: &std::path::Path) -> std::path::PathBuf {
    path.with_extension("joining")
}

/// On start: a join that stopped after moving the old vault aside and before moving the new
/// one into place is finished; one that stopped earlier leaves an unfinished file, which goes
/// (review A1d-2 I8).
pub(super) fn recover_interrupted_join(path: &std::path::Path) {
    let joining = joining_path(path);
    if joining.symlink_metadata().is_err() {
        return;
    }
    if path.symlink_metadata().is_err() {
        let _ = move_aside(&joining, path, |from, to| std::fs::rename(from, to));
    } else {
        remove_database(&joining);
    }
}

fn folder_error(e: String) -> CmdError {
    CmdError::new(ErrorKind::Other, format!("Sync folder: {e}"))
}

fn open_transport(link: &dyn SyncLink, account: &AccountId) -> CmdResult<BoxedTransport> {
    link.transport(account).map_err(folder_error)
}

/// The account folder to join (review A2 I4): among the folders of the sync place, those
/// named after the account their header gives for this Secret Key id; each is tried with
/// `open` (the password); exactly one must open. A folder that fails to be read does not stop
/// the others; header files still downloading make a retryable error.
pub(super) fn choose_join_folder<T: Transport>(
    candidates: Vec<(String, T)>,
    secret_key_id: &str,
    mut open: impl FnMut(&T) -> keyorra_sync::Result<()>,
) -> CmdResult<T> {
    let mut downloading = false;
    let mut last_error = None;
    let mut opened = Vec::new();
    for (name, folder) in candidates {
        match s::find_account(&folder, secret_key_id) {
            Ok(s::AccountMatch::Account(account))
                if name == data_encoding::HEXLOWER.encode(&account) =>
            {
                match open(&folder) {
                    Ok(()) => opened.push(folder),
                    Err(e) => last_error = Some(e),
                }
            }
            Ok(s::AccountMatch::Downloading) => downloading = true,
            _ => {}
        }
    }
    match opened.len() {
        1 => Ok(opened.pop().expect("one")),
        0 => Err(match (last_error, downloading) {
            (Some(e), _) => sync_error(e),
            (None, true) => CmdError::new(
                ErrorKind::Other,
                "The account's files are still downloading to this Mac; try again in a moment",
            ),
            (None, false) => CmdError::new(
                ErrorKind::NotFound,
                "No account for this Secret Key in the sync folder",
            ),
        }),
        _ => Err(CmdError::new(
            ErrorKind::Invalid,
            "More than one folder holds this account; keep one and try again",
        )),
    }
}

fn join_transport(
    link: &dyn SyncLink,
    password: &str,
    (sk, sk_id): (&SecretKey, &str),
    pin: Option<&keyorra_sync::account::RootPin>,
) -> CmdResult<BoxedTransport> {
    let candidates = link.join_candidates().map_err(folder_error)?;
    choose_join_folder(candidates, sk_id, |t| {
        s::opens(t, pin, |h: &Header| link.unlock_header(h, password, sk))
    })
}

/// Where the old database goes when the vault joins another account (spec §7.3):
/// `keyorra.db.pre-sync-YYYYMMDD`, then `-2`, `-3`… if taken.
fn pre_sync_path(path: &std::path::Path, now: u64) -> std::path::PathBuf {
    let (y, m, d) = civil_date(now / 86_400);
    let base = sibling(path, &format!(".pre-sync-{y:04}{m:02}{d:02}"));
    let taken = |p: &std::path::Path| p.symlink_metadata().is_ok();
    (1u32..)
        .map(|n| match n {
            1 => base.clone(),
            n => sibling(&base, &format!("-{n}")),
        })
        .find(|c| !taken(c) && !DB_SIBLINGS.iter().any(|s| taken(&sibling(c, s))))
        .expect("some counter is free")
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil_date(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn wall_ms(now: u64) -> u64 {
    now.saturating_mul(1000)
}

/// A key code as the user typed it, in the form it is shown (`xxxx-xxxx-xxxx`, lower-case
/// hex): case, dashes and anything else that is not a hex digit are ignored.
fn normalize_key_code(typed: &str) -> CmdResult<String> {
    let hex: String = typed
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 {
        return Err(CmdError::new(
            ErrorKind::Invalid,
            "The code has 12 letters and digits",
        ));
    }
    Ok(format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12]))
}

impl Session {
    pub fn set_sync_link(&mut self, link: Box<dyn SyncLink>) {
        self.sync_link = Some(link);
    }

    fn link(&self) -> CmdResult<&dyn SyncLink> {
        self.sync_link.as_deref().ok_or_else(no_link)
    }

    /// The folder of the account this vault syncs with.
    fn transport(&self) -> CmdResult<BoxedTransport> {
        let account = s::account_id(self.store()?).map_err(sync_error)?;
        open_transport(self.link()?, &account)
    }

    /// Runs `f` with the link taken out of the session (so `f` may change the session).
    fn with_link<R>(
        &mut self,
        f: impl FnOnce(&mut Self, &dyn SyncLink) -> CmdResult<R>,
    ) -> CmdResult<R> {
        let link = self.sync_link.take().ok_or_else(no_link)?;
        let result = f(self, link.as_ref());
        self.sync_link = Some(link);
        result
    }

    /// Whether the place sync accounts live in may change now: only while sync is off,
    /// which is known only while unlocked (or before the first vault exists, to join on
    /// first run).
    pub fn may_change_sync_place(&self) -> CmdResult<()> {
        match self.status() {
            Status::New => Ok(()),
            Status::Locked => Err(locked()),
            Status::Unlocked => {
                if self.sync_status()?.enabled {
                    Err(CmdError::new(
                        ErrorKind::Invalid,
                        "Turn sync off before choosing another folder",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Called right after every unlock: sync continues where it stopped. A failure is kept
    /// for the status (unlocking never fails because of sync).
    pub(super) fn resume_sync(&mut self) {
        self.sync_error = None;
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if !s::is_enabled(store).unwrap_or(false) {
            return;
        }
        let result = (|| -> CmdResult<Synced<BoxedTransport>> {
            let link = self.link()?;
            let transport = self.transport()?;
            let keys = link.device_keys();
            s::resume(store, transport, keys.as_ref()).map_err(sync_error)
        })();
        match result {
            Ok(synced) => self.synced = Some(synced),
            Err(e) => self.sync_error = Some(e.message),
        }
    }

    /// Keeps what the UI shows about the last round, and its lines for the Sync log.
    fn note_round(&mut self, round: keyorra_sync::Result<s::RoundReport>, now: u64) {
        let mut lines = Vec::new();
        match round {
            Ok(report) => {
                self.sync_error = None;
                self.last_round = Some((now, true));
                if let Some(synced) = self.synced.as_ref() {
                    lines.extend(report.events.iter().filter_map(|e| synced.describe(e)));
                }
                lines.extend(
                    report
                        .reverted
                        .iter()
                        .map(|(_, why)| format!("Undone: {why}")),
                );
                self.sync_notices = report
                    .reverted
                    .iter()
                    .map(|(_, why)| why.clone())
                    .chain(report.failed.iter().map(|(id, why)| format!("{id}: {why}")))
                    .collect();
            }
            Err(e) => {
                let message = sync_error(e).message;
                lines.push(format!("Sync failed: {message}"));
                self.last_round = Some((now, false));
                self.sync_error = Some(message);
            }
        }
        for text in lines {
            if self.sync_log.len() == SYNC_LOG_LINES {
                self.sync_log.pop_front();
            }
            self.sync_log.push_back(LogLine { at: now, text });
        }
    }

    pub fn sync_status(&self) -> CmdResult<SyncStatusDto> {
        let store = self.store()?;
        Ok(SyncStatusDto {
            enabled: s::is_enabled(store).map_err(sync_error)?,
            error: self.sync_error.clone(),
            status: self.synced.as_ref().map(|x| x.status()),
            notices: self.sync_notices.clone(),
        })
    }

    /// One sync round (the app calls it on a timer and after every change while unlocked).
    /// Sync that is on but not running (its folder was not there at unlock) is started again
    /// first (review A1d-2 I9).
    pub fn sync_now(&mut self, now: u64) -> CmdResult<SyncStatusDto> {
        let enabled = s::is_enabled(self.store()?).map_err(sync_error)?;
        if enabled && self.synced.is_none() {
            self.resume_sync();
        }
        let store = self.store.as_mut().ok_or_else(locked)?;
        if let Some(synced) = self.synced.as_mut() {
            let round = synced.round(store, wall_ms(now));
            self.note_round(round, now);
            self.watchtower_count = None;
        }
        self.sync_status()
    }

    /// Turns this vault into the main device of a new synced account. The master password
    /// is asked again (it also protects the account header).
    pub fn enable_sync(&mut self, password: &str, now: u64) -> CmdResult<EmergencyKitDto> {
        self.touch(now);
        self.check_password_throttled(password, now)?;
        let link = self.link()?;
        let account = s::new_account_id();
        let (transport, mut keys, name) = (
            link.new_account_transport(&account).map_err(folder_error)?,
            link.device_keys(),
            link.device_name(),
        );
        let kdf = self.kdf;
        let store = self.store.as_mut().ok_or_else(locked)?;
        let s::Enabled {
            synced,
            kit,
            first_round,
            ..
        } = s::enable(
            store,
            account,
            transport,
            keys.as_mut(),
            &name,
            password,
            kdf,
            wall_ms(now),
        )
        .map_err(sync_error)?;
        let dto = EmergencyKitDto {
            account_id: kit.account_id,
            secret_key: kit.secret_key.to_string(),
            setup_code: synced.setup_code().to_text().to_string(),
            location: self.link()?.location(&account),
        };
        self.synced = Some(synced);
        self.note_round(first_round, now);
        Ok(dto)
    }

    /// The master password, checked against the unlock throttle (wrong guesses count).
    fn check_password_throttled(&mut self, password: &str, now: u64) -> CmdResult<()> {
        self.store()?;
        self.throttle.check(now).map_err(CmdError::throttled)?;
        match self.store()?.check_password(password) {
            Ok(()) => {
                self.throttle.record_success();
                self.password_verified_at = Some(now);
                Ok(())
            }
            Err(keyorra_core::Error::WrongPassword) => {
                self.throttle.record_failure(now);
                Err(keyorra_core::Error::WrongPassword.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The Emergency Kit and setup code again (unlocked, sync on). They hold the Secret Key:
    /// the master password is needed unless it was entered in the last few minutes (review
    /// A1d-2 I11).
    pub fn emergency_kit(
        &mut self,
        password: Option<&str>,
        now: u64,
    ) -> CmdResult<EmergencyKitDto> {
        self.store()?;
        match password {
            Some(p) => self.check_password_throttled(p, now)?,
            None => {
                let recent = self
                    .password_verified_at
                    .is_some_and(|at| at <= now && now - at <= KIT_PASSWORD_SECS);
                if !recent {
                    return Err(CmdError::new(
                        ErrorKind::PasswordRequired,
                        "Enter your master password to see the Emergency Kit",
                    ));
                }
            }
        }
        let synced = self
            .synced
            .as_ref()
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Sync is off"))?;
        let kit = synced.emergency_kit();
        let location = s::account_id(self.store()?)
            .ok()
            .and_then(|a| self.link().ok().and_then(|l| l.location(&a)));
        Ok(EmergencyKitDto {
            account_id: kit.account_id,
            secret_key: kit.secret_key.to_string(),
            setup_code: synced.setup_code().to_text().to_string(),
            location,
        })
    }

    /// Joins a synced account with the master password and a setup code (or the Secret Key
    /// alone: then the main device is not pinned and the UI warns).
    ///
    /// - No vault on this Mac yet: one is created for the account.
    /// - This vault (unlocked, sync off) belonged to the same account: it rejoins; records
    ///   merge by id.
    /// - It belongs to another account: a vault is made for the account and this vault's
    ///   items are carried over into it; the old file is kept aside.
    pub fn join_sync(&mut self, password: &str, code: &str, now: u64) -> CmdResult<JoinOutcome> {
        self.touch(now);
        let (sk_id, sk, pin) = match SetupCode::parse(code) {
            Ok(c) => (c.secret_key_id, c.secret_key, Some(c.pin)),
            Err(_) => {
                let (id, sk) = SecretKey::parse(code).map_err(|_| {
                    CmdError::new(ErrorKind::Invalid, "That isn't a setup code or Secret Key")
                })?;
                (id, sk, None)
            }
        };
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(CmdError::new(
                ErrorKind::WrongPassword,
                "Wrong master password",
            ));
        }
        self.with_link(|this, link| this.join_with(link, password, (&sk, &sk_id), pin, now))
    }

    fn join_with(
        &mut self,
        link: &dyn SyncLink,
        password: &str,
        (sk, sk_id): (&SecretKey, &str),
        pin: Option<keyorra_sync::account::RootPin>,
        now: u64,
    ) -> CmdResult<JoinOutcome> {
        let (transport, mut keys, name) = (
            join_transport(link, password, (sk, sk_id), pin.as_ref())?,
            link.device_keys(),
            link.device_name(),
        );
        let unlock = |h: &Header| link.unlock_header(h, password, sk);
        let outcome = |mode: &'static str, synced: &Synced<BoxedTransport>| JoinOutcome {
            mode,
            key_code: synced.key_code(),
            copied: 0,
            trashed_left: 0,
            damaged: 0,
        };
        match self.status() {
            Status::Locked => Err(locked()),
            Status::New => {
                if let Some(dir) = self.path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
                }
                let s::Joined {
                    store,
                    synced,
                    first_round,
                } = s::join(
                    &self.path,
                    password,
                    self.kdf,
                    sk,
                    sk_id,
                    pin.as_ref(),
                    transport,
                    keys.as_mut(),
                    &name,
                    unlock,
                    wall_ms(now),
                )
                .map_err(sync_error)?;
                let joined = outcome("new", &synced);
                self.store = Some(store);
                self.synced = Some(synced);
                self.note_round(first_round, now);
                self.password_verified_at = Some(now);
                self.keyring.delete();
                Ok(joined)
            }
            Status::Unlocked => {
                let store = self.store.as_mut().ok_or_else(locked)?;
                if s::is_enabled(store).map_err(sync_error)? {
                    return Err(CmdError::new(ErrorKind::Invalid, "Sync is already on"));
                }
                let result = s::rejoin(
                    store,
                    sk,
                    sk_id,
                    pin.as_ref(),
                    transport,
                    keys.as_mut(),
                    &name,
                    unlock,
                    wall_ms(now),
                );
                match result {
                    Ok(rejoined) => {
                        let joined = outcome("rejoined", &rejoined.synced);
                        self.synced = Some(rejoined.synced);
                        self.note_round(rejoined.first_round, now);
                        Ok(joined)
                    }
                    Err(keyorra_sync::Error::AnotherAccount) => {
                        self.join_carrying_over(link, password, (sk, sk_id), pin, now)
                    }
                    Err(e) => Err(sync_error(e)),
                }
            }
        }
    }

    fn join_carrying_over(
        &mut self,
        link: &dyn SyncLink,
        password: &str,
        (sk, sk_id): (&SecretKey, &str),
        pin: Option<keyorra_sync::account::RootPin>,
        now: u64,
    ) -> CmdResult<JoinOutcome> {
        let (transport, mut keys, name) = (
            join_transport(link, password, (sk, sk_id), pin.as_ref())?,
            link.device_keys(),
            link.device_name(),
        );
        let joining = joining_path(&self.path);
        remove_database(&joining);
        let s::Joined {
            store: mut new_store,
            synced,
            ..
        } = s::join(
            &joining,
            password,
            self.kdf,
            sk,
            sk_id,
            pin.as_ref(),
            transport,
            keys.as_mut(),
            &name,
            |h: &Header| link.unlock_header(h, password, sk),
            wall_ms(now),
        )
        .map_err(sync_error)?;
        let key_code = synced.key_code();
        let old = self.store.take().ok_or_else(locked)?;
        let carried = s::carry_over(&old, &mut new_store);
        drop(new_store);
        drop(synced);
        let report = match carried {
            Ok(r) => r,
            Err(e) => {
                self.store = Some(old);
                remove_database(&joining);
                return Err(sync_error(e));
            }
        };
        drop(old);
        let aside = pre_sync_path(&self.path, now);
        let moved =
            move_aside(&self.path, &aside, |from, to| std::fs::rename(from, to)).and_then(|()| {
                move_aside(&joining, &self.path, |from, to| std::fs::rename(from, to)).inspect_err(
                    |_| {
                        // Put the old vault back where it was.
                        let _ =
                            move_aside(&aside, &self.path, |from, to| std::fs::rename(from, to));
                    },
                )
            });
        if let Err(e) = moved {
            let mut store = Store::open(&self.path)?;
            store.unlock(password)?;
            self.store = Some(store);
            remove_database(&joining);
            return Err(CmdError::new(
                ErrorKind::Other,
                format!("Can't move the file: {e}"),
            ));
        }
        // The Touch ID record wraps the old vault's key.
        self.keyring.delete();
        let mut store = Store::open(&self.path)?;
        store.unlock(password)?;
        self.store = Some(store);
        self.password_verified_at = Some(now);
        if report.trashed_left + report.damaged > 0 {
            self.sync_notices = vec![format!(
                "{} in Recently Deleted and {} stayed in the old file",
                crate::text::plural(report.trashed_left, "item", "items"),
                crate::text::plural(report.damaged, "unreadable item", "unreadable items")
            )];
        }
        // The new vault is in place: sync that cannot start now starts on the next round.
        let store = self.store.as_ref().ok_or_else(locked)?;
        let resumed = s::account_id(store)
            .map_err(sync_error)
            .and_then(|account| open_transport(link, &account))
            .and_then(|t| s::resume(store, t, link.device_keys().as_ref()).map_err(sync_error));
        match resumed {
            Ok(synced) => self.synced = Some(synced),
            Err(e) => self.sync_error = Some(e.message),
        }
        Ok(JoinOutcome {
            mode: "carriedOver",
            key_code,
            copied: report.copied,
            trashed_left: report.trashed_left,
            damaged: report.damaged,
        })
    }

    /// Turns sync off on this Mac; everything stays in the vault.
    pub fn disable_sync(&mut self, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        let mut keys = self.link()?.device_keys();
        let synced = self.synced.take();
        let store = self.store.as_mut().ok_or_else(locked)?;
        s::disable(store, synced, keys.as_mut()).map_err(sync_error)?;
        self.sync_error = None;
        Ok(())
    }

    /// The main device approves a device after the user compared its key code.
    pub fn approve_device(&mut self, id: &str, code: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        let device: [u8; 16] = data_encoding::HEXLOWER
            .decode(id.as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Unknown device"))?;
        let code = normalize_key_code(code)?;
        let synced = self
            .synced
            .as_mut()
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Sync is off"))?;
        synced
            .approve(device, &code, wall_ms(now))
            .map_err(sync_error)
    }

    /// Makes this Mac the main device of a new account with new keys, carrying everything
    /// over (the main device was copied or lost its key; or the user wants a clean start).
    pub fn start_new_sync_account(
        &mut self,
        password: &str,
        now: u64,
    ) -> CmdResult<EmergencyKitDto> {
        self.touch(now);
        self.check_password_throttled(password, now)?;
        let link = self.link()?;
        let account = s::new_account_id();
        let (transport, mut keys, name) = (
            link.new_account_transport(&account).map_err(folder_error)?,
            link.device_keys(),
            link.device_name(),
        );
        let kdf = self.kdf;
        let store = self.store.as_mut().ok_or_else(locked)?;
        let before = store.account_key_copy()?;
        let started = s::start_new_account(
            store,
            account,
            transport,
            keys.as_mut(),
            &name,
            password,
            kdf,
            wall_ms(now),
        );
        let rotated = store.account_key_copy()?.as_bytes() != before.as_bytes();
        if rotated {
            // The old engine and the Touch ID record belong to the replaced key (review
            // A1d-2 I7), whatever happens next.
            self.synced = None;
            self.keyring.delete();
        }
        let s::Enabled {
            synced,
            kit,
            first_round,
            ..
        } = started.map_err(|e| {
            let e = sync_error(e);
            if rotated {
                self.sync_error = Some(e.message.clone());
            }
            e
        })?;
        let dto = EmergencyKitDto {
            account_id: kit.account_id,
            secret_key: kit.secret_key.to_string(),
            setup_code: synced.setup_code().to_text().to_string(),
            location: self.link()?.location(&account),
        };
        self.synced = Some(synced);
        self.note_round(first_round, now);
        Ok(dto)
    }

    /// A new vault while synced is created through sync (its id commits to its key).
    pub(super) fn create_vault_synced(
        &mut self,
        name: &str,
        now: u64,
    ) -> Option<CmdResult<uuid::Uuid>> {
        let synced = self.synced.as_mut()?;
        if !synced.engine().can_write() {
            return None;
        }
        let store = self.store.as_mut()?;
        Some(
            synced
                .create_vault(store, name, wall_ms(now))
                .map_err(sync_error),
        )
    }

    /// Before a master password change: whether sync must publish it. While sync is on, only
    /// the main device changes it, and only with sync running and ready (after a restart the
    /// account header is known after the first round, which runs here if needed). Decided
    /// from the store's configuration, not from whether sync runs (review A1d-2 C1, I5).
    pub(super) fn prepare_sync_password_change(&mut self, now: u64) -> CmdResult<bool> {
        let store = self.store()?;
        if !s::is_enabled(store).map_err(sync_error)? {
            return Ok(false);
        }
        if !s::is_main(store).map_err(sync_error)? {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "Change the master password on your main device",
            ));
        }
        if self.synced.is_none() {
            self.resume_sync();
        }
        let ready = |s: &Self| {
            s.synced
                .as_ref()
                .is_some_and(|x| x.ready_for_password_change())
        };
        if self.synced.is_some() && !ready(self) {
            let _ = self.sync_now(now);
        }
        if self.synced.is_none() {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "Sync must be running to change the password",
            ));
        }
        if !ready(self) {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "Sync is still starting; try again in a moment",
            ));
        }
        Ok(true)
    }

    /// After the local change: the main device publishes the new password for the account.
    /// A failure here does not undo the local change; it is shown and retried by changing
    /// the password again (A3).
    pub(super) fn publish_sync_password(&mut self, new: &str, now: u64) {
        let (Some(synced), Some(store)) = (self.synced.as_mut(), self.store.as_ref()) else {
            return;
        };
        let published = store
            .account_key_copy()
            .map_err(keyorra_sync::Error::from)
            .and_then(|account| synced.change_password(&account, new, self.kdf, wall_ms(now)));
        if let Err(e) = published {
            self.sync_error = Some(format!(
                "The new master password was not sent to sync: {}",
                sync_error(e).message
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_for_the_old_file_name() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert_eq!(civil_date(19_723), (2024, 1, 1));
        assert_eq!(civil_date(20_731), (2026, 10, 5));
        assert_eq!(civil_date(11_016), (2000, 2, 29));
    }
}
