//! The Sync screen's commands (plan A3): everything it shows in one call, and what it does
//! (alarm actions, removing a device, checking the local copy, the files in the folder, the
//! backup copies of the database).

use serde::Serialize;

use super::sync::{sync_error, LogLine};
use super::{locked, sibling, Session, DB_SIBLINGS};
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::sync::{self as s, AlarmView, SyncStatus, VerifyReport};

/// The Sync screen in one call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncScreenDto {
    pub enabled: bool,
    /// On and running this unlock.
    pub running: bool,
    pub error: Option<String>,
    /// Where the account lives (a folder path).
    pub location: Option<String>,
    pub last_round_at: Option<u64>,
    pub last_round_ok: Option<bool>,
    pub status: Option<SyncStatus>,
    pub alarms: Vec<AlarmView>,
    pub notices: Vec<String>,
    pub log: Vec<LogLine>,
}

/// A copy of the database kept next to it: before a migration (`.bak-v1`) or the vault a
/// join replaced (`.pre-sync-YYYYMMDD`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupFile {
    pub name: String,
    pub size: u64,
    /// Unix seconds.
    pub modified: u64,
    /// "migration" or "preSync".
    pub kind: &'static str,
}

/// One file of the account as the folder holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderFile {
    pub path: String,
    pub size: u64,
    pub counted: bool,
}

fn not_synced() -> CmdError {
    CmdError::new(ErrorKind::Invalid, "Sync is not running")
}

fn wall_ms(now: u64) -> u64 {
    now.saturating_mul(1000)
}

impl Session {
    pub fn sync_screen(&self) -> CmdResult<SyncScreenDto> {
        let store = self.store()?;
        let enabled = s::is_enabled(store).map_err(sync_error)?;
        let location = if enabled {
            s::account_id(store)
                .ok()
                .and_then(|a| self.sync_link.as_ref().and_then(|l| l.location(&a)))
        } else {
            None
        };
        Ok(SyncScreenDto {
            enabled,
            running: self.synced.is_some(),
            error: self.sync_error.clone(),
            location,
            last_round_at: self.last_round.map(|(at, _)| at),
            last_round_ok: self.last_round.map(|(_, ok)| ok),
            status: self.synced.as_ref().map(|x| x.status()),
            alarms: self
                .synced
                .as_ref()
                .map(|x| x.alarm_views())
                .unwrap_or_default(),
            notices: self.sync_notices.clone(),
            log: self.sync_log.iter().cloned().collect(),
        })
    }

    /// Accept, restore, remove or leave, as the alarm offers.
    pub fn sync_alarm_action(&mut self, id: &str, action: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        let synced = self.synced.as_mut().ok_or_else(not_synced)?;
        synced
            .alarm_action(id, action, wall_ms(now))
            .map_err(sync_error)
    }

    /// The main Mac removes a device.
    pub fn remove_sync_device(&mut self, id: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        let device: [u8; 16] = data_encoding::HEXLOWER
            .decode(id.as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Unknown device"))?;
        let synced = self.synced.as_mut().ok_or_else(not_synced)?;
        synced
            .remove_device(device, wall_ms(now))
            .map_err(sync_error)
    }

    /// "Verify everything": the local copy decrypts and matches what sync shows.
    pub fn verify_sync(&self) -> CmdResult<VerifyReport> {
        let store = self.store()?;
        let synced = self.synced.as_ref().ok_or_else(not_synced)?;
        synced.verify(store).map_err(sync_error)
    }

    /// "What the folder sees": names and sizes only.
    pub fn sync_folder_files(&self) -> CmdResult<Vec<FolderFile>> {
        self.store()?;
        let synced = self.synced.as_ref().ok_or_else(not_synced)?;
        Ok(synced
            .inventory()
            .map_err(sync_error)?
            .into_iter()
            .map(|e| FolderFile {
                path: e.path,
                size: e.size,
                counted: e.counted,
            })
            .collect())
    }

    /// The backup copies of the database next to it.
    pub fn backups(&self) -> CmdResult<Vec<BackupFile>> {
        self.store()?;
        let Some(dir) = self.path.parent() else {
            return Ok(Vec::new());
        };
        let Some(base) = self.path.file_name().and_then(|n| n.to_str()) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(out);
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(rest) = name.strip_prefix(base) else {
                continue;
            };
            if DB_SIBLINGS.iter().any(|s| rest.ends_with(s)) {
                continue;
            }
            let kind = if rest.starts_with(".bak-v") {
                "migration"
            } else if rest.starts_with(".pre-sync-") {
                "preSync"
            } else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            out.push(BackupFile {
                size: meta.len(),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs()),
                name,
                kind,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes one backup copy (with SQLite's companions); only a name `backups` lists.
    pub fn delete_backup(&mut self, name: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        if !self.backups()?.iter().any(|b| b.name == name) {
            return Err(CmdError::new(ErrorKind::NotFound, "No such backup"));
        }
        let dir = self.path.parent().ok_or_else(locked)?;
        let path = dir.join(name);
        std::fs::remove_file(&path)
            .map_err(|e| CmdError::new(ErrorKind::Other, format!("Can't delete it: {e}")))?;
        for suffix in DB_SIBLINGS {
            let _ = std::fs::remove_file(sibling(&path, suffix));
        }
        Ok(())
    }
}
