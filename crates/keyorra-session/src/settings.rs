use std::ops::RangeInclusive;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CmdError, CmdResult, ErrorKind};

/// User preferences; not secret, stored as `settings.json` next to the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub auto_lock_minutes: u64,
    pub clipboard_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
            clipboard_seconds: 90,
        }
    }
}

const AUTO_LOCK_MINUTES: RangeInclusive<u64> = 1..=240;
const CLIPBOARD_SECONDS: RangeInclusive<u64> = 10..=600;

impl Settings {
    pub fn validate(&self) -> CmdResult<()> {
        if !AUTO_LOCK_MINUTES.contains(&self.auto_lock_minutes) {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "Auto-lock must be between 1 and 240 minutes",
            ));
        }
        if !CLIPBOARD_SECONDS.contains(&self.clipboard_seconds) {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                "Clipboard clearing must be between 10 and 600 seconds",
            ));
        }
        Ok(())
    }

    /// Missing, unreadable or invalid files give the defaults.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .filter(|s| s.validate().is_ok())
            .unwrap_or_default()
    }

    /// Writes atomically (temp file + rename).
    pub fn save(&self, path: &Path) -> CmdResult<()> {
        let io = |e: std::io::Error| {
            CmdError::new(ErrorKind::Other, format!("Can't save settings: {e}"))
        };
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).expect("settings serialize");
        std::fs::write(&tmp, json).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_validation() {
        assert_eq!(
            Settings::default(),
            Settings {
                auto_lock_minutes: 10,
                clipboard_seconds: 90
            }
        );
        assert!(Settings::default().validate().is_ok());
        for bad in [
            Settings {
                auto_lock_minutes: 0,
                ..Settings::default()
            },
            Settings {
                auto_lock_minutes: 241,
                ..Settings::default()
            },
            Settings {
                clipboard_seconds: 9,
                ..Settings::default()
            },
            Settings {
                clipboard_seconds: 601,
                ..Settings::default()
            },
        ] {
            assert_eq!(bad.validate().unwrap_err().kind, crate::ErrorKind::Invalid);
        }
    }

    #[test]
    fn load_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert_eq!(Settings::load(&path), Settings::default());
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        std::fs::write(&path, r#"{"autoLockMinutes":0}"#).unwrap();
        assert_eq!(
            Settings::load(&path),
            Settings::default(),
            "invalid values are ignored"
        );
    }

    #[test]
    fn save_then_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let s = Settings {
            auto_lock_minutes: 5,
            clipboard_seconds: 30,
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(json["autoLockMinutes"], 5);
    }
}
