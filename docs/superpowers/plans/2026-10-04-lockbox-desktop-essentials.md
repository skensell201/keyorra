# Lockbox Desktop Essentials Implementation Plan (Plan 2b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop app usable day to day: edit any field (incl. adding a one-time-password secret), sensible field templates for cards/identities/API credentials, a Recently Deleted view with restore, settings (auto-lock and clipboard timeouts) and changing the master password, and locking when the Mac sleeps or the screen locks.

**Architecture:** Same layering as Plan 2a. New logic goes into `crates/lockbox-session` (tested, time injected): field templates and TOTP validation in `Session`, `Settings` persisted as `settings.json` next to the database, `SleepDetector`, `change_password` with the unlock throttle. The Tauri shell gains thin commands and reads the macOS screen-lock flag (CoreGraphics session dictionary) in the housekeeping thread. The React UI gains a generic field editor, a Recently Deleted view and a Settings dialog.

**Tech Stack:** as Plan 2a (Rust, Tauri 2, React 19, Vitest 5) + `core-foundation` 0.10 (macOS only, shell crate).

**Spec:** `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md` §5 (auto-lock on sleep/screen lock), §2 (Recently Deleted, 30 days). Plan 2c (next): Touch ID, Watchtower view, menu bar + ⌘⇧Space quick search, vault rename/delete, "not a lockbox database → start over".

**Conventions for every task:**
- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (omitted below — always add it).
- Rust from the repo root, frontend from `app/`. `cargo fmt --all`; `cargo clippy -p <crate> --all-targets -- -D warnings` clean; `pnpm typecheck && pnpm test` green.
- Rust tests compare errors by `kind`. Session tests live in `crates/lockbox-session/src/session/tests.rs` and reuse its helpers `new_session()`, `unlocked_session()`, `personal(&mut s)`, `save_login(&mut s, vault, title, user, pw)`, `PW`.
- **Vitest 5 pitfall:** a function returned from `beforeEach` runs as teardown, and `mockReset()`/`mockResolvedValue()` return the mock. Always give `beforeEach` a braced body: `beforeEach(() => { ...; });`.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw.

## File map

```
crates/lockbox-session/src/autolock.rs        + set_timeout
crates/lockbox-session/src/settings.rs        NEW Settings (load/save/validate)
crates/lockbox-session/src/sleep.rs           NEW SleepDetector
crates/lockbox-session/src/lib.rs             + modules, re-exports
crates/lockbox-session/src/session/mod.rs     templates, TOTP validation, trash, settings, change_password, tick_with
crates/lockbox-session/src/session/tests.rs   tests for the above
app/src-tauri/Cargo.toml                      + core-foundation (macOS)
app/src-tauri/src/screen.rs                   NEW is_locked() via CGSessionCopyCurrentDictionary
app/src-tauri/src/commands.rs                 + deleted_items, restore_item, settings, update_settings, change_password
app/src-tauri/src/lib.rs                      register commands, housekeeping uses tick_with
app/src/api.ts                                + Settings, new calls
app/src/styles.css                            + field editor styles
app/src/components/ItemEditor.tsx (+test)     generic field editor
app/src/components/ItemDetail.tsx (+test)     toast text no longer hardcodes 90 s
app/src/components/Sidebar.tsx (+test)        Recently Deleted entry, Settings button
app/src/components/TrashItem.tsx (+test)      NEW restore pane
app/src/components/SettingsDialog.tsx (+test) NEW settings + change password
app/src/components/Main.tsx (+test)           trash mode, settings dialog
```

---

### Task 1: Field templates and one-time-password validation

**Files:** Modify `crates/lockbox-session/src/session/mod.rs`, `session/tests.rs`.

- [ ] **Step 1: Write the failing tests** (append to `session/tests.rs`)

```rust
fn field_ids(item: &Item) -> Vec<&str> {
    item.fields.iter().map(|f| f.id.as_str()).collect()
}

#[test]
fn new_items_get_templates_per_kind() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let card = s.new_item(p, ItemKind::CreditCard, 1_000).unwrap();
    assert_eq!(field_ids(&card), ["cardholder", "number", "expiry", "cvv"]);
    assert!(matches!(card.fields[1].value, FieldValue::Concealed(_)));
    let id = s.new_item(p, ItemKind::Identity, 1_000).unwrap();
    assert_eq!(field_ids(&id), ["first-name", "last-name", "email", "phone"]);
    assert!(matches!(id.fields[2].value, FieldValue::Email(_)));
    let api = s.new_item(p, ItemKind::ApiCredential, 1_000).unwrap();
    assert_eq!(field_ids(&api), ["username", "credential", "hostname"]);
    assert!(api.fields.iter().all(|f| f.purpose.is_none()));
}

#[test]
fn saving_a_valid_totp_secret_enables_codes() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp(RFC_SECRET.into()),
        purpose: None,
    });
    let saved = s.save_item(item, 1_000).unwrap();
    assert_eq!(s.totp(saved.id, 59).unwrap().unwrap().code, "287082");
}

#[test]
fn saving_an_invalid_totp_secret_is_refused() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("not a secret!!".into()),
        purpose: None,
    });
    assert_eq!(s.save_item(item, 1_000).unwrap_err().kind, ErrorKind::Invalid);
}

#[test]
fn empty_totp_fields_are_dropped_on_save() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("   ".into()),
        purpose: None,
    });
    let saved = s.save_item(item, 1_000).unwrap();
    assert_eq!(saved.totp(), None);
    assert_eq!(saved.fields.len(), 2);
}
```

(`RFC_SECRET` already exists in the tests file.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p lockbox-session`. Expected: `new_items_get_templates_per_kind` and `saving_an_invalid_totp_secret_is_refused` and `empty_totp_fields_are_dropped_on_save` FAIL (the valid-secret test may already pass).

- [ ] **Step 3: Implement** in `session/mod.rs`:
  - Replace the `match kind { … }` block in `new_item` with `item.fields = template_fields(kind);`.
  - At the start of `save_item`, right after trimming the title and before the title check, add:

```rust
        // An empty one-time-password field would make every code request fail.
        item.fields.retain(|f| !matches!(&f.value, FieldValue::Totp(s) if s.trim().is_empty()));
        for field in item.fields.iter().chain(item.sections.iter().flat_map(|s| s.fields.iter())) {
            if let FieldValue::Totp(raw) = &field.value {
                Totp::parse(raw).map_err(|e| {
                    CmdError::new(ErrorKind::Invalid, format!("One-time password \"{}\": {e}", field.label))
                })?;
            }
        }
```

  - Add free functions (next to `purpose_field`):

```rust
fn field(id: &str, label: &str, value: FieldValue) -> Field {
    Field { id: id.into(), label: label.into(), value, purpose: None }
}

/// Built-in fields a new item of this kind starts with.
fn template_fields(kind: ItemKind) -> Vec<Field> {
    let text = |id: &str, label: &str| field(id, label, FieldValue::Text(String::new()));
    let hidden = |id: &str, label: &str| field(id, label, FieldValue::Concealed(String::new()));
    match kind {
        ItemKind::Login => vec![purpose_field(Purpose::Username), purpose_field(Purpose::Password)],
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
```

- [ ] **Step 4: Run** — `cargo test -p lockbox-session` all pass; clippy clean.
- [ ] **Step 5: Commit** — `git commit -m "Add field templates per kind and validate one-time-password secrets"`

---

### Task 2: Recently Deleted (list, restore, purge on unlock)

**Files:** Modify `session/mod.rs`, `session/tests.rs`.

- [ ] **Step 1: Write the failing tests**

```rust
use lockbox_core::store::DELETED_RETENTION_SECS;

#[test]
fn deleted_items_can_be_listed_and_restored() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    s.delete_item(item.id, 1_000).unwrap();
    let trash: Vec<_> = s.deleted_items(1_000).unwrap().into_iter().map(|i| i.title).collect();
    assert_eq!(trash, ["GitHub"]);
    s.restore_item(item.id, 1_000).unwrap();
    assert!(s.deleted_items(1_000).unwrap().is_empty());
    assert_eq!(s.item(item.id, 1_000).unwrap().title, "GitHub");
}

#[test]
fn unlocking_purges_items_deleted_more_than_30_days_ago() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let old = save_login(&mut s, p, "Old", "a", "pw");
    let recent = save_login(&mut s, p, "Recent", "b", "pw");
    s.delete_item(old.id, 1_000).unwrap();
    s.delete_item(recent.id, 1_000 + DELETED_RETENTION_SECS as u64).unwrap();
    s.lock();
    s.unlock(PW, 1_000 + DELETED_RETENTION_SECS as u64 + 1).unwrap();
    let trash: Vec<_> = s.deleted_items(2_000).unwrap().into_iter().map(|i| i.title).collect();
    assert_eq!(trash, ["Recent"]);
}

#[test]
fn trash_requires_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.deleted_items(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(s.restore_item(Uuid::new_v4(), 1_000).unwrap_err().kind, ErrorKind::Locked);
}
```

- [ ] **Step 2: Run to verify failure** (compile errors: `deleted_items`, `restore_item`).
- [ ] **Step 3: Implement** inside `impl Session`:

```rust
    /// Items in Recently Deleted, sorted by title.
    pub fn deleted_items(&mut self, now: u64) -> CmdResult<Vec<ItemSummary>> {
        self.touch(now);
        let mut out: Vec<ItemSummary> =
            self.store()?.deleted_items()?.iter().map(ItemSummary::from_entry).collect();
        out.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn restore_item(&mut self, id: Uuid, now: u64) -> CmdResult<()> {
        self.touch(now);
        Ok(self.store_mut()?.restore_item(id)?)
    }
```

  and in `unlock`, in the `Ok(())` arm before `self.store = Some(store);`:

```rust
                // Housekeeping, not part of unlocking: a failure here must not lock the user out.
                let _ = store.purge_expired(now as i64);
```

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add Recently Deleted listing, restore and purge on unlock"`

---

### Task 3: Settings (auto-lock and clipboard timeouts)

**Files:** Create `crates/lockbox-session/src/settings.rs`; modify `autolock.rs`, `lib.rs`, `session/mod.rs`, `session/tests.rs`.

- [ ] **Step 1: Failing tests**

`autolock.rs` tests module, add:
```rust
    #[test]
    fn timeout_can_change() {
        let mut lock = AutoLock::new(60, 1_000);
        lock.set_timeout(300);
        assert!(!lock.is_due(1_299));
        assert!(lock.is_due(1_300));
    }
```

`settings.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_validation() {
        assert_eq!(Settings::default(), Settings { auto_lock_minutes: 10, clipboard_seconds: 90 });
        assert!(Settings::default().validate().is_ok());
        for bad in [
            Settings { auto_lock_minutes: 0, ..Settings::default() },
            Settings { auto_lock_minutes: 241, ..Settings::default() },
            Settings { clipboard_seconds: 9, ..Settings::default() },
            Settings { clipboard_seconds: 601, ..Settings::default() },
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
        assert_eq!(Settings::load(&path), Settings::default(), "invalid values are ignored");
    }

    #[test]
    fn save_then_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let s = Settings { auto_lock_minutes: 5, clipboard_seconds: 30 };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(json["autoLockMinutes"], 5);
    }
}
```

`session/tests.rs`:
```rust
use crate::settings::Settings;

#[test]
fn settings_persist_and_apply() {
    let (dir, mut s) = unlocked_session();
    assert_eq!(s.settings(), Settings::default());
    let new = Settings { auto_lock_minutes: 1, clipboard_seconds: 30 };
    assert_eq!(s.update_settings(new, 1_000).unwrap(), new);
    assert!(!s.tick(1_059));
    assert!(s.tick(1_060), "1-minute auto-lock applies immediately");

    let path = dir.path().join("Application Support").join("lockbox.db");
    let reopened = Session::new(path, KdfParams::INSECURE_FAST, 5_000);
    assert_eq!(reopened.settings(), new);
}

#[test]
fn clipboard_timeout_follows_settings() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "hunter2");
    s.update_settings(Settings { auto_lock_minutes: 10, clipboard_seconds: 30 }, 1_000).unwrap();
    s.copy_value(item.id, "password", 1_000).unwrap();
    assert!(!s.clipboard_should_clear(1_029, Some("hunter2")));
    assert!(s.clipboard_should_clear(1_030, Some("hunter2")));
}

#[test]
fn invalid_settings_and_locked_sessions_are_refused() {
    let (_dir, mut s) = unlocked_session();
    let bad = Settings { auto_lock_minutes: 0, clipboard_seconds: 90 };
    assert_eq!(s.update_settings(bad, 1_000).unwrap_err().kind, ErrorKind::Invalid);
    s.lock();
    assert_eq!(s.update_settings(Settings::default(), 1_000).unwrap_err().kind, ErrorKind::Locked);
}
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement**

`autolock.rs` (inside `impl AutoLock`):
```rust
    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout_secs = timeout_secs;
    }
```

`settings.rs` (prepend):
```rust
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
        Self { auto_lock_minutes: 10, clipboard_seconds: 90 }
    }
}

const AUTO_LOCK_MINUTES: RangeInclusive<u64> = 1..=240;
const CLIPBOARD_SECONDS: RangeInclusive<u64> = 10..=600;

impl Settings {
    pub fn validate(&self) -> CmdResult<()> {
        if !AUTO_LOCK_MINUTES.contains(&self.auto_lock_minutes) {
            return Err(CmdError::new(ErrorKind::Invalid, "Auto-lock must be between 1 and 240 minutes"));
        }
        if !CLIPBOARD_SECONDS.contains(&self.clipboard_seconds) {
            return Err(CmdError::new(ErrorKind::Invalid, "Clipboard clearing must be between 10 and 600 seconds"));
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
        let io = |e: std::io::Error| CmdError::new(ErrorKind::Other, format!("Can't save settings: {e}"));
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).expect("settings serialize");
        std::fs::write(&tmp, json).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)
    }
}
```

`lib.rs`: add `pub mod settings;` and `pub use settings::Settings;`.

`session/mod.rs`:
  - add `use crate::settings::Settings;`
  - add fields `settings: Settings, settings_path: PathBuf` to `Session`.
  - in `new`: `let settings_path = path.with_file_name("settings.json"); let settings = Settings::load(&settings_path);` and `autolock: AutoLock::new(settings.auto_lock_minutes * 60, now),` (replacing `DEFAULT_TIMEOUT_SECS`), plus the two new fields.
  - in `copy_value`, replace `ClipboardGuard::DEFAULT_CLEAR_SECS` with `self.settings.clipboard_seconds`.
  - add methods:

```rust
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
```

  Existing tests that use `AutoLock::DEFAULT_TIMEOUT_SECS` stay valid (default 10 min = 600 s). If `ClipboardGuard::DEFAULT_CLEAR_SECS` becomes unused outside tests, keep it (tests use it) or mark it `#[cfg(test)]`-only only if clippy complains.

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add persisted settings for auto-lock and clipboard timeouts"`

---

### Task 4: Change the master password

**Files:** Modify `session/mod.rs`, `session/tests.rs`.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn change_password_then_unlock_with_the_new_one() {
    let (_dir, mut s) = unlocked_session();
    s.change_password(PW, "a brand new password", 1_000).unwrap();
    s.lock();
    assert_eq!(s.unlock(PW, 1_001).unwrap_err().kind, ErrorKind::WrongPassword);
    s.unlock("a brand new password", 1_002).unwrap();
}

#[test]
fn change_password_checks_input_and_counts_wrong_guesses() {
    let (_dir, mut s) = unlocked_session();
    assert_eq!(s.change_password(PW, "short", 1_000).unwrap_err().kind, ErrorKind::Invalid);
    assert_eq!(s.change_password(PW, PW, 1_000).unwrap_err().kind, ErrorKind::Invalid);
    assert_eq!(
        s.change_password("not the password", "a brand new password", 1_000).unwrap_err().kind,
        ErrorKind::WrongPassword
    );
    assert_eq!(s.throttle.failures(), 1);
    s.lock();
    assert_eq!(s.change_password(PW, "a brand new password", 1_000).unwrap_err().kind, ErrorKind::Locked);
}
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement**

```rust
    /// Re-wraps the account key under a new master password. Wrong guesses count towards the
    /// unlock throttle, so this form can't be used to brute-force the password.
    pub fn change_password(&mut self, current: &str, new: &str, now: u64) -> CmdResult<()> {
        self.touch(now);
        self.store()?;
        self.throttle.check(now).map_err(CmdError::throttled)?;
        if new.chars().count() < MIN_PASSWORD_LEN {
            return Err(CmdError::new(ErrorKind::Invalid, format!("Use at least {MIN_PASSWORD_LEN} characters")));
        }
        if new == current {
            return Err(CmdError::new(ErrorKind::Invalid, "The new password must be different"));
        }
        let result = self.store_mut()?.change_password(current, new);
        match result {
            Ok(()) => {
                self.throttle.record_success();
                Ok(())
            }
            Err(lockbox_core::Error::WrongPassword) => {
                self.throttle.record_failure(now);
                Err(lockbox_core::Error::WrongPassword.into())
            }
            Err(e) => Err(e.into()),
        }
    }
```

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add master password change with throttled verification"`

---

### Task 5: Lock when the Mac sleeps or the screen locks

**Files:** Create `crates/lockbox-session/src/sleep.rs`; modify `lib.rs`, `session/mod.rs`, `session/tests.rs`.

- [ ] **Step 1: Failing tests**

`sleep.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_a_jump_in_wall_clock_time() {
        let mut d = SleepDetector::default();
        assert!(!d.observe(1_000), "first observation");
        assert!(!d.observe(1_002));
        assert!(!d.observe(1_002 + SleepDetector::GAP_SECS));
        assert!(d.observe(1_003 + 2 * SleepDetector::GAP_SECS));
        assert!(!d.observe(500), "clock going backwards is not sleep");
    }
}
```

`session/tests.rs`:
```rust
#[test]
fn tick_with_locks_on_screen_lock_and_after_sleep() {
    let (_dir, mut s) = unlocked_session();
    assert!(!s.tick_with(1_002, false));
    assert!(s.tick_with(1_004, true), "screen locked");
    s.unlock(PW, 1_006).unwrap();
    assert!(!s.tick_with(1_008, false));
    assert!(s.tick_with(1_008 + 300, false), "the Mac slept");
    assert!(!s.tick_with(1_400, true), "already locked");
}
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement**

`sleep.rs` (prepend):
```rust
/// Notices that the Mac slept: housekeeping ticks every couple of seconds, so a big jump in
/// wall-clock time between two ticks means the process was suspended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SleepDetector {
    last: Option<u64>,
}

impl SleepDetector {
    pub const GAP_SECS: u64 = 60;

    /// Records a tick; `true` if more than `GAP_SECS` passed since the previous one.
    pub fn observe(&mut self, now: u64) -> bool {
        let slept = self.last.is_some_and(|last| now > last && now - last > Self::GAP_SECS);
        self.last = Some(now);
        slept
    }
}
```

`lib.rs`: `pub mod sleep;`

`session/mod.rs`: field `sleep: SleepDetector` (init `SleepDetector::default()`), import `use crate::sleep::SleepDetector;`, and:

```rust
    /// Housekeeping tick from the app: also locks when the screen is locked or the Mac slept.
    pub fn tick_with(&mut self, now: u64, screen_locked: bool) -> bool {
        let slept = self.sleep.observe(now);
        if self.store.is_some() && (screen_locked || slept || self.autolock.is_due(now)) {
            self.lock();
            true
        } else {
            false
        }
    }
```

(`tick(now)` stays as is for idle-only checks.)

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Lock when the Mac sleeps or the screen locks"`

---

### Task 6: Shell — new commands and screen-lock detection

**Files:** Create `app/src-tauri/src/screen.rs`; modify `app/src-tauri/Cargo.toml`, `src/commands.rs`, `src/lib.rs`.

- [ ] **Step 1: Dependency** — append to `app/src-tauri/Cargo.toml`:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
core-foundation = "0.10"
```

- [ ] **Step 2: Screen lock** — `app/src-tauri/src/screen.rs`:

```rust
//! Whether the macOS login session's screen is locked (CoreGraphics session dictionary).

#[cfg(target_os = "macos")]
pub fn is_locked() -> bool {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    // SAFETY: the function follows the Create rule (we own the returned dictionary) and may
    // return NULL when there is no GUI session.
    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return false;
    }
    let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    dict.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|value| value.downcast::<CFBoolean>())
        .map(bool::from)
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub fn is_locked() -> bool {
    false
}
```

(If the `core-foundation` 0.10 API differs — e.g. `find` signature or `downcast` — check the crate source in `~/.cargo/registry` and adapt; behaviour must stay "true only when the key is present and true".)

- [ ] **Step 3: Commands** — add to `commands.rs` (imports: `lockbox_session::Settings`):

```rust
#[tauri::command(async)]
pub fn deleted_items(state: State<'_, AppState>) -> CmdResult<Vec<ItemSummary>> {
    lock_session(&state).deleted_items(now())
}

#[tauri::command(async)]
pub fn restore_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).restore_item(id, now())
}

#[tauri::command(async)]
pub fn settings(state: State<'_, AppState>) -> CmdResult<Settings> {
    Ok(lock_session(&state).settings())
}

#[tauri::command(async)]
pub fn update_settings(state: State<'_, AppState>, settings: Settings) -> CmdResult<Settings> {
    lock_session(&state).update_settings(settings, now())
}

#[tauri::command(async)]
pub fn change_password(state: State<'_, AppState>, current: String, new_password: String) -> CmdResult<()> {
    lock_session(&state).change_password(&current, &new_password, now())
}
```

- [ ] **Step 4: Wiring** — in `lib.rs`: `mod screen;`; register the five commands in `generate_handler!`; in `housekeeping`, read the flag before taking the session lock and use `tick_with`:

```rust
        let t = now();
        let screen_locked = screen::is_locked();
        // The lock spans the clipboard calls on purpose: …(keep the existing comment)
        let mut session = lock_session(&state);
        let locked = session.tick_with(t, screen_locked);
```

- [ ] **Step 5: Build** — `cd app && pnpm build && cd .. && cargo build -p lockbox-app && cargo clippy -p lockbox-app -- -D warnings`.
- [ ] **Step 6: Commit** — `"Add trash, settings and password commands; lock on screen lock"`

---

### Task 7: Frontend API and the generic field editor

**Files:** Modify `app/src/api.ts`, `app/src/styles.css`, `app/src/components/ItemEditor.tsx`, `ItemEditor.test.tsx`, `ItemDetail.tsx`, `ItemDetail.test.tsx` (only if a test checks "90 seconds").

- [ ] **Step 1: API** — in `api.ts` add the type and calls (remove the `CLIPBOARD_CLEAR_SECS` export and its use in ItemDetail; the timeout is now a setting):

```ts
export interface Settings {
  autoLockMinutes: number;
  clipboardSeconds: number;
}
```
and in `api`:
```ts
  deletedItems: () => invoke<ItemSummary[]>("deleted_items"),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  settings: () => invoke<Settings>("settings"),
  updateSettings: (settings: Settings) => invoke<Settings>("update_settings", { settings }),
  changePassword: (current: string, newPassword: string) =>
    invoke<void>("change_password", { current, newPassword }),
```

In `ItemDetail.tsx` change the toast text to `Copied. The clipboard is cleared automatically.` and adjust any test that matched the old text.

- [ ] **Step 2: Failing editor tests** — append to `ItemEditor.test.tsx` (the file already mocks `api.saveItem` to echo the item and defines `saved()`; reuse them):

```tsx
test("adds a one-time password secret", async () => {
  const user = userEvent.setup();
  render(<ItemEditor item={loginItem({ sections: [] })} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Add one-time password" }));
  await user.type(screen.getByLabelText("Value of one-time password"), "JBSWY3DPEHPK3PXP");
  await user.click(screen.getByRole("button", { name: "Save" }));
  const otp = saved().fields.find((f) => f.value.type === "totp");
  expect(otp).toMatchObject({ label: "one-time password", value: { type: "totp", value: "JBSWY3DPEHPK3PXP" } });
  expect(otp!.id).toMatch(/^otp-/);
});

test("edits, retypes, relabels and removes template fields", async () => {
  const user = userEvent.setup();
  const card = loginItem({
    kind: "credit_card",
    sections: [],
    fields: [
      { id: "cardholder", label: "cardholder name", value: { type: "text", value: "" } },
      { id: "number", label: "number", value: { type: "concealed", value: "" } },
      { id: "cvv", label: "verification number", value: { type: "concealed", value: "" } },
    ],
  });
  render(<ItemEditor item={card} isNew onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.type(screen.getByLabelText("Value of number"), "4111111111111111");
  await user.selectOptions(screen.getByLabelText("Type of cardholder name"), "concealed");
  await user.clear(screen.getByLabelText("Label of cardholder name"));
  await user.type(screen.getByLabelText("Label of field 1"), "owner");
  await user.click(screen.getByRole("button", { name: "Remove verification number" }));
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(saved().fields).toEqual([
    { id: "cardholder", label: "owner", value: { type: "concealed", value: "" } },
    { id: "number", label: "number", value: { type: "concealed", value: "4111111111111111" } },
  ]);
});

test("adds a plain field", async () => {
  const user = userEvent.setup();
  render(<ItemEditor item={loginItem({ sections: [] })} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Add field" }));
  await user.type(screen.getByLabelText("Value of field 1"), "PIN 1234");
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(saved().fields[2]).toMatchObject({ label: "", value: { type: "text", value: "PIN 1234" } });
});
```

(After clearing its label the first row is named "field 1", so its label input becomes "Label of field 1".)

- [ ] **Step 3: Run to verify failure.**
- [ ] **Step 4: Implement** — in `ItemEditor.tsx`:
  - imports: add `type Field` from `../api` and `fieldText` from `../format`.
  - module constants and helper:

```tsx
type EditableType = "text" | "concealed" | "totp" | "url" | "email" | "phone";
const EDITABLE_TYPES: EditableType[] = ["text", "concealed", "totp", "url", "email", "phone"];
const TYPE_LABEL: Record<EditableType, string> = {
  text: "Text",
  concealed: "Hidden",
  totp: "One-time password",
  url: "URL",
  email: "Email",
  phone: "Phone",
};

function newFieldId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}
```

  - inside the component (after `setField`):

```tsx
  const custom = draft.fields.map((field, index) => ({ field, index })).filter(({ field }) => !field.purpose);
  const updateField = (index: number, patch: Partial<Field>) =>
    setDraft((d) => ({ ...d, fields: d.fields.map((f, i) => (i === index ? { ...f, ...patch } : f)) }));
  const removeField = (index: number) => setDraft((d) => ({ ...d, fields: d.fields.filter((_, i) => i !== index) }));
  const addField = (type: "text" | "totp") =>
    setDraft((d) => ({
      ...d,
      fields: [
        ...d.fields,
        {
          id: newFieldId(type === "totp" ? "otp" : "field"),
          label: type === "totp" ? "one-time password" : "",
          value: { type, value: "" },
        },
      ],
    }));
```

  - JSX, right after the Websites block:

```tsx
      {custom.length > 0 && (
        <fieldset className="fields">
          <legend>Fields</legend>
          {custom.map(({ field, index }, n) => {
            const name = field.label || `field ${n + 1}`;
            const editable = field.value.type !== "date" && field.value.type !== "month_year";
            return (
              <div className="field-edit" key={field.id}>
                <input
                  aria-label={`Label of ${name}`}
                  placeholder="Label"
                  value={field.label}
                  onChange={(e) => updateField(index, { label: e.target.value })}
                />
                {editable ? (
                  <input
                    aria-label={`Value of ${name}`}
                    className={field.value.type === "text" ? undefined : "mono"}
                    type={field.value.type === "concealed" ? "password" : "text"}
                    placeholder={field.value.type === "totp" ? "otpauth://… or secret key" : ""}
                    value={text(index)}
                    onChange={(e) => setField(index, e.target.value)}
                  />
                ) : (
                  <span className="muted">{fieldText(field.value)}</span>
                )}
                {editable ? (
                  <select
                    aria-label={`Type of ${name}`}
                    value={field.value.type}
                    onChange={(e) =>
                      updateField(index, {
                        value: { type: e.target.value as EditableType, value: text(index) },
                      })
                    }
                  >
                    {EDITABLE_TYPES.map((t) => (
                      <option key={t} value={t}>
                        {TYPE_LABEL[t]}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span />
                )}
                <button type="button" aria-label={`Remove ${name}`} onClick={() => removeField(index)}>
                  Remove
                </button>
              </div>
            );
          })}
        </fieldset>
      )}
      <div className="actions">
        <button type="button" onClick={() => addField("text")}>
          Add field
        </button>
        <button type="button" onClick={() => addField("totp")}>
          Add one-time password
        </button>
      </div>
```

  - `styles.css` append:

```css
fieldset.fields { border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; margin: 0; display: flex; flex-direction: column; gap: 8px; }
fieldset.fields legend { color: var(--muted); font-size: 12px; padding: 0 6px; }
.field-edit { display: grid; grid-template-columns: 170px 1fr 150px auto; gap: 8px; align-items: center; }
select { width: auto; }
```

- [ ] **Step 5: Run** `pnpm test && pnpm typecheck`. **Step 6: Commit** — `"Add a generic field editor with one-time password support"`

---

### Task 8: Recently Deleted view

**Files:** Modify `Sidebar.tsx` (+test), `Main.tsx` (+test); create `TrashItem.tsx` (+test).

- [ ] **Step 1: Failing tests**

`Sidebar.test.tsx` — the `setup()` helper's props gain `onSettings: vi.fn()`; add:
```tsx
test("recently deleted and settings", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(screen.getByRole("button", { name: "Recently Deleted" }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "trash" });
  await user.click(screen.getByRole("button", { name: "Settings…" }));
  expect(props.onSettings).toHaveBeenCalled();
});
```

`TrashItem.test.tsx`:
```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary } from "../api";
import { TrashItem } from "./TrashItem";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, restoreItem: vi.fn() } };
});

const deleted: ItemSummary = {
  id: "d1", vaultId: "v1", kind: "login", title: "Old forum", subtitle: "ivan",
  favorite: false, hasTotp: false, updatedAt: 0, damaged: false,
};

beforeEach(() => {
  vi.mocked(api.restoreItem).mockReset().mockResolvedValue(undefined);
});

test("restores the item", async () => {
  const user = userEvent.setup();
  const onRestored = vi.fn();
  render(<TrashItem item={deleted} onRestored={onRestored} />);
  expect(screen.getByRole("heading", { name: "Old forum" })).toBeInTheDocument();
  expect(screen.getByText(/removed for good 30 days/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(api.restoreItem).toHaveBeenCalledWith("d1");
  await waitFor(() => expect(onRestored).toHaveBeenCalled());
});

test("shows a restore error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.restoreItem).mockRejectedValue({ kind: "notFound", message: "not found: deleted item d1" });
  render(<TrashItem item={deleted} onRestored={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("not found");
});
```

`Main.test.tsx` — add `deletedItems: vi.fn()` and `restoreItem: vi.fn()` to the mocked api, reset them in `beforeEach` (`deletedItems` resolves `[{ ...github, id: "d1", title: "Old forum" }]`, `restoreItem` resolves `undefined`), then:
```tsx
test("recently deleted lists deleted items and restores one", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Recently Deleted" }));
  await user.click(await screen.findByText("Old forum"));
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(api.restoreItem).toHaveBeenCalledWith("d1");
  await waitFor(() => expect(api.deletedItems).toHaveBeenCalledTimes(2));
  expect(screen.getByRole("button", { name: "+ New" })).toBeDisabled();
});
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement**

`Sidebar.tsx`: `Selection` gains `| { kind: "trash" }`; props gain `onSettings: () => void`; after the Favorites button add
```tsx
      <button className="nav" aria-current={isCurrent({ kind: "trash" })} onClick={() => onSelect({ kind: "trash" })}>
        Recently Deleted
      </button>
```
and before the Lock button add
```tsx
      <button className="nav" onClick={onSettings}>
        Settings…
      </button>
```

`TrashItem.tsx`:
```tsx
import { useState } from "react";
import { api, errorMessage, type ItemSummary } from "../api";
import { KIND_LABEL } from "../format";

export function TrashItem({ item, onRestored }: { item: ItemSummary; onRestored: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function restore() {
    setBusy(true);
    setError(null);
    try {
      await api.restoreItem(item.id);
      onRestored();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="item-detail">
      <header>
        <div>
          <span className="kind">{item.kind ? KIND_LABEL[item.kind] : "Item"}</span>
          <h2>{item.title}</h2>
        </div>
        <div className="actions">
          <button className="primary" onClick={restore} disabled={busy}>
            Restore
          </button>
        </div>
      </header>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      <p className="muted">
        This item is in Recently Deleted. Items here are removed for good 30 days after they were deleted.
      </p>
    </article>
  );
}
```

`Main.tsx`:
  - `loadItems`: when `selection.kind === "trash"` call `api.deletedItems()` and filter client-side: `list.filter((i) => !query.trim() || i.title.toLowerCase().includes(query.trim().toLowerCase()))`; otherwise as now (the `favorites` flag stays `selection.kind === "favorites"`; `vaultId` null for trash is irrelevant).
  - `targetVault`: `selection.kind === "vault" ? selection.id : selection.kind === "trash" ? undefined : vaults[0]?.id`.
  - In the view pane: when `selection.kind === "trash"`, render `<TrashItem key={pane.id} item={items.find((i) => i.id === pane.id)!} onRestored={async () => { setPane({ mode: "empty" }); await refresh(); }} />` instead of `ItemDetail` (guard: if the summary is not found, show the empty pane).
  - Pass `onSettings={() => setShowSettings(true)}` to `Sidebar` (state `showSettings`; the dialog itself comes in Task 9 — for now render nothing for it).

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Add Recently Deleted view with restore"`

---

### Task 9: Settings dialog with password change

**Files:** Create `SettingsDialog.tsx` (+test); modify `Main.tsx` (+test).

- [ ] **Step 1: Failing tests** — `SettingsDialog.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, settings: vi.fn(), updateSettings: vi.fn(), changePassword: vi.fn() },
  };
});

beforeEach(() => {
  vi.mocked(api.settings).mockReset().mockResolvedValue({ autoLockMinutes: 10, clipboardSeconds: 90 });
  vi.mocked(api.updateSettings).mockReset().mockImplementation(async (s) => s);
  vi.mocked(api.changePassword).mockReset().mockResolvedValue(undefined);
});

test("loads and saves timeouts", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByLabelText("Lock after")).toHaveValue("10");
  await user.selectOptions(screen.getByLabelText("Lock after"), "30");
  await user.selectOptions(screen.getByLabelText("Clear copied secrets after"), "30");
  await user.click(screen.getByRole("button", { name: "Save settings" }));
  expect(api.updateSettings).toHaveBeenCalledWith({ autoLockMinutes: 30, clipboardSeconds: 30 });
  expect(await screen.findByRole("status")).toHaveTextContent("Saved");
});

test("changes the master password", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  const submit = screen.getByRole("button", { name: "Change password" });
  await user.type(screen.getByLabelText("Current password"), "old password 1");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new passwor");
  expect(submit).toBeDisabled();
  await user.type(screen.getByLabelText("Confirm new password"), "d");
  await user.click(submit);
  expect(api.changePassword).toHaveBeenCalledWith("old password 1", "a brand new password");
  expect(await screen.findByText("Password changed")).toBeInTheDocument();
  expect(screen.getByLabelText("Current password")).toHaveValue("");
});

test("wrong current password", async () => {
  const user = userEvent.setup();
  vi.mocked(api.changePassword).mockRejectedValue({ kind: "wrongPassword", message: "incorrect password" });
  render(<SettingsDialog onClose={vi.fn()} />);
  await user.type(screen.getByLabelText("Current password"), "nope nope nope");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new password");
  await user.click(screen.getByRole("button", { name: "Change password" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Current password is incorrect");
});

test("closes", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  render(<SettingsDialog onClose={onClose} />);
  await user.click(screen.getByRole("button", { name: "Close" }));
  expect(onClose).toHaveBeenCalled();
});
```

`Main.test.tsx` — add `settings: vi.fn()` to the mocked api (resolve `{ autoLockMinutes: 10, clipboardSeconds: 90 }` in `beforeEach`) and:
```tsx
test("settings open from the sidebar", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Settings…" }));
  expect(await screen.findByRole("dialog", { name: "Settings" })).toBeInTheDocument();
});
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** — `SettingsDialog.tsx`:

```tsx
import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError, type Settings } from "../api";

const LOCK_MINUTES = [1, 5, 10, 30, 60, 240];
const CLIPBOARD_SECONDS = [30, 60, 90, 180];
const MIN_LENGTH = 10;

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changed, setChanged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.settings().then(setSettings).catch((e) => setError(errorMessage(e)));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function save() {
    if (!settings) return;
    setError(null);
    try {
      setSettings(await api.updateSettings(settings));
      setSaved(true);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  const canChange = current.length > 0 && next.length >= MIN_LENGTH && next === confirm && !busy;

  async function change(e: FormEvent) {
    e.preventDefault();
    if (!canChange) return;
    setBusy(true);
    setError(null);
    setChanged(false);
    try {
      await api.changePassword(current, next);
      setChanged(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(isCmdError(err) && err.kind === "wrongPassword" ? "Current password is incorrect" : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <h2 id="settings-title">Settings</h2>
        {settings && (
          <>
            <label>
              Lock after
              <select
                value={String(settings.autoLockMinutes)}
                onChange={(e) => {
                  setSaved(false);
                  setSettings({ ...settings, autoLockMinutes: Number(e.target.value) });
                }}
              >
                {LOCK_MINUTES.map((m) => (
                  <option key={m} value={m}>
                    {m} min of inactivity
                  </option>
                ))}
              </select>
            </label>
            <label>
              Clear copied secrets after
              <select
                value={String(settings.clipboardSeconds)}
                onChange={(e) => {
                  setSaved(false);
                  setSettings({ ...settings, clipboardSeconds: Number(e.target.value) });
                }}
              >
                {CLIPBOARD_SECONDS.map((s) => (
                  <option key={s} value={s}>
                    {s} seconds
                  </option>
                ))}
              </select>
            </label>
            <div className="actions">
              <button className="primary" onClick={save}>
                Save settings
              </button>
              {saved && <span role="status">Saved</span>}
            </div>
          </>
        )}
        <form className="editor" onSubmit={change}>
          <h3>Change master password</h3>
          <label>
            Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </label>
          <label>
            New password
            <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
          </label>
          <label>
            Confirm new password
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
          {next.length > 0 && next.length < MIN_LENGTH && <p className="error">Use at least {MIN_LENGTH} characters</p>}
          <div className="actions">
            <button type="submit" disabled={!canChange}>
              Change password
            </button>
            {changed && <span>Password changed</span>}
          </div>
        </form>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button onClick={onClose}>Close</button>
      </div>
    </div>
  );
}
```

`Main.tsx`: import `SettingsDialog`; render `{showSettings && <SettingsDialog onClose={() => setShowSettings(false)} />}` next to the import dialog.

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck && pnpm build`. **Step 5: Commit** — `"Add settings dialog with password change"`

---

### Task 10: Full checks, manual run, docs (controller)

- [ ] **Step 1:** `cargo fmt --all --check && cargo clippy -p lockbox-core -p lockbox-session -p lockbox-app --all-targets -- -D warnings && cargo test && (cd app && pnpm typecheck && pnpm test)`.
- [ ] **Step 2 (controller, by hand):** with `~/Library/Application Support/app.lockbox.mac` moved aside, run `pnpm tauri dev` and check: new credit card shows template fields; add a one-time password to a login and see a live code; invalid secret shows an error; delete → Recently Deleted → Restore; Settings: set 1-minute lock and see it lock; change password, lock, unlock with the new one; lock the screen (⌃⌘Q) and see the app locked after unlocking the Mac.
- [ ] **Step 3:** rebuild and reinstall `/Applications/Lockbox.app` (`pnpm tauri build --bundles app`).
- [ ] **Step 4:** Commit any fixes; merge/push per the user's choice.

## Self-review notes

- Covers the gaps found in the Plan 2a manual run (no way to add a one-time password; empty templates for cards/identities) and spec items deferred from Plan 2a: lock on sleep/screen lock, Recently Deleted, settings, password change. Touch ID, Watchtower UI, menu bar quick search, vault rename/delete stay in Plan 2c.
- Password change goes through the unlock throttle, settings can only change while unlocked, and the KDF parameters of the existing header are kept (`KdfParams::DEFAULT` in the app).
