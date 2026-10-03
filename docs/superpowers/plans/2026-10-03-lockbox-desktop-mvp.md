# Lockbox Desktop MVP Implementation Plan (Plan 2a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working macOS app on top of `lockbox-core`: create/unlock the vault, browse vaults and items, view/copy/edit items (with TOTP codes and a password generator), import a 1Password export, auto-lock when idle, clear copied secrets from the clipboard, throttle password guessing.

**Architecture:** Three layers. `crates/lockbox-session` is plain Rust (no Tauri) holding all app logic as a `Session` with injected time, so it is unit-tested like the core. `app/src-tauri` is a thin Tauri 2 shell: commands lock a `Mutex<Session>` and call one method each; a housekeeping thread auto-locks and clears the clipboard. `app/src` is React + TypeScript, talking to the shell only through `src/api.ts`, tested with Vitest + Testing Library against a mocked `api`.

**Tech Stack:** Rust 2021, Tauri 2 (+ plugins dialog, clipboard-manager), React 19, TypeScript 6, Vite 8, Vitest 5, Testing Library, pnpm 9. Same toolchain versions as the user's Aftergram app.

**Spec:** `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md` §5 (desktop), §7 (errors). Plan 2b (next) adds: Touch ID, Watchtower view, settings (auto-lock/clipboard timeouts, change password), menu-bar icon + ⌘⇧Space quick search, lock on sleep/screen lock, Recently Deleted view, vault rename/delete, "not a lockbox database → start over".

**Conventions for every task:**
- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- Everything in English. Commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (omitted below for brevity — always add it).
- Run Rust commands from the repo root `/Users/skensel/WORKING/AI/lockbox`, frontend commands from `app/`.
- Rust: `cargo fmt --all` before each commit; `cargo clippy -p <crate> --all-targets -- -D warnings` must be clean.
- Frontend: `pnpm typecheck` and `pnpm test` must pass before each commit.
- Plain `cargo test` at the root runs only `lockbox-core` and `lockbox-session` (`default-members`); the Tauri crate needs `app/dist` and is built explicitly with `-p lockbox-app`.
- Errors in Rust tests are compared by `kind` (`ErrorKind`), never by message text.

## File map

```
Cargo.toml                                   workspace (+ lockbox-session, app/src-tauri)
.github/workflows/ci.yml                     Rust + frontend CI (Linux)
crates/lockbox-core/src/store/mod.rs         delete/restore require unlock (Task 1)
crates/lockbox-session/
  Cargo.toml
  src/lib.rs                                 module list + re-exports
  src/error.rs                               CmdError/ErrorKind (serializable for the UI)
  src/autolock.rs                            idle timeout
  src/throttle.rs                            growing delay after failed unlocks
  src/clipboard.rs                           clear clipboard only if it still holds our copy
  src/dto.rs                                 UI-facing data: summaries, filters, TOTP, generator, import preview
  src/session/mod.rs                         Session: lifecycle, vaults, items, copy, TOTP, import
  src/session/tests.rs                       Session tests
app/
  package.json, pnpm-lock.yaml, index.html, vite.config.ts, tsconfig.json, tsconfig.node.json
  design/make_icon.py                        draws design/icon.png (no dependencies)
  src/main.tsx, src/App.tsx, src/api.ts, src/format.ts, src/styles.css, src/vite-env.d.ts
  src/test/setup.ts, src/test/fixtures.ts
  src/components/Setup.tsx, Unlock.tsx, Main.tsx, Sidebar.tsx, ItemList.tsx,
                 ItemDetail.tsx, ItemEditor.tsx, Generator.tsx, ImportDialog.tsx (+ *.test.tsx)
  src-tauri/Cargo.toml, build.rs, tauri.conf.json, capabilities/default.json, icons/
  src-tauri/src/main.rs, lib.rs (setup + housekeeping), commands.rs
```

---

### Task 1: Core — deleting and restoring require an unlocked store

The final review of Plan 1 found `delete_item`/`restore_item` work on a locked store while everything else returns `Locked`.

**Files:**
- Modify: `crates/lockbox-core/src/store/mod.rs` (`delete_item`, `restore_item`)
- Test: `crates/lockbox-core/src/store/tests.rs`

- [ ] **Step 1: Write the failing test** (append to `store/tests.rs`)

```rust
#[test]
fn delete_and_restore_require_unlock() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let kept = login(v.id, "Kept");
    let trashed = login(v.id, "Trashed");
    store.save_item(&kept).unwrap();
    store.save_item(&trashed).unwrap();
    store.delete_item(trashed.id, 10).unwrap();
    store.lock();

    assert!(matches!(store.delete_item(kept.id, 20), Err(Error::Locked)));
    assert!(matches!(store.restore_item(trashed.id), Err(Error::Locked)));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p lockbox-core delete_and_restore_require_unlock`
Expected: FAIL (the calls return `Ok(())`).

- [ ] **Step 3: Implement** — add `self.account_key()?;` as the first line of both `delete_item` and `restore_item` in `store/mod.rs`.

- [ ] **Step 4: Run the core suite**

Run: `cargo test -p lockbox-core`
Expected: all pass (113 lib + 17 integration).

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Require an unlocked store to delete or restore items"
```

---

### Task 2: `lockbox-session` crate and UI error type

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/lockbox-session/Cargo.toml`, `crates/lockbox-session/src/lib.rs`, `crates/lockbox-session/src/error.rs`

- [ ] **Step 1: Register the crate in the workspace** — replace the `[workspace]` table of the root `Cargo.toml` (keep the `[profile…]` tables) with:

```toml
[workspace]
members = ["crates/lockbox-core", "crates/lockbox-session"]
default-members = ["crates/lockbox-core", "crates/lockbox-session"]
resolver = "2"
```

- [ ] **Step 2: Create the manifest** `crates/lockbox-session/Cargo.toml`:

```toml
[package]
name = "lockbox-session"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
lockbox-core = { path = "../lockbox-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
uuid = { version = "1", features = ["v4", "serde"] }

[dev-dependencies]
lockbox-core = { path = "../lockbox-core", features = ["test-utils"] }
tempfile = "3"
```

- [ ] **Step 3: Write the failing tests**

`crates/lockbox-session/src/lib.rs`:
```rust
//! Desktop-app logic over `lockbox-core`, free of any UI framework so it can be unit-tested.

pub mod error;

pub use error::{CmdError, CmdResult, ErrorKind};
```

`crates/lockbox-session/src/error.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_core::Error as CoreError;

    #[test]
    fn core_errors_map_to_kinds() {
        let cases = [
            (CoreError::WrongPassword, ErrorKind::WrongPassword),
            (CoreError::Locked, ErrorKind::Locked),
            (CoreError::NotFound("x".into()), ErrorKind::NotFound),
            (CoreError::Invalid("x".into()), ErrorKind::Invalid),
            (CoreError::Decrypt, ErrorKind::Other),
            (CoreError::Network("x".into()), ErrorKind::Other),
        ];
        for (core, kind) in cases {
            assert_eq!(CmdError::from(core).kind, kind);
        }
    }

    #[test]
    fn serializes_for_the_ui() {
        let json = serde_json::to_string(&CmdError::from(CoreError::WrongPassword)).unwrap();
        assert_eq!(json, r#"{"kind":"wrongPassword","message":"incorrect password"}"#);
        let json = serde_json::to_value(CmdError::throttled(4)).unwrap();
        assert_eq!(json["kind"], "throttled");
        assert_eq!(json["retryAfter"], 4);
        assert_eq!(json["message"], "Too many attempts. Try again in 4 s.");
    }
}
```

- [ ] **Step 4: Run to verify failure**

Run: `cargo test -p lockbox-session`
Expected: compile errors (`CmdError`, `ErrorKind` not found).

- [ ] **Step 5: Implement** (prepend to `error.rs`)

```rust
use lockbox_core::Error as CoreError;
use serde::Serialize;

/// What the UI receives for a failed command: a stable `kind` to branch on, a message to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CmdError {
    pub kind: ErrorKind,
    pub message: String,
    /// Seconds until the next unlock attempt is allowed (only for `Throttled`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    WrongPassword,
    Locked,
    Throttled,
    NotFound,
    Invalid,
    Other,
}

pub type CmdResult<T> = Result<T, CmdError>;

impl CmdError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), retry_after: None }
    }

    pub fn throttled(retry_after: u64) -> Self {
        Self {
            kind: ErrorKind::Throttled,
            message: format!("Too many attempts. Try again in {retry_after} s."),
            retry_after: Some(retry_after),
        }
    }
}

impl From<CoreError> for CmdError {
    fn from(e: CoreError) -> Self {
        let kind = match &e {
            CoreError::WrongPassword => ErrorKind::WrongPassword,
            CoreError::Locked => ErrorKind::Locked,
            CoreError::NotFound(_) => ErrorKind::NotFound,
            CoreError::Invalid(_) => ErrorKind::Invalid,
            _ => ErrorKind::Other,
        };
        Self::new(kind, e.to_string())
    }
}
```

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p lockbox-session`
Expected: 2 tests pass.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/lockbox-session
git commit -m "Add lockbox-session crate with UI error type"
```

---

### Task 3: Auto-lock timer and unlock throttle

**Files:**
- Create: `crates/lockbox-session/src/autolock.rs`, `crates/lockbox-session/src/throttle.rs`
- Modify: `crates/lockbox-session/src/lib.rs` (add `pub mod autolock;` and `pub mod throttle;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-session/src/autolock.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_only_after_the_timeout() {
        let lock = AutoLock::new(60, 1_000);
        assert!(!lock.is_due(1_059));
        assert!(lock.is_due(1_060));
    }

    #[test]
    fn touch_postpones_and_never_moves_back() {
        let mut lock = AutoLock::new(60, 1_000);
        lock.touch(1_050);
        assert!(!lock.is_due(1_100));
        lock.touch(900);
        assert!(!lock.is_due(1_100), "an older timestamp must not shorten the timer");
        assert!(lock.is_due(1_110));
    }

    #[test]
    fn clock_going_backwards_does_not_lock() {
        let lock = AutoLock::new(60, 1_000);
        assert!(!lock.is_due(10));
    }
}
```

`crates/lockbox-session/src/throttle.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_attempts_then_doubling_delay() {
        let mut t = UnlockThrottle::default();
        for _ in 0..UnlockThrottle::FREE_ATTEMPTS - 1 {
            t.record_failure(100);
            assert_eq!(t.check(100), Ok(()));
        }
        t.record_failure(100); // 5th failure
        assert_eq!(t.check(100), Err(1));
        assert_eq!(t.check(101), Ok(()));
        t.record_failure(101); // 6th
        assert_eq!(t.check(101), Err(2));
        t.record_failure(103); // 7th
        assert_eq!(t.check(103), Err(4));
    }

    #[test]
    fn delay_is_capped() {
        let mut t = UnlockThrottle::default();
        for _ in 0..80 {
            t.record_failure(0);
        }
        assert_eq!(t.check(0), Err(UnlockThrottle::MAX_DELAY_SECS));
    }

    #[test]
    fn success_resets() {
        let mut t = UnlockThrottle::default();
        for _ in 0..10 {
            t.record_failure(0);
        }
        t.record_success();
        assert_eq!(t.check(0), Ok(()));
        assert_eq!(t.failures(), 0);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p lockbox-session`
Expected: compile errors (`AutoLock`, `UnlockThrottle` not found).

- [ ] **Step 3: Implement** (prepend to each file)

`autolock.rs`:
```rust
/// Locks the vault after a period without user activity. Times are Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoLock {
    timeout_secs: u64,
    last_activity: u64,
}

impl AutoLock {
    pub const DEFAULT_TIMEOUT_SECS: u64 = 10 * 60;

    pub fn new(timeout_secs: u64, now: u64) -> Self {
        Self { timeout_secs, last_activity: now }
    }

    pub fn touch(&mut self, now: u64) {
        self.last_activity = self.last_activity.max(now);
    }

    pub fn is_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) >= self.timeout_secs
    }
}
```

`throttle.rs`:
```rust
/// Slows down password guessing: a few free attempts, then a doubling wait. Times are Unix seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnlockThrottle {
    failures: u32,
    blocked_until: u64,
}

impl UnlockThrottle {
    pub const FREE_ATTEMPTS: u32 = 5;
    pub const MAX_DELAY_SECS: u64 = 300;

    /// `Ok` if an attempt is allowed now, otherwise the seconds to wait.
    pub fn check(&self, now: u64) -> Result<(), u64> {
        if now < self.blocked_until {
            Err(self.blocked_until - now)
        } else {
            Ok(())
        }
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Self::FREE_ATTEMPTS {
            let exponent = self.failures - Self::FREE_ATTEMPTS;
            let delay = 1u64.checked_shl(exponent).unwrap_or(u64::MAX).min(Self::MAX_DELAY_SECS);
            self.blocked_until = now.saturating_add(delay);
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p lockbox-session`
Expected: 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add auto-lock timer and unlock throttle"
```

---

### Task 4: Clipboard guard

**Files:**
- Create: `crates/lockbox-session/src/clipboard.rs`
- Modify: `crates/lockbox-session/src/lib.rs` (add `pub mod clipboard;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-session/src/clipboard.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_our_copy_when_time_is_up() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(g.is_pending());
        assert!(!g.should_clear(189, Some("hunter2")));
        assert!(g.should_clear(190, Some("hunter2")));
        assert!(!g.is_pending());
        assert!(!g.should_clear(500, Some("hunter2")), "only once");
    }

    #[test]
    fn leaves_the_clipboard_alone_if_the_user_copied_something_else() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(!g.should_clear(120, Some("my own text")));
        assert!(!g.is_pending(), "forget once it's no longer ours");
        assert!(!g.should_clear(300, Some("hunter2")));
    }

    #[test]
    fn empty_clipboard_cancels() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(!g.should_clear(300, None));
        assert!(!g.is_pending());
    }

    #[test]
    fn a_new_copy_replaces_the_old_one() {
        let mut g = ClipboardGuard::default();
        g.copied("first", 100, 90);
        g.copied("second", 150, 90);
        assert!(!g.should_clear(200, Some("second")));
        assert!(g.should_clear(240, Some("second")));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p lockbox-session clipboard`
Expected: compile error (`ClipboardGuard` not found).

- [ ] **Step 3: Implement** (prepend)

```rust
use sha2::{Digest, Sha256};

/// Remembers what we put on the clipboard (only as a hash) so we clear it later — and only if it
/// still holds our copy. Times are Unix seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClipboardGuard {
    pending: Option<Pending>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    digest: [u8; 32],
    clear_at: u64,
}

impl ClipboardGuard {
    pub const DEFAULT_CLEAR_SECS: u64 = 90;

    pub fn copied(&mut self, text: &str, now: u64, clear_after: u64) {
        self.pending = Some(Pending { digest: digest(text), clear_at: now.saturating_add(clear_after) });
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Call periodically with the clipboard's current text; `true` means clear it now.
    pub fn should_clear(&mut self, now: u64, current: Option<&str>) -> bool {
        let Some(pending) = self.pending else { return false };
        match current {
            Some(text) if digest(text) == pending.digest => {
                if now >= pending.clear_at {
                    self.pending = None;
                    true
                } else {
                    false
                }
            }
            _ => {
                self.pending = None;
                false
            }
        }
    }
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p lockbox-session`
Expected: 12 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add clipboard guard that clears only our own copy"
```

---

### Task 5: Session — create, unlock, lock, auto-lock

**Files:**
- Create: `crates/lockbox-session/src/session/mod.rs`, `crates/lockbox-session/src/session/tests.rs`
- Modify: `crates/lockbox-session/src/lib.rs` (add `pub mod session;` and `pub use session::{Session, Status};`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-session/src/session/tests.rs`:
```rust
use super::*;
use crate::error::ErrorKind;
use tempfile::TempDir;

pub(super) const PW: &str = "correct horse battery";

pub(super) fn new_session() -> (TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    // A missing parent directory must be created on first run.
    let path = dir.path().join("Application Support").join("lockbox.db");
    (dir, Session::new(path, KdfParams::INSECURE_FAST, 1_000))
}

pub(super) fn unlocked_session() -> (TempDir, Session) {
    let (dir, mut s) = new_session();
    s.create(PW, 1_000).unwrap();
    (dir, s)
}

#[test]
fn first_run_creates_an_unlocked_vault_with_a_personal_vault() {
    let (_dir, mut s) = new_session();
    assert_eq!(s.status(), Status::New);
    s.create(PW, 1_000).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
    let names: Vec<_> =
        s.store.as_ref().unwrap().vaults().unwrap().into_iter().map(|v| v.name).collect();
    assert_eq!(names, [DEFAULT_VAULT]);
}

#[test]
fn create_rejects_short_passwords_and_an_existing_vault() {
    let (_dir, mut s) = new_session();
    assert_eq!(s.create("short", 1_000).unwrap_err().kind, ErrorKind::Invalid);
    assert_eq!(s.status(), Status::New);
    s.create(PW, 1_000).unwrap();
    s.lock();
    assert_eq!(s.create(PW, 1_000).unwrap_err().kind, ErrorKind::Invalid);
}

#[test]
fn lock_and_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.status(), Status::Locked);
    assert_eq!(s.unlock("wrong password", 1_001).unwrap_err().kind, ErrorKind::WrongPassword);
    s.unlock(PW, 1_002).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
}

#[test]
fn repeated_wrong_passwords_are_throttled() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    for _ in 0..UnlockThrottle::FREE_ATTEMPTS {
        assert_eq!(s.unlock("nope nope nope", 2_000).unwrap_err().kind, ErrorKind::WrongPassword);
    }
    let err = s.unlock(PW, 2_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Throttled);
    assert_eq!(err.retry_after, Some(1));
    s.unlock(PW, 2_001).unwrap();
}

#[test]
fn tick_locks_after_the_idle_timeout_and_touch_postpones_it() {
    let (_dir, mut s) = unlocked_session(); // last activity: 1_000
    let timeout = AutoLock::DEFAULT_TIMEOUT_SECS;
    assert!(!s.tick(1_000 + timeout - 1));
    s.touch(1_500);
    assert!(!s.tick(1_000 + timeout));
    assert!(s.tick(1_500 + timeout));
    assert_eq!(s.status(), Status::Locked);
    assert!(!s.tick(1_500 + timeout + 10), "already locked");
}

#[test]
fn clipboard_guard_is_exposed() {
    let (_dir, mut s) = unlocked_session();
    assert!(!s.clipboard_pending());
    s.clipboard.copied("x", 1_000, 90);
    assert!(s.clipboard_pending());
    assert!(s.clipboard_should_clear(1_090, Some("x")));
}
```

- [ ] **Step 2: Run to verify failure**

Create `session/mod.rs` containing only `#[cfg(test)] mod tests;`, add the lib.rs lines, run `cargo test -p lockbox-session`.
Expected: compile errors (`Session`, `Status`, … not found).

- [ ] **Step 3: Implement** — replace `session/mod.rs` with:

```rust
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
            return Err(CmdError::new(ErrorKind::Invalid, "A vault already exists on this Mac"));
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(CmdError::new(
                ErrorKind::Invalid,
                format!("Use at least {MIN_PASSWORD_LEN} characters"),
            ));
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p lockbox-session` then `cargo clippy -p lockbox-session --all-targets -- -D warnings`
Expected: 18 tests pass; clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add session lifecycle: create, unlock with throttle, lock, auto-lock"
```

---

### Task 6: Session — vaults and items

**Files:**
- Create: `crates/lockbox-session/src/dto.rs`
- Modify: `crates/lockbox-session/src/lib.rs` (add `pub mod dto;`), `src/session/mod.rs`, `src/session/tests.rs`

- [ ] **Step 1: Write the DTOs and their test**

`crates/lockbox-session/src/dto.rs`:
```rust
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
        assert_eq!(f, ItemFilter { query: "git".into(), ..ItemFilter::default() });
        let id = Uuid::new_v4();
        let f: ItemFilter =
            serde_json::from_str(&format!(r#"{{"vaultId":"{id}","favorites":true}}"#)).unwrap();
        assert_eq!((f.vault_id, f.favorites), (Some(id), true));
    }
}
```

- [ ] **Step 2: Write the failing session tests** (append to `session/tests.rs`)

```rust
use lockbox_core::model::{FieldValue, Item, ItemKind};
use uuid::Uuid;

use crate::dto::ItemFilter;

pub(super) fn personal(s: &mut Session) -> Uuid {
    s.vaults(1_000).unwrap()[0].id
}

pub(super) fn save_login(s: &mut Session, vault: Uuid, title: &str, user: &str, pw: &str) -> Item {
    let mut item = s.new_item(vault, ItemKind::Login, 1_000).unwrap();
    item.title = title.into();
    item.fields[0].value = FieldValue::Text(user.into());
    item.fields[1].value = FieldValue::Concealed(pw.into());
    s.save_item(item, 1_000).unwrap()
}

fn titles(s: &mut Session, filter: ItemFilter) -> Vec<String> {
    s.items(&filter, 1_000).unwrap().into_iter().map(|i| i.title).collect()
}

#[test]
fn vaults_report_item_counts() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "GitHub", "ivan", "pw");
    save_login(&mut s, p, "Bank", "me", "pw");
    s.create_vault("Work", 1_000).unwrap();
    let vaults: Vec<_> = s.vaults(1_000).unwrap().into_iter().map(|v| (v.name, v.item_count)).collect();
    assert_eq!(vaults, [("Personal".to_string(), 2), ("Work".to_string(), 0)]);
}

#[test]
fn create_vault_requires_a_name() {
    let (_dir, mut s) = unlocked_session();
    assert_eq!(s.create_vault("   ", 1_000).unwrap_err().kind, ErrorKind::Invalid);
    assert_eq!(s.create_vault("  Work ", 1_000).unwrap().name, "Work");
}

#[test]
fn new_items_get_purpose_fields_and_need_a_known_vault() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let login = s.new_item(p, ItemKind::Login, 1_000).unwrap();
    let ids: Vec<_> = login.fields.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["username", "password"]);
    assert_eq!(s.new_item(p, ItemKind::Password, 1_000).unwrap().fields.len(), 1);
    assert!(s.new_item(p, ItemKind::SecureNote, 1_000).unwrap().fields.is_empty());
    let err = s.new_item(Uuid::new_v4(), ItemKind::Login, 1_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn items_are_sorted_and_filtered() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let work = s.create_vault("Work", 1_000).unwrap().id;
    save_login(&mut s, p, "zeta", "z", "pw");
    save_login(&mut s, p, "Alpha", "a", "pw");
    let mut beta = save_login(&mut s, p, "beta", "b", "pw");
    beta.favorite = true;
    s.save_item(beta, 1_000).unwrap();
    save_login(&mut s, work, "Work item", "w", "pw");

    assert_eq!(titles(&mut s, ItemFilter::default()), ["Alpha", "beta", "Work item", "zeta"]);
    assert_eq!(titles(&mut s, ItemFilter { vault_id: Some(work), ..Default::default() }), ["Work item"]);
    assert_eq!(titles(&mut s, ItemFilter { query: "ALP".into(), ..Default::default() }), ["Alpha"]);
    assert_eq!(titles(&mut s, ItemFilter { favorites: true, ..Default::default() }), ["beta"]);
}

#[test]
fn save_requires_a_title_and_trims_it() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = s.new_item(p, ItemKind::SecureNote, 1_000).unwrap();
    assert_eq!(s.save_item(item.clone(), 1_000).unwrap_err().kind, ErrorKind::Invalid);
    let mut item = item;
    item.title = "  Wi-Fi  ".into();
    assert_eq!(s.save_item(item, 1_000).unwrap().title, "Wi-Fi");
}

#[test]
fn save_records_password_history_and_keeps_created_at() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "first");
    item.fields[1].value = FieldValue::Concealed("second".into());
    let saved = s.save_item(item, 2_000).unwrap();
    assert_eq!(saved.password(), Some("second"));
    assert_eq!(saved.password_history[0].value, "first");
    assert_eq!(saved.password_history[0].changed_at, 2_000);
    assert_eq!((saved.created_at, saved.updated_at), (1_000, 2_000));
    let again = s.save_item(saved, 3_000).unwrap();
    assert_eq!(again.password_history.len(), 1, "unchanged password adds no history");
}

#[test]
fn item_and_delete() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    assert_eq!(s.item(item.id, 1_000).unwrap().title, "GitHub");
    s.delete_item(item.id, 1_000).unwrap();
    assert!(titles(&mut s, ItemFilter::default()).is_empty());
    assert_eq!(s.item(item.id, 1_000).unwrap_err().kind, ErrorKind::NotFound);
}

#[test]
fn a_locked_session_refuses_vault_access() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.vaults(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(s.items(&ItemFilter::default(), 1_000).unwrap_err().kind, ErrorKind::Locked);
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p lockbox-session`
Expected: compile errors (`vaults`, `new_item`, … not found).

- [ ] **Step 4: Implement** — in `session/mod.rs` extend the imports:

```rust
use lockbox_core::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose};
use lockbox_core::store::ItemEntry;
use uuid::Uuid;

use crate::dto::{ItemFilter, ItemSummary, VaultDto};
```

and add inside `impl Session`:

```rust
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
        Ok(VaultDto { id: info.id, name: info.name, item_count: 0 })
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
        out.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()).then(a.id.cmp(&b.id)));
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
            return Err(CmdError::new(ErrorKind::NotFound, format!("vault {vault_id}")));
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
                        item.password_history
                            .insert(0, HistoryEntry { value: old_pw.to_owned(), changed_at: now });
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
```

and these free functions at the end of the file:

```rust
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
    Field { id: id.into(), label: id.into(), value, purpose: Some(purpose) }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p lockbox-session` and clippy.
Expected: 28 tests pass; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add session vault and item operations"
```

---

### Task 7: Session — TOTP codes, copying, generator

**Files:**
- Modify: `crates/lockbox-session/src/dto.rs`, `src/session/mod.rs`, `src/session/tests.rs`

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `dto.rs`:
```rust
    #[test]
    fn generator_defaults_and_partial_json() {
        assert_eq!(GeneratorRequest::default().generate().unwrap().chars().count(), 20);
        let req: GeneratorRequest =
            serde_json::from_str(r#"{"kind":"passphrase","words":4,"separator":"."}"#).unwrap();
        assert_eq!(req.generate().unwrap().split('.').count(), 4);
        let bad = GeneratorRequest { length: 7, ..GeneratorRequest::default() };
        assert_eq!(bad.generate().unwrap_err().kind, crate::ErrorKind::Invalid);
    }
```

Append to `session/tests.rs`:
```rust
use lockbox_core::model::{Field, Section};

/// base32 of "12345678901234567890" (RFC 6238 SHA-1 secret).
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn with_totp_and_dates(s: &mut Session) -> Item {
    let p = personal(s);
    let mut item = s.new_item(p, ItemKind::Login, 1_000).unwrap();
    item.title = "GitHub".into();
    item.fields[1].value = FieldValue::Concealed("hunter2".into());
    item.sections.push(Section {
        id: "extra".into(),
        title: "Extra".into(),
        fields: vec![
            Field { id: "otp".into(), label: "one-time password".into(), value: FieldValue::Totp(RFC_SECRET.into()), purpose: None },
            Field { id: "born".into(), label: "birth date".into(), value: FieldValue::Date(631_152_000), purpose: None },
            Field { id: "exp".into(), label: "expiry".into(), value: FieldValue::MonthYear(202_712), purpose: None },
        ],
    });
    s.save_item(item, 1_000).unwrap()
}

#[test]
fn totp_code_for_a_known_secret() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    let code = s.totp(item.id, 59).unwrap().unwrap();
    assert_eq!(code.code, "287082");
    assert_eq!((code.seconds_left, code.period), (1, 30));
}

#[test]
fn totp_is_none_without_a_totp_field() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "Bank", "me", "pw");
    assert_eq!(s.totp(item.id, 59).unwrap(), None);
}

#[test]
fn polling_totp_does_not_keep_the_vault_unlocked() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    let timeout = AutoLock::DEFAULT_TIMEOUT_SECS;
    s.totp(item.id, 1_000 + timeout - 1).unwrap();
    assert!(s.tick(1_000 + timeout));
}

#[test]
fn copy_returns_the_value_and_arms_clipboard_clearing() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    assert_eq!(s.copy_value(item.id, "password", 1_000).unwrap(), "hunter2");
    assert!(s.clipboard_pending());
    assert!(s.clipboard_should_clear(1_000 + ClipboardGuard::DEFAULT_CLEAR_SECS, Some("hunter2")));
}

#[test]
fn copy_totp_dates_and_errors() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    assert_eq!(s.copy_value(item.id, "totp", 59).unwrap(), "287082");
    assert_eq!(s.copy_value(item.id, "otp", 59).unwrap(), "287082");
    assert_eq!(s.copy_value(item.id, "born", 1_000).unwrap(), "1990-01-01");
    assert_eq!(s.copy_value(item.id, "exp", 1_000).unwrap(), "12/2027");
    assert_eq!(s.copy_value(item.id, "nope", 1_000).unwrap_err().kind, ErrorKind::NotFound);
    assert_eq!(s.copy_value(item.id, "username", 1_000).unwrap_err().kind, ErrorKind::Invalid);
}

#[test]
fn formats_dates_as_iso() {
    assert_eq!(format_date(0), "1970-01-01");
    assert_eq!(format_date(951_782_400), "2000-02-29");
    assert_eq!(format_date(-86_400), "1969-12-31");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p lockbox-session`
Expected: compile errors (`GeneratorRequest`, `totp`, `copy_value`, `format_date` not found).

- [ ] **Step 3: Implement the DTOs** — add to `dto.rs` (above the tests; extend imports with `use lockbox_core::generator::{self, PassphraseOptions, PasswordOptions};` and `use crate::CmdResult;`):

```rust
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
```

- [ ] **Step 4: Implement the session methods** — extend `session/mod.rs` imports with `use lockbox_core::totp::Totp;` and `use crate::dto::TotpCode;`, then add inside `impl Session`:

```rust
    /// Current code of the item's first TOTP field. Not activity: the UI polls it every second,
    /// which must not keep the vault unlocked.
    pub fn totp(&self, id: Uuid, now: u64) -> CmdResult<Option<TotpCode>> {
        let item = self.store()?.get_item(id)?;
        let Some(raw) = item.totp() else { return Ok(None) };
        let totp = Totp::parse(raw)?;
        Ok(Some(TotpCode {
            code: totp.code_at(now),
            seconds_left: totp.seconds_left(now),
            period: totp.period(),
        }))
    }

    /// Text to put on the clipboard for one field (`"totp"` = the current one-time code), and
    /// arms clearing it after `ClipboardGuard::DEFAULT_CLEAR_SECS`.
    pub fn copy_value(&mut self, id: Uuid, field_id: &str, now: u64) -> CmdResult<String> {
        self.touch(now);
        let item = self.store()?.get_item(id)?;
        let text = if field_id == "totp" {
            let raw = item
                .totp()
                .ok_or_else(|| CmdError::new(ErrorKind::NotFound, "This item has no one-time password"))?;
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
        self.clipboard.copied(&text, now, ClipboardGuard::DEFAULT_CLEAR_SECS);
        Ok(text)
    }
```

and free functions:

```rust
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
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p lockbox-session` and clippy.
Expected: 35 tests pass; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add TOTP codes, copying with clipboard clearing, and generator requests"
```

---

### Task 8: Session — import preview and apply

**Files:**
- Modify: `crates/lockbox-session/src/dto.rs`, `src/session/mod.rs`, `src/session/tests.rs`

- [ ] **Step 1: Write the failing tests** (append to `session/tests.rs`)

```rust
fn csv_export(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("export.csv");
    std::fs::write(
        &path,
        "Title,Url,Username,Password\nGitHub,https://github.com,ivan,pw1\nBank,,me,pw2\n",
    )
    .unwrap();
    path
}

#[test]
fn import_preview_then_apply() {
    let (dir, mut s) = unlocked_session();
    let preview = s.import_preview(&csv_export(&dir), 1_000).unwrap();
    assert_eq!(preview.total_items, 2);
    assert_eq!(preview.vaults.len(), 1);
    assert_eq!((preview.vaults[0].name.as_str(), preview.vaults[0].items), ("Imported", 2));
    assert!(preview.skipped.is_empty());

    let result = s.import_apply(1_000).unwrap();
    assert_eq!((result.vaults, result.items, result.attachments), (1, 2, 0));
    let vaults: Vec<_> = s.vaults(1_000).unwrap().into_iter().map(|v| (v.name, v.item_count)).collect();
    assert_eq!(vaults, [("Personal".to_string(), 0), ("Imported".to_string(), 2)]);
    assert_eq!(s.import_apply(1_000).unwrap_err().kind, ErrorKind::Invalid, "plan is used once");
}

#[test]
fn import_rejects_other_files_and_locked_sessions() {
    let (dir, mut s) = unlocked_session();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, "hello").unwrap();
    assert_eq!(s.import_preview(&txt, 1_000).unwrap_err().kind, ErrorKind::Invalid);
    let csv = csv_export(&dir);
    s.lock();
    assert_eq!(s.import_preview(&csv, 1_000).unwrap_err().kind, ErrorKind::Locked);
}

#[test]
fn locking_discards_a_pending_import() {
    let (dir, mut s) = unlocked_session();
    s.import_preview(&csv_export(&dir), 1_000).unwrap();
    s.lock();
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(s.import_apply(1_000).unwrap_err().kind, ErrorKind::Invalid);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p lockbox-session`
Expected: compile errors (`import_preview`, `import_apply` not found).

- [ ] **Step 3: Implement the DTOs** — add to `dto.rs` (extend imports with `use lockbox_core::import::{ImportPlan, ImportReport};`):

```rust
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
                .map(|v| ImportVaultPreview { name: v.name.clone(), items: v.items.len() })
                .collect(),
            skipped: plan
                .skipped
                .iter()
                .map(|s| SkippedDto { title: s.title.clone(), reason: s.reason.clone() })
                .collect(),
            total_items: plan.item_count(),
        }
    }
}

impl From<ImportReport> for ImportResult {
    fn from(r: ImportReport) -> Self {
        Self { vaults: r.vaults, items: r.items, attachments: r.attachments }
    }
}
```

- [ ] **Step 4: Implement the session part**
  - Add a field `pending_import: Option<ImportPlan>` to `Session`, initialised to `None` in `new`, and set `self.pending_import = None;` in `lock()` (before or after dropping the store).
  - Extend imports: `use std::path::Path;`, `use lockbox_core::import::{self, onepux, ImportPlan};`, `use crate::dto::{ImportPreview, ImportResult};`.
  - Add inside `impl Session`:

```rust
    /// Parses a 1Password export (.1pux or .csv) and keeps the plan until `import_apply`.
    pub fn import_preview(&mut self, path: &Path, now: u64) -> CmdResult<ImportPreview> {
        self.touch(now);
        self.store()?;
        let ext = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
        let bytes = std::fs::read(path).map_err(|e| {
            CmdError::new(ErrorKind::Other, format!("Can't read {}: {e}", path.display()))
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
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p lockbox-session` and clippy.
Expected: 38 tests pass; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-session
git commit -m "Add import preview and apply to the session"
```

---

### Task 9: Tauri app scaffold, icon and CI

**Files:**
- Create: everything under `app/` listed in the file map except the components, `.github/workflows/ci.yml`
- Modify: root `Cargo.toml` (`members` += `"app/src-tauri"`), `.gitignore`

- [ ] **Step 1: Frontend toolchain files**

`app/package.json`:
```json
{
  "name": "lockbox",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "test": "vitest run",
    "typecheck": "tsc --noEmit",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "^2",
    "@tauri-apps/plugin-dialog": "^2",
    "react": "^19.1.0",
    "react-dom": "^19.1.0"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2",
    "@testing-library/jest-dom": "^7",
    "@testing-library/react": "^16",
    "@testing-library/user-event": "^14",
    "@types/react": "^19.1.8",
    "@types/react-dom": "^19.1.6",
    "@vitejs/plugin-react": "^6.0.2",
    "jsdom": "^30",
    "typescript": "~6.0.3",
    "vite": "^8.0.16",
    "vitest": "^5"
  }
}
```

`app/vite.config.ts`:
```ts
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(() => ({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1440,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    include: ["src/**/*.test.{ts,tsx}"],
  },
}));
```

`app/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

`app/tsconfig.node.json`:
```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
```

`app/index.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Lockbox</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`app/src/vite-env.d.ts`:
```ts
/// <reference types="vite/client" />
```

`app/src/test/setup.ts`:
```ts
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest runs without globals, so Testing Library cannot register its own cleanup.
afterEach(cleanup);
```

`app/src/main.tsx`:
```tsx
import "./styles.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

- [ ] **Step 2: Placeholder App with a failing test first**

`app/src/App.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { App } from "./App";

test("renders the app name", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "Lockbox" })).toBeInTheDocument();
});
```

Run: `cd app && pnpm install && pnpm test`
Expected: FAIL (cannot resolve `./App`).

`app/src/App.tsx`:
```tsx
export function App() {
  return (
    <main className="center">
      <h1>Lockbox</h1>
    </main>
  );
}
```

`app/src/styles.css`:
```css
:root {
  color-scheme: dark;
  --bg: #121418;
  --panel: #181b21;
  --surface: #1f232a;
  --surface-2: #272c35;
  --border: #2e343e;
  --text: #e8eaef;
  --muted: #9aa2ae;
  --accent: #5b8cff;
  --accent-strong: #3f74f2;
  --danger: #ff6b6b;
  --radius: 10px;
  --mono: ui-monospace, "SF Mono", Menlo, monospace;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  color: var(--text);
  background: var(--bg);
}
* { box-sizing: border-box; }
html, body, #root { height: 100%; margin: 0; }
body { background: var(--bg); }
button { font: inherit; color: var(--text); background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 6px 12px; cursor: pointer; }
button:hover:not(:disabled) { border-color: var(--accent); }
button:disabled { opacity: 0.5; cursor: default; }
button.primary { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; }
button.danger { background: transparent; border-color: var(--danger); color: var(--danger); }
input, textarea, select { font: inherit; color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; width: 100%; }
input:focus, textarea:focus { outline: none; border-color: var(--accent); }
input[type="checkbox"], input[type="range"] { width: auto; }
label { display: flex; flex-direction: column; gap: 6px; color: var(--muted); font-size: 12px; }
label.check { flex-direction: row; align-items: center; gap: 8px; font-size: 13px; color: var(--text); }
h1, h2, h3 { margin: 0; font-weight: 600; }
.muted { color: var(--muted); }
.mono { font-family: var(--mono); }
.error { color: var(--danger); font-size: 13px; margin: 0; }
.center { height: 100%; display: grid; place-items: center; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 28px; }
.auth { width: 380px; display: flex; flex-direction: column; gap: 16px; }
.auth h1 { font-size: 20px; }
.app { display: grid; grid-template-columns: 220px 320px 1fr; height: 100%; }
.sidebar { background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 16px 10px; gap: 4px; }
.sidebar .brand { font-weight: 700; padding: 4px 10px 12px; }
.sidebar .nav { background: none; border: none; text-align: left; padding: 7px 10px; border-radius: 8px; display: flex; justify-content: space-between; }
.sidebar .nav[aria-current="true"] { background: var(--surface-2); }
.sidebar .heading { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; padding: 14px 10px 4px; }
.sidebar .spacer { flex: 1; }
.list { border-right: 1px solid var(--border); display: flex; flex-direction: column; min-height: 0; }
.list .toolbar { display: flex; gap: 8px; padding: 12px; border-bottom: 1px solid var(--border); position: relative; }
.list ul { list-style: none; margin: 0; padding: 6px; overflow-y: auto; flex: 1; }
.list li button { width: 100%; text-align: left; background: none; border: none; border-radius: 8px; padding: 8px 10px; display: flex; flex-direction: column; gap: 2px; }
.list li button[aria-current="true"] { background: var(--surface-2); }
.list .subtitle { color: var(--muted); font-size: 12px; }
.list .damaged { color: var(--danger); }
.menu { position: absolute; top: 48px; right: 12px; z-index: 5; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 6px; display: flex; flex-direction: column; min-width: 170px; }
.menu button { background: none; border: none; text-align: left; }
.detail { overflow-y: auto; padding: 24px 28px; min-width: 0; }
.empty { color: var(--muted); height: 100%; display: grid; place-items: center; margin: 0; }
.item-detail header, .editor header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 20px; }
.kind { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.field-group { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 14px; }
.field-group h3 { font-size: 12px; color: var(--muted); padding: 10px 14px 0; }
.field { display: grid; grid-template-columns: 140px 1fr auto; gap: 12px; align-items: center; padding: 10px 14px; }
.field + .field { border-top: 1px solid var(--border); }
.field .label { color: var(--muted); font-size: 12px; }
.field .value { overflow-wrap: anywhere; }
.field-actions { display: flex; gap: 6px; }
.notes { white-space: pre-wrap; }
.urls { display: flex; flex-direction: column; gap: 4px; margin-bottom: 14px; color: var(--accent); }
.toast { position: fixed; bottom: 20px; right: 24px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px; }
.banner { border-radius: 10px; padding: 10px 14px; margin-bottom: 14px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }
.banner.error { background: rgba(255, 107, 107, 0.12); color: var(--danger); }
.editor { display: flex; flex-direction: column; gap: 14px; max-width: 640px; }
.row { display: flex; gap: 8px; align-items: flex-end; }
.row > label { flex: 1; }
.generator { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px; display: flex; flex-direction: column; gap: 12px; }
.generated { display: block; font-size: 15px; padding: 10px; background: var(--surface); border-radius: 8px; overflow-wrap: anywhere; min-height: 40px; }
.segmented { display: flex; gap: 4px; }
.segmented button[aria-pressed="true"] { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; }
.checks { display: flex; flex-wrap: wrap; gap: 12px; }
.modal-backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.55); display: grid; place-items: center; z-index: 10; }
.modal { width: 520px; max-height: 80vh; overflow-y: auto; display: flex; flex-direction: column; gap: 14px; }
.modal ul { margin: 0; padding-left: 18px; }
```

Run: `pnpm test && pnpm typecheck && pnpm build`
Expected: 1 test passes; `dist/` built.

- [ ] **Step 3: App icon** — `app/design/make_icon.py`:

```python
#!/usr/bin/env python3
"""Draws the 1024x1024 Lockbox icon (a keyhole on a blue rounded square) as a PNG. No dependencies."""
import struct
import zlib
from pathlib import Path

SIZE = 1024
MARGIN, RADIUS = 100, 185  # macOS icon grid
TOP, BOTTOM = (0x5B, 0x8C, 0xFF), (0x2F, 0x5F, 0xE0)
KEYHOLE = (0xF5, 0xF7, 0xFB)


def in_rounded_square(x: int, y: int) -> bool:
    lo, hi = MARGIN, SIZE - MARGIN
    if not (lo <= x < hi and lo <= y < hi):
        return False
    cx = min(max(x, lo + RADIUS), hi - RADIUS)
    cy = min(max(y, lo + RADIUS), hi - RADIUS)
    return (x - cx) ** 2 + (y - cy) ** 2 <= RADIUS**2


def in_keyhole(x: int, y: int) -> bool:
    if (x - 512) ** 2 + (y - 430) ** 2 <= 120**2:
        return True
    if 470 <= y <= 720:
        half = 55 + (y - 470) * (95 - 55) / (720 - 470)
        return abs(x - 512) <= half
    return False


def pixel(x: int, y: int) -> tuple:
    if not in_rounded_square(x, y):
        return (0, 0, 0, 0)
    if in_keyhole(x, y):
        return (*KEYHOLE, 255)
    t = (y - MARGIN) / (SIZE - 2 * MARGIN)
    return tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM)) + (255,)


def png(width: int, height: int, rows: list) -> bytes:
    raw = b"".join(b"\x00" + bytes(row) for row in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


rows = [bytearray(b for x in range(SIZE) for b in pixel(x, y)) for y in range(SIZE)]
out = Path(__file__).with_name("icon.png")
out.write_bytes(png(SIZE, SIZE, rows))
print(f"wrote {out}")
```

Run (from `app/`):
```bash
python3 design/make_icon.py
pnpm tauri icon design/icon.png -o src-tauri/icons
rm -rf src-tauri/icons/android src-tauri/icons/ios src-tauri/icons/Square*.png src-tauri/icons/StoreLogo.png src-tauri/icons/icon.ico
ls src-tauri/icons
```
Expected: `32x32.png 128x128.png 128x128@2x.png icon.icns icon.png`. Open `design/icon.png` with the Read tool to eyeball it.

- [ ] **Step 4: Tauri shell**

`app/src-tauri/Cargo.toml`:
```toml
[package]
name = "lockbox-app"
version = "0.1.0"
description = "Lockbox password manager for macOS"
edition = "2021"
publish = false

[lib]
name = "lockbox_app_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-dialog = "2"
tauri-plugin-clipboard-manager = "2"
```

`app/src-tauri/build.rs`:
```rust
fn main() {
    tauri_build::build()
}
```

`app/src-tauri/src/main.rs`:
```rust
// Prevents an extra console window on Windows in release; harmless on macOS.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lockbox_app_lib::run()
}
```

`app/src-tauri/src/lib.rs`:
```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .run(tauri::generate_context!())
        .expect("error while running Lockbox");
}
```

`app/src-tauri/tauri.conf.json`:
```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Lockbox",
  "version": "0.1.0",
  "identifier": "app.lockbox.mac",
  "build": {
    "beforeDevCommand": "pnpm dev",
    "devUrl": "http://localhost:1440",
    "beforeBuildCommand": "pnpm build",
    "frontendDist": "../dist"
  },
  "app": {
    "windows": [
      {
        "label": "main",
        "title": "Lockbox",
        "width": 1180,
        "height": 760,
        "minWidth": 900,
        "minHeight": 560,
        "backgroundColor": "#121418"
      }
    ],
    "security": {
      "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src ipc: http://ipc.localhost"
    }
  },
  "bundle": {
    "active": true,
    "targets": ["app", "dmg"],
    "category": "Utility",
    "icon": ["icons/32x32.png", "icons/128x128.png", "icons/128x128@2x.png", "icons/icon.icns"],
    "macOS": { "minimumSystemVersion": "13.0" }
  }
}
```

`app/src-tauri/capabilities/default.json`:
```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "windows": ["main"],
  "permissions": ["core:default", "dialog:allow-open"]
}
```

Root `Cargo.toml`: `members = ["crates/lockbox-core", "crates/lockbox-session", "app/src-tauri"]` (keep `default-members` as is).
Root `.gitignore`: add a line `app/src-tauri/gen/`.

Run: `cargo build -p lockbox-app && cargo clippy -p lockbox-app -- -D warnings`
Expected: builds (first build takes a few minutes).

- [ ] **Step 5: CI** — `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy -p lockbox-core -p lockbox-session --all-targets -- -D warnings
      - run: cargo test -p lockbox-core -p lockbox-session

  frontend:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: app
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
          cache-dependency-path: app/pnpm-lock.yaml
      - run: pnpm install --frozen-lockfile
      - run: pnpm typecheck
      - run: pnpm test
```

(The Tauri crate is not built in CI: it needs WebKit system libraries; it is built locally on macOS.)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore .github app
git commit -m "Scaffold the Tauri desktop app, icon and CI"
```

---

### Task 10: Tauri commands and housekeeping

**Files:**
- Modify: `app/src-tauri/Cargo.toml`, `app/src-tauri/src/lib.rs`
- Create: `app/src-tauri/src/commands.rs`

- [ ] **Step 1: Dependencies** — add to `[dependencies]` in `app/src-tauri/Cargo.toml`:

```toml
lockbox-core = { path = "../../crates/lockbox-core" }
lockbox-session = { path = "../../crates/lockbox-session" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["serde"] }
```

- [ ] **Step 2: Commands** — `app/src-tauri/src/commands.rs` (all logic lives in `Session`, which is tested; these are one-line adapters):

```rust
//! Tauri commands: each locks the session and calls one `Session` method.

use std::path::PathBuf;

use lockbox_core::model::{Item, ItemKind};
use lockbox_session::dto::{
    GeneratorRequest, ImportPreview, ImportResult, ItemFilter, ItemSummary, TotpCode, VaultDto,
};
use lockbox_session::{CmdError, CmdResult, ErrorKind, Status};
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;

use crate::{lock_session, now, AppState};

#[tauri::command(async)]
pub fn status(state: State<'_, AppState>) -> CmdResult<Status> {
    Ok(lock_session(&state).status())
}

#[tauri::command(async)]
pub fn create_vault_file(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).create(&password, now())
}

#[tauri::command(async)]
pub fn unlock(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).unlock(&password, now())
}

#[tauri::command(async)]
pub fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    lock_session(&state).lock();
    Ok(())
}

#[tauri::command(async)]
pub fn vaults(state: State<'_, AppState>) -> CmdResult<Vec<VaultDto>> {
    lock_session(&state).vaults(now())
}

#[tauri::command(async)]
pub fn create_vault(state: State<'_, AppState>, name: String) -> CmdResult<VaultDto> {
    lock_session(&state).create_vault(&name, now())
}

#[tauri::command(async)]
pub fn items(state: State<'_, AppState>, filter: ItemFilter) -> CmdResult<Vec<ItemSummary>> {
    lock_session(&state).items(&filter, now())
}

#[tauri::command(async)]
pub fn item(state: State<'_, AppState>, id: Uuid) -> CmdResult<Item> {
    lock_session(&state).item(id, now())
}

#[tauri::command(async)]
pub fn new_item(state: State<'_, AppState>, vault_id: Uuid, kind: ItemKind) -> CmdResult<Item> {
    lock_session(&state).new_item(vault_id, kind, now())
}

#[tauri::command(async)]
pub fn save_item(state: State<'_, AppState>, item: Item) -> CmdResult<Item> {
    lock_session(&state).save_item(item, now())
}

#[tauri::command(async)]
pub fn delete_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).delete_item(id, now())
}

#[tauri::command(async)]
pub fn totp(state: State<'_, AppState>, id: Uuid) -> CmdResult<Option<TotpCode>> {
    lock_session(&state).totp(id, now())
}

#[tauri::command(async)]
pub fn copy_field(app: AppHandle, state: State<'_, AppState>, id: Uuid, field: String) -> CmdResult<()> {
    let text = lock_session(&state).copy_value(id, &field, now())?;
    app.clipboard()
        .write_text(text)
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Clipboard: {e}")))
}

#[tauri::command(async)]
pub fn generate(request: GeneratorRequest) -> CmdResult<String> {
    request.generate()
}

#[tauri::command(async)]
pub fn import_preview(state: State<'_, AppState>, path: String) -> CmdResult<ImportPreview> {
    lock_session(&state).import_preview(&PathBuf::from(path), now())
}

#[tauri::command(async)]
pub fn import_apply(state: State<'_, AppState>) -> CmdResult<ImportResult> {
    lock_session(&state).import_apply(now())
}
```

- [ ] **Step 3: Wiring and housekeeping** — replace `app/src-tauri/src/lib.rs`:

```rust
mod commands;

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lockbox_core::crypto::KdfParams;
use lockbox_session::Session;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// The one session behind every command.
pub struct AppState(Mutex<Session>);

/// A poisoned lock only means a command panicked mid-way; the session itself stays usable.
pub(crate) fn lock_session(state: &AppState) -> MutexGuard<'_, Session> {
    state.0.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let path = app.path().app_data_dir()?.join("lockbox.db");
            app.manage(AppState(Mutex::new(Session::new(path, KdfParams::DEFAULT, now()))));
            let handle = app.handle().clone();
            std::thread::spawn(move || housekeeping(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_vault_file,
            commands::unlock,
            commands::lock,
            commands::vaults,
            commands::create_vault,
            commands::items,
            commands::item,
            commands::new_item,
            commands::save_item,
            commands::delete_item,
            commands::totp,
            commands::copy_field,
            commands::generate,
            commands::import_preview,
            commands::import_apply,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lockbox");
}

/// Every two seconds: lock when idle (and tell the window), clear the clipboard once our copy
/// has expired — but only if it still holds our copy.
fn housekeeping(app: AppHandle) {
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let state = app.state::<AppState>();
        let t = now();
        let (locked, clipboard_pending) = {
            let mut session = lock_session(&state);
            (session.tick(t), session.clipboard_pending())
        };
        if locked {
            let _ = app.emit("locked", ());
        }
        if clipboard_pending {
            let current = app.clipboard().read_text().ok();
            if lock_session(&state).clipboard_should_clear(t, current.as_deref()) {
                let _ = app.clipboard().clear();
            }
        }
    }
}
```

- [ ] **Step 4: Build and lint**

Run: `cargo build -p lockbox-app && cargo clippy -p lockbox-app -- -D warnings && cargo fmt --all --check`
Expected: clean. If a plugin API differs (e.g. clipboard `clear`), adapt minimally and note it in the report.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri Cargo.lock
git commit -m "Add Tauri commands and housekeeping thread"
```

---

### Task 11: Frontend API, App routing, Setup and Unlock

**Files:**
- Create: `app/src/api.ts`, `app/src/components/Setup.tsx`, `Setup.test.tsx`, `Unlock.tsx`, `Unlock.test.tsx`, `Main.tsx` (stub)
- Modify: `app/src/App.tsx`, `app/src/App.test.tsx`

- [ ] **Step 1: The API module** (types only + thin `invoke` wrappers; no test of its own) — `app/src/api.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Status = "new" | "locked" | "unlocked";

export type ErrorKind = "wrongPassword" | "locked" | "throttled" | "notFound" | "invalid" | "other";
export interface CmdError {
  kind: ErrorKind;
  message: string;
  retryAfter?: number;
}

export function isCmdError(e: unknown): e is CmdError {
  return typeof e === "object" && e !== null && "kind" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  return isCmdError(e) ? e.message : String(e);
}

export type ItemKind = "login" | "secure_note" | "credit_card" | "identity" | "password" | "api_credential";

/** Matches lockbox-core's `FieldValue` JSON. */
export type FieldValue =
  | { type: "text" | "concealed" | "email" | "url" | "totp" | "phone"; value: string }
  | { type: "date"; value: number }
  | { type: "month_year"; value: number };

export interface Field {
  id: string;
  label: string;
  value: FieldValue;
  purpose?: "username" | "password";
}

export interface Section {
  id: string;
  title: string;
  fields: Field[];
}

/** lockbox-core's `Item`, snake_case as stored. Send it back unchanged except edited fields. */
export interface Item {
  id: string;
  vault_id: string;
  kind: ItemKind;
  title: string;
  tags: string[];
  favorite: boolean;
  urls: string[];
  fields: Field[];
  sections: Section[];
  notes: string;
  password_history: { value: string; changed_at: number }[];
  attachments: { id: string; name: string; size: number }[];
  created_at: number;
  updated_at: number;
}

export interface Vault {
  id: string;
  name: string;
  itemCount: number;
}

export interface ItemSummary {
  id: string;
  vaultId: string;
  kind: ItemKind | null;
  title: string;
  subtitle: string;
  favorite: boolean;
  hasTotp: boolean;
  updatedAt: number;
  damaged: boolean;
}

export interface ItemFilter {
  vaultId?: string | null;
  query?: string;
  favorites?: boolean;
}

export interface TotpCode {
  code: string;
  secondsLeft: number;
  period: number;
}

export interface GeneratorRequest {
  kind: "password" | "passphrase";
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface ImportPreview {
  vaults: { name: string; items: number }[];
  skipped: { title: string; reason: string }[];
  totalItems: number;
}

export interface ImportResult {
  vaults: number;
  items: number;
  attachments: number;
}

export const api = {
  status: () => invoke<Status>("status"),
  create: (password: string) => invoke<void>("create_vault_file", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),
  vaults: () => invoke<Vault[]>("vaults"),
  createVault: (name: string) => invoke<Vault>("create_vault", { name }),
  items: (filter: ItemFilter) => invoke<ItemSummary[]>("items", { filter }),
  item: (id: string) => invoke<Item>("item", { id }),
  newItem: (vaultId: string, kind: ItemKind) => invoke<Item>("new_item", { vaultId, kind }),
  saveItem: (item: Item) => invoke<Item>("save_item", { item }),
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  totp: (id: string) => invoke<TotpCode | null>("totp", { id }),
  copyField: (id: string, field: string) => invoke<void>("copy_field", { id, field }),
  generate: (request: GeneratorRequest) => invoke<string>("generate", { request }),
  importPreview: (path: string) => invoke<ImportPreview>("import_preview", { path }),
  importApply: () => invoke<ImportResult>("import_apply"),
  onLocked: (callback: () => void): Promise<UnlistenFn> => listen("locked", () => callback()),
};
```

- [ ] **Step 2: Write the failing tests**

`app/src/components/Setup.test.tsx`:
```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Setup } from "./Setup";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, create: vi.fn() } };
});

beforeEach(() => vi.mocked(api.create).mockReset());

test("creates the vault once both passwords match and are long enough", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  vi.mocked(api.create).mockResolvedValue(undefined);
  render(<Setup onDone={onDone} />);
  const submit = screen.getByRole("button", { name: "Create vault" });
  expect(submit).toBeDisabled();

  await user.type(screen.getByLabelText("Master password"), "short");
  expect(screen.getByText("Use at least 10 characters")).toBeInTheDocument();
  await user.clear(screen.getByLabelText("Master password"));
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Confirm password"), "correct horse");
  expect(screen.getByText("Passwords don't match")).toBeInTheDocument();
  expect(submit).toBeDisabled();
  await user.type(screen.getByLabelText("Confirm password"), " battery");

  await user.click(submit);
  expect(api.create).toHaveBeenCalledWith("correct horse battery");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("shows a backend error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.create).mockRejectedValue({ kind: "invalid", message: "A vault already exists on this Mac" });
  render(<Setup onDone={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Confirm password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Create vault" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("A vault already exists on this Mac");
});
```

`app/src/components/Unlock.test.tsx`:
```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Unlock } from "./Unlock";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, unlock: vi.fn() } };
});

beforeEach(() => vi.mocked(api.unlock).mockReset());

test("unlocks with the master password", async () => {
  const user = userEvent.setup();
  const onUnlocked = vi.fn();
  vi.mocked(api.unlock).mockResolvedValue(undefined);
  render(<Unlock onUnlocked={onUnlocked} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(api.unlock).toHaveBeenCalledWith("correct horse battery");
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
});

test("wrong password shows an error and clears the field", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "wrongPassword", message: "incorrect password" });
  render(<Unlock onUnlocked={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect password");
  expect(screen.getByLabelText("Master password")).toHaveValue("");
});

test("throttling disables the button and shows the wait", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "throttled", message: "Too many attempts. Try again in 3 s.", retryAfter: 3 });
  render(<Unlock onUnlocked={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 3 s.");
  await user.type(screen.getByLabelText("Master password"), "x");
  expect(screen.getByRole("button", { name: "Unlock" })).toBeDisabled();
});
```

Replace `app/src/App.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "./api";
import { App } from "./App";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      status: vi.fn(),
      lock: vi.fn(),
      vaults: vi.fn().mockResolvedValue([]),
      items: vi.fn().mockResolvedValue([]),
      onLocked: vi.fn().mockResolvedValue(() => {}),
    },
  };
});

beforeEach(() => vi.mocked(api.status).mockReset());

test("first run shows setup", async () => {
  vi.mocked(api.status).mockResolvedValue("new");
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Create your Lockbox" })).toBeInTheDocument();
});

test("a locked vault shows the unlock screen", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Unlock" })).toBeInTheDocument();
});

test("an unlocked vault shows the main window", async () => {
  vi.mocked(api.status).mockResolvedValue("unlocked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Lock" })).toBeInTheDocument();
});
```

- [ ] **Step 3: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (missing `Setup`, `Unlock`; App still the placeholder).

- [ ] **Step 4: Implement**

`app/src/components/Setup.tsx`:
```tsx
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";

const MIN_LENGTH = 10;

export function Setup({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const tooShort = password.length > 0 && password.length < MIN_LENGTH;
  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = password.length >= MIN_LENGTH && confirm === password;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      await api.create(password);
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>Create your Lockbox</h1>
        <p className="muted">
          Your master password encrypts everything. It can't be recovered, so write it down and keep it somewhere safe.
        </p>
        <label>
          Master password
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {tooShort && <p className="error">Use at least {MIN_LENGTH} characters</p>}
        <label>
          Confirm password
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
        {mismatch && <p className="error">Passwords don't match</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button className="primary" type="submit" disabled={!valid || busy}>
          {busy ? "Creating…" : "Create vault"}
        </button>
      </form>
    </div>
  );
}
```

`app/src/components/Unlock.tsx`:
```tsx
import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError } from "../api";

export function Unlock({ onUnlocked }: { onUnlocked: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [wait, setWait] = useState(0);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (wait <= 0) return;
    const timer = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(timer);
  }, [wait]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password || wait > 0) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      onUnlocked();
    } catch (err) {
      setPassword("");
      if (isCmdError(err) && err.kind === "throttled") {
        setWait(err.retryAfter ?? 1);
        setError(err.message);
      } else if (isCmdError(err) && err.kind === "wrongPassword") {
        setError("Incorrect password");
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>Lockbox is locked</h1>
        <label>
          Master password
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" role="alert">
            {wait > 0 ? `Too many attempts. Try again in ${wait} s.` : error}
          </p>
        )}
        <button className="primary" type="submit" disabled={busy || !password || wait > 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </div>
  );
}
```

`app/src/components/Main.tsx` (stub; Task 16 replaces it):
```tsx
export function Main({ onLock }: { onLock: () => void }) {
  return (
    <div className="center">
      <button onClick={onLock}>Lock</button>
    </div>
  );
}
```

Replace `app/src/App.tsx`:
```tsx
import { useCallback, useEffect, useState } from "react";
import { api, type Status } from "./api";
import { Main } from "./components/Main";
import { Setup } from "./components/Setup";
import { Unlock } from "./components/Unlock";

export function App() {
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    api.status().then(setStatus);
    const unlisten = api.onLocked(() => setStatus("locked"));
    return () => {
      unlisten.then((stop) => stop());
    };
  }, []);

  const lock = useCallback(async () => {
    await api.lock();
    setStatus("locked");
  }, []);

  if (status === null) return null;
  if (status === "new") return <Setup onDone={() => setStatus("unlocked")} />;
  if (status === "locked") return <Unlock onUnlocked={() => setStatus("unlocked")} />;
  return <Main onLock={lock} />;
}
```

- [ ] **Step 5: Run to verify pass**

Run: `pnpm test && pnpm typecheck`
Expected: 8 tests pass; no type errors.

- [ ] **Step 6: Commit**

```bash
git add app/src
git commit -m "Add frontend API, setup and unlock screens"
```

---

### Task 12: Sidebar and item list

**Files:**
- Create: `app/src/format.ts`, `app/src/format.test.ts`, `app/src/components/Sidebar.tsx`, `Sidebar.test.tsx`, `ItemList.tsx`, `ItemList.test.tsx`

- [ ] **Step 1: Write the failing tests**

`app/src/format.test.ts`:
```ts
import { expect, test } from "vitest";
import { fieldText, formatCode } from "./format";

test("field values as text", () => {
  expect(fieldText({ type: "text", value: "ivan" })).toBe("ivan");
  expect(fieldText({ type: "month_year", value: 202712 })).toBe("12/2027");
  expect(fieldText({ type: "date", value: 631152000 })).toBe("1990-01-01");
});

test("one-time codes are grouped", () => {
  expect(formatCode("123456")).toBe("123 456");
  expect(formatCode("12345678")).toBe("1234 5678");
  expect(formatCode("1234567")).toBe("1234567");
});
```

`app/src/components/Sidebar.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Sidebar } from "./Sidebar";

const vaults = [
  { id: "v1", name: "Personal", itemCount: 3 },
  { id: "v2", name: "Datagile", itemCount: 2 },
];

function setup() {
  const props = { onSelect: vi.fn(), onNewVault: vi.fn(), onImport: vi.fn(), onLock: vi.fn() };
  render(<Sidebar vaults={vaults} selection={{ kind: "all" }} {...props} />);
  return props;
}

test("lists vaults with counts and selects them", async () => {
  const user = userEvent.setup();
  const props = setup();
  expect(screen.getByRole("button", { name: /All items/ })).toHaveTextContent("5");
  expect(screen.getByRole("button", { name: /All items/ })).toHaveAttribute("aria-current", "true");
  await user.click(screen.getByRole("button", { name: /Datagile/ }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "vault", id: "v2" });
  await user.click(screen.getByRole("button", { name: "Favorites" }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "favorites" });
});

test("creates a vault, imports and locks", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(screen.getByRole("button", { name: "+ New vault" }));
  await user.type(screen.getByLabelText("Vault name"), "Work{Enter}");
  expect(props.onNewVault).toHaveBeenCalledWith("Work");
  await user.click(screen.getByRole("button", { name: "Import from 1Password…" }));
  expect(props.onImport).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Lock" }));
  expect(props.onLock).toHaveBeenCalled();
});
```

`app/src/components/ItemList.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import type { ItemSummary } from "../api";
import { ItemList } from "./ItemList";

const summary = (over: Partial<ItemSummary>): ItemSummary => ({
  id: "i1", vaultId: "v1", kind: "login", title: "GitHub", subtitle: "ivan",
  favorite: false, hasTotp: false, updatedAt: 0, damaged: false, ...over,
});

function setup(items: ItemSummary[], query = "") {
  const props = { onQuery: vi.fn(), onSelect: vi.fn(), onNew: vi.fn() };
  render(<ItemList items={items} query={query} selectedId={null} canCreate {...props} />);
  return props;
}

test("shows items and selects one", async () => {
  const user = userEvent.setup();
  const props = setup([summary({}), summary({ id: "i2", title: "Bank", subtitle: "", favorite: true })]);
  expect(screen.getByText("ivan")).toBeInTheDocument();
  expect(screen.getByText("★ Bank")).toBeInTheDocument();
  await user.click(screen.getByText("GitHub"));
  expect(props.onSelect).toHaveBeenCalledWith("i1");
});

test("search reports every change", async () => {
  const user = userEvent.setup();
  const props = setup([]);
  await user.type(screen.getByLabelText("Search"), "g");
  expect(props.onQuery).toHaveBeenCalledWith("g");
  expect(screen.getByText("No items yet")).toBeInTheDocument();
});

test("new item menu offers every kind", async () => {
  const user = userEvent.setup();
  const props = setup([]);
  await user.click(screen.getByRole("button", { name: "+ New" }));
  expect(screen.getAllByRole("menuitem")).toHaveLength(6);
  await user.click(screen.getByRole("menuitem", { name: "Secure note" }));
  expect(props.onNew).toHaveBeenCalledWith("secure_note");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
});

test("damaged items are marked and an empty search says so", () => {
  setup([summary({ title: "Damaged item", subtitle: "This item can't be decrypted", kind: null, damaged: true })], "x");
  expect(screen.getByText("Damaged item")).toHaveClass("damaged");
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (modules not found).

- [ ] **Step 3: Implement**

`app/src/format.ts`:
```ts
import type { FieldValue, ItemKind } from "./api";

export const KIND_LABEL: Record<ItemKind, string> = {
  login: "Login",
  secure_note: "Secure note",
  credit_card: "Credit card",
  identity: "Identity",
  password: "Password",
  api_credential: "API credential",
};

export const NEW_KINDS: ItemKind[] = ["login", "secure_note", "password", "credit_card", "identity", "api_credential"];

export function fieldText(value: FieldValue): string {
  switch (value.type) {
    case "date":
      return new Date(value.value * 1000).toISOString().slice(0, 10);
    case "month_year":
      return `${String(value.value % 100).padStart(2, "0")}/${Math.floor(value.value / 100)}`;
    default:
      return value.value;
  }
}

export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
```

`app/src/components/Sidebar.tsx`:
```tsx
import { useState, type FormEvent } from "react";
import type { Vault } from "../api";

export type Selection = { kind: "all" } | { kind: "favorites" } | { kind: "vault"; id: string };

interface Props {
  vaults: Vault[];
  selection: Selection;
  onSelect: (selection: Selection) => void;
  onNewVault: (name: string) => void;
  onImport: () => void;
  onLock: () => void;
}

export function Sidebar({ vaults, selection, onSelect, onNewVault, onImport, onLock }: Props) {
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const total = vaults.reduce((n, v) => n + v.itemCount, 0);
  const isCurrent = (s: Selection) =>
    s.kind === "vault" ? selection.kind === "vault" && selection.id === s.id : selection.kind === s.kind;

  function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    onNewVault(trimmed);
    setName("");
    setNaming(false);
  }

  return (
    <nav className="sidebar" aria-label="Vaults">
      <div className="brand">Lockbox</div>
      <button className="nav" aria-current={isCurrent({ kind: "all" })} onClick={() => onSelect({ kind: "all" })}>
        <span>All items</span>
        <span className="muted">{total}</span>
      </button>
      <button className="nav" aria-current={isCurrent({ kind: "favorites" })} onClick={() => onSelect({ kind: "favorites" })}>
        Favorites
      </button>
      <div className="heading">Vaults</div>
      {vaults.map((v) => (
        <button
          key={v.id}
          className="nav"
          aria-current={isCurrent({ kind: "vault", id: v.id })}
          onClick={() => onSelect({ kind: "vault", id: v.id })}
        >
          <span>{v.name}</span>
          <span className="muted">{v.itemCount}</span>
        </button>
      ))}
      {naming ? (
        <form onSubmit={submit}>
          <input
            aria-label="Vault name"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => !name.trim() && setNaming(false)}
          />
        </form>
      ) : (
        <button className="nav muted" onClick={() => setNaming(true)}>
          + New vault
        </button>
      )}
      <div className="spacer" />
      <button className="nav" onClick={onImport}>
        Import from 1Password…
      </button>
      <button className="nav" onClick={onLock}>
        Lock
      </button>
    </nav>
  );
}
```

`app/src/components/ItemList.tsx`:
```tsx
import { useState } from "react";
import type { ItemKind, ItemSummary } from "../api";
import { KIND_LABEL, NEW_KINDS } from "../format";

interface Props {
  items: ItemSummary[];
  query: string;
  onQuery: (query: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onNew: (kind: ItemKind) => void;
  canCreate: boolean;
}

export function ItemList({ items, query, onQuery, selectedId, onSelect, onNew, canCreate }: Props) {
  const [menu, setMenu] = useState(false);
  return (
    <section className="list" aria-label="Items">
      <div className="toolbar">
        <input type="search" placeholder="Search" aria-label="Search" value={query} onChange={(e) => onQuery(e.target.value)} />
        <button aria-haspopup="menu" aria-expanded={menu} disabled={!canCreate} onClick={() => setMenu((m) => !m)}>
          + New
        </button>
        {menu && (
          <div className="menu" role="menu">
            {NEW_KINDS.map((kind) => (
              <button
                key={kind}
                role="menuitem"
                onClick={() => {
                  setMenu(false);
                  onNew(kind);
                }}
              >
                {KIND_LABEL[kind]}
              </button>
            ))}
          </div>
        )}
      </div>
      {items.length === 0 ? (
        <p className="empty">{query ? "Nothing matches your search" : "No items yet"}</p>
      ) : (
        <ul>
          {items.map((item) => (
            <li key={item.id}>
              <button aria-current={item.id === selectedId} onClick={() => onSelect(item.id)}>
                <span className={item.damaged ? "damaged" : undefined}>
                  {item.favorite ? "★ " : ""}
                  {item.title || "Untitled"}
                </span>
                {item.subtitle && <span className="subtitle">{item.subtitle}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
```

- [ ] **Step 4: Run to verify pass**

Run: `pnpm test && pnpm typecheck`
Expected: 16 tests pass.

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "Add sidebar and item list"
```

---

### Task 13: Item detail with copy, reveal and TOTP

**Files:**
- Create: `app/src/test/fixtures.ts`, `app/src/components/ItemDetail.tsx`, `ItemDetail.test.tsx`

- [ ] **Step 1: Fixture** — `app/src/test/fixtures.ts`:

```ts
import type { Item } from "../api";

export function loginItem(overrides: Partial<Item> = {}): Item {
  return {
    id: "i1",
    vault_id: "v1",
    kind: "login",
    title: "GitHub",
    tags: ["dev"],
    favorite: false,
    urls: ["https://github.com/login"],
    fields: [
      { id: "username", label: "username", value: { type: "text", value: "ivan" }, purpose: "username" },
      { id: "password", label: "password", value: { type: "concealed", value: "hunter2" }, purpose: "password" },
    ],
    sections: [
      {
        id: "s1",
        title: "Security",
        fields: [
          { id: "otp", label: "one-time password", value: { type: "totp", value: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" } },
          { id: "exp", label: "expires", value: { type: "month_year", value: 202712 } },
        ],
      },
    ],
    notes: "main account",
    password_history: [],
    attachments: [],
    created_at: 1,
    updated_at: 2,
    ...overrides,
  };
}
```

- [ ] **Step 2: Write the failing tests** — `app/src/components/ItemDetail.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { loginItem } from "../test/fixtures";
import { ItemDetail } from "./ItemDetail";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, item: vi.fn(), totp: vi.fn(), copyField: vi.fn(), deleteItem: vi.fn() },
  };
});

beforeEach(() => {
  vi.mocked(api.item).mockReset().mockResolvedValue(loginItem());
  vi.mocked(api.totp).mockReset().mockResolvedValue({ code: "123456", secondsLeft: 12, period: 30 });
  vi.mocked(api.copyField).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.deleteItem).mockReset().mockResolvedValue(undefined);
});

function setup() {
  const props = { onEdit: vi.fn(), onDeleted: vi.fn() };
  render(<ItemDetail itemId="i1" {...props} />);
  return props;
}

test("shows fields with concealed values masked until revealed", async () => {
  const user = userEvent.setup();
  setup();
  expect(await screen.findByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  expect(screen.getByText("ivan")).toBeInTheDocument();
  expect(screen.queryByText("hunter2")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Reveal password" }));
  expect(screen.getByText("hunter2")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Security" })).toBeInTheDocument();
  expect(screen.getByText("12/2027")).toBeInTheDocument();
  expect(screen.getByText("main account")).toBeInTheDocument();
  expect(screen.getByText("https://github.com/login")).toBeInTheDocument();
});

test("copies a field and confirms", async () => {
  const user = userEvent.setup();
  setup();
  await user.click(await screen.findByRole("button", { name: "Copy username" }));
  expect(api.copyField).toHaveBeenCalledWith("i1", "username");
  expect(screen.getByRole("status")).toHaveTextContent("Copied");
});

test("shows the current one-time code and copies it", async () => {
  const user = userEvent.setup();
  setup();
  expect(await screen.findByText("123 456")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy one-time password" }));
  expect(api.copyField).toHaveBeenCalledWith("i1", "totp");
});

test("edit and delete", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  expect(props.onEdit).toHaveBeenCalledWith(loginItem());
  await user.click(screen.getByRole("button", { name: "Delete" }));
  await user.click(screen.getByRole("button", { name: "Move to trash" }));
  expect(api.deleteItem).toHaveBeenCalledWith("i1");
  await waitFor(() => expect(props.onDeleted).toHaveBeenCalled());
});

test("shows a load error", async () => {
  vi.mocked(api.item).mockRejectedValue({ kind: "notFound", message: "not found: item i1" });
  setup();
  expect(await screen.findByRole("alert")).toHaveTextContent("not found");
});
```

- [ ] **Step 3: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (module `./ItemDetail` not found).

- [ ] **Step 4: Implement** — `app/src/components/ItemDetail.tsx`:

```tsx
import { useEffect, useState } from "react";
import { api, errorMessage, type Field, type Item, type TotpCode } from "../api";
import { fieldText, formatCode, KIND_LABEL } from "../format";

interface Props {
  itemId: string;
  onEdit: (item: Item) => void;
  onDeleted: () => void;
}

export function ItemDetail({ itemId, onEdit, onDeleted }: Props) {
  const [item, setItem] = useState<Item | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .item(itemId)
      .then((loaded) => live && setItem(loaded))
      .catch((e) => live && setError(errorMessage(e)));
    return () => {
      live = false;
    };
  }, [itemId]);

  if (error) {
    return (
      <div className="banner error" role="alert">
        {error}
      </div>
    );
  }
  if (!item) return null;

  async function copy(fieldId: string) {
    try {
      await api.copyField(itemId, fieldId);
      setCopied(true);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function remove() {
    try {
      await api.deleteItem(itemId);
      onDeleted();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  function toggle(fieldId: string) {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(fieldId)) next.delete(fieldId);
      else next.add(fieldId);
      return next;
    });
  }

  const groups = [{ id: "__main", title: "", fields: item.fields }, ...item.sections].filter((g) => g.fields.length > 0);

  return (
    <article className="item-detail">
      <header>
        <div>
          <span className="kind">{KIND_LABEL[item.kind]}</span>
          <h2>{item.title}</h2>
        </div>
        <div className="actions">
          <button onClick={() => onEdit(item)}>Edit</button>
          {confirmDelete ? (
            <>
              <button className="danger" onClick={remove}>
                Move to trash
              </button>
              <button onClick={() => setConfirmDelete(false)}>Cancel</button>
            </>
          ) : (
            <button onClick={() => setConfirmDelete(true)}>Delete</button>
          )}
        </div>
      </header>
      {item.urls.length > 0 && (
        <div className="urls">
          {item.urls.map((url) => (
            <span key={url}>{url}</span>
          ))}
        </div>
      )}
      {groups.map((group) => (
        <section key={group.id} className="field-group">
          {group.title && <h3>{group.title}</h3>}
          {group.fields.map((field) =>
            field.value.type === "totp" ? (
              <TotpRow key={field.id} itemId={itemId} label={field.label} onCopy={() => copy("totp")} />
            ) : (
              <FieldRow
                key={field.id}
                field={field}
                revealed={revealed.has(field.id)}
                onToggle={() => toggle(field.id)}
                onCopy={() => copy(field.id)}
              />
            ),
          )}
        </section>
      ))}
      {item.notes && (
        <section className="field-group">
          <h3>Notes</h3>
          <div className="field notes">{item.notes}</div>
        </section>
      )}
      {item.tags.length > 0 && <p className="muted">Tags: {item.tags.join(", ")}</p>}
      {item.attachments.length > 0 && (
        <p className="muted">Attachments: {item.attachments.map((a) => a.name).join(", ")}</p>
      )}
      {item.password_history.length > 0 && (
        <p className="muted">Password changed {item.password_history.length} time(s)</p>
      )}
      {copied && (
        <div className="toast" role="status">
          Copied. The clipboard clears in 90 seconds.
        </div>
      )}
    </article>
  );
}

function FieldRow(props: { field: Field; revealed: boolean; onToggle: () => void; onCopy: () => void }) {
  const { field, revealed, onToggle, onCopy } = props;
  const text = fieldText(field.value);
  if (!text) return null;
  const concealed = field.value.type === "concealed";
  return (
    <div className="field">
      <span className="label">{field.label}</span>
      <span className={concealed ? "value mono" : "value"}>{concealed && !revealed ? "••••••••••" : text}</span>
      <span className="field-actions">
        {concealed && (
          <button aria-label={`${revealed ? "Hide" : "Reveal"} ${field.label}`} onClick={onToggle}>
            {revealed ? "Hide" : "Reveal"}
          </button>
        )}
        <button aria-label={`Copy ${field.label}`} onClick={onCopy}>
          Copy
        </button>
      </span>
    </div>
  );
}

function TotpRow({ itemId, label, onCopy }: { itemId: string; label: string; onCopy: () => void }) {
  const [code, setCode] = useState<TotpCode | null>(null);
  const name = label || "one-time password";

  useEffect(() => {
    let live = true;
    const load = () =>
      api
        .totp(itemId)
        .then((c) => live && setCode(c))
        .catch(() => live && setCode(null));
    load();
    const timer = setInterval(load, 1000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [itemId]);

  if (!code) return null;
  return (
    <div className="field">
      <span className="label">{name}</span>
      <span className="value mono">
        {formatCode(code.code)} <span className="muted">{code.secondsLeft}s</span>
      </span>
      <span className="field-actions">
        <button aria-label={`Copy ${name}`} onClick={onCopy}>
          Copy
        </button>
      </span>
    </div>
  );
}
```

- [ ] **Step 5: Run to verify pass**

Run: `pnpm test && pnpm typecheck`
Expected: 21 tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/src
git commit -m "Add item detail with copy, reveal and live TOTP"
```

---

### Task 14: Password generator and item editor

**Files:**
- Create: `app/src/components/Generator.tsx`, `Generator.test.tsx`, `ItemEditor.tsx`, `ItemEditor.test.tsx`

- [ ] **Step 1: Write the failing tests**

`app/src/components/Generator.test.tsx`:
```tsx
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Generator } from "./Generator";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, generate: vi.fn() } };
});

beforeEach(() => vi.mocked(api.generate).mockReset().mockResolvedValue("Gen-123"));

const lastRequest = () => vi.mocked(api.generate).mock.lastCall![0];

test("generates with defaults and on every option change", async () => {
  render(<Generator onUse={vi.fn()} />);
  expect(await screen.findByText("Gen-123")).toBeInTheDocument();
  expect(lastRequest()).toMatchObject({ kind: "password", length: 20, symbols: true });

  fireEvent.change(screen.getByLabelText(/Length/), { target: { value: "32" } });
  await waitFor(() => expect(lastRequest().length).toBe(32));

  await userEvent.setup().click(screen.getByRole("button", { name: "Passphrase" }));
  await waitFor(() => expect(lastRequest().kind).toBe("passphrase"));
  expect(screen.getByLabelText(/Words/)).toBeInTheDocument();
});

test("use passes the generated value", async () => {
  const user = userEvent.setup();
  const onUse = vi.fn();
  render(<Generator onUse={onUse} />);
  await screen.findByText("Gen-123");
  await user.click(screen.getByRole("button", { name: "Use" }));
  expect(onUse).toHaveBeenCalledWith("Gen-123");
});
```

`app/src/components/ItemEditor.test.tsx`:
```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type Item } from "../api";
import { loginItem } from "../test/fixtures";
import { ItemEditor } from "./ItemEditor";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, saveItem: vi.fn(), generate: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.saveItem).mockReset().mockImplementation(async (item: Item) => item);
  vi.mocked(api.generate).mockReset().mockResolvedValue("Gen-123");
});

const saved = () => vi.mocked(api.saveItem).mock.lastCall![0];

test("edits basic fields and keeps everything else", async () => {
  const user = userEvent.setup();
  const onSave = vi.fn();
  render(<ItemEditor item={loginItem()} onSave={onSave} onCancel={vi.fn()} />);

  await user.clear(screen.getByLabelText("Title"));
  await user.type(screen.getByLabelText("Title"), "GitHub work");
  await user.clear(screen.getByLabelText("Password"));
  await user.type(screen.getByLabelText("Password"), "new-pass");
  await user.clear(screen.getByLabelText("Websites"));
  await user.type(screen.getByLabelText("Websites"), "https://github.com{Enter}https://gist.github.com");
  await user.clear(screen.getByLabelText("Tags"));
  await user.type(screen.getByLabelText("Tags"), "dev, work");
  await user.click(screen.getByLabelText("Favorite"));
  await user.click(screen.getByRole("button", { name: "Save" }));

  expect(saved().title).toBe("GitHub work");
  expect(saved().fields[1].value).toEqual({ type: "concealed", value: "new-pass" });
  expect(saved().fields[0].value).toEqual({ type: "text", value: "ivan" });
  expect(saved().urls).toEqual(["https://github.com", "https://gist.github.com"]);
  expect(saved().tags).toEqual(["dev", "work"]);
  expect(saved().favorite).toBe(true);
  expect(saved().sections).toEqual(loginItem().sections);
  await waitFor(() => expect(onSave).toHaveBeenCalled());
});

test("shows a save error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.saveItem).mockRejectedValue({ kind: "invalid", message: "Title is required" });
  render(<ItemEditor item={loginItem({ title: "" })} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Title is required");
});

test("the generator fills the password", async () => {
  const user = userEvent.setup();
  render(<ItemEditor item={loginItem()} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Generate" }));
  await screen.findByText("Gen-123");
  await user.click(screen.getByRole("button", { name: "Use" }));
  expect(screen.getByLabelText("Password")).toHaveValue("Gen-123");
});

test("cancel", async () => {
  const user = userEvent.setup();
  const onCancel = vi.fn();
  render(<ItemEditor item={loginItem()} onSave={vi.fn()} onCancel={onCancel} />);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(onCancel).toHaveBeenCalled();
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (modules not found).

- [ ] **Step 3: Implement**

`app/src/components/Generator.tsx`:
```tsx
import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type GeneratorRequest } from "../api";

const DEFAULTS: GeneratorRequest = {
  kind: "password",
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  words: 5,
  separator: "-",
  capitalize: false,
  includeNumber: false,
};

type Toggle = "lowercase" | "uppercase" | "digits" | "symbols" | "avoidAmbiguous" | "capitalize" | "includeNumber";

export function Generator({ onUse }: { onUse: (value: string) => void }) {
  const [request, setRequest] = useState<GeneratorRequest>(DEFAULTS);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(() => {
    api
      .generate(request)
      .then((v) => {
        setValue(v);
        setError(null);
      })
      .catch((e) => setError(errorMessage(e)));
  }, [request]);

  useEffect(regenerate, [regenerate]);

  const set = (patch: Partial<GeneratorRequest>) => setRequest((r) => ({ ...r, ...patch }));
  const check = (key: Toggle, label: string) => (
    <label className="check">
      <input
        type="checkbox"
        checked={request[key]}
        onChange={(e) => set({ [key]: e.target.checked } as Partial<GeneratorRequest>)}
      />
      {label}
    </label>
  );

  return (
    <div className="generator" role="group" aria-label="Password generator">
      <div className="segmented">
        <button type="button" aria-pressed={request.kind === "password"} onClick={() => set({ kind: "password" })}>
          Password
        </button>
        <button type="button" aria-pressed={request.kind === "passphrase"} onClick={() => set({ kind: "passphrase" })}>
          Passphrase
        </button>
      </div>
      <output className="mono generated">{value}</output>
      {request.kind === "password" ? (
        <>
          <label>
            Length {request.length}
            <input type="range" min={8} max={100} value={request.length} onChange={(e) => set({ length: Number(e.target.value) })} />
          </label>
          <div className="checks">
            {check("lowercase", "a–z")}
            {check("uppercase", "A–Z")}
            {check("digits", "0–9")}
            {check("symbols", "Symbols")}
            {check("avoidAmbiguous", "Avoid look-alikes")}
          </div>
        </>
      ) : (
        <>
          <label>
            Words {request.words}
            <input type="range" min={3} max={10} value={request.words} onChange={(e) => set({ words: Number(e.target.value) })} />
          </label>
          <label>
            Separator
            <input value={request.separator} maxLength={3} onChange={(e) => set({ separator: e.target.value })} />
          </label>
          <div className="checks">
            {check("capitalize", "Capitalize")}
            {check("includeNumber", "Add a number")}
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <button type="button" onClick={regenerate}>
          Regenerate
        </button>
        <button type="button" className="primary" disabled={!value} onClick={() => onUse(value)}>
          Use
        </button>
      </div>
    </div>
  );
}
```

`app/src/components/ItemEditor.tsx`:
```tsx
import { useState, type FormEvent } from "react";
import { api, errorMessage, type FieldValue, type Item } from "../api";
import { KIND_LABEL } from "../format";
import { Generator } from "./Generator";

interface Props {
  item: Item;
  onSave: (saved: Item) => void;
  onCancel: () => void;
}

/** Edits the common fields; other fields and sections are passed through unchanged. */
export function ItemEditor({ item, onSave, onCancel }: Props) {
  const [draft, setDraft] = useState<Item>(item);
  const [urls, setUrls] = useState(item.urls.join("\n"));
  const [tags, setTags] = useState(item.tags.join(", "));
  const [showPassword, setShowPassword] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const usernameIndex = draft.fields.findIndex((f) => f.purpose === "username");
  const passwordIndex = draft.fields.findIndex((f) => f.purpose === "password");
  const text = (index: number) => {
    const value = draft.fields[index]?.value;
    return value && typeof value.value === "string" ? value.value : "";
  };
  const setField = (index: number, value: string) =>
    setDraft((d) => ({
      ...d,
      fields: d.fields.map((f, i) => (i === index ? { ...f, value: { type: f.value.type, value } as FieldValue } : f)),
    }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const saved = await api.saveItem({
        ...draft,
        urls: urls.split("\n").map((u) => u.trim()).filter(Boolean),
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
      onSave(saved);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="editor" onSubmit={submit}>
      <header>
        <div>
          <span className="kind">{KIND_LABEL[draft.kind]}</span>
          <h2>{item.title ? "Edit item" : "New item"}</h2>
        </div>
        <div className="actions">
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={busy}>
            Save
          </button>
        </div>
      </header>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      <label>
        Title
        <input autoFocus value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
      </label>
      {usernameIndex >= 0 && (
        <label>
          Username
          <input value={text(usernameIndex)} onChange={(e) => setField(usernameIndex, e.target.value)} />
        </label>
      )}
      {passwordIndex >= 0 && (
        <>
          <div className="row">
            <label>
              Password
              <input
                className="mono"
                type={showPassword ? "text" : "password"}
                value={text(passwordIndex)}
                onChange={(e) => setField(passwordIndex, e.target.value)}
              />
            </label>
            <button type="button" onClick={() => setShowPassword((s) => !s)}>
              {showPassword ? "Hide" : "Show"}
            </button>
            <button type="button" onClick={() => setGenerating((g) => !g)}>
              Generate
            </button>
          </div>
          {generating && (
            <Generator
              onUse={(value) => {
                setField(passwordIndex, value);
                setGenerating(false);
              }}
            />
          )}
        </>
      )}
      {draft.kind === "login" && (
        <label>
          Websites
          <textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} />
        </label>
      )}
      <label>
        Notes
        <textarea rows={4} value={draft.notes} onChange={(e) => setDraft({ ...draft, notes: e.target.value })} />
      </label>
      <label>
        Tags
        <input value={tags} onChange={(e) => setTags(e.target.value)} />
      </label>
      <label className="check">
        <input type="checkbox" checked={draft.favorite} onChange={(e) => setDraft({ ...draft, favorite: e.target.checked })} />
        Favorite
      </label>
      {draft.sections.length > 0 && <p className="muted">Other fields are kept as they are.</p>}
    </form>
  );
}
```

- [ ] **Step 4: Run to verify pass**

Run: `pnpm test && pnpm typecheck`
Expected: 27 tests pass.

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "Add password generator and item editor"
```

---

### Task 15: Import dialog

**Files:**
- Create: `app/src/components/ImportDialog.tsx`, `ImportDialog.test.tsx`

- [ ] **Step 1: Write the failing tests** — `app/src/components/ImportDialog.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { open } from "@tauri-apps/plugin-dialog";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { ImportDialog } from "./ImportDialog";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, importPreview: vi.fn(), importApply: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(open).mockReset().mockResolvedValue("/Users/me/Downloads/export.1pux");
  vi.mocked(api.importPreview).mockReset().mockResolvedValue({
    vaults: [{ name: "Personal", items: 120 }, { name: "Datagile", items: 34 }],
    skipped: [{ title: "Passport scan / passport.pdf", reason: "attachment missing from export" }],
    totalItems: 154,
  });
  vi.mocked(api.importApply).mockReset().mockResolvedValue({ vaults: 2, items: 154, attachments: 3 });
});

test("pick, preview, import", async () => {
  const user = userEvent.setup();
  const onImported = vi.fn();
  const onClose = vi.fn();
  render(<ImportDialog onClose={onClose} onImported={onImported} />);

  await user.click(screen.getByRole("button", { name: "Choose export file…" }));
  expect(api.importPreview).toHaveBeenCalledWith("/Users/me/Downloads/export.1pux");
  expect(await screen.findByText("Personal — 120 items")).toBeInTheDocument();
  expect(screen.getByText("Datagile — 34 items")).toBeInTheDocument();
  expect(screen.getByText(/attachment missing from export/)).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Import 154 items" }));
  expect(await screen.findByText(/Imported 154 items into 2 vaults/)).toBeInTheDocument();
  expect(onImported).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Done" }));
  expect(onClose).toHaveBeenCalled();
});

test("cancelling the file picker stays on the first step", async () => {
  const user = userEvent.setup();
  vi.mocked(open).mockResolvedValue(null);
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Choose export file…" }));
  expect(api.importPreview).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Choose export file…" })).toBeInTheDocument();
});

test("shows parse errors and can be cancelled", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  vi.mocked(api.importPreview).mockRejectedValue({ kind: "invalid", message: "invalid data: not a .1pux file" });
  render(<ImportDialog onClose={onClose} onImported={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Choose export file…" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("not a .1pux file");
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(onClose).toHaveBeenCalled();
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (module `./ImportDialog` not found).

- [ ] **Step 3: Implement** — `app/src/components/ImportDialog.tsx`:

```tsx
import { open } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import { api, errorMessage, type ImportPreview, type ImportResult } from "../api";

type Step = { kind: "pick" } | { kind: "preview"; preview: ImportPreview } | { kind: "done"; result: ImportResult };

export function ImportDialog({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [step, setStep] = useState<Step>({ kind: "pick" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function choose() {
    setError(null);
    const path = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "1Password export", extensions: ["1pux", "csv"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    try {
      setStep({ kind: "preview", preview: await api.importPreview(path) });
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.importApply();
      setStep({ kind: "done", result });
      onImported();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal" role="dialog" aria-modal="true" aria-labelledby="import-title">
        <h2 id="import-title">Import from 1Password</h2>
        {step.kind === "pick" && (
          <>
            <p className="muted">
              In 1Password choose File → Export, pick your account and the <b>1PUX</b> format (it keeps vaults,
              attachments and one-time codes). CSV works too but has less.
            </p>
            <button className="primary" onClick={choose} disabled={busy}>
              Choose export file…
            </button>
          </>
        )}
        {step.kind === "preview" && (
          <>
            <p>
              {step.preview.totalItems} items will be added as new vaults:
            </p>
            <ul>
              {step.preview.vaults.map((v) => (
                <li key={v.name}>
                  {v.name} — {v.items} items
                </li>
              ))}
            </ul>
            {step.preview.skipped.length > 0 && (
              <details open>
                <summary>{step.preview.skipped.length} not imported</summary>
                <ul>
                  {step.preview.skipped.map((s, i) => (
                    <li key={i}>
                      <b>{s.title}</b>: {s.reason}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <button className="primary" onClick={apply} disabled={busy}>
              Import {step.preview.totalItems} items
            </button>
          </>
        )}
        {step.kind === "done" && (
          <>
            <p>
              Imported {step.result.items} items into {step.result.vaults} vaults ({step.result.attachments} attachments).
            </p>
            <p className="muted">Delete the export file now: it is not encrypted.</p>
            <button className="primary" onClick={onClose}>
              Done
            </button>
          </>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {step.kind !== "done" && (
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run to verify pass**

Run: `pnpm test && pnpm typecheck`
Expected: 30 tests pass.

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "Add 1Password import dialog"
```

---

### Task 16: Main window wiring

**Files:**
- Modify: `app/src/components/Main.tsx` (replace the stub)
- Create: `app/src/components/Main.test.tsx`

- [ ] **Step 1: Write the failing tests** — `app/src/components/Main.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary } from "../api";
import { loginItem } from "../test/fixtures";
import { Main } from "./Main";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      vaults: vi.fn(),
      items: vi.fn(),
      item: vi.fn(),
      totp: vi.fn(),
      newItem: vi.fn(),
      saveItem: vi.fn(),
      createVault: vi.fn(),
    },
  };
});

const github: ItemSummary = {
  id: "i1", vaultId: "v1", kind: "login", title: "GitHub", subtitle: "ivan",
  favorite: false, hasTotp: true, updatedAt: 2, damaged: false,
};

beforeEach(() => {
  vi.mocked(api.vaults).mockReset().mockResolvedValue([
    { id: "v1", name: "Personal", itemCount: 1 },
    { id: "v2", name: "Work", itemCount: 0 },
  ]);
  vi.mocked(api.items).mockReset().mockResolvedValue([github]);
  vi.mocked(api.item).mockReset().mockResolvedValue(loginItem());
  vi.mocked(api.totp).mockReset().mockResolvedValue(null);
  vi.mocked(api.newItem).mockReset().mockResolvedValue(loginItem({ id: "new", title: "" }));
  vi.mocked(api.saveItem).mockReset().mockImplementation(async (item) => item);
  vi.mocked(api.createVault).mockReset().mockResolvedValue({ id: "v3", name: "Home", itemCount: 0 });
});

const lastFilter = () => vi.mocked(api.items).mock.lastCall![0];

test("loads everything, filters by vault and search", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  expect(await screen.findByText("GitHub")).toBeInTheDocument();
  expect(lastFilter()).toEqual({ query: "", vaultId: null, favorites: false });

  await user.click(screen.getByRole("button", { name: /Work/ }));
  await waitFor(() => expect(lastFilter()).toEqual({ query: "", vaultId: "v2", favorites: false }));
  await user.type(screen.getByLabelText("Search"), "git");
  await waitFor(() => expect(lastFilter().query).toBe("git"));
});

test("selecting an item opens its details and Edit opens the editor", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByText("GitHub"));
  expect(await screen.findByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Edit" }));
  expect(screen.getByLabelText("Title")).toHaveValue("GitHub");
});

test("a new item is created in the selected vault, saved and shown", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "+ New" }));
  await user.click(screen.getByRole("menuitem", { name: "Login" }));
  expect(api.newItem).toHaveBeenCalledWith("v2", "login");
  await user.type(await screen.findByLabelText("Title"), "Jira");
  await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(api.saveItem).toHaveBeenCalled());
  await waitFor(() => expect(api.vaults).toHaveBeenCalledTimes(2));
});

test("new vault and lock", async () => {
  const user = userEvent.setup();
  const onLock = vi.fn();
  render(<Main onLock={onLock} />);
  await user.click(await screen.findByRole("button", { name: "+ New vault" }));
  await user.type(screen.getByLabelText("Vault name"), "Home{Enter}");
  expect(api.createVault).toHaveBeenCalledWith("Home");
  await user.click(screen.getByRole("button", { name: "Lock" }));
  expect(onLock).toHaveBeenCalled();
});

test("import opens the dialog", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Import from 1Password…" }));
  expect(screen.getByRole("dialog", { name: "Import from 1Password" })).toBeInTheDocument();
});
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm test`
Expected: FAIL (the stub `Main` has none of this).

- [ ] **Step 3: Implement** — replace `app/src/components/Main.tsx`:

```tsx
import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type Item, type ItemKind, type ItemSummary, type Vault } from "../api";
import { ImportDialog } from "./ImportDialog";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { ItemList } from "./ItemList";
import { Sidebar, type Selection } from "./Sidebar";

type Pane = { mode: "empty" } | { mode: "view"; id: string } | { mode: "edit"; item: Item };

export function Main({ onLock }: { onLock: () => void }) {
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [pane, setPane] = useState<Pane>({ mode: "empty" });
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadVaults = useCallback(
    () => api.vaults().then(setVaults).catch((e) => setError(errorMessage(e))),
    [],
  );
  const loadItems = useCallback(
    () =>
      api
        .items({
          query,
          vaultId: selection.kind === "vault" ? selection.id : null,
          favorites: selection.kind === "favorites",
        })
        .then(setItems)
        .catch((e) => setError(errorMessage(e))),
    [query, selection],
  );
  const refresh = useCallback(() => Promise.all([loadVaults(), loadItems()]), [loadVaults, loadItems]);

  useEffect(() => {
    loadVaults();
  }, [loadVaults]);
  useEffect(() => {
    loadItems();
  }, [loadItems]);

  const targetVault = selection.kind === "vault" ? selection.id : vaults[0]?.id;

  async function newItem(kind: ItemKind) {
    if (!targetVault) return;
    try {
      setPane({ mode: "edit", item: await api.newItem(targetVault, kind) });
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function newVault(name: string) {
    try {
      await api.createVault(name);
      await loadVaults();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <div className="app">
      <Sidebar
        vaults={vaults}
        selection={selection}
        onSelect={(s) => {
          setSelection(s);
          setPane({ mode: "empty" });
        }}
        onNewVault={newVault}
        onImport={() => setImporting(true)}
        onLock={onLock}
      />
      <ItemList
        items={items}
        query={query}
        onQuery={setQuery}
        selectedId={pane.mode === "view" ? pane.id : null}
        onSelect={(id) => setPane({ mode: "view", id })}
        onNew={newItem}
        canCreate={Boolean(targetVault)}
      />
      <section className="detail">
        {error && (
          <div className="banner error" role="alert">
            {error}
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}
        {pane.mode === "empty" && <p className="empty">Select an item</p>}
        {pane.mode === "view" && (
          <ItemDetail
            key={pane.id}
            itemId={pane.id}
            onEdit={(item) => setPane({ mode: "edit", item })}
            onDeleted={async () => {
              setPane({ mode: "empty" });
              await refresh();
            }}
          />
        )}
        {pane.mode === "edit" && (
          <ItemEditor
            key={pane.item.id}
            item={pane.item}
            onCancel={() =>
              setPane(items.some((i) => i.id === pane.item.id) ? { mode: "view", id: pane.item.id } : { mode: "empty" })
            }
            onSave={async (saved) => {
              setPane({ mode: "view", id: saved.id });
              await refresh();
            }}
          />
        )}
      </section>
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={refresh} />}
    </div>
  );
}
```

- [ ] **Step 4: Run to verify pass**

Run: `pnpm test && pnpm typecheck && pnpm build`
Expected: 35 tests pass (App tests included); build succeeds.

- [ ] **Step 5: Commit**

```bash
git add app/src
git commit -m "Wire the main window: vaults, list, detail, editor, import"
```

---

### Task 17: Run the app, verify by hand, document

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Full checks**

```bash
cargo fmt --all --check
cargo clippy -p lockbox-core -p lockbox-session -p lockbox-app --all-targets -- -D warnings
cargo test
cd app && pnpm typecheck && pnpm test && cd ..
```
Expected: all clean.

- [ ] **Step 2: Manual verification (controller, not a subagent)** — the app keeps its vault in `~/Library/Application Support/app.lockbox.mac/`; check that folder doesn't exist yet (if it does, move it aside first). Run the app detached (`cd app && nohup pnpm tauri dev > /tmp/lockbox-dev.log 2>&1 &`) and walk through and screenshot: first-run setup → main window with "Personal" → new Login with generated password → copy password (check `pbpaste`, then that it is cleared ~90 s later) → TOTP item shows a changing code → Lock → wrong password ×5 shows the wait → unlock → import a CSV (`Title,Url,Username,Password` with two rows) → "Imported" vault appears. Fix anything found with a test first.

- [ ] **Step 3: README** — replace the "Layout" and "Development" sections with:

````markdown
## Layout

- `crates/lockbox-core` — encryption, vault store, item model, TOTP, generator,
  1Password import, Watchtower. No UI.
- `crates/lockbox-session` — desktop-app logic (unlock throttling, auto-lock,
  clipboard clearing, import flow) over the core, without any UI framework.
- `app/` — macOS app: Tauri 2 shell (`app/src-tauri`) + React UI (`app/src`).
- `extension/` — Chrome extension — Plan 3.

## Development

```bash
cargo test                          # core + session
cd app && pnpm install && pnpm test # UI
cd app && pnpm tauri dev            # run the app (vault in ~/Library/Application Support/app.lockbox.mac)
cd app && pnpm tauri build --bundles app
```

Security model: see the spec, section "Cryptography".
````

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Document running the desktop app"
```

---

## Self-review notes

- Spec §5 coverage in this plan: first-run create, unlock, three-column main window, item view/edit, generator, import (with preview), auto-lock on idle (10 min), clipboard clearing after 90 s only if unchanged, wrong-password delay after 5 attempts (§7). Deferred to Plan 2b (stated in the header): Touch ID, lock on sleep/screen lock, menu bar + quick search, settings, Watchtower UI, Recently Deleted, vault rename/delete.
- Inputs from the Plan 1 final review used here: delete/restore require unlock (Task 1); app-side DTOs instead of adding `Serialize` to core types; TOTP for an item computed in the session (no core change); KDF floor enforced by the app always passing `KdfParams::DEFAULT` (tests use `INSECURE_FAST` via the `test-utils` feature).
