# Keepsake Desktop 2c Implementation Plan (Touch ID, Watchtower, menu bar, polish)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the MVP desktop app: vault rename/delete, a warning before unsaved edits are lost, "Start over" when the database file is unreadable, the Watchtower screen (weak, reused, breached, missing 2FA), a menu bar icon with a ⌘⇧Space quick-search window, and Touch ID unlock.

**Architecture:** Same layering as Plans 2a/2b. Logic and policy live in `crates/keepsake-session` (tested, time injected); `keepsake-core` gains a "not a Keepsake database" error, vault rename/delete and an HIBP call by hash. The Tauri shell stays thin: commands, the tray, a second (hidden) webview window for quick search, and a small Swift file compiled into the app for the Secure Enclave and the keychain. The React UI gains a Watchtower column, the quick-search root (`index.html#quick`), Touch ID on the lock screen and in Settings.

**Tech Stack:** as Plan 2b + `p256` 0.13 (ECDH, session crate), `tauri` feature `tray-icon`, `tauri-plugin-global-shortcut` 2, Swift (CryptoKit, LocalAuthentication, Security) built by `build.rs` with the Xcode toolchain.

**Spec:** `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md` §4 (Watchtower), §5 (Touch ID, menu bar and quick search), §7 (errors). Plan 2b listed these items as "Plan 2c".

## Decisions

- **Order of work:** polish (Tasks 1–6) → Watchtower (7–10) → menu bar and quick search (11–13) → Touch ID (14–18), riskiest last. Every task leaves the app building and all tests green.
- **Deleting a vault:** only an *empty* vault (no live items), and never the last one. Its items in Recently Deleted are purged with it (the confirmation says so). Why: there is no "move to another vault" UI yet, and restoring a trashed item into a deleted vault would leave it orphaned; refusing non-empty vaults means nothing is lost by accident. The row stays as a tombstone for sync; its wrapped key stays so `load_keys` keeps working.
- **Unsaved edits:** leaving the editor (another item, another sidebar entry, New, Lock, Watchtower item) while the form differs from the item asks "Discard changes?". The editor's own Cancel discards without asking (explicit intent). Auto-lock still locks (security first).
- **Start over:** offered only for `ErrorKind::NotADatabase` (the file is not SQLite, has no Keepsake schema, no or an unreadable header). A database from a *newer* app version keeps the plain error. The session re-checks before moving anything; the file is renamed to `keepsake.db.unreadable-<unix time>` (plus `-journal`/`-wal`/`-shm` siblings), never deleted.
- **Watchtower:** weak (zxcvbn < 3) and reused come from `keepsake-core`; "missing 2FA" = a login without a one-time password whose site is in a hand-kept list of domains known to offer authenticator codes (`crates/keepsake-session/assets/totp-sites.txt`, extend freely). Breach check is opt-in per session: the session hands out SHA-1 hashes (never passwords), the command queries HIBP *without holding the session lock*, answers are cached in memory and forgotten on lock.
- **Quick search:** a second webview window (`label "quick"`, `index.html#quick`), created hidden at startup, frameless, always on top, hidden when it loses focus. ⌘⇧Space toggles it (Rust-side registration through `tauri-plugin-global-shortcut`, no JS permission needed). Enter copies the password, ⌘Enter the username, ⌘C (with no text selected in the search box) the one-time code, Esc closes; copying closes the window. When locked it shows the normal unlock form (password, and Touch ID after Task 18). Closing the main window now hides it (Keepsake keeps running in the menu bar); Quit is in the tray menu and ⌘Q; clicking the Dock icon shows the main window again.
- **Touch ID:** see the next section. Key facts: the *account key* (not the KEK, never the password) is wrapped to a Secure Enclave key that only Touch ID with the currently enrolled fingers can use; the wrapped record sits in the login keychain; no password is needed after an app restart; the password is required again 14 days after it was last typed; a password change replaces the record.

## Touch ID: what works with a Personal Team on macOS 26 (evidence)

Experiments run on 2026-10-05 on this Mac (macOS 26.6.2, Xcode 26.6, Swift 6.3.3, Touch ID present: `LAContext.biometryType == .touchID`), with small Swift binaries signed ad hoc or with "Apple Development: aleks42viet@gmail.com (JV6NUZ7W9X)", team 4889865CU4, hardened runtime. No Touch ID prompt was triggered; all test items were deleted.

| Attempt | Result |
|---|---|
| (a) Data-protection keychain item (`kSecUseDataProtectionKeychain`) with `SecAccessControl(.biometryCurrentSet)`, team-signed, no entitlements | `-34018 errSecMissingEntitlement` (also with `kSecAttrAccessGroup = 4889865CU4.<id>`) |
| (a) + `com.apple.application-identifier` entitlement, no profile | launches, still `-34018` (the entitlement is ignored without a profile) |
| (a) + `keychain-access-groups` entitlement, no profile | process killed at launch (exit 137, AMFI) |
| (a) get a provisioning profile: minimal Xcode project, bundle id `app.keepsake.kcprobe`, automatic signing, `-allowProvisioningUpdates -allowProvisioningDeviceRegistration` | fails: "Your team has no devices from which to generate a provisioning profile" (a free team can't register this Mac from the command line; free profiles would also expire after 7 days) |
| `LARightStore.saveRight` (LocalAuthentication persisted rights) | `-34018` (uses the data-protection keychain internally) |
| (b) legacy file-based keychain item created with a biometry `SecAccessControl` | `SecItemAdd` succeeds but the ACL is **silently ignored**: the creator reads it back with `interactionNotAllowed`, no Touch ID |
| (b) legacy item, default ACL, read by another binary (different signature), dialogs disabled | `-25293`, no dialog; delete by it: `-25244`; add over it: `-25299` |
| (b) legacy item, read by a *rebuilt* binary with the same team signature and identifier | read succeeds silently (the ACL names the designated requirement `identifier "…" and anchor apple generic and certificate leaf[subject.CN] = "Apple Development: …"`, stable across rebuilds); a different identifier is refused |
| (c) **CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: [.privateKeyUsage, .biometryCurrentSet])`**, ad hoc *and* team-signed, no entitlements | **works**: key created without a prompt (569-byte opaque blob, 65-byte public key); reloading the blob without a prompt works; *using* it with `LAContext.interactionNotAllowed` fails with `LAError -1004 "User interaction is required"` and the error carries `BiometryDatabaseHash` (the enclave enforces the enrolled set) |
| (c) the same blob used by another process | loads, but use needs Touch ID too (`-1004`), and the system prompt names the calling process |
| ECDH result of CryptoKit vs the Rust `p256` crate | identical shared secrets (x-coordinate, 32 bytes) |
| Rust binary linking a Swift static library (`swiftc -emit-library -static`, `@_cdecl`), Swift runtime from `/usr/lib/swift` | links and runs; `ks_enclave_create` from Rust returns a key |
| The real `keepsake-app` crate with that Swift file, `cargo test` and an ignored live test (enclave key + keychain round trip under a test service) | passes, no prompt, keychain left clean |
| `APPLE_SIGNING_IDENTITY="Apple Development" pnpm tauri build --bundles app` | signs `Keepsake.app`: `Identifier=app.keepsake.mac`, `TeamIdentifier=4889865CU4`, `flags=0x10000(runtime)`, no entitlements, `codesign --verify --strict --deep` OK |

**Chosen approach: (c) + (b).**

1. **Enable (unlocked, after a password entry):** the app creates a CryptoKit Secure Enclave P-256 key with `[.privateKeyUsage, .biometryCurrentSet]` (no prompt). Rust wraps the account key: fresh ephemeral P-256 key, ECDH with the enclave's public key, `K = SHA-256("keepsake-touchid-v1/key" ‖ shared ‖ ephemeral_pub ‖ enclave_pub)`, `sealed = XChaCha20-Poly1305(K, account_key, aad = "keepsake-touchid-v1/account-key/" ‖ BE64(verified_at))`. The record `{enclave key blob, enclave pub, ephemeral pub, verified_at, sealed}` is stored as JSON in the **login keychain** (legacy, `kSecUseDataProtectionKeychain = false`), service `app.keepsake.mac.touchid`, account `account-key`. Its default ACL trusts only the app's designated requirement, and all keychain calls run with dialogs disabled, so a differently signed binary gets an error, never a password dialog.
2. **Unlock:** Rust reads the record (session lock held briefly), releases the lock, Swift loads the blob with an `LAContext` (reason "unlock Keepsake", fallback button "Use Password") and runs ECDH with the ephemeral public key → the system Touch ID prompt; Rust derives `K`, opens `sealed`, and calls the existing `Store::unlock_with_key`.
3. **Why the account key, not the KEK:** the KEK is only useful to unwrap the account key from the header, so storing it protects nothing more; the account key is what `Store::unlock_with_key` (already in core, written for this) needs, and it survives password changes. The master password itself is never stored.
4. **Policy:** enrolment changes destroy the enclave key (hardware-enforced) → unlock fails with "invalid" → the record is deleted and the user is told to unlock with the password and turn Touch ID on again. No password after an app restart (the record is in the keychain). The password is required again 14 days after it was last typed: `verified_at` is in the AAD, so editing it breaks decryption; a password unlock re-wraps the record with `verified_at = now` (no prompt, the enclave public key suffices); a Touch ID unlock keeps the old `verified_at`. Changing the master password re-wraps (replaces) the record. Creating a vault or "Start over" deletes any stale record.
5. **Why not (a):** impossible without a provisioning profile, which a free Personal Team can't produce for this Mac from the command line (and would expire weekly). **Why not (b) alone:** the legacy keychain ignores biometric ACLs, so Touch ID would be a UI gate in our own process only; with (c) the Secure Enclave enforces it.
6. **Signing:** `app/scripts/sign.sh` builds with `APPLE_SIGNING_IDENTITY` (Personal Team, hardened runtime, no entitlements needed) so the keychain ACL stays valid across rebuilds. Debug builds (`pnpm tauri dev`, ad hoc) use their own keychain service `app.keepsake.mac.touchid.dev`. The Chrome native host is the same binary (`--native-host` path unchanged); signing does not change it.

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (omitted below — always add it).
- Rust from the repo root, frontend from `app/`. `cargo fmt --all`; `cargo clippy -p <crate> --all-targets -- -D warnings` clean (for the shell: `cargo clippy -p keepsake-app --all-targets -- -D warnings`, which needs `app/dist` to exist — run `pnpm build` in `app/` once); `pnpm typecheck && pnpm test` green.
- Rust tests compare errors by `kind`. Session tests for this plan go into **new** files under `crates/keepsake-session/src/session/` (`polish_tests.rs`, `watchtower_tests.rs`, `touchid_tests.rs`) so tasks don't fight over imports; they reuse `tests.rs` helpers (`unlocked_session()`, `personal(&mut s)`, `save_login(...)`, `PW`), which are `pub(super)`.
- **Vitest 5 pitfall:** a function returned from `beforeEach` runs as teardown, and `mockReset()`/`mockResolvedValue()` return the mock. Always give `beforeEach` a braced body.
- Components that gain an `api.*` call: add the call to the `vi.mock("../api", …)` list of **every** test file that renders them (`Main.test.tsx`, `App.test.tsx`, `QuickApp.test.tsx`, …), or the real `invoke` runs and fails.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw.
- The Touch ID experiments above must not be repeated with prompts during automated work: never call `touchid::agree` from tests; the live test is `#[ignore]`.

## File map

```
crates/keepsake-core/src/error.rs                 + Error::NotADatabase
crates/keepsake-core/src/store/mod.rs             open() maps unreadable files; rename_vault, delete_vault
crates/keepsake-core/src/store/tests.rs           tests for the above
crates/keepsake-core/src/watchtower/hibp.rs       + breach_count_for_hash
crates/keepsake-session/Cargo.toml                + p256
crates/keepsake-session/assets/totp-sites.txt     NEW domains offering authenticator codes
crates/keepsake-session/src/error.rs              + NotADatabase, PasswordRequired, Cancelled
crates/keepsake-session/src/dto.rs                + ItemSummary::of
crates/keepsake-session/src/watchtower.rs         NEW report for the UI
crates/keepsake-session/src/touchid.rs            NEW record wrap/unwrap, Keyring trait
crates/keepsake-session/src/lib.rs                modules, re-exports
crates/keepsake-session/src/session/mod.rs        vault rename/delete, start_over, watchtower, copy_quick, Touch ID
crates/keepsake-session/src/session/{polish,watchtower,touchid}_tests.rs  NEW
app/src-tauri/Cargo.toml                          + tray-icon, global-shortcut, zeroize
app/src-tauri/build.rs                            compiles swift/TouchId.swift
app/src-tauri/swift/TouchId.swift                 NEW Secure Enclave + keychain via C ABI
app/src-tauri/src/touchid.rs                      NEW safe wrappers, MacKeyring
app/src-tauri/src/tray.rs                         NEW menu bar icon
app/src-tauri/src/quick.rs                        NEW quick-search window, shortcut
app/src-tauri/src/commands.rs                     new commands
app/src-tauri/src/lib.rs                          wiring, close-to-menu-bar, Reopen
app/src-tauri/capabilities/default.json           windows: main, quick
app/scripts/sign.sh                               NEW signed build + install
app/src/api.ts                                    types and calls
app/src/main.tsx                                  #quick → QuickApp
app/src/App.tsx (+test)                           unlocked event, start over
app/src/styles.css                                vault row, confirm, watchtower, quick
app/src/components/icons.tsx                      + IconPencil, IconShield
app/src/components/ConfirmDialog.tsx (+test)      NEW
app/src/components/Sidebar.tsx (+test)            rename/delete vault, Watchtower entry
app/src/components/ItemEditor.tsx (+test)         onDirtyChange
app/src/components/Main.tsx (+test)               vault actions, discard guard, Watchtower mode
app/src/components/Unlock.tsx (+test)             start over, Touch ID
app/src/components/Watchtower.tsx (+test)         NEW
app/src/components/QuickSearch.tsx (+test)        NEW
app/src/components/QuickApp.tsx (+test)           NEW
app/src/components/SettingsDialog.tsx (+test)     Touch ID section
README.md, spec                                   docs (Task 19)
```

---

## Part A — Polish

### Task 1: Core — "not a Keepsake database", vault rename and delete

**Files:** Modify `crates/keepsake-core/src/error.rs`, `crates/keepsake-core/src/store/mod.rs`, `crates/keepsake-core/src/store/tests.rs`.

- [ ] **Step 1: Failing tests.** In `store/tests.rs`, three existing tests now expect the new error — change `Err(Error::Invalid(_))` to `Err(Error::NotADatabase(_))` in `open_rejects_empty_file_without_writing`, `open_rejects_foreign_sqlite_database_without_writing` and `negative_user_version_is_rejected_without_backup` (leave `newer_database_version_is_rejected` on `Invalid`: a newer app's file is ours). Append:

```rust
#[test]
fn open_rejects_a_file_that_is_not_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    std::fs::write(&path, b"this is a text file, not a database at all.......").unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
}

#[test]
fn open_rejects_a_damaged_header() {
    let (_dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE meta SET value = X'7B' WHERE key = 'header'", [])
        .unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
}

#[test]
fn rename_vault_keeps_its_items() {
    let (_dir, path, mut store) = new_store();
    let vault = store.create_vault("Personal").unwrap();
    store.save_item(&login(vault.id, "GitHub")).unwrap();
    let renamed = store.rename_vault(vault.id, "Home").unwrap();
    assert_eq!(renamed.name, "Home");
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.vaults().unwrap()[0].name, "Home");
    assert_eq!(store.list_items(Some(vault.id)).unwrap().len(), 1);
    assert!(matches!(
        store.rename_vault(Uuid::new_v4(), "x"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn delete_vault_refuses_live_items_and_purges_its_trash() {
    let (_dir, _path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let old = store.create_vault("Old").unwrap();
    let item = login(old.id, "Forum");
    store.save_item(&item).unwrap();
    assert!(matches!(
        store.delete_vault(old.id, 1_000),
        Err(Error::Invalid(_))
    ));
    store.delete_item(item.id, 1_000).unwrap();
    store.delete_vault(old.id, 2_000).unwrap();
    let names: Vec<_> = store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert!(
        store.deleted_items().unwrap().is_empty(),
        "its trash is purged"
    );
    assert!(matches!(
        store.restore_item(item.id),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.delete_vault(old.id, 3_000),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn deleted_vault_does_not_break_unlock() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let old = store.create_vault("Old").unwrap();
    store.delete_vault(old.id, 1_000).unwrap();
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}
```

- [ ] **Step 2: Run** `cargo test -p keepsake-core store` — compile errors (`NotADatabase`, `rename_vault`, `delete_vault`).

- [ ] **Step 3: Implement.**

`error.rs`, before `Network`:

```rust
    /// The file exists but is not a Keepsake database (or is damaged beyond opening).
    #[error("not a keepsake database: {0}")]
    NotADatabase(String),
```

`store/mod.rs` — in `Store::open`, replace the body between `let conn = Connection::open(path)?;` and `Ok(Store {` with:

```rust
        let conn = Connection::open(path)?;
        configure(&conn).map_err(not_a_database)?;
        upgrade(&conn, path).map_err(not_a_database)?;
        let raw: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key = 'header'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| not_a_database(e.into()))?
            .ok_or_else(|| Error::NotADatabase("missing header".into()))?;
        let header = serde_json::from_slice(&raw)
            .map_err(|e| Error::NotADatabase(format!("unreadable header: {e}")))?;
```

In `upgrade`, the `version <= 0` branch returns `Err(Error::NotADatabase("no keepsake schema".into()))`. Add next to `backup`:

```rust
/// Errors that mean "this file is not ours or is damaged"; others (I/O, a newer schema, a busy
/// database) pass through unchanged so the UI never offers to start over for them.
fn not_a_database(e: Error) -> Error {
    use rusqlite::ErrorCode::{DatabaseCorrupt, NotADatabase};
    match e {
        Error::Db(rusqlite::Error::SqliteFailure(f, _))
            if matches!(f.code, NotADatabase | DatabaseCorrupt) =>
        {
            Error::NotADatabase(f.to_string())
        }
        other => other,
    }
}
```

Inside `impl Store`, after `create_vault`:

```rust
    pub fn rename_vault(&mut self, id: Uuid, name: &str) -> Result<VaultInfo> {
        let account = self.account_key()?;
        let info = VaultInfo {
            id,
            name: name.to_owned(),
        };
        let meta = crypto::seal(account, &serde_json::to_vec(&info)?, &vault_meta_aad(id));
        let n = self.conn.execute(
            "UPDATE vaults SET meta = ?2, revision = revision + 1 WHERE id = ?1 AND deleted = 0",
            params![id.to_string(), meta],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("vault {id}")));
        }
        Ok(info)
    }

    /// Deletes an empty vault. Its items in Recently Deleted are purged with it; the row stays
    /// as a tombstone (for sync), and its key is kept so old tombstones still parse.
    pub fn delete_vault(&mut self, id: Uuid, now: i64) -> Result<()> {
        self.vault_key(id)?;
        let tx = self.conn.unchecked_transaction()?;
        let live: i64 = tx.query_row(
            "SELECT COUNT(*) FROM items WHERE vault_id = ?1 AND deleted_at IS NULL",
            [id.to_string()],
            |r| r.get(0),
        )?;
        if live > 0 {
            return Err(Error::Invalid(format!("vault has {live} items")));
        }
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?1) AND deleted = 0",
            [id.to_string()],
        )?;
        tx.execute(
            "UPDATE items SET data = X'', deleted_at = COALESCE(deleted_at, ?2), revision = revision + 1
             WHERE vault_id = ?1 AND length(data) > 0",
            params![id.to_string(), now],
        )?;
        let n = tx.execute(
            "UPDATE vaults SET deleted = 1, revision = revision + 1 WHERE id = ?1 AND deleted = 0",
            [id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("vault {id}")));
        }
        tx.commit()?;
        Ok(())
    }
```

- [ ] **Step 4: Run** `cargo test -p keepsake-core` (all pass) and `cargo clippy -p keepsake-core --all-targets -- -D warnings`. The session crate still compiles: its `From<CoreError>` has a `_ =>` arm (the new kind is mapped in Task 2).
- [ ] **Step 5: Commit** — `git commit -m "Core: report unreadable database files; rename and delete vaults"`

---

### Task 2: Session — vault rename/delete and "Start over"

**Files:** Modify `crates/keepsake-session/src/error.rs`, `crates/keepsake-session/src/session/mod.rs`; create `crates/keepsake-session/src/session/polish_tests.rs`.

- [ ] **Step 1: Failing tests.** `error.rs` test `core_errors_map_to_kinds`: add the case `(CoreError::NotADatabase("x".into()), ErrorKind::NotADatabase),`. Create `session/polish_tests.rs`:

```rust
use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;

#[test]
fn rename_vault_trims_and_requires_a_name() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    assert_eq!(s.rename_vault(p, "  Home ", 1_000).unwrap().name, "Home");
    assert_eq!(s.vaults(1_000).unwrap()[0].name, "Home");
    assert_eq!(
        s.rename_vault(p, " ", 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        s.rename_vault(Uuid::new_v4(), "x", 1_000).unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[test]
fn delete_vault_only_when_empty_and_not_the_last() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    assert_eq!(
        s.delete_vault(p, 1_000).unwrap_err().kind,
        ErrorKind::Invalid,
        "last vault"
    );
    let work = s.create_vault("Work", 1_000).unwrap().id;
    let item = save_login(&mut s, work, "Jira", "ivan", "pw");
    let err = s.delete_vault(work, 1_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Invalid);
    assert!(err.message.contains("1 item"), "{}", err.message);
    s.delete_item(item.id, 1_000).unwrap();
    s.delete_vault(work, 1_000).unwrap();
    let names: Vec<_> = s
        .vaults(1_000)
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert!(s.deleted_items(1_000).unwrap().is_empty());
}

#[test]
fn vault_changes_require_unlock() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    s.lock();
    assert_eq!(
        s.rename_vault(p, "x", 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
    assert_eq!(
        s.delete_vault(p, 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

fn session_with_file(contents: &[u8]) -> (tempfile::TempDir, Session, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    std::fs::write(&path, contents).unwrap();
    let s = Session::new(path.clone(), KdfParams::INSECURE_FAST, 1_000);
    (dir, s, path)
}

#[test]
fn unlocking_a_foreign_file_says_it_is_not_a_database() {
    let (_dir, mut s, _path) = session_with_file(b"definitely not sqlite, just some text here....");
    assert_eq!(s.status(), Status::Locked);
    assert_eq!(
        s.unlock(PW, 1_000).unwrap_err().kind,
        ErrorKind::NotADatabase
    );
}

#[test]
fn start_over_moves_the_file_aside_and_allows_setup() {
    let (dir, mut s, path) = session_with_file(b"definitely not sqlite, just some text here....");
    let aside = s.start_over(5_000).unwrap();
    assert_eq!(aside, dir.path().join("keepsake.db.unreadable-5000"));
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        b"definitely not sqlite, just some text here....",
        "nothing is deleted"
    );
    assert!(!path.exists());
    assert_eq!(s.status(), Status::New);
    s.create(PW, 5_001).unwrap();
}

#[test]
fn start_over_never_moves_a_working_vault() {
    let (dir, mut s) = unlocked_session();
    assert_eq!(
        s.start_over(5_000).unwrap_err().kind,
        ErrorKind::Invalid,
        "unlocked"
    );
    s.lock();
    assert_eq!(s.start_over(5_000).unwrap_err().kind, ErrorKind::Invalid);
    assert!(dir
        .path()
        .join("Application Support")
        .join("keepsake.db")
        .exists());
    s.unlock(PW, 5_001).unwrap();
}
```

and register it in `session/mod.rs` next to the other test modules:

```rust
#[cfg(test)]
mod polish_tests;
```

- [ ] **Step 2: Run** `cargo test -p keepsake-session` — compile errors.

- [ ] **Step 3: Implement.**

`error.rs`: add to `ErrorKind` (before `Other`):

```rust
    /// The database file is not a Keepsake database: offer "Start over".
    NotADatabase,
```

and in `From<CoreError>`: `CoreError::NotADatabase(_) => ErrorKind::NotADatabase,`.

`session/mod.rs`, inside `impl Session` after `create_vault`:

```rust
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
```

and next to `fn locked()`:

```rust
/// `path` with `suffix` appended to the whole file name (`keepsake.db` → `keepsake.db-journal`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
```

(Task 15 adds `self.keyring.delete();` at the start of the rename part of `start_over`.)

- [ ] **Step 4: Run** `cargo test -p keepsake-session` and clippy.
- [ ] **Step 5: Commit** — `git commit -m "Session: rename and delete vaults, start over with an unreadable database"`

---

### Task 3: Shell commands, API and a confirm dialog

**Files:** Modify `app/src-tauri/src/commands.rs`, `app/src-tauri/src/lib.rs`, `app/src/api.ts`, `app/src/styles.css`; create `app/src/components/ConfirmDialog.tsx`, `ConfirmDialog.test.tsx`.

- [ ] **Step 1: Commands** — append to `commands.rs`:

```rust
#[tauri::command(async)]
pub fn start_over(state: State<'_, AppState>) -> CmdResult<String> {
    let aside = lock_session(&state).start_over(now())?;
    Ok(aside.display().to_string())
}

#[tauri::command(async)]
pub fn rename_vault(state: State<'_, AppState>, id: Uuid, name: String) -> CmdResult<VaultDto> {
    lock_session(&state).rename_vault(id, &name, now())
}

#[tauri::command(async)]
pub fn delete_vault(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).delete_vault(id, now())
}
```

Register `commands::start_over, commands::rename_vault, commands::delete_vault` in `generate_handler!` (`lib.rs`). Build: `(cd app && pnpm build) && cargo clippy -p keepsake-app --all-targets -- -D warnings`.

- [ ] **Step 2: API** — in `api.ts` replace the `ErrorKind` type (Tasks 15/18 use the last two kinds):

```ts
export type ErrorKind =
  | "wrongPassword"
  | "locked"
  | "throttled"
  | "notFound"
  | "invalid"
  | "notADatabase"
  | "passwordRequired"
  | "cancelled"
  | "other";
```

and add to `api` after `createVault`:

```ts
  renameVault: (id: string, name: string) => invoke<Vault>("rename_vault", { id, name }),
  deleteVault: (id: string) => invoke<void>("delete_vault", { id }),
  /** Moves an unreadable database aside; returns where it went. */
  startOver: () => invoke<string>("start_over"),
```

- [ ] **Step 3: Failing test** — `ConfirmDialog.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";

test("confirms, cancels and closes on Escape", async () => {
  const user = userEvent.setup();
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <ConfirmDialog title="Delete vault Work?" confirmLabel="Delete vault" danger onConfirm={onConfirm} onCancel={onCancel}>
      It is empty.
    </ConfirmDialog>,
  );
  expect(screen.getByRole("alertdialog", { name: "Delete vault Work?" })).toHaveTextContent("It is empty.");
  await user.click(screen.getByRole("button", { name: "Delete vault" }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  await user.keyboard("{Escape}");
  expect(onCancel).toHaveBeenCalledTimes(2);
});
```

- [ ] **Step 4: Run** `pnpm test ConfirmDialog` — fails (no module).
- [ ] **Step 5: Implement** `ConfirmDialog.tsx`:

```tsx
import { useEffect, type ReactNode } from "react";

interface Props {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A small yes/no dialog; Escape cancels. */
export function ConfirmDialog({ title, children, confirmLabel, danger, onConfirm, onCancel }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  return (
    <div className="modal-backdrop">
      <div className="card modal confirm" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{title}</h2>
        <div className="muted">{children}</div>
        <div className="modal-actions">
          <button onClick={onCancel}>Cancel</button>
          <button className={danger ? "danger" : "primary"} autoFocus onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
```

and append to `styles.css`:

```css
/* Plan 2c */
.modal.confirm { width: 420px; }
```

- [ ] **Step 6: Run** `pnpm typecheck && pnpm test`. **Step 7: Commit** — `git commit -m "Add vault and start-over commands and a confirm dialog"`

---

### Task 4: Rename and delete vaults in the sidebar

**Files:** Modify `app/src/components/icons.tsx`, `Sidebar.tsx`, `Sidebar.test.tsx`, `Main.tsx`, `Main.test.tsx`, `app/src/styles.css`.

- [ ] **Step 1: Failing tests.**

`Sidebar.test.tsx` — import `type Selection` (`import { Sidebar, type Selection } from "./Sidebar";`), replace `setup()` with:

```tsx
function setup(selection: Selection = { kind: "all" }) {
  const props = {
    onSelect: vi.fn(),
    onNewVault: vi.fn(),
    onRenameVault: vi.fn(),
    onDeleteVault: vi.fn(),
    onImport: vi.fn(),
    onLock: vi.fn(),
    onSettings: vi.fn(),
  };
  render(<Sidebar vaults={vaults} selection={selection} {...props} />);
  return props;
}
```

and append:

```tsx
test("the selected vault can be renamed and deleted", async () => {
  const user = userEvent.setup();
  const props = setup({ kind: "vault", id: "v2" });
  expect(screen.queryByRole("button", { name: "Rename Personal" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Rename Datagile" }));
  const input = screen.getByLabelText("New name for Datagile");
  expect(input).toHaveValue("Datagile");
  await user.clear(input);
  await user.type(input, "Work{Enter}");
  expect(props.onRenameVault).toHaveBeenCalledWith("v2", "Work");
  await user.click(screen.getByRole("button", { name: "Delete Datagile" }));
  expect(props.onDeleteVault).toHaveBeenCalledWith(vaults[1]);
});

test("Escape cancels a rename", async () => {
  const user = userEvent.setup();
  const props = setup({ kind: "vault", id: "v1" });
  await user.click(screen.getByRole("button", { name: "Rename Personal" }));
  await user.type(screen.getByLabelText("New name for Personal"), "x{Escape}");
  expect(props.onRenameVault).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("New name for Personal")).not.toBeInTheDocument();
});
```

`Main.test.tsx` — add `renameVault: vi.fn(), deleteVault: vi.fn(),` to the mocked api; in `beforeEach`:

```tsx
  vi.mocked(api.renameVault).mockReset().mockResolvedValue({ id: "v2", name: "Office", itemCount: 0 });
  vi.mocked(api.deleteVault).mockReset().mockResolvedValue(undefined);
```

and append:

```tsx
test("renames the selected vault", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "Rename Work" }));
  await user.clear(screen.getByLabelText("New name for Work"));
  await user.type(screen.getByLabelText("New name for Work"), "Office{Enter}");
  expect(api.renameVault).toHaveBeenCalledWith("v2", "Office");
  await waitFor(() => expect(api.vaults).toHaveBeenCalledTimes(2));
});

test("deletes an empty vault after confirming", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "Delete Work" }));
  const dialog = screen.getByRole("alertdialog", { name: 'Delete vault "Work"?' });
  expect(dialog).toHaveTextContent("Recently Deleted");
  await user.click(screen.getByRole("button", { name: "Delete vault" }));
  expect(api.deleteVault).toHaveBeenCalledWith("v2");
  await waitFor(() => expect(lastFilter().vaultId).toBeNull());
});

test("a vault with items is not deleted", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Personal/ }));
  await user.click(screen.getByRole("button", { name: "Delete Personal" }));
  expect(await screen.findByRole("alert")).toHaveTextContent('"Personal" still has 1 item. Delete them first.');
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  expect(api.deleteVault).not.toHaveBeenCalled();
});
```

- [ ] **Step 2: Run** `pnpm test Sidebar Main` — failures (no Rename/Delete buttons).

- [ ] **Step 3: Implement.**

`icons.tsx`, before `IconClose`:

```tsx
export const IconPencil = icon(<path d="M5 19l1-4.5L15.5 5a2.1 2.1 0 013 3L9 17.5zM13.5 7l3 3" />);
```

`Sidebar.tsx` — import `IconPencil`; props gain

```tsx
  onRenameVault: (id: string, name: string) => void;
  onDeleteVault: (vault: Vault) => void;
```

the component destructures them (`export function Sidebar(props: Props) { const { vaults, selection, onSelect, onNewVault, onRenameVault, onDeleteVault, onImport, onLock, onSettings } = props;`), adds state

```tsx
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");

  function submitRename(e: FormEvent, id: string) {
    e.preventDefault();
    const trimmed = newName.trim();
    if (trimmed) onRenameVault(id, trimmed);
    setRenaming(null);
  }
```

and the vault list becomes:

```tsx
      {vaults.map((v) =>
        renaming === v.id ? (
          <form key={v.id} onSubmit={(e) => submitRename(e, v.id)}>
            <input
              aria-label={`New name for ${v.name}`}
              autoFocus
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Escape" && setRenaming(null)}
              onBlur={() => setRenaming(null)}
            />
          </form>
        ) : (
          <div key={v.id} className="vault-row">
            <button
              className="nav"
              aria-current={isCurrent({ kind: "vault", id: v.id })}
              onClick={() => onSelect({ kind: "vault", id: v.id })}
            >
              <IconVault />
              <span>{v.name}</span>
              <span className="count">{v.itemCount}</span>
            </button>
            {isCurrent({ kind: "vault", id: v.id }) && (
              <span className="vault-actions">
                <button
                  className="icon"
                  title="Rename"
                  aria-label={`Rename ${v.name}`}
                  onClick={() => {
                    setNewName(v.name);
                    setRenaming(v.id);
                  }}
                >
                  <IconPencil />
                </button>
                <button className="icon" title="Delete" aria-label={`Delete ${v.name}`} onClick={() => onDeleteVault(v)}>
                  <IconTrash />
                </button>
              </span>
            )}
          </div>
        ),
      )}
```

`styles.css` append:

```css
.vault-row { position: relative; }
.vault-row .nav { width: 100%; }
.vault-row .vault-actions { position: absolute; right: 34px; top: 50%; transform: translateY(-50%); display: flex; gap: 2px; }
.vault-row .vault-actions button.icon { width: 24px; height: 24px; }
```

`Main.tsx` — import `ConfirmDialog`; state `const [deletingVault, setDeletingVault] = useState<Vault | null>(null);`; functions:

```tsx
  async function renameVault(id: string, name: string) {
    try {
      await api.renameVault(id, name);
      await loadVaults();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  function askDeleteVault(vault: Vault) {
    if (vault.itemCount > 0) {
      const s = vault.itemCount === 1 ? "" : "s";
      setError(`"${vault.name}" still has ${vault.itemCount} item${s}. Delete them first.`);
      return;
    }
    setDeletingVault(vault);
  }

  async function deleteVault(vault: Vault) {
    setDeletingVault(null);
    try {
      await api.deleteVault(vault.id);
      setSelection({ kind: "all" });
      setPane({ mode: "empty" });
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }
```

pass `onRenameVault={renameVault}` and `onDeleteVault={askDeleteVault}` to `Sidebar`, and render next to the other dialogs:

```tsx
      {deletingVault && (
        <ConfirmDialog
          title={`Delete vault "${deletingVault.name}"?`}
          confirmLabel="Delete vault"
          danger
          onConfirm={() => deleteVault(deletingVault)}
          onCancel={() => setDeletingVault(null)}
        >
          The vault is empty. Its items in Recently Deleted are removed for good.
        </ConfirmDialog>
      )}
```

- [ ] **Step 4: Run** `pnpm typecheck && pnpm test`. **Step 5: Commit** — `git commit -m "Rename and delete vaults from the sidebar"`

---

### Task 5: Warn before unsaved edits are lost

**Files:** Modify `app/src/components/ItemEditor.tsx`, `ItemEditor.test.tsx`, `Main.tsx`, `Main.test.tsx`.

- [ ] **Step 1: Failing tests.** `ItemEditor.test.tsx` append:

```tsx
test("reports unsaved changes", async () => {
  const user = userEvent.setup();
  const onDirtyChange = vi.fn();
  render(<ItemEditor item={loginItem()} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} onDirtyChange={onDirtyChange} />);
  expect(onDirtyChange).toHaveBeenLastCalledWith(false);
  await user.type(screen.getByLabelText("Title"), "!");
  expect(onDirtyChange).toHaveBeenLastCalledWith(true);
  await user.type(screen.getByLabelText("Title"), "{Backspace}");
  expect(onDirtyChange).toHaveBeenLastCalledWith(false);
  await user.type(screen.getByLabelText("Tags"), ", x");
  expect(onDirtyChange).toHaveBeenLastCalledWith(true);
});
```

`Main.test.tsx` — import `within` from `@testing-library/react` and append:

```tsx
test("leaving the editor with unsaved changes asks first", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByText("GitHub"));
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  await user.type(screen.getByLabelText("Title"), " work");
  await user.click(screen.getByRole("button", { name: "Favorites" }));
  const dialog = screen.getByRole("alertdialog", { name: "Discard changes?" });
  await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
  expect(screen.getByLabelText("Title")).toHaveValue("GitHub work");
  await user.click(screen.getByRole("button", { name: "Favorites" }));
  await user.click(screen.getByRole("button", { name: "Discard" }));
  await waitFor(() => expect(lastFilter().favorites).toBe(true));
  expect(screen.queryByLabelText("Title")).not.toBeInTheDocument();
});

test("leaving an unchanged editor does not ask", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByText("GitHub"));
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  await user.click(screen.getByRole("button", { name: "Favorites" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  await waitFor(() => expect(lastFilter().favorites).toBe(true));
});
```

- [ ] **Step 2: Run** `pnpm test ItemEditor Main` — failures.

- [ ] **Step 3: Implement.**

`ItemEditor.tsx` — import `useEffect`; `Props` gains

```tsx
  /** Called when the form starts or stops differing from `item`. */
  onDirtyChange?: (dirty: boolean) => void;
```

destructure it, and before `const usernameIndex = …` add:

```tsx
  const dirty =
    JSON.stringify(draft) !== JSON.stringify(item) || urls !== item.urls.join("\n") || tags !== item.tags.join(", ");
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
```

`Main.tsx`:

```tsx
  /** Runs once the user agreed to drop unsaved edits. */
  const [pendingLeave, setPendingLeave] = useState<(() => void) | null>(null);
  const editorDirty = useRef(false);
  const onDirtyChange = useCallback((dirty: boolean) => {
    editorDirty.current = dirty;
  }, []);

  useEffect(() => {
    if (pane.mode !== "edit") editorDirty.current = false;
  }, [pane]);

  /** Leaving the editor with unsaved changes asks first. */
  function leaveEditor(action: () => void) {
    if (pane.mode === "edit" && editorDirty.current) setPendingLeave(() => action);
    else action();
  }
```

Wrap the navigation callbacks:

```tsx
        onSelect={(s) =>
          leaveEditor(() => {
            setSelection(s);
            setPane({ mode: "empty" });
          })
        }
        …
        onLock={() => leaveEditor(onLock)}
```

in `Sidebar`, and in `ItemList`:

```tsx
        onSelect={(id) => leaveEditor(() => setPane({ mode: "view", id }))}
        onNew={(kind) => leaveEditor(() => void newItem(kind))}
```

pass `onDirtyChange={onDirtyChange}` to `ItemEditor`, and render:

```tsx
      {pendingLeave && (
        <ConfirmDialog
          title="Discard changes?"
          confirmLabel="Discard"
          danger
          onConfirm={() => {
            const leave = pendingLeave;
            setPendingLeave(null);
            editorDirty.current = false;
            leave();
          }}
          onCancel={() => setPendingLeave(null)}
        >
          Your edits to this item haven't been saved.
        </ConfirmDialog>
      )}
```

- [ ] **Step 4: Run** `pnpm typecheck && pnpm test`. **Step 5: Commit** — `git commit -m "Ask before discarding unsaved item edits"`

---

### Task 6: "Start over" on the lock screen

**Files:** Modify `app/src/components/Unlock.tsx`, `Unlock.test.tsx`, `app/src/App.tsx`.

- [ ] **Step 1: Failing test.** `Unlock.test.tsx` — mock `startOver: vi.fn()` next to `unlock`, reset it in `beforeEach` (`vi.mocked(api.startOver).mockReset().mockResolvedValue("/x/keepsake.db.unreadable-1");`), render every `<Unlock …>` with `onStartOver={vi.fn()}`, and append:

```tsx
test("an unreadable database offers to start over", async () => {
  const user = userEvent.setup();
  const onStartOver = vi.fn();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "notADatabase", message: "not a keepsake database: file is not a database" });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={onStartOver} />);
  await user.type(screen.getByLabelText("Master password"), "whatever");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("heading", { name: "This file is not a Keepsake database" })).toBeInTheDocument();
  expect(screen.getByText(/never deleted/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Start over…" }));
  expect(api.startOver).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Move it aside and start over" }));
  expect(api.startOver).toHaveBeenCalled();
  await waitFor(() => expect(onStartOver).toHaveBeenCalled());
});
```

- [ ] **Step 2: Run** `pnpm test Unlock` — fails.

- [ ] **Step 3: Implement.** `Unlock.tsx`:

```tsx
interface Props {
  onUnlocked: () => void;
  /** The database was moved aside: show first-run setup. */
  onStartOver: () => void;
}

export function Unlock({ onUnlocked, onStartOver }: Props) {
```

state `const [unreadable, setUnreadable] = useState(false); const [confirmStartOver, setConfirmStartOver] = useState(false);`; in `submit`'s `catch`, before the `wrongPassword` branch:

```tsx
      } else if (isCmdError(err) && err.kind === "notADatabase") {
        setUnreadable(true);
```

and before the main `return`:

```tsx
  async function startOver() {
    setBusy(true);
    try {
      await api.startOver();
      onStartOver();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  if (unreadable) {
    return (
      <div className="center">
        <div className="card auth" role="group" aria-labelledby="unreadable-title">
          <h1 id="unreadable-title">This file is not a Keepsake database</h1>
          <p className="muted">
            Keepsake can't read its database: it belongs to another app or is damaged. You can start over with a new,
            empty vault. The old file is moved aside next to it (it ends in ".unreadable-…"), never deleted.
          </p>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {confirmStartOver ? (
            <button className="danger" onClick={startOver} disabled={busy}>
              Move it aside and start over
            </button>
          ) : (
            <button className="primary" onClick={() => setConfirmStartOver(true)}>
              Start over…
            </button>
          )}
        </div>
      </div>
    );
  }
```

`App.tsx`: `<Unlock onUnlocked={() => setStatus("unlocked")} onStartOver={() => setStatus("new")} />`.

- [ ] **Step 4: Run** `pnpm typecheck && pnpm test`. **Step 5: Commit** — `git commit -m "Offer to start over when the database file is unreadable"`

---

## Part B — Watchtower

### Task 7: Core — HIBP by hash

**Files:** Modify `crates/keepsake-core/src/watchtower/hibp.rs`.

- [ ] **Step 1: Failing test** (in the `tests` module):

```rust
    #[test]
    fn a_precomputed_hash_sends_only_its_prefix() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/range/5BAA6")
            .with_body("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n")
            .create();
        let hibp = Hibp::with_base_url(&server.url());
        let lower = PASSWORD_SHA1.to_ascii_lowercase();
        assert_eq!(hibp.breach_count_for_hash(&lower).unwrap(), 42);
        mock.assert();
        assert!(matches!(
            hibp.breach_count_for_hash("5BAA6"),
            Err(Error::Invalid(_))
        ));
    }
```

- [ ] **Step 2: Run** `cargo test -p keepsake-core hibp` — compile error.
- [ ] **Step 3: Implement** — `breach_count` delegates:

```rust
    /// How many times the password appears in known breaches (0 = not found).
    pub fn breach_count(&self, password: &str) -> Result<u64> {
        self.breach_count_for_hash(&sha1_hex_upper(password))
    }

    /// Same, for a password the caller already hashed (40 hex characters of SHA-1). Only the
    /// first five characters are sent.
    pub fn breach_count_for_hash(&self, sha1_hex: &str) -> Result<u64> {
        if sha1_hex.len() != 40 || !sha1_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid("expected a SHA-1 hex digest".into()));
        }
        let hash = sha1_hex.to_ascii_uppercase();
        let (prefix, suffix) = hash.split_at(5);
        // … the rest of the former breach_count body, unchanged …
    }
```

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `git commit -m "Core: query HIBP with a precomputed hash"`

---

### Task 8: Session — the Watchtower report

**Files:** Create `crates/keepsake-session/assets/totp-sites.txt`, `crates/keepsake-session/src/watchtower.rs`, `crates/keepsake-session/src/session/watchtower_tests.rs`; modify `dto.rs`, `lib.rs`, `session/mod.rs`.

- [ ] **Step 1: The site list** — `assets/totp-sites.txt`:

```text
# Registrable domains (eTLD+1) whose accounts can use an authenticator app (TOTP codes).
# Watchtower flags saved logins for these sites that have no one-time password.
# A starter list maintained by hand: one domain per line, "#" starts a comment.
adobe.com
amazon.com
atlassian.com
atlassian.net
binance.com
bitbucket.org
bitwarden.com
cloudflare.com
coinbase.com
digitalocean.com
discord.com
docker.com
dropbox.com
ebay.com
epicgames.com
facebook.com
fastmail.com
figma.com
github.com
gitlab.com
godaddy.com
google.com
heroku.com
hetzner.com
instagram.com
kraken.com
linkedin.com
linode.com
live.com
mailchimp.com
microsoft.com
namecheap.com
netlify.com
notion.so
npmjs.com
okta.com
ovh.com
paypal.com
porkbun.com
proton.me
pypi.org
reddit.com
salesforce.com
shopify.com
slack.com
stripe.com
tiktok.com
twitch.tv
twitter.com
vercel.com
vk.com
wordpress.com
x.com
yandex.ru
zoho.com
zoom.us
```

- [ ] **Step 2: Failing tests.** The module's own tests are at the bottom of `watchtower.rs` (Step 4 shows the whole file; write the `#[cfg(test)] mod tests` part first with an empty `report`/`unchecked_hashes` stub if you want to watch them fail). Session tests — `session/watchtower_tests.rs`:

```rust
use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use keepsake_core::watchtower::hibp::sha1_hex_upper;

#[test]
fn watchtower_reports_live_items_only() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "Bank", "me", "password");
    let gone = save_login(&mut s, p, "Old", "me", "password");
    s.delete_item(gone.id, 1_000).unwrap();
    let r = s.watchtower(1_000).unwrap();
    let weak: Vec<_> = r.weak.iter().map(|f| f.item.title.as_str()).collect();
    assert_eq!(weak, ["Bank"]);
    assert!(r.reused.is_empty(), "the deleted copy does not count");
}

#[test]
fn breach_answers_are_cached_until_lock() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "Bank", "me", "password");
    save_login(&mut s, p, "Shop", "me", "password");
    let hashes = s.breach_hashes_to_check(1_000).unwrap();
    assert_eq!(hashes, [sha1_hex_upper("password")]);
    s.record_breaches([(hashes[0].clone(), 12)]);
    assert!(s.breach_hashes_to_check(1_000).unwrap().is_empty());
    let r = s.watchtower(1_000).unwrap();
    assert_eq!(r.breached.len(), 2);
    assert!(r.breaches_checked);

    s.lock();
    s.record_breaches([(hashes[0].clone(), 12)]);
    s.unlock(PW, 1_001).unwrap();
    assert_eq!(
        s.breach_hashes_to_check(1_001).unwrap().len(),
        1,
        "forgotten on lock"
    );
}

#[test]
fn watchtower_requires_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.watchtower(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(
        s.breach_hashes_to_check(1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}
```

registered with `#[cfg(test)] mod watchtower_tests;` in `session/mod.rs`.

- [ ] **Step 3: Run** `cargo test -p keepsake-session watchtower` — fails.

- [ ] **Step 4: Implement.**

`dto.rs` — import `Item` (`use keepsake_core::model::{Item, ItemKind};`) and split the `Ok` arm out of `from_entry`:

```rust
    pub fn of(item: &Item) -> Self {
        Self {
            id: item.id,
            vault_id: item.vault_id,
            kind: Some(item.kind),
            title: item.title.clone(),
            subtitle: item.username().unwrap_or_default().to_owned(),
            favorite: item.favorite,
            has_totp: item.totp().is_some(),
            updated_at: item.updated_at,
            damaged: false,
        }
    }
```

with `ItemEntry::Ok(item) => Self::of(item),` in `from_entry`.

`watchtower.rs`:

```rust
//! The Watchtower report the UI shows: weak, reused, breached and missing-2FA passwords.
//! Breach counts come from a cache of Have I Been Pwned answers the session keeps in memory.

use std::collections::{BTreeSet, HashMap};

use keepsake_core::model::{Item, ItemKind};
use keepsake_core::watchtower::{self, hibp::sha1_hex_upper, FindingKind};
use serde::Serialize;

use crate::bridge::site::Site;
use crate::dto::ItemSummary;

/// Registrable domains known to offer authenticator-app codes; see the file's header.
const TOTP_SITES: &str = include_str!("../assets/totp-sites.txt");

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub item: ItemSummary,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub breached: Vec<Finding>,
    pub reused: Vec<Finding>,
    pub weak: Vec<Finding>,
    pub missing_two_factor: Vec<Finding>,
    /// Every current password has a cached breach answer.
    pub breaches_checked: bool,
    /// Distinct passwords without a breach answer yet.
    pub unchecked_passwords: usize,
}

/// `breaches` maps upper-case SHA-1 hex of a password to its HIBP count.
pub fn report(items: &[Item], breaches: &HashMap<String, u64>) -> Report {
    let by_id: HashMap<_, _> = items.iter().map(|i| (i.id, i)).collect();
    let finding = |id, detail: String| Finding {
        item: ItemSummary::of(by_id[&id]),
        detail,
    };
    let weak = watchtower::weak(items)
        .into_iter()
        .map(|f| match f.kind {
            FindingKind::Weak { score } => {
                finding(f.item_id, format!("Weak password (strength {score} of 4)"))
            }
            _ => unreachable!("weak() only reports weak passwords"),
        })
        .collect();
    let reused = watchtower::reused(items)
        .into_iter()
        .map(|f| match f.kind {
            FindingKind::Reused { count } => {
                let others = count - 1;
                let s = if others == 1 { "" } else { "s" };
                finding(
                    f.item_id,
                    format!("Same password as {others} other item{s}"),
                )
            }
            _ => unreachable!("reused() only reports reuse"),
        })
        .collect();
    let breached = items
        .iter()
        .filter_map(|item| {
            let count = *breaches.get(&sha1_hex_upper(password(item)?))?;
            (count > 0).then(|| {
                finding(
                    item.id,
                    format!("Found {} times in data breaches", thousands(count)),
                )
            })
        })
        .collect();
    let missing_two_factor = items
        .iter()
        .filter_map(|item| {
            let domain = totp_domain(item)?;
            Some(finding(
                item.id,
                format!("{domain} offers one-time passwords"),
            ))
        })
        .collect();
    let unchecked_passwords = unchecked_hashes(items, breaches).len();
    let mut report = Report {
        breached,
        reused,
        weak,
        missing_two_factor,
        breaches_checked: unchecked_passwords == 0,
        unchecked_passwords,
    };
    for list in [
        &mut report.breached,
        &mut report.reused,
        &mut report.weak,
        &mut report.missing_two_factor,
    ] {
        list.sort_by(|a, b| {
            a.item
                .title
                .to_lowercase()
                .cmp(&b.item.title.to_lowercase())
                .then(a.item.id.cmp(&b.item.id))
        });
    }
    report
}

/// Distinct password hashes with no cached breach answer, sorted.
pub fn unchecked_hashes(items: &[Item], breaches: &HashMap<String, u64>) -> Vec<String> {
    items
        .iter()
        .filter_map(password)
        .map(sha1_hex_upper)
        .filter(|h| !breaches.contains_key(h))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn password(item: &Item) -> Option<&str> {
    item.password().filter(|p| !p.is_empty())
}

/// The site's domain when this login has no one-time password but its site offers them.
fn totp_domain(item: &Item) -> Option<String> {
    if item.kind != ItemKind::Login || item.totp().is_some() {
        return None;
    }
    item.urls.iter().find_map(|url| {
        let url = if url.contains("://") {
            url.clone()
        } else {
            format!("https://{url}")
        };
        let domain = Site::of(&url)?.domain;
        totp_sites().any(|d| d == domain).then_some(domain)
    })
}

fn totp_sites() -> impl Iterator<Item = &'static str> {
    TOTP_SITES
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
}

/// 3861493 → "3,861,493".
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_core::model::{Field, FieldValue};
    use uuid::Uuid;

    fn login(title: &str, password: &str, url: &str) -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, title, 0);
        if !password.is_empty() {
            item.set_password(password, 0);
        }
        if !url.is_empty() {
            item.urls.push(url.into());
        }
        item
    }

    fn titles(list: &[Finding]) -> Vec<&str> {
        list.iter().map(|f| f.item.title.as_str()).collect()
    }

    #[test]
    fn weak_and_reused_with_details() {
        let items = [
            login("Bank", "password", ""),
            login("Alpha", "Tr0ub4dor&3-horse-staple!", ""),
            login("Zulu", "Tr0ub4dor&3-horse-staple!", ""),
        ];
        let r = report(&items, &HashMap::new());
        assert_eq!(titles(&r.weak), ["Bank"]);
        assert!(r.weak[0].detail.starts_with("Weak password (strength "));
        assert_eq!(titles(&r.reused), ["Alpha", "Zulu"]);
        assert_eq!(r.reused[0].detail, "Same password as 1 other item");
    }

    #[test]
    fn breaches_come_from_the_cache_only() {
        let items = [
            login("Old", "password", ""),
            login("New", "n3w-Unique-Pass!", ""),
        ];
        let r = report(&items, &HashMap::new());
        assert!(r.breached.is_empty());
        assert!(!r.breaches_checked);
        assert_eq!(r.unchecked_passwords, 2);

        let mut cache = HashMap::new();
        cache.insert(sha1_hex_upper("password"), 3_861_493);
        cache.insert(sha1_hex_upper("n3w-Unique-Pass!"), 0);
        let r = report(&items, &cache);
        assert_eq!(titles(&r.breached), ["Old"]);
        assert_eq!(
            r.breached[0].detail,
            "Found 3,861,493 times in data breaches"
        );
        assert!(r.breaches_checked);
        assert_eq!(r.unchecked_passwords, 0);
    }

    #[test]
    fn unchecked_hashes_are_distinct_and_skip_empty_passwords() {
        let items = [
            login("A", "same", ""),
            login("B", "same", ""),
            login("C", "", ""),
        ];
        assert_eq!(
            unchecked_hashes(&items, &HashMap::new()),
            [sha1_hex_upper("same")]
        );
    }

    #[test]
    fn missing_two_factor_for_known_sites_without_a_code() {
        let mut with_code = login("GitHub work", "x", "https://github.com/login");
        with_code.fields.push(Field {
            id: "otp".into(),
            label: "one-time password".into(),
            value: FieldValue::Totp("JBSWY3DPEHPK3PXP".into()),
            purpose: None,
        });
        let items = [
            login("GitHub", "x", "https://github.com/login"),
            login("Google", "x", "accounts.google.com"),
            login("Local NAS", "x", "http://192.168.1.10"),
            login("Unknown", "x", "https://example.org"),
            with_code,
        ];
        let r = report(&items, &HashMap::new());
        assert_eq!(titles(&r.missing_two_factor), ["GitHub", "Google"]);
        assert_eq!(
            r.missing_two_factor[0].detail,
            "github.com offers one-time passwords"
        );
    }

    #[test]
    fn site_list_is_clean() {
        let sites: Vec<_> = totp_sites().collect();
        assert!(sites.len() > 40);
        for d in &sites {
            assert_eq!(*d, d.to_ascii_lowercase(), "{d}");
            assert_eq!(
                Site::of(&format!("https://{d}")).unwrap().domain,
                *d,
                "{d} is not eTLD+1"
            );
        }
    }

    #[test]
    fn thousands_groups_digits() {
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(3_861_493), "3,861,493");
    }
}
```

`lib.rs`: `pub mod watchtower;`.

`session/mod.rs` — `use crate::watchtower;`; field `/// Have I Been Pwned answers by password SHA-1 (upper-case hex); forgotten on lock. breaches: std::collections::HashMap<String, u64>,` (init `std::collections::HashMap::new()`); in `lock()` add `self.breaches.clear();`; methods:

```rust
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
```

- [ ] **Step 5: Run** `cargo test -p keepsake-session` + clippy. **Step 6: Commit** — `git commit -m "Session: Watchtower report with cached breach answers and missing 2FA"`

---

### Task 9: Watchtower commands and view

**Files:** Modify `commands.rs`, `lib.rs`, `app/src/api.ts`, `app/src/styles.css`; create `app/src/components/Watchtower.tsx`, `Watchtower.test.tsx`.

- [ ] **Step 1: Commands** — imports `use keepsake_core::watchtower::Hibp;` and `use keepsake_session::watchtower::Report;`, then:

```rust
#[tauri::command(async)]
pub fn watchtower(state: State<'_, AppState>) -> CmdResult<Report> {
    lock_session(&state).watchtower(now())
}

/// Asks Have I Been Pwned about every unchecked password, without holding the session: only
/// the first five hex characters of each SHA-1 leave the Mac.
#[tauri::command(async)]
pub fn check_breaches(state: State<'_, AppState>) -> CmdResult<Report> {
    let hashes = lock_session(&state).breach_hashes_to_check(now())?;
    let hibp = Hibp::default();
    let mut results = Vec::with_capacity(hashes.len());
    for hash in hashes {
        match hibp.breach_count_for_hash(&hash) {
            Ok(count) => results.push((hash, count)),
            Err(e) => {
                // Keep what we learned; the next check continues from there.
                lock_session(&state).record_breaches(results);
                return Err(CmdError::new(
                    ErrorKind::Other,
                    format!("Couldn't reach Have I Been Pwned: {e}"),
                ));
            }
        }
    }
    let mut session = lock_session(&state);
    session.record_breaches(results);
    session.watchtower(now())
}
```

Register both; `cargo clippy -p keepsake-app --all-targets -- -D warnings`.

- [ ] **Step 2: API** — in `api.ts`:

```ts
export interface WatchtowerFinding {
  item: ItemSummary;
  detail: string;
}

export interface WatchtowerReport {
  breached: WatchtowerFinding[];
  reused: WatchtowerFinding[];
  weak: WatchtowerFinding[];
  missingTwoFactor: WatchtowerFinding[];
  breachesChecked: boolean;
  uncheckedPasswords: number;
}

/** Items with at least one Watchtower finding. */
export function watchtowerCount(report: WatchtowerReport): number {
  const lists = [report.breached, report.reused, report.weak, report.missingTwoFactor];
  return new Set(lists.flatMap((list) => list.map((f) => f.item.id))).size;
}

export interface ImportPreview {
  vaults: { name: string; items: number }[];
  skipped: { title: string; reason: string }[];
  totalItems: number;
}
```

and in `api`: `watchtower: () => invoke<WatchtowerReport>("watchtower"), checkBreaches: () => invoke<WatchtowerReport>("check_breaches"),`.

- [ ] **Step 3: Failing tests** — `Watchtower.test.tsx`:

```tsx
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, watchtowerCount, type ItemSummary, type WatchtowerReport } from "../api";
import { Watchtower } from "./Watchtower";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, checkBreaches: vi.fn() } };
});

const summary = (id: string, title: string): ItemSummary => ({
  id, vaultId: "v1", kind: "login", title, subtitle: "", favorite: false, hasTotp: false, updatedAt: 0, damaged: false,
});

const report: WatchtowerReport = {
  breached: [],
  reused: [
    { item: summary("a", "Bank"), detail: "Same password as 1 other item" },
    { item: summary("b", "Shop"), detail: "Same password as 1 other item" },
  ],
  weak: [{ item: summary("b", "Shop"), detail: "Weak password (strength 1 of 4)" }],
  missingTwoFactor: [{ item: summary("c", "GitHub"), detail: "github.com offers one-time passwords" }],
  breachesChecked: false,
  uncheckedPasswords: 2,
};

beforeEach(() => {
  vi.mocked(api.checkBreaches).mockReset();
});

test("counts per category and opens an item", async () => {
  const user = userEvent.setup();
  const onOpen = vi.fn();
  render(<Watchtower report={report} selectedId={null} onOpen={onOpen} onReport={vi.fn()} />);
  expect(screen.getByRole("tab", { name: "Compromised (–)" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tab", { name: "Weak (1)" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Missing 2FA (1)" })).toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Reused (2)" }));
  const list = screen.getByRole("list", { name: "Reused" });
  expect(within(list).getAllByRole("button").map((b) => b.textContent)).toEqual([
    "BankSame password as 1 other item",
    "ShopSame password as 1 other item",
  ]);
  await user.click(within(list).getByRole("button", { name: /Shop/ }));
  expect(onOpen).toHaveBeenCalledWith("b");
});

test("breach check is opt-in and explains k-anonymity", async () => {
  const user = userEvent.setup();
  const onReport = vi.fn();
  const checked = { ...report, breachesChecked: true, uncheckedPasswords: 0, breached: [{ item: summary("a", "Bank"), detail: "Found 12 times in data breaches" }] };
  vi.mocked(api.checkBreaches).mockResolvedValue(checked);
  render(<Watchtower report={report} selectedId={null} onOpen={vi.fn()} onReport={onReport} />);
  expect(screen.getByText(/first 5 characters of each password's SHA-1 hash/)).toBeInTheDocument();
  expect(api.checkBreaches).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Check for breaches" }));
  await waitFor(() => expect(onReport).toHaveBeenCalledWith(checked));
});

test("a failed breach check shows the error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.checkBreaches).mockRejectedValue({ kind: "other", message: "Couldn't reach Have I Been Pwned: timeout" });
  render(<Watchtower report={report} selectedId={null} onOpen={vi.fn()} onReport={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Check for breaches" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't reach Have I Been Pwned");
});

test("after the check, an empty category says so", () => {
  const clean = { ...report, breachesChecked: true, uncheckedPasswords: 0 };
  render(<Watchtower report={clean} selectedId={null} onOpen={vi.fn()} onReport={vi.fn()} />);
  expect(screen.getByRole("tab", { name: "Compromised (0)" })).toBeInTheDocument();
  expect(screen.getByText("No passwords found in known breaches")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Check for breaches" })).not.toBeInTheDocument();
});

test("watchtowerCount counts each item once", () => {
  expect(watchtowerCount(report)).toBe(3);
});
```

- [ ] **Step 4: Run** `pnpm test Watchtower` — fails.
- [ ] **Step 5: Implement** — `Watchtower.tsx`:

```tsx
import { useState } from "react";
import { api, errorMessage, type WatchtowerReport } from "../api";

type Category = "breached" | "reused" | "weak" | "missingTwoFactor";

const CATEGORIES: { key: Category; label: string; empty: string }[] = [
  { key: "breached", label: "Compromised", empty: "No passwords found in known breaches" },
  { key: "reused", label: "Reused", empty: "No password is used twice" },
  { key: "weak", label: "Weak", empty: "No weak passwords" },
  { key: "missingTwoFactor", label: "Missing 2FA", empty: "No known sites without a one-time password" },
];

interface Props {
  report: WatchtowerReport | null;
  selectedId: string | null;
  onOpen: (id: string) => void;
  onReport: (report: WatchtowerReport) => void;
}

/** The middle column in Watchtower mode: problem categories and the affected items. */
export function Watchtower({ report, selectedId, onOpen, onReport }: Props) {
  const [category, setCategory] = useState<Category>("breached");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function check() {
    setBusy(true);
    setError(null);
    try {
      onReport(await api.checkBreaches());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const current = CATEGORIES.find((c) => c.key === category)!;
  const findings = report?.[category] ?? [];
  const notChecked = report !== null && !report.breachesChecked;

  return (
    <section className="list watchtower" aria-label="Watchtower">
      <div className="toolbar">
        <h2>Watchtower</h2>
      </div>
      {report === null ? (
        <p className="empty">Checking your passwords…</p>
      ) : (
        <>
          <div className="categories" role="tablist" aria-label="Problems">
            {CATEGORIES.map((c) => {
              const count = c.key === "breached" && notChecked && report.breached.length === 0 ? "–" : report[c.key].length;
              return (
                <button
                  key={c.key}
                  role="tab"
                  aria-selected={category === c.key}
                  aria-label={`${c.label} (${count})`}
                  onClick={() => setCategory(c.key)}
                >
                  <span className="count">{count}</span>
                  <span>{c.label}</span>
                </button>
              );
            })}
          </div>
          {category === "breached" && notChecked && (
            <div className="breach-check">
              <p>
                Check your passwords against the Have I Been Pwned list of breached passwords. Only the first 5 characters
                of each password's SHA-1 hash are sent (k-anonymity): your passwords never leave this Mac.
              </p>
              <button className="primary" onClick={check} disabled={busy}>
                {busy ? "Checking…" : "Check for breaches"}
              </button>
              {error && (
                <p className="error" role="alert">
                  {error}
                </p>
              )}
            </div>
          )}
          {findings.length === 0 ? (
            !(category === "breached" && notChecked) && <p className="empty">{current.empty}</p>
          ) : (
            <ul aria-label={current.label}>
              {findings.map((f) => (
                <li key={f.item.id}>
                  <button aria-current={f.item.id === selectedId} onClick={() => onOpen(f.item.id)}>
                    <span className="text">
                      <span>{f.item.title || "Untitled"}</span>
                      <span className="subtitle">{f.detail}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}
```

`styles.css` append:

```css
.watchtower h2 { margin: 6px 4px 0; font-size: 20px; }
.watchtower .categories { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 0 14px 12px; }
.watchtower .categories button { flex-direction: column; align-items: flex-start; gap: 2px; border-radius: 14px; padding: 10px 12px; background: var(--surface-2); border-color: transparent; font-weight: 600; }
.watchtower .categories button[aria-selected="true"] { background: var(--surface); box-shadow: var(--shadow); }
.watchtower .categories .count { font-family: var(--mono); font-size: 20px; font-weight: 700; }
.watchtower .breach-check { margin: 0 14px 12px; padding: 12px; border-radius: 14px; background: var(--surface); display: flex; flex-direction: column; gap: 10px; font-size: 13px; }
.watchtower .breach-check p { margin: 0; color: var(--muted); }
```

- [ ] **Step 6: Run** `pnpm typecheck && pnpm test`. **Step 7: Commit** — `git commit -m "Add the Watchtower view and its commands"`

---

### Task 10: Watchtower in the sidebar and main window

**Files:** Modify `icons.tsx`, `Sidebar.tsx`, `Sidebar.test.tsx`, `Main.tsx`, `Main.test.tsx`, `App.test.tsx`.

- [ ] **Step 1: Failing tests.** `Sidebar.test.tsx` append:

```tsx
test("watchtower entry with its count", async () => {
  const user = userEvent.setup();
  const onSelect = vi.fn();
  render(
    <Sidebar
      vaults={vaults}
      selection={{ kind: "all" }}
      watchtowerCount={4}
      onSelect={onSelect}
      onNewVault={vi.fn()}
      onRenameVault={vi.fn()}
      onDeleteVault={vi.fn()}
      onImport={vi.fn()}
      onLock={vi.fn()}
      onSettings={vi.fn()}
    />,
  );
  const button = screen.getByRole("button", { name: /Watchtower/ });
  expect(button).toHaveTextContent("4");
  await user.click(button);
  expect(onSelect).toHaveBeenCalledWith({ kind: "watchtower" });
});
```

`Main.test.tsx` — add `watchtower: vi.fn(), checkBreaches: vi.fn(),` to the mock; in `beforeEach`:

```tsx
  vi.mocked(api.watchtower).mockReset().mockResolvedValue({
    breached: [],
    reused: [],
    weak: [{ item: github, detail: "Weak password (strength 1 of 4)" }],
    missingTwoFactor: [],
    breachesChecked: false,
    uncheckedPasswords: 1,
  });
```

and append:

```tsx
test("watchtower lists problems and opens the item", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  const entry = await screen.findByRole("button", { name: /Watchtower/ });
  await waitFor(() => expect(entry).toHaveTextContent("1"));
  await user.click(entry);
  await user.click(screen.getByRole("tab", { name: "Weak (1)" }));
  await user.click(screen.getByRole("button", { name: /GitHub/ }));
  expect(await screen.findByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  expect(api.item).toHaveBeenCalledWith("i1");
});

test("saving an item refreshes the watchtower", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByText("GitHub"));
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(api.watchtower).toHaveBeenCalledTimes(2));
});
```

`App.test.tsx` — add `watchtower: vi.fn().mockRejectedValue({ kind: "locked", message: "locked" }),` to its mock.

- [ ] **Step 2: Run** — failures.
- [ ] **Step 3: Implement.**

`icons.tsx`: `export const IconShield = icon(<path d="M12 3.5l7 2.8v5.2c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6.3z" />);`

`Sidebar.tsx` — `Selection` gains `| { kind: "watchtower" }`; prop `/** Items with Watchtower findings; hidden while unknown. */ watchtowerCount?: number;` (destructured); after the Recently Deleted button:

```tsx
      <button className="nav" aria-current={isCurrent({ kind: "watchtower" })} onClick={() => onSelect({ kind: "watchtower" })}>
        <IconShield />
        <span>Watchtower</span>
        {watchtowerCount !== undefined && <span className="count">{watchtowerCount}</span>}
      </button>
```

`Main.tsx` — import `watchtowerCount`, `type WatchtowerReport` and `Watchtower`; state `const [report, setReport] = useState<WatchtowerReport | null>(null);`;

```tsx
  const loadWatchtower = useCallback(
    () =>
      api
        .watchtower()
        .then(setReport)
        .catch(() => setReport(null)),
    [],
  );
  const refresh = useCallback(
    () => Promise.all([loadVaults(), loadItems(), loadWatchtower()]),
    [loadVaults, loadItems, loadWatchtower],
  );
```

the mount effect calls `loadVaults(); loadWatchtower();` (deps `[loadVaults, loadWatchtower]`); `targetVault` is `undefined` for `trash` and `watchtower`:

```tsx
  const targetVault =
    selection.kind === "vault"
      ? selection.id
      : selection.kind === "trash" || selection.kind === "watchtower"
        ? undefined
        : vaults[0]?.id;
```

`Sidebar` gets `watchtowerCount={report ? watchtowerCount(report) : undefined}`, and the middle column switches:

```tsx
      {selection.kind === "watchtower" ? (
        <Watchtower
          report={report}
          selectedId={pane.mode === "view" ? pane.id : null}
          onOpen={(id) => leaveEditor(() => setPane({ mode: "view", id }))}
          onReport={setReport}
        />
      ) : (
        <ItemList … unchanged … />
      )}
```

The right pane already shows `ItemDetail`/`ItemEditor` for any non-trash selection, so items open, edit and delete from Watchtower as usual, and `refresh()` reloads the report after each save or delete.

- [ ] **Step 4: Run** `pnpm typecheck && pnpm test`. **Step 5: Commit** — `git commit -m "Show Watchtower in the sidebar with its count"`

---

## Part C — Menu bar and quick search

### Task 11: Session — copy for quick search

**Files:** Modify `session/mod.rs`, `lib.rs`, `session/polish_tests.rs`.

- [ ] **Step 1: Failing test** (append to `polish_tests.rs`):

```rust
#[test]
fn quick_copy_finds_fields_by_purpose() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "hunter2");
    // Imported logins may use other field ids; purpose is what counts.
    item.fields[0].id = "imported-user".into();
    item.fields[1].id = "imported-pass".into();
    let item = s.save_item(item, 1_000).unwrap();
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Username, 1_000).unwrap(),
        "ivan"
    );
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Password, 1_000).unwrap(),
        "hunter2"
    );
    assert!(s.clipboard_pending(), "the clipboard guard is armed");
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Totp, 1_000)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    let note = s.new_item(p, ItemKind::SecureNote, 1_000).unwrap();
    let mut note = note;
    note.title = "Note".into();
    let note = s.save_item(note, 1_000).unwrap();
    let err = s
        .copy_quick(note.id, QuickCopy::Password, 1_000)
        .unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::NotFound, "This item has no password")
    );
}
```

- [ ] **Step 2: Run** — compile error.
- [ ] **Step 3: Implement** — after `DEFAULT_VAULT` in `session/mod.rs`:

```rust
/// What the quick-search window copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuickCopy {
    Username,
    Password,
    Totp,
}
```

in `impl Session` after `copy_value`:

```rust
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
```

`lib.rs`: re-export `QuickCopy` (`pub use session::{BridgeEvent, PairedBrowser, PairingRequest, QuickCopy, Session, Status};`).

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `git commit -m "Session: copy username, password or code by purpose for quick search"`

---

### Task 12: Shell — menu bar icon, quick-search window, ⌘⇧Space

**Files:** Modify `app/src-tauri/Cargo.toml`, `src/lib.rs`, `src/commands.rs`, `capabilities/default.json`; create `src/tray.rs`, `src/quick.rs`.

- [ ] **Step 1: Dependencies** — `Cargo.toml`: `tauri = { version = "2", features = ["macos-private-api", "tray-icon"] }` and `tauri-plugin-global-shortcut = "2"` (resolves to 2.4.x; 3.0 is alpha — do not use).

- [ ] **Step 2: Failing test** — create `src/tray.rs` with only the test module and an empty `pub fn glyph(size: u32) -> Vec<u8> { vec![] }` + `pub const GLYPH_SIZE: u32 = 36;`, add `mod tray;` to `lib.rs`, run `cargo test -p keepsake-app tray` → fails.

- [ ] **Step 3: Implement** — `src/tray.rs`:

```rust
//! Menu bar icon: Open Keepsake, Quick search, Lock, Quit.

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

use crate::{lock_session, quick, AppState};

pub const GLYPH_SIZE: u32 = 36;

/// The keyhole mark as a template image (black on transparent; macOS tints it).
pub fn glyph(size: u32) -> Vec<u8> {
    let s = size as f32 / 24.0; // the mark is drawn on a 24×24 grid, like Keyhole.tsx
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (px, py) = ((x as f32 + 0.5) / s, (y as f32 + 0.5) / s);
            let in_circle = (px - 12.0).powi(2) + (py - 9.0).powi(2) <= 16.0;
            // Trapezoid from (10.2, 11.5)-(13.8, 11.5) down to (9, 19.5)-(15, 19.5).
            let t = (py - 11.5) / 8.0;
            let half = 1.8 + 1.2 * t;
            let in_stem = (0.0..=1.0).contains(&t) && (px - 12.0).abs() <= half;
            if in_circle || in_stem {
                rgba[((y * size + x) * 4 + 3) as usize] = 255;
            }
        }
    }
    rgba
}

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Keepsake", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Quick Search", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Keepsake", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &quick, &lock, &separator, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(Image::new_owned(glyph(GLYPH_SIZE), GLYPH_SIZE, GLYPH_SIZE))
        .icon_as_template(true)
        .tooltip("Keepsake")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "quick" => quick::toggle(app),
            "lock" => {
                lock_session(&app.state::<AppState>()).lock();
                let _ = app.emit("locked", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_is_a_keyhole() {
        let size = GLYPH_SIZE;
        let px = glyph(size);
        assert_eq!(px.len(), (size * size * 4) as usize);
        let alpha = |x: u32, y: u32| px[((y * size + x) * 4 + 3) as usize];
        assert_eq!(alpha(size / 2, size * 9 / 24), 255, "circle centre");
        assert_eq!(alpha(size / 2, size * 18 / 24), 255, "stem");
        assert_eq!(alpha(0, 0), 0, "corner");
        assert_eq!(alpha(size / 2, size - 1), 0, "below the stem");
        assert!(
            px.chunks(4).all(|p| p[..3] == [0, 0, 0]),
            "template images are black"
        );
    }
}
```

`src/quick.rs` (Task 16 adds `HoldOpen`):

```rust
//! The ⌘⇧Space quick-search window: small, floating, hidden when it loses focus.

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

pub const LABEL: &str = "quick";

pub fn shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::Space)
}

/// Creates the hidden window and registers the shortcut. A taken shortcut is not fatal.
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let window = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html#quick".into()))
        .title("Keepsake Quick Search")
        .inner_size(640.0, 420.0)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false)
        .center()
        .build()?;
    let handle = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Focused(false) = event {
            let _ = handle.hide();
        }
    });
    if let Err(e) = app.global_shortcut().register(shortcut()) {
        eprintln!("keepsake: ⌘⇧Space is not available: {e}");
    }
    Ok(())
}

pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, shortcut, event| {
            if *shortcut == self::shortcut() && event.state() == ShortcutState::Pressed {
                toggle(app);
            }
        })
        .build()
}

pub fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit_to(LABEL, "quick-open", ());
}

pub fn hide(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.hide();
    }
}
```

`commands.rs` — import `Emitter` and `QuickCopy`; `unlock` and `lock` now tell every window:

```rust
#[tauri::command(async)]
pub fn unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).unlock(&password, now())?;
    // Both windows (main and quick search) follow the lock state.
    let _ = app.emit("unlocked", ());
    Ok(())
}

#[tauri::command(async)]
pub fn lock(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    lock_session(&state).lock();
    let _ = app.emit("locked", ());
    Ok(())
}

#[tauri::command(async)]
pub fn quick_copy(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    what: QuickCopy,
) -> CmdResult<()> {
    let mut session = lock_session(&state);
    let text = session.copy_quick(id, what, now())?;
    app.clipboard()
        .write_text(text)
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Clipboard: {e}")))
}

#[tauri::command(async)]
pub fn quick_hide(app: AppHandle) {
    crate::quick::hide(&app);
}
```

`lib.rs` — `mod quick;`; register `quick_copy`, `quick_hide`; the builder becomes:

```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(quick::plugin())
        .setup(|app| {
            let path = app.path().app_data_dir()?.join("keepsake.db");
            app.manage(AppState(Mutex::new(Session::new(
                path,
                KdfParams::DEFAULT,
                now(),
            ))));
            // After `manage`: both call commands that need the session. Neither is essential;
            // without them Keepsake still works from its main window.
            if let Err(e) = tray::install(app.handle()) {
                eprintln!("keepsake: menu bar icon unavailable: {e}");
            }
            if let Err(e) = quick::install(app.handle()) {
                eprintln!("keepsake: quick search unavailable: {e}");
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || housekeeping(handle));
            if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                let socket = keepsake_session::bridge::wire::socket_path(&home);
                let bridge_app = app.handle().clone();
                std::thread::spawn(move || bridge::serve(bridge_app, socket));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_vault_file,
            commands::unlock,
            commands::lock,
            commands::start_over,
            commands::rename_vault,
            commands::delete_vault,
            commands::watchtower,
            commands::check_breaches,
            commands::quick_copy,
            commands::quick_hide,
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
            commands::deleted_items,
            commands::restore_item,
            commands::settings,
            commands::update_settings,
            commands::change_password,
            commands::connect_browsers,
            commands::approve_pairing,
            commands::deny_pairing,
            commands::paired_browsers,
            commands::remove_paired_browser,
        ])
        .on_window_event(|window, event| {
            // Closing the main window keeps Keepsake in the menu bar; Quit is in the tray menu.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Keepsake")
        .run(|app, event| {
            if let tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = event
            {
                tray::show_main(app);
            }
        });
}
```

`capabilities/default.json`: `"windows": ["main", "quick"]`.

- [ ] **Step 4: Build and test** — `(cd app && pnpm build) && cargo clippy -p keepsake-app --all-targets -- -D warnings && cargo test -p keepsake-app`.
- [ ] **Step 5: Commit** — `git commit -m "Menu bar icon and a hidden quick-search window on Cmd+Shift+Space"`

---

### Task 13: Quick-search UI

**Files:** Modify `app/src/api.ts`, `app/src/App.tsx`, `App.test.tsx`, `app/src/main.tsx`, `app/src/styles.css`; create `components/QuickSearch.tsx`, `QuickSearch.test.tsx`, `components/QuickApp.tsx`, `QuickApp.test.tsx`.

- [ ] **Step 1: API** — `export type QuickCopy = "username" | "password" | "totp";` and in `api`:

```ts
  onUnlocked: (callback: () => void): Promise<UnlistenFn> => listen("unlocked", () => callback()),
  /** The quick-search window was just shown (⌘⇧Space or the menu bar). */
  onQuickOpen: (callback: () => void): Promise<UnlistenFn> => listen("quick-open", () => callback()),
  quickCopy: (id: string, what: QuickCopy) => invoke<void>("quick_copy", { id, what }),
  quickHide: () => invoke<void>("quick_hide"),
```

- [ ] **Step 2: Failing tests** — `QuickSearch.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary } from "../api";
import { QuickSearch } from "./QuickSearch";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, items: vi.fn(), quickCopy: vi.fn() } };
});

const row = (id: string, title: string, hasTotp = false): ItemSummary => ({
  id, vaultId: "v1", kind: "login", title, subtitle: "ivan", favorite: false, hasTotp, updatedAt: 0, damaged: false,
});

beforeEach(() => {
  vi.mocked(api.items).mockReset().mockResolvedValue([row("i1", "GitHub", true), row("i2", "GitLab")]);
  vi.mocked(api.quickCopy).mockReset().mockResolvedValue(undefined);
});

test("searches as you type", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  expect(await screen.findByRole("option", { name: /GitHub/ })).toHaveAttribute("aria-selected", "true");
  await user.type(screen.getByLabelText("Quick search"), "git");
  await waitFor(() => expect(api.items).toHaveBeenLastCalledWith({ query: "git" }));
});

test("Enter copies the password, ⌘Enter the username, then closes", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<QuickSearch onDone={onDone} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{ArrowDown}{Enter}");
  expect(api.quickCopy).toHaveBeenLastCalledWith("i2", "password");
  await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
  await user.keyboard("{ArrowUp}{Meta>}{Enter}{/Meta}");
  expect(api.quickCopy).toHaveBeenLastCalledWith("i1", "username");
});

test("⌘C copies the one-time code when nothing is selected in the box", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{Meta>}c{/Meta}");
  expect(api.quickCopy).toHaveBeenCalledWith("i1", "totp");
  await user.keyboard("{ArrowDown}{Meta>}c{/Meta}");
  expect(await screen.findByRole("alert")).toHaveTextContent("no one-time password");
  expect(api.quickCopy).toHaveBeenCalledTimes(1);
});

test("clicking a result copies its password", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  await user.click(await screen.findByRole("option", { name: /GitLab/ }));
  expect(api.quickCopy).toHaveBeenCalledWith("i2", "password");
});

test("copy errors are shown", async () => {
  const user = userEvent.setup();
  vi.mocked(api.quickCopy).mockRejectedValue({ kind: "notFound", message: "This item has no password" });
  const onDone = vi.fn();
  render(<QuickSearch onDone={onDone} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{Enter}");
  expect(await screen.findByRole("alert")).toHaveTextContent("This item has no password");
  expect(onDone).not.toHaveBeenCalled();
});
```

`QuickApp.test.tsx`:

```tsx
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { QuickApp } from "./QuickApp";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      status: vi.fn(),
      items: vi.fn(),
      quickHide: vi.fn(),
      onLocked: vi.fn(),
      onUnlocked: vi.fn(),
      onQuickOpen: vi.fn(),
    },
  };
});

const callbacks: Record<string, () => void> = {};

beforeEach(() => {
  vi.mocked(api.status).mockReset().mockResolvedValue("unlocked");
  vi.mocked(api.items).mockReset().mockResolvedValue([]);
  vi.mocked(api.quickHide).mockReset().mockResolvedValue(undefined);
  for (const name of ["onLocked", "onUnlocked", "onQuickOpen"] as const) {
    vi.mocked(api[name])
      .mockReset()
      .mockImplementation(async (cb: () => void) => {
        callbacks[name] = cb;
        return () => {};
      });
  }
});

test("unlocked shows the search box; Escape hides the window", async () => {
  const user = userEvent.setup();
  render(<QuickApp />);
  expect(await screen.findByLabelText("Quick search")).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(api.quickHide).toHaveBeenCalled();
});

test("locked shows the unlock form and follows lock events", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<QuickApp />);
  expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
  await waitFor(() => expect(callbacks.onUnlocked).toBeDefined());
  act(() => callbacks.onUnlocked());
  expect(await screen.findByLabelText("Quick search")).toBeInTheDocument();
  act(() => callbacks.onLocked());
  expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
});

test("opening the window again starts with an empty search", async () => {
  const user = userEvent.setup();
  render(<QuickApp />);
  await user.type(await screen.findByLabelText("Quick search"), "git");
  act(() => callbacks.onQuickOpen());
  await waitFor(() => expect(screen.getByLabelText("Quick search")).toHaveValue(""));
  expect(api.status).toHaveBeenCalledTimes(2);
});
```

`App.test.tsx` — import `act, waitFor`; add `onUnlocked: vi.fn(),` to the mock and:

```tsx
let unlockedCallback: (() => void) | null = null;

// in beforeEach:
  unlockedCallback = null;
  vi.mocked(api.onUnlocked)
    .mockReset()
    .mockImplementation(async (cb) => {
      unlockedCallback = cb;
      return () => {};
    });

test("unlocking in the quick-search window unlocks the main window too", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Unlock" })).toBeInTheDocument();
  await waitFor(() => expect(unlockedCallback).not.toBeNull());
  act(() => unlockedCallback!());
  expect(await screen.findByRole("button", { name: "Lock" })).toBeInTheDocument();
});
```

- [ ] **Step 3: Run** `pnpm test` — failures.
- [ ] **Step 4: Implement** — `QuickSearch.tsx`:

```tsx
import { useEffect, useState, type KeyboardEvent } from "react";
import { api, errorMessage, type ItemSummary, type QuickCopy } from "../api";
import { IconSearch } from "./icons";

const MAX_RESULTS = 50;

/** Search box and results of the ⌘⇧Space window. Copying closes the window via `onDone`. */
export function QuickSearch({ onDone }: { onDone: () => void }) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [index, setIndex] = useState(0);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .items({ query })
      .then((list) => {
        if (!live) return;
        setItems(list.filter((i) => !i.damaged).slice(0, MAX_RESULTS));
        setIndex(0);
      })
      .catch((e) => live && setMessage(errorMessage(e)));
    return () => {
      live = false;
    };
  }, [query]);

  async function copy(what: QuickCopy, item = items[index]) {
    if (!item) return;
    setMessage(null);
    try {
      await api.quickCopy(item.id, what);
      onDone();
    } catch (e) {
      setMessage(errorMessage(e));
    }
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    const input = e.currentTarget;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIndex((i) => Math.min(i + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      void copy(e.metaKey ? "username" : "password");
    } else if (e.metaKey && e.key.toLowerCase() === "c" && input.selectionStart === input.selectionEnd) {
      // ⌘C with no text selected copies the one-time code instead of nothing.
      e.preventDefault();
      if (items[index]?.hasTotp) void copy("totp");
      else setMessage("This item has no one-time password");
    }
  }

  return (
    <div className="quick-search">
      <div className="search">
        <IconSearch />
        <input
          autoFocus
          aria-label="Quick search"
          placeholder="Search Keepsake"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
        />
      </div>
      {items.length === 0 ? (
        <p className="empty">{query ? "Nothing matches your search" : "No items yet"}</p>
      ) : (
        <ul role="listbox" aria-label="Results">
          {items.map((item, i) => (
            <li
              key={item.id}
              role="option"
              aria-selected={i === index}
              onMouseEnter={() => setIndex(i)}
              onClick={() => void copy("password", item)}
            >
              <span className="title">{item.title || "Untitled"}</span>
              <span className="subtitle">{item.subtitle}</span>
              {item.hasTotp && <span className="badge">2FA</span>}
            </li>
          ))}
        </ul>
      )}
      {message && (
        <p className="error" role="alert">
          {message}
        </p>
      )}
      <footer className="hints">↵ copy password · ⌘↵ copy username · ⌘C copy one-time code · esc close</footer>
    </div>
  );
}
```

`QuickApp.tsx`:

```tsx
import { useEffect, useState } from "react";
import { api, type Status } from "../api";
import { QuickSearch } from "./QuickSearch";
import { Unlock } from "./Unlock";

/** Root of the ⌘⇧Space window (`index.html#quick`). */
export function QuickApp() {
  const [status, setStatus] = useState<Status | null>(null);
  // Remounts the search box each time the window opens, so it starts empty and focused.
  const [opened, setOpened] = useState(0);

  useEffect(() => {
    const refresh = () => api.status().then(setStatus);
    refresh();
    const subscriptions = [
      api.onLocked(() => setStatus("locked")),
      api.onUnlocked(() => setStatus("unlocked")),
      api.onQuickOpen(() => {
        refresh();
        setOpened((n) => n + 1);
      }),
    ];
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.quickHide();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  if (status === null) return null;
  return (
    <div className="quick">
      {status === "unlocked" && <QuickSearch key={opened} onDone={() => void api.quickHide()} />}
      {status === "locked" && (
        <Unlock key={opened} onUnlocked={() => setStatus("unlocked")} onStartOver={() => setStatus("new")} />
      )}
      {status === "new" && <p className="empty">Set up Keepsake in its main window first.</p>}
    </div>
  );
}
```

`App.tsx` — subscribe to both events:

```tsx
    const subscriptions = [
      api.onLocked(() => setStatus("locked")),
      // Unlocked from the quick-search window.
      api.onUnlocked(() => setStatus((s) => (s === "locked" ? "unlocked" : s))),
    ];
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
    };
```

`main.tsx` — `import { QuickApp } from "./components/QuickApp";` and render `{window.location.hash === "#quick" ? <QuickApp /> : <App />}` inside `StrictMode`.

`styles.css` append:

```css
/* Quick search window (index.html#quick): a floating card on a transparent window. */
.quick { height: 100vh; padding: 10px; background: transparent; }
.quick > * { height: 100%; border-radius: 18px; background: var(--surface); border: 1px solid var(--line); box-shadow: var(--shadow-pop); overflow: hidden; }
.quick .center { background: var(--surface); }
.quick .auth { box-shadow: none; border: none; }
.quick-search { display: flex; flex-direction: column; }
.quick-search .search { position: relative; display: flex; align-items: center; padding: 12px; border-bottom: 1px solid var(--line); }
.quick-search .search svg { position: absolute; left: 24px; color: var(--muted); }
.quick-search .search input { padding-left: 36px; font-size: 16px; border-radius: 12px; }
.quick-search ul { list-style: none; margin: 0; padding: 6px; overflow-y: auto; flex: 1; }
.quick-search li { display: flex; align-items: baseline; gap: 10px; padding: 8px 12px; border-radius: 10px; cursor: default; }
.quick-search li[aria-selected="true"] { background: var(--hover); }
.quick-search .title { font-weight: 600; }
.quick-search .subtitle { color: var(--muted); font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.quick-search .badge { font-size: 10px; font-weight: 700; color: var(--muted); border: 1px solid var(--line); border-radius: 6px; padding: 1px 5px; }
.quick-search .error { margin: 0 12px 8px; }
.quick-search .hints { color: var(--muted); font-size: 11px; padding: 8px 14px; border-top: 1px solid var(--line); }
```

- [ ] **Step 5: Run** `pnpm typecheck && pnpm test && pnpm build`. **Step 6: Commit** — `git commit -m "Quick-search window: search, copy and unlock"`

---

## Part D — Touch ID

### Task 14: Session — wrapping the account key for the Secure Enclave

**Files:** Modify `crates/keepsake-session/Cargo.toml`, `src/lib.rs`; create `src/touchid.rs`.

- [ ] **Step 1: Dependency** — `p256 = { version = "0.13", features = ["ecdh"] }` (uses `rand_core` 0.6, so `rand::rngs::OsRng` from rand 0.8 works).
- [ ] **Step 2: Failing tests** — write the `#[cfg(test)]` parts of the file below first (`FakeEnclave` + `mod tests`) with stub `wrap`/`unwrap` that `todo!()`, add `pub mod touchid;` to `lib.rs`, run `cargo test -p keepsake-session touchid` → panics.
- [ ] **Step 3: Implement** — `src/touchid.rs`:

```rust
//! Touch ID unlock, minus the OS calls: the account key wrapped to a Secure Enclave key.
//!
//! The app creates a P-256 key inside the Secure Enclave that only works after Touch ID with
//! the fingerprints enrolled at that moment (`.biometryCurrentSet`). To wrap, we do ECDH with a
//! fresh ephemeral key against the enclave's public key (no prompt needed); to unwrap, the
//! enclave does the same ECDH with the ephemeral public key after Touch ID. The time of the
//! last master-password entry is bound into the ciphertext, so the 14-day limit can't be
//! extended by editing the record.

use data_encoding::BASE64;
use keepsake_core::crypto::{self, Key};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CmdError, CmdResult, ErrorKind};

/// The master password is required again this long after it was last entered.
pub const MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;
const LABEL: &str = "keepsake-touchid-v1";
const VERSION: u32 = 1;

/// What the keychain holds. Useless without this Mac's Secure Enclave and a matching finger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub version: u32,
    /// CryptoKit's opaque handle of the enclave key.
    #[serde(with = "b64")]
    pub enclave_key: Vec<u8>,
    /// X9.63 uncompressed, 65 bytes.
    #[serde(with = "b64")]
    pub enclave_public: Vec<u8>,
    #[serde(with = "b64")]
    pub ephemeral_public: Vec<u8>,
    /// Unix seconds of the last master-password entry.
    pub verified_at: u64,
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

impl Record {
    pub fn expires_at(&self) -> u64 {
        self.verified_at + MAX_AGE_SECS
    }

    /// Expired, or stamped in the future (clock moved back): either way ask for the password.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at() || self.verified_at > now + 300
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("record serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Record> {
        serde_json::from_slice::<Record>(bytes)
            .ok()
            .filter(|r| r.version == VERSION)
    }
}

/// Where the record lives: the login keychain in the app, memory in tests.
pub trait Keyring: Send {
    fn load(&self) -> Option<Vec<u8>>;
    fn save(&self, data: &[u8]) -> Result<(), String>;
    fn delete(&self);
}

/// No keychain at all: Touch ID stays off.
pub struct NoKeyring;

impl Keyring for NoKeyring {
    fn load(&self) -> Option<Vec<u8>> {
        None
    }
    fn save(&self, _: &[u8]) -> Result<(), String> {
        Err("Touch ID isn't available".into())
    }
    fn delete(&self) {}
}

/// What the UI needs to show the Touch ID button and the setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TouchIdState {
    /// This Mac has Touch ID with enrolled fingers (filled in by the app).
    pub available: bool,
    pub enabled: bool,
    /// Enabled, but the master password is due (14 days passed).
    pub password_due: bool,
}

/// What the app hands to the Secure Enclave for one unlock.
#[derive(Debug)]
pub struct UnlockRequest {
    pub enclave_key: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
}

/// Wraps `account` for the enclave key; needs only its public key, so it never prompts.
pub fn wrap(
    account: &Key,
    enclave_key: Vec<u8>,
    enclave_public: &[u8],
    verified_at: u64,
) -> CmdResult<Record> {
    let enclave = PublicKey::from_sec1_bytes(enclave_public)
        .map_err(|_| CmdError::new(ErrorKind::Invalid, "Bad Secure Enclave public key"))?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = ephemeral.diffie_hellman(&enclave);
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.raw_secret_bytes());
    let key = wrapping_key(&secret, &ephemeral_public, enclave_public);
    Ok(Record {
        version: VERSION,
        enclave_key,
        enclave_public: enclave_public.to_vec(),
        sealed: crypto::seal(&key, account.as_bytes(), &aad(verified_at)),
        ephemeral_public,
        verified_at,
    })
}

/// Recovers the account key from the enclave's ECDH result.
pub fn unwrap(record: &Record, shared: &[u8; 32]) -> CmdResult<Key> {
    let key = wrapping_key(shared, &record.ephemeral_public, &record.enclave_public);
    let raw = crypto::open(&key, &record.sealed, &aad(record.verified_at)).map_err(|_| {
        CmdError::new(
            ErrorKind::PasswordRequired,
            "Touch ID needs to be set up again. Unlock with your master password.",
        )
    })?;
    Ok(Key::from_slice(&raw)?)
}

fn wrapping_key(shared: &[u8; 32], ephemeral_public: &[u8], enclave_public: &[u8]) -> Key {
    let mut h = Sha256::new();
    h.update(format!("{LABEL}/key").as_bytes());
    h.update(shared);
    h.update(ephemeral_public);
    h.update(enclave_public);
    Key::from_bytes(h.finalize().into())
}

fn aad(verified_at: u64) -> Vec<u8> {
    let mut aad = format!("{LABEL}/account-key/").into_bytes();
    aad.extend_from_slice(&verified_at.to_be_bytes());
    aad
}

mod b64 {
    use super::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Software stand-in for the Secure Enclave in tests.
#[cfg(test)]
pub(crate) struct FakeEnclave(p256::SecretKey);

#[cfg(test)]
impl FakeEnclave {
    pub fn new() -> Self {
        Self(p256::SecretKey::random(&mut OsRng))
    }

    pub fn public(&self) -> Vec<u8> {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// What the enclave returns after a successful Touch ID.
    pub fn agree(&self, ephemeral_public: &[u8]) -> [u8; 32] {
        let peer = PublicKey::from_sec1_bytes(ephemeral_public).unwrap();
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_then_unwrap_with_the_enclave() {
        let enclave = FakeEnclave::new();
        let account = Key::random();
        let record = wrap(&account, b"blob".to_vec(), &enclave.public(), 1_000).unwrap();
        let shared = enclave.agree(&record.ephemeral_public);
        assert_eq!(
            unwrap(&record, &shared).unwrap().as_bytes(),
            account.as_bytes()
        );
    }

    #[test]
    fn another_enclave_key_cannot_unwrap() {
        let record = wrap(&Key::random(), vec![], &FakeEnclave::new().public(), 1_000).unwrap();
        let other = FakeEnclave::new().agree(&record.ephemeral_public);
        assert_eq!(
            unwrap(&record, &other).unwrap_err().kind,
            ErrorKind::PasswordRequired
        );
    }

    #[test]
    fn the_password_time_cannot_be_moved() {
        let enclave = FakeEnclave::new();
        let mut record = wrap(&Key::random(), vec![], &enclave.public(), 1_000).unwrap();
        record.verified_at += 7 * 24 * 60 * 60;
        let shared = enclave.agree(&record.ephemeral_public);
        assert!(unwrap(&record, &shared).is_err());
    }

    #[test]
    fn expiry_after_14_days_or_from_the_future() {
        let record = wrap(
            &Key::random(),
            vec![],
            &FakeEnclave::new().public(),
            1_000_000,
        )
        .unwrap();
        assert!(!record.is_expired(1_000_000));
        assert!(!record.is_expired(1_000_000 + MAX_AGE_SECS - 1));
        assert!(record.is_expired(1_000_000 + MAX_AGE_SECS));
        assert!(
            record.is_expired(1_000_000 - 3_600),
            "verified in the future"
        );
    }

    #[test]
    fn record_round_trips_as_compact_json() {
        let record = wrap(
            &Key::random(),
            vec![1, 2, 3],
            &FakeEnclave::new().public(),
            5,
        )
        .unwrap();
        let bytes = record.to_bytes();
        assert_eq!(Record::from_bytes(&bytes), Some(record));
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("\"enclaveKey\":\"AQID\""));
        assert_eq!(Record::from_bytes(b"{}"), None);
    }

    #[test]
    fn a_bad_public_key_is_refused() {
        assert_eq!(
            wrap(&Key::random(), vec![], &[4; 65], 1).unwrap_err().kind,
            ErrorKind::Invalid
        );
    }
}
```

`Keyring`, `NoKeyring`, `TouchIdState` and `UnlockRequest` are used by Task 15 (they are `pub`, so no dead-code warnings); Task 15 also adds the test-only `MemKeyring`.

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `git commit -m "Session: wrap the account key to a Secure Enclave key"`

---

### Task 15: Session — Touch ID unlock policy

**Files:** Modify `src/error.rs`, `src/session/mod.rs`; create `src/session/touchid_tests.rs`.

- [ ] **Step 1: Failing tests** — first add the test keyring to `src/touchid.rs`, just before `/// What the UI needs to show …`:

```rust
/// Shared in-memory keyring for tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemKeyring(pub std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

#[cfg(test)]
impl Keyring for MemKeyring {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
    fn delete(&self) {
        *self.0.lock().unwrap() = None;
    }
}
```

then `session/touchid_tests.rs` (register with `#[cfg(test)] mod touchid_tests;`):

```rust
use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use crate::touchid::{FakeEnclave, MemKeyring, MAX_AGE_SECS};

/// Unlocked session (created at 1_000) with an in-memory keyring and Touch ID turned on.
fn with_touch_id() -> (tempfile::TempDir, Session, MemKeyring, FakeEnclave) {
    let (dir, mut s) = unlocked_session();
    let keyring = MemKeyring::default();
    s.set_keyring(Box::new(keyring.clone()));
    let enclave = FakeEnclave::new();
    s.enable_touch_id(b"blob".to_vec(), &enclave.public(), 1_000)
        .unwrap();
    (dir, s, keyring, enclave)
}

fn touch(s: &mut Session, enclave: &FakeEnclave, now: u64) -> CmdResult<()> {
    let request = s.touch_id_request(now)?;
    assert_eq!(request.enclave_key, b"blob");
    let shared = enclave.agree(&request.ephemeral_public);
    s.unlock_with_touch_id(&shared, now)
}

#[test]
fn touch_id_unlocks_after_lock_and_restart() {
    let (dir, mut s, keyring, enclave) = with_touch_id();
    let p = personal(&mut s);
    save_login(&mut s, p, "GitHub", "ivan", "pw");
    s.lock();
    touch(&mut s, &enclave, 2_000).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
    assert_eq!(s.items(&Default::default(), 2_000).unwrap().len(), 1);

    // A restart does not require the password (the record lives in the keychain).
    let path = dir.path().join("Application Support").join("keepsake.db");
    let mut restarted = Session::new(path, KdfParams::INSECURE_FAST, 3_000);
    restarted.set_keyring(Box::new(keyring));
    touch(&mut restarted, &enclave, 3_000).unwrap();
    assert_eq!(restarted.status(), Status::Unlocked);
}

#[test]
fn state_reports_enabled_and_password_due() {
    let (_dir, mut s, _keyring, _enclave) = with_touch_id();
    let state = s.touch_id_state(true, 1_000);
    assert!(state.available && state.enabled && !state.password_due);
    assert!(s.touch_id_state(true, 1_000 + MAX_AGE_SECS).password_due);
    s.disable_touch_id();
    assert!(!s.touch_id_state(true, 1_000).enabled);
}

#[test]
fn the_password_is_required_every_14_days() {
    let (_dir, mut s, _keyring, enclave) = with_touch_id();
    s.lock();
    let late = 1_000 + MAX_AGE_SECS;
    assert_eq!(
        touch(&mut s, &enclave, late).unwrap_err().kind,
        ErrorKind::PasswordRequired
    );
    s.unlock(PW, late).unwrap();
    s.lock();
    touch(&mut s, &enclave, late + MAX_AGE_SECS - 1).unwrap();
}

#[test]
fn touch_id_unlocks_do_not_restart_the_14_days() {
    let (_dir, mut s, _keyring, enclave) = with_touch_id();
    s.lock();
    touch(&mut s, &enclave, 1_000 + MAX_AGE_SECS - 10).unwrap();
    // Re-enabling while unlocked by Touch ID keeps the original password time.
    s.enable_touch_id(
        b"blob".to_vec(),
        &enclave.public(),
        1_000 + MAX_AGE_SECS - 5,
    )
    .unwrap();
    s.lock();
    let err = touch(&mut s, &enclave, 1_000 + MAX_AGE_SECS).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);
}

#[test]
fn changing_the_password_replaces_the_record() {
    let (_dir, mut s, keyring, enclave) = with_touch_id();
    let before = keyring.load().unwrap();
    s.change_password(PW, "a brand new password", 5_000)
        .unwrap();
    let after = keyring.load().unwrap();
    assert_ne!(before, after);
    assert_eq!(
        touchid::Record::from_bytes(&after).unwrap().verified_at,
        5_000
    );
    s.lock();
    touch(&mut s, &enclave, 5_001).unwrap();
}

#[test]
fn a_wrong_enclave_answer_forgets_touch_id() {
    let (_dir, mut s, keyring, _enclave) = with_touch_id();
    s.lock();
    let request = s.touch_id_request(2_000).unwrap();
    let wrong = FakeEnclave::new().agree(&request.ephemeral_public);
    let err = s.unlock_with_touch_id(&wrong, 2_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);
    assert!(keyring.load().is_none(), "the record is removed");
    assert_eq!(s.status(), Status::Locked);
}

#[test]
fn enabling_needs_an_unlocked_vault_and_a_password_entry() {
    let (_dir, mut s) = unlocked_session();
    let keyring = MemKeyring::default();
    s.set_keyring(Box::new(keyring.clone()));
    let enclave = FakeEnclave::new();
    s.lock();
    assert_eq!(
        s.enable_touch_id(vec![], &enclave.public(), 1_000)
            .unwrap_err()
            .kind,
        ErrorKind::Locked
    );
    assert_eq!(
        s.touch_id_request(1_000).unwrap_err().kind,
        ErrorKind::PasswordRequired,
        "off"
    );
}

#[test]
fn creating_a_vault_forgets_an_old_record() {
    let keyring = MemKeyring::default();
    keyring.save(b"stale").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut s = Session::new(
        dir.path().join("keepsake.db"),
        KdfParams::INSECURE_FAST,
        1_000,
    );
    s.set_keyring(Box::new(keyring.clone()));
    s.create(PW, 1_000).unwrap();
    assert!(keyring.load().is_none());
}
```

- [ ] **Step 2: Run** — compile errors.
- [ ] **Step 3: Implement.**

`error.rs` — `ErrorKind` gains (before `Other`):

```rust
    /// Touch ID can't be used right now (off, expired, fingerprints changed): ask for the password.
    PasswordRequired,
    /// The user dismissed the Touch ID prompt.
    Cancelled,
```

`session/mod.rs` — `use crate::touchid::{self, Keyring, NoKeyring, TouchIdState, UnlockRequest};`; fields:

```rust
    /// Holds the Touch ID record (the macOS login keychain in the app).
    keyring: Box<dyn Keyring>,
    /// When the master password was last entered (or the Touch ID record says so).
    password_verified_at: Option<u64>,
```

initialised `keyring: Box::new(NoKeyring), password_verified_at: None,`. In `create`, after `self.autolock.touch(now);`:

```rust
        // A Touch ID record left from an earlier vault would only ever fail.
        self.keyring.delete();
        self.password_verified_at = Some(now);
```

In `unlock`'s success arm after `self.store = Some(store);`: `self.password_verified_at = Some(now); self.rearm_touch_id(now);`. In `change_password`'s success arm after `record_success()`:

```rust
                self.password_verified_at = Some(now);
                // Replace the Touch ID record, like 1Password does after a password change.
                self.rearm_touch_id(now);
```

In `start_over`, right before the rename: `self.keyring.delete();`. New methods (after `unlock`):

```rust
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
```

and next to `fn locked()`:

```rust
fn password_due() -> CmdError {
    CmdError::new(
        ErrorKind::PasswordRequired,
        "Enter your master password. Keepsake asks for it every 14 days.",
    )
}
```

- [ ] **Step 4: Run** `cargo test -p keepsake-session` + clippy (also `cargo test -p keepsake-core`). **Step 5: Commit** — `git commit -m "Session: Touch ID unlock with a 14-day password rule"`

---

### Task 16: Shell — Secure Enclave and keychain through Swift

**Files:** Create `app/src-tauri/swift/TouchId.swift`, `app/src-tauri/src/touchid.rs`; modify `app/src-tauri/build.rs`, `Cargo.toml` (+ `zeroize = "1"`), `src/lib.rs`, `src/commands.rs`, `src/quick.rs`.

- [ ] **Step 1: Swift** — `swift/TouchId.swift`:

```swift
// Touch ID for Keepsake: a Secure Enclave key that only the current Touch ID set can use, and a
// login-keychain item for the wrapped account key. Called from Rust (src/touchid.rs) through C.
//
// Why this shape (see docs/superpowers/plans/2026-10-05-keepsake-desktop-2c.md, "Touch ID"):
// a Personal Team app can't get a provisioning profile, so the data-protection keychain and
// biometric keychain ACLs are unavailable (errSecMissingEntitlement). CryptoKit Secure Enclave
// keys need no entitlement, and the enclave itself enforces .biometryCurrentSet.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Status codes; keep in sync with `Status` in src/touchid.rs.
private let OK: Int32 = 0
private let CANCELLED: Int32 = 1
private let LOCKOUT: Int32 = 2
private let INVALID: Int32 = 3
private let UNAVAILABLE: Int32 = 4
private let NOT_FOUND: Int32 = 5
private let FAILED: Int32 = 6

private let account = "account-key"

@_cdecl("ks_biometry_available")
public func ks_biometry_available() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
}

/// New enclave key usable only after Touch ID with the fingerprints enrolled right now.
/// Writes the key blob (`*blobLen` bytes) and its 65-byte X9.63 public key. Never prompts.
@_cdecl("ks_enclave_create")
public func ks_enclave_create(
    _ blobOut: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ publicOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return UNAVAILABLE }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil)
    else { return FAILED }
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else { return FAILED }
    let blob = key.dataRepresentation
    guard blob.count <= blobCap else { return FAILED }
    blob.copyBytes(to: blobOut, count: blob.count)
    blobLen.pointee = blob.count
    key.publicKey.x963Representation.copyBytes(to: publicOut, count: 65)
    return OK
}

/// ECDH between the enclave key and `peer` (65-byte X9.63). Shows the Touch ID prompt with
/// `reason`; blocks until the user answers. Writes the 32-byte shared secret.
@_cdecl("ks_enclave_agree")
public func ks_enclave_agree(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ peer: UnsafePointer<UInt8>,
    _ reason: UnsafePointer<CChar>, _ sharedOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedFallbackTitle = "Use Password"
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: peer, count: 65))
        let shared = try key.sharedSecretFromKeyAgreement(with: peerKey)
        shared.withUnsafeBytes { raw in
            sharedOut.update(from: raw.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return OK
    } catch let error as LAError {
        switch error.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback, .notInteractive: return CANCELLED
        case .biometryLockout: return LOCKOUT
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: return UNAVAILABLE
        default: return INVALID
        }
    } catch {
        // Fingerprints changed (the key is gone for good) or the blob is damaged.
        return INVALID
    }
}

private func baseQuery(_ service: UnsafePointer<CChar>) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: String(cString: service),
        kSecAttrAccount as String: account,
        // The file-based login keychain: its default access list trusts only the app that
        // created the item (its designated requirement), so other apps get a password dialog.
        kSecUseDataProtectionKeychain as String: false,
    ]
}

/// Keychain dialogs are never shown: an item this build may not touch makes the call fail.
private func withoutDialogs<T>(_ body: () -> T) -> T {
    SecKeychainSetUserInteractionAllowed(false)
    defer { SecKeychainSetUserInteractionAllowed(true) }
    return body()
}

@_cdecl("ks_keychain_save")
public func ks_keychain_save(_ service: UnsafePointer<CChar>, _ data: UnsafePointer<UInt8>, _ len: Int) -> Int32 {
    withoutDialogs {
        SecItemDelete(baseQuery(service) as CFDictionary)
        var add = baseQuery(service)
        add[kSecAttrLabel as String] = "Keepsake Touch ID"
        add[kSecValueData as String] = Data(bytes: data, count: len)
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess ? OK : FAILED
    }
}

/// Reads the item. A build signed differently gets FAILED instead of a password dialog.
@_cdecl("ks_keychain_load")
public func ks_keychain_load(
    _ service: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    var query = baseQuery(service)
    query[kSecReturnData as String] = true
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = withoutDialogs { SecItemCopyMatching(query as CFDictionary, &result) }
    if status == errSecItemNotFound { return NOT_FOUND }
    guard status == errSecSuccess, let data = result as? Data, data.count <= cap else { return FAILED }
    data.copyBytes(to: out, count: data.count)
    len.pointee = data.count
    return OK
}

@_cdecl("ks_keychain_delete")
public func ks_keychain_delete(_ service: UnsafePointer<CChar>) -> Int32 {
    let status = withoutDialogs { SecItemDelete(baseQuery(service) as CFDictionary) }
    return status == errSecSuccess || status == errSecItemNotFound ? OK : FAILED
}
```

(`SecKeychainSetUserInteractionAllowed` is deprecated; the compiler warns, the call still works on macOS 26 and is what keeps a differently signed build from getting a keychain password dialog.)

- [ ] **Step 2: build.rs**:

```rust
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_touch_id();
    }
    tauri_build::build()
}

/// Compiles swift/TouchId.swift into a static library and links the Swift runtime from the OS.
fn build_touch_id() {
    let source = "swift/TouchId.swift";
    println!("cargo:rerun-if-changed={source}");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => other,
    }
    .to_owned();
    let lib = out.join("libkeepsake_touchid.a");
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-O",
            "-parse-as-library",
        ])
        .args(["-module-name", "KeepsakeTouchId", "-target"])
        .arg(format!("{arch}-apple-macosx13.0"))
        .arg(source)
        .arg("-o")
        .arg(&lib)
        .status()
        .expect("xcrun swiftc (install Xcode or the Command Line Tools)");
    assert!(status.success(), "compiling {source} failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=keepsake_touchid");
    let swiftc = xcrun(&["--find", "swiftc"]);
    let toolchain = Path::new(&swiftc).parent().unwrap().parent().unwrap();
    println!(
        "cargo:rustc-link-search=native={}",
        toolchain.join("lib/swift/macosx").display()
    );
    let sdk = xcrun(&["--sdk", "macosx", "--show-sdk-path"]);
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}

fn xcrun(args: &[&str]) -> String {
    let out = Command::new("xcrun").args(args).output().expect("xcrun");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
```

- [ ] **Step 3: Failing tests** — `src/touchid.rs` test module first (from the file below), `mod touchid;` in `lib.rs`, `cargo test -p keepsake-app touchid` → compile errors.
- [ ] **Step 4: Implement** — `src/touchid.rs`:

```rust
//! Safe wrappers over swift/TouchId.swift: the Secure Enclave key and the keychain item.

use std::ffi::CString;

use zeroize::Zeroizing;

/// Keychain service of the Touch ID record. Debug builds are signed ad hoc and can't read the
/// release app's item (or the other way round), so they keep their own.
pub const SERVICE: &str = if cfg!(debug_assertions) {
    "app.keepsake.mac.touchid.dev"
} else {
    "app.keepsake.mac.touchid"
};

/// Why a call failed; mirrors the status codes in TouchId.swift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Cancelled,
    Lockout,
    /// Fingerprints changed or the key is damaged: Touch ID must be set up again.
    Invalid,
    Unavailable,
    NotFound,
    Failed,
}

fn check(code: i32) -> Result<(), Failure> {
    match code {
        0 => Ok(()),
        1 => Err(Failure::Cancelled),
        2 => Err(Failure::Lockout),
        3 => Err(Failure::Invalid),
        4 => Err(Failure::Unavailable),
        5 => Err(Failure::NotFound),
        _ => Err(Failure::Failed),
    }
}

const MAX_BLOB: usize = 4096;
const MAX_RECORD: usize = 16 * 1024;

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::c_char;

    extern "C" {
        pub fn ks_biometry_available() -> bool;
        pub fn ks_enclave_create(
            blob: *mut u8,
            cap: usize,
            len: *mut usize,
            public: *mut u8,
        ) -> i32;
        pub fn ks_enclave_agree(
            blob: *const u8,
            len: usize,
            peer: *const u8,
            reason: *const c_char,
            shared: *mut u8,
        ) -> i32;
        pub fn ks_keychain_save(service: *const c_char, data: *const u8, len: usize) -> i32;
        pub fn ks_keychain_load(
            service: *const c_char,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
        pub fn ks_keychain_delete(service: *const c_char) -> i32;
    }
}

/// Without macOS there is no Touch ID: every call reports it unavailable.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
mod ffi {
    use std::os::raw::c_char;

    pub unsafe fn ks_biometry_available() -> bool {
        false
    }
    pub unsafe fn ks_enclave_create(_: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
        4
    }
    pub unsafe fn ks_enclave_agree(
        _: *const u8,
        _: usize,
        _: *const u8,
        _: *const c_char,
        _: *mut u8,
    ) -> i32 {
        4
    }
    pub unsafe fn ks_keychain_save(_: *const c_char, _: *const u8, _: usize) -> i32 {
        4
    }
    pub unsafe fn ks_keychain_load(_: *const c_char, _: *mut u8, _: usize, _: *mut usize) -> i32 {
        5
    }
    pub unsafe fn ks_keychain_delete(_: *const c_char) -> i32 {
        0
    }
}

/// This Mac has Touch ID with enrolled fingers. Never prompts.
pub fn available() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::ks_biometry_available() }
}

/// A new enclave key: (opaque blob, 65-byte public key). Never prompts.
pub fn create_key() -> Result<(Vec<u8>, [u8; 65]), Failure> {
    let mut blob = vec![0u8; MAX_BLOB];
    let mut len = 0usize;
    let mut public = [0u8; 65];
    // SAFETY: the buffers are as large as we say; Swift writes at most `cap` and 65 bytes.
    check(unsafe {
        ffi::ks_enclave_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr())
    })?;
    blob.truncate(len);
    Ok((blob, public))
}

/// Shows the Touch ID prompt and returns the ECDH secret. Blocks until the user answers:
/// never call it while holding the session lock.
pub fn agree(blob: &[u8], peer: &[u8; 65], reason: &str) -> Result<Zeroizing<[u8; 32]>, Failure> {
    let reason = CString::new(reason).map_err(|_| Failure::Failed)?;
    let mut shared = Zeroizing::new([0u8; 32]);
    // SAFETY: pointers and lengths come from live buffers; Swift writes exactly 32 bytes.
    check(unsafe {
        ffi::ks_enclave_agree(
            blob.as_ptr(),
            blob.len(),
            peer.as_ptr(),
            reason.as_ptr(),
            shared.as_mut_ptr(),
        )
    })?;
    Ok(shared)
}

fn service(name: &str) -> CString {
    CString::new(name).expect("service names have no NUL")
}

pub fn keychain_save(name: &str, data: &[u8]) -> Result<(), Failure> {
    // SAFETY: a live C string and slice.
    check(unsafe { ffi::ks_keychain_save(service(name).as_ptr(), data.as_ptr(), data.len()) })
}

pub fn keychain_load(name: &str) -> Result<Vec<u8>, Failure> {
    let mut out = vec![0u8; MAX_RECORD];
    let mut len = 0usize;
    // SAFETY: Swift writes at most `cap` bytes.
    check(unsafe {
        ffi::ks_keychain_load(
            service(name).as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    })?;
    out.truncate(len);
    Ok(out)
}

pub fn keychain_delete(name: &str) -> Result<(), Failure> {
    // SAFETY: a live C string.
    check(unsafe { ffi::ks_keychain_delete(service(name).as_ptr()) })
}

/// The login keychain as the session's Touch ID store.
pub struct MacKeyring;

impl keepsake_session::touchid::Keyring for MacKeyring {
    fn load(&self) -> Option<Vec<u8>> {
        keychain_load(SERVICE).ok()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        keychain_save(SERVICE, data).map_err(|e| format!("{e:?}"))
    }
    fn delete(&self) {
        let _ = keychain_delete(SERVICE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_failures() {
        assert_eq!(check(0), Ok(()));
        assert_eq!(check(1), Err(Failure::Cancelled));
        assert_eq!(check(2), Err(Failure::Lockout));
        assert_eq!(check(3), Err(Failure::Invalid));
        assert_eq!(check(4), Err(Failure::Unavailable));
        assert_eq!(check(5), Err(Failure::NotFound));
        assert_eq!(check(99), Err(Failure::Failed));
    }

    #[test]
    fn availability_never_prompts() {
        let _ = available();
    }

    /// Run by hand: `cargo test -p keepsake-app -- --ignored`. Creates a Secure Enclave key and a
    /// keychain item under a test service, then removes the item. Never shows a prompt.
    #[test]
    #[ignore = "touches the Secure Enclave and the login keychain"]
    fn enclave_key_and_keychain_round_trip() {
        const TEST: &str = "app.keepsake.mac.touchid.test";
        let (blob, public) = create_key().unwrap();
        assert!(!blob.is_empty());
        assert_eq!(public[0], 4, "uncompressed X9.63 point");
        keychain_save(TEST, &blob).unwrap();
        keychain_save(TEST, b"replaced").unwrap();
        assert_eq!(keychain_load(TEST).unwrap(), b"replaced");
        keychain_delete(TEST).unwrap();
        assert_eq!(keychain_load(TEST), Err(Failure::NotFound));
        keychain_delete(TEST).unwrap();
    }
}
```

`quick.rs` — keep the window open while the Touch ID sheet has focus: add `use std::sync::atomic::{AtomicBool, Ordering};`,

```rust
/// While set, losing focus does not hide the window (the Touch ID sheet takes focus).
static HOLD: AtomicBool = AtomicBool::new(false);

/// Keeps the quick window open while it lives.
pub struct HoldOpen;

impl HoldOpen {
    pub fn new() -> Self {
        HOLD.store(true, Ordering::SeqCst);
        HoldOpen
    }
}

impl Drop for HoldOpen {
    fn drop(&mut self) {
        HOLD.store(false, Ordering::SeqCst);
    }
}
```

and in the `Focused(false)` handler: `if !HOLD.load(Ordering::SeqCst) { let _ = handle.hide(); }`.

`lib.rs` — the session gets the keychain:

```rust
            let mut session = Session::new(path, KdfParams::DEFAULT, now());
            session.set_keyring(Box::new(touchid::MacKeyring));
            app.manage(AppState(Mutex::new(session)));
```

`commands.rs` — `use keepsake_session::touchid::TouchIdState;` and:

```rust
#[tauri::command(async)]
pub fn touch_id_state(state: State<'_, AppState>) -> TouchIdState {
    lock_session(&state).touch_id_state(crate::touchid::available(), now())
}

#[tauri::command(async)]
pub fn enable_touch_id(state: State<'_, AppState>) -> CmdResult<()> {
    if !crate::touchid::available() {
        return Err(CmdError::new(
            ErrorKind::Invalid,
            "Touch ID isn't available on this Mac",
        ));
    }
    let (blob, public) = crate::touchid::create_key()
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Secure Enclave: {e:?}")))?;
    lock_session(&state).enable_touch_id(blob, &public, now())
}

#[tauri::command(async)]
pub fn disable_touch_id(state: State<'_, AppState>) {
    lock_session(&state).disable_touch_id();
}

/// Shows the Touch ID prompt (blocking this worker thread, never the session) and unlocks.
#[tauri::command(async)]
pub fn unlock_with_touch_id(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    use crate::touchid::Failure;
    let request = lock_session(&state).touch_id_request(now())?;
    let peer: [u8; 65] = request
        .ephemeral_public
        .as_slice()
        .try_into()
        .map_err(|_| {
            CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID needs to be set up again",
            )
        })?;
    let _hold = crate::quick::HoldOpen::new();
    let shared = match crate::touchid::agree(&request.enclave_key, &peer, "unlock Keepsake") {
        Ok(shared) => shared,
        Err(Failure::Cancelled) => return Err(CmdError::new(ErrorKind::Cancelled, "Cancelled")),
        Err(Failure::Lockout) => {
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID is locked after too many tries. Use your master password.",
            ))
        }
        Err(Failure::Invalid) => {
            lock_session(&state).disable_touch_id();
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Your fingerprints changed. Unlock with your master password, then turn Touch ID on again in Settings.",
            ));
        }
        Err(_) => {
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID isn't available right now. Use your master password.",
            ))
        }
    };
    lock_session(&state).unlock_with_touch_id(&shared, now())?;
    let _ = app.emit("unlocked", ());
    Ok(())
}
```

Register `touch_id_state`, `enable_touch_id`, `disable_touch_id`, `unlock_with_touch_id`.

- [ ] **Step 5: Run** `cargo clippy -p keepsake-app --all-targets -- -D warnings && cargo test -p keepsake-app`, then once by hand `cargo test -p keepsake-app -- --ignored` (creates an enclave key and a test keychain item, removes it; no prompt) and check `security find-generic-password -s app.keepsake.mac.touchid.test` finds nothing afterwards.
- [ ] **Step 6: Commit** — `git commit -m "Touch ID through the Secure Enclave and the login keychain"`

---

### Task 17: Signed builds

**Files:** Create `app/scripts/sign.sh` (executable); modify `README.md`.

- [ ] **Step 1: Script** — `app/scripts/sign.sh`:

```sh
#!/bin/sh
# Builds Keepsake.app signed with the owner's Personal Team ("Apple Development" certificate in
# the login keychain; sign in once in Xcode → Settings → Accounts) and installs it to
# /Applications. A stable team signature keeps the Touch ID keychain item readable across
# rebuilds: its access list names the app's designated requirement, not one build.
#   KEEPSAKE_SIGNING_IDENTITY="Apple Development: Name (ABCDE12345)" KEEPSAKE_TEAM=ABCDE12345 app/scripts/sign.sh
# No entitlements are needed (see docs/superpowers/plans/2026-10-05-keepsake-desktop-2c.md).
set -eu
app_dir=$(cd "$(dirname "$0")/.." && pwd)
root=$(dirname "$app_dir")
identity=${KEEPSAKE_SIGNING_IDENTITY:-Apple Development}
team=${KEEPSAKE_TEAM:-4889865CU4}

(cd "$app_dir" && APPLE_SIGNING_IDENTITY="$identity" pnpm tauri build --bundles app)

built="$root/target/release/bundle/macos/Keepsake.app"
codesign --verify --strict --deep "$built"
signed_team=$(codesign -dv "$built" 2>&1 | sed -n 's/^TeamIdentifier=//p')
if [ "$signed_team" != "$team" ]; then
  echo "Keepsake.app is signed by team '$signed_team', expected $team" >&2
  exit 1
fi
rm -rf /Applications/Keepsake.app
ditto "$built" /Applications/Keepsake.app
echo "Installed /Applications/Keepsake.app (team $team)"
```

`chmod +x app/scripts/sign.sh`.

- [ ] **Step 2: Run** it (quit Keepsake first). Expected: `Installed /Applications/Keepsake.app (team 4889865CU4)`; `codesign -dv /Applications/Keepsake.app` shows `Identifier=app.keepsake.mac`, `TeamIdentifier=4889865CU4`, `flags=0x10000(runtime)`.
- [ ] **Step 3: README** — in "Development", replace the `pnpm tauri build` line with `app/scripts/sign.sh  # signed build (Personal Team), installs /Applications/Keepsake.app` and add a short "Touch ID" paragraph: needs a signed build for a stable keychain item; dev builds keep their own item; turning it on is in Settings → Touch ID; the password is asked every 14 days and after fingerprint changes. Also fix the spec link (`docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md`).
- [ ] **Step 4: Commit** — `git commit -m "Sign the app with the Personal Team for Touch ID"`

---

### Task 18: Touch ID in the lock screen and Settings

**Files:** Modify `app/src/api.ts`, `Unlock.tsx`, `Unlock.test.tsx`, `SettingsDialog.tsx`, `SettingsDialog.test.tsx`, `App.test.tsx`, `QuickApp.test.tsx`.

- [ ] **Step 1: API**:

```ts
export interface TouchIdState {
  /** This Mac has Touch ID with enrolled fingers. */
  available: boolean;
  enabled: boolean;
  /** 14 days since the master password was entered: Touch ID waits for it. */
  passwordDue: boolean;
}
```

and in `api`:

```ts
  touchIdState: () => invoke<TouchIdState>("touch_id_state"),
  enableTouchId: () => invoke<void>("enable_touch_id"),
  disableTouchId: () => invoke<void>("disable_touch_id"),
  /** Shows the system Touch ID prompt; rejects with kind "cancelled" when dismissed. */
  unlockWithTouchId: () => invoke<void>("unlock_with_touch_id"),
```

- [ ] **Step 2: Failing tests.** `Unlock.test.tsx` — mock `touchIdState` and `unlockWithTouchId`; before `beforeEach`:

```tsx
const touchOff = { available: true, enabled: false, passwordDue: false };
const touchOn = { available: true, enabled: true, passwordDue: false };
```

at the top of `beforeEach`:

```tsx
  vi.restoreAllMocks();
  vi.mocked(api.touchIdState).mockReset().mockResolvedValue(touchOff);
  vi.mocked(api.unlockWithTouchId).mockReset().mockResolvedValue(undefined);
```

and append:

```tsx
test("Touch ID unlocks right away when the window is in front", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  const onUnlocked = vi.fn();
  render(<Unlock onUnlocked={onUnlocked} onStartOver={vi.fn()} />);
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
  expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1);
});

test("Touch ID waits until the window comes to the front", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(false);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByRole("button", { name: "Unlock with Touch ID" })).toBeInTheDocument();
  expect(api.unlockWithTouchId).not.toHaveBeenCalled();
  act(() => {
    window.dispatchEvent(new Event("focus"));
  });
  await waitFor(() => expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1));
  act(() => {
    window.dispatchEvent(new Event("focus"));
  });
  expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1);
});

test("a dismissed prompt leaves the password form; the button tries again", async () => {
  const user = userEvent.setup();
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  vi.mocked(api.unlockWithTouchId).mockRejectedValueOnce({ kind: "cancelled", message: "Cancelled" });
  const onUnlocked = vi.fn();
  render(<Unlock onUnlocked={onUnlocked} onStartOver={vi.fn()} />);
  const button = await screen.findByRole("button", { name: "Unlock with Touch ID" });
  await waitFor(() => expect(button).toBeEnabled());
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await user.click(button);
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
});

test("when the password is required, Touch ID steps aside with the reason", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  vi.mocked(api.unlockWithTouchId).mockRejectedValue({
    kind: "passwordRequired",
    message: "Your fingerprints changed. Unlock with your master password, then turn Touch ID on again in Settings.",
  });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("fingerprints changed");
  expect(screen.queryByRole("button", { name: "Unlock with Touch ID" })).not.toBeInTheDocument();
});

test("every 14 days the password is asked for instead", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue({ ...touchOn, passwordDue: true });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByText(/every 14 days/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Unlock with Touch ID" })).not.toBeInTheDocument();
  expect(api.unlockWithTouchId).not.toHaveBeenCalled();
});
```

`SettingsDialog.test.tsx` — mock `touchIdState`, `enableTouchId`, `disableTouchId`; in `beforeEach`:

```tsx
  vi.mocked(api.touchIdState).mockReset().mockResolvedValue({ available: true, enabled: false, passwordDue: false });
  vi.mocked(api.enableTouchId).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.disableTouchId).mockReset().mockResolvedValue(undefined);
```

and append:

```tsx
test("turns Touch ID on and off", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  const box = await screen.findByLabelText("Unlock with Touch ID");
  expect(box).not.toBeChecked();
  vi.mocked(api.touchIdState).mockResolvedValue({ available: true, enabled: true, passwordDue: false });
  await user.click(box);
  expect(api.enableTouchId).toHaveBeenCalled();
  await waitFor(() => expect(box).toBeChecked());
  vi.mocked(api.touchIdState).mockResolvedValue({ available: true, enabled: false, passwordDue: false });
  await user.click(box);
  expect(api.disableTouchId).toHaveBeenCalled();
  await waitFor(() => expect(box).not.toBeChecked());
  expect(screen.getByText(/every 14 days/)).toBeInTheDocument();
});

test("Touch ID errors and Macs without it", async () => {
  const user = userEvent.setup();
  vi.mocked(api.enableTouchId).mockRejectedValue({ kind: "other", message: "Keychain: Failed" });
  const { unmount } = render(<SettingsDialog onClose={vi.fn()} />);
  await user.click(await screen.findByLabelText("Unlock with Touch ID"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Keychain: Failed");
  unmount();
  vi.mocked(api.touchIdState).mockResolvedValue({ available: false, enabled: false, passwordDue: false });
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByText("Touch ID isn't available on this Mac.")).toBeInTheDocument();
  expect(screen.queryByLabelText("Unlock with Touch ID")).not.toBeInTheDocument();
});
```

`App.test.tsx` and `QuickApp.test.tsx` — add to the mocked api: `touchIdState: vi.fn().mockResolvedValue({ available: false, enabled: false, passwordDue: false }),`.

- [ ] **Step 3: Run** — failures.
- [ ] **Step 4: Implement.**

`Unlock.tsx` — imports `useCallback, useRef` and `type TouchIdState`; after the `shakes` state:

```tsx
  const [touchId, setTouchId] = useState<TouchIdState | null>(null);
  const prompted = useRef(false);
  const canTouch = Boolean(touchId?.available && touchId.enabled && !touchId.passwordDue);

  useEffect(() => {
    api
      .touchIdState()
      .then(setTouchId)
      .catch(() => setTouchId(null));
  }, []);

  const touchUnlock = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await api.unlockWithTouchId();
      onUnlocked();
    } catch (err) {
      if (isCmdError(err) && err.kind === "cancelled") {
        // The user chose the password instead; nothing to say.
      } else if (isCmdError(err) && err.kind === "passwordRequired") {
        setTouchId(null);
        setError(err.message);
      } else if (isCmdError(err) && err.kind === "notADatabase") {
        setUnreadable(true);
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }, [onUnlocked]);

  // Ask once, as soon as this window is in front (not while the Mac sits idle behind it).
  useEffect(() => {
    if (!canTouch) return;
    const attempt = () => {
      if (prompted.current) return;
      prompted.current = true;
      void touchUnlock();
    };
    if (document.hasFocus()) attempt();
    window.addEventListener("focus", attempt);
    return () => window.removeEventListener("focus", attempt);
  }, [canTouch, touchUnlock]);
```

and after the Unlock button:

```tsx
        {canTouch && (
          <button type="button" onClick={touchUnlock} disabled={busy}>
            Unlock with Touch ID
          </button>
        )}
        {touchId?.enabled && touchId.passwordDue && (
          <p className="muted">Enter your master password. Keepsake asks for it every 14 days, then Touch ID works again.</p>
        )}
```

`SettingsDialog.tsx` — import `type TouchIdState`; state and handler:

```tsx
  const [touchId, setTouchId] = useState<TouchIdState | null>(null);
  const [touchIdError, setTouchIdError] = useState<string | null>(null);
  useEffect(() => {
    api
      .touchIdState()
      .then(setTouchId)
      .catch(() => setTouchId(null));
  }, []);
  async function toggleTouchId(on: boolean) {
    setTouchIdError(null);
    try {
      if (on) await api.enableTouchId();
      else await api.disableTouchId();
      setTouchId(await api.touchIdState());
    } catch (e) {
      setTouchIdError(errorMessage(e));
    }
  }
```

and a section before "Change master password":

```tsx
        <section className="modal-section">
          <h3>Touch ID</h3>
          {touchId && !touchId.available && <p className="muted">Touch ID isn't available on this Mac.</p>}
          {touchId?.available && (
            <label className="check">
              <input type="checkbox" checked={touchId.enabled} onChange={(e) => toggleTouchId(e.target.checked)} />
              Unlock with Touch ID
            </label>
          )}
          <p className="muted">
            Keepsake still asks for your master password every 14 days and after your fingerprints change.
          </p>
          {touchIdError && (
            <p className="error" role="alert">
              {touchIdError}
            </p>
          )}
        </section>
```

- [ ] **Step 5: Run** `pnpm typecheck && pnpm test && pnpm build`. **Step 6: Commit** — `git commit -m "Unlock with Touch ID; turn it on in Settings"`

---

### Task 19: Full checks, docs, manual run (controller)

- [ ] **Step 1:** `cargo fmt --all --check && cargo clippy -p keepsake-core -p keepsake-session -p keepsake-app --all-targets -- -D warnings && cargo test && cargo test -p keepsake-app && (cd app && pnpm typecheck && pnpm test)`.
- [ ] **Step 2: Spec addendum** — append to `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md`:

```markdown
## Addendum (2026-10-05): Touch ID, Watchtower, menu bar (Plan 2c)

Replaces the Touch ID paragraph of §5 where they differ.

- **Touch ID** wraps the account key to a Secure Enclave P-256 key created by CryptoKit with
  `[.privateKeyUsage, .biometryCurrentSet]` (ECDH with an ephemeral key, SHA-256 KDF,
  XChaCha20-Poly1305 with the last password time in the AAD). The record lives in the login
  keychain (service `app.keepsake.mac.touchid`), readable only by the app's designated
  requirement; the app is signed with the owner's Personal Team. A free team can't get the
  provisioning profile the data-protection keychain needs, which is why the enclave key, not a
  biometric keychain ACL, enforces Touch ID. No password after a restart; the password is
  required every 14 days, after fingerprint changes, and a password change replaces the record.
- **Watchtower** adds "missing 2FA" (logins without a one-time password on sites from a
  built-in list). The breach check is opt-in per session and sends only 5-character SHA-1
  prefixes; answers are kept in memory until the vault locks.
- **Menu bar and quick search:** closing the main window keeps Keepsake in the menu bar;
  ⌘⇧Space opens the quick-search window (Enter: password, ⌘Enter: username, ⌘C: code).
- **Vaults** can be renamed; only empty vaults can be deleted (their trash goes with them),
  never the last one. An unreadable database can be moved aside ("Start over"), never deleted.
```

- [ ] **Step 3 (controller, by hand):** `app/scripts/sign.sh`, then with the installed app:
  1. *Polish:* rename a vault; try deleting a non-empty vault (refused with the count), delete an empty one (confirm text mentions Recently Deleted); edit an item, click another item → "Discard changes?" → Cancel keeps the edit, Discard leaves; with Keepsake quit, `cp ~/Library/Application\ Support/app.keepsake.mac/keepsake.db /tmp/keepsake-backup.db`, write junk into the db (`echo junk > …/keepsake.db`), start → unlock → "This file is not a Keepsake database" → Start over → the file `keepsake.db.unreadable-*` exists, setup shows; afterwards restore the backup.
  2. *Watchtower:* counts in the sidebar; Weak/Reused/Missing 2FA lists; click opens the item; "Check for breaches" (network) fills Compromised; lock + unlock → Compromised shows "–" again (cache forgotten).
  3. *Menu bar:* the keyhole icon is in the menu bar (tinted for light/dark); Open Keepsake, Quick Search, Lock, Quit work; closing the main window keeps the icon; Dock click reopens the window.
  4. *Quick search:* ⌘⇧Space from another app opens the floating window; type, ↑/↓, Enter pastes the password elsewhere with ⌘V; ⌘Enter username; ⌘C on an item with 2FA copies the code; Esc and clicking elsewhere hide it; when locked it shows the unlock form and unlocking there also unlocks the main window. If ⌘⇧Space is taken by another app, note it (stderr says so) — a configurable shortcut is follow-up work.
  5. *Touch ID:* Settings → Touch ID → turn on; Lock → the Touch ID prompt appears when the window is in front ("Keepsake wants to unlock Keepsake"); Cancel → password form stays; the button retries; Quit and restart → Touch ID works without the password; unlock from the quick window with Touch ID (the window must stay open while the sheet is up); change the master password → Touch ID still works; `security find-generic-password -s app.keepsake.mac.touchid` shows the item; from Terminal `security find-generic-password -s app.keepsake.mac.touchid -w` shows a keychain *dialog* (not the data) — deny it. Optional (changes fingerprints): add a finger in System Settings → next unlock says fingerprints changed, Touch ID is off until re-enabled. The 14-day rule is covered by tests; to see it by hand, temporarily set the Mac clock 15 days ahead.
  6. *Browsers:* the Chrome extension still fills (the native host is the same, now signed, binary); Safari via "Keepsake for Safari" too.
- [ ] **Step 4:** Commit fixes; merge/push per the user's choice.

## Open risks

- **⌘⇧Space may be taken** (another app or a future macOS shortcut). Registration failure is logged and non-fatal; the tray item still opens quick search. Follow-up: a shortcut setting.
- **Unverified at runtime by the planner:** the Touch ID prompt itself (never triggered during planning), the exact `LAError` code after a fingerprint change (mapped to "invalid" by the catch-all, which deletes the record — a misclassified transient error only costs re-enabling), and that the quick window's focus-loss hide does not fire before `HoldOpen` is set (it is set before the prompt).
- **Deprecated APIs:** `SecKeychainSetUserInteractionAllowed` and the file-based login keychain are deprecated but work on macOS 26.6. If Apple removes them, a paid team (provisioning profile) moves the record to the data-protection keychain; the enclave part stays.
- **Development certificate lifetime:** the Personal Team certificate expires after a year; the designated requirement uses the certificate's common name, so a renewed certificate with the same name keeps the keychain item readable. A different identity means turning Touch ID on again.
- **Watchtower cost:** zxcvbn runs over all passwords whenever the report reloads (mount and after saves). Fine for hundreds of items; memoise by password hash if it gets slow.
- **"Missing 2FA" is list-based** and only as good as `totp-sites.txt`.
- **Two windows, one session:** the quick window and the main window share the session; events (`locked`, `unlocked`, `items-changed`) keep them in step. Starting over from the quick window leaves the main window on its lock screen until it gets focus/restarts (rare; acceptable).
