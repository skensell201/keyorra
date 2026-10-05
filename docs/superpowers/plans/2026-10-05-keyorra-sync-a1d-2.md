# Keyorra Sync A1d-2 Implementation Plan (sync in the session: wiring, setup code, device keys, leaving and rejoining)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync becomes part of the desktop session. A vault can turn sync on (and get its Emergency Kit data and a setup code), another Mac joins with the master password and the setup code, the main Mac approves it after comparing key codes, sync runs only while the vault is unlocked and continues after every unlock, and a vault can turn sync off and join again: the same account merges by record id (a record changed on both sides keeps both versions), another account's vault is carried over into the new one with the old file kept aside, and the main Mac can start a new account with new keys. Device signing keys stay on their Mac: they are sealed to a Secure Enclave key, so a keychain or disk restored on another Mac opens nothing and the device retires its id.

**Builds on:** A1d-1 (`docs/superpowers/plans/2026-10-05-keyorra-sync-a1d-1.md`), applied on `feat/sync-design`.

**Verified:** every task was applied in order in a scratch worktree on top of A1d-1; the full workspace suite passes (605 tests, 4 ignored), `cargo clippy --workspace --all-targets -- -D warnings` is clean (this compiles the Swift helper), and the adversary and convergence property tests pass at 2000 cases in release. The one test that touches the real Secure Enclave and login keychain is `#[ignore]` and is run by hand (Task 6).

**Architecture:**

- `keyorra-core`: `Store::check_password`, `delete_sealed_meta`, `record_changes` (by hand, for rejoining) and `rotate_keys` (new account key and vault keys, everything re-encrypted in one transaction).
- `keyorra-sync`: `Transport` for `Box<T>` (the app chooses the transport at run time).
- `keyorra-session::sync`: `SetupCode` (Secret Key + the main device's id and key code), `EnclaveDeviceKeys` (device keys sealed to an `Enclave`), and `merge`: `disable`, `rejoin`, `carry_over`, `start_new_account`. `Synced` gains `status`, `setup_code` and `change_password` (main device only).
- `keyorra-session::session::sync`: the `SyncLink` the app supplies (transport, device keys, device name), and the session commands `enable_sync`, `join_sync`, `sync_now`, `sync_status`, `approve_device`, `disable_sync`, `emergency_kit`, `start_new_sync_account`; hooks in `unlock`, `unlock_with_touch_id`, `lock`, `create_vault`, `change_password`.
- App: `ks_device_enclave_create` in `swift/TouchId.swift`, `MacEnclave`, the `device-keys` keychain item and `device_keys()`, ready for the folder transport (A2) to build a `SyncLink`.

**Tech Stack:** unchanged. The app gains the dev-dependency `ed25519-dalek` for its manual test.

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`:

1. **§4.2**, first paragraph, replace "The private key lives in the macOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (through the existing `Keyring` abstraction), so it does not travel …" with:

   > The private key is sealed to a Secure Enclave key of this Mac (created with
   > `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and no user presence, so sync never
   > prompts), and the sealed record is kept in a login-keychain item. The data-protection
   > keychain, which offers `…ThisDeviceOnly` items directly, needs a provisioning profile the
   > app does not have (the same reason as Touch ID). An enclave key never leaves its Mac, so
   > the device key does not travel with Time Machine restores, Migration Assistant or a
   > copied home directory, while the SQLite database does. Macs without a Secure Enclave
   > cannot turn sync on.

2. **§7.3 step 1**, the setup code: replace the format with "`KEYORRA-SETUP-1-` followed by base32 (no padding) of: Secret Key id (4 ASCII), Secret Key (16 bytes), main device id (16), main device key code (6 bytes), check (first 2 bytes of SHA-256 of `keyorra-setup-code-v1` and the rest). Spaces and case are ignored. It pins the main device; it does not carry the account id (the header names it) or the main device's head (A3 may add a version 2 that does)."

3. **§7.3 step 4**, replace the two "different account" and "same account" bullets with:

   > - a local vault of a **different** account → its live items are **carried over** as new
   >   records into a new vault store for the account (vaults of the same names; trashed items
   >   stay behind in the old file);
   > - a local vault of the **same** account (it left sync earlier) → merged **by record id**:
   >   when sync was turned off, a fingerprint of every record was kept; a record unchanged
   >   here since then takes what the account has; one changed only here is written by the
   >   new device; one changed here **and** in the account becomes a conflict copy here (so
   >   neither edit is lost). No duplicates. (A version written by the new device after it read
   >   the account is not concurrent with what it read, so without the fingerprints a local
   >   change would silently replace a remote one.)

   and "the old database is kept as `keyorra.db.pre-sync-YYYYMMDD`" stays (only when the file is replaced, i.e. another account).

4. **§7.4 "Turn off sync on this Mac"**: add "The main device cannot turn sync off while other devices are approved (they would be left without a main device): it removes them first or starts a new account. What is kept for a later rejoin is a fingerprint per record (`sync-base`), not the sync tables."

5. **§7.4**, new bullet: "**Start a new account from this Mac**: when the main device must start over (§4.2) or the user chooses it. Sync is turned off, every key of the local vault is replaced (new account key and vault keys, everything re-encrypted), and sync is turned on again as a new account with a new Secret Key. Other Macs join the new account; the old account's files stay until deleted. This is not C1 key rotation: it makes a new account rather than moving the existing one forward."

6. **§8.1**: "On the main device:" instead of "On device A:"; add "Other devices refuse a master password change while synced."

## Decisions

Visible to the user (to confirm):

- **No Secure Enclave, no sync.** Device keys are sealed to the Secure Enclave (Apple silicon or T2). On an Intel Mac without T2 `enable_sync`/`join_sync` fail with the enclave error. The alternative is a plain login-keychain item there, which travels with a restored keychain (a copied Mac would sign as the original until the clone is noticed by the stream checks).
- **The setup code contains the Secret Key.** It is as secret as the Emergency Kit, shown only after the master password (A3) and handled like other secrets on the clipboard (spec §7.6). Joining with the Secret Key alone works too, without a pin on the main device (A3 warns).
- **Carry over keeps vaults separate.** A vault of another account joins as new vaults named as before, so the user may see two "Personal" vaults. Merging same-named vaults is possible but guesses; "Replace" (spec §7.3) is not offered yet (A3 decides whether to).
- **The main device cannot turn sync off** while it has approved devices.
- **Only the main device changes the master password while synced**; it publishes header epoch n+1. Other devices keep their local password until A3 asks for the new one at unlock (spec §8.1).
- **Sync runs only while unlocked**: it stops on lock, auto-lock and sleep, and continues after unlock (also with Touch ID). Nothing syncs in the background while locked.
- **Attachments**: their contents are not synced until the folder transport (A2); an item's attachment list is, so another Mac shows the names but cannot open the files until A2.
- **Approval** happens through the transport (SelfJoin, then the main device approves after comparing the key code shown on both Macs); the commitment exchange of spec §6.4 is for the server (B).

Internal:

- **No local write before the first round read the store.** A device that just joined knows no vault yet; a change waits until the first successful round (otherwise it was dropped as "not found").
- **A vault created while synced** goes through `Engine::create_vault` (its id commits to its key) when the engine can write; otherwise it is created locally and adopted when written.
- **The old database** (another account) is moved aside with its SQLite companions as `keyorra.db.pre-sync-YYYYMMDD` (`-2`, `-3`… if taken), and the Touch ID record is deleted (it wrapped the old key).
- **`SyncLink::unlock_header`** defaults to `Header::unlock` (which refuses KDF parameters below the remote floor); only tests replace it.

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings` clean; the crate's tests green.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against the state after the previous task (the first against the end of A1d-1); apply them with `git apply` (or by hand), in task order. New files are given in full.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-core/src/store/rotate.rs            NEW Store::rotate_keys
crates/keyorra-core/src/store/{mod,sync}.rs        check_password, delete_sealed_meta, record_changes
crates/keyorra-sync/src/transport.rs               Transport for Box<T>
crates/keyorra-session/src/sync/setup.rs           NEW the setup code
crates/keyorra-session/src/sync/enclave_keys.rs    NEW device keys sealed to the Secure Enclave
crates/keyorra-session/src/sync/merge.rs           NEW disable, rejoin, carry_over, start_new_account
crates/keyorra-session/src/sync/{mod,keys}.rs      base fingerprints, catch-up before writing, status, setup code, password
crates/keyorra-session/src/session/sync.rs         NEW SyncLink and the session's sync commands
crates/keyorra-session/src/session/sync_tests.rs   NEW two sessions through MemoryTransport
crates/keyorra-session/src/session/mod.rs          fields and hooks (unlock, lock, create_vault, change_password)
app/src-tauri/swift/TouchId.swift                  + ks_device_enclave_create
app/src-tauri/src/touchid.rs                       MacEnclave, the device-keys keychain item, device_keys()
app/src-tauri/Cargo.toml                           dev-dependency ed25519-dalek
```

---

### Task 1: Store: password check, recording by hand, rotating every key

**Files:** Create `crates/keyorra-core/src/store/rotate.rs`; modify `crates/keyorra-core/src/store/mod.rs`, `crates/keyorra-core/src/store/sync.rs`, `crates/keyorra-core/src/store/sync_tests.rs`.

- [ ] **Step 1: Failing tests.**

The three tests at the end of `sync_tests.rs` (`the_password_can_be_checked_without_locking`, `changes_can_be_recorded_by_hand_and_meta_deleted`, `rotating_the_keys_keeps_every_record_and_drops_the_old_keys`) are in this patch; apply it and see the crate fail to compile:

```diff
diff --git a/crates/keyorra-core/src/store/sync_tests.rs b/crates/keyorra-core/src/store/sync_tests.rs
index a93c504..b075c87 100644
--- a/crates/keyorra-core/src/store/sync_tests.rs
+++ b/crates/keyorra-core/src/store/sync_tests.rs
@@ -192,3 +192,63 @@ fn the_meta_writer_writes_what_the_store_reads() {
         b"state"
     );
 }
+
+#[test]
+fn the_password_can_be_checked_without_locking() {
+    let (_dir, _path, store) = new_store();
+    store.check_password(PW).unwrap();
+    assert!(matches!(
+        store.check_password("wrong one"),
+        Err(Error::WrongPassword)
+    ));
+    assert!(store.is_unlocked());
+}
+
+#[test]
+fn changes_can_be_recorded_by_hand_and_meta_deleted() {
+    let (_dir, _path, mut store) = new_store();
+    store.set_sync_tracking(true).unwrap();
+    let id = Uuid::from_bytes([3; 16]);
+    store.record_changes(&[item_change(id)]).unwrap();
+    assert_eq!(changes(&store), vec![item_change(id)]);
+    store.set_sealed_meta("sync:config", b"x").unwrap();
+    store.delete_sealed_meta("sync:config").unwrap();
+    assert!(store.sealed_meta("sync:config").unwrap().is_none());
+}
+
+#[test]
+fn rotating_the_keys_keeps_every_record_and_drops_the_old_keys() {
+    let (_dir, path, mut store) = new_store();
+    let v = store.create_vault("Personal").unwrap();
+    let live = Item::new(v.id, ItemKind::Login, "live", 1);
+    store.save_item(&live).unwrap();
+    let att = store.add_attachment(live.id, "a.txt", b"bytes", 2).unwrap();
+    let trashed = Item::new(v.id, ItemKind::Login, "trashed", 1);
+    store.save_item(&trashed).unwrap();
+    store.delete_item(trashed.id, 3).unwrap();
+    store.set_sealed_meta("pairings", b"kept").unwrap();
+    let old_account = store.account_key_copy().unwrap();
+    let old_vault_key = store.vault_rows().unwrap()[0].1.clone();
+
+    store.rotate_keys(PW).unwrap();
+
+    assert_ne!(
+        store.account_key().unwrap().as_bytes(),
+        old_account.as_bytes()
+    );
+    assert_ne!(
+        store.vault_rows().unwrap()[0].1.as_bytes(),
+        old_vault_key.as_bytes()
+    );
+    drop(store);
+    let mut store = Store::open(&path).unwrap();
+    assert!(store.unlock_with_key(old_account).is_err());
+    store.unlock(PW).unwrap();
+    assert_eq!(store.get_item(live.id).unwrap().title, "live");
+    assert_eq!(&store.get_attachment(att.id).unwrap()[..], b"bytes");
+    assert_eq!(store.deleted_items().unwrap().len(), 1);
+    assert_eq!(
+        &store.sealed_meta("pairings").unwrap().unwrap()[..],
+        b"kept"
+    );
+}
```

- [ ] **Step 2: Implement.**

Apply:

```diff
diff --git a/crates/keyorra-core/src/store/mod.rs b/crates/keyorra-core/src/store/mod.rs
index 9dad7de..624aa18 100644
--- a/crates/keyorra-core/src/store/mod.rs
+++ b/crates/keyorra-core/src/store/mod.rs
@@ -13,6 +13,7 @@ use crate::import::{ImportPlan, ImportReport};
 use crate::model::{AttachmentRef, Item, VaultInfo, SCHEMA_VERSION};
 use crate::{Error, Result};
 
+mod rotate;
 mod sync;
 #[cfg(test)]
 mod sync_tests;
@@ -731,6 +732,27 @@ fn insert_attachment(
     Ok(())
 }
 
+/// Replaces an attachment's encrypted bytes (rotating keys).
+fn insert_attachment_data(
+    conn: &Connection,
+    key: &Key,
+    vault_id: Uuid,
+    item_id: Uuid,
+    att_id: Uuid,
+    bytes: &[u8],
+) -> Result<()> {
+    let data = crypto::seal(
+        key,
+        bytes,
+        &crypto::attachment_aad(vault_id, item_id, att_id),
+    );
+    conn.execute(
+        "UPDATE attachments SET data = ?2, revision = revision + 1 WHERE id = ?1",
+        params![att_id.to_string(), data],
+    )?;
+    Ok(())
+}
+
 fn reencrypt_attachments(
     conn: &Connection,
     item_id: Uuid,
diff --git a/crates/keyorra-core/src/store/sync.rs b/crates/keyorra-core/src/store/sync.rs
index 5d2c5f4..af8f16f 100644
--- a/crates/keyorra-core/src/store/sync.rs
+++ b/crates/keyorra-core/src/store/sync.rs
@@ -310,6 +310,30 @@ impl Store {
         Ok(())
     }
 
+    /// Whether `password` is the master password (enabling sync asks for it again).
+    pub fn check_password(&self, password: &str) -> Result<()> {
+        crypto::unlock(&self.header, password).map(drop)
+    }
+
+    pub fn delete_sealed_meta(&mut self, name: &str) -> Result<()> {
+        self.conn
+            .execute("DELETE FROM meta WHERE key = ?1", [sealed_meta_key(name)])?;
+        Ok(())
+    }
+
+    /// Records changes by hand (rejoining an account: what changed while sync was off).
+    pub fn record_changes(&mut self, changes: &[Change]) -> Result<()> {
+        let tx = self.conn.unchecked_transaction()?;
+        for c in changes {
+            tx.execute(
+                "INSERT OR IGNORE INTO sync_changes (kind, id) VALUES (?1, ?2)",
+                params![c.kind.as_str(), c.id.to_string()],
+            )?;
+        }
+        tx.commit()?;
+        Ok(())
+    }
+
     /// A second connection to the same database that writes sealed meta (the sync engine's
     /// outbox is saved through it before every append, while the session holds the store).
     pub fn meta_writer(&self) -> Result<MetaWriter> {
```

Create `crates/keyorra-core/src/store/rotate.rs`:

```rust
//! New keys for everything (plan A1d: starting a new synced account from this device). The
//! old account key and vault keys stop opening anything in this file; whoever kept them
//! (devices of the old account) cannot read what the new account writes.

use std::collections::HashMap;

use rusqlite::params;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    insert_attachment_data, parse_id, schema_u32, sealed_meta_aad, upsert_item, vault_meta_aad,
    Store, CHECK_AAD,
};
use crate::crypto::{self, Key};
use crate::model::VaultInfo;
use crate::Result;

impl Store {
    /// Re-encrypts every vault, item, attachment and sealed meta value under new keys, and
    /// the header under the same password, in one transaction.
    pub fn rotate_keys(&mut self, password: &str) -> Result<()> {
        let old_account = self.account_key()?.clone();
        crypto::unlock(&self.header, password)?;
        let account = Key::random();
        let header = crypto::header_for_account(&account, password, self.header.kdf)?;
        let tx = self.conn.unchecked_transaction()?;

        let mut new_keys: HashMap<Uuid, Key> = HashMap::new();
        let vaults: Vec<(String, Vec<u8>)> = {
            let mut stmt = tx.prepare("SELECT id, meta FROM vaults")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, meta) in vaults {
            let vault = parse_id(&id)?;
            let plain = crypto::open(&old_account, &meta, &vault_meta_aad(vault))?;
            let info: VaultInfo = serde_json::from_slice(&plain)?;
            let key = Key::random();
            tx.execute(
                "UPDATE vaults SET wrapped_key = ?2, meta = ?3, revision = revision + 1
                 WHERE id = ?1",
                params![
                    id,
                    crypto::wrap_vault_key(&account, vault, &key),
                    crypto::seal(
                        &account,
                        &serde_json::to_vec(&info)?,
                        &vault_meta_aad(vault)
                    )
                ],
            )?;
            new_keys.insert(vault, key);
        }

        type Row = (String, String, Vec<u8>, i64, Option<i64>);
        let items: Vec<Row> = {
            let mut stmt = tx.prepare(
                "SELECT id, vault_id, data, schema, deleted_at FROM items WHERE length(data) > 0",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, vault, data, schema, deleted_at) in items {
            let (item_id, vault_id) = (parse_id(&id)?, parse_id(&vault)?);
            let item = self.decrypt_item(item_id, vault_id, schema_u32(schema)?, &data)?;
            let key = &new_keys[&vault_id];
            upsert_item(&tx, key, &item)?;
            tx.execute(
                "UPDATE items SET deleted_at = ?2 WHERE id = ?1",
                params![id, deleted_at],
            )?;
            let attachments: Vec<(String, Vec<u8>)> = {
                let mut stmt = tx.prepare(
                    "SELECT id, data FROM attachments WHERE item_id = ?1 AND length(data) > 0",
                )?;
                let rows = stmt.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            for (att, sealed) in attachments {
                let att_id = parse_id(&att)?;
                let plain = Zeroizing::new(crypto::open(
                    self.vault_key(vault_id)?,
                    &sealed,
                    &crypto::attachment_aad(vault_id, item_id, att_id),
                )?);
                insert_attachment_data(&tx, key, vault_id, item_id, att_id, &plain)?;
            }
        }

        let sealed: Vec<(String, Vec<u8>)> = {
            let mut stmt = tx.prepare("SELECT key, value FROM meta WHERE key LIKE 'sealed:%'")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (name, value) in sealed {
            let aad = sealed_meta_aad(&name["sealed:".len()..]);
            let plain = Zeroizing::new(crypto::open(&old_account, &value, &aad)?);
            tx.execute(
                "UPDATE meta SET value = ?2 WHERE key = ?1",
                params![name, crypto::seal(&account, &plain, &aad)],
            )?;
        }
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'header'",
            params![serde_json::to_vec(&header)?],
        )?;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'check'",
            params![crypto::seal(&account, b"lockbox", CHECK_AAD)],
        )?;
        tx.commit()?;
        self.header = header;
        self.vault_keys = new_keys;
        self.account = Some(account);
        Ok(())
    }
}
```

- [ ] **Step 3: Run and commit.**

`cargo test -p keyorra-core` green (137 + 17). Commit: `Core A1d-2: check the password, record changes by hand, rotate every key`.

---

### Task 2: A boxed transport

**Files:** Modify `crates/keyorra-sync/src/transport.rs`.

- [ ] **Step 1: Implement.**

Delegating impl (used by the session in Task 4, which is its test):

```diff
diff --git a/crates/keyorra-sync/src/transport.rs b/crates/keyorra-sync/src/transport.rs
index e59b765..3345d29 100644
--- a/crates/keyorra-sync/src/transport.rs
+++ b/crates/keyorra-sync/src/transport.rs
@@ -56,6 +56,52 @@ pub trait Transport {
     fn put_root_head_file(&self, bytes: &[u8]) -> Result<()>;
 }
 
+/// A boxed transport (the app picks the transport at run time).
+impl<T: Transport + ?Sized> Transport for Box<T> {
+    fn streams(&self) -> Result<Vec<DeviceId>> {
+        (**self).streams()
+    }
+    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
+        (**self).segments(stream, after_seq)
+    }
+    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
+        (**self).append(segment)
+    }
+    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
+        (**self).head(stream)
+    }
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        (**self).headers()
+    }
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        (**self).put_header(name, bytes)
+    }
+    fn delete_header(&self, name: &str) -> Result<()> {
+        (**self).delete_header(name)
+    }
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        (**self).snapshots()
+    }
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        (**self).get_snapshot(name)
+    }
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        (**self).put_snapshot(bytes)
+    }
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        (**self).delete_snapshot(name)
+    }
+    fn delete_segment(&self, stream: &DeviceId, first_seq: u64) -> Result<()> {
+        (**self).delete_segment(stream, first_seq)
+    }
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        (**self).root_head_file()
+    }
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        (**self).put_root_head_file(bytes)
+    }
+}
+
 #[derive(Clone, Debug, Default)]
 struct Files {
     headers: BTreeMap<String, Vec<u8>>,
```

- [ ] **Step 2: Run and commit.**

Commit: `Sync A1d-2: Transport for Box<T>`.

---

### Task 3: Setup code, enclave device keys, leaving and rejoining

**Files:** Create `crates/keyorra-session/src/sync/setup.rs`, `crates/keyorra-session/src/sync/enclave_keys.rs`, `crates/keyorra-session/src/sync/merge.rs`; modify `crates/keyorra-session/src/sync/mod.rs`, `crates/keyorra-session/src/sync/keys.rs`, `crates/keyorra-session/src/sync/tests.rs`.

- [ ] **Step 1: Failing tests.**

Apply the tests (join with the setup code alone; turning sync off keeps everything and records nothing; the main device cannot turn sync off under other devices; **rejoining merges by record id and keeps both sides of a double edit**; another account's vault cannot rejoin; carrying another account's vault over; the main device starts a new account with new keys):

```diff
diff --git a/crates/keyorra-session/src/sync/tests.rs b/crates/keyorra-session/src/sync/tests.rs
index de9b7ca..e64d028 100644
--- a/crates/keyorra-session/src/sync/tests.rs
+++ b/crates/keyorra-session/src/sync/tests.rs
@@ -259,3 +259,262 @@ fn vaults_created_while_synced_get_committed_ids() {
     assert!(names.contains("Work"));
     assert!(laptop.store.vaults().unwrap().iter().any(|v| v.id == id));
 }
+
+// ---- setup code, turning sync off and on, other accounts (plan A1d-2) ----
+
+fn item_id(store: &Store, title: &str) -> uuid::Uuid {
+    store
+        .list_items(None)
+        .unwrap()
+        .into_iter()
+        .find_map(|e| match e {
+            keyorra_core::store::ItemEntry::Ok(i) if i.title == title => Some(i.id),
+            _ => None,
+        })
+        .unwrap()
+}
+
+fn retitle(store: &mut Store, old: &str, title: &str) {
+    let mut item = store.get_item(item_id(store, old)).unwrap();
+    item.title = title.into();
+    store.save_item(&item).unwrap();
+}
+
+fn approve_all(main: &mut Device, other: &mut Device, from: u64) {
+    round(main, from);
+    let code = other.synced.key_code();
+    let id = other.synced.engine().device();
+    main.synced.approve(id, &code, from + 1).unwrap();
+    for t in from + 2..from + 6 {
+        round(main, t);
+        round(other, t);
+    }
+}
+
+#[test]
+fn a_device_joins_with_the_setup_code_alone() {
+    let transport = MemoryTransport::new();
+    let (mut main, _kit) = main_device(&transport);
+    let code = SetupCode::parse(&main.synced.setup_code().to_text()).unwrap();
+    let dir = tempfile::tempdir().unwrap();
+    let path = dir.path().join("j.db");
+    let mut keys = MemoryDeviceKeys::default();
+    let sk = *code.secret_key.as_bytes();
+    let (store, synced) = join(
+        &path,
+        PW,
+        KdfParams::INSECURE_FAST,
+        &code.secret_key,
+        &code.secret_key_id,
+        Some(&code.pin),
+        transport.clone(),
+        &mut keys,
+        "Laptop",
+        cheap_unlock(PW, sk),
+        NOW_MS,
+    )
+    .unwrap();
+    let mut laptop = Device {
+        _dir: dir,
+        path,
+        store,
+        synced,
+        keys,
+    };
+    approve_all(&mut main, &mut laptop, NOW_MS + 1);
+    assert!(titles(&laptop.store).contains("before sync"));
+}
+
+#[test]
+fn turning_sync_off_keeps_everything_and_records_nothing() {
+    let (_t, _main, mut laptop) = pair();
+    let before = titles(&laptop.store);
+    disable(&mut laptop.store, Some(laptop.synced), &mut laptop.keys).unwrap();
+    assert_eq!(titles(&laptop.store), before);
+    assert!(!is_enabled(&laptop.store).unwrap());
+    let vault = laptop.store.vaults().unwrap()[0].id;
+    laptop
+        .store
+        .save_item(&Item::new(vault, ItemKind::Login, "offline", 50))
+        .unwrap();
+    assert!(laptop.store.pending_changes().unwrap().is_empty());
+    assert!(
+        laptop.keys.0.lock().unwrap().is_empty(),
+        "device key forgotten"
+    );
+}
+
+#[test]
+fn the_main_device_cannot_turn_sync_off_under_other_devices() {
+    let (_t, mut main, _laptop) = pair();
+    let synced = std::mem::replace(
+        &mut main.synced,
+        main_device(&MemoryTransport::new()).0.synced,
+    );
+    assert!(matches!(
+        disable(&mut main.store, Some(synced), &mut main.keys),
+        Err(Error::Refused(_))
+    ));
+}
+
+#[test]
+fn rejoining_merges_by_record_id_and_keeps_both_sides_of_a_double_edit() {
+    let (transport, mut main, mut laptop) = pair();
+    let vault = main.store.vaults().unwrap()[0].id;
+    for title in ["only here", "both", "only there"] {
+        main.store
+            .save_item(&Item::new(vault, ItemKind::Login, title, 60))
+            .unwrap();
+    }
+    for t in 60..64 {
+        round(&mut main, NOW_MS + t);
+        round(&mut laptop, NOW_MS + t);
+    }
+    let Device {
+        _dir,
+        path,
+        mut store,
+        synced,
+        mut keys,
+    } = laptop;
+    disable(&mut store, Some(synced), &mut keys).unwrap();
+    // While sync is off here: edits on both sides.
+    retitle(&mut store, "only here", "only here, edited here");
+    retitle(&mut store, "both", "both, edited here");
+    retitle(&mut main.store, "both", "both, edited there");
+    retitle(&mut main.store, "only there", "only there, edited there");
+    round(&mut main, NOW_MS + 70);
+
+    let kit = main.synced.emergency_kit();
+    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
+    let synced = rejoin(
+        &mut store,
+        &sk,
+        &id,
+        Some(&main.synced.root_pin()),
+        transport.clone(),
+        &mut keys,
+        "Laptop",
+        cheap_unlock(PW, *sk.as_bytes()),
+        NOW_MS + 71,
+    )
+    .unwrap();
+    let mut laptop = Device {
+        _dir,
+        path,
+        store,
+        synced,
+        keys,
+    };
+    approve_all(&mut main, &mut laptop, NOW_MS + 72);
+    for t in 80..84 {
+        round(&mut main, NOW_MS + t);
+        round(&mut laptop, NOW_MS + t);
+    }
+    let seen = titles(&main.store);
+    for title in [
+        "before sync",
+        "only here, edited here",
+        "only there, edited there",
+        "both, edited there",
+        "both, edited here",
+    ] {
+        assert!(seen.contains(title), "{title}: {seen:?}");
+    }
+    assert_eq!(titles(&laptop.store), seen);
+    assert_eq!(seen.len(), 5, "nothing doubled: {seen:?}");
+    let copy = laptop
+        .store
+        .get_item(item_id(&laptop.store, "both, edited here"))
+        .unwrap();
+    assert_eq!(
+        copy.conflict.unwrap().of,
+        item_id(&laptop.store, "both, edited there")
+    );
+    assert!(laptop.store.sealed_meta("sync-base").unwrap().is_none());
+}
+
+#[test]
+fn a_vault_of_another_account_cannot_rejoin() {
+    let (transport, main, _laptop) = pair();
+    let (other, _) = main_device(&MemoryTransport::new());
+    let Device {
+        mut store,
+        synced,
+        mut keys,
+        ..
+    } = other;
+    disable(&mut store, Some(synced), &mut keys).unwrap();
+    let kit = main.synced.emergency_kit();
+    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
+    let result = rejoin(
+        &mut store,
+        &sk,
+        &id,
+        None,
+        transport,
+        &mut keys,
+        "Other",
+        cheap_unlock(PW, *sk.as_bytes()),
+        NOW_MS + 90,
+    );
+    assert!(matches!(result, Err(Error::Refused(_))));
+}
+
+#[test]
+fn another_accounts_vault_is_carried_over_as_new_records() {
+    let (_t, _main, mut laptop) = pair();
+    let dir = tempfile::tempdir().unwrap();
+    let mut old = Store::create(&dir.path().join("old.db"), PW, KdfParams::INSECURE_FAST).unwrap();
+    let v = old.create_vault("Old Mac").unwrap();
+    let item = Item::new(v.id, ItemKind::SecureNote, "carried", 1);
+    old.save_item(&item).unwrap();
+    old.add_attachment(item.id, "a.txt", b"bytes", 2).unwrap();
+    assert_eq!(carry_over(&old, &mut laptop.store).unwrap(), 1);
+    for t in 100..104 {
+        round(&mut laptop, NOW_MS + t);
+    }
+    let copied = laptop
+        .store
+        .get_item(item_id(&laptop.store, "carried"))
+        .unwrap();
+    assert_ne!(copied.id, item.id);
+    assert_eq!(
+        &laptop
+            .store
+            .get_attachment(copied.attachments[0].id)
+            .unwrap()[..],
+        b"bytes"
+    );
+}
+
+#[test]
+fn the_main_device_starts_a_new_account_with_new_keys() {
+    let (_t, mut main, _laptop) = pair();
+    let old_account = main.store.account_key_copy().unwrap();
+    let fresh = MemoryTransport::new();
+    let synced = std::mem::replace(
+        &mut main.synced,
+        main_device(&MemoryTransport::new()).0.synced,
+    );
+    let (synced, kit) = start_new_account(
+        &mut main.store,
+        Some(synced),
+        fresh.clone(),
+        &mut main.keys,
+        "Main",
+        PW,
+        KdfParams::INSECURE_FAST,
+        NOW_MS + 110,
+    )
+    .unwrap();
+    main.synced = synced;
+    assert_ne!(
+        main.store.account_key().unwrap().as_bytes(),
+        old_account.as_bytes()
+    );
+    let mut newcomer = joiner(&fresh, &kit, Some(main.synced.root_pin()));
+    approve_all(&mut main, &mut newcomer, NOW_MS + 111);
+    assert_eq!(titles(&newcomer.store), titles(&main.store));
+    assert!(titles(&newcomer.store).contains("before sync"));
+}
```

The setup code and the enclave keys have their tests in their files below. Nothing compiles yet.

- [ ] **Step 2: Setup code.**

Create `crates/keyorra-session/src/sync/setup.rs`:

```rust
//! The setup code the main device shows to add a device (plan A1d; A3 also renders it as a
//! QR code). It carries the Secret Key and pins the main device (its id and key code), so the
//! new device needs only the master password and refuses a header that names another main
//! device. It is as secret as the Secret Key.

use data_encoding::BASE32_NOPAD;
use keyorra_sync::account::RootPin;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::{DeviceId, Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PREFIX: &str = "KEYORRA-SETUP-1-";
const ID_LEN: usize = 4;
/// id (4 ASCII) | secret key (16) | main device id (16) | key code (6) | check (2)
const BODY: usize = ID_LEN + 16 + 16 + 6;

pub struct SetupCode {
    pub secret_key_id: String,
    pub secret_key: SecretKey,
    pub pin: RootPin,
}

fn check(body: &[u8]) -> [u8; 2] {
    let d = Sha256::digest([b"keyorra-setup-code-v1".as_slice(), body].concat());
    [d[0], d[1]]
}

fn bad() -> Error {
    Error::Malformed("setup code".into())
}

impl SetupCode {
    pub fn to_text(&self) -> Zeroizing<String> {
        let fp: Vec<u8> = data_encoding::HEXLOWER
            .decode(self.pin.key_fingerprint.replace('-', "").as_bytes())
            .expect("key codes are hex");
        let mut body = Zeroizing::new(Vec::with_capacity(BODY + 2));
        body.extend_from_slice(self.secret_key_id.as_bytes());
        body.extend_from_slice(self.secret_key.as_bytes());
        body.extend_from_slice(&self.pin.device);
        body.extend_from_slice(&fp);
        let c = check(&body);
        body.extend_from_slice(&c);
        Zeroizing::new(format!("{PREFIX}{}", BASE32_NOPAD.encode(&body)))
    }

    pub fn parse(text: &str) -> Result<SetupCode> {
        let compact: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let rest = compact.strip_prefix(PREFIX).ok_or_else(bad)?;
        let body = Zeroizing::new(BASE32_NOPAD.decode(rest.as_bytes()).map_err(|_| bad())?);
        if body.len() != BODY + 2 || check(&body[..BODY]) != body[BODY..] {
            return Err(bad());
        }
        let secret_key_id = std::str::from_utf8(&body[..ID_LEN])
            .map_err(|_| bad())?
            .to_owned();
        let mut sk = [0u8; 16];
        sk.copy_from_slice(&body[ID_LEN..ID_LEN + 16]);
        let mut device: DeviceId = [0; 16];
        device.copy_from_slice(&body[ID_LEN + 16..ID_LEN + 32]);
        let hex = data_encoding::HEXLOWER.encode(&body[ID_LEN + 32..BODY]);
        Ok(SetupCode {
            secret_key_id,
            secret_key: SecretKey::from_bytes(sk),
            pin: RootPin {
                device,
                key_fingerprint: format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12]),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SetupCode {
        SetupCode {
            secret_key_id: "A3KX".into(),
            secret_key: SecretKey::from_bytes([9; 16]),
            pin: RootPin {
                device: [4; 16],
                key_fingerprint: "0a1b-2c3d-4e5f".into(),
            },
        }
    }

    #[test]
    fn round_trips_and_tolerates_spaces_and_case() {
        let text = sample().to_text();
        let spaced = format!(" {} ", text.to_lowercase());
        let back = SetupCode::parse(&spaced).unwrap();
        assert_eq!(back.secret_key_id, "A3KX");
        assert_eq!(back.secret_key.as_bytes(), &[9; 16]);
        assert_eq!(back.pin.device, [4; 16]);
        assert_eq!(back.pin.key_fingerprint, "0a1b-2c3d-4e5f");
    }

    #[test]
    fn a_mistyped_code_is_refused() {
        let text = sample().to_text();
        let mut chars: Vec<char> = text.chars().collect();
        let i = PREFIX.len() + 5;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(SetupCode::parse(&typo).is_err());
        assert!(SetupCode::parse("KEYORRA-SETUP-1-").is_err());
        assert!(SetupCode::parse("hello").is_err());
    }
}
```

- [ ] **Step 3: Device keys sealed to the Secure Enclave.**

`DeviceKeyStore::store` now reports failure and `forget` drops an id:

```diff
diff --git a/crates/keyorra-session/src/sync/keys.rs b/crates/keyorra-session/src/sync/keys.rs
index b234063..8c5f67a 100644
--- a/crates/keyorra-session/src/sync/keys.rs
+++ b/crates/keyorra-session/src/sync/keys.rs
@@ -1,6 +1,6 @@
-//! Device signing keys. A1d-2 keeps them in the macOS Keychain with
-//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (a Swift helper, like Touch ID), so a
-//! database restored or copied to another Mac finds no key and the device retires its id.
+//! Device signing keys: where they are kept ([`super::EnclaveDeviceKeys`] in the app, sealed
+//! to this Mac's Secure Enclave; in memory in tests). A database restored or copied to another
+//! Mac finds no key and the device retires its id.
 
 use std::collections::BTreeMap;
 use std::sync::{Arc, Mutex};
@@ -12,7 +12,9 @@ use zeroize::Zeroizing;
 
 pub trait DeviceKeyStore: Send {
     fn load(&self, device: &DeviceId) -> Option<SigningKey>;
-    fn store(&mut self, device: DeviceId, key: &SigningKey);
+    fn store(&mut self, device: DeviceId, key: &SigningKey) -> Result<(), String>;
+    /// The id is no longer used here (sync turned off, or a new account).
+    fn forget(&mut self, device: &DeviceId);
     /// Another handle to the same keys (the engine keeps one to store a new id's key when it
     /// retires the old one).
     fn boxed_clone(&self) -> Box<dyn DeviceKeyStore>;
@@ -31,11 +33,16 @@ impl DeviceKeyStore for MemoryDeviceKeys {
             .map(|k| SigningKey::from_bytes(k))
     }
 
-    fn store(&mut self, device: DeviceId, key: &SigningKey) {
+    fn store(&mut self, device: DeviceId, key: &SigningKey) -> Result<(), String> {
         self.0
             .lock()
             .unwrap()
             .insert(device, Zeroizing::new(key.to_bytes()));
+        Ok(())
+    }
+
+    fn forget(&mut self, device: &DeviceId) {
+        self.0.lock().unwrap().remove(device);
     }
 
     fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
@@ -50,7 +57,8 @@ impl DeviceKeys for EngineKeys {
     fn holds(&self, device: &DeviceId) -> bool {
         self.0.load(device).is_some()
     }
+    /// A failure leaves the new id without a stored key: the next restart retires it again.
     fn store(&mut self, device: DeviceId, key: &SigningKey) {
-        self.0.store(device, key);
+        let _ = self.0.store(device, key);
     }
 }
```

Create `crates/keyorra-session/src/sync/enclave_keys.rs` (one enclave key per Mac, one sealed record per device id; tests: a key comes back on the same Mac; a keychain restored on another Mac opens nothing):

```rust
//! Device signing keys that stay on this Mac (plan A1d).
//!
//! The data-protection keychain (`kSecAttrAccessible…ThisDeviceOnly` items) needs a
//! provisioning profile the app does not have (see swift/TouchId.swift). So each device key is
//! sealed to a Secure Enclave key created with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
//! and no user presence: the enclave key never leaves this Mac, so a keychain or disk restored
//! on another Mac (or a copied database) finds a record it cannot open, and the engine retires
//! the device id (spec §4.2). The sealed records are kept in one login-keychain item.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use keyorra_core::crypto::{self, Key};
use keyorra_sync::DeviceId;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::keys::DeviceKeyStore;
use crate::touchid::Keyring;

const LABEL: &str = "keyorra-device-key-v1";

/// The Secure Enclave as the device keys need it (never prompts).
pub trait Enclave: Send + Sync {
    /// A new enclave key bound to this Mac: (opaque blob, 65-byte X9.63 public key).
    fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String>;
    /// ECDH of the enclave key with `peer`.
    fn agree(&self, blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, String>;
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    enclave_key: String,
    enclave_public: String,
    ephemeral_public: String,
    sealed: String,
}

/// Device keys sealed to the Secure Enclave, kept in one keychain item.
#[derive(Clone)]
pub struct EnclaveDeviceKeys {
    keyring: Arc<dyn Keyring + Sync>,
    enclave: Arc<dyn Enclave>,
    /// One enclave key serves every device id of this Mac; made on first use.
    lock: Arc<Mutex<()>>,
}

impl EnclaveDeviceKeys {
    pub fn new(keyring: Arc<dyn Keyring + Sync>, enclave: Arc<dyn Enclave>) -> Self {
        Self {
            keyring,
            enclave,
            lock: Arc::new(Mutex::new(())),
        }
    }

    fn records(&self) -> BTreeMap<String, Record> {
        self.keyring
            .load()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

fn wrapping_key(device: &DeviceId, shared: &[u8; 32], ephemeral: &[u8], enclave: &[u8]) -> Key {
    let mut h = Sha256::new();
    h.update(LABEL.as_bytes());
    h.update(device);
    h.update(shared);
    h.update(ephemeral);
    h.update(enclave);
    Key::from_bytes(h.finalize().into())
}

fn aad(device: &DeviceId) -> Vec<u8> {
    [LABEL.as_bytes(), b"/", device.as_slice()].concat()
}

impl DeviceKeyStore for EnclaveDeviceKeys {
    fn load(&self, device: &DeviceId) -> Option<SigningKey> {
        let r = self.records().remove(&HEXLOWER.encode(device))?;
        let blob = HEXLOWER.decode(r.enclave_key.as_bytes()).ok()?;
        let enclave_public = HEXLOWER.decode(r.enclave_public.as_bytes()).ok()?;
        let ephemeral: [u8; 65] = HEXLOWER
            .decode(r.ephemeral_public.as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        let shared = self.enclave.agree(&blob, &ephemeral).ok()?;
        let key = wrapping_key(device, &shared, &ephemeral, &enclave_public);
        let sealed = HEXLOWER.decode(r.sealed.as_bytes()).ok()?;
        let secret = crypto::open(&key, &sealed, &aad(device)).ok()?;
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(secret.as_slice().try_into().ok()?);
        Some(SigningKey::from_bytes(&bytes))
    }

    fn store(&mut self, device: DeviceId, key: &SigningKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap();
        let mut records = self.records();
        let (blob, public) = match records.values().next() {
            Some(r) => (
                HEXLOWER
                    .decode(r.enclave_key.as_bytes())
                    .map_err(|e| e.to_string())?,
                HEXLOWER
                    .decode(r.enclave_public.as_bytes())
                    .map_err(|e| e.to_string())?,
            ),
            None => {
                let (blob, public) = self.enclave.create()?;
                (blob, public.to_vec())
            }
        };
        let enclave = PublicKey::from_sec1_bytes(&public).map_err(|e| e.to_string())?;
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral.public_key().to_encoded_point(false);
        let shared = ephemeral.diffie_hellman(&enclave);
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(shared.raw_secret_bytes());
        let wrap = wrapping_key(&device, &secret, ephemeral_public.as_bytes(), &public);
        let sealed = crypto::seal(&wrap, &key.to_bytes(), &aad(&device));
        records.insert(
            HEXLOWER.encode(&device),
            Record {
                enclave_key: HEXLOWER.encode(&blob),
                enclave_public: HEXLOWER.encode(&public),
                ephemeral_public: HEXLOWER.encode(ephemeral_public.as_bytes()),
                sealed: HEXLOWER.encode(&sealed),
            },
        );
        let bytes = serde_json::to_vec(&records).map_err(|e| e.to_string())?;
        self.keyring.save(&bytes)
    }

    fn forget(&mut self, device: &DeviceId) {
        let _guard = self.lock.lock().unwrap();
        let mut records = self.records();
        if records.remove(&HEXLOWER.encode(device)).is_some() {
            if let Ok(bytes) = serde_json::to_vec(&records) {
                let _ = self.keyring.save(&bytes);
            }
        }
    }

    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::touchid::MemKeyring;

    /// A software enclave: one P-256 key per "Mac".
    pub(crate) struct SoftEnclave(pub p256::SecretKey);

    impl Enclave for SoftEnclave {
        fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String> {
            let public = self.0.public_key().to_encoded_point(false);
            Ok((b"blob".to_vec(), public.as_bytes().try_into().unwrap()))
        }
        fn agree(&self, _blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, String> {
            let peer = PublicKey::from_sec1_bytes(peer).map_err(|e| e.to_string())?;
            let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(shared.raw_secret_bytes());
            Ok(out)
        }
    }

    fn keys(keyring: &MemKeyring) -> EnclaveDeviceKeys {
        EnclaveDeviceKeys::new(
            Arc::new(keyring.clone()),
            Arc::new(SoftEnclave(p256::SecretKey::random(&mut OsRng))),
        )
    }

    #[test]
    fn a_device_key_comes_back_on_the_same_mac() {
        let keyring = MemKeyring::default();
        let mut store = keys(&keyring);
        let key = SigningKey::from_bytes(&[5; 32]);
        store.store([1; 16], &key).unwrap();
        store
            .store([2; 16], &SigningKey::from_bytes(&[6; 32]))
            .unwrap();
        assert_eq!(store.load(&[1; 16]).unwrap().to_bytes(), [5; 32]);
        assert_eq!(store.load(&[2; 16]).unwrap().to_bytes(), [6; 32]);
        assert!(store.load(&[3; 16]).is_none());
        store.forget(&[1; 16]);
        assert!(store.load(&[1; 16]).is_none());
        assert!(store.load(&[2; 16]).is_some());
    }

    #[test]
    fn a_keychain_restored_on_another_mac_opens_nothing() {
        let keyring = MemKeyring::default();
        let mut here = keys(&keyring);
        here.store([1; 16], &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
        // Same keychain contents, another Secure Enclave.
        let elsewhere = keys(&keyring);
        assert!(elsewhere.load(&[1; 16]).is_none());
    }
}
```

- [ ] **Step 4: Leaving, rejoining, carrying over, starting over.**

Create `crates/keyorra-session/src/sync/merge.rs`:

```rust
//! Turning sync off and on again, and moving to another account (plan A1d).
//!
//! - **Disable** keeps every record and its id; the store stops recording changes, and a
//!   fingerprint of every record is kept (`sync-base`).
//! - **Rejoin** the same account (same account key): a new device id joins; records changed
//!   here since sync was turned off are written; a record also changed in the account since
//!   then becomes a conflict copy here, so neither edit is lost. Records with the same id are
//!   the same record.
//! - **Carry over** to another account: the live items of the old store are copied, as new
//!   records, into the store made for the new account.
//! - **Start a new account** from this device (the main device must start over, or the user
//!   chooses it): sync is turned off, every key of the store is replaced, and sync is enabled
//!   again as a new account.

use std::collections::BTreeMap;

use keyorra_core::crypto::KdfParams;
use keyorra_core::import::{ImportPlan, ImportedItem, ImportedVault};
use keyorra_core::model::{ConflictInfo, Item};
use keyorra_core::store::{Change, ChangeKind, ItemEntry, Store};
use keyorra_sync::account::RootPin;
use keyorra_sync::fold::View;
use keyorra_sync::header::Header;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::Transport;
use keyorra_sync::{DeviceId, Error, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    enable, join_store, load_config, open_account, DeviceKeyStore, EmergencyKit, Synced, BASE,
    CONFIG, MEMO, OUTBOX,
};
use keyorra_core::crypto::Key;

/// Record id → fingerprint of what it held.
pub(super) type Base = BTreeMap<Uuid, [u8; 32]>;

fn item_print(item: &Item, deleted_at: Option<i64>) -> [u8; 32] {
    let json = serde_json::to_vec(item).expect("items serialize");
    let mut h = Sha256::new();
    h.update(b"keyorra-sync-base/item/");
    h.update(deleted_at.unwrap_or(-1).to_be_bytes());
    h.update(&json);
    h.finalize().into()
}

fn vault_print(name: &str, deleted: bool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"keyorra-sync-base/vault/");
    h.update([deleted as u8]);
    h.update(name.as_bytes());
    h.finalize().into()
}

fn all_items(store: &Store) -> Result<Vec<Item>> {
    let mut out: Vec<Item> = Vec::new();
    for v in store.vaults()? {
        for e in store.list_items(Some(v.id))? {
            if let ItemEntry::Ok(i) = e {
                out.push(i);
            }
        }
    }
    for e in store.deleted_items()? {
        if let ItemEntry::Ok(i) = e {
            out.push(i);
        }
    }
    Ok(out)
}

/// Fingerprints of every vault and item the store holds now.
fn prints(store: &Store) -> Result<(Base, Vec<Change>)> {
    let mut base = Base::new();
    let mut changes = Vec::new();
    for (info, _, deleted) in store.vault_rows()? {
        base.insert(info.id, vault_print(&info.name, deleted));
        changes.push(Change {
            kind: ChangeKind::Vault,
            id: info.id,
        });
    }
    for item in all_items(store)? {
        if let Some((item, deleted_at)) = store.item_state(item.id)? {
            base.insert(item.id, item_print(&item, deleted_at));
            changes.push(Change {
                kind: ChangeKind::Item,
                id: item.id,
            });
        }
    }
    Ok((base, changes))
}

/// The records that differ from `base` (changed or new here while sync was off).
pub(super) fn changed_since(store: &Store, base: &Base) -> Result<Vec<Change>> {
    let (now, changes) = prints(store)?;
    Ok(changes
        .into_iter()
        .filter(|c| base.get(&c.id) != now.get(&c.id))
        .collect())
}

pub(super) fn load_base(store: &Store) -> Result<Option<Base>> {
    let Some(raw) = store.sealed_meta(BASE)? else {
        return Ok(None);
    };
    let map: BTreeMap<Uuid, String> =
        serde_json::from_slice(&raw).map_err(|e| Error::Malformed(e.to_string()))?;
    let mut base = Base::new();
    for (id, hex) in map {
        let bytes = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|_| Error::Malformed("sync base".into()))?;
        base.insert(
            id,
            bytes
                .try_into()
                .map_err(|_| Error::Malformed("sync base".into()))?,
        );
    }
    Ok(Some(base))
}

fn save_base(store: &mut Store, base: &Base) -> Result<()> {
    let map: BTreeMap<Uuid, String> = base
        .iter()
        .map(|(id, p)| (*id, data_encoding::HEXLOWER.encode(p)))
        .collect();
    let bytes = serde_json::to_vec(&map).map_err(|e| Error::Malformed(e.to_string()))?;
    store.set_sealed_meta(BASE, &bytes)?;
    Ok(())
}

/// Rejoining: if the item changed here and in the account since `base`, keep this device's
/// version as a conflict copy (written as a new record) and let the account's version stand.
pub(super) fn copy_if_both_changed(
    store: &mut Store,
    base: &Base,
    view: &View,
    id: Uuid,
    device: DeviceId,
) -> Result<bool> {
    let Some(base_print) = base.get(&id) else {
        return Ok(false);
    };
    let Some((local, local_deleted)) = store.item_state(id)? else {
        return Ok(false);
    };
    let Some(remote) = view.items.get(&id) else {
        return Ok(false);
    };
    let Some(payload) = &remote.payload else {
        return Ok(false);
    };
    let Ok(mut theirs) = serde_json::from_slice::<Item>(&payload.item_json) else {
        return Ok(false);
    };
    theirs.id = id;
    if let Some(v) = remote.vault_id {
        theirs.vault_id = v;
    }
    let their_deleted = payload.deleted_at.map(|d| d as i64);
    let theirs_print = item_print(&theirs, their_deleted);
    if theirs_print == *base_print || theirs_print == item_print(&local, local_deleted) {
        return Ok(false);
    }
    let mut copy = local;
    copy.id = Uuid::new_v4();
    copy.attachments.clear();
    copy.conflict = Some(ConflictInfo {
        of: id,
        version: String::new(),
        from_device: data_encoding::HEXLOWER.encode(&device),
    });
    store.save_item(&copy)?;
    Ok(true)
}

/// Turns sync off on this device. Every record keeps its id; what each looked like is kept
/// for rejoining. The main device refuses while other devices are approved (they would be
/// left without a main device): it starts a new account instead, or removes them first.
pub fn disable<T: Transport>(
    store: &mut Store,
    synced: Option<Synced<T>>,
    keys: &mut dyn DeviceKeyStore,
) -> Result<()> {
    if let Some(s) = &synced {
        if s.engine.is_root() && s.engine.trust().devices().len() > 1 {
            return Err(Error::Refused(
                "this Mac is the main device of other devices".into(),
            ));
        }
    }
    let device = match &synced {
        Some(s) => Some(s.engine.device()),
        None => load_config(store).ok().map(|c| c.device),
    };
    forget(store)?;
    let (base, _) = prints(store)?;
    save_base(store, &base)?;
    if let Some(device) = device {
        keys.forget(&device);
    }
    Ok(())
}

fn forget(store: &mut Store) -> Result<()> {
    for name in [CONFIG, OUTBOX, MEMO, BASE] {
        store.delete_sealed_meta(name)?;
    }
    store.set_own_segments(&BTreeMap::new())?;
    store.set_sync_tracking(false)?;
    Ok(())
}

/// Joins the account this store belonged to (sync was turned off here): same account key
/// required. A new device id joins and waits for approval.
#[allow(clippy::too_many_arguments)]
pub fn rejoin<T: Transport>(
    store: &mut Store,
    secret_key: &SecretKey,
    secret_key_id: &str,
    pin: Option<&RootPin>,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    unlock: impl FnMut(&Header) -> Result<Key>,
    wall_ms: u64,
) -> Result<Synced<T>> {
    if super::is_enabled(store)? {
        return Err(Error::Refused("sync is already on".into()));
    }
    let (header, account_key) = open_account(&transport, pin, unlock)?;
    if account_key.as_bytes() != store.account_key()?.as_bytes() {
        return Err(Error::Refused(
            "this vault belongs to another account".into(),
        ));
    }
    let base = load_base(store)?.unwrap_or_default();
    join_store(
        store,
        transport,
        keys,
        device_name,
        (secret_key, secret_key_id),
        &header,
        account_key,
        Some(base),
        wall_ms,
    )
}

/// Copies the live items of `from` (with attachments) into `to`, as new records in new
/// vaults of the same names. Returns how many items were copied.
pub fn carry_over(from: &Store, to: &mut Store) -> Result<usize> {
    let mut plan = ImportPlan::default();
    for vault in from.vaults()? {
        let mut items = Vec::new();
        for e in from.list_items(Some(vault.id))? {
            let ItemEntry::Ok(item) = e else { continue };
            let mut attachments = Vec::new();
            for a in &item.attachments {
                attachments.push((a.name.clone(), from.get_attachment(a.id)?.to_vec()));
            }
            let mut item = item;
            item.attachments.clear();
            items.push(ImportedItem { item, attachments });
        }
        plan.vaults.push(ImportedVault {
            name: vault.name,
            items,
        });
    }
    let n = plan.item_count();
    to.apply_import(&plan)?;
    Ok(n)
}

/// Leaves the current account (if any) and makes this device the main device of a new one,
/// with every key of the store replaced first.
#[allow(clippy::too_many_arguments)]
pub fn start_new_account<T: Transport, U: Transport>(
    store: &mut Store,
    old: Option<Synced<U>>,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<(Synced<T>, EmergencyKit)> {
    let device = match &old {
        Some(s) => Some(s.engine.device()),
        None => load_config(store).ok().map(|c| c.device),
    };
    drop(old);
    store.check_password(password)?;
    forget(store)?;
    if let Some(device) = device {
        keys.forget(&device);
    }
    store.rotate_keys(password)?;
    enable(store, transport, keys, device_name, password, kdf, wall_ms)
}
```

- [ ] **Step 5: The bridge.**

Apply (module declarations; `open_account` and `join_store` shared by `join` and `rejoin`; the `base` of a rejoin and the conflict copy when both sides changed; **no local write before the first round read the store** (`caught_up`), found by the rejoin test: a fresh joiner's change to a vault it did not know yet was dropped as "not found"; `setup_code`):

```diff
diff --git a/crates/keyorra-session/src/sync/mod.rs b/crates/keyorra-session/src/sync/mod.rs
index 9945dc9..9ba0183 100644
--- a/crates/keyorra-session/src/sync/mod.rs
+++ b/crates/keyorra-session/src/sync/mod.rs
@@ -15,7 +15,10 @@
 //! is kept as sealed meta of the store (`sync:config`, `sync:outbox`, `sync:memo`) and in its
 //! `sync_segments` table. Attachment contents travel with the folder transport (plan A2).
 
+mod enclave_keys;
 mod keys;
+mod merge;
+mod setup;
 #[cfg(test)]
 mod tests;
 
@@ -39,11 +42,16 @@ use serde::{Deserialize, Serialize};
 use uuid::Uuid;
 use zeroize::Zeroizing;
 
+pub use enclave_keys::{Enclave, EnclaveDeviceKeys};
 pub use keys::{DeviceKeyStore, MemoryDeviceKeys};
+pub use merge::{carry_over, disable, rejoin, start_new_account};
+pub use setup::SetupCode;
 
 const CONFIG: &str = "sync:config";
 const OUTBOX: &str = "sync:outbox";
 const MEMO: &str = "sync:memo";
+/// What every record looked like when sync was turned off (kept for rejoining).
+const BASE: &str = "sync-base";
 
 /// What this device knows about its synced account (sealed meta `sync:config`).
 #[derive(Clone, Debug, Serialize, Deserialize)]
@@ -80,6 +88,12 @@ pub struct Synced<T: Transport> {
     engine: Engine<OsRng>,
     transport: T,
     config: SyncConfig,
+    /// Rejoining: what each record looked like when sync was turned off; a record changed
+    /// both here and in the account since then becomes a conflict copy.
+    base: Option<merge::Base>,
+    /// A round read the store since this started: before that the engine's view may lack
+    /// what a local change refers to (a joining device knows no vault yet).
+    caught_up: bool,
 }
 
 fn random_id() -> [u8; 16] {
@@ -134,7 +148,7 @@ pub fn enable<T: Transport>(
     let account_id = random_id();
     let device = random_id();
     let signer = new_signer();
-    keys.store(device, &signer);
+    keys.store(device, &signer).map_err(Error::Refused)?;
     let (secret_key, secret_key_id) = SecretKey::generate(&mut OsRng);
     let account_key = store.account_key_copy()?;
     let root_key = signer.verifying_key();
@@ -205,6 +219,8 @@ pub fn enable<T: Transport>(
         engine,
         transport,
         config,
+        base: None,
+        caught_up: false,
     };
     synced.round(store, wall_ms)?;
     Ok((synced, kit))
@@ -229,18 +245,53 @@ pub fn join<T: Transport>(
     unlock: impl FnMut(&Header) -> Result<Key>,
     wall_ms: u64,
 ) -> Result<(Store, Synced<T>)> {
+    let (header, account_key) = open_account(&transport, pin, unlock)?;
+    let mut store = Store::create_with_account_key(path, password, local_kdf, account_key.clone())?;
+    let synced = join_store(
+        &mut store,
+        transport,
+        keys,
+        device_name,
+        (secret_key, secret_key_id),
+        &header,
+        account_key,
+        None,
+        wall_ms,
+    )?;
+    Ok((store, synced))
+}
+
+/// The account header the transport holds, unlocked: (header, account key).
+fn open_account<T: Transport>(
+    transport: &T,
+    pin: Option<&RootPin>,
+    unlock: impl FnMut(&Header) -> Result<Key>,
+) -> Result<(Header, Key)> {
     let files = transport.headers()?;
     let root_head = match transport.root_head_file()? {
         Fetched::Ready(b) => Some(b),
         _ => None,
     };
     let joined = unlock_join_with(&files, root_head.as_deref(), pin, unlock)?;
-    let header = joined.file.header.clone();
-    let mut store =
-        Store::create_with_account_key(path, password, local_kdf, joined.account_key.clone())?;
+    Ok((joined.file.header.clone(), joined.account_key))
+}
+
+/// A new device id for `store` in the account: self-joins and waits for approval.
+#[allow(clippy::too_many_arguments)]
+fn join_store<T: Transport>(
+    store: &mut Store,
+    transport: T,
+    keys: &mut dyn DeviceKeyStore,
+    device_name: &str,
+    (secret_key, secret_key_id): (&SecretKey, &str),
+    header: &Header,
+    account_key: Key,
+    base: Option<merge::Base>,
+    wall_ms: u64,
+) -> Result<Synced<T>> {
     let device = random_id();
     let signer = new_signer();
-    keys.store(device, &signer);
+    keys.store(device, &signer).map_err(Error::Refused)?;
     let root_key = VerifyingKey::from_bytes(&header.root_key)
         .map_err(|_| Error::Malformed("main device key".into()))?;
     let mut engine = Engine::join(
@@ -248,7 +299,7 @@ pub fn join<T: Transport>(
         signer,
         device_name,
         header.account_id,
-        joined.account_key,
+        account_key,
         header.root_device,
         root_key,
         OsRng,
@@ -264,15 +315,21 @@ pub fn join<T: Transport>(
         secret_key: *secret_key.as_bytes(),
         secret_key_id: secret_key_id.to_owned(),
     };
-    save_config(&mut store, &config)?;
+    save_config(store, &config)?;
     store.set_sync_tracking(true)?;
+    if let Some(base) = &base {
+        // What changed here while sync was off is written once the device may write.
+        store.record_changes(&merge::changed_since(store, base)?)?;
+    }
     let mut synced = Synced {
         engine,
         transport,
         config,
+        base,
+        caught_up: false,
     };
-    synced.round(&mut store, wall_ms)?;
-    Ok((store, synced))
+    synced.round(store, wall_ms)?;
+    Ok(synced)
 }
 
 /// Continues sync after a restart (the store unlocked). The device key comes from `keys`; if
@@ -315,6 +372,8 @@ pub fn resume<T: Transport>(
         engine,
         transport,
         config,
+        base: merge::load_base(store)?,
+        caught_up: false,
     })
 }
 
@@ -346,6 +405,9 @@ impl<T: Transport> Synced<T> {
     pub fn round(&mut self, store: &mut Store, wall_ms: u64) -> Result<Vec<Event>> {
         self.write_changes(store, wall_ms)?;
         let synced = self.engine.sync(&self.transport, wall_ms);
+        if synced.is_ok() {
+            self.caught_up = true;
+        }
         // What could not be written before (the engine was still reading its own stream).
         self.write_changes(store, wall_ms)?;
         self.show(store)?;
@@ -357,22 +419,26 @@ impl<T: Transport> Synced<T> {
     /// The store's recorded changes, as versions. A change the engine cannot take yet (it
     /// is still reading its own stream after a restart, or conflict copies are owed) stays.
     fn write_changes(&mut self, store: &mut Store, wall_ms: u64) -> Result<()> {
-        if !self.engine.can_write() {
+        if !self.caught_up || !self.engine.can_write() {
             return Ok(());
         }
         let mut done = Vec::new();
+        let mut all = true;
         for change in store.pending_changes()? {
             match self.write_change(store, change, wall_ms) {
                 Ok(()) | Err(Error::NotFound(_)) => done.push(change),
-                Err(Error::Refused(_)) => {}
+                Err(Error::Refused(_)) => all = false,
                 Err(e) => return Err(e),
             }
         }
         store.clear_changes(&done)?;
+        if all && self.base.take().is_some() {
+            store.delete_sealed_meta(BASE)?;
+        }
         Ok(())
     }
 
-    fn write_change(&mut self, store: &Store, change: Change, wall_ms: u64) -> Result<()> {
+    fn write_change(&mut self, store: &mut Store, change: Change, wall_ms: u64) -> Result<()> {
         let view = self.engine.view();
         match change.kind {
             ChangeKind::Vault => {
@@ -396,6 +462,17 @@ impl<T: Transport> Synced<T> {
                 }
             }
             ChangeKind::Item => {
+                if let Some(base) = &self.base {
+                    if merge::copy_if_both_changed(
+                        store,
+                        base,
+                        &view,
+                        change.id,
+                        self.config.device,
+                    )? {
+                        return Ok(());
+                    }
+                }
                 let synced = view.items.get(&change.id);
                 match store.item_state(change.id)? {
                     Some((item, None)) => {
@@ -498,6 +575,15 @@ impl<T: Transport> Synced<T> {
         }
     }
 
+    /// The setup code for adding a device (secret: it carries the Secret Key).
+    pub fn setup_code(&self) -> SetupCode {
+        SetupCode {
+            secret_key_id: self.config.secret_key_id.clone(),
+            secret_key: SecretKey::from_bytes(self.config.secret_key),
+            pin: self.root_pin(),
+        }
+    }
+
     /// The pin a setup code shown on this device carries (the main device's id and key code).
     pub fn root_pin(&self) -> RootPin {
         RootPin {
```

- [ ] **Step 6: Run and commit.**

`cargo test -p keyorra-session sync::` green. Commit: `Session A1d-2: setup code, enclave device keys, turning sync off, rejoining, carrying over, starting over`.

---

### Task 4: Sync in the session

**Files:** Create `crates/keyorra-session/src/session/sync.rs`, `crates/keyorra-session/src/session/sync_tests.rs`; modify `crates/keyorra-session/src/session/mod.rs`, `crates/keyorra-session/src/sync/mod.rs`.

- [ ] **Step 1: Failing tests.**

Create `crates/keyorra-session/src/session/sync_tests.rs` (sync turned on, joined with the setup code and approved; sync runs only while unlocked and resumes on unlock; a vault created while synced reaches the other Mac; only the main Mac changes the master password; turning sync off and joining again rejoins the same vault; joining from a vault of another account carries it over and keeps the old file as `keyorra.db.pre-sync-YYYYMMDD`):

```rust
//! Plan A1d: sync through the session (two sessions, one in-memory store of files).

use keyorra_core::crypto::Key;
use keyorra_core::model::ItemKind;
use keyorra_sync::header::Header;
use keyorra_sync::keys::derive_sync_keys;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::MemoryTransport;

use super::tests::{new_session, unlocked_session, PW};
use super::*;
use crate::sync::{DeviceKeyStore, MemoryDeviceKeys};

struct TestLink {
    transport: MemoryTransport,
    keys: MemoryDeviceKeys,
    name: &'static str,
}

impl SyncLink for TestLink {
    fn transport(&self) -> Result<BoxedTransport, String> {
        Ok(Box::new(self.transport.clone()))
    }
    fn device_keys(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.keys.clone())
    }
    fn device_name(&self) -> String {
        self.name.into()
    }
    /// The real unlock refuses the cheap KDF parameters of these tests.
    fn unlock_header(
        &self,
        header: &Header,
        password: &str,
        secret_key: &SecretKey,
    ) -> keyorra_sync::Result<Key> {
        let keys = derive_sync_keys(
            password,
            &header.salt,
            header.kdf,
            secret_key,
            &header.account_id,
        )?;
        header.unwrap_account_key(&keys.kek)
    }
}

fn link(s: &mut Session, transport: &MemoryTransport, name: &'static str) {
    s.set_sync_link(Box::new(TestLink {
        transport: transport.clone(),
        keys: MemoryDeviceKeys::default(),
        name,
    }));
}

fn titles(s: &mut Session, now: u64) -> Vec<String> {
    let mut t: Vec<String> = s
        .items(&crate::dto::ItemFilter::default(), now)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    t.sort();
    t
}

fn add(s: &mut Session, title: &str, now: u64) {
    let vault = s.vaults(now).unwrap()[0].id;
    let mut item = s.new_item(vault, ItemKind::SecureNote, now).unwrap();
    item.title = title.into();
    s.save_item(item, now).unwrap();
}

fn rounds(a: &mut Session, b: &mut Session, from: u64) {
    for t in from..from + 4 {
        a.sync_now(t).unwrap();
        b.sync_now(t).unwrap();
    }
}

/// The main Mac with sync on, and a second Mac joined with the setup code and approved.
fn two_macs() -> (
    MemoryTransport,
    (tempfile::TempDir, Session),
    (tempfile::TempDir, Session),
) {
    let transport = MemoryTransport::new();
    let (d1, mut main) = unlocked_session();
    link(&mut main, &transport, "Main");
    add(&mut main, "before sync", 1_000);
    let kit = main.enable_sync(PW, 1_001).unwrap();
    assert!(kit.secret_key.len() > 20 && kit.setup_code.starts_with("KEYORRA-SETUP-1-"));

    let (d2, mut laptop) = new_session();
    link(&mut laptop, &transport, "Laptop");
    laptop.join_sync(PW, &kit.setup_code, 1_002).unwrap();
    assert_eq!(laptop.status(), Status::Unlocked);
    let waiting = laptop.sync_status().unwrap().status.unwrap();
    assert!(waiting.waiting_for_approval);

    main.sync_now(1_003).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    assert_eq!(joiner.name, "Laptop");
    main.approve_device(&joiner.id, &waiting.key_code, 1_004)
        .unwrap();
    rounds(&mut main, &mut laptop, 1_005);
    (transport, (d1, main), (d2, laptop))
}

#[test]
fn sync_turned_on_joined_with_the_setup_code_and_approved() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    assert_eq!(titles(&mut laptop, 1_010), ["before sync"]);
    add(&mut laptop, "from the laptop", 1_011);
    rounds(&mut main, &mut laptop, 1_012);
    assert_eq!(titles(&mut main, 1_020), ["before sync", "from the laptop"]);
    let status = laptop.sync_status().unwrap();
    assert!(status.enabled && status.error.is_none());
    assert!(!status.status.unwrap().waiting_for_approval);
}

#[test]
fn sync_runs_only_while_unlocked_and_resumes_on_unlock() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    laptop.lock();
    assert_eq!(laptop.sync_now(1_030).unwrap_err().kind, ErrorKind::Locked);
    add(&mut main, "while the laptop was locked", 1_031);
    main.sync_now(1_032).unwrap();
    laptop.unlock(PW, 1_033).unwrap();
    rounds(&mut main, &mut laptop, 1_034);
    assert!(titles(&mut laptop, 1_040).contains(&"while the laptop was locked".to_owned()));
}

#[test]
fn a_vault_created_while_synced_reaches_the_other_mac() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    let v = laptop.create_vault("Work", 1_050).unwrap();
    rounds(&mut main, &mut laptop, 1_051);
    assert!(main.vaults(1_060).unwrap().iter().any(|x| x.id == v.id));
}

#[test]
fn only_the_main_mac_changes_the_master_password() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    assert_eq!(
        laptop
            .change_password(PW, "another long password", 1_070)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    main.change_password(PW, "another long password", 1_071)
        .unwrap();
    rounds(&mut main, &mut laptop, 1_072);
    assert_eq!(main.synced.as_ref().unwrap().engine().header_epoch(), 2);
    assert_eq!(laptop.synced.as_ref().unwrap().engine().header_epoch(), 2);
}

#[test]
fn turning_sync_off_and_joining_again_rejoins_the_same_vault() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    let kit = main.emergency_kit().unwrap();
    laptop.disable_sync(1_080).unwrap();
    assert!(!laptop.sync_status().unwrap().enabled);
    add(&mut laptop, "while sync was off", 1_081);
    laptop.join_sync(PW, &kit.setup_code, 1_082).unwrap();
    main.sync_now(1_083).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    let code = laptop.sync_status().unwrap().status.unwrap().key_code;
    main.approve_device(&joiner.id, &code, 1_084).unwrap();
    rounds(&mut main, &mut laptop, 1_085);
    assert_eq!(
        titles(&mut main, 1_090),
        ["before sync", "while sync was off"]
    );
}

#[test]
fn joining_from_a_vault_of_another_account_carries_it_over() {
    let (transport, (_d1, mut main), _laptop) = two_macs();
    let kit = main.emergency_kit().unwrap();
    let (dir, mut other) = unlocked_session();
    link(&mut other, &transport, "Old Mac");
    add(&mut other, "old local item", 1_100);
    other.join_sync(PW, &kit.setup_code, 1_101).unwrap();
    let names: Vec<String> = std::fs::read_dir(dir.path().join("Application Support"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n == "keyorra.db.pre-sync-19700101"),
        "old file kept aside: {names:?}"
    );
    main.sync_now(1_102).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    let code = other.sync_status().unwrap().status.unwrap().key_code;
    main.approve_device(&joiner.id, &code, 1_103).unwrap();
    rounds(&mut main, &mut other, 1_104);
    assert_eq!(titles(&mut main, 1_110), ["before sync", "old local item"]);
    assert_eq!(titles(&mut other, 1_110), ["before sync", "old local item"]);
}
```

- [ ] **Step 2: Status and password on the bridge.**

Apply (`SyncStatus`, `SyncDevice`, `Synced::status`, `Synced::change_password`):

```diff
diff --git a/crates/keyorra-session/src/sync/mod.rs b/crates/keyorra-session/src/sync/mod.rs
index 9ba0183..0840263 100644
--- a/crates/keyorra-session/src/sync/mod.rs
+++ b/crates/keyorra-session/src/sync/mod.rs
@@ -65,6 +65,29 @@ struct SyncConfig {
     secret_key_id: String,
 }
 
+/// Sync as the UI shows it.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
+#[serde(rename_all = "camelCase")]
+pub struct SyncStatus {
+    pub main_device: bool,
+    /// This device self-joined and waits for the main device.
+    pub waiting_for_approval: bool,
+    /// This device's key code (compared on the main device before approving it).
+    pub key_code: String,
+    pub devices: Vec<SyncDevice>,
+    pub alarms: usize,
+}
+
+#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
+#[serde(rename_all = "camelCase")]
+pub struct SyncDevice {
+    pub id: String,
+    pub name: String,
+    pub approved: bool,
+    pub main: bool,
+    pub this_device: bool,
+}
+
 /// What the user writes down when sync is enabled (spec §7.6). The location is the
 /// transport's (plan A2/A3 add it).
 pub struct EmergencyKit {
@@ -575,6 +598,70 @@ impl<T: Transport> Synced<T> {
         }
     }
 
+    /// A new master password for the account (main device only): a new header epoch.
+    /// `account_key` is the store's (the same as the account's).
+    pub fn change_password(
+        &mut self,
+        account_key: &Key,
+        password: &str,
+        kdf: KdfParams,
+        wall_ms: u64,
+    ) -> Result<()> {
+        if !self.engine.is_root() {
+            return Err(Error::Refused(
+                "the master password is changed on the main device".into(),
+            ));
+        }
+        let current = self
+            .engine
+            .current_header()
+            .cloned()
+            .ok_or_else(|| Error::NotFound("account header".into()))?;
+        let mut salt = [0u8; 16];
+        OsRng.fill_bytes(&mut salt);
+        let sk = SecretKey::from_bytes(self.config.secret_key);
+        let keys = derive_sync_keys(password, &salt, kdf, &sk, &self.config.account_id)?;
+        let mut header = Header {
+            epoch: current.epoch + 1,
+            kdf,
+            salt,
+            wrapped_account_key: Vec::new(),
+            ..current
+        };
+        header.wrapped_account_key = wrap_account_key(&keys.kek, account_key, &header, &mut OsRng);
+        self.engine.publish_header(header, wall_ms)
+    }
+
+    /// What the UI shows about sync.
+    pub fn status(&self) -> SyncStatus {
+        let trust = self.engine.trust();
+        let mut devices: Vec<SyncDevice> = trust
+            .devices()
+            .iter()
+            .map(|(id, d)| SyncDevice {
+                id: data_encoding::HEXLOWER.encode(id),
+                name: d.name.clone(),
+                approved: true,
+                main: *id == trust.root(),
+                this_device: *id == self.engine.device(),
+            })
+            .collect();
+        devices.extend(trust.unapproved().iter().map(|(id, d)| SyncDevice {
+            id: data_encoding::HEXLOWER.encode(id),
+            name: d.name.clone(),
+            approved: false,
+            main: false,
+            this_device: *id == self.engine.device(),
+        }));
+        SyncStatus {
+            main_device: self.engine.is_root(),
+            waiting_for_approval: !trust.devices().contains_key(&self.engine.device()),
+            key_code: self.engine.key_fingerprint(),
+            devices,
+            alarms: self.engine.alarms().len(),
+        }
+    }
+
     /// The setup code for adding a device (secret: it carries the Secret Key).
     pub fn setup_code(&self) -> SetupCode {
         SetupCode {
```

- [ ] **Step 3: The session's sync commands.**

Create `crates/keyorra-session/src/session/sync.rs`:

```rust
//! Sync in the session (plan A1d): turned on, joined, run and turned off here; it runs only
//! while the vault is unlocked. The app supplies the transport and the device key store
//! through a [`SyncLink`] (the folder transport is plan A2; the UI is plan A3).

use keyorra_core::crypto::Key;
use keyorra_core::store::Store;
use keyorra_sync::header::Header;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::Transport;
use serde::Serialize;

use super::{locked, move_aside, sibling, Session, Status, DB_SIBLINGS, MIN_PASSWORD_LEN};
use crate::error::{CmdError, CmdResult, ErrorKind};
use crate::sync::{self as s, DeviceKeyStore, SetupCode, SyncStatus, Synced};

/// The transport sync runs over, boxed.
pub type BoxedTransport = Box<dyn Transport + Send>;

/// What the app gives the session for sync.
pub trait SyncLink: Send {
    /// The store of files the account lives in (opened per use).
    fn transport(&self) -> Result<BoxedTransport, String>;
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
    pub setup_code: String,
}

/// The sync part of the settings screen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub enabled: bool,
    /// Set but not running (e.g. the transport could not be opened); shown with a retry.
    pub error: Option<String>,
    pub status: Option<SyncStatus>,
}

fn sync_error(e: keyorra_sync::Error) -> CmdError {
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

fn open_transport(link: &dyn SyncLink) -> CmdResult<BoxedTransport> {
    link.transport()
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Sync folder: {e}")))
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

impl Session {
    pub fn set_sync_link(&mut self, link: Box<dyn SyncLink>) {
        self.sync_link = Some(link);
    }

    fn link(&self) -> CmdResult<&dyn SyncLink> {
        self.sync_link.as_deref().ok_or_else(no_link)
    }

    fn transport(&self) -> CmdResult<BoxedTransport> {
        open_transport(self.link()?)
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

    pub fn sync_status(&self) -> CmdResult<SyncStatusDto> {
        let store = self.store()?;
        Ok(SyncStatusDto {
            enabled: s::is_enabled(store).map_err(sync_error)?,
            error: self.sync_error.clone(),
            status: self.synced.as_ref().map(|x| x.status()),
        })
    }

    /// One sync round (the app calls it on a timer and after every change while unlocked).
    pub fn sync_now(&mut self, now: u64) -> CmdResult<SyncStatusDto> {
        let store = self.store.as_mut().ok_or_else(locked)?;
        if let Some(synced) = self.synced.as_mut() {
            match synced.round(store, wall_ms(now)) {
                Ok(_) => self.sync_error = None,
                Err(e) => self.sync_error = Some(sync_error(e).message),
            }
            self.watchtower_count = None;
        }
        self.sync_status()
    }

    /// Turns this vault into the main device of a new synced account. The master password
    /// is asked again (it also protects the account header).
    pub fn enable_sync(&mut self, password: &str, now: u64) -> CmdResult<EmergencyKitDto> {
        self.touch(now);
        let link = self.link()?;
        let (transport, mut keys, name) =
            (self.transport()?, link.device_keys(), link.device_name());
        let kdf = self.kdf;
        let store = self.store.as_mut().ok_or_else(locked)?;
        store.check_password(password)?;
        let (synced, kit) = s::enable(
            store,
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
        };
        self.synced = Some(synced);
        Ok(dto)
    }

    /// The Emergency Kit and setup code again (unlocked, sync on).
    pub fn emergency_kit(&self) -> CmdResult<EmergencyKitDto> {
        self.store()?;
        let synced = self
            .synced
            .as_ref()
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Sync is off"))?;
        let kit = synced.emergency_kit();
        Ok(EmergencyKitDto {
            account_id: kit.account_id,
            secret_key: kit.secret_key.to_string(),
            setup_code: synced.setup_code().to_text().to_string(),
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
    pub fn join_sync(&mut self, password: &str, code: &str, now: u64) -> CmdResult<()> {
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
    ) -> CmdResult<()> {
        let (transport, mut keys, name) = (
            open_transport(link)?,
            link.device_keys(),
            link.device_name(),
        );
        let unlock = |h: &Header| link.unlock_header(h, password, sk);
        match self.status() {
            Status::Locked => Err(locked()),
            Status::New => {
                if let Some(dir) = self.path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
                }
                let (store, synced) = s::join(
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
                self.store = Some(store);
                self.synced = Some(synced);
                self.password_verified_at = Some(now);
                self.keyring.delete();
                Ok(())
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
                    Ok(synced) => {
                        self.synced = Some(synced);
                        Ok(())
                    }
                    Err(keyorra_sync::Error::Refused(m)) if m.contains("another account") => {
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
    ) -> CmdResult<()> {
        let (transport, mut keys, name) = (
            open_transport(link)?,
            link.device_keys(),
            link.device_name(),
        );
        let joining = self.path.with_extension("joining");
        let _ = std::fs::remove_file(&joining);
        let (mut new_store, synced) = s::join(
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
        let old = self.store.take().ok_or_else(locked)?;
        if let Err(e) = s::carry_over(&old, &mut new_store) {
            self.store = Some(old);
            drop(new_store);
            let _ = std::fs::remove_file(&joining);
            return Err(sync_error(e));
        }
        drop(old);
        drop(new_store);
        drop(synced);
        let aside = pre_sync_path(&self.path, now);
        move_aside(&self.path, &aside, |from, to| std::fs::rename(from, to))
            .and_then(|()| std::fs::rename(&joining, &self.path))
            .map_err(|e| CmdError::new(ErrorKind::Other, format!("Can't move the file: {e}")))?;
        // The Touch ID record wraps the old vault's key.
        self.keyring.delete();
        let mut store = Store::open(&self.path)?;
        store.unlock(password)?;
        self.store = Some(store);
        self.password_verified_at = Some(now);
        let resumed = s::resume(
            self.store.as_ref().ok_or_else(locked)?,
            open_transport(link)?,
            link.device_keys().as_ref(),
        )
        .map_err(sync_error)?;
        self.synced = Some(resumed);
        Ok(())
    }

    /// Turns sync off on this Mac; everything stays in the vault.
    pub fn disable_sync(&mut self, now: u64) -> CmdResult<()> {
        self.touch(now);
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
        let synced = self
            .synced
            .as_mut()
            .ok_or_else(|| CmdError::new(ErrorKind::Invalid, "Sync is off"))?;
        synced
            .approve(device, code.trim(), wall_ms(now))
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
        let link = self.link()?;
        let (transport, mut keys, name) =
            (self.transport()?, link.device_keys(), link.device_name());
        let kdf = self.kdf;
        let old = self.synced.take();
        let store = self.store.as_mut().ok_or_else(locked)?;
        let (synced, kit) = s::start_new_account(
            store,
            old,
            transport,
            keys.as_mut(),
            &name,
            password,
            kdf,
            wall_ms(now),
        )
        .map_err(sync_error)?;
        // The Touch ID record wraps the replaced account key.
        self.keyring.delete();
        let dto = EmergencyKitDto {
            account_id: kit.account_id,
            secret_key: kit.secret_key.to_string(),
            setup_code: synced.setup_code().to_text().to_string(),
        };
        self.synced = Some(synced);
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

    /// While synced, the master password is changed on the main device, which publishes it
    /// for the account; other devices refuse.
    pub(super) fn change_sync_password(&mut self, new: &str, now: u64) -> CmdResult<()> {
        let Some(synced) = self.synced.as_mut() else {
            return Ok(());
        };
        let store = self.store.as_ref().ok_or_else(locked)?;
        let account = store.account_key_copy()?;
        synced
            .change_password(&account, new, self.kdf, wall_ms(now))
            .map_err(sync_error)
    }

    pub(super) fn sync_blocks_password_change(&self) -> bool {
        self.synced.as_ref().is_some_and(|x| !x.engine().is_root())
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
```

- [ ] **Step 4: Hooks.**

Apply (fields; `resume_sync` after both unlock paths; `lock` drops sync; `create_vault` through sync; `change_password` refused on other devices and published by the main device):

```diff
diff --git a/crates/keyorra-session/src/session/mod.rs b/crates/keyorra-session/src/session/mod.rs
index b994bd7..357c755 100644
--- a/crates/keyorra-session/src/session/mod.rs
+++ b/crates/keyorra-session/src/session/mod.rs
@@ -25,6 +25,9 @@ mod bridge;
 mod bridge_tests;
 #[cfg(test)]
 mod polish_tests;
+mod sync;
+#[cfg(test)]
+mod sync_tests;
 #[cfg(test)]
 mod tests;
 #[cfg(test)]
@@ -84,8 +87,16 @@ pub struct Session {
     keyring: Box<dyn Keyring>,
     /// When the master password was last entered (or the Touch ID record says so).
     password_verified_at: Option<u64>,
+    /// Transport and device keys for sync (from the app).
+    sync_link: Option<Box<dyn sync::SyncLink>>,
+    /// Running while unlocked and sync is on.
+    synced: Option<crate::sync::Synced<sync::BoxedTransport>>,
+    /// Why sync is not running (shown with a retry).
+    sync_error: Option<String>,
 }
 
+pub use sync::{BoxedTransport, EmergencyKitDto, SyncLink, SyncStatusDto};
+
 impl Session {
     /// `kdf` is `KdfParams::DEFAULT` in the app; tests pass cheap parameters.
     pub fn new(path: PathBuf, kdf: KdfParams, now: u64) -> Self {
@@ -114,6 +125,9 @@ impl Session {
             watchtower_count: None,
             keyring: Box::new(NoKeyring),
             password_verified_at: None,
+            sync_link: None,
+            synced: None,
+            sync_error: None,
         }
     }
 
@@ -177,6 +191,7 @@ impl Session {
                 self.store = Some(store);
                 self.password_verified_at = Some(now);
                 self.rearm_touch_id(now);
+                self.resume_sync();
                 Ok(())
             }
             Err(keyorra_core::Error::WrongPassword) => {
@@ -301,6 +316,7 @@ impl Session {
         let _ = store.purge_expired(now as i64);
         self.store = Some(store);
         self.password_verified_at = Some(record.verified_at);
+        self.resume_sync();
         Ok(())
     }
 
@@ -326,6 +342,8 @@ impl Session {
 
     /// Drops the store; its keys are wiped on drop.
     pub fn lock(&mut self) {
+        // Sync runs only while unlocked; its state is in the store.
+        self.synced = None;
         self.store = None;
         self.breaches.clear();
         self.watchtower_count = None;
@@ -382,10 +400,17 @@ impl Session {
                 "The new password must be different",
             ));
         }
+        if self.sync_blocks_password_change() {
+            return Err(CmdError::new(
+                ErrorKind::Invalid,
+                "Change the master password on your main device",
+            ));
+        }
         let result = self.store_mut()?.change_password(current, new);
         match result {
             Ok(()) => {
                 self.throttle.record_success();
+                self.change_sync_password(new, now)?;
                 self.password_verified_at = Some(now);
                 // Replace the Touch ID record, like 1Password does after a password change.
                 self.rearm_touch_id(now);
@@ -440,6 +465,13 @@ impl Session {
         if name.is_empty() {
             return Err(CmdError::new(ErrorKind::Invalid, "Vault name is required"));
         }
+        if let Some(created) = self.create_vault_synced(name, now) {
+            return Ok(VaultDto {
+                id: created?,
+                name: name.to_owned(),
+                item_count: 0,
+            });
+        }
         let info = self.store_mut()?.create_vault(name)?;
         Ok(VaultDto {
             id: info.id,
```

- [ ] **Step 5: Run and commit.**

`cargo test -p keyorra-session` green (200 when verified). Commit: `Session A1d-2: sync commands, only while unlocked`.

---

### Task 5: Device keys on this Mac (app)

**Files:** Modify `app/src-tauri/swift/TouchId.swift`, `app/src-tauri/src/touchid.rs`, `app/src-tauri/Cargo.toml`.

- [ ] **Step 1: Swift.**

A Secure Enclave key without user presence, usable after the first unlock, this Mac only:

```diff
diff --git a/app/src-tauri/swift/TouchId.swift b/app/src-tauri/swift/TouchId.swift
index 1430756..8483445 100644
--- a/app/src-tauri/swift/TouchId.swift
+++ b/app/src-tauri/swift/TouchId.swift
@@ -47,6 +47,27 @@ public func ks_enclave_create(
     return OK
 }
 
+/// New enclave key for sealing sync device keys: usable without a prompt once the Mac was
+/// unlocked after boot, and only on this Mac (it never leaves the Secure Enclave), so a
+/// keychain restored elsewhere cannot open what it sealed. Never prompts.
+@_cdecl("ks_device_enclave_create")
+public func ks_device_enclave_create(
+    _ blobOut: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
+    _ publicOut: UnsafeMutablePointer<UInt8>
+) -> Int32 {
+    guard SecureEnclave.isAvailable else { return UNAVAILABLE }
+    guard let access = SecAccessControlCreateWithFlags(
+        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], nil)
+    else { return FAILED }
+    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else { return FAILED }
+    let blob = key.dataRepresentation
+    guard blob.count <= blobCap else { return FAILED }
+    blob.copyBytes(to: blobOut, count: blob.count)
+    blobLen.pointee = blob.count
+    key.publicKey.x963Representation.copyBytes(to: publicOut, count: 65)
+    return OK
+}
+
 /// ECDH between the enclave key and `peer` (65-byte X9.63). Shows the Touch ID prompt with
 /// `reason`; blocks until the user answers. Writes the 32-byte shared secret.
 @_cdecl("ks_enclave_agree")
```

- [ ] **Step 2: Rust.**

`MacEnclave`, the `device-keys` keychain item (its own service; debug builds keep their own), `device_keys()` for A2, and a manual test:

```diff
diff --git a/app/src-tauri/src/touchid.rs b/app/src-tauri/src/touchid.rs
index bd6a75e..b6e41ab 100644
--- a/app/src-tauri/src/touchid.rs
+++ b/app/src-tauri/src/touchid.rs
@@ -51,6 +51,12 @@ mod ffi {
             len: *mut usize,
             public: *mut u8,
         ) -> i32;
+        pub fn ks_device_enclave_create(
+            blob: *mut u8,
+            cap: usize,
+            len: *mut usize,
+            public: *mut u8,
+        ) -> i32;
         pub fn ks_enclave_agree(
             blob: *const u8,
             len: usize,
@@ -81,6 +87,9 @@ mod ffi {
     pub unsafe fn ks_enclave_create(_: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
         4
     }
+    pub unsafe fn ks_device_enclave_create(_: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
+        4
+    }
     pub unsafe fn ks_enclave_agree(
         _: *const u8,
         _: usize,
@@ -120,6 +129,19 @@ pub fn create_key() -> Result<(Vec<u8>, [u8; 65]), Failure> {
     Ok((blob, public))
 }
 
+/// A new enclave key for sync device keys (no Touch ID, this Mac only). Never prompts.
+pub fn create_device_key() -> Result<(Vec<u8>, [u8; 65]), Failure> {
+    let mut blob = vec![0u8; MAX_BLOB];
+    let mut len = 0usize;
+    let mut public = [0u8; 65];
+    // SAFETY: the buffers are as large as we say; Swift writes at most `cap` and 65 bytes.
+    check(unsafe {
+        ffi::ks_device_enclave_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr())
+    })?;
+    blob.truncate(len);
+    Ok((blob, public))
+}
+
 /// Shows the Touch ID prompt and returns the ECDH secret. Blocks until the user answers:
 /// never call it while holding the session lock.
 pub fn agree(blob: &[u8], peer: &[u8; 65], reason: &str) -> Result<Zeroizing<[u8; 32]>, Failure> {
@@ -183,6 +205,50 @@ impl keyorra_session::touchid::Keyring for MacKeyring {
     }
 }
 
+/// Keychain service of the sealed sync device keys (debug builds keep their own).
+pub const DEVICE_KEYS_SERVICE: &str = if cfg!(debug_assertions) {
+    "app.keyorra.mac.device-keys.dev"
+} else {
+    "app.keyorra.mac.device-keys"
+};
+
+/// The login-keychain item holding the sealed device keys.
+pub struct DeviceKeysKeyring;
+
+impl keyorra_session::touchid::Keyring for DeviceKeysKeyring {
+    fn load(&self) -> Option<Vec<u8>> {
+        keychain_load(DEVICE_KEYS_SERVICE).ok()
+    }
+    fn save(&self, data: &[u8]) -> Result<(), String> {
+        keychain_save(DEVICE_KEYS_SERVICE, data).map_err(|e| format!("{e:?}"))
+    }
+    fn delete(&self) {
+        let _ = keychain_delete(DEVICE_KEYS_SERVICE);
+    }
+}
+
+/// This Mac's Secure Enclave for sync device keys (no prompts: the keys carry no Touch ID).
+pub struct MacEnclave;
+
+impl keyorra_session::sync::Enclave for MacEnclave {
+    fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String> {
+        create_device_key().map_err(|e| format!("{e:?}"))
+    }
+    fn agree(&self, blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, String> {
+        agree(blob, peer, "Keyorra sync").map_err(|e| format!("{e:?}"))
+    }
+}
+
+/// Sync device keys sealed to this Mac (plan A1d; the app hands them to sync with the
+/// transport in plan A2).
+#[allow(dead_code)]
+pub fn device_keys() -> keyorra_session::sync::EnclaveDeviceKeys {
+    keyorra_session::sync::EnclaveDeviceKeys::new(
+        std::sync::Arc::new(DeviceKeysKeyring),
+        std::sync::Arc::new(MacEnclave),
+    )
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -205,6 +271,35 @@ mod tests {
 
     /// Run by hand: `cargo test -p keyorra-app -- --ignored`. Creates a Secure Enclave key and a
     /// keychain item under a test service, then removes the item. Never shows a prompt.
+    /// Run by hand: `cargo test -p keyorra-app -- --ignored`. Seals a device key to the
+    /// Secure Enclave under a test service, reads it back without a prompt, removes it.
+    #[test]
+    #[ignore = "touches the Secure Enclave and the login keychain"]
+    fn a_device_key_sealed_to_the_enclave_comes_back() {
+        use keyorra_session::sync::{DeviceKeyStore, EnclaveDeviceKeys};
+        struct TestItem;
+        impl keyorra_session::touchid::Keyring for TestItem {
+            fn load(&self) -> Option<Vec<u8>> {
+                keychain_load("app.keyorra.mac.device-keys.test").ok()
+            }
+            fn save(&self, data: &[u8]) -> Result<(), String> {
+                keychain_save("app.keyorra.mac.device-keys.test", data)
+                    .map_err(|e| format!("{e:?}"))
+            }
+            fn delete(&self) {
+                let _ = keychain_delete("app.keyorra.mac.device-keys.test");
+            }
+        }
+        let mut keys = EnclaveDeviceKeys::new(
+            std::sync::Arc::new(TestItem),
+            std::sync::Arc::new(MacEnclave),
+        );
+        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
+        keys.store([1; 16], &key).unwrap();
+        assert_eq!(keys.load(&[1; 16]).unwrap().to_bytes(), [7; 32]);
+        keychain_delete("app.keyorra.mac.device-keys.test").unwrap();
+    }
+
     #[test]
     #[ignore = "touches the Secure Enclave and the login keychain"]
     fn enclave_key_and_keychain_round_trip() {
```

```diff
diff --git a/app/src-tauri/Cargo.toml b/app/src-tauri/Cargo.toml
index 6f4f13a..8611552 100644
--- a/app/src-tauri/Cargo.toml
+++ b/app/src-tauri/Cargo.toml
@@ -27,3 +27,6 @@ zeroize = "1"
 
 [target.'cfg(target_os = "macos")'.dependencies]
 core-foundation = "0.10"
+
+[dev-dependencies]
+ed25519-dalek = "2"
```

- [ ] **Step 3: Build and commit.**

`cargo clippy --workspace --all-targets -- -D warnings` (compiles the Swift file). Commit: `App A1d-2: sync device keys sealed to the Secure Enclave`.

---

### Task 6: Spec, and the manual Secure Enclave check

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Commit: `docs: A1d-2 device keys in the Secure Enclave, setup code, leaving and rejoining`.

- [ ] **Step 2: By hand, on a Mac with a Secure Enclave.**

`cargo test -p keyorra-app -- --ignored a_device_key_sealed_to_the_enclave_comes_back`: seals a key to the enclave under a test keychain service, reads it back without a prompt, removes the item. Not run in the scratch verification (it touches the login keychain).

---

### Task 7: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (605 passed, 4 ignored when verified); `PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

