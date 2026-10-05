use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, Header, KdfParams, Key};
use crate::import::{ImportPlan, ImportReport};
use crate::model::{AttachmentRef, Item, VaultInfo, SCHEMA_VERSION};
use crate::{Error, Result};

#[cfg(test)]
mod tests;

const DB_VERSION: i64 = MIGRATIONS.len() as i64;
// Format label from the Lockbox days; kept so existing vaults and pairings stay readable.
const CHECK_AAD: &[u8] = b"lockbox/check/v1";
const VAULT_META_AAD: &[u8] = b"lockbox/vault-meta/v1";
const SEALED_META_AAD: &[u8] = b"lockbox/meta/v1\0";

/// Deleted items stay restorable for 30 days, then their data is purged.
pub const DELETED_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

// Boxing `Item` would change the public shape the plan's tests (and Task 13) rely on.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemEntry {
    Ok(Item),
    /// The row exists but does not decrypt; the rest of the vault still loads.
    Damaged {
        id: Uuid,
        vault_id: Uuid,
    },
}

const SCHEMA_V1: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    wrapped_key BLOB NOT NULL,
    meta BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    data BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    schema INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    data BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0,
    schema INTEGER NOT NULL DEFAULT 1
);
";

/// `MIGRATIONS[i]` upgrades database version `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[SCHEMA_V1];

/// The encrypted vault database. Locked until `unlock`/`unlock_with_key`.
pub struct Store {
    conn: Connection,
    header: Header,
    account: Option<Key>,
    vault_keys: HashMap<Uuid, Key>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("unlocked", &self.is_unlocked())
            .finish()
    }
}

impl Store {
    /// Creates a new database at `path` and returns it unlocked.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Store> {
        // Argon2 can fail on bad params; do it before touching the filesystem.
        let (header, account) = crypto::create_header(password, kdf)?;
        claim_path(path)?;
        match Self::init_file(path, &header, &account) {
            Ok(conn) => Ok(Store {
                conn,
                header,
                account: Some(account),
                vault_keys: HashMap::new(),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(path);
                let _ = std::fs::remove_file(sibling(path, "-journal"));
                Err(e)
            }
        }
    }

    fn init_file(path: &Path, header: &Header, account: &Key) -> Result<Connection> {
        let conn = Connection::open(path)?;
        configure(&conn)?;
        let tx = conn.unchecked_transaction()?;
        apply_migrations(&tx, 0)?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('header', ?1), ('check', ?2)",
            params![
                serde_json::to_vec(header)?,
                crypto::seal(account, b"lockbox", CHECK_AAD)
            ],
        )?;
        tx.commit()?;
        Ok(conn)
    }

    /// Opens an existing database, locked.
    pub fn open(path: &Path) -> Result<Store> {
        if !path.exists() {
            return Err(Error::NotFound(path.display().to_string()));
        }
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
        Ok(Store {
            conn,
            header,
            account: None,
            vault_keys: HashMap::new(),
        })
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let account = crypto::unlock(&self.header, password)?;
        self.load_keys(account)
    }

    /// Unlocks with an account key kept elsewhere (macOS Keychain behind Touch ID).
    pub fn unlock_with_key(&mut self, account: Key) -> Result<()> {
        let check: Vec<u8> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'check'", [], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| Error::Invalid("missing check value".into()))?;
        crypto::open(&account, &check, CHECK_AAD).map_err(|_| Error::WrongPassword)?;
        self.load_keys(account)
    }

    pub fn lock(&mut self) {
        self.account = None;
        self.vault_keys.clear();
    }

    pub fn is_unlocked(&self) -> bool {
        self.account.is_some()
    }

    pub fn account_key(&self) -> Result<&Key> {
        self.account.as_ref().ok_or(Error::Locked)
    }

    /// A small secret blob stored next to the vault (e.g. browser pairings), sealed with the
    /// account key and bound to its name.
    pub fn sealed_meta(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let account = self.account_key()?;
        let raw: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [sealed_meta_key(name)],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|data| crypto::open(account, &data, &sealed_meta_aad(name)))
            .transpose()
    }

    pub fn set_sealed_meta(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let account = self.account_key()?;
        let data = crypto::seal(account, value, &sealed_meta_aad(name));
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![sealed_meta_key(name), data],
        )?;
        Ok(())
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<()> {
        let header = crypto::change_password(&self.header, old, new, self.header.kdf)?;
        self.conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'header'",
            params![serde_json::to_vec(&header)?],
        )?;
        self.header = header;
        Ok(())
    }

    pub fn create_vault(&mut self, name: &str) -> Result<VaultInfo> {
        let account = self.account.as_ref().ok_or(Error::Locked)?;
        let info = VaultInfo {
            id: Uuid::new_v4(),
            name: name.to_owned(),
        };
        let key = Key::random();
        insert_vault(&self.conn, account, &info, &key)?;
        self.vault_keys.insert(info.id, key);
        Ok(info)
    }

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

    /// Writes a previewed import: one new vault per imported vault, all in one transaction.
    pub fn apply_import(&mut self, plan: &ImportPlan) -> Result<ImportReport> {
        let account = self.account.as_ref().ok_or(Error::Locked)?;
        let tx = self.conn.unchecked_transaction()?;
        let mut report = ImportReport::default();
        let mut new_keys = Vec::new();
        for vault in plan.vaults.iter().filter(|v| !v.items.is_empty()) {
            let info = VaultInfo {
                id: Uuid::new_v4(),
                name: vault.name.clone(),
            };
            let key = Key::random();
            insert_vault(&tx, account, &info, &key)?;
            report.vaults += 1;
            for imported in &vault.items {
                let mut item = imported.item.clone();
                item.id = Uuid::new_v4();
                item.vault_id = info.id;
                item.attachments.clear();
                for (name, bytes) in &imported.attachments {
                    let att = AttachmentRef {
                        id: Uuid::new_v4(),
                        name: name.clone(),
                        size: bytes.len() as u64,
                    };
                    insert_attachment(&tx, &key, &item, &att, bytes)?;
                    item.attachments.push(att);
                    report.attachments += 1;
                }
                upsert_item(&tx, &key, &item)?;
                report.items += 1;
            }
            new_keys.push((info.id, key));
        }
        tx.commit()?;
        self.vault_keys.extend(new_keys);
        Ok(report)
    }

    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let account = self.account_key()?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta FROM vaults WHERE deleted = 0 ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, meta) = row?;
            let id = parse_id(&id)?;
            let plain = crypto::open(account, &meta, &vault_meta_aad(id))?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok(out)
    }

    /// Inserts or updates an item; a later save of a deleted item undeletes it.
    ///
    /// The stored attachment list is authoritative: the caller's `attachments` are ignored
    /// (use `add_attachment`/`remove_attachment`). Moving an item to another vault
    /// re-encrypts its attachments with the new vault key. An existing row that does not
    /// decrypt is never overwritten.
    pub fn save_item(&mut self, item: &Item) -> Result<()> {
        let new_key = self.vault_key(item.vault_id)?;
        let tx = self.conn.unchecked_transaction()?;
        let existing: Option<(String, Vec<u8>, i64)> = tx
            .query_row(
                "SELECT vault_id, data, schema FROM items WHERE id = ?1",
                [item.id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let mut item = item.clone();
        match existing {
            Some((old_vault, data, schema)) => {
                if data.is_empty() {
                    // Purged tombstone: nothing left to save over.
                    return Err(Error::NotFound(format!("item {}", item.id)));
                }
                let old_vault = parse_id(&old_vault)?;
                let stored = self.decrypt_item(item.id, old_vault, schema_u32(schema)?, &data)?;
                item.attachments = stored.attachments;
                if old_vault != item.vault_id {
                    let old_key = self.vault_key(old_vault)?;
                    reencrypt_attachments(
                        &tx,
                        item.id,
                        (old_vault, old_key),
                        (item.vault_id, new_key),
                    )?;
                }
            }
            None => item.attachments.clear(),
        }
        upsert_item(&tx, new_key, &item)?;
        tx.commit()?;
        Ok(())
    }

    pub fn add_attachment(
        &mut self,
        item_id: Uuid,
        name: &str,
        bytes: &[u8],
        now: i64,
    ) -> Result<AttachmentRef> {
        let mut item = self.get_item(item_id)?;
        let key = self.vault_key(item.vault_id)?;
        let att = AttachmentRef {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            size: bytes.len() as u64,
        };
        let tx = self.conn.unchecked_transaction()?;
        insert_attachment(&tx, key, &item, &att, bytes)?;
        item.attachments.push(att.clone());
        item.updated_at = now;
        upsert_item(&tx, key, &item)?;
        tx.commit()?;
        Ok(att)
    }

    /// Tombstones an attachment and drops its reference from the item.
    /// Removal is immediate and permanent (the UI must confirm).
    pub fn remove_attachment(
        &mut self,
        item_id: Uuid,
        attachment_id: Uuid,
        now: i64,
    ) -> Result<()> {
        let mut item = self.get_item(item_id)?;
        let key = self.vault_key(item.vault_id)?;
        let pos = item
            .attachments
            .iter()
            .position(|a| a.id == attachment_id)
            .ok_or_else(|| Error::NotFound(format!("attachment {attachment_id}")))?;
        item.attachments.remove(pos);
        item.updated_at = now;
        let tx = self.conn.unchecked_transaction()?;
        // A missing or already-deleted row (n == 0) must not keep a dangling ref alive.
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE id = ?1 AND item_id = ?2 AND deleted = 0",
            params![attachment_id.to_string(), item_id.to_string()],
        )?;
        upsert_item(&tx, key, &item)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_attachment(&self, id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
        self.account_key()?;
        let row: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT a.data, a.item_id, i.vault_id FROM attachments a
                 JOIN items i ON i.id = a.item_id
                 WHERE a.id = ?1 AND a.deleted = 0 AND i.deleted_at IS NULL",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (data, item_id, vault_id) =
            row.ok_or_else(|| Error::NotFound(format!("attachment {id}")))?;
        let (item_id, vault_id) = (parse_id(&item_id)?, parse_id(&vault_id)?);
        crypto::open(
            self.vault_key(vault_id)?,
            &data,
            &crypto::attachment_aad(vault_id, item_id, id),
        )
    }

    pub fn get_item(&self, id: Uuid) -> Result<Item> {
        let row: Option<(String, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT vault_id, data, schema FROM items WHERE id = ?1 AND deleted_at IS NULL",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (vault_id, data, schema) = row.ok_or_else(|| Error::NotFound(format!("item {id}")))?;
        self.decrypt_item(id, parse_id(&vault_id)?, schema_u32(schema)?, &data)
    }

    /// Live items, in insertion order, optionally limited to one vault.
    pub fn list_items(&self, vault: Option<Uuid>) -> Result<Vec<ItemEntry>> {
        self.load_items(false, vault)
    }

    /// Items in "Recently Deleted" (deleted, not yet purged).
    pub fn deleted_items(&self) -> Result<Vec<ItemEntry>> {
        self.load_items(true, None)
    }

    pub fn delete_item(&mut self, id: Uuid, now: i64) -> Result<()> {
        self.account_key()?;
        let n = self.conn.execute(
            "UPDATE items SET deleted_at = ?2, revision = revision + 1
             WHERE id = ?1 AND deleted_at IS NULL",
            params![id.to_string(), now],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("item {id}")));
        }
        Ok(())
    }

    pub fn restore_item(&mut self, id: Uuid) -> Result<()> {
        self.account_key()?;
        let n = self.conn.execute(
            "UPDATE items SET deleted_at = NULL, revision = revision + 1
             WHERE id = ?1 AND deleted_at IS NOT NULL AND length(data) > 0",
            [id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("deleted item {id}")));
        }
        Ok(())
    }

    /// Wipes data of items deleted at least 30 days ago; rows stay as tombstones.
    pub fn purge_expired(&mut self, now: i64) -> Result<usize> {
        let cutoff = now - DELETED_RETENTION_SECS;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE item_id IN (SELECT id FROM items
                               WHERE deleted_at IS NOT NULL AND deleted_at <= ?1 AND length(data) > 0)",
            [cutoff],
        )?;
        let n = tx.execute(
            "UPDATE items SET data = X'', revision = revision + 1
             WHERE deleted_at IS NOT NULL AND deleted_at <= ?1 AND length(data) > 0",
            [cutoff],
        )?;
        tx.commit()?;
        Ok(n)
    }

    fn load_items(&self, deleted: bool, vault: Option<Uuid>) -> Result<Vec<ItemEntry>> {
        self.account_key()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, vault_id, data, schema FROM items
             WHERE ((?1 = 0 AND deleted_at IS NULL)
                 OR (?1 = 1 AND deleted_at IS NOT NULL AND length(data) > 0))
               AND (?2 IS NULL OR vault_id = ?2)
             ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![deleted as i64, vault.map(|v| v.to_string())], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, vault_id, data, schema) = row?;
            let (id, vault_id) = (parse_id(&id)?, parse_id(&vault_id)?);
            let decrypted =
                schema_u32(schema).and_then(|s| self.decrypt_item(id, vault_id, s, &data));
            out.push(match decrypted {
                Ok(item) => ItemEntry::Ok(item),
                Err(_) => ItemEntry::Damaged { id, vault_id },
            });
        }
        Ok(out)
    }

    fn decrypt_item(&self, id: Uuid, vault_id: Uuid, schema: u32, data: &[u8]) -> Result<Item> {
        let key = self.vault_key(vault_id)?;
        let plain = crypto::open(key, data, &crypto::item_aad(vault_id, id, schema))?;
        Ok(serde_json::from_slice(&plain)?)
    }

    fn vault_key(&self, vault_id: Uuid) -> Result<&Key> {
        if self.account.is_none() {
            return Err(Error::Locked);
        }
        self.vault_keys
            .get(&vault_id)
            .ok_or_else(|| Error::NotFound(format!("vault {vault_id}")))
    }

    fn load_keys(&mut self, account: Key) -> Result<()> {
        let mut keys = HashMap::new();
        {
            let mut stmt = self.conn.prepare("SELECT id, wrapped_key FROM vaults")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (id, wrapped) = row?;
                let id = parse_id(&id)?;
                keys.insert(id, crypto::unwrap_vault_key(&account, id, &wrapped)?);
            }
        }
        self.vault_keys = keys;
        self.account = Some(account);
        Ok(())
    }
}

fn insert_vault(conn: &Connection, account: &Key, info: &VaultInfo, key: &Key) -> Result<()> {
    let meta = crypto::seal(
        account,
        &serde_json::to_vec(info)?,
        &vault_meta_aad(info.id),
    );
    conn.execute(
        "INSERT INTO vaults (id, wrapped_key, meta) VALUES (?1, ?2, ?3)",
        params![
            info.id.to_string(),
            crypto::wrap_vault_key(account, info.id, key),
            meta
        ],
    )?;
    Ok(())
}

fn schema_u32(schema: i64) -> Result<u32> {
    u32::try_from(schema).map_err(|_| Error::Invalid(format!("bad item schema {schema}")))
}

/// Does not re-encrypt attachments if the vault changes; callers that may change an item's
/// vault must go through `Store::save_item` (Task 13 import always uses fresh ids).
fn upsert_item(conn: &Connection, key: &Key, item: &Item) -> Result<()> {
    let plain = Zeroizing::new(serde_json::to_vec(item)?);
    let data = crypto::seal(
        key,
        &plain,
        &crypto::item_aad(item.vault_id, item.id, SCHEMA_VERSION),
    );
    conn.execute(
        "INSERT INTO items (id, vault_id, data, updated_at, schema) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET
             vault_id = excluded.vault_id, data = excluded.data,
             updated_at = excluded.updated_at, schema = excluded.schema,
             revision = items.revision + 1, deleted_at = NULL",
        params![
            item.id.to_string(),
            item.vault_id.to_string(),
            data,
            item.updated_at,
            SCHEMA_VERSION
        ],
    )?;
    Ok(())
}

/// Does not re-encrypt attachments on a vault change; see `upsert_item`.
fn insert_attachment(
    conn: &Connection,
    key: &Key,
    item: &Item,
    att: &AttachmentRef,
    bytes: &[u8],
) -> Result<()> {
    let data = crypto::seal(
        key,
        bytes,
        &crypto::attachment_aad(item.vault_id, item.id, att.id),
    );
    conn.execute(
        "INSERT INTO attachments (id, item_id, data, schema) VALUES (?1, ?2, ?3, ?4)",
        params![
            att.id.to_string(),
            item.id.to_string(),
            data,
            SCHEMA_VERSION
        ],
    )?;
    Ok(())
}

fn reencrypt_attachments(
    conn: &Connection,
    item_id: Uuid,
    (old_vault, old_key): (Uuid, &Key),
    (new_vault, new_key): (Uuid, &Key),
) -> Result<()> {
    let rows: Vec<(String, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT id, data FROM attachments WHERE item_id = ?1 AND deleted = 0")?;
        let mapped = stmt.query_map([item_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        mapped.collect::<rusqlite::Result<_>>()?
    };
    for (id, data) in rows {
        let att_id = parse_id(&id)?;
        let plain = crypto::open(
            old_key,
            &data,
            &crypto::attachment_aad(old_vault, item_id, att_id),
        )?;
        let sealed = crypto::seal(
            new_key,
            &plain,
            &crypto::attachment_aad(new_vault, item_id, att_id),
        );
        conn.execute(
            "UPDATE attachments SET data = ?2, revision = revision + 1 WHERE id = ?1",
            params![id, sealed],
        )?;
    }
    Ok(())
}

fn vault_meta_aad(id: Uuid) -> Vec<u8> {
    let mut aad = VAULT_META_AAD.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn parse_id(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| Error::Invalid(format!("bad id {s}: {e}")))
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    Ok(())
}

/// Runs `MIGRATIONS[from..]` and bumps `user_version`, atomically.
fn apply_migrations(tx: &Connection, from: i64) -> Result<()> {
    for sql in &MIGRATIONS[from as usize..] {
        tx.execute_batch(sql)?;
    }
    tx.pragma_update(None, "user_version", DB_VERSION)?;
    Ok(())
}

/// Brings an existing Keepsake database up to `DB_VERSION`; never initialises one.
fn upgrade(conn: &Connection, path: &Path) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version <= 0 {
        return Err(Error::NotADatabase("no keepsake schema".into()));
    }
    if version > DB_VERSION {
        return Err(Error::Invalid(format!(
            "database version {version} is newer than this app supports ({DB_VERSION})"
        )));
    }
    if version < DB_VERSION {
        backup(path, version)?;
        let tx = conn.unchecked_transaction()?;
        apply_migrations(&tx, version)?;
        tx.commit()?;
    }
    Ok(())
}

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

/// Copies the database next to itself before a schema migration.
pub fn backup(path: &Path, from_version: i64) -> Result<PathBuf> {
    let copy = sibling(path, &format!(".bak-v{from_version}"));
    std::fs::copy(path, &copy)?;
    Ok(copy)
}

/// `path` with `suffix` appended to the full file name (how SQLite names `-journal`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

/// Atomically creates an empty, owner-only file at `path`; SQLite treats it as a new database.
fn claim_path(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(Error::Invalid(format!("{} already exists", path.display())))
        }
        Err(e) => Err(e.into()),
    }
}

fn sealed_meta_key(name: &str) -> String {
    format!("sealed:{name}")
}

fn sealed_meta_aad(name: &str) -> Vec<u8> {
    let mut aad = SEALED_META_AAD.to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad
}
