use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::{self, Header, KdfParams, Key};
use crate::model::VaultInfo;
use crate::{Error, Result};

#[cfg(test)]
mod tests;

const DB_VERSION: i64 = 1;
const CHECK_AAD: &[u8] = b"lockbox/check/v1";
const VAULT_META_AAD: &[u8] = b"lockbox/vault-meta/v1";

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
    deleted_at INTEGER
);
CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    data BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0
);
";

/// The encrypted vault database. Locked until `unlock`/`unlock_with_key`.
pub struct Store {
    conn: Connection,
    header: Header,
    account: Option<Key>,
    vault_keys: HashMap<Uuid, Key>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("unlocked", &self.is_unlocked()).finish()
    }
}

impl Store {
    /// Creates a new database at `path` and returns it unlocked.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Store> {
        if path.exists() {
            return Err(Error::Invalid(format!("{} already exists", path.display())));
        }
        let conn = Connection::open(path)?;
        migrate(&conn, path)?;
        let (header, account) = crypto::create_header(password, kdf)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('header', ?1), ('check', ?2)",
            params![serde_json::to_vec(&header)?, crypto::seal(&account, b"lockbox", CHECK_AAD)],
        )?;
        Ok(Store { conn, header, account: Some(account), vault_keys: HashMap::new() })
    }

    /// Opens an existing database, locked.
    pub fn open(path: &Path) -> Result<Store> {
        if !path.exists() {
            return Err(Error::NotFound(path.display().to_string()));
        }
        let conn = Connection::open(path)?;
        migrate(&conn, path)?;
        let raw: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key = 'header'", [], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::Invalid("missing header".into()))?;
        let header = serde_json::from_slice(&raw)?;
        Ok(Store { conn, header, account: None, vault_keys: HashMap::new() })
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let account = crypto::unlock(&self.header, password)?;
        self.load_keys(account)
    }

    /// Unlocks with an account key kept elsewhere (macOS Keychain behind Touch ID).
    pub fn unlock_with_key(&mut self, account: Key) -> Result<()> {
        let check: Vec<u8> =
            self.conn.query_row("SELECT value FROM meta WHERE key = 'check'", [], |r| r.get(0))?;
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
        let info = VaultInfo { id: Uuid::new_v4(), name: name.to_owned() };
        let key = Key::random();
        insert_vault(&self.conn, account, &info, &key)?;
        self.vault_keys.insert(info.id, key);
        Ok(info)
    }

    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let account = self.account_key()?;
        let mut stmt =
            self.conn.prepare("SELECT id, meta FROM vaults WHERE deleted = 0 ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, meta) = row?;
            let id = parse_id(&id)?;
            let plain = crypto::open(account, &meta, &vault_meta_aad(id))?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok(out)
    }

    fn load_keys(&mut self, account: Key) -> Result<()> {
        let mut keys = HashMap::new();
        {
            let mut stmt = self.conn.prepare("SELECT id, wrapped_key FROM vaults")?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
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
    let meta = crypto::seal(account, &serde_json::to_vec(info)?, &vault_meta_aad(info.id));
    conn.execute(
        "INSERT INTO vaults (id, wrapped_key, meta) VALUES (?1, ?2, ?3)",
        params![info.id.to_string(), crypto::wrap_vault_key(account, info.id, key), meta],
    )?;
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

fn migrate(conn: &Connection, path: &Path) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == DB_VERSION {
        return Ok(());
    }
    if version > DB_VERSION {
        return Err(Error::Invalid(format!(
            "database version {version} is newer than this app supports ({DB_VERSION})"
        )));
    }
    if version > 0 {
        backup(path, version)?;
    }
    conn.execute_batch(SCHEMA_V1)?;
    conn.pragma_update(None, "user_version", DB_VERSION)?;
    Ok(())
}

/// Copies the database next to itself before a schema migration.
pub fn backup(path: &Path, from_version: i64) -> Result<PathBuf> {
    let copy = path.with_extension(format!("db.bak-v{from_version}"));
    std::fs::copy(path, &copy)?;
    Ok(copy)
}
