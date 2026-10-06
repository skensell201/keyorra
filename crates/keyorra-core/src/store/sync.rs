//! The store's side of sync (plan A1d, spec §7.1).
//!
//! **Single change path.** Every mutating method records the records it changed in
//! `sync_changes` inside its own transaction, when sync is on (`record_change`); the sync
//! layer turns them into versions and clears them. **Remote applies** write what the sync
//! engine shows without recording anything. Sync's own state is kept as sealed meta and, for
//! the device's own confirmed segments (already encrypted), in `sync_segments`.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    configure, insert_vault, parse_id, reencrypt_attachments, sealed_meta_aad, sealed_meta_key,
    upsert_item, vault_meta_aad, Store,
};
use crate::crypto::{self, Key};
use crate::model::{Item, VaultInfo, SCHEMA_VERSION};
use crate::{Error, Result};

const TRACKING_KEY: &str = "sync_tracking";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    Vault,
    Item,
    Attachment,
}

impl ChangeKind {
    fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Vault => "vault",
            ChangeKind::Item => "item",
            ChangeKind::Attachment => "attachment",
        }
    }

    fn parse(s: &str) -> Result<ChangeKind> {
        Ok(match s {
            "vault" => ChangeKind::Vault,
            "item" => ChangeKind::Item,
            "attachment" => ChangeKind::Attachment,
            other => return Err(Error::Invalid(format!("bad change kind {other}"))),
        })
    }
}

/// A record changed locally, waiting to be written by the sync engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Change {
    pub kind: ChangeKind,
    pub id: Uuid,
}

/// Records a change if sync is on. Called by every mutating method inside its transaction.
pub(super) fn record_change(conn: &Connection, kind: ChangeKind, id: Uuid) -> Result<()> {
    let on: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [TRACKING_KEY],
            |r| r.get(0),
        )
        .optional()?;
    if on.as_deref() == Some(b"1") {
        conn.execute(
            "INSERT OR IGNORE INTO sync_changes (kind, id) VALUES (?1, ?2)",
            params![kind.as_str(), id.to_string()],
        )?;
    }
    Ok(())
}

impl Store {
    /// Turns recording of local changes on or off (sync enabled or disabled).
    pub fn set_sync_tracking(&mut self, on: bool) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![TRACKING_KEY, if on { &b"1"[..] } else { &b"0"[..] }],
        )?;
        if !on {
            self.conn.execute("DELETE FROM sync_changes", [])?;
        }
        Ok(())
    }

    pub fn sync_tracking(&self) -> Result<bool> {
        let on: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [TRACKING_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(on.as_deref() == Some(b"1"))
    }

    /// The records changed locally and not yet written by the sync engine: vaults first
    /// (an item may have moved into a vault created in the same batch, review A1d C1), then
    /// items, then attachments, each in the order first recorded.
    ///
    /// Clearing what was written ([`Store::clear_changes`]) is safe without a generation
    /// counter because both happen under one `&mut Store` borrow: no change can be recorded
    /// between reading and clearing.
    pub fn pending_changes(&self) -> Result<Vec<Change>> {
        let mut stmt = self.conn.prepare(
            "SELECT kind, id FROM sync_changes
             ORDER BY CASE kind WHEN 'vault' THEN 0 WHEN 'item' THEN 1 ELSE 2 END, rowid",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id) = row?;
            out.push(Change {
                kind: ChangeKind::parse(&kind)?,
                id: parse_id(&id)?,
            });
        }
        Ok(out)
    }

    /// The sync engine wrote these.
    pub fn clear_changes(&mut self, changes: &[Change]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for c in changes {
            tx.execute(
                "DELETE FROM sync_changes WHERE kind = ?1 AND id = ?2",
                params![c.kind.as_str(), c.id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// A vault as the sync engine shows it (its key wrapped under the account key, as
    /// locally; the caller passes the key the engine chose, `Engine::vault_key`). Records
    /// nothing; writes nothing when it is the same. The key of a vault this store already
    /// has is never changed (that is key rotation, C1): a different key is refused, so items
    /// can never become unreadable through what sync shows (review A1d C3).
    pub fn apply_remote_vault(
        &mut self,
        id: Uuid,
        name: &str,
        wrapped_key: &[u8],
        deleted: bool,
    ) -> Result<()> {
        let account = self.account_key()?.clone();
        let key = crypto::unwrap_vault_key(&account, id, wrapped_key)?;
        if let Some(current) = self.vault_keys.get(&id) {
            if current.as_bytes() != key.as_bytes() {
                return Err(Error::Invalid(format!(
                    "vault {id}: sync shows another key; it is kept as it is"
                )));
            }
        }
        let info = VaultInfo {
            id,
            name: name.to_owned(),
        };
        let row: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT meta, deleted FROM vaults WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let tx = self.conn.unchecked_transaction()?;
        match row {
            Some((meta, was_deleted)) => {
                let same_name = crypto::open(&account, &meta, &vault_meta_aad(id))
                    .ok()
                    .and_then(|m| serde_json::from_slice::<VaultInfo>(&m).ok())
                    .is_some_and(|i| i.name == name);
                if same_name && (was_deleted != 0) == deleted {
                    return Ok(());
                }
                let meta = crypto::seal(&account, &serde_json::to_vec(&info)?, &vault_meta_aad(id));
                tx.execute(
                    "UPDATE vaults SET meta = ?2, deleted = ?3, revision = revision + 1
                     WHERE id = ?1",
                    params![id.to_string(), meta, deleted as i64],
                )?;
            }
            None => {
                insert_vault(&tx, &account, &info, &key)?;
                tx.execute(
                    "UPDATE vaults SET deleted = ?2 WHERE id = ?1",
                    params![id.to_string(), deleted as i64],
                )?;
            }
        }
        tx.commit()?;
        self.vault_keys.insert(id, key);
        Ok(())
    }

    /// An item as the sync engine shows it, live or in Recently Deleted (`deleted_at`). Its
    /// attachment list is taken as is. Records nothing; rewrites nothing that is the same.
    pub fn apply_remote_item(&mut self, item: &Item, deleted_at: Option<i64>) -> Result<()> {
        let key = self.vault_key(item.vault_id)?.clone();
        let current: Option<(String, Vec<u8>, i64, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT vault_id, data, schema, deleted_at FROM items WHERE id = ?1",
                [item.id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((vault, data, schema, was_deleted)) = &current {
            let same = !data.is_empty()
                && was_deleted == &deleted_at
                && parse_id(vault).ok() == Some(item.vault_id)
                && u32::try_from(*schema)
                    .ok()
                    .and_then(|s| self.decrypt_item(item.id, item.vault_id, s, data).ok())
                    .as_ref()
                    == Some(item);
            if same {
                return Ok(());
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        // Moved to another vault elsewhere: its attachments follow under the new key
        // (review A1d C2).
        if let Some(old) = current
            .as_ref()
            .and_then(|(vault, _, _, _)| parse_id(vault).ok())
            .filter(|old| *old != item.vault_id)
        {
            let old_key = self.vault_key(old)?.clone();
            reencrypt_attachments(&tx, item.id, (old, &old_key), (item.vault_id, &key))?;
        }
        upsert_item(&tx, &key, item)?;
        tx.execute(
            "UPDATE items SET deleted_at = ?2 WHERE id = ?1",
            params![item.id.to_string(), deleted_at],
        )?;
        // A live item keeps its vault: one deleted here comes back (review A1d I4).
        if deleted_at.is_none() {
            tx.execute(
                "UPDATE vaults SET deleted = 0, revision = revision + 1
                 WHERE id = ?1 AND deleted = 1",
                [item.vault_id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// An attachment row as the sync layer needs it, without decrypting: its item and
    /// whether it is live (`None` when there is no row).
    pub fn attachment_state(&self, id: Uuid) -> Result<Option<AttachmentState>> {
        self.account_key()?;
        let row: Option<(String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT item_id, deleted, length(data) FROM attachments WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(match row {
            None => None,
            Some((item_id, deleted, len)) => Some(AttachmentState {
                item_id: parse_id(&item_id)?,
                live: deleted == 0 && len > 0,
            }),
        })
    }

    /// The content of a live attachment row, whatever state its item is in.
    pub fn attachment_content(&self, id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
        self.account_key()?;
        let row: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT a.data, a.item_id, i.vault_id FROM attachments a
                 JOIN items i ON i.id = a.item_id
                 WHERE a.id = ?1 AND a.deleted = 0 AND length(a.data) > 0",
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

    /// Ids of the live attachment rows.
    pub fn attachment_ids(&self) -> Result<Vec<Uuid>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM attachments WHERE deleted = 0 AND length(data) > 0 ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| parse_id(&r?)).collect()
    }

    /// An attachment's content from sync, for an item the store has. Records nothing;
    /// writes nothing when the same content is there.
    pub fn apply_remote_attachment(&mut self, id: Uuid, item_id: Uuid, bytes: &[u8]) -> Result<()> {
        if let Some(state) = self.attachment_state(id)? {
            // Attachments never change content: a live row of that item is the same.
            if state.item_id == item_id && state.live {
                return Ok(());
            }
        }
        let vault_id: String = self
            .conn
            .query_row(
                "SELECT vault_id FROM items WHERE id = ?1",
                [item_id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("item {item_id}")))?;
        let vault_id = parse_id(&vault_id)?;
        let data = crypto::seal(
            self.vault_key(vault_id)?,
            bytes,
            &crypto::attachment_aad(vault_id, item_id, id),
        );
        self.conn.execute(
            "INSERT INTO attachments (id, item_id, data, schema) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET item_id = excluded.item_id, data = excluded.data,
                 deleted = 0, revision = attachments.revision + 1",
            params![id.to_string(), item_id.to_string(), data, SCHEMA_VERSION],
        )?;
        Ok(())
    }

    /// An attachment sync shows as removed. Records nothing.
    pub fn apply_remote_attachment_removed(&mut self, id: Uuid) -> Result<()> {
        self.account_key()?;
        self.conn.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE id = ?1 AND deleted = 0",
            [id.to_string()],
        )?;
        Ok(())
    }

    /// An item the sync engine shows as purged: its data goes, the row stays a tombstone.
    pub fn apply_remote_purge(&mut self, id: Uuid) -> Result<()> {
        self.account_key()?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE item_id = ?1 AND deleted = 0",
            [id.to_string()],
        )?;
        tx.execute(
            "UPDATE items SET data = X'', deleted_at = COALESCE(deleted_at, 0),
                 revision = revision + 1
             WHERE id = ?1 AND length(data) > 0",
            [id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Every vault row with its key as stored (wrapped under the account key) and whether it
    /// is deleted: what enabling sync writes as the first versions.
    pub fn vault_rows(&self) -> Result<Vec<(VaultInfo, Key, bool)>> {
        let account = self.account_key()?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta, deleted FROM vaults ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, meta, deleted) = row?;
            let id = parse_id(&id)?;
            let plain = crypto::open(account, &meta, &vault_meta_aad(id))?;
            let info: VaultInfo = serde_json::from_slice(&plain)?;
            out.push((info, self.vault_key(id)?.clone(), deleted != 0));
        }
        Ok(out)
    }

    /// An item with its deletion time, if it is live or in Recently Deleted (not purged).
    pub fn item_state(&self, id: Uuid) -> Result<Option<(Item, Option<i64>)>> {
        let row: Option<(String, Vec<u8>, i64, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT vault_id, data, schema, deleted_at FROM items WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((vault, data, schema, deleted_at)) = row else {
            return Ok(None);
        };
        if data.is_empty() {
            return Ok(None);
        }
        let schema = u32::try_from(schema).map_err(|_| Error::Invalid("bad item schema".into()))?;
        let item = self.decrypt_item(id, parse_id(&vault)?, schema, &data)?;
        Ok(Some((item, deleted_at)))
    }

    /// Whether the item row exists as a purged tombstone.
    pub fn item_purged(&self, id: Uuid) -> Result<bool> {
        let row: Option<i64> = self
            .conn
            .query_row(
                "SELECT length(data) FROM items WHERE id = ?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row == Some(0))
    }

    pub fn own_segments(&self) -> Result<BTreeMap<u64, Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT first_seq, data FROM sync_segments ORDER BY first_seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (seq, data) = row?;
            out.insert(seq as u64, data);
        }
        Ok(out)
    }

    /// Replaces the kept own segments (they are already encrypted and signed).
    pub fn set_own_segments(&mut self, segments: &BTreeMap<u64, Vec<u8>>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sync_segments", [])?;
        for (seq, data) in segments {
            tx.execute(
                "INSERT INTO sync_segments (first_seq, data) VALUES (?1, ?2)",
                params![*seq as i64, data],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether `password` is the master password (enabling sync asks for it again).
    pub fn check_password(&self, password: &str) -> Result<()> {
        crypto::unlock(&self.header, password).map(drop)
    }

    pub fn delete_sealed_meta(&mut self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", [sealed_meta_key(name)])?;
        Ok(())
    }

    /// Records changes by hand (rejoining an account: what changed while sync was off).
    pub fn record_changes(&mut self, changes: &[Change]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for c in changes {
            tx.execute(
                "INSERT OR IGNORE INTO sync_changes (kind, id) VALUES (?1, ?2)",
                params![c.kind.as_str(), c.id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// A second connection to the same database that writes sealed meta (the sync engine's
    /// outbox is saved through it before every append, while the session holds the store).
    pub fn meta_writer(&self) -> Result<MetaWriter> {
        let path = self
            .conn
            .path()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| Error::Invalid("the store has no file".into()))?;
        let conn = Connection::open(path)?;
        configure(&conn)?;
        Ok(MetaWriter {
            conn,
            key: self.account_key()?.clone(),
        })
    }

    /// The account key itself, for the sync engine (which uses it as the account key `AK`).
    pub fn account_key_copy(&self) -> Result<Key> {
        Ok(self.account_key()?.clone())
    }
}

/// Writes sealed meta of one store through its own connection ([`Store::meta_writer`]).
pub struct MetaWriter {
    conn: Connection,
    key: Key,
}

impl MetaWriter {
    pub fn set_sealed_meta(&self, name: &str, value: &[u8]) -> Result<()> {
        let data = crypto::seal(&self.key, value, &sealed_meta_aad(name));
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![sealed_meta_key(name), data],
        )?;
        Ok(())
    }
}

/// What [`Store::attachment_state`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentState {
    pub item_id: Uuid,
    /// `false`: removed.
    pub live: bool,
}
