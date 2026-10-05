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
