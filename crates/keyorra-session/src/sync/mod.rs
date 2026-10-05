//! Sync for a vault store (plan A1d): the bridge between the local [`Store`] and the sync
//! [`Engine`].
//!
//! - **Enabling** turns a store into the main device of a new synced account: Secret Key,
//!   account header, every vault and item written as first versions.
//! - **Joining** creates a store on a new device from the account header in the store
//!   (password + Secret Key, optionally pinned to the main device by a setup code); the
//!   device then self-joins and waits for the main device's approval.
//! - **Resuming** continues after a restart (the engine reads the streams again).
//! - **A round** writes the local changes the store recorded, syncs, shows what sync shows in
//!   the store, and persists the engine's state.
//!
//! The account key `AK` is the store's own account key: vault keys are wrapped the same way
//! locally and in sync. The engine's state that cannot be read again from the store's streams
//! is kept as sealed meta of the store (`sync:config`, `sync:outbox`, `sync:memo`) and in its
//! `sync_segments` table. Attachment contents travel with the folder transport (plan A2).

mod keys;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{KdfParams, Key};
use keyorra_core::model::Item;
use keyorra_core::store::{Change, ChangeKind, MetaWriter, Store};
use keyorra_sync::account::{unlock_join_with, RootPin};
use keyorra_sync::engine::{Engine, EngineMemo, Event, OutboxState, OutboxStore, Resumed};
use keyorra_sync::header::{wrap_account_key, Header};
use keyorra_sync::keys::derive_sync_keys;
use keyorra_sync::present::ItemState;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::{Fetched, Transport};
use keyorra_sync::{AccountId, DeviceId, Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use keys::{DeviceKeyStore, MemoryDeviceKeys};

const CONFIG: &str = "sync:config";
const OUTBOX: &str = "sync:outbox";
const MEMO: &str = "sync:memo";

/// What this device knows about its synced account (sealed meta `sync:config`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SyncConfig {
    account_id: AccountId,
    device: DeviceId,
    device_name: String,
    root: DeviceId,
    root_key: [u8; 32],
    secret_key: [u8; 16],
    secret_key_id: String,
}

/// What the user writes down when sync is enabled (spec §7.6). The location is the
/// transport's (plan A2/A3 add it).
pub struct EmergencyKit {
    pub account_id: String,
    pub secret_key: Zeroizing<String>,
}

/// Saves the engine's outbox through a second connection, before every append.
struct StoreOutbox(MetaWriter);

impl OutboxStore for StoreOutbox {
    fn save(&mut self, state: &OutboxState) -> Result<()> {
        self.0
            .set_sealed_meta(OUTBOX, &state.to_bytes())
            .map_err(Error::from)
    }
}

/// Sync of one store over one transport.
pub struct Synced<T: Transport> {
    engine: Engine<OsRng>,
    transport: T,
    config: SyncConfig,
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

fn new_signer() -> SigningKey {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut secret[..]);
    SigningKey::from_bytes(&secret)
}

fn save_config(store: &mut Store, config: &SyncConfig) -> Result<()> {
    let bytes = serde_json::to_vec(config).map_err(|e| Error::Malformed(e.to_string()))?;
    store.set_sealed_meta(CONFIG, &bytes)?;
    Ok(())
}

fn load_config(store: &Store) -> Result<SyncConfig> {
    let raw = store
        .sealed_meta(CONFIG)?
        .ok_or_else(|| Error::NotFound("sync is not set up on this vault".into()))?;
    serde_json::from_slice(&raw).map_err(|e| Error::Malformed(e.to_string()))
}

fn item_json(item: &Item) -> Result<Vec<u8>> {
    serde_json::to_vec(item).map_err(|e| Error::Malformed(e.to_string()))
}

/// Whether sync is set up on this store.
pub fn is_enabled(store: &Store) -> Result<bool> {
    Ok(store.sync_tracking()? && store.sealed_meta(CONFIG)?.is_some())
}

/// Turns `store` into the main device of a new synced account, writing everything it holds
/// as first versions. The synced header uses `kdf` (the remote floor applies when joining).
#[allow(clippy::too_many_arguments)]
pub fn enable<T: Transport>(
    store: &mut Store,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<(Synced<T>, EmergencyKit)> {
    if is_enabled(store)? {
        return Err(Error::Refused("sync is already on".into()));
    }
    let account_id = random_id();
    let device = random_id();
    let signer = new_signer();
    keys.store(device, &signer);
    let (secret_key, secret_key_id) = SecretKey::generate(&mut OsRng);
    let account_key = store.account_key_copy()?;
    let root_key = signer.verifying_key();
    let mut engine = Engine::create_account(
        device,
        signer,
        device_name,
        account_id,
        account_key.clone(),
        OsRng,
        wall_ms,
    );
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let sync_keys = derive_sync_keys(password, &salt, kdf, &secret_key, &account_id)?;
    let mut header = Header {
        account_id,
        epoch: 1,
        generation: 1,
        root_device: device,
        root_key: root_key.to_bytes(),
        kdf,
        salt,
        secret_key_id: secret_key_id.clone(),
        wrapped_account_key: Vec::new(),
    };
    header.wrapped_account_key =
        wrap_account_key(&sync_keys.kek, &account_key, &header, &mut OsRng);
    engine.publish_header(header, wall_ms)?;
    // Everything the store holds: vaults with their ids and keys, then items.
    for (info, key, deleted) in store.vault_rows()? {
        if !deleted {
            engine.adopt_vault(info.id, &info.name, &key, wall_ms)?;
        }
    }
    for vault in store.vaults()? {
        for entry in store.list_items(Some(vault.id))? {
            if let keyorra_core::store::ItemEntry::Ok(item) = entry {
                engine.save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)?;
            }
        }
    }
    for entry in store.deleted_items()? {
        if let keyorra_core::store::ItemEntry::Ok(item) = entry {
            if let Some((_, Some(at))) = store.item_state(item.id)? {
                engine.save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)?;
                engine.trash_item(item.id, at.max(0) as u64, wall_ms)?;
            }
        }
    }
    let config = SyncConfig {
        account_id,
        device,
        device_name: device_name.to_owned(),
        root: device,
        root_key: root_key.to_bytes(),
        secret_key: *secret_key.as_bytes(),
        secret_key_id: secret_key_id.clone(),
    };
    save_config(store, &config)?;
    store.set_sync_tracking(true)?;
    let kit = EmergencyKit {
        account_id: data_encoding::HEXLOWER.encode(&account_id),
        secret_key: secret_key.display(&secret_key_id),
    };
    let mut synced = Synced {
        engine,
        transport,
        config,
    };
    synced.round(store, wall_ms)?;
    Ok((synced, kit))
}

/// A new device joins a synced account it has no local vault for: a store is created at
/// `path` with the account's key (unlocked with the local `password`), and the device
/// self-joins; it waits for the main device's approval (comparing [`Synced::key_code`]).
/// `unlock` opens a header with the master password and the Secret Key (the app passes
/// `Header::unlock`, which refuses KDF parameters below the remote floor).
#[allow(clippy::too_many_arguments)]
pub fn join<T: Transport>(
    path: &std::path::Path,
    password: &str,
    local_kdf: KdfParams,
    secret_key: &SecretKey,
    secret_key_id: &str,
    pin: Option<&RootPin>,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    unlock: impl FnMut(&Header) -> Result<Key>,
    wall_ms: u64,
) -> Result<(Store, Synced<T>)> {
    let files = transport.headers()?;
    let root_head = match transport.root_head_file()? {
        Fetched::Ready(b) => Some(b),
        _ => None,
    };
    let joined = unlock_join_with(&files, root_head.as_deref(), pin, unlock)?;
    let header = joined.file.header.clone();
    let mut store =
        Store::create_with_account_key(path, password, local_kdf, joined.account_key.clone())?;
    let device = random_id();
    let signer = new_signer();
    keys.store(device, &signer);
    let root_key = VerifyingKey::from_bytes(&header.root_key)
        .map_err(|_| Error::Malformed("main device key".into()))?;
    let mut engine = Engine::join(
        device,
        signer,
        device_name,
        header.account_id,
        joined.account_key,
        header.root_device,
        root_key,
        OsRng,
    );
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    engine.self_join(wall_ms)?;
    let config = SyncConfig {
        account_id: header.account_id,
        device,
        device_name: device_name.to_owned(),
        root: header.root_device,
        root_key: header.root_key,
        secret_key: *secret_key.as_bytes(),
        secret_key_id: secret_key_id.to_owned(),
    };
    save_config(&mut store, &config)?;
    store.set_sync_tracking(true)?;
    let mut synced = Synced {
        engine,
        transport,
        config,
    };
    synced.round(&mut store, wall_ms)?;
    Ok((store, synced))
}

/// Continues sync after a restart (the store unlocked). The device key comes from `keys`; if
/// it is gone, the engine retires the id on its first round (spec §4.2).
pub fn resume<T: Transport>(
    store: &Store,
    transport: T,
    keys: &dyn DeviceKeyStore,
) -> Result<Synced<T>> {
    let config = load_config(store)?;
    let outbox = match store.sealed_meta(OUTBOX)? {
        Some(b) => OutboxState::from_bytes(&b)?,
        None => return Err(Error::NotFound("sync outbox".into())),
    };
    let memo = match store.sealed_meta(MEMO)? {
        Some(b) => EngineMemo::from_bytes(&b)?,
        None => EngineMemo::default(),
    };
    let signer = keys.load(&config.device).unwrap_or_else(new_signer);
    let root_key = VerifyingKey::from_bytes(&config.root_key)
        .map_err(|_| Error::Malformed("main device key".into()))?;
    let mut engine = Engine::resume(
        config.device,
        signer,
        &config.device_name,
        config.account_id,
        store.account_key_copy()?,
        config.root,
        root_key,
        OsRng,
        Resumed {
            outbox,
            own_segments: store.own_segments()?,
            memo,
        },
    )?;
    engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
    engine.set_device_keys(Box::new(keys::EngineKeys(keys.boxed_clone())));
    Ok(Synced {
        engine,
        transport,
        config,
    })
}

impl<T: Transport> Synced<T> {
    pub fn engine(&self) -> &Engine<OsRng> {
        &self.engine
    }

    /// The code to compare on the main device before it approves this one.
    pub fn key_code(&self) -> String {
        self.engine.key_fingerprint()
    }

    /// The main device approves a device that self-joined, after the user compared codes.
    pub fn approve(&mut self, device: DeviceId, code: &str, wall_ms: u64) -> Result<()> {
        self.engine.approve(device, code, wall_ms)
    }

    /// A new vault, created through sync so its id commits to its key (spec §4.4), then
    /// shown in the store.
    pub fn create_vault(&mut self, store: &mut Store, name: &str, wall_ms: u64) -> Result<Uuid> {
        let id = self.engine.create_vault(name, wall_ms)?;
        self.show(store)?;
        Ok(id)
    }

    /// One round: write the local changes, sync, show the result in the store, persist.
    /// Returns the engine's events.
    pub fn round(&mut self, store: &mut Store, wall_ms: u64) -> Result<Vec<Event>> {
        self.write_changes(store, wall_ms)?;
        let synced = self.engine.sync(&self.transport, wall_ms);
        // What could not be written before (the engine was still reading its own stream).
        self.write_changes(store, wall_ms)?;
        self.show(store)?;
        self.persist(store)?;
        synced?;
        Ok(self.engine.take_events())
    }

    /// The store's recorded changes, as versions. A change the engine cannot take yet (it
    /// is still reading its own stream after a restart, or conflict copies are owed) stays.
    fn write_changes(&mut self, store: &mut Store, wall_ms: u64) -> Result<()> {
        if !self.engine.can_write() {
            return Ok(());
        }
        let mut done = Vec::new();
        for change in store.pending_changes()? {
            match self.write_change(store, change, wall_ms) {
                Ok(()) | Err(Error::NotFound(_)) => done.push(change),
                Err(Error::Refused(_)) => {}
                Err(e) => return Err(e),
            }
        }
        store.clear_changes(&done)?;
        Ok(())
    }

    fn write_change(&mut self, store: &Store, change: Change, wall_ms: u64) -> Result<()> {
        let view = self.engine.view();
        match change.kind {
            ChangeKind::Vault => {
                let Some((info, key, deleted)) = store
                    .vault_rows()?
                    .into_iter()
                    .find(|(i, _, _)| i.id == change.id)
                else {
                    return Ok(());
                };
                match view.vaults.get(&change.id) {
                    None if !deleted => self.engine.adopt_vault(info.id, &info.name, &key, wall_ms),
                    None => Ok(()),
                    Some(v) if deleted && !v.deleted => {
                        self.engine.delete_vault(change.id, wall_ms)
                    }
                    Some(v) if !deleted && v.name != info.name => {
                        self.engine.rename_vault(change.id, &info.name, wall_ms)
                    }
                    Some(_) => Ok(()),
                }
            }
            ChangeKind::Item => {
                let synced = view.items.get(&change.id);
                match store.item_state(change.id)? {
                    Some((item, None)) => {
                        self.engine
                            .save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)
                    }
                    Some((item, Some(at))) => {
                        let live_same = synced.is_some_and(|v| {
                            v.state == ItemState::Live
                                && v.payload
                                    .as_ref()
                                    .and_then(|p| serde_json::from_slice::<Item>(&p.item_json).ok())
                                    == Some(item.clone())
                        });
                        if !live_same && synced.is_none_or(|v| v.state != ItemState::Trashed) {
                            self.engine.save_item(
                                item.vault_id,
                                item.id,
                                &item_json(&item)?,
                                wall_ms,
                            )?;
                        }
                        match self.engine.view().items.get(&change.id).map(|v| v.state) {
                            Some(ItemState::Live) => {
                                self.engine.trash_item(change.id, at.max(0) as u64, wall_ms)
                            }
                            _ => Ok(()),
                        }
                    }
                    None if store.item_purged(change.id)? => {
                        if synced.is_some_and(|v| v.state == ItemState::Live) {
                            self.engine.trash_item(change.id, 0, wall_ms)?;
                        }
                        match self.engine.view().items.get(&change.id).map(|v| v.state) {
                            Some(ItemState::Trashed) => self.engine.purge_item(change.id, wall_ms),
                            _ => Ok(()),
                        }
                    }
                    None => Ok(()),
                }
            }
            // Attachment contents travel with the folder transport (plan A2).
            ChangeKind::Attachment => Ok(()),
        }
    }

    /// What sync shows, in the store. Records with local changes not yet written are left as
    /// they are (they will be written, then shown).
    fn show(&mut self, store: &mut Store) -> Result<()> {
        let pending: BTreeSet<Uuid> = store.pending_changes()?.into_iter().map(|c| c.id).collect();
        let view = self.engine.view();
        for (id, v) in &view.vaults {
            if !pending.contains(id) {
                store.apply_remote_vault(*id, &v.name, &v.wrapped_key, v.deleted)?;
            }
        }
        for (id, v) in &view.items {
            if pending.contains(id) {
                continue;
            }
            match (v.state, &v.payload, v.vault_id) {
                (ItemState::Purged, _, _) => store.apply_remote_purge(*id)?,
                (_, Some(p), Some(vault)) => {
                    let Ok(mut item) = serde_json::from_slice::<Item>(&p.item_json) else {
                        continue;
                    };
                    item.id = *id;
                    item.vault_id = vault;
                    let deleted_at = match v.state {
                        ItemState::Trashed => Some(p.deleted_at.unwrap_or(0) as i64),
                        _ => None,
                    };
                    store.apply_remote_item(&item, deleted_at)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Everything the engine cannot read again from the streams.
    fn persist(&mut self, store: &mut Store) -> Result<()> {
        // A retired id: the device goes on under its new one.
        if self.engine.device() != self.config.device {
            self.config.device = self.engine.device();
            save_config(store, &self.config)?;
        }
        store.set_sealed_meta(OUTBOX, &self.engine.outbox_state().to_bytes())?;
        store.set_sealed_meta(MEMO, &self.engine.memo().to_bytes())?;
        store.set_own_segments(self.engine.own_segments())?;
        Ok(())
    }

    /// The account id and Secret Key, for the Emergency Kit or a setup code.
    pub fn emergency_kit(&self) -> EmergencyKit {
        let sk = SecretKey::from_bytes(self.config.secret_key);
        EmergencyKit {
            account_id: data_encoding::HEXLOWER.encode(&self.config.account_id),
            secret_key: sk.display(&self.config.secret_key_id),
        }
    }

    /// The pin a setup code shown on this device carries (the main device's id and key code).
    pub fn root_pin(&self) -> RootPin {
        RootPin {
            device: self.config.root,
            key_fingerprint: keyorra_sync::trust::key_fingerprint(
                &VerifyingKey::from_bytes(&self.config.root_key).expect("checked when saved"),
            ),
        }
    }
}
