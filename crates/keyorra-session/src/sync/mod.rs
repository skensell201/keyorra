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

mod enclave_keys;
mod keys;
mod merge;
mod screen;
mod setup;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{KdfParams, Key};
use keyorra_core::model::Item;
use keyorra_core::store::{Change, ChangeKind, ItemEntry, MetaWriter, Store};
use keyorra_sync::account::{unlock_join_with, RootPin};
use keyorra_sync::engine::{Engine, EngineMemo, Event, OutboxState, OutboxStore, Resumed};
use keyorra_sync::fold::View;
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

pub use enclave_keys::{Enclave, EnclaveDeviceKeys, EnclaveError};
pub use keys::{DeviceKeyStore, MemoryDeviceKeys};
pub use merge::{carry_over, disable, rejoin, start_new_account, CarryReport, Rejoined};
pub use screen::{AlarmView, VerifyReport};
pub use setup::SetupCode;

const CONFIG: &str = "sync:config";
const OUTBOX: &str = "sync:outbox";
const MEMO: &str = "sync:memo";
/// What every record looked like when sync was turned off (kept for rejoining).
const BASE: &str = "sync-base";

/// What this device knows about its synced account (sealed meta `sync:config`).
#[derive(Clone, Serialize, Deserialize)]
struct SyncConfig {
    account_id: AccountId,
    device: DeviceId,
    device_name: String,
    root: DeviceId,
    root_key: [u8; 32],
    /// Wiped when dropped, never printed (review A1d-2 I10).
    secret_key: Zeroizing<[u8; 16]>,
    secret_key_id: String,
}

impl std::fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncConfig")
            .field(
                "account_id",
                &data_encoding::HEXLOWER.encode(&self.account_id),
            )
            .field("device", &data_encoding::HEXLOWER.encode(&self.device))
            .field("device_name", &self.device_name)
            .field("root", &data_encoding::HEXLOWER.encode(&self.root))
            .field("secret_key", &"(redacted)")
            .field("secret_key_id", &self.secret_key_id)
            .finish()
    }
}

/// Sync as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub main_device: bool,
    /// This device self-joined and waits for the main device.
    pub waiting_for_approval: bool,
    /// This device's key code (compared on the main device before approving it).
    pub key_code: String,
    pub devices: Vec<SyncDevice>,
    pub alarms: usize,
    /// Other devices' changes are confirmed by the main Mac's newest decisions (false while
    /// its newest changes are not all here).
    pub root_confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDevice {
    pub id: String,
    pub name: String,
    pub approved: bool,
    pub main: bool,
    pub this_device: bool,
    /// Removed by the main Mac.
    pub removed: bool,
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

/// How a local change went.
enum Outcome {
    Written,
    /// Sync can never take it: undone, with the reason.
    Undone(String),
}

/// Whether the changed record still exists locally (live or in Recently Deleted).
fn still_here(store: &Store, change: Change) -> Result<bool> {
    Ok(match change.kind {
        ChangeKind::Item => store.item_state(change.id)?.is_some(),
        ChangeKind::Vault => store
            .vault_rows()?
            .iter()
            .any(|(i, _, deleted)| i.id == change.id && !deleted),
        ChangeKind::Attachment => false,
    })
}

/// Writes `view` into `store`, except the records in `skip`. `vault_key` names the wrapped
/// key a vault must keep. Returns the records that could not be written, with the reason.
fn show_view(
    store: &mut Store,
    view: &View,
    skip: &BTreeSet<Uuid>,
    vault_key: impl Fn(Uuid) -> Option<Vec<u8>>,
    now_secs: u64,
) -> Vec<(Uuid, String)> {
    let mut failed = Vec::new();
    for (id, v) in &view.vaults {
        if skip.contains(id) {
            continue;
        }
        let Some(wrapped) = vault_key(*id) else {
            failed.push((*id, "no usable vault key".to_owned()));
            continue;
        };
        if let Err(e) = store.apply_remote_vault(*id, &v.name, &wrapped, v.deleted) {
            failed.push((*id, e.to_string()));
        }
    }
    for (id, v) in &view.items {
        if skip.contains(id) {
            continue;
        }
        let result = match (v.state, &v.payload, v.vault_id) {
            (ItemState::Purged, _, _) => store.apply_remote_purge(*id),
            (_, Some(p), Some(vault)) => {
                let Ok(mut item) = serde_json::from_slice::<Item>(&p.item_json) else {
                    failed.push((*id, "unreadable item".to_owned()));
                    continue;
                };
                item.id = *id;
                item.vault_id = vault;
                let deleted_at = match v.state {
                    ItemState::Trashed => Some(p.deleted_at.unwrap_or(now_secs) as i64),
                    _ => None,
                };
                store.apply_remote_item(&item, deleted_at)
            }
            _ => Ok(()),
        };
        if let Err(e) = result {
            failed.push((*id, e.to_string()));
        }
    }
    failed
}

/// Sync of one store over one transport.
pub struct Synced<T: Transport> {
    engine: Engine<OsRng>,
    transport: T,
    config: SyncConfig,
    /// Rejoining: what each record looked like when sync was turned off; a record changed
    /// both here and in the account since then becomes a conflict copy.
    base: Option<merge::Base>,
    /// A round read the store since this started: before that the engine's view may lack
    /// what a local change refers to (a joining device knows no vault yet).
    caught_up: bool,
    /// Attachments whose chunks did not open, by the chunks named (not read again).
    unopenable: BTreeSet<(Uuid, Vec<[u8; 32]>)>,
    /// Size of the chunks new attachments are cut into (tests make it small).
    chunk_size: usize,
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

fn item_json(item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(item)
        .map(Zeroizing::new)
        .map_err(|e| Error::Malformed(e.to_string()))
}

/// A new account's id (its folder is named after it, plan A2).
pub fn new_account_id() -> AccountId {
    random_id()
}

/// The account this store syncs with.
pub fn account_id(store: &Store) -> Result<AccountId> {
    Ok(load_config(store)?.account_id)
}

/// Whether `transport` holds an account whose header names this Secret Key id (choosing the
/// account folder to join without trying the password on each, plan A2).
pub fn holds_account<T: Transport>(transport: &T, secret_key_id: &str) -> Result<bool> {
    Ok(matches!(
        find_account(transport, secret_key_id)?,
        AccountMatch::Account(_)
    ))
}

/// What a folder says about a Secret Key id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountMatch {
    /// A header names it, of this account.
    Account(AccountId),
    /// No header names it, but some header file is not on this device yet.
    Downloading,
    None,
}

/// Which account of `transport` a Secret Key id belongs to, from its header files.
pub fn find_account<T: Transport>(transport: &T, secret_key_id: &str) -> Result<AccountMatch> {
    let mut downloading = false;
    for (_, f) in transport.headers()? {
        match f {
            Fetched::Ready(bytes) => {
                if let Ok(h) = keyorra_sync::header::HeaderFile::decode(&bytes) {
                    if h.header.secret_key_id == secret_key_id {
                        return Ok(AccountMatch::Account(h.header.account_id));
                    }
                }
            }
            Fetched::Pending => downloading = true,
            Fetched::Missing => {}
        }
    }
    Ok(if downloading {
        AccountMatch::Downloading
    } else {
        AccountMatch::None
    })
}

/// Whether the account in `transport` opens with this unlock (and pin).
pub fn opens<T: Transport>(
    transport: &T,
    pin: Option<&RootPin>,
    unlock: impl FnMut(&Header) -> Result<Key>,
) -> Result<()> {
    open_account(transport, pin, unlock).map(drop)
}

/// Every live attachment of the store, as changes (written unless sync has them).
fn attachment_changes(store: &Store) -> Result<Vec<Change>> {
    Ok(store
        .attachment_ids()?
        .into_iter()
        .map(|id| Change {
            kind: ChangeKind::Attachment,
            id,
        })
        .collect())
}

/// Whether this store is the main device of its synced account (from its configuration, so
/// also while sync is not running).
pub fn is_main(store: &Store) -> Result<bool> {
    Ok(is_enabled(store)? && load_config(store)?.root == load_config(store)?.device)
}

/// Whether sync is set up on this store.
pub fn is_enabled(store: &Store) -> Result<bool> {
    Ok(store.sync_tracking()? && store.sealed_meta(CONFIG)?.is_some())
}

/// Sync turned on: the store is the main device of a new account. `first_round` is the
/// result of the first sync round; sync is on whatever it says (a failed round is retried).
pub struct Enabled<T: Transport> {
    pub synced: Synced<T>,
    pub kit: EmergencyKit,
    /// Items that could not be read here and so were not written to sync.
    pub damaged: usize,
    pub first_round: Result<RoundReport>,
}

/// A device that joined: its new store, waiting for approval. `first_round` as for
/// [`Enabled`].
pub struct Joined<T: Transport> {
    pub store: Store,
    pub synced: Synced<T>,
    pub first_round: Result<RoundReport>,
}

/// What a round did besides the engine's events.
#[derive(Debug, Default)]
pub struct RoundReport {
    pub events: Vec<Event>,
    /// Local changes sync cannot take (deleting a vault that has items on another device):
    /// undone here, and the account's state shown instead.
    pub reverted: Vec<(Change, String)>,
    /// Records sync shows that could not be written into the store, and local changes that
    /// wait for something (both are tried again every round).
    pub failed: Vec<(Uuid, String)>,
}

/// Turns `store` into the main device of a new synced account, writing everything it holds
/// as first versions. The synced header uses `kdf` (the remote floor applies when joining).
/// Nothing is changed in the store unless this returns `Ok` (review A1d I5).
#[allow(clippy::too_many_arguments)]
pub fn enable<T: Transport>(
    store: &mut Store,
    account_id: AccountId,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<Enabled<T>> {
    if is_enabled(store)? {
        return Err(Error::Refused("sync is already on".into()));
    }
    // Each account has its own location: one that holds another account's files is not used
    // (review A1d-2 I12).
    if !transport.headers()?.is_empty() {
        return Err(Error::Refused(
            "this location already holds a Keyorra account; choose an empty one".into(),
        ));
    }
    let device = random_id();
    let signer = new_signer();
    keys.store(device, &signer).map_err(Error::Refused)?;
    let started = start_account(
        store,
        keys,
        device,
        signer,
        device_name,
        account_id,
        password,
        kdf,
        wall_ms,
    );
    let (engine, config, kit, damaged) = match started {
        Ok(x) => x,
        Err(e) => {
            keys.forget(&device);
            let _ = store.delete_sealed_meta(OUTBOX);
            return Err(e);
        }
    };
    // What an earlier "off" kept for rejoining another account (review A1d-2 I6).
    store.delete_sealed_meta(BASE)?;
    let mut synced = Synced {
        engine,
        transport,
        config,
        base: None,
        caught_up: false,
        unopenable: BTreeSet::new(),
        chunk_size: keyorra_sync::chunk::MAX_CHUNK,
    };
    synced.commit(store)?;
    // Attachment contents go through the normal path (chunks first, then the record).
    store.record_changes(&attachment_changes(store)?)?;
    let first_round = synced.round(store, wall_ms);
    Ok(Enabled {
        synced,
        kit,
        damaged,
        first_round,
    })
}

/// The new account's engine with everything of the store written, before anything is
/// committed to the store.
#[allow(clippy::too_many_arguments)]
fn start_account(
    store: &mut Store,
    keys: &dyn DeviceKeyStore,
    device: DeviceId,
    signer: SigningKey,
    device_name: &str,
    account_id: AccountId,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<(Engine<OsRng>, SyncConfig, EmergencyKit, usize)> {
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
    engine.set_device_keys(Box::new(keys::EngineKeys(keys.boxed_clone())));
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
    let mut damaged = 0;
    let mut entries = Vec::new();
    for vault in store.vaults()? {
        entries.extend(store.list_items(Some(vault.id))?);
    }
    entries.extend(store.deleted_items()?);
    for entry in entries {
        let ItemEntry::Ok(item) = entry else {
            damaged += 1;
            continue;
        };
        engine.save_item(item.vault_id, item.id, &item_json(&item)?, wall_ms)?;
        if let Some((_, Some(at))) = store.item_state(item.id)? {
            engine.trash_item(item.id, at.max(0) as u64, wall_ms)?;
        }
    }
    let config = SyncConfig {
        account_id,
        device,
        device_name: device_name.to_owned(),
        root: device,
        root_key: root_key.to_bytes(),
        secret_key: Zeroizing::new(*secret_key.as_bytes()),
        secret_key_id: secret_key_id.clone(),
    };
    let kit = EmergencyKit {
        account_id: data_encoding::HEXLOWER.encode(&account_id),
        secret_key: secret_key.display(&secret_key_id),
    };
    Ok((engine, config, kit, damaged))
}

/// A new device joins a synced account it has no local vault for: a store is created at
/// `path` with the account's key (unlocked with the local `password`), and the device
/// self-joins; it waits for the main device's approval (comparing [`Synced::key_code`]).
/// `unlock` opens a header with the master password and the Secret Key (the app passes
/// `Header::unlock`, which refuses KDF parameters below the remote floor). On an error no
/// file is left at `path`.
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
) -> Result<Joined<T>> {
    let (header, account_key) = open_account(&transport, pin, unlock)?;
    let mut store = Store::create_with_account_key(path, password, local_kdf, account_key.clone())?;
    match join_store(
        &mut store,
        transport,
        keys,
        device_name,
        (secret_key, secret_key_id),
        &header,
        account_key,
        None,
        wall_ms,
    ) {
        Ok((synced, first_round)) => Ok(Joined {
            store,
            synced,
            first_round,
        }),
        Err(e) => {
            drop(store);
            remove_database(path);
            Err(e)
        }
    }
}

/// The account header the transport holds, unlocked: (header, account key).
fn open_account<T: Transport>(
    transport: &T,
    pin: Option<&RootPin>,
    unlock: impl FnMut(&Header) -> Result<Key>,
) -> Result<(Header, Key)> {
    let files = transport.headers()?;
    let root_head = match transport.root_head_file()? {
        Fetched::Ready(b) => Some(b),
        _ => None,
    };
    let joined = unlock_join_with(&files, root_head.as_deref(), pin, unlock)?;
    Ok((joined.file.header.clone(), joined.account_key))
}

/// A new device id for `store` in the account: self-joins and waits for approval. On an
/// error nothing of sync is left in the store and the key is forgotten; otherwise sync is
/// committed and the first round's result is returned with it.
#[allow(clippy::too_many_arguments)]
fn join_store<T: Transport>(
    store: &mut Store,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    (secret_key, secret_key_id): (&SecretKey, &str),
    header: &Header,
    account_key: Key,
    base: Option<merge::Base>,
    wall_ms: u64,
) -> Result<(Synced<T>, Result<RoundReport>)> {
    let device = random_id();
    let started = (|| -> Result<Synced<T>> {
        let signer = new_signer();
        keys.store(device, &signer).map_err(Error::Refused)?;
        let root_key = VerifyingKey::from_bytes(&header.root_key)
            .map_err(|_| Error::Malformed("main device key".into()))?;
        let mut engine = Engine::join(
            device,
            signer,
            device_name,
            header.account_id,
            account_key,
            header.root_device,
            root_key,
            OsRng,
        );
        engine.set_outbox_store(Box::new(StoreOutbox(store.meta_writer()?)));
        engine.set_device_keys(Box::new(keys::EngineKeys(keys.boxed_clone())));
        engine.self_join(wall_ms)?;
        let config = SyncConfig {
            account_id: header.account_id,
            device,
            device_name: device_name.to_owned(),
            root: header.root_device,
            root_key: header.root_key,
            secret_key: Zeroizing::new(*secret_key.as_bytes()),
            secret_key_id: secret_key_id.to_owned(),
        };
        let mut synced = Synced {
            engine,
            transport,
            config,
            base,
            caught_up: false,
            unopenable: BTreeSet::new(),
            chunk_size: keyorra_sync::chunk::MAX_CHUNK,
        };
        if let Some(base) = &synced.base {
            // What changed here while sync was off is written once the device may write.
            let mut changed = merge::changed_since(store, base)?;
            changed.extend(attachment_changes(store)?);
            synced.commit(store)?;
            store.record_changes(&changed)?;
        } else {
            synced.commit(store)?;
        }
        Ok(synced)
    })();
    let mut synced = match started {
        Ok(s) => s,
        Err(e) => {
            keys.forget(&device);
            let _ = store.delete_sealed_meta(OUTBOX);
            let _ = store.delete_sealed_meta(CONFIG);
            let _ = store.set_sync_tracking(false);
            return Err(e);
        }
    };
    let first_round = synced.round(store, wall_ms);
    Ok((synced, first_round))
}

/// Removes a database file this module created, with SQLite's companions.
fn remove_database(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(name));
    }
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
    // No key here: the engine retires the id on its first round. A key that cannot be read
    // now is not "no key": sync waits (review A1d-2 I3).
    let signer = match keys.load(&config.device) {
        Ok(Some(key)) => key,
        Ok(None) => new_signer(),
        Err(e) => {
            return Err(Error::Refused(format!(
                "this Mac's device key could not be read: {e}"
            )))
        }
    };
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
        base: merge::load_base(store)?,
        caught_up: false,
        unopenable: BTreeSet::new(),
        chunk_size: keyorra_sync::chunk::MAX_CHUNK,
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
        self.show(store, wall_ms)?;
        Ok(id)
    }

    /// One round: write the local changes, sync, show the result in the store, persist.
    /// The engine's state is persisted whatever else fails.
    pub fn round(&mut self, store: &mut Store, wall_ms: u64) -> Result<RoundReport> {
        // The whole round shares one time budget, which ends with it (review A2 I1).
        self.transport.begin_round();
        let result = self.round_inner(store, wall_ms);
        self.transport.end_round();
        result
    }

    fn round_inner(&mut self, store: &mut Store, wall_ms: u64) -> Result<RoundReport> {
        let mut report = RoundReport::default();
        let before = self.write_changes(store, wall_ms, &mut report);
        let synced = self.engine.sync(&self.transport, wall_ms);
        if synced.is_ok() {
            self.caught_up = true;
        }
        // What could not be written before (the engine was still reading its own stream).
        let after = self.write_changes(store, wall_ms, &mut report);
        // While the engine reads its streams again after a restart, its view lacks this
        // device's own latest versions: showing it would put older data back (review A1d I1).
        let shown = if self.engine.is_rebuilding() {
            Ok(Vec::new())
        } else {
            self.show(store, wall_ms)
        };
        let persisted = self.persist(store);
        before?;
        after?;
        report.failed.extend(shown?);
        persisted?;
        synced?;
        report.events = self.engine.take_events();
        Ok(report)
    }

    /// The store's recorded changes, as versions. A change the engine cannot take yet stays
    /// recorded: it is still reading its own stream after a restart, conflict copies are
    /// owed, what it refers to is not in sync yet, or the outbox could not be saved (review
    /// A1d C1, I3). A change it can never take is undone (review A1d I4).
    fn write_changes(
        &mut self,
        store: &mut Store,
        wall_ms: u64,
        report: &mut RoundReport,
    ) -> Result<()> {
        if !self.caught_up || !self.engine.can_write() {
            return Ok(());
        }
        let mut done = Vec::new();
        let mut all = true;
        for change in store.pending_changes()? {
            match self.write_change(store, change, wall_ms) {
                Ok(Outcome::Written) => done.push(change),
                Ok(Outcome::Undone(reason)) => {
                    done.push(change);
                    report.reverted.push((change, reason));
                }
                Err(Error::Refused(_)) => all = false,
                // The store of files did not take a chunk: tried again next round.
                Err(Error::Transport(reason)) => {
                    all = false;
                    report.failed.push((change.id, reason));
                }
                Err(Error::NotFound(reason)) => {
                    if still_here(store, change)? {
                        all = false;
                        report.failed.push((change.id, reason));
                    } else {
                        done.push(change);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if self.engine.outbox_unsaved() {
            // Written to the engine but not safe from a crash: written again next round.
            return Ok(());
        }
        store.clear_changes(&done)?;
        if all && self.base.take().is_some() {
            store.delete_sealed_meta(BASE)?;
        }
        Ok(())
    }

    fn write_change(&mut self, store: &mut Store, change: Change, wall_ms: u64) -> Result<Outcome> {
        let view = self.engine.view();
        let now_secs = wall_ms / 1000;
        match change.kind {
            ChangeKind::Vault => {
                let Some((info, key, deleted)) = store
                    .vault_rows()?
                    .into_iter()
                    .find(|(i, _, _)| i.id == change.id)
                else {
                    return Ok(Outcome::Written);
                };
                match view.vaults.get(&change.id) {
                    None if !deleted => self
                        .engine
                        .adopt_vault(info.id, &info.name, &key, wall_ms)?,
                    None => {}
                    Some(v) if deleted && !v.deleted => {
                        let live_elsewhere = view
                            .items
                            .values()
                            .any(|i| i.state == ItemState::Live && i.vault_id == Some(change.id));
                        if live_elsewhere {
                            return Ok(Outcome::Undone(
                                "the vault has items on another device; it was not deleted".into(),
                            ));
                        }
                        self.engine.delete_vault(change.id, wall_ms)?
                    }
                    Some(v) if !deleted && v.name != info.name => {
                        self.engine.rename_vault(change.id, &info.name, wall_ms)?
                    }
                    Some(_) => {}
                }
                Ok(Outcome::Written)
            }
            ChangeKind::Item => {
                if let Some(base) = &self.base {
                    if merge::copy_if_both_changed(
                        store,
                        base,
                        &view,
                        change.id,
                        self.config.device,
                    )? {
                        return Ok(Outcome::Written);
                    }
                }
                let synced = view.items.get(&change.id);
                let shown = |state: ItemState| {
                    synced.filter(|v| v.state == state).and_then(|v| {
                        let p = v.payload.as_ref()?;
                        let mut item = serde_json::from_slice::<Item>(&p.item_json).ok()?;
                        item.id = change.id;
                        item.vault_id = v.vault_id?;
                        Some(item)
                    })
                };
                match store.item_state(change.id)? {
                    Some((item, None)) => {
                        // Written already (e.g. again after a failed outbox save).
                        if shown(ItemState::Live).as_ref() != Some(&item) {
                            self.engine.save_item(
                                item.vault_id,
                                item.id,
                                &item_json(&item)?,
                                wall_ms,
                            )?;
                        }
                    }
                    Some((item, Some(at))) => {
                        let same = shown(ItemState::Live).as_ref() == Some(&item)
                            || shown(ItemState::Trashed).as_ref() == Some(&item);
                        if !same {
                            self.engine.save_item(
                                item.vault_id,
                                item.id,
                                &item_json(&item)?,
                                wall_ms,
                            )?;
                        }
                        if self.engine.view().items.get(&change.id).map(|v| v.state)
                            == Some(ItemState::Live)
                        {
                            self.engine
                                .trash_item(change.id, at.max(0) as u64, wall_ms)?;
                        }
                    }
                    None if store.item_purged(change.id)? => {
                        if synced.is_some_and(|v| v.state == ItemState::Live) {
                            self.engine.trash_item(change.id, now_secs, wall_ms)?;
                        }
                        if self.engine.view().items.get(&change.id).map(|v| v.state)
                            == Some(ItemState::Trashed)
                        {
                            self.engine.purge_item(change.id, wall_ms)?;
                        }
                    }
                    None => {}
                }
                Ok(Outcome::Written)
            }
            // Attachment contents travel with the folder transport (plan A2).
            // Its content as chunks, stored before the record is written (spec §5.3).
            // Attachments never change: an id sync has is the same content.
            ChangeKind::Attachment => {
                let Some(state) = store.attachment_state(change.id)? else {
                    return Ok(Outcome::Written);
                };
                let in_sync = view.attachments.contains_key(&change.id);
                if state.live && !in_sync {
                    let Some((item, _)) = store.item_state(state.item_id)? else {
                        return Ok(Outcome::Written);
                    };
                    let name = item
                        .attachments
                        .iter()
                        .find(|a| a.id == change.id)
                        .map(|a| a.name.clone())
                        .unwrap_or_default();
                    let bytes = store.attachment_content(change.id)?;
                    let (payload, chunks) = self.engine.seal_attachment(
                        change.id,
                        item.id,
                        &name,
                        &bytes,
                        self.chunk_size,
                    )?;
                    for chunk in &chunks {
                        self.transport.put_chunk(chunk)?;
                    }
                    self.engine
                        .write_attachment(item.vault_id, change.id, payload, wall_ms)?;
                } else if !state.live && in_sync {
                    self.engine.remove_attachment(change.id, wall_ms)?;
                }
                Ok(Outcome::Written)
            }
        }
    }

    /// Attachment contents sync shows: fetched as chunks and stored; removed ones removed.
    /// Content whose chunks are not here yet waits (reported), and is tried every round.
    fn show_attachments(
        &mut self,
        store: &mut Store,
        view: &View,
        pending: &BTreeSet<Uuid>,
    ) -> Result<Vec<(Uuid, String)>> {
        let mut failed = Vec::new();
        for (id, payload) in &view.attachments {
            if pending.contains(id) {
                continue;
            }
            let here = store.attachment_state(*id)?;
            if here.is_some_and(|h| h.live && h.item_id == payload.item_id) {
                continue;
            }
            if store.item_state(payload.item_id)?.is_none() {
                continue;
            }
            if self.unopenable.contains(&(*id, payload.chunks.clone())) {
                failed.push((*id, "the attachment's content does not open".to_owned()));
                continue;
            }
            // First whether every chunk is here (missing ones are asked for, all at once),
            // then read them, each once (review A2 I6).
            let mut waiting = None;
            for name in &payload.chunks {
                match self
                    .transport
                    .chunk_state(&data_encoding::HEXLOWER.encode(name))
                {
                    Ok(Fetched::Ready(())) => {}
                    Ok(_) => {
                        waiting.get_or_insert_with(|| {
                            "waiting for the attachment's content".to_owned()
                        });
                    }
                    Err(e) => waiting = Some(e.to_string()),
                }
            }
            if let Some(why) = waiting {
                failed.push((*id, why));
                continue;
            }
            let mut chunks = Vec::with_capacity(payload.chunks.len());
            for name in &payload.chunks {
                match self
                    .transport
                    .get_chunk(&data_encoding::HEXLOWER.encode(name))
                {
                    Ok(Fetched::Ready(bytes)) => chunks.push(bytes),
                    Ok(_) => break,
                    Err(e) => {
                        failed.push((*id, e.to_string()));
                        break;
                    }
                }
            }
            if chunks.len() != payload.chunks.len() {
                if !failed.iter().any(|(f, _)| f == id) {
                    failed.push((*id, "waiting for the attachment's content".to_owned()));
                }
                continue;
            }
            match self.engine.open_attachment(payload, &chunks) {
                Ok(bytes) => {
                    if let Err(e) = store.apply_remote_attachment(*id, payload.item_id, &bytes) {
                        failed.push((*id, e.to_string()));
                    }
                }
                Err(e) => {
                    // Not tried again until the record names other chunks.
                    self.unopenable.insert((*id, payload.chunks.clone()));
                    failed.push((*id, e.to_string()));
                }
            }
        }
        // Removed in sync: an attachment record the account has that is no longer live.
        for id in store.attachment_ids()? {
            if pending.contains(&id) || view.attachments.contains_key(&id) {
                continue;
            }
            if self
                .engine
                .fold()
                .contains(keyorra_sync::envelope::RecordKind::Attachment, id)
            {
                store.apply_remote_attachment_removed(id)?;
            }
        }
        Ok(failed)
    }

    /// What sync shows, in the store. Records with local changes not yet written are left as
    /// they are (they will be written, then shown). A vault keeps the key the engine chose
    /// (review A1d C3). A record that cannot be written is skipped and reported; the rest is
    /// still shown.
    fn show(&mut self, store: &mut Store, wall_ms: u64) -> Result<Vec<(Uuid, String)>> {
        let pending: BTreeSet<Uuid> = store.pending_changes()?.into_iter().map(|c| c.id).collect();
        let view = self.engine.view();
        let engine = &self.engine;
        let mut failed = show_view(
            store,
            &view,
            &pending,
            |v| engine.vault_key(v),
            wall_ms / 1000,
        );
        failed.extend(self.show_attachments(store, &view, &pending)?);
        Ok(failed)
    }
    /// Everything the engine cannot read again from the streams.
    /// Sync is on: the configuration, the change tracking and the engine's state, saved.
    fn commit(&mut self, store: &mut Store) -> Result<()> {
        save_config(store, &self.config)?;
        store.set_sync_tracking(true)?;
        self.persist(store)
    }

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
        let sk = SecretKey::from_bytes(*self.config.secret_key);
        EmergencyKit {
            account_id: data_encoding::HEXLOWER.encode(&self.config.account_id),
            secret_key: sk.display(&self.config.secret_key_id),
        }
    }

    /// Whether a new master password can be published now: the main device, writing, with
    /// the account header read (after a restart it is known only after the first round).
    pub fn ready_for_password_change(&self) -> bool {
        self.engine.is_root() && self.engine.can_write() && self.engine.current_header().is_some()
    }

    /// A new master password for the account (main device only): a new header epoch.
    /// `account_key` is the store's (the same as the account's).
    pub fn change_password(
        &mut self,
        account_key: &Key,
        password: &str,
        kdf: KdfParams,
        wall_ms: u64,
    ) -> Result<()> {
        if !self.engine.is_root() {
            return Err(Error::Refused(
                "the master password is changed on the main device".into(),
            ));
        }
        let current = self
            .engine
            .current_header()
            .cloned()
            .ok_or_else(|| Error::NotFound("account header".into()))?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let sk = SecretKey::from_bytes(*self.config.secret_key);
        let keys = derive_sync_keys(password, &salt, kdf, &sk, &self.config.account_id)?;
        let mut header = Header {
            epoch: current.epoch + 1,
            kdf,
            salt,
            wrapped_account_key: Vec::new(),
            ..current
        };
        header.wrapped_account_key = wrap_account_key(&keys.kek, account_key, &header, &mut OsRng);
        self.engine.publish_header(header, wall_ms)
    }

    /// What the UI shows about sync.
    pub fn status(&self) -> SyncStatus {
        let trust = self.engine.trust();
        let mut devices: Vec<SyncDevice> = trust
            .devices()
            .iter()
            .map(|(id, d)| SyncDevice {
                id: data_encoding::HEXLOWER.encode(id),
                name: d.name.clone(),
                approved: true,
                main: *id == trust.root(),
                this_device: *id == self.engine.device(),
                removed: d.cut.is_some(),
            })
            .collect();
        devices.extend(trust.unapproved().iter().map(|(id, d)| SyncDevice {
            id: data_encoding::HEXLOWER.encode(id),
            name: d.name.clone(),
            approved: false,
            main: false,
            this_device: *id == self.engine.device(),
            removed: false,
        }));
        SyncStatus {
            main_device: self.engine.is_root(),
            waiting_for_approval: !trust.devices().contains_key(&self.engine.device()),
            key_code: self.engine.key_fingerprint(),
            devices,
            alarms: self.engine.alarms().len(),
            root_confirmed: self.engine.root_confirmed(),
        }
    }

    /// The setup code for adding a device (secret: it carries the Secret Key).
    pub fn setup_code(&self) -> SetupCode {
        SetupCode {
            secret_key_id: self.config.secret_key_id.clone(),
            secret_key: SecretKey::from_bytes(*self.config.secret_key),
            pin: self.root_pin(),
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
