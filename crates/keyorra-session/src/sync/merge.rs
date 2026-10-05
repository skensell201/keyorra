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
    enable, join_store, load_config, open_account, DeviceKeyStore, Enabled, RoundReport, Synced,
    BASE, CONFIG, MEMO, OUTBOX,
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

/// The fingerprint of what sync shows of a record.
fn synced_print(view: &View, id: Uuid) -> Option<[u8; 32]> {
    if let Some(v) = view.vaults.get(&id) {
        return Some(vault_print(&v.name, v.deleted));
    }
    let v = view.items.get(&id)?;
    let p = v.payload.as_ref()?;
    let mut item = serde_json::from_slice::<Item>(&p.item_json).ok()?;
    item.id = id;
    item.vault_id = v.vault_id?;
    let deleted_at = (v.state == keyorra_sync::present::ItemState::Trashed)
        .then(|| p.deleted_at.map_or(0, |d| d as i64));
    Some(item_print(&item, deleted_at))
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
    let attachments: Vec<(String, Vec<u8>)> = local
        .attachments
        .iter()
        .filter_map(|a| Some((a.name.clone(), store.get_attachment(a.id).ok()?.to_vec())))
        .collect();
    let mut copy = local;
    copy.id = Uuid::new_v4();
    copy.attachments.clear();
    copy.conflict = Some(ConflictInfo {
        of: id,
        version: String::new(),
        from_device: data_encoding::HEXLOWER.encode(&device),
    });
    store.save_item(&copy)?;
    // The copy's own attachment records (an attachment is bound to its item).
    for (name, bytes) in attachments {
        store.add_attachment(copy.id, &name, &bytes, copy.updated_at)?;
    }
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
    match &synced {
        Some(s) => {
            if s.engine.is_root() && s.engine.trust().devices().len() > 1 {
                return Err(Error::Refused(
                    "this Mac is the main device of other devices".into(),
                ));
            }
        }
        // Not running: whether other devices depend on it cannot be told (review A1d-2 I4).
        None => {
            if load_config(store).is_ok_and(|c| c.root == c.device) {
                return Err(Error::Refused(
                    "this Mac is the main device: sync must be running to turn it off".into(),
                ));
            }
        }
    }
    let device = match &synced {
        Some(s) => Some(s.engine.device()),
        None => load_config(store).ok().map(|c| c.device),
    };
    // Records with local changes sync has not taken yet: the base is what sync has of them
    // (or nothing), so a rejoin writes them.
    let pending = store.pending_changes()?;
    let (mut base, _) = prints(store)?;
    let view = synced.as_ref().map(|s| s.engine.view());
    for change in pending {
        match view.as_ref().and_then(|v| synced_print(v, change.id)) {
            Some(print) => base.insert(change.id, print),
            None => base.remove(&change.id),
        };
    }
    forget(store)?;
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

/// A vault that rejoined its account: `first_round` as for [`super::Enabled`].
pub struct Rejoined<T: Transport> {
    pub synced: Synced<T>,
    pub first_round: Result<RoundReport>,
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
) -> Result<Rejoined<T>> {
    if super::is_enabled(store)? {
        return Err(Error::Refused("sync is already on".into()));
    }
    let (header, account_key) = open_account(&transport, pin, unlock)?;
    if account_key.as_bytes() != store.account_key()?.as_bytes() {
        return Err(Error::AnotherAccount);
    }
    let base = load_base(store)?.unwrap_or_default();
    let (synced, first_round) = join_store(
        store,
        transport,
        keys,
        device_name,
        (secret_key, secret_key_id),
        &header,
        account_key,
        Some(base),
        wall_ms,
    )?;
    Ok(Rejoined {
        synced,
        first_round,
    })
}

/// What carrying over did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CarryReport {
    pub copied: usize,
    /// Items in Recently Deleted: they stay in the old file.
    pub trashed_left: usize,
    /// Items that could not be read: they stay in the old file.
    pub damaged: usize,
}

/// Copies the live items of `from` (with attachments) into `to`, as new records in new
/// vaults of the same names.
pub fn carry_over(from: &Store, to: &mut Store) -> Result<CarryReport> {
    let mut plan = ImportPlan::default();
    let mut report = CarryReport {
        trashed_left: from.deleted_items()?.len(),
        ..CarryReport::default()
    };
    for vault in from.vaults()? {
        let mut items = Vec::new();
        for e in from.list_items(Some(vault.id))? {
            let ItemEntry::Ok(item) = e else {
                report.damaged += 1;
                continue;
            };
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
    report.copied = plan.item_count();
    to.apply_import(&plan)?;
    Ok(report)
}

/// Leaves the current account (if any) and makes this device the main device of a new one,
/// with every key of the store replaced first. Replacing the keys is the step that can fail
/// on the store's content (an item that cannot be read): it runs first, in one transaction,
/// so on such a failure sync is as it was (review A1d-2 I7). The caller drops its old
/// [`Synced`] only on success; the Touch ID record must go once the keys were replaced
/// (the store's account key changed), whatever happens after.
#[allow(clippy::too_many_arguments)]
pub fn start_new_account<T: Transport>(
    store: &mut Store,
    transport: T,
    keys: &mut dyn DeviceKeyStore,
    device_name: &str,
    password: &str,
    kdf: KdfParams,
    wall_ms: u64,
) -> Result<Enabled<T>> {
    store.check_password(password)?;
    if !transport.headers()?.is_empty() {
        return Err(Error::Refused(
            "this location already holds a Keyorra account; choose an empty one".into(),
        ));
    }
    let device = load_config(store).ok().map(|c| c.device);
    store.rotate_keys(password)?;
    forget(store)?;
    if let Some(device) = device {
        keys.forget(&device);
    }
    enable(store, transport, keys, device_name, password, kdf, wall_ms)
}
