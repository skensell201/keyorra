//! Plan A1d: two vault stores synced through an in-memory store of files.

use std::collections::BTreeSet;

use keyorra_core::crypto::KdfParams;
use keyorra_core::model::{Item, ItemKind};
use keyorra_core::store::Store;
use keyorra_sync::header::Header;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::transport::MemoryTransport;

use super::*;

const PW: &str = "correct horse battery";
const NOW_MS: u64 = 1_790_000_000_000;

struct Device {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
    synced: Synced<MemoryTransport>,
    keys: MemoryDeviceKeys,
}

fn titles(store: &Store) -> BTreeSet<String> {
    store
        .vaults()
        .unwrap()
        .iter()
        .flat_map(|v| store.list_items(Some(v.id)).unwrap())
        .filter_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) => Some(i.title),
            _ => None,
        })
        .collect()
}

/// The test header unlock: the real one refuses the cheap KDF parameters used here.
fn cheap_unlock(password: &'static str, sk: [u8; 16]) -> impl FnMut(&Header) -> Result<Key> {
    move |h: &Header| {
        let keys = derive_sync_keys(
            password,
            &h.salt,
            h.kdf,
            &SecretKey::from_bytes(sk),
            &h.account_id,
        )?;
        h.unwrap_account_key(&keys.kek)
    }
}

/// A store with a vault and an item, made the main device of a new account.
fn main_device(transport: &MemoryTransport) -> (Device, EmergencyKit) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    let mut store = Store::create(&path, PW, KdfParams::INSECURE_FAST).unwrap();
    let vault = store.create_vault("Personal").unwrap();
    store
        .save_item(&Item::new(vault.id, ItemKind::Login, "before sync", 1))
        .unwrap();
    let mut keys = MemoryDeviceKeys::default();
    let (synced, kit) = enable(
        &mut store,
        transport.clone(),
        &mut keys,
        "Main",
        PW,
        KdfParams::INSECURE_FAST,
        NOW_MS,
    )
    .unwrap();
    (
        Device {
            _dir: dir,
            path,
            store,
            synced,
            keys,
        },
        kit,
    )
}

fn joiner(transport: &MemoryTransport, kit: &EmergencyKit, pin: Option<RootPin>) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("join.db");
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let mut keys = MemoryDeviceKeys::default();
    let (store, synced) = join(
        &path,
        PW,
        KdfParams::INSECURE_FAST,
        &sk,
        &id,
        pin.as_ref(),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS,
    )
    .unwrap();
    Device {
        _dir: dir,
        path,
        store,
        synced,
        keys,
    }
}

fn round(d: &mut Device, at: u64) {
    d.synced.round(&mut d.store, at).unwrap();
}

/// Main device and an approved second device, in step.
fn pair() -> (MemoryTransport, Device, Device) {
    let transport = MemoryTransport::new();
    let (mut main, kit) = main_device(&transport);
    let pin = main.synced.root_pin();
    let mut laptop = joiner(&transport, &kit, Some(pin));
    round(&mut main, NOW_MS + 1);
    let code = laptop.synced.key_code();
    let id = laptop.synced.engine().device();
    main.synced.approve(id, &code, NOW_MS + 2).unwrap();
    for t in 3..6 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    (transport, main, laptop)
}

#[test]
fn enabling_writes_the_vault_and_a_new_device_joins_and_sees_it() {
    let (_t, main, laptop) = pair();
    assert!(is_enabled(&main.store).unwrap());
    assert!(is_enabled(&laptop.store).unwrap());
    assert_eq!(titles(&laptop.store), titles(&main.store));
    assert!(titles(&laptop.store).contains("before sync"));
    assert!(laptop.synced.engine().can_write());
}

#[test]
fn local_changes_travel_both_ways() {
    let (_t, mut main, mut laptop) = pair();
    let vault = laptop.store.vaults().unwrap()[0].id;
    let item = Item::new(vault, ItemKind::SecureNote, "from the laptop", 10);
    laptop.store.save_item(&item).unwrap();
    round(&mut laptop, NOW_MS + 10);
    round(&mut main, NOW_MS + 11);
    assert!(titles(&main.store).contains("from the laptop"));
    main.store.delete_item(item.id, 12).unwrap();
    round(&mut main, NOW_MS + 12);
    round(&mut laptop, NOW_MS + 13);
    assert!(!titles(&laptop.store).contains("from the laptop"));
    assert_eq!(laptop.store.deleted_items().unwrap().len(), 1);
    assert!(laptop.store.pending_changes().unwrap().is_empty());
}

#[test]
fn concurrent_edits_become_a_conflict_copy_in_both_stores() {
    let (_t, mut main, mut laptop) = pair();
    let vault = main.store.vaults().unwrap()[0].id;
    let id = main
        .store
        .list_items(Some(vault))
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) => Some(i.id),
            _ => None,
        })
        .unwrap();
    let mut a = main.store.get_item(id).unwrap();
    a.title = "edited on main".into();
    main.store.save_item(&a).unwrap();
    let mut b = laptop.store.get_item(id).unwrap();
    b.title = "edited on laptop".into();
    laptop.store.save_item(&b).unwrap();
    for t in 20..26 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    let seen = titles(&main.store);
    assert!(
        seen.contains("edited on main") && seen.contains("edited on laptop"),
        "{seen:?}"
    );
    assert_eq!(titles(&laptop.store), seen);
    let copies = main
        .store
        .list_items(Some(vault))
        .unwrap()
        .into_iter()
        .filter(|e| matches!(e, keyorra_core::store::ItemEntry::Ok(i) if i.conflict.is_some()))
        .count();
    assert_eq!(copies, 1);
}

#[test]
fn a_restart_resumes_from_the_store() {
    let (transport, mut main, mut laptop) = pair();
    let vault = laptop.store.vaults().unwrap()[0].id;
    laptop
        .store
        .save_item(&Item::new(vault, ItemKind::Login, "before restart", 30))
        .unwrap();
    round(&mut laptop, NOW_MS + 30);
    // The app quits; the store is opened again and unlocked.
    let Device {
        _dir, path, keys, ..
    } = laptop;
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    let synced = resume(&store, transport.clone(), &keys).unwrap();
    let mut laptop = Device {
        _dir,
        path,
        store,
        synced,
        keys,
    };
    // A change made right after unlock, while the engine reads its streams again.
    laptop
        .store
        .save_item(&Item::new(vault, ItemKind::Login, "after restart", 31))
        .unwrap();
    for t in 31..35 {
        round(&mut laptop, NOW_MS + t);
        round(&mut main, NOW_MS + t);
    }
    let seen = titles(&main.store);
    assert!(seen.contains("before restart") && seen.contains("after restart"));
    assert_eq!(titles(&laptop.store), seen);
    assert!(main
        .store
        .list_items(None)
        .unwrap()
        .iter()
        .all(|e| !matches!(e, keyorra_core::store::ItemEntry::Ok(i) if i.conflict.is_some())));
}

#[test]
fn vaults_created_while_synced_get_committed_ids() {
    let (_t, mut main, mut laptop) = pair();
    let id = main
        .synced
        .create_vault(&mut main.store, "Work", NOW_MS + 40)
        .unwrap();
    round(&mut main, NOW_MS + 41);
    round(&mut laptop, NOW_MS + 42);
    let names: BTreeSet<String> = laptop
        .store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert!(names.contains("Work"));
    assert!(laptop.store.vaults().unwrap().iter().any(|v| v.id == id));
}
