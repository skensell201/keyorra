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
    let Enabled {
        synced,
        kit,
        first_round,
        ..
    } = enable(
        &mut store,
        transport.clone(),
        &mut keys,
        "Main",
        PW,
        KdfParams::INSECURE_FAST,
        NOW_MS,
    )
    .unwrap();
    first_round.unwrap();
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
    let Joined {
        store,
        synced,
        first_round,
    } = join(
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
    first_round.unwrap();
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

// ---- data-safety review of A1d-1 ----

fn find(store: &Store, title: &str) -> Item {
    store
        .list_items(None)
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) if i.title == title => Some(i),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no item {title:?}"))
}

fn restart(d: Device, transport: &MemoryTransport) -> Device {
    let Device {
        _dir, path, keys, ..
    } = d;
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    let synced = resume(&store, transport.clone(), &keys).unwrap();
    Device {
        _dir,
        path,
        store,
        synced,
        keys,
    }
}

/// Review A1d C1: an edited item moved into a vault created in the same offline batch.
#[test]
fn review_a1d_c1_a_move_into_a_vault_made_in_the_same_batch_lands() {
    let (_t, mut main, mut laptop) = pair();
    let mut item = find(&laptop.store, "before sync");
    let att = laptop
        .store
        .add_attachment(item.id, "a.txt", b"bytes", 10)
        .unwrap();
    round(&mut laptop, NOW_MS + 10);
    // Offline: edit, new vault, move.
    item = laptop.store.get_item(item.id).unwrap();
    item.title = "moved".into();
    laptop.store.save_item(&item).unwrap();
    let work = laptop.store.create_vault("Work").unwrap();
    item.vault_id = work.id;
    laptop.store.save_item(&item).unwrap();
    for t in 11..15 {
        round(&mut laptop, NOW_MS + t);
        round(&mut main, NOW_MS + t);
    }
    for store in [&laptop.store, &main.store] {
        let got = find(store, "moved");
        assert_eq!(got.vault_id, work.id);
    }
    assert_eq!(&laptop.store.get_attachment(att.id).unwrap()[..], b"bytes");
    assert!(laptop.store.pending_changes().unwrap().is_empty());
}

/// Review A1d C3: the store keeps the key the engine chose; a vault sync cannot give a
/// usable key for is reported and skipped, and everything else is still shown.
#[test]
fn review_a1d_c3_show_uses_the_chosen_key_and_skips_what_fails() {
    use keyorra_sync::fold::{ItemView, VaultView};
    use keyorra_sync::payload::ItemPayload;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(&dir.path().join("s.db"), PW, KdfParams::INSECURE_FAST).unwrap();
    let account = store.account_key_copy().unwrap();
    let good = Uuid::from_bytes([1; 16]);
    let broken = Uuid::from_bytes([2; 16]);
    let good_key = keyorra_core::crypto::wrap_vault_key(&account, good, &Key::random());
    let vault = |key: Vec<u8>| VaultView {
        name: "V".into(),
        wrapped_key: key,
        deleted: false,
        revived: false,
        key_mismatch: true,
    };
    let mut view = View::default();
    // The view's top sibling carries garbage; the engine names the good key.
    view.vaults.insert(good, vault(vec![0xab; 72]));
    view.vaults.insert(broken, vault(vec![0xcd; 72]));
    let item = Item::new(good, ItemKind::Login, "shown", 1);
    view.items.insert(
        item.id,
        ItemView {
            state: ItemState::Live,
            vault_id: Some(good),
            payload: Some(ItemPayload {
                item_json: Zeroizing::new(serde_json::to_vec(&item).unwrap()),
                deleted_at: None,
                content_from: Default::default(),
            }),
        },
    );
    let chosen = |v: Uuid| (v == good).then(|| good_key.clone());
    let failed = show_view(&mut store, &view, &BTreeSet::new(), chosen, 0);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, broken);
    assert_eq!(store.get_item(item.id).unwrap().title, "shown");
}

/// Review A1d I1: while the engine reads its own stream again after a restart, the store
/// is not overwritten with the older versions other streams still show.
#[test]
fn review_a1d_i1_nothing_is_shown_while_rebuilding() {
    let (transport, mut main, mut laptop) = pair();
    let mut item = find(&laptop.store, "before sync");
    item.title = "laptop edit".into();
    laptop.store.save_item(&item).unwrap();
    round(&mut laptop, NOW_MS + 20);
    round(&mut main, NOW_MS + 21);
    let me = laptop.synced.engine().device();
    let own: Vec<u64> = transport
        .dump()
        .into_iter()
        .filter(|(d, _, _)| *d == me)
        .map(|(_, seq, _)| seq)
        .collect();
    let mut laptop = restart(laptop, &transport);
    // The store does not have the laptop's segments for a moment.
    let hidden = transport.deep_copy();
    for seq in &own {
        transport.remove_segment(&me, *seq);
    }
    let _ = laptop.synced.round(&mut laptop.store, NOW_MS + 22);
    assert_eq!(laptop.store.get_item(item.id).unwrap().title, "laptop edit");
    for f in hidden.segments(&me, 0).unwrap() {
        if let keyorra_sync::transport::Fetched::Ready(b) = f {
            let _ = transport.append(&b);
        }
    }
    for t in 23..27 {
        let _ = laptop.synced.round(&mut laptop.store, NOW_MS + t);
    }
    assert_eq!(laptop.store.get_item(item.id).unwrap().title, "laptop edit");
}

struct FailingOutbox;

impl OutboxStore for FailingOutbox {
    fn save(&mut self, _: &OutboxState) -> Result<()> {
        Err(Error::Transport("disk full".into()))
    }
}

/// Review A1d I3: an edit whose outbox save failed, then a crash, still reaches sync.
#[test]
fn review_a1d_i3_a_failed_outbox_save_and_a_crash_lose_nothing() {
    let (transport, mut main, mut laptop) = pair();
    laptop
        .synced
        .engine
        .set_outbox_store(Box::new(FailingOutbox));
    let mut item = find(&laptop.store, "before sync");
    item.title = "unsaved".into();
    laptop.store.save_item(&item).unwrap();
    let _ = laptop.synced.round(&mut laptop.store, NOW_MS + 30);
    assert!(!laptop.store.pending_changes().unwrap().is_empty());
    // Crash: whatever the engine held in memory is gone.
    let mut laptop = restart(laptop, &transport);
    for t in 31..36 {
        round(&mut laptop, NOW_MS + t);
        round(&mut main, NOW_MS + t);
    }
    assert_eq!(find(&main.store, "unsaved").id, item.id);
    assert!(laptop.store.pending_changes().unwrap().is_empty());
}

/// Review A1d I4: deleting a vault here that has items on another device is undone.
#[test]
fn review_a1d_i4_a_vault_delete_sync_refuses_is_undone() {
    let (transport, mut main, mut laptop) = pair();
    let v = main
        .synced
        .create_vault(&mut main.store, "Shared", NOW_MS + 40)
        .unwrap();
    for t in 41..44 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    // The laptop is closed; meanwhile the main device adds an item to the vault.
    let mut laptop = restart(laptop, &transport);
    main.store
        .save_item(&Item::new(v, ItemKind::Login, "added there", 45))
        .unwrap();
    round(&mut main, NOW_MS + 45);
    // Right after unlock, before the first round: the (empty here) vault is deleted.
    laptop.store.delete_vault(v, 46).unwrap();
    let report = laptop.synced.round(&mut laptop.store, NOW_MS + 46).unwrap();
    assert!(
        report.reverted.iter().any(|(c, _)| c.id == v),
        "{:?}",
        report.reverted
    );
    round(&mut laptop, NOW_MS + 47);
    assert!(laptop.store.vaults().unwrap().iter().any(|x| x.id == v));
    assert_eq!(find(&laptop.store, "added there").vault_id, v);
    assert!(laptop.store.pending_changes().unwrap().is_empty());
}

/// Review A1d I5: sync is on once the store committed it, even if the first round fails.
#[test]
fn review_a1d_i5_enable_succeeds_when_the_first_round_fails() {
    use keyorra_sync::faults::{Faults, Faulty};
    let memory = MemoryTransport::new();
    let faulty = Faulty::new(
        memory.clone(),
        Faults {
            fail_before_append: 100,
            ..Faults::NONE
        },
        1,
    );
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(&dir.path().join("m.db"), PW, KdfParams::INSECURE_FAST).unwrap();
    let mut keys = MemoryDeviceKeys::default();
    let enabled = enable(
        &mut store,
        faulty,
        &mut keys,
        "Main",
        PW,
        KdfParams::INSECURE_FAST,
        NOW_MS,
    )
    .unwrap();
    assert!(is_enabled(&store).unwrap());
    let mut synced = enabled.synced;
    synced.transport.set_faults(Faults::NONE);
    synced.round(&mut store, NOW_MS + 1).unwrap();
    let laptop = joiner(&memory, &enabled.kit, Some(synced.root_pin()));
    assert!(is_enabled(&laptop.store).unwrap());
}

struct BrokenKeys;

impl DeviceKeyStore for BrokenKeys {
    fn load(&self, _: &DeviceId) -> Option<ed25519_dalek::SigningKey> {
        None
    }
    fn store(
        &mut self,
        _: DeviceId,
        _: &ed25519_dalek::SigningKey,
    ) -> std::result::Result<(), String> {
        Err("keychain locked".into())
    }
    fn forget(&mut self, _: &DeviceId) {}
    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(BrokenKeys)
    }
}

/// Review A1d I5: a join that fails after creating its file leaves no file behind.
#[test]
fn review_a1d_i5_a_failed_join_leaves_no_file() {
    let transport = MemoryTransport::new();
    let (_main, kit) = main_device(&transport);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("join.db");
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let result = join(
        &path,
        PW,
        KdfParams::INSECURE_FAST,
        &sk,
        &id,
        None,
        transport,
        &mut BrokenKeys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS,
    );
    assert!(result.is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

// ---- setup code, turning sync off and on, other accounts (plan A1d-2) ----

fn item_id(store: &Store, title: &str) -> uuid::Uuid {
    store
        .list_items(None)
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            keyorra_core::store::ItemEntry::Ok(i) if i.title == title => Some(i.id),
            _ => None,
        })
        .unwrap()
}

fn retitle(store: &mut Store, old: &str, title: &str) {
    let mut item = store.get_item(item_id(store, old)).unwrap();
    item.title = title.into();
    store.save_item(&item).unwrap();
}

fn approve_all(main: &mut Device, other: &mut Device, from: u64) {
    round(main, from);
    let code = other.synced.key_code();
    let id = other.synced.engine().device();
    main.synced.approve(id, &code, from + 1).unwrap();
    for t in from + 2..from + 6 {
        round(main, t);
        round(other, t);
    }
}

#[test]
fn a_device_joins_with_the_setup_code_alone() {
    let transport = MemoryTransport::new();
    let (mut main, _kit) = main_device(&transport);
    let code = SetupCode::parse(&main.synced.setup_code().to_text()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let mut keys = MemoryDeviceKeys::default();
    let sk = *code.secret_key.as_bytes();
    let Joined {
        store,
        synced,
        first_round,
    } = join(
        &path,
        PW,
        KdfParams::INSECURE_FAST,
        &code.secret_key,
        &code.secret_key_id,
        Some(&code.pin),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, sk),
        NOW_MS,
    )
    .unwrap();
    first_round.unwrap();
    let mut laptop = Device {
        _dir: dir,
        path,
        store,
        synced,
        keys,
    };
    approve_all(&mut main, &mut laptop, NOW_MS + 1);
    assert!(titles(&laptop.store).contains("before sync"));
}

#[test]
fn turning_sync_off_keeps_everything_and_records_nothing() {
    let (_t, _main, mut laptop) = pair();
    let before = titles(&laptop.store);
    disable(&mut laptop.store, Some(laptop.synced), &mut laptop.keys).unwrap();
    assert_eq!(titles(&laptop.store), before);
    assert!(!is_enabled(&laptop.store).unwrap());
    let vault = laptop.store.vaults().unwrap()[0].id;
    laptop
        .store
        .save_item(&Item::new(vault, ItemKind::Login, "offline", 50))
        .unwrap();
    assert!(laptop.store.pending_changes().unwrap().is_empty());
    assert!(
        laptop.keys.0.lock().unwrap().is_empty(),
        "device key forgotten"
    );
}

#[test]
fn the_main_device_cannot_turn_sync_off_under_other_devices() {
    let (_t, mut main, _laptop) = pair();
    let synced = std::mem::replace(
        &mut main.synced,
        main_device(&MemoryTransport::new()).0.synced,
    );
    assert!(matches!(
        disable(&mut main.store, Some(synced), &mut main.keys),
        Err(Error::Refused(_))
    ));
}

#[test]
fn rejoining_merges_by_record_id_and_keeps_both_sides_of_a_double_edit() {
    let (transport, mut main, mut laptop) = pair();
    let vault = main.store.vaults().unwrap()[0].id;
    for title in ["only here", "both", "only there"] {
        main.store
            .save_item(&Item::new(vault, ItemKind::Login, title, 60))
            .unwrap();
    }
    for t in 60..64 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    let Device {
        _dir,
        path,
        mut store,
        synced,
        mut keys,
    } = laptop;
    disable(&mut store, Some(synced), &mut keys).unwrap();
    // While sync is off here: edits on both sides.
    retitle(&mut store, "only here", "only here, edited here");
    retitle(&mut store, "both", "both, edited here");
    retitle(&mut main.store, "both", "both, edited there");
    retitle(&mut main.store, "only there", "only there, edited there");
    round(&mut main, NOW_MS + 70);

    let kit = main.synced.emergency_kit();
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let synced = rejoin(
        &mut store,
        &sk,
        &id,
        Some(&main.synced.root_pin()),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS + 71,
    )
    .unwrap()
    .synced;
    let mut laptop = Device {
        _dir,
        path,
        store,
        synced,
        keys,
    };
    approve_all(&mut main, &mut laptop, NOW_MS + 72);
    for t in 80..84 {
        round(&mut main, NOW_MS + t);
        round(&mut laptop, NOW_MS + t);
    }
    let seen = titles(&main.store);
    for title in [
        "before sync",
        "only here, edited here",
        "only there, edited there",
        "both, edited there",
        "both, edited here",
    ] {
        assert!(seen.contains(title), "{title}: {seen:?}");
    }
    assert_eq!(titles(&laptop.store), seen);
    assert_eq!(seen.len(), 5, "nothing doubled: {seen:?}");
    let copy = laptop
        .store
        .get_item(item_id(&laptop.store, "both, edited here"))
        .unwrap();
    assert_eq!(
        copy.conflict.unwrap().of,
        item_id(&laptop.store, "both, edited there")
    );
    assert!(laptop.store.sealed_meta("sync-base").unwrap().is_none());
}

#[test]
fn a_vault_of_another_account_cannot_rejoin() {
    let (transport, main, _laptop) = pair();
    let (other, _) = main_device(&MemoryTransport::new());
    let Device {
        mut store,
        synced,
        mut keys,
        ..
    } = other;
    disable(&mut store, Some(synced), &mut keys).unwrap();
    let kit = main.synced.emergency_kit();
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let result = rejoin(
        &mut store,
        &sk,
        &id,
        None,
        transport,
        &mut keys,
        "Other",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS + 90,
    );
    assert!(matches!(result, Err(Error::Refused(_))));
}

#[test]
fn another_accounts_vault_is_carried_over_as_new_records() {
    let (_t, _main, mut laptop) = pair();
    let dir = tempfile::tempdir().unwrap();
    let mut old = Store::create(&dir.path().join("old.db"), PW, KdfParams::INSECURE_FAST).unwrap();
    let v = old.create_vault("Old Mac").unwrap();
    let item = Item::new(v.id, ItemKind::SecureNote, "carried", 1);
    old.save_item(&item).unwrap();
    old.add_attachment(item.id, "a.txt", b"bytes", 2).unwrap();
    assert_eq!(carry_over(&old, &mut laptop.store).unwrap(), 1);
    for t in 100..104 {
        round(&mut laptop, NOW_MS + t);
    }
    let copied = laptop
        .store
        .get_item(item_id(&laptop.store, "carried"))
        .unwrap();
    assert_ne!(copied.id, item.id);
    assert_eq!(
        &laptop
            .store
            .get_attachment(copied.attachments[0].id)
            .unwrap()[..],
        b"bytes"
    );
}

#[test]
fn the_main_device_starts_a_new_account_with_new_keys() {
    let (_t, mut main, _laptop) = pair();
    let old_account = main.store.account_key_copy().unwrap();
    let fresh = MemoryTransport::new();
    let synced = std::mem::replace(
        &mut main.synced,
        main_device(&MemoryTransport::new()).0.synced,
    );
    let Enabled { synced, kit, .. } = start_new_account(
        &mut main.store,
        Some(synced),
        fresh.clone(),
        &mut main.keys,
        "Main",
        PW,
        KdfParams::INSECURE_FAST,
        NOW_MS + 110,
    )
    .unwrap();
    main.synced = synced;
    assert_ne!(
        main.store.account_key().unwrap().as_bytes(),
        old_account.as_bytes()
    );
    let mut newcomer = joiner(&fresh, &kit, Some(main.synced.root_pin()));
    approve_all(&mut main, &mut newcomer, NOW_MS + 111);
    assert_eq!(titles(&newcomer.store), titles(&main.store));
    assert!(titles(&newcomer.store).contains("before sync"));
}

/// An edit not synced yet when sync is turned off is written when the vault rejoins (it is
/// not mistaken for what the account already had).
#[test]
fn an_unsynced_edit_survives_turning_sync_off_and_rejoining() {
    let (transport, mut main, laptop) = pair();
    let Device {
        _dir,
        path,
        mut store,
        synced,
        mut keys,
    } = laptop;
    retitle(
        &mut store,
        "before sync",
        "edited just before turning sync off",
    );
    disable(&mut store, Some(synced), &mut keys).unwrap();
    let kit = main.synced.emergency_kit();
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let synced = rejoin(
        &mut store,
        &sk,
        &id,
        Some(&main.synced.root_pin()),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS + 120,
    )
    .unwrap()
    .synced;
    let mut laptop = Device {
        _dir,
        path,
        store,
        synced,
        keys,
    };
    approve_all(&mut main, &mut laptop, NOW_MS + 121);
    assert!(titles(&main.store).contains("edited just before turning sync off"));
    assert_eq!(titles(&laptop.store), titles(&main.store));
}

/// The conflict copy made when rejoining keeps the local version's attachments.
#[test]
fn a_rejoin_conflict_copy_keeps_its_attachments() {
    let (transport, mut main, laptop) = pair();
    let Device {
        _dir,
        path,
        mut store,
        synced,
        mut keys,
    } = laptop;
    disable(&mut store, Some(synced), &mut keys).unwrap();
    let local = item_id(&store, "before sync");
    store
        .add_attachment(local, "mine.txt", b"local bytes", 130)
        .unwrap();
    retitle(&mut store, "before sync", "edited here");
    retitle(&mut main.store, "before sync", "edited there");
    round(&mut main, NOW_MS + 131);
    let kit = main.synced.emergency_kit();
    let (id, sk) = SecretKey::parse(&kit.secret_key).unwrap();
    let synced = rejoin(
        &mut store,
        &sk,
        &id,
        Some(&main.synced.root_pin()),
        transport.clone(),
        &mut keys,
        "Laptop",
        cheap_unlock(PW, *sk.as_bytes()),
        NOW_MS + 132,
    )
    .unwrap()
    .synced;
    let mut laptop = Device {
        _dir,
        path,
        store,
        synced,
        keys,
    };
    approve_all(&mut main, &mut laptop, NOW_MS + 133);
    let copy = laptop
        .store
        .get_item(item_id(&laptop.store, "edited here"))
        .unwrap();
    assert_eq!(copy.attachments.len(), 1);
    assert_eq!(
        &laptop.store.get_attachment(copy.attachments[0].id).unwrap()[..],
        b"local bytes"
    );
}
