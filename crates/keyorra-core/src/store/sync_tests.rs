//! Plan A1d: the store's side of sync (migration v2, the single change path, remote applies).

use std::collections::BTreeMap;

use super::tests::{new_store, PW};
use super::*;
use crate::model::ItemKind;

fn changes(store: &Store) -> Vec<Change> {
    store.pending_changes().unwrap()
}

fn item_change(id: Uuid) -> Change {
    Change {
        kind: ChangeKind::Item,
        id,
    }
}

fn vault_change(id: Uuid) -> Change {
    Change {
        kind: ChangeKind::Vault,
        id,
    }
}

#[test]
fn version_1_databases_migrate_to_2_with_sync_tables() {
    let (_dir, path, store) = new_store();
    drop(store);
    // Downgrade the file to version 1 as an older app left it.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE sync_changes; DROP TABLE sync_segments;")
        .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    store.set_sync_tracking(true).unwrap();
    let v = store.create_vault("Personal").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    assert!(sibling(&path, ".bak-v1").exists());
}

#[test]
fn nothing_is_recorded_while_sync_is_off() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    store
        .save_item(&Item::new(v.id, ItemKind::Login, "x", 1))
        .unwrap();
    assert!(changes(&store).is_empty());
    assert!(!store.sync_tracking().unwrap());
}

#[test]
fn every_mutating_method_records_its_records() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let v = store.create_vault("Personal").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.rename_vault(v.id, "Home").unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let item = Item::new(v.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let att = store.add_attachment(item.id, "f.txt", b"hi", 2).unwrap();
    let mut got = changes(&store);
    got.sort();
    let mut want = vec![
        item_change(item.id),
        Change {
            kind: ChangeKind::Attachment,
            id: att.id,
        },
    ];
    want.sort();
    assert_eq!(got, want);
    store.clear_changes(&changes(&store)).unwrap();

    store.remove_attachment(item.id, att.id, 3).unwrap();
    assert_eq!(changes(&store).len(), 2);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_item(item.id, 4).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.restore_item(item.id).unwrap();
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_item(item.id, 5).unwrap();
    store.clear_changes(&changes(&store)).unwrap();
    assert_eq!(store.purge_expired(5 + DELETED_RETENTION_SECS).unwrap(), 1);
    assert_eq!(changes(&store), vec![item_change(item.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    store.delete_vault(v.id, 6).unwrap();
    assert_eq!(changes(&store), vec![vault_change(v.id)]);
    store.clear_changes(&changes(&store)).unwrap();

    let plan = crate::import::ImportPlan {
        vaults: vec![crate::import::ImportedVault {
            name: "Imported".into(),
            items: vec![crate::import::ImportedItem {
                item: Item::new(Uuid::nil(), ItemKind::SecureNote, "n", 1),
                attachments: vec![],
            }],
        }],
        ..Default::default()
    };
    store.apply_import(&plan).unwrap();
    let kinds: Vec<ChangeKind> = changes(&store).into_iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&ChangeKind::Vault) && kinds.contains(&ChangeKind::Item));
}

#[test]
fn remote_applies_record_nothing_and_round_trip() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let vault = Uuid::from_bytes([1; 16]);
    let key = Key::random();
    let wrapped = crypto::wrap_vault_key(store.account_key().unwrap(), vault, &key);
    store
        .apply_remote_vault(vault, "Shared", &wrapped, false)
        .unwrap();
    let mut item = Item::new(vault, ItemKind::Login, "from elsewhere", 1);
    store.apply_remote_item(&item, None).unwrap();
    assert!(changes(&store).is_empty());
    assert_eq!(store.get_item(item.id).unwrap(), item);
    // Trashed remotely, then restored, then edited.
    store.apply_remote_item(&item, Some(9)).unwrap();
    assert!(store.get_item(item.id).is_err());
    assert_eq!(store.deleted_items().unwrap().len(), 1);
    item.title = "edited".into();
    store.apply_remote_item(&item, None).unwrap();
    assert_eq!(store.get_item(item.id).unwrap().title, "edited");
    store.apply_remote_purge(item.id).unwrap();
    assert!(store.get_item(item.id).is_err());
    assert!(store.deleted_items().unwrap().is_empty());
    store
        .apply_remote_vault(vault, "Shared", &wrapped, true)
        .unwrap();
    assert!(store.vaults().unwrap().is_empty());
    assert!(changes(&store).is_empty());
}

#[test]
fn kept_segments_and_sync_blobs_persist() {
    let (_dir, path, mut store) = new_store();
    let segs: BTreeMap<u64, Vec<u8>> = [(1, vec![1, 2]), (4, vec![3])].into_iter().collect();
    store.set_own_segments(&segs).unwrap();
    store.set_sealed_meta("sync:memo", b"memo").unwrap();
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.own_segments().unwrap(), segs);
    assert_eq!(
        &store.sealed_meta("sync:memo").unwrap().unwrap()[..],
        b"memo"
    );
}

#[test]
fn a_joining_device_creates_its_store_with_the_accounts_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.db");
    let account = Key::from_bytes([7; 32]);
    let store =
        Store::create_with_account_key(&path, PW, KdfParams::INSECURE_FAST, account).unwrap();
    assert_eq!(store.account_key().unwrap().as_bytes(), &[7; 32]);
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.account_key().unwrap().as_bytes(), &[7; 32]);
}

#[test]
fn the_meta_writer_writes_what_the_store_reads() {
    let (_dir, _path, store) = new_store();
    let writer = store.meta_writer().unwrap();
    writer.set_sealed_meta("sync:outbox", b"state").unwrap();
    assert_eq!(
        &store.sealed_meta("sync:outbox").unwrap().unwrap()[..],
        b"state"
    );
}

/// Review A1d C1: a vault created offline must be written before the items moved into it,
/// whatever order their changes were first recorded in.
#[test]
fn vault_changes_come_before_item_changes() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let old = store.create_vault("Old").unwrap();
    let mut item = Item::new(old.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    store.clear_changes(&changes(&store)).unwrap();
    item.title = "edited".into();
    store.save_item(&item).unwrap();
    let new = store.create_vault("New").unwrap();
    item.vault_id = new.id;
    store.save_item(&item).unwrap();
    assert_eq!(
        changes(&store),
        vec![vault_change(new.id), item_change(item.id)]
    );
}

/// Review A1d C2: an item moved to another vault elsewhere keeps readable attachments here.
#[test]
fn a_remote_move_reencrypts_the_attachments() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = Item::new(a.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    let att = store.add_attachment(item.id, "f.txt", b"bytes", 2).unwrap();
    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    store.apply_remote_item(&moved, None).unwrap();
    assert_eq!(store.get_item(item.id).unwrap().vault_id, b.id);
    assert_eq!(&store.get_attachment(att.id).unwrap()[..], b"bytes");
}

/// Review A1d C3: what sync shows can rename or delete a vault, never change its key.
#[test]
fn an_existing_vaults_key_is_never_replaced_remotely() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    let item = Item::new(v.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    let account = store.account_key_copy().unwrap();
    let other = crypto::wrap_vault_key(&account, v.id, &Key::random());
    assert!(store
        .apply_remote_vault(v.id, "Personal", &other, false)
        .is_err());
    // The same key wrapped again (another nonce) is the same vault.
    let key = store.vault_rows().unwrap()[0].1.clone();
    let rewrapped = crypto::wrap_vault_key(&account, v.id, &key);
    store
        .apply_remote_vault(v.id, "Renamed", &rewrapped, false)
        .unwrap();
    assert!(store
        .apply_remote_vault(v.id, "Bad", &[0xab; 72], false)
        .is_err());
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.vaults().unwrap()[0].name, "Renamed");
    assert_eq!(store.get_item(item.id).unwrap().title, "x");
}

/// Review A1d I4: a live item shown in a vault deleted here brings the vault back.
#[test]
fn a_live_remote_item_revives_its_deleted_vault() {
    let (_dir, _path, mut store) = new_store();
    let keep = store.create_vault("Keep").unwrap();
    let v = store.create_vault("Gone").unwrap();
    store.delete_vault(v.id, 5).unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
    let item = Item::new(v.id, ItemKind::Login, "added elsewhere", 6);
    store.apply_remote_item(&item, None).unwrap();
    let names: Vec<String> = store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|x| x.name)
        .collect();
    assert!(names.contains(&"Gone".to_owned()) && names.contains(&keep.name));
    assert_eq!(store.get_item(item.id).unwrap().title, "added elsewhere");
}

/// A version 1 database as the released app wrote it (items, Recently Deleted, an
/// attachment, sealed meta) opens as version 2 with everything readable, and the backup is
/// the untouched version 1 file.
#[test]
fn a_real_version_1_database_migrates_with_everything() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    let live = Item::new(v.id, ItemKind::Login, "live", 1);
    store.save_item(&live).unwrap();
    let att = store.add_attachment(live.id, "a.txt", b"bytes", 2).unwrap();
    let trashed = Item::new(v.id, ItemKind::SecureNote, "trashed", 1);
    store.save_item(&trashed).unwrap();
    store.delete_item(trashed.id, 3).unwrap();
    store.set_sealed_meta("pairings", b"paired").unwrap();
    drop(store);
    // Exactly what version 1 had: no sync tables, user_version 1.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE sync_changes; DROP TABLE sync_segments;")
        .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let v1 = std::fs::read(&path).unwrap();

    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.get_item(live.id).unwrap().title, "live");
    assert_eq!(&store.get_attachment(att.id).unwrap()[..], b"bytes");
    assert_eq!(store.deleted_items().unwrap().len(), 1);
    assert_eq!(
        &store.sealed_meta("pairings").unwrap().unwrap()[..],
        b"paired"
    );
    assert!(store.pending_changes().unwrap().is_empty());
    assert_eq!(std::fs::read(sibling(&path, ".bak-v1")).unwrap(), v1);
}

#[test]
fn the_password_can_be_checked_without_locking() {
    let (_dir, _path, store) = new_store();
    store.check_password(PW).unwrap();
    assert!(matches!(
        store.check_password("wrong one"),
        Err(Error::WrongPassword)
    ));
    assert!(store.is_unlocked());
}

#[test]
fn changes_can_be_recorded_by_hand_and_meta_deleted() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let id = Uuid::from_bytes([3; 16]);
    store.record_changes(&[item_change(id)]).unwrap();
    assert_eq!(changes(&store), vec![item_change(id)]);
    store.set_sealed_meta("sync:config", b"x").unwrap();
    store.delete_sealed_meta("sync:config").unwrap();
    assert!(store.sealed_meta("sync:config").unwrap().is_none());
}

#[test]
fn rotating_the_keys_keeps_every_record_and_drops_the_old_keys() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    let live = Item::new(v.id, ItemKind::Login, "live", 1);
    store.save_item(&live).unwrap();
    let att = store.add_attachment(live.id, "a.txt", b"bytes", 2).unwrap();
    let trashed = Item::new(v.id, ItemKind::Login, "trashed", 1);
    store.save_item(&trashed).unwrap();
    store.delete_item(trashed.id, 3).unwrap();
    store.set_sealed_meta("pairings", b"kept").unwrap();
    let old_account = store.account_key_copy().unwrap();
    let old_vault_key = store.vault_rows().unwrap()[0].1.clone();

    store.rotate_keys(PW).unwrap();

    assert_ne!(
        store.account_key().unwrap().as_bytes(),
        old_account.as_bytes()
    );
    assert_ne!(
        store.vault_rows().unwrap()[0].1.as_bytes(),
        old_vault_key.as_bytes()
    );
    drop(store);
    let mut store = Store::open(&path).unwrap();
    assert!(store.unlock_with_key(old_account).is_err());
    store.unlock(PW).unwrap();
    assert_eq!(store.get_item(live.id).unwrap().title, "live");
    assert_eq!(&store.get_attachment(att.id).unwrap()[..], b"bytes");
    assert_eq!(store.deleted_items().unwrap().len(), 1);
    assert_eq!(
        &store.sealed_meta("pairings").unwrap().unwrap()[..],
        b"kept"
    );
}

/// Review A1d-2 I7: an item that cannot be read stops the rotation before anything changes.
#[test]
fn rotation_stops_on_an_unreadable_item_and_changes_nothing() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("Personal").unwrap();
    let good = Item::new(v.id, ItemKind::Login, "good", 1);
    store.save_item(&good).unwrap();
    let bad = Item::new(v.id, ItemKind::Login, "bad", 1);
    store.save_item(&bad).unwrap();
    let account = store.account_key_copy().unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE items SET data = X'00112233445566778899aabbccddeeff00112233445566778899' WHERE id = ?1",
        [bad.id.to_string()],
    )
    .unwrap();
    drop(conn);
    assert!(store.rotate_keys(PW).is_err());
    assert_eq!(store.account_key().unwrap().as_bytes(), account.as_bytes());
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.get_item(good.id).unwrap().title, "good");
}

/// Plan A2-2: attachment contents from sync, and what the sync layer reads of local ones.
#[test]
fn attachments_from_sync_are_stored_and_removed() {
    let (_dir, _path, mut store) = new_store();
    store.set_sync_tracking(true).unwrap();
    let v = store.create_vault("Personal").unwrap();
    let mut item = Item::new(v.id, ItemKind::Login, "x", 1);
    store.save_item(&item).unwrap();
    store.clear_changes(&changes(&store)).unwrap();
    let att = Uuid::from_bytes([9; 16]);
    item.attachments.push(crate::model::AttachmentRef {
        id: att,
        name: "a.txt".into(),
        size: 5,
        extra: Default::default(),
    });
    store.apply_remote_item(&item, None).unwrap();
    assert_eq!(store.attachment_state(att).unwrap(), None);
    store
        .apply_remote_attachment(att, item.id, b"bytes")
        .unwrap();
    store
        .apply_remote_attachment(att, item.id, b"bytes")
        .unwrap();
    assert_eq!(&store.get_attachment(att).unwrap()[..], b"bytes");
    let state = store.attachment_state(att).unwrap().unwrap();
    assert_eq!((state.item_id, state.live), (item.id, true));
    assert_eq!(&store.attachment_content(att).unwrap()[..], b"bytes");
    assert_eq!(store.attachment_ids().unwrap(), vec![att]);
    store.apply_remote_attachment_removed(att).unwrap();
    assert!(store.get_attachment(att).is_err());
    assert!(!store.attachment_state(att).unwrap().unwrap().live);
    assert!(store.attachment_ids().unwrap().is_empty());
    assert!(changes(&store).is_empty(), "nothing recorded");
    // A local attachment reads the same way.
    let local = store.add_attachment(item.id, "b.txt", b"local", 3).unwrap();
    assert_eq!(&store.attachment_content(local.id).unwrap()[..], b"local");
}
