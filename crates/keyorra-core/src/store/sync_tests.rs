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
