use super::*;
use crate::Error;

pub(super) const PW: &str = "correct horse";

pub(super) fn new_store() -> (tempfile::TempDir, PathBuf, Store) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    let store = Store::create(&path, PW, KdfParams::INSECURE_FAST).unwrap();
    (dir, path, store)
}

#[test]
fn reopened_store_is_locked_until_unlocked() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(!store.is_unlocked());
    assert!(matches!(store.vaults(), Err(Error::Locked)));
    assert!(matches!(store.unlock("wrong"), Err(Error::WrongPassword)));
    store.unlock(PW).unwrap();
    let names: Vec<_> = store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Personal"]);
}

#[test]
fn create_refuses_existing_file() {
    let (_dir, path, _store) = new_store();
    assert!(matches!(
        Store::create(&path, PW, KdfParams::INSECURE_FAST),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn open_missing_file_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Store::open(&dir.path().join("nope.db")),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn lock_forgets_keys() {
    let (_dir, _path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    store.lock();
    assert!(!store.is_unlocked());
    assert!(matches!(store.vaults(), Err(Error::Locked)));
    assert!(matches!(store.create_vault("x"), Err(Error::Locked)));
}

#[test]
fn change_password_persists() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    assert!(matches!(
        store.change_password("wrong", "new pw"),
        Err(Error::WrongPassword)
    ));
    store.change_password(PW, "new pw").unwrap();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(matches!(store.unlock(PW), Err(Error::WrongPassword)));
    store.unlock("new pw").unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}

#[test]
fn unlock_with_account_key_for_touch_id() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let account = store.account_key().unwrap().clone();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(matches!(store.account_key(), Err(Error::Locked)));
    assert!(matches!(
        store.unlock_with_key(Key::random()),
        Err(Error::WrongPassword)
    ));
    store.unlock_with_key(account).unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}

#[test]
fn vault_names_are_not_stored_in_plaintext() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("SuperSecretVaultName").unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(20).any(|w| w == b"SuperSecretVaultName"));
}

#[test]
fn newer_database_version_is_rejected() {
    let (_dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
}

#[test]
fn backup_copies_the_file_next_to_itself() {
    let (_dir, path, store) = new_store();
    drop(store);
    let copy = backup(&path, 1).unwrap();
    assert_eq!(copy, dir_path_join(&path, "keepsake.db.bak-v1"));
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&path).unwrap());
}

#[test]
fn open_rejects_empty_file_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.db");
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
    assert_eq!(std::fs::read(&path).unwrap(), b"");
}

#[test]
fn open_rejects_foreign_sqlite_database_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE other (x INTEGER);")
            .unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn create_with_invalid_kdf_params_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    let bad = KdfParams {
        m_kib: 8,
        t: 0,
        p: 1,
    };
    assert!(matches!(
        Store::create(&path, PW, bad),
        Err(Error::Invalid(_))
    ));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn created_database_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path, _store) = new_store();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn unlock_with_key_without_check_row_is_invalid() {
    let (_dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM meta WHERE key = 'check'", [])
        .unwrap();
    let mut store = Store::open(&path).unwrap();
    assert!(matches!(
        store.unlock_with_key(Key::random()),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn item_and_attachment_rows_carry_a_schema_column() {
    let (_dir, path, store) = new_store();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    for table in ["items", "attachments"] {
        conn.prepare(&format!("SELECT schema FROM {table}"))
            .unwrap();
    }
}

fn dir_path_join(path: &Path, name: &str) -> PathBuf {
    path.parent().unwrap().join(name)
}

#[test]
fn backup_name_appends_to_the_full_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    std::fs::write(&path, b"x").unwrap();
    assert_eq!(backup(&path, 2).unwrap(), dir.path().join("vault.bak-v2"));
}

#[test]
fn negative_user_version_is_rejected_without_backup() {
    let (dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", -1)
        .unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
    let files = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(files, 1, "no backup or other file should appear");
}

use crate::model::{Item, ItemKind};

pub(super) fn login(vault: Uuid, title: &str) -> Item {
    let mut item = Item::new(vault, ItemKind::Login, title, 1_000);
    item.set_password("hunter2", 1_000);
    item
}

fn revision(store: &Store, id: Uuid) -> i64 {
    store
        .conn
        .query_row(
            "SELECT revision FROM items WHERE id = ?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .unwrap()
}

/// (length of data, deleted, revision) of an attachment row.
fn attachment_row(store: &Store, id: Uuid) -> (i64, i64, i64) {
    store
        .conn
        .query_row(
            "SELECT length(data), deleted, revision FROM attachments WHERE id = ?1",
            [id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

fn ok_titles(entries: Vec<ItemEntry>) -> Vec<String> {
    entries
        .into_iter()
        .map(|e| match e {
            ItemEntry::Ok(item) => item.title,
            ItemEntry::Damaged { .. } => "<damaged>".into(),
        })
        .collect()
}

#[test]
fn save_get_and_list_items() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let github = login(a.id, "GitHub");
    store.save_item(&github).unwrap();
    store.save_item(&login(b.id, "Bank")).unwrap();

    assert_eq!(store.get_item(github.id).unwrap(), github);
    assert_eq!(ok_titles(store.list_items(Some(a.id)).unwrap()), ["GitHub"]);
    assert_eq!(
        ok_titles(store.list_items(None).unwrap()),
        ["GitHub", "Bank"]
    );
}

#[test]
fn saving_again_bumps_revision() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let mut item = login(v.id, "GitHub");
    store.save_item(&item).unwrap();
    assert_eq!(revision(&store, item.id), 1);
    item.set_password("new", 2_000);
    store.save_item(&item).unwrap();
    assert_eq!(revision(&store, item.id), 2);
    assert_eq!(store.get_item(item.id).unwrap().password(), Some("new"));
}

#[test]
fn save_requires_unlock_and_known_vault() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    assert!(matches!(
        store.save_item(&login(Uuid::new_v4(), "x")),
        Err(Error::NotFound(_))
    ));
    store.lock();
    assert!(matches!(
        store.save_item(&login(v.id, "x")),
        Err(Error::Locked)
    ));
}

#[test]
fn delete_restore_and_purge() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "GitHub");
    store.save_item(&item).unwrap();

    store.delete_item(item.id, 10_000).unwrap();
    assert!(matches!(store.get_item(item.id), Err(Error::NotFound(_))));
    assert!(store.list_items(None).unwrap().is_empty());
    assert_eq!(ok_titles(store.deleted_items().unwrap()), ["GitHub"]);

    store.restore_item(item.id).unwrap();
    assert_eq!(store.get_item(item.id).unwrap().title, "GitHub");

    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    assert_eq!(revision(&store, item.id), 4);
    store.delete_item(item.id, 10_000).unwrap();
    assert_eq!(revision(&store, item.id), 5);
    store.restore_item(item.id).unwrap();
    assert_eq!(revision(&store, item.id), 6);
    store.delete_item(item.id, 10_000).unwrap();
    assert_eq!(revision(&store, item.id), 7);
    assert_eq!(
        store
            .purge_expired(10_000 + DELETED_RETENTION_SECS - 1)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .purge_expired(10_000 + DELETED_RETENTION_SECS)
            .unwrap(),
        1
    );
    assert_eq!(revision(&store, item.id), 8);
    assert!(matches!(
        store.get_attachment(att.id),
        Err(Error::NotFound(_))
    ));
    assert_eq!(attachment_row(&store, att.id), (0, 1, 2));
    assert!(store.deleted_items().unwrap().is_empty());
    assert!(matches!(
        store.restore_item(item.id),
        Err(Error::NotFound(_))
    ));
    // The tombstone row stays for future sync.
    let rows: i64 = store
        .conn
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn delete_unknown_item_is_not_found() {
    let (_dir, _path, mut store) = new_store();
    assert!(matches!(
        store.delete_item(Uuid::new_v4(), 1),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn corrupted_row_is_reported_damaged_without_hiding_others() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let good = login(v.id, "Good");
    let bad = login(v.id, "Bad");
    store.save_item(&good).unwrap();
    store.save_item(&bad).unwrap();
    store
        .conn
        .execute(
            "UPDATE items SET data = X'00112233' WHERE id = ?1",
            [bad.id.to_string()],
        )
        .unwrap();

    let entries = store.list_items(None).unwrap();
    assert_eq!(entries[0], ItemEntry::Ok(good));
    assert_eq!(
        entries[1],
        ItemEntry::Damaged {
            id: bad.id,
            vault_id: v.id
        }
    );
    assert!(matches!(store.get_item(bad.id), Err(Error::Decrypt)));
}

#[test]
fn ciphertext_swapped_between_items_does_not_decrypt() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let a = login(v.id, "A");
    let b = login(v.id, "B");
    store.save_item(&a).unwrap();
    store.save_item(&b).unwrap();
    store
        .conn
        .execute(
            "UPDATE items SET data = (SELECT data FROM items WHERE id = ?1) WHERE id = ?2",
            [a.id.to_string(), b.id.to_string()],
        )
        .unwrap();
    assert!(matches!(store.get_item(b.id), Err(Error::Decrypt)));
}

#[test]
fn item_contents_are_not_stored_in_plaintext() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    store.save_item(&login(v.id, "VerySecretTitle")).unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    for needle in [&b"VerySecretTitle"[..], b"hunter2"] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle));
    }
}

#[test]
fn stored_schema_feeds_the_item_aad() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "GitHub");
    store.save_item(&item).unwrap();
    store
        .conn
        .execute(
            "UPDATE items SET schema = 2 WHERE id = ?1",
            [item.id.to_string()],
        )
        .unwrap();
    assert!(matches!(store.get_item(item.id), Err(Error::Decrypt)));
    assert!(matches!(
        store.list_items(None).unwrap()[0],
        ItemEntry::Damaged { .. }
    ));
}

#[test]
fn attachments_round_trip_and_are_listed_on_the_item() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();

    let att = store
        .add_attachment(item.id, "scan.pdf", b"%PDF-SECRET", 5_000)
        .unwrap();
    assert_eq!(att.name, "scan.pdf");
    assert_eq!(att.size, 11);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"%PDF-SECRET");
    let saved = store.get_item(item.id).unwrap();
    assert_eq!(saved.attachments, vec![att]);
    assert_eq!(saved.updated_at, 5_000);
    drop(store);

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(11).any(|w| w == b"%PDF-SECRET"));
}

#[test]
fn unknown_attachment_is_not_found() {
    let (_dir, _path, store) = new_store();
    assert!(matches!(
        store.get_attachment(Uuid::new_v4()),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn moving_an_item_to_another_vault_keeps_attachments_readable() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = login(a.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();

    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    store.save_item(&moved).unwrap();

    assert_eq!(store.get_item(item.id).unwrap().vault_id, b.id);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"bytes");
}

#[test]
fn attachment_of_a_deleted_item_is_not_served_until_restored() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    store.delete_item(item.id, 6_000).unwrap();
    assert!(matches!(
        store.get_attachment(att.id),
        Err(Error::NotFound(_))
    ));
    store.restore_item(item.id).unwrap();
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"bytes");
}

#[test]
fn locked_store_reports_locked_for_attachments() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    store.lock();
    assert!(matches!(store.get_attachment(att.id), Err(Error::Locked)));
    assert!(matches!(
        store.get_attachment(Uuid::new_v4()),
        Err(Error::Locked)
    ));
}

#[test]
fn saving_a_stale_copy_keeps_stored_attachments() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();
    let mut stale = store.get_item(item.id).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    stale.title = "Renamed".into();
    store.save_item(&stale).unwrap();
    let saved = store.get_item(item.id).unwrap();
    assert_eq!(saved.title, "Renamed");
    assert_eq!(saved.attachments, vec![att.clone()]);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"bytes");
}

#[test]
fn saving_fabricated_attachment_refs_does_not_store_them() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let fake = || crate::model::AttachmentRef {
        id: Uuid::new_v4(),
        name: "x".into(),
        size: 1,
    };
    let mut fresh = login(v.id, "New");
    fresh.attachments.push(fake());
    store.save_item(&fresh).unwrap();
    assert!(store.get_item(fresh.id).unwrap().attachments.is_empty());

    let mut existing = store.get_item(fresh.id).unwrap();
    existing.attachments.push(fake());
    store.save_item(&existing).unwrap();
    assert!(store.get_item(fresh.id).unwrap().attachments.is_empty());
}

#[test]
fn saving_over_a_damaged_row_is_refused() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Bad");
    store.save_item(&item).unwrap();
    store
        .conn
        .execute(
            "UPDATE items SET data = X'00112233' WHERE id = ?1",
            [item.id.to_string()],
        )
        .unwrap();
    assert!(matches!(store.save_item(&item), Err(Error::Decrypt)));
}

#[test]
fn removed_attachment_is_tombstoned_and_unlisted() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    store.remove_attachment(item.id, att.id, 7_000).unwrap();
    assert!(matches!(
        store.get_attachment(att.id),
        Err(Error::NotFound(_))
    ));
    let saved = store.get_item(item.id).unwrap();
    assert!(saved.attachments.is_empty());
    assert_eq!(saved.updated_at, 7_000);
    assert_eq!(attachment_row(&store, att.id), (0, 1, 2));
    assert!(matches!(
        store.remove_attachment(item.id, att.id, 8_000),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.remove_attachment(item.id, Uuid::new_v4(), 8_000),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn failed_vault_move_rolls_back_completely() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = login(a.id, "Passport");
    store.save_item(&item).unwrap();
    let first = store.add_attachment(item.id, "one", b"one", 5_000).unwrap();
    let second = store.add_attachment(item.id, "two", b"two", 5_001).unwrap();
    store
        .conn
        .execute(
            "UPDATE attachments SET data = X'00112233' WHERE id = ?1",
            [second.id.to_string()],
        )
        .unwrap();

    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    assert!(matches!(store.save_item(&moved), Err(Error::Decrypt)));

    assert_eq!(store.get_item(item.id).unwrap().vault_id, a.id);
    assert_eq!(&*store.get_attachment(first.id).unwrap(), b"one");
}

#[test]
fn vault_move_bumps_item_and_attachment_revisions() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = login(a.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    assert_eq!(attachment_row(&store, att.id).2, 1);
    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    store.save_item(&moved).unwrap();
    assert_eq!(attachment_row(&store, att.id).2, 2);
    assert_eq!(revision(&store, item.id), 3);
}

#[test]
fn saving_over_a_purged_tombstone_is_not_found() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Gone");
    store.save_item(&item).unwrap();
    store.delete_item(item.id, 10_000).unwrap();
    store
        .purge_expired(10_000 + DELETED_RETENTION_SECS)
        .unwrap();
    let before = revision(&store, item.id);
    assert!(matches!(store.save_item(&item), Err(Error::NotFound(_))));
    assert_eq!(revision(&store, item.id), before);
    let len: i64 = store
        .conn
        .query_row(
            "SELECT length(data) FROM items WHERE id = ?1",
            [item.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(len, 0);
}

#[test]
fn removing_an_attachment_whose_row_is_missing_still_drops_the_ref() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store
        .add_attachment(item.id, "scan.pdf", b"bytes", 5_000)
        .unwrap();
    store
        .conn
        .execute(
            "DELETE FROM attachments WHERE id = ?1",
            [att.id.to_string()],
        )
        .unwrap();
    store.remove_attachment(item.id, att.id, 7_000).unwrap();
    let saved = store.get_item(item.id).unwrap();
    assert!(saved.attachments.is_empty());
    assert_eq!(saved.updated_at, 7_000);
}

use crate::import::{ImportPlan, ImportReport, ImportedItem, ImportedVault};

fn sample_plan() -> ImportPlan {
    let note = Item::new(Uuid::nil(), ItemKind::SecureNote, "Passport", 1);
    ImportPlan {
        vaults: vec![
            ImportedVault {
                name: "Personal".into(),
                items: vec![
                    ImportedItem {
                        item: login(Uuid::nil(), "GitHub"),
                        attachments: vec![],
                    },
                    ImportedItem {
                        item: note,
                        attachments: vec![("scan.pdf".into(), b"PDF".to_vec())],
                    },
                ],
            },
            ImportedVault {
                name: "Datagile".into(),
                items: vec![ImportedItem {
                    item: login(Uuid::nil(), "Jira"),
                    attachments: vec![],
                }],
            },
        ],
        skipped: vec![],
    }
}

#[test]
fn apply_import_creates_vaults_items_and_attachments() {
    let (_dir, _path, mut store) = new_store();
    let report = store.apply_import(&sample_plan()).unwrap();
    assert_eq!(
        report,
        ImportReport {
            vaults: 2,
            items: 3,
            attachments: 1
        }
    );

    let vaults = store.vaults().unwrap();
    let names: Vec<_> = vaults.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["Personal", "Datagile"]);
    assert_eq!(
        ok_titles(store.list_items(Some(vaults[0].id)).unwrap()),
        ["GitHub", "Passport"]
    );
    assert_eq!(
        ok_titles(store.list_items(Some(vaults[1].id)).unwrap()),
        ["Jira"]
    );

    let passport = match &store.list_items(Some(vaults[0].id)).unwrap()[1] {
        ItemEntry::Ok(item) => item.clone(),
        other => panic!("{other:?}"),
    };
    assert_ne!(passport.id, Uuid::nil());
    assert_eq!(passport.vault_id, vaults[0].id);
    assert_eq!(
        &*store.get_attachment(passport.attachments[0].id).unwrap(),
        b"PDF"
    );
}

#[test]
fn apply_import_requires_unlock() {
    let (_dir, _path, mut store) = new_store();
    store.lock();
    assert!(matches!(
        store.apply_import(&sample_plan()),
        Err(Error::Locked)
    ));
}

#[test]
fn failed_import_writes_nothing() {
    let (_dir, _path, mut store) = new_store();
    store.conn.execute_batch("DROP TABLE attachments").unwrap();
    assert!(store.apply_import(&sample_plan()).is_err());
    assert!(store.vaults().unwrap().is_empty());
    let items: i64 = store
        .conn
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(items, 0);
}

#[test]
fn apply_import_skips_vaults_without_items() {
    let (_dir, _path, mut store) = new_store();
    let mut plan = sample_plan();
    plan.vaults.insert(
        1,
        ImportedVault {
            name: "Empty".into(),
            items: vec![],
        },
    );
    let report = store.apply_import(&plan).unwrap();
    assert_eq!(report.vaults, 2);
    let vaults = store.vaults().unwrap();
    let names: Vec<_> = vaults.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["Personal", "Datagile"]);
}

#[test]
fn delete_and_restore_require_unlock() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let kept = login(v.id, "Kept");
    let trashed = login(v.id, "Trashed");
    store.save_item(&kept).unwrap();
    store.save_item(&trashed).unwrap();
    store.delete_item(trashed.id, 10).unwrap();
    store.lock();

    assert!(matches!(store.delete_item(kept.id, 20), Err(Error::Locked)));
    assert!(matches!(store.restore_item(trashed.id), Err(Error::Locked)));
}

#[test]
fn sealed_meta_round_trips_and_needs_unlock() {
    let (_dir, _path, mut store) = new_store();
    assert!(store.sealed_meta("bridge.pairings").unwrap().is_none());
    store
        .set_sealed_meta("bridge.pairings", b"[secret]")
        .unwrap();
    assert_eq!(
        &**store.sealed_meta("bridge.pairings").unwrap().unwrap(),
        b"[secret]"
    );
    store.set_sealed_meta("bridge.pairings", b"[v2]").unwrap();
    assert_eq!(
        &**store.sealed_meta("bridge.pairings").unwrap().unwrap(),
        b"[v2]"
    );
    store.lock();
    assert!(matches!(
        store.sealed_meta("bridge.pairings"),
        Err(Error::Locked)
    ));
    assert!(matches!(
        store.set_sealed_meta("x", b"y"),
        Err(Error::Locked)
    ));
}

#[test]
fn sealed_meta_is_bound_to_its_name_and_not_plaintext() {
    let (_dir, path, mut store) = new_store();
    store.set_sealed_meta("a", b"TopSecretBlob").unwrap();
    store
        .conn
        .execute(
            "INSERT INTO meta (key, value) SELECT 'sealed:b', value FROM meta WHERE key = 'sealed:a'",
            [],
        )
        .unwrap();
    assert!(matches!(store.sealed_meta("b"), Err(Error::Decrypt)));
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(13).any(|w| w == b"TopSecretBlob"));
}

#[test]
fn open_rejects_a_file_that_is_not_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    std::fs::write(&path, b"this is a text file, not a database at all.......").unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
}

#[test]
fn open_rejects_a_damaged_header() {
    let (_dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE meta SET value = X'7B' WHERE key = 'header'", [])
        .unwrap();
    assert!(matches!(Store::open(&path), Err(Error::NotADatabase(_))));
}

#[test]
fn rename_vault_keeps_its_items() {
    let (_dir, path, mut store) = new_store();
    let vault = store.create_vault("Personal").unwrap();
    store.save_item(&login(vault.id, "GitHub")).unwrap();
    let renamed = store.rename_vault(vault.id, "Home").unwrap();
    assert_eq!(renamed.name, "Home");
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.vaults().unwrap()[0].name, "Home");
    assert_eq!(store.list_items(Some(vault.id)).unwrap().len(), 1);
    assert!(matches!(
        store.rename_vault(Uuid::new_v4(), "x"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn delete_vault_refuses_live_items_and_purges_its_trash() {
    let (_dir, _path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let old = store.create_vault("Old").unwrap();
    let item = login(old.id, "Forum");
    store.save_item(&item).unwrap();
    assert!(matches!(
        store.delete_vault(old.id, 1_000),
        Err(Error::Invalid(_))
    ));
    store.delete_item(item.id, 1_000).unwrap();
    store.delete_vault(old.id, 2_000).unwrap();
    let names: Vec<_> = store
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert!(
        store.deleted_items().unwrap().is_empty(),
        "its trash is purged"
    );
    assert!(matches!(
        store.restore_item(item.id),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        store.delete_vault(old.id, 3_000),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn deleted_vault_does_not_break_unlock() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let old = store.create_vault("Old").unwrap();
    store.delete_vault(old.id, 1_000).unwrap();
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.unlock(PW).unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}

#[test]
fn save_item_refuses_a_deleted_vault() {
    let (_dir, _path, mut store) = new_store();
    let keep = store.create_vault("Personal").unwrap();
    let old = store.create_vault("Old").unwrap();
    let moved = login(keep.id, "GitHub");
    store.save_item(&moved).unwrap();
    store.delete_vault(old.id, 1_000).unwrap();

    // The deleted vault's key stays loaded (for tombstones), but nothing new may land there.
    assert!(matches!(
        store.save_item(&login(old.id, "Late")),
        Err(Error::NotFound(_))
    ));
    let mut into_old = moved.clone();
    into_old.vault_id = old.id;
    assert!(matches!(
        store.save_item(&into_old),
        Err(Error::NotFound(_))
    ));
    assert!(store.list_items(Some(old.id)).unwrap().is_empty());
    assert_eq!(store.get_item(moved.id).unwrap().vault_id, keep.id);
}
