use super::*;
use crate::Error;

pub(super) const PW: &str = "correct horse";

pub(super) fn new_store() -> (tempfile::TempDir, PathBuf, Store) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lockbox.db");
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
    let names: Vec<_> = store.vaults().unwrap().into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["Personal"]);
}

#[test]
fn create_refuses_existing_file() {
    let (_dir, path, _store) = new_store();
    assert!(matches!(Store::create(&path, PW, KdfParams::INSECURE_FAST), Err(Error::Invalid(_))));
}

#[test]
fn open_missing_file_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(Store::open(&dir.path().join("nope.db")), Err(Error::NotFound(_))));
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
    assert!(matches!(store.change_password("wrong", "new pw"), Err(Error::WrongPassword)));
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
    assert!(matches!(store.unlock_with_key(Key::random()), Err(Error::WrongPassword)));
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
    rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
}

#[test]
fn backup_copies_the_file_next_to_itself() {
    let (_dir, path, store) = new_store();
    drop(store);
    let copy = backup(&path, 1).unwrap();
    assert_eq!(copy, dir_path_join(&path, "lockbox.db.bak-v1"));
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&path).unwrap());
}

#[test]
fn open_rejects_empty_file_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.db");
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
    assert_eq!(std::fs::read(&path).unwrap(), b"");
}

#[test]
fn open_rejects_foreign_sqlite_database_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE other (x INTEGER);").unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn create_with_invalid_kdf_params_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lockbox.db");
    let bad = KdfParams { m_kib: 8, t: 0, p: 1 };
    assert!(matches!(Store::create(&path, PW, bad), Err(Error::Invalid(_))));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn created_database_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path, _store) = new_store();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
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
    assert!(matches!(store.unlock_with_key(Key::random()), Err(Error::Invalid(_))));
}

#[test]
fn item_and_attachment_rows_carry_a_schema_column() {
    let (_dir, path, store) = new_store();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    for table in ["items", "attachments"] {
        conn.prepare(&format!("SELECT schema FROM {table}")).unwrap();
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
    rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", -1).unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
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
        .query_row("SELECT revision FROM items WHERE id = ?1", [id.to_string()], |r| r.get(0))
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
    assert_eq!(ok_titles(store.list_items(None).unwrap()), ["GitHub", "Bank"]);
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
    assert!(matches!(store.save_item(&login(Uuid::new_v4(), "x")), Err(Error::NotFound(_))));
    store.lock();
    assert!(matches!(store.save_item(&login(v.id, "x")), Err(Error::Locked)));
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

    store.delete_item(item.id, 10_000).unwrap();
    assert_eq!(store.purge_expired(10_000 + DELETED_RETENTION_SECS - 1).unwrap(), 0);
    assert_eq!(store.purge_expired(10_000 + DELETED_RETENTION_SECS).unwrap(), 1);
    assert!(store.deleted_items().unwrap().is_empty());
    assert!(matches!(store.restore_item(item.id), Err(Error::NotFound(_))));
    // The tombstone row stays for future sync.
    let rows: i64 = store.conn.query_row("SELECT count(*) FROM items", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn delete_unknown_item_is_not_found() {
    let (_dir, _path, mut store) = new_store();
    assert!(matches!(store.delete_item(Uuid::new_v4(), 1), Err(Error::NotFound(_))));
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
        .execute("UPDATE items SET data = X'00112233' WHERE id = ?1", [bad.id.to_string()])
        .unwrap();

    let entries = store.list_items(None).unwrap();
    assert_eq!(entries[0], ItemEntry::Ok(good));
    assert_eq!(entries[1], ItemEntry::Damaged { id: bad.id, vault_id: v.id });
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
        .execute("UPDATE items SET schema = 2 WHERE id = ?1", [item.id.to_string()])
        .unwrap()
    ;
    assert!(matches!(store.get_item(item.id), Err(Error::Decrypt)));
    assert!(matches!(store.list_items(None).unwrap()[0], ItemEntry::Damaged { .. }));
}

#[test]
fn attachments_round_trip_and_are_listed_on_the_item() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();

    let att = store.add_attachment(item.id, "scan.pdf", b"%PDF-SECRET", 5_000).unwrap();
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
    assert!(matches!(store.get_attachment(Uuid::new_v4()), Err(Error::NotFound(_))));
}

#[test]
fn moving_an_item_to_another_vault_keeps_attachments_readable() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = login(a.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store.add_attachment(item.id, "scan.pdf", b"bytes", 5_000).unwrap();

    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    store.save_item(&moved).unwrap();

    assert_eq!(store.get_item(item.id).unwrap().vault_id, b.id);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"bytes");
}
