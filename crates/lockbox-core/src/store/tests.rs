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
