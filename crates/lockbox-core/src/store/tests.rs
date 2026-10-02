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
    assert_eq!(copy, path.with_extension("db.bak-v1"));
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&path).unwrap());
}
