use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;

#[test]
fn rename_vault_trims_and_requires_a_name() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    assert_eq!(s.rename_vault(p, "  Home ", 1_000).unwrap().name, "Home");
    assert_eq!(s.vaults(1_000).unwrap()[0].name, "Home");
    assert_eq!(
        s.rename_vault(p, " ", 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        s.rename_vault(Uuid::new_v4(), "x", 1_000).unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[test]
fn delete_vault_only_when_empty_and_not_the_last() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    assert_eq!(
        s.delete_vault(p, 1_000).unwrap_err().kind,
        ErrorKind::Invalid,
        "last vault"
    );
    let work = s.create_vault("Work", 1_000).unwrap().id;
    let item = save_login(&mut s, work, "Jira", "ivan", "pw");
    let err = s.delete_vault(work, 1_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Invalid);
    assert!(err.message.contains("1 item"), "{}", err.message);
    s.delete_item(item.id, 1_000).unwrap();
    s.delete_vault(work, 1_000).unwrap();
    let names: Vec<_> = s
        .vaults(1_000)
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert!(s.deleted_items(1_000).unwrap().is_empty());
}

#[test]
fn vault_changes_require_unlock() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    s.lock();
    assert_eq!(
        s.rename_vault(p, "x", 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
    assert_eq!(
        s.delete_vault(p, 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

fn session_with_file(contents: &[u8]) -> (tempfile::TempDir, Session, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keepsake.db");
    std::fs::write(&path, contents).unwrap();
    let s = Session::new(path.clone(), KdfParams::INSECURE_FAST, 1_000);
    (dir, s, path)
}

#[test]
fn unlocking_a_foreign_file_says_it_is_not_a_database() {
    let (_dir, mut s, _path) = session_with_file(b"definitely not sqlite, just some text here....");
    assert_eq!(s.status(), Status::Locked);
    assert_eq!(
        s.unlock(PW, 1_000).unwrap_err().kind,
        ErrorKind::NotADatabase
    );
}

#[test]
fn start_over_moves_the_file_aside_and_allows_setup() {
    let (dir, mut s, path) = session_with_file(b"definitely not sqlite, just some text here....");
    let aside = s.start_over(5_000).unwrap();
    assert_eq!(aside, dir.path().join("keepsake.db.unreadable-5000"));
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        b"definitely not sqlite, just some text here....",
        "nothing is deleted"
    );
    assert!(!path.exists());
    assert_eq!(s.status(), Status::New);
    s.create(PW, 5_001).unwrap();
}

#[test]
fn start_over_never_moves_a_working_vault() {
    let (dir, mut s) = unlocked_session();
    assert_eq!(
        s.start_over(5_000).unwrap_err().kind,
        ErrorKind::Invalid,
        "unlocked"
    );
    s.lock();
    assert_eq!(s.start_over(5_000).unwrap_err().kind, ErrorKind::Invalid);
    assert!(dir
        .path()
        .join("Application Support")
        .join("keepsake.db")
        .exists());
    s.unlock(PW, 5_001).unwrap();
}
