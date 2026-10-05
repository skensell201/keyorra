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
    let path = dir.path().join("keyorra.db");
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
    assert_eq!(aside, dir.path().join("keyorra.db.unreadable-5000"));
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
fn start_over_never_overwrites_an_earlier_aside_file() {
    const JUNK: &[u8] = b"definitely not sqlite, just some text here....";
    let (dir, mut s, path) = session_with_file(JUNK);
    let taken = dir.path().join("keyorra.db.unreadable-5000");
    std::fs::write(&taken, b"first").unwrap();
    // A leftover sibling of the next name counts as taken too.
    std::fs::write(
        dir.path().join("keyorra.db.unreadable-5000-2-wal"),
        b"old wal",
    )
    .unwrap();

    let aside = s.start_over(5_000).unwrap();
    assert_eq!(aside, dir.path().join("keyorra.db.unreadable-5000-3"));
    assert_eq!(std::fs::read(&taken).unwrap(), b"first");
    assert_eq!(std::fs::read(&aside).unwrap(), JUNK);
    assert!(!path.exists());
}

#[test]
fn move_aside_takes_the_companion_files_along() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyorra.db");
    std::fs::write(&path, b"main").unwrap();
    std::fs::write(sibling(&path, "-wal"), b"wal").unwrap();
    let aside = sibling(&path, ".unreadable-1");
    move_aside(&path, &aside, |a, b| std::fs::rename(a, b)).unwrap();
    assert_eq!(std::fs::read(&aside).unwrap(), b"main");
    assert_eq!(std::fs::read(sibling(&aside, "-wal")).unwrap(), b"wal");
    assert!(!path.exists() && !sibling(&path, "-wal").exists());
}

#[test]
fn a_failed_sibling_move_puts_everything_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyorra.db");
    std::fs::write(&path, b"main").unwrap();
    std::fs::write(sibling(&path, "-journal"), b"journal").unwrap();
    std::fs::write(sibling(&path, "-wal"), b"wal").unwrap();
    let aside = sibling(&path, ".unreadable-1");

    let err = move_aside(&path, &aside, |from, to| {
        if from.to_string_lossy().ends_with("-wal") {
            Err(std::io::Error::other("disk on fire"))
        } else {
            std::fs::rename(from, to)
        }
    })
    .unwrap_err();
    assert!(err.to_string().contains("disk on fire"), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"main");
    assert_eq!(
        std::fs::read(sibling(&path, "-journal")).unwrap(),
        b"journal"
    );
    assert_eq!(std::fs::read(sibling(&path, "-wal")).unwrap(), b"wal");
    assert!(!aside.exists() && !sibling(&aside, "-journal").exists());
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
        .join("keyorra.db")
        .exists());
    s.unlock(PW, 5_001).unwrap();
}

#[test]
fn quick_copy_finds_fields_by_purpose() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "hunter2");
    // Imported logins may use other field ids; purpose is what counts.
    item.fields[0].id = "imported-user".into();
    item.fields[1].id = "imported-pass".into();
    let item = s.save_item(item, 1_000).unwrap();
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Username, 1_000).unwrap(),
        "ivan"
    );
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Password, 1_000).unwrap(),
        "hunter2"
    );
    assert!(s.clipboard_pending(), "the clipboard guard is armed");
    assert_eq!(
        s.copy_quick(item.id, QuickCopy::Totp, 1_000)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    let note = s.new_item(p, ItemKind::SecureNote, 1_000).unwrap();
    let mut note = note;
    note.title = "Note".into();
    let note = s.save_item(note, 1_000).unwrap();
    let err = s
        .copy_quick(note.id, QuickCopy::Password, 1_000)
        .unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::NotFound, "This item has no password")
    );
}
