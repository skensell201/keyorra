use super::*;
use crate::error::ErrorKind;
use tempfile::TempDir;

pub(super) const PW: &str = "correct horse battery";

pub(super) fn new_session() -> (TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    // A missing parent directory must be created on first run.
    let path = dir.path().join("Application Support").join("lockbox.db");
    (dir, Session::new(path, KdfParams::INSECURE_FAST, 1_000))
}

pub(super) fn unlocked_session() -> (TempDir, Session) {
    let (dir, mut s) = new_session();
    s.create(PW, 1_000).unwrap();
    (dir, s)
}

#[test]
fn first_run_creates_an_unlocked_vault_with_a_personal_vault() {
    let (_dir, mut s) = new_session();
    assert_eq!(s.status(), Status::New);
    s.create(PW, 1_000).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
    let names: Vec<_> = s
        .store
        .as_ref()
        .unwrap()
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, [DEFAULT_VAULT]);
}

#[test]
fn create_rejects_short_passwords_and_an_existing_vault() {
    let (_dir, mut s) = new_session();
    assert_eq!(
        s.create("short", 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    assert_eq!(s.status(), Status::New);
    s.create(PW, 1_000).unwrap();
    s.lock();
    assert_eq!(s.create(PW, 1_000).unwrap_err().kind, ErrorKind::Invalid);
}

#[test]
fn lock_and_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.status(), Status::Locked);
    assert_eq!(
        s.unlock("wrong password", 1_001).unwrap_err().kind,
        ErrorKind::WrongPassword
    );
    s.unlock(PW, 1_002).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
}

#[test]
fn repeated_wrong_passwords_are_throttled() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    for _ in 0..UnlockThrottle::FREE_ATTEMPTS {
        assert_eq!(
            s.unlock("nope nope nope", 2_000).unwrap_err().kind,
            ErrorKind::WrongPassword
        );
    }
    let err = s.unlock(PW, 2_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Throttled);
    assert_eq!(err.retry_after, Some(1));
    s.unlock(PW, 2_001).unwrap();
}

#[test]
fn tick_locks_after_the_idle_timeout_and_touch_postpones_it() {
    let (_dir, mut s) = unlocked_session(); // last activity: 1_000
    let timeout = AutoLock::DEFAULT_TIMEOUT_SECS;
    assert!(!s.tick(1_000 + timeout - 1));
    s.touch(1_500);
    assert!(!s.tick(1_000 + timeout));
    assert!(s.tick(1_500 + timeout));
    assert_eq!(s.status(), Status::Locked);
    assert!(!s.tick(1_500 + timeout + 10), "already locked");
}

#[test]
fn clipboard_guard_is_exposed() {
    let (_dir, mut s) = unlocked_session();
    assert!(!s.clipboard_pending());
    s.clipboard.copied("x", 1_000, 90);
    assert!(s.clipboard_pending());
    assert!(s.clipboard_should_clear(1_090, Some("x")));
}
