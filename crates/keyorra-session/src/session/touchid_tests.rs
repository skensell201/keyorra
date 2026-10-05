use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use crate::touchid::{FakeEnclave, MemKeyring, MAX_AGE_SECS};

/// Unlocked session (created at 1_000) with an in-memory keyring and Touch ID turned on.
fn with_touch_id() -> (tempfile::TempDir, Session, MemKeyring, FakeEnclave) {
    let (dir, mut s) = unlocked_session();
    let keyring = MemKeyring::default();
    s.set_keyring(Box::new(keyring.clone()));
    let enclave = FakeEnclave::new();
    s.enable_touch_id(b"blob".to_vec(), &enclave.public(), 1_000)
        .unwrap();
    (dir, s, keyring, enclave)
}

fn touch(s: &mut Session, enclave: &FakeEnclave, now: u64) -> CmdResult<()> {
    let request = s.touch_id_request(now)?;
    assert_eq!(request.enclave_key, b"blob");
    let shared = enclave.agree(&request.ephemeral_public);
    s.unlock_with_touch_id(&request, &shared, now)
}

#[test]
fn touch_id_unlocks_after_lock_and_restart() {
    let (dir, mut s, keyring, enclave) = with_touch_id();
    let p = personal(&mut s);
    save_login(&mut s, p, "GitHub", "ivan", "pw");
    s.lock();
    touch(&mut s, &enclave, 2_000).unwrap();
    assert_eq!(s.status(), Status::Unlocked);
    assert_eq!(s.items(&Default::default(), 2_000).unwrap().len(), 1);

    // A restart does not require the password (the record lives in the keychain).
    let path = dir.path().join("Application Support").join("keyorra.db");
    let mut restarted = Session::new(path, KdfParams::INSECURE_FAST, 3_000);
    restarted.set_keyring(Box::new(keyring));
    touch(&mut restarted, &enclave, 3_000).unwrap();
    assert_eq!(restarted.status(), Status::Unlocked);
}

#[test]
fn state_reports_enabled_and_password_due() {
    let (_dir, mut s, _keyring, _enclave) = with_touch_id();
    let state = s.touch_id_state(true, 1_000);
    assert!(state.available && state.enabled && !state.password_due);
    assert!(s.touch_id_state(true, 1_000 + MAX_AGE_SECS).password_due);
    s.disable_touch_id();
    assert!(!s.touch_id_state(true, 1_000).enabled);
}

#[test]
fn the_password_is_required_every_14_days() {
    let (_dir, mut s, _keyring, enclave) = with_touch_id();
    s.lock();
    let late = 1_000 + MAX_AGE_SECS;
    assert_eq!(
        touch(&mut s, &enclave, late).unwrap_err().kind,
        ErrorKind::PasswordRequired
    );
    s.unlock(PW, late).unwrap();
    s.lock();
    touch(&mut s, &enclave, late + MAX_AGE_SECS - 1).unwrap();
}

#[test]
fn touch_id_unlocks_do_not_restart_the_14_days() {
    let (_dir, mut s, _keyring, enclave) = with_touch_id();
    s.lock();
    touch(&mut s, &enclave, 1_000 + MAX_AGE_SECS - 10).unwrap();
    // Re-enabling while unlocked by Touch ID keeps the original password time.
    s.enable_touch_id(
        b"blob".to_vec(),
        &enclave.public(),
        1_000 + MAX_AGE_SECS - 5,
    )
    .unwrap();
    s.lock();
    let err = touch(&mut s, &enclave, 1_000 + MAX_AGE_SECS).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);
}

#[test]
fn changing_the_password_replaces_the_record() {
    let (_dir, mut s, keyring, enclave) = with_touch_id();
    let before = keyring.load().unwrap();
    s.change_password(PW, "a brand new password", 5_000)
        .unwrap();
    let after = keyring.load().unwrap();
    assert_ne!(before, after);
    assert_eq!(
        touchid::Record::from_bytes(&after).unwrap().verified_at,
        5_000
    );
    s.lock();
    touch(&mut s, &enclave, 5_001).unwrap();
}

#[test]
fn a_wrong_enclave_answer_forgets_touch_id() {
    let (_dir, mut s, keyring, _enclave) = with_touch_id();
    s.lock();
    let request = s.touch_id_request(2_000).unwrap();
    let wrong = FakeEnclave::new().agree(&request.ephemeral_public);
    let err = s.unlock_with_touch_id(&request, &wrong, 2_000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);
    assert!(keyring.load().is_none(), "the record is removed");
    assert_eq!(s.status(), Status::Locked);
}

#[test]
fn enabling_needs_an_unlocked_vault_and_a_password_entry() {
    let (_dir, mut s) = unlocked_session();
    let keyring = MemKeyring::default();
    s.set_keyring(Box::new(keyring.clone()));
    let enclave = FakeEnclave::new();
    s.lock();
    assert_eq!(
        s.enable_touch_id(vec![], &enclave.public(), 1_000)
            .unwrap_err()
            .kind,
        ErrorKind::Locked
    );
    assert_eq!(
        s.touch_id_request(1_000).unwrap_err().kind,
        ErrorKind::PasswordRequired,
        "off"
    );
}

#[test]
fn creating_a_vault_forgets_an_old_record() {
    let keyring = MemKeyring::default();
    keyring.save(b"stale").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut s = Session::new(
        dir.path().join("keyorra.db"),
        KdfParams::INSECURE_FAST,
        1_000,
    );
    s.set_keyring(Box::new(keyring.clone()));
    s.create(PW, 1_000).unwrap();
    assert!(keyring.load().is_none());
}

/// Another app can create the keychain item while Touch ID is off. A record it planted must
/// never make Keyorra wrap the account key to the planter's public key.
fn plant(keyring: &MemKeyring, attacker: &FakeEnclave, at: u64) {
    let fake = touchid::wrap(
        &keyorra_core::crypto::Key::random(),
        b"evil".to_vec(),
        &attacker.public(),
        at,
    )
    .unwrap();
    keyring.save(&fake.to_bytes()).unwrap();
}

fn attacker_can_unwrap(keyring: &MemKeyring, attacker: &FakeEnclave) -> bool {
    keyring
        .load()
        .and_then(|b| touchid::Record::from_bytes(&b))
        .is_some_and(|r| touchid::unwrap(&r, &attacker.agree(&r.ephemeral_public)).is_ok())
}

#[test]
fn a_password_unlock_never_rewraps_a_planted_record() {
    let (_dir, mut s) = unlocked_session();
    let keyring = MemKeyring::default();
    s.set_keyring(Box::new(keyring.clone()));
    s.lock();
    let attacker = FakeEnclave::new();
    plant(&keyring, &attacker, 1_500);

    s.unlock(PW, 2_000).unwrap();
    assert!(!attacker_can_unwrap(&keyring, &attacker));
    assert!(keyring.load().is_none(), "the planted record is removed");
}

#[test]
fn a_password_change_never_rewraps_a_planted_record() {
    let (_dir, mut s, keyring, _enclave) = with_touch_id();
    let attacker = FakeEnclave::new();
    plant(&keyring, &attacker, 1_500);
    s.change_password(PW, "a brand new password", 2_000)
        .unwrap();
    assert!(!attacker_can_unwrap(&keyring, &attacker));
    assert!(keyring.load().is_none());
}

#[test]
fn a_record_with_a_swapped_enclave_key_is_not_rewrapped() {
    let (_dir, mut s, keyring, _enclave) = with_touch_id();
    // Keep the genuine proof, swap in the attacker's enclave key.
    let mut record = touchid::Record::from_bytes(&keyring.load().unwrap()).unwrap();
    let attacker = FakeEnclave::new();
    record.enclave_public = attacker.public();
    keyring.save(&record.to_bytes()).unwrap();
    s.lock();
    s.unlock(PW, 2_000).unwrap();
    assert!(!attacker_can_unwrap(&keyring, &attacker));
}

#[test]
fn a_genuine_record_is_still_rewrapped_after_a_password_unlock() {
    let (_dir, mut s, keyring, enclave) = with_touch_id();
    s.lock();
    s.unlock(PW, 9_000).unwrap();
    let record = touchid::Record::from_bytes(&keyring.load().unwrap()).unwrap();
    assert_eq!(record.verified_at, 9_000);
    s.lock();
    touch(&mut s, &enclave, 9_001).unwrap();
}

#[test]
fn a_stale_touch_id_answer_keeps_the_newer_record() {
    let (_dir, mut s, keyring, enclave) = with_touch_id();
    s.lock();
    let stale = s.touch_id_request(2_000).unwrap();
    // Meanwhile the password was typed (the record is re-wrapped) and the vault locked again.
    s.unlock(PW, 2_001).unwrap();
    s.lock();
    let shared = enclave.agree(&stale.ephemeral_public);
    let err = s.unlock_with_touch_id(&stale, &shared, 2_002).unwrap_err();
    assert_ne!(err.kind, ErrorKind::PasswordRequired, "{}", err.message);
    assert!(keyring.load().is_some(), "the newer record is kept");
    assert_eq!(s.status(), Status::Locked);
    touch(&mut s, &enclave, 2_003).unwrap();
}
