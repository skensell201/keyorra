use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use crate::watchtower::PasswordHash;
use keepsake_core::watchtower::hibp::sha1_hex_upper;

#[test]
fn watchtower_reports_live_items_only() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "Bank", "me", "password");
    let gone = save_login(&mut s, p, "Old", "me", "password");
    s.delete_item(gone.id, 1_000).unwrap();
    let r = s.watchtower(1_000).unwrap();
    let weak: Vec<_> = r.weak.iter().map(|f| f.item.title.as_str()).collect();
    assert_eq!(weak, ["Bank"]);
    assert!(r.reused.is_empty(), "the deleted copy does not count");
}

#[test]
fn breach_answers_are_cached_until_lock() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "Bank", "me", "password");
    save_login(&mut s, p, "Shop", "me", "password");
    let hashes = s.breach_hashes_to_check(1_000).unwrap();
    assert_eq!(hashes, [PasswordHash::of("password")]);
    assert_eq!(*hashes[0].hex(), sha1_hex_upper("password"));
    s.record_breaches([(hashes[0].clone(), 12)]);
    assert!(s.breach_hashes_to_check(1_000).unwrap().is_empty());
    let r = s.watchtower(1_000).unwrap();
    assert_eq!(r.breached.len(), 2);
    assert!(r.breaches_checked);

    s.lock();
    s.record_breaches([(hashes[0].clone(), 12)]);
    s.unlock(PW, 1_001).unwrap();
    assert_eq!(
        s.breach_hashes_to_check(1_001).unwrap().len(),
        1,
        "forgotten on lock"
    );
}

#[test]
fn watchtower_requires_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.watchtower(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(
        s.breach_hashes_to_check(1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

#[test]
fn watchtower_count_is_cached_until_something_changes() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    assert_eq!(s.watchtower_count().unwrap(), 0);
    let bank = save_login(&mut s, p, "Bank", "me", "password");
    assert_eq!(s.watchtower_count().unwrap(), 1, "a save invalidates it");
    save_login(&mut s, p, "Shop", "me", "password");
    assert_eq!(s.watchtower_count().unwrap(), 2);
    s.delete_item(bank.id, 1_000).unwrap();
    assert_eq!(s.watchtower_count().unwrap(), 1, "a delete invalidates it");
    s.restore_item(bank.id, 1_000).unwrap();
    assert_eq!(s.watchtower_count().unwrap(), 2, "a restore invalidates it");

    s.lock();
    assert_eq!(s.watchtower_count().unwrap_err().kind, ErrorKind::Locked);
}

#[test]
fn watchtower_count_follows_breach_answers() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "Bank", "me", "Tr0ub4dor&3-horse-staple!");
    assert_eq!(s.watchtower_count().unwrap(), 0);
    let hashes = s.breach_hashes_to_check(1_000).unwrap();
    s.record_breaches(hashes.into_iter().map(|h| (h, 7)));
    assert_eq!(s.watchtower_count().unwrap(), 1);
}
