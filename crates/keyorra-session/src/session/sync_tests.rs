//! Plan A1d: sync through the session (two sessions, one in-memory store of files).

use keyorra_core::crypto::Key;
use keyorra_core::model::ItemKind;
use keyorra_sync::header::Header;
use keyorra_sync::keys::derive_sync_keys;
use keyorra_sync::secret_key::SecretKey;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use keyorra_sync::transport::MemoryTransport;

use super::sync::choose_join_folder;
use super::tests::{new_session, unlocked_session, PW};
use super::*;
use crate::sync::{DeviceKeyStore, MemoryDeviceKeys};

/// The sync place the test Macs share: one folder (in memory) per account.
#[derive(Clone, Default)]
struct Place(Arc<Mutex<BTreeMap<keyorra_sync::AccountId, MemoryTransport>>>);

impl Place {
    fn folders(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

struct TestLink {
    place: Place,
    keys: MemoryDeviceKeys,
    name: &'static str,
}

thread_local! {
    /// Takes every link's folder away (per test thread).
    static OFFLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl SyncLink for TestLink {
    fn transport(&self, account: &keyorra_sync::AccountId) -> Result<BoxedTransport, String> {
        if OFFLINE.get() {
            return Err("the folder is not available".into());
        }
        match self.place.0.lock().unwrap().get(account) {
            Some(t) => Ok(Box::new(t.clone())),
            None => Err("no folder for this account".into()),
        }
    }
    fn new_account_transport(
        &self,
        account: &keyorra_sync::AccountId,
    ) -> Result<BoxedTransport, String> {
        let t = MemoryTransport::new();
        self.place.0.lock().unwrap().insert(*account, t.clone());
        Ok(Box::new(t))
    }
    fn location(&self, account: &keyorra_sync::AccountId) -> Option<String> {
        Some(format!("place/{}", data_encoding::HEXLOWER.encode(account)))
    }
    fn join_candidates(&self) -> Result<Vec<(String, BoxedTransport)>, String> {
        Ok(self
            .place
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(a, t)| {
                (
                    data_encoding::HEXLOWER.encode(a),
                    Box::new(t.clone()) as BoxedTransport,
                )
            })
            .collect())
    }
    fn device_keys(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.keys.clone())
    }
    fn device_name(&self) -> String {
        self.name.into()
    }
    /// The real unlock refuses the cheap KDF parameters of these tests.
    fn unlock_header(
        &self,
        header: &Header,
        password: &str,
        secret_key: &SecretKey,
    ) -> keyorra_sync::Result<Key> {
        let keys = derive_sync_keys(
            password,
            &header.salt,
            header.kdf,
            secret_key,
            &header.account_id,
        )?;
        header.unwrap_account_key(&keys.kek)
    }
}

fn link(s: &mut Session, place: &Place, name: &'static str) {
    s.set_sync_link(Box::new(TestLink {
        place: place.clone(),
        keys: MemoryDeviceKeys::default(),
        name,
    }));
}

fn titles(s: &mut Session, now: u64) -> Vec<String> {
    let mut t: Vec<String> = s
        .items(&crate::dto::ItemFilter::default(), now)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    t.sort();
    t
}

fn add(s: &mut Session, title: &str, now: u64) {
    let vault = s.vaults(now).unwrap()[0].id;
    let mut item = s.new_item(vault, ItemKind::SecureNote, now).unwrap();
    item.title = title.into();
    s.save_item(item, now).unwrap();
}

fn rounds(a: &mut Session, b: &mut Session, from: u64) {
    for t in from..from + 4 {
        a.sync_now(t).unwrap();
        b.sync_now(t).unwrap();
    }
}

/// The main Mac with sync on, and a second Mac joined with the setup code and approved.
fn two_macs() -> (
    Place,
    (tempfile::TempDir, Session),
    (tempfile::TempDir, Session),
) {
    let transport = Place::default();
    let (d1, mut main) = unlocked_session();
    link(&mut main, &transport, "Main");
    add(&mut main, "before sync", 1_000);
    let kit = main.enable_sync(PW, 1_001).unwrap();
    assert!(kit.secret_key.len() > 20 && kit.setup_code.starts_with("KEYORRA-SETUP-1-"));

    let (d2, mut laptop) = new_session();
    link(&mut laptop, &transport, "Laptop");
    laptop.join_sync(PW, &kit.setup_code, 1_002).unwrap();
    assert_eq!(laptop.status(), Status::Unlocked);
    let waiting = laptop.sync_status().unwrap().status.unwrap();
    assert!(waiting.waiting_for_approval);

    main.sync_now(1_003).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    assert_eq!(joiner.name, "Laptop");
    main.approve_device(&joiner.id, &waiting.key_code, 1_004)
        .unwrap();
    rounds(&mut main, &mut laptop, 1_005);
    (transport, (d1, main), (d2, laptop))
}

#[test]
fn sync_turned_on_joined_with_the_setup_code_and_approved() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    assert_eq!(titles(&mut laptop, 1_010), ["before sync"]);
    add(&mut laptop, "from the laptop", 1_011);
    rounds(&mut main, &mut laptop, 1_012);
    assert_eq!(titles(&mut main, 1_020), ["before sync", "from the laptop"]);
    let status = laptop.sync_status().unwrap();
    assert!(status.enabled && status.error.is_none());
    assert!(!status.status.unwrap().waiting_for_approval);
}

#[test]
fn sync_runs_only_while_unlocked_and_resumes_on_unlock() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    laptop.lock();
    assert_eq!(laptop.sync_now(1_030).unwrap_err().kind, ErrorKind::Locked);
    add(&mut main, "while the laptop was locked", 1_031);
    main.sync_now(1_032).unwrap();
    laptop.unlock(PW, 1_033).unwrap();
    rounds(&mut main, &mut laptop, 1_034);
    assert!(titles(&mut laptop, 1_040).contains(&"while the laptop was locked".to_owned()));
}

#[test]
fn a_vault_created_while_synced_reaches_the_other_mac() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    let v = laptop.create_vault("Work", 1_050).unwrap();
    rounds(&mut main, &mut laptop, 1_051);
    assert!(main.vaults(1_060).unwrap().iter().any(|x| x.id == v.id));
}

#[test]
fn only_the_main_mac_changes_the_master_password() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    assert_eq!(
        laptop
            .change_password(PW, "another long password", 1_070)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    main.change_password(PW, "another long password", 1_071)
        .unwrap();
    rounds(&mut main, &mut laptop, 1_072);
    assert_eq!(main.synced.as_ref().unwrap().engine().header_epoch(), 2);
    assert_eq!(laptop.synced.as_ref().unwrap().engine().header_epoch(), 2);
}

#[test]
fn turning_sync_off_and_joining_again_rejoins_the_same_vault() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    let kit = main.emergency_kit(None, 1_005).unwrap();
    laptop.disable_sync(1_080).unwrap();
    assert!(!laptop.sync_status().unwrap().enabled);
    add(&mut laptop, "while sync was off", 1_081);
    laptop.join_sync(PW, &kit.setup_code, 1_082).unwrap();
    main.sync_now(1_083).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    let code = laptop.sync_status().unwrap().status.unwrap().key_code;
    main.approve_device(&joiner.id, &code, 1_084).unwrap();
    rounds(&mut main, &mut laptop, 1_085);
    assert_eq!(
        titles(&mut main, 1_090),
        ["before sync", "while sync was off"]
    );
}

#[test]
fn joining_from_a_vault_of_another_account_carries_it_over() {
    let (transport, (_d1, mut main), _laptop) = two_macs();
    let kit = main.emergency_kit(None, 1_005).unwrap();
    let (dir, mut other) = unlocked_session();
    link(&mut other, &transport, "Old Mac");
    add(&mut other, "old local item", 1_100);
    other.join_sync(PW, &kit.setup_code, 1_101).unwrap();
    let names: Vec<String> = std::fs::read_dir(dir.path().join("Application Support"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n == "keyorra.db.pre-sync-19700101"),
        "old file kept aside: {names:?}"
    );
    main.sync_now(1_102).unwrap();
    let pending = main.sync_status().unwrap().status.unwrap();
    let joiner = pending
        .devices
        .iter()
        .find(|d| !d.approved)
        .unwrap()
        .clone();
    let code = other.sync_status().unwrap().status.unwrap().key_code;
    main.approve_device(&joiner.id, &code, 1_103).unwrap();
    rounds(&mut main, &mut other, 1_104);
    assert_eq!(titles(&mut main, 1_110), ["before sync", "old local item"]);
    assert_eq!(titles(&mut other, 1_110), ["before sync", "old local item"]);
}

// ---- review of A1d-2 ----

const NEW_PW: &str = "another long password";

/// Review A1d-2 C1: right after unlock (before the first round) the main Mac changes the
/// password: sync publishes it, and nothing is left half done.
#[test]
fn review_a1d2_c1_the_main_mac_changes_the_password_right_after_unlock() {
    let (_t, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    main.lock();
    main.unlock(PW, 1_100).unwrap();
    main.change_password(PW, NEW_PW, 1_101).unwrap();
    rounds(&mut main, &mut laptop, 1_102);
    assert_eq!(laptop.synced.as_ref().unwrap().engine().header_epoch(), 2);
    main.lock();
    main.unlock(NEW_PW, 1_110).unwrap();
}

/// After a restart the main Mac reads its own stream again: the log says "Re-read", not
/// "Received … from This Mac".
#[test]
fn the_log_does_not_say_this_mac_received_its_own_changes() {
    let (_t, (_d1, mut main), (_d2, _laptop)) = two_macs();
    main.lock();
    main.unlock(PW, 1_200).unwrap();
    main.sync_now(1_201).unwrap();
    let log = main.sync_screen().unwrap().log;
    assert!(
        !log.iter().any(|l| l.text.contains("from This Mac")),
        "{log:?}"
    );
}

/// Review A1d-2 I5 and I9: with sync on but not running, the password stays as it is; once
/// the folder is back, the next round starts sync again.
#[test]
fn review_a1d2_i5_i9_no_password_change_while_sync_is_not_running() {
    let (_t, (_d1, mut main), (_d2, _laptop)) = two_macs();
    main.lock();
    OFFLINE.set(true);
    main.unlock(PW, 1_120).unwrap();
    assert!(main.sync_status().unwrap().error.is_some());
    assert_eq!(
        main.change_password(PW, NEW_PW, 1_121).unwrap_err().kind,
        ErrorKind::Invalid
    );
    main.lock();
    main.unlock(PW, 1_122).unwrap();
    OFFLINE.set(false);
    let status = main.sync_now(1_123).unwrap();
    assert!(status.status.is_some(), "{status:?}");
}

/// Review A1d-2 I11: the Emergency Kit needs a recent master password.
#[test]
fn review_a1d2_i11_the_kit_needs_a_recent_password() {
    let (_t, (_d1, mut main), _laptop) = two_macs();
    assert!(main.emergency_kit(None, 1_010).is_ok());
    assert_eq!(
        main.emergency_kit(None, 5_000).unwrap_err().kind,
        ErrorKind::PasswordRequired
    );
    assert_eq!(
        main.emergency_kit(Some("wrong password!"), 5_001)
            .unwrap_err()
            .kind,
        ErrorKind::WrongPassword
    );
    assert!(main.emergency_kit(Some(PW), 5_002).is_ok());
}

/// Review A1d-2 I12 with plan A2: each account gets its own folder; a vault of another
/// account turning sync on does not touch the first account's folder.
#[test]
fn review_a1d2_i12_each_account_gets_its_own_folder() {
    let (place, _main, _laptop) = two_macs();
    let (_d, mut other) = unlocked_session();
    link(&mut other, &place, "Other");
    other.enable_sync(PW, 1_130).unwrap();
    assert_eq!(place.folders(), 2);
}

/// Review A1d-2 I7: a wrong password leaves sync running on the old account; a right one
/// moves to a new account in its own folder.
#[test]
fn review_a1d2_i7_starting_a_new_account() {
    let (place, (_d1, mut main), _laptop) = two_macs();
    assert_eq!(
        main.start_new_sync_account("wrong password!", 1_140)
            .unwrap_err()
            .kind,
        ErrorKind::WrongPassword
    );
    assert!(main.synced.is_some());
    assert_eq!(place.folders(), 1);
    let kit = main.start_new_sync_account(PW, 1_142).unwrap();
    assert!(kit.setup_code.starts_with("KEYORRA-SETUP-1-"));
    assert!(main.sync_status().unwrap().enabled);
    assert_eq!(place.folders(), 2, "the old account's folder stays");
}

/// Wrong passwords given to turn sync on count towards the unlock throttle.
#[test]
fn wrong_passwords_for_sync_are_throttled() {
    let (_d, mut s) = unlocked_session();
    link(&mut s, &Place::default(), "Main");
    let mut kinds = Vec::new();
    for t in 0..8 {
        kinds.push(
            s.enable_sync("wrong password!", 1_200 + t)
                .unwrap_err()
                .kind,
        );
    }
    assert!(kinds.contains(&ErrorKind::Throttled), "{kinds:?}");
}

/// Review A1d-2 I8: a join that was moving the new vault into place when the app stopped
/// is finished on the next start; an unfinished one is removed.
#[test]
fn review_a1d2_i8_an_interrupted_carry_over_is_finished_on_start() {
    let (dir, s) = unlocked_session();
    let path = s.path.clone();
    drop(s);
    let joining = path.with_extension("joining");
    std::fs::rename(&path, &joining).unwrap();
    let mut s = Session::new(path.clone(), KdfParams::INSECURE_FAST, 1_300);
    assert_eq!(s.status(), Status::Locked);
    assert!(!joining.exists());
    s.unlock(PW, 1_301).unwrap();
    // A left-over half-made joining file next to a vault is removed.
    std::fs::write(&joining, b"half").unwrap();
    drop(s);
    let s = Session::new(path, KdfParams::INSECURE_FAST, 1_302);
    assert_eq!(s.status(), Status::Locked);
    assert!(!joining.exists());
    drop(dir);
}

/// Review A2 I4: the folder to join must be named after its account, exactly one may open,
/// a folder that cannot be read does not stop the others, and files still downloading say so.
#[test]
fn review_a2_i4_choosing_the_folder_to_join() {
    let (place, (_d1, main), _laptop) = two_macs();
    let (account, folder) = place
        .0
        .lock()
        .unwrap()
        .iter()
        .next()
        .map(|(a, t)| (*a, t.clone()))
        .unwrap();
    let kit = main.synced.as_ref().unwrap().emergency_kit();
    let (sk_id, _) = SecretKey::parse(&kit.secret_key).unwrap();
    let name = data_encoding::HEXLOWER.encode(&account);
    let ok = |_: &MemoryTransport| Ok(());
    // The right name: chosen.
    assert!(choose_join_folder(vec![(name.clone(), folder.clone())], &sk_id, ok).is_ok());
    // A copy under another name (a sync client's "Keyorra (1)") is never taken.
    assert_eq!(
        choose_join_folder(vec![("copy".into(), folder.clone())], &sk_id, ok)
            .err()
            .unwrap()
            .kind,
        ErrorKind::NotFound
    );
    // One that does not open (wrong password) next to one that does: the one that opens.
    let mut calls = 0;
    let chosen = choose_join_folder(
        vec![
            (name.clone(), folder.clone()),
            (name.clone(), folder.clone()),
        ],
        &sk_id,
        |_| {
            calls += 1;
            if calls == 1 {
                Err(keyorra_sync::Error::WrongPassword)
            } else {
                Ok(())
            }
        },
    );
    assert!(chosen.is_ok());
    // Two that open: ambiguous.
    assert_eq!(
        choose_join_folder(
            vec![
                (name.clone(), folder.clone()),
                (name.clone(), folder.clone())
            ],
            &sk_id,
            ok
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Invalid
    );
    // None opens: the password error.
    assert_eq!(
        choose_join_folder(vec![(name, folder)], &sk_id, |_| Err(
            keyorra_sync::Error::WrongPassword
        ))
        .err()
        .unwrap()
        .kind,
        ErrorKind::WrongPassword
    );
}

/// Review A2 I4: header files that are not on this Mac yet make a retryable error.
#[test]
fn review_a2_i4_a_folder_still_downloading_says_so() {
    use keyorra_sync_fs::{Availability, FileState, FolderTransport};
    struct NothingHere;
    impl Availability for NothingHere {
        fn state(&self, _: &std::path::Path) -> FileState {
            FileState::NotDownloaded
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("01".repeat(16)).join("account");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::write(
        account.join(format!("00000001-{}.hdr", "02".repeat(16))),
        b"x",
    )
    .unwrap();
    let folder = FolderTransport::probe(
        &dir.path().join("01".repeat(16)),
        None,
        std::sync::Arc::new(NothingHere),
    )
    .unwrap();
    let err = choose_join_folder(vec![("01".repeat(16), folder)], "ABCD", |_| Ok(()))
        .err()
        .unwrap();
    assert!(err.message.contains("still downloading"), "{}", err.message);
}

// ---- the Sync screen (plan A3) ----

/// The Sync screen in one call: location, last round, devices, log; joining tells what
/// happened and the code to compare.
#[test]
fn the_sync_screen_shows_the_account() {
    let (place, (_d1, mut main), _laptop) = two_macs();
    let (_d3, mut third) = new_session();
    link(&mut third, &place, "Third");
    let kit = main.emergency_kit(None, 1_005).unwrap();
    let joined = third.join_sync(PW, &kit.setup_code, 1_400).unwrap();
    assert_eq!(joined.mode, "new");
    assert_eq!(
        joined.key_code,
        third.sync_status().unwrap().status.unwrap().key_code
    );
    main.sync_now(1_401).unwrap();
    let screen = main.sync_screen().unwrap();
    assert!(screen.enabled && screen.running);
    assert!(screen.location.unwrap().starts_with("place/"));
    assert_eq!(screen.last_round_at, Some(1_401));
    assert_eq!(screen.last_round_ok, Some(true));
    let status = screen.status.unwrap();
    assert!(status.main_device && status.root_confirmed);
    assert!(status
        .devices
        .iter()
        .any(|d| d.name == "Third" && !d.approved));
    assert!(
        screen.log.iter().any(|l| l.text.starts_with("Received")),
        "{:?}",
        screen.log
    );
    let files = main.sync_folder_files().unwrap();
    assert!(files
        .iter()
        .any(|f| f.path.starts_with("streams/") && f.counted));
    main.lock();
    main.unlock(PW, 1_402).unwrap();
    assert!(
        main.sync_screen().unwrap().log.is_empty(),
        "the log is per unlock"
    );
}

/// An alarm with its explanation and the actions that fit; accepting clears it.
#[test]
fn an_alarm_is_explained_and_accepted() {
    let (place, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    add(&mut main, "one more", 1_410);
    rounds(&mut main, &mut laptop, 1_411);
    // The folder loses the main Mac's newest changes.
    let folder = place.0.lock().unwrap().values().next().unwrap().clone();
    let main_id = main.synced.as_ref().unwrap().engine().device();
    let newest = folder
        .dump()
        .into_iter()
        .filter(|(d, _, _)| *d == main_id)
        .map(|(_, seq, _)| seq)
        .max()
        .unwrap();
    folder.remove_segment(&main_id, newest);
    laptop.sync_now(1_420).unwrap();
    let alarms = laptop.sync_screen().unwrap().alarms;
    let rollback = alarms
        .iter()
        .find(|a| a.kind == "rollback")
        .expect("an alarm");
    assert!(rollback.title.contains("Main"), "{}", rollback.title);
    assert_eq!(
        rollback.actions,
        vec!["accept"],
        "only the main Mac restores"
    );
    assert_eq!(
        laptop
            .sync_alarm_action(&rollback.id, "restore", 1_421)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    laptop
        .sync_alarm_action(&rollback.id, "accept", 1_422)
        .unwrap();
    assert!(laptop
        .sync_screen()
        .unwrap()
        .alarms
        .iter()
        .all(|a| a.id != rollback.id));
}

/// The main Mac removes a device; "Verify everything" checks the local copy.
#[test]
fn removing_a_device_and_verifying() {
    let (_place, (_d1, mut main), (_d2, mut laptop)) = two_macs();
    let report = laptop.verify_sync().unwrap();
    assert_eq!(report.items, 1);
    assert_eq!((report.damaged, report.missing), (0, 0));
    assert!(report.differing.is_empty());
    let laptop_id = laptop
        .sync_status()
        .unwrap()
        .status
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.this_device)
        .unwrap()
        .id;
    assert_eq!(
        laptop
            .remove_sync_device(&laptop_id, 1_430)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid,
        "only the main Mac removes devices"
    );
    main.remove_sync_device(&laptop_id, 1_431).unwrap();
    main.sync_now(1_432).unwrap();
    let devices = main.sync_status().unwrap().status.unwrap().devices;
    assert!(devices.iter().any(|d| d.id == laptop_id && d.removed));
}

/// The database's backup copies are listed and can be deleted; nothing else can.
#[test]
fn backup_copies_are_listed_and_deleted() {
    let (dir, mut s) = unlocked_session();
    let base = dir.path().join("Application Support");
    std::fs::write(base.join("keyorra.db.bak-v1"), b"old").unwrap();
    std::fs::write(base.join("keyorra.db.pre-sync-20261006"), b"older").unwrap();
    std::fs::write(base.join("keyorra.db.pre-sync-20261006-journal"), b"x").unwrap();
    std::fs::write(base.join("settings.json"), b"{}").unwrap();
    let backups = s.backups().unwrap();
    let names: Vec<&str> = backups.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["keyorra.db.bak-v1", "keyorra.db.pre-sync-20261006"]);
    assert_eq!(backups[0].kind, "migration");
    assert_eq!(backups[1].size, 5);
    assert_eq!(
        s.delete_backup("settings.json", 1_440).unwrap_err().kind,
        ErrorKind::NotFound
    );
    s.delete_backup("keyorra.db.pre-sync-20261006", 1_441)
        .unwrap();
    assert!(!base.join("keyorra.db.pre-sync-20261006-journal").exists());
    assert_eq!(s.backups().unwrap().len(), 1);
}

// ---- review of A3 ----

/// The main Mac and a second Mac waiting for approval; returns the waiting device's id and
/// the key code it shows.
fn a_mac_waiting() -> (
    Place,
    (tempfile::TempDir, Session),
    (tempfile::TempDir, Session),
    String,
    String,
) {
    let place = Place::default();
    let (d1, mut main) = unlocked_session();
    link(&mut main, &place, "Main");
    let kit = main.enable_sync(PW, 1_001).unwrap();
    let (d2, mut laptop) = new_session();
    link(&mut laptop, &place, "Laptop");
    laptop.join_sync(PW, &kit.setup_code, 1_002).unwrap();
    let code = laptop.sync_status().unwrap().status.unwrap().key_code;
    main.sync_now(1_003).unwrap();
    let id = main
        .sync_status()
        .unwrap()
        .status
        .unwrap()
        .devices
        .into_iter()
        .find(|d| !d.approved)
        .unwrap()
        .id;
    (place, (d1, main), (d2, laptop), id, code)
}

fn approved(main: &Session, id: &str) -> bool {
    main.sync_status()
        .unwrap()
        .status
        .unwrap()
        .devices
        .iter()
        .any(|d| d.id == id && d.approved)
}

/// Review A3 I1: the approval code is compared with case and dashes ignored.
#[test]
fn review_a3_approval_code_in_upper_case() {
    let (_p, (_d1, mut main), _laptop, id, code) = a_mac_waiting();
    main.approve_device(&id, &code.to_uppercase(), 1_004)
        .unwrap();
    assert!(approved(&main, &id));
}

#[test]
fn review_a3_approval_code_without_dashes_or_with_spaces() {
    let (_p, (_d1, mut main), _laptop, id, code) = a_mac_waiting();
    let typed = format!(" {} ", code.replace('-', " ").to_uppercase());
    main.approve_device(&id, &typed.replace(' ', ""), 1_004)
        .unwrap();
    assert!(approved(&main, &id));
}

#[test]
fn review_a3_approval_code_of_the_wrong_length_is_refused() {
    let (_p, (_d1, mut main), _laptop, id, code) = a_mac_waiting();
    let short = &code[..code.len() - 1];
    let err = main.approve_device(&id, short, 1_004).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Invalid);
    let err = main
        .approve_device(&id, &format!("{code}0"), 1_005)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Invalid);
    assert!(!approved(&main, &id));
}

/// Review A3 I5: the Emergency Kit says where the account lives; the setup code never
/// leaves Rust in the kit (it is copied by the app from Rust).
#[test]
fn review_a3_the_kit_has_the_location_and_no_setup_code_in_json() {
    let place = Place::default();
    let (_d, mut main) = unlocked_session();
    link(&mut main, &place, "Main");
    let kit = main.enable_sync(PW, 1_001).unwrap();
    assert_eq!(
        kit.location,
        Some(format!("place/{}", kit.account_id)),
        "the kit shown right after turning on"
    );
    assert_eq!(
        main.emergency_kit(None, 1_002).unwrap().location,
        kit.location
    );
    let json = serde_json::to_value(&kit).unwrap();
    assert!(json.get("setupCode").is_none(), "{json}");
    assert!(json.get("location").is_some());
    let renewed = main.start_new_sync_account(PW, 1_003).unwrap();
    assert_eq!(
        renewed.location,
        Some(format!("place/{}", renewed.account_id))
    );
}

/// Review A3 I2: the sync place changes only while sync is off, which is known only while
/// unlocked (or before the first vault exists, for joining on first run).
#[test]
fn review_a3_the_sync_place_changes_only_while_unlocked_and_off() {
    let place = Place::default();
    let (_d0, fresh) = new_session();
    assert_eq!(fresh.status(), Status::New);
    fresh.may_change_sync_place().unwrap();

    let (_d, mut main) = unlocked_session();
    link(&mut main, &place, "Main");
    main.may_change_sync_place().unwrap();
    main.enable_sync(PW, 1_001).unwrap();
    assert_eq!(
        main.may_change_sync_place().unwrap_err().kind,
        ErrorKind::Invalid
    );
    main.lock();
    assert_eq!(
        main.may_change_sync_place().unwrap_err().kind,
        ErrorKind::Locked,
        "locked: whether sync is on is not known"
    );
}
