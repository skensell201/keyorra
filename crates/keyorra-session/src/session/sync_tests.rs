//! Plan A1d: sync through the session (two sessions, one in-memory store of files).

use keyorra_core::crypto::Key;
use keyorra_core::model::ItemKind;
use keyorra_sync::header::Header;
use keyorra_sync::keys::derive_sync_keys;
use keyorra_sync::secret_key::SecretKey;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use keyorra_sync::transport::MemoryTransport;

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
    fn join_candidates(&self) -> Result<Vec<BoxedTransport>, String> {
        Ok(self
            .place
            .0
            .lock()
            .unwrap()
            .values()
            .map(|t| Box::new(t.clone()) as BoxedTransport)
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
