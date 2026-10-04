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

use lockbox_core::model::{FieldValue, Item, ItemKind};
use uuid::Uuid;

use crate::dto::ItemFilter;

pub(super) fn personal(s: &mut Session) -> Uuid {
    s.vaults(1_000).unwrap()[0].id
}

pub(super) fn save_login(s: &mut Session, vault: Uuid, title: &str, user: &str, pw: &str) -> Item {
    let mut item = s.new_item(vault, ItemKind::Login, 1_000).unwrap();
    item.title = title.into();
    item.fields[0].value = FieldValue::Text(user.into());
    item.fields[1].value = FieldValue::Concealed(pw.into());
    s.save_item(item, 1_000).unwrap()
}

fn titles(s: &mut Session, filter: ItemFilter) -> Vec<String> {
    s.items(&filter, 1_000)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect()
}

#[test]
fn vaults_report_item_counts() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    save_login(&mut s, p, "GitHub", "ivan", "pw");
    save_login(&mut s, p, "Bank", "me", "pw");
    s.create_vault("Work", 1_000).unwrap();
    let vaults: Vec<_> = s
        .vaults(1_000)
        .unwrap()
        .into_iter()
        .map(|v| (v.name, v.item_count))
        .collect();
    assert_eq!(
        vaults,
        [("Personal".to_string(), 2), ("Work".to_string(), 0)]
    );
}

#[test]
fn create_vault_requires_a_name() {
    let (_dir, mut s) = unlocked_session();
    assert_eq!(
        s.create_vault("   ", 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    assert_eq!(s.create_vault("  Work ", 1_000).unwrap().name, "Work");
}

#[test]
fn new_items_get_purpose_fields_and_need_a_known_vault() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let login = s.new_item(p, ItemKind::Login, 1_000).unwrap();
    let ids: Vec<_> = login.fields.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["username", "password"]);
    assert_eq!(
        s.new_item(p, ItemKind::Password, 1_000)
            .unwrap()
            .fields
            .len(),
        1
    );
    assert!(s
        .new_item(p, ItemKind::SecureNote, 1_000)
        .unwrap()
        .fields
        .is_empty());
    let err = s
        .new_item(Uuid::new_v4(), ItemKind::Login, 1_000)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn items_are_sorted_and_filtered() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let work = s.create_vault("Work", 1_000).unwrap().id;
    save_login(&mut s, p, "zeta", "z", "pw");
    save_login(&mut s, p, "Alpha", "a", "pw");
    let mut beta = save_login(&mut s, p, "beta", "b", "pw");
    beta.favorite = true;
    s.save_item(beta, 1_000).unwrap();
    save_login(&mut s, work, "Work item", "w", "pw");

    assert_eq!(
        titles(&mut s, ItemFilter::default()),
        ["Alpha", "beta", "Work item", "zeta"]
    );
    assert_eq!(
        titles(
            &mut s,
            ItemFilter {
                vault_id: Some(work),
                ..Default::default()
            }
        ),
        ["Work item"]
    );
    assert_eq!(
        titles(
            &mut s,
            ItemFilter {
                query: "ALP".into(),
                ..Default::default()
            }
        ),
        ["Alpha"]
    );
    assert_eq!(
        titles(
            &mut s,
            ItemFilter {
                favorites: true,
                ..Default::default()
            }
        ),
        ["beta"]
    );
}

#[test]
fn save_requires_a_title_and_trims_it() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = s.new_item(p, ItemKind::SecureNote, 1_000).unwrap();
    assert_eq!(
        s.save_item(item.clone(), 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    let mut item = item;
    item.title = "  Wi-Fi  ".into();
    assert_eq!(s.save_item(item, 1_000).unwrap().title, "Wi-Fi");
}

#[test]
fn save_records_password_history_and_keeps_created_at() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "first");
    item.fields[1].value = FieldValue::Concealed("second".into());
    let saved = s.save_item(item, 2_000).unwrap();
    assert_eq!(saved.password(), Some("second"));
    assert_eq!(saved.password_history[0].value, "first");
    assert_eq!(saved.password_history[0].changed_at, 2_000);
    assert_eq!((saved.created_at, saved.updated_at), (1_000, 2_000));
    let again = s.save_item(saved, 3_000).unwrap();
    assert_eq!(
        again.password_history.len(),
        1,
        "unchanged password adds no history"
    );
}

#[test]
fn item_and_delete() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    assert_eq!(s.item(item.id, 1_000).unwrap().title, "GitHub");
    s.delete_item(item.id, 1_000).unwrap();
    assert!(titles(&mut s, ItemFilter::default()).is_empty());
    assert_eq!(
        s.item(item.id, 1_000).unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[test]
fn a_locked_session_refuses_vault_access() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.vaults(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(
        s.items(&ItemFilter::default(), 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

use lockbox_core::model::{Field, Section};

/// base32 of "12345678901234567890" (RFC 6238 SHA-1 secret).
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn with_totp_and_dates(s: &mut Session) -> Item {
    let p = personal(s);
    let mut item = s.new_item(p, ItemKind::Login, 1_000).unwrap();
    item.title = "GitHub".into();
    item.fields[1].value = FieldValue::Concealed("hunter2".into());
    item.sections.push(Section {
        id: "extra".into(),
        title: "Extra".into(),
        fields: vec![
            Field {
                id: "otp".into(),
                label: "one-time password".into(),
                value: FieldValue::Totp(RFC_SECRET.into()),
                purpose: None,
            },
            Field {
                id: "born".into(),
                label: "birth date".into(),
                value: FieldValue::Date(631_152_000),
                purpose: None,
            },
            Field {
                id: "exp".into(),
                label: "expiry".into(),
                value: FieldValue::MonthYear(202_712),
                purpose: None,
            },
        ],
    });
    s.save_item(item, 1_000).unwrap()
}

#[test]
fn totp_code_for_a_known_secret() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    let code = s.totp(item.id, 59).unwrap().unwrap();
    assert_eq!(code.code, "287082");
    assert_eq!((code.seconds_left, code.period), (1, 30));
}

#[test]
fn totp_is_none_without_a_totp_field() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "Bank", "me", "pw");
    assert_eq!(s.totp(item.id, 59).unwrap(), None);
}

#[test]
fn polling_totp_does_not_keep_the_vault_unlocked() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    let timeout = AutoLock::DEFAULT_TIMEOUT_SECS;
    s.totp(item.id, 1_000 + timeout - 1).unwrap();
    assert!(s.tick(1_000 + timeout));
}

#[test]
fn copy_returns_the_value_and_arms_clipboard_clearing() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    assert_eq!(s.copy_value(item.id, "password", 1_000).unwrap(), "hunter2");
    assert!(s.clipboard_pending());
    assert!(s.clipboard_should_clear(1_000 + ClipboardGuard::DEFAULT_CLEAR_SECS, Some("hunter2")));
}

#[test]
fn copy_totp_dates_and_errors() {
    let (_dir, mut s) = unlocked_session();
    let item = with_totp_and_dates(&mut s);
    assert_eq!(s.copy_value(item.id, "totp", 59).unwrap(), "287082");
    assert_eq!(s.copy_value(item.id, "otp", 59).unwrap(), "287082");
    assert_eq!(s.copy_value(item.id, "born", 1_000).unwrap(), "1990-01-01");
    assert_eq!(s.copy_value(item.id, "exp", 1_000).unwrap(), "12/2027");
    assert_eq!(
        s.copy_value(item.id, "nope", 1_000).unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        s.copy_value(item.id, "username", 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
}

#[test]
fn formats_dates_as_iso() {
    assert_eq!(format_date(0), "1970-01-01");
    assert_eq!(format_date(951_782_400), "2000-02-29");
    assert_eq!(format_date(-86_400), "1969-12-31");
}

fn csv_export(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("export.csv");
    std::fs::write(
        &path,
        "Title,Url,Username,Password\nGitHub,https://github.com,ivan,pw1\nBank,,me,pw2\n",
    )
    .unwrap();
    path
}

#[test]
fn import_preview_then_apply() {
    let (dir, mut s) = unlocked_session();
    let preview = s.import_preview(&csv_export(&dir), 1_000).unwrap();
    assert_eq!(preview.total_items, 2);
    assert_eq!(preview.vaults.len(), 1);
    assert_eq!(
        (preview.vaults[0].name.as_str(), preview.vaults[0].items),
        ("Imported", 2)
    );
    assert!(preview.skipped.is_empty());

    let result = s.import_apply(1_000).unwrap();
    assert_eq!((result.vaults, result.items, result.attachments), (1, 2, 0));
    let vaults: Vec<_> = s
        .vaults(1_000)
        .unwrap()
        .into_iter()
        .map(|v| (v.name, v.item_count))
        .collect();
    assert_eq!(
        vaults,
        [("Personal".to_string(), 0), ("Imported".to_string(), 2)]
    );
    assert_eq!(
        s.import_apply(1_000).unwrap_err().kind,
        ErrorKind::Invalid,
        "plan is used once"
    );
}

#[test]
fn import_rejects_other_files_and_locked_sessions() {
    let (dir, mut s) = unlocked_session();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, "hello").unwrap();
    assert_eq!(
        s.import_preview(&txt, 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    let csv = csv_export(&dir);
    s.lock();
    assert_eq!(
        s.import_preview(&csv, 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

#[test]
fn locking_discards_a_pending_import() {
    let (dir, mut s) = unlocked_session();
    s.import_preview(&csv_export(&dir), 1_000).unwrap();
    s.lock();
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(s.import_apply(1_000).unwrap_err().kind, ErrorKind::Invalid);
}

#[test]
fn saving_a_deleted_item_is_refused_and_does_not_undelete_it() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    s.delete_item(item.id, 1_000).unwrap();
    assert_eq!(
        s.save_item(item.clone(), 2_000).unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert!(titles(&mut s, ItemFilter::default()).is_empty());
    let deleted = s.store.as_ref().unwrap().deleted_items().unwrap();
    assert_eq!(deleted.len(), 1);
    assert!(matches!(&deleted[0], lockbox_core::store::ItemEntry::Ok(i) if i.id == item.id));
}

#[test]
fn moving_an_item_to_another_vault_keeps_its_password_history() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let work = s.create_vault("Work", 1_000).unwrap().id;
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "first");
    item.fields[1].value = FieldValue::Concealed("second".into());
    let mut item = s.save_item(item, 2_000).unwrap();
    item.vault_id = work;
    let moved = s.save_item(item, 3_000).unwrap();
    assert_eq!(moved.vault_id, work);
    assert_eq!(moved.password_history.len(), 1);
    assert_eq!(moved.password_history[0].value, "first");
}

#[test]
fn clearing_the_password_records_the_old_one() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "secret");
    item.fields[1].value = FieldValue::Concealed(String::new());
    let saved = s.save_item(item, 2_000).unwrap();
    assert_eq!(saved.password_history[0].value, "secret");
}

#[test]
fn unlock_with_a_missing_database_is_not_a_wrong_password() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    std::fs::remove_file(&s.path).unwrap();
    let err = s.unlock(PW, 1_001).unwrap_err();
    assert_ne!(err.kind, ErrorKind::WrongPassword);
    assert_eq!(s.throttle.failures(), 0);
}

fn field_ids(item: &Item) -> Vec<&str> {
    item.fields.iter().map(|f| f.id.as_str()).collect()
}

#[test]
fn new_items_get_templates_per_kind() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let card = s.new_item(p, ItemKind::CreditCard, 1_000).unwrap();
    assert_eq!(field_ids(&card), ["cardholder", "number", "expiry", "cvv"]);
    assert!(matches!(card.fields[1].value, FieldValue::Concealed(_)));
    let id = s.new_item(p, ItemKind::Identity, 1_000).unwrap();
    assert_eq!(
        field_ids(&id),
        ["first-name", "last-name", "email", "phone"]
    );
    assert!(matches!(id.fields[2].value, FieldValue::Email(_)));
    let api = s.new_item(p, ItemKind::ApiCredential, 1_000).unwrap();
    assert_eq!(field_ids(&api), ["username", "credential", "hostname"]);
    assert!(api.fields.iter().all(|f| f.purpose.is_none()));
}

#[test]
fn saving_a_valid_totp_secret_enables_codes() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp(RFC_SECRET.into()),
        purpose: None,
    });
    let saved = s.save_item(item, 1_000).unwrap();
    assert_eq!(s.totp(saved.id, 59).unwrap().unwrap().code, "287082");
}

#[test]
fn saving_an_invalid_totp_secret_is_refused() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("not a secret!!".into()),
        purpose: None,
    });
    assert_eq!(
        s.save_item(item, 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
}

#[test]
fn empty_totp_fields_are_dropped_on_save() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.fields.push(Field {
        id: "otp-1".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("   ".into()),
        purpose: None,
    });
    let saved = s.save_item(item, 1_000).unwrap();
    assert_eq!(saved.totp(), None);
    assert_eq!(saved.fields.len(), 2);
}

use lockbox_core::store::DELETED_RETENTION_SECS;

#[test]
fn deleted_items_can_be_listed_and_restored() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    s.delete_item(item.id, 1_000).unwrap();
    let trash: Vec<_> = s
        .deleted_items(1_000)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(trash, ["GitHub"]);
    s.restore_item(item.id, 1_000).unwrap();
    assert!(s.deleted_items(1_000).unwrap().is_empty());
    assert_eq!(s.item(item.id, 1_000).unwrap().title, "GitHub");
}

#[test]
fn unlocking_purges_items_deleted_more_than_30_days_ago() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let old = save_login(&mut s, p, "Old", "a", "pw");
    let recent = save_login(&mut s, p, "Recent", "b", "pw");
    s.delete_item(old.id, 1_000).unwrap();
    s.delete_item(recent.id, 1_000 + DELETED_RETENTION_SECS as u64)
        .unwrap();
    s.lock();
    s.unlock(PW, 1_000 + DELETED_RETENTION_SECS as u64 + 1)
        .unwrap();
    let trash: Vec<_> = s
        .deleted_items(2_000)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(trash, ["Recent"]);
}

#[test]
fn trash_requires_unlock() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    assert_eq!(s.deleted_items(1_000).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(
        s.restore_item(Uuid::new_v4(), 1_000).unwrap_err().kind,
        ErrorKind::Locked
    );
}

use crate::settings::Settings;

#[test]
fn settings_persist_and_apply() {
    let (dir, mut s) = unlocked_session();
    assert_eq!(s.settings(), Settings::default());
    let new = Settings {
        auto_lock_minutes: 1,
        clipboard_seconds: 30,
    };
    assert_eq!(s.update_settings(new, 1_000).unwrap(), new);
    assert!(!s.tick(1_059));
    assert!(s.tick(1_060), "1-minute auto-lock applies immediately");

    let path = dir.path().join("Application Support").join("lockbox.db");
    let reopened = Session::new(path, KdfParams::INSECURE_FAST, 5_000);
    assert_eq!(reopened.settings(), new);
}

#[test]
fn clipboard_timeout_follows_settings() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let item = save_login(&mut s, p, "GitHub", "ivan", "hunter2");
    s.update_settings(
        Settings {
            auto_lock_minutes: 10,
            clipboard_seconds: 30,
        },
        1_000,
    )
    .unwrap();
    s.copy_value(item.id, "password", 1_000).unwrap();
    assert!(!s.clipboard_should_clear(1_029, Some("hunter2")));
    assert!(s.clipboard_should_clear(1_030, Some("hunter2")));
}

#[test]
fn invalid_settings_and_locked_sessions_are_refused() {
    let (_dir, mut s) = unlocked_session();
    let bad = Settings {
        auto_lock_minutes: 0,
        clipboard_seconds: 90,
    };
    assert_eq!(
        s.update_settings(bad, 1_000).unwrap_err().kind,
        ErrorKind::Invalid
    );
    s.lock();
    assert_eq!(
        s.update_settings(Settings::default(), 1_000)
            .unwrap_err()
            .kind,
        ErrorKind::Locked
    );
}
