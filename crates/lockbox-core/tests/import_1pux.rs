use std::io::{Cursor, Write};

use lockbox_core::import::{onepux, ImportPlan};
use lockbox_core::model::{FieldValue, Item, ItemKind};
use lockbox_core::Error;
use zip::write::SimpleFileOptions;

const EXPORT_DATA: &str = include_str!("fixtures/export.data.json");
const NOW: i64 = 1_800_000_000;

fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        for (name, data) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    buf.into_inner()
}

fn full_export() -> Vec<u8> {
    build_zip(&[
        ("export.attributes", br#"{"version":3}"#),
        ("export.data", EXPORT_DATA.as_bytes()),
        ("files/DOC123__passport.pdf", b"%PDF-1.4"),
    ])
}

fn find<'a>(plan: &'a ImportPlan, title: &str) -> &'a Item {
    plan.vaults
        .iter()
        .flat_map(|v| v.items.iter())
        .map(|i| &i.item)
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn section_value<'a>(item: &'a Item, label: &str) -> &'a FieldValue {
    &item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find(|f| f.label == label)
        .unwrap()
        .value
}

#[test]
fn imports_vaults_and_skips_trashed_items() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let vaults: Vec<_> = plan
        .vaults
        .iter()
        .map(|v| (v.name.as_str(), v.items.len()))
        .collect();
    assert_eq!(vaults, [("Personal", 6), ("Datagile", 2)]);
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].title, "Old login");
    assert!(plan.skipped[0].reason.contains("trashed"));
}

#[test]
fn imports_a_login_completely() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let github = find(&plan, "GitHub");
    assert_eq!(github.kind, ItemKind::Login);
    assert_eq!(github.username(), Some("ivan"));
    assert_eq!(github.password(), Some("s3cret-Pass!"));
    assert_eq!(github.fields.len(), 2, "checkbox login fields are dropped");
    assert_eq!(github.urls, ["https://github.com/login"]);
    assert_eq!(github.tags, ["dev", "work"]);
    assert!(github.favorite);
    assert_eq!(github.notes, "work account");
    assert_eq!(
        github.totp(),
        Some("otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    );
    assert_eq!(
        *section_value(github, "recovery code"),
        FieldValue::Concealed("abcd-efgh".into())
    );
    assert_eq!(
        github.sections[0].fields.len(),
        2,
        "empty fields are dropped"
    );
    assert_eq!(github.password_history[0].value, "old-pass");
    assert_eq!(github.password_history[0].changed_at, 1690000000);
    assert_eq!(
        (github.created_at, github.updated_at),
        (1700000000, 1700000500)
    );
}

#[test]
fn imports_other_categories() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();

    let card = find(&plan, "Visa");
    assert_eq!(card.kind, ItemKind::CreditCard);
    assert!(!card.favorite);
    assert_eq!(
        *section_value(card, "number"),
        FieldValue::Concealed("4111111111111111".into())
    );
    assert_eq!(
        *section_value(card, "expiry date"),
        FieldValue::MonthYear(202712)
    );
    assert_eq!(
        *section_value(card, "type"),
        FieldValue::Text("visa".into())
    );

    assert_eq!(find(&plan, "Home Wi-Fi").kind, ItemKind::SecureNote);
    assert_eq!(find(&plan, "Home Wi-Fi").notes, "wifi: hunter2");

    let router = find(&plan, "Router admin");
    assert_eq!(router.kind, ItemKind::Password);
    assert_eq!(router.password(), Some("pw-only-123"));

    let api = find(&plan, "Stripe API");
    assert_eq!(api.kind, ItemKind::ApiCredential);
    assert_eq!(
        *section_value(api, "credential"),
        FieldValue::Concealed("sk-live-123".into())
    );

    let identity = find(&plan, "Ivan at work");
    assert_eq!(identity.kind, ItemKind::Identity);
    assert_eq!(
        *section_value(identity, "email"),
        FieldValue::Email("ivan@datagile.example".into())
    );
    assert_eq!(
        *section_value(identity, "birth date"),
        FieldValue::Date(631152000)
    );
    assert_eq!(
        *section_value(identity, "address"),
        FieldValue::Text("Main st 1, Hanoi, vn".into())
    );
    assert_eq!(
        *section_value(identity, "phone"),
        FieldValue::Phone("+84 123".into())
    );
    assert_eq!(identity.sections[0].title, "Identification");

    let server = find(&plan, "Prod server");
    assert_eq!(
        server.kind,
        ItemKind::SecureNote,
        "unknown categories become notes"
    );
    assert_eq!(
        *section_value(server, "URL"),
        FieldValue::Url("ssh://10.0.0.5".into())
    );
    assert_eq!(
        *section_value(server, "admin password"),
        FieldValue::Concealed("root-pw".into())
    );
}

#[test]
fn imports_document_attachments() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let doc = plan.vaults[0]
        .items
        .iter()
        .find(|i| i.item.title == "Passport scan")
        .unwrap();
    assert_eq!(
        doc.attachments,
        vec![("passport.pdf".to_string(), b"%PDF-1.4".to_vec())]
    );
}

#[test]
fn missing_attachment_is_reported_but_item_is_kept() {
    let zip = build_zip(&[("export.data", EXPORT_DATA.as_bytes())]);
    let plan = onepux::parse(&zip, NOW).unwrap();
    assert!(find(&plan, "Passport scan").attachments.is_empty());
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.title == "Passport scan / passport.pdf"));
}

#[test]
fn rejects_files_that_are_not_1pux() {
    assert!(matches!(
        onepux::parse(b"not a zip", NOW),
        Err(Error::Invalid(_))
    ));
    let no_data = build_zip(&[("something.txt", b"x")]);
    assert!(matches!(
        onepux::parse(&no_data, NOW),
        Err(Error::Invalid(_))
    ));
}
