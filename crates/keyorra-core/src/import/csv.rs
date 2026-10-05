//! CSV export of 1Password (and other managers with similar headers).

use uuid::Uuid;

use super::{ImportPlan, ImportedItem, ImportedVault};
use crate::model::{Field, FieldValue, Item, ItemKind, Purpose};
use crate::{Error, Result};

fn is_true(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "true" | "1" | "yes")
}

pub fn parse(text: &str, vault_name: &str, now: i64) -> Result<ImportPlan> {
    let csv_err = |e: ::csv::Error| Error::Invalid(format!("CSV: {e}"));
    let mut reader = ::csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(csv_err)?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let c_title = col(&["title", "name"]);
    let c_url = col(&["url", "website", "login_uri"]);
    let c_user = col(&["username", "login", "login_username"]);
    let c_pass = col(&["password", "login_password"]);
    let c_otp = col(&["otpauth", "otp", "totp", "one-time password", "login_totp"]);
    let c_notes = col(&["notes", "note"]);
    let c_tags = col(&["tags"]);
    let c_fav = col(&["favorite"]);
    let c_archived = col(&["archived"]);
    if c_title.is_none() && c_url.is_none() && c_pass.is_none() {
        return Err(Error::Invalid(
            "unrecognized CSV: expected a header row with title/url/username/password columns"
                .into(),
        ));
    }

    let mut vault = ImportedVault {
        name: vault_name.to_owned(),
        items: Vec::new(),
    };
    for record in reader.records() {
        let record = record.map_err(csv_err)?;
        // Secrets and notes are taken verbatim: whitespace may be part of them.
        let raw = |c: Option<usize>| c.and_then(|i| record.get(i)).unwrap_or("");
        let get = |c: Option<usize>| raw(c).trim();
        let (url, user, pass) = (get(c_url), raw(c_user), raw(c_pass));
        if [c_title, c_url, c_tags]
            .into_iter()
            .all(|c| get(c).is_empty())
            && [c_user, c_pass, c_otp, c_notes]
                .into_iter()
                .all(|c| raw(c).is_empty())
        {
            continue;
        }
        let kind = if url.is_empty() && user.is_empty() && pass.is_empty() {
            ItemKind::SecureNote
        } else {
            ItemKind::Login
        };
        let title = if get(c_title).is_empty() {
            url
        } else {
            get(c_title)
        };
        let mut item = Item::new(Uuid::nil(), kind, title, now);
        if !url.is_empty() {
            item.urls.push(url.to_owned());
        }
        if !user.is_empty() {
            item.fields.push(Field {
                id: "username".into(),
                label: "username".into(),
                value: FieldValue::Text(user.to_owned()),
                purpose: Some(Purpose::Username),
                extra: Default::default(),
            });
        }
        if !pass.is_empty() {
            item.set_password(pass, now);
        }
        let otp = raw(c_otp);
        if !otp.is_empty() {
            item.fields.push(Field {
                id: "one-time-password".into(),
                label: "one-time password".into(),
                value: FieldValue::Totp(otp.to_owned()),
                purpose: None,
                extra: Default::default(),
            });
        }
        item.notes = raw(c_notes).to_owned();
        item.tags = get(c_tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        if is_true(get(c_archived)) && !item.tags.iter().any(|t| t == "archived") {
            item.tags.push("archived".into());
        }
        item.favorite = is_true(get(c_fav));
        vault.items.push(ImportedItem {
            item,
            attachments: Vec::new(),
        });
    }
    Ok(ImportPlan {
        vaults: vec![vault],
        skipped: Vec::new(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, ItemKind};
    use crate::Error;

    const ONEPASSWORD_CSV: &str = "\
Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
GitHub,https://github.com,ivan,s3cret,otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP,true,false,\"dev,work\",main account
Wi-Fi,,,,,false,false,,\"ssid: home
pass: hunter2\"
";

    #[test]
    fn parses_1password_csv() {
        let plan = parse(ONEPASSWORD_CSV, "Imported", 42).unwrap();
        assert_eq!(plan.vaults.len(), 1);
        assert_eq!(plan.vaults[0].name, "Imported");
        assert_eq!(plan.item_count(), 2);

        let github = &plan.vaults[0].items[0].item;
        assert_eq!(github.kind, ItemKind::Login);
        assert_eq!(github.title, "GitHub");
        assert_eq!(github.urls, ["https://github.com"]);
        assert_eq!(github.username(), Some("ivan"));
        assert_eq!(github.password(), Some("s3cret"));
        assert_eq!(
            github.totp(),
            Some("otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP")
        );
        assert!(github.favorite);
        assert_eq!(github.tags, ["dev", "work"]);
        assert_eq!(github.notes, "main account");
        assert_eq!(github.created_at, 42);

        let wifi = &plan.vaults[0].items[1].item;
        assert_eq!(wifi.kind, ItemKind::SecureNote);
        assert_eq!(wifi.notes, "ssid: home\npass: hunter2");
        assert!(wifi.fields.is_empty());
    }

    #[test]
    fn accepts_other_common_header_names() {
        let csv = "name,login_uri,login_username,login_password\nBank,https://bank.example,me,pw\n";
        let item = &parse(csv, "Imported", 0).unwrap().vaults[0].items[0].item;
        assert_eq!(item.title, "Bank");
        assert_eq!(item.urls, ["https://bank.example"]);
        assert_eq!(item.username(), Some("me"));
        assert_eq!(item.password(), Some("pw"));
    }

    #[test]
    fn title_falls_back_to_url() {
        let csv = "url,password\nhttps://x.example,pw\n";
        assert_eq!(
            parse(csv, "I", 0).unwrap().vaults[0].items[0].item.title,
            "https://x.example"
        );
    }

    #[test]
    fn rejects_unrecognized_headers() {
        assert!(matches!(
            parse("a,b\n1,2\n", "I", 0),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn otp_field_is_a_totp_field() {
        let item = &parse(ONEPASSWORD_CSV, "I", 0).unwrap().vaults[0].items[0].item;
        assert!(item
            .fields
            .iter()
            .any(|f| matches!(f.value, FieldValue::Totp(_))));
    }

    #[test]
    fn archived_rows_get_a_tag() {
        let plan = parse(
            "Title,Password,Archived,Tags\nOld,pw,true,x\nNew,pw,false,\n",
            "I",
            0,
        )
        .unwrap();
        let items = &plan.vaults[0].items;
        assert_eq!(items[0].item.tags, ["x", "archived"]);
        assert!(items[1].item.tags.is_empty());
    }

    #[test]
    fn secrets_and_notes_are_taken_verbatim() {
        let csv = "Title,Username,Password,OTPAuth,Notes\nA, bob ,  pw with spaces  , otpauth://x ,\" note \"\n";
        let item = &parse(csv, "I", 0).unwrap().vaults[0].items[0].item;
        assert_eq!(item.username(), Some(" bob "));
        assert_eq!(item.password(), Some("  pw with spaces  "));
        assert_eq!(item.totp(), Some(" otpauth://x "));
        assert_eq!(item.notes, " note ");
    }

    #[test]
    fn rows_with_every_column_empty_are_skipped() {
        let csv = "Title,Url,Password,Favorite\nA,,pw,false\n,,,false\n,,,\n";
        let plan = parse(csv, "I", 0).unwrap();
        assert_eq!(plan.item_count(), 1);
    }
}
