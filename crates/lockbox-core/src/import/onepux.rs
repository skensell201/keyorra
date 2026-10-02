//! 1Password `.1pux` export: a zip with `export.data` (JSON) and `files/<documentId>__<fileName>`.

use std::io::{Cursor, Read, Seek};

use serde_json::Value;
use uuid::Uuid;
use zip::ZipArchive;

use super::{ImportPlan, ImportedItem, ImportedVault, Skipped};
use crate::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose, Section};
use crate::{Error, Result};

const MIB: u64 = 1024 * 1024;
const MAX_EXPORT_DATA: u64 = 256 * MIB;
const MAX_ATTACHMENT: u64 = 100 * MIB;

pub fn parse(bytes: &[u8], now: i64) -> Result<ImportPlan> {
    parse_with_limits(bytes, now, MAX_EXPORT_DATA, MAX_ATTACHMENT)
}

/// Reads at most `limit` bytes; `Ok(None)` if the entry is larger.
fn read_limited(entry: impl Read, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    entry.take(limit + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

fn parse_with_limits(
    bytes: &[u8],
    now: i64,
    max_data: u64,
    max_attachment: u64,
) -> Result<ImportPlan> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| Error::Invalid(format!("not a .1pux file: {e}")))?;
    let data: Value = {
        let entry = zip
            .by_name("export.data")
            .map_err(|_| Error::Invalid("export.data not found in .1pux".into()))?;
        let raw = read_limited(entry, max_data)?.ok_or_else(|| {
            Error::Invalid(format!("export.data is larger than {} MiB", max_data / MIB))
        })?;
        serde_json::from_slice(&raw)?
    };

    let mut plan = ImportPlan::default();
    let several_accounts = arr(&data["accounts"]).len() > 1;
    for account in arr(&data["accounts"]) {
        for vault in arr(&account["vaults"]) {
            let mut name = vault["attrs"]["name"]
                .as_str()
                .unwrap_or("Imported")
                .to_owned();
            if several_accounts {
                let account_name = account["attrs"]["accountName"]
                    .as_str()
                    .or_else(|| account["attrs"]["name"].as_str())
                    .unwrap_or("account");
                name = format!("{account_name} \u{2014} {name}");
            }
            let mut items = Vec::new();
            for raw in arr(&vault["items"]) {
                let title = str_of(&raw["overview"]["title"]).to_owned();
                let state = raw["state"].as_str().unwrap_or("active");
                match state {
                    "active" | "archived" => {}
                    other => {
                        plan.skipped.push(Skipped {
                            title,
                            reason: format!("item state is {other}"),
                        });
                        continue;
                    }
                }
                let mut item = convert_item(raw, now);
                if state == "archived" && !item.tags.iter().any(|t| t == "archived") {
                    item.tags.push("archived".into());
                }
                let attachments =
                    read_files(raw, &mut zip, &mut plan.skipped, &title, max_attachment)?;
                items.push(ImportedItem { item, attachments });
            }
            plan.vaults.push(ImportedVault { name, items });
        }
    }
    Ok(plan)
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn convert_item(raw: &Value, now: i64) -> Item {
    let kind = match str_of(&raw["categoryUuid"]) {
        "001" => ItemKind::Login,
        "002" => ItemKind::CreditCard,
        "003" => ItemKind::SecureNote,
        "004" => ItemKind::Identity,
        "005" => ItemKind::Password,
        "112" => ItemKind::ApiCredential,
        _ => ItemKind::SecureNote,
    };
    let overview = &raw["overview"];
    let details = &raw["details"];
    let created = raw["createdAt"].as_i64().unwrap_or(now);

    let mut item = Item::new(Uuid::nil(), kind, str_of(&overview["title"]), created);
    item.updated_at = raw["updatedAt"].as_i64().unwrap_or(created);
    item.favorite = raw["favIndex"].as_i64().unwrap_or(0) > 0;
    item.tags = arr(&overview["tags"])
        .iter()
        .filter_map(|t| t.as_str().map(str::to_owned))
        .collect();
    item.urls = arr(&overview["urls"])
        .iter()
        .filter_map(|u| u["url"].as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if item.urls.is_empty() {
        if let Some(url) = overview["url"].as_str().filter(|s| !s.is_empty()) {
            item.urls.push(url.to_owned());
        }
    }

    let mut extra_login_fields = Vec::new();
    for field in arr(&details["loginFields"]) {
        let value = str_of(&field["value"]);
        if value.is_empty() {
            continue;
        }
        let built_in = match str_of(&field["designation"]) {
            "username" => Some((
                Purpose::Username,
                FieldValue::Text(value.to_owned()),
                "username",
            )),
            "password" => Some((
                Purpose::Password,
                FieldValue::Concealed(value.to_owned()),
                "password",
            )),
            _ => None,
        };
        if let Some((purpose, value, id)) = built_in {
            item.fields.push(Field {
                id: id.into(),
                label: id.into(),
                value,
                purpose: Some(purpose),
            });
            continue;
        }
        let value = match str_of(&field["fieldType"]) {
            "C" | "B" => continue, // checkboxes and buttons carry no data
            "P" => FieldValue::Concealed(value.to_owned()),
            "E" => FieldValue::Email(value.to_owned()),
            _ => FieldValue::Text(value.to_owned()),
        };
        let name = str_of(&field["name"]);
        let label = if name.is_empty() {
            str_of(&field["id"])
        } else {
            name
        };
        extra_login_fields.push(Field {
            id: label.to_owned(),
            label: label.to_owned(),
            value,
            purpose: None,
        });
    }
    if let Some(password) = details["password"].as_str().filter(|s| !s.is_empty()) {
        if item.password().is_none() {
            item.fields.push(Field {
                id: "password".into(),
                label: "password".into(),
                value: FieldValue::Concealed(password.to_owned()),
                purpose: Some(Purpose::Password),
            });
        }
    }

    item.notes = str_of(&details["notesPlain"]).to_owned();
    for section in arr(&details["sections"]) {
        let fields: Vec<Field> = arr(&section["fields"])
            .iter()
            .flat_map(convert_field)
            .collect();
        if fields.is_empty() {
            continue;
        }
        item.sections.push(Section {
            id: str_of(&section["name"]).to_owned(),
            title: str_of(&section["title"]).to_owned(),
            fields,
        });
    }
    if !extra_login_fields.is_empty() {
        item.sections.push(Section {
            id: "login-fields".into(),
            title: "Login fields".into(),
            fields: extra_login_fields,
        });
    }
    item.password_history = arr(&details["passwordHistory"])
        .iter()
        .filter_map(|h| {
            Some(HistoryEntry {
                value: h["value"].as_str()?.to_owned(),
                changed_at: h["time"].as_i64().unwrap_or(0),
            })
        })
        .collect();
    item.password_history
        .sort_by_key(|h| std::cmp::Reverse(h.changed_at));
    item
}

/// Section field value is an object with exactly one key naming its type.
/// One source field can yield several fields (SSH keys).
fn convert_field(field: &Value) -> Vec<Field> {
    let Some((kind, raw)) = field["value"].as_object().and_then(|o| o.iter().next()) else {
        return Vec::new();
    };
    let id = str_of(&field["id"]);
    let title = str_of(&field["title"]);
    let make = |id: &str, label: &str, value: FieldValue| Field {
        id: id.to_owned(),
        label: label.to_owned(),
        value,
        purpose: None,
    };
    if kind == "sshKey" {
        let mut out = Vec::new();
        let label = if title.is_empty() {
            "private key"
        } else {
            title
        };
        if let Some(key) = text(&raw["privateKey"]) {
            out.push(make(id, label, FieldValue::Concealed(key)));
        }
        for (json_key, label) in [("publicKey", "public key"), ("fingerprint", "fingerprint")] {
            if let Some(v) = text(&raw["metadata"][json_key]) {
                out.push(make(
                    &format!("{id}-{json_key}"),
                    label,
                    FieldValue::Text(v),
                ));
            }
        }
        return out;
    }
    let value = match kind.as_str() {
        "concealed" | "creditCardNumber" => text(raw).map(FieldValue::Concealed),
        "totp" => text(raw).map(FieldValue::Totp),
        "email" => raw["email_address"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| text(raw))
            .map(FieldValue::Email),
        "url" => text(raw).map(FieldValue::Url),
        "phone" => text(raw).map(FieldValue::Phone),
        "date" => match raw.as_i64() {
            Some(n) => Some(FieldValue::Date(n)),
            None => text(raw).map(FieldValue::Text),
        },
        "monthYear" => match raw.as_i64().and_then(|n| u32::try_from(n).ok()) {
            Some(n) => Some(FieldValue::MonthYear(n)),
            None => text(raw).map(FieldValue::Text),
        },
        "address" => address(raw).or_else(|| text(raw)).map(FieldValue::Text),
        "file" => None, // handled by read_files
        _ => text(raw).map(FieldValue::Text),
    };
    value.map(|v| make(id, title, v)).into_iter().collect()
}

/// Non-empty text of a value; flat string objects become their non-empty parts joined by ", ",
/// anything else nested becomes compact JSON.
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::String(_) | Value::Null => None,
        Value::Object(map) if map.values().all(|v| v.is_string() || v.is_null()) => {
            let parts: Vec<&str> = map
                .values()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        // Nested data is kept as compact JSON rather than dropped.
        other => Some(other.to_string()),
    }
}

/// Postal order, independent of JSON key order.
fn address(v: &Value) -> Option<String> {
    let parts: Vec<&str> = ["street", "city", "state", "zip", "country"]
        .iter()
        .filter_map(|k| v[*k].as_str())
        .filter(|s| !s.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// (documentId, fileName) for the item's document and any file fields in sections.
fn file_refs(raw: &Value) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut push = |v: &Value| {
        if let (Some(id), Some(name)) = (v["documentId"].as_str(), v["fileName"].as_str()) {
            refs.push((id.to_owned(), name.to_owned()));
        }
    };
    push(&raw["details"]["documentAttributes"]);
    for section in arr(&raw["details"]["sections"]) {
        for field in arr(&section["fields"]) {
            push(&field["value"]["file"]);
        }
    }
    refs
}

/// Last path component; never empty, never a relative-path marker.
fn basename(name: &str) -> String {
    match name.rsplit(['/', '\\']).next().unwrap_or("") {
        "" | "." | ".." => "attachment".to_owned(),
        base => base.to_owned(),
    }
}

fn read_files<R: Read + Seek>(
    raw: &Value,
    zip: &mut ZipArchive<R>,
    skipped: &mut Vec<Skipped>,
    title: &str,
    max_attachment: u64,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for (document_id, stored_name) in file_refs(raw) {
        let name = basename(&stored_name);
        let mut skip = |reason: String| {
            skipped.push(Skipped {
                title: format!("{title} / {name}"),
                reason,
            })
        };
        match zip.by_name(&format!("files/{document_id}__{stored_name}")) {
            Ok(entry) => match read_limited(entry, max_attachment) {
                Ok(Some(bytes)) => out.push((name.clone(), bytes)),
                Ok(None) => skip(format!(
                    "attachment larger than {} MiB",
                    max_attachment / MIB
                )),
                Err(e) => skip(format!("attachment unreadable: {e}")),
            },
            Err(_) => skip("attachment missing from export".into()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    use super::*;

    const DATA: &str = r#"{"accounts":[{"vaults":[{"attrs":{"name":"V"},"items":[{"uuid":"d","state":"active","categoryUuid":"006","details":{"documentAttributes":{"fileName":"a.bin","documentId":"D"}},"overview":{"title":"Doc"}}]}]}]}"#;

    fn zip_with(data: &str, file: &[u8]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("export.data", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(data.as_bytes()).unwrap();
            zip.start_file("files/D__a.bin", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(file).unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn oversized_attachment_is_skipped() {
        let zip = zip_with(DATA, &[7; 10]);
        let plan = parse_with_limits(&zip, 0, 1 << 20, 5).unwrap();
        assert!(plan.vaults[0].items[0].attachments.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].title, "Doc / a.bin");
        assert!(plan.skipped[0].reason.contains("larger than"));
        // exactly at the limit is accepted
        let plan = parse_with_limits(&zip, 0, 1 << 20, 10).unwrap();
        assert_eq!(plan.vaults[0].items[0].attachments.len(), 1);
    }

    #[test]
    fn oversized_export_data_is_rejected() {
        let zip = zip_with(DATA, b"x");
        let err = parse_with_limits(&zip, 0, 10, 1 << 20).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
