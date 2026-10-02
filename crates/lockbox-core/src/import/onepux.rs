//! 1Password `.1pux` export: a zip with `export.data` (JSON) and `files/<documentId>__<fileName>`.

use std::io::{Cursor, Read, Seek};

use serde_json::Value;
use uuid::Uuid;
use zip::ZipArchive;

use super::{ImportPlan, ImportedItem, ImportedVault, Skipped};
use crate::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose, Section};
use crate::{Error, Result};

pub fn parse(bytes: &[u8], now: i64) -> Result<ImportPlan> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| Error::Invalid(format!("not a .1pux file: {e}")))?;
    let data: Value = {
        let mut entry = zip
            .by_name("export.data")
            .map_err(|_| Error::Invalid("export.data not found in .1pux".into()))?;
        let mut text = String::new();
        entry.read_to_string(&mut text)?;
        serde_json::from_str(&text)?
    };

    let mut plan = ImportPlan::default();
    for account in arr(&data["accounts"]) {
        for vault in arr(&account["vaults"]) {
            let name = vault["attrs"]["name"]
                .as_str()
                .unwrap_or("Imported")
                .to_owned();
            let mut items = Vec::new();
            for raw in arr(&vault["items"]) {
                let title = str_of(&raw["overview"]["title"]).to_owned();
                match raw["state"].as_str().unwrap_or("active") {
                    "active" | "archived" => {}
                    other => {
                        plan.skipped.push(Skipped {
                            title,
                            reason: format!("item state is {other}"),
                        });
                        continue;
                    }
                }
                let item = convert_item(raw, now);
                let attachments = read_files(raw, &mut zip, &mut plan.skipped, &title)?;
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

    for field in arr(&details["loginFields"]) {
        let value = str_of(&field["value"]);
        if value.is_empty() {
            continue;
        }
        let (purpose, value, id) = match str_of(&field["designation"]) {
            "username" => (
                Purpose::Username,
                FieldValue::Text(value.to_owned()),
                "username",
            ),
            "password" => (
                Purpose::Password,
                FieldValue::Concealed(value.to_owned()),
                "password",
            ),
            _ => continue,
        };
        item.fields.push(Field {
            id: id.into(),
            label: id.into(),
            value,
            purpose: Some(purpose),
        });
    }
    if let Some(password) = details["password"].as_str().filter(|s| !s.is_empty()) {
        item.fields.push(Field {
            id: "password".into(),
            label: "password".into(),
            value: FieldValue::Concealed(password.to_owned()),
            purpose: Some(Purpose::Password),
        });
    }

    item.notes = str_of(&details["notesPlain"]).to_owned();
    for section in arr(&details["sections"]) {
        let fields: Vec<Field> = arr(&section["fields"])
            .iter()
            .filter_map(convert_field)
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
    item.password_history = arr(&details["passwordHistory"])
        .iter()
        .filter_map(|h| {
            Some(HistoryEntry {
                value: h["value"].as_str()?.to_owned(),
                changed_at: h["time"].as_i64().unwrap_or(0),
            })
        })
        .collect();
    item
}

/// Section field value is an object with exactly one key naming its type.
fn convert_field(field: &Value) -> Option<Field> {
    let (kind, raw) = field["value"].as_object()?.iter().next()?;
    let value = match kind.as_str() {
        "concealed" | "creditCardNumber" => FieldValue::Concealed(text(raw)?),
        "totp" => FieldValue::Totp(text(raw)?),
        "email" => FieldValue::Email(
            raw["email_address"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| text(raw))?,
        ),
        "url" => FieldValue::Url(text(raw)?),
        "phone" => FieldValue::Phone(text(raw)?),
        "date" => FieldValue::Date(raw.as_i64()?),
        "monthYear" => FieldValue::MonthYear(u32::try_from(raw.as_i64()?).ok()?),
        "address" => FieldValue::Text(address(raw)?),
        "file" => return None, // handled by read_files
        _ => FieldValue::Text(text(raw)?),
    };
    Some(Field {
        id: str_of(&field["id"]).to_owned(),
        label: str_of(&field["title"]).to_owned(),
        value,
        purpose: None,
    })
}

/// Non-empty text of a value; objects (addresses) become their non-empty parts joined by ", ".
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::String(_) | Value::Null => None,
        Value::Object(map) => {
            let parts: Vec<&str> = map
                .values()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
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

fn read_files<R: Read + Seek>(
    raw: &Value,
    zip: &mut ZipArchive<R>,
    skipped: &mut Vec<Skipped>,
    title: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for (document_id, name) in file_refs(raw) {
        match zip.by_name(&format!("files/{document_id}__{name}")) {
            Ok(mut entry) => {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                out.push((name, bytes));
            }
            Err(_) => skipped.push(Skipped {
                title: format!("{title} / {name}"),
                reason: "attachment missing from export".into(),
            }),
        }
    }
    Ok(out)
}
