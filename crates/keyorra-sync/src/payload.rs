//! Plaintext payloads of record versions: what an envelope's body carries once opened.
//!
//! ```text
//! item       = { "item": bytes (the Item JSON, as stored locally), "deleted_at": uint | null,
//!                "content_from": { bytes16 → uint } }
//! vault      = { "name": text, "wrapped_key": bytes, "deleted": bool }
//! attachment = { "item_id": bytes16, "name": text, "size": uint, "key": bytes32,
//!                "chunk_size": uint, "chunks": [bytes32, …] }
//! ```

use std::fmt;

use serde_json::Value as Json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::envelope::RecordKind;
use crate::error::{malformed, Result};
use crate::vv::Vector;

#[derive(Clone, PartialEq, Eq)]
pub struct ItemPayload {
    /// The item exactly as the local store serializes it (JSON object).
    pub item_json: Zeroizing<Vec<u8>>,
    /// Unix seconds when it was moved to Recently Deleted.
    pub deleted_at: Option<u64>,
    /// The version vector of the write that last changed `item_json`. Trashing and restoring
    /// keep it; an edit sets it to its own vector. Lets the fold tell a pure delete or restore
    /// from an edit (spec §3.5). Empty for a conflict copy as first written.
    pub content_from: Vector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPayload {
    pub name: String,
    /// The vault key wrapped by the account key (`keyorra-core` `wrap_vault_key`).
    pub wrapped_key: Vec<u8>,
    pub deleted: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentPayload {
    pub item_id: Uuid,
    pub name: String,
    pub size: u64,
    /// The attachment's own random key; its chunks are sealed with it.
    pub key: Zeroizing<[u8; 32]>,
    pub chunk_size: u32,
    pub chunks: Vec<[u8; 32]>,
}

/// The decoded content of one record version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Doc {
    Item(ItemPayload),
    Vault(VaultPayload),
    Attachment(AttachmentPayload),
    /// A purged record.
    Tombstone,
}

impl fmt::Debug for ItemPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemPayload")
            .field("item_json", &format_args!("{} bytes", self.item_json.len()))
            .field("deleted_at", &self.deleted_at)
            .field("content_from", &self.content_from)
            .finish()
    }
}

impl fmt::Debug for AttachmentPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentPayload")
            .field("item_id", &self.item_id)
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

impl Doc {
    pub fn kind(&self) -> Option<RecordKind> {
        match self {
            Doc::Item(_) => Some(RecordKind::Item),
            Doc::Vault(_) => Some(RecordKind::Vault),
            Doc::Attachment(_) => Some(RecordKind::Attachment),
            Doc::Tombstone => None,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let value = match self {
            Doc::Item(p) => Value::map(vec![
                ("item", Value::bytes(&*p.item_json)),
                ("deleted_at", p.deleted_at.map_or(Value::Null, Value::Uint)),
                (
                    "content_from",
                    Value::Map(
                        p.content_from
                            .iter()
                            .map(|(d, n)| (Value::bytes(d), Value::Uint(*n)))
                            .collect(),
                    ),
                ),
            ]),
            Doc::Vault(p) => Value::map(vec![
                ("name", Value::text(&p.name)),
                ("wrapped_key", Value::bytes(&p.wrapped_key)),
                ("deleted", Value::Bool(p.deleted)),
            ]),
            Doc::Attachment(p) => Value::map(vec![
                ("item_id", Value::bytes(p.item_id.as_bytes())),
                ("name", Value::text(&p.name)),
                ("size", Value::Uint(p.size)),
                ("key", Value::bytes(*p.key)),
                ("chunk_size", Value::Uint(p.chunk_size.into())),
                (
                    "chunks",
                    Value::Array(p.chunks.iter().map(Value::bytes).collect()),
                ),
            ]),
            Doc::Tombstone => return Zeroizing::new(Vec::new()),
        };
        Zeroizing::new(cbor::encode(&value))
    }

    pub fn decode(kind: RecordKind, bytes: &[u8]) -> Result<Doc> {
        let value = cbor::decode(bytes)?;
        Ok(match kind {
            RecordKind::Item => {
                let f = value.fields(&["item", "deleted_at", "content_from"])?;
                let item_json = Zeroizing::new(f.get("item")?.as_bytes()?.to_vec());
                if !matches!(
                    serde_json::from_slice::<Json>(&item_json),
                    Ok(Json::Object(_))
                ) {
                    return Err(malformed("item payload is not a JSON object"));
                }
                let mut content_from = Vector::new();
                for (device, n) in f.get("content_from")?.as_map()? {
                    content_from.insert(device.as_array_of()?, n.as_uint()?);
                }
                if content_from.values().any(|n| *n == 0) {
                    return Err(malformed("item content_from"));
                }
                Doc::Item(ItemPayload {
                    item_json,
                    deleted_at: match f.get("deleted_at")? {
                        Value::Null => None,
                        v => Some(v.as_uint()?),
                    },
                    content_from,
                })
            }
            RecordKind::Vault => {
                let f = value.fields(&["name", "wrapped_key", "deleted"])?;
                Doc::Vault(VaultPayload {
                    name: f.get("name")?.as_text()?.to_owned(),
                    wrapped_key: f.get("wrapped_key")?.as_bytes()?.to_vec(),
                    deleted: f.get("deleted")?.as_bool()?,
                })
            }
            RecordKind::Attachment => {
                let f =
                    value.fields(&["item_id", "name", "size", "key", "chunk_size", "chunks"])?;
                Doc::Attachment(AttachmentPayload {
                    item_id: Uuid::from_bytes(f.get("item_id")?.as_array_of()?),
                    name: f.get("name")?.as_text()?.to_owned(),
                    size: f.get("size")?.as_uint()?,
                    key: Zeroizing::new(f.get("key")?.as_array_of()?),
                    chunk_size: f.get("chunk_size")?.as_u32()?,
                    chunks: f
                        .get("chunks")?
                        .as_list()?
                        .iter()
                        .map(|c| c.as_array_of())
                        .collect::<Result<_>>()?,
                })
            }
        })
    }
}

fn parse_object(json: &[u8]) -> Option<serde_json::Map<String, Json>> {
    match serde_json::from_slice::<Json>(json) {
        Ok(Json::Object(map)) => Some(map),
        _ => None,
    }
}

/// "Same content" for items (spec §3.5): equal JSON values once `updated_at` is ignored.
/// `deleted_at` and `content_from` live outside the JSON, so they are ignored too.
pub fn item_content_eq(a: &ItemPayload, b: &ItemPayload) -> bool {
    match (parse_object(&a.item_json), parse_object(&b.item_json)) {
        (Some(mut x), Some(mut y)) => {
            x.remove("updated_at");
            y.remove("updated_at");
            x == y
        }
        _ => a.item_json == b.item_json,
    }
}

/// The attachment ids an item refers to (`attachments[].id`).
pub fn attachment_refs(item: &ItemPayload) -> Vec<Uuid> {
    parse_object(&item.item_json)
        .and_then(|o| o.get("attachments").cloned())
        .and_then(|a| match a {
            Json::Array(list) => Some(list),
            _ => None,
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|a| a.get("id")?.as_str()?.parse().ok())
        .collect()
}

/// Attachments of a conflict copy that stand for an attachment of the original:
/// (attachment id in the copy, original attachment id).
pub fn copied_attachment_refs(item: &ItemPayload) -> Vec<(Uuid, Uuid)> {
    let Some(Json::Array(list)) =
        parse_object(&item.item_json).and_then(|o| o.get("attachments").cloned())
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|a| {
            let id = a.get("id")?.as_str()?.parse().ok()?;
            let from = a.get("copied_from")?.as_str()?.parse().ok()?;
            Some((id, from))
        })
        .collect()
}

/// The conflict marker stored in a conflict copy (`conflict` field of the item JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictMarker {
    pub of: Uuid,
    pub version: [u8; 32],
    pub from_device: crate::DeviceId,
}

/// The item JSON of a conflict copy: new id, the conflict marker, attachment ids replaced
/// through `attachments` (old → new, with `copied_from` = old so the attachment record can be
/// created by whichever device knows the original). The title is left alone; the app shows the
/// "(conflict from …)" suffix from the marker, so the copy is the same on every device.
pub fn copy_item_json(
    item: &ItemPayload,
    copy_id: Uuid,
    marker: &ConflictMarker,
    attachments: &[(Uuid, Uuid)],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut obj = parse_object(&item.item_json).ok_or_else(|| malformed("item JSON"))?;
    obj.insert("id".into(), Json::String(copy_id.to_string()));
    obj.insert(
        "conflict".into(),
        serde_json::json!({
            "of": marker.of.to_string(),
            "version": data_encoding::HEXLOWER.encode(&marker.version),
            "from_device": data_encoding::HEXLOWER.encode(&marker.from_device),
        }),
    );
    if let Some(Json::Array(list)) = obj.get_mut("attachments") {
        for entry in list.iter_mut() {
            let Some(old) = entry
                .get("id")
                .and_then(Json::as_str)
                .and_then(|s| s.parse::<Uuid>().ok())
            else {
                continue;
            };
            if let Some((_, new)) = attachments.iter().find(|(o, _)| *o == old) {
                entry["id"] = Json::String(new.to_string());
                entry["copied_from"] = Json::String(old.to_string());
            }
        }
    }
    Ok(Zeroizing::new(
        serde_json::to_vec(&Json::Object(obj)).expect("JSON values serialize"),
    ))
}

/// The conflict marker of an item, if it is a conflict copy.
pub fn conflict_marker(item: &ItemPayload) -> Option<ConflictMarker> {
    let obj = parse_object(&item.item_json)?;
    let c = obj.get("conflict")?;
    let hex = |k: &str| {
        data_encoding::HEXLOWER
            .decode(c.get(k)?.as_str()?.as_bytes())
            .ok()
    };
    Some(ConflictMarker {
        of: c.get("of")?.as_str()?.parse().ok()?,
        version: hex("version")?.try_into().ok()?,
        from_device: hex("from_device")?.try_into().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn item(json: &str, deleted_at: Option<u64>) -> ItemPayload {
        ItemPayload {
            item_json: Zeroizing::new(json.as_bytes().to_vec()),
            deleted_at,
            content_from: [([1; 16], 1)].into_iter().collect(),
        }
    }

    fn attachment() -> AttachmentPayload {
        AttachmentPayload {
            item_id: Uuid::from_bytes([1; 16]),
            name: "scan.pdf".into(),
            size: 5,
            key: Zeroizing::new([2; 32]),
            chunk_size: 4 * 1024 * 1024,
            chunks: vec![[3; 32]],
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let docs = [
            (
                RecordKind::Item,
                Doc::Item(item(r#"{"title":"a"}"#, Some(7))),
            ),
            (RecordKind::Item, Doc::Item(item(r#"{"title":"a"}"#, None))),
            (
                RecordKind::Vault,
                Doc::Vault(VaultPayload {
                    name: "Personal".into(),
                    wrapped_key: vec![9; 72],
                    deleted: true,
                }),
            ),
            (RecordKind::Attachment, Doc::Attachment(attachment())),
        ];
        for (kind, doc) in docs {
            assert_eq!(doc.kind(), Some(kind));
            assert_eq!(Doc::decode(kind, &doc.encode()).unwrap(), doc);
        }
    }

    #[test]
    fn decode_checks_shape_and_kind() {
        let vault = Doc::Vault(VaultPayload {
            name: "x".into(),
            wrapped_key: vec![],
            deleted: false,
        })
        .encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &vault),
            Err(Error::Malformed(_))
        ));
        let not_object = Doc::Item(item("[1]", None)).encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &not_object),
            Err(Error::Malformed(_))
        ));
        // An empty content_from (a copy as first written) is fine; a zero entry is not.
        let mut first_copy = item("{}", None);
        first_copy.content_from.clear();
        let first_copy = Doc::Item(first_copy);
        assert_eq!(
            Doc::decode(RecordKind::Item, &first_copy.encode()).unwrap(),
            first_copy
        );
        let mut zero = item("{}", None);
        zero.content_from.insert([2; 16], 0);
        let zero = Doc::Item(zero).encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &zero),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn content_equality_ignores_updated_at_and_deleted_at_only() {
        let a = item(r#"{"title":"a","updated_at":1}"#, None);
        assert!(item_content_eq(
            &a,
            &item(r#"{"updated_at":2,"title":"a"}"#, Some(5))
        ));
        assert!(!item_content_eq(
            &a,
            &item(r#"{"title":"b","updated_at":1}"#, None)
        ));
    }

    #[test]
    fn copy_json_gets_new_id_marker_and_attachment_ids() {
        let (old_att, new_att) = (Uuid::from_bytes([5; 16]), Uuid::from_bytes([6; 16]));
        let original = item(
            &format!(
                r#"{{"id":"x","title":"GitHub","attachments":[{{"id":"{old_att}","name":"a"}}]}}"#
            ),
            None,
        );
        let marker = ConflictMarker {
            of: Uuid::from_bytes([4; 16]),
            version: [7; 32],
            from_device: [8; 16],
        };
        let copy_id = Uuid::from_bytes([9; 16]);
        let json = copy_item_json(&original, copy_id, &marker, &[(old_att, new_att)]).unwrap();
        let copy = item(std::str::from_utf8(&json).unwrap(), None);
        let v: Json = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["id"], copy_id.to_string());
        assert_eq!(v["title"], "GitHub");
        assert_eq!(attachment_refs(&copy), vec![new_att]);
        assert_eq!(copied_attachment_refs(&copy), vec![(new_att, old_att)]);
        assert_eq!(copied_attachment_refs(&original), vec![]);
        assert_eq!(conflict_marker(&copy), Some(marker));
        assert_eq!(conflict_marker(&original), None);
    }

    #[test]
    fn debug_hides_secrets() {
        let shown = format!(
            "{:?} {:?}",
            item(r#"{"password":"hunter2"}"#, None),
            attachment()
        );
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("[2, 2"));
    }
}
