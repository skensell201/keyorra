//! One version of one record, as carried inline in a log segment (plan A1c).
//!
//! For items and attachments the `body` is sealed with the vault key; its associated data
//! binds account, kind, ids, schema and the full version, so a body cannot be moved to another
//! record, vault or version. For vault records the body is the plaintext payload (protected by
//! the segment layer; the vault key inside is wrapped by the account key as today).

use std::collections::BTreeMap;

use keyorra_core::crypto::{self, Key, NONCE_LEN};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::{AccountId, DeviceId};

pub const ENVELOPE_FORMAT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    Vault,
    Item,
    Attachment,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Vault => "vault",
            RecordKind::Item => "item",
            RecordKind::Attachment => "attachment",
        }
    }

    pub fn parse(s: &str) -> Result<RecordKind> {
        match s {
            "vault" => Ok(RecordKind::Vault),
            "item" => Ok(RecordKind::Item),
            "attachment" => Ok(RecordKind::Attachment),
            other => Err(Error::Unsupported(format!("record kind {other}"))),
        }
    }

    /// Whether the body is sealed with the vault key (and `vault_id` is required).
    pub fn sealed_with_vault_key(self) -> bool {
        !matches!(self, RecordKind::Vault)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// How many writes of each device this version includes.
    pub vector: BTreeMap<DeviceId, u64>,
    /// Hybrid logical clock: 48-bit unix milliseconds | 16-bit counter.
    pub hlc: u64,
    pub author: DeviceId,
}

impl Version {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (
                "vector",
                Value::Map(
                    self.vector
                        .iter()
                        .map(|(d, n)| (Value::bytes(d), Value::Uint(*n)))
                        .collect(),
                ),
            ),
            ("hlc", Value::Uint(self.hlc)),
            ("author", Value::bytes(self.author)),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Version> {
        let f = value.fields(&["vector", "hlc", "author"])?;
        let mut vector = BTreeMap::new();
        for (device, count) in f.get("vector")?.as_map()? {
            let count = count.as_uint()?;
            if count == 0 {
                return Err(malformed("zero entry in version vector"));
            }
            vector.insert(device.as_array_of()?, count);
        }
        Ok(Version {
            vector,
            hlc: f.get("hlc")?.as_uint()?,
            author: f.get("author")?.as_array_of()?,
        })
    }
}

/// `SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, version]))`.
pub fn version_hash(kind: RecordKind, record_id: Uuid, version: &Version) -> [u8; 32] {
    let value = Value::Array(vec![
        Value::text(kind.as_str()),
        Value::bytes(record_id.as_bytes()),
        version.to_value(),
    ]);
    Sha256::digest(tagged(labels::VERSION, &[&cbor::encode(&value)])).into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: RecordKind,
    pub record_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub schema: u32,
    pub version: Version,
    /// A purged record: no body.
    pub tombstone: bool,
    pub body: Option<Vec<u8>>,
}

const FIELDS: [&str; 8] = [
    "format",
    "kind",
    "record_id",
    "vault_id",
    "schema",
    "version",
    "tombstone",
    "body",
];

impl Envelope {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("format", Value::Uint(ENVELOPE_FORMAT)),
            ("kind", Value::text(self.kind.as_str())),
            ("record_id", Value::bytes(self.record_id.as_bytes())),
            (
                "vault_id",
                self.vault_id
                    .map_or(Value::Null, |v| Value::bytes(v.as_bytes())),
            ),
            ("schema", Value::Uint(self.schema.into())),
            ("version", self.version.to_value()),
            ("tombstone", Value::Bool(self.tombstone)),
            ("body", self.body.as_ref().map_or(Value::Null, Value::bytes)),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Envelope> {
        let format = value
            .as_map()?
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "format"))
            .ok_or_else(|| malformed("envelope without format"))?
            .1
            .as_uint()?;
        if format != ENVELOPE_FORMAT {
            return Err(Error::Unsupported(format!("envelope format {format}")));
        }
        let f = value.fields(&FIELDS)?;
        let uuid = |v: &Value| v.as_array_of::<16>().map(Uuid::from_bytes);
        let env = Envelope {
            kind: RecordKind::parse(f.get("kind")?.as_text()?)?,
            record_id: uuid(f.get("record_id")?)?,
            vault_id: match f.get("vault_id")? {
                Value::Null => None,
                v => Some(uuid(v)?),
            },
            schema: f.get("schema")?.as_u32()?,
            version: Version::from_value(f.get("version")?)?,
            tombstone: f.get("tombstone")?.as_bool()?,
            body: match f.get("body")? {
                Value::Null => None,
                v => Some(v.as_bytes()?.to_vec()),
            },
        };
        env.check()?;
        Ok(env)
    }

    /// Shape rules: a tombstone has no body, anything else has one; vault-key kinds name
    /// their vault.
    pub fn check(&self) -> Result<()> {
        if self.tombstone == self.body.is_some() {
            return Err(malformed("tombstone and body disagree"));
        }
        if self.kind.sealed_with_vault_key() && self.vault_id.is_none() {
            return Err(malformed("record without vault"));
        }
        Ok(())
    }

    /// `SHA-256(canonical(envelope with body = null))`: what the body is bound to.
    pub fn header_hash(&self) -> [u8; 32] {
        let bare = Envelope {
            body: None,
            ..self.clone()
        };
        Sha256::digest(cbor::encode(&bare.to_value())).into()
    }

    pub fn version_hash(&self) -> [u8; 32] {
        version_hash(self.kind, self.record_id, &self.version)
    }

    fn body_aad(&self, account_id: &AccountId) -> Vec<u8> {
        tagged(labels::BODY, &[account_id, &self.header_hash()])
    }

    /// Seals `payload` with the vault key into `self.body`.
    pub fn seal_body(
        &mut self,
        vault_key: &Key,
        account_id: &AccountId,
        payload: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) {
        assert!(
            self.kind.sealed_with_vault_key(),
            "vault records carry plaintext bodies"
        );
        self.tombstone = false;
        let aad = self.body_aad(account_id);
        self.body = Some(crypto::seal_with_nonce(vault_key, nonce, payload, &aad));
    }

    pub fn open_body(&self, vault_key: &Key, account_id: &AccountId) -> Result<Zeroizing<Vec<u8>>> {
        let body = self.body.as_ref().ok_or_else(|| malformed("no body"))?;
        crypto::open(vault_key, body, &self.body_aad(account_id)).map_err(|_| Error::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = [0x10; 16];
    const A: DeviceId = [0x40; 16];
    const B: DeviceId = [0x41; 16];

    fn version() -> Version {
        Version {
            vector: BTreeMap::from([(A, 2), (B, 1)]),
            hlc: 0x0192_0000_0000_0001,
            author: A,
        }
    }

    fn item() -> Envelope {
        let mut env = Envelope {
            kind: RecordKind::Item,
            record_id: Uuid::from_bytes([0x60; 16]),
            vault_id: Some(Uuid::from_bytes([0x61; 16])),
            schema: 1,
            version: version(),
            tombstone: false,
            body: None,
        };
        env.seal_body(
            &Key::from_bytes([0x70; 32]),
            &ACCOUNT,
            b"{\"title\":\"x\"}",
            &[0x51; NONCE_LEN],
        );
        env
    }

    #[test]
    fn round_trips_through_cbor() {
        let env = item();
        let bytes = cbor::encode(&env.to_value());
        assert_eq!(
            Envelope::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
            env
        );
    }

    #[test]
    fn body_opens_with_the_right_key_and_account() {
        let env = item();
        let key = Key::from_bytes([0x70; 32]);
        assert_eq!(
            &*env.open_body(&key, &ACCOUNT).unwrap(),
            b"{\"title\":\"x\"}"
        );
        assert!(matches!(
            env.open_body(&Key::from_bytes([0x71; 32]), &ACCOUNT),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            env.open_body(&key, &[0x11; 16]),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn body_cannot_move_to_another_record_vault_schema_or_version() {
        let key = Key::from_bytes([0x70; 32]);
        let env = item();
        let mut newer = version();
        newer.vector.insert(A, 3);
        for moved in [
            Envelope {
                record_id: Uuid::from_bytes([0x62; 16]),
                ..env.clone()
            },
            Envelope {
                vault_id: Some(Uuid::from_bytes([0x63; 16])),
                ..env.clone()
            },
            Envelope {
                schema: 2,
                ..env.clone()
            },
            Envelope {
                kind: RecordKind::Attachment,
                ..env.clone()
            },
            Envelope {
                version: newer,
                ..env.clone()
            },
            Envelope {
                version: Version {
                    hlc: 7,
                    ..version()
                },
                ..env.clone()
            },
            Envelope {
                version: Version {
                    author: B,
                    ..version()
                },
                ..env.clone()
            },
        ] {
            assert!(
                matches!(moved.open_body(&key, &ACCOUNT), Err(Error::Decrypt)),
                "{moved:?}"
            );
        }
    }

    #[test]
    fn version_hash_depends_on_every_component() {
        let id = Uuid::from_bytes([0x60; 16]);
        let base = version_hash(RecordKind::Item, id, &version());
        assert_ne!(base, version_hash(RecordKind::Vault, id, &version()));
        assert_ne!(
            base,
            version_hash(RecordKind::Item, Uuid::from_bytes([0x62; 16]), &version())
        );
        assert_ne!(
            base,
            version_hash(
                RecordKind::Item,
                id,
                &Version {
                    hlc: 1,
                    ..version()
                }
            )
        );
        assert_ne!(
            base,
            version_hash(
                RecordKind::Item,
                id,
                &Version {
                    author: B,
                    ..version()
                }
            )
        );
        let mut v = version();
        v.vector.insert(B, 2);
        assert_ne!(base, version_hash(RecordKind::Item, id, &v));
    }

    #[test]
    fn shape_rules() {
        let tomb_with_body = Envelope {
            tombstone: true,
            ..item()
        };
        assert!(tomb_with_body.check().is_err());
        let no_body = Envelope {
            body: None,
            ..item()
        };
        assert!(no_body.check().is_err());
        let no_vault = Envelope {
            vault_id: None,
            ..item()
        };
        assert!(no_vault.check().is_err());
        let tomb = Envelope {
            tombstone: true,
            body: None,
            ..item()
        };
        tomb.check().unwrap();
        let vault = Envelope {
            kind: RecordKind::Vault,
            vault_id: None,
            ..item()
        };
        vault.check().unwrap();
        // from_value applies the same rules.
        assert!(Envelope::from_value(&no_body.to_value()).is_err());
    }

    #[test]
    fn newer_format_or_kind_is_unsupported() {
        let mut value = item().to_value();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if k == &Value::text("format") {
                    *v = Value::Uint(2);
                }
            }
        }
        assert!(matches!(
            Envelope::from_value(&value),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            RecordKind::parse("passkey"),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn zero_vector_entries_are_rejected() {
        let mut v = version().to_value();
        if let Value::Map(entries) = &mut v {
            entries[0].1 = Value::Map(vec![(Value::bytes(A), Value::Uint(0))]);
        }
        assert!(Version::from_value(&v).is_err());
    }
}
