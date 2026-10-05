//! Stream entries (spec §4.1): what a device's log segments carry.
//!
//! ```text
//! entry = { "put": Envelope }
//!       | { "checkpoint": { bytes16 → [seq, hash] } }        heads of other streams applied by the writer
//!       | { "genesis": { "account_id", "key", "name" } }     the root device, first entry of its stream
//!       | { "self_join": { "key", "name", "sig" } }          a device that joined with the Emergency Kit
//!       | { "endorse": { "device", "key", "name", "sig" } }  a live device vouches for another one
//!       | { "revoke": { "device", "last_valid_seq" } }       entries of `device` after the cut stop counting
//! sig   = Ed25519(signer, "keyorra/sync/v1/endorse\0" ‖ account_id ‖ device ‖ key)
//! ```
//!
//! `endorse` is signed by the endorsing device, `self_join` by the joining device itself. The
//! same signature is what a server checks when a device is approved (spec §6.4).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor::Value;
use crate::envelope::Envelope;
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::{AccountId, DeviceId};

/// A stream position: the sequence number and chain hash of an entry (normally the last entry
/// of a segment).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Head {
    pub seq: u64,
    pub hash: [u8; 32],
}

pub type Heads = BTreeMap<DeviceId, Head>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Put(Envelope),
    Checkpoint(Heads),
    Genesis {
        account_id: AccountId,
        key: [u8; 32],
        name: String,
    },
    SelfJoin {
        key: [u8; 32],
        name: String,
        sig: [u8; 64],
    },
    Endorse {
        device: DeviceId,
        key: [u8; 32],
        name: String,
        sig: [u8; 64],
    },
    Revoke {
        device: DeviceId,
        last_valid_seq: u64,
    },
}

/// What an endorsement (or a self-join) signs.
pub fn endorse_statement(account_id: &AccountId, device: &DeviceId, key: &[u8; 32]) -> Vec<u8> {
    tagged(labels::ENDORSE, &[account_id, device, key])
}

pub fn sign_endorsement(
    signer: &SigningKey,
    account_id: &AccountId,
    device: &DeviceId,
    key: &[u8; 32],
) -> [u8; 64] {
    signer
        .sign(&endorse_statement(account_id, device, key))
        .to_bytes()
}

pub fn verify_endorsement(
    signer: &VerifyingKey,
    account_id: &AccountId,
    device: &DeviceId,
    key: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    signer
        .verify_strict(
            &endorse_statement(account_id, device, key),
            &Signature::from_bytes(sig),
        )
        .is_ok()
}

impl Entry {
    pub fn to_value(&self) -> Value {
        let (tag, body) = match self {
            Entry::Put(env) => ("put", env.to_value()),
            Entry::Checkpoint(heads) => (
                "checkpoint",
                Value::Map(
                    heads
                        .iter()
                        .map(|(d, h)| {
                            (
                                Value::bytes(d),
                                Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
                            )
                        })
                        .collect(),
                ),
            ),
            Entry::Genesis {
                account_id,
                key,
                name,
            } => (
                "genesis",
                Value::map(vec![
                    ("account_id", Value::bytes(account_id)),
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                ]),
            ),
            Entry::SelfJoin { key, name, sig } => (
                "self_join",
                Value::map(vec![
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                    ("sig", Value::bytes(sig)),
                ]),
            ),
            Entry::Endorse {
                device,
                key,
                name,
                sig,
            } => (
                "endorse",
                Value::map(vec![
                    ("device", Value::bytes(device)),
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                    ("sig", Value::bytes(sig)),
                ]),
            ),
            Entry::Revoke {
                device,
                last_valid_seq,
            } => (
                "revoke",
                Value::map(vec![
                    ("device", Value::bytes(device)),
                    ("last_valid_seq", Value::Uint(*last_valid_seq)),
                ]),
            ),
        };
        Value::map(vec![(tag, body)])
    }

    /// Unknown entry types are `Unsupported` (a newer app wrote them), never `Malformed`.
    pub fn from_value(value: &Value) -> Result<Entry> {
        let map = value.as_map()?;
        let [(tag, body)] = map else {
            return Err(malformed("entry must have exactly one type"));
        };
        let tag = tag.as_text()?;
        Ok(match tag {
            "put" => Entry::Put(Envelope::from_value(body)?),
            "checkpoint" => {
                let mut heads = Heads::new();
                for (d, h) in body.as_map()? {
                    let [seq, hash] = h.as_list()? else {
                        return Err(malformed("checkpoint head"));
                    };
                    heads.insert(
                        d.as_array_of()?,
                        Head {
                            seq: seq.as_uint()?,
                            hash: hash.as_array_of()?,
                        },
                    );
                }
                Entry::Checkpoint(heads)
            }
            "genesis" => {
                let f = body.fields(&["account_id", "key", "name"])?;
                Entry::Genesis {
                    account_id: f.get("account_id")?.as_array_of()?,
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                }
            }
            "self_join" => {
                let f = body.fields(&["key", "name", "sig"])?;
                Entry::SelfJoin {
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                    sig: f.get("sig")?.as_array_of()?,
                }
            }
            "endorse" => {
                let f = body.fields(&["device", "key", "name", "sig"])?;
                Entry::Endorse {
                    device: f.get("device")?.as_array_of()?,
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                    sig: f.get("sig")?.as_array_of()?,
                }
            }
            "revoke" => {
                let f = body.fields(&["device", "last_valid_seq"])?;
                Entry::Revoke {
                    device: f.get("device")?.as_array_of()?,
                    last_valid_seq: f.get("last_valid_seq")?.as_uint()?,
                }
            }
            other => return Err(Error::Unsupported(format!("entry type {other}"))),
        })
    }

    /// The key a stream's first entry carries for itself (root `Genesis`, `SelfJoin`).
    pub fn own_key(&self) -> Option<[u8; 32]> {
        match self {
            Entry::Genesis { key, .. } | Entry::SelfJoin { key, .. } => Some(*key),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::envelope::{RecordKind, Version};
    use uuid::Uuid;

    const ACCOUNT: AccountId = [0x10; 16];

    fn samples() -> Vec<Entry> {
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let key = signer.verifying_key().to_bytes();
        vec![
            Entry::Put(Envelope {
                kind: RecordKind::Item,
                record_id: Uuid::from_bytes([0x60; 16]),
                vault_id: Some(Uuid::from_bytes([0x61; 16])),
                schema: 1,
                version: Version {
                    vector: [([1; 16], 1)].into_iter().collect(),
                    hlc: 7,
                    author: [1; 16],
                },
                tombstone: true,
                body: None,
            }),
            Entry::Checkpoint(
                [(
                    [2; 16],
                    Head {
                        seq: 4,
                        hash: [9; 32],
                    },
                )]
                .into_iter()
                .collect(),
            ),
            Entry::Genesis {
                account_id: ACCOUNT,
                key,
                name: "MacBook Pro".into(),
            },
            Entry::SelfJoin {
                key,
                name: "MacBook Air".into(),
                sig: sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key),
            },
            Entry::Endorse {
                device: [3; 16],
                key,
                name: "MacBook Air".into(),
                sig: sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key),
            },
            Entry::Revoke {
                device: [3; 16],
                last_valid_seq: 12,
            },
        ]
    }

    #[test]
    fn every_entry_round_trips_through_canonical_cbor() {
        for entry in samples() {
            let bytes = cbor::encode(&entry.to_value());
            assert_eq!(
                Entry::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
                entry
            );
        }
    }

    #[test]
    fn unknown_types_are_unsupported_and_shapes_are_checked() {
        let future = Value::map(vec![("passkey", Value::Null)]);
        assert!(matches!(
            Entry::from_value(&future),
            Err(Error::Unsupported(_))
        ));
        let two = Value::map(vec![("revoke", Value::Null), ("put", Value::Null)]);
        assert!(matches!(Entry::from_value(&two), Err(Error::Malformed(_))));
        let bad = Value::map(vec![("revoke", Value::map(vec![]))]);
        assert!(matches!(Entry::from_value(&bad), Err(Error::Malformed(_))));
    }

    #[test]
    fn endorsements_are_bound_to_account_device_and_key() {
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let pk = signer.verifying_key();
        let key = [7; 32];
        let sig = sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key);
        assert!(verify_endorsement(&pk, &ACCOUNT, &[3; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &[0x11; 16], &[3; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &ACCOUNT, &[4; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &ACCOUNT, &[3; 16], &[8; 32], &sig));
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(!verify_endorsement(&other, &ACCOUNT, &[3; 16], &key, &sig));
    }

    #[test]
    fn only_first_entries_carry_their_own_key() {
        let keys: Vec<bool> = samples().iter().map(|e| e.own_key().is_some()).collect();
        assert_eq!(keys, [false, false, true, true, false, false]);
    }
}
