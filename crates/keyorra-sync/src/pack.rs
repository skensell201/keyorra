//! The body of a snapshot (spec §4.8): everything a device needs to start from it.
//!
//! ```text
//! body = { "account_id": bytes16,
//!          "frontier": { device → [seq, hash] },   every stream's position the snapshot covers
//!          "floors":   { device → seq },           below these, segments are not needed by it
//!          "entries":  [[device, seq, entry], …],  the main device's trust and header entries,
//!                                                  everyone's header-seen entries, positioned
//!          "versions": [[device, seq, envelope], …] } every admitted record version
//! ```
//!
//! Versions keep their stream positions, so a revocation learned later still applies to them
//! (the receiver's admission decides), and all admitted versions are included (not only the
//! sibling sets) so such a refold has what it needs. Floors equal the frontier in phase A;
//! garbage collection (C1) uses them.

use std::collections::BTreeMap;

use crate::cbor::Value;
use crate::entry::{heads_from, heads_value, Entry, Head, Heads};
use crate::envelope::Envelope;
use crate::error::{malformed, Error, Result};
use crate::{AccountId, DeviceId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBody {
    pub account_id: AccountId,
    pub frontier: Heads,
    pub floors: BTreeMap<DeviceId, u64>,
    pub entries: Vec<(DeviceId, u64, Entry)>,
    pub versions: Vec<(DeviceId, u64, Envelope)>,
}

fn positioned(device: &DeviceId, seq: u64, value: Value) -> Value {
    Value::Array(vec![Value::bytes(device), Value::Uint(seq), value])
}

fn unpositioned(value: &Value) -> Result<(DeviceId, u64, &Value)> {
    let [device, seq, inner] = value.as_list()? else {
        return Err(malformed("positioned entry"));
    };
    Ok((device.as_array_of()?, seq.as_uint()?, inner))
}

impl SnapshotBody {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("account_id", Value::bytes(self.account_id)),
            ("frontier", heads_value(&self.frontier)),
            (
                "floors",
                Value::Map(
                    self.floors
                        .iter()
                        .map(|(d, s)| (Value::bytes(d), Value::Uint(*s)))
                        .collect(),
                ),
            ),
            (
                "entries",
                Value::Array(
                    self.entries
                        .iter()
                        .map(|(d, s, e)| positioned(d, *s, e.to_value()))
                        .collect(),
                ),
            ),
            (
                "versions",
                Value::Array(
                    self.versions
                        .iter()
                        .map(|(d, s, e)| positioned(d, *s, e.to_value()))
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SnapshotBody> {
        let f = value.fields(&["account_id", "frontier", "floors", "entries", "versions"])?;
        let mut floors = BTreeMap::new();
        for (d, s) in f.get("floors")?.as_map()? {
            floors.insert(d.as_array_of()?, s.as_uint()?);
        }
        let entries = f
            .get("entries")?
            .as_list()?
            .iter()
            .map(|v| {
                let (d, s, e) = unpositioned(v)?;
                Ok((d, s, Entry::from_value(e)?))
            })
            .collect::<Result<_>>()?;
        let versions = f
            .get("versions")?
            .as_list()?
            .iter()
            .map(|v| {
                let (d, s, e) = unpositioned(v)?;
                Ok((d, s, Envelope::from_value(e)?))
            })
            .collect::<Result<_>>()?;
        Ok(SnapshotBody {
            account_id: f.get("account_id")?.as_array_of()?,
            frontier: heads_from(f.get("frontier")?)?,
            floors,
            entries,
            versions,
        })
    }

    /// The position the snapshot covers for `device`.
    pub fn covers(&self, device: &DeviceId) -> Option<Head> {
        self.frontier.get(device).copied()
    }
}

/// A snapshot's entries must be trust or header entries.
pub fn check_entries(body: &SnapshotBody) -> Result<()> {
    for (_, _, e) in &body.entries {
        if matches!(
            e,
            Entry::Put(_) | Entry::Checkpoint(_) | Entry::Snapshot { .. }
        ) {
            return Err(Error::Malformed("snapshot entry of the wrong kind".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::envelope::{RecordKind, Version};
    use uuid::Uuid;

    fn body() -> SnapshotBody {
        SnapshotBody {
            account_id: [0x10; 16],
            frontier: [(
                [1; 16],
                Head {
                    seq: 7,
                    hash: [3; 32],
                },
            )]
            .into_iter()
            .collect(),
            floors: [([1; 16], 7)].into_iter().collect(),
            entries: vec![(
                [1; 16],
                2,
                Entry::Revoke {
                    device: [2; 16],
                    last_valid_seq: 4,
                    last_valid_hash: [5; 32],
                },
            )],
            versions: vec![(
                [1; 16],
                5,
                Envelope {
                    kind: RecordKind::Item,
                    record_id: Uuid::from_bytes([0x60; 16]),
                    vault_id: Some(Uuid::from_bytes([0x61; 16])),
                    schema: 1,
                    version: Version {
                        vector: [([1; 16], 1)].into_iter().collect(),
                        hlc: 9,
                        author: [1; 16],
                    },
                    tombstone: true,
                    body: None,
                },
            )],
        }
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let b = body();
        let bytes = cbor::encode(&b.to_value());
        assert_eq!(
            SnapshotBody::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
            b
        );
        assert_eq!(b.covers(&[1; 16]).unwrap().seq, 7);
        assert!(b.covers(&[2; 16]).is_none());
    }

    #[test]
    fn only_trust_and_header_entries_belong_in_a_snapshot() {
        let mut b = body();
        check_entries(&b).unwrap();
        b.entries
            .push(([1; 16], 3, Entry::Checkpoint(Heads::new())));
        assert!(check_entries(&b).is_err());
    }
}
