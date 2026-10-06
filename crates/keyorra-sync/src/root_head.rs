//! The main device's advertised head (spec §4.3, review W1): a small file the root rewrites
//! after every confirmed append, signed with its key, so every device can tell whether the
//! store withholds the root's newest entries (a removal, an approval).
//!
//! ```text
//! file = canonical({ "account_id": bytes16, "seq": uint, "hash": bytes32, "at_ms": uint,
//!                    "devices": uint, "pending": [[seq, entry], …], "sig": bytes64 })
//! sig  = Ed25519(root_sk, "keyorra/sync/v1/root-head\0" ‖ canonical(file without "sig"))
//! ```
//!
//! `at_ms` is the main device's wall time when it wrote the file. It rewrites the file at
//! least daily while online (a heartbeat), so a store that freezes or replays an old file is
//! noticed (review I1). `pending` lists the main device's removals (`revoke` entries) that
//! are written but not yet confirmed in its stream, with their positions: a squatter who
//! keeps the main device's next position occupied cannot hold a removal back (review F1).
//! Readers apply them at once and reconcile when the stream delivers them. `devices` counts
//! the approved devices other than the main one: a device joining with the Emergency Kit
//! alone is refused while there are any, and must use the setup code of one of them
//! (review F4).
//!
//! A reader only moves its advertised head forward, so an old file served later changes
//! nothing.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor::{self, Value};
use crate::entry::{Entry, Head};
use crate::error::{Error, Result};
use crate::labels::{self, tagged};
use crate::AccountId;

/// The file name in the store.
pub const ROOT_HEAD_FILE: &str = "root.head";
const MAX_LEN: usize = 512;

/// What a root head file says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootHead {
    pub head: Head,
    pub at_ms: u64,
    /// Approved devices other than the main one, not removed.
    pub devices: u64,
    pub pending: Vec<(u64, Entry)>,
}

fn body(account_id: &AccountId, r: &RootHead) -> Value {
    Value::map(vec![
        ("account_id", Value::bytes(account_id)),
        ("seq", Value::Uint(r.head.seq)),
        ("hash", Value::bytes(r.head.hash)),
        ("at_ms", Value::Uint(r.at_ms)),
        ("devices", Value::Uint(r.devices)),
        (
            "pending",
            Value::Array(
                r.pending
                    .iter()
                    .map(|(seq, e)| Value::Array(vec![Value::Uint(*seq), e.to_value()]))
                    .collect(),
            ),
        ),
    ])
}

fn message(body: &Value) -> Vec<u8> {
    tagged(labels::ROOT_HEAD, &[&cbor::encode(body)])
}

pub fn seal_root_head(account_id: &AccountId, r: &RootHead, root: &SigningKey) -> Vec<u8> {
    let b = body(account_id, r);
    let sig = root.sign(&message(&b)).to_bytes();
    let Value::Map(mut fields) = b else {
        unreachable!("a map")
    };
    fields.push((Value::text("sig"), Value::bytes(sig)));
    cbor::encode(&Value::Map(fields))
}

/// Opens a root head file: this account, signed by the main device; only `revoke` entries
/// may be pending.
pub fn open_root_head(
    account_id: &AccountId,
    root: &VerifyingKey,
    bytes: &[u8],
) -> Result<RootHead> {
    let value = cbor::decode_limited(bytes, MAX_LEN)?;
    let f = value.fields(&[
        "account_id",
        "seq",
        "hash",
        "at_ms",
        "devices",
        "pending",
        "sig",
    ])?;
    let file_account: AccountId = f.get("account_id")?.as_array_of()?;
    if file_account != *account_id {
        return Err(Error::Refused("root head of another account".into()));
    }
    let mut pending = Vec::new();
    for item in f.get("pending")?.as_list()? {
        let [seq, entry] = item.as_list()? else {
            return Err(Error::Malformed("pending entry".into()));
        };
        let entry = Entry::from_value(entry)?;
        if !matches!(entry, Entry::Revoke { .. }) {
            return Err(Error::Malformed("only removals are pending".into()));
        }
        pending.push((seq.as_uint()?, entry));
    }
    let r = RootHead {
        head: Head {
            seq: f.get("seq")?.as_uint()?,
            hash: f.get("hash")?.as_array_of()?,
        },
        at_ms: f.get("at_ms")?.as_uint()?,
        devices: f.get("devices")?.as_uint()?,
        pending,
    };
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    root.verify_strict(
        &message(&body(account_id, &r)),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| Error::BadSignature)?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_head_file_opens_only_with_the_root_key_and_account() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let r = RootHead {
            head: Head {
                seq: 42,
                hash: [7; 32],
            },
            at_ms: 77,
            devices: 2,
            pending: vec![(
                43,
                Entry::Revoke {
                    device: [5; 16],
                    last_valid_seq: 9,
                    last_valid_hash: [3; 32],
                },
            )],
        };
        let bytes = seal_root_head(&[9; 16], &r, &root);
        assert_eq!(
            open_root_head(&[9; 16], &root.verifying_key(), &bytes).unwrap(),
            r
        );
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert!(open_root_head(&[9; 16], &other, &bytes).is_err());
        assert!(open_root_head(&[8; 16], &root.verifying_key(), &bytes).is_err());
        assert!(open_root_head(&[9; 16], &root.verifying_key(), b"junk").is_err());
    }
}
