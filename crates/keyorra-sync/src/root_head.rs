//! The main device's advertised head (spec §4.3, review W1): a small file the root rewrites
//! after every confirmed append, signed with its key, so every device can tell whether the
//! store withholds the root's newest entries (a removal, an approval).
//!
//! ```text
//! file = canonical({ "account_id": bytes16, "seq": uint, "hash": bytes32, "sig": bytes64 })
//! sig  = Ed25519(root_sk, "keyorra/sync/v1/root-head\0" ‖ account_id ‖ seq:u64be ‖ hash)
//! ```
//!
//! A reader only moves its advertised head forward, so an old file served later changes
//! nothing; a store that serves no file or an old one is no worse than before, and the setup
//! code (which carries the root's head when a device joins) and checkpoints cover the rest.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor::{self, Value};
use crate::entry::Head;
use crate::error::{Error, Result};
use crate::labels::{self, tagged};
use crate::AccountId;

/// The file name in the store.
pub const ROOT_HEAD_FILE: &str = "root.head";
const MAX_LEN: usize = 512;

fn message(account_id: &AccountId, head: &Head) -> Vec<u8> {
    tagged(
        labels::ROOT_HEAD,
        &[account_id, &head.seq.to_be_bytes(), &head.hash],
    )
}

pub fn seal_root_head(account_id: &AccountId, head: &Head, root: &SigningKey) -> Vec<u8> {
    let sig = root.sign(&message(account_id, head)).to_bytes();
    cbor::encode(&Value::map(vec![
        ("account_id", Value::bytes(account_id)),
        ("seq", Value::Uint(head.seq)),
        ("hash", Value::bytes(head.hash)),
        ("sig", Value::bytes(sig)),
    ]))
}

pub fn open_root_head(account_id: &AccountId, root: &VerifyingKey, bytes: &[u8]) -> Result<Head> {
    let value = cbor::decode_limited(bytes, MAX_LEN)?;
    let f = value.fields(&["account_id", "seq", "hash", "sig"])?;
    let file_account: AccountId = f.get("account_id")?.as_array_of()?;
    if file_account != *account_id {
        return Err(Error::Refused("root head of another account".into()));
    }
    let head = Head {
        seq: f.get("seq")?.as_uint()?,
        hash: f.get("hash")?.as_array_of()?,
    };
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    root.verify_strict(&message(account_id, &head), &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)?;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_head_file_opens_only_with_the_root_key_and_account() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let head = Head {
            seq: 42,
            hash: [7; 32],
        };
        let bytes = seal_root_head(&[9; 16], &head, &root);
        assert_eq!(
            open_root_head(&[9; 16], &root.verifying_key(), &bytes).unwrap(),
            head
        );
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert!(open_root_head(&[9; 16], &other, &bytes).is_err());
        assert!(open_root_head(&[8; 16], &root.verifying_key(), &bytes).is_err());
        assert!(open_root_head(&[9; 16], &root.verifying_key(), b"junk").is_err());
    }
}
