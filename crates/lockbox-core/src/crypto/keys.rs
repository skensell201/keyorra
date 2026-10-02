use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{derive_kek, open, seal, KdfParams, Key};
use crate::{Error, Result};

pub const FORMAT_VERSION: u32 = 1;
const ACCOUNT_KEY_AAD: &[u8] = b"lockbox/account-key/v1";

/// Everything needed to turn the master password into the account key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub wrapped_account_key: Vec<u8>,
}

/// Creates a new random account key and a header that unlocks it with `password`.
pub fn create_header(password: &str, kdf: KdfParams) -> Result<(Header, Key)> {
    let account = Key::random();
    let header = wrap_account_key(&account, password, kdf)?;
    Ok((header, account))
}

/// Recovers the account key. A wrong password fails AEAD authentication.
pub fn unlock(header: &Header, password: &str) -> Result<Key> {
    let kek = derive_kek(password, &header.salt, header.kdf)?;
    let raw = open(&kek, &header.wrapped_account_key, ACCOUNT_KEY_AAD)
        .map_err(|_| Error::WrongPassword)?;
    Key::from_slice(&raw)
}

/// Re-wraps the same account key under a new password (fresh salt). Items are untouched.
pub fn change_password(header: &Header, old: &str, new: &str, kdf: KdfParams) -> Result<Header> {
    let account = unlock(header, old)?;
    wrap_account_key(&account, new, kdf)
}

fn wrap_account_key(account: &Key, password: &str, kdf: KdfParams) -> Result<Header> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(password, &salt, kdf)?;
    Ok(Header {
        format: FORMAT_VERSION,
        kdf,
        salt,
        wrapped_account_key: seal(&kek, account.as_bytes(), ACCOUNT_KEY_AAD),
    })
}

pub fn wrap_vault_key(account: &Key, vault_id: Uuid, vault_key: &Key) -> Vec<u8> {
    seal(account, vault_key.as_bytes(), &with_ids(b"lockbox/vault-key/v1", &[vault_id]))
}

pub fn unwrap_vault_key(account: &Key, vault_id: Uuid, wrapped: &[u8]) -> Result<Key> {
    let raw = open(account, wrapped, &with_ids(b"lockbox/vault-key/v1", &[vault_id]))?;
    Key::from_slice(&raw)
}

/// Associated data for an item: moving a ciphertext to another row or vault fails to decrypt.
pub fn item_aad(vault_id: Uuid, item_id: Uuid, schema: u32) -> Vec<u8> {
    let mut aad = with_ids(b"lockbox/item/v1", &[vault_id, item_id]);
    aad.extend_from_slice(&schema.to_be_bytes());
    aad
}

pub fn attachment_aad(vault_id: Uuid, item_id: Uuid, attachment_id: Uuid) -> Vec<u8> {
    with_ids(b"lockbox/attachment/v1", &[vault_id, item_id, attachment_id])
}

fn with_ids(label: &[u8], ids: &[Uuid]) -> Vec<u8> {
    let mut aad = label.to_vec();
    for id in ids {
        aad.extend_from_slice(id.as_bytes());
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;

    #[test]
    fn unlock_returns_the_created_account_key() {
        let (header, account) = create_header("correct horse", FAST).unwrap();
        let unlocked = unlock(&header, "correct horse").unwrap();
        assert_eq!(unlocked.as_bytes(), account.as_bytes());
        assert_eq!(header.format, FORMAT_VERSION);
        assert_eq!(header.kdf, FAST);
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        let (header, _) = create_header("correct horse", FAST).unwrap();
        assert!(matches!(unlock(&header, "battery staple"), Err(Error::WrongPassword)));
    }

    #[test]
    fn change_password_keeps_account_key_and_rotates_salt() {
        let (header, account) = create_header("old", FAST).unwrap();
        let changed = change_password(&header, "old", "new", FAST).unwrap();
        assert_ne!(changed.salt, header.salt);
        assert!(matches!(unlock(&changed, "old"), Err(Error::WrongPassword)));
        assert_eq!(unlock(&changed, "new").unwrap().as_bytes(), account.as_bytes());
    }

    #[test]
    fn change_password_requires_the_old_one() {
        let (header, _) = create_header("old", FAST).unwrap();
        assert!(matches!(change_password(&header, "nope", "new", FAST), Err(Error::WrongPassword)));
    }

    #[test]
    fn vault_key_is_bound_to_its_vault_id() {
        let account = Key::random();
        let vault_key = Key::random();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let wrapped = wrap_vault_key(&account, a, &vault_key);
        assert_eq!(unwrap_vault_key(&account, a, &wrapped).unwrap().as_bytes(), vault_key.as_bytes());
        assert!(matches!(unwrap_vault_key(&account, b, &wrapped), Err(Error::Decrypt)));
    }

    #[test]
    fn item_aad_depends_on_every_component() {
        let (v, i) = (Uuid::new_v4(), Uuid::new_v4());
        let base = item_aad(v, i, 1);
        assert_ne!(base, item_aad(Uuid::new_v4(), i, 1));
        assert_ne!(base, item_aad(v, Uuid::new_v4(), 1));
        assert_ne!(base, item_aad(v, i, 2));
    }

    #[test]
    fn header_survives_json() {
        let (header, _) = create_header("pw", FAST).unwrap();
        let json = serde_json::to_vec(&header).unwrap();
        assert_eq!(serde_json::from_slice::<Header>(&json).unwrap(), header);
    }
}
