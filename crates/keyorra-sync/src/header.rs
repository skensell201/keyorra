//! The synced account header: what a joining device needs before it has any key.
//!
//! Stored as a standalone, signed file per epoch (`<epoch:08x>-<author hex>.hdr`). The file
//! counts only together with a matching signed log entry (defined in plan A1c).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, KdfParams, Key, NONCE_LEN};

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::keys::{derive_sync_keys, SyncKeys};
use crate::labels::{self, tagged};
use crate::secret_key::SecretKey;
use crate::{AccountId, DeviceId};

pub const SYNC_FORMAT: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub account_id: AccountId,
    pub epoch: u32,
    pub generation: u32,
    pub root_device: DeviceId,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub secret_key_id: String,
    pub wrapped_account_key: Vec<u8>,
}

const FIELDS: [&str; 9] = [
    "keyorra_sync",
    "account_id",
    "epoch",
    "generation",
    "root_device",
    "kdf",
    "salt",
    "secret_key_id",
    "wrapped_account_key",
];

fn account_key_aad(account_id: &AccountId, epoch: u32, generation: u32) -> Vec<u8> {
    tagged(
        labels::ACCOUNT_KEY,
        &[account_id, &epoch.to_be_bytes(), &generation.to_be_bytes()],
    )
}

/// Seals the account key under `KEK_sync`, bound to account, epoch and generation.
pub fn wrap_account_key(
    kek: &Key,
    account_key: &Key,
    account_id: &AccountId,
    epoch: u32,
    generation: u32,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    crypto::seal_with_nonce(
        kek,
        nonce,
        account_key.as_bytes(),
        &account_key_aad(account_id, epoch, generation),
    )
}

impl Header {
    /// Derives the sync keys from password and Secret Key and unwraps the account key.
    /// A wrong password or Secret Key (or a tampered header) is `WrongPassword`.
    pub fn unlock(&self, password: &str, secret_key: &SecretKey) -> Result<(Key, SyncKeys)> {
        let keys = derive_sync_keys(password, &self.salt, self.kdf, secret_key, &self.account_id)?;
        let account_key = self.unwrap_account_key(&keys.kek)?;
        Ok((account_key, keys))
    }

    pub fn unwrap_account_key(&self, kek: &Key) -> Result<Key> {
        let raw = crypto::open(
            kek,
            &self.wrapped_account_key,
            &account_key_aad(&self.account_id, self.epoch, self.generation),
        )
        .map_err(|_| Error::WrongPassword)?;
        Ok(Key::from_slice(&raw)?)
    }

    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("keyorra_sync", Value::Uint(SYNC_FORMAT)),
            ("account_id", Value::bytes(self.account_id)),
            ("epoch", Value::Uint(self.epoch.into())),
            ("generation", Value::Uint(self.generation.into())),
            ("root_device", Value::bytes(self.root_device)),
            (
                "kdf",
                Value::map(vec![
                    ("m_kib", Value::Uint(self.kdf.m_kib.into())),
                    ("t", Value::Uint(self.kdf.t.into())),
                    ("p", Value::Uint(self.kdf.p.into())),
                ]),
            ),
            ("salt", Value::bytes(self.salt)),
            ("secret_key_id", Value::text(&self.secret_key_id)),
            (
                "wrapped_account_key",
                Value::bytes(&self.wrapped_account_key),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Header> {
        let format = value
            .as_map()?
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "keyorra_sync"))
            .ok_or_else(|| malformed("header without keyorra_sync"))?
            .1
            .as_uint()?;
        if format != SYNC_FORMAT {
            return Err(Error::Unsupported(format!("sync header format {format}")));
        }
        let f = value.fields(&FIELDS)?;
        let kdf = f.get("kdf")?.fields(&["m_kib", "t", "p"])?;
        let secret_key_id = f.get("secret_key_id")?.as_text()?.to_owned();
        if secret_key_id.len() != 4 || !secret_key_id.is_ascii() {
            return Err(malformed("secret key id"));
        }
        Ok(Header {
            account_id: f.get("account_id")?.as_array_of()?,
            epoch: f.get("epoch")?.as_u32()?,
            generation: f.get("generation")?.as_u32()?,
            root_device: f.get("root_device")?.as_array_of()?,
            kdf: KdfParams {
                m_kib: kdf.get("m_kib")?.as_u32()?,
                t: kdf.get("t")?.as_u32()?,
                p: kdf.get("p")?.as_u32()?,
            },
            salt: f.get("salt")?.as_array_of()?,
            secret_key_id,
            wrapped_account_key: f.get("wrapped_account_key")?.as_bytes()?.to_vec(),
        })
    }
}

/// A header signed by the device that wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFile {
    pub header: Header,
    pub author: DeviceId,
    pub sig: [u8; 64],
}

fn signed_message(header: &Header) -> Vec<u8> {
    tagged(labels::HEADER, &[&cbor::encode(&header.to_value())])
}

impl HeaderFile {
    pub fn sign(header: Header, author: DeviceId, key: &SigningKey) -> HeaderFile {
        let sig = key.sign(&signed_message(&header)).to_bytes();
        HeaderFile {
            header,
            author,
            sig,
        }
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        key.verify_strict(
            &signed_message(&self.header),
            &Signature::from_bytes(&self.sig),
        )
        .map_err(|_| Error::BadSignature)
    }

    pub fn file_name(&self) -> String {
        format!(
            "{:08x}-{}.hdr",
            self.header.epoch,
            data_encoding::HEXLOWER.encode(&self.author)
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::map(vec![
            ("header", self.header.to_value()),
            ("author", Value::bytes(self.author)),
            ("sig", Value::bytes(self.sig)),
        ]))
    }

    pub fn decode(bytes: &[u8]) -> Result<HeaderFile> {
        let value = cbor::decode(bytes)?;
        let f = value.fields(&["header", "author", "sig"])?;
        Ok(HeaderFile {
            header: Header::from_value(f.get("header")?)?,
            author: f.get("author")?.as_array_of()?,
            sig: f.get("sig")?.as_array_of()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = [0x10; 16];
    const DEVICE: DeviceId = [0x40; 16];
    const SALT: [u8; 16] = [0x20; 16];

    fn sk() -> SecretKey {
        SecretKey::from_bytes([0x01; 16])
    }

    fn header_for(password: &str, account_key: &Key, epoch: u32) -> Header {
        let kdf = KdfParams::INSECURE_FAST;
        let keys = derive_sync_keys(password, &SALT, kdf, &sk(), &ACCOUNT).unwrap();
        Header {
            account_id: ACCOUNT,
            epoch,
            generation: 1,
            root_device: DEVICE,
            kdf,
            salt: SALT,
            secret_key_id: "A3K7".into(),
            wrapped_account_key: wrap_account_key(
                &keys.kek,
                account_key,
                &ACCOUNT,
                epoch,
                1,
                &[0x50; NONCE_LEN],
            ),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    /// RFC 8032 §7.1 test 1: pins the Ed25519 dependency.
    #[test]
    fn ed25519_rfc8032_test_1() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let key = SigningKey::from_bytes(
            &hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(key.verifying_key().as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(&key.sign(b"").to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn unlock_returns_the_account_key() {
        let ak = Key::from_bytes([0x30; 32]);
        let (unlocked, _) = header_for("pw", &ak, 1).unlock("pw", &sk()).unwrap();
        assert_eq!(unlocked.as_bytes(), ak.as_bytes());
    }

    #[test]
    fn wrong_password_or_secret_key_is_wrong_password() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        assert!(matches!(h.unlock("nope", &sk()), Err(Error::WrongPassword)));
        let other = SecretKey::from_bytes([0x02; 16]);
        assert!(matches!(h.unlock("pw", &other), Err(Error::WrongPassword)));
    }

    #[test]
    fn wrapped_key_is_bound_to_epoch_generation_and_account() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        for tampered in [
            Header {
                epoch: 2,
                ..h.clone()
            },
            Header {
                generation: 2,
                ..h.clone()
            },
        ] {
            assert!(matches!(
                tampered.unlock("pw", &sk()),
                Err(Error::WrongPassword)
            ));
        }
    }

    #[test]
    fn file_round_trips_and_verifies() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 3);
        let file = HeaderFile::sign(h, DEVICE, &signing_key());
        let decoded = HeaderFile::decode(&file.encode()).unwrap();
        assert_eq!(decoded, file);
        decoded.verify(&signing_key().verifying_key()).unwrap();
        assert_eq!(
            decoded.file_name(),
            "00000003-40404040404040404040404040404040.hdr"
        );
    }

    #[test]
    fn signature_fails_for_another_key_or_a_changed_header() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let file = HeaderFile::sign(h, DEVICE, &signing_key());
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(file.verify(&other), Err(Error::BadSignature)));
        let mut changed = file.clone();
        changed.header.epoch = 9;
        assert!(matches!(
            changed.verify(&signing_key().verifying_key()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn newer_format_is_unsupported_and_junk_is_malformed() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let mut value = h.to_value();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if k == &Value::text("keyorra_sync") {
                    *v = Value::Uint(2);
                }
            }
        }
        assert!(matches!(
            Header::from_value(&value),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            HeaderFile::decode(b"\xa0"),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            HeaderFile::decode(b"junk"),
            Err(Error::Malformed(_))
        ));
    }
}
