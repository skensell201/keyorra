//! The synced account header: what a joining device needs before it has any key.
//!
//! Stored as a standalone, signed file per epoch (`<epoch:08x>-<author hex>.hdr`). The file
//! counts only together with a matching signed log entry (defined in plan A1c).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, KdfParams, Key, NONCE_LEN};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::keys::{check_remote_kdf, derive_sync_keys, SyncKeys};
use crate::labels::{self, tagged};
use crate::secret_key::{SecretKey, DIGITS};
use crate::{AccountId, DeviceId};

pub const SYNC_FORMAT: u64 = 1;
/// Exactly: nonce, 32-byte account key, tag.
pub const WRAPPED_KEY_LEN: usize = NONCE_LEN + 32 + 16;
/// Cap on a header file read from untrusted storage (a real one is a few hundred bytes).
pub const MAX_HEADER_FILE_LEN: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub account_id: AccountId,
    pub epoch: u32,
    pub generation: u32,
    pub root_device: DeviceId,
    /// The main device's public key: how a joining device learns it (never from the store's
    /// streams). Bound into the wrapped account key like every other field, so only someone
    /// with the master password and Secret Key can change it.
    pub root_key: [u8; 32],
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub secret_key_id: String,
    pub wrapped_account_key: Vec<u8>,
}

const FIELDS: [&str; 10] = [
    "keyorra_sync",
    "account_id",
    "epoch",
    "generation",
    "root_device",
    "root_key",
    "kdf",
    "salt",
    "secret_key_id",
    "wrapped_account_key",
];

fn account_key_aad(binding: &[u8; 32]) -> Vec<u8> {
    tagged(labels::ACCOUNT_KEY, &[binding])
}

/// Seals the account key under `KEK_sync`. The associated data is the header's
/// [`binding`](Header::binding), so the wrapped key only opens under exactly this account,
/// epoch, generation, root device, KDF parameters, salt and Secret Key id. The nonce is drawn
/// from `rng`; `header.wrapped_account_key` is ignored (it is the field being produced).
pub fn wrap_account_key(
    kek: &Key,
    account_key: &Key,
    header: &Header,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    crypto::seal_with_rng(
        kek,
        rng,
        account_key.as_bytes(),
        &account_key_aad(&header.binding()),
    )
}

impl Header {
    /// Derives the sync keys from password and Secret Key and unwraps the account key.
    /// A wrong password or Secret Key (or a tampered header) is `WrongPassword`.
    ///
    /// The header must be treated as untrusted until [`HeaderFile::verify`] has succeeded with
    /// a key the stream-trust rules of plan A1c accept: call `verify` (or at least decode via
    /// `HeaderFile`) first and only use the returned keys for a header that passed. KDF
    /// parameters below the remote floor are refused before any Argon2 work, see
    /// [`check_remote_kdf`].
    pub fn unlock(&self, password: &str, secret_key: &SecretKey) -> Result<(Key, SyncKeys)> {
        check_remote_kdf(&self.kdf)?;
        self.unlock_unchecked_floor(password, secret_key)
    }

    /// [`unlock`](Self::unlock) without the KDF floor, for tests and vectors with cheap
    /// parameters.
    #[cfg(test)]
    pub(crate) fn unlock_cheap(
        &self,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<(Key, SyncKeys)> {
        self.unlock_unchecked_floor(password, secret_key)
    }

    fn unlock_unchecked_floor(
        &self,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<(Key, SyncKeys)> {
        let keys = derive_sync_keys(password, &self.salt, self.kdf, secret_key, &self.account_id)?;
        let account_key = self.unwrap_account_key(&keys.kek)?;
        Ok((account_key, keys))
    }

    pub fn unwrap_account_key(&self, kek: &Key) -> Result<Key> {
        let raw = crypto::open(
            kek,
            &self.wrapped_account_key,
            &account_key_aad(&self.binding()),
        )
        .map_err(|_| Error::WrongPassword)?;
        Ok(Key::from_slice(&raw)?)
    }

    /// `SHA-256(canonical(header with an empty wrapped_account_key))`: ties the wrapped key to
    /// every other header field.
    pub fn binding(&self) -> [u8; 32] {
        Sha256::digest(cbor::encode(&self.value_with(&[]))).into()
    }

    pub fn to_value(&self) -> Value {
        self.value_with(&self.wrapped_account_key)
    }

    fn value_with(&self, wrapped: &[u8]) -> Value {
        Value::map(vec![
            ("keyorra_sync", Value::Uint(SYNC_FORMAT)),
            ("account_id", Value::bytes(self.account_id)),
            ("epoch", Value::Uint(self.epoch.into())),
            ("generation", Value::Uint(self.generation.into())),
            ("root_device", Value::bytes(self.root_device)),
            ("root_key", Value::bytes(self.root_key)),
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
            ("wrapped_account_key", Value::bytes(wrapped)),
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
        if secret_key_id.len() != 4 || !secret_key_id.bytes().all(|c| DIGITS.contains(&c)) {
            return Err(malformed("secret key id"));
        }
        let wrapped_account_key = f.get("wrapped_account_key")?.as_bytes()?.to_vec();
        if wrapped_account_key.len() != WRAPPED_KEY_LEN {
            return Err(malformed("wrapped account key length"));
        }
        Ok(Header {
            account_id: f.get("account_id")?.as_array_of()?,
            epoch: f.get("epoch")?.as_u32()?,
            generation: f.get("generation")?.as_u32()?,
            root_device: f.get("root_device")?.as_array_of()?,
            root_key: f.get("root_key")?.as_array_of()?,
            kdf: KdfParams {
                m_kib: kdf.get("m_kib")?.as_u32()?,
                t: kdf.get("t")?.as_u32()?,
                p: kdf.get("p")?.as_u32()?,
            },
            salt: f.get("salt")?.as_array_of()?,
            secret_key_id,
            wrapped_account_key,
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

/// The signature covers the author too, so a file cannot be re-attributed to another device.
fn signed_message(header: &Header, author: &DeviceId) -> Vec<u8> {
    tagged(labels::HEADER, &[author, &cbor::encode(&header.to_value())])
}

impl HeaderFile {
    pub fn sign(header: Header, author: DeviceId, key: &SigningKey) -> HeaderFile {
        let sig = key.sign(&signed_message(&header, &author)).to_bytes();
        HeaderFile {
            header,
            author,
            sig,
        }
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        key.verify_strict(
            &signed_message(&self.header, &self.author),
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
        let value = cbor::decode_limited(bytes, MAX_HEADER_FILE_LEN)?;
        let f = value.fields(&["header", "author", "sig"])?;
        Ok(HeaderFile {
            header: Header::from_value(f.get("header")?)?,
            author: f.get("author")?.as_array_of()?,
            sig: f.get("sig")?.as_array_of()?,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A valid header for other modules' tests.
    pub(crate) fn sample_header() -> Header {
        header_for("pw", &Key::from_bytes([0x30; 32]), 1)
    }

    const ACCOUNT: AccountId = [0x10; 16];
    const DEVICE: DeviceId = [0x40; 16];
    const SALT: [u8; 16] = [0x20; 16];

    fn sk() -> SecretKey {
        SecretKey::from_bytes([0x01; 16])
    }

    fn header_for(password: &str, account_key: &Key, epoch: u32) -> Header {
        let kdf = KdfParams::INSECURE_FAST;
        let keys = derive_sync_keys(password, &SALT, kdf, &sk(), &ACCOUNT).unwrap();
        let mut header = Header {
            account_id: ACCOUNT,
            epoch,
            generation: 1,
            root_device: DEVICE,
            root_key: [0x42; 32],
            kdf,
            salt: SALT,
            secret_key_id: "A3K7".into(),
            wrapped_account_key: vec![],
        };
        header.wrapped_account_key = wrap_account_key(
            &keys.kek,
            account_key,
            &header,
            &mut crate::nonce::fixed([0x50; NONCE_LEN]),
        );
        header
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
        let (unlocked, _) = header_for("pw", &ak, 1).unlock_cheap("pw", &sk()).unwrap();
        assert_eq!(unlocked.as_bytes(), ak.as_bytes());
    }

    #[test]
    fn wrong_password_or_secret_key_is_wrong_password() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        assert!(matches!(
            h.unlock_cheap("nope", &sk()),
            Err(Error::WrongPassword)
        ));
        let other = SecretKey::from_bytes([0x02; 16]);
        assert!(matches!(
            h.unlock_cheap("pw", &other),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn wrapped_key_is_bound_to_every_other_header_field() {
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
            Header {
                root_device: [0x41; 16],
                ..h.clone()
            },
            Header {
                root_key: [0x43; 32],
                ..h.clone()
            },
            Header {
                secret_key_id: "B3K7".into(),
                ..h.clone()
            },
        ] {
            assert!(matches!(
                tampered.unlock_cheap("pw", &sk()),
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

    #[test]
    fn unlock_refuses_weak_remote_kdf_before_running_argon2() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        assert!(matches!(h.unlock("pw", &sk()), Err(Error::Malformed(_))));
    }

    #[test]
    fn signature_covers_the_author() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let mut file = HeaderFile::sign(h, DEVICE, &signing_key());
        file.author = [0x43; 16];
        assert!(matches!(
            file.verify(&signing_key().verifying_key()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn decode_checks_sizes_and_the_key_id_alphabet() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let file = HeaderFile::sign(h.clone(), DEVICE, &signing_key());
        for bad in [
            Header {
                wrapped_account_key: vec![0; WRAPPED_KEY_LEN - 1],
                ..h.clone()
            },
            Header {
                wrapped_account_key: vec![0; WRAPPED_KEY_LEN + 1],
                ..h.clone()
            },
            Header {
                secret_key_id: "a3k7".into(),
                ..h.clone()
            },
            Header {
                secret_key_id: "A3KU".into(),
                ..h.clone()
            },
        ] {
            let bytes = HeaderFile {
                header: bad,
                ..file.clone()
            }
            .encode();
            assert!(matches!(
                HeaderFile::decode(&bytes),
                Err(Error::Malformed(_))
            ));
        }
        let mut huge = file.encode();
        huge.resize(MAX_HEADER_FILE_LEN + 1, 0);
        assert!(matches!(
            HeaderFile::decode(&huge),
            Err(Error::Malformed(_))
        ));
    }
}
