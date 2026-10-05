//! Touch ID unlock, minus the OS calls: the account key wrapped to a Secure Enclave key.
//!
//! The app creates a P-256 key inside the Secure Enclave that only works after Touch ID with
//! the fingerprints enrolled at that moment (`.biometryCurrentSet`). To wrap, we do ECDH with a
//! fresh ephemeral key against the enclave's public key (no prompt needed); to unwrap, the
//! enclave does the same ECDH with the ephemeral public key after Touch ID. The time of the
//! last master-password entry is bound into the ciphertext, so the 14-day limit can't be
//! extended by editing the record.

use data_encoding::BASE64;
use keepsake_core::crypto::{self, Key};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CmdError, CmdResult, ErrorKind};

/// The master password is required again this long after it was last entered.
pub const MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;
const LABEL: &str = "keepsake-touchid-v1";
const VERSION: u32 = 1;

/// What the keychain holds. Useless without this Mac's Secure Enclave and a matching finger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub version: u32,
    /// CryptoKit's opaque handle of the enclave key.
    #[serde(with = "b64")]
    pub enclave_key: Vec<u8>,
    /// X9.63 uncompressed, 65 bytes.
    #[serde(with = "b64")]
    pub enclave_public: Vec<u8>,
    #[serde(with = "b64")]
    pub ephemeral_public: Vec<u8>,
    /// Unix seconds of the last master-password entry.
    pub verified_at: u64,
    #[serde(with = "b64")]
    pub sealed: Vec<u8>,
}

impl Record {
    pub fn expires_at(&self) -> u64 {
        self.verified_at + MAX_AGE_SECS
    }

    /// Expired, or stamped in the future (clock moved back): either way ask for the password.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at() || self.verified_at > now + 300
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("record serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Record> {
        serde_json::from_slice::<Record>(bytes)
            .ok()
            .filter(|r| r.version == VERSION)
    }
}

/// Where the record lives: the login keychain in the app, memory in tests.
pub trait Keyring: Send {
    fn load(&self) -> Option<Vec<u8>>;
    fn save(&self, data: &[u8]) -> Result<(), String>;
    fn delete(&self);
}

/// No keychain at all: Touch ID stays off.
pub struct NoKeyring;

impl Keyring for NoKeyring {
    fn load(&self) -> Option<Vec<u8>> {
        None
    }
    fn save(&self, _: &[u8]) -> Result<(), String> {
        Err("Touch ID isn't available".into())
    }
    fn delete(&self) {}
}

/// Shared in-memory keyring for tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemKeyring(pub std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

#[cfg(test)]
impl Keyring for MemKeyring {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
    fn delete(&self) {
        *self.0.lock().unwrap() = None;
    }
}

/// What the UI needs to show the Touch ID button and the setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TouchIdState {
    /// This Mac has Touch ID with enrolled fingers (filled in by the app).
    pub available: bool,
    pub enabled: bool,
    /// Enabled, but the master password is due (14 days passed).
    pub password_due: bool,
}

/// What the app hands to the Secure Enclave for one unlock.
#[derive(Debug)]
pub struct UnlockRequest {
    pub enclave_key: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
}

/// Wraps `account` for the enclave key; needs only its public key, so it never prompts.
pub fn wrap(
    account: &Key,
    enclave_key: Vec<u8>,
    enclave_public: &[u8],
    verified_at: u64,
) -> CmdResult<Record> {
    let enclave = PublicKey::from_sec1_bytes(enclave_public)
        .map_err(|_| CmdError::new(ErrorKind::Invalid, "Bad Secure Enclave public key"))?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = ephemeral.diffie_hellman(&enclave);
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.raw_secret_bytes());
    let key = wrapping_key(&secret, &ephemeral_public, enclave_public);
    Ok(Record {
        version: VERSION,
        enclave_key,
        enclave_public: enclave_public.to_vec(),
        sealed: crypto::seal(&key, account.as_bytes(), &aad(verified_at)),
        ephemeral_public,
        verified_at,
    })
}

/// Recovers the account key from the enclave's ECDH result.
pub fn unwrap(record: &Record, shared: &[u8; 32]) -> CmdResult<Key> {
    let key = wrapping_key(shared, &record.ephemeral_public, &record.enclave_public);
    let raw = crypto::open(&key, &record.sealed, &aad(record.verified_at)).map_err(|_| {
        CmdError::new(
            ErrorKind::PasswordRequired,
            "Touch ID needs to be set up again. Unlock with your master password.",
        )
    })?;
    Ok(Key::from_slice(&raw)?)
}

fn wrapping_key(shared: &[u8; 32], ephemeral_public: &[u8], enclave_public: &[u8]) -> Key {
    let mut h = Sha256::new();
    h.update(format!("{LABEL}/key").as_bytes());
    h.update(shared);
    h.update(ephemeral_public);
    h.update(enclave_public);
    Key::from_bytes(h.finalize().into())
}

fn aad(verified_at: u64) -> Vec<u8> {
    let mut aad = format!("{LABEL}/account-key/").into_bytes();
    aad.extend_from_slice(&verified_at.to_be_bytes());
    aad
}

mod b64 {
    use super::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Software stand-in for the Secure Enclave in tests.
#[cfg(test)]
pub(crate) struct FakeEnclave(p256::SecretKey);

#[cfg(test)]
impl FakeEnclave {
    pub fn new() -> Self {
        Self(p256::SecretKey::random(&mut OsRng))
    }

    pub fn public(&self) -> Vec<u8> {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// What the enclave returns after a successful Touch ID.
    pub fn agree(&self, ephemeral_public: &[u8]) -> [u8; 32] {
        let peer = PublicKey::from_sec1_bytes(ephemeral_public).unwrap();
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_then_unwrap_with_the_enclave() {
        let enclave = FakeEnclave::new();
        let account = Key::random();
        let record = wrap(&account, b"blob".to_vec(), &enclave.public(), 1_000).unwrap();
        let shared = enclave.agree(&record.ephemeral_public);
        assert_eq!(
            unwrap(&record, &shared).unwrap().as_bytes(),
            account.as_bytes()
        );
    }

    #[test]
    fn another_enclave_key_cannot_unwrap() {
        let record = wrap(&Key::random(), vec![], &FakeEnclave::new().public(), 1_000).unwrap();
        let other = FakeEnclave::new().agree(&record.ephemeral_public);
        assert_eq!(
            unwrap(&record, &other).unwrap_err().kind,
            ErrorKind::PasswordRequired
        );
    }

    #[test]
    fn the_password_time_cannot_be_moved() {
        let enclave = FakeEnclave::new();
        let mut record = wrap(&Key::random(), vec![], &enclave.public(), 1_000).unwrap();
        record.verified_at += 7 * 24 * 60 * 60;
        let shared = enclave.agree(&record.ephemeral_public);
        assert!(unwrap(&record, &shared).is_err());
    }

    #[test]
    fn expiry_after_14_days_or_from_the_future() {
        let record = wrap(
            &Key::random(),
            vec![],
            &FakeEnclave::new().public(),
            1_000_000,
        )
        .unwrap();
        assert!(!record.is_expired(1_000_000));
        assert!(!record.is_expired(1_000_000 + MAX_AGE_SECS - 1));
        assert!(record.is_expired(1_000_000 + MAX_AGE_SECS));
        assert!(
            record.is_expired(1_000_000 - 3_600),
            "verified in the future"
        );
    }

    #[test]
    fn record_round_trips_as_compact_json() {
        let record = wrap(
            &Key::random(),
            vec![1, 2, 3],
            &FakeEnclave::new().public(),
            5,
        )
        .unwrap();
        let bytes = record.to_bytes();
        assert_eq!(Record::from_bytes(&bytes), Some(record));
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("\"enclaveKey\":\"AQID\""));
        assert_eq!(Record::from_bytes(b"{}"), None);
    }

    #[test]
    fn a_bad_public_key_is_refused() {
        assert_eq!(
            wrap(&Key::random(), vec![], &[4; 65], 1).unwrap_err().kind,
            ErrorKind::Invalid
        );
    }
}
