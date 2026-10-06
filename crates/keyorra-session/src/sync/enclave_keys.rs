//! Device signing keys that stay on this Mac (plan A1d).
//!
//! The data-protection keychain (`kSecAttrAccessible…ThisDeviceOnly` items) needs a
//! provisioning profile the app does not have (see swift/TouchId.swift). So each device key is
//! sealed to a Secure Enclave key created with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
//! and no user presence: the enclave key never leaves this Mac, so a keychain or disk restored
//! on another Mac (or a copied database) finds a record it cannot open, and the engine retires
//! the device id (spec §4.2). The sealed records are kept in one login-keychain item.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use keyorra_core::crypto::{self, Key};
use keyorra_sync::DeviceId;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::keys::DeviceKeyStore;
use crate::touchid::Keyring;

const LABEL: &str = "keyorra-device-key-v1";

/// Why an enclave agreement failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnclaveError {
    /// The enclave key cannot be used on this Mac (made on another Mac, or deleted).
    Invalid,
    /// Something else, maybe for a moment.
    Failed(String),
}

/// The Secure Enclave as the device keys need it (never prompts).
pub trait Enclave: Send + Sync {
    /// A new enclave key bound to this Mac: (opaque blob, 65-byte X9.63 public key).
    fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String>;
    /// ECDH of the enclave key with `peer`.
    fn agree(&self, blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, EnclaveError>;
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    enclave_key: String,
    enclave_public: String,
    ephemeral_public: String,
    sealed: String,
}

/// Device keys sealed to the Secure Enclave, kept in one keychain item.
#[derive(Clone)]
pub struct EnclaveDeviceKeys {
    keyring: Arc<dyn Keyring + Sync>,
    enclave: Arc<dyn Enclave>,
    /// One enclave key serves every device id of this Mac; made on first use.
    lock: Arc<Mutex<()>>,
}

impl EnclaveDeviceKeys {
    pub fn new(keyring: Arc<dyn Keyring + Sync>, enclave: Arc<dyn Enclave>) -> Self {
        Self {
            keyring,
            enclave,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// The records in the keychain item; an item that cannot be read is an error, never
    /// "no records" (it would be overwritten, review A1d-2 I3).
    fn records(&self) -> Result<BTreeMap<String, Record>, String> {
        match self.keyring.load()? {
            None => Ok(BTreeMap::new()),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("the device key item is unreadable: {e}")),
        }
    }

    /// Opens one record: `Ok(None)` when it cannot be opened on this Mac (another Mac's
    /// enclave, damaged), `Err` when the enclave failed for another reason.
    fn open(&self, device: &DeviceId, r: &Record) -> Result<Option<SigningKey>, String> {
        let parts = (|| {
            let blob = HEXLOWER.decode(r.enclave_key.as_bytes()).ok()?;
            let public = HEXLOWER.decode(r.enclave_public.as_bytes()).ok()?;
            let ephemeral: [u8; 65] = HEXLOWER
                .decode(r.ephemeral_public.as_bytes())
                .ok()?
                .try_into()
                .ok()?;
            let sealed = HEXLOWER.decode(r.sealed.as_bytes()).ok()?;
            Some((blob, public, ephemeral, sealed))
        })();
        let Some((blob, public, ephemeral, sealed)) = parts else {
            return Ok(None);
        };
        let shared = match self.enclave.agree(&blob, &ephemeral) {
            Ok(s) => s,
            Err(EnclaveError::Invalid) => return Ok(None),
            Err(EnclaveError::Failed(e)) => return Err(e),
        };
        let key = wrapping_key(device, &shared, &ephemeral, &public);
        let Ok(secret) = crypto::open(&key, &sealed, &aad(device)) else {
            return Ok(None);
        };
        let Ok(bytes) = <[u8; 32]>::try_from(secret.as_slice()) else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        Ok(Some(SigningKey::from_bytes(&bytes)))
    }
}

fn wrapping_key(device: &DeviceId, shared: &[u8; 32], ephemeral: &[u8], enclave: &[u8]) -> Key {
    let mut h = Sha256::new();
    h.update(LABEL.as_bytes());
    h.update(device);
    h.update(shared);
    h.update(ephemeral);
    h.update(enclave);
    Key::from_bytes(h.finalize().into())
}

fn aad(device: &DeviceId) -> Vec<u8> {
    [LABEL.as_bytes(), b"/", device.as_slice()].concat()
}

fn device_of(hex: &str) -> Option<DeviceId> {
    HEXLOWER.decode(hex.as_bytes()).ok()?.try_into().ok()
}

impl DeviceKeyStore for EnclaveDeviceKeys {
    fn load(&self, device: &DeviceId) -> Result<Option<SigningKey>, String> {
        let records = self.records()?;
        match records.get(&HEXLOWER.encode(device)) {
            None => Ok(None),
            Some(r) => self.open(device, r),
        }
    }

    fn store(&mut self, device: DeviceId, key: &SigningKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap();
        let mut records = self.records()?;
        // The enclave key of a record that opens here; a record that does not (a keychain
        // restored or migrated from another Mac) is useless here and goes (review A1d-2 C2).
        let mut reuse = None;
        let mut unusable = Vec::new();
        for (hex, r) in &records {
            let opened = match device_of(hex) {
                Some(d) => self.open(&d, r)?,
                None => None,
            };
            match opened {
                Some(_) if reuse.is_none() => {
                    reuse = Some((
                        HEXLOWER
                            .decode(r.enclave_key.as_bytes())
                            .map_err(|e| e.to_string())?,
                        HEXLOWER
                            .decode(r.enclave_public.as_bytes())
                            .map_err(|e| e.to_string())?,
                    ))
                }
                Some(_) => {}
                None => unusable.push(hex.clone()),
            }
        }
        for hex in unusable {
            records.remove(&hex);
        }
        let (blob, public) = match reuse {
            Some(x) => x,
            None => {
                let (blob, public) = self.enclave.create()?;
                (blob, public.to_vec())
            }
        };
        let enclave = PublicKey::from_sec1_bytes(&public).map_err(|e| e.to_string())?;
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = ephemeral.public_key().to_encoded_point(false);
        let shared = ephemeral.diffie_hellman(&enclave);
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(shared.raw_secret_bytes());
        let wrap = wrapping_key(&device, &secret, ephemeral_public.as_bytes(), &public);
        let sealed = crypto::seal(&wrap, &key.to_bytes(), &aad(&device));
        records.insert(
            HEXLOWER.encode(&device),
            Record {
                enclave_key: HEXLOWER.encode(&blob),
                enclave_public: HEXLOWER.encode(&public),
                ephemeral_public: HEXLOWER.encode(ephemeral_public.as_bytes()),
                sealed: HEXLOWER.encode(&sealed),
            },
        );
        let bytes = serde_json::to_vec(&records).map_err(|e| e.to_string())?;
        self.keyring.save(&bytes)
    }

    fn forget(&mut self, device: &DeviceId) {
        let _guard = self.lock.lock().unwrap();
        let Ok(mut records) = self.records() else {
            return;
        };
        if records.remove(&HEXLOWER.encode(device)).is_some() {
            if let Ok(bytes) = serde_json::to_vec(&records) {
                let _ = self.keyring.save(&bytes);
            }
        }
    }

    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::touchid::MemKeyring;

    /// A software enclave: one P-256 key per "Mac". `failing` makes every agreement fail for
    /// a moment (not an invalid key).
    pub(crate) struct SoftEnclave(pub p256::SecretKey, pub Arc<Mutex<bool>>);

    impl SoftEnclave {
        fn new() -> Self {
            Self(p256::SecretKey::random(&mut OsRng), Arc::default())
        }
    }

    impl Enclave for SoftEnclave {
        fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String> {
            let public = self.0.public_key().to_encoded_point(false);
            Ok((b"blob".to_vec(), public.as_bytes().try_into().unwrap()))
        }
        fn agree(
            &self,
            _blob: &[u8],
            peer: &[u8; 65],
        ) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
            if *self.1.lock().unwrap() {
                return Err(EnclaveError::Failed("busy".into()));
            }
            let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| EnclaveError::Invalid)?;
            let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(shared.raw_secret_bytes());
            Ok(out)
        }
    }

    /// A keychain item that can fail to be read for a moment.
    #[derive(Clone, Default)]
    struct FlakyKeyring(MemKeyring, Arc<Mutex<bool>>);

    impl Keyring for FlakyKeyring {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            if *self.1.lock().unwrap() {
                return Err("keychain locked".into());
            }
            self.0.load()
        }
        fn save(&self, data: &[u8]) -> Result<(), String> {
            self.0.save(data)
        }
        fn delete(&self) {
            self.0.delete()
        }
    }

    fn keys(keyring: &MemKeyring) -> EnclaveDeviceKeys {
        EnclaveDeviceKeys::new(Arc::new(keyring.clone()), Arc::new(SoftEnclave::new()))
    }

    fn loaded(store: &EnclaveDeviceKeys, device: [u8; 16]) -> Option<[u8; 32]> {
        store.load(&device).unwrap().map(|k| k.to_bytes())
    }

    #[test]
    fn a_device_key_comes_back_on_the_same_mac() {
        let keyring = MemKeyring::default();
        let mut store = keys(&keyring);
        let key = SigningKey::from_bytes(&[5; 32]);
        store.store([1; 16], &key).unwrap();
        store
            .store([2; 16], &SigningKey::from_bytes(&[6; 32]))
            .unwrap();
        assert_eq!(loaded(&store, [1; 16]), Some([5; 32]));
        assert_eq!(loaded(&store, [2; 16]), Some([6; 32]));
        assert_eq!(loaded(&store, [3; 16]), None);
        store.forget(&[1; 16]);
        assert_eq!(loaded(&store, [1; 16]), None);
        assert!(loaded(&store, [2; 16]).is_some());
    }

    /// Review A1d-2 C2: a keychain restored on another Mac opens nothing there, and a key
    /// stored there afterwards is sealed to that Mac's enclave (not the old Mac's).
    #[test]
    fn a_keychain_restored_on_another_mac_opens_nothing() {
        let keyring = MemKeyring::default();
        let mut here = keys(&keyring);
        here.store([1; 16], &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
        // Same keychain contents, another Secure Enclave.
        let mut elsewhere = keys(&keyring);
        assert_eq!(loaded(&elsewhere, [1; 16]), None);
        elsewhere
            .store([2; 16], &SigningKey::from_bytes(&[7; 32]))
            .unwrap();
        assert_eq!(loaded(&elsewhere, [2; 16]), Some([7; 32]));
        // The old Mac's record is of no use here and is dropped.
        let records: BTreeMap<String, Record> =
            serde_json::from_slice(&keyring.load().unwrap().unwrap()).unwrap();
        assert_eq!(records.len(), 1);
    }

    /// Review A1d-2 I3: a keychain that cannot be read for a moment is not "no key": nothing
    /// is overwritten and no key is reported missing.
    #[test]
    fn a_failing_keychain_or_enclave_is_an_error_not_a_missing_key() {
        let keyring = FlakyKeyring::default();
        let enclave = Arc::new(SoftEnclave::new());
        let mut store = EnclaveDeviceKeys::new(Arc::new(keyring.clone()), enclave.clone());
        store
            .store([1; 16], &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
        *keyring.1.lock().unwrap() = true;
        assert!(store.load(&[1; 16]).is_err());
        assert!(store
            .store([2; 16], &SigningKey::from_bytes(&[6; 32]))
            .is_err());
        *keyring.1.lock().unwrap() = false;
        assert_eq!(
            loaded(&store, [1; 16]),
            Some([5; 32]),
            "nothing was overwritten"
        );
        *enclave.1.lock().unwrap() = true;
        assert!(store.load(&[1; 16]).is_err());
        assert!(store
            .store([2; 16], &SigningKey::from_bytes(&[6; 32]))
            .is_err());
    }
}
