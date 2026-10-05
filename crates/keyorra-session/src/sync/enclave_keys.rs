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

/// The Secure Enclave as the device keys need it (never prompts).
pub trait Enclave: Send + Sync {
    /// A new enclave key bound to this Mac: (opaque blob, 65-byte X9.63 public key).
    fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String>;
    /// ECDH of the enclave key with `peer`.
    fn agree(&self, blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, String>;
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

    fn records(&self) -> BTreeMap<String, Record> {
        self.keyring
            .load()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
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

impl DeviceKeyStore for EnclaveDeviceKeys {
    fn load(&self, device: &DeviceId) -> Option<SigningKey> {
        let r = self.records().remove(&HEXLOWER.encode(device))?;
        let blob = HEXLOWER.decode(r.enclave_key.as_bytes()).ok()?;
        let enclave_public = HEXLOWER.decode(r.enclave_public.as_bytes()).ok()?;
        let ephemeral: [u8; 65] = HEXLOWER
            .decode(r.ephemeral_public.as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        let shared = self.enclave.agree(&blob, &ephemeral).ok()?;
        let key = wrapping_key(device, &shared, &ephemeral, &enclave_public);
        let sealed = HEXLOWER.decode(r.sealed.as_bytes()).ok()?;
        let secret = crypto::open(&key, &sealed, &aad(device)).ok()?;
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(secret.as_slice().try_into().ok()?);
        Some(SigningKey::from_bytes(&bytes))
    }

    fn store(&mut self, device: DeviceId, key: &SigningKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap();
        let mut records = self.records();
        let (blob, public) = match records.values().next() {
            Some(r) => (
                HEXLOWER
                    .decode(r.enclave_key.as_bytes())
                    .map_err(|e| e.to_string())?,
                HEXLOWER
                    .decode(r.enclave_public.as_bytes())
                    .map_err(|e| e.to_string())?,
            ),
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
        let mut records = self.records();
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

    /// A software enclave: one P-256 key per "Mac".
    pub(crate) struct SoftEnclave(pub p256::SecretKey);

    impl Enclave for SoftEnclave {
        fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String> {
            let public = self.0.public_key().to_encoded_point(false);
            Ok((b"blob".to_vec(), public.as_bytes().try_into().unwrap()))
        }
        fn agree(&self, _blob: &[u8], peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, String> {
            let peer = PublicKey::from_sec1_bytes(peer).map_err(|e| e.to_string())?;
            let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(shared.raw_secret_bytes());
            Ok(out)
        }
    }

    fn keys(keyring: &MemKeyring) -> EnclaveDeviceKeys {
        EnclaveDeviceKeys::new(
            Arc::new(keyring.clone()),
            Arc::new(SoftEnclave(p256::SecretKey::random(&mut OsRng))),
        )
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
        assert_eq!(store.load(&[1; 16]).unwrap().to_bytes(), [5; 32]);
        assert_eq!(store.load(&[2; 16]).unwrap().to_bytes(), [6; 32]);
        assert!(store.load(&[3; 16]).is_none());
        store.forget(&[1; 16]);
        assert!(store.load(&[1; 16]).is_none());
        assert!(store.load(&[2; 16]).is_some());
    }

    #[test]
    fn a_keychain_restored_on_another_mac_opens_nothing() {
        let keyring = MemKeyring::default();
        let mut here = keys(&keyring);
        here.store([1; 16], &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
        // Same keychain contents, another Secure Enclave.
        let elsewhere = keys(&keyring);
        assert!(elsewhere.load(&[1; 16]).is_none());
    }
}
