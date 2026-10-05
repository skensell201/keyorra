//! Device signing keys. A1d-2 keeps them in the macOS Keychain with
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (a Swift helper, like Touch ID), so a
//! database restored or copied to another Mac finds no key and the device retires its id.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use keyorra_sync::engine::DeviceKeys;
use keyorra_sync::DeviceId;
use zeroize::Zeroizing;

pub trait DeviceKeyStore: Send {
    fn load(&self, device: &DeviceId) -> Option<SigningKey>;
    fn store(&mut self, device: DeviceId, key: &SigningKey);
    /// Another handle to the same keys (the engine keeps one to store a new id's key when it
    /// retires the old one).
    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore>;
}

/// In memory (tests, and until the Keychain helper exists); clones share the keys.
#[derive(Clone, Default)]
pub struct MemoryDeviceKeys(pub Arc<Mutex<BTreeMap<DeviceId, Zeroizing<[u8; 32]>>>>);

impl DeviceKeyStore for MemoryDeviceKeys {
    fn load(&self, device: &DeviceId) -> Option<SigningKey> {
        self.0
            .lock()
            .unwrap()
            .get(device)
            .map(|k| SigningKey::from_bytes(k))
    }

    fn store(&mut self, device: DeviceId, key: &SigningKey) {
        self.0
            .lock()
            .unwrap()
            .insert(device, Zeroizing::new(key.to_bytes()));
    }

    fn boxed_clone(&self) -> Box<dyn DeviceKeyStore> {
        Box::new(self.clone())
    }
}

/// The engine's view of the key store: whether a key is held, and storing a new id's key.
pub(super) struct EngineKeys(pub Box<dyn DeviceKeyStore>);

impl DeviceKeys for EngineKeys {
    fn holds(&self, device: &DeviceId) -> bool {
        self.0.load(device).is_some()
    }
    fn store(&mut self, device: DeviceId, key: &SigningKey) {
        self.0.store(device, key);
    }
}
