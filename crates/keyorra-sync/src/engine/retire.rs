//! Stub until Task 10 (retiring the device id): the id is not retired yet; the engine halts as before.

use super::*;

/// The device's signing keys. A1d keeps them in the Keychain with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so a database restored or copied to
/// another Mac finds no key and retires.
pub trait DeviceKeys: Send {
    fn holds(&self, device: &DeviceId) -> bool;
    fn store(&mut self, device: DeviceId, key: &SigningKey);
}

/// Assumes every key is held and stores nothing (tests, and until A1d).
pub struct KeepKeys;

impl DeviceKeys for KeepKeys {
    fn holds(&self, _: &DeviceId) -> bool {
        true
    }
    fn store(&mut self, _: DeviceId, _: &SigningKey) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// The signing key is not in this device's key store.
    KeyMissing,
    /// Another copy of this device wrote to its stream.
    OtherCopyWrote,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn set_device_keys(&mut self, keys: Box<dyn DeviceKeys>) {
        self.keys = keys;
    }

    pub(super) fn retire(&mut self, reason: RetireReason, _: u64) -> Result<()> {
        if !self.halted {
            self.halted = true;
            if self.is_root() {
                self.events.push(Event::RootMustStartOver { reason });
            }
        }
        Ok(())
    }
}
