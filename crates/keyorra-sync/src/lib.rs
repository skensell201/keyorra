//! Keyorra sync. This crate is pure: no files, no network, no clock, no OS APIs.
//! Randomness (nonces, keys) is passed in by the caller so every format is reproducible
//! from the test vectors in `docs/sync-test-vectors/`.

pub mod cbor;
pub mod error;
pub mod keys;
pub mod labels;
pub mod pad;
pub mod secret_key;

pub use error::{Error, Result};

/// 16 random bytes fixed when sync is first enabled.
pub type AccountId = [u8; 16];
/// 16 random bytes per device.
pub type DeviceId = [u8; 16];
