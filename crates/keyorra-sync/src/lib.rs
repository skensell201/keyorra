//! Keyorra sync. This crate is pure: no files, no network, no clock, no OS APIs.
//! Randomness (nonces, keys) is passed in by the caller so every format is reproducible
//! from the test vectors in `docs/sync-test-vectors/`.

pub mod cbor;
pub mod chunk;
pub mod clock;
pub mod envelope;
pub mod error;
pub mod header;
pub mod keys;
pub mod labels;
mod nonce;
pub mod pad;
pub mod payload;
pub mod secret_key;
pub mod segment;
pub mod siblings;
pub mod snapshot;
pub mod vv;

pub use error::{Error, Result};

/// 16 random bytes fixed when sync is first enabled.
pub type AccountId = [u8; 16];
/// 16 random bytes per device.
pub type DeviceId = [u8; 16];

#[cfg(test)]
mod vectors;
