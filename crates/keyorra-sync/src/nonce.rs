//! Nonce handling. Production callers pass a CSPRNG into every sealing function; the nonce is
//! drawn here, once, so no public API accepts a caller-chosen nonce.

use keyorra_core::crypto::NONCE_LEN;
use rand::{CryptoRng, RngCore};

pub(crate) fn draw(rng: &mut (impl RngCore + CryptoRng)) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Hands an already-drawn nonce to code that wants an RNG (the core sealing function), for the
/// cases where the nonce is also part of the associated data and so must be known first.
/// Only ever replays one nonce; not a general-purpose generator.
pub(crate) struct Replay(pub [u8; NONCE_LEN]);

impl RngCore for Replay {
    fn next_u32(&mut self) -> u32 {
        unreachable!("Replay only serves nonce draws")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("Replay only serves nonce draws")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), NONCE_LEN, "Replay only serves nonce draws");
        dest.copy_from_slice(&self.0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Marker only: the bytes were drawn from a CSPRNG by `draw`.
impl CryptoRng for Replay {}

/// Test helper: the same scripted nonce for every draw.
#[cfg(test)]
pub(crate) fn fixed(nonce: [u8; NONCE_LEN]) -> Replay {
    Replay(nonce)
}
