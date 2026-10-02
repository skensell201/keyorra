use std::fmt;

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// A 32-byte symmetric key, wiped from memory on drop.
pub struct Key(Zeroizing<[u8; 32]>);

impl Key {
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut bytes[..]);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::Error::Invalid("key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(array))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Self::from_bytes(*self.0)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_keys_differ() {
        assert_ne!(Key::random().as_bytes(), Key::random().as_bytes());
    }

    #[test]
    fn from_slice_requires_32_bytes() {
        assert!(Key::from_slice(&[7u8; 32]).is_ok());
        assert!(matches!(Key::from_slice(&[7u8; 31]), Err(crate::Error::Invalid(_))));
    }

    #[test]
    fn debug_does_not_print_key_material() {
        let key = Key::from_bytes([0xAB; 32]);
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
