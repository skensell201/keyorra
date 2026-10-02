use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Key as CipherKey, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use super::Key;
use crate::{Error, Result};

pub const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Encrypts `plaintext`; output is `nonce || ciphertext || tag`.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.as_bytes()));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 cannot fail on in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts output of [`seal`]. Any mismatch (key, nonce, data, aad) is `Error::Decrypt`.
pub fn open(key: &Key, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.as_bytes()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn round_trip() {
        let key = Key::random();
        let sealed = seal(&key, b"hello", b"aad");
        assert_eq!(&*open(&key, &sealed, b"aad").unwrap(), b"hello");
    }

    #[test]
    fn same_plaintext_seals_differently() {
        let key = Key::random();
        assert_ne!(seal(&key, b"hello", b""), seal(&key, b"hello", b""));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = Key::random();
        let sealed = seal(&key, b"hello", b"item-1");
        assert!(matches!(open(&key, &sealed, b"item-2"), Err(Error::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&Key::random(), b"hello", b"");
        assert!(matches!(open(&Key::random(), &sealed, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = Key::random();
        let mut sealed = seal(&key, b"hello", b"");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(matches!(open(&key, &sealed, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = Key::random();
        let mut sealed = seal(&key, b"hello", b"");
        sealed[0] ^= 1;
        assert!(matches!(open(&key, &sealed, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn truncated_input_fails() {
        assert!(matches!(open(&Key::random(), &[0u8; 10], b""), Err(Error::Decrypt)));
    }
}
