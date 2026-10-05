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
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&XChaCha20Poly1305::generate_nonce(&mut OsRng));
    seal_with_nonce(key, &nonce, plaintext, aad)
}

/// [`seal`] with a caller-chosen nonce, for deterministic test vectors and for callers that
/// draw the nonce from a CSPRNG themselves. Reusing a (key, nonce) pair breaks the cipher.
pub fn seal_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("plaintext exceeds the XChaCha20-Poly1305 length limit");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
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
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
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
        assert!(matches!(
            open(&key, &sealed, b"item-2"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&Key::random(), b"hello", b"");
        assert!(matches!(
            open(&Key::random(), &sealed, b""),
            Err(Error::Decrypt)
        ));
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
    fn seal_with_nonce_is_deterministic_and_opens() {
        let key = Key::from_bytes([7u8; 32]);
        let nonce = [9u8; NONCE_LEN];
        let a = seal_with_nonce(&key, &nonce, b"hello", b"aad");
        assert_eq!(a, seal_with_nonce(&key, &nonce, b"hello", b"aad"));
        assert_eq!(&a[..NONCE_LEN], &nonce);
        assert_eq!(&*open(&key, &a, b"aad").unwrap(), b"hello");
    }

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn xchacha20poly1305_known_answer() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let key = Key::from_slice(&hex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ))
        .unwrap();
        let nonce: [u8; NONCE_LEN] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal_with_nonce(&key, &nonce, plaintext, &aad);
        let expected = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                        731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                        2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                        21f9664c97637da9768812f615c68b13b52e\
                        c0875924c1c7987947deafd8780acf49";
        assert_eq!(
            data_encoding::HEXLOWER.encode(&sealed[NONCE_LEN..]),
            expected
        );
    }

    #[test]
    fn truncated_input_fails() {
        assert!(matches!(
            open(&Key::random(), &[0u8; 10], b""),
            Err(Error::Decrypt)
        ));
    }
}
