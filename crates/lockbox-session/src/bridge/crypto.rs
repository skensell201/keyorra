//! Pairing keys and sealed message boxes shared with the browser extension.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const PROTOCOL: &str = "lockbox-bridge-v1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub struct KeyPair {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl KeyPair {
    pub fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut bytes[..]);
        Self::from_secret(*bytes)
    }

    pub fn from_secret(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }
}

/// The session key and the confirmation code both sides show for one pairing.
pub struct Derived {
    pub key: Zeroizing<[u8; 32]>,
    pub code: String,
}

pub fn derive(
    own: &KeyPair,
    peer_public: &[u8; 32],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Derived {
    let shared = Zeroizing::new(
        own.secret
            .diffie_hellman(&PublicKey::from(*peer_public))
            .to_bytes(),
    );
    let hash = |label: &str| {
        let mut h = Sha256::new();
        h.update(format!("{PROTOCOL}/{label}").as_bytes());
        h.update(&shared[..]);
        h.update(client_public);
        h.update(server_public);
        h.finalize()
    };
    let key: [u8; 32] = hash("key").into();
    let c = hash("code");
    let n = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) % 1_000_000;
    Derived {
        key: Zeroizing::new(key),
        code: format!("{n:06}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

fn aad(client_id: &str, direction: Direction) -> Vec<u8> {
    let dir = match direction {
        Direction::Request => "req",
        Direction::Response => "res",
    };
    format!("{PROTOCOL}/{client_id}/{dir}").into_bytes()
}

/// `base64(nonce ‖ XChaCha20-Poly1305(key, nonce, aad, plaintext))`.
pub fn seal(key: &[u8; 32], client_id: &str, direction: Direction, plaintext: &[u8]) -> String {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(key, client_id, direction, plaintext, nonce)
}

fn seal_with_nonce(
    key: &[u8; 32],
    client_id: &str,
    direction: Direction,
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
) -> String {
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(client_id, direction),
            },
        )
        .expect("XChaCha20-Poly1305 cannot fail on in-memory buffers");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    BASE64.encode(&out)
}

/// `None` for anything that doesn't authenticate.
pub fn open(
    key: &[u8; 32],
    client_id: &str,
    direction: Direction,
    boxed: &str,
) -> Option<Zeroizing<Vec<u8>>> {
    let raw = BASE64.decode(boxed.as_bytes()).ok()?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(client_id, direction),
            },
        )
        .ok()
        .map(Zeroizing::new)
}

pub fn b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

pub fn public_from_b64(s: &str) -> Option<[u8; 32]> {
    BASE64.decode(s.as_bytes()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const CLIENT_ID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn matches_the_shared_test_vectors() {
        let client = KeyPair::from_secret([1; 32]);
        let server = KeyPair::from_secret([2; 32]);
        assert_eq!(
            hex(&client.public),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
        assert_eq!(
            hex(&server.public),
            "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"
        );
        let on_server = derive(&server, &client.public, &client.public, &server.public);
        let on_client = derive(&client, &server.public, &client.public, &server.public);
        assert_eq!(
            hex(&*on_server.key),
            "a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab"
        );
        assert_eq!(*on_client.key, *on_server.key);
        assert_eq!(
            (on_server.code.as_str(), on_client.code.as_str()),
            ("381262", "381262")
        );

        let boxed = seal_with_nonce(
            &on_server.key,
            CLIENT_ID,
            Direction::Request,
            br#"{"op":"ping"}"#,
            [3; 24],
        );
        assert_eq!(
            boxed,
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD1AE3nLoQfQz8s+kYte/Lb0sVrtQoMnmqsIE17w4="
        );
    }

    #[test]
    fn boxes_are_bound_to_key_client_and_direction() {
        let key = [7u8; 32];
        let boxed = seal(&key, CLIENT_ID, Direction::Response, b"hello");
        assert_eq!(
            &**open(&key, CLIENT_ID, Direction::Response, &boxed).unwrap(),
            b"hello"
        );
        assert!(open(&key, CLIENT_ID, Direction::Request, &boxed).is_none());
        assert!(open(&key, "other", Direction::Response, &boxed).is_none());
        assert!(open(&[8u8; 32], CLIENT_ID, Direction::Response, &boxed).is_none());
        assert!(open(&key, CLIENT_ID, Direction::Response, "AAAA").is_none());
        assert!(open(&key, CLIENT_ID, Direction::Response, "not base64!").is_none());
        assert_ne!(
            seal(&key, CLIENT_ID, Direction::Response, b"hello"),
            boxed,
            "fresh nonce every time"
        );
    }

    #[test]
    fn base64_keys() {
        let k = KeyPair::random();
        assert_eq!(public_from_b64(&b64(&k.public)), Some(k.public));
        assert_eq!(public_from_b64("AAAA"), None);
    }
}
