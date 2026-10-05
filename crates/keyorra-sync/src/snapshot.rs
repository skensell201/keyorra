//! Snapshots: self-contained, signed packs of a device's whole fold (contents defined in plan
//! A1c; here the body is any CBOR value).
//!
//! ```text
//! snapshot = "KYP1" ‖ collection:u8 ‖ author:16
//!            ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
//!            (the sealed output starts with the nonce)
//! payload  = { "body": …, "sig": Ed25519(author key, "keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body)) }
//! name     = lowercase hex SHA-256 of the whole snapshot
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key, NONCE_LEN};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::nonce::{self, Replay};
use crate::pad::{pad, padded_len, unpad};
use crate::segment::ACCOUNT_COLLECTION;
use crate::DeviceId;

pub const MAGIC: &[u8; 4] = b"KYP1";
pub const HEADER_LEN: usize = 4 + 1 + 16;
/// Cap on the canonical size of a snapshot body.
pub const MAX_BODY_LEN: usize = 64 * 1024 * 1024;

/// Largest valid sealed snapshot: header, nonce, padded payload, tag.
pub fn max_snapshot_len() -> usize {
    HEADER_LEN + NONCE_LEN + padded_len(MAX_BODY_LEN + 128) + 16
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub collection: u8,
    pub author: DeviceId,
}

impl SnapshotHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = self.collection;
        out[5..].copy_from_slice(&self.author);
        out
    }

    pub fn parse(snapshot: &[u8]) -> Result<SnapshotHeader> {
        if snapshot.len() < HEADER_LEN || &snapshot[..4] != MAGIC {
            return Err(malformed("snapshot header"));
        }
        if snapshot[4] != ACCOUNT_COLLECTION {
            return Err(Error::Unsupported(format!("collection {}", snapshot[4])));
        }
        Ok(SnapshotHeader {
            collection: snapshot[4],
            author: snapshot[5..HEADER_LEN].try_into().unwrap(),
        })
    }
}

fn signed_message(header: &[u8; HEADER_LEN], body: &Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(tagged(labels::SNAPSHOT, &[header, &cbor::encode(body)]))
}

fn aad(header: &[u8; HEADER_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(nonce);
    aad
}

pub fn seal_snapshot(
    segment_key: &Key,
    signer: &SigningKey,
    author: DeviceId,
    body: Value,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    if cbor::encode(&body).len() > MAX_BODY_LEN {
        return Err(malformed("snapshot too large"));
    }
    let header = SnapshotHeader {
        collection: ACCOUNT_COLLECTION,
        author,
    }
    .to_bytes();
    let sig = signer.sign(&signed_message(&header, &body)).to_bytes();
    let encoded = Zeroizing::new(cbor::encode(&Value::map(vec![
        ("body", body),
        ("sig", Value::bytes(sig)),
    ])));
    let payload = Zeroizing::new(pad(&encoded));
    let nonce = nonce::draw(rng);
    let mut out = header.to_vec();
    out.extend_from_slice(&crypto::seal_with_rng(
        segment_key,
        &mut Replay(nonce),
        &payload,
        &aad(&header, &nonce),
    ));
    Ok(out)
}

pub fn open_snapshot(
    segment_key: &Key,
    author: &VerifyingKey,
    snapshot: &[u8],
) -> Result<(SnapshotHeader, Value)> {
    decrypt_snapshot(segment_key, snapshot)?.verify(author)
}

/// A decrypted snapshot whose signature is not checked yet: the author's key may only be known
/// from the trust entries inside it (bootstrap, plan A1c-2).
#[derive(Clone, Debug)]
pub struct UnverifiedSnapshot {
    pub header: SnapshotHeader,
    pub body: Value,
    sig: [u8; 64],
}

impl UnverifiedSnapshot {
    pub fn verify(self, author: &VerifyingKey) -> Result<(SnapshotHeader, Value)> {
        author
            .verify_strict(
                &signed_message(&self.header.to_bytes(), &self.body),
                &Signature::from_bytes(&self.sig),
            )
            .map_err(|_| Error::BadSignature)?;
        Ok((self.header, self.body))
    }
}

pub fn decrypt_snapshot(segment_key: &Key, snapshot: &[u8]) -> Result<UnverifiedSnapshot> {
    if snapshot.len() > max_snapshot_len() {
        return Err(malformed("snapshot larger than allowed"));
    }
    let header = SnapshotHeader::parse(snapshot)?;
    let header_bytes = header.to_bytes();
    let sealed = &snapshot[HEADER_LEN..];
    let nonce: &[u8; NONCE_LEN] = sealed
        .get(..NONCE_LEN)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("snapshot nonce"))?;
    let padded = crypto::open(segment_key, sealed, &aad(&header_bytes, nonce))
        .map_err(|_| Error::Decrypt)?;
    let content = unpad(&padded)?;
    if content.len() > MAX_BODY_LEN + 128 {
        return Err(malformed("snapshot payload larger than allowed"));
    }
    let payload = cbor::decode(content)?;
    let f = payload.fields(&["body", "sig"])?;
    let body = f.get("body")?.clone();
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    Ok(UnverifiedSnapshot { header, body, sig })
}

/// The file/blob name: lowercase hex SHA-256 of the snapshot bytes.
pub fn snapshot_name(snapshot: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHOR: DeviceId = [0x40; 16];

    fn k_seg() -> Key {
        Key::from_bytes([0x90; 32])
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn body() -> Value {
        Value::map(vec![("records", Value::Array(vec![Value::Uint(1)]))])
    }

    fn sealed() -> Vec<u8> {
        seal_snapshot(
            &k_seg(),
            &signer(),
            AUTHOR,
            body(),
            &mut crate::nonce::fixed([0x55; 24]),
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let (header, value) =
            open_snapshot(&k_seg(), &signer().verifying_key(), &sealed()).unwrap();
        assert_eq!(header.author, AUTHOR);
        assert_eq!(value, body());
        assert_eq!(SnapshotHeader::parse(&sealed()).unwrap(), header);
        assert_eq!(sealed().len(), HEADER_LEN + NONCE_LEN + 1024 + 16);
    }

    #[test]
    fn decrypt_then_verify_equals_open() {
        let unverified = decrypt_snapshot(&k_seg(), &sealed()).unwrap();
        assert_eq!(unverified.body, body());
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(
            unverified.clone().verify(&other),
            Err(Error::BadSignature)
        ));
        assert_eq!(
            unverified.verify(&signer().verifying_key()).unwrap(),
            open_snapshot(&k_seg(), &signer().verifying_key(), &sealed()).unwrap()
        );
    }

    #[test]
    fn author_bytes_wrong_key_and_wrong_signer_fail() {
        let pk = signer().verifying_key();
        let mut moved = sealed();
        moved[5] ^= 1;
        assert!(matches!(
            open_snapshot(&k_seg(), &pk, &moved),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            open_snapshot(&Key::from_bytes([0x91; 32]), &pk, &sealed()),
            Err(Error::Decrypt)
        ));
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(
            open_snapshot(&k_seg(), &other, &sealed()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn segment_and_snapshot_signatures_are_domain_separated() {
        // The same key signs both kinds; a snapshot signature must never verify as a segment one.
        let header = SnapshotHeader {
            collection: 0,
            author: AUTHOR,
        }
        .to_bytes();
        assert_ne!(
            *signed_message(&header, &body()),
            tagged(labels::SEGMENT, &[&header, &cbor::encode(&body())])
        );
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(snapshot_name(&sealed()), snapshot_name(&sealed()));
        assert_eq!(snapshot_name(&sealed()).len(), 64);
    }

    #[test]
    fn oversized_snapshots_are_rejected_before_decrypting() {
        let mut huge = sealed();
        huge.resize(max_snapshot_len() + 1, 0);
        assert!(matches!(
            open_snapshot(&k_seg(), &signer().verifying_key(), &huge),
            Err(Error::Malformed(_))
        ));
    }
}
