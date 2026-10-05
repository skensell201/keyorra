//! Attachment chunks: the only data stored as separate blobs. Each attachment has its own
//! random key (kept, sealed with the vault key, in the attachment record), so moving an item
//! or copying it on a conflict never re-uploads chunks.
//!
//! `chunk = "KYC1" ‖ nonce ‖ XChaCha20-Poly1305(att_key, nonce, pad(bytes), aad)`, with
//! `aad = "keyorra/sync/v1/chunk\0" ‖ account_id ‖ attachment_id ‖ index:u32 ‖ count:u32`;
//! the blob's name is the lowercase hex SHA-256 of the whole chunk.

use keyorra_core::crypto::{self, Key, NONCE_LEN};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::pad::{pad, unpad};
use crate::AccountId;

pub const MAGIC: &[u8; 4] = b"KYC1";
pub const MAX_CHUNK: usize = 4 * 1024 * 1024;

/// Where a chunk belongs; every field is bound into the ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkPlace {
    pub account_id: AccountId,
    pub attachment_id: Uuid,
    pub index: u32,
    pub count: u32,
}

impl ChunkPlace {
    fn aad(&self) -> Vec<u8> {
        tagged(
            labels::CHUNK,
            &[
                &self.account_id,
                self.attachment_id.as_bytes(),
                &self.index.to_be_bytes(),
                &self.count.to_be_bytes(),
            ],
        )
    }
}

pub fn seal_chunk(
    attachment_key: &Key,
    place: &ChunkPlace,
    data: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if data.len() > MAX_CHUNK {
        return Err(malformed("chunk larger than 4 MiB"));
    }
    if place.index >= place.count {
        return Err(malformed("chunk index out of range"));
    }
    let padded = Zeroizing::new(pad(data));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&crypto::seal_with_nonce(
        attachment_key,
        nonce,
        &padded,
        &place.aad(),
    ));
    Ok(out)
}

pub fn open_chunk(
    attachment_key: &Key,
    place: &ChunkPlace,
    chunk: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let sealed = chunk
        .strip_prefix(MAGIC)
        .ok_or_else(|| malformed("chunk magic"))?;
    let padded = crypto::open(attachment_key, sealed, &place.aad()).map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
}

/// The blob name: lowercase hex SHA-256 of the chunk bytes.
pub fn chunk_name(chunk: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(chunk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place() -> ChunkPlace {
        ChunkPlace {
            account_id: [0x10; 16],
            attachment_id: Uuid::from_bytes([0x80; 16]),
            index: 0,
            count: 2,
        }
    }

    fn key() -> Key {
        Key::from_bytes([0x81; 32])
    }

    #[test]
    fn round_trip_and_padding() {
        let chunk = seal_chunk(&key(), &place(), b"hello", &[0x52; NONCE_LEN]).unwrap();
        assert!(chunk.starts_with(MAGIC));
        assert_eq!(chunk.len(), 4 + NONCE_LEN + 1024 + 16);
        assert_eq!(&*open_chunk(&key(), &place(), &chunk).unwrap(), b"hello");
    }

    #[test]
    fn bound_to_account_attachment_index_and_count() {
        let chunk = seal_chunk(&key(), &place(), b"hello", &[0x52; NONCE_LEN]).unwrap();
        for other in [
            ChunkPlace {
                account_id: [0x11; 16],
                ..place()
            },
            ChunkPlace {
                attachment_id: Uuid::from_bytes([0x82; 16]),
                ..place()
            },
            ChunkPlace {
                index: 1,
                ..place()
            },
            ChunkPlace {
                count: 3,
                ..place()
            },
        ] {
            assert!(matches!(
                open_chunk(&key(), &other, &chunk),
                Err(Error::Decrypt)
            ));
        }
        assert!(matches!(
            open_chunk(&Key::from_bytes([0x83; 32]), &place(), &chunk),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn rejects_oversized_bad_index_and_bad_magic() {
        let big = vec![0u8; MAX_CHUNK + 1];
        assert!(seal_chunk(&key(), &place(), &big, &[0; NONCE_LEN]).is_err());
        let bad = ChunkPlace {
            index: 2,
            ..place()
        };
        assert!(seal_chunk(&key(), &bad, b"x", &[0; NONCE_LEN]).is_err());
        let mut chunk = seal_chunk(&key(), &place(), b"x", &[0; NONCE_LEN]).unwrap();
        chunk[0] = b'X';
        assert!(matches!(
            open_chunk(&key(), &place(), &chunk),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn name_is_hex_sha256() {
        assert_eq!(
            chunk_name(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
