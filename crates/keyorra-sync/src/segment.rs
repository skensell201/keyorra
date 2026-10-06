//! Log segments: immutable, signed, hash-chained batches of one device's entries.
//!
//! ```text
//! segment = header ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
//!           (the sealed output starts with the nonce)
//! header  = "KYS1" ‖ collection:u8 ‖ device_id:16 ‖ first_seq:u64 ‖ last_seq:u64 ‖ prev_hash:32 ‖ last_hash:32
//! payload = { "entries": [entry…], "sig": Ed25519(device key, "keyorra/sync/v1/segment\0" ‖ header ‖ canonical(entries)) }
//! chain_0 = SHA-256("keyorra/sync/v1/chain-genesis\0" ‖ account_id ‖ device_id)
//! chain_n = SHA-256("keyorra/sync/v1/chain\0" ‖ chain_{n-1} ‖ canonical(entry_n))
//! ```
//!
//! The plaintext header carries only random ids, counters and hashes, so a server can enforce
//! append-only, contiguous, chained streams without reading anything. Entry contents are
//! defined in plan A1c; here an entry is any CBOR value.

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
use crate::{AccountId, DeviceId};

pub const MAGIC: &[u8; 4] = b"KYS1";
pub const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 8 + 32 + 32;
/// Collection 0 is the account's own data; other values are reserved for shared vaults.
pub const ACCOUNT_COLLECTION: u8 = 0;
/// Cap on the canonical size of a segment's entries; larger rounds become several segments.
pub const MAX_ENTRIES_LEN: usize = 4 * 1024 * 1024;

/// Largest valid sealed segment: header, nonce, padded payload (entries plus signature
/// framing), tag. Anything longer is rejected before it is parsed or decrypted.
pub fn max_segment_len() -> usize {
    HEADER_LEN + NONCE_LEN + padded_len(MAX_ENTRIES_LEN + 128) + 16
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    pub collection: u8,
    pub device_id: DeviceId,
    pub first_seq: u64,
    pub last_seq: u64,
    pub prev_hash: [u8; 32],
    pub last_hash: [u8; 32],
}

impl SegmentHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = self.collection;
        out[5..21].copy_from_slice(&self.device_id);
        out[21..29].copy_from_slice(&self.first_seq.to_be_bytes());
        out[29..37].copy_from_slice(&self.last_seq.to_be_bytes());
        out[37..69].copy_from_slice(&self.prev_hash);
        out[69..101].copy_from_slice(&self.last_hash);
        out
    }

    /// Reads the plaintext header of a segment. Needs no key (a server uses this).
    ///
    /// The header is unauthenticated: `prev_hash` of a stream's first segment must equal
    /// [`chain_genesis`], which is checked by the stream logic of plan A1c, not here.
    pub fn parse(segment: &[u8]) -> Result<SegmentHeader> {
        if segment.len() > max_segment_len() {
            return Err(malformed("segment larger than allowed"));
        }
        if segment.len() < HEADER_LEN || &segment[..4] != MAGIC {
            return Err(malformed("segment header"));
        }
        let b = &segment[..HEADER_LEN];
        let header = SegmentHeader {
            collection: b[4],
            device_id: b[5..21].try_into().unwrap(),
            first_seq: u64::from_be_bytes(b[21..29].try_into().unwrap()),
            last_seq: u64::from_be_bytes(b[29..37].try_into().unwrap()),
            prev_hash: b[37..69].try_into().unwrap(),
            last_hash: b[69..101].try_into().unwrap(),
        };
        if header.collection != ACCOUNT_COLLECTION {
            return Err(Error::Unsupported(format!(
                "collection {}",
                header.collection
            )));
        }
        if header.first_seq == 0 || header.last_seq < header.first_seq {
            return Err(malformed("segment sequence numbers"));
        }
        Ok(header)
    }

    pub fn entry_count(&self) -> u64 {
        self.last_seq - self.first_seq + 1
    }
}

pub fn chain_genesis(account_id: &AccountId, device_id: &DeviceId) -> [u8; 32] {
    Sha256::digest(tagged(labels::CHAIN_GENESIS, &[account_id, device_id])).into()
}

pub fn chain_next(prev: &[u8; 32], entry: &Value) -> [u8; 32] {
    Sha256::digest(tagged(labels::CHAIN, &[prev, &cbor::encode(entry)])).into()
}

pub fn chain(prev: &[u8; 32], entries: &[Value]) -> [u8; 32] {
    entries.iter().fold(*prev, |h, e| chain_next(&h, e))
}

fn signed_message(header: &[u8; HEADER_LEN], entries: &Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(tagged(labels::SEGMENT, &[header, &cbor::encode(entries)]))
}

fn aad(header: &[u8; HEADER_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(nonce);
    aad
}

/// Where a new segment continues its stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPosition {
    pub device_id: DeviceId,
    /// Sequence number of the first entry in the new segment (the stream starts at 1).
    pub first_seq: u64,
    /// Chain hash of the entry before it (`chain_genesis` for seq 1).
    pub prev_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub header: SegmentHeader,
    pub entries: Vec<Value>,
}

pub fn seal_segment(
    segment_key: &Key,
    signer: &SigningKey,
    at: &StreamPosition,
    entries: Vec<Value>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    if entries.is_empty() || at.first_seq == 0 {
        return Err(malformed("empty segment or seq 0"));
    }
    let last_seq = at
        .first_seq
        .checked_add(entries.len() as u64 - 1)
        .ok_or_else(|| malformed("segment sequence numbers overflow"))?;
    let header = SegmentHeader {
        collection: ACCOUNT_COLLECTION,
        device_id: at.device_id,
        first_seq: at.first_seq,
        last_seq,
        prev_hash: at.prev_hash,
        last_hash: chain(&at.prev_hash, &entries),
    }
    .to_bytes();
    let entries = Value::Array(entries);
    if cbor::encode(&entries).len() > MAX_ENTRIES_LEN {
        return Err(malformed("segment too large"));
    }
    let sig = signer.sign(&signed_message(&header, &entries)).to_bytes();
    let encoded = Zeroizing::new(cbor::encode(&Value::map(vec![
        ("entries", entries),
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

/// Decrypts and fully verifies a segment written by the holder of `author`.
pub fn open_segment(segment_key: &Key, author: &VerifyingKey, segment: &[u8]) -> Result<Segment> {
    decrypt_segment(segment_key, segment)?.verify(author)
}

/// A decrypted segment whose signature is not checked yet: for streams whose key is carried
/// by their own first entry (the root's `Genesis`, a `SelfJoin`; plan A1c).
#[derive(Clone, Debug)]
pub struct Unverified {
    pub header: SegmentHeader,
    pub entries: Vec<Value>,
    entries_value: Value,
    sig: [u8; 64],
}

impl Unverified {
    /// Checks the signature, the entry count and the chain.
    pub fn verify(self, author: &VerifyingKey) -> Result<Segment> {
        author
            .verify_strict(
                &signed_message(&self.header.to_bytes(), &self.entries_value),
                &Signature::from_bytes(&self.sig),
            )
            .map_err(|_| Error::BadSignature)?;
        if self.entries.len() as u64 != self.header.entry_count() {
            return Err(malformed("segment entry count"));
        }
        if chain(&self.header.prev_hash, &self.entries) != self.header.last_hash {
            return Err(malformed("segment chain"));
        }
        Ok(Segment {
            header: self.header,
            entries: self.entries,
        })
    }
}

/// Decrypts and decodes a segment without checking who signed it.
pub fn decrypt_segment(segment_key: &Key, segment: &[u8]) -> Result<Unverified> {
    let header = SegmentHeader::parse(segment)?;
    let header_bytes = header.to_bytes();
    let sealed = &segment[HEADER_LEN..];
    let nonce: &[u8; NONCE_LEN] = sealed
        .get(..NONCE_LEN)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("segment nonce"))?;
    let padded = crypto::open(segment_key, sealed, &aad(&header_bytes, nonce))
        .map_err(|_| Error::Decrypt)?;
    let content = unpad(&padded)?;
    if content.len() > MAX_ENTRIES_LEN + 128 {
        return Err(malformed("segment payload larger than allowed"));
    }
    let payload = cbor::decode(content)?;
    let f = payload.fields(&["entries", "sig"])?;
    let entries_value = f.get("entries")?.clone();
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    if cbor::encode(&entries_value).len() > MAX_ENTRIES_LEN {
        return Err(malformed("segment too large"));
    }
    let entries = entries_value.as_list()?.to_vec();
    Ok(Unverified {
        header,
        entries,
        entries_value,
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = [0x10; 16];
    const DEVICE: DeviceId = [0x40; 16];

    fn k_seg() -> Key {
        Key::from_bytes([0x90; 32])
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn start() -> StreamPosition {
        StreamPosition {
            device_id: DEVICE,
            first_seq: 1,
            prev_hash: chain_genesis(&ACCOUNT, &DEVICE),
        }
    }

    fn entries() -> Vec<Value> {
        vec![Value::text("first"), Value::Uint(2), Value::bytes([3])]
    }

    fn sealed() -> Vec<u8> {
        seal_segment(
            &k_seg(),
            &signer(),
            &start(),
            entries(),
            &mut crate::nonce::fixed([0x53; 24]),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_with_header_fields() {
        let seg = open_segment(&k_seg(), &signer().verifying_key(), &sealed()).unwrap();
        assert_eq!(seg.entries, entries());
        assert_eq!(seg.header.first_seq, 1);
        assert_eq!(seg.header.last_seq, 3);
        assert_eq!(seg.header.prev_hash, chain_genesis(&ACCOUNT, &DEVICE));
        assert_eq!(seg.header.last_hash, chain(&start().prev_hash, &entries()));
        assert_eq!(SegmentHeader::parse(&sealed()).unwrap(), seg.header);
    }

    #[test]
    fn segments_chain_into_each_other() {
        let first = open_segment(&k_seg(), &signer().verifying_key(), &sealed()).unwrap();
        let next_at = StreamPosition {
            device_id: DEVICE,
            first_seq: 4,
            prev_hash: first.header.last_hash,
        };
        let next = seal_segment(
            &k_seg(),
            &signer(),
            &next_at,
            vec![Value::Null],
            &mut crate::nonce::fixed([0x54; 24]),
        )
        .unwrap();
        let next = open_segment(&k_seg(), &signer().verifying_key(), &next).unwrap();
        assert_eq!(next.header.prev_hash, first.header.last_hash);
        assert_eq!(next.header.last_seq, 4);
    }

    #[test]
    fn genesis_depends_on_account_and_device() {
        let g = chain_genesis(&ACCOUNT, &DEVICE);
        assert_ne!(g, chain_genesis(&[0x11; 16], &DEVICE));
        assert_ne!(g, chain_genesis(&ACCOUNT, &[0x41; 16]));
    }

    #[test]
    fn every_header_byte_is_authenticated() {
        let good = sealed();
        for i in 4..HEADER_LEN {
            let mut bad = good.clone();
            bad[i] ^= 1;
            assert!(
                open_segment(&k_seg(), &signer().verifying_key(), &bad).is_err(),
                "byte {i}"
            );
        }
    }

    #[test]
    fn tampered_ciphertext_wrong_key_or_wrong_author_fail() {
        let mut bad = sealed();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let pk = signer().verifying_key();
        assert!(matches!(
            open_segment(&k_seg(), &pk, &bad),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            open_segment(&Key::from_bytes([0x91; 32]), &pk, &sealed()),
            Err(Error::Decrypt)
        ));
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(
            open_segment(&k_seg(), &other, &sealed()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn decrypt_then_verify_equals_open() {
        let unverified = decrypt_segment(&k_seg(), &sealed()).unwrap();
        assert_eq!(unverified.entries, entries());
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(
            unverified.clone().verify(&other),
            Err(Error::BadSignature)
        ));
        assert_eq!(
            unverified.verify(&signer().verifying_key()).unwrap(),
            open_segment(&k_seg(), &signer().verifying_key(), &sealed()).unwrap()
        );
    }

    #[test]
    fn header_parse_rejects_bad_magic_collection_and_seqs() {
        let good = sealed();
        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(matches!(
            SegmentHeader::parse(&magic),
            Err(Error::Malformed(_))
        ));
        let mut coll = good.clone();
        coll[4] = 1;
        assert!(matches!(
            SegmentHeader::parse(&coll),
            Err(Error::Unsupported(_))
        ));
        let mut zero = good.clone();
        zero[21..29].copy_from_slice(&0u64.to_be_bytes());
        assert!(SegmentHeader::parse(&zero).is_err());
        assert!(SegmentHeader::parse(&good[..50]).is_err());
    }

    #[test]
    fn refuses_empty_segments_and_seq_zero() {
        let k = k_seg();
        assert!(seal_segment(
            &k,
            &signer(),
            &start(),
            vec![],
            &mut crate::nonce::fixed([0; 24])
        )
        .is_err());
        let zero = StreamPosition {
            first_seq: 0,
            ..start()
        };
        assert!(seal_segment(
            &k,
            &signer(),
            &zero,
            entries(),
            &mut crate::nonce::fixed([0; 24])
        )
        .is_err());
    }

    #[test]
    fn size_is_padded() {
        let len = sealed().len();
        assert_eq!(len, HEADER_LEN + NONCE_LEN + 1024 + 16);
    }

    #[test]
    fn sequence_overflow_and_oversized_input_are_rejected() {
        let k = k_seg();
        let at = StreamPosition {
            first_seq: u64::MAX,
            ..start()
        };
        assert!(matches!(
            seal_segment(
                &k,
                &signer(),
                &at,
                entries(),
                &mut crate::nonce::fixed([0; 24])
            ),
            Err(Error::Malformed(_))
        ));
        let mut huge = sealed();
        huge.resize(max_segment_len() + 1, 0);
        assert!(matches!(
            SegmentHeader::parse(&huge),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            open_segment(&k, &signer().verifying_key(), &huge),
            Err(Error::Malformed(_))
        ));
    }
}
