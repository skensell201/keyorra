# Keyorra Sync A1a Implementation Plan (keys and formats)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The byte-level foundation of sync, with nothing that runs yet: the Secret Key, key derivation (`KEK_sync`, `AUTH`, `K_seg`), a strict canonical CBOR codec, Padmé padding, the account header and its signed file, record envelopes with sealed bodies and version hashes, attachment chunks, signed hash-chained segment framing, snapshot framing, deterministic test vectors and the first sections of `docs/sync-protocol.md`.

**Architecture:** A new crate `crates/keyorra-sync`: pure, no I/O, no clock, no OS APIs; every nonce and key is passed in, so every output is reproducible. It builds on `keyorra-core` (the `Key` type, Argon2id `derive_kek`, `KdfParams`, XChaCha20-Poly1305 `seal`/`open`), which gains one function, `seal_with_nonce`. Later plans add the fold (A1b) and streams and trust (A1c) to the same crate; the folder transport (A2) and the server (B1) depend on it.

**Tech Stack:** Rust 2021; `hkdf` 0.12 and `sha2` 0.10 (already in `Cargo.lock`), `ed25519-dalek` 2 (new; its `curve25519-dalek` 4.1.3 is already locked through `x25519-dalek`), `data-encoding` 2, `rand` 0.8, `uuid` 1, `zeroize` 1, `thiserror` 2; dev: `serde_json`.

**Spec:** `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md` §3.2 (keys and labels), §3.3 (versions), §3.6 (formats), §4.1 (segments), §4.7 (headers), §4.8 (snapshots), §7.6 (Secret Key), §9.3 (protocol doc and vectors), §12 (A1a).

## Decisions

- **A new crate, not a module of `keyorra-core`.** Sync formats are a separate, versioned protocol that the server (B1) and the iPhone app will also link; core stays the local vault. The crate is pure like core (no files, network, clock or OS APIs), so the same TDD style applies.
- **Hand-written canonical CBOR (about 250 lines) instead of a crate.** There is no CBOR crate in `Cargo.lock`. The common ones (`ciborium`, `serde_cbor`, `minicbor`) neither guarantee deterministic output for maps nor reject non-canonical input; we need both, because hashes and signatures are computed over re-encoded values and must equal the bytes received. The codec supports only what the formats use (unsigned integers, byte and text strings, arrays, maps, booleans, null) and is checked against the RFC 8949 Appendix A examples. This is an encoding, not a cryptographic primitive; the MVP rule "no hand-written primitives" still holds.
- **Ed25519: `ed25519-dalek` 2** with `verify_strict` (rejects malleable and small-order cases). Pinned by the RFC 8032 test 1 vector.
- **HKDF: `hkdf` 0.12 + `sha2` 0.10**, already in the lockfile. Pinned by the RFC 5869 test case 1 vector; the vectors in `a1a.json` were cross-checked with an independent Python HKDF (hmac + hashlib).
- **XChaCha20-Poly1305 stays in core.** Core gains `seal_with_nonce` (deterministic vectors and callers that draw nonces themselves); `seal` keeps drawing from `OsRng` and now delegates to it. Pinned by the draft-irtf-cfrg-xchacha A.3.1 vector.
- **Explicit nonces everywhere in `keyorra-sync`.** Every sealing function takes `&[u8; 24]`; production callers (A1c onwards) pass fresh `OsRng` bytes. Nothing in this crate draws randomness except `SecretKey::generate`, which takes the RNG as a parameter.
- **Test vectors are pinned in a file**, `docs/sync-test-vectors/a1a.json`, written by an ignored generator test and checked by a normal test byte for byte. The plan pins the important values inline too (Task 12), so an implementer can tell a wrong implementation from a stale file. Argon2 in the vectors uses cheap parameters (m = 64 KiB, t = 1, p = 1).
- **Entry and snapshot contents are opaque here.** Segment and snapshot framing take any CBOR values; the entry types (`Put`, `Endorse`, …) and the snapshot body are A1c.
- **Error kinds:** `Malformed` (bytes not in the format), `Unsupported` (a newer format or kind; callers keep such data untouched), `Decrypt`, `BadSignature`, `WrongPassword` (header unwrap: wrong password *or* Secret Key, deliberately not distinguished), `Core`.

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean (Task 1: `-p keyorra-core`).
- Tests use fixed byte patterns (`[0x10; 16]` …) instead of randomness, so failures reproduce.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Test counts are printed in the `test result:` lines.
- Work on branch `feat/sync-design` (or a feature branch from it); do not push.

## File map

```
Cargo.toml                                  + crates/keyorra-sync in members and default-members
Cargo.lock                                  + ed25519-dalek, ed25519 (and their already-locked deps)
crates/keyorra-core/src/crypto/aead.rs      + seal_with_nonce, XChaCha known-answer test
crates/keyorra-core/src/crypto/mod.rs       re-export seal_with_nonce
crates/keyorra-sync/Cargo.toml              NEW
crates/keyorra-sync/src/lib.rs              NEW modules, AccountId, DeviceId
crates/keyorra-sync/src/error.rs            NEW Error, Result
crates/keyorra-sync/src/labels.rs           NEW domain-separation labels, tagged()
crates/keyorra-sync/src/cbor.rs             NEW canonical CBOR codec
crates/keyorra-sync/src/pad.rs              NEW Padmé padding
crates/keyorra-sync/src/secret_key.rs       NEW Secret Key, display and parsing
crates/keyorra-sync/src/keys.rs             NEW KEK_sync, AUTH, K_seg, remote KDF bounds
crates/keyorra-sync/src/header.rs           NEW account header, wrapped account key, signed header file
crates/keyorra-sync/src/envelope.rs         NEW record kinds, versions, envelopes, sealed bodies, version hash
crates/keyorra-sync/src/chunk.rs            NEW attachment chunks
crates/keyorra-sync/src/segment.rs          NEW segment framing, hash chain, signatures
crates/keyorra-sync/src/snapshot.rs         NEW snapshot framing
crates/keyorra-sync/src/vectors.rs          NEW test vectors (test-only module)
docs/sync-test-vectors/a1a.json             NEW generated, pinned
docs/sync-protocol.md                       NEW normative protocol, sections 1–8 (+ placeholders)
```

---

### Task 1: Core — `seal_with_nonce`

**Files:** Modify `crates/keyorra-core/src/crypto/aead.rs`, `crates/keyorra-core/src/crypto/mod.rs`.

- [ ] **Step 1: Failing tests.** In `aead.rs`, add to `mod tests` (before `truncated_input_fails`):

```rust
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
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-core crypto::aead` → does not compile (`seal_with_nonce` not found).

- [ ] **Step 3: Implement.** Replace `seal` in `aead.rs` with:

```rust
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
```

and in `crypto/mod.rs` change the re-export to `pub use aead::{open, seal, seal_with_nonce, NONCE_LEN};`.

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-core` → all pass (the existing `same_plaintext_seals_differently` still proves `seal` draws a fresh nonce); `cargo clippy -p keyorra-core --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-core/src/crypto/aead.rs crates/keyorra-core/src/crypto/mod.rs
git commit -m "core: seal_with_nonce for deterministic sync vectors"
```

### Task 2: The `keyorra-sync` crate, errors and labels

**Files:** Modify `Cargo.toml`; create `crates/keyorra-sync/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/labels.rs`.

- [ ] **Step 1: Workspace.** In the root `Cargo.toml`:

```toml
members = ["crates/keyorra-core", "crates/keyorra-session", "crates/keyorra-sync", "app/src-tauri"]
default-members = ["crates/keyorra-core", "crates/keyorra-session", "crates/keyorra-sync"]
```

Create `crates/keyorra-sync/Cargo.toml`:

```toml
[package]
name = "keyorra-sync"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-or-later"
publish = false
description = "Keyorra sync: wire formats and (later) the sync engine. Pure: no I/O, no OS APIs."

[dependencies]
data-encoding = "2"
ed25519-dalek = { version = "2", features = ["zeroize"] }
hkdf = "0.12"
keyorra-core = { path = "../keyorra-core" }
rand = "0.8"
sha2 = "0.10"
thiserror = "2"
uuid = "1"
zeroize = "1"

[dev-dependencies]
keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
serde_json = "1"
```

Create `crates/keyorra-sync/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Bytes that do not follow the format (bad magic, bad CBOR, wrong lengths, bad padding).
    #[error("malformed {0}")]
    Malformed(String),
    /// A newer format than this build understands; the caller keeps the bytes untouched.
    #[error("unsupported {0}")]
    Unsupported(String),
    #[error("decryption failed")]
    Decrypt,
    #[error("bad signature")]
    BadSignature,
    #[error("incorrect password or secret key")]
    WrongPassword,
    #[error(transparent)]
    Core(#[from] keyorra_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn malformed(what: impl Into<String>) -> Error {
    Error::Malformed(what.into())
}
```

Create `crates/keyorra-sync/src/lib.rs` (later tasks add one `pub mod` line each):

```rust
//! Keyorra sync. This crate is pure: no files, no network, no clock, no OS APIs.
//! Randomness (nonces, keys) is passed in by the caller so every format is reproducible
//! from the test vectors in `docs/sync-test-vectors/`.

pub mod error;
pub mod labels;

pub use error::{Error, Result};

/// 16 random bytes fixed when sync is first enabled.
pub type AccountId = [u8; 16];
/// 16 random bytes per device.
pub type DeviceId = [u8; 16];
```

- [ ] **Step 2: Failing tests.** Create `crates/keyorra-sync/src/labels.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_versioned_and_nul_free() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.starts_with(b"keyorra/sync/v1/"), "{a:?}");
            assert!(!a.contains(&0));
            for b in &ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn tagged_terminates_the_label() {
        assert_eq!(tagged(b"x", &[b"ab", b"c"]), b"x\0abc");
        assert_eq!(tagged(b"x", &[]), b"x\0");
        // "chain" vs "chain-genesis" cannot collide thanks to the terminator.
        assert!(!tagged(CHAIN_GENESIS, &[]).starts_with(&tagged(CHAIN, &[])));
    }
}
```

Run `cargo test -p keyorra-sync` → does not compile (`ALL`, `tagged`, the label constants are missing). `Cargo.lock` gains `ed25519-dalek` and `ed25519`.

- [ ] **Step 3: Implement.** Put this above the test module in `labels.rs`:

```rust
//! Domain-separation labels. Every label is used as `label ‖ 0x00 ‖ parts…` (see [`tagged`]),
//! so no label can be a prefix of another.

pub const KEK: &[u8] = b"keyorra/sync/v1/kek";
pub const SERVER_AUTH: &[u8] = b"keyorra/sync/v1/server-auth";
pub const SEGMENT_KEY: &[u8] = b"keyorra/sync/v1/segment-key";
pub const ACCOUNT_KEY: &[u8] = b"keyorra/sync/v1/account-key";
pub const HEADER: &[u8] = b"keyorra/sync/v1/header";
pub const BODY: &[u8] = b"keyorra/sync/v1/body";
pub const VERSION: &[u8] = b"keyorra/sync/v1/version";
pub const CHUNK: &[u8] = b"keyorra/sync/v1/chunk";
pub const SEGMENT: &[u8] = b"keyorra/sync/v1/segment";
pub const SNAPSHOT: &[u8] = b"keyorra/sync/v1/snapshot";
pub const CHAIN_GENESIS: &[u8] = b"keyorra/sync/v1/chain-genesis";
pub const CHAIN: &[u8] = b"keyorra/sync/v1/chain";

pub const ALL: &[&[u8]] = &[
    KEK,
    SERVER_AUTH,
    SEGMENT_KEY,
    ACCOUNT_KEY,
    HEADER,
    BODY,
    VERSION,
    CHUNK,
    SEGMENT,
    SNAPSHOT,
    CHAIN_GENESIS,
    CHAIN,
];

/// `label ‖ 0x00 ‖ parts[0] ‖ parts[1] ‖ …`. Parts are fixed-length or the last field.
pub fn tagged(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(label.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    out.extend_from_slice(label);
    out.push(0);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync` → 2 passed; clippy clean (unused dependencies are fine until later tasks use them).

- [ ] **Step 5: Commit.**

```bash
git add Cargo.toml Cargo.lock crates/keyorra-sync
git commit -m "sync: new keyorra-sync crate with errors and domain-separation labels"
```

### Task 3: Canonical CBOR

**Files:** Create `crates/keyorra-sync/src/cbor.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Deterministic encoding and strict decoding of the subset the formats use; typed accessors and `fields()` (a map with exactly the named text keys) keep the struct codecs in later tasks short.

- [ ] **Step 1: Failing tests.** Add `pub mod cbor;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/cbor.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn hex(b: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(b)
    }

    fn unhex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn uints(range: std::ops::RangeInclusive<u64>) -> Value {
        Value::Array(range.map(Value::Uint).collect())
    }

    /// RFC 8949 Appendix A, the examples inside our subset.
    #[test]
    fn rfc8949_appendix_a_examples() {
        let cases: Vec<(Value, &str)> = vec![
            (Value::Uint(0), "00"),
            (Value::Uint(23), "17"),
            (Value::Uint(24), "1818"),
            (Value::Uint(100), "1864"),
            (Value::Uint(1000), "1903e8"),
            (Value::Uint(1_000_000), "1a000f4240"),
            (Value::Uint(1_000_000_000_000), "1b000000e8d4a51000"),
            (Value::Uint(u64::MAX), "1bffffffffffffffff"),
            (Value::Bool(false), "f4"),
            (Value::Bool(true), "f5"),
            (Value::Null, "f6"),
            (Value::bytes([]), "40"),
            (Value::bytes([1, 2, 3, 4]), "4401020304"),
            (Value::text(""), "60"),
            (Value::text("a"), "6161"),
            (Value::text("IETF"), "6449455446"),
            (Value::text("\u{fc}"), "62c3bc"),
            (Value::Array(vec![]), "80"),
            (uints(1..=3), "83010203"),
            (
                Value::Array(vec![Value::Uint(1), uints(2..=3), uints(4..=5)]),
                "8301820203820405",
            ),
            (
                uints(1..=25),
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ),
            (Value::Map(vec![]), "a0"),
            (
                Value::map(vec![("a", Value::Uint(1)), ("b", uints(2..=3))]),
                "a26161016162820203",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(hex(&encode(&value)), expected, "{value:?}");
            assert_eq!(decode(&unhex(expected)).unwrap(), value, "{expected}");
        }
    }

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes() {
        // Shorter text keys sort first because the length is part of the encoding.
        let value = Value::map(vec![
            ("aa", Value::Uint(3)),
            ("b", Value::Uint(2)),
            ("a", Value::Uint(1)),
        ]);
        assert_eq!(hex(&encode(&value)), "a361610161620262616103");
    }

    #[test]
    #[should_panic(expected = "duplicate CBOR map key")]
    fn duplicate_keys_are_a_programming_error() {
        encode(&Value::map(vec![("a", Value::Null), ("a", Value::Null)]));
    }

    #[test]
    fn decoding_rejects_everything_non_canonical() {
        for bad in [
            "1817",       // 23 in two bytes
            "190017",     // 23 in three bytes
            "1a000000ff", // 255 in five bytes
            "1b00000000ffffffff",
            "5f4100ff",           // indefinite byte string
            "9f01ff",             // indefinite array
            "20",                 // negative integer
            "c100",               // tag
            "f93c00",             // half float
            "f7",                 // undefined
            "a2616201616101",     // keys out of order
            "a2616101616102",     // duplicate key
            "62c328",             // invalid UTF-8
            "4401",               // truncated
            "0000",               // trailing byte
            "9bffffffffffffffff", // absurd length
        ] {
            assert!(
                matches!(decode(&unhex(bad)), Err(Error::Malformed(_))),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn decoding_limits_nesting() {
        let mut bytes = vec![0x81; 40];
        bytes.push(0x00);
        assert!(matches!(decode(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn fields_require_exactly_the_named_keys() {
        let v = Value::map(vec![("a", Value::Uint(1)), ("b", Value::Null)]);
        let f = v.fields(&["a", "b"]).unwrap();
        assert_eq!(f.get("a").unwrap(), &Value::Uint(1));
        assert!(v.fields(&["a"]).is_err());
        assert!(v.fields(&["a", "c"]).is_err());
        assert!(Value::Uint(1).fields(&[]).is_err());
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync cbor::` → does not compile (`Value`, `encode`, `decode` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/cbor.rs`:

```rust
//! Deterministic CBOR (RFC 8949 §4.2.1) for the small subset the sync formats use:
//! unsigned integers, byte strings, text strings, arrays, maps, booleans and null.
//!
//! Encoding is canonical: shortest heads, definite lengths, map entries sorted by the bytes of
//! their encoded keys. Decoding is strict and accepts *only* canonical input, so every value
//! has exactly one encoding and hashing re-encoded data equals hashing the received bytes.
//! Not supported on purpose: negative integers, floats, tags, indefinite lengths.

use crate::error::{malformed, Result};

const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in any order; [`encode`] sorts them. Duplicate keys are a programming error.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn bytes(b: impl AsRef<[u8]>) -> Value {
        Value::Bytes(b.as_ref().to_vec())
    }

    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    /// A map with text keys, the shape every sync structure uses.
    pub fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::text(k), v))
                .collect(),
        )
    }

    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(malformed("expected unsigned integer")),
        }
    }

    pub fn as_u32(&self) -> Result<u32> {
        u32::try_from(self.as_uint()?).map_err(|_| malformed("integer exceeds u32"))
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(malformed("expected byte string")),
        }
    }

    pub fn as_array_of<const N: usize>(&self) -> Result<[u8; N]> {
        self.as_bytes()?
            .try_into()
            .map_err(|_| malformed(format!("expected {N} bytes")))
    }

    pub fn as_text(&self) -> Result<&str> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(malformed("expected text")),
        }
    }

    pub fn as_bool(&self) -> Result<bool> {
        match self {
            Value::Bool(b) => Ok(*b),
            _ => Err(malformed("expected bool")),
        }
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(malformed("expected array")),
        }
    }

    pub fn as_map(&self) -> Result<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err(malformed("expected map")),
        }
    }

    /// A text-keyed map that must have exactly the keys `names` (in any order).
    pub fn fields(&self, names: &[&str]) -> Result<Fields<'_>> {
        let map = self.as_map()?;
        if map.len() != names.len() {
            return Err(malformed(format!("expected {} fields", names.len())));
        }
        for (k, _) in map {
            let k = k.as_text()?;
            if !names.contains(&k) {
                return Err(malformed(format!("unexpected field {k}")));
            }
        }
        Ok(Fields(map))
    }
}

/// Lookup into a map checked by [`Value::fields`].
pub struct Fields<'a>(&'a [(Value, Value)]);

impl<'a> Fields<'a> {
    pub fn get(&self, name: &str) -> Result<&'a Value> {
        self.0
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
            .ok_or_else(|| malformed(format!("missing field {name}")))
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => head(0, *n, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                write(item, out);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in encoded.windows(2) {
                assert!(pair[0].0 != pair[1].0, "duplicate CBOR map key");
            }
            head(5, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                write(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

/// Decodes exactly one canonical value; trailing bytes are an error.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.value(0)?;
    if reader.pos != bytes.len() {
        return Err(malformed("trailing bytes after CBOR value"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| malformed("truncated CBOR"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn head(&mut self) -> Result<(u8, u8, u64)> {
        let first = self.take(1)?[0];
        let (major, info) = (first >> 5, first & 0x1f);
        let n = match info {
            0..=23 => info as u64,
            24 => {
                let n = self.take(1)?[0] as u64;
                if n < 24 {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            25 => {
                let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if n <= 0xff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            26 => {
                let n = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if n <= 0xffff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            27 => {
                let n = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if n <= 0xffff_ffff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            _ => return Err(malformed("indefinite or reserved CBOR length")),
        };
        Ok((major, info, n))
    }

    fn len(&self, n: u64) -> Result<usize> {
        // Every element takes at least one byte, so a length beyond the input is a lie.
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.bytes.len() - self.pos)
            .ok_or_else(|| malformed("CBOR length exceeds input"))
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(malformed("CBOR nested too deeply"));
        }
        let (major, info, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            2 => {
                let len = self.len(n)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.len(n)?;
                let raw = self.take(len)?.to_vec();
                String::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| malformed("CBOR text is not UTF-8"))
            }
            4 => {
                let len = self.len(n)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.len(n)?;
                let mut entries = Vec::with_capacity(len);
                let mut last_key: Option<&[u8]> = None;
                for _ in 0..len {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = &self.bytes[start..self.pos];
                    if last_key.is_some_and(|last| last >= key_bytes) {
                        return Err(malformed("CBOR map keys not in canonical order"));
                    }
                    last_key = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(malformed("unsupported CBOR simple value or float")),
            },
            _ => Err(malformed("unsupported CBOR major type")),
        }
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync cbor::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/cbor.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: strict canonical CBOR codec"
```

### Task 4: Padmé padding

**Files:** Create `crates/keyorra-sync/src/pad.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Everything that leaves the device in bulk (segments, snapshots, chunks) is padded so sizes leak only O(log log L) bits.

- [ ] **Step 1: Failing tests.** Add `pub mod pad;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/pad.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn padme_matches_hand_computed_values() {
        // L = 1025: E = 10, S = 4, mask = 2^6 - 1 → 1088.
        for (len, expected) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (9, 10),
            (100, 104),
            (1025, 1088),
            (4_194_305, 4_325_376),
            (1 << 20, 1 << 20),
        ] {
            assert_eq!(padme(len), expected, "padme({len})");
        }
    }

    #[test]
    fn padme_overhead_is_at_most_12_percent_and_monotonic() {
        let mut prev = 0;
        for len in 2..200_000u64 {
            let p = padme(len);
            assert!(p >= len && p >= prev);
            assert!((p - len) * 100 <= len * 12, "len {len} → {p}");
            prev = p;
        }
    }

    #[test]
    fn small_inputs_pad_to_the_minimum() {
        assert_eq!(pad(b"").len(), MIN_PADDED);
        assert_eq!(pad(&[1; 1023]).len(), MIN_PADDED);
        assert_eq!(pad(&[1; 1024]).len(), padme(1025) as usize);
    }

    #[test]
    fn round_trips_including_trailing_zeros_in_the_data() {
        for data in [&b""[..], b"x", &[0u8; 10], &[0x80; 5], &[7u8; 5000]] {
            assert_eq!(unpad(&pad(data)).unwrap(), data);
        }
    }

    #[test]
    fn rejects_foreign_padding() {
        let mut p = pad(b"abc");
        p[3] = 0x81;
        assert!(matches!(unpad(&p), Err(Error::Malformed(_))));
        assert!(matches!(unpad(&[0u8; 1024]), Err(Error::Malformed(_))));
        let mut short = pad(b"abc");
        short.truncate(1000);
        assert!(matches!(unpad(&short), Err(Error::Malformed(_))));
        let mut long = pad(b"abc");
        long.push(0);
        assert!(matches!(unpad(&long), Err(Error::Malformed(_))));
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync pad::` → does not compile (`padme`, `pad`, `unpad` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/pad.rs`:

```rust
//! Length hiding: `data ‖ 0x80 ‖ 0x00…` up to a Padmé length (Nikitin et al., "Reducing
//! Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019), never
//! below [`MIN_PADDED`]. Padmé leaks O(log log L) bits of the length and adds at most ~12%.

use crate::error::{malformed, Result};

pub const MIN_PADDED: usize = 1024;
const MARKER: u8 = 0x80;

/// The Padmé length for `len` (unchanged below 2).
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - u64::from(len.leading_zeros()); // floor(log2 len)
    let s = 64 - u64::from(e.leading_zeros()); // floor(log2 e) + 1
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// Total padded size for `content_len` bytes of content (the marker byte included).
pub fn padded_len(content_len: usize) -> usize {
    let needed = content_len + 1;
    (padme(needed as u64) as usize).max(MIN_PADDED)
}

pub fn pad(data: &[u8]) -> Vec<u8> {
    let total = padded_len(data.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(data);
    out.push(MARKER);
    out.resize(total, 0);
    out
}

/// Inverse of [`pad`]; rejects any other padding (wrong marker, wrong total length).
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let marker = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| malformed("padding"))?;
    if padded[marker] != MARKER || padded_len(marker) != padded.len() {
        return Err(malformed("padding"));
    }
    Ok(&padded[..marker])
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync pad::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/pad.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: Padmé padding with a 1 KiB floor"
```

### Task 5: The Secret Key

**Files:** Create `crates/keyorra-sync/src/secret_key.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The expected display string in the first test was cross-checked with an independent Python encoder.

- [ ] **Step 1: Failing tests.** Add `pub mod secret_key;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/secret_key.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn sample() -> SecretKey {
        SecretKey::from_bytes(*b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    }

    #[test]
    fn display_has_the_documented_shape() {
        // Cross-checked with an independent Python encoder.
        let shown = sample().display("A3K7");
        assert_eq!(&*shown, "A3K7-00041-06105-0R3GG-28A1C-60T3G-F6");
        let groups: Vec<_> = shown.split('-').map(str::len).collect();
        assert_eq!(groups, [4, 5, 5, 5, 5, 5, 2]);
    }

    #[test]
    fn parse_round_trips_and_forgives_case_and_lookalikes() {
        let shown = sample().display("A3K7");
        let (id, key) = SecretKey::parse(&shown).unwrap();
        assert_eq!(id, "A3K7");
        assert_eq!(key.as_bytes(), sample().as_bytes());
        let sloppy = shown.to_lowercase().replace('1', "l").replace('0', "o");
        let (_, key) = SecretKey::parse(&sloppy).unwrap();
        assert_eq!(key.as_bytes(), sample().as_bytes());
    }

    #[test]
    fn parse_rejects_typos() {
        let shown = sample().display("A3K7").to_string();
        let mut typo = shown.clone().into_bytes();
        typo[6] = if typo[6] == b'2' { b'3' } else { b'2' };
        let typo = String::from_utf8(typo).unwrap();
        for bad in [
            &typo[..],
            &shown[..shown.len() - 1],
            "A3K7",
            &format!("{shown}0"),
        ] {
            assert!(
                matches!(SecretKey::parse(bad), Err(Error::Malformed(_))),
                "{bad}"
            );
        }
        // A first digit above 7 would need more than 128 bits.
        let too_big = format!("A3K7-8{}", &shown[6..]);
        assert!(SecretKey::parse(&too_big).is_err());
    }

    #[test]
    fn extreme_keys_round_trip() {
        for bytes in [[0u8; 16], [0xff; 16]] {
            let shown = SecretKey::from_bytes(bytes).display("0000");
            assert_eq!(SecretKey::parse(&shown).unwrap().1.as_bytes(), &bytes);
        }
    }

    #[test]
    fn generate_gives_fresh_keys_and_ids_from_the_alphabet() {
        let mut rng = rand::rngs::OsRng;
        let (a, id) = SecretKey::generate(&mut rng);
        let (b, _) = SecretKey::generate(&mut rng);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(id.len(), 4);
        assert!(id.bytes().all(|c| DIGITS.contains(&c)));
    }

    #[test]
    fn debug_hides_the_key() {
        assert_eq!(format!("{:?}", sample()), "SecretKey(..)");
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync secret_key::` → does not compile (`SecretKey` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/secret_key.rs`:

```rust
//! The Secret Key: 128 random bits mixed into the key that protects the synced header.
//!
//! Shown as `ID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XC`: a 4-character id (20 random bits,
//! independent of the key, safe to publish), 26 Crockford base32 digits carrying the 128 key
//! bits (big-endian, the top 2 bits of the first digit zero), and one Crockford check
//! character (the key as an integer mod 37). Parsing ignores case and hyphens and reads
//! `I`/`L` as `1` and `O` as `0`.

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{malformed, Result};

const DIGITS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";
const ID_LEN: usize = 4;
const KEY_DIGITS: usize = 26;

pub struct SecretKey(Zeroizing<[u8; 16]>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A fresh key and its independent public id.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> (SecretKey, String) {
        let mut bytes = Zeroizing::new([0u8; 16]);
        rng.fill_bytes(&mut bytes[..]);
        let id = (0..ID_LEN)
            .map(|_| DIGITS[(rng.next_u32() & 31) as usize] as char)
            .collect();
        (SecretKey(bytes), id)
    }

    /// The human form, e.g. for the Emergency Kit.
    pub fn display(&self, id: &str) -> Zeroizing<String> {
        let value = u128::from_be_bytes(*self.0);
        let mut chars: Vec<u8> = (0..KEY_DIGITS)
            .map(|i| DIGITS[((value >> (5 * (KEY_DIGITS - 1 - i))) & 31) as usize])
            .collect();
        chars.push(CHECK[(value % 37) as usize]);
        let mut out = Zeroizing::new(id.to_owned());
        for group in chars.chunks(5) {
            out.push('-');
            out.push_str(std::str::from_utf8(group).expect("ASCII"));
        }
        chars.iter_mut().for_each(|c| *c = 0);
        out
    }

    /// Parses [`display`](Self::display) output; returns the id and the key.
    pub fn parse(text: &str) -> Result<(String, SecretKey)> {
        let chars: Zeroizing<Vec<u8>> = Zeroizing::new(
            text.bytes()
                .filter(|&b| b != b'-' && !b.is_ascii_whitespace())
                .map(|b| match b.to_ascii_uppercase() {
                    b'I' | b'L' => b'1',
                    b'O' => b'0',
                    other => other,
                })
                .collect(),
        );
        if chars.len() != ID_LEN + KEY_DIGITS + 1 {
            return Err(malformed("secret key length"));
        }
        let digit = |c: u8| {
            DIGITS
                .iter()
                .position(|&d| d == c)
                .ok_or_else(|| malformed("secret key character"))
        };
        for &c in &chars[..ID_LEN] {
            digit(c)?;
        }
        let mut value: u128 = 0;
        for &c in &chars[ID_LEN..ID_LEN + KEY_DIGITS] {
            let d = digit(c)? as u128;
            value = value
                .checked_mul(32)
                .and_then(|v| v.checked_add(d))
                .ok_or_else(|| malformed("secret key out of range"))?;
        }
        if chars[ID_LEN + KEY_DIGITS] != CHECK[(value % 37) as usize] {
            return Err(malformed("secret key check character"));
        }
        let id = String::from_utf8(chars[..ID_LEN].to_vec()).expect("ASCII");
        Ok((id, SecretKey::from_bytes(value.to_be_bytes())))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync secret_key::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/secret_key.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: Secret Key generation, display and parsing"
```

### Task 6: Key derivation

**Files:** Create `crates/keyorra-sync/src/keys.rs`; modify `crates/keyorra-sync/src/lib.rs`.

`KEK_sync` and `AUTH` from master password + Secret Key + account id; `K_seg` from the account key; bounds for KDF parameters that come from a synced header.

- [ ] **Step 1: Failing tests.** Add `pub mod keys;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/keys.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;
    const SALT: [u8; 16] = [0x20; 16];
    const ACCOUNT: AccountId = [0x10; 16];

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 16])
    }

    fn keys(pw: &str, salt: [u8; 16], secret: u8, account: AccountId) -> SyncKeys {
        derive_sync_keys(pw, &salt, FAST, &sk(secret), &account).unwrap()
    }

    /// RFC 5869 test case 1: pins the HKDF dependency.
    #[test]
    fn hkdf_sha256_rfc5869_case_1() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&hex("000102030405060708090a0b0c")), &[0x0b; 22]);
        let mut okm = [0u8; 42];
        hk.expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn same_inputs_same_keys_and_kek_differs_from_auth() {
        let a = keys("pw", SALT, 1, ACCOUNT);
        let b = keys("pw", SALT, 1, ACCOUNT);
        assert_eq!(a.kek.as_bytes(), b.kek.as_bytes());
        assert_eq!(a.auth.as_bytes(), b.auth.as_bytes());
        assert_ne!(a.kek.as_bytes(), a.auth.as_bytes());
    }

    #[test]
    fn every_input_matters() {
        let base = keys("pw", SALT, 1, ACCOUNT);
        for other in [
            keys("pw2", SALT, 1, ACCOUNT),
            keys("pw", [0x21; 16], 1, ACCOUNT),
            keys("pw", SALT, 2, ACCOUNT),
            keys("pw", SALT, 1, [0x11; 16]),
        ] {
            assert_ne!(base.kek.as_bytes(), other.kek.as_bytes());
            assert_ne!(base.auth.as_bytes(), other.auth.as_bytes());
        }
    }

    #[test]
    fn remote_kdf_bounds_are_checked_before_argon2() {
        let start = std::time::Instant::now();
        for kdf in [
            KdfParams {
                m_kib: MAX_REMOTE_M_KIB + 1,
                ..FAST
            },
            KdfParams {
                t: MAX_REMOTE_T + 1,
                ..FAST
            },
            KdfParams {
                p: MAX_REMOTE_P + 1,
                ..FAST
            },
            KdfParams { t: 0, ..FAST },
        ] {
            let r = derive_sync_keys("pw", &SALT, kdf, &sk(1), &ACCOUNT);
            assert!(
                matches!(r, Err(Error::Malformed(_) | Error::Core(_))),
                "{kdf:?}"
            );
        }
        assert!(start.elapsed().as_secs() < 2);
        assert!(check_remote_kdf(&KdfParams::DEFAULT).is_ok());
    }

    #[test]
    fn segment_key_depends_on_account_key_and_id() {
        let ak = Key::from_bytes([0x30; 32]);
        let base = segment_key(&ak, &ACCOUNT);
        assert_eq!(base.as_bytes(), segment_key(&ak, &ACCOUNT).as_bytes());
        assert_ne!(
            base.as_bytes(),
            segment_key(&Key::from_bytes([0x31; 32]), &ACCOUNT).as_bytes()
        );
        assert_ne!(base.as_bytes(), segment_key(&ak, &[0x11; 16]).as_bytes());
        assert_ne!(base.as_bytes(), ak.as_bytes());
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync keys::` → does not compile (`derive_sync_keys`, `segment_key`, `check_remote_kdf` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/keys.rs`:

````rust
//! Keys for sync, derived from the master password, the Secret Key and the account key.
//!
//! ```text
//! U        = Argon2id(master password, header salt, header kdf)     (keyorra-core derive_kek)
//! M        = HKDF-Extract(salt = Secret Key, ikm = U)
//! KEK_sync = HKDF-Expand(M, "keyorra/sync/v1/kek\0" ‖ account_id, 32)
//! AUTH     = HKDF-Expand(M, "keyorra/sync/v1/server-auth\0" ‖ account_id, 32)
//! K_seg    = HKDF-SHA256(ikm = AK, salt = account_id, info = "keyorra/sync/v1/segment-key\0")
//! ```

use hkdf::Hkdf;
use keyorra_core::crypto::{derive_kek, KdfParams, Key};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{malformed, Result};
use crate::labels::{self, tagged};
use crate::secret_key::SecretKey;
use crate::AccountId;

/// Bounds for KDF parameters read from a synced header, checked before running Argon2:
/// stricter than the local bounds, because anyone with write access to the folder or server
/// can put parameters there.
pub const MAX_REMOTE_M_KIB: u32 = 1024 * 1024;
pub const MAX_REMOTE_T: u32 = 10;
pub const MAX_REMOTE_P: u32 = 4;

pub fn check_remote_kdf(kdf: &KdfParams) -> Result<()> {
    kdf.validate()?;
    if kdf.m_kib > MAX_REMOTE_M_KIB || kdf.t > MAX_REMOTE_T || kdf.p > MAX_REMOTE_P {
        return Err(malformed(
            "kdf parameters out of bounds for a synced header",
        ));
    }
    Ok(())
}

/// What the master password and the Secret Key unlock for one account.
pub struct SyncKeys {
    /// Unwraps the account key from the synced header.
    pub kek: Key,
    /// Proves knowledge of password and Secret Key to a sync server (phase B).
    pub auth: Key,
}

pub fn derive_sync_keys(
    password: &str,
    salt: &[u8; 16],
    kdf: KdfParams,
    secret_key: &SecretKey,
    account_id: &AccountId,
) -> Result<SyncKeys> {
    check_remote_kdf(&kdf)?;
    let u = derive_kek(password, salt, kdf)?;
    let hk = Hkdf::<Sha256>::new(Some(secret_key.as_bytes()), u.as_bytes());
    Ok(SyncKeys {
        kek: expand(&hk, &tagged(labels::KEK, &[account_id])),
        auth: expand(&hk, &tagged(labels::SERVER_AUTH, &[account_id])),
    })
}

/// The key that seals segments and snapshots of one account.
pub fn segment_key(account_key: &Key, account_id: &AccountId) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(account_id), account_key.as_bytes());
    expand(&hk, &tagged(labels::SEGMENT_KEY, &[]))
}

fn expand(hk: &Hkdf<Sha256>, info: &[u8]) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key::from_bytes(*out)
}
````

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync keys::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/keys.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: KEK_sync, AUTH and segment key derivation"
```

### Task 7: Account header and header file

**Files:** Create `crates/keyorra-sync/src/header.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The header a joining device reads before it has any key, the account key wrapped under `KEK_sync` (bound to account, epoch and generation), and the signed header file. Which header counts is A1c.

- [ ] **Step 1: Failing tests.** Add `pub mod header;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/header.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = [0x10; 16];
    const DEVICE: DeviceId = [0x40; 16];
    const SALT: [u8; 16] = [0x20; 16];

    fn sk() -> SecretKey {
        SecretKey::from_bytes([0x01; 16])
    }

    fn header_for(password: &str, account_key: &Key, epoch: u32) -> Header {
        let kdf = KdfParams::INSECURE_FAST;
        let keys = derive_sync_keys(password, &SALT, kdf, &sk(), &ACCOUNT).unwrap();
        Header {
            account_id: ACCOUNT,
            epoch,
            generation: 1,
            root_device: DEVICE,
            kdf,
            salt: SALT,
            secret_key_id: "A3K7".into(),
            wrapped_account_key: wrap_account_key(
                &keys.kek,
                account_key,
                &ACCOUNT,
                epoch,
                1,
                &[0x50; NONCE_LEN],
            ),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    /// RFC 8032 §7.1 test 1: pins the Ed25519 dependency.
    #[test]
    fn ed25519_rfc8032_test_1() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let key = SigningKey::from_bytes(
            &hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(key.verifying_key().as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(&key.sign(b"").to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn unlock_returns_the_account_key() {
        let ak = Key::from_bytes([0x30; 32]);
        let (unlocked, _) = header_for("pw", &ak, 1).unlock("pw", &sk()).unwrap();
        assert_eq!(unlocked.as_bytes(), ak.as_bytes());
    }

    #[test]
    fn wrong_password_or_secret_key_is_wrong_password() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        assert!(matches!(h.unlock("nope", &sk()), Err(Error::WrongPassword)));
        let other = SecretKey::from_bytes([0x02; 16]);
        assert!(matches!(h.unlock("pw", &other), Err(Error::WrongPassword)));
    }

    #[test]
    fn wrapped_key_is_bound_to_epoch_generation_and_account() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        for tampered in [
            Header {
                epoch: 2,
                ..h.clone()
            },
            Header {
                generation: 2,
                ..h.clone()
            },
        ] {
            assert!(matches!(
                tampered.unlock("pw", &sk()),
                Err(Error::WrongPassword)
            ));
        }
    }

    #[test]
    fn file_round_trips_and_verifies() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 3);
        let file = HeaderFile::sign(h, DEVICE, &signing_key());
        let decoded = HeaderFile::decode(&file.encode()).unwrap();
        assert_eq!(decoded, file);
        decoded.verify(&signing_key().verifying_key()).unwrap();
        assert_eq!(
            decoded.file_name(),
            "00000003-40404040404040404040404040404040.hdr"
        );
    }

    #[test]
    fn signature_fails_for_another_key_or_a_changed_header() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let file = HeaderFile::sign(h, DEVICE, &signing_key());
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(file.verify(&other), Err(Error::BadSignature)));
        let mut changed = file.clone();
        changed.header.epoch = 9;
        assert!(matches!(
            changed.verify(&signing_key().verifying_key()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn newer_format_is_unsupported_and_junk_is_malformed() {
        let h = header_for("pw", &Key::from_bytes([0x30; 32]), 1);
        let mut value = h.to_value();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if k == &Value::text("keyorra_sync") {
                    *v = Value::Uint(2);
                }
            }
        }
        assert!(matches!(
            Header::from_value(&value),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            HeaderFile::decode(b"\xa0"),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            HeaderFile::decode(b"junk"),
            Err(Error::Malformed(_))
        ));
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync header::` → does not compile (`Header`, `HeaderFile`, `wrap_account_key` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/header.rs`:

```rust
//! The synced account header: what a joining device needs before it has any key.
//!
//! Stored as a standalone, signed file per epoch (`<epoch:08x>-<author hex>.hdr`). The file
//! counts only together with a matching signed log entry (defined in plan A1c).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, KdfParams, Key, NONCE_LEN};

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::keys::{derive_sync_keys, SyncKeys};
use crate::labels::{self, tagged};
use crate::secret_key::SecretKey;
use crate::{AccountId, DeviceId};

pub const SYNC_FORMAT: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub account_id: AccountId,
    pub epoch: u32,
    pub generation: u32,
    pub root_device: DeviceId,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub secret_key_id: String,
    pub wrapped_account_key: Vec<u8>,
}

const FIELDS: [&str; 9] = [
    "keyorra_sync",
    "account_id",
    "epoch",
    "generation",
    "root_device",
    "kdf",
    "salt",
    "secret_key_id",
    "wrapped_account_key",
];

fn account_key_aad(account_id: &AccountId, epoch: u32, generation: u32) -> Vec<u8> {
    tagged(
        labels::ACCOUNT_KEY,
        &[account_id, &epoch.to_be_bytes(), &generation.to_be_bytes()],
    )
}

/// Seals the account key under `KEK_sync`, bound to account, epoch and generation.
pub fn wrap_account_key(
    kek: &Key,
    account_key: &Key,
    account_id: &AccountId,
    epoch: u32,
    generation: u32,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    crypto::seal_with_nonce(
        kek,
        nonce,
        account_key.as_bytes(),
        &account_key_aad(account_id, epoch, generation),
    )
}

impl Header {
    /// Derives the sync keys from password and Secret Key and unwraps the account key.
    /// A wrong password or Secret Key (or a tampered header) is `WrongPassword`.
    pub fn unlock(&self, password: &str, secret_key: &SecretKey) -> Result<(Key, SyncKeys)> {
        let keys = derive_sync_keys(password, &self.salt, self.kdf, secret_key, &self.account_id)?;
        let account_key = self.unwrap_account_key(&keys.kek)?;
        Ok((account_key, keys))
    }

    pub fn unwrap_account_key(&self, kek: &Key) -> Result<Key> {
        let raw = crypto::open(
            kek,
            &self.wrapped_account_key,
            &account_key_aad(&self.account_id, self.epoch, self.generation),
        )
        .map_err(|_| Error::WrongPassword)?;
        Ok(Key::from_slice(&raw)?)
    }

    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("keyorra_sync", Value::Uint(SYNC_FORMAT)),
            ("account_id", Value::bytes(self.account_id)),
            ("epoch", Value::Uint(self.epoch.into())),
            ("generation", Value::Uint(self.generation.into())),
            ("root_device", Value::bytes(self.root_device)),
            (
                "kdf",
                Value::map(vec![
                    ("m_kib", Value::Uint(self.kdf.m_kib.into())),
                    ("t", Value::Uint(self.kdf.t.into())),
                    ("p", Value::Uint(self.kdf.p.into())),
                ]),
            ),
            ("salt", Value::bytes(self.salt)),
            ("secret_key_id", Value::text(&self.secret_key_id)),
            (
                "wrapped_account_key",
                Value::bytes(&self.wrapped_account_key),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Header> {
        let format = value
            .as_map()?
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "keyorra_sync"))
            .ok_or_else(|| malformed("header without keyorra_sync"))?
            .1
            .as_uint()?;
        if format != SYNC_FORMAT {
            return Err(Error::Unsupported(format!("sync header format {format}")));
        }
        let f = value.fields(&FIELDS)?;
        let kdf = f.get("kdf")?.fields(&["m_kib", "t", "p"])?;
        let secret_key_id = f.get("secret_key_id")?.as_text()?.to_owned();
        if secret_key_id.len() != 4 || !secret_key_id.is_ascii() {
            return Err(malformed("secret key id"));
        }
        Ok(Header {
            account_id: f.get("account_id")?.as_array_of()?,
            epoch: f.get("epoch")?.as_u32()?,
            generation: f.get("generation")?.as_u32()?,
            root_device: f.get("root_device")?.as_array_of()?,
            kdf: KdfParams {
                m_kib: kdf.get("m_kib")?.as_u32()?,
                t: kdf.get("t")?.as_u32()?,
                p: kdf.get("p")?.as_u32()?,
            },
            salt: f.get("salt")?.as_array_of()?,
            secret_key_id,
            wrapped_account_key: f.get("wrapped_account_key")?.as_bytes()?.to_vec(),
        })
    }
}

/// A header signed by the device that wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFile {
    pub header: Header,
    pub author: DeviceId,
    pub sig: [u8; 64],
}

fn signed_message(header: &Header) -> Vec<u8> {
    tagged(labels::HEADER, &[&cbor::encode(&header.to_value())])
}

impl HeaderFile {
    pub fn sign(header: Header, author: DeviceId, key: &SigningKey) -> HeaderFile {
        let sig = key.sign(&signed_message(&header)).to_bytes();
        HeaderFile {
            header,
            author,
            sig,
        }
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        key.verify_strict(
            &signed_message(&self.header),
            &Signature::from_bytes(&self.sig),
        )
        .map_err(|_| Error::BadSignature)
    }

    pub fn file_name(&self) -> String {
        format!(
            "{:08x}-{}.hdr",
            self.header.epoch,
            data_encoding::HEXLOWER.encode(&self.author)
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::map(vec![
            ("header", self.header.to_value()),
            ("author", Value::bytes(self.author)),
            ("sig", Value::bytes(self.sig)),
        ]))
    }

    pub fn decode(bytes: &[u8]) -> Result<HeaderFile> {
        let value = cbor::decode(bytes)?;
        let f = value.fields(&["header", "author", "sig"])?;
        Ok(HeaderFile {
            header: Header::from_value(f.get("header")?)?,
            author: f.get("author")?.as_array_of()?,
            sig: f.get("sig")?.as_array_of()?,
        })
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync header::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/header.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: account header, wrapped account key and signed header file"
```

### Task 8: Envelopes, versions and sealed bodies

**Files:** Create `crates/keyorra-sync/src/envelope.rs`; modify `crates/keyorra-sync/src/lib.rs`.

One record version as it travels inside a segment. The body's associated data binds account, kind, ids, schema and the whole version.

- [ ] **Step 1: Failing tests.** Add `pub mod envelope;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/envelope.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = [0x10; 16];
    const A: DeviceId = [0x40; 16];
    const B: DeviceId = [0x41; 16];

    fn version() -> Version {
        Version {
            vector: BTreeMap::from([(A, 2), (B, 1)]),
            hlc: 0x0192_0000_0000_0001,
            author: A,
        }
    }

    fn item() -> Envelope {
        let mut env = Envelope {
            kind: RecordKind::Item,
            record_id: Uuid::from_bytes([0x60; 16]),
            vault_id: Some(Uuid::from_bytes([0x61; 16])),
            schema: 1,
            version: version(),
            tombstone: false,
            body: None,
        };
        env.seal_body(
            &Key::from_bytes([0x70; 32]),
            &ACCOUNT,
            b"{\"title\":\"x\"}",
            &[0x51; NONCE_LEN],
        );
        env
    }

    #[test]
    fn round_trips_through_cbor() {
        let env = item();
        let bytes = cbor::encode(&env.to_value());
        assert_eq!(
            Envelope::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
            env
        );
    }

    #[test]
    fn body_opens_with_the_right_key_and_account() {
        let env = item();
        let key = Key::from_bytes([0x70; 32]);
        assert_eq!(
            &*env.open_body(&key, &ACCOUNT).unwrap(),
            b"{\"title\":\"x\"}"
        );
        assert!(matches!(
            env.open_body(&Key::from_bytes([0x71; 32]), &ACCOUNT),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            env.open_body(&key, &[0x11; 16]),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn body_cannot_move_to_another_record_vault_schema_or_version() {
        let key = Key::from_bytes([0x70; 32]);
        let env = item();
        let mut newer = version();
        newer.vector.insert(A, 3);
        for moved in [
            Envelope {
                record_id: Uuid::from_bytes([0x62; 16]),
                ..env.clone()
            },
            Envelope {
                vault_id: Some(Uuid::from_bytes([0x63; 16])),
                ..env.clone()
            },
            Envelope {
                schema: 2,
                ..env.clone()
            },
            Envelope {
                kind: RecordKind::Attachment,
                ..env.clone()
            },
            Envelope {
                version: newer,
                ..env.clone()
            },
            Envelope {
                version: Version {
                    hlc: 7,
                    ..version()
                },
                ..env.clone()
            },
            Envelope {
                version: Version {
                    author: B,
                    ..version()
                },
                ..env.clone()
            },
        ] {
            assert!(
                matches!(moved.open_body(&key, &ACCOUNT), Err(Error::Decrypt)),
                "{moved:?}"
            );
        }
    }

    #[test]
    fn version_hash_depends_on_every_component() {
        let id = Uuid::from_bytes([0x60; 16]);
        let base = version_hash(RecordKind::Item, id, &version());
        assert_ne!(base, version_hash(RecordKind::Vault, id, &version()));
        assert_ne!(
            base,
            version_hash(RecordKind::Item, Uuid::from_bytes([0x62; 16]), &version())
        );
        assert_ne!(
            base,
            version_hash(
                RecordKind::Item,
                id,
                &Version {
                    hlc: 1,
                    ..version()
                }
            )
        );
        assert_ne!(
            base,
            version_hash(
                RecordKind::Item,
                id,
                &Version {
                    author: B,
                    ..version()
                }
            )
        );
        let mut v = version();
        v.vector.insert(B, 2);
        assert_ne!(base, version_hash(RecordKind::Item, id, &v));
    }

    #[test]
    fn shape_rules() {
        let tomb_with_body = Envelope {
            tombstone: true,
            ..item()
        };
        assert!(tomb_with_body.check().is_err());
        let no_body = Envelope {
            body: None,
            ..item()
        };
        assert!(no_body.check().is_err());
        let no_vault = Envelope {
            vault_id: None,
            ..item()
        };
        assert!(no_vault.check().is_err());
        let tomb = Envelope {
            tombstone: true,
            body: None,
            ..item()
        };
        tomb.check().unwrap();
        let vault = Envelope {
            kind: RecordKind::Vault,
            vault_id: None,
            ..item()
        };
        vault.check().unwrap();
        // from_value applies the same rules.
        assert!(Envelope::from_value(&no_body.to_value()).is_err());
    }

    #[test]
    fn newer_format_or_kind_is_unsupported() {
        let mut value = item().to_value();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if k == &Value::text("format") {
                    *v = Value::Uint(2);
                }
            }
        }
        assert!(matches!(
            Envelope::from_value(&value),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            RecordKind::parse("passkey"),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn zero_vector_entries_are_rejected() {
        let mut v = version().to_value();
        if let Value::Map(entries) = &mut v {
            entries[0].1 = Value::Map(vec![(Value::bytes(A), Value::Uint(0))]);
        }
        assert!(Version::from_value(&v).is_err());
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync envelope::` → does not compile (`Envelope`, `Version`, `RecordKind`, `version_hash` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/envelope.rs`:

```rust
//! One version of one record, as carried inline in a log segment (plan A1c).
//!
//! For items and attachments the `body` is sealed with the vault key; its associated data
//! binds account, kind, ids, schema and the full version, so a body cannot be moved to another
//! record, vault or version. For vault records the body is the plaintext payload (protected by
//! the segment layer; the vault key inside is wrapped by the account key as today).

use std::collections::BTreeMap;

use keyorra_core::crypto::{self, Key, NONCE_LEN};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::{AccountId, DeviceId};

pub const ENVELOPE_FORMAT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    Vault,
    Item,
    Attachment,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Vault => "vault",
            RecordKind::Item => "item",
            RecordKind::Attachment => "attachment",
        }
    }

    pub fn parse(s: &str) -> Result<RecordKind> {
        match s {
            "vault" => Ok(RecordKind::Vault),
            "item" => Ok(RecordKind::Item),
            "attachment" => Ok(RecordKind::Attachment),
            other => Err(Error::Unsupported(format!("record kind {other}"))),
        }
    }

    /// Whether the body is sealed with the vault key (and `vault_id` is required).
    pub fn sealed_with_vault_key(self) -> bool {
        !matches!(self, RecordKind::Vault)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// How many writes of each device this version includes.
    pub vector: BTreeMap<DeviceId, u64>,
    /// Hybrid logical clock: 48-bit unix milliseconds | 16-bit counter.
    pub hlc: u64,
    pub author: DeviceId,
}

impl Version {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (
                "vector",
                Value::Map(
                    self.vector
                        .iter()
                        .map(|(d, n)| (Value::bytes(d), Value::Uint(*n)))
                        .collect(),
                ),
            ),
            ("hlc", Value::Uint(self.hlc)),
            ("author", Value::bytes(self.author)),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Version> {
        let f = value.fields(&["vector", "hlc", "author"])?;
        let mut vector = BTreeMap::new();
        for (device, count) in f.get("vector")?.as_map()? {
            let count = count.as_uint()?;
            if count == 0 {
                return Err(malformed("zero entry in version vector"));
            }
            vector.insert(device.as_array_of()?, count);
        }
        Ok(Version {
            vector,
            hlc: f.get("hlc")?.as_uint()?,
            author: f.get("author")?.as_array_of()?,
        })
    }
}

/// `SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, version]))`.
pub fn version_hash(kind: RecordKind, record_id: Uuid, version: &Version) -> [u8; 32] {
    let value = Value::Array(vec![
        Value::text(kind.as_str()),
        Value::bytes(record_id.as_bytes()),
        version.to_value(),
    ]);
    Sha256::digest(tagged(labels::VERSION, &[&cbor::encode(&value)])).into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: RecordKind,
    pub record_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub schema: u32,
    pub version: Version,
    /// A purged record: no body.
    pub tombstone: bool,
    pub body: Option<Vec<u8>>,
}

const FIELDS: [&str; 8] = [
    "format",
    "kind",
    "record_id",
    "vault_id",
    "schema",
    "version",
    "tombstone",
    "body",
];

impl Envelope {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("format", Value::Uint(ENVELOPE_FORMAT)),
            ("kind", Value::text(self.kind.as_str())),
            ("record_id", Value::bytes(self.record_id.as_bytes())),
            (
                "vault_id",
                self.vault_id
                    .map_or(Value::Null, |v| Value::bytes(v.as_bytes())),
            ),
            ("schema", Value::Uint(self.schema.into())),
            ("version", self.version.to_value()),
            ("tombstone", Value::Bool(self.tombstone)),
            ("body", self.body.as_ref().map_or(Value::Null, Value::bytes)),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Envelope> {
        let format = value
            .as_map()?
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "format"))
            .ok_or_else(|| malformed("envelope without format"))?
            .1
            .as_uint()?;
        if format != ENVELOPE_FORMAT {
            return Err(Error::Unsupported(format!("envelope format {format}")));
        }
        let f = value.fields(&FIELDS)?;
        let uuid = |v: &Value| v.as_array_of::<16>().map(Uuid::from_bytes);
        let env = Envelope {
            kind: RecordKind::parse(f.get("kind")?.as_text()?)?,
            record_id: uuid(f.get("record_id")?)?,
            vault_id: match f.get("vault_id")? {
                Value::Null => None,
                v => Some(uuid(v)?),
            },
            schema: f.get("schema")?.as_u32()?,
            version: Version::from_value(f.get("version")?)?,
            tombstone: f.get("tombstone")?.as_bool()?,
            body: match f.get("body")? {
                Value::Null => None,
                v => Some(v.as_bytes()?.to_vec()),
            },
        };
        env.check()?;
        Ok(env)
    }

    /// Shape rules: a tombstone has no body, anything else has one; vault-key kinds name
    /// their vault.
    pub fn check(&self) -> Result<()> {
        if self.tombstone == self.body.is_some() {
            return Err(malformed("tombstone and body disagree"));
        }
        if self.kind.sealed_with_vault_key() && self.vault_id.is_none() {
            return Err(malformed("record without vault"));
        }
        Ok(())
    }

    /// `SHA-256(canonical(envelope with body = null))`: what the body is bound to.
    pub fn header_hash(&self) -> [u8; 32] {
        let bare = Envelope {
            body: None,
            ..self.clone()
        };
        Sha256::digest(cbor::encode(&bare.to_value())).into()
    }

    pub fn version_hash(&self) -> [u8; 32] {
        version_hash(self.kind, self.record_id, &self.version)
    }

    fn body_aad(&self, account_id: &AccountId) -> Vec<u8> {
        tagged(labels::BODY, &[account_id, &self.header_hash()])
    }

    /// Seals `payload` with the vault key into `self.body`.
    pub fn seal_body(
        &mut self,
        vault_key: &Key,
        account_id: &AccountId,
        payload: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) {
        assert!(
            self.kind.sealed_with_vault_key(),
            "vault records carry plaintext bodies"
        );
        self.tombstone = false;
        let aad = self.body_aad(account_id);
        self.body = Some(crypto::seal_with_nonce(vault_key, nonce, payload, &aad));
    }

    pub fn open_body(&self, vault_key: &Key, account_id: &AccountId) -> Result<Zeroizing<Vec<u8>>> {
        let body = self.body.as_ref().ok_or_else(|| malformed("no body"))?;
        crypto::open(vault_key, body, &self.body_aad(account_id)).map_err(|_| Error::Decrypt)
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync envelope::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/envelope.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: record envelopes, version hashes and sealed bodies"
```

### Task 9: Attachment chunks

**Files:** Create `crates/keyorra-sync/src/chunk.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The only separate blobs. Each attachment has its own random key, so moves and conflict copies never re-upload chunks.

- [ ] **Step 1: Failing tests.** Add `pub mod chunk;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/chunk.rs` with only the test module:

```rust
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
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync chunk::` → does not compile (`seal_chunk`, `open_chunk`, `ChunkPlace`, `chunk_name` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/chunk.rs`:

```rust
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
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync chunk::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/chunk.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: attachment chunk format"
```

### Task 10: Segments

**Files:** Create `crates/keyorra-sync/src/segment.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Framing, hash chain and signature of one device's batch of entries. Entries are opaque CBOR values here (A1c defines them). `SegmentHeader::parse` needs no key, for the server.

- [ ] **Step 1: Failing tests.** Add `pub mod segment;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/segment.rs` with only the test module:

```rust
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
        seal_segment(&k_seg(), &signer(), &start(), entries(), &[0x53; NONCE_LEN]).unwrap()
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
            &[0x54; NONCE_LEN],
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
        assert!(seal_segment(&k, &signer(), &start(), vec![], &[0; NONCE_LEN]).is_err());
        let zero = StreamPosition {
            first_seq: 0,
            ..start()
        };
        assert!(seal_segment(&k, &signer(), &zero, entries(), &[0; NONCE_LEN]).is_err());
    }

    #[test]
    fn size_is_padded() {
        let len = sealed().len();
        assert_eq!(len, HEADER_LEN + NONCE_LEN + 1024 + 16);
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync segment::` → does not compile (`seal_segment`, `open_segment`, `SegmentHeader`, `chain*` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/segment.rs`:

````rust
//! Log segments: immutable, signed, hash-chained batches of one device's entries.
//!
//! ```text
//! segment = header ‖ nonce:24 ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
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
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::pad::{pad, unpad};
use crate::{AccountId, DeviceId};

pub const MAGIC: &[u8; 4] = b"KYS1";
pub const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 8 + 32 + 32;
/// Collection 0 is the account's own data; other values are reserved for shared vaults.
pub const ACCOUNT_COLLECTION: u8 = 0;
/// Cap on the canonical size of a segment's entries; larger rounds become several segments.
pub const MAX_ENTRIES_LEN: usize = 4 * 1024 * 1024;

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
    pub fn parse(segment: &[u8]) -> Result<SegmentHeader> {
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

fn signed_message(header: &[u8; HEADER_LEN], entries: &Value) -> Vec<u8> {
    tagged(labels::SEGMENT, &[header, &cbor::encode(entries)])
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
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if entries.is_empty() || at.first_seq == 0 {
        return Err(malformed("empty segment or seq 0"));
    }
    let header = SegmentHeader {
        collection: ACCOUNT_COLLECTION,
        device_id: at.device_id,
        first_seq: at.first_seq,
        last_seq: at.first_seq + entries.len() as u64 - 1,
        prev_hash: at.prev_hash,
        last_hash: chain(&at.prev_hash, &entries),
    }
    .to_bytes();
    let entries = Value::Array(entries);
    if cbor::encode(&entries).len() > MAX_ENTRIES_LEN {
        return Err(malformed("segment too large"));
    }
    let sig = signer.sign(&signed_message(&header, &entries)).to_bytes();
    let payload = Zeroizing::new(pad(&cbor::encode(&Value::map(vec![
        ("entries", entries),
        ("sig", Value::bytes(sig)),
    ]))));
    let mut out = header.to_vec();
    out.extend_from_slice(&crypto::seal_with_nonce(
        segment_key,
        nonce,
        &payload,
        &aad(&header, nonce),
    ));
    Ok(out)
}

/// Decrypts and fully verifies a segment written by the holder of `author`.
pub fn open_segment(segment_key: &Key, author: &VerifyingKey, segment: &[u8]) -> Result<Segment> {
    let header = SegmentHeader::parse(segment)?;
    let header_bytes = header.to_bytes();
    let sealed = &segment[HEADER_LEN..];
    let nonce: &[u8; NONCE_LEN] = sealed
        .get(..NONCE_LEN)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("segment nonce"))?;
    let padded = crypto::open(segment_key, sealed, &aad(&header_bytes, nonce))
        .map_err(|_| Error::Decrypt)?;
    let payload = cbor::decode(unpad(&padded)?)?;
    let f = payload.fields(&["entries", "sig"])?;
    let entries_value = f.get("entries")?;
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    author
        .verify_strict(
            &signed_message(&header_bytes, entries_value),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| Error::BadSignature)?;
    let entries = entries_value.as_list()?.to_vec();
    if entries.len() as u64 != header.entry_count() {
        return Err(malformed("segment entry count"));
    }
    if chain(&header.prev_hash, &entries) != header.last_hash {
        return Err(malformed("segment chain"));
    }
    Ok(Segment { header, entries })
}
````

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync segment::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/segment.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: signed, hash-chained, padded segment framing"
```

### Task 11: Snapshots

**Files:** Create `crates/keyorra-sync/src/snapshot.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Framing and signature of a snapshot; the body is opaque here (A1c defines it).

- [ ] **Step 1: Failing tests.** Add `pub mod snapshot;` to `lib.rs` (keep the `pub mod` lines sorted) and create `crates/keyorra-sync/src/snapshot.rs` with only the test module:

```rust
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
        seal_snapshot(&k_seg(), &signer(), AUTHOR, body(), &[0x55; NONCE_LEN])
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
            signed_message(&header, &body()),
            tagged(labels::SEGMENT, &[&header, &cbor::encode(&body())])
        );
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(snapshot_name(&sealed()), snapshot_name(&sealed()));
        assert_eq!(snapshot_name(&sealed()).len(), 64);
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync snapshot::` → does not compile (`seal_snapshot`, `open_snapshot`, `SnapshotHeader` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/snapshot.rs`:

````rust
//! Snapshots: self-contained, signed packs of a device's whole fold (contents defined in plan
//! A1c; here the body is any CBOR value).
//!
//! ```text
//! snapshot = "KYP1" ‖ collection:u8 ‖ author:16 ‖ nonce:24
//!            ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
//! payload  = { "body": …, "sig": Ed25519(author key, "keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body)) }
//! name     = lowercase hex SHA-256 of the whole snapshot
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key, NONCE_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::pad::{pad, unpad};
use crate::segment::ACCOUNT_COLLECTION;
use crate::DeviceId;

pub const MAGIC: &[u8; 4] = b"KYP1";
pub const HEADER_LEN: usize = 4 + 1 + 16;

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

fn signed_message(header: &[u8; HEADER_LEN], body: &Value) -> Vec<u8> {
    tagged(labels::SNAPSHOT, &[header, &cbor::encode(body)])
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
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let header = SnapshotHeader {
        collection: ACCOUNT_COLLECTION,
        author,
    }
    .to_bytes();
    let sig = signer.sign(&signed_message(&header, &body)).to_bytes();
    let payload = Zeroizing::new(pad(&cbor::encode(&Value::map(vec![
        ("body", body),
        ("sig", Value::bytes(sig)),
    ]))));
    let mut out = header.to_vec();
    out.extend_from_slice(&crypto::seal_with_nonce(
        segment_key,
        nonce,
        &payload,
        &aad(&header, nonce),
    ));
    out
}

pub fn open_snapshot(
    segment_key: &Key,
    author: &VerifyingKey,
    snapshot: &[u8],
) -> Result<(SnapshotHeader, Value)> {
    let header = SnapshotHeader::parse(snapshot)?;
    let header_bytes = header.to_bytes();
    let sealed = &snapshot[HEADER_LEN..];
    let nonce: &[u8; NONCE_LEN] = sealed
        .get(..NONCE_LEN)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("snapshot nonce"))?;
    let padded = crypto::open(segment_key, sealed, &aad(&header_bytes, nonce))
        .map_err(|_| Error::Decrypt)?;
    let payload = cbor::decode(unpad(&padded)?)?;
    let f = payload.fields(&["body", "sig"])?;
    let body = f.get("body")?;
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    author
        .verify_strict(
            &signed_message(&header_bytes, body),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| Error::BadSignature)?;
    Ok((header, body.clone()))
}

/// The file/blob name: lowercase hex SHA-256 of the snapshot bytes.
pub fn snapshot_name(snapshot: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(snapshot))
}
````

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync snapshot::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/snapshot.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: snapshot framing"
```

### Task 12: Deterministic test vectors

**Files:** Create `crates/keyorra-sync/src/vectors.rs`, `docs/sync-test-vectors/a1a.json` (generated); modify `crates/keyorra-sync/src/lib.rs`.

- [ ] **Step 1: The vector module.** Append to `lib.rs`:

```rust

#[cfg(test)]
mod vectors;
```

Create `crates/keyorra-sync/src/vectors.rs`:

```rust
//! Deterministic test vectors: fixed inputs → exact bytes, pinned in
//! `docs/sync-test-vectors/a1a.json` so that any other implementation (and any future change
//! here) can be checked against them. Regenerate only on a deliberate format change:
//! `cargo test -p keyorra-sync write_vectors -- --ignored`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::{derive_kek, KdfParams, Key, NONCE_LEN};
use uuid::Uuid;

use crate::cbor::{self, Value};
use crate::chunk::{chunk_name, seal_chunk, ChunkPlace};
use crate::envelope::{Envelope, RecordKind, Version};
use crate::header::{wrap_account_key, Header, HeaderFile};
use crate::keys::{derive_sync_keys, segment_key};
use crate::pad::padme;
use crate::secret_key::SecretKey;
use crate::segment::{chain_genesis, seal_segment, StreamPosition};
use crate::snapshot::{seal_snapshot, snapshot_name};

const PASSWORD: &str = "correct horse battery staple";
/// Cheap Argon2 parameters so the vectors run fast. Never used for a real account.
const KDF: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/sync-test-vectors/a1a.json")
}

pub(crate) fn compute() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        out.insert(k.to_owned(), v);
    };

    let account_id = seq::<16>(0x10);
    let salt = seq::<16>(0x20);
    let secret_key = SecretKey::from_bytes(seq::<16>(0x00));
    let account_key = Key::from_bytes(seq::<32>(0x30));
    let device_id = seq::<16>(0x70);
    let device_key = SigningKey::from_bytes(&seq::<32>(0x40));
    let vault_key = Key::from_bytes(seq::<32>(0x90));
    let attachment_key = Key::from_bytes(seq::<32>(0xb0));

    put("in.password", PASSWORD.to_owned());
    put(
        "in.kdf",
        format!("m_kib={} t={} p={}", KDF.m_kib, KDF.t, KDF.p),
    );
    put("in.account_id", hex(&account_id));
    put("in.salt", hex(&salt));
    put("in.secret_key", hex(secret_key.as_bytes()));
    put("in.account_key", hex(account_key.as_bytes()));
    put("in.device_id", hex(&device_id));
    put("in.device_signing_seed", hex(&seq::<32>(0x40)));
    put("in.vault_key", hex(vault_key.as_bytes()));
    put("in.attachment_key", hex(attachment_key.as_bytes()));

    put("secret_key.display", secret_key.display("A3K7").to_string());
    put(
        "device.public_key",
        hex(device_key.verifying_key().as_bytes()),
    );

    let u = derive_kek(PASSWORD, &salt, KDF).unwrap();
    put("keys.argon2id_u", hex(u.as_bytes()));
    let keys = derive_sync_keys(PASSWORD, &salt, KDF, &secret_key, &account_id).unwrap();
    put("keys.kek_sync", hex(keys.kek.as_bytes()));
    put("keys.auth", hex(keys.auth.as_bytes()));
    let k_seg = segment_key(&account_key, &account_id);
    put("keys.segment_key", hex(k_seg.as_bytes()));

    let header = Header {
        account_id,
        epoch: 1,
        generation: 1,
        root_device: device_id,
        kdf: KDF,
        salt,
        secret_key_id: "A3K7".into(),
        wrapped_account_key: wrap_account_key(
            &keys.kek,
            &account_key,
            &account_id,
            1,
            1,
            &seq::<NONCE_LEN>(0x60),
        ),
    };
    let file = HeaderFile::sign(header, device_id, &device_key);
    put("header.file", hex(&file.encode()));
    put("header.file_name", file.file_name());

    let version = Version {
        vector: BTreeMap::from([(device_id, 1)]),
        hlc: 1_790_000_000_000 << 16,
        author: device_id,
    };
    let mut item = Envelope {
        kind: RecordKind::Item,
        record_id: Uuid::from_bytes(seq::<16>(0xd0)),
        vault_id: Some(Uuid::from_bytes(seq::<16>(0xe0))),
        schema: 1,
        version,
        tombstone: false,
        body: None,
    };
    item.seal_body(
        &vault_key,
        &account_id,
        br#"{"title":"GitHub"}"#,
        &seq::<NONCE_LEN>(0x80),
    );
    put("envelope.item", hex(&cbor::encode(&item.to_value())));
    put("envelope.item.header_hash", hex(&item.header_hash()));
    put("envelope.item.version_hash", hex(&item.version_hash()));

    let place = ChunkPlace {
        account_id,
        attachment_id: Uuid::from_bytes(seq::<16>(0xf0)),
        index: 0,
        count: 1,
    };
    let chunk = seal_chunk(
        &attachment_key,
        &place,
        b"attachment bytes",
        &seq::<NONCE_LEN>(0xa0),
    )
    .unwrap();
    put("chunk", hex(&chunk));
    put("chunk.name", chunk_name(&chunk));

    let genesis = chain_genesis(&account_id, &device_id);
    put("segment.chain_genesis", hex(&genesis));
    let at = StreamPosition {
        device_id,
        first_seq: 1,
        prev_hash: genesis,
    };
    let entries = vec![Value::map(vec![("put", item.to_value())])];
    let segment = seal_segment(&k_seg, &device_key, &at, entries, &seq::<NONCE_LEN>(0xc0)).unwrap();
    put("segment", hex(&segment));

    let body = Value::map(vec![("records", Value::Array(vec![item.to_value()]))]);
    let snapshot = seal_snapshot(
        &k_seg,
        &device_key,
        device_id,
        body,
        &seq::<NONCE_LEN>(0xe8),
    );
    put("snapshot", hex(&snapshot));
    put("snapshot.name", snapshot_name(&snapshot));

    for len in [1025u64, 5000, 1_000_000] {
        put(&format!("padme.{len}"), padme(len).to_string());
    }
    out
}

fn to_json(map: &BTreeMap<String, String>) -> String {
    serde_json::to_string_pretty(map).unwrap() + "\n"
}

#[test]
fn vectors_match_the_pinned_file() {
    let text = std::fs::read_to_string(path())
        .expect("docs/sync-test-vectors/a1a.json missing: run the ignored write_vectors test");
    let pinned: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
    let computed = compute();
    for (key, value) in &computed {
        assert_eq!(pinned.get(key), Some(value), "vector {key}");
    }
    assert_eq!(
        pinned.len(),
        computed.len(),
        "extra keys in the pinned file"
    );
    assert_eq!(text, to_json(&computed), "file formatting drifted");
}

#[test]
fn vectors_open_again() {
    use crate::segment::open_segment;
    use crate::snapshot::open_snapshot;
    let v = compute();
    let unhex = |k: &str| data_encoding::HEXLOWER.decode(v[k].as_bytes()).unwrap();
    let file = HeaderFile::decode(&unhex("header.file")).unwrap();
    let device = SigningKey::from_bytes(&seq::<32>(0x40)).verifying_key();
    file.verify(&device).unwrap();
    let secret = SecretKey::parse(&v["secret_key.display"]).unwrap().1;
    let (ak, _) = file.header.unlock(PASSWORD, &secret).unwrap();
    assert_eq!(hex(ak.as_bytes()), v["in.account_key"]);
    let k_seg = segment_key(&ak, &file.header.account_id);
    let segment = open_segment(&k_seg, &device, &unhex("segment")).unwrap();
    let item = Envelope::from_value(
        segment.entries[0]
            .fields(&["put"])
            .unwrap()
            .get("put")
            .unwrap(),
    )
    .unwrap();
    let vault_key = Key::from_bytes(seq::<32>(0x90));
    assert_eq!(
        &*item.open_body(&vault_key, &file.header.account_id).unwrap(),
        br#"{"title":"GitHub"}"#
    );
    open_snapshot(&k_seg, &device, &unhex("snapshot")).unwrap();
}

#[test]
#[ignore = "rewrites docs/sync-test-vectors/a1a.json; run only on a deliberate format change"]
fn write_vectors() {
    std::fs::create_dir_all(path().parent().unwrap()).unwrap();
    std::fs::write(path(), to_json(&compute())).unwrap();
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync vectors` → `vectors_match_the_pinned_file` fails: "docs/sync-test-vectors/a1a.json missing". `vectors_open_again` passes.

- [ ] **Step 3: Generate and check.** Run `cargo test -p keyorra-sync write_vectors -- --ignored`. The file must contain 30 keys and these values (`keys.kek_sync`, `keys.auth`, `keys.segment_key` and `segment.chain_genesis` were cross-checked with an independent Python HKDF/SHA-256; the Secret Key display with an independent Python base32 encoder):

| Key | Value |
|---|---|
| `secret_key.display` | `A3K7-00041-06105-0R3GG-28A1C-60T3G-F6` |
| `device.public_key` | `2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d` |
| `keys.argon2id_u` | `de3c4f14e0a7e9b443a0616def109437ffbb93ee6a33a1e88d356dbfd3b16e99` |
| `keys.kek_sync` | `9b847f66f18b18e6a491a8b6c1d3c9742e2ef91452219605afd7663c0a1460b7` |
| `keys.auth` | `c7e016f1f7e2c623d3c555a0ff7c4489696c930fc47d37cbaa86106a30d65372` |
| `keys.segment_key` | `4333b25cbce1a270ac1fe4157b60bf829d72a31b3045c8b40aca9c64710e72a0` |
| `segment.chain_genesis` | `e3a6a5e73a4ab25707e0bd5bcbd7b96cf6e038435ad9f257cb057957ae0cc81e` |
| `envelope.item.header_hash` | `96229a37708dc18100666b9a950e606c7c95e8cd531c9dbd90e8ae25d82ee660` |
| `envelope.item.version_hash` | `d425186f8163a42e6091b4927f20e0e924247b4714d1b662119f21bb4d170d88` |
| `header.file_name` | `00000001-707172737475767778797a7b7c7d7e7f.hdr` |
| `chunk.name` | `5ba27e28cb6f6469964da38bd3ef608a80beb63adb09eb175a93c21a7a0fcb0a` |
| `snapshot.name` | `f9113ca44a2059afe8e6d9a3beb8503b2456514146affcf77a5071b2e891ccb7` |
| `padme.1025` | `1088` |
| `padme.5000` | `5120` |
| `padme.1000000` | `1015808` |

The whole file has SHA-256 `8da10ae56c66713d8ccde9ddeffb850e7e048a48bf183a749f2c09953ee1318e` (`shasum -a 256 docs/sync-test-vectors/a1a.json`). If anything differs, an earlier task deviates from this plan: fix the code, never the expectation.

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync` → all pass, 1 ignored (`write_vectors`).

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/vectors.rs crates/keyorra-sync/src/lib.rs docs/sync-test-vectors/a1a.json
git commit -m "sync: deterministic test vectors for keys and formats"
```

### Task 13: `docs/sync-protocol.md`, sections 1–8

**Files:** Create `docs/sync-protocol.md`.

- [ ] **Step 1: Write the document.** It is normative for what A1a implements and has placeholders for later plans:

````markdown
# Keyorra Sync Protocol

Version: 1 (draft). Status: sections 1–8 are defined and implemented in `crates/keyorra-sync`
(plan A1a); later sections are placeholders filled by later plans. The design rationale is in
`docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`; this document is the normative
description. Any change to bytes on the wire changes this file in the same commit.

Test vectors: `docs/sync-test-vectors/a1a.json` (fixed inputs → exact outputs). An
implementation is conforming for this part when it reproduces every value in that file.

## 1. Notation

- `‖` concatenation; `x:N` a field of N bytes; integers in headers are unsigned big-endian
  (`u32` = 4 bytes, `u64` = 8 bytes).
- `SHA-256`, `HKDF-SHA256` (RFC 5869), `Ed25519` (RFC 8032, verification with the strict
  rules of `ed25519-dalek` `verify_strict`), `XChaCha20-Poly1305` (draft-irtf-cfrg-xchacha;
  sealed output is `nonce:24 ‖ ciphertext ‖ tag:16`).
- `Argon2id` (RFC 9106, version 0x13).
- `canonical(v)`: the deterministic CBOR encoding of section 3.
- Hex in this document and in the vectors is lowercase.

## 2. Labels

Every label is used as `label ‖ 0x00 ‖ parts…`, so no label is a prefix of another.

| Label | Used for |
|---|---|
| `keyorra/sync/v1/kek` | HKDF info for `KEK_sync` |
| `keyorra/sync/v1/server-auth` | HKDF info for `AUTH` |
| `keyorra/sync/v1/segment-key` | HKDF info for `K_seg` |
| `keyorra/sync/v1/account-key` | AAD of the wrapped account key |
| `keyorra/sync/v1/header` | header signature |
| `keyorra/sync/v1/body` | AAD of record bodies |
| `keyorra/sync/v1/version` | version hash |
| `keyorra/sync/v1/chunk` | AAD of attachment chunks |
| `keyorra/sync/v1/segment` | segment signature |
| `keyorra/sync/v1/snapshot` | snapshot signature |
| `keyorra/sync/v1/chain-genesis` | first link of a stream's hash chain |
| `keyorra/sync/v1/chain` | every further link |

## 3. Canonical CBOR

A subset of RFC 8949: major types 0 (unsigned integer), 2 (byte string), 3 (UTF-8 text),
4 (array), 5 (map) and the simple values `false` (0xf4), `true` (0xf5), `null` (0xf6).

Encoding: the shortest head for every length or integer; definite lengths only; map entries
sorted by the bytewise order of their encoded keys, no duplicate keys.

Decoding is strict and rejects: non-shortest heads, indefinite lengths, reserved
additional-information values, negative integers, tags, floats and other simple values,
unsorted or duplicate map keys, invalid UTF-8, lengths beyond the input, nesting deeper
than 32, and trailing bytes. Structures are maps with text keys and exactly the listed
fields.

## 4. Padding

`pad(data) = data ‖ 0x80 ‖ 0x00…` up to `max(1024, padme(len(data) + 1))` bytes, where
`padme(L)` (Padmé, PURBs paper, PETS 2019) is: for `L < 2`, `L`; otherwise
`E = floor(log2 L)`, `S = floor(log2 E) + 1`, `mask = 2^(E−S) − 1`,
`padme(L) = (L + mask) & ~mask`. Unpadding strips trailing zeros, requires the last
non-zero byte to be `0x80` and the total length to equal the formula. Applied to segment
payloads, snapshot payloads and attachment chunks.

## 5. Secret Key and keys

**Secret Key.** 16 random bytes `SK` and an independent 4-character id (random digits of
the alphabet below). Display: `ID-ddddd-ddddd-ddddd-ddddd-ddddd-dc` where the 26 `d` are the
big-endian base32 digits of `SK` as a 128-bit integer (Crockford alphabet
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`; the first digit is at most 7) and `c` is
`"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"[SK mod 37]`. Parsing ignores case, hyphens and
whitespace and maps `I`, `L` → `1` and `O` → `0`.

**Derivation.**

```
U        = Argon2id(password, salt, m, t, p, 32 bytes)        salt, m, t, p from the account header
M        = HKDF-Extract(salt = SK, ikm = U)
KEK_sync = HKDF-Expand(M, "keyorra/sync/v1/kek\0" ‖ account_id, 32)
AUTH     = HKDF-Expand(M, "keyorra/sync/v1/server-auth\0" ‖ account_id, 32)
K_seg    = HKDF(salt = account_id, ikm = AK, info = "keyorra/sync/v1/segment-key\0", 32)
```

KDF parameters read from a header must satisfy, before Argon2 runs: `m ≤ 1048576` KiB,
`1 ≤ t ≤ 10`, `1 ≤ p ≤ 4` (and Argon2's own minimum `m ≥ 8p`).

## 6. Account header

```
Header = { "keyorra_sync": 1, "account_id": bytes16, "epoch": uint32, "generation": uint32,
           "root_device": bytes16, "kdf": { "m_kib", "t", "p" }, "salt": bytes16,
           "secret_key_id": text(4), "wrapped_account_key": bytes }
wrapped_account_key = XChaCha20-Poly1305(KEK_sync, nonce, AK,
                        aad = "keyorra/sync/v1/account-key\0" ‖ account_id ‖ epoch:u32 ‖ generation:u32)
HeaderFile = { "header": Header, "author": bytes16, "sig": bytes64 }
sig        = Ed25519(author key, "keyorra/sync/v1/header\0" ‖ canonical(Header))
file name  = hex8(epoch) ‖ "-" ‖ hex(author) ‖ ".hdr"
```

A `keyorra_sync` value other than 1 is "unsupported", not "malformed". Which header counts
(highest epoch, matching log entry, tie-breaks) is defined in section 10.

## 7. Record envelopes, versions and bodies

```
Version  = { "vector": { bytes16 → uint ≥ 1 }, "hlc": uint, "author": bytes16 }
Envelope = { "format": 1, "kind": "vault" | "item" | "attachment", "record_id": bytes16,
             "vault_id": bytes16 | null, "schema": uint32, "version": Version,
             "tombstone": bool, "body": bytes | null }
version_hash = SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, version]))
header_hash  = SHA-256(canonical(envelope with "body" = null))
body (item, attachment) = XChaCha20-Poly1305(vault key, nonce, payload,
                            aad = "keyorra/sync/v1/body\0" ‖ account_id ‖ header_hash)
body (vault) = the plaintext payload (protected by the segment layer)
```

Rules: `tombstone` is true exactly when `body` is null; `item` and `attachment` envelopes
have a `vault_id`. Unknown `format` or `kind`: unsupported (kept, not interpreted). The
payload contents and the merge rules are defined in section 9.

## 8. Framing: chunks, segments, snapshots

**Attachment chunk** (at most 4 MiB of data):

```
chunk = "KYC1" ‖ XChaCha20-Poly1305(attachment key, nonce, pad(data),
          aad = "keyorra/sync/v1/chunk\0" ‖ account_id ‖ attachment_id:16 ‖ index:u32 ‖ count:u32)
name  = hex(SHA-256(chunk))
```

**Segment.**

```
header  = "KYS1" ‖ collection:u8 (= 0) ‖ device_id:16 ‖ first_seq:u64 ‖ last_seq:u64 ‖ prev_hash:32 ‖ last_hash:32
segment = header ‖ nonce:24 ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload = { "entries": [entry, …], "sig": Ed25519(device key, "keyorra/sync/v1/segment\0" ‖ header ‖ canonical(entries)) }
chain_0 = SHA-256("keyorra/sync/v1/chain-genesis\0" ‖ account_id ‖ device_id)
chain_n = SHA-256("keyorra/sync/v1/chain\0" ‖ chain_{n−1} ‖ canonical(entry_n))
```

`first_seq ≥ 1`; the entry count equals `last_seq − first_seq + 1`; `last_hash` is the chain
over the entries starting from `prev_hash`; the canonical entries are at most 4 MiB. A
non-zero collection is unsupported in version 1 (reserved for shared vaults).

**Snapshot.**

```
header   = "KYP1" ‖ collection:u8 (= 0) ‖ author:16
snapshot = header ‖ nonce:24 ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload  = { "body": …, "sig": Ed25519(author key, "keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body)) }
name     = hex(SHA-256(snapshot))
```

## 9. Fold and presentation

To be defined by plan A1b (sibling sets, presentation rules, conflict copies).

## 10. Streams, entries and trust

To be defined by plan A1c (entry types, endorsement, acceptance rule, causal delivery,
headers as log entries, snapshot contents, restore, clone detection).

## 11. Folder transport

To be defined by plan A2.

## 12. Server API

To be defined by plans B1 and B2.
````

- [ ] **Step 2: Check it against the code.** Every label in `labels::ALL` appears in §2; every magic (`KYC1`, `KYS1`, `KYP1`), field name and bound in §§3–8 matches the code (`grep -n '"' crates/keyorra-sync/src/{header,envelope}.rs` for field names). A mismatch is fixed in the document unless the code contradicts the spec.
- [ ] **Step 3: Commit.**

```bash
git add docs/sync-protocol.md
git commit -m "docs: sync protocol, keys and formats (sections 1-8)"
```

### Task 14: Final verification

- [ ] **Step 1: Whole workspace, from a clean state.**

```bash
cargo fmt --all -- --check
cargo clippy -p keyorra-core -p keyorra-session -p keyorra-sync --all-targets -- -D warnings
cargo test -p keyorra-core -p keyorra-session -p keyorra-sync
cargo test -p keyorra-sync -- --ignored --list   # exactly one ignored test: vectors::write_vectors
```

Expected: no format diff, no clippy warnings, every `test result:` line `ok` (keyorra-sync: 56 passed, 1 ignored; core: two more tests than before this plan).

- [ ] **Step 2: Purity check.** `grep -rnE "std::(fs|net|time|env|process)|SystemTime|OsRng|thread_rng" crates/keyorra-sync/src` → matches only in `vectors.rs` (`std::fs`, test-only) and in tests (`OsRng`, `std::time::Instant` in a timing assertion); none in non-test code.
- [ ] **Step 3: Vectors are stable.** Run `cargo test -p keyorra-sync write_vectors -- --ignored` again; `git status --short docs/sync-test-vectors` shows no change.
- [ ] **Step 4: Spec cross-check.** For each line of the spec's A1a row (§12): keys and labels (Tasks 2, 6), canonical CBOR (3), Padmé (4), envelopes (8), chunks (9), segment/snapshot/header framing (7, 10, 11), test vectors (12), protocol draft (13). Nothing from A1b/A1c (fold, entries, endorsement) has been started.
- [ ] **Step 5: Wrap up.** If any step needed a fix, commit it as `sync: A1a verification fixes`. Do not push.
