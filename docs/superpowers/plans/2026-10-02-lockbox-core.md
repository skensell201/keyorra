# Lockbox Core Implementation Plan (Plan 1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `lockbox-core`, the Rust library that holds all of Lockbox's security-critical logic: encryption, the SQLite vault store, the item model, TOTP, the password generator, 1Password import and Watchtower.

**Architecture:** One Rust crate in a Cargo workspace (`crates/lockbox-core`), no UI and no OS APIs. A master password derives a KEK (Argon2id) that wraps an account key; the account key wraps one key per vault; every item, vault name and attachment is sealed with XChaCha20-Poly1305 using associated data that binds it to its ids. `Store` is the only type that touches SQLite. Plan 2 (Tauri desktop app) and Plan 3 (Chrome extension) build on this crate and are written after this plan lands.

**Tech Stack:** Rust 2021, argon2 0.5, chacha20poly1305 0.10, rand 0.8, zeroize 1, rusqlite 0.32 (bundled), serde/serde_json, uuid 1, hmac/sha1/sha2, data-encoding, url, percent-encoding, zip 2, csv 1, zxcvbn 3, ureq 2; tests: tempfile, mockito.

**Spec:** `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md`

**Conventions for every task:**
- Test first. Run the test, see it fail for the expected reason, then implement.
- All code, comments, test names and commit messages in English.
- Run commands from the repo root `/Users/skensel/WORKING/AI/lockbox`.
- End every commit message with the line `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (shown once below, omitted from later commit commands for brevity — always add it).
- Errors are compared with `matches!` because `Error` wraps non-comparable library errors.

## File map

```
Cargo.toml                                  workspace
crates/lockbox-core/
  Cargo.toml
  assets/eff_large_wordlist.txt             EFF long wordlist (7776 words)
  src/lib.rs                                module list + re-exports
  src/error.rs                              Error, Result
  src/crypto/mod.rs                         re-exports
  src/crypto/key.rs                         Key (32 bytes, zeroized)
  src/crypto/aead.rs                        seal/open (XChaCha20-Poly1305)
  src/crypto/kdf.rs                         KdfParams, derive_kek (Argon2id)
  src/crypto/keys.rs                        Header, key hierarchy, AAD builders
  src/model.rs                              Item, Field, Section, VaultInfo, overview/search
  src/store/mod.rs                          Store: SQLite, lock/unlock, vaults, items, attachments, import apply
  src/store/tests.rs                        Store unit tests (need private access)
  src/totp.rs                               RFC 6238 + otpauth parsing
  src/wordlist.rs                           parsed EFF wordlist
  src/generator.rs                          password + passphrase
  src/import/mod.rs                         ImportPlan & friends
  src/import/csv.rs                         1Password CSV
  src/import/onepux.rs                      1Password .1pux
  src/watchtower/mod.rs                     weak, reused, Finding
  src/watchtower/hibp.rs                    Have I Been Pwned range client
  tests/import_1pux.rs                      .1pux integration test
  tests/fixtures/export.data.json           hand-built 1Password export
```

---

### Task 1: Workspace scaffold and error type

**Files:**
- Create: `Cargo.toml`, `crates/lockbox-core/Cargo.toml`, `crates/lockbox-core/src/lib.rs`, `crates/lockbox-core/src/error.rs`

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:
```toml
[workspace]
members = ["crates/lockbox-core"]
resolver = "2"

# Argon2 with 64 MiB is painfully slow unoptimized; keep debug builds usable.
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.blake2]
opt-level = 3
```

- [ ] **Step 2: Create the crate manifest with all dependencies**

`crates/lockbox-core/Cargo.toml`:
```toml
[package]
name = "lockbox-core"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
argon2 = "0.5"
chacha20poly1305 = "0.10"
csv = "1"
data-encoding = "2"
hmac = "0.12"
percent-encoding = "2"
rand = "0.8"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha1 = "0.10"
sha2 = "0.10"
thiserror = "2"
ureq = "2"
url = "2"
uuid = { version = "1", features = ["v4", "serde"] }
zeroize = "1"
zip = { version = "2", default-features = false, features = ["deflate"] }
zxcvbn = "3"

[dev-dependencies]
mockito = "1"
tempfile = "3"
```

- [ ] **Step 3: Write the failing test**

`crates/lockbox-core/src/error.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_message_is_generic() {
        assert_eq!(Error::WrongPassword.to_string(), "incorrect password");
    }
}
```

`crates/lockbox-core/src/lib.rs`:
```rust
pub mod error;

pub use error::{Error, Result};
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cargo test -p lockbox-core`
Expected: compile error `cannot find type Error`.

- [ ] **Step 5: Implement the error type** (prepend to `error.rs`, above the test module)

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("incorrect password")]
    WrongPassword,
    #[error("decryption failed")]
    Decrypt,
    #[error("vault is locked")]
    Locked,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("network: {0}")]
    Network(String),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p lockbox-core`
Expected: `test error::tests::wrong_password_message_is_generic ... ok`

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/lockbox-core
git commit -m "Scaffold lockbox-core crate with error type

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Key type and authenticated encryption

**Files:**
- Create: `crates/lockbox-core/src/crypto/mod.rs`, `crates/lockbox-core/src/crypto/key.rs`, `crates/lockbox-core/src/crypto/aead.rs`
- Modify: `crates/lockbox-core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/crypto/mod.rs`:
```rust
mod aead;
mod key;

pub use aead::{open, seal, NONCE_LEN};
pub use key::Key;
```

`crates/lockbox-core/src/crypto/key.rs`:
```rust
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
```

`crates/lockbox-core/src/crypto/aead.rs`:
```rust
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
```

Add to `lib.rs`: `pub mod crypto;`

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core crypto`
Expected: compile errors (`Key`, `seal`, `open` not found).

- [ ] **Step 3: Implement `Key`** (prepend to `key.rs`)

```rust
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
```

- [ ] **Step 4: Implement `seal`/`open`** (prepend to `aead.rs`)

```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p lockbox-core crypto`
Expected: 10 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add zeroized Key and XChaCha20-Poly1305 seal/open"
```

---

### Task 3: Argon2id key derivation

**Files:**
- Create: `crates/lockbox-core/src/crypto/kdf.rs`
- Modify: `crates/lockbox-core/src/crypto/mod.rs`

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/crypto/kdf.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [2u8; 16];

    #[test]
    fn same_inputs_same_key() {
        let a = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let b = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn password_salt_and_params_all_matter() {
        let base = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let other_pw = derive_kek("pw2", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let other_salt = derive_kek("pw", &[3u8; 16], KdfParams::INSECURE_FAST).unwrap();
        let other_params =
            derive_kek("pw", &SALT, KdfParams { t: 2, ..KdfParams::INSECURE_FAST }).unwrap();
        assert_ne!(base.as_bytes(), other_pw.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_params.as_bytes());
    }

    #[test]
    fn rejects_invalid_params() {
        let bad = KdfParams { m_kib: 1, t: 1, p: 1 };
        assert!(matches!(derive_kek("pw", &SALT, bad), Err(crate::Error::Invalid(_))));
    }

    #[test]
    fn default_params_match_spec() {
        assert_eq!(KdfParams::DEFAULT, KdfParams { m_kib: 65536, t: 3, p: 1 });
    }

    /// RFC 9106 §5.3 known-answer test: guards that the dependency is Argon2id v1.3.
    #[test]
    fn rfc9106_argon2id_vector() {
        use argon2::{AssociatedData, ParamsBuilder};
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon = Argon2::new_with_secret(&[3u8; 8], ALGORITHM, VERSION, params).unwrap();
        let mut out = [0u8; 32];
        argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }
}
```

Update `crypto/mod.rs`:
```rust
mod aead;
mod kdf;
mod key;

pub use aead::{open, seal, NONCE_LEN};
pub use kdf::{derive_kek, KdfParams};
pub use key::Key;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core kdf`
Expected: compile errors (`derive_kek`, `KdfParams` not found).

- [ ] **Step 3: Implement** (prepend to `kdf.rs`)

```rust
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::Key;
use crate::{Error, Result};

const ALGORITHM: Algorithm = Algorithm::Argon2id;
const VERSION: Version = Version::V0x13;

/// Argon2id cost parameters, stored in the vault header so they can be raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Cheap parameters for tests only. Never use for a real vault.
    pub const INSECURE_FAST: Self = Self { m_kib: 8, t: 1, p: 1 };
}

/// Derives the key-encryption key from the master password.
pub fn derive_kek(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<Key> {
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Invalid(format!("kdf params: {e}")))?;
    let mut out = [0u8; 32];
    Argon2::new(ALGORITHM, VERSION, argon_params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Invalid(format!("kdf: {e}")))?;
    let key = Key::from_bytes(out);
    out.zeroize();
    Ok(key)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core kdf`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add Argon2id key derivation with RFC 9106 vector"
```

---

### Task 4: Key hierarchy (header, account key, vault keys, AAD)

**Files:**
- Create: `crates/lockbox-core/src/crypto/keys.rs`
- Modify: `crates/lockbox-core/src/crypto/mod.rs`

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/crypto/keys.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;

    #[test]
    fn unlock_returns_the_created_account_key() {
        let (header, account) = create_header("correct horse", FAST).unwrap();
        let unlocked = unlock(&header, "correct horse").unwrap();
        assert_eq!(unlocked.as_bytes(), account.as_bytes());
        assert_eq!(header.format, FORMAT_VERSION);
        assert_eq!(header.kdf, FAST);
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        let (header, _) = create_header("correct horse", FAST).unwrap();
        assert!(matches!(unlock(&header, "battery staple"), Err(Error::WrongPassword)));
    }

    #[test]
    fn change_password_keeps_account_key_and_rotates_salt() {
        let (header, account) = create_header("old", FAST).unwrap();
        let changed = change_password(&header, "old", "new", FAST).unwrap();
        assert_ne!(changed.salt, header.salt);
        assert!(matches!(unlock(&changed, "old"), Err(Error::WrongPassword)));
        assert_eq!(unlock(&changed, "new").unwrap().as_bytes(), account.as_bytes());
    }

    #[test]
    fn change_password_requires_the_old_one() {
        let (header, _) = create_header("old", FAST).unwrap();
        assert!(matches!(change_password(&header, "nope", "new", FAST), Err(Error::WrongPassword)));
    }

    #[test]
    fn vault_key_is_bound_to_its_vault_id() {
        let account = Key::random();
        let vault_key = Key::random();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let wrapped = wrap_vault_key(&account, a, &vault_key);
        assert_eq!(unwrap_vault_key(&account, a, &wrapped).unwrap().as_bytes(), vault_key.as_bytes());
        assert!(matches!(unwrap_vault_key(&account, b, &wrapped), Err(Error::Decrypt)));
    }

    #[test]
    fn item_aad_depends_on_every_component() {
        let (v, i) = (Uuid::new_v4(), Uuid::new_v4());
        let base = item_aad(v, i, 1);
        assert_ne!(base, item_aad(Uuid::new_v4(), i, 1));
        assert_ne!(base, item_aad(v, Uuid::new_v4(), 1));
        assert_ne!(base, item_aad(v, i, 2));
    }

    #[test]
    fn header_survives_json() {
        let (header, _) = create_header("pw", FAST).unwrap();
        let json = serde_json::to_vec(&header).unwrap();
        assert_eq!(serde_json::from_slice::<Header>(&json).unwrap(), header);
    }
}
```

Update `crypto/mod.rs` (add `mod keys;` and):
```rust
pub use keys::{
    attachment_aad, change_password, create_header, item_aad, unlock, unwrap_vault_key,
    wrap_vault_key, Header, FORMAT_VERSION,
};
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core keys`
Expected: compile errors (`create_header` etc. not found).

- [ ] **Step 3: Implement** (prepend to `keys.rs`)

```rust
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{derive_kek, open, seal, KdfParams, Key};
use crate::{Error, Result};

pub const FORMAT_VERSION: u32 = 1;
const ACCOUNT_KEY_AAD: &[u8] = b"lockbox/account-key/v1";

/// Everything needed to turn the master password into the account key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub wrapped_account_key: Vec<u8>,
}

/// Creates a new random account key and a header that unlocks it with `password`.
pub fn create_header(password: &str, kdf: KdfParams) -> Result<(Header, Key)> {
    let account = Key::random();
    let header = wrap_account_key(&account, password, kdf)?;
    Ok((header, account))
}

/// Recovers the account key. A wrong password fails AEAD authentication.
pub fn unlock(header: &Header, password: &str) -> Result<Key> {
    let kek = derive_kek(password, &header.salt, header.kdf)?;
    let raw = open(&kek, &header.wrapped_account_key, ACCOUNT_KEY_AAD)
        .map_err(|_| Error::WrongPassword)?;
    Key::from_slice(&raw)
}

/// Re-wraps the same account key under a new password (fresh salt). Items are untouched.
pub fn change_password(header: &Header, old: &str, new: &str, kdf: KdfParams) -> Result<Header> {
    let account = unlock(header, old)?;
    wrap_account_key(&account, new, kdf)
}

fn wrap_account_key(account: &Key, password: &str, kdf: KdfParams) -> Result<Header> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(password, &salt, kdf)?;
    Ok(Header {
        format: FORMAT_VERSION,
        kdf,
        salt,
        wrapped_account_key: seal(&kek, account.as_bytes(), ACCOUNT_KEY_AAD),
    })
}

pub fn wrap_vault_key(account: &Key, vault_id: Uuid, vault_key: &Key) -> Vec<u8> {
    seal(account, vault_key.as_bytes(), &with_ids(b"lockbox/vault-key/v1", &[vault_id]))
}

pub fn unwrap_vault_key(account: &Key, vault_id: Uuid, wrapped: &[u8]) -> Result<Key> {
    let raw = open(account, wrapped, &with_ids(b"lockbox/vault-key/v1", &[vault_id]))?;
    Key::from_slice(&raw)
}

/// Associated data for an item: moving a ciphertext to another row or vault fails to decrypt.
pub fn item_aad(vault_id: Uuid, item_id: Uuid, schema: u32) -> Vec<u8> {
    let mut aad = with_ids(b"lockbox/item/v1", &[vault_id, item_id]);
    aad.extend_from_slice(&schema.to_be_bytes());
    aad
}

pub fn attachment_aad(vault_id: Uuid, item_id: Uuid, attachment_id: Uuid) -> Vec<u8> {
    with_ids(b"lockbox/attachment/v1", &[vault_id, item_id, attachment_id])
}

fn with_ids(label: &[u8], ids: &[Uuid]) -> Vec<u8> {
    let mut aad = label.to_vec();
    for id in ids {
        aad.extend_from_slice(id.as_bytes());
    }
    aad
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core keys`
Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add key hierarchy: header, account key, vault keys, AAD"
```

---

### Task 5: Item model

**Files:**
- Create: `crates/lockbox-core/src/model.rs`
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod model;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/model.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, "GitHub", 100);
        item.urls.push("https://github.com/login".into());
        item.tags.push("dev".into());
        item.fields.push(Field {
            id: "username".into(),
            label: "username".into(),
            value: FieldValue::Text("ivan".into()),
            purpose: Some(Purpose::Username),
        });
        item.set_password("first", 100);
        item.sections.push(Section {
            id: "s1".into(),
            title: "".into(),
            fields: vec![Field {
                id: "otp".into(),
                label: "one-time password".into(),
                value: FieldValue::Totp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                purpose: None,
            }],
        });
        item
    }

    #[test]
    fn accessors_find_purpose_fields_and_totp_in_sections() {
        let item = login();
        assert_eq!(item.username(), Some("ivan"));
        assert_eq!(item.password(), Some("first"));
        assert_eq!(item.totp(), Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn set_password_records_history_newest_first() {
        let mut item = login();
        item.set_password("second", 200);
        item.set_password("third", 300);
        assert_eq!(item.password(), Some("third"));
        let history: Vec<_> = item.password_history.iter().map(|h| (h.value.as_str(), h.changed_at)).collect();
        assert_eq!(history, vec![("second", 300), ("first", 200)]);
        assert_eq!(item.updated_at, 300);
    }

    #[test]
    fn set_password_to_same_value_is_a_no_op() {
        let mut item = login();
        item.set_password("first", 500);
        assert!(item.password_history.is_empty());
        assert_eq!(item.updated_at, 100);
    }

    #[test]
    fn json_round_trip() {
        let item = login();
        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);
    }

    #[test]
    fn overview_search_is_case_insensitive_over_title_user_url_tags() {
        let o = login().overview();
        assert_eq!(o.subtitle, "ivan");
        for q in ["", "  ", "git", "IVAN", "github.com", "DEV"] {
            assert!(o.matches(q), "query {q:?} should match");
        }
        assert!(!o.matches("gitlab"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core model`
Expected: compile errors (`Item` not found).

- [ ] **Step 3: Implement** (prepend to `model.rs`)

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped when the encrypted JSON layout changes; part of the item AAD.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    SecureNote,
    CreditCard,
    Identity,
    Password,
    ApiCredential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Username,
    Password,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Concealed(String),
    Email(String),
    Url(String),
    /// Unix seconds.
    Date(i64),
    /// YYYYMM, e.g. 202712.
    MonthYear(u32),
    /// An `otpauth://` URI or a bare base32 secret.
    Totp(String),
    Phone(String),
}

impl FieldValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) | Self::Concealed(s) | Self::Email(s) | Self::Url(s) | Self::Totp(s)
            | Self::Phone(s) => Some(s),
            Self::Date(_) | Self::MonthYear(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub id: String,
    pub label: String,
    pub value: FieldValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Purpose>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    pub title: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub value: String,
    pub changed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub id: Uuid,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Login only; the first one is primary.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Built-in fields (username/password carry a `purpose`).
    #[serde(default)]
    pub fields: Vec<Field>,
    /// Custom sections, like 1Password's.
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub notes: String,
    /// Newest first.
    #[serde(default)]
    pub password_history: Vec<HistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Item {
    pub fn new(vault_id: Uuid, kind: ItemKind, title: &str, now: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            vault_id,
            kind,
            title: title.to_owned(),
            tags: Vec::new(),
            favorite: false,
            urls: Vec::new(),
            fields: Vec::new(),
            sections: Vec::new(),
            notes: String::new(),
            password_history: Vec::new(),
            attachments: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn username(&self) -> Option<&str> {
        self.purpose_value(Purpose::Username)
    }

    pub fn password(&self) -> Option<&str> {
        self.purpose_value(Purpose::Password)
    }

    /// First TOTP field, built-in or in a section.
    pub fn totp(&self) -> Option<&str> {
        self.fields
            .iter()
            .chain(self.sections.iter().flat_map(|s| s.fields.iter()))
            .find_map(|f| match &f.value {
                FieldValue::Totp(s) => Some(s.as_str()),
                _ => None,
            })
    }

    /// Sets the password, pushing a changed non-empty old value into history.
    pub fn set_password(&mut self, new: &str, now: i64) {
        match self.fields.iter_mut().find(|f| f.purpose == Some(Purpose::Password)) {
            Some(field) => {
                let old = field.value.as_str().unwrap_or_default().to_owned();
                if old == new {
                    return;
                }
                field.value = FieldValue::Concealed(new.to_owned());
                if !old.is_empty() {
                    self.password_history.insert(0, HistoryEntry { value: old, changed_at: now });
                }
            }
            None => self.fields.push(Field {
                id: "password".into(),
                label: "password".into(),
                value: FieldValue::Concealed(new.to_owned()),
                purpose: Some(Purpose::Password),
            }),
        }
        self.updated_at = now;
    }

    pub fn overview(&self) -> ItemOverview {
        ItemOverview {
            id: self.id,
            vault_id: self.vault_id,
            kind: self.kind,
            title: self.title.clone(),
            subtitle: self.username().unwrap_or_default().to_owned(),
            urls: self.urls.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            updated_at: self.updated_at,
        }
    }

    fn purpose_value(&self, purpose: Purpose) -> Option<&str> {
        self.fields.iter().find(|f| f.purpose == Some(purpose)).and_then(|f| f.value.as_str())
    }
}

/// What lists and search need; no secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemOverview {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub updated_at: i64,
}

impl ItemOverview {
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        std::iter::once(&self.title)
            .chain(std::iter::once(&self.subtitle))
            .chain(self.urls.iter())
            .chain(self.tags.iter())
            .any(|s| s.to_lowercase().contains(&q))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: Uuid,
    pub name: String,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core model`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add item model with password history and search"
```

---

### Task 6: Store — create, open, lock/unlock, password change, vaults

**Files:**
- Create: `crates/lockbox-core/src/store/mod.rs`, `crates/lockbox-core/src/store/tests.rs`
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod store;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/store/tests.rs`:
```rust
use super::*;
use crate::Error;

pub(super) const PW: &str = "correct horse";

pub(super) fn new_store() -> (tempfile::TempDir, PathBuf, Store) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lockbox.db");
    let store = Store::create(&path, PW, KdfParams::INSECURE_FAST).unwrap();
    (dir, path, store)
}

#[test]
fn reopened_store_is_locked_until_unlocked() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(!store.is_unlocked());
    assert!(matches!(store.vaults(), Err(Error::Locked)));
    assert!(matches!(store.unlock("wrong"), Err(Error::WrongPassword)));
    store.unlock(PW).unwrap();
    let names: Vec<_> = store.vaults().unwrap().into_iter().map(|v| v.name).collect();
    assert_eq!(names, ["Personal"]);
}

#[test]
fn create_refuses_existing_file() {
    let (_dir, path, _store) = new_store();
    assert!(matches!(Store::create(&path, PW, KdfParams::INSECURE_FAST), Err(Error::Invalid(_))));
}

#[test]
fn open_missing_file_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(Store::open(&dir.path().join("nope.db")), Err(Error::NotFound(_))));
}

#[test]
fn lock_forgets_keys() {
    let (_dir, _path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    store.lock();
    assert!(!store.is_unlocked());
    assert!(matches!(store.vaults(), Err(Error::Locked)));
    assert!(matches!(store.create_vault("x"), Err(Error::Locked)));
}

#[test]
fn change_password_persists() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    assert!(matches!(store.change_password("wrong", "new pw"), Err(Error::WrongPassword)));
    store.change_password(PW, "new pw").unwrap();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(matches!(store.unlock(PW), Err(Error::WrongPassword)));
    store.unlock("new pw").unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}

#[test]
fn unlock_with_account_key_for_touch_id() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("Personal").unwrap();
    let account = store.account_key().unwrap().clone();
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert!(matches!(store.account_key(), Err(Error::Locked)));
    assert!(matches!(store.unlock_with_key(Key::random()), Err(Error::WrongPassword)));
    store.unlock_with_key(account).unwrap();
    assert_eq!(store.vaults().unwrap().len(), 1);
}

#[test]
fn vault_names_are_not_stored_in_plaintext() {
    let (_dir, path, mut store) = new_store();
    store.create_vault("SuperSecretVaultName").unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(20).any(|w| w == b"SuperSecretVaultName"));
}

#[test]
fn newer_database_version_is_rejected() {
    let (_dir, path, store) = new_store();
    drop(store);
    rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Invalid(_))));
}

#[test]
fn backup_copies_the_file_next_to_itself() {
    let (_dir, path, store) = new_store();
    drop(store);
    let copy = backup(&path, 1).unwrap();
    assert_eq!(copy, path.with_extension("db.bak-v1"));
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&path).unwrap());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Create `crates/lockbox-core/src/store/mod.rs` containing only:
```rust
#[cfg(test)]
mod tests;
```
Run: `cargo test -p lockbox-core store`
Expected: compile errors (`Store`, `backup`, `PathBuf`, `KdfParams`, `Key` not found).

- [ ] **Step 3: Implement** (replace `store/mod.rs` with)

```rust
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::{self, Header, KdfParams, Key};
use crate::model::VaultInfo;
use crate::{Error, Result};

#[cfg(test)]
mod tests;

const DB_VERSION: i64 = 1;
const CHECK_AAD: &[u8] = b"lockbox/check/v1";
const VAULT_META_AAD: &[u8] = b"lockbox/vault-meta/v1";

const SCHEMA_V1: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    wrapped_key BLOB NOT NULL,
    meta BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    data BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    data BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0
);
";

/// The encrypted vault database. Locked until `unlock`/`unlock_with_key`.
pub struct Store {
    conn: Connection,
    header: Header,
    account: Option<Key>,
    vault_keys: HashMap<Uuid, Key>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("unlocked", &self.is_unlocked()).finish()
    }
}

impl Store {
    /// Creates a new database at `path` and returns it unlocked.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Store> {
        if path.exists() {
            return Err(Error::Invalid(format!("{} already exists", path.display())));
        }
        let conn = Connection::open(path)?;
        migrate(&conn, path)?;
        let (header, account) = crypto::create_header(password, kdf)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('header', ?1), ('check', ?2)",
            params![serde_json::to_vec(&header)?, crypto::seal(&account, b"lockbox", CHECK_AAD)],
        )?;
        Ok(Store { conn, header, account: Some(account), vault_keys: HashMap::new() })
    }

    /// Opens an existing database, locked.
    pub fn open(path: &Path) -> Result<Store> {
        if !path.exists() {
            return Err(Error::NotFound(path.display().to_string()));
        }
        let conn = Connection::open(path)?;
        migrate(&conn, path)?;
        let raw: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key = 'header'", [], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::Invalid("missing header".into()))?;
        let header = serde_json::from_slice(&raw)?;
        Ok(Store { conn, header, account: None, vault_keys: HashMap::new() })
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let account = crypto::unlock(&self.header, password)?;
        self.load_keys(account)
    }

    /// Unlocks with an account key kept elsewhere (macOS Keychain behind Touch ID).
    pub fn unlock_with_key(&mut self, account: Key) -> Result<()> {
        let check: Vec<u8> =
            self.conn.query_row("SELECT value FROM meta WHERE key = 'check'", [], |r| r.get(0))?;
        crypto::open(&account, &check, CHECK_AAD).map_err(|_| Error::WrongPassword)?;
        self.load_keys(account)
    }

    pub fn lock(&mut self) {
        self.account = None;
        self.vault_keys.clear();
    }

    pub fn is_unlocked(&self) -> bool {
        self.account.is_some()
    }

    pub fn account_key(&self) -> Result<&Key> {
        self.account.as_ref().ok_or(Error::Locked)
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<()> {
        let header = crypto::change_password(&self.header, old, new, self.header.kdf)?;
        self.conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'header'",
            params![serde_json::to_vec(&header)?],
        )?;
        self.header = header;
        Ok(())
    }

    pub fn create_vault(&mut self, name: &str) -> Result<VaultInfo> {
        let account = self.account.as_ref().ok_or(Error::Locked)?;
        let info = VaultInfo { id: Uuid::new_v4(), name: name.to_owned() };
        let key = Key::random();
        insert_vault(&self.conn, account, &info, &key)?;
        self.vault_keys.insert(info.id, key);
        Ok(info)
    }

    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let account = self.account_key()?;
        let mut stmt =
            self.conn.prepare("SELECT id, meta FROM vaults WHERE deleted = 0 ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, meta) = row?;
            let id = parse_id(&id)?;
            let plain = crypto::open(account, &meta, &vault_meta_aad(id))?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok(out)
    }

    fn load_keys(&mut self, account: Key) -> Result<()> {
        let mut keys = HashMap::new();
        {
            let mut stmt = self.conn.prepare("SELECT id, wrapped_key FROM vaults")?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
            for row in rows {
                let (id, wrapped) = row?;
                let id = parse_id(&id)?;
                keys.insert(id, crypto::unwrap_vault_key(&account, id, &wrapped)?);
            }
        }
        self.vault_keys = keys;
        self.account = Some(account);
        Ok(())
    }
}

fn insert_vault(conn: &Connection, account: &Key, info: &VaultInfo, key: &Key) -> Result<()> {
    let meta = crypto::seal(account, &serde_json::to_vec(info)?, &vault_meta_aad(info.id));
    conn.execute(
        "INSERT INTO vaults (id, wrapped_key, meta) VALUES (?1, ?2, ?3)",
        params![info.id.to_string(), crypto::wrap_vault_key(account, info.id, key), meta],
    )?;
    Ok(())
}

fn vault_meta_aad(id: Uuid) -> Vec<u8> {
    let mut aad = VAULT_META_AAD.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn parse_id(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| Error::Invalid(format!("bad id {s}: {e}")))
}

fn migrate(conn: &Connection, path: &Path) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == DB_VERSION {
        return Ok(());
    }
    if version > DB_VERSION {
        return Err(Error::Invalid(format!(
            "database version {version} is newer than this app supports ({DB_VERSION})"
        )));
    }
    if version > 0 {
        backup(path, version)?;
    }
    conn.execute_batch(SCHEMA_V1)?;
    conn.pragma_update(None, "user_version", DB_VERSION)?;
    Ok(())
}

/// Copies the database next to itself before a schema migration.
pub fn backup(path: &Path, from_version: i64) -> Result<PathBuf> {
    let copy = path.with_extension(format!("db.bak-v{from_version}"));
    std::fs::copy(path, &copy)?;
    Ok(copy)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core store`
Expected: 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add SQLite store with lock/unlock, password change and vaults"
```

---

### Task 7: Store — items, damaged rows, tombstones

**Files:**
- Modify: `crates/lockbox-core/src/store/mod.rs`, `crates/lockbox-core/src/store/tests.rs`

- [ ] **Step 1: Write the failing tests** (append to `store/tests.rs`)

```rust
use crate::model::{Item, ItemKind};

pub(super) fn login(vault: Uuid, title: &str) -> Item {
    let mut item = Item::new(vault, ItemKind::Login, title, 1_000);
    item.set_password("hunter2", 1_000);
    item
}

fn revision(store: &Store, id: Uuid) -> i64 {
    store
        .conn
        .query_row("SELECT revision FROM items WHERE id = ?1", [id.to_string()], |r| r.get(0))
        .unwrap()
}

fn ok_titles(entries: Vec<ItemEntry>) -> Vec<String> {
    entries
        .into_iter()
        .map(|e| match e {
            ItemEntry::Ok(item) => item.title,
            ItemEntry::Damaged { .. } => "<damaged>".into(),
        })
        .collect()
}

#[test]
fn save_get_and_list_items() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let github = login(a.id, "GitHub");
    store.save_item(&github).unwrap();
    store.save_item(&login(b.id, "Bank")).unwrap();

    assert_eq!(store.get_item(github.id).unwrap(), github);
    assert_eq!(ok_titles(store.list_items(Some(a.id)).unwrap()), ["GitHub"]);
    assert_eq!(ok_titles(store.list_items(None).unwrap()), ["GitHub", "Bank"]);
}

#[test]
fn saving_again_bumps_revision() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let mut item = login(v.id, "GitHub");
    store.save_item(&item).unwrap();
    assert_eq!(revision(&store, item.id), 1);
    item.set_password("new", 2_000);
    store.save_item(&item).unwrap();
    assert_eq!(revision(&store, item.id), 2);
    assert_eq!(store.get_item(item.id).unwrap().password(), Some("new"));
}

#[test]
fn save_requires_unlock_and_known_vault() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    assert!(matches!(store.save_item(&login(Uuid::new_v4(), "x")), Err(Error::NotFound(_))));
    store.lock();
    assert!(matches!(store.save_item(&login(v.id, "x")), Err(Error::Locked)));
}

#[test]
fn delete_restore_and_purge() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "GitHub");
    store.save_item(&item).unwrap();

    store.delete_item(item.id, 10_000).unwrap();
    assert!(matches!(store.get_item(item.id), Err(Error::NotFound(_))));
    assert!(store.list_items(None).unwrap().is_empty());
    assert_eq!(ok_titles(store.deleted_items().unwrap()), ["GitHub"]);

    store.restore_item(item.id).unwrap();
    assert_eq!(store.get_item(item.id).unwrap().title, "GitHub");

    store.delete_item(item.id, 10_000).unwrap();
    assert_eq!(store.purge_expired(10_000 + DELETED_RETENTION_SECS - 1).unwrap(), 0);
    assert_eq!(store.purge_expired(10_000 + DELETED_RETENTION_SECS).unwrap(), 1);
    assert!(store.deleted_items().unwrap().is_empty());
    assert!(matches!(store.restore_item(item.id), Err(Error::NotFound(_))));
    // The tombstone row stays for future sync.
    let rows: i64 = store.conn.query_row("SELECT count(*) FROM items", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn delete_unknown_item_is_not_found() {
    let (_dir, _path, mut store) = new_store();
    assert!(matches!(store.delete_item(Uuid::new_v4(), 1), Err(Error::NotFound(_))));
}

#[test]
fn corrupted_row_is_reported_damaged_without_hiding_others() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let good = login(v.id, "Good");
    let bad = login(v.id, "Bad");
    store.save_item(&good).unwrap();
    store.save_item(&bad).unwrap();
    store
        .conn
        .execute("UPDATE items SET data = X'00112233' WHERE id = ?1", [bad.id.to_string()])
        .unwrap();

    let entries = store.list_items(None).unwrap();
    assert_eq!(entries[0], ItemEntry::Ok(good));
    assert_eq!(entries[1], ItemEntry::Damaged { id: bad.id, vault_id: v.id });
    assert!(matches!(store.get_item(bad.id), Err(Error::Decrypt)));
}

#[test]
fn ciphertext_swapped_between_items_does_not_decrypt() {
    let (_dir, _path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let a = login(v.id, "A");
    let b = login(v.id, "B");
    store.save_item(&a).unwrap();
    store.save_item(&b).unwrap();
    store
        .conn
        .execute(
            "UPDATE items SET data = (SELECT data FROM items WHERE id = ?1) WHERE id = ?2",
            [a.id.to_string(), b.id.to_string()],
        )
        .unwrap();
    assert!(matches!(store.get_item(b.id), Err(Error::Decrypt)));
}

#[test]
fn item_contents_are_not_stored_in_plaintext() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    store.save_item(&login(v.id, "VerySecretTitle")).unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    for needle in [&b"VerySecretTitle"[..], b"hunter2"] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core store`
Expected: compile errors (`save_item`, `ItemEntry`, `DELETED_RETENTION_SECS` … not found).

- [ ] **Step 3: Implement**

In `store/mod.rs`, change the model import to:
```rust
use crate::model::{Item, VaultInfo, SCHEMA_VERSION};
use zeroize::Zeroizing;
```

Add below the `CHECK_AAD`/`VAULT_META_AAD` constants:
```rust
/// Deleted items stay restorable for 30 days, then their data is purged.
pub const DELETED_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemEntry {
    Ok(Item),
    /// The row exists but does not decrypt; the rest of the vault still loads.
    Damaged { id: Uuid, vault_id: Uuid },
}
```

Add inside `impl Store` (after `vaults`):
```rust
    /// Inserts or updates an item; a later save of a deleted item undeletes it.
    pub fn save_item(&mut self, item: &Item) -> Result<()> {
        let key = self.vault_key(item.vault_id)?;
        upsert_item(&self.conn, key, item)
    }

    pub fn get_item(&self, id: Uuid) -> Result<Item> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT vault_id, data FROM items WHERE id = ?1 AND deleted_at IS NULL",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (vault_id, data) = row.ok_or_else(|| Error::NotFound(format!("item {id}")))?;
        self.decrypt_item(id, parse_id(&vault_id)?, &data)
    }

    /// Live items, in insertion order, optionally limited to one vault.
    pub fn list_items(&self, vault: Option<Uuid>) -> Result<Vec<ItemEntry>> {
        self.load_items(false, vault)
    }

    /// Items in "Recently Deleted" (deleted, not yet purged).
    pub fn deleted_items(&self) -> Result<Vec<ItemEntry>> {
        self.load_items(true, None)
    }

    pub fn delete_item(&mut self, id: Uuid, now: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE items SET deleted_at = ?2, revision = revision + 1
             WHERE id = ?1 AND deleted_at IS NULL",
            params![id.to_string(), now],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("item {id}")));
        }
        Ok(())
    }

    pub fn restore_item(&mut self, id: Uuid) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE items SET deleted_at = NULL, revision = revision + 1
             WHERE id = ?1 AND deleted_at IS NOT NULL AND length(data) > 0",
            [id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("deleted item {id}")));
        }
        Ok(())
    }

    /// Wipes data of items deleted at least 30 days ago; rows stay as tombstones.
    pub fn purge_expired(&mut self, now: i64) -> Result<usize> {
        let cutoff = now - DELETED_RETENTION_SECS;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE attachments SET data = X'', deleted = 1, revision = revision + 1
             WHERE item_id IN (SELECT id FROM items
                               WHERE deleted_at IS NOT NULL AND deleted_at <= ?1 AND length(data) > 0)",
            [cutoff],
        )?;
        let n = tx.execute(
            "UPDATE items SET data = X'', revision = revision + 1
             WHERE deleted_at IS NOT NULL AND deleted_at <= ?1 AND length(data) > 0",
            [cutoff],
        )?;
        tx.commit()?;
        Ok(n)
    }

    fn load_items(&self, deleted: bool, vault: Option<Uuid>) -> Result<Vec<ItemEntry>> {
        self.account_key()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, vault_id, data FROM items
             WHERE ((?1 = 0 AND deleted_at IS NULL)
                 OR (?1 = 1 AND deleted_at IS NOT NULL AND length(data) > 0))
               AND (?2 IS NULL OR vault_id = ?2)
             ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![deleted as i64, vault.map(|v| v.to_string())], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, vault_id, data) = row?;
            let (id, vault_id) = (parse_id(&id)?, parse_id(&vault_id)?);
            out.push(match self.decrypt_item(id, vault_id, &data) {
                Ok(item) => ItemEntry::Ok(item),
                Err(_) => ItemEntry::Damaged { id, vault_id },
            });
        }
        Ok(out)
    }

    fn decrypt_item(&self, id: Uuid, vault_id: Uuid, data: &[u8]) -> Result<Item> {
        let key = self.vault_key(vault_id)?;
        let plain = crypto::open(key, data, &crypto::item_aad(vault_id, id, SCHEMA_VERSION))?;
        Ok(serde_json::from_slice(&plain)?)
    }

    fn vault_key(&self, vault_id: Uuid) -> Result<&Key> {
        if self.account.is_none() {
            return Err(Error::Locked);
        }
        self.vault_keys.get(&vault_id).ok_or_else(|| Error::NotFound(format!("vault {vault_id}")))
    }
```

Add as a free function (next to `insert_vault`):
```rust
fn upsert_item(conn: &Connection, key: &Key, item: &Item) -> Result<()> {
    let plain = Zeroizing::new(serde_json::to_vec(item)?);
    let data = crypto::seal(key, &plain, &crypto::item_aad(item.vault_id, item.id, SCHEMA_VERSION));
    conn.execute(
        "INSERT INTO items (id, vault_id, data, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET
             vault_id = excluded.vault_id, data = excluded.data,
             updated_at = excluded.updated_at, revision = items.revision + 1, deleted_at = NULL",
        params![item.id.to_string(), item.vault_id.to_string(), data, item.updated_at],
    )?;
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core store`
Expected: 17 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add encrypted items with damaged-row handling and tombstones"
```

---

### Task 8: Store — attachments and moving items between vaults

**Files:**
- Modify: `crates/lockbox-core/src/store/mod.rs`, `crates/lockbox-core/src/store/tests.rs`

- [ ] **Step 1: Write the failing tests** (append to `store/tests.rs`)

```rust
#[test]
fn attachments_round_trip_and_are_listed_on_the_item() {
    let (_dir, path, mut store) = new_store();
    let v = store.create_vault("A").unwrap();
    let item = login(v.id, "Passport");
    store.save_item(&item).unwrap();

    let att = store.add_attachment(item.id, "scan.pdf", b"%PDF-SECRET", 5_000).unwrap();
    assert_eq!(att.name, "scan.pdf");
    assert_eq!(att.size, 11);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"%PDF-SECRET");
    let saved = store.get_item(item.id).unwrap();
    assert_eq!(saved.attachments, vec![att]);
    assert_eq!(saved.updated_at, 5_000);
    drop(store);

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(11).any(|w| w == b"%PDF-SECRET"));
}

#[test]
fn unknown_attachment_is_not_found() {
    let (_dir, _path, store) = new_store();
    assert!(matches!(store.get_attachment(Uuid::new_v4()), Err(Error::NotFound(_))));
}

#[test]
fn moving_an_item_to_another_vault_keeps_attachments_readable() {
    let (_dir, _path, mut store) = new_store();
    let a = store.create_vault("A").unwrap();
    let b = store.create_vault("B").unwrap();
    let item = login(a.id, "Passport");
    store.save_item(&item).unwrap();
    let att = store.add_attachment(item.id, "scan.pdf", b"bytes", 5_000).unwrap();

    let mut moved = store.get_item(item.id).unwrap();
    moved.vault_id = b.id;
    store.save_item(&moved).unwrap();

    assert_eq!(store.get_item(item.id).unwrap().vault_id, b.id);
    assert_eq!(&*store.get_attachment(att.id).unwrap(), b"bytes");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core store`
Expected: compile errors (`add_attachment`, `get_attachment` not found).

- [ ] **Step 3: Implement**

Change the model import in `store/mod.rs` to:
```rust
use crate::model::{AttachmentRef, Item, VaultInfo, SCHEMA_VERSION};
```

Replace `save_item` with a version that re-encrypts attachments on a vault move:
```rust
    /// Inserts or updates an item; a later save of a deleted item undeletes it.
    /// Moving an item to another vault re-encrypts its attachments with the new vault key.
    pub fn save_item(&mut self, item: &Item) -> Result<()> {
        let new_key = self.vault_key(item.vault_id)?;
        let tx = self.conn.unchecked_transaction()?;
        let old_vault: Option<String> = tx
            .query_row("SELECT vault_id FROM items WHERE id = ?1", [item.id.to_string()], |r| r.get(0))
            .optional()?;
        if let Some(old_vault) = old_vault {
            let old_vault = parse_id(&old_vault)?;
            if old_vault != item.vault_id {
                let old_key = self.vault_key(old_vault)?;
                reencrypt_attachments(&tx, item.id, (old_vault, old_key), (item.vault_id, new_key))?;
            }
        }
        upsert_item(&tx, new_key, item)?;
        tx.commit()?;
        Ok(())
    }
```

Add inside `impl Store`:
```rust
    pub fn add_attachment(
        &mut self,
        item_id: Uuid,
        name: &str,
        bytes: &[u8],
        now: i64,
    ) -> Result<AttachmentRef> {
        let mut item = self.get_item(item_id)?;
        let key = self.vault_key(item.vault_id)?;
        let att = AttachmentRef { id: Uuid::new_v4(), name: name.to_owned(), size: bytes.len() as u64 };
        let tx = self.conn.unchecked_transaction()?;
        insert_attachment(&tx, key, &item, &att, bytes)?;
        item.attachments.push(att.clone());
        item.updated_at = now;
        upsert_item(&tx, key, &item)?;
        tx.commit()?;
        Ok(att)
    }

    pub fn get_attachment(&self, id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
        let row: Option<(Vec<u8>, String, String)> = self
            .conn
            .query_row(
                "SELECT a.data, a.item_id, i.vault_id FROM attachments a
                 JOIN items i ON i.id = a.item_id
                 WHERE a.id = ?1 AND a.deleted = 0",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (data, item_id, vault_id) = row.ok_or_else(|| Error::NotFound(format!("attachment {id}")))?;
        let (item_id, vault_id) = (parse_id(&item_id)?, parse_id(&vault_id)?);
        crypto::open(self.vault_key(vault_id)?, &data, &crypto::attachment_aad(vault_id, item_id, id))
    }
```

Add free functions:
```rust
fn insert_attachment(
    conn: &Connection,
    key: &Key,
    item: &Item,
    att: &AttachmentRef,
    bytes: &[u8],
) -> Result<()> {
    let data = crypto::seal(key, bytes, &crypto::attachment_aad(item.vault_id, item.id, att.id));
    conn.execute(
        "INSERT INTO attachments (id, item_id, data) VALUES (?1, ?2, ?3)",
        params![att.id.to_string(), item.id.to_string(), data],
    )?;
    Ok(())
}

fn reencrypt_attachments(
    conn: &Connection,
    item_id: Uuid,
    (old_vault, old_key): (Uuid, &Key),
    (new_vault, new_key): (Uuid, &Key),
) -> Result<()> {
    let rows: Vec<(String, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT id, data FROM attachments WHERE item_id = ?1 AND deleted = 0",
        )?;
        let mapped = stmt.query_map([item_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        mapped.collect::<rusqlite::Result<_>>()?
    };
    for (id, data) in rows {
        let att_id = parse_id(&id)?;
        let plain = crypto::open(old_key, &data, &crypto::attachment_aad(old_vault, item_id, att_id))?;
        let sealed = crypto::seal(new_key, &plain, &crypto::attachment_aad(new_vault, item_id, att_id));
        conn.execute(
            "UPDATE attachments SET data = ?2, revision = revision + 1 WHERE id = ?1",
            params![id, sealed],
        )?;
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core store`
Expected: 20 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add encrypted attachments and vault moves"
```

---

### Task 9: TOTP (RFC 6238) and otpauth parsing

**Files:**
- Create: `crates/lockbox-core/src/totp.rs`
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod totp;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/totp.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn rfc(alg: Algorithm, secret: &[u8]) -> Totp {
        Totp { secret: secret.to_vec(), algorithm: alg, digits: 8, period: 30, issuer: None, account: None }
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = rfc(Algorithm::Sha1, b"12345678901234567890");
        let sha256 = rfc(Algorithm::Sha256, b"12345678901234567890123456789012");
        let sha512 = rfc(
            Algorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234",
        );
        let cases: [(&Totp, u64, &str); 10] = [
            (&sha1, 59, "94287082"),
            (&sha1, 1111111109, "07081804"),
            (&sha1, 1111111111, "14050471"),
            (&sha1, 1234567890, "89005924"),
            (&sha1, 2000000000, "69279037"),
            (&sha1, 20000000000, "65353130"),
            (&sha256, 59, "46119246"),
            (&sha256, 1111111109, "68084774"),
            (&sha512, 59, "90693936"),
            (&sha512, 1111111109, "25091201"),
        ];
        for (totp, t, expected) in cases {
            assert_eq!(totp.code_at(t), expected, "{:?} at {t}", totp.algorithm);
        }
    }

    #[test]
    fn six_digit_code_is_last_six_of_truncation() {
        let mut totp = rfc(Algorithm::Sha1, b"12345678901234567890");
        totp.digits = 6;
        assert_eq!(totp.code_at(59), "287082");
    }

    #[test]
    fn seconds_left_in_period() {
        let totp = rfc(Algorithm::Sha1, b"x");
        assert_eq!(totp.seconds_left(0), 30);
        assert_eq!(totp.seconds_left(59), 1);
        assert_eq!(totp.seconds_left(60), 30);
    }

    #[test]
    fn parses_google_style_uri() {
        let t = Totp::parse(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(t.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(t.issuer.as_deref(), Some("Example"));
        assert_eq!(t.account.as_deref(), Some("alice@google.com"));
        assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha1, 6, 30));
    }

    #[test]
    fn parses_uri_parameters_and_encoded_label() {
        let t = Totp::parse(
            "otpauth://totp/ACME%20Co:john%40example.com?secret=jbswy3dpehpk3pxp&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("john@example.com"));
        assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha256, 8, 60));
    }

    #[test]
    fn parses_bare_secret_with_spaces_and_lowercase() {
        let t = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(t.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(t.issuer, None);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "not base32 !!!",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ] {
            assert!(matches!(Totp::parse(bad), Err(Error::Invalid(_))), "{bad:?} should fail");
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core totp`
Expected: compile errors (`Totp` not found).

- [ ] **Step 3: Implement** (prepend to `totp.rs`)

```rust
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Totp {
    /// Accepts an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(input: &str) -> Result<Totp> {
        let s = input.trim();
        if s.to_ascii_lowercase().starts_with("otpauth://") {
            parse_uri(s)
        } else {
            Ok(Totp {
                secret: decode_base32(s)?,
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                account: None,
            })
        }
    }

    pub fn code_at(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let hash = hmac(self.algorithm, &self.secret, &counter);
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    pub fn seconds_left(&self, unix: u64) -> u64 {
        self.period - unix % self.period
    }
}

fn hmac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    const ANY_KEY: &str = "HMAC accepts keys of any length";
    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if clean.is_empty() {
        return Err(Error::Invalid("empty TOTP secret".into()));
    }
    // Authenticator apps ignore non-zero trailing bits; so do we.
    let mut spec = data_encoding::BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    let encoding = spec.encoding().expect("valid base32 spec");
    encoding
        .decode(clean.as_bytes())
        .map_err(|e| Error::Invalid(format!("TOTP secret is not base32: {e}")))
}

fn parse_uri(s: &str) -> Result<Totp> {
    let invalid = |msg: &str| Error::Invalid(format!("otpauth URI: {msg}"));
    let url = url::Url::parse(s).map_err(|e| invalid(&e.to_string()))?;
    if url.host_str().map(|h| h.to_ascii_lowercase()).as_deref() != Some("totp") {
        return Err(invalid("only totp is supported"));
    }
    let label = percent_decode_str(url.path().trim_start_matches('/')).decode_utf8_lossy().into_owned();
    let (issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if label.is_empty() => (None, None),
        None => (None, Some(label)),
    };
    let mut totp =
        Totp { secret: Vec::new(), algorithm: Algorithm::Sha1, digits: 6, period: 30, issuer, account };
    let mut secret = None;
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_base32(&value)?),
            "algorithm" => {
                totp.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => return Err(invalid(&format!("unsupported algorithm {other}"))),
                }
            }
            "digits" => totp.digits = value.parse().map_err(|_| invalid("bad digits"))?,
            "period" => totp.period = value.parse().map_err(|_| invalid("bad period"))?,
            "issuer" => totp.issuer = Some(value.into_owned()),
            _ => {}
        }
    }
    totp.secret = secret.ok_or_else(|| invalid("missing secret"))?;
    if !(6..=8).contains(&totp.digits) || totp.period == 0 {
        return Err(invalid("digits must be 6-8 and period above 0"));
    }
    Ok(totp)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core totp`
Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add RFC 6238 TOTP with otpauth parsing"
```

---

### Task 10: Password and passphrase generator

**Files:**
- Create: `crates/lockbox-core/assets/eff_large_wordlist.txt`, `crates/lockbox-core/src/wordlist.rs`, `crates/lockbox-core/src/generator.rs`
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod generator;` and `mod wordlist;`)

- [ ] **Step 1: Download the EFF wordlist**

```bash
mkdir -p crates/lockbox-core/assets
curl -fsSL https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt -o crates/lockbox-core/assets/eff_large_wordlist.txt
wc -l crates/lockbox-core/assets/eff_large_wordlist.txt
```
Expected: `7776`. First line `11111	abacus`, last line `66666	zoom`.

- [ ] **Step 2: Write the failing tests**

`crates/lockbox-core/src/wordlist.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_all_eff_words() {
        let w = words();
        assert_eq!(w.len(), 7776);
        assert_eq!(w[0], "abacus");
        assert_eq!(w[7775], "zoom");
    }
}
```

`crates/lockbox-core/src/generator.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn default_password_has_every_class() {
        for _ in 0..200 {
            let p = password(&PasswordOptions::default()).unwrap();
            assert_eq!(p.chars().count(), 20);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn respects_disabled_classes_and_ambiguous_filter() {
        let opts = PasswordOptions {
            length: 64,
            symbols: false,
            uppercase: false,
            avoid_ambiguous: true,
            ..PasswordOptions::default()
        };
        for _ in 0..100 {
            let p = password(&opts).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rejects_bad_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert!(matches!(password(&none), Err(Error::Invalid(_))));
        for length in [7, 101] {
            let opts = PasswordOptions { length, ..PasswordOptions::default() };
            assert!(matches!(password(&opts), Err(Error::Invalid(_))));
        }
    }

    /// Smoke test against modulo bias: 16000 digits, each should appear ~1600 times.
    #[test]
    fn digits_are_roughly_uniform() {
        let opts = PasswordOptions {
            length: 8,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        let mut counts = [0u32; 10];
        for _ in 0..2000 {
            for c in password(&opts).unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        for (digit, n) in counts.iter().enumerate() {
            assert!((1400..=1800).contains(n), "digit {digit} appeared {n} times");
        }
    }

    #[test]
    fn passphrase_uses_wordlist_and_separator() {
        // EFF words may contain '-', so split on a separator that never appears in them.
        let opts = PassphraseOptions { words: 5, separator: " ".into(), capitalize: false, include_number: false };
        let p = passphrase(&opts).unwrap();
        let parts: Vec<_> = p.split(' ').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| crate::wordlist::words().contains(w)));
    }

    #[test]
    fn passphrase_capitalizes_and_adds_one_digit() {
        let opts = PassphraseOptions { words: 4, separator: ".".into(), capitalize: true, include_number: true };
        let p = passphrase(&opts).unwrap();
        let parts: Vec<_> = p.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);
    }

    #[test]
    fn passphrase_word_count_bounds() {
        for words in [2, 11] {
            let opts = PassphraseOptions { words, ..PassphraseOptions::default() };
            assert!(matches!(passphrase(&opts), Err(Error::Invalid(_))));
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p lockbox-core generator wordlist`
Expected: compile errors (`words`, `password`, … not found). (If cargo rejects two filters, run `cargo test -p lockbox-core` and look for the same errors.)

- [ ] **Step 4: Implement the wordlist** (prepend to `wordlist.rs`)

```rust
use std::sync::OnceLock;

static RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// The EFF long wordlist (7776 words), parsed once.
pub fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| RAW.lines().filter_map(|line| line.split_whitespace().nth(1)).collect())
}
```

- [ ] **Step 5: Implement the generator** (prepend to `generator.rs`)

```rust
use rand::{rngs::OsRng, seq::SliceRandom, Rng};

use crate::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self { words: 5, separator: "-".into(), capitalize: false, include_number: false }
    }
}

/// Random password with at least one character from every enabled class.
pub fn password(opts: &PasswordOptions) -> Result<String> {
    if !(8..=100).contains(&opts.length) {
        return Err(Error::Invalid("password length must be 8-100".into()));
    }
    let classes: Vec<Vec<char>> = [
        (opts.lowercase, LOWER),
        (opts.uppercase, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| set.chars().filter(|c| !(opts.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect())
    .collect();
    if classes.is_empty() {
        return Err(Error::Invalid("enable at least one character set".into()));
    }
    let all: Vec<char> = classes.concat();
    let mut rng = OsRng;
    let mut out: Vec<char> = classes.iter().map(|set| *set.choose(&mut rng).expect("non-empty set")).collect();
    while out.len() < opts.length {
        out.push(*all.choose(&mut rng).expect("non-empty set"));
    }
    out.shuffle(&mut rng);
    Ok(out.into_iter().collect())
}

/// Random words from the EFF long wordlist.
pub fn passphrase(opts: &PassphraseOptions) -> Result<String> {
    if !(3..=10).contains(&opts.words) {
        return Err(Error::Invalid("passphrase must have 3-10 words".into()));
    }
    let words = crate::wordlist::words();
    let mut rng = OsRng;
    let mut parts: Vec<String> = (0..opts.words)
        .map(|_| {
            let word = *words.choose(&mut rng).expect("wordlist is not empty");
            if opts.capitalize { capitalize(word) } else { word.to_owned() }
        })
        .collect();
    if opts.include_number {
        let i = rng.gen_range(0..parts.len());
        let digit = char::from(b'0' + rng.gen_range(0..10u8));
        parts[i].push(digit);
    }
    Ok(parts.join(&opts.separator))
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p lockbox-core`
Expected: all tests pass, including 1 wordlist + 7 generator tests.

- [ ] **Step 7: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add password and EFF passphrase generator"
```

---

### Task 11: Import types and 1Password CSV

**Files:**
- Create: `crates/lockbox-core/src/import/mod.rs`, `crates/lockbox-core/src/import/csv.rs`
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod import;`)

- [ ] **Step 1: Write the import types** (no behaviour, so no test of their own)

`crates/lockbox-core/src/import/mod.rs`:
```rust
//! Parsing other managers' exports into an [`ImportPlan`] the user previews
//! before `Store::apply_import` writes it in one transaction.

pub mod csv;
pub mod onepux;

use crate::model::Item;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImportPlan {
    pub vaults: Vec<ImportedVault>,
    pub skipped: Vec<Skipped>,
}

impl ImportPlan {
    pub fn item_count(&self) -> usize {
        self.vaults.iter().map(|v| v.items.len()).sum()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImportedVault {
    pub name: String,
    pub items: Vec<ImportedItem>,
}

/// `item.id` and `item.vault_id` are placeholders; `apply_import` assigns real ones.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedItem {
    pub item: Item,
    /// (file name, bytes)
    pub attachments: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub vaults: usize,
    pub items: usize,
    pub attachments: usize,
}
```

Create `crates/lockbox-core/src/import/onepux.rs` with a stub so the module compiles (Task 12 replaces it):
```rust
//! 1Password `.1pux` import (Task 12).
```

- [ ] **Step 2: Write the failing tests**

`crates/lockbox-core/src/import/csv.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, ItemKind};
    use crate::Error;

    const ONEPASSWORD_CSV: &str = "\
Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
GitHub,https://github.com,ivan,s3cret,otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP,true,false,\"dev,work\",main account
Wi-Fi,,,,,false,false,,\"ssid: home
pass: hunter2\"
";

    #[test]
    fn parses_1password_csv() {
        let plan = parse(ONEPASSWORD_CSV, "Imported", 42).unwrap();
        assert_eq!(plan.vaults.len(), 1);
        assert_eq!(plan.vaults[0].name, "Imported");
        assert_eq!(plan.item_count(), 2);

        let github = &plan.vaults[0].items[0].item;
        assert_eq!(github.kind, ItemKind::Login);
        assert_eq!(github.title, "GitHub");
        assert_eq!(github.urls, ["https://github.com"]);
        assert_eq!(github.username(), Some("ivan"));
        assert_eq!(github.password(), Some("s3cret"));
        assert_eq!(github.totp(), Some("otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP"));
        assert!(github.favorite);
        assert_eq!(github.tags, ["dev", "work"]);
        assert_eq!(github.notes, "main account");
        assert_eq!(github.created_at, 42);

        let wifi = &plan.vaults[0].items[1].item;
        assert_eq!(wifi.kind, ItemKind::SecureNote);
        assert_eq!(wifi.notes, "ssid: home\npass: hunter2");
        assert!(wifi.fields.is_empty());
    }

    #[test]
    fn accepts_other_common_header_names() {
        let csv = "name,login_uri,login_username,login_password\nBank,https://bank.example,me,pw\n";
        let item = &parse(csv, "Imported", 0).unwrap().vaults[0].items[0].item;
        assert_eq!(item.title, "Bank");
        assert_eq!(item.urls, ["https://bank.example"]);
        assert_eq!(item.username(), Some("me"));
        assert_eq!(item.password(), Some("pw"));
    }

    #[test]
    fn title_falls_back_to_url() {
        let csv = "url,password\nhttps://x.example,pw\n";
        assert_eq!(parse(csv, "I", 0).unwrap().vaults[0].items[0].item.title, "https://x.example");
    }

    #[test]
    fn rejects_unrecognized_headers() {
        assert!(matches!(parse("a,b\n1,2\n", "I", 0), Err(Error::Invalid(_))));
    }

    #[test]
    fn otp_field_is_a_totp_field() {
        let item = &parse(ONEPASSWORD_CSV, "I", 0).unwrap().vaults[0].items[0].item;
        assert!(item.fields.iter().any(|f| matches!(f.value, FieldValue::Totp(_))));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p lockbox-core import::csv`
Expected: compile error (`parse` not found).

- [ ] **Step 4: Implement** (prepend to `import/csv.rs`)

```rust
//! CSV export of 1Password (and other managers with similar headers).

use uuid::Uuid;

use super::{ImportPlan, ImportedItem, ImportedVault};
use crate::model::{Field, FieldValue, Item, ItemKind, Purpose};
use crate::{Error, Result};

pub fn parse(text: &str, vault_name: &str, now: i64) -> Result<ImportPlan> {
    let csv_err = |e: ::csv::Error| Error::Invalid(format!("CSV: {e}"));
    let mut reader = ::csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> =
        reader.headers().map_err(csv_err)?.iter().map(|h| h.trim().to_lowercase()).collect();
    let col = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let c_title = col(&["title", "name"]);
    let c_url = col(&["url", "website", "login_uri"]);
    let c_user = col(&["username", "login", "login_username"]);
    let c_pass = col(&["password", "login_password"]);
    let c_otp = col(&["otpauth", "otp", "totp", "one-time password", "login_totp"]);
    let c_notes = col(&["notes", "note"]);
    let c_tags = col(&["tags"]);
    let c_fav = col(&["favorite"]);
    if c_title.is_none() && c_url.is_none() && c_pass.is_none() {
        return Err(Error::Invalid(
            "unrecognized CSV: expected a header row with title/url/username/password columns".into(),
        ));
    }

    let mut vault = ImportedVault { name: vault_name.to_owned(), items: Vec::new() };
    for record in reader.records() {
        let record = record.map_err(csv_err)?;
        let get = |c: Option<usize>| c.and_then(|i| record.get(i)).map(str::trim).unwrap_or("");
        let (url, user, pass) = (get(c_url), get(c_user), get(c_pass));
        let kind = if url.is_empty() && user.is_empty() && pass.is_empty() {
            ItemKind::SecureNote
        } else {
            ItemKind::Login
        };
        let title = if get(c_title).is_empty() { url } else { get(c_title) };
        let mut item = Item::new(Uuid::nil(), kind, title, now);
        if !url.is_empty() {
            item.urls.push(url.to_owned());
        }
        if !user.is_empty() {
            item.fields.push(Field {
                id: "username".into(),
                label: "username".into(),
                value: FieldValue::Text(user.to_owned()),
                purpose: Some(Purpose::Username),
            });
        }
        if !pass.is_empty() {
            item.set_password(pass, now);
        }
        let otp = get(c_otp);
        if !otp.is_empty() {
            item.fields.push(Field {
                id: "one-time-password".into(),
                label: "one-time password".into(),
                value: FieldValue::Totp(otp.to_owned()),
                purpose: None,
            });
        }
        item.notes = get(c_notes).to_owned();
        item.tags = get(c_tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        item.favorite = matches!(get(c_fav).to_lowercase().as_str(), "true" | "1" | "yes");
        vault.items.push(ImportedItem { item, attachments: Vec::new() });
    }
    Ok(ImportPlan { vaults: vec![vault], skipped: Vec::new() })
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p lockbox-core import::csv`
Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add import plan types and 1Password CSV import"
```

---

### Task 12: 1Password `.1pux` import

**Files:**
- Create: `crates/lockbox-core/tests/fixtures/export.data.json`, `crates/lockbox-core/tests/import_1pux.rs`
- Modify: `crates/lockbox-core/src/import/onepux.rs`

- [ ] **Step 1: Create the fixture** — a hand-built `export.data` covering every mapped category

`crates/lockbox-core/tests/fixtures/export.data.json`:
```json
{
  "accounts": [
    {
      "attrs": { "accountName": "Ivan", "name": "Ivan Kostin", "email": "ivan@example.com", "uuid": "ACCOUNT1", "domain": "https://my.1password.com/" },
      "vaults": [
        {
          "attrs": { "uuid": "VAULT1", "desc": "", "avatar": "", "name": "Personal", "type": "P" },
          "items": [
            {
              "uuid": "login1", "favIndex": 1, "createdAt": 1700000000, "updatedAt": 1700000500,
              "state": "active", "categoryUuid": "001",
              "details": {
                "loginFields": [
                  { "value": "ivan", "id": "", "name": "username", "fieldType": "T", "designation": "username" },
                  { "value": "s3cret-Pass!", "id": "", "name": "password", "fieldType": "P", "designation": "password" },
                  { "value": "✓", "id": "", "name": "remember", "fieldType": "C" }
                ],
                "notesPlain": "work account",
                "sections": [
                  {
                    "title": "", "name": "add more",
                    "fields": [
                      { "title": "one-time password", "id": "TOTP_1", "value": { "totp": "otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" } },
                      { "title": "recovery code", "id": "rc", "value": { "concealed": "abcd-efgh" } },
                      { "title": "empty", "id": "e", "value": { "string": "" } }
                    ]
                  }
                ],
                "passwordHistory": [ { "value": "old-pass", "time": 1690000000 } ]
              },
              "overview": {
                "subtitle": "ivan",
                "urls": [ { "label": "website", "url": "https://github.com/login" } ],
                "title": "GitHub", "url": "https://github.com/login", "tags": [ "dev", "work" ]
              }
            },
            {
              "uuid": "card1", "favIndex": 0, "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "002",
              "details": {
                "loginFields": [], "notesPlain": "",
                "sections": [
                  {
                    "title": "", "name": "",
                    "fields": [
                      { "title": "cardholder name", "id": "cardholder", "value": { "string": "IVAN KOSTIN" } },
                      { "title": "type", "id": "type", "value": { "creditCardType": "visa" } },
                      { "title": "number", "id": "ccnum", "value": { "creditCardNumber": "4111111111111111" } },
                      { "title": "verification number", "id": "cvv", "value": { "concealed": "123" } },
                      { "title": "expiry date", "id": "expiry", "value": { "monthYear": 202712 } }
                    ]
                  }
                ],
                "passwordHistory": []
              },
              "overview": { "subtitle": "4111 ****", "title": "Visa", "url": "", "tags": [] }
            },
            {
              "uuid": "note1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "003",
              "details": { "notesPlain": "wifi: hunter2", "sections": [] },
              "overview": { "title": "Home Wi-Fi" }
            },
            {
              "uuid": "pw1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "005",
              "details": { "password": "pw-only-123", "notesPlain": "" },
              "overview": { "title": "Router admin" }
            },
            {
              "uuid": "api1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "112",
              "details": {
                "sections": [
                  {
                    "title": "", "name": "",
                    "fields": [
                      { "title": "credential", "id": "credential", "value": { "concealed": "sk-live-123" } },
                      { "title": "hostname", "id": "hostname", "value": { "string": "api.example.com" } }
                    ]
                  }
                ]
              },
              "overview": { "title": "Stripe API" }
            },
            {
              "uuid": "doc1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "006",
              "details": { "documentAttributes": { "fileName": "passport.pdf", "documentId": "DOC123", "decryptedSize": 8 } },
              "overview": { "title": "Passport scan" }
            },
            {
              "uuid": "trash1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "trashed", "categoryUuid": "001",
              "details": {},
              "overview": { "title": "Old login" }
            }
          ]
        },
        {
          "attrs": { "uuid": "VAULT2", "desc": "", "avatar": "", "name": "Datagile", "type": "E" },
          "items": [
            {
              "uuid": "id1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "active", "categoryUuid": "004",
              "details": {
                "sections": [
                  {
                    "title": "Identification", "name": "name",
                    "fields": [
                      { "title": "first name", "id": "firstname", "value": { "string": "Ivan" } },
                      { "title": "birth date", "id": "birthdate", "value": { "date": 631152000 } }
                    ]
                  },
                  {
                    "title": "Address", "name": "address",
                    "fields": [
                      { "title": "address", "id": "address", "value": { "address": { "street": "Main st 1", "city": "Hanoi", "country": "vn", "zip": "", "state": "" } } }
                    ]
                  },
                  {
                    "title": "Internet Details", "name": "internet",
                    "fields": [
                      { "title": "email", "id": "email", "value": { "email": { "email_address": "ivan@datagile.example", "provider": null } } },
                      { "title": "phone", "id": "cell", "value": { "phone": "+84 123" } }
                    ]
                  }
                ]
              },
              "overview": { "title": "Ivan at work" }
            },
            {
              "uuid": "srv1", "createdAt": 1700000000, "updatedAt": 1700000000,
              "state": "archived", "categoryUuid": "110",
              "details": {
                "loginFields": [],
                "sections": [
                  {
                    "title": "", "name": "",
                    "fields": [
                      { "title": "URL", "id": "url", "value": { "url": "ssh://10.0.0.5" } },
                      { "title": "admin password", "id": "pw", "value": { "concealed": "root-pw" } }
                    ]
                  }
                ]
              },
              "overview": { "title": "Prod server" }
            }
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Write the failing integration test**

`crates/lockbox-core/tests/import_1pux.rs`:
```rust
use std::io::{Cursor, Write};

use lockbox_core::import::{onepux, ImportPlan};
use lockbox_core::model::{FieldValue, Item, ItemKind};
use lockbox_core::Error;
use zip::write::SimpleFileOptions;

const EXPORT_DATA: &str = include_str!("fixtures/export.data.json");
const NOW: i64 = 1_800_000_000;

fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        for (name, data) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    buf.into_inner()
}

fn full_export() -> Vec<u8> {
    build_zip(&[
        ("export.attributes", br#"{"version":3}"#),
        ("export.data", EXPORT_DATA.as_bytes()),
        ("files/DOC123__passport.pdf", b"%PDF-1.4"),
    ])
}

fn find<'a>(plan: &'a ImportPlan, title: &str) -> &'a Item {
    plan.vaults
        .iter()
        .flat_map(|v| v.items.iter())
        .map(|i| &i.item)
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn section_value<'a>(item: &'a Item, label: &str) -> &'a FieldValue {
    &item.sections.iter().flat_map(|s| s.fields.iter()).find(|f| f.label == label).unwrap().value
}

#[test]
fn imports_vaults_and_skips_trashed_items() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let vaults: Vec<_> = plan.vaults.iter().map(|v| (v.name.as_str(), v.items.len())).collect();
    assert_eq!(vaults, [("Personal", 6), ("Datagile", 2)]);
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].title, "Old login");
    assert!(plan.skipped[0].reason.contains("trashed"));
}

#[test]
fn imports_a_login_completely() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let github = find(&plan, "GitHub");
    assert_eq!(github.kind, ItemKind::Login);
    assert_eq!(github.username(), Some("ivan"));
    assert_eq!(github.password(), Some("s3cret-Pass!"));
    assert_eq!(github.fields.len(), 2, "checkbox login fields are dropped");
    assert_eq!(github.urls, ["https://github.com/login"]);
    assert_eq!(github.tags, ["dev", "work"]);
    assert!(github.favorite);
    assert_eq!(github.notes, "work account");
    assert_eq!(
        github.totp(),
        Some("otpauth://totp/GitHub:ivan?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    );
    assert_eq!(*section_value(github, "recovery code"), FieldValue::Concealed("abcd-efgh".into()));
    assert_eq!(github.sections[0].fields.len(), 2, "empty fields are dropped");
    assert_eq!(github.password_history[0].value, "old-pass");
    assert_eq!(github.password_history[0].changed_at, 1690000000);
    assert_eq!((github.created_at, github.updated_at), (1700000000, 1700000500));
}

#[test]
fn imports_other_categories() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();

    let card = find(&plan, "Visa");
    assert_eq!(card.kind, ItemKind::CreditCard);
    assert!(!card.favorite);
    assert_eq!(*section_value(card, "number"), FieldValue::Concealed("4111111111111111".into()));
    assert_eq!(*section_value(card, "expiry date"), FieldValue::MonthYear(202712));
    assert_eq!(*section_value(card, "type"), FieldValue::Text("visa".into()));

    assert_eq!(find(&plan, "Home Wi-Fi").kind, ItemKind::SecureNote);
    assert_eq!(find(&plan, "Home Wi-Fi").notes, "wifi: hunter2");

    let router = find(&plan, "Router admin");
    assert_eq!(router.kind, ItemKind::Password);
    assert_eq!(router.password(), Some("pw-only-123"));

    let api = find(&plan, "Stripe API");
    assert_eq!(api.kind, ItemKind::ApiCredential);
    assert_eq!(*section_value(api, "credential"), FieldValue::Concealed("sk-live-123".into()));

    let identity = find(&plan, "Ivan at work");
    assert_eq!(identity.kind, ItemKind::Identity);
    assert_eq!(*section_value(identity, "email"), FieldValue::Email("ivan@datagile.example".into()));
    assert_eq!(*section_value(identity, "birth date"), FieldValue::Date(631152000));
    assert_eq!(*section_value(identity, "address"), FieldValue::Text("Main st 1, Hanoi, vn".into()));
    assert_eq!(*section_value(identity, "phone"), FieldValue::Phone("+84 123".into()));
    assert_eq!(identity.sections[0].title, "Identification");

    let server = find(&plan, "Prod server");
    assert_eq!(server.kind, ItemKind::SecureNote, "unknown categories become notes");
    assert_eq!(*section_value(server, "URL"), FieldValue::Url("ssh://10.0.0.5".into()));
    assert_eq!(*section_value(server, "admin password"), FieldValue::Concealed("root-pw".into()));
}

#[test]
fn imports_document_attachments() {
    let plan = onepux::parse(&full_export(), NOW).unwrap();
    let doc = plan.vaults[0].items.iter().find(|i| i.item.title == "Passport scan").unwrap();
    assert_eq!(doc.attachments, vec![("passport.pdf".to_string(), b"%PDF-1.4".to_vec())]);
}

#[test]
fn missing_attachment_is_reported_but_item_is_kept() {
    let zip = build_zip(&[("export.data", EXPORT_DATA.as_bytes())]);
    let plan = onepux::parse(&zip, NOW).unwrap();
    assert!(find(&plan, "Passport scan").attachments.is_empty());
    assert!(plan.skipped.iter().any(|s| s.title == "Passport scan / passport.pdf"));
}

#[test]
fn rejects_files_that_are_not_1pux() {
    assert!(matches!(onepux::parse(b"not a zip", NOW), Err(Error::Invalid(_))));
    let no_data = build_zip(&[("something.txt", b"x")]);
    assert!(matches!(onepux::parse(&no_data, NOW), Err(Error::Invalid(_))));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p lockbox-core --test import_1pux`
Expected: compile error (`onepux::parse` not found).

- [ ] **Step 4: Implement** (replace `import/onepux.rs`)

```rust
//! 1Password `.1pux` export: a zip with `export.data` (JSON) and `files/<documentId>__<fileName>`.

use std::io::{Cursor, Read, Seek};

use serde_json::Value;
use uuid::Uuid;
use zip::ZipArchive;

use super::{ImportPlan, ImportedItem, ImportedVault, Skipped};
use crate::model::{Field, FieldValue, HistoryEntry, Item, ItemKind, Purpose, Section};
use crate::{Error, Result};

pub fn parse(bytes: &[u8], now: i64) -> Result<ImportPlan> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| Error::Invalid(format!("not a .1pux file: {e}")))?;
    let data: Value = {
        let mut entry = zip
            .by_name("export.data")
            .map_err(|_| Error::Invalid("export.data not found in .1pux".into()))?;
        let mut text = String::new();
        entry.read_to_string(&mut text)?;
        serde_json::from_str(&text)?
    };

    let mut plan = ImportPlan::default();
    for account in arr(&data["accounts"]) {
        for vault in arr(&account["vaults"]) {
            let name = vault["attrs"]["name"].as_str().unwrap_or("Imported").to_owned();
            let mut items = Vec::new();
            for raw in arr(&vault["items"]) {
                let title = str_of(&raw["overview"]["title"]).to_owned();
                match raw["state"].as_str().unwrap_or("active") {
                    "active" | "archived" => {}
                    other => {
                        plan.skipped.push(Skipped { title, reason: format!("item state is {other}") });
                        continue;
                    }
                }
                let item = convert_item(raw, now);
                let attachments = read_files(raw, &mut zip, &mut plan.skipped, &title)?;
                items.push(ImportedItem { item, attachments });
            }
            plan.vaults.push(ImportedVault { name, items });
        }
    }
    Ok(plan)
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn convert_item(raw: &Value, now: i64) -> Item {
    let kind = match str_of(&raw["categoryUuid"]) {
        "001" => ItemKind::Login,
        "002" => ItemKind::CreditCard,
        "003" => ItemKind::SecureNote,
        "004" => ItemKind::Identity,
        "005" => ItemKind::Password,
        "112" => ItemKind::ApiCredential,
        _ => ItemKind::SecureNote,
    };
    let overview = &raw["overview"];
    let details = &raw["details"];
    let created = raw["createdAt"].as_i64().unwrap_or(now);

    let mut item = Item::new(Uuid::nil(), kind, str_of(&overview["title"]), created);
    item.updated_at = raw["updatedAt"].as_i64().unwrap_or(created);
    item.favorite = raw["favIndex"].as_i64().unwrap_or(0) > 0;
    item.tags = arr(&overview["tags"]).iter().filter_map(|t| t.as_str().map(str::to_owned)).collect();
    item.urls = arr(&overview["urls"])
        .iter()
        .filter_map(|u| u["url"].as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if item.urls.is_empty() {
        if let Some(url) = overview["url"].as_str().filter(|s| !s.is_empty()) {
            item.urls.push(url.to_owned());
        }
    }

    for field in arr(&details["loginFields"]) {
        let value = str_of(&field["value"]);
        if value.is_empty() {
            continue;
        }
        let (purpose, value, id) = match str_of(&field["designation"]) {
            "username" => (Purpose::Username, FieldValue::Text(value.to_owned()), "username"),
            "password" => (Purpose::Password, FieldValue::Concealed(value.to_owned()), "password"),
            _ => continue,
        };
        item.fields.push(Field { id: id.into(), label: id.into(), value, purpose: Some(purpose) });
    }
    if let Some(password) = details["password"].as_str().filter(|s| !s.is_empty()) {
        item.fields.push(Field {
            id: "password".into(),
            label: "password".into(),
            value: FieldValue::Concealed(password.to_owned()),
            purpose: Some(Purpose::Password),
        });
    }

    item.notes = str_of(&details["notesPlain"]).to_owned();
    for section in arr(&details["sections"]) {
        let fields: Vec<Field> = arr(&section["fields"]).iter().filter_map(convert_field).collect();
        if fields.is_empty() {
            continue;
        }
        item.sections.push(Section {
            id: str_of(&section["name"]).to_owned(),
            title: str_of(&section["title"]).to_owned(),
            fields,
        });
    }
    item.password_history = arr(&details["passwordHistory"])
        .iter()
        .filter_map(|h| {
            Some(HistoryEntry {
                value: h["value"].as_str()?.to_owned(),
                changed_at: h["time"].as_i64().unwrap_or(0),
            })
        })
        .collect();
    item
}

/// Section field value is an object with exactly one key naming its type.
fn convert_field(field: &Value) -> Option<Field> {
    let (kind, raw) = field["value"].as_object()?.iter().next()?;
    let value = match kind.as_str() {
        "concealed" | "creditCardNumber" => FieldValue::Concealed(text(raw)?),
        "totp" => FieldValue::Totp(text(raw)?),
        "email" => FieldValue::Email(raw["email_address"].as_str().map(str::to_owned).or_else(|| text(raw))?),
        "url" => FieldValue::Url(text(raw)?),
        "phone" => FieldValue::Phone(text(raw)?),
        "date" => FieldValue::Date(raw.as_i64()?),
        "monthYear" => FieldValue::MonthYear(u32::try_from(raw.as_i64()?).ok()?),
        "address" => FieldValue::Text(address(raw)?),
        "file" => return None, // handled by read_files
        _ => FieldValue::Text(text(raw)?),
    };
    Some(Field {
        id: str_of(&field["id"]).to_owned(),
        label: str_of(&field["title"]).to_owned(),
        value,
        purpose: None,
    })
}

/// Non-empty text of a value; objects (addresses) become their non-empty parts joined by ", ".
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::String(_) | Value::Null => None,
        Value::Object(map) => {
            let parts: Vec<&str> = map.values().filter_map(Value::as_str).filter(|s| !s.is_empty()).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        other => Some(other.to_string()),
    }
}

/// Postal order, independent of JSON key order.
fn address(v: &Value) -> Option<String> {
    let parts: Vec<&str> = ["street", "city", "state", "zip", "country"]
        .iter()
        .filter_map(|k| v[*k].as_str())
        .filter(|s| !s.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// (documentId, fileName) for the item's document and any file fields in sections.
fn file_refs(raw: &Value) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut push = |v: &Value| {
        if let (Some(id), Some(name)) = (v["documentId"].as_str(), v["fileName"].as_str()) {
            refs.push((id.to_owned(), name.to_owned()));
        }
    };
    push(&raw["details"]["documentAttributes"]);
    for section in arr(&raw["details"]["sections"]) {
        for field in arr(&section["fields"]) {
            push(&field["value"]["file"]);
        }
    }
    refs
}

fn read_files<R: Read + Seek>(
    raw: &Value,
    zip: &mut ZipArchive<R>,
    skipped: &mut Vec<Skipped>,
    title: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for (document_id, name) in file_refs(raw) {
        match zip.by_name(&format!("files/{document_id}__{name}")) {
            Ok(mut entry) => {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                out.push((name, bytes));
            }
            Err(_) => skipped.push(Skipped {
                title: format!("{title} / {name}"),
                reason: "attachment missing from export".into(),
            }),
        }
    }
    Ok(out)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p lockbox-core --test import_1pux`
Expected: 6 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add 1Password .1pux import"
```

---

### Task 13: Store — apply an import in one transaction

**Files:**
- Modify: `crates/lockbox-core/src/store/mod.rs`, `crates/lockbox-core/src/store/tests.rs`

- [ ] **Step 1: Write the failing tests** (append to `store/tests.rs`)

```rust
use crate::import::{ImportPlan, ImportReport, ImportedItem, ImportedVault};

fn sample_plan() -> ImportPlan {
    let note = Item::new(Uuid::nil(), ItemKind::SecureNote, "Passport", 1);
    ImportPlan {
        vaults: vec![
            ImportedVault {
                name: "Personal".into(),
                items: vec![
                    ImportedItem { item: login(Uuid::nil(), "GitHub"), attachments: vec![] },
                    ImportedItem { item: note, attachments: vec![("scan.pdf".into(), b"PDF".to_vec())] },
                ],
            },
            ImportedVault {
                name: "Datagile".into(),
                items: vec![ImportedItem { item: login(Uuid::nil(), "Jira"), attachments: vec![] }],
            },
        ],
        skipped: vec![],
    }
}

#[test]
fn apply_import_creates_vaults_items_and_attachments() {
    let (_dir, _path, mut store) = new_store();
    let report = store.apply_import(&sample_plan()).unwrap();
    assert_eq!(report, ImportReport { vaults: 2, items: 3, attachments: 1 });

    let vaults = store.vaults().unwrap();
    let names: Vec<_> = vaults.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["Personal", "Datagile"]);
    assert_eq!(ok_titles(store.list_items(Some(vaults[0].id)).unwrap()), ["GitHub", "Passport"]);
    assert_eq!(ok_titles(store.list_items(Some(vaults[1].id)).unwrap()), ["Jira"]);

    let passport = match &store.list_items(Some(vaults[0].id)).unwrap()[1] {
        ItemEntry::Ok(item) => item.clone(),
        other => panic!("{other:?}"),
    };
    assert_ne!(passport.id, Uuid::nil());
    assert_eq!(passport.vault_id, vaults[0].id);
    assert_eq!(&*store.get_attachment(passport.attachments[0].id).unwrap(), b"PDF");
}

#[test]
fn apply_import_requires_unlock() {
    let (_dir, _path, mut store) = new_store();
    store.lock();
    assert!(matches!(store.apply_import(&sample_plan()), Err(Error::Locked)));
}

#[test]
fn failed_import_writes_nothing() {
    let (_dir, _path, mut store) = new_store();
    store.conn.execute_batch("DROP TABLE attachments").unwrap();
    assert!(store.apply_import(&sample_plan()).is_err());
    assert!(store.vaults().unwrap().is_empty());
    let items: i64 = store.conn.query_row("SELECT count(*) FROM items", [], |r| r.get(0)).unwrap();
    assert_eq!(items, 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core store`
Expected: compile error (`apply_import` not found).

- [ ] **Step 3: Implement** — add the import to `store/mod.rs`:

```rust
use crate::import::{ImportPlan, ImportReport};
```

and inside `impl Store`:
```rust
    /// Writes a previewed import: one new vault per imported vault, all in one transaction.
    pub fn apply_import(&mut self, plan: &ImportPlan) -> Result<ImportReport> {
        let account = self.account.as_ref().ok_or(Error::Locked)?;
        let tx = self.conn.unchecked_transaction()?;
        let mut report = ImportReport::default();
        let mut new_keys = Vec::new();
        for vault in &plan.vaults {
            let info = VaultInfo { id: Uuid::new_v4(), name: vault.name.clone() };
            let key = Key::random();
            insert_vault(&tx, account, &info, &key)?;
            report.vaults += 1;
            for imported in &vault.items {
                let mut item = imported.item.clone();
                item.id = Uuid::new_v4();
                item.vault_id = info.id;
                item.attachments.clear();
                for (name, bytes) in &imported.attachments {
                    let att = AttachmentRef { id: Uuid::new_v4(), name: name.clone(), size: bytes.len() as u64 };
                    insert_attachment(&tx, &key, &item, &att, bytes)?;
                    item.attachments.push(att);
                    report.attachments += 1;
                }
                upsert_item(&tx, &key, &item)?;
                report.items += 1;
            }
            new_keys.push((info.id, key));
        }
        tx.commit()?;
        self.vault_keys.extend(new_keys);
        Ok(report)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core store`
Expected: 23 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Apply imports to the store in a single transaction"
```

---

### Task 14: Watchtower — weak and reused passwords

**Files:**
- Create: `crates/lockbox-core/src/watchtower/mod.rs`, `crates/lockbox-core/src/watchtower/hibp.rs` (stub)
- Modify: `crates/lockbox-core/src/lib.rs` (add `pub mod watchtower;`)

- [ ] **Step 1: Write the failing tests**

`crates/lockbox-core/src/watchtower/hibp.rs` (stub, filled in Task 15):
```rust
//! Have I Been Pwned range API client (Task 15).
```

`crates/lockbox-core/src/watchtower/mod.rs`:
```rust
pub mod hibp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ItemKind;

    pub(super) fn with_password(pw: &str) -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, pw, 0);
        if !pw.is_empty() {
            item.set_password(pw, 0);
        }
        item
    }

    #[test]
    fn weak_flags_guessable_passwords_only() {
        let items = [with_password("password"), with_password("correct-horse-battery-staple-91!"), with_password("")];
        let findings = weak(&items);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].item_id, items[0].id);
        assert!(matches!(findings[0].kind, FindingKind::Weak { score } if score < 3));
    }

    #[test]
    fn reused_groups_identical_passwords() {
        let items = [
            with_password("same-Pass-123!"),
            with_password("unique-Pass-456!"),
            with_password("same-Pass-123!"),
            with_password("same-Pass-123!"),
            with_password(""),
            with_password(""),
        ];
        let findings = reused(&items);
        let mut expected: Vec<_> = [&items[0], &items[2], &items[3]]
            .iter()
            .map(|i| Finding { item_id: i.id, kind: FindingKind::Reused { count: 3 } })
            .collect();
        expected.sort_by_key(|f| f.item_id);
        assert_eq!(findings, expected);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core watchtower`
Expected: compile errors (`weak`, `Finding` … not found).

- [ ] **Step 3: Implement** (insert into `watchtower/mod.rs` between `pub mod hibp;` and the tests)

```rust
use std::collections::HashMap;

use uuid::Uuid;

use crate::model::Item;

pub use hibp::{breached, Hibp};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub item_id: Uuid,
    pub kind: FindingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// zxcvbn score 0-2 (of 4).
    Weak { score: u8 },
    /// The same password is used by `count` items.
    Reused { count: usize },
    /// Seen `count` times in known breaches.
    Breached { count: u64 },
}

/// Passwords with a zxcvbn score below 3.
pub fn weak(items: &[Item]) -> Vec<Finding> {
    items
        .iter()
        .filter_map(|item| {
            let password = item.password().filter(|p| !p.is_empty())?;
            let score = u8::from(zxcvbn::zxcvbn(password, &[]).score());
            (score < 3).then(|| Finding { item_id: item.id, kind: FindingKind::Weak { score } })
        })
        .collect()
}

/// Every item whose password is shared with another item, sorted by item id.
pub fn reused(items: &[Item]) -> Vec<Finding> {
    let mut groups: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for item in items {
        if let Some(password) = item.password().filter(|p| !p.is_empty()) {
            groups.entry(password).or_default().push(item.id);
        }
    }
    let mut out: Vec<Finding> = groups
        .values()
        .filter(|ids| ids.len() > 1)
        .flat_map(|ids| {
            ids.iter().map(|id| Finding { item_id: *id, kind: FindingKind::Reused { count: ids.len() } })
        })
        .collect();
    out.sort_by_key(|f| f.item_id);
    out
}
```

Because `pub use hibp::{breached, Hibp}` needs those names, add this temporary content to `hibp.rs` (Task 15 replaces it fully):
```rust
//! Have I Been Pwned range API client (Task 15).

use super::Finding;
use crate::model::Item;
use crate::Result;

pub struct Hibp;

pub fn breached(_items: &[Item], _hibp: &Hibp) -> Result<Vec<Finding>> {
    unimplemented!("Task 15")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core watchtower`
Expected: 2 tests pass. If `u8::from(score)` does not compile, check `zxcvbn::Score` in the installed version (`cargo doc -p zxcvbn --open`) and convert accordingly (e.g. `score as u8`); keep the 0–4 scale.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add Watchtower weak and reused password checks"
```

---

### Task 15: Watchtower — breached passwords via HIBP (k-anonymity)

**Files:**
- Modify: `crates/lockbox-core/src/watchtower/hibp.rs`

- [ ] **Step 1: Write the failing tests** (replace `hibp.rs` with the tests only; implementation comes next)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ItemKind;
    use crate::Error;
    use uuid::Uuid;

    const PASSWORD_SHA1: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_is_uppercase_hex() {
        assert_eq!(sha1_hex_upper("password"), PASSWORD_SHA1);
    }

    #[test]
    fn count_in_range_finds_suffix_case_insensitively() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1e4c9b93f3f0682250b6cf8331b7ee68fd8:3861493\r\n";
        assert_eq!(count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 3861493);
        assert_eq!(count_in_range(body, "FFFF"), 0);
    }

    #[test]
    fn only_the_hash_prefix_is_sent() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/range/5BAA6")
            .match_header("add-padding", "true")
            .with_body("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n")
            .create();
        let hibp = Hibp::with_base_url(&server.url());
        assert_eq!(hibp.breach_count("password").unwrap(), 3861493);
        mock.assert();
    }

    #[test]
    fn breached_reports_items_and_queries_each_password_once() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/range/5BAA6")
            .with_body("1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\r\n")
            .expect(1)
            .create();
        let other_prefix = sha1_hex_upper("unbreached-zz9")[..5].to_owned();
        let other = server.mock("GET", format!("/range/{other_prefix}").as_str()).with_body("").expect(1).create();
        let mut a = Item::new(Uuid::new_v4(), ItemKind::Login, "a", 0);
        a.set_password("password", 0);
        let mut b = a.clone();
        b.id = Uuid::new_v4();
        let mut c = Item::new(Uuid::new_v4(), ItemKind::Login, "c", 0);
        c.set_password("unbreached-zz9", 0);

        let findings = breached(&[a.clone(), b.clone(), c], &Hibp::with_base_url(&server.url())).unwrap();
        assert_eq!(
            findings,
            vec![
                Finding { item_id: a.id, kind: FindingKind::Breached { count: 10 } },
                Finding { item_id: b.id, kind: FindingKind::Breached { count: 10 } },
            ]
        );
        mock.assert();
        other.assert();
    }

    #[test]
    fn network_failure_is_a_network_error() {
        let hibp = Hibp::with_base_url("http://127.0.0.1:9");
        assert!(matches!(hibp.breach_count("password"), Err(Error::Network(_))));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p lockbox-core hibp`
Expected: compile errors (`sha1_hex_upper`, `Hibp`, `breached` not found).

- [ ] **Step 3: Implement** (prepend to `hibp.rs`)

```rust
//! Have I Been Pwned "range" API with k-anonymity: only the first 5 hex
//! characters of the password's SHA-1 leave the machine.

use std::collections::HashMap;
use std::time::Duration;

use sha1::{Digest, Sha1};

use super::{Finding, FindingKind};
use crate::model::Item;
use crate::{Error, Result};

pub const DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com";

pub struct Hibp {
    base_url: String,
    agent: ureq::Agent,
}

impl Default for Hibp {
    fn default() -> Self {
        Self::with_base_url(DEFAULT_BASE_URL)
    }
}

impl Hibp {
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build(),
        }
    }

    /// How many times the password appears in known breaches (0 = not found).
    pub fn breach_count(&self, password: &str) -> Result<u64> {
        let hash = sha1_hex_upper(password);
        let (prefix, suffix) = hash.split_at(5);
        let network = |e: &dyn std::fmt::Display| Error::Network(e.to_string());
        let body = self
            .agent
            .get(&format!("{}/range/{prefix}", self.base_url))
            .set("Add-Padding", "true")
            .set("User-Agent", "Lockbox")
            .call()
            .map_err(|e| network(&e))?
            .into_string()
            .map_err(|e| network(&e))?;
        Ok(count_in_range(&body, suffix))
    }
}

pub fn sha1_hex_upper(password: &str) -> String {
    Sha1::digest(password.as_bytes()).iter().map(|b| format!("{b:02X}")).collect()
}

/// Parses `SUFFIX:COUNT` lines; padding lines have count 0.
pub fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .find_map(|line| {
            let (s, count) = line.trim().split_once(':')?;
            s.eq_ignore_ascii_case(suffix).then(|| count.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0)
}

/// Items whose password appears in a breach. Each distinct password is queried once.
pub fn breached(items: &[Item], hibp: &Hibp) -> Result<Vec<Finding>> {
    let mut cache: HashMap<&str, u64> = HashMap::new();
    let mut out = Vec::new();
    for item in items {
        let Some(password) = item.password().filter(|p| !p.is_empty()) else { continue };
        let count = match cache.get(password) {
            Some(count) => *count,
            None => {
                let count = hibp.breach_count(password)?;
                cache.insert(password, count);
                count
            }
        };
        if count > 0 {
            out.push(Finding { item_id: item.id, kind: FindingKind::Breached { count } });
        }
    }
    Ok(out)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p lockbox-core hibp`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/lockbox-core
git commit -m "Add HIBP breached-password check with k-anonymity"
```

---

### Task 16: Lint, format, README, push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the full suite, clippy and rustfmt**

```bash
cargo fmt --all
cargo clippy -p lockbox-core --all-targets -- -D warnings
cargo test -p lockbox-core
```
Expected: no clippy warnings; all tests pass (≈90). Fix any clippy findings without changing behaviour, re-run tests.

- [ ] **Step 2: Document how to develop** — append to `README.md`:

```markdown
## Layout

- `crates/lockbox-core` — encryption, vault store, item model, TOTP, generator,
  1Password import, Watchtower. No UI.
- `app/` — macOS desktop app (Tauri 2) — Plan 2.
- `extension/` — Chrome extension — Plan 3.

## Development

```bash
cargo test -p lockbox-core          # all core tests
cargo clippy -p lockbox-core --all-targets -- -D warnings
```

Security model: see the spec, section "Cryptography".
```

- [ ] **Step 3: Commit and push**

```bash
git add -A
git commit -m "Format, lint and document lockbox-core"
git push origin main
```

---

## Self-review notes

- Spec coverage for this plan: crypto (Tasks 2–4), storage incl. tombstones, revisions, encrypted titles, migration backup (6–8), model (5), generator (10), TOTP (9), `.1pux`/CSV import with preview + single transaction (11–13), Watchtower weak/reused/breached (14–15), damaged-row handling (7), error mapping (all).
- Deliberately in Plans 2/3: wrong-password delay after 5 attempts, auto-lock timers, clipboard clearing, Touch ID Keychain storage (core only exposes `account_key`/`unlock_with_key`), URL matching by eTLD+1, pairing and native messaging.
