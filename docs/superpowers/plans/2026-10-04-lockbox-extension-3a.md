# Lockbox Browser Extension 3a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A browser extension (Chromium browsers + Firefox) that pairs with the Lockbox app and fills username, password and one-time code on web pages — from an inline icon in the fields, from the toolbar popup, or with ⌘⇧L.

**Architecture:** All protocol logic lives in Rust in `lockbox-session::bridge` (site matching, pairing crypto, message types, framing, host manifests) plus `Session` methods for pairing and serving requests — unit-tested. The Tauri app serves a Unix socket; the same binary started by the browser (`--native-host` detection by argv) is a dumb pipe between the browser's native-messaging stdio and that socket. The extension (`extension/`, TypeScript, esbuild) holds only its pairing key; its crypto mirrors the Rust side and both are pinned by the same test vectors.

**Tech Stack:** Rust (x25519-dalek 2, chacha20poly1305 0.10, sha2, psl, url), Tauri 2, React; extension: TypeScript 6, esbuild, @noble/curves + @noble/ciphers + @noble/hashes 2.x, Vitest 5 + jsdom.

**Spec:** `docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md`, "Addendum (2026-10-04): browser extension in detail".

**Conventions for every task:**
- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (omitted below — always add it).
- Rust from the repo root: `cargo fmt --all`; `cargo clippy -p <crate> --all-targets -- -D warnings` clean.
- Frontend from `app/`, extension from `extension/`: `pnpm typecheck && pnpm test` green.
- **Vitest 5 pitfall:** a function returned from `beforeEach` runs as teardown; always give `beforeEach` a braced body.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw.

**Shared test vectors** (computed with @noble; both sides must reproduce them):

| What | Value |
|---|---|
| client secret / server secret | 32 × `0x01` / 32 × `0x02` |
| client public | `a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209` |
| server public | `ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59` |
| key | `a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab` |
| code | `381262` |
| box of `{"op":"ping"}`, client id `11111111-1111-4111-8111-111111111111`, direction req, nonce 24 × `0x03` | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD1AE3nLoQfQz8s+kYte/Lb0sVrtQoMnmqsIE17w4=` |

Chromium extension id: `kaaofpbpmnghapcafbbhjflonijdijbj`; its manifest `key` (public, safe to commit):
`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2jJDTesCwmnIGSvj2HgKyf7bWpFpdIxq94r0rACWQ8xIsJtCZLKWRrIdX6WcKkM0DiQnIfdrnAwjeQJA68Qfefz6VHswDzp2dMIQzoN6HThOUZfvgyQJ1xtINCVSrJlQWplOKvvqwq4H8pwnoA/WNGp40PHmVxs8ihfcUHR2+zeCfs9LTBmIFVdoJg8/QbH9iSnWEs3a766Z2XHmFyfRP9Sx85XvdSSofpyyvtPIp8fQUXuC952WFOk3Q3PX5AeeoDawIhCc8GIwMj4lers9rmjyy2ZYaJguLFPAjQwGvRVdADg39FVUbF4MATRlFdfkYBmR0fX6j6SDDDpaiAGHNwIDAQAB`

## File map

```
crates/lockbox-core/src/store/mod.rs, store/tests.rs     sealed meta blobs (Task 1)
crates/lockbox-session/Cargo.toml                        + psl, url, x25519-dalek, chacha20poly1305, rand, data-encoding, zeroize
crates/lockbox-session/src/bridge/mod.rs                 module list
crates/lockbox-session/src/bridge/site.rs                eTLD+1 site matching (Task 2)
crates/lockbox-session/src/bridge/crypto.rs              X25519, key/code derivation, boxes (Task 3)
crates/lockbox-session/src/bridge/protocol.rs            envelope + request/reply types (Task 4)
crates/lockbox-session/src/bridge/wire.rs                framing, socket path (Task 4)
crates/lockbox-session/src/bridge/host.rs                launch detection, host manifests (Task 5)
crates/lockbox-session/src/session/bridge.rs (+ bridge_tests.rs)   Session: pairing + serving (Task 6)
app/src-tauri/src/bridge.rs, native_host.rs, main.rs, lib.rs, commands.rs   socket server, pipe, commands (Task 7)
app/src/api.ts, components/PairingDialog.tsx, SettingsDialog.tsx, Main.tsx (+tests)   UI (Task 8)
extension/                                                the extension (Tasks 9–13)
```

---

### Task 1: Core — sealed metadata blobs

Small secrets kept next to the vault (browser pairings), sealed with the account key.

**Files:** Modify `crates/lockbox-core/src/store/mod.rs`, `crates/lockbox-core/src/store/tests.rs`.

- [ ] **Step 1: Failing tests** (append to `store/tests.rs`)

```rust
#[test]
fn sealed_meta_round_trips_and_needs_unlock() {
    let (_dir, _path, mut store) = new_store();
    assert!(store.sealed_meta("bridge.pairings").unwrap().is_none());
    store.set_sealed_meta("bridge.pairings", b"[secret]").unwrap();
    assert_eq!(&**store.sealed_meta("bridge.pairings").unwrap().unwrap(), b"[secret]");
    store.set_sealed_meta("bridge.pairings", b"[v2]").unwrap();
    assert_eq!(&**store.sealed_meta("bridge.pairings").unwrap().unwrap(), b"[v2]");
    store.lock();
    assert!(matches!(store.sealed_meta("bridge.pairings"), Err(Error::Locked)));
    assert!(matches!(store.set_sealed_meta("x", b"y"), Err(Error::Locked)));
}

#[test]
fn sealed_meta_is_bound_to_its_name_and_not_plaintext() {
    let (_dir, path, mut store) = new_store();
    store.set_sealed_meta("a", b"TopSecretBlob").unwrap();
    store
        .conn
        .execute(
            "INSERT INTO meta (key, value) SELECT 'sealed:b', value FROM meta WHERE key = 'sealed:a'",
            [],
        )
        .unwrap();
    assert!(matches!(store.sealed_meta("b"), Err(Error::Decrypt)));
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(13).any(|w| w == b"TopSecretBlob"));
}
```

- [ ] **Step 2: Run** `cargo test -p lockbox-core sealed_meta` → compile errors (`sealed_meta` missing).
- [ ] **Step 3: Implement** in `store/mod.rs` — constant next to the other AADs:

```rust
const SEALED_META_AAD: &[u8] = b"lockbox/meta/v1\0";
```

methods inside `impl Store`:

```rust
    /// A small secret blob stored next to the vault (e.g. browser pairings), sealed with the
    /// account key and bound to its name.
    pub fn sealed_meta(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let account = self.account_key()?;
        let raw: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [sealed_meta_key(name)], |r| r.get(0))
            .optional()?;
        raw.map(|data| crypto::open(account, &data, &sealed_meta_aad(name))).transpose()
    }

    pub fn set_sealed_meta(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let account = self.account_key()?;
        let data = crypto::seal(account, value, &sealed_meta_aad(name));
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![sealed_meta_key(name), data],
        )?;
        Ok(())
    }
```

free functions:

```rust
fn sealed_meta_key(name: &str) -> String {
    format!("sealed:{name}")
}

fn sealed_meta_aad(name: &str) -> Vec<u8> {
    let mut aad = SEALED_META_AAD.to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad
}
```

- [ ] **Step 4: Run** `cargo test -p lockbox-core` → all pass; clippy clean.
- [ ] **Step 5: Commit** — `git commit -m "Add sealed metadata blobs to the store"`

---

### Task 2: Site matching (eTLD+1)

**Files:** Modify `crates/lockbox-session/Cargo.toml`, `src/lib.rs`; create `src/bridge/mod.rs`, `src/bridge/site.rs`.

- [ ] **Step 1: Dependencies** — add to `[dependencies]` of `crates/lockbox-session/Cargo.toml`:

```toml
chacha20poly1305 = "0.10"
data-encoding = "2"
psl = "2"
rand = "0.8"
url = "2"
x25519-dalek = { version = "2", features = ["static_secrets"] }
zeroize = "1"
```

`src/lib.rs`: add `pub mod bridge;`. `src/bridge/mod.rs`:

```rust
//! Talking to the browser extension (spec addendum "browser extension in detail").

pub mod site;
```

- [ ] **Step 2: Failing tests** — `src/bridge/site.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn site(url: &str) -> Site {
        Site::of(url).unwrap()
    }

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(site("https://accounts.google.com/signin").domain, "google.com");
        assert_eq!(site("https://www.bbc.co.uk/").domain, "bbc.co.uk");
        assert_eq!(site("https://ivan.github.io/x").domain, "ivan.github.io");
        assert_eq!(site("https://GitHub.COM./login").host, "github.com");
        assert_eq!(site("http://192.168.1.10:8006/").domain, "192.168.1.10");
        assert_eq!(site("http://localhost:8765/login.html").domain, "localhost");
    }

    #[test]
    fn only_web_pages_have_a_site() {
        for url in ["chrome://settings", "file:///Users/x/a.html", "about:blank", "not a url"] {
            assert_eq!(Site::of(url), None, "{url}");
        }
    }

    #[test]
    fn matching_saved_urls() {
        let page = site("https://github.com/login");
        assert_eq!(matches(&page, "https://github.com"), Some(Match::SameHost));
        assert_eq!(matches(&page, "github.com"), Some(Match::SameHost), "imported URLs may lack a scheme");
        assert_eq!(matches(&site("https://gist.github.com/"), "https://github.com"), Some(Match::SameSite));
        assert_eq!(matches(&page, "https://evil-github.com"), None);
        assert_eq!(matches(&site("https://a.github.io/"), "https://b.github.io"), None);
        assert_eq!(matches(&site("http://192.168.1.10:8006/"), "https://192.168.1.10:8006"), Some(Match::SameHost));
        assert_eq!(matches(&site("http://192.168.1.10/"), "http://192.168.1.11"), None);
        assert!(Match::SameHost > Match::SameSite);
    }
}
```

- [ ] **Step 3: Run** `cargo test -p lockbox-session site` → compile errors.
- [ ] **Step 4: Implement** (prepend to `site.rs`):

```rust
//! Which saved logins belong to a web page: same registrable domain (eTLD+1).

use url::{Host, Url};

/// A web page's host and registrable domain. Only http(s) pages have one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub host: String,
    pub domain: String,
}

impl Site {
    pub fn of(url: &str) -> Option<Site> {
        let url = Url::parse(url).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        let domain = match url.host()? {
            // IP addresses only ever match themselves.
            Host::Ipv4(_) | Host::Ipv6(_) => host.clone(),
            Host::Domain(_) => psl::domain_str(&host).map(str::to_owned).unwrap_or_else(|| host.clone()),
        };
        Some(Site { host, domain })
    }
}

/// How well a saved URL fits a page; better matches compare greater.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    SameSite,
    SameHost,
}

pub fn matches(page: &Site, saved_url: &str) -> Option<Match> {
    let saved = Site::of(saved_url).or_else(|| Site::of(&format!("https://{saved_url}")))?;
    if saved.host == page.host {
        Some(Match::SameHost)
    } else if saved.domain == page.domain {
        Some(Match::SameSite)
    } else {
        None
    }
}
```

If `psl::domain_str` returns `None` for `localhost`, the fallback keeps the host — the test expects `"localhost"`.

- [ ] **Step 5: Run** tests + clippy. **Step 6: Commit** — `"Add site matching by registrable domain"`

---

### Task 3: Pairing crypto

**Files:** Create `crates/lockbox-session/src/bridge/crypto.rs`; modify `bridge/mod.rs` (`pub mod crypto;`).

- [ ] **Step 1: Failing tests** — `crypto.rs`:

```rust
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
        assert_eq!(hex(&client.public), "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209");
        assert_eq!(hex(&server.public), "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59");
        let on_server = derive(&server, &client.public, &client.public, &server.public);
        let on_client = derive(&client, &server.public, &client.public, &server.public);
        assert_eq!(hex(&*on_server.key), "a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab");
        assert_eq!(*on_client.key, *on_server.key);
        assert_eq!((on_server.code.as_str(), on_client.code.as_str()), ("381262", "381262"));

        let boxed = seal_with_nonce(&on_server.key, CLIENT_ID, Direction::Request, br#"{"op":"ping"}"#, [3; 24]);
        assert_eq!(boxed, "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD1AE3nLoQfQz8s+kYte/Lb0sVrtQoMnmqsIE17w4=");
    }

    #[test]
    fn boxes_are_bound_to_key_client_and_direction() {
        let key = [7u8; 32];
        let boxed = seal(&key, CLIENT_ID, Direction::Response, b"hello");
        assert_eq!(&**open(&key, CLIENT_ID, Direction::Response, &boxed).unwrap(), b"hello");
        assert!(open(&key, CLIENT_ID, Direction::Request, &boxed).is_none());
        assert!(open(&key, "other", Direction::Response, &boxed).is_none());
        assert!(open(&[8u8; 32], CLIENT_ID, Direction::Response, &boxed).is_none());
        assert!(open(&key, CLIENT_ID, Direction::Response, "AAAA").is_none());
        assert!(open(&key, CLIENT_ID, Direction::Response, "not base64!").is_none());
        assert_ne!(seal(&key, CLIENT_ID, Direction::Response, b"hello"), boxed, "fresh nonce every time");
    }

    #[test]
    fn base64_keys() {
        let k = KeyPair::random();
        assert_eq!(public_from_b64(&b64(&k.public)), Some(k.public));
        assert_eq!(public_from_b64("AAAA"), None);
    }
}
```

- [ ] **Step 2: Run** `cargo test -p lockbox-session crypto` → compile errors.
- [ ] **Step 3: Implement** (prepend):

```rust
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

pub fn derive(own: &KeyPair, peer_public: &[u8; 32], client_public: &[u8; 32], server_public: &[u8; 32]) -> Derived {
    let shared = Zeroizing::new(own.secret.diffie_hellman(&PublicKey::from(*peer_public)).to_bytes());
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
    Derived { key: Zeroizing::new(key), code: format!("{n:06}") }
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

fn seal_with_nonce(key: &[u8; 32], client_id: &str, direction: Direction, plaintext: &[u8], nonce: [u8; NONCE_LEN]) -> String {
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad(client_id, direction) })
        .expect("XChaCha20-Poly1305 cannot fail on in-memory buffers");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    BASE64.encode(&out)
}

/// `None` for anything that doesn't authenticate.
pub fn open(key: &[u8; 32], client_id: &str, direction: Direction, boxed: &str) -> Option<Zeroizing<Vec<u8>>> {
    let raw = BASE64.decode(boxed.as_bytes()).ok()?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad(client_id, direction) })
        .ok()
        .map(Zeroizing::new)
}

pub fn b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

pub fn public_from_b64(s: &str) -> Option<[u8; 32]> {
    BASE64.decode(s.as_bytes()).ok()?.try_into().ok()
}
```

If x25519-dalek's `StaticSecret` doesn't apply the same clamping as @noble (vector mismatch), STOP and report — the vectors are authoritative.

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add pairing crypto shared with the extension"`

---

### Task 4: Messages and framing

**Files:** Create `bridge/protocol.rs`, `bridge/wire.rs`; modify `bridge/mod.rs` (`pub mod protocol; pub mod wire;`).

- [ ] **Step 1: Failing tests**

`protocol.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inbound(v: serde_json::Value) -> Inbound {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_what_the_extension_sends() {
        assert_eq!(inbound(json!({"kind": "status"})), Inbound::Status);
        assert_eq!(inbound(json!({"kind": "show"})), Inbound::Show);
        assert_eq!(
            inbound(json!({"kind": "pair", "clientPub": "AAA", "name": "Chrome"})),
            Inbound::Pair { client_pub: "AAA".into(), name: "Chrome".into() }
        );
        assert_eq!(inbound(json!({"kind": "pairStatus", "clientId": "c1"})), Inbound::PairStatus { client_id: "c1".into() });
        assert_eq!(
            inbound(json!({"kind": "call", "clientId": "c1", "box": "B"})),
            Inbound::Call { client_id: "c1".into(), sealed: "B".into() }
        );
        assert!(serde_json::from_value::<Inbound>(json!({"kind": "nope"})).is_err());
    }

    #[test]
    fn serializes_what_the_app_answers() {
        let s = |o: &Outbound| serde_json::to_value(o).unwrap();
        assert_eq!(s(&Outbound::Status { locked: true, version: 1 }), json!({"kind": "status", "locked": true, "version": 1}));
        assert_eq!(s(&Outbound::Ok), json!({"kind": "ok"}));
        assert_eq!(
            s(&Outbound::PairPending { client_id: "c1".into(), server_pub: "S".into() }),
            json!({"kind": "pairPending", "clientId": "c1", "serverPub": "S"})
        );
        assert_eq!(s(&Outbound::Paired), json!({"kind": "paired"}));
        assert_eq!(s(&Outbound::PairDenied), json!({"kind": "pairDenied"}));
        assert_eq!(s(&Outbound::Locked), json!({"kind": "locked"}));
        assert_eq!(s(&Outbound::UnknownClient), json!({"kind": "unknownClient"}));
        assert_eq!(s(&Outbound::Reply { sealed: "B".into() }), json!({"kind": "reply", "box": "B"}));
        assert_eq!(s(&Outbound::Error { message: "x".into() }), json!({"kind": "error", "message": "x"}));
    }

    #[test]
    fn requests_and_replies_inside_the_box() {
        let id = uuid::Uuid::nil();
        assert_eq!(serde_json::from_value::<Request>(json!({"op": "ping"})).unwrap(), Request::Ping);
        assert_eq!(
            serde_json::from_value::<Request>(json!({"op": "list", "url": "https://a.com"})).unwrap(),
            Request::List { url: "https://a.com".into() }
        );
        assert_eq!(
            serde_json::from_value::<Request>(json!({"op": "fill", "url": "https://a.com", "itemId": id})).unwrap(),
            Request::Fill { url: "https://a.com".into(), item_id: id }
        );
        let items = Reply::Items { items: vec![Candidate { id, title: "A".into(), username: "u".into(), has_totp: true }] };
        assert_eq!(
            serde_json::to_value(&items).unwrap(),
            json!({"items": [{"id": id, "title": "A", "username": "u", "hasTotp": true}]})
        );
        let creds = Reply::Credentials { username: "u".into(), password: "p".into(), totp: None };
        assert_eq!(serde_json::to_value(&creds).unwrap(), json!({"username": "u", "password": "p", "totp": null}));
        assert_eq!(serde_json::to_value(Reply::Pong { pong: true }).unwrap(), json!({"pong": true}));
        assert_eq!(serde_json::to_value(Reply::Error { error: "e".into() }).unwrap(), json!({"error": "e"}));
    }
}
```

`wire.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip_little_endian() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"kind":"status"}"#).unwrap();
        assert_eq!(&buf[..4], &17u32.to_le_bytes());
        let mut r = Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), br#"{"kind":"status"}"#);
        assert_eq!(read_frame(&mut r).unwrap(), None, "clean end of stream");
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let mut huge = (MAX_FRAME + 1).to_le_bytes().to_vec();
        huge.extend_from_slice(b"x");
        assert!(read_frame(&mut Cursor::new(huge)).is_err());
        let mut short = 10u32.to_le_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut Cursor::new(short)).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME as usize + 1]).is_err());
    }

    #[test]
    fn socket_lives_in_the_app_data_folder() {
        assert_eq!(
            socket_path(std::path::Path::new("/Users/ivan")),
            std::path::PathBuf::from("/Users/ivan/Library/Application Support/app.lockbox.mac/bridge.sock")
        );
    }
}
```

- [ ] **Step 2: Run** → compile errors.
- [ ] **Step 3: Implement**

`protocol.rs` (prepend):
```rust
//! JSON messages between the extension and the app. Secrets only travel inside `box`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Inbound {
    Status,
    Show,
    #[serde(rename_all = "camelCase")]
    Pair { client_pub: String, name: String },
    #[serde(rename_all = "camelCase")]
    PairStatus { client_id: String },
    #[serde(rename_all = "camelCase")]
    Call {
        client_id: String,
        #[serde(rename = "box")]
        sealed: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Outbound {
    Status { locked: bool, version: u32 },
    Ok,
    #[serde(rename_all = "camelCase")]
    PairPending { client_id: String, server_pub: String },
    Paired,
    PairDenied,
    Locked,
    UnknownClient,
    Reply {
        #[serde(rename = "box")]
        sealed: String,
    },
    Error { message: String },
}

/// Inside a request box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    Ping,
    List { url: String },
    #[serde(rename_all = "camelCase")]
    Fill { url: String, item_id: Uuid },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

/// Inside a reply box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Reply {
    Items { items: Vec<Candidate> },
    Credentials { username: String, password: String, totp: Option<String> },
    Pong { pong: bool },
    Error { error: String },
}

pub const VERSION: u32 = 1;
```

`wire.rs` (prepend):
```rust
//! Native-messaging framing (4-byte little-endian length + JSON), also used on the socket.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Chrome's limit for messages from the host.
pub const MAX_FRAME: u32 = 1024 * 1024;

/// `Ok(None)` at a clean end of stream.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(len);
    if n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// The app's socket; the native host finds it from `$HOME` alone.
pub fn socket_path(home: &Path) -> PathBuf {
    home.join("Library/Application Support/app.lockbox.mac/bridge.sock")
}
```

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add bridge message types and framing"`

---

### Task 5: Native host launch detection and manifests

**Files:** Create `bridge/host.rs`; modify `bridge/mod.rs` (`pub mod host;`).

- [ ] **Step 1: Failing tests** — `host.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn recognises_browser_launches() {
        assert!(is_host_launch(&args(&["lockbox-app", "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/"])));
        assert!(is_host_launch(&args(&["lockbox-app", "/x/app.lockbox.bridge.json", "lockbox@lockbox.app"])));
        assert!(!is_host_launch(&args(&["lockbox-app"])));
        assert!(!is_host_launch(&args(&["lockbox-app", "--hidden"])));
    }

    #[test]
    fn writes_manifests_only_for_installed_browsers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Google/Chrome")).unwrap();
        std::fs::create_dir_all(dir.path().join("Mozilla")).unwrap();
        let exe = std::path::Path::new("/Applications/Lockbox.app/Contents/MacOS/lockbox-app");
        let found = manifests(dir.path(), exe);
        let names: Vec<_> = found.iter().map(|m| m.browser).collect();
        assert_eq!(names, ["Chrome", "Firefox"]);
        assert_eq!(found[0].path, dir.path().join("Google/Chrome/NativeMessagingHosts/app.lockbox.bridge.json"));

        let chrome: serde_json::Value = serde_json::from_str(&found[0].contents).unwrap();
        assert_eq!(chrome["name"], "app.lockbox.bridge");
        assert_eq!(chrome["type"], "stdio");
        assert_eq!(chrome["path"], exe.to_str().unwrap());
        assert_eq!(chrome["allowed_origins"][0], "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/");
        assert!(chrome.get("allowed_extensions").is_none());

        let firefox: serde_json::Value = serde_json::from_str(&found[1].contents).unwrap();
        assert_eq!(firefox["allowed_extensions"][0], "lockbox@lockbox.app");
        assert!(firefox.get("allowed_origins").is_none());
    }
}
```

- [ ] **Step 2: Run** → compile errors.
- [ ] **Step 3: Implement** (prepend):

```rust
//! The native-messaging host: how browsers start us and where their host manifests live.

use std::path::{Path, PathBuf};

use serde_json::json;

pub const HOST_NAME: &str = "app.lockbox.bridge";
pub const CHROMIUM_EXTENSION_ID: &str = "kaaofpbpmnghapcafbbhjflonijdijbj";
pub const FIREFOX_EXTENSION_ID: &str = "lockbox@lockbox.app";

/// Chromium passes the caller's origin; Firefox passes the manifest path and the extension id.
pub fn is_host_launch(args: &[String]) -> bool {
    args.iter().skip(1).any(|a| a.starts_with("chrome-extension://") || a == FIREFOX_EXTENSION_ID)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Chromium,
    Firefox,
}

pub struct Browser {
    pub name: &'static str,
    /// Profile folder under `~/Library/Application Support`.
    pub dir: &'static str,
    pub family: Family,
}

pub const BROWSERS: &[Browser] = &[
    Browser { name: "Chrome", dir: "Google/Chrome", family: Family::Chromium },
    Browser { name: "Chrome Beta", dir: "Google/Chrome Beta", family: Family::Chromium },
    Browser { name: "Chromium", dir: "Chromium", family: Family::Chromium },
    Browser { name: "Opera", dir: "com.operasoftware.Opera", family: Family::Chromium },
    Browser { name: "Yandex", dir: "Yandex/YandexBrowser", family: Family::Chromium },
    Browser { name: "Brave", dir: "BraveSoftware/Brave-Browser", family: Family::Chromium },
    Browser { name: "Edge", dir: "Microsoft Edge", family: Family::Chromium },
    Browser { name: "Vivaldi", dir: "Vivaldi", family: Family::Chromium },
    Browser { name: "Arc", dir: "Arc/User Data", family: Family::Chromium },
    Browser { name: "Firefox", dir: "Mozilla", family: Family::Firefox },
];

pub struct Manifest {
    pub browser: &'static str,
    pub path: PathBuf,
    pub contents: String,
}

/// Host manifests for every browser whose profile folder exists under `app_support`.
pub fn manifests(app_support: &Path, exe: &Path) -> Vec<Manifest> {
    BROWSERS
        .iter()
        .filter(|b| app_support.join(b.dir).is_dir())
        .map(|b| Manifest {
            browser: b.name,
            path: app_support.join(b.dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json")),
            contents: manifest_json(b.family, exe),
        })
        .collect()
}

fn manifest_json(family: Family, exe: &Path) -> String {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "Lockbox password manager",
        "path": exe.to_string_lossy(),
        "type": "stdio",
    });
    match family {
        Family::Chromium => m["allowed_origins"] = json!([format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")]),
        Family::Firefox => m["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]),
    }
    serde_json::to_string_pretty(&m).expect("manifest serializes")
}
```

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Add native host detection and manifests"`

---

### Task 6: Session — pairing and serving the extension

**Files:** Create `crates/lockbox-session/src/session/bridge.rs` and `session/bridge_tests.rs`; modify `session/mod.rs`, `src/lib.rs`.

- [ ] **Step 1: Wire up** — in `session/mod.rs`: `mod bridge;` and `#[cfg(test)] mod bridge_tests;` next to `mod tests;`; add field `pending: Vec<bridge::PendingPairing>` to `Session` (init `Vec::new()` in `new`); in `lock()` add `self.pending.clear();`. In `lib.rs`: `pub use session::{BridgeEvent, PairedBrowser, PairingRequest};` and in `session/mod.rs`: `pub use bridge::{BridgeEvent, PairedBrowser, PairingRequest};`.

- [ ] **Step 2: Failing tests** — `session/bridge_tests.rs`:

```rust
use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use crate::bridge::crypto::{self, b64, derive, public_from_b64, Direction, KeyPair};
use crate::bridge::protocol::{Inbound, Outbound};
use serde_json::{json, Value};

/// Plays the extension's side.
struct Ext {
    keys: KeyPair,
    client_id: String,
    key: [u8; 32],
    code: String,
}

fn pair(s: &mut Session) -> (Ext, PairingRequest) {
    let keys = KeyPair::random();
    let (out, event) = s.bridge(Inbound::Pair { client_pub: b64(&keys.public), name: "Chrome".into() }, 1_000);
    let Outbound::PairPending { client_id, server_pub } = out else { panic!("{out:?}") };
    let server_pub = public_from_b64(&server_pub).unwrap();
    let d = derive(&keys, &server_pub, &keys.public, &server_pub);
    let Some(BridgeEvent::PairRequest(request)) = event else { panic!("no pairing event") };
    (Ext { keys, client_id, key: *d.key, code: d.code }, request)
}

fn paired(s: &mut Session) -> Ext {
    let (ext, request) = pair(s);
    s.approve_pairing(&request.client_id, 1_000).unwrap();
    assert_eq!(s.bridge(Inbound::PairStatus { client_id: ext.client_id.clone() }, 1_000).0, Outbound::Paired);
    ext
}

fn call(s: &mut Session, ext: &Ext, request: Value, now: u64) -> Value {
    let sealed = crypto::seal(&ext.key, &ext.client_id, Direction::Request, request.to_string().as_bytes());
    match s.bridge(Inbound::Call { client_id: ext.client_id.clone(), sealed }, now).0 {
        Outbound::Reply { sealed } => {
            let plain = crypto::open(&ext.key, &ext.client_id, Direction::Response, &sealed).unwrap();
            serde_json::from_slice(&plain).unwrap()
        }
        other => json!({ "outbound": format!("{other:?}") }),
    }
}

#[test]
fn status_and_show() {
    let (_dir, mut s) = unlocked_session();
    assert_eq!(s.bridge(Inbound::Status, 1_000).0, Outbound::Status { locked: false, version: 1 });
    assert_eq!(s.bridge(Inbound::Show, 1_000), (Outbound::Ok, Some(BridgeEvent::Show)));
    s.lock();
    assert_eq!(s.bridge(Inbound::Status, 1_000).0, Outbound::Status { locked: true, version: 1 });
}

#[test]
fn pairing_shows_the_same_code_on_both_sides_and_needs_approval() {
    let (_dir, mut s) = unlocked_session();
    let (ext, request) = pair(&mut s);
    assert_eq!(request.code, ext.code);
    assert_eq!(request.name, "Chrome");
    assert!(matches!(s.bridge(Inbound::PairStatus { client_id: ext.client_id.clone() }, 1_001).0, Outbound::PairPending { .. }));
    assert_eq!(call(&mut s, &ext, json!({"op": "ping"}), 1_001), json!({"outbound": "UnknownClient"}));
    s.approve_pairing(&request.client_id, 1_002).unwrap();
    assert_eq!(s.bridge(Inbound::PairStatus { client_id: ext.client_id.clone() }, 1_003).0, Outbound::Paired);
    assert_eq!(call(&mut s, &ext, json!({"op": "ping"}), 1_004), json!({"pong": true}));
    let _ = ext.keys;
}

#[test]
fn denied_and_expired_pairings() {
    let (_dir, mut s) = unlocked_session();
    let (ext, request) = pair(&mut s);
    s.deny_pairing(&request.client_id);
    assert_eq!(s.bridge(Inbound::PairStatus { client_id: ext.client_id.clone() }, 1_001).0, Outbound::PairDenied);
    let (_ext2, request2) = pair(&mut s);
    let err = s.approve_pairing(&request2.client_id, 1_000 + PAIRING_TTL_SECS + 1).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn pairing_needs_an_unlocked_vault() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    let keys = KeyPair::random();
    let (out, event) = s.bridge(Inbound::Pair { client_pub: b64(&keys.public), name: "Chrome".into() }, 1_000);
    assert_eq!((out, event), (Outbound::Locked, Some(BridgeEvent::Show)));
}

#[test]
fn lists_and_fills_logins_for_the_page_site_only() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut github = save_login(&mut s, p, "GitHub", "ivan", "gh-pass");
    github.urls = vec!["https://github.com".into()];
    let github = s.save_item(github, 1_000).unwrap();
    let mut gist = save_login(&mut s, p, "Gist", "ivan2", "gist-pass");
    gist.urls = vec!["https://gist.github.com".into()];
    s.save_item(gist, 1_000).unwrap();
    let mut other = save_login(&mut s, p, "Bank", "me", "bank-pass");
    other.urls = vec!["https://bank.example".into()];
    let other = s.save_item(other, 1_000).unwrap();
    let ext = paired(&mut s);

    let list = call(&mut s, &ext, json!({"op": "list", "url": "https://gist.github.com/new"}), 1_000);
    let titles: Vec<_> = list["items"].as_array().unwrap().iter().map(|i| i["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Gist", "GitHub"], "exact host first, then same site");
    assert_eq!(list["items"][1]["username"], "ivan");
    assert!(list["items"][0].get("password").is_none(), "no secrets in a list");

    let creds = call(&mut s, &ext, json!({"op": "fill", "url": "https://github.com/login", "itemId": github.id}), 1_000);
    assert_eq!(creds, json!({"username": "ivan", "password": "gh-pass", "totp": null}));

    let refused = call(&mut s, &ext, json!({"op": "fill", "url": "https://github.com/login", "itemId": other.id}), 1_000);
    assert_eq!(refused["error"], "This login doesn't belong to this site");
    let none = call(&mut s, &ext, json!({"op": "list", "url": "chrome://settings"}), 1_000);
    assert_eq!(none, json!({"items": []}));
}

#[test]
fn fill_includes_the_current_one_time_code() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    item.fields.push(lockbox_core::model::Field {
        id: "otp".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        purpose: None,
    });
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    let creds = call(&mut s, &ext, json!({"op": "fill", "url": "https://github.com/", "itemId": item.id}), 59);
    assert_eq!(creds["totp"], "287082");
    let list = call(&mut s, &ext, json!({"op": "list", "url": "https://github.com/"}), 59);
    assert_eq!(list["items"][0]["hasTotp"], true);
}

#[test]
fn locked_vault_and_unknown_clients() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    s.lock();
    assert_eq!(call(&mut s, &ext, json!({"op": "ping"}), 1_000), json!({"outbound": "Locked"}));
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(call(&mut s, &ext, json!({"op": "ping"}), 1_000), json!({"pong": true}), "pairings survive locking");

    let stranger = Ext { keys: KeyPair::random(), client_id: "nobody".into(), key: [9; 32], code: String::new() };
    assert_eq!(call(&mut s, &stranger, json!({"op": "ping"}), 1_000), json!({"outbound": "UnknownClient"}));
    let forged = Ext { keys: KeyPair::random(), client_id: ext.client_id.clone(), key: [9; 32], code: String::new() };
    assert!(call(&mut s, &forged, json!({"op": "ping"}), 1_000)["outbound"].as_str().unwrap().starts_with("Error"));
}

#[test]
fn paired_browsers_can_be_listed_and_removed() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let list = s.paired_browsers().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].client_id.as_str(), list[0].name.as_str()), (ext.client_id.as_str(), "Chrome"));
    s.remove_paired_browser(&ext.client_id).unwrap();
    assert!(s.paired_browsers().unwrap().is_empty());
    assert_eq!(call(&mut s, &ext, json!({"op": "ping"}), 1_000), json!({"outbound": "UnknownClient"}));
}
```

Also make the existing test helpers in `session/tests.rs` reachable: they are already `pub(super)` (`personal`, `save_login`, `unlocked_session`, `PW`); `session/mod.rs` must declare `#[cfg(test)] mod tests;` before `bridge_tests` (it does).

- [ ] **Step 3: Run** `cargo test -p lockbox-session bridge` → compile errors.
- [ ] **Step 4: Implement** — `session/bridge.rs`:

```rust
//! Serving the browser extension: pairing and the list/fill requests.

use lockbox_core::store::ItemEntry;
use lockbox_core::totp::Totp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::Session;
use crate::bridge::crypto::{self, b64, derive, public_from_b64, Direction, KeyPair};
use crate::bridge::protocol::{Candidate, Inbound, Outbound, Reply, Request, VERSION};
use crate::bridge::site::{matches, Site};
use crate::error::{CmdError, CmdResult, ErrorKind};

/// How long a pairing request waits for approval in the app.
pub const PAIRING_TTL_SECS: u64 = 300;
const PAIRINGS_META: &str = "bridge.pairings";

/// Something the app window should react to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    /// Bring the window to the front (e.g. so the user can unlock).
    Show,
    /// Ask the user to confirm a browser.
    PairRequest(PairingRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub client_id: String,
    pub name: String,
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedBrowser {
    pub client_id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingState {
    Waiting,
    Approved,
    Denied,
}

pub(super) struct PendingPairing {
    client_id: String,
    name: String,
    server_pub: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    created_at: u64,
    state: PendingState,
}

/// Stored sealed in the vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pairing {
    client_id: String,
    name: String,
    key: String,
    created_at: u64,
}

impl Session {
    /// One message from the extension; the event, if any, is for the app window.
    pub fn bridge(&mut self, msg: Inbound, now: u64) -> (Outbound, Option<BridgeEvent>) {
        match msg {
            Inbound::Status => (Outbound::Status { locked: self.store.is_none(), version: VERSION }, None),
            Inbound::Show => (Outbound::Ok, Some(BridgeEvent::Show)),
            Inbound::Pair { client_pub, name } => self.start_pairing(&client_pub, &name, now),
            Inbound::PairStatus { client_id } => (self.pairing_status(&client_id), None),
            Inbound::Call { client_id, sealed } => (self.serve_call(&client_id, &sealed, now), None),
        }
    }

    pub fn approve_pairing(&mut self, client_id: &str, now: u64) -> CmdResult<()> {
        self.store()?;
        self.forget_expired(now);
        let pending = self
            .pending
            .iter_mut()
            .find(|p| p.client_id == client_id && p.state == PendingState::Waiting)
            .ok_or_else(|| CmdError::new(ErrorKind::NotFound, "This request has expired"))?;
        pending.state = PendingState::Approved;
        let record = Pairing {
            client_id: pending.client_id.clone(),
            name: pending.name.clone(),
            key: b64(&pending.key[..]),
            created_at: now,
        };
        let mut all = self.load_pairings()?;
        all.retain(|p| p.client_id != record.client_id);
        all.push(record);
        self.save_pairings(&all)
    }

    pub fn deny_pairing(&mut self, client_id: &str) {
        if let Some(p) = self.pending.iter_mut().find(|p| p.client_id == client_id) {
            p.state = PendingState::Denied;
        }
    }

    pub fn paired_browsers(&self) -> CmdResult<Vec<PairedBrowser>> {
        Ok(self
            .load_pairings()?
            .into_iter()
            .map(|p| PairedBrowser { client_id: p.client_id, name: p.name, created_at: p.created_at })
            .collect())
    }

    pub fn remove_paired_browser(&mut self, client_id: &str) -> CmdResult<()> {
        let mut all = self.load_pairings()?;
        all.retain(|p| p.client_id != client_id);
        self.save_pairings(&all)
    }

    fn start_pairing(&mut self, client_pub: &str, name: &str, now: u64) -> (Outbound, Option<BridgeEvent>) {
        if self.store.is_none() {
            return (Outbound::Locked, Some(BridgeEvent::Show));
        }
        let Some(client_pub) = public_from_b64(client_pub) else {
            return (Outbound::Error { message: "Bad public key".into() }, None);
        };
        self.forget_expired(now);
        let server = KeyPair::random();
        let derived = derive(&server, &client_pub, &client_pub, &server.public);
        let client_id = Uuid::new_v4().to_string();
        let name = clean_name(name);
        self.pending.push(PendingPairing {
            client_id: client_id.clone(),
            name: name.clone(),
            server_pub: server.public,
            key: derived.key,
            created_at: now,
            state: PendingState::Waiting,
        });
        let event = BridgeEvent::PairRequest(PairingRequest { client_id: client_id.clone(), name, code: derived.code });
        (Outbound::PairPending { client_id, server_pub: b64(&server.public) }, Some(event))
    }

    fn pairing_status(&mut self, client_id: &str) -> Outbound {
        if let Some(i) = self.pending.iter().position(|p| p.client_id == client_id) {
            return match self.pending[i].state {
                PendingState::Waiting => Outbound::PairPending {
                    client_id: client_id.to_owned(),
                    server_pub: b64(&self.pending[i].server_pub),
                },
                PendingState::Approved => {
                    self.pending.remove(i);
                    Outbound::Paired
                }
                PendingState::Denied => {
                    self.pending.remove(i);
                    Outbound::PairDenied
                }
            };
        }
        match self.load_pairings() {
            Ok(all) if all.iter().any(|p| p.client_id == client_id) => Outbound::Paired,
            Ok(_) => Outbound::UnknownClient,
            Err(_) => Outbound::Locked,
        }
    }

    fn serve_call(&mut self, client_id: &str, sealed: &str, now: u64) -> Outbound {
        if self.store.is_none() {
            return Outbound::Locked;
        }
        let Ok(all) = self.load_pairings() else { return Outbound::Locked };
        let Some(pairing) = all.into_iter().find(|p| p.client_id == client_id) else {
            return Outbound::UnknownClient;
        };
        let Some(key) = public_from_b64(&pairing.key).map(Zeroizing::new) else {
            return Outbound::Error { message: "Damaged pairing".into() };
        };
        let Some(plain) = crypto::open(&key, client_id, Direction::Request, sealed) else {
            return Outbound::Error { message: "Message did not authenticate".into() };
        };
        let reply = match serde_json::from_slice::<Request>(&plain) {
            Ok(request) => self.serve_request(request, now),
            Err(_) => Reply::Error { error: "Unknown request".into() },
        };
        let json = Zeroizing::new(serde_json::to_vec(&reply).expect("reply serializes"));
        Outbound::Reply { sealed: crypto::seal(&key, client_id, Direction::Response, &json) }
    }

    fn serve_request(&mut self, request: Request, now: u64) -> Reply {
        match request {
            Request::Ping => Reply::Pong { pong: true },
            // Not activity: the extension may list on its own; only a fill keeps the vault open.
            Request::List { url } => Reply::Items { items: self.candidates(&url) },
            Request::Fill { url, item_id } => self.credentials(&url, item_id, now),
        }
    }

    fn candidates(&self, url: &str) -> Vec<Candidate> {
        let (Some(page), Some(store)) = (Site::of(url), self.store.as_ref()) else { return Vec::new() };
        let Ok(entries) = store.list_items(None) else { return Vec::new() };
        let mut found: Vec<_> = entries
            .into_iter()
            .filter_map(|e| match e {
                ItemEntry::Ok(item) => {
                    let best = item.urls.iter().filter_map(|u| matches(&page, u)).max()?;
                    Some((best, item))
                }
                ItemEntry::Damaged { .. } => None,
            })
            .collect();
        found.sort_by(|(ma, a), (mb, b)| mb.cmp(ma).then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase())));
        found
            .into_iter()
            .map(|(_, item)| Candidate {
                id: item.id,
                title: item.title.clone(),
                username: item.username().unwrap_or_default().to_owned(),
                has_totp: item.totp().is_some(),
            })
            .collect()
    }

    fn credentials(&mut self, url: &str, item_id: Uuid, now: u64) -> Reply {
        let Some(page) = Site::of(url) else {
            return Reply::Error { error: "This page can't be filled".into() };
        };
        let item = match self.store().and_then(|s| s.get_item(item_id).map_err(Into::into)) {
            Ok(item) => item,
            Err(e) => return Reply::Error { error: e.message },
        };
        if !item.urls.iter().any(|u| matches(&page, u).is_some()) {
            return Reply::Error { error: "This login doesn't belong to this site".into() };
        }
        self.touch(now);
        Reply::Credentials {
            username: item.username().unwrap_or_default().to_owned(),
            password: item.password().unwrap_or_default().to_owned(),
            totp: item.totp().and_then(|raw| Totp::parse(raw).ok()).map(|t| t.code_at(now)),
        }
    }

    fn forget_expired(&mut self, now: u64) {
        self.pending.retain(|p| now.saturating_sub(p.created_at) <= PAIRING_TTL_SECS);
    }

    fn load_pairings(&self) -> CmdResult<Vec<Pairing>> {
        let raw = self.store()?.sealed_meta(PAIRINGS_META)?;
        Ok(raw.and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default())
    }

    fn save_pairings(&mut self, all: &[Pairing]) -> CmdResult<()> {
        let json = Zeroizing::new(serde_json::to_vec(all).expect("pairings serialize"));
        Ok(self.store_mut()?.set_sealed_meta(PAIRINGS_META, &json)?)
    }
}

fn clean_name(name: &str) -> String {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(40).collect();
    if name.is_empty() { "Browser".into() } else { name }
}
```

Notes: `self.store()`/`store_mut()` are existing private helpers in `session/mod.rs` returning `CmdResult`; `CmdError` converts from `lockbox_core::Error` (`From` exists), so `.map_err(Into::into)` works. If the borrow checker objects to `self.store()` inside `candidates` returning a reference while iterating, keep the `self.store.as_ref()` form shown. `Totp::parse(...).code_at` matches the existing session code.

- [ ] **Step 5: Run** `cargo test -p lockbox-session` + clippy. **Step 6: Commit** — `"Serve the browser extension: pairing, list and fill"`

---

### Task 7: Shell — socket server, native host pipe, commands

**Files:** Create `app/src-tauri/src/bridge.rs`, `app/src-tauri/src/native_host.rs`; modify `main.rs`, `lib.rs`, `commands.rs`, `Cargo.toml` (none needed beyond workspace crates), `capabilities/default.json` (nothing new: events from Rust need no permission; `core:event:default` is in `core:default`).

- [ ] **Step 1: Socket server** — `app/src-tauri/src/bridge.rs`:

```rust
//! Serves the browser extension over a Unix socket; the native host pipes the browser to it.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use lockbox_session::bridge::protocol::{Inbound, Outbound};
use lockbox_session::bridge::wire::{read_frame, write_frame};
use lockbox_session::BridgeEvent;
use tauri::{AppHandle, Emitter, Manager};

use crate::{lock_session, now, AppState};

pub fn serve(app: AppHandle, socket: PathBuf) {
    if let Some(dir) = socket.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A stale socket from a previous run would make bind fail.
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lockbox: browser bridge unavailable: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    for stream in listener.incoming().flatten() {
        let app = app.clone();
        std::thread::spawn(move || connection(app, stream));
    }
}

fn connection(app: AppHandle, mut stream: UnixStream) {
    while let Ok(Some(frame)) = read_frame(&mut stream) {
        let reply = match serde_json::from_slice::<Inbound>(&frame) {
            Ok(msg) => {
                let (out, event) = {
                    let state = app.state::<AppState>();
                    let mut session = lock_session(&state);
                    session.bridge(msg, now())
                };
                if let Some(event) = event {
                    on_event(&app, event);
                }
                out
            }
            Err(_) => Outbound::Error { message: "Unknown message".into() },
        };
        let bytes = serde_json::to_vec(&reply).expect("outbound serializes");
        if write_frame(&mut stream, &bytes).is_err() {
            break;
        }
    }
}

fn on_event(app: &AppHandle, event: BridgeEvent) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    if let BridgeEvent::PairRequest(request) = event {
        let _ = app.emit("pair-request", request);
    }
}
```

- [ ] **Step 2: Native host** — `app/src-tauri/src/native_host.rs`:

```rust
//! Started by the browser: a pipe between its stdio and the running app's socket.

use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use lockbox_session::bridge::wire::socket_path;

pub fn run() -> i32 {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return 1 };
    let Ok(stream) = connect(&socket_path(&home)) else { return 1 };
    let Ok(mut to_app) = stream.try_clone() else { return 1 };
    // The framing is identical on both sides, so bytes are copied as they are.
    let upstream = std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_app);
        let _ = to_app.shutdown(Shutdown::Write);
    });
    let mut from_app = stream;
    let _ = io::copy(&mut from_app, &mut io::stdout().lock());
    let _ = upstream.join();
    0
}

/// Connects to the app, starting it in the background if it isn't running.
fn connect(socket: &Path) -> io::Result<UnixStream> {
    if let Ok(s) = UnixStream::connect(socket) {
        return Ok(s);
    }
    let _ = Command::new("open").args(["-g", "-b", "app.lockbox.mac"]).status();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(s) = UnixStream::connect(socket) {
            return Ok(s);
        }
    }
    UnixStream::connect(socket)
}
```

Note: `io::copy` of stdin may block after the app replied; the browser closes stdin after reading one reply for `sendNativeMessage`, ending the thread. `main` returns after `from_app` hits EOF (the app closes the stream when the browser closes stdin).

- [ ] **Step 3: Entry point** — `app/src-tauri/src/main.rs`:

```rust
// Prevents an extra console window on Windows in release; harmless on macOS.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Started by a browser for the extension: act as the native-messaging pipe, not the app.
    let args: Vec<String> = std::env::args().collect();
    if lockbox_session::bridge::host::is_host_launch(&args) {
        std::process::exit(lockbox_app_lib::native_host::run());
    }
    lockbox_app_lib::run()
}
```

- [ ] **Step 4: Wiring** — in `lib.rs`: `mod bridge;` and `pub mod native_host;`; in `setup`, after the housekeeping thread:

```rust
            if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                let socket = lockbox_session::bridge::wire::socket_path(&home);
                let bridge_app = app.handle().clone();
                std::thread::spawn(move || bridge::serve(bridge_app, socket));
            }
```

- [ ] **Step 5: Commands** — add to `commands.rs` (imports: `lockbox_session::{PairedBrowser}`):

```rust
#[tauri::command(async)]
pub fn connect_browsers() -> CmdResult<Vec<String>> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| CmdError::new(ErrorKind::Other, "HOME is not set"))?;
    let exe = std::env::current_exe().map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
    let app_support = home.join("Library/Application Support");
    let mut done = Vec::new();
    for m in lockbox_session::bridge::host::manifests(&app_support, &exe) {
        if let Some(dir) = m.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
        }
        std::fs::write(&m.path, m.contents).map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
        done.push(m.browser.to_string());
    }
    Ok(done)
}

#[tauri::command(async)]
pub fn approve_pairing(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).approve_pairing(&client_id, now())
}

#[tauri::command(async)]
pub fn deny_pairing(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).deny_pairing(&client_id);
    Ok(())
}

#[tauri::command(async)]
pub fn paired_browsers(state: State<'_, AppState>) -> CmdResult<Vec<PairedBrowser>> {
    lock_session(&state).paired_browsers()
}

#[tauri::command(async)]
pub fn remove_paired_browser(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).remove_paired_browser(&client_id)
}
```

Register the five in `generate_handler!`.

- [ ] **Step 6: Build** — `cd app && pnpm build && cd .. && cargo build -p lockbox-app && cargo clippy -p lockbox-app --all-targets -- -D warnings`.
- [ ] **Step 7: Smoke test the pipe by hand** (no browser yet): run the dev app (`cd app && nohup pnpm tauri dev > /tmp/lockbox-dev.log 2>&1 &`, wait ~40 s), then

```bash
python3 - <<'EOF'
import json, struct, subprocess
p = subprocess.run(["target/debug/lockbox-app", "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/"],
                   input=(lambda b: struct.pack("<I", len(b)) + b)(json.dumps({"kind": "status"}).encode()),
                   capture_output=True, timeout=20)
n = struct.unpack("<I", p.stdout[:4])[0]
print(p.stdout[4:4 + n].decode())
EOF
```
Expected: `{"kind":"status","locked":...,"version":1}`. Stop the dev app afterwards.

- [ ] **Step 8: Commit** — `"Serve the extension bridge from the app; native host pipe"`

---

### Task 8: App UI — pairing approval and connected browsers

**Files:** Modify `app/src/api.ts`, `app/src/components/Main.tsx` (+test), `SettingsDialog.tsx` (+test); create `PairingDialog.tsx` (+test).

- [ ] **Step 1: API** — add to `api.ts`:

```ts
export interface PairingRequest {
  clientId: string;
  name: string;
  code: string;
}

export interface PairedBrowser {
  clientId: string;
  name: string;
  createdAt: number;
}
```
and to `api`:
```ts
  connectBrowsers: () => invoke<string[]>("connect_browsers"),
  approvePairing: (clientId: string) => invoke<void>("approve_pairing", { clientId }),
  denyPairing: (clientId: string) => invoke<void>("deny_pairing", { clientId }),
  pairedBrowsers: () => invoke<PairedBrowser[]>("paired_browsers"),
  removePairedBrowser: (clientId: string) => invoke<void>("remove_paired_browser", { clientId }),
  onPairRequest: (callback: (request: PairingRequest) => void): Promise<UnlistenFn> =>
    listen<PairingRequest>("pair-request", (e) => callback(e.payload)),
```

- [ ] **Step 2: Failing tests** — `PairingDialog.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { PairingDialog } from "./PairingDialog";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, approvePairing: vi.fn(), denyPairing: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.approvePairing).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.denyPairing).mockReset().mockResolvedValue(undefined);
});

const request = { clientId: "c1", name: "Chrome", code: "381262" };

test("shows the browser and the code and connects", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<PairingDialog request={request} onDone={onDone} />);
  expect(screen.getByRole("dialog", { name: "Connect Chrome?" })).toBeInTheDocument();
  expect(screen.getByText("381 262")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Connect" }));
  expect(api.approvePairing).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("deny", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<PairingDialog request={request} onDone={onDone} />);
  await user.click(screen.getByRole("button", { name: "Deny" }));
  expect(api.denyPairing).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("shows an expired request", async () => {
  const user = userEvent.setup();
  vi.mocked(api.approvePairing).mockRejectedValue({ kind: "notFound", message: "This request has expired" });
  render(<PairingDialog request={request} onDone={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Connect" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("This request has expired");
});
```

Append to `SettingsDialog.test.tsx` (add `connectBrowsers`, `pairedBrowsers`, `removePairedBrowser` to its `vi.mock` api object; in `beforeEach` reset them: `pairedBrowsers` resolves `[{ clientId: "c1", name: "Chrome", createdAt: 1 }]`, `connectBrowsers` resolves `["Chrome", "Opera"]`, `removePairedBrowser` resolves `undefined`):

```tsx
test("connects browsers and removes a paired one", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByText("Chrome")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Connect browsers" }));
  expect(await screen.findByText("Ready in Chrome, Opera. Load the Lockbox extension there and click Connect.")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Disconnect Chrome" }));
  expect(api.removePairedBrowser).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(screen.queryByRole("button", { name: "Disconnect Chrome" })).not.toBeInTheDocument());
});
```

Append to `Main.test.tsx` (add `onPairRequest` to the mocked api: `vi.fn()` that captures the callback; in `beforeEach`: `vi.mocked(api.onPairRequest).mockReset().mockImplementation(async (cb) => { pairCallback = cb; return () => {}; });` with `let pairCallback: ((r: PairingRequest) => void) | null = null;` at file top; import `act` from Testing Library and the type):

```tsx
test("a pairing request from a browser opens the confirmation", async () => {
  render(<Main onLock={vi.fn()} />);
  await waitFor(() => expect(pairCallback).not.toBeNull());
  act(() => pairCallback!({ clientId: "c1", name: "Opera", code: "123456" }));
  expect(await screen.findByRole("dialog", { name: "Connect Opera?" })).toBeInTheDocument();
});
```

- [ ] **Step 3: Run** → failures.
- [ ] **Step 4: Implement**

`PairingDialog.tsx`:
```tsx
import { useState } from "react";
import { api, errorMessage, type PairingRequest } from "../api";

export function PairingDialog({ request, onDone }: { request: PairingRequest; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function answer(approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (approve) await api.approvePairing(request.clientId);
      else await api.denyPairing(request.clientId);
      onDone();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal pairing" role="dialog" aria-modal="true" aria-labelledby="pair-title">
        <h2 id="pair-title">Connect {request.name}?</h2>
        <p className="muted">Check that the Lockbox extension in {request.name} shows the same code.</p>
        <p className="pair-code mono">{`${request.code.slice(0, 3)} ${request.code.slice(3)}`}</p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button onClick={() => answer(false)} disabled={busy}>
            Deny
          </button>
          <button className="primary" onClick={() => answer(true)} disabled={busy}>
            Connect
          </button>
        </div>
      </div>
    </div>
  );
}
```
CSS (append to `styles.css`): `.pair-code { font-size: 34px; font-weight: 600; letter-spacing: 0.12em; text-align: center; margin: 4px 0; }`

`Main.tsx`: state `const [pairing, setPairing] = useState<PairingRequest | null>(null);`, effect:
```tsx
  useEffect(() => {
    const unlisten = api.onPairRequest(setPairing);
    return () => {
      unlisten.then((stop) => stop());
    };
  }, []);
```
and render `{pairing && <PairingDialog request={pairing} onDone={() => setPairing(null)} />}` next to the other dialogs.

`SettingsDialog.tsx`: new section between "Change master password" and "Appearance":
```tsx
        <section className="modal-section">
          <h3>Browsers</h3>
          {browsers.length > 0 ? (
            <ul className="browser-list">
              {browsers.map((b) => (
                <li key={b.clientId}>
                  <span>{b.name}</span>
                  <button className="icon" aria-label={`Disconnect ${b.name}`} title="Disconnect" onClick={() => disconnect(b)}>
                    <IconClose />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">No browsers connected yet.</p>
          )}
          <div className="modal-actions">
            <span className="status" role="status" aria-label="Browsers">
              {browsersNote}
            </span>
            <button className="secondary" onClick={connectBrowsers}>
              Connect browsers
            </button>
          </div>
        </section>
```
with state/handlers:
```tsx
  const [browsers, setBrowsers] = useState<PairedBrowser[]>([]);
  const [browsersNote, setBrowsersNote] = useState("");
  useEffect(() => {
    api.pairedBrowsers().then(setBrowsers).catch(() => setBrowsers([]));
  }, []);
  async function connectBrowsers() {
    try {
      const found = await api.connectBrowsers();
      setBrowsersNote(
        found.length
          ? `Ready in ${found.join(", ")}. Load the Lockbox extension there and click Connect.`
          : "No supported browsers found.",
      );
    } catch (e) {
      setBrowsersNote(errorMessage(e));
    }
  }
  async function disconnect(b: PairedBrowser) {
    try {
      await api.removePairedBrowser(b.clientId);
      setBrowsers((all) => all.filter((x) => x.clientId !== b.clientId));
    } catch (e) {
      setBrowsersNote(errorMessage(e));
    }
  }
```
Imports: `PairedBrowser` type, `IconClose` from `./icons` (already imported there). CSS: `.browser-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; } .browser-list li { display: flex; justify-content: space-between; align-items: center; padding: 6px 4px 6px 12px; background: var(--surface-2); border-radius: 12px; font-weight: 600; }` and `.modal-actions .status` already exists (it uses `--success`; fine for this note).

- [ ] **Step 5: Run** `pnpm test && pnpm typecheck`. **Step 6: Commit** — `"Approve browser pairings and manage connected browsers"`

---

### Task 9: Extension scaffold, build and crypto

**Files:** Create `extension/package.json`, `tsconfig.json`, `build.mjs`, `vitest.config.ts`, `icons/` (generated), `src/crypto.ts`, `src/crypto.test.ts`; modify root `.gitignore` (`extension/dist/`), `.github/workflows/ci.yml`.

- [ ] **Step 1: Toolchain**

`extension/package.json`:
```json
{
  "name": "lockbox-extension",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "build": "node build.mjs",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  }
}
```
Then (from `extension/`): `pnpm add @noble/curves@^2.4.0 @noble/ciphers@^2.4.0 @noble/hashes@^2.4.0 && pnpm add -D esbuild typescript@~6.0.3 vitest@^5 jsdom@^30 @types/chrome`.

`extension/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["chrome"],
    "strict": true,
    "noEmit": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "skipLibCheck": true,
    "isolatedModules": true
  },
  "include": ["src", "build.mjs"]
}
```
(If `build.mjs` in `include` causes type errors, drop it from `include`.)

`extension/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";

export default defineConfig({ test: { environment: "jsdom", include: ["src/**/*.test.ts"] } });
```

`extension/build.mjs`:
```js
// Builds dist/chromium and dist/firefox from one source tree.
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

const KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2jJDTesCwmnIGSvj2HgKyf7bWpFpdIxq94r0rACWQ8xIsJtCZLKWRrIdX6WcKkM0DiQnIfdrnAwjeQJA68Qfefz6VHswDzp2dMIQzoN6HThOUZfvgyQJ1xtINCVSrJlQWplOKvvqwq4H8pwnoA/WNGp40PHmVxs8ihfcUHR2+zeCfs9LTBmIFVdoJg8/QbH9iSnWEs3a766Z2XHmFyfRP9Sx85XvdSSofpyyvtPIp8fQUXuC952WFOk3Q3PX5AeeoDawIhCc8GIwMj4lers9rmjyy2ZYaJguLFPAjQwGvRVdADg39FVUbF4MATRlFdfkYBmR0fX6j6SDDDpaiAGHNwIDAQAB";

const icons = { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" };

const base = {
  manifest_version: 3,
  name: "Lockbox",
  version: "0.1.0",
  description: "Fill passwords and one-time codes from the Lockbox app on your Mac.",
  icons,
  permissions: ["nativeMessaging", "storage", "activeTab"],
  action: { default_popup: "popup.html", default_title: "Lockbox", default_icon: icons },
  content_scripts: [
    { matches: ["http://*/*", "https://*/*"], js: ["content.js"], all_frames: true, run_at: "document_idle" },
  ],
  commands: {
    "fill-login": {
      suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" },
      description: "Fill the best login for this page",
    },
  },
};

const targets = {
  chromium: { ...base, key: KEY, minimum_chrome_version: "116", background: { service_worker: "background.js" } },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: { gecko: { id: "lockbox@lockbox.app", strict_min_version: "128.0" } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const out = `dist/${name}`;
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  await build({
    entryPoints: { background: "src/background.ts", content: "src/content.ts", popup: "src/popup/popup.ts" },
    bundle: true,
    format: "iife",
    target: "es2022",
    outdir: out,
    minify: false,
    legalComments: "none",
  });
  cpSync("src/popup/popup.html", `${out}/popup.html`);
  cpSync("src/popup/popup.css", `${out}/popup.css`);
  cpSync("icons", `${out}/icons`, { recursive: true });
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log(`built ${out}`);
}
```

Icons (from `extension/`):
```bash
mkdir -p icons && for s in 16 32 48 128; do sips -z $s $s ../app/src-tauri/icons/icon.png --out icons/$s.png >/dev/null; done
```

Root `.gitignore`: add `extension/dist/`. CI: add a job like `frontend` with `working-directory: extension`, `cache-dependency-path: extension/pnpm-lock.yaml`, running `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test`.

The build needs `src/background.ts`, `src/content.ts`, `src/popup/*` (Tasks 10–13). Until then only tests run; `pnpm build` is first run in Task 13.

- [ ] **Step 2: Failing test** — `src/crypto.test.ts`:

```ts
import { expect, test } from "vitest";
import { derive, fromB64, newKeyPair, open, seal, toB64 } from "./crypto";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const CLIENT_ID = "11111111-1111-4111-8111-111111111111";

test("matches the shared test vectors", () => {
  const client = newKeyPair(new Uint8Array(32).fill(1));
  const server = newKeyPair(new Uint8Array(32).fill(2));
  expect(hex(client.public)).toBe("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209");
  expect(hex(server.public)).toBe("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59");
  const d = derive(client, server.public, client.public, server.public);
  expect(hex(d.key)).toBe("a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab");
  expect(d.code).toBe("381262");
  expect(seal(d.key, CLIENT_ID, "req", { op: "ping" }, new Uint8Array(24).fill(3))).toBe(
    "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD1AE3nLoQfQz8s+kYte/Lb0sVrtQoMnmqsIE17w4=",
  );
});

test("boxes are bound to key, client and direction", () => {
  const key = new Uint8Array(32).fill(7);
  const boxed = seal(key, CLIENT_ID, "res", { hello: 1 });
  expect(open(key, CLIENT_ID, "res", boxed)).toEqual({ hello: 1 });
  expect(open(key, CLIENT_ID, "req", boxed)).toBeNull();
  expect(open(key, "other", "res", boxed)).toBeNull();
  expect(open(new Uint8Array(32).fill(8), CLIENT_ID, "res", boxed)).toBeNull();
  expect(open(key, CLIENT_ID, "res", "AAAA")).toBeNull();
  expect(seal(key, CLIENT_ID, "res", { hello: 1 })).not.toBe(boxed);
});

test("base64 round trip", () => {
  const bytes = new Uint8Array([0, 1, 254, 255]);
  expect(fromB64(toB64(bytes))).toEqual(bytes);
});
```

- [ ] **Step 3: Run** `pnpm test` → fails (module missing).
- [ ] **Step 4: Implement** — `src/crypto.ts`:

```ts
// Mirrors crates/lockbox-session/src/bridge/crypto.rs; both are pinned by the same test vectors.
import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

export const PROTOCOL = "lockbox-bridge-v1";
const enc = new TextEncoder();
const dec = new TextDecoder();

export interface KeyPair {
  secret: Uint8Array;
  public: Uint8Array;
}

export function newKeyPair(secret: Uint8Array = randomBytes(32)): KeyPair {
  return { secret, public: x25519.getPublicKey(secret) };
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function derive(own: KeyPair, peerPublic: Uint8Array, clientPublic: Uint8Array, serverPublic: Uint8Array) {
  const shared = x25519.getSharedSecret(own.secret, peerPublic);
  const hash = (label: string) => sha256(concat(enc.encode(`${PROTOCOL}/${label}`), shared, clientPublic, serverPublic));
  const key = hash("key");
  const c = hash("code");
  const n = ((c[0] << 24) >>> 0) + (c[1] << 16) + (c[2] << 8) + c[3];
  return { key, code: String(n % 1_000_000).padStart(6, "0") };
}

export type Direction = "req" | "res";

const aad = (clientId: string, direction: Direction) => enc.encode(`${PROTOCOL}/${clientId}/${direction}`);

export function seal(key: Uint8Array, clientId: string, direction: Direction, value: unknown, nonce: Uint8Array = randomBytes(24)): string {
  const ciphertext = xchacha20poly1305(key, nonce, aad(clientId, direction)).encrypt(enc.encode(JSON.stringify(value)));
  return toB64(concat(nonce, ciphertext));
}

export function open<T>(key: Uint8Array, clientId: string, direction: Direction, boxed: string): T | null {
  try {
    const raw = fromB64(boxed);
    if (raw.length < 40) return null;
    const plain = xchacha20poly1305(key, raw.slice(0, 24), aad(clientId, direction)).decrypt(raw.slice(24));
    return JSON.parse(dec.decode(plain)) as T;
  } catch {
    return null;
  }
}

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}
```

- [ ] **Step 5: Run** `pnpm test && pnpm typecheck`. **Step 6: Commit** — `"Scaffold the browser extension with bridge crypto"` (include `pnpm-lock.yaml`, `icons/`).

---

### Task 10: Extension client and background

**Files:** Create `extension/src/client.ts`, `client.test.ts`, `background.ts`, `messages.ts`.

- [ ] **Step 1: Failing tests** — `src/client.test.ts` (a fake app built on the same crypto):

```ts
import { beforeEach, expect, test } from "vitest";
import { Client, LockedError, type Pairing, type PairingStore } from "./client";
import { derive, fromB64, newKeyPair, open, seal, toB64 } from "./crypto";

class FakeApp {
  locked = false;
  running = true;
  approved = false;
  keys = new Map<string, Uint8Array>();
  pendingKey: Uint8Array | null = null;
  code = "";
  items = [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: false }];

  async send(msg: any): Promise<any> {
    if (!this.running) throw new Error("Native host has exited.");
    switch (msg.kind) {
      case "status":
        return { kind: "status", locked: this.locked, version: 1 };
      case "pair": {
        const server = newKeyPair();
        const clientPub = fromB64(msg.clientPub);
        const d = derive(server, clientPub, clientPub, server.public);
        this.pendingKey = d.key;
        this.code = d.code;
        return { kind: "pairPending", clientId: "c1", serverPub: toB64(server.public) };
      }
      case "pairStatus":
        if (!this.approved) return { kind: "pairPending", clientId: "c1", serverPub: "" };
        this.keys.set("c1", this.pendingKey!);
        return { kind: "paired" };
      case "call": {
        if (this.locked) return { kind: "locked" };
        const key = this.keys.get(msg.clientId);
        if (!key) return { kind: "unknownClient" };
        const req = open<any>(key, msg.clientId, "req", msg.box)!;
        const reply = req.op === "ping" ? { pong: true } : req.op === "list" ? { items: this.items } : { username: "ivan", password: "pw", totp: null };
        return { kind: "reply", box: seal(key, msg.clientId, "res", reply) };
      }
    }
  }
}

class MemoryStore implements PairingStore {
  pairing: Pairing | null = null;
  pending: Pairing | null = null;
  async get() { return this.pairing; }
  async set(p: Pairing) { this.pairing = p; }
  async clear() { this.pairing = null; }
  async getPending() { return this.pending; }
  async setPending(p: Pairing | null) { this.pending = p; }
}

let app: FakeApp;
let store: MemoryStore;
let client: Client;

beforeEach(() => {
  app = new FakeApp();
  store = new MemoryStore();
  client = new Client((m) => app.send(m), store);
});

test("no app, unpaired, paired, locked", async () => {
  app.running = false;
  expect(await client.state()).toBe("noApp");
  app.running = true;
  expect(await client.state()).toBe("unpaired");

  const { code } = await client.startPairing("Chrome");
  expect(code).toBe(app.code);
  expect(await client.pairingResult()).toBe("waiting");
  app.approved = true;
  expect(await client.pairingResult()).toBe("paired");
  expect(await client.state()).toBe("ready");

  app.locked = true;
  expect(await client.state()).toBe("locked");
  await expect(client.list("https://github.com")).rejects.toBeInstanceOf(LockedError);
});

test("lists and fills once paired", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  expect(await client.list("https://github.com")).toEqual(app.items);
  expect(await client.fill("https://github.com", "i1")).toEqual({ username: "ivan", password: "pw", totp: null });
});

test("a forgotten pairing resets to unpaired", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  app.keys.clear();
  expect(await client.state()).toBe("unpaired");
  expect(store.pairing).toBeNull();
});
```

- [ ] **Step 2: Run** → fails.
- [ ] **Step 3: Implement**

`src/client.ts`:
```ts
// Talks to the Lockbox app: pairing, then sealed list/fill calls. Transport and storage are injected.
import { derive, fromB64, newKeyPair, open, seal, toB64 } from "./crypto";

export type State = "noApp" | "unpaired" | "locked" | "ready";

export interface Pairing {
  clientId: string;
  /** base64 session key */
  key: string;
}

export interface PairingStore {
  get(): Promise<Pairing | null>;
  set(p: Pairing): Promise<void>;
  clear(): Promise<void>;
  getPending(): Promise<Pairing | null>;
  setPending(p: Pairing | null): Promise<void>;
}

export interface Candidate {
  id: string;
  title: string;
  username: string;
  hasTotp: boolean;
}

export interface Credentials {
  username: string;
  password: string;
  totp: string | null;
}

export type Send = (msg: object) => Promise<any>;

export class LockedError extends Error {}
export class UnpairedError extends Error {}
export class NoAppError extends Error {}

export class Client {
  constructor(
    private send: Send,
    private store: PairingStore,
  ) {}

  async state(): Promise<State> {
    let status: any;
    try {
      status = await this.send({ kind: "status" });
    } catch {
      return "noApp";
    }
    if (!(await this.store.get())) return "unpaired";
    if (status?.locked) return "locked";
    try {
      await this.request({ op: "ping" });
      return "ready";
    } catch (e) {
      if (e instanceof UnpairedError) return "unpaired";
      if (e instanceof LockedError) return "locked";
      throw e;
    }
  }

  async startPairing(name: string): Promise<{ code: string }> {
    const keys = newKeyPair();
    const res = await this.transport({ kind: "pair", clientPub: toB64(keys.public), name });
    if (res.kind === "locked") throw new LockedError();
    if (res.kind !== "pairPending") throw new Error(res.message ?? "Pairing failed");
    const serverPub = fromB64(res.serverPub);
    const { key, code } = derive(keys, serverPub, keys.public, serverPub);
    await this.store.setPending({ clientId: res.clientId, key: toB64(key) });
    return { code };
  }

  async pairingResult(): Promise<"waiting" | "paired" | "denied"> {
    const pending = await this.store.getPending();
    if (!pending) return "denied";
    const res = await this.transport({ kind: "pairStatus", clientId: pending.clientId });
    if (res.kind === "pairPending") return "waiting";
    await this.store.setPending(null);
    if (res.kind === "paired") {
      await this.store.set(pending);
      return "paired";
    }
    return "denied";
  }

  async list(url: string): Promise<Candidate[]> {
    return (await this.request({ op: "list", url })).items;
  }

  async fill(url: string, itemId: string): Promise<Credentials> {
    const r = await this.request({ op: "fill", url, itemId });
    return { username: r.username, password: r.password, totp: r.totp ?? null };
  }

  async show(): Promise<void> {
    await this.transport({ kind: "show" });
  }

  private async transport(msg: object): Promise<any> {
    try {
      return await this.send(msg);
    } catch {
      throw new NoAppError();
    }
  }

  private async request(req: object): Promise<any> {
    const pairing = await this.store.get();
    if (!pairing) throw new UnpairedError();
    const key = fromB64(pairing.key);
    const res = await this.transport({ kind: "call", clientId: pairing.clientId, box: seal(key, pairing.clientId, "req", req) });
    if (res.kind === "locked") throw new LockedError();
    if (res.kind === "unknownClient") {
      await this.store.clear();
      throw new UnpairedError();
    }
    if (res.kind !== "reply") throw new Error(res.message ?? "Lockbox error");
    const reply = open<any>(key, pairing.clientId, "res", res.box);
    if (!reply) throw new Error("Lockbox sent a reply that did not authenticate");
    if (reply.error) throw new Error(reply.error);
    return reply;
  }
}
```

`src/messages.ts` (shared between content, popup and background):
```ts
import type { Candidate, Credentials, State } from "./client";

/** Requests to the background; the page URL for content scripts comes from the browser, not the message. */
export type ToBackground =
  | { type: "state" }
  | { type: "pair" }
  | { type: "pairStatus" }
  | { type: "show" }
  | { type: "list"; url?: string }
  | { type: "fill"; itemId: string };

/** Requests from the popup/shortcut to the content script in the top frame. */
export type ToContent = { type: "fill-item"; itemId: string } | { type: "fill-best" };

export type ErrorKind = "noApp" | "locked" | "unpaired" | "other";
export type Result<T> = { ok: true; value: T } | { ok: false; error: ErrorKind; message: string };

export type { Candidate, Credentials, State };

export async function ask<T>(msg: ToBackground): Promise<Result<T>> {
  return chrome.runtime.sendMessage(msg);
}
```

`src/background.ts`:
```ts
import { Client, LockedError, NoAppError, UnpairedError, type Pairing } from "./client";
import type { ErrorKind, Result, ToBackground, ToContent } from "./messages";

const HOST = "app.lockbox.bridge";

const client = new Client((msg) => chrome.runtime.sendNativeMessage(HOST, msg), {
  get: async () => ((await chrome.storage.local.get("pairing")).pairing as Pairing | undefined) ?? null,
  set: (p) => chrome.storage.local.set({ pairing: p }),
  clear: () => chrome.storage.local.remove("pairing"),
  getPending: async () => ((await chrome.storage.session.get("pending")).pending as Pairing | undefined) ?? null,
  setPending: (p) => (p ? chrome.storage.session.set({ pending: p }) : chrome.storage.session.remove("pending")),
});

function browserName(): string {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/YaBrowser\//.test(ua)) return "Yandex";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Edg\//.test(ua)) return "Edge";
  if (/Vivaldi\//.test(ua)) return "Vivaldi";
  return "Chrome";
}

function kind(e: unknown): ErrorKind {
  if (e instanceof LockedError) return "locked";
  if (e instanceof UnpairedError) return "unpaired";
  if (e instanceof NoAppError) return "noApp";
  return "other";
}

/** Content scripts: the URL of the frame that asked, as the browser reports it. Popup: the active tab's. */
async function pageUrl(msg: { url?: string }, sender: chrome.runtime.MessageSender): Promise<string> {
  if (sender.tab) return sender.url ?? sender.tab.url ?? "";
  if (msg.url) return msg.url;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? "";
}

async function handle(msg: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (msg.type) {
    case "state":
      return client.state();
    case "pair":
      return client.startPairing(browserName());
    case "pairStatus":
      return client.pairingResult();
    case "show":
      return client.show();
    case "list":
      return client.list(await pageUrl(msg, sender));
    case "fill":
      if (!sender.tab) throw new Error("Fill is only available from the page");
      return client.fill(await pageUrl(msg, sender), msg.itemId);
  }
}

chrome.runtime.onMessage.addListener((msg: ToBackground, sender, respond) => {
  handle(msg, sender).then(
    (value) => respond({ ok: true, value } satisfies Result<unknown>),
    (e) => respond({ ok: false, error: kind(e), message: e instanceof Error ? e.message : String(e) } satisfies Result<unknown>),
  );
  return true;
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== "fill-login" || tab?.id === undefined) return;
  chrome.tabs.sendMessage(tab.id, { type: "fill-best" } satisfies ToContent, { frameId: 0 }).catch(() => {});
});
```

Fill is refused for the popup on purpose: the popup asks the content script (which then calls `fill` from the page, so the URL check uses the frame's real URL).

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Add the extension client and background worker"`

---

### Task 11: Field detection and filling

**Files:** Create `extension/src/detect.ts`, `detect.test.ts`, `fill.ts`, `fill.test.ts`.

- [ ] **Step 1: Failing tests**

`src/detect.test.ts`:
```ts
import { beforeEach, expect, test } from "vitest";
import { findLoginFields } from "./detect";

function page(html: string) {
  document.body.innerHTML = html;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

test("classic login form", () => {
  page(`<form><input name="q" type="search"><input id="login" name="login" type="text"><input type="password" name="password"><button>Sign in</button></form>`);
  const f = findLoginFields(document);
  expect(f.username?.id).toBe("login");
  expect(f.password?.name).toBe("password");
  expect(f.totp).toBeNull();
});

test("autocomplete hints win", () => {
  page(`<input type="text" name="a"><input type="email" autocomplete="username" name="who"><input type="password" autocomplete="current-password" name="pw">`);
  const f = findLoginFields(document);
  expect(f.username?.name).toBe("who");
  expect(f.password?.name).toBe("pw");
});

test("username-first step", () => {
  page(`<form><label for="e">Email</label><input id="e" type="email"><button>Next</button></form>`);
  const f = findLoginFields(document);
  expect(f.username?.id).toBe("e");
  expect(f.password).toBeNull();
});

test("one-time code step", () => {
  page(`<form><input name="app_otp" inputmode="numeric" maxlength="6" type="text"><button>Verify</button></form>`);
  expect(findLoginFields(document).totp?.name).toBe("app_otp");
  page(`<input autocomplete="one-time-code" name="c">`);
  expect(findLoginFields(document).totp?.name).toBe("c");
});

test("ignores hidden, disabled and sign-up password fields", () => {
  page(`<input type="password" name="h" style="display:none"><input type="password" name="d" disabled><input type="password" autocomplete="new-password" name="n">`);
  expect(findLoginFields(document).password).toBeNull();
});
```

`src/fill.test.ts`:
```ts
import { expect, test } from "vitest";
import { fillLogin, setValue } from "./fill";

test("setValue fires input and change", () => {
  document.body.innerHTML = `<input id="a">`;
  const input = document.getElementById("a") as HTMLInputElement;
  const seen: string[] = [];
  input.addEventListener("input", () => seen.push(`input:${input.value}`));
  input.addEventListener("change", () => seen.push(`change:${input.value}`));
  setValue(input, "ivan");
  expect(input.value).toBe("ivan");
  expect(seen).toEqual(["input:ivan", "change:ivan"]);
});

test("fillLogin fills what exists and counts it", () => {
  document.body.innerHTML = `<input id="u"><input id="p" type="password">`;
  const u = document.getElementById("u") as HTMLInputElement;
  const p = document.getElementById("p") as HTMLInputElement;
  const n = fillLogin({ username: u, password: p, totp: null }, { username: "ivan", password: "pw", totp: "123456" });
  expect(n).toBe(2);
  expect([u.value, p.value]).toEqual(["ivan", "pw"]);
});
```

- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement**

`src/detect.ts`:
```ts
// Finds the username, password and one-time-code fields on a page.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  totp: HTMLInputElement | null;
}

const USER_HINT = /user|login|email|e-mail|account|phone|ident|логин|почт/i;
const TOTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code|код/i;
const TEXTISH = new Set(["text", "email", "tel", "number", ""]);

function usable(el: HTMLInputElement): boolean {
  if (el.disabled || el.readOnly || el.type === "hidden") return false;
  for (let n: HTMLElement | null = el; n; n = n.parentElement) {
    const s = getComputedStyle(n);
    if (n.hidden || s.display === "none" || s.visibility === "hidden") return false;
  }
  return true;
}

function hints(el: HTMLInputElement): string {
  const label = el.labels?.[0]?.textContent ?? "";
  return [el.name, el.id, el.placeholder, el.getAttribute("aria-label") ?? "", label].join(" ");
}

function isTotp(el: HTMLInputElement): boolean {
  if (el.autocomplete === "one-time-code") return true;
  if (!TEXTISH.has(el.type)) return false;
  const short = el.maxLength >= 4 && el.maxLength <= 8;
  return TOTP_HINT.test(hints(el)) && (short || el.inputMode === "numeric" || el.type === "tel" || el.type === "number");
}

export function findLoginFields(root: Document | HTMLElement): LoginFields {
  const inputs = Array.from(root.querySelectorAll("input")).filter(usable);
  const password =
    inputs.find((i) => i.type === "password" && i.autocomplete === "current-password") ??
    inputs.find((i) => i.type === "password" && i.autocomplete !== "new-password") ??
    null;
  const totp = inputs.find((i) => i !== password && isTotp(i)) ?? null;
  const candidates = inputs.filter((i) => i !== totp && TEXTISH.has(i.type) && i.type !== "number");
  const scope = password ? candidates.filter((i) => i.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) : candidates;
  const username =
    scope.find((i) => i.autocomplete === "username" || i.autocomplete === "email") ??
    (password ? scope[scope.length - 1] : scope.find((i) => i.type === "email" || USER_HINT.test(hints(i)))) ??
    null;
  return { username: username ?? null, password, totp };
}
```

`src/fill.ts`:
```ts
import type { LoginFields } from "./detect";
import type { Credentials } from "./client";

/** Sets a value the way a user would, so frameworks (React, Vue) notice it. */
export function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

export function fillLogin(fields: LoginFields, creds: Credentials): number {
  let filled = 0;
  if (fields.username && creds.username) {
    setValue(fields.username, creds.username);
    filled++;
  }
  if (fields.password && creds.password) {
    setValue(fields.password, creds.password);
    filled++;
  }
  if (fields.totp && creds.totp) {
    setValue(fields.totp, creds.totp);
    filled++;
  }
  return filled;
}
```

In the "classic login form" test the search box comes before the login field; `scope[scope.length - 1]` picks the input right before the password — correct. The one-time code test's `<input name="app_otp" maxlength="6">`: jsdom reports `maxLength` from the attribute.

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Detect login fields and fill them like a user"`

---

### Task 12: Inline icon and dropdown

**Files:** Create `extension/src/inline.ts`, `inline.test.ts`, `content.ts`.

- [ ] **Step 1: Failing tests** — `src/inline.test.ts`:

```ts
import { beforeEach, expect, test, vi } from "vitest";
import { InlineMenu, type MenuActions } from "./inline";

let actions: MenuActions;
let menu: InlineMenu;
let field: HTMLInputElement;

beforeEach(() => {
  document.body.innerHTML = `<input id="u">`;
  field = document.getElementById("u") as HTMLInputElement;
  actions = {
    list: vi.fn().mockResolvedValue({ state: "ready", items: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: true }] }),
    fill: vi.fn().mockResolvedValue(undefined),
    unlock: vi.fn().mockResolvedValue(undefined),
  };
  menu = new InlineMenu(actions);
});

const shadow = () => document.querySelector("lockbox-inline")!.shadowRoot!;

test("focusing a field shows the icon; clicking it lists logins; picking one fills", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const icon = shadow().querySelector<HTMLButtonElement>("button.icon")!;
  expect(icon.getAttribute("aria-label")).toBe("Fill with Lockbox");
  icon.click();
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  expect(shadow().querySelector(".item")!.textContent).toContain("GitHub");
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.fill).toHaveBeenCalledWith("i1");
});

test("locked and unpaired states", async () => {
  vi.mocked(actions.list).mockResolvedValue({ state: "locked", items: [] });
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Lockbox is locked"));
  shadow().querySelector<HTMLButtonElement>("button.unlock")!.click();
  expect(actions.unlock).toHaveBeenCalled();

  vi.mocked(actions.list).mockResolvedValue({ state: "unpaired", items: [] });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Connect this browser"));
});

test("no logins for the site", async () => {
  vi.mocked(actions.list).mockResolvedValue({ state: "ready", items: [] });
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("No logins for this site"));
});
```

- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** — `src/inline.ts`:

```ts
// The Lockbox icon inside focused login fields and its dropdown, isolated in a shadow root.
import type { Candidate, State } from "./client";

export interface MenuActions {
  list(): Promise<{ state: State; items: Candidate[] }>;
  fill(itemId: string): Promise<void>;
  unlock(): Promise<void>;
}

const KEYHOLE = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="9" r="4" fill="currentColor"/><path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor"/></svg>`;

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
.icon { position: fixed; z-index: 2147483646; width: 24px; height: 24px; border-radius: 7px; border: 0; padding: 0;
  display: grid; place-items: center; background: #111; color: #fff; cursor: pointer; box-shadow: 0 1px 3px rgba(0,0,0,.25);
  transition: transform 120ms cubic-bezier(.2,.8,.2,1), opacity 120ms; }
.icon:hover { transform: scale(1.08); }
.panel { position: fixed; z-index: 2147483647; min-width: 260px; max-width: 340px; padding: 6px; border-radius: 16px;
  background: rgba(255,255,255,.96); color: #111; box-shadow: 0 12px 40px rgba(17,17,17,.2), 0 2px 6px rgba(17,17,17,.08);
  backdrop-filter: blur(20px); animation: pop 160ms cubic-bezier(.2,.8,.2,1); font-size: 13px; }
@media (prefers-color-scheme: dark) { .panel { background: rgba(32,32,34,.96); color: #f5f5f7; } .icon { background: #f5f5f7; color: #111; } }
@keyframes pop { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
.item, .unlock { width: 100%; display: flex; align-items: center; gap: 10px; padding: 8px 10px; border: 0; border-radius: 10px;
  background: transparent; color: inherit; text-align: left; cursor: pointer; font-size: 13px; }
.item:hover, .item:focus-visible, .unlock:hover { background: rgba(127,127,127,.14); outline: none; }
.mono { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; flex-shrink: 0;
  background: rgba(127,127,127,.16); font-weight: 800; text-transform: uppercase; }
.text { display: flex; flex-direction: column; min-width: 0; }
.title { font-weight: 600; } .sub { opacity: .6; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.note { padding: 10px; opacity: .7; }
@media (prefers-reduced-motion: reduce) { .panel { animation: none; } .icon { transition: none; } }
`;

export class InlineMenu {
  private host: HTMLElement;
  private root: ShadowRoot;
  private icon: HTMLButtonElement;
  private panel: HTMLDivElement | null = null;
  private field: HTMLInputElement | null = null;

  constructor(private actions: MenuActions) {
    this.host = document.createElement("lockbox-inline");
    this.root = this.host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.icon = document.createElement("button");
    this.icon.className = "icon";
    this.icon.type = "button";
    this.icon.setAttribute("aria-label", "Fill with Lockbox");
    this.icon.innerHTML = KEYHOLE;
    this.icon.hidden = true;
    this.icon.addEventListener("mousedown", (e) => e.preventDefault());
    this.icon.addEventListener("click", () => this.open());
    this.root.append(style, this.icon);
    document.documentElement.append(this.host);
    window.addEventListener("scroll", () => this.place(), true);
    window.addEventListener("resize", () => this.place());
    document.addEventListener("mousedown", (e) => {
      if (!e.composedPath().includes(this.host)) this.close();
    });
  }

  watch(field: HTMLInputElement): void {
    if (field.dataset.lockbox) return;
    field.dataset.lockbox = "1";
    field.addEventListener("focus", () => {
      this.field = field;
      this.icon.hidden = false;
      this.place();
    });
    field.addEventListener("blur", () => setTimeout(() => !this.panel && (this.icon.hidden = true), 150));
  }

  async open(): Promise<void> {
    this.close();
    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "listbox");
    panel.innerHTML = `<div class="note">Loading…</div>`;
    this.root.append(panel);
    this.panel = panel;
    this.place();
    const { state, items } = await this.actions.list();
    if (this.panel !== panel) return;
    panel.replaceChildren();
    if (state === "locked") {
      panel.append(note("Lockbox is locked"), button("unlock", "Unlock Lockbox", () => this.actions.unlock()));
    } else if (state === "unpaired") {
      panel.append(note("Connect this browser: open the Lockbox extension in the toolbar."));
    } else if (state === "noApp") {
      panel.append(note("Lockbox isn't running."), button("unlock", "Open Lockbox", () => this.actions.unlock()));
    } else if (items.length === 0) {
      panel.append(note("No logins for this site"));
    } else {
      for (const item of items) panel.append(entry(item, () => this.choose(item.id)));
    }
  }

  close(): void {
    this.panel?.remove();
    this.panel = null;
  }

  private async choose(itemId: string): Promise<void> {
    this.close();
    this.icon.hidden = true;
    await this.actions.fill(itemId);
  }

  private place(): void {
    if (!this.field) return;
    const r = this.field.getBoundingClientRect();
    this.icon.style.left = `${r.right - 30}px`;
    this.icon.style.top = `${r.top + (r.height - 24) / 2}px`;
    if (this.panel) {
      this.panel.style.left = `${Math.max(8, r.right - 300)}px`;
      this.panel.style.top = `${r.bottom + 6}px`;
    }
  }
}

function note(text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = "note";
  el.textContent = text;
  return el;
}

function button(className: string, text: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

function entry(item: Candidate, onClick: () => void): HTMLButtonElement {
  const b = button("item", "", onClick);
  b.setAttribute("role", "option");
  const mono = document.createElement("span");
  mono.className = "mono";
  mono.textContent = item.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "•";
  const text = document.createElement("span");
  text.className = "text";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = item.title;
  const sub = document.createElement("span");
  sub.className = "sub";
  sub.textContent = item.username + (item.hasTotp ? " · one-time code" : "");
  text.append(title, sub);
  b.append(mono, text);
  return b;
}
```

All page text goes in via `textContent`, never `innerHTML`, except the constant icon SVG.

`src/content.ts`:
```ts
import { findLoginFields } from "./detect";
import { fillLogin } from "./fill";
import { InlineMenu } from "./inline";
import { ask, type Candidate, type Credentials, type State, type ToContent } from "./messages";

async function list(): Promise<{ state: State; items: Candidate[] }> {
  const r = await ask<Candidate[]>({ type: "list" });
  if (r.ok) return { state: "ready", items: r.value };
  return { state: r.error === "other" ? "ready" : r.error, items: [] };
}

async function fillItem(itemId: string): Promise<void> {
  const r = await ask<Credentials>({ type: "fill", itemId });
  if (r.ok) fillLogin(findLoginFields(document), r.value);
}

const menu = new InlineMenu({
  list,
  fill: fillItem,
  unlock: async () => {
    await ask({ type: "show" });
  },
});

function scan(): void {
  const f = findLoginFields(document);
  for (const field of [f.username, f.password, f.totp]) if (field) menu.watch(field);
}

let timer: number | undefined;
new MutationObserver(() => {
  clearTimeout(timer);
  timer = window.setTimeout(scan, 300);
}).observe(document.documentElement, { childList: true, subtree: true });
scan();

chrome.runtime.onMessage.addListener((msg: ToContent, _sender, respond) => {
  (async () => {
    if (msg.type === "fill-item") await fillItem(msg.itemId);
    if (msg.type === "fill-best") {
      const { items } = await list();
      if (items[0]) await fillItem(items[0].id);
    }
  })().then(() => respond({}), () => respond({}));
  return true;
});
```

`messages.ts` must also export `ToContent` (it does). The content script runs in every frame; only the top frame receives `fill-best`/`fill-item` (sent with `frameId: 0`).

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Inline Lockbox icon and dropdown in login fields"`

---

### Task 13: Popup and build

**Files:** Create `extension/src/popup/popup.html`, `popup.css`, `popup.ts`, `popup.test.ts`.

- [ ] **Step 1: Failing tests** — `src/popup/popup.test.ts`:

```ts
import { beforeEach, expect, test, vi } from "vitest";
import { renderPopup, type PopupDeps } from "./popup";

let deps: PopupDeps;

beforeEach(() => {
  document.body.innerHTML = `<main id="app"></main>`;
  deps = {
    ask: vi.fn(),
    activeTab: vi.fn().mockResolvedValue({ id: 7, url: "https://github.com/login" }),
    fillInTab: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    sleep: () => Promise.resolve(),
  };
});

const app = () => document.getElementById("app")!;

test("unpaired: connect shows the code and waits for approval", async () => {
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "unpaired" };
    if (m.type === "pair") return { ok: true, value: { code: "381262" } };
    if (m.type === "pairStatus") return { ok: true, value: "paired" };
    if (m.type === "list") return { ok: true, value: [] };
    return { ok: true, value: undefined };
  });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Connect this browser to Lockbox");
  (app().querySelector("button.primary") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(app().textContent).toContain("381 262"));
  await vi.waitFor(() => expect(app().textContent).toContain("No logins for github.com"));
});

test("ready: lists logins and fills in the tab", async () => {
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "ready" };
    if (m.type === "list") return { ok: true, value: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: false }] };
    return { ok: true, value: undefined };
  });
  await renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().textContent).toContain("GitHub"));
  (app().querySelector("button.item") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(deps.fillInTab).toHaveBeenCalledWith(7, "i1"));
  expect(deps.close).toHaveBeenCalled();
});

test("locked and no app", async () => {
  vi.mocked(deps.ask).mockResolvedValue({ ok: true, value: "locked" });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Lockbox is locked");
  vi.mocked(deps.ask).mockResolvedValue({ ok: true, value: "noApp" });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Lockbox isn't running");
});
```

- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement**

`src/popup/popup.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="stylesheet" href="popup.css" />
    <title>Lockbox</title>
  </head>
  <body>
    <main id="app"></main>
    <script src="popup.js"></script>
  </body>
</html>
```

`src/popup/popup.css`:
```css
:root { color-scheme: light dark; --bg: #f1f2f3; --surface: #fff; --text: #111; --muted: #76767b; --hover: rgba(17,17,17,.05); --cta: #111; --cta-text: #fff; }
@media (prefers-color-scheme: dark) { :root { --bg: #161618; --surface: #222224; --text: #f5f5f7; --muted: #8e8e93; --hover: rgba(255,255,255,.06); --cta: #f5f5f7; --cta-text: #111; } }
* { box-sizing: border-box; }
body { margin: 0; width: 340px; background: var(--bg); color: var(--text); font: 500 13px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
main { padding: 14px; display: flex; flex-direction: column; gap: 10px; animation: in 180ms cubic-bezier(.2,.8,.2,1); }
@keyframes in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
header { display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 16px; letter-spacing: -0.03em; }
.mark { width: 26px; height: 26px; border-radius: 8px; background: var(--cta); color: var(--cta-text); display: grid; place-items: center; }
p { margin: 0; color: var(--muted); }
button { font: inherit; font-weight: 600; border-radius: 999px; padding: 8px 16px; cursor: pointer; border: 1px solid transparent; color: var(--text); background: transparent; transition: transform 120ms, background 120ms; }
button:active { transform: scale(.97); }
button.primary { background: var(--cta); color: var(--cta-text); }
.code { font: 600 30px/1.2 ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .12em; text-align: center; padding: 8px 0; color: var(--text); }
ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
button.item { width: 100%; display: flex; gap: 10px; align-items: center; text-align: left; border-radius: 12px; padding: 8px 10px; }
button.item:hover { background: var(--hover); }
.mono { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; background: var(--hover); font-weight: 800; text-transform: uppercase; flex-shrink: 0; }
.text { display: flex; flex-direction: column; min-width: 0; }
.sub { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
@media (prefers-reduced-motion: reduce) { main { animation: none; } }
```

`src/popup/popup.ts`:
```ts
import type { Candidate, Result, State, ToBackground } from "../messages";

export interface PopupDeps {
  ask<T>(msg: ToBackground): Promise<Result<T>>;
  activeTab(): Promise<{ id?: number; url?: string }>;
  fillInTab(tabId: number, itemId: string): Promise<void>;
  close(): void;
  sleep(ms: number): Promise<void>;
}

const MARK = `<span class="mark"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="9" r="4" fill="currentColor"/><path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor"/></svg></span>`;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function shell(root: HTMLElement, ...content: Node[]): void {
  const header = el("header");
  header.innerHTML = MARK;
  header.append("Lockbox");
  root.replaceChildren(header, ...content);
}

export async function renderPopup(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const state = await deps.ask<State>({ type: "state" });
  const value: State = state.ok ? state.value : state.error === "other" ? "noApp" : state.error;
  if (value === "noApp") {
    shell(root, el("p", { textContent: "Lockbox isn't running." }), el("button", { className: "primary", textContent: "Open Lockbox", onclick: () => deps.ask({ type: "show" }) }));
  } else if (value === "locked") {
    shell(root, el("p", { textContent: "Lockbox is locked." }), el("button", { className: "primary", textContent: "Unlock", onclick: () => deps.ask({ type: "show" }) }));
  } else if (value === "unpaired") {
    shell(
      root,
      el("p", { textContent: "Connect this browser to Lockbox. You'll confirm a code in the app." }),
      el("button", { className: "primary", textContent: "Connect", onclick: () => pair(root, deps) }),
    );
  } else {
    await showLogins(root, deps);
  }
}

async function pair(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const r = await deps.ask<{ code: string }>({ type: "pair" });
  if (!r.ok) {
    shell(root, el("p", { textContent: r.error === "locked" ? "Unlock Lockbox first, then try again." : r.message }));
    return;
  }
  const code = `${r.value.code.slice(0, 3)} ${r.value.code.slice(3)}`;
  shell(root, el("p", { textContent: "Confirm this code in the Lockbox app:" }), el("div", { className: "code", textContent: code }));
  for (let i = 0; i < 120; i++) {
    const s = await deps.ask<"waiting" | "paired" | "denied">({ type: "pairStatus" });
    if (s.ok && s.value === "paired") return showLogins(root, deps);
    if (!s.ok || s.value === "denied") {
      shell(root, el("p", { textContent: "Connection was declined." }));
      return;
    }
    await deps.sleep(1000);
  }
  shell(root, el("p", { textContent: "Timed out. Open the popup to try again." }));
}

async function showLogins(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const tab = await deps.activeTab();
  const host = safeHost(tab.url);
  const r = await deps.ask<Candidate[]>({ type: "list", url: tab.url });
  const items = r.ok ? r.value : [];
  if (items.length === 0) {
    shell(root, el("p", { textContent: host ? `No logins for ${host}` : "Open a website to fill a login." }));
    return;
  }
  const list = el("ul");
  for (const item of items) {
    const button = el("button", { className: "item", onclick: async () => {
      if (tab.id !== undefined) await deps.fillInTab(tab.id, item.id);
      deps.close();
    } });
    const text = el("span", { className: "text" }, el("span", { textContent: item.title }), el("span", { className: "sub", textContent: item.username }));
    button.append(el("span", { className: "mono", textContent: item.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "•" }), text);
    list.append(el("li", {}, button));
  }
  shell(root, list);
}

function safeHost(url?: string): string {
  try {
    return url ? new URL(url).hostname : "";
  } catch {
    return "";
  }
}

// Wire up when loaded as the real popup (tests import renderPopup directly).
if (typeof chrome !== "undefined" && chrome.runtime?.id && document.getElementById("app")) {
  renderPopup(document.getElementById("app")!, {
    ask: (msg) => chrome.runtime.sendMessage(msg),
    activeTab: async () => (await chrome.tabs.query({ active: true, currentWindow: true }))[0] ?? {},
    fillInTab: async (tabId, itemId) => {
      await chrome.tabs.sendMessage(tabId, { type: "fill-item", itemId }, { frameId: 0 });
    },
    close: () => window.close(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  });
}
```

- [ ] **Step 4: Run** `pnpm test && pnpm typecheck && pnpm build` → `dist/chromium` and `dist/firefox` each contain `manifest.json, background.js, content.js, popup.js, popup.html, popup.css, icons/`.
- [ ] **Step 5: Commit** — `"Add the extension popup and build"`

---

### Task 14: End-to-end in browsers (controller), docs

- [ ] **Step 1:** Full checks: `cargo fmt --all --check`, clippy for all three crates, `cargo test`, `(cd app && pnpm typecheck && pnpm test)`, `(cd extension && pnpm typecheck && pnpm test && pnpm build)`.
- [ ] **Step 2 (controller, by hand, Chrome):**
  1. Run the dev app, unlock the demo vault, add a Login "Local test" with URL `http://localhost:8765` and a TOTP secret.
  2. Serve a test page: `mkdir -p /tmp/lbtest && cat > /tmp/lbtest/login.html` with a username, password and a `one-time-code` input; `python3 -m http.server 8765 -d /tmp/lbtest`.
  3. Settings → Connect browsers (expect Chrome listed); `chrome://extensions` → Developer mode → Load unpacked `extension/dist/chromium`; check the id is `kaaofpbpmnghapcafbbhjflonijdijbj`.
  4. Toolbar popup → Connect → same code in app and popup → Connect in the app → popup lists "Local test" on the test page.
  5. Focus the username field → icon → dropdown → pick → username, password and code filled. ⌘⇧L also fills.
  6. Lock the app → icon shows "Lockbox is locked" → Unlock brings the app forward.
  7. Remove the browser in Settings → popup shows "Connect" again.
- [ ] **Step 3:** Firefox, Opera, Yandex are not installed on this Mac; ask the user before installing any (`brew install --cask firefox opera yandex`). For Firefox: `about:debugging` → This Firefox → Load Temporary Add-on → `extension/dist/firefox/manifest.json`.
- [ ] **Step 4:** README: an "Extension" section (build, load unpacked, Connect browsers, pairing). Commit, merge/push per the user.

## Self-review notes

- Spec addendum coverage: transport (Tasks 4, 5, 7), pairing with code + approval + storage in the vault (1, 3, 6, 8), sealed calls and release rules incl. frame URL from the browser (3, 6, 10, 12), site matching (2), browsers incl. Firefox (5, 9), inline icon + popup + shortcut (12, 13). Saving logins, generator on sign-up forms, cards/addresses are plan 3c; Safari is 3b.
- Type names used across tasks: `Inbound/Outbound/Request/Reply/Candidate` (Rust), `BridgeEvent/PairingRequest/PairedBrowser` re-exported from `lockbox_session`; TS `Client/State/Candidate/Credentials/Pairing/PairingStore/ToBackground/ToContent/Result`.

---

## Protocol revision after the Tasks 1–5 review (supersedes earlier text where they differ)

Implemented first as **Task 5b** (Rust), then Tasks 6, 9, 10 follow the revised shapes below.

**New shared vectors** (in addition to the table above):

| What | Value |
|---|---|
| commit of the client public (secret 32 × `0x01`) | `0508377f5f81fe96b49ca9716290979eb78f4998351ea5839718bcb263fd3f72` |
| reply box of `{"pong":true}`, key from the table, client id `11111111-1111-4111-8111-111111111111`, request nonce 24 × `0x03`, reply nonce 24 × `0x04` | `BAQEBAQEBAQEBAQEBAQEBAQEBAQEygTHFmx53/OhKi8d/MurWGQxk4F6NCh6C7zMkk8=` |

Reply AAD = UTF-8 `"lockbox-bridge-v1/<clientId>/res/"` followed by the **raw 24 bytes** of the request box's nonce. Request AAD is unchanged (`…/<clientId>/req`).

### Task 5b: Harden the bridge primitives (Rust)

- `crypto.rs`:
  - `pub fn commitment(client_public: &[u8; 32]) -> [u8; 32]` = SHA-256(`"lockbox-bridge-v1/commit"` ‖ client_public). Test against the vector.
  - `Direction` becomes `pub enum Direction { Request, Response { request_nonce: [u8; 24] } }`; `aad()` appends `b"/res/"` + nonce bytes for responses. Test: the reply vector above (`seal_with_nonce(key, CLIENT_ID, Direction::Response { request_nonce: [3; 24] }, br#"{"pong":true}"#, [4; 24])`), and that a reply sealed for nonce A doesn't open for nonce B.
  - `pub fn nonce_of(boxed: &str) -> Option<[u8; 24]>` (first 24 bytes of a well-formed box).
  - `derive` returns `Option<Derived>`: `None` when `SharedSecret::was_contributory()` is false. Test with an all-zero peer public key.
  - Update existing tests to the new signatures (vectors unchanged).
- `protocol.rs`: `Inbound::Pair { commit: String, name: String }` (field `commit`, base64 of 32 bytes) and new `Inbound::PairReveal { client_id: String, client_pub: String }` (`{"kind":"pairReveal","clientId","clientPub"}`). Update the parse test.
- `site.rs`:
  - `Site` gains `pub secure: bool` (scheme `https`) and `pub local: bool` (IP address, `localhost` or `*.localhost`).
  - `matches(page, saved)`: trim `saved`; use the `https://` fallback only when `saved` has no `"://"`, and remember that it had no scheme. If the saved URL has scheme `https`, the page is not secure, and the page isn't local → `None`.
  - Tests: `http://github.com` vs `https://github.com` → None; vs `github.com` (no scheme) → SameHost; `http://192.168.1.10:8006` vs `https://192.168.1.10:8006` → SameHost; `http://localhost:8765` vs `https://localhost:8765` → SameHost; `http://ftp/` vs `ftp://github.com` → None; `" https://github.com "` with spaces → SameHost on `https://github.com`.
- `wire.rs`: a stream that ends inside the 4-byte length is an error (`Ok(None)` only when 0 bytes were read). Test with 2 bytes.
- Commit: `"Harden bridge pairing and reply binding"`.

### Revised Task 6 (Session)

- `PendingPairing` gains `commit: [u8; 32]`, `server: KeyPair` (kept until reveal), `code: Option<String>`, and state `AwaitingReveal` before `Waiting`. Only one pending pairing exists at a time (a new `pair` replaces any other).
- `Inbound::Pair { commit, name }`: locked → `(Locked, Some(Show))`; bad base64 → `Error`; else create the pending entry with a fresh server key pair, reply `PairPending { client_id, server_pub }`, **no event**.
- `Inbound::PairReveal { client_id, client_pub }`: find the `AwaitingReveal` entry; `commitment(client_pub) != commit` → drop the entry, `Error { "Pairing check failed" }`; `derive` returns `None` → same; else store key + code, state `Waiting`, reply `PairPending { client_id, server_pub }`, event `PairRequest { client_id, name, code }`.
- `pairing_status` for an `AwaitingReveal` entry answers `PairPending` too.
- `serve_call`: `let Some(request_nonce) = nonce_of(sealed)` (else `Error`); seal the reply with `Direction::Response { request_nonce }`.
- Tests: the `pair()` helper sends `Pair { commit: b64(&commitment(&keys.public)) }`, then `PairReveal { client_pub: b64(&keys.public) }`, and takes the event from the reveal; the `call()` helper opens replies with `Direction::Response { request_nonce: nonce_of(&request_box).unwrap() }`. Add: a reveal with a different public key than committed → `Error` and no event; a second `pair` replaces the first (the first's reveal → `Error`/`UnknownClient`); `pairing_needs_an_unlocked_vault` uses the new `Pair` shape.

### Revised Tasks 9–10 (extension)

- `crypto.ts`: `commitment(clientPublic)`; `seal()` unchanged for requests; `openReply(key, clientId, requestBox, boxed)` builds the reply AAD from the request box's first 24 bytes. Tests: commit vector, reply vector, wrong request nonce → `null`.
- `client.ts` `startPairing`: send `{kind:"pair", commit: toB64(commitment(keys.public)), name}` → `pairPending {clientId, serverPub}`; then `{kind:"pairReveal", clientId, clientPub: toB64(keys.public)}` → `pairPending`; derive and return the code. `request()` keeps the request box and opens the reply with `openReply`. The fake app in `client.test.ts` follows the same flow (checks the commitment, binds replies to the request nonce).
