> Renamed to Keepsake on 2026-10-05; identifiers below that say lockbox now say keepsake, except the encryption format labels.

# Lockbox MVP — Design

Date: 2026-10-02
Status: approved 2026-10-02

## Goal

A personal, free replacement for 1Password: a local encrypted vault with a macOS
desktop app and a Chrome extension for autofill. The user must be able to import
everything from their 1Password account (all vaults) and stop using 1Password.

## Scope

**In the MVP**

- Local encrypted vault (multiple vaults, e.g. "Personal", "Datagile")
- Item types: Login, Secure Note, Credit Card, Identity, Password, API Credential;
  custom sections/fields on any item; password history; file attachments
- Search, favorites, tags
- Password and passphrase generator
- TOTP codes (RFC 6238)
- Import from 1Password: `.1pux` (primary) and CSV (fallback)
- Touch ID unlock
- Watchtower: weak, reused and breached passwords
- macOS desktop app (Tauri 2 + React)
- Chrome extension (MV3): fill login/password/TOTP, save new logins

**Not in the MVP (roadmap, in order)**

1. Self-hosted sync server (Rust, deployable to the user's Proxmox VM)
2. iPhone app with AutoFill provider
3. Vault sharing between users
4. Passkeys
5. Windows/Linux builds, other browsers

The MVP storage format already carries what sync needs (revisions, tombstones), so
adding the server does not require a data migration.

## Architecture

```
lockbox/
  crates/lockbox-core/     Rust library: crypto, storage, model, import, TOTP,
                           generator, Watchtower. No UI, no OS APIs.
  app/                     Tauri 2 desktop app (React + TypeScript frontend,
    src-tauri/             Rust backend: commands, Touch ID, auto-lock,
                           native-messaging host mode)
  extension/               Chrome MV3 extension (TypeScript)
```

- `lockbox-core` holds all security-critical logic and is the main TDD target. The
  future server and mobile app reuse it.
- The desktop app is the only process that ever holds the vault key.
- The extension never stores secrets. It asks the desktop app for a single
  credential at a time over Chrome Native Messaging.

## 1. Cryptography (`lockbox-core::crypto`)

- **Key derivation:** Argon2id(master password, 16-byte random salt),
  m = 64 MiB, t = 3, p = 1 → 32-byte key-encryption key (KEK). Parameters are
  stored in the vault header so they can be raised later.
- **Key hierarchy:** the KEK wraps a random 32-byte account key; the account key
  wraps one random 32-byte key per vault; each vault key encrypts that vault's
  items. A future share of one vault does not expose the others.
- **Item encryption:** XChaCha20-Poly1305 with a random 24-byte nonce per write.
  Associated data = `vault_id || item_id || schema_version`. Swapping a ciphertext
  between items or vaults fails authentication.
- **Changing the master password** re-wraps the account key only; items are untouched.
- **Verifying the password:** a wrong password fails to unwrap the account key
  (AEAD tag mismatch). No password hash is stored.
- **Memory hygiene:** keys live in `zeroize::Zeroizing` buffers; plaintext
  items are dropped when the vault locks.
- **Crates:** `argon2`, `chacha20poly1305`, `rand` (OsRng), `zeroize`.
  No hand-written primitives.

## 2. Storage (`lockbox-core::store`)

SQLite file at `~/Library/Application Support/app.lockbox.mac/lockbox.db`
(rusqlite, bundled).

| Table | Columns |
|---|---|
| `meta` | key, value (format version, KDF params, salt, wrapped account key) |
| `vaults` | id (UUID), wrapped_key, encrypted_meta (name, icon), revision, deleted |
| `items` | id (UUID), vault_id, encrypted blob, revision, updated_at, deleted |
| `attachments` | id, item_id, encrypted blob, revision, deleted |

- Titles and URLs are encrypted too. After unlock the app decrypts item overviews
  into an in-memory search index; nothing searchable is stored in plaintext.
- `revision` is a per-row counter; `deleted` rows are tombstones (kept for the
  future sync server, purged from "Recently Deleted" after 30 days).
- Writes are transactional. Before each schema migration the file is backed up
  next to itself.

## 3. Data model (`lockbox-core::model`)

```rust
struct Item {
    id: Uuid, vault_id: Uuid, kind: ItemKind,
    title: String, tags: Vec<String>, favorite: bool,
    urls: Vec<String>,                 // Login only, first is primary
    fields: Vec<Field>,                // built-in fields per kind
    sections: Vec<Section>,            // custom, like 1Password
    notes: String,
    password_history: Vec<HistoryEntry>,
    created_at, updated_at,
}
struct Field { id, label, value: FieldValue, purpose: Option<Purpose> }
enum FieldValue { Text, Concealed, Email, Url, Date, MonthYear, Totp(String), Phone }
```

Serialized as JSON before encryption, with a `schema_version`.

## 4. Core features

- **Generator:** random passwords (length 8–100; letters/digits/symbols toggles;
  no ambiguous characters option) and passphrases from the EFF long wordlist
  (3–10 words, separator, capitalize). Uses OsRng with rejection sampling.
- **TOTP:** RFC 6238 (SHA1/SHA256/SHA512, 6–8 digits, 30 s default). Parses
  `otpauth://` URIs and bare base32 secrets.
- **1Password import:**
  - `.1pux`: zip → `export.data` (JSON) → accounts → vaults → items, `files/`
    → attachments. Maps categories (Login 001, Credit Card 002, Secure Note 003,
    Identity 004, Password 005, API Credential 112; others → Secure Note with all
    fields preserved as custom sections). Keeps URLs, TOTP, notes, tags,
    favorites, password history. Items in 1Password's trash are skipped.
  - CSV: 1Password CSV export (title, url, username, password, otp, notes).
  - Import shows a preview (vaults, item counts, unsupported items) before writing.
- **Watchtower:**
  - Weak: zxcvbn score < 3.
  - Reused: same password in more than one item (compared in memory after unlock).
  - Breached: Have I Been Pwned range API with k-anonymity (only the first 5 hex
    characters of SHA-1 leave the machine). Off by default, user turns it on.

## 5. Desktop app (`app/`)

- **Screens:** create vault (first run) → unlock → main window with three columns:
  vaults/categories sidebar | item list | item detail/editor. Settings, Import,
  Watchtower, Generator as separate views.
- **Touch ID:** after a password unlock, the account key is stored in the macOS
  Keychain with access control `biometryCurrentSet`. Unlock reads it after a
  LocalAuthentication prompt. The master password is still required after a
  restart and every 14 days. Re-enrolling fingerprints invalidates the item.
- **Auto-lock:** after N minutes idle (default 10), on sleep, on screen lock.
- **Clipboard:** copied secrets are cleared after 90 s (only if unchanged).
- **Menu bar** icon and a quick-search window on ⌘⇧Space.
- **Style:** dark, consistent with the user's other apps; UI strings in English.

## 6. Chrome extension (`extension/`)

- **Transport:** Chrome Native Messaging. The desktop binary runs as the host
  with `--native-host`; that process connects to the running app over a Unix
  socket in the app's container directory. If the app is locked, the extension
  shows "Unlock Lockbox" and the app brings up its unlock window.
- **Pairing:** first connection shows a 6-digit code in both the app and the
  extension popup; the user confirms. Keys exchanged with X25519; all messages
  then encrypted with XChaCha20-Poly1305. The host manifest only allows the
  extension's ID.
- **Features:** popup with search; on a page, suggest logins whose URL matches by
  eTLD+1 (exact host preferred); fill username, password, then TOTP on the next
  step; detect a submitted login form and offer "Save to Lockbox" / "Update password".
- **The extension only receives** the one credential the user picked, never the
  vault.

## 7. Error handling

- Wrong password → generic "Incorrect password", with growing delay after 5 attempts.
- Corrupted item (AEAD failure) → item shown as "Damaged", others still load;
  never crash the vault on one bad row.
- Import errors are per item and listed in the import report; import is one
  transaction (all or nothing) per run.
- Extension with no app running → popup explains how to start Lockbox.

## 8. Testing (TDD)

Every unit in `lockbox-core` is written test-first (red → green → refactor).

- **Crypto:** round-trip; wrong password fails; tampered ciphertext, nonce or AAD
  fails; swapped items between vaults fail; master-password change keeps items readable.
- **Known-answer tests:** RFC 6238 TOTP vectors; Argon2id reference vector.
- **Import:** a hand-built `.1pux` fixture covering every mapped category,
  TOTP, attachments, multiple vaults, unknown category.
- **Store:** migrations, tombstones, revision increments, transactional rollback.
- **Generator:** length/charset guarantees, no modulo bias (statistical smoke test).
- **Watchtower:** weak/reused detection; HIBP client tested against a mock server.
- **Frontend:** Vitest + Testing Library. **Extension:** Vitest for URL matching and
  form detection; Playwright against local test pages for fill/save.

## Conventions

- Private repo `skensell201/lockbox`, branch `main`. Everything in the repo is in
  English (code, UI, docs, commits).
- Bundle id `app.lockbox.mac`.

---

## Addendum (2026-10-04): browser extension in detail

Replaces section 6 where they differ. Agreed with the user on 2026-10-04.

**Browsers.** One code base for Chromium browsers (Chrome, Opera, Yandex; Arc, Brave,
Edge, Vivaldi, Chromium work the same way) and Firefox (MV3, background script). Safari
needs a containing macOS app and its own native bridge; it is a separate plan (3b).

**Plans.** 3a: transport, pairing, popup, filling login, password and one-time code with
an inline icon and dropdown, shortcut ⌘⇧L. 3c: saving new logins, password generator on
sign-up forms, cards and addresses.

**Transport.** Chrome-style native messaging (4-byte little-endian length + UTF-8 JSON).
The host is the Lockbox binary itself, recognised by its launch arguments; it is a dumb
pipe that connects to a Unix socket served by the running app
(`~/Library/Application Support/app.lockbox.mac/bridge.sock`, mode 0600) and copies
bytes both ways. If the app is not running, the host launches it (`open -b app.lockbox.mac`)
and waits up to 15 s. Host manifests (`app.lockbox.bridge`) are installed by the app into
each browser's `NativeMessagingHosts` folder that exists; Chromium manifests allow only
the extension id `kaaofpbpmnghapcafbbhjflonijdijbj` (fixed by the manifest `key`; private
key kept outside the repo in `~/.config/lockbox-extension/chromium-key.pem`), Firefox
only `lockbox@lockbox.app`.

**Pairing.** Extension sends its X25519 public key; the app answers with its own and
shows "Connect Chrome? Code 123 456". Both sides derive
`key = SHA-256("lockbox-bridge-v1/key" ‖ shared ‖ clientPub ‖ serverPub)` and
`code = BE-u32(SHA-256("lockbox-bridge-v1/code" ‖ shared ‖ clientPub ‖ serverPub)[0..4]) mod 10^6`.
Pairing is possible only while the vault is unlocked and needs approval in the app.
Pairings are stored sealed with the account key in the vault (`meta`), listed in Settings
and removable there.

**Messages.** Plaintext envelope `{kind}`: `status`, `show`, `pair`, `pairStatus`, `call`.
A `call` carries `box = base64(nonce ‖ XChaCha20-Poly1305(key, nonce, aad, json))` with
`aad = "lockbox-bridge-v1/<clientId>/req"` (`/res` for replies). Requests: `list {url}` →
items for the page's site (title, username, hasTotp; no secrets), `fill {url, itemId}` →
username, password, current one-time code. While locked every call answers plaintext
`{kind:"locked"}`.

**Release rules.** Site match = same registrable domain (eTLD+1 via the Public Suffix
List); exact host first. `fill` re-checks that the item matches the URL of the frame that
asked (taken from the browser, not from the page). The extension asks for a fill only
after a click or the shortcut.

**Hardening after review (2026-10-04), supersedes the pairing/messages text above:**
- *Commit-then-reveal pairing* (stops a relay from brute-forcing the 6-digit code): the
  extension first sends `pair {commit, name}` with `commit = SHA-256("lockbox-bridge-v1/commit" ‖ clientPub)`,
  gets `pairPending {clientId, serverPub}`, then sends `pairReveal {clientId, clientPub}`.
  The app checks the commitment and only then derives key and code and asks the user.
  One pending pairing at a time; low-order (non-contributory) keys are rejected.
- *Replies bound to their request*: reply AAD = `"lockbox-bridge-v1/<clientId>/res/" ‖ the
  24-byte nonce of the request box`, so a recorded reply can't answer another request.
- *Scheme rule* (user decision): an item saved with `https://` is not offered on an `http:`
  page. Exempt: IP addresses, `localhost`/`*.localhost`, and saved URLs without a scheme.
- *Pairing attempt cap*: five pairings that end without approval (replaced, expired, failed
  check, denied) block new pairing requests for 10 minutes, so the app side can't be
  re-rolled until the codes collide.
