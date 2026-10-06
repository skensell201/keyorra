# Changelog

All notable changes to Keyorra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-06

### Added
- **Sync through iCloud Drive or any folder you choose**, end-to-end encrypted. Turn it on in
  Settings → Sync; this Mac becomes the main Mac and you get an Emergency Kit to print
  (Secret Key, account, folder). Another Mac joins with the setup code or the Emergency Kit
  and your main Mac approves it by typing the code the new Mac shows.
- **Sync screen**: status, devices (approve, remove), alarms with explanations and actions,
  Emergency Kit, Verify everything, What the folder sees, copies of your vault on this Mac,
  sync log, turn off sync, start a new account.
- Attachments sync too.
- Item conflicts are kept as copies; an edit always beats a concurrent delete.

### Security
- Per-device signed, hash-chained logs; only the main Mac's word changes who counts; rollback,
  fork and withheld-change detection; padded segments; device keys sealed to the Secure Enclave.
- Removing a device stops its changes from counting. Until key rotation (planned) it can still
  read new changes while it can reach the folder: also sign it out of iCloud.

### Changed
- The vault database is upgraded to format 2 the first time sync is turned on; a copy of the
  old file is kept next to it and listed in Sync → Safety.

## [0.1.0] - 2026-10-05

First public release.

### Added

- Local encrypted vault: Argon2id master-password key, account key, per-vault keys,
  XChaCha20-Poly1305 per item, stored in SQLite on your Mac.
- Vaults; logins, credit cards, identities and secure notes; favorites, tags, password history
  and Recently Deleted.
- TOTP one-time codes.
- Import from 1Password (`.1pux`) and CSV.
- Password and passphrase generator.
- Watchtower: weak, reused and missing-2FA passwords, plus an opt-in Have I Been Pwned breach
  check (k-anonymity, only a 5-character hash prefix is sent).
- Touch ID unlock, auto-lock and clipboard clearing.
- Menu bar item and ⌘⇧Space quick search.
- Browser extensions for Chrome and Chromium browsers, Firefox and Safari ("Keyorra for
  Safari"): autofill logins and one-time codes, save and update logins, strong-password
  suggestion on sign-up forms, card and address filling. Browsers pair with the app once,
  confirmed by a matching code.

[0.1.0]: https://github.com/skensell201/keyorra/releases/tag/v0.1.0
