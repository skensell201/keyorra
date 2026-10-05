# Changelog

All notable changes to Keyorra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

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
