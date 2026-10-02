# Lockbox

A personal password manager for macOS with a Chrome extension: local encrypted vault, 1Password import, TOTP, Touch ID and Watchtower.

Design: [docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md](docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md)

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

All rights reserved.
