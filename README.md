# Lockbox

A personal password manager for macOS with a Chrome extension: local encrypted vault, 1Password import, TOTP, Touch ID and Watchtower.

Design: [docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md](docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md)

## Layout

- `crates/lockbox-core` — encryption, vault store, item model, TOTP, generator,
  1Password import, Watchtower. No UI.
- `crates/lockbox-session` — desktop-app logic (unlock throttling, auto-lock,
  clipboard clearing, import flow) over the core, without any UI framework.
- `app/` — macOS app: Tauri 2 shell (`app/src-tauri`) + React UI (`app/src`).
- `extension/` — Chrome extension — Plan 3.

## Development

```bash
cargo test                          # core + session
cd app && pnpm install && pnpm test # UI
cd app && pnpm tauri dev            # run the app (vault in ~/Library/Application Support/app.lockbox.mac)
cd app && pnpm tauri build --bundles app
```

Security model: see the spec, section "Cryptography".

All rights reserved.
