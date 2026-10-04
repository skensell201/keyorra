# Lockbox

A personal password manager for macOS with a Chrome extension: local encrypted vault, 1Password import, TOTP, Touch ID and Watchtower.

Design: [docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md](docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md)

## Layout

- `crates/lockbox-core` — encryption, vault store, item model, TOTP, generator,
  1Password import, Watchtower. No UI.
- `crates/lockbox-session` — desktop-app logic (unlock throttling, auto-lock,
  clipboard clearing, import flow) over the core, without any UI framework.
- `app/` — macOS app: Tauri 2 shell (`app/src-tauri`) + React UI (`app/src`).
- `extension/` — browser extension for Chromium browsers and Firefox (TypeScript).

## Development

```bash
cargo test                          # core + session
cd app && pnpm install && pnpm test # UI
cd app && pnpm tauri dev            # run the app (vault in ~/Library/Application Support/app.lockbox.mac)
cd app && pnpm tauri build --bundles app
```

## Browser extension

```bash
cd extension && pnpm install && pnpm test && pnpm build   # dist/chromium, dist/firefox
```

1. In Lockbox: Settings… → Browsers → **Connect browsers** (installs the native host
   manifest for every browser found; run it again after moving the app).
2. Chrome/Opera/Yandex/Brave/Edge: `chrome://extensions` → Developer mode → Load unpacked →
   `extension/dist/chromium` (id `kaaofpbpmnghapcafbbhjflonijdijbj`).
   Firefox: `about:debugging` → This Firefox → Load Temporary Add-on → `extension/dist/firefox/manifest.json`.
3. Click the Lockbox toolbar icon → **Connect**, check the code matches in the app → **Connect**.
4. Focus a login field → Lockbox icon → pick a login. Shortcut: set "Fill the best login"
   in `chrome://extensions/shortcuts`.

Security model: see the spec, section "Cryptography".

All rights reserved.
