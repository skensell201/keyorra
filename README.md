# Keyorra

A personal password manager for macOS with a Chrome extension: local encrypted vault, 1Password import, TOTP, Touch ID and Watchtower.

Design: [docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md](docs/superpowers/specs/2026-10-02-lockbox-mvp-design.md)

## Layout

- `crates/keyorra-core` — encryption, vault store, item model, TOTP, generator,
  1Password import, Watchtower. No UI.
- `crates/keyorra-session` — desktop-app logic (unlock throttling, auto-lock,
  clipboard clearing, import flow) over the core, without any UI framework.
- `app/` — macOS app: Tauri 2 shell (`app/src-tauri`) + React UI (`app/src`).
- `extension/` — browser extension for Chromium browsers, Firefox and Safari (TypeScript).
- `safari/` — Xcode project for "Keyorra for Safari.app", which carries the extension into Safari.

## Development

```bash
cargo test                          # core + session
cd app && pnpm install && pnpm test # UI
cd app && pnpm tauri dev            # run the app (vault in ~/Library/Application Support/app.keyorra.mac)
app/scripts/sign.sh                 # signed build (Personal Team), installs /Applications/Keyorra.app
```

### Touch ID

Touch ID needs a signed build (`app/scripts/sign.sh`): the keychain item that holds the wrapped
account key only opens for the app's stable team signature. Dev builds (`pnpm tauri dev`) are
signed ad hoc and keep their own item. Turn it on in Settings → Touch ID. Keyorra still asks
for the master password every 14 days and after your fingerprints change.

## Browser extension

```bash
cd extension && pnpm install && pnpm test && pnpm build   # dist/chromium, dist/firefox, dist/safari
```

1. In Keyorra: Settings… → Browsers → **Connect browsers** (installs the native host
   manifest for every browser found; run it again after moving the app).
2. Chrome/Opera/Yandex/Brave/Edge: `chrome://extensions` → Developer mode → Load unpacked →
   `extension/dist/chromium` (id `kaaofpbpmnghapcafbbhjflonijdijbj`).
   Firefox: `about:debugging` → This Firefox → Load Temporary Add-on → `extension/dist/firefox/manifest.json`.
3. Click the Keyorra toolbar icon → **Connect**, check the code matches in the app → **Connect**.
4. Focus a login field → Keyorra icon → pick a login. Shortcut: set "Fill the best login"
   in `chrome://extensions/shortcuts`.
5. After you sign in, Keyorra offers to save a new login or update a changed password
   (the old one stays in the item's history).
6. On sign-up and change-password forms the icon offers a strong password; Keyorra saves it
   as a separate draft login right away, so it is never lost.
7. Card and address fields get the icon too. Cards and addresses are offered only on https
   pages, this Mac or the local network. Payment fields inside separate iframes (e.g. Stripe
   Elements) are filled one field at a time.

### Safari

Safari loads web extensions only from inside a Mac app, so the extension ships in
"Keyorra for Safari.app" (`safari/`). Its app extension relays each message to the Keyorra
app's socket and starts Keyorra if it isn't running; no host manifest is involved.

```bash
safari/build.sh                           # builds extension/dist/safari and the app, installs it to /Applications
KEYORRA_TEAM=ABCDE12345 safari/build.sh  # same, signed with another Apple Developer team
```

1. The build is signed with the team in `safari/Signing.xcconfig` (a free Apple ID's Personal
   Team works; sign in once in Xcode → Settings → Accounts). Without any team, sign ad hoc and
   enable Develop → **Allow Unsigned Extensions** in Safari after every restart.
2. Open "Keyorra for Safari" → **Open Safari Extensions Settings** → turn on Keyorra and allow
   it on websites.
3. Pair as above: Keyorra toolbar icon → **Connect**; the app shows the request as "Safari".
   Reinstalling "Keyorra for Safari" (e.g. after `safari/build.sh`) gives the extension new
   storage, so pair again; restarting Safari keeps the pairing.

The app extension is sandboxed. Its one exception (`safari/Keyorra for Safari Extension/Extension.entitlements`)
allows connecting to the app's socket and nothing else; `safari/check/sandbox-check.sh` checks
it against the running app.

Security model: see the spec, section "Cryptography".

All rights reserved.
