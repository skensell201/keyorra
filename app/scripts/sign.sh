#!/bin/sh
# Builds Keyorra.app signed with the owner's Personal Team ("Apple Development" certificate in
# the login keychain; sign in once in Xcode → Settings → Accounts) and installs it to
# /Applications. A stable team signature keeps the Touch ID keychain item readable across
# rebuilds: its access list names the app's designated requirement, not one build.
#   KEYORRA_SIGNING_IDENTITY="Apple Development: Name (ABCDE12345)" KEYORRA_TEAM=ABCDE12345 app/scripts/sign.sh
# No entitlements are needed (see docs/superpowers/plans/2026-10-05-keyorra-desktop-2c.md).
set -eu
app_dir=$(cd "$(dirname "$0")/.." && pwd)
root=$(dirname "$app_dir")
identity=${KEYORRA_SIGNING_IDENTITY:-Apple Development}
team=${KEYORRA_TEAM:-4889865CU4}

(cd "$app_dir" && APPLE_SIGNING_IDENTITY="$identity" pnpm tauri build --bundles app)

built="$root/target/release/bundle/macos/Keyorra.app"
codesign --verify --strict --deep "$built"
signed_team=$(codesign -dv "$built" 2>&1 | sed -n 's/^TeamIdentifier=//p')
if [ "$signed_team" != "$team" ]; then
  echo "Keyorra.app is signed by team '$signed_team', expected $team" >&2
  exit 1
fi
# The keychain item trusts this signature, and the Touch ID prompt names this app: code injected
# into it would inherit both. Refuse a build that allows injection or debugging.
if ! codesign -dv "$built" 2>&1 | grep -q '^CodeDirectory.*flags=.*runtime'; then
  echo "Keyorra.app is not signed with the hardened runtime" >&2
  exit 1
fi
if codesign -d --entitlements - "$built" 2>/dev/null |
  grep -Eq 'get-task-allow|disable-library-validation|allow-dyld-environment-variables'; then
  echo "Keyorra.app has an entitlement that allows code injection or debugging" >&2
  exit 1
fi
rm -rf /Applications/Keyorra.app
ditto "$built" /Applications/Keyorra.app
echo "Installed /Applications/Keyorra.app (team $team)"
