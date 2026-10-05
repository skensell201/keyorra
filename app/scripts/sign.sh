#!/bin/sh
# Builds Keepsake.app signed with the owner's Personal Team ("Apple Development" certificate in
# the login keychain; sign in once in Xcode → Settings → Accounts) and installs it to
# /Applications. A stable team signature keeps the Touch ID keychain item readable across
# rebuilds: its access list names the app's designated requirement, not one build.
#   KEEPSAKE_SIGNING_IDENTITY="Apple Development: Name (ABCDE12345)" KEEPSAKE_TEAM=ABCDE12345 app/scripts/sign.sh
# No entitlements are needed (see docs/superpowers/plans/2026-10-05-keepsake-desktop-2c.md).
set -eu
app_dir=$(cd "$(dirname "$0")/.." && pwd)
root=$(dirname "$app_dir")
identity=${KEEPSAKE_SIGNING_IDENTITY:-Apple Development}
team=${KEEPSAKE_TEAM:-4889865CU4}

(cd "$app_dir" && APPLE_SIGNING_IDENTITY="$identity" pnpm tauri build --bundles app)

built="$root/target/release/bundle/macos/Keepsake.app"
codesign --verify --strict --deep "$built"
signed_team=$(codesign -dv "$built" 2>&1 | sed -n 's/^TeamIdentifier=//p')
if [ "$signed_team" != "$team" ]; then
  echo "Keepsake.app is signed by team '$signed_team', expected $team" >&2
  exit 1
fi
rm -rf /Applications/Keepsake.app
ditto "$built" /Applications/Keepsake.app
echo "Installed /Applications/Keepsake.app (team $team)"
