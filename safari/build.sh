#!/bin/sh
# Builds the web extension, then "Keepsake for Safari.app" around it, and installs the app to
# /Applications. Signs with the team in Signing.xcconfig; KEEPSAKE_TEAM=ABCDE12345 overrides it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
app="Keepsake for Safari.app"

(cd "$root/extension" && pnpm build)

set -- -project "$here/Keepsake for Safari.xcodeproj" -scheme "Keepsake for Safari" \
  -configuration Release -derivedDataPath "$here/build"
set -- "$@" -allowProvisioningUpdates
if [ -n "${KEEPSAKE_TEAM:-}" ]; then
  set -- "$@" DEVELOPMENT_TEAM="$KEEPSAKE_TEAM"
fi
xcodebuild "$@" build

built="$here/build/Build/Products/Release/$app"
codesign --verify --deep --strict "$built"
rm -rf "/Applications/$app"
ditto "$built" "/Applications/$app"
# Safari must find only the installed copy, not the one in the build folder.
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$lsregister" -u "$built" 2>/dev/null || true
rm -rf "$built"
"$lsregister" -f -R "/Applications/$app"
pluginkit -a "/Applications/$app/Contents/PlugIns/Keepsake for Safari Extension.appex"
echo "Installed /Applications/$app"
