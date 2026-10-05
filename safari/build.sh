#!/bin/sh
# Builds the web extension, then "Keepsake for Safari.app" around it, and installs the app to
# /Applications. Signs ad hoc ("Sign to Run Locally") unless KEEPSAKE_TEAM holds an Apple
# Developer Team ID, e.g. KEEPSAKE_TEAM=ABCDE12345 safari/build.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
app="Keepsake for Safari.app"

(cd "$root/extension" && pnpm build)

set -- -project "$here/Keepsake for Safari.xcodeproj" -scheme "Keepsake for Safari" \
  -configuration Release -derivedDataPath "$here/build"
if [ -n "${KEEPSAKE_TEAM:-}" ]; then
  set -- "$@" -allowProvisioningUpdates DEVELOPMENT_TEAM="$KEEPSAKE_TEAM" \
    CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development"
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
