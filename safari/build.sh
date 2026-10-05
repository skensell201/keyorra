#!/bin/sh
# Builds the web extension, then "Keyorra for Safari.app" around it, and installs the app to
# /Applications. Signs with the team in Signing.xcconfig; KEYORRA_TEAM=ABCDE12345 overrides it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
app="Keyorra for Safari.app"

(cd "$root/extension" && pnpm build)

set -- -project "$here/Keyorra for Safari.xcodeproj" -scheme "Keyorra for Safari" \
  -configuration Release -derivedDataPath "$here/build"
set -- "$@" -allowProvisioningUpdates
if [ -n "${KEYORRA_TEAM:-}" ]; then
  set -- "$@" DEVELOPMENT_TEAM="$KEYORRA_TEAM"
fi
# Clean every time: the copied extension files change without Xcode noticing, which breaks the signature.
xcodebuild "$@" clean build

built="$here/build/Build/Products/Release/$app"
codesign --verify --deep --strict "$built"
rm -rf "/Applications/$app"
ditto "$built" "/Applications/$app"
# Safari must find only the installed copy, not the one in the build folder.
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$lsregister" -u "$built" 2>/dev/null || true
rm -rf "$built"
"$lsregister" -f -R "/Applications/$app"
pluginkit -a "/Applications/$app/Contents/PlugIns/Keyorra for Safari Extension.appex"
echo "Installed /Applications/$app"
