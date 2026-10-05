#!/bin/sh
# Builds the extension's socket code into a command-line tool, signs it ad hoc with the
# extension's own entitlements (so it runs in the App Sandbox exactly like the appex) and asks
# the running Keyorra app for its status. Exit 0 means a sandboxed process can reach the app.
# The tool never starts Keyorra. Its sandbox container is ~/Library/Containers/app.keyorra.safari.check.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${TMPDIR:-/tmp}/keyorra-sandbox-check
swiftc -O -o "$out" \
  "$here/../Keyorra for Safari Extension/BridgeClient.swift" "$here/main.swift" \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$here/Info.plist"
codesign -s - -f -i app.keyorra.safari.check \
  --entitlements "$here/../Keyorra for Safari Extension/Extension.entitlements" "$out"
"$out"
