#!/bin/sh
# Builds the extension's socket code into a command-line tool, signs it ad hoc with the
# extension's own entitlements (so it runs in the App Sandbox exactly like the appex) and asks
# the running Keepsake app for its status. Exit 0 means a sandboxed process can reach the app.
# The tool never starts Keepsake. Its sandbox container is ~/Library/Containers/app.keepsake.safari.check.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${TMPDIR:-/tmp}/keepsake-sandbox-check
swiftc -O -o "$out" \
  "$here/../Keepsake for Safari Extension/BridgeClient.swift" "$here/main.swift" \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$here/Info.plist"
codesign -s - -f -i app.keepsake.safari.check \
  --entitlements "$here/../Keepsake for Safari Extension/Extension.entitlements" "$out"
"$out"
