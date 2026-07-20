#!/usr/bin/env bash
# Create a distributable archive. Prefer hdiutil DMG; fall back to zip.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${1:-$repo_root/target/release/bundle/macos/Clash for Mac.app}"
OUT_DIR="${repo_root}/target/release/bundle/dmg"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo 0.1.0)"
if [[ ! -d "$APP" ]]; then
  echo "error: app not found: $APP" >&2
  exit 1
fi
mkdir -p "$OUT_DIR"
DMG="$OUT_DIR/Clash for Mac_${VERSION}_aarch64.dmg"
ZIP="$OUT_DIR/Clash for Mac_${VERSION}_aarch64.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications" 2>/dev/null || true
if hdiutil create -volname "Clash for Mac" -srcfolder "$STAGE" -ov -format UDZO "$DMG"; then
  echo "==> DMG: $DMG"
  ls -lh "$DMG"
else
  echo "==> hdiutil failed; writing zip instead"
  rm -f "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  echo "==> ZIP: $ZIP"
  ls -lh "$ZIP"
fi
