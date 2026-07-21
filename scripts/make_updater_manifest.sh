#!/usr/bin/env bash
# Build updater artifacts (app.tar.gz + .sig + latest.json) from a signed .app.
#
# Usage:
#   scripts/make_updater_manifest.sh [path/to/Clash for Mac.app]
# Env:
#   TAURI_SIGNING_PRIVATE_KEY_PATH  default: .tauri/cfw-rs.key
#   VERSION                         default: from Info.plist
#   NOTES                           release notes string
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

APP_PATH="${1:-target/release/bundle/macos/Clash for Mac.app}"
if [[ ! -d "$APP_PATH" ]]; then
  echo "error: app bundle not found: $APP_PATH" >&2
  exit 1
fi

VERSION="${VERSION:-$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_PATH/Contents/Info.plist" 2>/dev/null || echo 0.2.0)}"
OUT_DIR="${OUT_DIR:-target/release/bundle/dmg}"
mkdir -p "$OUT_DIR"

ARCHIVE_NAME="Clash.for.Mac_${VERSION}_aarch64.app.tar.gz"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"
NOTES="${NOTES:-Clash for Mac ${VERSION}}"

echo "==> packing updater archive: $ARCHIVE_PATH"
rm -f "$ARCHIVE_PATH"
# Archive the .app directory itself (Tauri macOS updater expects a .app.tar.gz).
(
  cd "$(dirname "$APP_PATH")"
  tar -czf "$ARCHIVE_PATH" "$(basename "$APP_PATH")"
)

export TAURI_SIGNING_PRIVATE_KEY_PATH="${TAURI_SIGNING_PRIVATE_KEY_PATH:-$repo_root/.tauri/cfw-rs.key}"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
if [[ ! -f "$TAURI_SIGNING_PRIVATE_KEY_PATH" ]]; then
  echo "error: missing updater private key at $TAURI_SIGNING_PRIVATE_KEY_PATH" >&2
  exit 1
fi

echo "==> signing updater archive"
SIG_PATH="$ARCHIVE_PATH.sig"
cargo tauri signer sign -f "$TAURI_SIGNING_PRIVATE_KEY_PATH" -p "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" "$ARCHIVE_PATH"
if [[ ! -f "$SIG_PATH" ]]; then
  SIG_PATH="$(ls -1 "$OUT_DIR"/*.sig 2>/dev/null | head -1 || true)"
fi
if [[ -z "${SIG_PATH:-}" || ! -f "$SIG_PATH" ]]; then
  echo "error: signature file not produced for $ARCHIVE_PATH" >&2
  exit 1
fi
SIGNATURE="$(tr -d '\n' < "$SIG_PATH")"

PUB_URL_BASE="${PUB_URL_BASE:-https://github.com/billlza/cfw-rs/releases/download/v${VERSION}}"
DOWNLOAD_URL="${PUB_URL_BASE}/${ARCHIVE_NAME}"

LATEST_JSON="$OUT_DIR/latest.json"
python3 - <<PY
import json
from pathlib import Path
payload = {
  "version": "$VERSION",
  "notes": """$NOTES""",
  "pub_date": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
  "platforms": {
    "darwin-aarch64": {
      "signature": """$SIGNATURE""",
      "url": "$DOWNLOAD_URL",
    },
    "darwin-arm64": {
      "signature": """$SIGNATURE""",
      "url": "$DOWNLOAD_URL",
    },
  },
}
Path("$LATEST_JSON").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print("wrote", "$LATEST_JSON")
PY

echo "==> updater artifacts ready:"
echo "    $ARCHIVE_PATH"
echo "    $SIG_PATH"
echo "    $LATEST_JSON"
