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

APP_PATH="${1:-$repo_root/target/release/bundle/macos/Clash for Mac.app}"
if [[ ! -d "$APP_PATH" ]]; then
  echo "error: app bundle not found: $APP_PATH" >&2
  exit 1
fi
APP_DIR="$(cd "$(dirname "$APP_PATH")" && pwd)"
APP_NAME="$(basename "$APP_PATH")"
APP_ABS="$APP_DIR/$APP_NAME"

VERSION="${VERSION:-$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_ABS/Contents/Info.plist" 2>/dev/null || echo 0.2.0)}"
OUT_DIR="${OUT_DIR:-$repo_root/target/release/bundle/dmg}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

ARCHIVE_NAME="Clash.for.Mac_${VERSION}_aarch64.app.tar.gz"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"
NOTES="${NOTES:-Clash for Mac ${VERSION}}"

echo "==> packing updater archive: $ARCHIVE_PATH"
rm -f "$ARCHIVE_PATH"
# macOS bsdtar otherwise embeds AppleDouble `._*` sidecars for xattrs
# (com.apple.provenance). Tauri's updater then fails with:
#   failed to unpack ._Clash for Mac.app into .../tauri_updated_app...
export COPYFILE_DISABLE=1
# Drop non-essential xattrs so a future packer without COPYFILE_DISABLE stays clean.
xattr -cr "$APP_ABS" 2>/dev/null || true
(
  cd "$APP_DIR"
  COPYFILE_DISABLE=1 tar -czf "$ARCHIVE_PATH" --exclude='._*' --exclude='.DS_Store' "$APP_NAME"
)

python3 - "$ARCHIVE_PATH" <<'PY'
import sys, tarfile
path = sys.argv[1]
with tarfile.open(path, "r:gz") as tf:
    bad = [m.name for m in tf.getmembers() if m.name.startswith("._") or "/._" in m.name or m.name.endswith(".DS_Store")]
    tops = sorted({m.name.split("/", 1)[0] for m in tf.getmembers()})
if bad:
    raise SystemExit(f"error: updater archive contains AppleDouble/junk entries: {bad[:8]}")
if tops != ["Clash for Mac.app"] and not (len(tops) == 1 and tops[0].endswith(".app")):
    # Allow only the single .app root (name may vary if productName changes).
    if len(tops) != 1 or not tops[0].endswith(".app"):
        raise SystemExit(f"error: updater archive top-level must be a single .app, got {tops}")
print(f"==> archive OK ({len(tops)} top-level: {tops[0]})")
PY

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

PUB_URL_BASE="${PUB_URL_BASE:-https://github.com/billlza/cfw-rs/releases/download/v${VERSION}}"
DOWNLOAD_URL="${PUB_URL_BASE}/${ARCHIVE_NAME}"
LATEST_JSON="$OUT_DIR/latest.json"

VERSION="$VERSION" NOTES="$NOTES" SIGNATURE="$(tr -d '\n' < "$SIG_PATH")" \
DOWNLOAD_URL="$DOWNLOAD_URL" LATEST_JSON="$LATEST_JSON" python3 - <<'PY'
import json, os
from datetime import datetime, timezone
from pathlib import Path
payload = {
  "version": os.environ["VERSION"],
  "notes": os.environ["NOTES"],
  "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "platforms": {
    "darwin-aarch64": {
      "signature": os.environ["SIGNATURE"],
      "url": os.environ["DOWNLOAD_URL"],
    },
    "darwin-arm64": {
      "signature": os.environ["SIGNATURE"],
      "url": os.environ["DOWNLOAD_URL"],
    },
  },
}
path = Path(os.environ["LATEST_JSON"])
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print("wrote", path)
PY

echo "==> updater artifacts ready:"
echo "    $ARCHIVE_PATH"
echo "    $SIG_PATH"
echo "    $LATEST_JSON"
