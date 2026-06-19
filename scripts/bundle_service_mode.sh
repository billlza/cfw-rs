#!/usr/bin/env bash
# Assemble and Developer ID-sign a Service-Mode-capable "Clash for Mac.app".
#
# Pipeline:
#   1. cargo tauri build           (produces the .app; beforeBuildCommand stages
#                                    cfw-helper into Contents/Resources/helpers/)
#   2. this script                 (stage the SMAppService daemon plist into
#                                    Contents/Library/LaunchDaemons/, then sign
#                                    inner executables and the app, inside-out)
#
# SMAppService requires the app AND every nested executable (the helper, the
# bundled mihomo core) to be signed with the same Team ID and hardened runtime,
# otherwise registerAndReturnError fails and TUN/Service Mode never come up.
#
# Usage:
#   scripts/bundle_service_mode.sh [path/to/Clash for Mac.app]
# Env overrides:
#   SIGN_IDENTITY  codesign identity (default: the Developer ID below)
#   SKIP_BUILD=1   skip `cargo tauri build` and sign an existing .app
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

SIGN_IDENTITY="${SIGN_IDENTITY:-Developer ID Application: Zi ang Li (YKUPL7Z869)}"
PLIST_SRC="apps/cfw-tauri-shell/macos/com.bill.clashformac.helper.plist"
HELPER_REL="Contents/Resources/helpers/cfw-helper"
CORE_REL="Contents/Resources/cores/clash-darwin"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> cargo tauri build (release)"
  cargo tauri build
fi

APP_PATH="${1:-target/release/bundle/macos/Clash for Mac.app}"
if [[ ! -d "$APP_PATH" ]]; then
  echo "error: app bundle not found: $APP_PATH" >&2
  echo "       build it first (cargo tauri build) or pass the path explicitly." >&2
  exit 1
fi
echo "==> app bundle: $APP_PATH"

# 1. Stage the SMAppService daemon plist.
launch_daemons_dir="$APP_PATH/Contents/Library/LaunchDaemons"
mkdir -p "$launch_daemons_dir"
cp "$PLIST_SRC" "$launch_daemons_dir/com.bill.clashformac.helper.plist"
chmod 644 "$launch_daemons_dir/com.bill.clashformac.helper.plist"
echo "==> staged daemon plist into Contents/Library/LaunchDaemons/"

# 2. Sign inside-out: nested executables first, then the outer app last.
sign_runtime() {
  local target="$1"
  if [[ -e "$APP_PATH/$target" ]]; then
    echo "==> sign $target"
    codesign --force --timestamp --options runtime \
      --sign "$SIGN_IDENTITY" "$APP_PATH/$target"
  else
    echo "   (skip, not present: $target)"
  fi
}

sign_runtime "$CORE_REL"
sign_runtime "$HELPER_REL"

echo "==> sign app bundle (outermost)"
codesign --force --timestamp --options runtime \
  --sign "$SIGN_IDENTITY" "$APP_PATH"

echo "==> verify signature"
codesign --verify --strict --verbose=2 "$APP_PATH"
codesign --display --verbose=2 "$APP_PATH/$HELPER_REL" 2>&1 | grep -E "Authority|TeamIdentifier" || true

cat <<EOF

Done. Next (on your Mac):
  1. Move "$APP_PATH" to /Applications and launch it once.
  2. Turn on Service Mode / TUN in the app — macOS will surface the helper in
     System Settings > General > Login Items & Extensions. Approve it.
  3. Re-check: 'launchctl print system/com.bill.clashformac.helper' should list
     the daemon once enabled.
  4. For distribution to other machines, notarize:
     xcrun notarytool submit "<zipped app>" --keychain-profile <profile> --wait
     xcrun stapler staple "$APP_PATH"

Known TODO (real-machine): wire the root daemon's app-home discovery so its core
spawns with the active user's config (plist RunAtLoad is false until then).
EOF
