#!/usr/bin/env bash
# Create a Tauri updater archive only from the fully verified release app.
# The URL origin, target, identity, and updater public key are not configurable.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/release_publication_gate.sh
source "$repo_root/scripts/release_publication_gate.sh"
readonly tauri_config="$repo_root/apps/cfw-tauri-shell/tauri.conf.json"
readonly official_release_origin="https://github.com/billlza/cfw-rs/releases/download"
readonly maximum_updater_archive_bytes=$((192 * 1024 * 1024))

die() {
  echo "error: $*" >&2
  exit 1
}

assert_semver() {
  local version="$1"
  local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$version" =~ $semver ]] || die "version is not a strict SemVer value: $version"
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular, non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "file must not have hard links: $path"
}

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "updater release creation requires Apple Silicon macOS"

app_path="${1:-$repo_root/target/candidates/0.4.0/signed/Clash for Mac.app}"
[[ "$app_path" == /* ]] || die "application path must be absolute"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle not found or is a symlink: $app_path"
app_path="$(cd "$(dirname "$app_path")" && pwd -P)/$(basename "$app_path")"
app_directory="$(dirname "$app_path")"
app_name="$(basename "$app_path")"
[[ "$app_name" == "Clash for Mac.app" ]] || die "unexpected release application name: $app_name"

info_plist="$app_path/Contents/Info.plist"
require_regular_file "$info_plist"
bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info_plist" 2>/dev/null)" ||
  die "cannot read CFBundleShortVersionString"
version="${VERSION:-$bundle_version}"
assert_semver "$version"
[[ "$version" == "$bundle_version" ]] ||
  die "VERSION ($version) does not match the signed app version ($bundle_version)"

native_products_root="$(release_native_products_root_for_app "$app_path")" ||
  die "cannot resolve candidate-specific native products"
"$repo_root/scripts/verify_release_app.sh" "$app_path" "$native_products_root"

verify_release_publication_evidence "$app_path"

: "${TAURI_SIGNING_PRIVATE_KEY_PATH:?set an absolute updater key path outside the repository}"
: "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:?set the non-empty updater key password}"
[[ "$TAURI_SIGNING_PRIVATE_KEY_PATH" == /* ]] || die "updater private key path must be absolute"
[[ -f "$TAURI_SIGNING_PRIVATE_KEY_PATH" && ! -L "$TAURI_SIGNING_PRIVATE_KEY_PATH" ]] ||
  die "updater private key must be a regular, non-symlink file"
key_directory="$(cd "$(dirname "$TAURI_SIGNING_PRIVATE_KEY_PATH")" && pwd -P)"
key_path="$key_directory/$(basename "$TAURI_SIGNING_PRIVATE_KEY_PATH")"
case "$key_path" in
  "$repo_root" | "$repo_root"/*)
    die "updater private key must be stored outside the repository"
    ;;
esac
[[ "$(stat -f '%u' "$key_path")" == "$(id -u)" ]] ||
  die "updater private key must be owned by the release user"
[[ "$(stat -f '%Lp' "$key_path")" == "600" ]] ||
  die "updater private key permissions must be 0600"
[[ "$(stat -f '%l' "$key_path")" == "1" ]] ||
  die "updater private key must not have hard links"
[[ "$(stat -f '%u' "$key_directory")" == "$(id -u)" ]] ||
  die "updater key directory must be owned by the release user"
key_directory_mode="$(stat -f '%Lp' "$key_directory")"
(( (8#$key_directory_mode & 8#077) == 0 )) ||
  die "updater key directory must not grant group or other permissions"

output_directory="${OUT_DIR:-$repo_root/target/candidates/0.4.0/release}"
[[ ! -L "$output_directory" ]] || die "updater output directory must not be a symlink"
mkdir -p "$output_directory"
output_directory="$(cd "$output_directory" && pwd -P)"

archive_name="Clash.for.Mac_${version}_aarch64.app.tar.gz"
archive_path="$output_directory/$archive_name"
signature_path="$archive_path.sig"
latest_json="$output_directory/latest.json"
for output in "$archive_path" "$signature_path" "$latest_json"; do
  [[ ! -e "$output" && ! -L "$output" ]] || die "refusing to replace updater output: $output"
done

staging="$(mktemp -d "$output_directory/updater-stage.XXXXXX")"
completed=0
cleanup() {
  /bin/rm -rf "$staging"
  if [[ $completed -ne 1 ]]; then
    /bin/rm -f "$archive_path" "$signature_path" "$latest_json"
  fi
}
trap cleanup EXIT

staged_archive="$staging/$archive_name"
staged_signature="$staged_archive.sig"
staged_latest="$staging/latest.json"

echo "==> packing updater archive: $archive_path"
export COPYFILE_DISABLE=1
(
  cd "$app_directory"
  COPYFILE_DISABLE=1 tar -czf "$staged_archive" --exclude='._*' --exclude='.DS_Store' "$app_name"
)
require_regular_file "$staged_archive"
archive_size="$(stat -f '%z' "$staged_archive")"
(( archive_size > 0 && archive_size <= maximum_updater_archive_bytes )) ||
  die "updater archive size must be within 1..=$maximum_updater_archive_bytes bytes"

python3 "$repo_root/scripts/validate_updater_archive.py" "$staged_archive" "$app_name"

echo "==> signing updater archive"
(
  cd "$repo_root"
  cargo tauri signer sign -f "$key_path" "$staged_archive"
)
unset TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_SIGNING_PRIVATE_KEY_PATH
require_regular_file "$staged_signature"

echo "==> verifying updater signature against the embedded public key"
(
  cd "$repo_root"
  CARGO_NET_OFFLINE=true cargo run --offline --locked --quiet \
    -p cfw-release-verifier -- "$tauri_config" "$staged_archive" "$staged_signature"
)

download_url="$official_release_origin/v${version}/${archive_name}"
notes="${NOTES:-Clash for Mac ${version}}"
VERSION="$version" NOTES="$notes" SIGNATURE="$(tr -d '\n' <"$staged_signature")" \
DOWNLOAD_URL="$download_url" LATEST_JSON="$staged_latest" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

signature = os.environ["SIGNATURE"]
if not signature:
    raise SystemExit("error: updater signature is empty")
payload = {
    "version": os.environ["VERSION"],
    "notes": os.environ["NOTES"],
    "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "platforms": {
        "darwin-aarch64": {
            "signature": signature,
            "url": os.environ["DOWNLOAD_URL"],
        },
        "darwin-arm64": {
            "signature": signature,
            "url": os.environ["DOWNLOAD_URL"],
        },
    },
}
path = Path(os.environ["LATEST_JSON"])
with path.open("x", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
PY
require_regular_file "$staged_latest"

python3 - "$staged_latest" "$version" "$download_url" "$staged_signature" <<'PY'
import json
from pathlib import Path
import sys

manifest_path, version, expected_url, signature_path = sys.argv[1:]
payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
signature = Path(signature_path).read_text(encoding="utf-8").strip()
if set(payload) != {"version", "notes", "pub_date", "platforms"}:
    raise SystemExit("error: updater manifest contains an unexpected top-level field set")
if payload["version"] != version or not isinstance(payload["notes"], str):
    raise SystemExit("error: updater manifest version or notes mismatch")
platforms = payload.get("platforms")
if set(platforms or {}) != {"darwin-aarch64", "darwin-arm64"}:
    raise SystemExit("error: updater manifest platform set is not the fixed arm64 macOS set")
for target, item in platforms.items():
    if set(item) != {"signature", "url"}:
        raise SystemExit(f"error: updater target {target} contains unexpected fields")
    if item["signature"] != signature or item["url"] != expected_url:
        raise SystemExit(f"error: updater target {target} signature or URL mismatch")
    if not item["url"].startswith("https://github.com/billlza/cfw-rs/releases/download/"):
        raise SystemExit(f"error: updater target {target} URL is outside the official HTTPS origin")
PY

/bin/ln "$staged_archive" "$archive_path" || die "cannot publish updater archive exclusively"
/bin/rm "$staged_archive"
/bin/ln "$staged_signature" "$signature_path" || die "cannot publish updater signature exclusively"
/bin/rm "$staged_signature"
/bin/ln "$staged_latest" "$latest_json" || die "cannot publish updater manifest exclusively"
/bin/rm "$staged_latest"
completed=1

echo "==> updater artifacts ready:"
echo "    $archive_path"
echo "    $signature_path"
echo "    $latest_json"
shasum -a 256 "$archive_path" "$signature_path" "$latest_json"
