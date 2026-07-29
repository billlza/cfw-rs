#!/usr/bin/env bash
# Create a Tauri updater archive only from the fully verified release app.
# The URL origin, target, identity, and updater public key are not configurable.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/release_publication_gate.sh
source "$repo_root/scripts/release_publication_gate.sh"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
readonly tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"
readonly official_release_origin="https://github.com/billlza/cfw-rs/releases/download"
readonly maximum_updater_archive_bytes=$((192 * 1024 * 1024))

die() {
  echo "error: $*" >&2
  exit 1
}

cfw_require_supported_python

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
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"

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
updater_root="$output_directory/updater"
[[ ! -L "$updater_root" ]] || die "updater release-set directory must not be a symlink"
mkdir -p "$updater_root"
updater_root="$(cd "$updater_root" && pwd -P)"
final_set="$updater_root/v$version"
[[ ! -e "$final_set" && ! -L "$final_set" ]] ||
  die "refusing to replace existing updater release set: $final_set"
for legacy_output in \
  "$output_directory/$archive_name" \
  "$output_directory/$archive_name.sig" \
  "$output_directory/latest.json"; do
  [[ ! -e "$legacy_output" && ! -L "$legacy_output" ]] ||
    die "legacy partial updater output must be removed after review: $legacy_output"
done

staging="$(mktemp -d "$updater_root/updater-stage.XXXXXX")"
cleanup() {
  /bin/rm -rf "$staging"
}
trap cleanup EXIT

staged_archive="$staging/$archive_name"
staged_signature="$staged_archive.sig"
staged_latest="$staging/latest.json"

echo "==> packing updater archive: $final_set/$archive_name"
export COPYFILE_DISABLE=1
(
  cd "$app_directory"
  COPYFILE_DISABLE=1 tar -czf "$staged_archive" \
    --no-xattrs \
    --no-mac-metadata \
    --no-acls \
    --no-fflags \
    --exclude='._*' \
    --exclude='.DS_Store' \
    "$app_name"
)
require_regular_file "$staged_archive"
archive_size="$(stat -f '%z' "$staged_archive")"
(( archive_size > 0 && archive_size <= maximum_updater_archive_bytes )) ||
  die "updater archive size must be within 1..=$maximum_updater_archive_bytes bytes"

python3 "$repo_root/scripts/validate_updater_archive.py" "$staged_archive" "$app_name"

echo "==> signing updater archive"
(
  cd "$repo_root"
  "$tauri_bin" signer sign -f "$key_path" "$staged_archive"
)
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
unset TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_SIGNING_PRIVATE_KEY_PATH
require_regular_file "$staged_signature"

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

PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/release_artifact_set.py" seal-updater \
  --staging "$staging" \
  --destination "$final_set" \
  --version "$version" \
  --repository "$repo_root"

echo "==> updater artifacts ready:"
echo "    $final_set/$archive_name"
echo "    $final_set/$archive_name.sig"
echo "    $final_set/latest.json"
echo "    $final_set/updater-set.seal.json"
shasum -a 256 \
  "$final_set/$archive_name" \
  "$final_set/$archive_name.sig" \
  "$final_set/latest.json" \
  "$final_set/updater-set.seal.json"
