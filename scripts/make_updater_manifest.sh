#!/bin/bash -p
# Create a Tauri updater archive only from the fully verified release app.
# The URL origin, target, identity, and updater public key are not configurable.

# Release secrets are acquired only by updater_signing_launcher.py after every
# preflight. This script rejects legacy caller injection and traced/startup-hook
# execution before invoking any release logic.
case "$-" in
  *x*)
    set +x
    printf '%s\n' "error: updater release creation refuses shell xtrace" >&2
    exit 1
    ;;
  *v*)
    set +v
    printf '%s\n' "error: updater release creation refuses shell verbose mode" >&2
    exit 1
    ;;
esac
case "$-" in
  *p*) ;;
  *)
    set +x
    printf '%s\n' \
      "error: updater release creation requires its /bin/bash -p entrypoint" >&2
    exit 1
    ;;
esac
# Reject environment names that can change shell parsing, directory traversal,
# archive semantics, Python imports, or dynamic loading before any Homebrew
# interpreter or release tool is executed. Values are never expanded or logged.
IFS=$' \t\n'
exported_environment_names="$(compgen -e)" || {
  printf '%s\n' "error: cannot inspect exported release environment" >&2
  exit 1
}
for exported_environment_name in $exported_environment_names; do
  case "$exported_environment_name" in
    DYLD_*|LD_*|BASH_FUNC_*|CDPATH|GLOBIGNORE|POSIXLY_CORRECT|BASH_COMPAT|\
    TAR_OPTIONS|GZIP|PYTHON*|\
    BASH_XTRACEFD)
      printf '%s\n' \
        "error: updater release creation refuses unsafe exported environment state" >&2
      exit 1
      ;;
  esac
done
unset exported_environment_name exported_environment_names
# Release helpers must never resolve through a caller-controlled PATH. The
# shared publication gate replaces this temporary system PATH with the exact
# pinned release environment before any Python release tool executes.
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
LC_ALL=C
LANG=C
export LC_ALL LANG
if [[ -n "${BASHOPTS-}" ||
  "$SHELLOPTS" != "braceexpand:hashall:interactive-comments:privileged" ]]; then
  printf '%s\n' \
    "error: updater release creation refuses exported shell option state" >&2
  exit 1
fi
set +T +E +v +x
set +x
set +a
if [[ -n "${BASH_ENV+x}" || -n "${ENV+x}" ]]; then
  printf '%s\n' "error: updater release creation refuses shell startup hooks" >&2
  exit 1
fi
if [[ -n "${TAURI_SIGNING_PRIVATE_KEY+x}" ||
  -n "${TAURI_SIGNING_PRIVATE_KEY_PATH+x}" ||
  -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD+x}" ||
  -n "${TAURI_PRIVATE_KEY+x}" ||
  -n "${TAURI_PRIVATE_KEY_PATH+x}" ||
  -n "${TAURI_PRIVATE_KEY_PASSWORD+x}" ]]; then
  printf '%s\n' "error: caller-supplied Tauri signing secrets are forbidden" >&2
  exit 1
fi
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PATH
unset TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_PRIVATE_KEY TAURI_PRIVATE_KEY_PATH
unset TAURI_PRIVATE_KEY_PASSWORD

set -euo pipefail
umask 077

# A signing process must never be allowed to persist its environment or key
# material in a core file. An unavailable process limit is a release failure.
if ! ulimit -c 0 >/dev/null 2>&1 || [[ "$(ulimit -c)" != "0" ]]; then
  printf '%s\n' "error: updater release creation cannot disable core dumps" >&2
  exit 1
fi

unset CDPATH
repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"

die() {
  echo "error: $*" >&2
  exit 1
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular, non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "file must not have hard links: $path"
}

# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/release_publication_gate.sh
source "$repo_root/scripts/release_publication_gate.sh"
# The shared production seal assigns the fixed locale before it is frozen.
readonly LC_ALL LANG
readonly artifact_repository="$publication_artifact_repository"
readonly toolchain_root="$artifact_repository/target/toolchains"
readonly official_release_origin="https://github.com/billlza/cfw-rs/releases/download"
readonly maximum_updater_archive_bytes=$((192 * 1024 * 1024))

[[ $# -eq 0 ]] || die "usage: make_updater_manifest.sh"
if [[ -n "${VERSION+x}" || -n "${OUT_DIR+x}" ]]; then
  die "VERSION and OUT_DIR overrides are forbidden for the fixed GA package"
fi

require_xtrace_disabled() {
  case "$-" in
    *x*)
      set +x
      die "updater release creation refuses shell xtrace"
      ;;
  esac
}

require_xtrace_disabled
set +a
python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
[[ "$python_bin" == /* && -x "$python_bin" ]] ||
  die "closed release Python interpreter is unavailable"
require_regular_file "$python_bin"
readonly python_bin
cfw_require_supported_python "$python_bin"

assert_semver() {
  local version="$1"
  local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$version" =~ $semver ]] || die "version is not a strict SemVer value: $version"
}

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "updater release creation requires Apple Silicon macOS"
cfw_verify_tauri_toolchain_tree "$artifact_repository" "$toolchain_root"

readonly ga_root="$artifact_repository/target/candidates/0.4.0/ga/40043"
readonly app_path="$ga_root/signed/Clash for Mac.app"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle not found or is a symlink: $app_path"
app_directory="$(dirname "$app_path")"
app_name="$(basename "$app_path")"
[[ "$app_name" == "Clash for Mac.app" ]] || die "unexpected release application name: $app_name"

info_plist="$app_path/Contents/Info.plist"
require_regular_file "$info_plist"
bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info_plist" 2>/dev/null)" ||
  die "cannot read CFBundleShortVersionString"
version="$bundle_version"
assert_semver "$version"
build_number="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info_plist" 2>/dev/null)" ||
  die "cannot read CFBundleVersion"
[[ "$version" == "0.4.0" && "$build_number" == "40043" ]] ||
  die "signed app is not the active GA 0.4.0/40043 identity"

native_products_root="$(release_native_products_root_for_app "$app_path")" ||
  die "cannot resolve candidate-specific native products"
/bin/bash -p "$artifact_repository/scripts/verify_release_app.sh" \
  "$app_path" "$native_products_root" \
  --context canonical-native-content

verify_release_prepackage_evidence "$app_path"

package_root="$ga_root/packages"
[[ ! -L "$package_root" ]] || die "GA package directory must not be a symlink"
mkdir -p "$package_root"
package_root="$(cd "$package_root" && pwd -P)"

archive_name="Clash.for.Mac_${version}_aarch64.app.tar.gz"
updater_root="$package_root/updater"
[[ ! -L "$updater_root" ]] || die "updater release-set directory must not be a symlink"
mkdir -p "$updater_root"
updater_root="$(cd "$updater_root" && pwd -P)"
final_set="$updater_root/v$version"
[[ ! -e "$final_set" && ! -L "$final_set" ]] ||
  die "refusing to replace existing updater release set: $final_set"
for legacy_output in \
  "$package_root/$archive_name" \
  "$package_root/$archive_name.sig" \
  "$package_root/latest.json"; do
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

cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/validate_updater_archive.py" \
  "$staged_archive" "$app_name"

echo "==> signing updater archive"
require_xtrace_disabled
set +a
/usr/bin/env -i \
  PATH="$PATH" \
  LC_ALL=C \
  LANG=C \
  PYTHONDONTWRITEBYTECODE=1 \
  "$python_bin" -I -S -B -W error \
  "$artifact_repository/scripts/updater_signing_launcher.py" \
  "$staged_archive"
cfw_verify_tauri_toolchain_tree "$artifact_repository" "$toolchain_root"
require_regular_file "$staged_signature"

download_url="$official_release_origin/v${version}/${archive_name}"
notes="${NOTES:-Clash for Mac ${version}}"
VERSION="$version" NOTES="$notes" SIGNATURE="$(tr -d '\n' <"$staged_signature")" \
DOWNLOAD_URL="$download_url" LATEST_JSON="$staged_latest" \
  "$python_bin" -I -S -B -W error - <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if sys.flags.no_site != 1 or sys.flags.isolated != 1:
    raise SystemExit("error: updater metadata Python isolation is unavailable")
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

cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/release_artifact_set_cli.py" \
  seal-updater \
  --staging "$staging" \
  --destination "$final_set" \
  --version "$version" \
  --repository "$artifact_repository"

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
