#!/bin/bash -p
# Package a fully verified arm64 application, then sign, notarize, staple, and
# Gatekeeper-assess the DMG. No unsigned or partially verified fallback exists.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/release_publication_gate.sh
source "$repo_root/scripts/release_publication_gate.sh"
readonly expected_team_id="YKUPL7Z869"

die() {
  echo "error: $*" >&2
  exit 1
}

cfw_require_supported_python "$CFW_RELEASE_PYTHON_EXECUTABLE"

assert_semver() {
  local version="$1"
  local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$version" =~ $semver ]] || die "version is not a strict SemVer value: $version"
}

recovery_submission_id=""
if [[ "${1:-}" == "--recover-submission-id" ]]; then
  [[ $# -eq 2 ]] || die "usage: make_dmg.sh --recover-submission-id UUID"
  recovery_submission_id="$2"
else
  [[ $# -eq 0 ]] || die "usage: make_dmg.sh [--recover-submission-id UUID]"
fi
readonly ga_root="$repo_root/target/candidates/0.4.0/ga/40037"
readonly app_path="$ga_root/signed/Clash for Mac.app"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle not found or is a symlink: $app_path"

notary_profile="${NOTARY_PROFILE:-}"
[[ -n "$notary_profile" ]] || die "NOTARY_PROFILE is required"
[[ "$notary_profile" == "clashformac-notary" ]] ||
  die "NOTARY_PROFILE must be the frozen clashformac-notary profile"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "DMG release creation requires Apple Silicon macOS"

native_products_root="$(release_native_products_root_for_app "$app_path")" ||
  die "cannot resolve candidate-specific native products"
"$repo_root/scripts/verify_release_app.sh" \
  "$app_path" "$native_products_root" \
  --context canonical-native-content

version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app_path/Contents/Info.plist" 2>/dev/null)" ||
  die "cannot read the signed app version"
assert_semver "$version"
build_number="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app_path/Contents/Info.plist" 2>/dev/null)" ||
  die "cannot read the signed app build number"
[[ "$build_number" =~ ^[1-9][0-9]*$ ]] ||
  die "signed app build number is not one canonical positive integer"
[[ "$version" == "0.4.0" && "$build_number" == "40037" ]] ||
  die "signed app is not the active GA 0.4.0/40037 identity"

verify_release_prepackage_evidence "$app_path"

package_root="$ga_root/packages"
[[ ! -L "$package_root" ]] || die "GA package directory must not be a symlink"
mkdir -p "$package_root"
package_root="$(cd "$package_root" && pwd -P)"
dmg_root="$package_root/dmg"
[[ ! -L "$dmg_root" ]] || die "DMG release-set directory must not be a symlink"
mkdir -p "$dmg_root"
dmg_root="$(cd "$dmg_root" && pwd -P)"
final_set="$dmg_root/v$version"
dmg_name="Clash.for.Mac_${version}_arm64.dmg"
for legacy_output in \
  "$package_root/$dmg_name" \
  "$package_root/Clash.for.Mac_${version}_arm64.notarization.json" \
  "$package_root/Clash.for.Mac_${version}_arm64.notarization-log.json" \
  "$package_root/Clash.for.Mac_${version}_arm64.gatekeeper.json" \
  "$package_root/Clash.for.Mac_${version}_arm64.dmg.manifest.json"; do
  [[ ! -e "$legacy_output" && ! -L "$legacy_output" ]] ||
    die "legacy partial DMG output must be removed after review: $legacy_output"
done

if [[ -n "$recovery_submission_id" ]]; then
  cfw_run_release_python_script \
    "$repo_root" \
    "$repo_root/scripts/dmg_notarization_transaction.py" \
    recover \
    --repository "$repo_root" \
    --version "$version" \
    --build-number "$build_number" \
    --notary-profile "$notary_profile" \
    --submission-id "$recovery_submission_id"
  shasum -a 256 "$final_set/$dmg_name" "$final_set/dmg-set.seal.json"
  exit 0
fi

cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/dmg_notarization_transaction.py" \
  preflight \
  --repository "$repo_root" \
  --version "$version" \
  --build-number "$build_number" \
  --notary-profile "$notary_profile"

signing_preflight_manifest="$ga_root/profiles/signing-preflight.json"
[[ -f "$signing_preflight_manifest" && ! -L "$signing_preflight_manifest" ]] ||
  die "frozen signing preflight is unavailable"
[[ "$(stat -f '%l' "$signing_preflight_manifest")" == "1" ]] ||
  die "frozen signing preflight must not have hard links"
signing_certificate_sha1="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/release_signing_preflight.py" \
  --print-certificate-sha1 "$signing_preflight_manifest")" ||
  die "cannot reopen the frozen Developer ID certificate SHA-1"
expected_certificate_sha256="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/release_signing_preflight.py" \
  --print-certificate-sha256 "$signing_preflight_manifest")" ||
  die "cannot reopen the frozen Developer ID certificate SHA-256"
readonly signing_certificate_sha1 expected_certificate_sha256
[[ "$signing_certificate_sha1" =~ ^[0-9A-F]{40}$ && \
  "$expected_certificate_sha256" =~ ^[0-9A-F]{64}$ ]] ||
  die "frozen Developer ID certificate fingerprints are malformed"

staging="$(mktemp -d "$dmg_root/dmg-stage.XXXXXX")"
payload_directory="$staging/payload"
mkdir "$payload_directory"
staged_dmg="$staging/$dmg_name"
cleanup() {
  /bin/rm -rf "$staging"
}
trap cleanup EXIT

/usr/bin/ditto "$app_path" "$payload_directory/Clash for Mac.app"
ln -s /Applications "$payload_directory/Applications"
"$repo_root/scripts/verify_release_app.sh" \
  "$payload_directory/Clash for Mac.app" \
  "$native_products_root" \
  --context canonical-native-content

/usr/sbin/diskutil image create from \
  --format UDZO \
  --volumeName "Clash for Mac" \
  "$payload_directory" \
  "$staged_dmg"
[[ -f "$staged_dmg" && ! -L "$staged_dmg" ]] || die "diskutil did not create a regular DMG"
[[ "$(stat -f '%l' "$staged_dmg")" == "1" ]] || die "DMG must not have hard links"

/usr/bin/codesign --force --timestamp --sign "$signing_certificate_sha1" "$staged_dmg"
/usr/bin/codesign --verify --strict --verbose=4 "$staged_dmg"
signature_details="$(/usr/bin/codesign -d --verbose=4 "$staged_dmg" 2>&1)"
[[ "$signature_details" == *"TeamIdentifier=$expected_team_id"* ]] ||
  die "DMG signature Team ID mismatch"
[[ "$signature_details" == *"Authority=Developer ID Application:"*"($expected_team_id)"* ]] ||
  die "DMG is not signed by the expected Developer ID Application identity"
[[ "$signature_details" == *"Timestamp="* && "$signature_details" != *"Timestamp=none"* ]] ||
  die "DMG secure signing timestamp is missing"
[[ "$signature_details" != *"Signature=adhoc"* ]] || die "ad-hoc DMG signature is forbidden"
certificate_prefix="$staging/dmg-leaf-certificate-"
/usr/bin/codesign -d --extract-certificates="$certificate_prefix" \
  "$staged_dmg" >/dev/null 2>&1 ||
  die "cannot extract the DMG Developer ID leaf certificate"
leaf_certificate="${certificate_prefix}0"
[[ -f "$leaf_certificate" && ! -L "$leaf_certificate" ]] ||
  die "DMG Developer ID leaf certificate is not a regular file"
[[ "$(stat -f '%l' "$leaf_certificate")" == "1" ]] ||
  die "DMG Developer ID leaf certificate must not have hard links"
observed_certificate_sha256="$(
  /usr/bin/shasum -a 256 "$leaf_certificate" |
    /usr/bin/awk '{print toupper($1)}'
)" || die "cannot hash the DMG Developer ID leaf certificate"
[[ "$observed_certificate_sha256" == "$expected_certificate_sha256" ]] ||
  die "DMG Developer ID leaf certificate differs from the frozen signing preflight"

cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/dmg_notarization_transaction.py" \
  start \
  --repository "$repo_root" \
  --version "$version" \
  --build-number "$build_number" \
  --notary-profile "$notary_profile" \
  --dmg "$staged_dmg"

shasum -a 256 "$final_set/$dmg_name" "$final_set/dmg-set.seal.json"
