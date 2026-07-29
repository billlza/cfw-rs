#!/usr/bin/env bash
# Package a fully verified arm64 application, then sign, notarize, staple, and
# Gatekeeper-assess the DMG. No unsigned or partially verified fallback exists.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/release_publication_gate.sh
source "$repo_root/scripts/release_publication_gate.sh"
readonly expected_team_id="YKUPL7Z869"

die() {
  echo "error: $*" >&2
  exit 1
}

assert_semver() {
  local version="$1"
  local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$version" =~ $semver ]] || die "version is not a strict SemVer value: $version"
}

app_path="${1:-$repo_root/target/candidates/0.4.0/signed/Clash for Mac.app}"
[[ "$app_path" == /* ]] || die "application path must be absolute"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle not found or is a symlink: $app_path"
app_path="$(cd "$(dirname "$app_path")" && pwd -P)/$(basename "$app_path")"
[[ "$(basename "$app_path")" == "Clash for Mac.app" ]] ||
  die "unexpected release application name: $(basename "$app_path")"

sign_identity="${MACOS_SIGN_IDENTITY:-}"
notary_profile="${NOTARY_PROFILE:-}"
[[ -n "$sign_identity" && -n "$notary_profile" ]] ||
  die "MACOS_SIGN_IDENTITY and NOTARY_PROFILE are required"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "DMG release creation requires Apple Silicon macOS"

native_products_root="$(release_native_products_root_for_app "$app_path")" ||
  die "cannot resolve candidate-specific native products"
"$repo_root/scripts/verify_release_app.sh" "$app_path" "$native_products_root"

version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app_path/Contents/Info.plist" 2>/dev/null)" ||
  die "cannot read the signed app version"
assert_semver "$version"

verify_release_publication_evidence "$app_path"

output_root="$repo_root/target/candidates/0.4.0/release"
[[ ! -L "$output_root" ]] || die "DMG output directory must not be a symlink"
mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd -P)"
dmg_path="$output_root/Clash.for.Mac_${version}_arm64.dmg"
[[ ! -e "$dmg_path" && ! -L "$dmg_path" ]] ||
  die "refusing to replace existing release image: $dmg_path"

staging="$(mktemp -d "$output_root/dmg-stage.XXXXXX")"
payload_directory="$staging/payload"
mkdir "$payload_directory"
notary_result="$staging/notary-result.json"
notary_log="$staging/notarization-log.json"
gatekeeper_evidence="$staging/gatekeeper.json"
staged_dmg="$staging/Clash.for.Mac_${version}_arm64.dmg"
notary_result_final="$output_root/Clash.for.Mac_${version}_arm64.notarization.json"
notary_log_final="$output_root/Clash.for.Mac_${version}_arm64.notarization-log.json"
gatekeeper_final="$output_root/Clash.for.Mac_${version}_arm64.gatekeeper.json"
dmg_manifest="$output_root/Clash.for.Mac_${version}_arm64.dmg.manifest.json"
for output in "$notary_result_final" "$notary_log_final" "$gatekeeper_final" "$dmg_manifest"; do
  [[ ! -e "$output" && ! -L "$output" ]] || die "refusing to replace DMG evidence: $output"
done
completed=0
cleanup() {
  /bin/rm -rf "$staging"
  if [[ $completed -ne 1 ]]; then
    /bin/rm -f \
      "$dmg_path" \
      "$notary_result_final" \
      "$notary_log_final" \
      "$gatekeeper_final" \
      "$dmg_manifest"
  fi
}
trap cleanup EXIT

/usr/bin/ditto "$app_path" "$payload_directory/Clash for Mac.app"
ln -s /Applications "$payload_directory/Applications"
"$repo_root/scripts/verify_release_app.sh" \
  "$payload_directory/Clash for Mac.app" \
  "$native_products_root"

hdiutil create \
  -volname "Clash for Mac" \
  -srcfolder "$payload_directory" \
  -format UDZO \
  "$staged_dmg"
[[ -f "$staged_dmg" && ! -L "$staged_dmg" ]] || die "hdiutil did not create a regular DMG"
[[ "$(stat -f '%l' "$staged_dmg")" == "1" ]] || die "DMG must not have hard links"

codesign --force --timestamp --sign "$sign_identity" "$staged_dmg"
codesign --verify --strict --verbose=4 "$staged_dmg"
signature_details="$(codesign -d --verbose=4 "$staged_dmg" 2>&1)"
[[ "$signature_details" == *"TeamIdentifier=$expected_team_id"* ]] ||
  die "DMG signature Team ID mismatch"
[[ "$signature_details" == *"Authority=Developer ID Application:"*"($expected_team_id)"* ]] ||
  die "DMG is not signed by the expected Developer ID Application identity"
[[ "$signature_details" == *"Timestamp="* && "$signature_details" != *"Timestamp=none"* ]] ||
  die "DMG secure signing timestamp is missing"
[[ "$signature_details" != *"Signature=adhoc"* ]] || die "ad-hoc DMG signature is forbidden"

xcrun notarytool submit "$staged_dmg" \
  --wait \
  --keychain-profile "$notary_profile" \
  --output-format json >"$notary_result"
notary_submission_id="$(python3 - "$notary_result" <<'PY'
import json
from pathlib import Path
import sys

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if result.get("status") != "Accepted":
    raise SystemExit(
        f"error: Apple notarization did not return Accepted (status={result.get('status')!r}, id={result.get('id')!r})"
    )
if not result.get("id"):
    raise SystemExit("error: Apple notarization result has no submission ID")
print(result["id"])
PY
)"
echo "notarization accepted: $notary_submission_id"
xcrun notarytool log \
  "$notary_submission_id" \
  "$notary_log" \
  --keychain-profile "$notary_profile"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/verify_notary_log.py" \
  "$notary_result" \
  "$notary_log" \
  "$staged_dmg"

xcrun stapler staple "$staged_dmg"
xcrun stapler validate "$staged_dmg"
dmg_sha256="$(shasum -a 256 "$staged_dmg" | awk '{print $1}')"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/gatekeeper_assessment.py" \
  --target "$staged_dmg" \
  --assessment-type open \
  --primary-signature-context \
  --target-signed-app-tree-sha256 "$dmg_sha256" \
  --output "$gatekeeper_evidence"
codesign --verify --strict --verbose=4 "$staged_dmg"
/bin/ln "$staged_dmg" "$dmg_path" || die "cannot publish DMG exclusively"
/bin/rm "$staged_dmg"
/bin/ln "$notary_result" "$notary_result_final" || die "cannot publish notarization result"
/bin/ln "$notary_log" "$notary_log_final" || die "cannot publish notarization log"
/bin/ln "$gatekeeper_evidence" "$gatekeeper_final" || die "cannot publish Gatekeeper evidence"
/bin/rm "$notary_result" "$notary_log" "$gatekeeper_evidence"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$dmg_path" \
  --output "$dmg_manifest" \
  --metadata "artifactKind=notarized-dmg-v1" \
  --metadata "architecture=arm64" \
  --metadata "teamID=$expected_team_id" \
  --metadata "version=$version"
completed=1
shasum -a 256 "$dmg_path"
