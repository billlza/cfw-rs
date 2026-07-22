#!/usr/bin/env bash
# Build, sign, notarize, staple, and verify the installable 0.4.0 candidate.
# This script never installs or launches the app and never changes network,
# proxy, DNS, helper, launchd, or Network Extension runtime state.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
readonly expected_team_id="YKUPL7Z869"
readonly candidate_base="$repo_root/target/candidates/0.4.0"

die() {
  echo "error: $*" >&2
  exit 1
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "release input must not have hard links: $path"
}

[[ $# -eq 1 ]] ||
  die "usage: scripts/build_signed_candidate.sh --validation|--release"
case "$1" in
  --validation) build_kind="validation" ;;
  --release) build_kind="release" ;;
  *) die "usage: scripts/build_signed_candidate.sh --validation|--release" ;;
esac
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "signed candidates require Apple Silicon macOS"
: "${CFW_BUILD_NUMBER:?set the explicit positive integer candidate build number}"
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$repo_root" "$CFW_BUILD_NUMBER" <<'PY'
import sys

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import canonical_build_version

canonical_build_version(sys.argv[2], "CFW_BUILD_NUMBER")
PY
if [[ "$build_kind" == "validation" ]]; then
  build_root="$candidate_base/validation/$CFW_BUILD_NUMBER"
  final_root="$build_root/signed"
  artifact_kind="notarized-validation-candidate-v1"
else
  build_root="$candidate_base/release-build/$CFW_BUILD_NUMBER"
  final_root="$candidate_base/signed"
  artifact_kind="notarized-release-v1"
  validated_review="$candidate_base/review/validated-candidate.json"
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "$repo_root/scripts/validated_candidate_evidence.py" \
    "$validated_review" \
    --final-build-number "$CFW_BUILD_NUMBER"
fi
native_products="$build_root/native-products"
cargo_target="$build_root/cargo"
built_app="$cargo_target/release/bundle/macos/Clash for Mac.app"
final_app="$final_root/Clash for Mac.app"
: "${MACOS_SIGN_IDENTITY:?set the exact Developer ID Application identity}"
: "${HOST_PROVISIONING_PROFILE_PATH:?set the absolute host Developer ID profile path}"
: "${PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER:?set the ProxyAgent profile specifier}"
: "${PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER:?set the Packet Tunnel profile specifier}"
: "${NOTARY_PROFILE:?set the notarytool Keychain profile name}"
[[ "$MACOS_SIGN_IDENTITY" == "Developer ID Application:"*"($expected_team_id)" ]] ||
  die "signing identity must be a Developer ID Application identity for $expected_team_id"
[[ "$HOST_PROVISIONING_PROFILE_PATH" == /* ]] ||
  die "host provisioning profile path must be absolute"
require_regular_file "$HOST_PROVISIONING_PROFILE_PATH"
security find-identity -v -p codesigning | grep -Fq "\"$MACOS_SIGN_IDENTITY\"" ||
  die "the requested Developer ID identity is unavailable"

for parent in "$repo_root/target" "$repo_root/target/candidates" "$candidate_base"; do
  [[ ! -L "$parent" ]] || die "candidate parent must not be a symlink: $parent"
  mkdir -p "$parent"
  [[ -d "$parent" ]] || die "candidate parent is not a directory: $parent"
done
for output in "$final_root" "$build_root"; do
  [[ ! -e "$output" && ! -L "$output" ]] || die "refusing to replace candidate output: $output"
done

export CFW_NATIVE_PRODUCTS_OUTPUT="$native_products"
export CFW_NATIVE_DERIVED_DATA="$build_root/xcode-derived-data"

"$repo_root/scripts/verify_release_environment.sh"
"$repo_root/scripts/build_native_products.sh" --developer-id
"$repo_root/scripts/build_legacy_tombstone.sh" --developer-id

for product in \
  CFWNativeBridge.framework \
  CFWProxyAgent.app \
  CFWPacketTunnel.systemextension; do
  PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
    "$native_products/$product" \
    "$native_products/$product.manifest.json" \
    --metadata "buildNumber=$CFW_BUILD_NUMBER" \
    --metadata "signingMode=developer-id"
done
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$native_products/CFWLegacyTombstone" \
  "$native_products/CFWLegacyTombstone.manifest.json" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "signingMode=developer-id"

"$repo_root/scripts/build_ui_with_pinned_node.sh"
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$cargo_target"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
tauri_override="$(python3 - "$CFW_BUILD_NUMBER" "$native_products" <<'PY'
import json
import sys

build, native = sys.argv[1:]
print(json.dumps({
    "bundle": {
        "macOS": {
            "bundleVersion": build,
            "files": {
                "Frameworks/CFWNativeBridge.framework": f"{native}/CFWNativeBridge.framework",
                "Library/HelperTools/cfw-helper-tombstone": (
                    f"{native}/CFWLegacyTombstone/cfw-helper-tombstone"
                ),
                "Library/LoginItems/CFWProxyAgent.app": f"{native}/CFWProxyAgent.app",
                "Library/SystemExtensions/CFWPacketTunnel.systemextension": (
                    f"{native}/CFWPacketTunnel.systemextension"
                ),
            },
        }
    }
}, separators=(",", ":")))
PY
)"
(
  cd "$repo_root/apps/cfw-tauri-shell"
  cargo tauri build --bundles app --no-sign --ci --config "$tauri_override"
)
"$repo_root/scripts/verify_candidate_bundle.sh" "$built_app" "$native_products"

staging="$(mktemp -d "$candidate_base/.signed-stage.XXXXXX")"
completed=0
cleanup() {
  if [[ -n "${staging:-}" && -d "$staging" && "$staging" == "$candidate_base/.signed-stage."* ]]; then
    /bin/rm -r "$staging"
  fi
  if [[ $completed -ne 1 && -d "$final_root" && ! -L "$final_root" ]]; then
    /bin/rm -r "$final_root"
  fi
  if [[ $completed -ne 1 && -d "$build_root" && ! -L "$build_root" ]]; then
    /bin/rm -r "$build_root"
  fi
}
trap cleanup EXIT
staged_app="$staging/Clash for Mac.app"
/usr/bin/ditto --noqtn "$built_app" "$staged_app"
/usr/bin/install -m 0644 \
  "$HOST_PROVISIONING_PROFILE_PATH" \
  "$staged_app/Contents/embedded.provisionprofile"

for nested in \
  "$staged_app/Contents/Frameworks/CFWNativeBridge.framework" \
  "$staged_app/Contents/Library/LoginItems/CFWProxyAgent.app" \
  "$staged_app/Contents/Library/SystemExtensions/CFWPacketTunnel.systemextension" \
  "$staged_app/Contents/Library/HelperTools/cfw-helper-tombstone"; do
  codesign --verify --strict --verbose=4 "$nested"
done

codesign \
  --force \
  --options runtime \
  --timestamp \
  --entitlements "$repo_root/apps/cfw-tauri-shell/macos/entitlements.plist" \
  --sign "$MACOS_SIGN_IDENTITY" \
  "$staged_app"
codesign --verify --deep --strict --verbose=4 "$staged_app"
"$repo_root/scripts/verify_release_app.sh" --pre-notary "$staged_app" "$native_products"

notary_zip="$staging/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip"
notary_result="$staging/notary-result.json"
(
  cd "$staging"
  COPYFILE_DISABLE=1 /usr/bin/ditto \
    -c \
    -k \
    --keepParent \
    --sequesterRsrc \
    "Clash for Mac.app" \
    "$notary_zip"
)
xcrun notarytool submit "$notary_zip" \
  --wait \
  --keychain-profile "$NOTARY_PROFILE" \
  --output-format json >"$notary_result"
python3 - "$notary_result" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if result.get("status") != "Accepted" or not result.get("id"):
    raise SystemExit(
        "error: Apple notarization was not accepted "
        f"(status={result.get('status')!r}, id={result.get('id')!r})"
    )
print(f"notarization accepted: {result['id']}")
PY
xcrun stapler staple "$staged_app"
xcrun stapler validate "$staged_app"
spctl --assess --type execute --verbose=4 "$staged_app"
"$repo_root/scripts/verify_release_app.sh" "$staged_app" "$native_products"

mkdir "$final_root"
/bin/mv "$staged_app" "$final_app"
/bin/mv "$notary_result" "$final_root/notarization.json"
/bin/mv "$notary_zip" "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip"
rmdir "$staging"
staging=""
python3 "$repo_root/scripts/hash_artifact.py" \
  "$final_app" \
  --output "$final_root/Clash for Mac.app.manifest.json" \
  --metadata "artifactKind=$artifact_kind" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "teamID=$expected_team_id" \
  --metadata "version=0.4.0"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip" \
  --output "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip.manifest.json" \
  --metadata "artifactKind=notarization-submission-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "teamID=$expected_team_id" \
  --metadata "version=0.4.0"
completed=1
trap - EXIT

echo "signed and notarized 0.4.0 $build_kind build $CFW_BUILD_NUMBER: $final_app"
echo "the app has not been installed or launched"
