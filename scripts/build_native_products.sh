#!/usr/bin/env bash
# Build the three native release products from the tracked Xcode project.
# Unsigned mode is for CI validation only. Developer ID mode requires the
# product's exact identity and target-specific provisioning profiles.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"

readonly expected_team_id="YKUPL7Z869"
readonly project="$repo_root/native/macos/CFWNative.xcodeproj"
readonly configuration="Release"
: "${CFW_BUILD_NUMBER:?set the candidate-specific positive integer build number}"
: "${CFW_NATIVE_PRODUCTS_OUTPUT:?set the candidate-specific native products output root}"
readonly output_input="$CFW_NATIVE_PRODUCTS_OUTPUT"
readonly derived_data="${CFW_NATIVE_DERIVED_DATA:-${output_input%/native-products}/xcode-derived-data}"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/build_native_products.sh --unsigned|--developer-id

--unsigned      Build arm64 Release products with code signing disabled.
--developer-id  Build signed products. Requires MACOS_SIGN_IDENTITY,
                PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER, and
                PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER.
EOF
  exit 2
}

[[ $# -eq 1 ]] || usage
case "$1" in
  --unsigned)
    signing_mode="unsigned-validation"
    ;;
  --developer-id)
    signing_mode="developer-id"
    ;;
  *)
    usage
    ;;
esac

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "native products require Apple Silicon macOS"
[[ "$output_input" == /* ]] || die "native product output must be absolute"
[[ "$output_input" == "$repo_root/target/candidates/0.4.0/"*"/native-products" ]] ||
  die "native products must use a 0.4.0 candidate-specific immutable root"
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$repo_root" "$CFW_BUILD_NUMBER" <<'PY'
import sys

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import canonical_build_version

canonical_build_version(sys.argv[2], "CFW_BUILD_NUMBER")
PY
[[ -d "$project" && ! -L "$project" ]] || die "tracked Xcode project is unavailable"
[[ -d "$repo_root/target/native-dependencies/Libbox.xcframework" ]] ||
  die "source-built Libbox.xcframework is unavailable"
[[ -f "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" ]] ||
  die "libbox artifact manifest is unavailable"
"$repo_root/scripts/verify_xcode_project.sh"
[[ ! -e "$derived_data" && ! -L "$derived_data" ]] ||
  die "refusing to replace derived data: $derived_data"
[[ ! -L "$output_input" ]] || die "native product output must not be a symlink"
mkdir -p "$output_input"
output_root="$(cd "$output_input" && pwd -P)"

products=(
  CFWNativeBridge.framework
  CFWProxyAgent.app
  CFWPacketTunnel.systemextension
)
for product in "${products[@]}"; do
  [[ ! -e "$output_root/$product" && ! -L "$output_root/$product" ]] ||
    die "refusing to replace native product: $output_root/$product"
  [[ ! -e "$output_root/$product.manifest.json" && ! -L "$output_root/$product.manifest.json" ]] ||
    die "refusing to replace native product manifest: $output_root/$product.manifest.json"
done

xcode_version_output="$(xcodebuild -version)" || die "cannot query Xcode identity"
xcode_version="$(printf '%s\n' "$xcode_version_output" | awk 'NR == 1 {print $2}')"
xcode_build="$(printf '%s\n' "$xcode_version_output" | awk 'NR == 2 {print $3}')"
[[ -n "$xcode_version" && -n "$xcode_build" ]] || die "invalid Xcode identity"
if [[ -n "${XCODE_VERSION:-}" && "$xcode_version" != "$XCODE_VERSION" ]]; then
  die "Xcode $XCODE_VERSION is required, found $xcode_version"
fi
if [[ -n "${XCODE_BUILD_VERSION:-}" && "$xcode_build" != "$XCODE_BUILD_VERSION" ]]; then
  die "Xcode build $XCODE_BUILD_VERSION is required, found $xcode_build"
fi

common_arguments=(
  -project "$project"
  -configuration "$configuration"
  -derivedDataPath "$derived_data"
  -destination 'generic/platform=macOS'
  ARCHS=arm64
  ONLY_ACTIVE_ARCH=NO
  DEVELOPMENT_TEAM="$expected_team_id"
  "TeamIdentifierPrefix=$expected_team_id."
  "AppIdentifierPrefix=$expected_team_id."
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
  CFW_BUILD_NUMBER="$CFW_BUILD_NUMBER"
  CURRENT_PROJECT_VERSION="$CFW_BUILD_NUMBER"
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
)

if [[ "$signing_mode" == "unsigned-validation" ]]; then
  signing_arguments=(
    CODE_SIGNING_ALLOWED=NO
    CODE_SIGNING_REQUIRED=NO
  )
else
  : "${MACOS_SIGN_IDENTITY:?set the exact Developer ID Application identity}"
  : "${PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER:?set the ProxyAgent Developer ID profile specifier}"
  : "${PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER:?set the Packet Tunnel Developer ID profile specifier}"
  [[ "$MACOS_SIGN_IDENTITY" == "Developer ID Application:"*"($expected_team_id)" ]] ||
    die "signing identity must be a Developer ID Application identity for $expected_team_id"
  security find-identity -v -p codesigning | grep -Fq "\"$MACOS_SIGN_IDENTITY\"" ||
    die "the requested Developer ID identity is not available in the keychain"
  signing_arguments=(
    CODE_SIGNING_ALLOWED=YES
    CODE_SIGNING_REQUIRED=YES
    CODE_SIGN_STYLE=Manual
    DEVELOPMENT_TEAM="$expected_team_id"
    CODE_SIGN_IDENTITY="$MACOS_SIGN_IDENTITY"
    ENABLE_HARDENED_RUNTIME=YES
    'OTHER_CODE_SIGN_FLAGS=--timestamp'
  )
fi

build_scheme() {
  local scheme="$1"
  shift
  xcodebuild build \
    "${common_arguments[@]}" \
    -scheme "$scheme" \
    "${signing_arguments[@]}" \
    "$@"
}

build_scheme CFWNativeBridge
if [[ "$signing_mode" == "developer-id" ]]; then
  build_scheme CFWProxyAgent \
    PROVISIONING_PROFILE_SPECIFIER="$PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER"
  build_scheme CFWPacketTunnelExtension \
    PROVISIONING_PROFILE_SPECIFIER="$PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER"
else
  build_scheme CFWProxyAgent
  build_scheme CFWPacketTunnelExtension
fi

built_root="$derived_data/Build/Products/$configuration"
[[ -d "$built_root" && ! -L "$built_root" ]] || die "Xcode product directory is unavailable"

staging="$(mktemp -d "$output_root/.native-products.XXXXXX")"
published=()
cleanup() {
  /bin/rm -rf "$staging" "$derived_data"
  if [[ ${#published[@]} -ne 0 ]]; then
    for path in "${published[@]}"; do
      /bin/rm -rf "$path"
    done
  fi
}
trap cleanup EXIT

for product in "${products[@]}"; do
  source_path="$built_root/$product"
  [[ -d "$source_path" && ! -L "$source_path" ]] ||
    die "Xcode did not produce a real $product bundle"
  /usr/bin/ditto --noqtn "$source_path" "$staging/$product"
done

verify_macho() {
  local binary="$1"
  local architecture
  local build_details
  architecture="$(lipo -archs "$binary")"
  [[ "$architecture" == "arm64" ]] || die "native product is not thin arm64: $binary"
  build_details="$(vtool -show-build "$binary")"
  [[ "$build_details" =~ platform[[:space:]]+MACOS ]] ||
    die "native product is not a macOS Mach-O: $binary"
  [[ "$build_details" =~ minos[[:space:]]+$MACOS_DEPLOYMENT_TARGET([[:space:]]|$) ]] ||
    die "native product deployment target differs from $MACOS_DEPLOYMENT_TARGET: $binary"
}

bridge_binary="$staging/CFWNativeBridge.framework/Versions/A/CFWNativeBridge"
agent_binary="$staging/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
tunnel_binary="$staging/CFWPacketTunnel.systemextension/Contents/MacOS/CFWPacketTunnel"
for binary in "$bridge_binary" "$agent_binary" "$tunnel_binary"; do
  [[ -f "$binary" && ! -L "$binary" ]] || die "native product executable is unavailable: $binary"
  verify_macho "$binary"
done

for info_plist in \
  "$staging/CFWNativeBridge.framework/Versions/A/Resources/Info.plist" \
  "$staging/CFWProxyAgent.app/Contents/Info.plist" \
  "$staging/CFWPacketTunnel.systemextension/Contents/Info.plist"; do
  built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info_plist" 2>/dev/null)" ||
    die "native product has no readable CFBundleVersion: $info_plist"
  [[ "$built_version" == "$CFW_BUILD_NUMBER" ]] ||
    die "native product build number mismatch: $info_plist ($built_version)"
done

if [[ "$signing_mode" == "developer-id" ]]; then
  for product in "${products[@]}"; do
    codesign --verify --strict --verbose=4 "$staging/$product"
    signature="$(codesign -d --verbose=4 "$staging/$product" 2>&1)"
    [[ "$signature" == *"TeamIdentifier=$expected_team_id"* ]] ||
      die "native product Team ID mismatch: $product"
    [[ "$signature" == *"Authority=Developer ID Application:"*"($expected_team_id)"* ]] ||
      die "native product does not have the expected Developer ID identity: $product"
    [[ "$signature" == *"Timestamp="* && "$signature" != *"Timestamp=none"* ]] ||
      die "native product has no secure timestamp: $product"
    [[ "$signature" != *"Signature=adhoc"* ]] || die "ad-hoc native product is forbidden: $product"
  done
fi

libbox_manifest_sha256="$(shasum -a 256 "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" | awk '{print $1}')"
native_source_sha256="$(PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/hash_native_build_inputs.py")"
libbox_tree_sha256="$(python3 - "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
digest = manifest.get("sha256")
if not isinstance(digest, str) or len(digest) != 64:
    raise SystemExit("error: libbox manifest has no valid tree digest")
print(digest)
PY
)"

for product in "${products[@]}"; do
  case "$product" in
    CFWNativeBridge.framework) artifact_kind="native-host-bridge-v1" ;;
    CFWProxyAgent.app) artifact_kind="native-proxy-agent-v1" ;;
    CFWPacketTunnel.systemextension) artifact_kind="native-packet-tunnel-v1" ;;
    *) die "unknown native product: $product" ;;
  esac
  python3 "$repo_root/scripts/hash_artifact.py" \
    "$staging/$product" \
    --output "$staging/$product.manifest.json" \
    --metadata "artifactKind=$artifact_kind" \
    --metadata "architecture=arm64" \
    --metadata "buildNumber=$CFW_BUILD_NUMBER" \
    --metadata "configuration=$configuration" \
    --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
    --metadata "libboxManifestSha256=$libbox_manifest_sha256" \
    --metadata "libboxTreeSha256=$libbox_tree_sha256" \
    --metadata "nativeSourceSha256=$native_source_sha256" \
    --metadata "signingMode=$signing_mode" \
    --metadata "singBoxCommit=$SING_BOX_COMMIT" \
    --metadata "xcodeBuild=$xcode_build" \
    --metadata "xcodeVersion=$xcode_version"
done

for product in "${products[@]}"; do
  /bin/mv "$staging/$product" "$output_root/$product"
  published+=("$output_root/$product")
  /bin/mv "$staging/$product.manifest.json" "$output_root/$product.manifest.json"
  published+=("$output_root/$product.manifest.json")
done
rmdir "$staging"
staging=""
/bin/rm -rf "$derived_data"
published=()
trap - EXIT

echo "native products built: $output_root"
echo "identity: Xcode $xcode_version ($xcode_build), arm64, macOS $MACOS_DEPLOYMENT_TARGET"
echo "build number: $CFW_BUILD_NUMBER"
echo "signing mode: $signing_mode"
