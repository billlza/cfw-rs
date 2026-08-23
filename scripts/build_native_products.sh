#!/bin/bash -p
# Build the four native release products from the tracked Xcode project.
# Unsigned mode is for CI validation only. Developer ID mode requires the
# product's exact identity and target-specific provisioning profiles.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
if [[ "${1:-}" == "--unsigned" && -n "${CFW_UNSIGNED_VALIDATION_PYTHON:-}" ]]; then
  cfw_seal_release_tool_environment unsigned-validation
else
  cfw_seal_release_tool_environment production
fi
readonly python_bin="$CFW_RELEASE_PYTHON_EXECUTABLE"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_select_release_apple_toolchain

readonly expected_team_id="YKUPL7Z869"
readonly authority_signing_identifier="com.bill.clashformac.global-authority"
readonly authority_designated_requirement='designated => anchor apple generic and identifier "com.bill.clashformac.global-authority" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "YKUPL7Z869"'
readonly project="$repo_root/native/macos/CFWNative.xcodeproj"
readonly configuration="Release"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
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

validate_candidate_output() {
  PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
    "$repo_root" "$CFW_BUILD_NUMBER" "$output_input" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import candidate_native_products_output

print(candidate_native_products_output(Path(sys.argv[1]), sys.argv[3], sys.argv[2]))
PY
}

validate_candidate_derived_data() {
  PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
    "$repo_root" "$CFW_BUILD_NUMBER" "$output_input" "$derived_data" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import candidate_native_derived_data_output

print(
    candidate_native_derived_data_output(
        Path(sys.argv[1]), sys.argv[3], sys.argv[4], sys.argv[2]
    )
)
PY
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
[[ "$(validate_candidate_output)" == "$output_input" ]] ||
  die "native products must use an exact candidate-specific immutable root"
[[ "$(validate_candidate_derived_data)" == "$derived_data" ]] ||
  die "Xcode derived data must use the exact candidate-specific output root"
[[ -d "$project" && ! -L "$project" ]] || die "tracked Xcode project is unavailable"
[[ -d "$repo_root/target/native-dependencies/Libbox.xcframework" ]] ||
  die "source-built Libbox.xcframework is unavailable"
[[ -f "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" ]] ||
  die "libbox artifact manifest is unavailable"
go_toolchain_tree_sha256="$(
  cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go toolchain tree"
go_tools_tree_sha256="$(
  cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go release-tools tree"
go_module_cache_tree_sha256="$(
  cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go module-cache tree"
libbox_tree_sha256_start="$(libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256")" || die "Libbox artifact does not match the current release contract"
libbox_manifest_sha256_start="$(
  shasum -a 256 "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" |
    awk '{print $1}'
)" || die "cannot hash the verified Libbox manifest"
"$repo_root/scripts/verify_xcode_project.sh"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/verify_native_product_graph.py"
source_identity_start="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot capture the release source identity"
read -r repository_commit release_source_sha256 <<<"$source_identity_start"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "release source identity is incomplete"
if [[ -n "${CFW_REPOSITORY_COMMIT:-}" && "$repository_commit" != "$CFW_REPOSITORY_COMMIT" ]]; then
  die "repository HEAD changed after the candidate build began"
fi
if [[ -n "${CFW_RELEASE_SOURCE_SHA256:-}" && "$release_source_sha256" != "$CFW_RELEASE_SOURCE_SHA256" ]]; then
  die "release source changed after the candidate build began"
fi
[[ ! -e "$derived_data" && ! -L "$derived_data" ]] ||
  die "refusing to replace derived data: $derived_data"
[[ ! -L "$output_input" ]] || die "native product output must not be a symlink"
mkdir -p "$output_input"
output_root="$(validate_candidate_output)" ||
  die "native product output changed while it was being created"
[[ "$output_root" == "$output_input" ]] ||
  die "native product output is not canonical"
[[ "$(validate_candidate_derived_data)" == "$derived_data" ]] ||
  die "Xcode derived-data output changed while the candidate root was created"

products=(
  CFWGlobalAuthority
  CFWNativeBridge.framework
  CFWProxyAgent.app
  com.bill.clashformac.packet-tunnel.systemextension
)
for product in "${products[@]}"; do
  [[ ! -e "$output_root/$product" && ! -L "$output_root/$product" ]] ||
    die "refusing to replace native product: $output_root/$product"
  [[ ! -e "$output_root/$product.manifest.json" && ! -L "$output_root/$product.manifest.json" ]] ||
    die "refusing to replace native product manifest: $output_root/$product.manifest.json"
done

xcode_version_output="$(/usr/bin/xcodebuild -version)" || die "cannot query Xcode identity"
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
  profile_uuid_pattern='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
  [[ "$PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER" =~ $profile_uuid_pattern ]] ||
    die "ProxyAgent provisioning profile specifier must be an exact profile UUID"
  [[ "$PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER" =~ $profile_uuid_pattern ]] ||
    die "Packet Tunnel provisioning profile specifier must be an exact profile UUID"
  [[ "$MACOS_SIGN_IDENTITY" == "Developer ID Application:"*"($expected_team_id)" ]] ||
    die "signing identity must be a Developer ID Application identity for $expected_team_id"
  /usr/bin/security find-identity -v -p codesigning | grep -Fq "\"$MACOS_SIGN_IDENTITY\"" ||
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
  /usr/bin/xcodebuild build \
    "${common_arguments[@]}" \
    -scheme "$scheme" \
    "${signing_arguments[@]}" \
    "$@"
}

build_scheme CFWNativeBridge
build_scheme CFWGlobalAuthorityDaemon
if [[ "$signing_mode" == "developer-id" ]]; then
  build_scheme CFWProxyAgent \
    CFW_PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER="$PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER"
  build_scheme CFWPacketTunnelExtension \
    CFW_PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER="$PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER"
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
  [[ -e "$source_path" && ! -L "$source_path" ]] ||
    die "Xcode did not produce a real $product"
  /usr/bin/ditto --noqtn "$source_path" "$staging/$product"
done

verify_macho() {
  local binary="$1"
  local architecture
  local build_details
  architecture="$(/usr/bin/lipo -archs "$binary")"
  [[ "$architecture" == "arm64" ]] || die "native product is not thin arm64: $binary"
  build_details="$(/usr/bin/vtool -show-build "$binary")"
  [[ "$build_details" =~ platform[[:space:]]+MACOS ]] ||
    die "native product is not a macOS Mach-O: $binary"
  [[ "$build_details" =~ minos[[:space:]]+$MACOS_DEPLOYMENT_TARGET([[:space:]]|$) ]] ||
    die "native product deployment target differs from $MACOS_DEPLOYMENT_TARGET: $binary"
}

authority_binary="$staging/CFWGlobalAuthority"
bridge_binary="$staging/CFWNativeBridge.framework/Versions/A/CFWNativeBridge"
agent_binary="$staging/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
tunnel_binary="$staging/com.bill.clashformac.packet-tunnel.systemextension/Contents/MacOS/CFWPacketTunnel"
for binary in "$authority_binary" "$bridge_binary" "$agent_binary" "$tunnel_binary"; do
  [[ -f "$binary" && ! -L "$binary" ]] || die "native product executable is unavailable: $binary"
  verify_macho "$binary"
done

if [[ "$signing_mode" == "developer-id" ]]; then
  # Xcode's generic tool signature deliberately accepts both Apple Development
  # and Developer ID certificates. The privileged launch daemon has a stricter
  # release identity, so replace only this standalone Mach-O signature with the
  # exact reviewed Developer ID designated requirement.
  /usr/bin/codesign \
    --force \
    --options runtime \
    --timestamp \
    --identifier "$authority_signing_identifier" \
    -r="$authority_designated_requirement" \
    --entitlements "$repo_root/native/macos/Config/GlobalAuthority.entitlements" \
    --sign "$MACOS_SIGN_IDENTITY" \
    "$authority_binary"

  authority_requirement_text="$staging/.authority-requirement.txt"
  authority_requirement_expected="$staging/.authority-requirement.expected"
  authority_requirement_actual="$staging/.authority-requirement.actual"
  /usr/bin/codesign -d -r "$authority_requirement_text" "$authority_binary" \
    >/dev/null 2>&1 || die "cannot extract the Global Authority designated requirement"
  /usr/bin/csreq -r="$authority_designated_requirement" -b "$authority_requirement_expected" ||
    die "cannot compile the expected Global Authority designated requirement"
  /usr/bin/csreq -r "$authority_requirement_text" -b "$authority_requirement_actual" ||
    die "cannot compile the signed Global Authority designated requirement"
  cmp -s "$authority_requirement_expected" "$authority_requirement_actual" ||
    die "Global Authority designated requirement mismatch"
  /bin/rm \
    "$authority_requirement_text" \
    "$authority_requirement_expected" \
    "$authority_requirement_actual"
fi

for info_plist in \
  "$staging/CFWNativeBridge.framework/Versions/A/Resources/Info.plist" \
  "$staging/CFWProxyAgent.app/Contents/Info.plist" \
  "$staging/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist"; do
  built_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info_plist" 2>/dev/null)" ||
    die "native product has no readable CFBundleVersion: $info_plist"
  [[ "$built_version" == "$CFW_BUILD_NUMBER" ]] ||
    die "native product build number mismatch: $info_plist ($built_version)"
done

if [[ "$signing_mode" == "developer-id" ]]; then
  for product in "${products[@]}"; do
    /usr/bin/codesign --verify --strict --verbose=4 "$staging/$product"
    signature="$(/usr/bin/codesign -d --verbose=4 "$staging/$product" 2>&1)"
    [[ "$signature" == *"TeamIdentifier=$expected_team_id"* ]] ||
      die "native product Team ID mismatch: $product"
    [[ "$signature" == *"Authority=Developer ID Application:"*"($expected_team_id)"* ]] ||
      die "native product does not have the expected Developer ID identity: $product"
    [[ "$signature" == *"Timestamp="* && "$signature" != *"Timestamp=none"* ]] ||
      die "native product has no secure timestamp: $product"
    [[ "$signature" != *"Signature=adhoc"* ]] || die "ad-hoc native product is forbidden: $product"
    if [[ "$product" == "CFWGlobalAuthority" ]]; then
      [[ "$signature" == *"Identifier=$authority_signing_identifier"* ]] ||
        die "Global Authority signing identifier mismatch"
    fi
  done
fi

libbox_manifest_sha256="$(
  shasum -a 256 "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" |
    awk '{print $1}'
)" || die "cannot re-hash the verified Libbox manifest"
native_source_sha256="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_native_build_inputs.py")"
source_identity_end="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot re-observe the release source identity"
[[ "$source_identity_end" == "$source_identity_start" ]] ||
  die "release source changed while native products were building"
libbox_tree_sha256="$(libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256")" || die "Libbox artifact changed or no longer matches the release contract"
[[ "$libbox_tree_sha256" == "$libbox_tree_sha256_start" ]] ||
  die "Libbox artifact changed while native products were building"
[[ "$libbox_manifest_sha256" == "$libbox_manifest_sha256_start" ]] ||
  die "Libbox manifest changed while native products were building"

for product in "${products[@]}"; do
  case "$product" in
    CFWGlobalAuthority) artifact_kind="native-global-authority-v1" ;;
    CFWNativeBridge.framework) artifact_kind="native-host-bridge-v1" ;;
    CFWProxyAgent.app) artifact_kind="native-proxy-agent-v1" ;;
    com.bill.clashformac.packet-tunnel.systemextension) artifact_kind="native-packet-tunnel-v1" ;;
    *) die "unknown native product: $product" ;;
  esac
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/hash_artifact.py" \
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
    --metadata "releaseSourceSha256=$release_source_sha256" \
    --metadata "repositoryCommit=$repository_commit" \
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
