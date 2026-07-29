#!/usr/bin/env bash
# Build, sign, notarize, staple, and verify the installable 0.4.0 candidate.
# This script never installs or launches the app and never changes network,
# proxy, DNS, helper, launchd, or Network Extension runtime state.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/ui_dependency_contract.sh
source "$repo_root/scripts/ui_dependency_contract.sh"
# shellcheck source=scripts/tauri_host_skeleton.sh
source "$repo_root/scripts/tauri_host_skeleton.sh"
readonly expected_team_id="YKUPL7Z869"
readonly expected_app_id="com.bill.clashformac"
readonly candidate_base="$repo_root/target/candidates/0.4.0"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
readonly tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"

die() {
  echo "error: $*" >&2
  exit 1
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "release input must not have hard links: $path"
}

sha256_file() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
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
pre_sign_manifest="$build_root/Clash for Mac.app.pre-sign.manifest.json"
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
host_profile_sha256="$(sha256_file "$HOST_PROVISIONING_PROFILE_PATH")"
host_profile_size="$(stat -f '%z' "$HOST_PROVISIONING_PROFILE_PATH")"
readonly host_profile_sha256 host_profile_size
[[ "$host_profile_sha256" =~ ^[0-9a-f]{64}$ && "$host_profile_size" =~ ^[1-9][0-9]*$ ]] ||
  die "host provisioning profile identity is malformed"
security find-identity -v -p codesigning | grep -Fq "\"$MACOS_SIGN_IDENTITY\"" ||
  die "the requested Developer ID identity is unavailable"
source_identity_start="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/repository_source_identity.py" --require-clean)" ||
  die "signed candidate builds require a clean release repository"
read -r repository_commit release_source_sha256 <<<"$source_identity_start"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "release source identity is incomplete"

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
export CFW_REPOSITORY_COMMIT="$repository_commit"
export CFW_RELEASE_SOURCE_SHA256="$release_source_sha256"

"$repo_root/scripts/verify_release_environment.sh"
ui_dependencies_tree_observed_start="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
toolchain_binding_start="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" ||
  die "cannot derive the canonical candidate toolchain binding"
read -r \
  toolchain_sha256 \
  go_toolchain_tree_sha256 \
  go_module_cache_tree_sha256 \
  go_tools_tree_sha256 \
  node_toolchain_tree_sha256 \
  tauri_toolchain_tree_sha256 \
  ui_dependencies_tree_sha256 \
  xcodegen_toolchain_tree_sha256 \
  unexpected_toolchain_field <<<"$toolchain_binding_start"
[[ -n "$xcodegen_toolchain_tree_sha256" && -z "${unexpected_toolchain_field:-}" ]] ||
  die "canonical candidate toolchain binding is incomplete"
[[ "$ui_dependencies_tree_sha256" == "$ui_dependencies_tree_observed_start" ]] ||
  die "canonical toolchain binding does not match the verified UI dependency tree"
export CFW_GO_TOOLCHAIN_TREE_SHA256="$go_toolchain_tree_sha256"
export CFW_GO_TOOLS_TREE_SHA256="$go_tools_tree_sha256"
export CFW_GO_MODULE_CACHE_TREE_SHA256="$go_module_cache_tree_sha256"
libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256" >/dev/null
"$repo_root/scripts/build_native_products.sh" --developer-id
"$repo_root/scripts/build_legacy_tombstone.sh" --developer-id

for product in \
  CFWGlobalAuthority \
  CFWNativeBridge.framework \
  CFWProxyAgent.app \
  com.bill.clashformac.packet-tunnel.systemextension; do
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
                "Library/HelperTools/CFWGlobalAuthority": f"{native}/CFWGlobalAuthority",
                "Library/HelperTools/cfw-helper-tombstone": (
                    f"{native}/CFWLegacyTombstone/cfw-helper-tombstone"
                ),
                "Library/LoginItems/CFWProxyAgent.app": f"{native}/CFWProxyAgent.app",
                "Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension": (
                    f"{native}/com.bill.clashformac.packet-tunnel.systemextension"
                ),
            },
        }
    }
}, separators=(",", ":")))
PY
)"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
cfw_build_tauri_host_skeleton \
  "$repo_root/apps/cfw-tauri-shell" \
  "$tauri_bin" \
  "$tauri_override"
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$built_app" \
  "$native_products" \
  --require-unsigned-host
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
ui_dependencies_tree_observed_end="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
[[ "$ui_dependencies_tree_observed_end" == "$ui_dependencies_tree_observed_start" ]] ||
  die "UI dependency tree changed while the signed candidate was building"
toolchain_binding_end="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" ||
  die "cannot re-observe the canonical candidate toolchain binding"
[[ "$toolchain_binding_end" == "$toolchain_binding_start" ]] ||
  die "release toolchain changed while the signed candidate was building"
source_identity_after_build="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/repository_source_identity.py" --require-clean)" ||
  die "release repository changed while the signed candidate was building"
[[ "$source_identity_after_build" == "$source_identity_start" ]] ||
  die "release source identity changed while the signed candidate was building"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$built_app" \
  --output "$pre_sign_manifest" \
  --metadata "artifactKind=pre-sign-application-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
  --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
  --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
  --metadata "nodeToolchainTreeSha256=$node_toolchain_tree_sha256" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit" \
  --metadata "tauriToolchainTreeSha256=$tauri_toolchain_tree_sha256" \
  --metadata "toolchainSha256=$toolchain_sha256" \
  --metadata "uiDependenciesTreeSha256=$ui_dependencies_tree_sha256" \
  --metadata "xcodegenToolchainTreeSha256=$xcodegen_toolchain_tree_sha256" \
  --metadata "version=0.4.0"
pre_sign_manifest_sha256="$(sha256_file "$pre_sign_manifest")"
host_executable_sha256="$(sha256_file "$built_app/Contents/MacOS/clash-for-mac")"
readonly pre_sign_manifest_sha256 host_executable_sha256
[[ "$pre_sign_manifest_sha256" =~ ^[0-9a-f]{64}$ && "$host_executable_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die "pre-sign application identity is malformed"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$built_app" \
  "$pre_sign_manifest" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"
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
[[ "$(sha256_file "$pre_sign_manifest")" == "$pre_sign_manifest_sha256" ]] ||
  die "pre-sign manifest changed before staging"
/usr/bin/ditto --noqtn "$built_app" "$staged_app"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$staged_app" \
  "$pre_sign_manifest" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$staged_app" \
  "$native_products" \
  --require-unsigned-host
/usr/bin/install -m 0644 \
  "$HOST_PROVISIONING_PROFILE_PATH" \
  "$staged_app/Contents/embedded.provisionprofile"
decoded_host_profile="$staging/host-profile.plist"
host_signing_identities="$staging/host-signing-identities.txt"
host_release_xcent="$staging/Host.release.xcent"
security cms -D \
  -i "$staged_app/Contents/embedded.provisionprofile" \
  >"$decoded_host_profile" || die "cannot decode the staged Host provisioning profile"
plutil -lint "$decoded_host_profile" >/dev/null ||
  die "the staged Host provisioning profile is not a valid plist"
security find-identity -v -p codesigning >"$host_signing_identities" ||
  die "cannot query the codesigning identities"
(
  cd "$repo_root"
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m scripts.host_release_entitlements \
    --decoded-profile "$decoded_host_profile" \
    --reviewed-entitlements "$repo_root/native/macos/Config/Host.entitlements" \
    --tauri-entitlements "$repo_root/apps/cfw-tauri-shell/macos/entitlements.plist" \
    --signing-identities "$host_signing_identities" \
    --signing-identity "$MACOS_SIGN_IDENTITY" \
    --expected-team-id "$expected_team_id" \
    --expected-bundle-id "$expected_app_id" \
    --output "$host_release_xcent"
)
require_regular_file "$host_release_xcent"
plutil -lint "$host_release_xcent" >/dev/null ||
  die "the generated Host release xcent is not a valid plist"

require_regular_file "$staged_app/Contents/embedded.provisionprofile"
[[ "$(stat -f '%Lp' "$staged_app/Contents/embedded.provisionprofile")" == "644" ]] ||
  die "staged Host provisioning profile mode is not 0644"
[[ "$(sha256_file "$HOST_PROVISIONING_PROFILE_PATH")" == "$host_profile_sha256" ]] ||
  die "host provisioning profile changed while the candidate was building"
[[ "$(stat -f '%z' "$HOST_PROVISIONING_PROFILE_PATH")" == "$host_profile_size" ]] ||
  die "host provisioning profile size changed while the candidate was building"
/usr/bin/cmp -s \
  "$HOST_PROVISIONING_PROFILE_PATH" \
  "$staged_app/Contents/embedded.provisionprofile" ||
  die "staged Host provisioning profile differs from the validated input"
[[ "$(sha256_file "$pre_sign_manifest")" == "$pre_sign_manifest_sha256" ]] ||
  die "pre-sign manifest changed before Host signing"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$staged_app" \
  "$pre_sign_manifest" \
  --added-file \
  "Contents/embedded.provisionprofile=$host_profile_sha256:$host_profile_size" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"
[[ "$(sha256_file "$staged_app/Contents/MacOS/clash-for-mac")" == "$host_executable_sha256" ]] ||
  die "staged Host executable differs from the pre-sign application"
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$staged_app" \
  "$native_products" \
  --require-unsigned-host

for nested in \
  "$staged_app/Contents/Frameworks/CFWNativeBridge.framework" \
  "$staged_app/Contents/Library/HelperTools/CFWGlobalAuthority" \
  "$staged_app/Contents/Library/LoginItems/CFWProxyAgent.app" \
  "$staged_app/Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension" \
  "$staged_app/Contents/Library/HelperTools/cfw-helper-tombstone"; do
  codesign --verify --strict --verbose=4 "$nested"
done

codesign \
  --force \
  --options runtime \
  --timestamp \
  --entitlements "$host_release_xcent" \
  --sign "$MACOS_SIGN_IDENTITY" \
  "$staged_app"
codesign --verify --deep --strict --verbose=4 "$staged_app"
"$repo_root/scripts/verify_release_app.sh" --pre-notary "$staged_app" "$native_products"
/bin/rm "$decoded_host_profile" "$host_signing_identities" "$host_release_xcent"

notary_zip="$staging/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip"
notary_result="$staging/notary-result.json"
notary_log="$staging/notarization-log.json"
gatekeeper_evidence="$staging/gatekeeper.json"
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
notary_submission_id="$(python3 - "$notary_result" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if result.get("status") != "Accepted" or not result.get("id"):
    raise SystemExit(
        "error: Apple notarization was not accepted "
        f"(status={result.get('status')!r}, id={result.get('id')!r})"
    )
print(result["id"])
PY
)"
echo "notarization accepted: $notary_submission_id"
xcrun notarytool log \
  "$notary_submission_id" \
  "$notary_log" \
  --keychain-profile "$NOTARY_PROFILE"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/verify_notary_log.py" \
  "$notary_result" \
  "$notary_log" \
  "$notary_zip"
xcrun stapler staple "$staged_app"
xcrun stapler validate "$staged_app"
signed_app_tree_sha256="$(PYTHONDONTWRITEBYTECODE=1 python3 -B - \
  "$repo_root" "$staged_app" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from hash_artifact import build_manifest

print(build_manifest(Path(sys.argv[2]))["sha256"])
PY
)"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/gatekeeper_assessment.py" \
  --target "$staged_app" \
  --assessment-type execute \
  --target-signed-app-tree-sha256 "$signed_app_tree_sha256" \
  --output "$gatekeeper_evidence"
"$repo_root/scripts/verify_release_app.sh" "$staged_app" "$native_products"

mkdir "$final_root"
/bin/mv "$staged_app" "$final_app"
/bin/mv "$notary_result" "$final_root/notarization.json"
/bin/mv "$notary_log" "$final_root/notarization-log.json"
/bin/mv "$gatekeeper_evidence" "$final_root/gatekeeper.json"
/bin/mv "$notary_zip" "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip"
rmdir "$staging"
staging=""
source_identity_final="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/repository_source_identity.py" --require-clean)" ||
  die "release repository changed before final artifact sealing"
[[ "$source_identity_final" == "$source_identity_start" ]] ||
  die "release source identity changed before final artifact sealing"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$final_app" \
  --output "$final_root/Clash for Mac.app.manifest.json" \
  --metadata "artifactKind=$artifact_kind" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
  --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
  --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
  --metadata "nodeToolchainTreeSha256=$node_toolchain_tree_sha256" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit" \
  --metadata "tauriToolchainTreeSha256=$tauri_toolchain_tree_sha256" \
  --metadata "teamID=$expected_team_id" \
  --metadata "toolchainSha256=$toolchain_sha256" \
  --metadata "uiDependenciesTreeSha256=$ui_dependencies_tree_sha256" \
  --metadata "xcodegenToolchainTreeSha256=$xcodegen_toolchain_tree_sha256" \
  --metadata "version=0.4.0"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip" \
  --output "$final_root/Clash.for.Mac_0.4.0_${CFW_BUILD_NUMBER}_notary.zip.manifest.json" \
  --metadata "artifactKind=notarization-submission-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
  --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
  --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
  --metadata "nodeToolchainTreeSha256=$node_toolchain_tree_sha256" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit" \
  --metadata "tauriToolchainTreeSha256=$tauri_toolchain_tree_sha256" \
  --metadata "teamID=$expected_team_id" \
  --metadata "toolchainSha256=$toolchain_sha256" \
  --metadata "uiDependenciesTreeSha256=$ui_dependencies_tree_sha256" \
  --metadata "xcodegenToolchainTreeSha256=$xcodegen_toolchain_tree_sha256" \
  --metadata "version=0.4.0"
completed=1
trap - EXIT

echo "signed and notarized 0.4.0 $build_kind build $CFW_BUILD_NUMBER: $final_app"
echo "the app has not been installed or launched"
