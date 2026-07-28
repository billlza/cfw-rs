#!/usr/bin/env bash
# Produce a structurally complete, non-runnable release skeleton for CI and
# local packaging validation. This script never launches the app or mutates
# proxy, route, DNS, helper, launchd, or Network Extension state.
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
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
node_bin="$toolchain_root/node-$NODE_VERSION/bin/node"
npm_bin="$toolchain_root/node-$NODE_VERSION/bin/npm"
tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"
candidate_root="$repo_root/target/candidates/0.4.0/unsigned"
cargo_target="$candidate_root/cargo"
native_products="$candidate_root/native-products"
app_path="$cargo_target/release/bundle/macos/Clash for Mac.app"
app_manifest="$candidate_root/Clash for Mac.app.manifest.json"
readonly build_version="40000"

die() {
  echo "error: $*" >&2
  exit 1
}

cfw_require_supported_python

[[ $# -eq 0 ]] || die "usage: scripts/build_unsigned_candidate.sh"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "candidate builds require Apple Silicon macOS"
[[ "$(xcodebuild -version)" == "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]] ||
  die "Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required"
[[ "$(rustc --version | awk '{print $2}')" == "$RUST_VERSION" ]] ||
  die "rustc $RUST_VERSION is required"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
[[ "$("$tauri_bin" --version)" == "tauri-cli $TAURI_CLI_VERSION" ]] ||
  die "tauri-cli $TAURI_CLI_VERSION is required"
[[ "$("$node_bin" --version)" == "v$NODE_VERSION" ]] ||
  die "pinned Node.js $NODE_VERSION is unavailable"
[[ -x "$npm_bin" ]] || die "pinned npm is unavailable"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_version_contract.py"
[[ -d "$repo_root/apps/cfw-tauri-shell/node_modules" ]] ||
  die "UI dependencies are not prepared; run pinned npm ci explicitly"
"$npm_bin" --prefix "$repo_root/apps/cfw-tauri-shell" ls --all --offline >/dev/null
source_identity_start="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot capture the release source identity"
read -r repository_commit release_source_sha256 <<<"$source_identity_start"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "release source identity is incomplete"
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
for parent in \
  "$repo_root/target" \
  "$repo_root/target/candidates" \
  "$repo_root/target/candidates/0.4.0"; do
  [[ ! -L "$parent" ]] || die "candidate parent must not be a symlink: $parent"
  mkdir -p "$parent"
  [[ -d "$parent" ]] || die "candidate parent is not a directory: $parent"
done
[[ ! -e "$candidate_root" && ! -L "$candidate_root" ]] ||
  die "refusing to replace an existing candidate root: $candidate_root"
export CFW_BUILD_NUMBER="$build_version"
export CFW_NATIVE_PRODUCTS_OUTPUT="$native_products"
export CFW_NATIVE_DERIVED_DATA="$candidate_root/xcode-derived-data"
export CFW_REPOSITORY_COMMIT="$repository_commit"
export CFW_RELEASE_SOURCE_SHA256="$release_source_sha256"
export CFW_GO_TOOLCHAIN_TREE_SHA256="$go_toolchain_tree_sha256"
export CFW_GO_TOOLS_TREE_SHA256="$go_tools_tree_sha256"
export CFW_GO_MODULE_CACHE_TREE_SHA256="$go_module_cache_tree_sha256"

"$repo_root/scripts/verify_xcode_project.sh"
libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256" >/dev/null

"$repo_root/scripts/build_native_products.sh" --unsigned
"$repo_root/scripts/build_legacy_tombstone.sh" --unsigned
"$repo_root/scripts/build_ui_with_pinned_node.sh"

unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$cargo_target"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
tauri_override="$(python3 - "$build_version" "$native_products" <<'PY'
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
cfw_build_tauri_host_skeleton \
  "$repo_root/apps/cfw-tauri-shell" \
  "$tauri_bin" \
  "$tauri_override"
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$app_path" \
  "$native_products" \
  --require-unsigned-host
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
ui_dependencies_tree_observed_end="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
[[ "$ui_dependencies_tree_observed_end" == "$ui_dependencies_tree_observed_start" ]] ||
  die "UI dependency tree changed while the unsigned candidate was building"
toolchain_binding_end="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" ||
  die "cannot re-observe the canonical candidate toolchain binding"
[[ "$toolchain_binding_end" == "$toolchain_binding_start" ]] ||
  die "release toolchain changed while the unsigned candidate was building"

source_identity_end="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot re-observe the release source identity"
[[ "$source_identity_end" == "$source_identity_start" ]] ||
  die "release source changed while the unsigned candidate was building"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$app_path" \
  --output "$app_manifest" \
  --metadata "artifactKind=unsigned-application-validation-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$build_version" \
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
app_manifest_sha256="$(
  /usr/bin/shasum -a 256 "$app_manifest" | /usr/bin/awk '{print $1}'
)"
readonly app_manifest_sha256
[[ "$app_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die "unsigned application manifest identity is malformed"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$app_path" \
  "$app_manifest" \
  --metadata "buildNumber=$build_version" \
  --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
  --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
  --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
  --metadata "nodeToolchainTreeSha256=$node_toolchain_tree_sha256" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit" \
  --metadata "tauriToolchainTreeSha256=$tauri_toolchain_tree_sha256" \
  --metadata "toolchainSha256=$toolchain_sha256" \
  --metadata "uiDependenciesTreeSha256=$ui_dependencies_tree_sha256" \
  --metadata "xcodegenToolchainTreeSha256=$xcodegen_toolchain_tree_sha256"

"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$app_path" \
  "$native_products" \
  --require-unsigned-host
[[ "$(/usr/bin/shasum -a 256 "$app_manifest" | /usr/bin/awk '{print $1}')" == "$app_manifest_sha256" ]] ||
  die "unsigned application manifest changed during final verification"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$app_path" \
  "$app_manifest" \
  --metadata "buildNumber=$build_version" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"

echo "unsigned 0.4.0 candidate skeleton: $app_path"
echo "build version: $build_version"
