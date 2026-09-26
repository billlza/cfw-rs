#!/bin/bash -p
# Produce a structurally complete, non-runnable release skeleton for CI and
# local packaging validation. This script never launches the app or mutates
# proxy, route, DNS, helper, launchd, or Network Extension state.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
candidate_binding_arguments=(--repository "$repo_root")
preview_validation=0
validation_python=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --preview-validation)
      [[ $preview_validation -eq 0 ]] || exit 2
      preview_validation=1
      shift
      ;;
    --validation-python-executable)
      [[ $# -ge 2 && "$2" == /* && -z "$validation_python" ]] || exit 2
      validation_python="$2"
      shift 2
      ;;
    *) echo "error: usage: scripts/build_unsigned_candidate.sh [--preview-validation] [--validation-python-executable ABSOLUTE_PATH]" >&2; exit 2 ;;
  esac
done
if [[ $preview_validation -eq 1 && -z "$validation_python" ]]; then
  echo "error: unsigned preview requires the explicit validation Python runtime" >&2
  exit 2
fi
if [[ -n "$validation_python" ]]; then
  export CFW_UNSIGNED_VALIDATION_PYTHON="$validation_python"
  cfw_seal_release_tool_environment unsigned-validation
  candidate_binding_arguments+=(--unsigned-validation-toolchain)
else
  cfw_seal_release_tool_environment production
fi
readonly python_bin="$CFW_RELEASE_PYTHON_EXECUTABLE"
readonly -a candidate_binding_arguments
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/ui_dependency_contract.sh
source "$repo_root/scripts/ui_dependency_contract.sh"
# shellcheck source=scripts/tauri_host_skeleton.sh
source "$repo_root/scripts/tauri_host_skeleton.sh"
cfw_select_release_apple_toolchain
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
node_root="$toolchain_root/node-$NODE_VERSION"
node_bin="$node_root/bin/node"
tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"
product_version="0.4.0"
build_version="40000"
candidate_relative="target/candidates/0.4.0/unsigned"
bundle_context="unsigned-host"
app_artifact_kind="unsigned-application-validation-v1"
# Keep real required arguments in every command/metadata array: Bash 3.2
# treats an empty array expansion as unbound under the required nounset mode.
version_contract_command=(
  cfw_run_release_python_script "$repo_root" "$repo_root/scripts/verify_version_contract.py"
)
if [[ $preview_validation -eq 1 ]]; then
  product_version="0.5.0"
  build_version="50000"
  candidate_relative="target/candidates/0.5.0/unsigned/50000"
  bundle_context="unsigned-preview-host"
  app_artifact_kind="unsigned-preview-application-validation-v1"
  version_contract_command+=(--preview)
fi
readonly product_version build_version candidate_relative bundle_context app_artifact_kind
validation_app_metadata=(--metadata "version=$product_version")
if [[ $preview_validation -eq 1 ]]; then
  validation_app_metadata+=(--metadata "signingMode=unsigned-validation")
fi
candidate_root="$repo_root/$candidate_relative"
cargo_target="$candidate_root/cargo"
native_products="$candidate_root/native-products"
app_path="$cargo_target/release/bundle/macos/Clash for Mac.app"
app_manifest="$candidate_root/Clash for Mac.app.manifest.json"

die() {
  echo "error: $*" >&2
  exit 1
}

cfw_require_supported_python "$python_bin"

[[ $# -eq 0 ]] || die "usage: scripts/build_unsigned_candidate.sh"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "candidate builds require Apple Silicon macOS"
[[ "$(/usr/bin/xcodebuild -version)" == \
  "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]] ||
  die "Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required"
[[ "$(rustc --version | awk '{print $2}')" == "$RUST_VERSION" ]] ||
  die "rustc $RUST_VERSION is required"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
[[ "$("$tauri_bin" --version)" == "tauri-cli $TAURI_CLI_VERSION" ]] ||
  die "tauri-cli $TAURI_CLI_VERSION is required"
[[ "$("$node_bin" --version)" == "v$NODE_VERSION" ]] ||
  die "pinned Node.js $NODE_VERSION is unavailable"
"${version_contract_command[@]}"
[[ -d "$repo_root/apps/cfw-tauri-shell/node_modules" ]] ||
  die "UI dependencies are not prepared; run pinned npm ci explicitly"
/bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh" \
  --verify-dependencies >/dev/null
source_identity_start="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot capture the release source identity"
read -r repository_commit release_source_sha256 <<<"$source_identity_start"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "release source identity is incomplete"
ui_dependencies_tree_observed_start="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
toolchain_binding_start="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/candidate_artifact_binding.py" \
  "${candidate_binding_arguments[@]}")" ||
  die "cannot derive the canonical candidate toolchain binding"
read -r \
  toolchain_sha256 \
  cargo_workspace_sources_tree_sha256 \
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
candidate_parents=(
  "$repo_root/target"
  "$repo_root/target/candidates"
  "$repo_root/target/candidates/$product_version"
)
if [[ $preview_validation -eq 1 ]]; then
  candidate_parents+=("$repo_root/target/candidates/$product_version/unsigned")
fi
for parent in "${candidate_parents[@]}"; do
  [[ ! -L "$parent" ]] || die "candidate parent must not be a symlink: $parent"
  mkdir -p "$parent"
  [[ -d "$parent" && "$(cd "$parent" && pwd -P)" == "$parent" ]] ||
    die "candidate parent is not a canonical directory: $parent"
done
[[ ! -e "$candidate_root" && ! -L "$candidate_root" ]] ||
  die "refusing to replace an existing candidate root: $candidate_root"
candidate_cargo_home="$(cfw_create_release_cargo_runtime "$repo_root")" ||
  die "cannot create the candidate Cargo runtime"
cleanup_candidate_cargo_runtime() {
  if [[ -n "${candidate_cargo_home:-}" ]]; then
    cfw_remove_release_cargo_runtime "$candidate_cargo_home"
  fi
}
trap cleanup_candidate_cargo_runtime EXIT
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
CARGO_HOME="$candidate_cargo_home" CARGO_NET_OFFLINE=true \
  "$repo_root/scripts/build_legacy_tombstone.sh" --unsigned
if [[ $preview_validation -eq 1 ]]; then
  "$repo_root/scripts/build_native_ui.sh" --unsigned-preview-validation
fi
"$repo_root/scripts/build_ui_with_pinned_node.sh"

unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
tauri_override="$("$python_bin" -I -S -B -W error - "$build_version" "$native_products" "$preview_validation" <<'PY'
import json
import sys

build, native, preview = sys.argv[1:]
override = {
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
}
if preview == "1":
    override["bundle"]["macOS"]["files"].update({
        "Frameworks/libCFMNativeDashboard.dylib": f"{native}/libCFMNativeDashboard.dylib",
        "Resources/CFMNativeDashboard_CFMNativeDashboard.bundle": f"{native}/CFMNativeDashboard_CFMNativeDashboard.bundle",
    })
print(json.dumps(override, separators=(",", ":")))
PY
)"
tauri_host_command=(
  cfw_build_tauri_host_skeleton "$repo_root/apps/cfw-tauri-shell" "$tauri_bin" "$tauri_override"
)
if [[ $preview_validation -eq 1 ]]; then
  tauri_host_command+=(--native-ui-unsigned-preview)
fi
CARGO_HOME="$candidate_cargo_home" \
  CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$cargo_target" \
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
  "${tauri_host_command[@]}"
cfw_verify_release_cargo_runtime "$repo_root" "$candidate_cargo_home"
cfw_remove_release_cargo_runtime "$candidate_cargo_home"
candidate_cargo_home=""
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$app_path" \
  "$native_products" \
  --context "$bundle_context"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
ui_dependencies_tree_observed_end="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
[[ "$ui_dependencies_tree_observed_end" == "$ui_dependencies_tree_observed_start" ]] ||
  die "UI dependency tree changed while the unsigned candidate was building"
toolchain_binding_end="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/candidate_artifact_binding.py" \
  "${candidate_binding_arguments[@]}")" ||
  die "cannot re-observe the canonical candidate toolchain binding"
[[ "$toolchain_binding_end" == "$toolchain_binding_start" ]] ||
  die "release toolchain changed while the unsigned candidate was building"

source_identity_end="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot re-observe the release source identity"
[[ "$source_identity_end" == "$source_identity_start" ]] ||
  die "release source changed while the unsigned candidate was building"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_artifact.py" \
  "$app_path" \
  --output "$app_manifest" \
  --metadata "artifactKind=$app_artifact_kind" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$build_version" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "cargoWorkspaceSourcesTreeSha256=$cargo_workspace_sources_tree_sha256" \
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
  "${validation_app_metadata[@]}"
app_manifest_sha256="$(
  /usr/bin/shasum -a 256 "$app_manifest" | /usr/bin/awk '{print $1}'
)"
readonly app_manifest_sha256
[[ "$app_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die "unsigned application manifest identity is malformed"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/verify_artifact_manifest.py" \
  "$app_path" \
  "$app_manifest" \
  --metadata "artifactKind=$app_artifact_kind" \
  "${validation_app_metadata[@]}" \
  --metadata "buildNumber=$build_version" \
  --metadata "cargoWorkspaceSourcesTreeSha256=$cargo_workspace_sources_tree_sha256" \
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
  --context "$bundle_context"
[[ "$(/usr/bin/shasum -a 256 "$app_manifest" | /usr/bin/awk '{print $1}')" == "$app_manifest_sha256" ]] ||
  die "unsigned application manifest changed during final verification"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/verify_artifact_manifest.py" \
  "$app_path" \
  "$app_manifest" \
  --metadata "artifactKind=$app_artifact_kind" \
  "${validation_app_metadata[@]}" \
  --metadata "buildNumber=$build_version" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"

echo "unsigned $product_version candidate skeleton: $app_path"
echo "build version: $build_version"
