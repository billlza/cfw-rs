#!/bin/bash -p
# Build the real 0.5 Host with in-place native components. This prepares one
# immutable pre-sign input; it does not sign, install, launch or change networks.
set -euo pipefail
umask 022
unset CDPATH
repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$repo_root/scripts/dependency_pins.env"
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
source "$repo_root/scripts/release_toolchain_contract.sh"
source "$repo_root/scripts/libbox_source_contract.sh"
source "$repo_root/scripts/tauri_host_skeleton.sh"
cfw_select_release_apple_toolchain

die() { echo "error: $*" >&2; exit 1; }
run_python() { cfw_run_release_python_script "$repo_root" "$@"; }
[[ $# -eq 0 ]] || die "usage: scripts/prepare_preview_candidate.sh"
: "${CFW_BUILD_NUMBER:?set the explicit preview build number}"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
readonly tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"
run_python "$repo_root/scripts/verify_version_contract.py" --preview
run_python "$repo_root/scripts/verify_pinned_source_contract.py"
source_start="$(run_python "$repo_root/scripts/repository_source_identity.py" --require-clean)"
read -r repository_commit release_source_sha256 <<<"$source_start"
[[ "$repository_commit" =~ ^[0-9a-f]{40}$ && "$release_source_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die "preview source identity is incomplete"

preflight_root="$("$CFW_RELEASE_PYTHON_EXECUTABLE" -I -S -B -W error - "$repo_root" "$CFW_BUILD_NUMBER" <<'PY'
from pathlib import Path
import os
import stat
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
from release_build_identity import SIGNED_PREVIEW_IDENTITY, preview_preflight_root, preview_root
repository = Path(sys.argv[1])
if sys.argv[2] != SIGNED_PREVIEW_IDENTITY.build_number:
    raise SystemExit("preview build must equal the reviewed 50008 identity")
root = preview_preflight_root(repository)
if os.path.lexists(root) or os.path.lexists(preview_root(repository)):
    raise SystemExit("preview identity already has retained work; do not replace or reuse it")
for parent in reversed(root.parents):
    if not parent.exists():
        parent.mkdir(mode=0o755)
    value = parent.lstat()
    if not stat.S_ISDIR(value.st_mode) or parent.resolve(strict=True) != parent:
        raise SystemExit(f"preview parent is not a real canonical directory: {parent}")
root.mkdir(mode=0o700)
print(root)
PY
)"
readonly preflight_root
readonly native_products="$preflight_root/native-products"
readonly cargo_target="$preflight_root/cargo"
readonly built_app="$cargo_target/release/bundle/macos/Clash for Mac.app"
readonly pre_sign_root="$preflight_root/pre-sign"
readonly pre_sign_app="$pre_sign_root/Clash for Mac.app"
mkdir -m 0700 "$pre_sign_root" "$preflight_root/profiles" "$preflight_root/entitlements"
candidate_cargo_home=""
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$candidate_cargo_home" ]]; then
    if ! cfw_remove_release_cargo_runtime "$candidate_cargo_home"; then
      echo "error: preview Cargo runtime cleanup failed" >&2
      status=1
    fi
  fi
  if [[ $status -ne 0 ]]; then
    echo "preview preparation failed; retained inputs and logs: $preflight_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
export CFW_NATIVE_PRODUCTS_OUTPUT="$native_products"
export CFW_NATIVE_DERIVED_DATA="$preflight_root/xcode-derived-data"
export CFW_REPOSITORY_COMMIT="$repository_commit"
export CFW_RELEASE_SOURCE_SHA256="$release_source_sha256"
binding_start="$(run_python "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")"
read -r toolchain_sha256 cargo_sources_sha256 go_toolchain_sha256 go_module_cache_sha256 \
  go_tools_sha256 node_sha256 tauri_sha256 ui_sha256 xcodegen_sha256 extra <<<"$binding_start"
[[ -n "$xcodegen_sha256" && -z "${extra:-}" ]] || die "preview toolchain binding is incomplete"
export CFW_GO_TOOLCHAIN_TREE_SHA256="$go_toolchain_sha256"
export CFW_GO_TOOLS_TREE_SHA256="$go_tools_sha256"
export CFW_GO_MODULE_CACHE_TREE_SHA256="$go_module_cache_sha256"
libbox_verify_xcframework_artifact "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  "$go_toolchain_sha256" "$go_tools_sha256" "$go_module_cache_sha256" >/dev/null
candidate_cargo_home="$(cfw_create_release_cargo_runtime "$repo_root")"
"$repo_root/scripts/build_native_products.sh" --pre-sign >"$preflight_root/native-build.log" 2>&1
CARGO_HOME="$candidate_cargo_home" CARGO_NET_OFFLINE=true \
  "$repo_root/scripts/build_legacy_tombstone.sh" --pre-sign >"$preflight_root/tombstone-build.log" 2>&1
"$repo_root/scripts/build_native_ui.sh" >"$preflight_root/native-ui-build.log" 2>&1
"$repo_root/scripts/build_ui_with_pinned_node.sh" >"$preflight_root/web-ui-build.log" 2>&1
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
override="$("$CFW_RELEASE_PYTHON_EXECUTABLE" -I -S -B -W error - "$native_products" <<'PY'
import json
import sys
native = sys.argv[1]
print(json.dumps({"bundle": {"macOS": {"bundleVersion": "50008", "files": {
    "Frameworks/CFWNativeBridge.framework": f"{native}/CFWNativeBridge.framework",
    "Frameworks/libCFMNativeDashboard.dylib": f"{native}/libCFMNativeDashboard.dylib",
    "Resources/CFMNativeDashboard_CFMNativeDashboard.bundle": f"{native}/CFMNativeDashboard_CFMNativeDashboard.bundle",
    "Library/HelperTools/CFWGlobalAuthority": f"{native}/CFWGlobalAuthority",
    "Library/HelperTools/cfw-helper-tombstone": f"{native}/CFWLegacyTombstone/cfw-helper-tombstone",
    "Library/LoginItems/CFWProxyAgent.app": f"{native}/CFWProxyAgent.app",
    "Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension": f"{native}/com.bill.clashformac.packet-tunnel.systemextension",
}}}}, separators=(",", ":")))
PY
)"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root" >/dev/null
CARGO_HOME="$candidate_cargo_home" CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$cargo_target" \
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
  cfw_build_tauri_host_skeleton "$repo_root/apps/cfw-tauri-shell" "$tauri_bin" "$override" \
  --native-ui-preview >"$preflight_root/host-build.log" 2>&1
"$repo_root/scripts/verify_candidate_bundle.sh" "$built_app" "$native_products" --context preview-pre-sign \
  >"$preflight_root/built-bundle-verification.log" 2>&1
/usr/bin/ditto --noqtn "$built_app" "$pre_sign_app"
"$repo_root/scripts/verify_candidate_bundle.sh" "$pre_sign_app" "$native_products" --context preview-pre-sign \
  >"$preflight_root/pre-sign-verification.log" 2>&1
[[ "$(run_python "$repo_root/scripts/repository_source_identity.py" --require-clean)" == "$source_start" ]] ||
  die "preview source changed during preparation"
[[ "$(run_python "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" == "$binding_start" ]] ||
  die "preview toolchain changed during preparation"
run_python "$repo_root/scripts/hash_artifact.py" "$pre_sign_app" --algorithm sha256-tree-v2 \
  --output "$pre_sign_app.manifest.json" \
  --metadata "version=0.5.0" --metadata "buildNumber=$CFW_BUILD_NUMBER" --metadata "signingMode=pre-sign" \
  --metadata "repositoryCommit=$repository_commit" --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "toolchainSha256=$toolchain_sha256"
echo "Real 0.5.0/50008 Host prepared and byte-verified: $pre_sign_app"
echo "This is an unsigned pre-sign input. Signing, notarization and installed acceptance remain required."
