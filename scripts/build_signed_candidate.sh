#!/bin/bash -p
# Build, sign, notarize, staple, and verify the installable 0.4.0 candidate.
# This script never installs or launches the app and never changes network,
# proxy, DNS, helper, launchd, or Network Extension runtime state.
set -euo pipefail
umask 022
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
python_bin="$CFW_RELEASE_PYTHON_EXECUTABLE"
readonly python_bin

die() {
  echo "error: $*" >&2
  exit 1
}

[[ -x "$python_bin" ]] || die "pinned Python interpreter is unavailable: $python_bin"

run_isolated_python_script() {
  cfw_run_release_python_script "$repo_root" "$@"
}

source_identity_start="$(run_isolated_python_script \
  "$repo_root/scripts/repository_source_identity.py" --require-clean)" ||
  die "signed candidate builds require a clean release repository"
read -r repository_commit release_source_sha256 <<<"$source_identity_start"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "release source identity is incomplete"

# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/ui_dependency_contract.sh
source "$repo_root/scripts/ui_dependency_contract.sh"
# shellcheck source=scripts/tauri_host_skeleton.sh
source "$repo_root/scripts/tauri_host_skeleton.sh"
cfw_select_release_apple_toolchain
readonly expected_team_id="YKUPL7Z869"
readonly expected_app_id="com.bill.clashformac"
readonly candidate_base="$repo_root/target/candidates/0.4.0"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
readonly tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"

cfw_require_supported_python "$python_bin"

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "release input must not have hard links: $path"
}

candidate_operation=""
signing_transaction_command=""
notarization_recovery_id=""
case "${1:-}" in
  --ga)
    [[ $# -eq 1 ]] || die "--ga accepts no additional arguments"
    candidate_operation="build"
    signing_transaction_command="run"
    ;;
  --resume-signing)
    [[ $# -eq 1 ]] || die "--resume-signing accepts no additional arguments"
    candidate_operation="resume-signing"
    signing_transaction_command="resume"
    ;;
  --recover-notarization-id)
    [[ $# -eq 2 ]] || die "--recover-notarization-id requires one submission UUID"
    [[ -n "$2" ]] ||
      die "--recover-notarization-id requires one non-empty submission UUID"
    candidate_operation="recover-notarization"
    notarization_recovery_id="$2"
    ;;
  *)
    die "usage: scripts/build_signed_candidate.sh --ga|--resume-signing|--recover-notarization-id UUID"
    ;;
esac
readonly candidate_operation
readonly signing_transaction_command
readonly notarization_recovery_id
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "signed candidates require Apple Silicon macOS"
: "${CFW_BUILD_NUMBER:?set the explicit positive integer candidate build number}"
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
  "$repo_root" "$CFW_BUILD_NUMBER" "$candidate_operation" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    BuildIdentityError,
    ReleaseWorkspaceError,
    canonical_build_version,
    verify_ga_workspace_path_preconditions,
)

try:
    canonical_build_version(sys.argv[2], "CFW_BUILD_NUMBER")
    if sys.argv[2] != ACTIVE_RELEASE_IDENTITY.ga_build:
        raise BuildIdentityError(
            "CFW_BUILD_NUMBER must be the single active GA build "
            + ACTIVE_RELEASE_IDENTITY.ga_build
        )
    if sys.argv[3] == "build":
        verify_ga_workspace_path_preconditions(Path(sys.argv[1]))
except (BuildIdentityError, ReleaseWorkspaceError) as error:
    raise SystemExit(f"error: {error}") from None
PY
preflight_root="$candidate_base/ga-preflight/$CFW_BUILD_NUMBER"
frozen_root="$candidate_base/ga/$CFW_BUILD_NUMBER"
native_products="$preflight_root/native-products"
cargo_target="$preflight_root/cargo"
built_app="$cargo_target/release/bundle/macos/Clash for Mac.app"
pre_sign_root="$preflight_root/pre-sign"
pre_sign_app="$pre_sign_root/Clash for Mac.app"
pre_sign_manifest="$pre_sign_root/Clash for Mac.app.manifest.json"
profiles_root="$preflight_root/profiles"
entitlements_root="$preflight_root/entitlements"
signing_output_root="$frozen_root/signing-output"
signed_native_products="$signing_output_root/signed-native-products"
signing_input_root="$signing_output_root/signing-input"
staged_app="$signing_input_root/Clash for Mac.app"
final_app="$frozen_root/signed/Clash for Mac.app"
: "${NOTARY_PROFILE:?set the notarytool Keychain profile name}"
[[ "$NOTARY_PROFILE" == "clashformac-notary" ]] ||
  die "NOTARY_PROFILE must be the frozen clashformac-notary profile"
if [[ "$candidate_operation" == "build" ]]; then
: "${MACOS_SIGN_IDENTITY:?set the exact Developer ID Application identity}"
: "${HOST_PROVISIONING_PROFILE_PATH:?set the absolute host Developer ID profile path}"
: "${PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER:?set the ProxyAgent profile specifier}"
: "${PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER:?set the Packet Tunnel profile specifier}"
for parent in "$repo_root/target" "$repo_root/target/candidates" "$candidate_base"; do
  [[ ! -L "$parent" ]] || die "candidate parent must not be a symlink: $parent"
  mkdir -p "$parent"
  [[ -d "$parent" ]] || die "candidate parent is not a directory: $parent"
done
[[ ! -e "$frozen_root" && ! -L "$frozen_root" ]] ||
  die "GA build $CFW_BUILD_NUMBER is already frozen or consumed"
preflight_parent="$(dirname "$preflight_root")"
[[ ! -L "$preflight_parent" ]] ||
  die "GA preflight parent must not be a symlink: $preflight_parent"
mkdir -p "$preflight_parent"
[[ -d "$preflight_parent" && ! -L "$preflight_parent" ]] ||
  die "GA preflight parent is not a real directory"
mkdir -m 0700 "$preflight_root" ||
  die "GA preflight already exists; inspect it instead of replacing it"
mkdir -m 0700 "$profiles_root" "$entitlements_root" "$pre_sign_root"

candidate_cargo_home=""
completed=0
cleanup() {
  if [[ -n "${candidate_cargo_home:-}" ]]; then
    cfw_remove_release_cargo_runtime "$candidate_cargo_home"
  fi
  if [[ $completed -ne 1 && ! -e "$frozen_root" && ! -L "$frozen_root" && \
    -d "$preflight_root" && ! -L "$preflight_root" && \
    ! -e "$preflight_root/candidate-freeze/intent.json" ]]; then
    /bin/rm -r "$preflight_root"
  fi
}
trap cleanup EXIT

candidate_cargo_home="$(cfw_create_release_cargo_runtime "$repo_root")" ||
  die "cannot create the candidate Cargo runtime"

export CFW_NATIVE_PRODUCTS_OUTPUT="$native_products"
export CFW_NATIVE_DERIVED_DATA="$preflight_root/xcode-derived-data"
export CFW_REPOSITORY_COMMIT="$repository_commit"
export CFW_RELEASE_SOURCE_SHA256="$release_source_sha256"

"$repo_root/scripts/verify_release_environment.sh"
ui_dependencies_tree_observed_start="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
toolchain_binding_start="$(run_isolated_python_script \
  "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" ||
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
run_isolated_python_script "$repo_root/scripts/release_signing_preflight.py" \
  --output "$profiles_root/signing-preflight.json"
release_user_home="$("$python_bin" -I -S -B -W error - <<'PY'
import os
import pwd

print(pwd.getpwuid(os.getuid()).pw_dir)
PY
)"
[[ "$release_user_home" == /* && -d "$release_user_home" && ! -L "$release_user_home" ]] ||
  die "release user home is unavailable"
proxy_profile_input="$release_user_home/Library/Developer/Xcode/UserData/Provisioning Profiles/$PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER.provisionprofile"
packet_profile_input="$release_user_home/Library/Developer/Xcode/UserData/Provisioning Profiles/$PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER.provisionprofile"
host_profile="$profiles_root/host.provisionprofile"
proxy_profile="$profiles_root/proxy-agent.provisionprofile"
packet_profile="$profiles_root/packet-tunnel.provisionprofile"
for profile_input in \
  "$HOST_PROVISIONING_PROFILE_PATH" \
  "$proxy_profile_input" \
  "$packet_profile_input"; do
  require_regular_file "$profile_input"
done
/usr/bin/install -m 0644 "$HOST_PROVISIONING_PROFILE_PATH" "$host_profile"
/usr/bin/install -m 0644 "$proxy_profile_input" "$proxy_profile"
/usr/bin/install -m 0644 "$packet_profile_input" "$packet_profile"
run_isolated_python_script "$repo_root/scripts/release_signing_preflight.py" \
  --verify-manifest "$profiles_root/signing-preflight.json" \
  --host-profile "$host_profile" \
  --proxy-agent-profile "$proxy_profile" \
  --packet-tunnel-profile "$packet_profile"
decoded_host_profile="$profiles_root/host.plist"
decoded_proxy_profile="$profiles_root/proxy-agent.plist"
decoded_packet_profile="$profiles_root/packet-tunnel.plist"
signing_identities="$profiles_root/signing-identities.txt"
/usr/bin/security cms -D -i "$host_profile" -o "$decoded_host_profile" ||
  die "cannot decode the Host provisioning profile"
/usr/bin/security cms -D -i "$proxy_profile" -o "$decoded_proxy_profile" ||
  die "cannot decode the Proxy Agent provisioning profile"
/usr/bin/security cms -D -i "$packet_profile" -o "$decoded_packet_profile" ||
  die "cannot decode the Packet Tunnel provisioning profile"
/usr/bin/security find-identity -v -p codesigning >"$signing_identities" ||
  die "cannot query the codesigning identities"
for decoded_profile in \
  "$decoded_host_profile" \
  "$decoded_proxy_profile" \
  "$decoded_packet_profile"; do
  /usr/bin/plutil -lint "$decoded_profile" >/dev/null ||
    die "decoded provisioning profile is not a valid plist: $decoded_profile"
done

host_release_xcent="$entitlements_root/Host.release.xcent"
proxy_release_xcent="$entitlements_root/ProxyAgent.release.xcent"
packet_release_xcent="$entitlements_root/PacketTunnel.release.xcent"
run_isolated_python_script "$repo_root/scripts/host_release_entitlements.py" \
  --decoded-profile "$decoded_host_profile" \
  --reviewed-entitlements "$repo_root/native/macos/Config/Host.entitlements" \
  --tauri-entitlements "$repo_root/apps/cfw-tauri-shell/macos/entitlements.plist" \
  --signing-identities "$signing_identities" \
  --signing-identity "$MACOS_SIGN_IDENTITY" \
  --expected-team-id "$expected_team_id" \
  --expected-bundle-id "$expected_app_id" \
  --output "$host_release_xcent"
run_isolated_python_script "$repo_root/scripts/release_component_entitlements.py" \
  --role proxy-agent \
  --decoded-profile "$decoded_proxy_profile" \
  --reviewed-entitlements "$repo_root/native/macos/Config/ProxyAgent.entitlements" \
  --signing-identities "$signing_identities" \
  --signing-identity "$MACOS_SIGN_IDENTITY" \
  --expected-profile-uuid "$PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER" \
  --output "$proxy_release_xcent"
run_isolated_python_script "$repo_root/scripts/release_component_entitlements.py" \
  --role packet-tunnel \
  --decoded-profile "$decoded_packet_profile" \
  --reviewed-entitlements "$repo_root/native/macos/Config/PacketTunnel.entitlements" \
  --signing-identities "$signing_identities" \
  --signing-identity "$MACOS_SIGN_IDENTITY" \
  --expected-profile-uuid "$PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER" \
  --output "$packet_release_xcent"
/usr/bin/install -m 0600 \
  "$repo_root/native/macos/Config/GlobalAuthority.entitlements" \
  "$entitlements_root/GlobalAuthority.entitlements"
/usr/bin/install -m 0600 \
  "$repo_root/native/macos/Config/signing-order.json" \
  "$entitlements_root/signing-order.json"

product_input="$preflight_root/product-input.json"
"$python_bin" -I -S -B -W error - \
  "$product_input" \
  "$repository_commit" \
  "$release_source_sha256" \
  "$toolchain_sha256" \
  "$cargo_workspace_sources_tree_sha256" \
  "$go_module_cache_tree_sha256" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$node_toolchain_tree_sha256" \
  "$tauri_toolchain_tree_sha256" \
  "$ui_dependencies_tree_sha256" \
  "$xcodegen_toolchain_tree_sha256" <<'PY'
import json
import os
from pathlib import Path
import sys

(
    output,
    repository_commit,
    release_source_sha256,
    toolchain_sha256,
    cargo_workspace_sources_tree_sha256,
    go_module_cache_tree_sha256,
    go_toolchain_tree_sha256,
    go_tools_tree_sha256,
    node_toolchain_tree_sha256,
    tauri_toolchain_tree_sha256,
    ui_dependencies_tree_sha256,
    xcodegen_toolchain_tree_sha256,
) = sys.argv[1:]
value = {
    "document": "cfm-ga-product-input-v1",
    "product": {"build_number": "40035", "version": "0.4.0"},
    "schema_version": 1,
    "source": {
        "release_source_sha256": release_source_sha256,
        "repository_commit": repository_commit,
    },
    "toolchain": {
        "cargoWorkspaceSourcesTreeSha256": cargo_workspace_sources_tree_sha256,
        "goModuleCacheTreeSha256": go_module_cache_tree_sha256,
        "goToolchainTreeSha256": go_toolchain_tree_sha256,
        "goToolsTreeSha256": go_tools_tree_sha256,
        "nodeToolchainTreeSha256": node_toolchain_tree_sha256,
        "tauriToolchainTreeSha256": tauri_toolchain_tree_sha256,
        "toolchainSha256": toolchain_sha256,
        "uiDependenciesTreeSha256": ui_dependencies_tree_sha256,
        "xcodegenToolchainTreeSha256": xcodegen_toolchain_tree_sha256,
    },
}
payload = (
    json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
path = Path(output)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short product-input write")
        offset += written
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
run_isolated_python_script "$repo_root/scripts/release_signing_plan.py" create

"$repo_root/scripts/build_native_products.sh" --pre-sign
CARGO_HOME="$candidate_cargo_home" CARGO_NET_OFFLINE=true \
  "$repo_root/scripts/build_legacy_tombstone.sh" --pre-sign
for product in \
  CFWGlobalAuthority \
  CFWNativeBridge.framework \
  CFWProxyAgent.app \
  com.bill.clashformac.packet-tunnel.systemextension \
  CFWLegacyTombstone; do
  run_isolated_python_script "$repo_root/scripts/verify_artifact_manifest.py" \
    "$native_products/$product" \
    "$native_products/$product.manifest.json" \
    --metadata "buildNumber=$CFW_BUILD_NUMBER" \
    --metadata "signingMode=pre-sign"
done

"$repo_root/scripts/build_ui_with_pinned_node.sh"
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
tauri_override="$("$python_bin" -I -S -B -W error - \
  "$CFW_BUILD_NUMBER" "$native_products" <<'PY'
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
CARGO_HOME="$candidate_cargo_home" \
  CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$cargo_target" \
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
  cfw_build_tauri_host_skeleton \
  "$repo_root/apps/cfw-tauri-shell" \
  "$tauri_bin" \
  "$tauri_override"
cfw_verify_release_cargo_runtime "$repo_root" "$candidate_cargo_home"
cfw_remove_release_cargo_runtime "$candidate_cargo_home"
candidate_cargo_home=""
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$built_app" \
  "$native_products" \
  --context unsigned-host
/usr/bin/ditto --noqtn "$built_app" "$pre_sign_app"
"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$pre_sign_app" \
  "$native_products" \
  --context unsigned-host
run_isolated_python_script "$repo_root/scripts/hash_artifact.py" \
  "$pre_sign_app" \
  --output "$pre_sign_manifest" \
  --metadata "artifactKind=pre-sign-application-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
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
  --metadata "version=0.4.0"
run_isolated_python_script "$repo_root/scripts/verify_artifact_manifest.py" \
  "$pre_sign_app" \
  "$pre_sign_manifest" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "releaseSourceSha256=$release_source_sha256" \
  --metadata "repositoryCommit=$repository_commit"
/bin/rm -r "$cargo_target"

cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
ui_dependencies_tree_observed_end="$(
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root"
)"
[[ "$ui_dependencies_tree_observed_end" == "$ui_dependencies_tree_observed_start" ]] ||
  die "UI dependency tree changed while the GA candidate was building"
toolchain_binding_end="$(run_isolated_python_script \
  "$repo_root/scripts/candidate_artifact_binding.py" --repository "$repo_root")" ||
  die "cannot re-observe the canonical candidate toolchain binding"
[[ "$toolchain_binding_end" == "$toolchain_binding_start" ]] ||
  die "release toolchain changed while the GA candidate was building"
source_identity_after_build="$(run_isolated_python_script \
  "$repo_root/scripts/repository_source_identity.py" --require-clean)" ||
  die "release repository changed while the GA candidate was building"
[[ "$source_identity_after_build" == "$source_identity_start" ]] ||
  die "release source identity changed while the GA candidate was building"
run_isolated_python_script "$repo_root/scripts/release_signing_plan.py" verify-preflight
run_isolated_python_script "$repo_root/scripts/updater_key_possession_proof.py" create
run_isolated_python_script "$repo_root/scripts/candidate_freeze.py" freeze

else
  run_isolated_python_script "$repo_root/scripts/candidate_freeze.py" verify
  run_isolated_python_script "$repo_root/scripts/release_signing_plan.py" verify-frozen
  run_isolated_python_script "$repo_root/scripts/updater_key_possession_proof.py" verify-frozen
  frozen_product_input="$frozen_root/product-input.json"
  frozen_binding="$($python_bin -I -S -B -W error - "$frozen_product_input" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
raw = path.read_bytes()
value = json.loads(raw.decode("ascii"))
canonical = (
    json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    + "\n"
).encode("ascii")
if raw != canonical:
    raise SystemExit("error: frozen product input is not canonical JSON")
if set(value) != {"document", "product", "schema_version", "source", "toolchain"}:
    raise SystemExit("error: frozen product input field set is invalid")
if value["document"] != "cfm-ga-product-input-v1" or value["schema_version"] != 1:
    raise SystemExit("error: frozen product input identity is invalid")
if value["product"] != {"build_number": "40035", "version": "0.4.0"}:
    raise SystemExit("error: frozen product identity is invalid")
source = value["source"]
toolchain = value["toolchain"]
expected_toolchain = {
    "cargoWorkspaceSourcesTreeSha256",
    "goModuleCacheTreeSha256",
    "goToolchainTreeSha256",
    "goToolsTreeSha256",
    "nodeToolchainTreeSha256",
    "tauriToolchainTreeSha256",
    "toolchainSha256",
    "uiDependenciesTreeSha256",
    "xcodegenToolchainTreeSha256",
}
if set(source) != {"release_source_sha256", "repository_commit"}:
    raise SystemExit("error: frozen product source field set is invalid")
if set(toolchain) != expected_toolchain:
    raise SystemExit("error: frozen product toolchain field set is invalid")
ordered = (
    source["repository_commit"],
    source["release_source_sha256"],
    toolchain["toolchainSha256"],
    toolchain["cargoWorkspaceSourcesTreeSha256"],
    toolchain["goModuleCacheTreeSha256"],
    toolchain["goToolchainTreeSha256"],
    toolchain["goToolsTreeSha256"],
    toolchain["nodeToolchainTreeSha256"],
    toolchain["tauriToolchainTreeSha256"],
    toolchain["uiDependenciesTreeSha256"],
    toolchain["xcodegenToolchainTreeSha256"],
)
if any(not isinstance(item, str) or "\t" in item or "\n" in item for item in ordered):
    raise SystemExit("error: frozen product input contains malformed values")
print("\t".join(ordered))
PY
)" || die "cannot reopen the frozen GA product input"
  IFS=$'\t' read -r \
    repository_commit \
    release_source_sha256 \
    toolchain_sha256 \
    cargo_workspace_sources_tree_sha256 \
    go_module_cache_tree_sha256 \
    go_toolchain_tree_sha256 \
    go_tools_tree_sha256 \
    node_toolchain_tree_sha256 \
    tauri_toolchain_tree_sha256 \
    ui_dependencies_tree_sha256 \
    xcodegen_toolchain_tree_sha256 \
    unexpected_frozen_binding <<<"$frozen_binding"
  [[ -n "$xcodegen_toolchain_tree_sha256" && -z "${unexpected_frozen_binding:-}" ]] ||
    die "frozen GA product input is incomplete"
  [[ "$repository_commit $release_source_sha256" == "$source_identity_start" ]] ||
    die "current release source differs from the frozen GA product input"
fi

run_candidate_transactions() {
  local -a notarization_mode

  run_isolated_python_script "$repo_root/scripts/candidate_freeze.py" verify
  run_isolated_python_script "$repo_root/scripts/release_signing_plan.py" verify-frozen
  run_isolated_python_script "$repo_root/scripts/updater_key_possession_proof.py" verify-frozen
  if [[ "$candidate_operation" != "recover-notarization" ]]; then
    run_isolated_python_script "$repo_root/scripts/signing_attempt_transaction.py" \
      "$signing_transaction_command"
    run_isolated_python_script \
      "$repo_root/scripts/verify_signing_transformation.py" verify
  fi

  notarization_mode=(--staged-app "$staged_app")
  if [[ "$candidate_operation" == "recover-notarization" ]]; then
    notarization_mode=(
      --recover-submission-id "$notarization_recovery_id"
      --artifact-repository "$repo_root"
      --toolchain-root "$toolchain_root"
    )
  fi
  run_isolated_python_script "$repo_root/scripts/notarization_transaction.py" \
    --build-kind ga \
    --build-number "$CFW_BUILD_NUMBER" \
    "${notarization_mode[@]}" \
    --native-products "$signed_native_products" \
    --notary-profile "$NOTARY_PROFILE" \
    --repository-commit "$repository_commit" \
    --release-source-sha256 "$release_source_sha256" \
    --deployment-target "$MACOS_DEPLOYMENT_TARGET" \
    --cargo-workspace-sources-tree-sha256 "$cargo_workspace_sources_tree_sha256" \
    --go-module-cache-tree-sha256 "$go_module_cache_tree_sha256" \
    --go-toolchain-tree-sha256 "$go_toolchain_tree_sha256" \
    --go-tools-tree-sha256 "$go_tools_tree_sha256" \
    --node-toolchain-tree-sha256 "$node_toolchain_tree_sha256" \
    --tauri-toolchain-tree-sha256 "$tauri_toolchain_tree_sha256" \
    --toolchain-sha256 "$toolchain_sha256" \
    --ui-dependencies-tree-sha256 "$ui_dependencies_tree_sha256" \
    --xcodegen-toolchain-tree-sha256 "$xcodegen_toolchain_tree_sha256"
}

run_candidate_transactions
completed=1
trap - EXIT

final_app_relative="${final_app#"$repo_root/"}"
echo "signed and notarized 0.4.0 GA build $CFW_BUILD_NUMBER: $final_app_relative"
echo "the app has not been installed or launched"
