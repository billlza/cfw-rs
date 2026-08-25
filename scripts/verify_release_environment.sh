#!/bin/bash -p
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
readonly python_bin="$CFW_RELEASE_PYTHON_EXECUTABLE"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_select_release_apple_toolchain
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
go_bin="$toolchain_root/go-$GO_VERSION/bin/go"
node_bin="$toolchain_root/node-$NODE_VERSION/bin/node"
xcodegen_root="$toolchain_root/xcodegen-$XCODEGEN_VERSION"
xcodegen_bin="$xcodegen_root/bin/xcodegen"
tauri_bin="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION/bin/cargo-tauri"

# shellcheck source=scripts/release_workspace_secret_gate.sh
source "$repo_root/scripts/release_workspace_secret_gate.sh"
verify_release_workspace_has_no_key_material "$repo_root"

"$repo_root/scripts/assert_apple_silicon.sh"
cfw_require_supported_python "$python_bin"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_version_contract.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_physical_capture_readiness.py"
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - "$repo_root" <<'PY'
import importlib
import sys

repository = sys.argv[1]
sys.path.insert(0, repository)
adapter = importlib.import_module(
    "scripts.physical_capture.ios_packet_lan_peer_adapter"
)

adapter.validate_static_source_identity(adapter.load_source_identity())
print("iPhone Packet LAN static source identity verified")
PY

macos_major="$(sw_vers -productVersion | cut -d. -f1)"
if (( macos_major < 15 )); then
  echo "error: macOS 15 or newer is required" >&2
  exit 1
fi
if [[ "$(rustc --version | awk '{print $2}')" != "$RUST_VERSION" ]]; then
  echo "error: rustc $RUST_VERSION is required" >&2
  exit 1
fi
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
if [[ "$("$go_bin" version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go $GO_VERSION toolchain is unavailable" >&2
  exit 1
fi
if [[ "$("$node_bin" --version)" != "v$NODE_VERSION" ]]; then
  echo "error: pinned Node.js $NODE_VERSION toolchain is unavailable" >&2
  exit 1
fi
if [[ "$(/usr/bin/xcodebuild -version)" != \
  "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]]; then
  echo "error: Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required" >&2
  exit 1
fi
if [[ "$("$xcodegen_bin" --version)" != "Version: $XCODEGEN_VERSION" ]]; then
  echo "error: pinned XcodeGen $XCODEGEN_VERSION toolchain is unavailable" >&2
  exit 1
fi
if [[ "$(/usr/bin/lipo -archs "$xcodegen_bin")" != "arm64" ]]; then
  echo "error: pinned XcodeGen must be thin arm64" >&2
  exit 1
fi
if [[ "$($CFW_RELEASE_CARGO_AUDIT_EXECUTABLE --version)" != \
  "cargo-audit $CARGO_AUDIT_VERSION" ]]; then
  echo "error: cargo-audit $CARGO_AUDIT_VERSION is required" >&2
  exit 1
fi
if [[ "$($CFW_RELEASE_CARGO_DENY_EXECUTABLE --version)" != \
  "cargo-deny $CARGO_DENY_VERSION" ]]; then
  echo "error: cargo-deny $CARGO_DENY_VERSION is required" >&2
  exit 1
fi
if [[ "$("$tauri_bin" --version)" != "tauri-cli $TAURI_CLI_VERSION" ]]; then
  echo "error: tauri-cli $TAURI_CLI_VERSION is required" >&2
  exit 1
fi

swift_identity="$(
  PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
    "$repo_root" "$MACOS_DEPLOYMENT_TARGET" <<'PY'
import os
import sys
from pathlib import Path

repository = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(repository))

from scripts.publication.release_environment import swift_toolchain_identity

identity = swift_toolchain_identity(repository, dict(os.environ), sys.argv[2])
print(identity.canonical)
PY
)" || {
  echo "error: selected Xcode Swift identity is invalid" >&2
  exit 1
}
if [[ -z "$swift_identity" ]]; then
  echo "error: selected Xcode Swift identity is empty" >&2
  exit 1
fi

"$python_bin" -I -S -B -W error - \
  "$repo_root/native/macos/Dependencies.lock.json" \
  "$repo_root/apps/cfw-tauri-shell/package.json" \
  "$repo_root/apps/cfw-tauri-shell/tauri.conf.json" \
  "$GO_VERSION" \
  "$GOMOBILE_VERSION" \
  "$SING_BOX_VERSION" \
  "$SING_BOX_COMMIT" \
  "$SING_BOX_ANDROID_REFERENCE_COMMIT" \
  "$SING_BOX_APPLE_REFERENCE_COMMIT" \
  "$SING_BOX_SECURITY_PATCH_PATH" \
  "$SING_BOX_SECURITY_PATCH_SHA256" \
  "$SING_BOX_RAW_PACKET_PATCH_PATH" \
  "$SING_BOX_RAW_PACKET_PATCH_SHA256" \
  "$SING_BOX_DNS_FAILOVER_PATCH_PATH" \
  "$SING_BOX_DNS_FAILOVER_PATCH_SHA256" \
  "$SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH" \
  "$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256" \
  "$SING_BOX_PATCHED_DIFF_SHA256" \
  "$SING_BOX_COMBINED_DIFF_SHA256" \
  "$SING_BOX_PATCHED_GO_MOD_SHA256" \
  "$SING_BOX_PATCHED_GO_SUM_SHA256" \
  "$NODE_VERSION" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    native_lock_path,
    package_path,
    tauri_path,
    go_version,
    gomobile_version,
    sing_box_version,
    sing_box_commit,
    android_commit,
    apple_commit,
    security_patch_path,
    security_patch_sha256,
    raw_packet_patch_path,
    raw_packet_patch_sha256,
    dns_failover_patch_path,
    dns_failover_patch_sha256,
    endpoint_conflict_patch_path,
    endpoint_conflict_patch_sha256,
    patched_diff_sha256,
    combined_diff_sha256,
    patched_go_mod_sha256,
    patched_go_sum_sha256,
    node_version,
) = sys.argv[1:]

native_lock = json.loads(Path(native_lock_path).read_text(encoding="utf-8"))
expected_native = {
    "go": go_version,
    "gomobile": gomobile_version,
    "singBox": {
        "tag": sing_box_version,
        "commit": sing_box_commit,
        "androidReferenceCommit": android_commit,
        "securityPatch": {
            "path": security_patch_path,
            "sha256": security_patch_sha256,
            "patchedDiffSha256": patched_diff_sha256,
            "patchedGoModSha256": patched_go_mod_sha256,
            "patchedGoSumSha256": patched_go_sum_sha256,
        },
        "rawPacketPatch": {
            "path": raw_packet_patch_path,
            "sha256": raw_packet_patch_sha256,
        },
        "dnsFailoverPatch": {
            "path": dns_failover_patch_path,
            "sha256": dns_failover_patch_sha256,
        },
        "endpointConflictPatch": {
            "path": endpoint_conflict_patch_path,
            "sha256": endpoint_conflict_patch_sha256,
        },
        "combinedDiffSha256": combined_diff_sha256,
    },
    "singBoxForAppleReference": {"commit": apple_commit},
}
if native_lock != expected_native:
    raise SystemExit("error: native dependency lock differs from release pins")

repository_root = Path(native_lock_path).resolve().parents[2]


def verify_repository_patch(relative_path: str, expected_sha256: str, description: str) -> None:
    path = Path(relative_path)
    if (
        path.is_absolute()
        or not path.parts
        or any(component in ("", ".", "..") for component in path.parts)
    ):
        raise SystemExit(f"error: {description} path is unsafe")
    patch_path = repository_root.joinpath(*path.parts)
    if not patch_path.is_file() or patch_path.is_symlink():
        raise SystemExit(f"error: {description} must be a regular repository file")
    if hashlib.sha256(patch_path.read_bytes()).hexdigest() != expected_sha256:
        raise SystemExit(f"error: {description} digest differs from release pin")


verify_repository_patch(
    security_patch_path,
    security_patch_sha256,
    "sing-box security patch",
)
verify_repository_patch(
    endpoint_conflict_patch_path,
    endpoint_conflict_patch_sha256,
    "sing-box endpoint conflict patch",
)
verify_repository_patch(
    raw_packet_patch_path,
    raw_packet_patch_sha256,
    "sing-box raw packet patch",
)
verify_repository_patch(
    dns_failover_patch_path,
    dns_failover_patch_sha256,
    "sing-box DNS failover patch",
)

package = json.loads(Path(package_path).read_text(encoding="utf-8"))
if package.get("engines", {}).get("node") != ">=24 <25":
    raise SystemExit("error: UI package must require the Node.js 24 LTS line")
if node_version.split(".", 1)[0] != "24":
    raise SystemExit("error: release pin is not a Node.js 24 release")

tauri = json.loads(Path(tauri_path).read_text(encoding="utf-8"))
if tauri.get("app", {}).get("withGlobalTauri") is not False:
    raise SystemExit("error: global Tauri JavaScript injection must be disabled")
if tauri.get("bundle", {}).get("macOS", {}).get("minimumSystemVersion") != "15.0":
    raise SystemExit("error: Tauri deployment target must be macOS 15.0")
if tauri.get("bundle", {}).get("createUpdaterArtifacts") is not False:
    raise SystemExit(
        "error: Tauri automatic updater artifacts must remain disabled; the reviewed release script owns packaging"
    )
if tauri.get("build", {}).get("frontendDist") != "ui/dist":
    raise SystemExit("error: Tauri must consume generated ui/dist output")
PY

# Identity probes and policy validation execute files inside the managed trees.
# Re-verify the complete payloads so self-modification or concurrent drift can
# never be accepted as a valid release environment.
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"

echo "release environment verified"
