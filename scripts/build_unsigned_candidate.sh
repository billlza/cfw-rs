#!/usr/bin/env bash
# Produce a structurally complete, non-runnable release skeleton for CI and
# local packaging validation. This script never launches the app or mutates
# proxy, route, DNS, helper, launchd, or Network Extension state.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
node_bin="$toolchain_root/node-$NODE_VERSION/bin/node"
npm_bin="$toolchain_root/node-$NODE_VERSION/bin/npm"
candidate_root="$repo_root/target/candidates/0.4.0/unsigned"
cargo_target="$candidate_root/cargo"
native_products="$candidate_root/native-products"
app_path="$cargo_target/release/bundle/macos/Clash for Mac.app"
readonly build_version="40000"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "usage: scripts/build_unsigned_candidate.sh"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "candidate builds require Apple Silicon macOS"
[[ "$(xcodebuild -version)" == "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]] ||
  die "Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required"
[[ "$(rustc --version | awk '{print $2}')" == "$RUST_VERSION" ]] ||
  die "rustc $RUST_VERSION is required"
[[ "$(cargo tauri --version)" == "tauri-cli $TAURI_CLI_VERSION" ]] ||
  die "tauri-cli $TAURI_CLI_VERSION is required"
[[ "$("$node_bin" --version)" == "v$NODE_VERSION" ]] ||
  die "pinned Node.js $NODE_VERSION is unavailable"
[[ -x "$npm_bin" ]] || die "pinned npm is unavailable"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_version_contract.py"
[[ -d "$repo_root/apps/cfw-tauri-shell/node_modules" ]] ||
  die "UI dependencies are not prepared; run pinned npm ci explicitly"
"$npm_bin" --prefix "$repo_root/apps/cfw-tauri-shell" ls --all --offline >/dev/null
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

"$repo_root/scripts/verify_xcode_project.sh"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json" \
  --metadata "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256" \
  --metadata "sourceCommit=$SING_BOX_COMMIT"

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

"$repo_root/scripts/verify_candidate_bundle.sh" "$app_path" "$native_products"
echo "unsigned 0.4.0 candidate skeleton: $app_path"
echo "build version: $build_version"
