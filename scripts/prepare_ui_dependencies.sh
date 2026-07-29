#!/usr/bin/env bash
# Materialize the exact lockfile-defined UI dependency tree with the pinned
# Node distribution, then seal every byte, mode, and internal symlink before it
# can enter a release build. This is an explicit networked preparation step.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/ui_dependency_contract.sh
source "$repo_root/scripts/ui_dependency_contract.sh"

toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
node_root="$toolchain_root/node-$NODE_VERSION"
node_bin="$node_root/bin/node"
npm_bin="$node_root/bin/npm"
shell_root="$repo_root/apps/cfw-tauri-shell"
dependency_root="$shell_root/node_modules"
dependency_manifest="$toolchain_root/ui-node-modules.manifest.json"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "usage: scripts/prepare_ui_dependencies.sh"
[[ "$toolchain_root" == /* ]] || die "CFW_TOOLCHAIN_ROOT must be absolute"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "UI release dependencies require Apple Silicon macOS"
[[ -d "$toolchain_root" && ! -L "$toolchain_root" ]] ||
  die "release toolchain root must be a real directory"

node_tree_sha256="$(cfw_verified_node_toolchain_tree_sha256 "$repo_root" "$toolchain_root")"
[[ "$node_tree_sha256" =~ ^[0-9a-f]{64}$ ]] || die "verified Node tree digest is malformed"
[[ "$("$node_bin" --version)" == "v$NODE_VERSION" ]] ||
  die "pinned Node.js $NODE_VERSION identity mismatch"

if [[ -e "$dependency_root" || -L "$dependency_root" || -e "$dependency_manifest" || -L "$dependency_manifest" ]]; then
  [[ -d "$dependency_root" && ! -L "$dependency_root" ]] ||
    die "refusing incomplete or linked UI dependency evidence"
  [[ -f "$dependency_manifest" && ! -L "$dependency_manifest" ]] ||
    die "refusing UI dependencies without their sealed manifest"
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root" >/dev/null
  PATH="$node_root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    "$npm_bin" --prefix "$shell_root" ls --all --offline >/dev/null
  cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root" >/dev/null
  echo "sealed UI dependencies already verified"
  exit 0
fi

staging="$(mktemp -d "$toolchain_root/ui-dependencies-bootstrap.XXXXXX")"
completed=0
cleanup() {
  if [[ $completed -ne 1 && -n "${staging:-}" && -d "$staging" && "$staging" == "$toolchain_root/ui-dependencies-bootstrap."* ]]; then
    /bin/rm -rf -- "$staging"
  fi
}
trap cleanup EXIT

workspace="$staging/workspace"
sealed_workspace="$staging/sealed-workspace"
bootstrap_home="$staging/home"
bootstrap_cache="$staging/npm-cache"
bootstrap_tmp="$staging/tmp"
staged_manifest="$staging/ui-node-modules.manifest.json"
mkdir -p \
  "$workspace" \
  "$sealed_workspace" \
  "$bootstrap_home" \
  "$bootstrap_cache" \
  "$bootstrap_tmp"
/usr/bin/install -m 0644 "$shell_root/package.json" "$workspace/package.json"
/usr/bin/install -m 0644 "$shell_root/package-lock.json" "$workspace/package-lock.json"

/usr/bin/env -i \
  CI=true \
  HOME="$bootstrap_home" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  NPM_CONFIG_AUDIT=false \
  NPM_CONFIG_CACHE="$bootstrap_cache" \
  NPM_CONFIG_FUND=false \
  NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ \
  NPM_CONFIG_USERCONFIG=/dev/null \
  PATH="$node_root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  TMPDIR="$bootstrap_tmp" \
  "$npm_bin" --prefix "$workspace" ci --ignore-scripts=false --install-links=true

# npm may hard-link native package payloads either to its download cache or to
# another package path. The release tree deliberately forbids hard links, so
# copy recursively without preserving link topology before hashing. macOS cp -R
# preserves symbolic links and executable modes while materializing each regular
# file with an independent inode.
/usr/bin/install -m 0644 "$shell_root/package.json" "$sealed_workspace/package.json"
/usr/bin/install -m 0644 \
  "$shell_root/package-lock.json" \
  "$sealed_workspace/package-lock.json"
/bin/cp -R "$workspace/node_modules" "$sealed_workspace/node_modules"

/usr/bin/env -i \
  HOME="$bootstrap_home" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  NPM_CONFIG_CACHE="$bootstrap_cache" \
  NPM_CONFIG_OFFLINE=true \
  NPM_CONFIG_USERCONFIG=/dev/null \
  PATH="$node_root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  TMPDIR="$bootstrap_tmp" \
  "$npm_bin" --prefix "$sealed_workspace" ls --all --offline >/dev/null

package_lock_sha256="$(cfw_ui_package_lock_sha256 "$repo_root")"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$sealed_workspace/node_modules" \
  --output "$staged_manifest" \
  --algorithm sha256-tree-v2 \
  --metadata "artifactKind=pinned-ui-dependencies-v1" \
  --metadata "nodeToolchainTreeSha256=$node_tree_sha256" \
  --metadata "nodeVersion=$NODE_VERSION" \
  --metadata "packageLockSha256=$package_lock_sha256" \
  --metadata "platform=darwin-arm64"
cfw_verify_ui_dependencies_artifact \
  "$repo_root" \
  "$toolchain_root" \
  "$sealed_workspace/node_modules" \
  "$staged_manifest" >/dev/null

[[ ! -e "$dependency_root" && ! -L "$dependency_root" ]] ||
  die "UI dependency destination appeared during preparation"
[[ ! -e "$dependency_manifest" && ! -L "$dependency_manifest" ]] ||
  die "UI dependency manifest destination appeared during preparation"
/bin/mv "$sealed_workspace/node_modules" "$dependency_root"
/bin/mv "$staged_manifest" "$dependency_manifest"
cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root" >/dev/null
cfw_verified_node_toolchain_tree_sha256 "$repo_root" "$toolchain_root" >/dev/null

completed=1
/bin/rm -rf -- "$staging"
trap - EXIT
echo "sealed UI dependencies prepared: $dependency_root"
