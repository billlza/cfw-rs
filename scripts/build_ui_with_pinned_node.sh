#!/usr/bin/env bash
# Run UI validation with the exact release Node.js toolchain and sealed
# dependencies. No mode can fall back to ambient Node, npm, or node_modules.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

mode=build
if [[ $# -eq 1 && "$1" == "--test" ]]; then
  mode='test'
elif [[ $# -eq 1 && "$1" == "--audit" ]]; then
  mode='audit'
elif [[ $# -eq 1 && "$1" == "--verify-dependencies" ]]; then
  mode='verify-dependencies'
elif [[ $# -ne 0 ]]; then
  echo "error: usage: scripts/build_ui_with_pinned_node.sh [--test|--audit|--verify-dependencies]" >&2
  exit 1
fi
readonly mode

[[ "$node_root" == /* && "$node_root" != *:* ]] || {
  echo "error: pinned Node root cannot be represented safely in PATH" >&2
  exit 1
}
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root" >/dev/null
if [[ "$("$node_bin" --version)" != "v$NODE_VERSION" ]]; then
  echo "error: pinned Node.js toolchain identity mismatch" >&2
  exit 1
fi

mkdir -p "$repo_root/target"
build_home="$(mktemp -d "$repo_root/target/ui-command-home.XXXXXX")"
cleanup() {
  if [[ -n "${build_home:-}" && -d "$build_home" && "$build_home" == "$repo_root/target/ui-command-home."* ]]; then
    /bin/rm -rf -- "$build_home"
  fi
}
trap cleanup EXIT
mkdir -p "$build_home/npm-cache" "$build_home/tmp"

npm_offline=true
npm_audit=false
case "$mode" in
  build)
    npm_arguments=(run build)
    ;;
  test)
    npm_arguments=(test)
    ;;
  audit)
    npm_arguments=(audit --audit-level=high)
    npm_offline=false
    npm_audit=true
    ;;
  verify-dependencies)
    npm_arguments=(ls --all --offline)
    ;;
esac
readonly npm_offline npm_audit
readonly -a npm_arguments

cd "$repo_root/apps/cfw-tauri-shell"
/usr/bin/env -i \
  CI=true \
  HOME="$build_home" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  NPM_CONFIG_AUDIT="$npm_audit" \
  NPM_CONFIG_CACHE="$build_home/npm-cache" \
  NPM_CONFIG_FUND=false \
  NPM_CONFIG_OFFLINE="$npm_offline" \
  NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ \
  NPM_CONFIG_UPDATE_NOTIFIER=false \
  NPM_CONFIG_USERCONFIG=/dev/null \
  PATH="$node_root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  TMPDIR="$build_home/tmp" \
  "$npm_bin" "${npm_arguments[@]}"
cfw_verify_ui_dependencies_tree "$repo_root" "$toolchain_root" >/dev/null
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
