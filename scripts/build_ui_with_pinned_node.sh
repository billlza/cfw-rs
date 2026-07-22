#!/usr/bin/env bash
# Build the UI with the exact release Node.js toolchain. There is no ambient
# PATH fallback because Tauri's beforeBuild hook is part of the release graph.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"

node_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}/node-$NODE_VERSION"
node_bin="$node_root/bin/node"
npm_bin="$node_root/bin/npm"
if [[ ! -x "$node_bin" || ! -x "$npm_bin" ]]; then
  echo "error: pinned Node.js toolchain is missing; run scripts/bootstrap_release_toolchain.sh explicitly" >&2
  exit 1
fi
if [[ "$("$node_bin" --version)" != "v$NODE_VERSION" ]]; then
  echo "error: pinned Node.js toolchain identity mismatch" >&2
  exit 1
fi

export PATH="$node_root/bin:/usr/bin:/bin:/usr/sbin:/sbin"
cd "$repo_root/apps/cfw-tauri-shell"
"$npm_bin" run build
