#!/usr/bin/env bash
# Shared fail-closed contract for the release UI dependency tree. Callers must
# source dependency_pins.env and release_toolchain_contract.sh before this file.

cfw_ui_package_lock_sha256() {
  local contract_repository="$1"
  local contract_lock="$contract_repository/apps/cfw-tauri-shell/package-lock.json"
  [[ -f "$contract_lock" && ! -L "$contract_lock" ]] || {
    echo "error: UI package lock must be a regular repository file" >&2
    return 1
  }
  /usr/bin/shasum -a 256 "$contract_lock" | /usr/bin/awk '{print $1}'
}

cfw_verified_node_toolchain_tree_sha256() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  if ! declare -F cfw_verify_node_toolchain_tree >/dev/null; then
    echo "error: release_toolchain_contract.sh must be sourced first" >&2
    return 1
  fi
  cfw_verify_node_toolchain_tree "$contract_repository" "$contract_toolchain_root"
}

cfw_verify_ui_dependencies_artifact() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  local contract_artifact="$3"
  local contract_manifest="$4"
  local contract_node_tree_sha256
  local contract_package_lock_sha256

  contract_node_tree_sha256="$(
    cfw_verified_node_toolchain_tree_sha256 \
      "$contract_repository" \
      "$contract_toolchain_root"
  )"
  contract_package_lock_sha256="$(cfw_ui_package_lock_sha256 "$contract_repository")"
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "$contract_repository/scripts/verify_artifact_manifest.py" \
    "$contract_artifact" \
    "$contract_manifest" \
    --algorithm sha256-tree-v2 \
    --exact-metadata \
    --metadata "artifactKind=pinned-ui-dependencies-v1" \
    --metadata "nodeToolchainTreeSha256=$contract_node_tree_sha256" \
    --metadata "nodeVersion=$NODE_VERSION" \
    --metadata "packageLockSha256=$contract_package_lock_sha256" \
    --metadata "platform=darwin-arm64" \
    --print-tree-sha256
}

cfw_verify_ui_dependencies_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_ui_dependencies_artifact \
    "$contract_repository" \
    "$contract_toolchain_root" \
    "$contract_repository/apps/cfw-tauri-shell/node_modules" \
    "$contract_toolchain_root/ui-node-modules.manifest.json"
}
