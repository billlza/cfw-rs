#!/bin/bash -p
# Produce the SwiftUI code/resource closure inside an already allocated preview.
set -euo pipefail
unset CDPATH
repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$repo_root/scripts/dependency_pins.env"
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_select_release_apple_toolchain
: "${CFW_NATIVE_PRODUCTS_OUTPUT:?set the exact preview native-products path}"
: "${CFW_BUILD_NUMBER:?set the exact preview build number}"
operation=build
if [[ $# -eq 1 && "$1" == "--verify" ]]; then
  operation=verify
elif [[ $# -ne 0 ]]; then
  echo "usage: scripts/build_native_ui.sh [--verify]" >&2
  exit 2
fi
cfw_run_release_python_script "$repo_root" "$repo_root/scripts/native_ui_artifact.py" "$operation" \
  --repository "$repo_root" --products "$CFW_NATIVE_PRODUCTS_OUTPUT" --build-number "$CFW_BUILD_NUMBER"
