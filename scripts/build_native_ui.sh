#!/bin/bash -p
# Produce the SwiftUI code/resource closure inside an already allocated GA
# pre-sign or unsigned preview validation candidate.
set -euo pipefail
unset CDPATH
repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$repo_root/scripts/dependency_pins.env"
source "$repo_root/scripts/release_tool_environment.sh"
usage() {
  echo "usage: scripts/build_native_ui.sh [--verify] --unsigned-preview-validation|--release" >&2
  exit 2
}
operation=build
mode=""
for argument in "$@"; do
  case "$argument" in
    --verify) [[ "$operation" == build ]] || usage; operation=verify ;;
    --unsigned-preview-validation | --release) [[ -z "$mode" ]] || usage; mode="$argument" ;;
    *) usage ;;
  esac
done
[[ -n "$mode" ]] || usage
if [[ "$mode" == "--unsigned-preview-validation" ]]; then
  cfw_seal_release_tool_environment unsigned-validation
else
  cfw_seal_release_tool_environment production
fi
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_select_release_apple_toolchain
: "${CFW_NATIVE_PRODUCTS_OUTPUT:?set the exact candidate native-products path}"
: "${CFW_BUILD_NUMBER:?set the exact candidate build number}"
cfw_run_release_python_script "$repo_root" "$repo_root/scripts/native_ui_artifact.py" "$operation" \
  --repository "$repo_root" --products "$CFW_NATIVE_PRODUCTS_OUTPUT" --build-number "$CFW_BUILD_NUMBER" \
  "$mode"
