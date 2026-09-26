#!/bin/bash -p
# Produce the SwiftUI code/resource closure inside an already allocated preview.
set -euo pipefail
unset CDPATH
repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$repo_root/scripts/dependency_pins.env"
source "$repo_root/scripts/release_tool_environment.sh"
operation=build
unsigned_preview=0
for argument in "$@"; do
  case "$argument" in
    --verify) [[ "$operation" == build ]] || exit 2; operation=verify ;;
    --unsigned-preview-validation) [[ $unsigned_preview -eq 0 ]] || exit 2; unsigned_preview=1 ;;
    *) echo "usage: scripts/build_native_ui.sh [--verify] [--unsigned-preview-validation]" >&2; exit 2 ;;
  esac
done
if [[ $unsigned_preview -eq 1 ]]; then
  cfw_seal_release_tool_environment unsigned-validation
else
  cfw_seal_release_tool_environment production
fi
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_select_release_apple_toolchain
: "${CFW_NATIVE_PRODUCTS_OUTPUT:?set the exact preview native-products path}"
: "${CFW_BUILD_NUMBER:?set the exact preview build number}"
# Bash 3.2 with nounset rejects expansion of an empty optional array. Build
# the complete command first so both production and CI always expand real argv.
artifact_command=(
  cfw_run_release_python_script "$repo_root" "$repo_root/scripts/native_ui_artifact.py" "$operation"
  --repository "$repo_root" --products "$CFW_NATIVE_PRODUCTS_OUTPUT" --build-number "$CFW_BUILD_NUMBER"
)
if [[ $unsigned_preview -eq 1 ]]; then
  artifact_command+=(--unsigned-preview-validation)
fi
"${artifact_command[@]}"
