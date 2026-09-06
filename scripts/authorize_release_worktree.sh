#!/bin/bash -p
# Publish or recover a release-worktree lifecycle receipt through the same closed
# production Python boundary used by later candidate construction.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain

scope_operation=--authorize-release-worktree
if [[ $# -eq 2 && "$1" == --recover-after-reboot ]]; then
  scope_operation=--recover-release-worktree
  shift
fi
[[ $# -eq 1 && "$1" =~ ^[1-9][0-9]{4}$ ]] || {
  echo "error: usage: scripts/authorize_release_worktree.sh [--recover-after-reboot] FIVE_DIGIT_BUILD" >&2
  exit 2
}
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/release_secret_material_blocker.py" \
  "$repo_root" "$scope_operation" "$1"
