#!/bin/bash -p
# Admit the GA journal export only through the closed production Python and
# Apple toolchain boundary.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/ga_acceptance_journal_export.py" \
  "$@"
