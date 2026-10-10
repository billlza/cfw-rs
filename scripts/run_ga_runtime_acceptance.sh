#!/bin/bash -p
# Admit GA runtime collection and verification only through the closed release
# Python and Apple toolchain boundary.
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
  "$repo_root/scripts/ga_runtime_acceptance_cli.py" \
  "$@"
