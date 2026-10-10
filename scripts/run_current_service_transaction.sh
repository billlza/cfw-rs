#!/bin/bash -p
# Admit the current-service transaction only through the closed production
# Python and Apple toolchain boundary.
set -euo pipefail
unset CDPATH

for argument in "$@"; do
  if [[ "$argument" == "--final" ]]; then
    echo "error: --final is retired; use the single active GA transaction" >&2
    exit 2
  fi
done

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/current_service_transaction.py" \
  "$@"
