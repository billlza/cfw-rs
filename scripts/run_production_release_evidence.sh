#!/bin/bash -p
set -euo pipefail
unset CDPATH

case "${1:-}" in
  prepare-physical-candidate-manifest | seal | validation | final)
    echo "error: ${1} is retired; use prepackage, ga-acceptance, or publication" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/production_release_evidence.py" \
  "$@"
