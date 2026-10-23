#!/bin/bash -p
# Before candidate freeze: prove that hosted CI passed on this exact, clean
# release checkout (scripts/github_hosted_ci_receipt.py preflight). Read-only.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/github_hosted_ci_receipt.py" \
  preflight \
  "$@"
