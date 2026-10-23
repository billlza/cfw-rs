#!/bin/bash -p
# Operator entry point of the release driver (scripts/release_driver.py):
#   scripts/cfm_release.sh status | next | run STAGE [ARGUMENTS] | shipped [--add ...]
# It runs the driver with the pinned release Python in a closed environment.
# The driver itself starts each release tool in its own sealed environment.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
if [[ "${CFM_RELEASE_DRIVER_CLOSED:-}" != 1 ]]; then
  [[ "${HOME:-}" == /* ]] || {
    echo "error: HOME must be the absolute home of the release account" >&2
    exit 2
  }
  exec /usr/bin/env -i \
    HOME="$HOME" LANG=C LC_ALL=C PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    TERM="${TERM:-dumb}" SSH_CONNECTION="${SSH_CONNECTION:-}" SSH_TTY="${SSH_TTY:-}" \
    CFM_RELEASE_DRIVER_CLOSED=1 \
    /bin/bash -p "$repo_root/scripts/cfm_release.sh" "$@"
fi

# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_python_launcher.sh
source "$repo_root/scripts/release_python_launcher.sh"
python_series="${PYTHON_VERSION%.*}"
CFW_RELEASE_PYTHON_EXECUTABLE="/opt/homebrew/Cellar/python@$python_series/$PYTHON_VERSION/Frameworks/Python.framework/Versions/$python_series/bin/python$python_series"
export CFW_RELEASE_PYTHON_EXECUTABLE
cfw_run_release_python_script "$repo_root" "$repo_root/scripts/release_driver.py" "$@"
