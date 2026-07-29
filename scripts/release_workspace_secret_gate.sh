#!/usr/bin/env bash

# Strengthened Requirement 8.1 response. The path/name-only atomic blocker
# reports the file path and name, mandates external relocation, and mandates
# key rotation plus updater trust migration when backup/archive/sharing
# exposure is plausible. It never opens or reads a candidate's bytes and fails
# closed on unavailable or malformed inputs.
run_updater_key_atomic_blocker() {
  local workspace_root="$1"
  local gate_dir
  gate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "$gate_dir/updater_key_release_blocker.py" "$workspace_root"
}

verify_release_workspace_has_no_key_material() {
  local workspace_root="$1"
  # The Python blocker is the single scanner and policy owner. It emits and
  # enforces the complete Requirement 8.1 response by path and name only.
  run_updater_key_atomic_blocker "$workspace_root"
}

release_workspace_secret_gate_main() {
  local gate_dir
  local workspace_root
  gate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || {
    echo "error: cannot resolve release workspace gate directory" >&2
    return 1
  }
  case $# in
    0)
      workspace_root="$(cd "$gate_dir/.." && pwd -P)" || {
        echo "error: cannot resolve repository workspace root" >&2
        return 1
      }
      ;;
    1)
      workspace_root="$1"
      [[ "$workspace_root" == /* ]] || {
        echo "error: release workspace root must be absolute" >&2
        return 1
      }
      ;;
    *)
      echo "error: usage: release_workspace_secret_gate.sh [ABSOLUTE_WORKSPACE_ROOT]" >&2
      return 1
      ;;
  esac
  verify_release_workspace_has_no_key_material "$workspace_root"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  release_workspace_secret_gate_main "$@"
fi
