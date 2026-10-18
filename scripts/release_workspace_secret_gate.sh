#!/usr/bin/env bash

# Requirement 8.1 path/name-only secret-material gate. One scanner classifies
# known updater keys, Apple App Store Connect .p8 keys, and unknown candidates,
# then emits the matching trust-domain response without reading file bytes.
run_release_secret_material_blocker() {
  local workspace_root="$1"
  local gate_dir
  gate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  PYTHONDONTWRITEBYTECODE=1 \
    "${CFW_RELEASE_PYTHON_EXECUTABLE:-python3}" -I -S -B -W error \
    "$gate_dir/release_secret_material_blocker.py" "$workspace_root"
}

verify_release_workspace_has_no_key_material() {
  local workspace_root="$1"
  # The Python blocker is the single scanner and policy owner. It emits and
  # enforces the complete Requirement 8.1 response by path and name only.
  run_release_secret_material_blocker "$workspace_root"
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
