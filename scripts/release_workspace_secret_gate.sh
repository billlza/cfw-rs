#!/usr/bin/env bash

validate_release_workspace_secret_scan() {
  local scan_status="$1"
  local first_match="$2"

  if [[ "$scan_status" -ne 0 ]]; then
    echo "error: repository key-material scan did not complete; release is blocked" >&2
    return 1
  fi
  if [[ -n "$first_match" ]]; then
    echo "error: updater signing key material must be moved outside the repository workspace before release" >&2
    return 1
  fi
}

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
  local first_match
  local scan_status

  # Do not pipe find into a predicate: pipefail would make a partial match plus
  # an I/O error look identical to "no match" inside an if condition. Capture
  # the traversal status independently and fail closed before inspecting data.
  if first_match="$(
    /usr/bin/find "$workspace_root" -xdev \
      \( -path "$workspace_root/.git" -o -path "$workspace_root/target" -o -name node_modules -o -name .build \) \
      -prune -o \( -type f -o -type l \) \( -name '*.key' -o -name '*.pem' \) \
      -print -quit 2>/dev/null
  )"; then
    scan_status=0
  else
    scan_status=$?
  fi

  validate_release_workspace_secret_scan "$scan_status" "$first_match" || return 1

  # Defense in depth: the atomic blocker emits and enforces the complete
  # Requirement 8.1 security response (block, path/name report, relocation, and
  # conditional rotation plus updater trust migration) by path and name only.
  run_updater_key_atomic_blocker "$workspace_root"
}
