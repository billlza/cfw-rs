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

  validate_release_workspace_secret_scan "$scan_status" "$first_match"
}
