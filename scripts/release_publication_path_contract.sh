#!/bin/bash -p
# Pure path admission shared by the production publication gate and its fixture.
# This file performs no environment sealing and has no release side effects.

cfw_require_fixed_publication_app_path() {
  if [[ $# -ne 2 ]]; then
    echo "error: fixed publication app admission requires repository and app" >&2
    return 1
  fi
  local repository="$1"
  local app_path="$2"
  if [[ "$repository" != /* || ! -d "$repository" || -L "$repository" || \
    "$app_path" != /* || ! -d "$app_path" || -L "$app_path" ]]; then
    echo "error: publication gate requires one available absolute signed app" >&2
    return 1
  fi
  local canonical_app expected_app
  canonical_app="$(cd "$app_path" && /bin/pwd -P)" || return 1
  expected_app="$repository/target/candidates/0.4.0/signed/Clash for Mac.app"
  if [[ "$canonical_app" != "$expected_app" ]]; then
    echo "error: publication gate accepts only the fixed 0.4.0 signed app: $expected_app" >&2
    return 1
  fi
}
