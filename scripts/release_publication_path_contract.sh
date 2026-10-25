#!/bin/bash -p
# Pure path admission shared by the production publication gate and its fixture.
# This file performs no environment sealing and has no release side effects.
# The caller passes the product version and GA build it has proven; nothing
# here names either.

cfw_require_fixed_publication_app_path() {
  if [[ $# -ne 4 ]]; then
    echo "error: fixed publication app admission requires repository, version, build and app" >&2
    return 1
  fi
  local publication_contract_repository="$1"
  local publication_contract_version="$2"
  local publication_contract_build="$3"
  local publication_contract_app="$4"
  if [[ ! "$publication_contract_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "error: publication version is not one canonical MAJOR.MINOR.PATCH version: $publication_contract_version" >&2
    return 1
  fi
  if [[ ! "$publication_contract_build" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: publication build is not one canonical positive integer: $publication_contract_build" >&2
    return 1
  fi
  if [[ "$publication_contract_repository" != /* || \
    ! -d "$publication_contract_repository" || -L "$publication_contract_repository" || \
    "$publication_contract_app" != /* || \
    ! -d "$publication_contract_app" || -L "$publication_contract_app" ]]; then
    echo "error: publication gate requires one available absolute signed app" >&2
    return 1
  fi
  local publication_contract_canonical_repository
  local publication_contract_canonical_app publication_contract_expected_app
  publication_contract_canonical_repository="$(cd "$publication_contract_repository" && /bin/pwd -P)" || return 1
  if [[ "$publication_contract_canonical_repository" != "$publication_contract_repository" ]]; then
    echo "error: publication repository is not canonical: $publication_contract_repository" >&2
    return 1
  fi
  publication_contract_canonical_app="$(cd "$publication_contract_app" && /bin/pwd -P)" || return 1
  publication_contract_expected_app="$publication_contract_repository/target/candidates/$publication_contract_version/ga/$publication_contract_build/signed/Clash for Mac.app"
  if [[ "$publication_contract_canonical_app" != "$publication_contract_expected_app" ]]; then
    echo "error: publication gate accepts only the fixed $publication_contract_version/$publication_contract_build GA app: $publication_contract_expected_app" >&2
    return 1
  fi
}
