#!/bin/bash -p
# Pure path admission shared by the production publication gate and its fixture.
# This file performs no environment sealing and has no release side effects.

cfw_require_fixed_publication_app_path() {
  if [[ $# -ne 2 ]]; then
    echo "error: fixed publication app admission requires repository and app" >&2
    return 1
  fi
  local publication_contract_repository="$1"
  local publication_contract_app="$2"
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
  publication_contract_expected_app="$publication_contract_repository/target/candidates/0.4.0/ga/40041/signed/Clash for Mac.app"
  if [[ "$publication_contract_canonical_app" != "$publication_contract_expected_app" ]]; then
    echo "error: publication gate accepts only the fixed 0.4.0/40041 GA app: $publication_contract_expected_app" >&2
    return 1
  fi
}
