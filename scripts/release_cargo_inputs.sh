#!/bin/bash -p
# Shell adapter for the single verified Cargo workspace-source boundary.

release_cargo_inputs_directory="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=scripts/release_python_launcher.sh
source "$release_cargo_inputs_directory/release_python_launcher.sh"
unset release_cargo_inputs_directory

cfw_release_cargo_inputs_identity() {
  if [[ $# -ne 2 || "$1" != /* || "$2" != /* ]]; then
    echo "error: Cargo input verification requires repository and release home" >&2
    return 1
  fi
  cfw_run_release_python_script \
    "$1" "$1/scripts/release_cargo_inputs.py" \
    verify --repository "$1" --release-home "$2"
}

cfw_create_release_cargo_runtime() {
  if [[ $# -ne 1 || "$1" != /* ]]; then
    echo "error: Cargo runtime creation requires one absolute repository" >&2
    return 1
  fi
  local contract_repository="$1"
  local runtime_parent="$HOME/.cfm-release-tooling/cargo-runtimes"
  local effective_uid runtime_parent_mode runtime_home
  effective_uid="$(/usr/bin/id -u)" || return 1
  if [[ ! -e "$runtime_parent" && ! -L "$runtime_parent" ]]; then
    /bin/mkdir -m 0700 "$runtime_parent" || return 1
  fi
  runtime_parent_mode="$(/usr/bin/stat -f '%Lp' "$runtime_parent")" || return 1
  if [[ ! -d "$runtime_parent" || -L "$runtime_parent" || \
    "$runtime_parent_mode" != "700" || \
    "$(/usr/bin/stat -f '%u' "$runtime_parent")" != "$effective_uid" || \
    "$(cd "$runtime_parent" && /bin/pwd -P)" != "$runtime_parent" ]]; then
    echo "error: Cargo runtime parent is unavailable or unsafe" >&2
    return 1
  fi
  runtime_home="$(/usr/bin/mktemp -d "$runtime_parent/runtime.XXXXXX")" || return 1
  /bin/chmod 0700 "$runtime_home" || {
    /bin/rm -rf -- "$runtime_home"
    return 1
  }
  if ! cfw_run_release_python_script \
    "$contract_repository" "$contract_repository/scripts/release_cargo_inputs.py" \
    create-runtime \
    --repository "$contract_repository" \
    --release-home "$HOME" \
    --cargo-home "$runtime_home"; then
    /bin/rm -rf -- "$runtime_home"
    return 1
  fi
  printf '%s\n' "$runtime_home"
}

cfw_verify_release_cargo_runtime() {
  if [[ $# -ne 2 || "$1" != /* || "$2" != /* ]]; then
    echo "error: Cargo runtime verification requires repository and runtime home" >&2
    return 1
  fi
  cfw_run_release_python_script \
    "$1" "$1/scripts/release_cargo_inputs.py" \
    verify-runtime \
    --repository "$1" \
    --release-home "$HOME" \
    --cargo-home "$2"
}

cfw_remove_release_cargo_runtime() {
  if [[ $# -ne 1 || "$1" != "$HOME/.cfm-release-tooling/cargo-runtimes/runtime."* ]]; then
    echo "error: refusing to remove an unowned Cargo runtime path" >&2
    return 1
  fi
  local runtime_home="$1"
  local runtime_parent="$HOME/.cfm-release-tooling/cargo-runtimes"
  if [[ ! -d "$runtime_home" || -L "$runtime_home" || \
    "$(/usr/bin/dirname "$runtime_home")" != "$runtime_parent" || \
    "$(cd "$runtime_home" && /bin/pwd -P)" != "$runtime_home" || \
    "$(/usr/bin/stat -f '%u' "$runtime_home")" != "$(/usr/bin/id -u)" || \
    "$(/usr/bin/stat -f '%Lp' "$runtime_home")" != "700" ]]; then
    echo "error: refusing to remove an unsafe Cargo runtime path" >&2
    return 1
  fi
  /bin/rm -rf -- "$runtime_home"
}

_cfw_run_with_release_cargo_runtime() (
  if [[ $# -lt 3 || "$1" != "shared-target" && "$1" != "fresh-target" ]]; then
    echo "error: internal Cargo runtime wrapper arguments are invalid" >&2
    return 1
  fi
  local runtime_mode="$1"
  local contract_repository="$2"
  shift 2
  local runtime_home target_directory command_status verification_status cleanup_status exit_status
  runtime_home="$(cfw_create_release_cargo_runtime "$contract_repository")" || return 1

  exit_status=0
  trap '
    exit_status=$?
    trap - EXIT
    if [[ -n "${runtime_home:-}" && -d "$runtime_home" ]]; then
      if ! cfw_remove_release_cargo_runtime "$runtime_home"; then
        exit_status=1
      fi
    fi
    exit "$exit_status"
  ' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [[ "$runtime_mode" == "fresh-target" ]]; then
    target_directory="$runtime_home/target"
    /bin/mkdir -m 0700 "$target_directory" || return 1
  fi

  command_status=0
  if [[ "$runtime_mode" == "fresh-target" ]]; then
    CARGO_HOME="$runtime_home" \
      CARGO_NET_OFFLINE=true \
      CARGO_TARGET_DIR="$target_directory" \
      "$@" || command_status=$?
  else
    CARGO_HOME="$runtime_home" CARGO_NET_OFFLINE=true "$@" || command_status=$?
  fi
  verification_status=0
  cfw_verify_release_cargo_runtime \
    "$contract_repository" "$runtime_home" || verification_status=$?
  cleanup_status=0
  cfw_remove_release_cargo_runtime "$runtime_home" || cleanup_status=$?
  if [[ $cleanup_status -eq 0 ]]; then
    runtime_home=""
  fi
  if [[ $command_status -ne 0 ]]; then
    return "$command_status"
  fi
  if [[ $verification_status -ne 0 || $cleanup_status -ne 0 ]]; then
    return 1
  fi
)

cfw_run_with_release_cargo_runtime() {
  if [[ $# -lt 2 ]]; then
    echo "error: Cargo runtime wrapper requires repository and command" >&2
    return 1
  fi
  local contract_repository="$1"
  shift
  _cfw_run_with_release_cargo_runtime shared-target \
    "$contract_repository" "$@"
}

cfw_run_with_fresh_release_cargo_target() {
  if [[ $# -lt 2 ]]; then
    echo "error: fresh Cargo target wrapper requires repository and command" >&2
    return 1
  fi
  local contract_repository="$1"
  shift
  _cfw_run_with_release_cargo_runtime fresh-target \
    "$contract_repository" "$@"
}
