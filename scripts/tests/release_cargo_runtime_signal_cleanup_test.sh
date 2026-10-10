#!/bin/bash -p
set -euo pipefail

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
# shellcheck source=scripts/release_cargo_inputs.sh
source "$repo_root/scripts/release_cargo_inputs.sh"

test_root="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/cfw-cargo-signal-test.XXXXXX")"
cleanup_test_root() {
  /bin/rm -rf -- "$test_root"
}
trap cleanup_test_root EXIT

export HOME="$test_root/home"
/bin/mkdir -m 0700 "$HOME"
test_runtime_path=""
test_cleanup_marker=""

cfw_create_release_cargo_runtime() {
  [[ $# -eq 1 && "$1" == "$repo_root" ]]
  /bin/mkdir -m 0700 "$test_runtime_path"
  printf '%s\n' "$test_runtime_path"
}

cfw_verify_release_cargo_runtime() {
  [[ $# -eq 2 && "$1" == "$repo_root" && "$2" == "$test_runtime_path" ]]
}

cfw_remove_release_cargo_runtime() {
  [[ $# -eq 1 && "$1" == "$test_runtime_path" ]]
  /bin/rm -rf -- "$test_runtime_path"
  /usr/bin/touch "$test_cleanup_marker"
}

terminate_runtime_parent_command="/bin/kill -TERM \"\$PPID\""
for mode in shared fresh; do
  test_runtime_path="$test_root/runtime-$mode"
  test_cleanup_marker="$test_root/cleanup-$mode"
  command_status=0
  if [[ "$mode" == "fresh" ]]; then
    cfw_run_with_fresh_release_cargo_target \
      "$repo_root" /bin/bash -p -c "$terminate_runtime_parent_command" || command_status=$?
  else
    cfw_run_with_release_cargo_runtime \
      "$repo_root" /bin/bash -p -c "$terminate_runtime_parent_command" || command_status=$?
  fi
  [[ "$command_status" -eq 143 ]] || {
    echo "error: $mode runtime wrapper returned $command_status after SIGTERM" >&2
    exit 1
  }
  [[ ! -e "$test_runtime_path" && ! -L "$test_runtime_path" ]] || {
    echo "error: $mode runtime wrapper left its private runtime behind" >&2
    exit 1
  }
  [[ -f "$test_cleanup_marker" && ! -L "$test_cleanup_marker" ]] || {
    echo "error: $mode runtime wrapper did not execute signal cleanup" >&2
    exit 1
  }
done
