#!/bin/bash -p
# Exercise the release environment's export boundary and the explicit Tauri
# temporary-directory forwarding pattern used by run_release_ci_gate.sh.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
cd "$repo_root"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"

test_parent="$repo_root/target/release-gate-tests"
/bin/mkdir -p "$test_parent"
[[ -d "$test_parent" && ! -L "$test_parent" ]] || {
  echo "error: Tauri TMPDIR test parent is unsafe" >&2
  exit 1
}
test_root="$(/usr/bin/mktemp -d "$test_parent/tauri-tmpdir.XXXXXX")"
cleanup() {
  if [[ "$test_root" == "$test_parent/tauri-tmpdir."* && \
    -d "$test_root" && ! -L "$test_root" ]]; then
    /bin/rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT
/bin/chmod 0700 "$test_root"

release_role="production"
if [[ -n "${CFW_UNSIGNED_VALIDATION_PYTHON:-}" ]]; then
  release_role="unsigned-validation"
fi
export TMPDIR="$test_root"
captured_temporary_parent="$TMPDIR"
cfw_seal_release_tool_environment "$release_role"

# Sealing leaves the shell value available to the dispatcher but deliberately
# removes it from the child environment.
/bin/bash -p -c '[[ -z "${TMPDIR+x}" ]]'
TMPDIR="$captured_temporary_parent" \
  /bin/bash -p -c \
    '[[ "$TMPDIR" == "$1" && -d "$TMPDIR" && ! -L "$TMPDIR" ]]' \
    _ "$captured_temporary_parent"

unsafe_temporary_parent="$test_root/group-writable"
/bin/mkdir -m 0700 "$unsafe_temporary_parent"
/bin/chmod 0770 "$unsafe_temporary_parent"
gate_command=("$repo_root/scripts/run_release_ci_gate.sh")
if [[ -n "${CFW_UNSIGNED_VALIDATION_PYTHON:-}" ]]; then
  gate_command+=(
    --validation-python-executable "$CFW_UNSIGNED_VALIDATION_PYTHON"
  )
fi
gate_command+=(install-tauri-cli)
if TMPDIR="$unsafe_temporary_parent" \
  "${gate_command[@]}" \
  >"$test_root/unsafe.stdout" 2>"$test_root/unsafe.stderr"; then
  echo "error: group-writable Tauri TMPDIR was accepted" >&2
  exit 1
else
  status=$?
fi
[[ "$status" -eq 1 ]] || {
  echo "error: unsafe Tauri TMPDIR did not fail with the policy status" >&2
  exit 1
}
/usr/bin/grep -Fqx \
  'error: the Tauri CLI temporary directory must not be group- or other-writable' \
  "$test_root/unsafe.stderr" || {
  echo "error: unsafe Tauri TMPDIR did not reach the mode boundary" >&2
  exit 1
}
