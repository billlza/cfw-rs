#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../release_workspace_secret_gate.sh
source "$repo_root/scripts/release_workspace_secret_gate.sh"

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-secret-gate.XXXXXX")"
trap '/bin/rm -rf "$temporary_root"' EXIT

verify_release_workspace_has_no_key_material "$temporary_root"

mkdir -p "$temporary_root/.tauri"
: >"$temporary_root/.tauri/updater.key"
if verify_release_workspace_has_no_key_material "$temporary_root" >/dev/null 2>&1; then
  echo "error: key fixture unexpectedly passed the release workspace gate" >&2
  exit 1
fi
/bin/rm "$temporary_root/.tauri/updater.key"

if validate_release_workspace_secret_scan 1 "" >/dev/null 2>&1; then
  echo "error: failed find traversal unexpectedly passed the release workspace gate" >&2
  exit 1
fi

if validate_release_workspace_secret_scan 1 "$temporary_root/exposed.pem" >/dev/null 2>&1; then
  echo "error: partial find traversal unexpectedly passed the release workspace gate" >&2
  exit 1
fi

echo "release workspace secret gate fails closed"
