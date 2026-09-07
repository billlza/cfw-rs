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
  echo "error: source-mode key fixture unexpectedly passed the gate" >&2
  exit 1
fi
/bin/rm "$temporary_root/.tauri/updater.key"

: >"$temporary_root/AuthKey_WORKSPACE.p8"
if verify_release_workspace_has_no_key_material "$temporary_root" >/dev/null 2>&1; then
  echo "error: .p8 signing-key fixture unexpectedly passed the gate" >&2
  exit 1
fi
/bin/rm "$temporary_root/AuthKey_WORKSPACE.p8"

# Install a self-contained gate fixture so direct execution with no arguments
# proves that main resolves and scans its own repository root.
fixture_repo="$temporary_root/direct-repository"
mkdir -p "$fixture_repo/scripts"
/bin/cp "$repo_root/scripts/release_workspace_secret_gate.sh" "$fixture_repo/scripts/"
/bin/cp "$repo_root/scripts/release_secret_material_blocker.py" "$fixture_repo/scripts/"

bash "$fixture_repo/scripts/release_workspace_secret_gate.sh"
mkdir -p "$fixture_repo/target/candidates/0.4.0"
: >"$fixture_repo/target/candidates/0.4.0/candidate.key"
if bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" >/dev/null 2>&1; then
  echo "error: direct no-argument execution did not scan target/candidates" >&2
  exit 1
fi
/bin/rm "$fixture_repo/target/candidates/0.4.0/candidate.key"

# Managed heavy roots are deliberately not traversed; generated and
# unexpected target children remain in scope.
mkdir -p "$fixture_repo/target/toolchains"
: >"$fixture_repo/target/toolchains/upstream-fixture.pem"
bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" "$fixture_repo"

for relative_key in \
  "target/tmp/transient.pem" \
  "target/candidates/0.4.0/AuthKey_GENERATED.p8" \
  "target/release/historical.key" \
  "target/unexpected/unexpected.key"
do
  mkdir -p "$fixture_repo/$(dirname "$relative_key")"
  : >"$fixture_repo/$relative_key"
  if bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" "$fixture_repo" >/dev/null 2>&1; then
    echo "error: direct execution did not block $relative_key" >&2
    exit 1
  fi
  /bin/rm "$fixture_repo/$relative_key"
done

outside="$temporary_root/outside"
mkdir -p "$outside"
ln -s "$outside" "$fixture_repo/target/symlinked-subtree"
if bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" "$fixture_repo" >/dev/null 2>&1; then
  echo "error: symlinked subtree unexpectedly passed the gate" >&2
  exit 1
fi
/bin/rm "$fixture_repo/target/symlinked-subtree"

# Sourcing the script defines functions but must not execute the gate.
: >"$fixture_repo/target/candidates/0.4.0/source-mode.key"
bash -c 'source "$1"; declare -F verify_release_workspace_has_no_key_material >/dev/null; echo sourced' \
  bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" \
  | /usr/bin/grep -qx sourced

if bash "$fixture_repo/scripts/release_workspace_secret_gate.sh" relative/root >/dev/null 2>&1; then
  echo "error: relative workspace root unexpectedly passed direct execution" >&2
  exit 1
fi

echo "release workspace secret gate fails closed"
