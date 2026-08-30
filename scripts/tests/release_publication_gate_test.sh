#!/bin/bash -p
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
# shellcheck source=scripts/release_publication_path_contract.sh
source "$repo_root/scripts/release_publication_path_contract.sh"
# shellcheck source=scripts/release_python_launcher.sh
source "$repo_root/scripts/release_python_launcher.sh"

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-ga-publication-path.XXXXXX")"
cleanup() {
  /bin/rm -rf "$fixture_root"
}
trap cleanup EXIT
fixture_root="$(cd "$fixture_root" && /bin/pwd -P)"

ga_app="$fixture_root/target/candidates/0.4.0/ga/40037/signed/Clash for Mac.app"
mkdir -p "$ga_app"
cfw_require_fixed_publication_app_path "$fixture_root" "$ga_app"

old_signed="$fixture_root/target/candidates/0.4.0/signed/Clash for Mac.app"
mkdir -p "$old_signed"
if cfw_require_fixed_publication_app_path "$fixture_root" "$old_signed" 2>"$fixture_root/old-path.stderr"; then
  echo "error: path contract accepted retired candidate-level signed path" >&2
  exit 1
fi
grep -Fq "only the fixed 0.4.0/40037 GA app" "$fixture_root/old-path.stderr"

for retired_build_number in 40030 40031 40032 40033 40034 40035 40036; do
  retired_build="$fixture_root/target/candidates/0.4.0/ga/$retired_build_number/signed/Clash for Mac.app"
  mkdir -p "$retired_build"
  if cfw_require_fixed_publication_app_path "$fixture_root" "$retired_build" 2>"$fixture_root/retired-build-$retired_build_number.stderr"; then
    echo "error: path contract accepted retired build $retired_build_number" >&2
    exit 1
  fi
  grep -Fq "only the fixed 0.4.0/40037 GA app" "$fixture_root/retired-build-$retired_build_number.stderr"
done

linked_app="$fixture_root/linked.app"
ln -s "$ga_app" "$linked_app"
if cfw_require_fixed_publication_app_path "$fixture_root" "$linked_app" 2>"$fixture_root/symlink.stderr"; then
  echo "error: path contract accepted a symlinked GA app" >&2
  exit 1
fi
grep -Fq "available absolute signed app" "$fixture_root/symlink.stderr"

noncanonical_repository="$fixture_root/target/../..$(printf '/%s' "$(basename "$fixture_root")")"
if cfw_require_fixed_publication_app_path "$noncanonical_repository" "$ga_app" 2>"$fixture_root/repository.stderr"; then
  echo "error: path contract accepted a noncanonical repository" >&2
  exit 1
fi

if cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/production_release_evidence.py" seal \
  >"$fixture_root/python.stdout" 2>"$fixture_root/python.stderr"; then
  echo "error: Python boundary accepted retired seal command" >&2
  exit 1
fi
grep -Fq "seal is retired" "$fixture_root/python.stderr"

for retired in prepare-physical-candidate-manifest seal validation final; do
  if /bin/bash -p "$repo_root/scripts/run_production_release_evidence.sh" "$retired" \
    >"$fixture_root/wrapper.stdout" 2>"$fixture_root/wrapper.stderr"; then
    echo "error: wrapper accepted retired command: $retired" >&2
    exit 1
  fi
  grep -Fq "$retired is retired" "$fixture_root/wrapper.stderr"
done

for retired in --seal-assets --prepare-physical-candidate-manifest --validation --final; do
  if /bin/bash -p "$repo_root/scripts/release_publication_gate.sh" "$retired" \
    >"$fixture_root/gate.stdout" 2>"$fixture_root/gate.stderr"; then
    echo "error: publication gate accepted retired command: $retired" >&2
    exit 1
  fi
  grep -Fq "retired publication command" "$fixture_root/gate.stderr"
done

grep -Fq -- "--seal-prepackage" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "--seal-ga-acceptance" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "--seal-publication" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "--capture-hosted-ci" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "--verify-hosted-ci" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "scripts/github_hosted_ci_receipt.py" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "seal-release" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "verify-release" "$repo_root/scripts/release_publication_gate.sh"
grep -Fq -- "publication_native_products=\"\$publication_ga_root/signing-output/signed-native-products\"" \
  "$repo_root/scripts/release_publication_gate.sh"
if grep -Fq "target/candidates/0.4.0/signed/" "$repo_root/scripts/release_publication_gate.sh"; then
  echo "error: publication gate retains the retired signed-app root" >&2
  exit 1
fi
if grep -Fq "release-build/" "$repo_root/scripts/release_publication_gate.sh"; then
  echo "error: publication gate retains the retired release-build root" >&2
  exit 1
fi

echo "single-GA publication path and retired-command fixture passed"
