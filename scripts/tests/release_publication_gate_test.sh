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

ga_app="$fixture_root/target/candidates/0.4.0/ga/40044/signed/Clash for Mac.app"
mkdir -p "$ga_app"
cfw_require_fixed_publication_app_path "$fixture_root" "$ga_app"

(
  readonly repository="caller-owned-repository"
  readonly app_path="$ga_app"
  readonly canonical_repository="caller-owned-canonical-repository"
  readonly canonical_app="caller-owned-canonical-app"
  readonly expected_app="caller-owned-expected-app"
  cfw_require_fixed_publication_app_path "$fixture_root" "$app_path"
  [[ "$repository" == "caller-owned-repository" ]]
  [[ "$canonical_repository" == "caller-owned-canonical-repository" ]]
  [[ "$canonical_app" == "caller-owned-canonical-app" ]]
  [[ "$expected_app" == "caller-owned-expected-app" ]]
)

gate_fixture="$fixture_root/gate-repository"
gate_artifact="$gate_fixture/target/release-worktrees/40044"
gate_ga_root="$gate_artifact/target/candidates/0.4.0/ga/40044"
mkdir -p "$gate_fixture/scripts" "$gate_artifact/scripts" \
  "$gate_ga_root/signed/Clash for Mac.app" \
  "$gate_ga_root/signing-output/signed-native-products"
/bin/cp "$repo_root/scripts/release_publication_gate.sh" \
  "$repo_root/scripts/release_publication_path_contract.sh" "$gate_fixture/scripts/"
: >"$gate_fixture/scripts/dependency_pins.env"
cat >"$gate_fixture/scripts/release_tool_environment.sh" <<'SH'
cfw_seal_release_tool_environment() {
  [[ "$#" -eq 1 && "$1" == "production" ]]
}
cfw_select_release_apple_toolchain() {
  [[ "$#" -eq 0 ]]
}
cfw_run_release_python_script() {
  case "$2" in
    "$1/scripts/release_executor_source.py")
      [[ "$#" -eq 3 && "$3" == "--print-frozen-artifact-repository" ]] || return 1
      printf '%s\n' "$1/target/release-worktrees/40044"
      ;;
    "$1/scripts/production_release_evidence.py")
      [[ "$#" -eq 4 && "$3" == "verify" && "$4" == "prepackage" ]] || return 1
      [[ ! -e "$1/scripts/fail-prepackage" ]] || return 1
      printf '%s\n' "fixed prepackage stage reopened"
      ;;
    *) return 1 ;;
  esac
}
SH
cat >"$gate_artifact/scripts/verify_release_app.sh" <<'SH'
#!/bin/bash -p
set -euo pipefail
fixture_artifact_root="${BASH_SOURCE[0]%/scripts/verify_release_app.sh}"
fixture_ga_root="$fixture_artifact_root/target/candidates/0.4.0/ga/40044"
[[ "$#" -eq 4 ]]
[[ "$1" == "$fixture_ga_root/signed/Clash for Mac.app" ]]
[[ "$2" == "$fixture_ga_root/signing-output/signed-native-products" ]]
[[ "$3" == "--context" && "$4" == "canonical-native-content" ]]
printf '%s\n' "fixed application verifier invoked"
SH
(
  # shellcheck source=scripts/release_publication_gate.sh
  source "$gate_fixture/scripts/release_publication_gate.sh"
  readonly app_path="$gate_ga_root/signed/Clash for Mac.app"
  verify_release_prepackage_evidence "$app_path"
) >"$fixture_root/readonly-caller.stdout" 2>"$fixture_root/readonly-caller.stderr"
[[ ! -s "$fixture_root/readonly-caller.stderr" ]]
grep -Fxq "fixed prepackage stage reopened" "$fixture_root/readonly-caller.stdout"
grep -Fxq "fixed application verifier invoked" "$fixture_root/readonly-caller.stdout"

touch "$gate_fixture/scripts/fail-prepackage"
if (
  # shellcheck source=scripts/release_publication_gate.sh
  source "$gate_fixture/scripts/release_publication_gate.sh"
  readonly app_path="$gate_ga_root/signed/Clash for Mac.app"
  verify_release_prepackage_evidence "$app_path"
) >"$fixture_root/failed-stage.stdout" 2>"$fixture_root/failed-stage.stderr"; then
  echo "error: failed prepackage verification was hidden by application verification" >&2
  exit 1
fi
[[ ! -s "$fixture_root/failed-stage.stdout" ]]

old_signed="$fixture_root/target/candidates/0.4.0/signed/Clash for Mac.app"
mkdir -p "$old_signed"
if cfw_require_fixed_publication_app_path "$fixture_root" "$old_signed" 2>"$fixture_root/old-path.stderr"; then
  echo "error: path contract accepted retired candidate-level signed path" >&2
  exit 1
fi
grep -Fq "only the fixed 0.4.0/40044 GA app" "$fixture_root/old-path.stderr"

for retired_build_number in 40030 40031 40032 40033 40034 40035 40036 40037 40038 40039 40040 40041 40042 40043; do
  retired_build="$fixture_root/target/candidates/0.4.0/ga/$retired_build_number/signed/Clash for Mac.app"
  mkdir -p "$retired_build"
  if cfw_require_fixed_publication_app_path "$fixture_root" "$retired_build" 2>"$fixture_root/retired-build-$retired_build_number.stderr"; then
    echo "error: path contract accepted retired build $retired_build_number" >&2
    exit 1
  fi
  grep -Fq "only the fixed 0.4.0/40044 GA app" "$fixture_root/retired-build-$retired_build_number.stderr"
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
