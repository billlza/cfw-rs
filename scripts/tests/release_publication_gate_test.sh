#!/bin/bash -p
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
# shellcheck source=scripts/release_identity.env
source "$repo_root/scripts/release_identity.env"
# The gate fixtures below unset the identity in subshells so that the gate
# loads it itself; the test reads its own copy of the version and build.
active_product_version="$CFW_PRODUCT_VERSION"
active_ga_build="$CFW_GA_BUILD"
# A version the identity file does not name: the next patch release.
other_product_version="${active_product_version%.*}.$((${active_product_version##*.} + 1))"
# A build the identity file does not name: the active GA plus one.
other_ga_build="$((active_ga_build + 1))"
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

ga_app="$fixture_root/target/candidates/$active_product_version/ga/$active_ga_build/signed/Clash for Mac.app"
mkdir -p "$ga_app"
cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$active_ga_build" "$ga_app"

# The contract is relational: it admits exactly the app of the version and
# build it is given.
other_app="$fixture_root/target/candidates/$active_product_version/ga/$other_ga_build/signed/Clash for Mac.app"
mkdir -p "$other_app"
cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$other_ga_build" "$other_app"
for mismatched in "$other_ga_build:$ga_app" "$active_ga_build:$other_app"; do
  if cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "${mismatched%%:*}" "${mismatched#*:}" \
    2>"$fixture_root/mismatched-build.stderr"; then
    echo "error: path contract accepted an app of another build: $mismatched" >&2
    exit 1
  fi
  grep -Fq "only the fixed $active_product_version/${mismatched%%:*} GA app" "$fixture_root/mismatched-build.stderr"
done
other_version_app="$fixture_root/target/candidates/$other_product_version/ga/$active_ga_build/signed/Clash for Mac.app"
mkdir -p "$other_version_app"
cfw_require_fixed_publication_app_path "$fixture_root" "$other_product_version" "$active_ga_build" "$other_version_app"
for mismatched in "$other_product_version:$ga_app" "$active_product_version:$other_version_app"; do
  if cfw_require_fixed_publication_app_path "$fixture_root" "${mismatched%%:*}" "$active_ga_build" "${mismatched#*:}" \
    2>"$fixture_root/mismatched-version.stderr"; then
    echo "error: path contract accepted an app of another version: $mismatched" >&2
    exit 1
  fi
  grep -Fq "only the fixed ${mismatched%%:*}/$active_ga_build GA app" "$fixture_root/mismatched-version.stderr"
done
for malformed_version in "" "0$active_product_version" "v$active_product_version" "${active_product_version%.*}" "$active_product_version.0" "$active_product_version/../$active_product_version"; do
  if cfw_require_fixed_publication_app_path "$fixture_root" "$malformed_version" "$active_ga_build" "$ga_app" \
    2>"$fixture_root/malformed-version.stderr"; then
    echo "error: path contract accepted a malformed version: $malformed_version" >&2
    exit 1
  fi
  grep -Fq "publication version is not one canonical MAJOR.MINOR.PATCH version" \
    "$fixture_root/malformed-version.stderr"
done
for malformed_build in "" "0$active_ga_build" "+$active_ga_build" "$active_ga_build/../$active_ga_build" "../ga/$active_ga_build"; do
  if cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$malformed_build" "$ga_app" \
    2>"$fixture_root/malformed-build.stderr"; then
    echo "error: path contract accepted a malformed build: $malformed_build" >&2
    exit 1
  fi
  grep -Fq "publication build is not one canonical positive integer" \
    "$fixture_root/malformed-build.stderr"
done

(
  readonly repository="caller-owned-repository"
  readonly app_path="$ga_app"
  readonly canonical_repository="caller-owned-canonical-repository"
  readonly canonical_app="caller-owned-canonical-app"
  readonly expected_app="caller-owned-expected-app"
  readonly build="caller-owned-build"
  readonly version="caller-owned-version"
  cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$active_ga_build" "$app_path"
  [[ "$repository" == "caller-owned-repository" ]]
  [[ "$canonical_repository" == "caller-owned-canonical-repository" ]]
  [[ "$canonical_app" == "caller-owned-canonical-app" ]]
  [[ "$expected_app" == "caller-owned-expected-app" ]]
  [[ "$build" == "caller-owned-build" ]]
  [[ "$version" == "caller-owned-version" ]]
)

gate_fixture="$fixture_root/gate-repository"
gate_artifact="$gate_fixture/target/release-worktrees/$active_ga_build"
gate_ga_root="$gate_artifact/target/candidates/$active_product_version/ga/$active_ga_build"
mkdir -p "$gate_fixture/scripts" "$gate_artifact/scripts" \
  "$gate_ga_root/signed/Clash for Mac.app" \
  "$gate_ga_root/signing-output/signed-native-products"
/bin/cp "$repo_root/scripts/release_publication_gate.sh" \
  "$repo_root/scripts/release_publication_path_contract.sh" \
  "$repo_root/scripts/release_identity.env" "$gate_fixture/scripts/"
: >"$gate_fixture/scripts/dependency_pins.env"
{
  printf 'fixture_product_version=%q\n' "$active_product_version"
  printf 'fixture_ga_build=%q\n' "$active_ga_build"
  cat <<'SH'
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
      printf '%s\n' "$1/target/release-worktrees/$fixture_ga_build"
      ;;
    "$1/scripts/production_release_evidence.py")
      [[ "$#" -eq 4 && "$3" == "verify" ]] || return 1
      case "$4" in
        prepackage) [[ ! -e "$1/scripts/fail-prepackage" ]] || return 1 ;;
        publication) ;;
        *) return 1 ;;
      esac
      printf '%s\n' "fixed $4 stage reopened"
      ;;
    "$1/scripts/release_artifact_set_cli.py")
      [[ "$#" -eq 7 && "$3" == "verify-release" && "$4" == "--repository" && \
        "$5" == "$1/target/release-worktrees/$fixture_ga_build" && \
        "$6" == "--version" && "$7" == "$fixture_product_version" ]] || return 1
      printf '%s\n' "fixed release sets verified"
      ;;
    "$1/scripts/github_hosted_ci_receipt.py")
      [[ "$1" != */target/release-worktrees/"$fixture_ga_build" ]] || return 1
      if [[ "$3" == "capture" ]]; then
        [[ "$#" -eq 5 && "$4" == "--run-id" && "$5" == "90012345678" ]] || return 1
      else
        [[ "$#" -eq 3 && "$3" == "verify" ]] || return 1
      fi
      printf '%s\n' "current hosted CI executor invoked"
      ;;
    *) return 1 ;;
  esac
}
SH
} >"$gate_fixture/scripts/release_tool_environment.sh"
{
  printf '%s\n' '#!/bin/bash -p' 'set -euo pipefail'
  printf 'fixture_product_version=%q\n' "$active_product_version"
  printf 'fixture_ga_build=%q\n' "$active_ga_build"
  cat <<'SH'
fixture_artifact_root="${BASH_SOURCE[0]%/scripts/verify_release_app.sh}"
fixture_ga_root="$fixture_artifact_root/target/candidates/$fixture_product_version/ga/$fixture_ga_build"
[[ "$#" -eq 4 ]]
[[ "$1" == "$fixture_ga_root/signed/Clash for Mac.app" ]]
[[ "$2" == "$fixture_ga_root/signing-output/signed-native-products" ]]
[[ "$3" == "--context" && "$4" == "canonical-native-content" ]]
if [[ -e "$fixture_artifact_root/scripts/fail-live-notarization" ]]; then
  echo "error: stapler validate failed with exit status 68" >&2
  exit 1
fi
printf '%s\n' "fixed application verifier invoked"
SH
} >"$gate_artifact/scripts/verify_release_app.sh"
(
  # The gate must load the identity itself, not inherit this test's values.
  unset CFW_PRODUCT_VERSION CFW_GA_BUILD
  # shellcheck source=scripts/release_publication_gate.sh
  source "$gate_fixture/scripts/release_publication_gate.sh"
  readonly app_path="$gate_ga_root/signed/Clash for Mac.app"
  verify_release_prepackage_evidence "$app_path"
) >"$fixture_root/readonly-caller.stdout" 2>"$fixture_root/readonly-caller.stderr"
[[ ! -s "$fixture_root/readonly-caller.stderr" ]]
grep -Fxq "fixed prepackage stage reopened" "$fixture_root/readonly-caller.stdout"
grep -Fxq "fixed application verifier invoked" "$fixture_root/readonly-caller.stdout"

for hosted_command in --capture-hosted-ci --verify-hosted-ci; do
  hosted_arguments=("$hosted_command")
  if [[ "$hosted_command" == "--capture-hosted-ci" ]]; then
    hosted_arguments+=(90012345678)
  fi
  /bin/bash -p "$gate_fixture/scripts/release_publication_gate.sh" \
    "${hosted_arguments[@]}" \
    >"$fixture_root/hosted-ci.stdout" 2>"$fixture_root/hosted-ci.stderr"
  [[ ! -s "$fixture_root/hosted-ci.stderr" ]]
  grep -Fxq "current hosted CI executor invoked" "$fixture_root/hosted-ci.stdout"
done

# Reopening a sealed stage verifies notarization offline, so upload itself
# runs the live check of the frozen application before the release sets.
/bin/bash -p "$gate_fixture/scripts/release_publication_gate.sh" --upload-assets "$active_product_version" \
  >"$fixture_root/upload.stdout" 2>"$fixture_root/upload.stderr"
[[ ! -s "$fixture_root/upload.stderr" ]]
printf '%s\n' \
  "current hosted CI executor invoked" \
  "fixed prepackage stage reopened" \
  "fixed application verifier invoked" \
  "fixed publication stage reopened" \
  "fixed release sets verified" >"$fixture_root/upload.expected"
if ! cmp -s "$fixture_root/upload.expected" "$fixture_root/upload.stdout"; then
  echo "error: upload did not check notarization live before the release sets" >&2
  exit 1
fi
touch "$gate_artifact/scripts/fail-live-notarization"
upload_status=0
/bin/bash -p "$gate_fixture/scripts/release_publication_gate.sh" --upload-assets "$active_product_version" \
  >"$fixture_root/failed-upload.stdout" 2>"$fixture_root/failed-upload.stderr" ||
  upload_status=$?
if [[ "$upload_status" -eq 0 ]]; then
  echo "error: upload passed although the live notarization check failed" >&2
  exit 1
fi
grep -Fxq "error: stapler validate failed with exit status 68" \
  "$fixture_root/failed-upload.stderr"
if grep -Fq "fixed release sets verified" "$fixture_root/failed-upload.stdout"; then
  echo "error: upload reached the release sets after the live notarization check failed" >&2
  exit 1
fi
/bin/rm "$gate_artifact/scripts/fail-live-notarization"

touch "$gate_fixture/scripts/fail-prepackage"
if (
  # The gate must load the identity itself, not inherit this test's values.
  unset CFW_PRODUCT_VERSION CFW_GA_BUILD
  # shellcheck source=scripts/release_publication_gate.sh
  source "$gate_fixture/scripts/release_publication_gate.sh"
  readonly app_path="$gate_ga_root/signed/Clash for Mac.app"
  verify_release_prepackage_evidence "$app_path"
) >"$fixture_root/failed-stage.stdout" 2>"$fixture_root/failed-stage.stderr"; then
  echo "error: failed prepackage verification was hidden by application verification" >&2
  exit 1
fi
[[ ! -s "$fixture_root/failed-stage.stdout" ]]

old_signed="$fixture_root/target/candidates/$active_product_version/signed/Clash for Mac.app"
mkdir -p "$old_signed"
if cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$active_ga_build" "$old_signed" 2>"$fixture_root/old-path.stderr"; then
  echo "error: path contract accepted retired candidate-level signed path" >&2
  exit 1
fi
grep -Fq "only the fixed $active_product_version/$active_ga_build GA app" "$fixture_root/old-path.stderr"

for retired_build_number in 40030 40031 40032 40033 40034 40035 40036 40037 40038 40039 40040 40041 40042 40043 40044 40045; do
  retired_build="$fixture_root/target/candidates/$active_product_version/ga/$retired_build_number/signed/Clash for Mac.app"
  mkdir -p "$retired_build"
  if cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$active_ga_build" "$retired_build" 2>"$fixture_root/retired-build-$retired_build_number.stderr"; then
    echo "error: path contract accepted retired build $retired_build_number" >&2
    exit 1
  fi
  grep -Fq "only the fixed $active_product_version/$active_ga_build GA app" "$fixture_root/retired-build-$retired_build_number.stderr"
done

linked_app="$fixture_root/linked.app"
ln -s "$ga_app" "$linked_app"
if cfw_require_fixed_publication_app_path "$fixture_root" "$active_product_version" "$active_ga_build" "$linked_app" 2>"$fixture_root/symlink.stderr"; then
  echo "error: path contract accepted a symlinked GA app" >&2
  exit 1
fi
grep -Fq "available absolute signed app" "$fixture_root/symlink.stderr"

noncanonical_repository="$fixture_root/target/../..$(printf '/%s' "$(basename "$fixture_root")")"
if cfw_require_fixed_publication_app_path "$noncanonical_repository" "$active_product_version" "$active_ga_build" "$ga_app" 2>"$fixture_root/repository.stderr"; then
  echo "error: path contract accepted a noncanonical repository" >&2
  exit 1
fi

python_status=0
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/production_release_evidence.py" seal \
  >"$fixture_root/python.stdout" 2>"$fixture_root/python.stderr" || python_status=$?
if [[ "$python_status" -ne 2 ]]; then
  echo "error: Python boundary did not reject an unknown stage command with usage" >&2
  exit 1
fi
[[ ! -s "$fixture_root/python.stdout" ]]
grep -Fq "invalid choice" "$fixture_root/python.stderr"

for unknown in --seal-assets --prepare-physical-candidate-manifest --validation --final; do
  gate_status=0
  /bin/bash -p "$gate_fixture/scripts/release_publication_gate.sh" "$unknown" \
    >"$fixture_root/gate.stdout" 2>"$fixture_root/gate.stderr" || gate_status=$?
  if [[ "$gate_status" -ne 2 ]]; then
    echo "error: publication gate did not reject unknown command with usage: $unknown" >&2
    exit 1
  fi
  [[ ! -s "$fixture_root/gate.stdout" ]]
  grep -Fq "error: choose one of --capture-hosted-ci" "$fixture_root/gate.stderr"
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
if grep -Eq 'target/candidates/[^/]+/signed/' "$repo_root/scripts/release_publication_gate.sh"; then
  echo "error: publication gate retains the retired signed-app root" >&2
  exit 1
fi
if grep -Fq "release-build/" "$repo_root/scripts/release_publication_gate.sh"; then
  echo "error: publication gate retains the retired release-build root" >&2
  exit 1
fi

echo "single-GA publication path and unknown-command fixture passed"
