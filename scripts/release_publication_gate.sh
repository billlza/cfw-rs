#!/bin/bash -p
# Closed shell boundary for the single-GA three-stage release transaction.
set -euo pipefail
unset CDPATH

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --seal-assets | --prepare-physical-candidate-manifest | --validation | --final)
      echo "error: retired publication command is forbidden: ${1}" >&2
      exit 2
      ;;
  esac
fi

publication_repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$publication_repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$publication_repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
# shellcheck source=scripts/release_publication_path_contract.sh
source "$publication_repo_root/scripts/release_publication_path_contract.sh"

readonly publication_ga_root="$publication_repo_root/target/candidates/0.4.0/ga/40035"
readonly publication_native_products="$publication_ga_root/signing-output/signed-native-products"

run_production_ga_stage() {
  [[ $# -ge 1 ]] || {
    echo "error: GA stage command is required" >&2
    return 1
  }
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/production_release_evidence.py" \
    "$@"
}

run_release_artifact_set() {
  [[ $# -ge 1 ]] || {
    echo "error: release artifact-set command is required" >&2
    return 1
  }
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/release_artifact_set_cli.py" \
    "$@"
}

run_hosted_ci_receipt() {
  [[ $# -ge 1 ]] || {
    echo "error: hosted CI receipt command is required" >&2
    return 1
  }
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/github_hosted_ci_receipt.py" \
    "$@"
}

release_native_products_root_for_app() {
  [[ $# -eq 1 ]] || {
    echo "error: signed-native-products admission requires the fixed GA app" >&2
    return 1
  }
  cfw_require_fixed_publication_app_path "$publication_repo_root" "$1" ||
    return 1
  if [[ ! -d "$publication_native_products" || -L "$publication_native_products" ]]; then
    echo "error: fixed GA signed-native-products root is unavailable: $publication_native_products" >&2
    return 1
  fi
  printf '%s\n' "$publication_native_products"
}

verify_release_prepackage_evidence() {
  [[ $# -eq 1 ]] || {
    echo "error: prepackage verification requires the fixed signed app" >&2
    return 1
  }
  local app_path="$1"
  cfw_require_fixed_publication_app_path "$publication_repo_root" "$app_path" ||
    return 1
  run_production_ga_stage verify prepackage
  /bin/bash -p \
    "$publication_repo_root/scripts/verify_release_app.sh" \
    "$app_path" \
    "$publication_native_products" \
    --context canonical-native-content
}

verify_release_ga_acceptance_evidence() {
  [[ $# -eq 0 ]] || {
    echo "error: ga-acceptance verification has no caller-selected inputs" >&2
    return 1
  }
  run_production_ga_stage verify ga-acceptance
}

verify_release_publication_evidence() {
  [[ $# -eq 0 ]] || {
    echo "error: publication verification has no legacy signed-app argument" >&2
    return 1
  }
  run_production_ga_stage verify publication
}

verify_release_upload_artifacts() {
  [[ $# -eq 1 && "$1" == "0.4.0" ]] || {
    echo "error: upload authorization is fixed to version 0.4.0" >&2
    return 1
  }
  run_hosted_ci_receipt verify
  verify_release_publication_evidence "${@:2}"
  run_release_artifact_set \
    verify-release \
    --repository "$publication_repo_root" \
    --version "0.4.0"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --capture-hosted-ci)
      [[ $# -eq 2 ]] || {
        echo "error: usage: release_publication_gate.sh --capture-hosted-ci RUN_ID" >&2
        exit 2
      }
      run_hosted_ci_receipt capture --run-id "$2"
      ;;
    --verify-hosted-ci)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --verify-hosted-ci" >&2
        exit 2
      }
      run_hosted_ci_receipt verify
      ;;
    --seal-prepackage)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --seal-prepackage" >&2
        exit 2
      }
      run_production_ga_stage prepackage
      ;;
    --seal-ga-acceptance)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --seal-ga-acceptance" >&2
        exit 2
      }
      run_production_ga_stage ga-acceptance
      ;;
    --seal-publication)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --seal-publication" >&2
        exit 2
      }
      run_production_ga_stage publication
      run_production_ga_stage verify publication
      run_release_artifact_set \
        seal-release \
        --repository "$publication_repo_root" \
        --version "0.4.0"
      ;;
    --verify-prepackage)
      [[ $# -eq 2 ]] || {
        echo "error: usage: release_publication_gate.sh --verify-prepackage SIGNED_APP" >&2
        exit 2
      }
      verify_release_prepackage_evidence "$2"
      ;;
    --verify-ga-acceptance)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --verify-ga-acceptance" >&2
        exit 2
      }
      shift
      verify_release_ga_acceptance_evidence "$@"
      ;;
    --verify-publication)
      [[ $# -eq 1 ]] || {
        echo "error: usage: release_publication_gate.sh --verify-publication" >&2
        exit 2
      }
      shift
      verify_release_publication_evidence "$@"
      ;;
    --upload-assets)
      [[ $# -eq 2 ]] || {
        echo "error: usage: release_publication_gate.sh --upload-assets 0.4.0" >&2
        exit 2
      }
      verify_release_upload_artifacts "$2"
      ;;
    *)
      echo "error: choose one of --capture-hosted-ci, --verify-hosted-ci, --seal-prepackage, --seal-ga-acceptance, --seal-publication, --verify-prepackage, --verify-ga-acceptance, --verify-publication, or --upload-assets" >&2
      exit 2
      ;;
  esac
fi
