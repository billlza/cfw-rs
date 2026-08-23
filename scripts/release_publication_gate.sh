#!/bin/bash -p
# Verify the sealed, legally reviewed publication evidence for the exact signed
# 0.4.0 application. This gate has no success override and performs no network
# access; evidence preparation is an explicit earlier release phase.
set -euo pipefail
unset CDPATH

publication_repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$publication_repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$publication_repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
# shellcheck source=scripts/release_publication_path_contract.sh
source "$publication_repo_root/scripts/release_publication_path_contract.sh"
publication_signed_app="$publication_repo_root/target/candidates/0.4.0/signed/Clash for Mac.app"
publication_evidence_root="$publication_repo_root/target/candidates/0.4.0/release/publication"

release_native_products_root_for_app() {
  local app_path="${1:-}"
  local build_number
  build_number="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
    "$app_path/Contents/Info.plist" 2>/dev/null)" || {
    echo "error: cannot read release CFBundleVersion" >&2
    return 1
  }
  [[ "$build_number" =~ ^[1-9][0-9]*$ ]] || {
    echo "error: release CFBundleVersion is not one canonical positive integer" >&2
    return 1
  }
  printf '%s\n' \
    "$publication_repo_root/target/candidates/0.4.0/release-build/$build_number/native-products"
}

verify_release_publication_evidence() {
  local app_path="${1:-}"
  cfw_require_fixed_publication_app_path "$publication_repo_root" "$app_path" ||
    return 1
  if [[ ! -d "$publication_evidence_root" || -L "$publication_evidence_root" ]]; then
    echo "error: publication evidence directory is missing or is a symlink: $publication_evidence_root" >&2
    return 1
  fi
  # Publication artifacts may only be created once the immutable sealed outer
  # Evidence Manifest authorizes publication: P0 source implementation, unsigned
  # CI, signed-installed evidence, sealed closure, the final-candidate binding,
  # and release-secret custody must all pass. A missing, blocked, or hand-edited
  # manifest refuses publication; there is no override and no fallback.
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/sealed_evidence_manifest.py" \
    publication-gate
  local native_products_root
  native_products_root="$(release_native_products_root_for_app "$app_path")" || return 1
  /bin/bash -p \
    "$publication_repo_root/scripts/verify_release_app.sh" \
    "$app_path" \
    "$native_products_root"
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/publication_evidence.py" \
    verify \
    --evidence "$publication_evidence_root" \
    --app "$app_path"
}

verify_release_upload_artifacts() {
  local version="${1:-}"
  if [[ -z "$version" ]]; then
    echo "error: upload-artifact gate requires an explicit version" >&2
    return 1
  fi
  # Packaging authorization and upload authorization are separate gates. The
  # latter first reopens the exact app/publication closure semantically, then
  # accepts only the final distribution seal after every package, component
  # seal, candidate manifest, CCS, SBOM, and legal-review byte recomputes.
  verify_release_publication_evidence "$publication_signed_app"
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/release_artifact_set.py" \
    verify-release \
    --repository "$publication_repo_root" \
    --release-root "$publication_repo_root/target/candidates/0.4.0/release" \
    --version "$version"
}

seal_release_upload_artifacts() {
  local version="${1:-}"
  if [[ -z "$version" ]]; then
    echo "error: distribution-seal gate requires an explicit version" >&2
    return 1
  fi
  # The distribution seal is deliberately post-packaging: it can be created
  # only after the app/publication lane and both byte-proven package sets pass.
  verify_release_publication_evidence "$publication_signed_app"
  cfw_run_release_python_script \
    "$publication_repo_root" \
    "$publication_repo_root/scripts/release_artifact_set.py" \
    seal-release \
    --repository "$publication_repo_root" \
    --release-root "$publication_repo_root/target/candidates/0.4.0/release" \
    --version "$version"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "${1:-}" == "--seal-assets" ]]; then
    [[ $# -eq 2 ]] || {
      echo "error: usage: release_publication_gate.sh --seal-assets VERSION" >&2
      exit 1
    }
    seal_release_upload_artifacts "$2"
  elif [[ "${1:-}" == "--upload-assets" ]]; then
    [[ $# -eq 2 ]] || {
      echo "error: usage: release_publication_gate.sh --upload-assets VERSION" >&2
      exit 1
    }
    verify_release_upload_artifacts "$2"
  else
    [[ $# -eq 1 ]] || {
      echo "error: usage: release_publication_gate.sh SIGNED_APP" >&2
      exit 1
    }
    verify_release_publication_evidence "$1"
  fi
fi
