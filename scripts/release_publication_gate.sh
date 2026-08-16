#!/usr/bin/env bash
# Verify the sealed, legally reviewed publication evidence for the exact signed
# 0.4.0 application. This gate has no success override and performs no network
# access; evidence preparation is an explicit earlier release phase.
set -euo pipefail

unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH \
  DYLD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_FRAMEWORK_PATH \
  DYLD_FALLBACK_LIBRARY_PATH
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

publication_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
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
  if [[ -z "$app_path" || "$app_path" != /* ]]; then
    echo "error: publication gate requires the absolute signed app path" >&2
    return 1
  fi
  if [[ ! -d "$app_path" || -L "$app_path" ]]; then
    echo "error: publication gate signed app is unavailable or is a symlink" >&2
    return 1
  fi
  local canonical_app
  canonical_app="$(cd "$app_path" && pwd -P)"
  if [[ "$canonical_app" != "$publication_signed_app" ]]; then
    echo "error: publication gate accepts only the fixed 0.4.0 signed app: $publication_signed_app" >&2
    return 1
  fi
  if [[ ! -d "$publication_evidence_root" || -L "$publication_evidence_root" ]]; then
    echo "error: publication evidence directory is missing or is a symlink: $publication_evidence_root" >&2
    return 1
  fi
  # Publication artifacts may only be created once the immutable sealed outer
  # Evidence Manifest authorizes publication: P0 source implementation, unsigned
  # CI, signed-installed evidence, sealed closure, the final-candidate binding,
  # and release-secret custody must all pass. A missing, blocked, or hand-edited
  # manifest refuses publication; there is no override and no fallback.
  PYTHONDONTWRITEBYTECODE=1 python3 -S -B \
    "$publication_repo_root/scripts/sealed_evidence_manifest.py" publication-gate
  local native_products_root
  native_products_root="$(release_native_products_root_for_app "$app_path")" || return 1
  "$publication_repo_root/scripts/verify_release_app.sh" "$app_path" "$native_products_root"
  /usr/bin/python3 -S -B \
    "$publication_repo_root/scripts/publication_evidence.py" verify \
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
  PYTHONDONTWRITEBYTECODE=1 python3 -S -B \
    "$publication_repo_root/scripts/release_artifact_set.py" verify-release \
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
  PYTHONDONTWRITEBYTECODE=1 python3 -S -B \
    "$publication_repo_root/scripts/release_artifact_set.py" seal-release \
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
