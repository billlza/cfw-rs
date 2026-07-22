#!/usr/bin/env bash
# Verify the sealed, legally reviewed publication evidence for the exact signed
# 0.4.0 application. This gate has no success override and performs no network
# access; evidence preparation is an explicit earlier release phase.
set -euo pipefail

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
  local native_products_root
  native_products_root="$(release_native_products_root_for_app "$app_path")" || return 1
  "$publication_repo_root/scripts/verify_release_app.sh" "$app_path" "$native_products_root"
  /usr/bin/python3 "$publication_repo_root/scripts/publication_evidence.py" verify \
    --evidence "$publication_evidence_root" \
    --app "$app_path"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  verify_release_publication_evidence "${1:-}"
fi
