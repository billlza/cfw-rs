#!/bin/bash -p
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/release_python_launcher.sh
source "$repo_root/scripts/release_python_launcher.sh"
[[ $# == 4 && "$3" == "--context" ]] || {
  echo "error: usage: scripts/verify_candidate_bundle.sh APP NATIVE_PRODUCTS --context CONTEXT" >&2
  exit 1
}
app_path="$1"
native_products_root="$2"
verification_context="$4"
[[ "$app_path" == /* ]] || {
  echo "error: candidate app path must be absolute" >&2
  exit 1
}
[[ "$native_products_root" == /* ]] || {
  echo "error: native products root must be absolute" >&2
  exit 1
}
arguments=(
  "$app_path"
  --native-products-root "$native_products_root"
  --context "$verification_context"
)
cfw_run_release_python_script \
  "$repo_root" \
  "$repo_root/scripts/verify_candidate_bundle.py" \
  "${arguments[@]}"
