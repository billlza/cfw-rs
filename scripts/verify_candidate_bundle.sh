#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
app_path="${1:-$repo_root/target/candidates/0.4.0/unsigned/cargo/release/bundle/macos/Clash for Mac.app}"
native_products_root="${2:-$repo_root/target/candidates/0.4.0/unsigned/native-products}"
unsigned_host_option="${3:-}"
[[ $# -le 3 ]] || {
  echo "error: usage: scripts/verify_candidate_bundle.sh [APP [NATIVE_PRODUCTS [--require-unsigned-host]]]" >&2
  exit 1
}
[[ -z "$unsigned_host_option" || "$unsigned_host_option" == "--require-unsigned-host" ]] || {
  echo "error: unsupported candidate verification option: $unsigned_host_option" >&2
  exit 1
}
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
)
if [[ -n "$unsigned_host_option" ]]; then
  arguments+=("$unsigned_host_option")
fi
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_candidate_bundle.py" \
  "${arguments[@]}"
