#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
app_path="${1:-$repo_root/target/candidates/0.4.0/unsigned/cargo/release/bundle/macos/Clash for Mac.app}"
native_products_root="${2:-$repo_root/target/candidates/0.4.0/unsigned/native-products}"
[[ "$app_path" == /* ]] || {
  echo "error: candidate app path must be absolute" >&2
  exit 1
}
[[ "$native_products_root" == /* ]] || {
  echo "error: native products root must be absolute" >&2
  exit 1
}
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_candidate_bundle.py" \
  "$app_path" \
  --native-products-root "$native_products_root"
