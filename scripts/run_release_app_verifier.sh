#!/bin/bash -p
# Bootstrap the fixed post-notarization app verifier from the physical evidence
# runner's minimal environment. This wrapper owns the complete verifier argv.
set -euo pipefail
unset CDPATH

if [[ $# -ne 0 ]]; then
  echo "error: the release app verifier wrapper accepts no arguments" >&2
  exit 2
fi

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain

readonly app_path="$repo_root/target/candidates/0.4.0/ga/40039/signed/Clash for Mac.app"
readonly native_products="$repo_root/target/candidates/0.4.0/ga/40039/signing-output/signed-native-products"
exec /bin/bash -p \
  "$repo_root/scripts/verify_release_app.sh" \
  "$app_path" \
  "$native_products" \
  --context canonical-native-content
