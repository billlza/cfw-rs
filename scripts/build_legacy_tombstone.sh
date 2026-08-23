#!/usr/bin/env bash
# Build the one-release legacy Service Mode tombstone in an isolated target
# directory and bind the staged binary to its small current source surface.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_python_launcher.sh
source "$repo_root/scripts/release_python_launcher.sh"
# shellcheck source=scripts/release_cargo_inputs.sh
source "$repo_root/scripts/release_cargo_inputs.sh"
: "${CFW_BUILD_NUMBER:?set the candidate-specific positive integer build number}"
: "${CFW_NATIVE_PRODUCTS_OUTPUT:?set the candidate-specific native products output root}"

usage() {
  echo "usage: scripts/build_legacy_tombstone.sh --unsigned|--developer-id" >&2
  exit 2
}

python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
if [[ "$python_bin" != /* || ! -x "$python_bin" ]]; then
  echo "error: the closed release Python executable is required" >&2
  exit 1
fi

validate_candidate_output() {
  PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
    "$repo_root" "$CFW_BUILD_NUMBER" "$CFW_NATIVE_PRODUCTS_OUTPUT" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import candidate_native_products_output

print(candidate_native_products_output(Path(sys.argv[1]), sys.argv[3], sys.argv[2]))
PY
}

[[ $# -eq 1 ]] || usage
case "$1" in
  --unsigned)
    signing_mode="unsigned-validation"
    ;;
  --developer-id)
    signing_mode="developer-id"
    ;;
  *)
    usage
    ;;
esac

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "error: the legacy tombstone release artifact requires arm64 macOS" >&2
  exit 1
fi
native_products_root="$(validate_candidate_output)" || exit 1
if [[ "$native_products_root" != "$CFW_NATIVE_PRODUCTS_OUTPUT" ]]; then
  echo "error: tombstone output is not canonical" >&2
  exit 1
fi
if [[ "${CFW_RELEASE_RUSTC_EXECUTABLE:-}" != /* || \
  "${CFW_RELEASE_CARGO_EXECUTABLE:-}" != /* || \
  "${CARGO_HOME:-}" != /* ]]; then
  echo "error: the closed Rust toolchain and candidate Cargo runtime are required" >&2
  exit 1
fi
cfw_verify_release_cargo_runtime "$repo_root" "$CARGO_HOME"
if [[ "$($CFW_RELEASE_RUSTC_EXECUTABLE --version | /usr/bin/awk '{print $2}')" != "$RUST_VERSION" ]]; then
  echo "error: rustc $RUST_VERSION is required" >&2
  exit 1
fi
if [[ "$($CFW_RELEASE_CARGO_EXECUTABLE --version | /usr/bin/awk '{print $2}')" != "$RUST_VERSION" ]]; then
  echo "error: cargo $RUST_VERSION is required" >&2
  exit 1
fi
rust_host="$($CFW_RELEASE_RUSTC_EXECUTABLE -vV | /usr/bin/awk '$1 == "host:" { print $2 }')"
if [[ "$rust_host" != "aarch64-apple-darwin" ]]; then
  echo "error: the pinned Rust host must be aarch64-apple-darwin" >&2
  exit 1
fi

unset CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS
export CARGO_NET_OFFLINE=true
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"

output_root="$native_products_root/CFWLegacyTombstone"
manifest_path="$native_products_root/CFWLegacyTombstone.manifest.json"
if [[ -e "$output_root" || -L "$output_root" || -e "$manifest_path" || -L "$manifest_path" ]]; then
  echo "error: refusing to replace an existing tombstone artifact or manifest" >&2
  exit 1
fi

mkdir -p "$native_products_root"
if [[ "$(validate_candidate_output)" != "$native_products_root" ]]; then
  echo "error: tombstone output changed while it was being created" >&2
  exit 1
fi
build_root="$(mktemp -d "${native_products_root%/native-products}/.tombstone-build.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
(
  cd "$repo_root"
  CARGO_TARGET_DIR="$build_root" "$CFW_RELEASE_CARGO_EXECUTABLE" build \
    --offline \
    --locked \
    --release \
    --target aarch64-apple-darwin \
    -p cfw-legacy-tombstone
)
cfw_verify_release_cargo_runtime "$repo_root" "$CARGO_HOME"

built_binary="$build_root/aarch64-apple-darwin/release/cfw-helper-tombstone"
if [[ ! -f "$built_binary" || -L "$built_binary" ]]; then
  echo "error: isolated build did not produce a regular tombstone binary" >&2
  exit 1
fi
if [[ "$(lipo -archs "$built_binary")" != "arm64" ]]; then
  echo "error: legacy tombstone must be thin arm64" >&2
  exit 1
fi
"${CFW_RELEASE_PYTHON_EXECUTABLE:-python3}" -I -S -B -W error - \
  "$built_binary" <<'PY'
import sys
from pathlib import Path

markers = (
    b"mihomo",
    b"clash-rs",
    b"clash-darwin",
    b"CFW_CORE_KIND",
    b"core install",
    b"want_core",
)
assert any(marker in b"fixture:mihomo" for marker in markers)
payload = Path(sys.argv[1]).read_bytes()
found = [marker.decode("ascii") for marker in markers if marker in payload]
if found:
    raise SystemExit(f"error: legacy tombstone contains retired supervisor markers: {found}")
PY

mkdir -p "$output_root"
/usr/bin/install -m 0755 "$built_binary" "$output_root/cfw-helper-tombstone"
if [[ "$signing_mode" == "developer-id" ]]; then
  : "${MACOS_SIGN_IDENTITY:?set the exact Developer ID Application identity}"
  if [[ "$MACOS_SIGN_IDENTITY" != "Developer ID Application:"*"(YKUPL7Z869)" ]]; then
    echo "error: tombstone signing identity must belong to Team ID YKUPL7Z869" >&2
    exit 1
  fi
  if ! security find-identity -v -p codesigning | grep -Fq "\"$MACOS_SIGN_IDENTITY\""; then
    echo "error: requested Developer ID identity is unavailable" >&2
    exit 1
  fi
  codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$MACOS_SIGN_IDENTITY" \
    "$output_root/cfw-helper-tombstone"
  codesign --verify --strict --verbose=4 "$output_root/cfw-helper-tombstone"
  signature="$(codesign -d --verbose=4 "$output_root/cfw-helper-tombstone" 2>&1)"
  if [[ "$signature" != *"TeamIdentifier=YKUPL7Z869"* ]] ||
    [[ "$signature" != *"Authority=Developer ID Application:"*"(YKUPL7Z869)"* ]] ||
    [[ "$signature" != *"Timestamp="* ]] ||
    [[ "$signature" == *"Timestamp=none"* ]] ||
    [[ "$signature" == *"Signature=adhoc"* ]]; then
    echo "error: staged tombstone does not have the required Developer ID signature" >&2
    exit 1
  fi
fi
source_sha256="$(shasum -a 256 "$repo_root/crates/cfw-legacy-tombstone/src/main.rs" | awk '{print $1}')"
manifest_sha256="$(shasum -a 256 "$repo_root/crates/cfw-legacy-tombstone/Cargo.toml" | awk '{print $1}')"
lock_sha256="$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_artifact.py" \
  "$output_root" \
  --output "$manifest_path" \
  --metadata "artifactKind=legacy-service-tombstone-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=$CFW_BUILD_NUMBER" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "signingMode=$signing_mode" \
  --metadata "rustVersion=$RUST_VERSION" \
  --metadata "sourceSha256=$source_sha256" \
  --metadata "cargoManifestSha256=$manifest_sha256" \
  --metadata "cargoLockSha256=$lock_sha256"

echo "legacy Service Mode tombstone staged: $output_root"
echo "signing mode: $signing_mode"
echo "build number: $CFW_BUILD_NUMBER"
