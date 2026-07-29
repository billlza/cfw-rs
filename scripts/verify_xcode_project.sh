#!/usr/bin/env bash
# Prove that the tracked Xcode project and generated plists are exact outputs
# of the pinned XcodeGen source build and project.yml.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
xcodegen_root="$toolchain_root/xcodegen-$XCODEGEN_VERSION"
xcodegen="$xcodegen_root/bin/xcodegen"
native_root="$repo_root/native/macos"

cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"
[[ "$("$xcodegen" --version)" == "Version: $XCODEGEN_VERSION" ]] || {
  echo "error: pinned XcodeGen $XCODEGEN_VERSION is unavailable" >&2
  exit 1
}

staging="$(mktemp -d "$repo_root/target/xcode-project-check.XXXXXX")"
cleanup() {
  if [[ -n "${staging:-}" && -d "$staging" && "$staging" == "$repo_root/target/xcode-project-check."* ]]; then
    /bin/rm -r "$staging"
  fi
}
trap cleanup EXIT
staged_native="$staging/native/macos"
mkdir -p "$staged_native"
for input in Config Headers Sources SystemExtension Tests; do
  /usr/bin/ditto --noqtn "$native_root/$input" "$staged_native/$input"
done
/usr/bin/ditto --noqtn "$native_root/project.yml" "$staged_native/project.yml"

"$xcodegen" generate \
  --spec "$staged_native/project.yml" \
  --project "$staged_native" \
  --project-root "$staged_native" \
  --no-env \
  --quiet

/usr/bin/diff -ruN "$native_root/CFWNative.xcodeproj" "$staged_native/CFWNative.xcodeproj"
/usr/bin/diff -qr "$native_root/Config" "$staged_native/Config"
cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"

echo "tracked Xcode project verified: XcodeGen $XCODEGEN_VERSION ($XCODEGEN_COMMIT)"
