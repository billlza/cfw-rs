#!/usr/bin/env bash
# Run the pinned macOS/arm64 libbox source tests with a fresh build cache and
# the already-sealed release Go/module trees.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/go_release_environment.sh
source "$repo_root/scripts/go_release_environment.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
# shellcheck source=scripts/release_cargo_inputs.sh
source "$repo_root/scripts/release_cargo_inputs.sh"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
cfw_select_release_apple_toolchain
libbox_load_module_cache_contract "$repo_root"

[[ $# -eq 0 ]] || {
  echo "error: usage: scripts/test_libbox_source.sh" >&2
  exit 1
}
source_input="${SING_BOX_SOURCE:-}"
[[ -n "$source_input" && -d "$source_input" && ! -L "$source_input" ]] || {
  echo "error: SING_BOX_SOURCE must name the real patched source directory" >&2
  exit 1
}
source_root="$(cd "$source_input" && pwd -P)"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
go_bin="$toolchain_root/go-$GO_VERSION/bin/go"
[[ -x "${CFW_RELEASE_CARGO_EXECUTABLE:-}" ]] || {
  echo "error: select the closed release Cargo executable before source validation" >&2
  exit 1
}

SING_BOX_SOURCE="$source_root" "$repo_root/scripts/prepare_libbox_modules.sh"
libbox_validate_patched_source "$repo_root" "$source_root"
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"

export GOPATH="$toolchain_root/go-workspace"
export GOMODCACHE="$GOPATH/pkg/mod"
cache_parent="${RUNNER_TEMP:-$repo_root/target/release-build-cache}"
mkdir -p "$cache_parent"
[[ -d "$cache_parent" && ! -L "$cache_parent" ]] || {
  echo "error: Go test cache parent must be a real directory" >&2
  exit 1
}
go_build_cache="$(mktemp -d "$cache_parent/cfw-go-tests.XXXXXX")"
trap '/bin/rm -rf -- "$go_build_cache"' EXIT
export GOCACHE="$go_build_cache"
configure_offline_go_environment
build_source_root="$(prepare_libbox_build_workspace "$source_root" "$go_bin" "$go_build_cache/workspace")"
CC="$(/usr/bin/xcrun --find clang)"
SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
export CC SDKROOT
libbox_test_ldflags="-checklinkname=0 '-extld=$repo_root/scripts/libbox_clang_linker.sh'"
readonly libbox_test_ldflags

# These fixtures come from the actual Rust projection. Always supply them to
# the Go integration tests so a missing fixture cannot turn into skipped DNS
# policy coverage in the release lane. They contain synthetic endpoints only.
export CFW_DNS_PROJECTED_FIXTURE_DIR="$go_build_cache/dns-projections"
cfw_run_with_release_cargo_runtime "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" \
  test --locked --offline -p cfw-singbox-config --lib tests::dns_policy
for fixture in mixed.json tunnel.json filter.json named.json; do
  [[ -s "$CFW_DNS_PROJECTED_FIXTURE_DIR/$fixture" ]] || {
    echo "error: Rust DNS projection fixture is missing: $fixture" >&2
    exit 1
  }
done

(
  cd "$build_source_root"
  "$go_bin" mod verify
  "$go_bin" test -count=1 -race ./cmd/cfm-build-workspace
  "$go_bin" test -count=1 -race -ldflags="$libbox_test_ldflags" \
    -tags "$LIBBOX_BUILD_TAGS" "${LIBBOX_RACE_TEST_PACKAGES[@]}"
  "$go_bin" test -count=1 -ldflags="$libbox_test_ldflags" \
    -tags "$LIBBOX_BUILD_TAGS" \
    "${LIBBOX_TEST_PACKAGES[@]}"
  "$go_bin" test -run '^$' -ldflags="$libbox_test_ldflags" \
    -tags "$LIBBOX_BUILD_TAGS" "${LIBBOX_COMPILE_TEST_PACKAGES[@]}"
  "$go_bin" vet -tags "$LIBBOX_BUILD_TAGS" \
    "${LIBBOX_VET_PACKAGES[@]}"
)

libbox_validate_patched_source "$repo_root" "$source_root"
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
