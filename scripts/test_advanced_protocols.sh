#!/bin/bash -p
# Real, local protocol interoperability; no system proxy, DNS or route mutations.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
[[ $# -eq 2 && "$1" == /* ]] || {
  echo "usage: scripts/test_advanced_protocols.sh ABSOLUTE_PATCHED_SOURCE LOCAL_IPV4" >&2
  exit 1
}
protocol_source="$1"
protocol_address="$2"
source "$repo_root/scripts/dependency_pins.env"
source "$repo_root/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment production
cfw_select_release_apple_toolchain
source "$repo_root/scripts/release_toolchain_contract.sh"
source "$repo_root/scripts/libbox_source_contract.sh"
source "$repo_root/scripts/go_release_environment.sh"
libbox_validate_patched_source "$repo_root" "$protocol_source"

protocol_toolchains="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
cfw_verify_go_toolchain_tree "$repo_root" "$protocol_toolchains"
cfw_verify_go_module_cache_tree "$repo_root" "$protocol_toolchains"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
cd "$repo_root"
cfw_run_with_release_cargo_runtime "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" \
  build --locked -p cfw-singbox-config --example project-profile

mkdir -p "$repo_root/target/release-build-cache"
protocol_cache="$(mktemp -d "$repo_root/target/release-build-cache/protocols.XXXXXX")"
trap '/bin/rm -rf -- "$protocol_cache"' EXIT
export GOPATH="$protocol_toolchains/go-workspace"
export GOMODCACHE="$GOPATH/pkg/mod"
export GOCACHE="$protocol_cache"
configure_offline_go_environment
protocol_go="$protocol_toolchains/go-$GO_VERSION/bin/go"
cd "$protocol_source"
"$protocol_go" test -race -ldflags=-checklinkname=0 -tags "$LIBBOX_BUILD_TAGS" ./protocol/group ./protocol/socks
"$protocol_go" vet -tags "$LIBBOX_BUILD_TAGS" \
  "$repo_root/scripts/fixtures/advanced_protocol_probe.go" \
  "$repo_root/scripts/fixtures/advanced_dns_probe.go"
"$protocol_go" run -race -ldflags=-checklinkname=0 -tags "$LIBBOX_BUILD_TAGS" \
  "$repo_root/scripts/fixtures/advanced_protocol_probe.go" \
  "$repo_root/scripts/fixtures/advanced_dns_probe.go" \
  "$repo_root/target/debug/examples/project-profile" "$protocol_address"
