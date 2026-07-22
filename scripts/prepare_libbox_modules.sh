#!/usr/bin/env bash
# Explicit, networked dependency preparation. Release builds never call this
# script; they consume only the already-verified local Go module cache.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/go_release_environment.sh
source "$repo_root/scripts/go_release_environment.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
source_input="${SING_BOX_SOURCE:-}"
if [[ -z "$source_input" ]]; then
  echo "error: set SING_BOX_SOURCE to the materialized patched sing-box checkout" >&2
  exit 1
fi
if [[ ! -d "$source_input" || -L "$source_input" ]]; then
  echo "error: SING_BOX_SOURCE must be a real directory, not a symlink" >&2
  exit 1
fi
source_root="$(cd "$source_input" && pwd -P)"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
go_bin="$toolchain_root/go-$GO_VERSION/bin/go"
gopath="$toolchain_root/go-workspace"
export GOBIN="$gopath/bin"
export GOPATH="$gopath"
export GOMODCACHE="$gopath/pkg/mod"
export GOCACHE="$toolchain_root/go-build-cache"
configure_networked_go_environment

libbox_validate_patched_source "$repo_root" "$source_root"
if [[ "$($go_bin version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go toolchain identity mismatch" >&2
  exit 1
fi

(
  cd "$source_root"
  # Resolve only the packages reachable by the single supported release
  # target. `go mod download all` also fetches very large Cronet binaries for
  # Linux, Windows, Android, iOS and tvOS that cannot enter a macOS/arm64
  # build; besides wasting bandwidth, those unrelated downloads make the
  # preparation step fragile without increasing release assurance.
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
    "$go_bin" list \
      -deps \
      -mod=readonly \
      -tags "$LIBBOX_BUILD_TAGS" \
      ./experimental/libbox >/dev/null
  "$go_bin" mod verify
)
libbox_validate_patched_source "$repo_root" "$source_root"

echo "verified Go module cache ready: $gopath/pkg/mod"
