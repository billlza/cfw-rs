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
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
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
module_cache="$gopath/pkg/mod"
module_manifest="$toolchain_root/go-module-cache.manifest.json"
export GOBIN="$gopath/bin"
export GOPATH="$gopath"
export GOMODCACHE="$module_cache"
export GOCACHE="$toolchain_root/go-build-cache"
configure_networked_go_environment

libbox_validate_patched_source "$repo_root" "$source_root"
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
if [[ "$($go_bin version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go toolchain identity mismatch" >&2
  exit 1
fi
if [[ -e "$module_manifest" || -L "$module_manifest" ]]; then
  cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
  echo "verified Go module cache ready: $module_cache"
  exit 0
fi

(
  cd "$source_root"
  # Populate the exact graph-selected binder module before checking its sealed-cache
  # location. This is the explicit networked preparation phase; release builds
  # remain offline and cannot perform this download.
  "$go_bin" mod download "github.com/sagernet/gomobile@$GOMOBILE_VERSION"
  expected_gomobile_dir="$GOMODCACHE/github.com/sagernet/gomobile@$GOMOBILE_VERSION"
  expected_gomobile_module="github.com/sagernet/gomobile $GOMOBILE_VERSION $GOMOBILE_MODULE_SUM $expected_gomobile_dir"
  if ! observed_gomobile_module="$(
    "$go_bin" list -m -mod=readonly \
      -f '{{.Path}} {{.Version}} {{.Sum}} {{.Dir}}' \
      github.com/sagernet/gomobile
  )"; then
    echo "error: pinned gomobile module is not resolvable during cache preparation" >&2
    exit 1
  fi
  if [[ "$observed_gomobile_module" != "$expected_gomobile_module" ]]; then
    echo "error: sing-box gomobile graph mismatch: expected '$expected_gomobile_module', got '$observed_gomobile_module'" >&2
    exit 1
  fi
  "$go_bin" list -mod=readonly \
    github.com/sagernet/gomobile/bind \
    github.com/sagernet/gomobile/bind/objc >/dev/null || {
    echo "error: module preparation lacks the exact pinned gomobile bind package closure" >&2
    exit 1
  }
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
  # The deterministic source lane also compiles and runs these packages' test
  # graphs. Seal that exact test-only closure (notably testify) now so the
  # later offline test cannot attempt a network lookup.
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
    "$go_bin" list \
      -deps \
      -test \
      -mod=readonly \
      -tags "$LIBBOX_BUILD_TAGS" \
      ./dns ./option ./common/dialer ./daemon ./experimental/libbox >/dev/null
  "$go_bin" mod verify
)
libbox_validate_patched_source "$repo_root" "$source_root"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$module_cache" \
  --output "$module_manifest" \
  --algorithm sha256-tree-v2 \
  --metadata "artifactKind=pinned-go-module-cache-v1" \
  --metadata "buildTags=$LIBBOX_BUILD_TAGS" \
  --metadata "goVersion=$GO_VERSION" \
  --metadata "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256" \
  --metadata "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256" \
  --metadata "platform=darwin-arm64" \
  --metadata "sourceCommit=$SING_BOX_COMMIT"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"

echo "verified Go module cache ready: $module_cache"
