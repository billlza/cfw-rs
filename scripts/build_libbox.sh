#!/usr/bin/env bash
# Build the pinned libbox XCFramework from the exact materialized patched tree.
# This script is deliberately offline and never clones source or installs tools.
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
output_root="${LIBBOX_OUTPUT:-$repo_root/target/native-dependencies/Libbox.xcframework}"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
go_bin="$toolchain_root/go-$GO_VERSION/bin/go"
gopath="$toolchain_root/go-workspace"
gobin="$gopath/bin"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "error: libbox release builds support only arm64 macOS" >&2
  exit 1
fi
libbox_validate_patched_source "$repo_root" "$source_root"
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
if [[ -d "$(dirname "$source_root")/sing-box-for-apple" ]]; then
  echo "error: place the build checkout away from a sing-box-for-apple sibling; upstream would move the artifact" >&2
  exit 1
fi
if [[ ! -x "$go_bin" ]]; then
  echo "error: missing pinned Go toolchain; run scripts/bootstrap_release_toolchain.sh explicitly" >&2
  exit 1
fi
if [[ "$($go_bin version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: Go toolchain identity mismatch" >&2
  exit 1
fi
for binary in gomobile gobind; do
  if [[ ! -x "$gobin/$binary" ]]; then
    echo "error: missing pinned $binary at $gobin/$binary" >&2
    exit 1
  fi
  "$go_bin" version -m "$gobin/$binary" | awk \
    -v version="$GOMOBILE_VERSION" \
    -v module_sum="$GOMOBILE_MODULE_SUM" \
    '$1 == "mod" && $2 == "github.com/sagernet/gomobile" && $3 == version && $4 == module_sum { found = 1 } END { exit !found }'
done
if [[ -e "$output_root" || -L "$output_root" ]]; then
  echo "error: refusing to replace existing libbox output: $output_root" >&2
  exit 1
fi

export GOBIN="$gobin"
export GOPATH="$gopath"
export GOMODCACHE="$gopath/pkg/mod"
mkdir -p "$repo_root/target/release-build-cache"
go_build_cache="$(mktemp -d "$repo_root/target/release-build-cache/libbox.XXXXXX")"
trap '/bin/rm -rf -- "$go_build_cache"' EXIT
export GOCACHE="$go_build_cache"
export PATH="$gobin:$toolchain_root/go-$GO_VERSION/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# Apple's archive tools otherwise stamp the generated c-archive symbol table
# with the wall clock, making identical libbox inputs produce different bytes.
# Override any caller value so the release artifact is reproducible.
export ZERO_AR_DATE=1
configure_offline_go_environment
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"

(
  cd "$source_root"
  expected_gomobile_dir="$GOMODCACHE/github.com/sagernet/gomobile@$GOMOBILE_VERSION"
  expected_gomobile_module="github.com/sagernet/gomobile $GOMOBILE_VERSION $GOMOBILE_MODULE_SUM $expected_gomobile_dir"
  if ! observed_gomobile_module="$(
    "$go_bin" list -m -mod=readonly \
      -f '{{.Path}} {{.Version}} {{.Sum}} {{.Dir}}' \
      github.com/sagernet/gomobile
  )"; then
    echo "error: pinned gomobile module is not resolvable from the sealed cache" >&2
    exit 1
  fi
  if [[ "$observed_gomobile_module" != "$expected_gomobile_module" ]]; then
    echo "error: sing-box gomobile graph mismatch: expected '$expected_gomobile_module', got '$observed_gomobile_module'" >&2
    exit 1
  fi
  "$go_bin" list -mod=readonly \
    github.com/sagernet/gomobile/bind \
    github.com/sagernet/gomobile/bind/objc >/dev/null || {
    echo "error: sealed cache lacks the exact pinned gomobile bind package closure" >&2
    exit 1
  }
  "$go_bin" mod verify
  version_without_prefix="${SING_BOX_VERSION#v}"
  libbox_ldflags="-X github.com/sagernet/sing-box/constant.Version=$version_without_prefix -X internal/godebug.defaultGODEBUG=multipathtcp=0 -s -w -buildid= -checklinkname=0"
  "$gobin/gomobile" bind \
    -v \
    -target "$LIBBOX_APPLE_PLATFORM" \
    -macosversion "$MACOS_DEPLOYMENT_TARGET" \
    -libname=box \
    -tags-not-macos="$LIBBOX_NON_MACOS_TAGS" \
    -trimpath \
    -buildvcs=false \
    -ldflags "$libbox_ldflags" \
    -tags "$LIBBOX_BUILD_TAGS" \
    ./experimental/libbox
)

built_framework="$source_root/Libbox.xcframework"
if [[ ! -d "$built_framework" || -L "$built_framework" ]]; then
  echo "error: pinned build did not produce $built_framework" >&2
  exit 1
fi

# gomobile currently emits quoted sibling imports in framework headers. Clang
# diagnoses those imports under the release warning policy because framework
# headers must name their module explicitly. Normalize only the three known
# generated imports, then reject every remaining quoted include so a generator
# change cannot silently weaken the build.
while IFS= read -r -d '' header; do
  /usr/bin/sed -i '' \
    -e 's|#include "ref.h"|#include <Libbox/ref.h>|g' \
    -e 's|#include "Universe.objc.h"|#include <Libbox/Universe.objc.h>|g' \
    -e 's|#include "Libbox.objc.h"|#include <Libbox/Libbox.objc.h>|g' \
    "$header"
done < <(/usr/bin/find "$built_framework" -path '*/Headers/*.h' -type f -print0)
if /usr/bin/grep -R -E '^#include "' "$built_framework" --include='*.h'; then
  echo "error: generated libbox framework contains an unnormalized quoted include" >&2
  exit 1
fi

mkdir -p "$(dirname "$output_root")"
/bin/mv "$built_framework" "$output_root"
libbox_validate_patched_source "$repo_root" "$source_root"
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
go_toolchain_tree_sha256="$(cfw_release_toolchain_tree_sha256 \
  "$toolchain_root/go-$GO_VERSION.manifest.json")"
go_tools_tree_sha256="$(cfw_release_toolchain_tree_sha256 \
  "$toolchain_root/go-workspace-bin.manifest.json")"
go_module_cache_tree_sha256="$(cfw_release_toolchain_tree_sha256 \
  "$toolchain_root/go-module-cache.manifest.json")"
output_manifest="$(dirname "$output_root")/$(basename "$output_root").manifest.json"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$output_root" \
  --output "$output_manifest" \
  --metadata "sourceTag=$SING_BOX_VERSION" \
  --metadata "sourceCommit=$SING_BOX_COMMIT" \
  --metadata "goVersion=$GO_VERSION" \
  --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
  --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
  --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
  --metadata "gomobileVersion=$GOMOBILE_VERSION" \
  --metadata "gomobileCommit=$GOMOBILE_COMMIT" \
  --metadata "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \
  --metadata "archiveDeterminism=zeroArDate-v1" \
  --metadata "headerNormalization=angleBracketFrameworkImports-v1" \
  --metadata "platform=$LIBBOX_APPLE_PLATFORM" \
  --metadata "buildTags=$LIBBOX_BUILD_TAGS" \
  --metadata "nonMacOsTags=$LIBBOX_NON_MACOS_TAGS" \
  --metadata "upstreamGoModSha256=$SING_BOX_UPSTREAM_GO_MOD_SHA256" \
  --metadata "upstreamGoSumSha256=$SING_BOX_UPSTREAM_GO_SUM_SHA256" \
  --metadata "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256" \
  --metadata "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256" \
  --metadata "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256" \
  --metadata "patchedDiffSha256=$SING_BOX_PATCHED_DIFF_SHA256" \
  --metadata "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256" \
  --metadata "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256" \
  --metadata "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256"
libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$output_root" \
  "$output_manifest" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256" >/dev/null

echo "libbox source: $SING_BOX_COMMIT"
echo "libbox tags: $LIBBOX_BUILD_TAGS"
echo "libbox artifact: $output_root"
