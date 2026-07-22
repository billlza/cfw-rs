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
export GOCACHE="$toolchain_root/go-build-cache"
export PATH="$gobin:$toolchain_root/go-$GO_VERSION/bin:/usr/bin:/bin:/usr/sbin:/sbin"
configure_offline_go_environment
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"

(
  cd "$source_root"
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
python3 "$repo_root/scripts/hash_artifact.py" \
  "$output_root" \
  --output "$(dirname "$output_root")/Libbox.xcframework.manifest.json" \
  --metadata "sourceTag=$SING_BOX_VERSION" \
  --metadata "sourceCommit=$SING_BOX_COMMIT" \
  --metadata "goVersion=$GO_VERSION" \
  --metadata "gomobileVersion=$GOMOBILE_VERSION" \
  --metadata "gomobileCommit=$GOMOBILE_COMMIT" \
  --metadata "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \
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

echo "libbox source: $SING_BOX_COMMIT"
echo "libbox tags: $LIBBOX_BUILD_TAGS"
echo "libbox artifact: $output_root"
