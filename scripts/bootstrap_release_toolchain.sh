#!/usr/bin/env bash
# Download pinned build tools into target/toolchains. Product builds never call
# this script and never download tools or binaries implicitly.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/go_release_environment.sh
source "$repo_root/scripts/go_release_environment.sh"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "error: the release toolchain supports only arm64 macOS" >&2
  exit 1
fi

toolchain_root="$repo_root/target/toolchains"
go_root="$toolchain_root/go-$GO_VERSION"
node_root="$toolchain_root/node-$NODE_VERSION"
xcodegen_root="$toolchain_root/xcodegen-$XCODEGEN_VERSION"
xcodegen_manifest="$toolchain_root/xcodegen-$XCODEGEN_VERSION.manifest.json"
go_bin="$go_root/bin/go"
node_bin="$node_root/bin/node"
xcodegen_bin="$xcodegen_root/bin/xcodegen"
mkdir -p "$toolchain_root"

install_archive() {
  local url="$1"
  local expected_sha256="$2"
  local archive="$3"
  local extracted="$4"
  local destination="$5"

  if [[ -e "$destination" || -L "$destination" ]]; then
    echo "error: refusing to replace existing toolchain directory: $destination" >&2
    exit 1
  fi

  local staging
  staging="$(mktemp -d "$toolchain_root/bootstrap.XXXXXX")"
  trap 'rm -rf "$staging"' RETURN
  curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$staging/$archive"
  printf '%s  %s\n' "$expected_sha256" "$staging/$archive" | shasum -a 256 --check
  tar -xzf "$staging/$archive" -C "$staging"
  mv "$staging/$extracted" "$destination"
  trap - RETURN
  rm -rf "$staging"
}

if [[ ! -x "$go_bin" ]]; then
  install_archive \
    "https://go.dev/dl/go$GO_VERSION.darwin-arm64.tar.gz" \
    "$GO_DARWIN_ARM64_SHA256" \
    "go$GO_VERSION.darwin-arm64.tar.gz" \
    go \
    "$go_root"
fi

if [[ ! -x "$node_bin" ]]; then
  install_archive \
    "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-darwin-arm64.tar.gz" \
    "$NODE_DARWIN_ARM64_SHA256" \
    "node-v$NODE_VERSION-darwin-arm64.tar.gz" \
    "node-v$NODE_VERSION-darwin-arm64" \
    "$node_root"
fi

install_xcodegen() {
  if [[ -e "$xcodegen_root" || -L "$xcodegen_root" || -e "$xcodegen_manifest" || -L "$xcodegen_manifest" ]]; then
    echo "error: refusing to replace incomplete XcodeGen toolchain evidence" >&2
    exit 1
  fi
  if [[ "$(xcodebuild -version)" != "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]]; then
    echo "error: Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required to build XcodeGen" >&2
    exit 1
  fi

  local staging archive extracted payload build_root swift_identity
  staging="$(mktemp -d "$toolchain_root/xcodegen-bootstrap.XXXXXX")"
  trap 'rm -rf "$staging"' RETURN
  archive="$staging/xcodegen-source.tar.gz"
  extracted="$staging/XcodeGen-$XCODEGEN_COMMIT"
  payload="$staging/xcodegen-$XCODEGEN_VERSION"
  build_root="$staging/swift-build"
  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://codeload.github.com/yonaskolb/XcodeGen/tar.gz/$XCODEGEN_COMMIT" \
    --output "$archive"
  printf '%s  %s\n' "$XCODEGEN_SOURCE_SHA256" "$archive" | shasum -a 256 --check
  tar -xzf "$archive" -C "$staging"
  if [[ ! -f "$extracted/Package.swift" || -L "$extracted/Package.swift" ]]; then
    echo "error: pinned XcodeGen source archive has an unexpected layout" >&2
    exit 1
  fi
  mkdir -p "$payload/bin" "$payload/source"
  COPYFILE_DISABLE=1 /bin/cp -R "$extracted/." "$payload/source/"
  swift build \
    --package-path "$payload/source" \
    --scratch-path "$build_root" \
    --configuration release \
    --product xcodegen
  /usr/bin/install -m 0755 "$build_root/release/xcodegen" "$payload/bin/xcodegen"
  mkdir -p "$payload/share/xcodegen"
  /usr/bin/ditto --noqtn \
    "$payload/source/SettingPresets" \
    "$payload/share/xcodegen/SettingPresets"
  if [[ "$("$payload/bin/xcodegen" --version)" != "Version: $XCODEGEN_VERSION" ]]; then
    echo "error: source-built XcodeGen identity mismatch" >&2
    exit 1
  fi
  swift_identity="$(swift --version 2>&1 | head -n 1)"
  python3 "$repo_root/scripts/hash_artifact.py" \
    "$payload" \
    --output "$staging/xcodegen-$XCODEGEN_VERSION.manifest.json" \
    --metadata "sourceArchiveSha256=$XCODEGEN_SOURCE_SHA256" \
    --metadata "sourceCommit=$XCODEGEN_COMMIT" \
    --metadata "swiftIdentity=$swift_identity" \
    --metadata "version=$XCODEGEN_VERSION" \
    --metadata "xcodeBuild=$XCODE_BUILD_VERSION" \
    --metadata "xcodeVersion=$XCODE_VERSION"
  /bin/mv "$payload" "$xcodegen_root"
  /bin/mv "$staging/xcodegen-$XCODEGEN_VERSION.manifest.json" "$xcodegen_manifest"
  trap - RETURN
  /bin/rm -r "$staging"
}

if [[ ! -x "$xcodegen_bin" ]]; then
  install_xcodegen
fi

if [[ "$($go_bin version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go toolchain identity mismatch" >&2
  exit 1
fi
if [[ "$($node_bin --version)" != "v$NODE_VERSION" ]]; then
  echo "error: pinned Node.js toolchain identity mismatch" >&2
  exit 1
fi
if [[ "$($xcodegen_bin --version)" != "Version: $XCODEGEN_VERSION" ]]; then
  echo "error: pinned XcodeGen toolchain identity mismatch" >&2
  exit 1
fi
if [[ "$(lipo -archs "$xcodegen_bin")" != "arm64" ]]; then
  echo "error: source-built XcodeGen must be thin arm64" >&2
  exit 1
fi
PYTHONDONTWRITEBYTECODE=1 python3 -B "$repo_root/scripts/verify_artifact_manifest.py" \
  "$xcodegen_root" \
  "$xcodegen_manifest" \
  --metadata "sourceArchiveSha256=$XCODEGEN_SOURCE_SHA256" \
  --metadata "sourceCommit=$XCODEGEN_COMMIT" \
  --metadata "version=$XCODEGEN_VERSION" \
  --metadata "xcodeBuild=$XCODE_BUILD_VERSION" \
  --metadata "xcodeVersion=$XCODE_VERSION"

gopath="$toolchain_root/go-workspace"
gobin="$gopath/bin"
mkdir -p "$gobin"
export GOBIN="$gobin"
export GOPATH="$gopath"
export GOMODCACHE="$gopath/pkg/mod"
export GOCACHE="$toolchain_root/go-build-cache"
configure_networked_go_environment
"$go_bin" install \
  "github.com/sagernet/gomobile/cmd/gomobile@$GOMOBILE_VERSION"
"$go_bin" install \
  "github.com/sagernet/gomobile/cmd/gobind@$GOMOBILE_VERSION"
"$go_bin" install \
  "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"

for binary in gomobile gobind; do
  "$go_bin" version -m "$gobin/$binary" | awk \
    -v version="$GOMOBILE_VERSION" \
    -v module_sum="$GOMOBILE_MODULE_SUM" \
    '$1 == "mod" && $2 == "github.com/sagernet/gomobile" && $3 == version && $4 == module_sum { found = 1 } END { exit !found }'
done
"$go_bin" version -m "$gobin/govulncheck" | awk \
  -v version="$GOVULNCHECK_VERSION" \
  -v module_sum="$GOVULNCHECK_MODULE_SUM" \
  '$1 == "mod" && $2 == "golang.org/x/vuln" && $3 == version && $4 == module_sum { found = 1 } END { exit !found }'

echo "toolchain ready: $toolchain_root"
echo "next: materialize the pinned patched source, then prepare its module cache"
