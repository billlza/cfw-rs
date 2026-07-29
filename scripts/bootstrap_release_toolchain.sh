#!/usr/bin/env bash
# Download pinned build tools into target/toolchains. Product builds never call
# this script and never download tools or binaries implicitly.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/go_release_environment.sh
source "$repo_root/scripts/go_release_environment.sh"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"

bootstrap_scope=full
if [[ $# -eq 1 && "$1" == "--node-only" ]]; then
  bootstrap_scope=node-only
elif [[ $# -ne 0 ]]; then
  echo "error: usage: scripts/bootstrap_release_toolchain.sh [--node-only]" >&2
  exit 1
fi
readonly bootstrap_scope

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "error: the release toolchain supports only arm64 macOS" >&2
  exit 1
fi

toolchain_root="$repo_root/target/toolchains"
go_root="$toolchain_root/go-$GO_VERSION"
go_manifest="$toolchain_root/go-$GO_VERSION.manifest.json"
node_root="$toolchain_root/node-$NODE_VERSION"
node_manifest="$toolchain_root/node-$NODE_VERSION.manifest.json"
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
  local manifest="$6"
  local payload
  shift 6

  if [[ -e "$destination" || -L "$destination" || -e "$manifest" || -L "$manifest" ]]; then
    echo "error: refusing to replace existing toolchain directory or manifest: $destination" >&2
    exit 1
  fi

  local staging
  staging="$(mktemp -d "$toolchain_root/bootstrap.XXXXXX")"
  trap '/bin/rm -rf -- "$staging"' RETURN
  curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$staging/$archive"
  printf '%s  %s\n' "$expected_sha256" "$staging/$archive" | shasum -a 256 --check
  tar -xzf "$staging/$archive" -C "$staging"
  payload="$staging/$(basename "$destination")"
  /bin/mv "$staging/$extracted" "$payload"
  python3 "$repo_root/scripts/hash_artifact.py" \
    "$payload" \
    --output "$staging/$(basename "$manifest")" \
    --algorithm sha256-tree-v2 \
    "$@"
  mv "$payload" "$destination"
  mv "$staging/$(basename "$manifest")" "$manifest"
  trap - RETURN
  /bin/rm -rf -- "$staging"
}

if [[ "$bootstrap_scope" == full ]]; then
  if [[ -e "$go_root" || -L "$go_root" || -e "$go_manifest" || -L "$go_manifest" ]]; then
    [[ -d "$go_root" && ! -L "$go_root" && -f "$go_manifest" && ! -L "$go_manifest" ]] || {
      echo "error: refusing to reuse incomplete Go toolchain evidence" >&2
      exit 1
    }
  else
    install_archive \
      "https://go.dev/dl/go$GO_VERSION.darwin-arm64.tar.gz" \
      "$GO_DARWIN_ARM64_SHA256" \
      "go$GO_VERSION.darwin-arm64.tar.gz" \
      go \
      "$go_root" \
      "$go_manifest" \
      --metadata "artifactKind=pinned-go-toolchain-v1" \
      --metadata "platform=darwin-arm64" \
      --metadata "sourceArchiveSha256=$GO_DARWIN_ARM64_SHA256" \
      --metadata "version=$GO_VERSION"
  fi
fi

if [[ -e "$node_root" || -L "$node_root" || -e "$node_manifest" || -L "$node_manifest" ]]; then
  [[ -d "$node_root" && ! -L "$node_root" && -f "$node_manifest" && ! -L "$node_manifest" ]] || {
    echo "error: refusing to reuse incomplete Node.js toolchain evidence" >&2
    exit 1
  }
else
  install_archive \
    "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-darwin-arm64.tar.gz" \
    "$NODE_DARWIN_ARM64_SHA256" \
    "node-v$NODE_VERSION-darwin-arm64.tar.gz" \
    "node-v$NODE_VERSION-darwin-arm64" \
    "$node_root" \
    "$node_manifest" \
    --metadata "artifactKind=pinned-node-toolchain-v1" \
    --metadata "platform=darwin-arm64" \
    --metadata "sourceArchiveSha256=$NODE_DARWIN_ARM64_SHA256" \
    --metadata "version=$NODE_VERSION"
fi

if [[ "$bootstrap_scope" == node-only ]]; then
  cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root" >/dev/null
  if [[ "$($node_bin --version)" != "v$NODE_VERSION" ]]; then
    echo "error: pinned Node.js toolchain identity mismatch" >&2
    exit 1
  fi
  cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root" >/dev/null
  echo "pinned Node.js toolchain ready: $node_root"
  exit 0
fi

install_xcodegen() {
  if [[ -e "$xcodegen_root" || -L "$xcodegen_root" || -e "$xcodegen_manifest" || -L "$xcodegen_manifest" ]]; then
    echo "error: refusing to replace incomplete XcodeGen toolchain evidence" >&2
    exit 1
  fi
  local developer_dir sdk_root swift_bin
  developer_dir="${DEVELOPER_DIR:-$(/usr/bin/xcode-select -p)}"
  if [[ "$(DEVELOPER_DIR="$developer_dir" /usr/bin/xcodebuild -version)" != \
    "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]]; then
    echo "error: Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required to build XcodeGen" >&2
    exit 1
  fi
  sdk_root="$(DEVELOPER_DIR="$developer_dir" /usr/bin/xcrun --sdk macosx --show-sdk-path)"
  swift_bin="$(DEVELOPER_DIR="$developer_dir" /usr/bin/xcrun --find swift)"
  if [[ "$swift_bin" != /* || ! -x "$swift_bin" ]]; then
    echo "error: pinned Xcode did not resolve an absolute Swift compiler" >&2
    exit 1
  fi

  local staging archive extracted payload build_root build_log xcodegen_patch settings_builder
  staging="$(mktemp -d "$toolchain_root/xcodegen-bootstrap.XXXXXX")"
  trap '/bin/rm -rf -- "$staging"' RETURN
  archive="$staging/xcodegen-source.tar.gz"
  extracted="$staging/XcodeGen-$XCODEGEN_COMMIT"
  payload="$staging/xcodegen-$XCODEGEN_VERSION"
  build_root="$staging/swift-build"
  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://codeload.github.com/yonaskolb/XcodeGen/tar.gz/$XCODEGEN_COMMIT" \
    --output "$archive"
  printf '%s  %s\n' "$XCODEGEN_SOURCE_SHA256" "$archive" | shasum -a 256 --check
  PYTHONDONTWRITEBYTECODE=1 python3 -B - "$archive" "XcodeGen-$XCODEGEN_COMMIT" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, expected_root = sys.argv[1:]


def normalized(parts: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not result:
                raise ValueError("path escapes archive root")
            result.pop()
        else:
            result.append(part)
    return tuple(result)


with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("error: the pinned XcodeGen archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or path.parts[0] != expected_root:
            raise SystemExit(f"error: unsafe XcodeGen archive path: {member.name!r}")
        if any(part in ("", ".", "..") for part in path.parts):
            raise SystemExit(f"error: unsafe XcodeGen archive component: {member.name!r}")
        if member.issym():
            target = PurePosixPath(member.linkname)
            if target.is_absolute():
                raise SystemExit(f"error: absolute XcodeGen archive symlink: {member.name!r}")
            try:
                resolved = normalized((*path.parent.parts, *target.parts))
            except ValueError as error:
                raise SystemExit(
                    f"error: escaping XcodeGen archive symlink: {member.name!r}"
                ) from error
            if not resolved or resolved[0] != expected_root:
                raise SystemExit(f"error: escaping XcodeGen archive symlink: {member.name!r}")
        elif not (member.isfile() or member.isdir()):
            raise SystemExit(f"error: unsupported XcodeGen archive entry: {member.name!r}")
PY
  /usr/bin/tar -xzf "$archive" -C "$staging"
  printf '%s  %s\n' "$XCODEGEN_SOURCE_SHA256" "$archive" |
    shasum -a 256 --check >/dev/null
  if [[ ! -f "$extracted/Package.swift" || -L "$extracted/Package.swift" ]]; then
    echo "error: pinned XcodeGen source archive has an unexpected layout" >&2
    exit 1
  fi
  if [[ ! -f "$extracted/Package.resolved" || -L "$extracted/Package.resolved" ]]; then
    echo "error: pinned XcodeGen source archive has no regular Package.resolved" >&2
    exit 1
  fi
  printf '%s  %s\n' "$XCODEGEN_PACKAGE_RESOLVED_SHA256" "$extracted/Package.resolved" |
    shasum -a 256 --check
  mkdir -p "$payload/bin" "$payload/source"
  COPYFILE_DISABLE=1 /bin/cp -R "$extracted/." "$payload/source/"
  xcodegen_patch="$repo_root/$XCODEGEN_PATCH_PATH"
  settings_builder="$payload/source/Sources/XcodeGenKit/SettingsBuilder.swift"
  if [[ ! -f "$xcodegen_patch" || -L "$xcodegen_patch" ]]; then
    echo "error: pinned XcodeGen patch is missing or is a symlink" >&2
    exit 1
  fi
  printf '%s  %s\n' "$XCODEGEN_PATCH_SHA256" "$xcodegen_patch" |
    shasum -a 256 --check >/dev/null
  GIT_CEILING_DIRECTORIES="$toolchain_root" \
    /usr/bin/git -C "$payload/source" apply --check "$xcodegen_patch"
  GIT_CEILING_DIRECTORIES="$toolchain_root" \
    /usr/bin/git -C "$payload/source" apply "$xcodegen_patch"
  printf '%s  %s\n' "$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256" "$settings_builder" |
    shasum -a 256 --check >/dev/null
  GIT_CEILING_DIRECTORIES="$toolchain_root" \
    /usr/bin/git -C "$payload/source" apply --reverse --check "$xcodegen_patch"
  local isolated_home isolated_tmp swift_cache swift_config swift_security
  isolated_home="$staging/home"
  isolated_tmp="$staging/tmp"
  swift_cache="$staging/swift-cache"
  swift_config="$staging/swift-config"
  swift_security="$staging/swift-security"
  build_log="$staging/swift-build.log"
  mkdir -p \
    "$build_root" \
    "$isolated_home" \
    "$isolated_tmp" \
    "$swift_cache" \
    "$swift_config" \
    "$swift_security"
  /usr/bin/env -i \
    HOME="$isolated_home" \
    TMPDIR="$isolated_tmp" \
    LANG=C \
    LC_ALL=C \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    DEVELOPER_DIR="$developer_dir" \
    SDKROOT="$sdk_root" \
    MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    "$swift_bin" package \
    --package-path "$payload/source" \
    --cache-path "$swift_cache" \
    --config-path "$swift_config" \
    --security-path "$swift_security" \
    --scratch-path "$build_root" \
    --disable-netrc \
    --disable-keychain \
    --disable-experimental-prebuilts \
    --manifest-cache local \
    --only-use-versions-from-resolved-file \
    --no-color-diagnostics \
    resolve
  if /usr/bin/env -i \
    HOME="$isolated_home" \
    TMPDIR="$isolated_tmp" \
    LANG=C \
    LC_ALL=C \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    DEVELOPER_DIR="$developer_dir" \
    SDKROOT="$sdk_root" \
    MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    "$swift_bin" build \
    --package-path "$payload/source" \
    --cache-path "$swift_cache" \
    --config-path "$swift_config" \
    --security-path "$swift_security" \
    --scratch-path "$build_root" \
    --disable-netrc \
    --disable-keychain \
    --disable-experimental-prebuilts \
    --manifest-cache local \
    --only-use-versions-from-resolved-file \
    --disable-automatic-resolution \
    --no-color-diagnostics \
    --disable-index-store \
    --configuration release \
    --product xcodegen \
    -Xswiftc -warnings-as-errors 2>&1 | tee "$build_log"; then
    :
  else
    echo "error: isolated XcodeGen build failed" >&2
    exit 1
  fi
  if grep -Eiq '(^|[[:space:]])warning([[:space:]]|:)' "$build_log"; then
    echo "error: isolated XcodeGen build emitted a warning" >&2
    exit 1
  fi
  printf '%s  %s\n' "$XCODEGEN_PACKAGE_RESOLVED_SHA256" "$payload/source/Package.resolved" |
    shasum -a 256 --check >/dev/null
  /usr/bin/strip -S "$build_root/release/xcodegen"
  /usr/bin/install -m 0755 "$build_root/release/xcodegen" "$payload/bin/xcodegen"
  mkdir -p "$payload/share/xcodegen"
  /usr/bin/ditto --noqtn \
    "$payload/source/SettingPresets" \
    "$payload/share/xcodegen/SettingPresets"
  if [[ "$("$payload/bin/xcodegen" --version)" != "Version: $XCODEGEN_VERSION" ]]; then
    echo "error: source-built XcodeGen identity mismatch" >&2
    exit 1
  fi
  if [[ "$(/usr/bin/lipo -archs "$payload/bin/xcodegen")" != "arm64" ]]; then
    echo "error: source-built XcodeGen must be thin arm64" >&2
    exit 1
  fi
  local resource_probe
  resource_probe="$staging/resource-probe"
  mkdir -p "$resource_probe/spec" "$resource_probe/output"
  printf '%s\n' \
    'name: XcodeGenResourceProbe' \
    'targets:' \
    '  Probe:' \
    '    type: tool' \
    '    platform: macOS' \
    '    deploymentTarget: "15.0"' \
    >"$resource_probe/spec/project.yml"
  /usr/bin/env -i \
    HOME="$isolated_home" \
    TMPDIR="$isolated_tmp" \
    USER=cfw-release \
    LOGNAME=cfw-release \
    LANG=C \
    LC_ALL=C \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    DEVELOPER_DIR="$developer_dir" \
    "$payload/bin/xcodegen" \
    --quiet \
    --spec "$resource_probe/spec/project.yml" \
    --project "$resource_probe/output"
  if [[ ! -f "$resource_probe/output/XcodeGenResourceProbe.xcodeproj/project.pbxproj" ]]; then
    echo "error: installed XcodeGen cannot load its SettingPresets resources" >&2
    exit 1
  fi
  if PYTHONDONTWRITEBYTECODE=1 python3 -B - "$payload/bin/xcodegen" "$staging" <<'PY'
import sys
from pathlib import Path

binary, forbidden = map(Path, sys.argv[1:])
needle = str(forbidden).encode("utf-8")
contents = binary.read_bytes()
offset = contents.find(needle)
if offset >= 0:
  suffix = contents[offset + len(needle):offset + len(needle) + 160]
  printable = bytes(byte for byte in suffix if byte in b"/._-" or 32 <= byte < 127)
  print(f"embedded temporary path suffix: {printable.decode('ascii', errors='replace')}", file=sys.stderr)
  raise SystemExit(1)
PY
  then
    :
  else
    echo "error: source-built XcodeGen embeds its temporary build path" >&2
    exit 1
  fi
  python3 "$repo_root/scripts/hash_artifact.py" \
    "$payload" \
    --output "$staging/xcodegen-$XCODEGEN_VERSION.manifest.json" \
    --algorithm sha256-tree-v2 \
    --metadata "artifactKind=pinned-xcodegen-toolchain-v2" \
    --metadata "buildPolicy=isolated-resolved-swiftpm-v1" \
    --metadata "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
    --metadata "packageResolvedSha256=$XCODEGEN_PACKAGE_RESOLVED_SHA256" \
    --metadata "patchSha256=$XCODEGEN_PATCH_SHA256" \
    --metadata "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256" \
    --metadata "platform=darwin-arm64" \
    --metadata "sourceArchiveSha256=$XCODEGEN_SOURCE_SHA256" \
    --metadata "sourceCommit=$XCODEGEN_COMMIT" \
    --metadata "version=$XCODEGEN_VERSION" \
    --metadata "xcodeBuild=$XCODE_BUILD_VERSION" \
    --metadata "xcodeVersion=$XCODE_VERSION"
  /bin/mv "$payload" "$xcodegen_root"
  /bin/mv "$staging/xcodegen-$XCODEGEN_VERSION.manifest.json" "$xcodegen_manifest"
  trap - RETURN
  /bin/rm -r "$staging"
}

if [[ -e "$xcodegen_root" || -L "$xcodegen_root" || -e "$xcodegen_manifest" || -L "$xcodegen_manifest" ]]; then
  [[ -d "$xcodegen_root" && ! -L "$xcodegen_root" && -f "$xcodegen_manifest" && ! -L "$xcodegen_manifest" ]] || {
    echo "error: refusing to reuse incomplete XcodeGen toolchain evidence" >&2
    exit 1
  }
else
  install_xcodegen
fi

cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_node_toolchain_tree "$repo_root" "$toolchain_root"
cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"

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
cfw_verify_xcodegen_toolchain_tree "$repo_root" "$toolchain_root"
gopath="$toolchain_root/go-workspace"
gobin="$gopath/bin"
go_tools_manifest="$toolchain_root/go-workspace-bin.manifest.json"
go_module_manifest="$toolchain_root/go-module-cache.manifest.json"
if [[ -e "$gobin" || -L "$gobin" || -e "$go_tools_manifest" || -L "$go_tools_manifest" ]]; then
  [[ -d "$gobin" && ! -L "$gobin" && -f "$go_tools_manifest" && ! -L "$go_tools_manifest" ]] || {
    echo "error: refusing to reuse incomplete Go release-tool evidence" >&2
    exit 1
  }
else
  [[ ! -e "$go_module_manifest" && ! -L "$go_module_manifest" ]] || {
    echo "error: sealed Go module cache cannot be mutated while installing release tools" >&2
    exit 1
  }
  mkdir -p "$gopath"
  tools_staging="$(mktemp -d "$toolchain_root/go-tools-bootstrap.XXXXXX")"
  trap '/bin/rm -rf -- "$tools_staging"' EXIT
  mkdir -p "$tools_staging/bin"
  export GOBIN="$tools_staging/bin"
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
  python3 "$repo_root/scripts/hash_artifact.py" \
    "$tools_staging/bin" \
    --output "$tools_staging/go-workspace-bin.manifest.json" \
    --algorithm sha256-tree-v2 \
    --metadata "artifactKind=pinned-go-release-tools-v1" \
    --metadata "goVersion=$GO_VERSION" \
    --metadata "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \
    --metadata "gomobileVersion=$GOMOBILE_VERSION" \
    --metadata "govulncheckModuleSum=$GOVULNCHECK_MODULE_SUM" \
    --metadata "govulncheckVersion=$GOVULNCHECK_VERSION" \
    --metadata "platform=darwin-arm64"
  /bin/mv "$tools_staging/bin" "$gobin"
  /bin/mv "$tools_staging/go-workspace-bin.manifest.json" "$go_tools_manifest"
  trap - EXIT
  /bin/rm -rf -- "$tools_staging"
fi

cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"

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
