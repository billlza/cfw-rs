#!/usr/bin/env bash
# Shared fail-closed contract for release toolchains installed under
# target/toolchains. Callers invoking managed-tree functions must source
# dependency_pins.env first.

release_contract_directory="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=scripts/release_python_launcher.sh
source "$release_contract_directory/release_python_launcher.sh"
# shellcheck source=scripts/apple_validation_policy.sh
source "$release_contract_directory/apple_validation_policy.sh"
cfw_apply_validation_apple_toolchain "$(cd "$release_contract_directory/.." && /bin/pwd -P)"
unset release_contract_directory

cfw_require_supported_python() {
  local contract_python="${1:-${CFW_RELEASE_PYTHON_EXECUTABLE:-python3}}"
  "$contract_python" -I -S -B -W error -c \
    'import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] < (4, 0)))' || {
    echo "error: Python 3.11 through 3.x is required" >&2
    return 1
  }
}

cfw_verify_release_toolchain_manifest() {
  local contract_repository="$1"
  local contract_artifact="$2"
  local contract_manifest="$3"
  shift 3

  local contract_metadata
  local -a contract_metadata_arguments=()
  for contract_metadata in "$@"; do
    contract_metadata_arguments+=(--metadata "$contract_metadata")
  done

  cfw_run_release_python_script \
    "$contract_repository" \
    "$contract_repository/scripts/verify_artifact_manifest.py" \
    "$contract_artifact" \
    "$contract_manifest" \
    --algorithm sha256-tree-v2 \
    --exact-metadata \
    --print-tree-sha256 \
    "${contract_metadata_arguments[@]}"
}

cfw_verify_go_toolchain_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/go-$GO_VERSION" \
    "$contract_toolchain_root/go-$GO_VERSION.manifest.json" \
    "artifactKind=pinned-go-toolchain-v1" \
    "platform=darwin-arm64" \
    "sourceArchiveSha256=$GO_DARWIN_ARM64_SHA256" \
    "version=$GO_VERSION"
}

cfw_verify_node_toolchain_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  : "${NODE_VERSION:?the pinned Node version must be loaded}"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/node-$NODE_VERSION" \
    "$contract_toolchain_root/node-$NODE_VERSION.manifest.json" \
    "artifactKind=pinned-node-toolchain-v1" \
    "platform=darwin-arm64" \
    "sourceArchiveSha256=$NODE_DARWIN_ARM64_SHA256" \
    "version=$NODE_VERSION"
}

cfw_verify_npm_toolchain_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/npm-$NPM_VERSION" \
    "$contract_toolchain_root/npm-$NPM_VERSION.manifest.json" \
    "artifactKind=pinned-npm-toolchain-v1" \
    "sourceArchiveSha256=$NPM_ARCHIVE_SHA256" \
    "version=$NPM_VERSION"
}

cfw_verify_tauri_toolchain_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/tauri-cli-$TAURI_CLI_VERSION" \
    "$contract_toolchain_root/tauri-cli-$TAURI_CLI_VERSION.manifest.json" \
    "artifactKind=pinned-tauri-cli-v3" \
    "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256" \
    "cacheNormalization=cargo-runtime-metadata-v1" \
    "crateSha256=$TAURI_CLI_CRATE_SHA256" \
    "dependencyMode=isolated-fetch-offline-locked-v1" \
    "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
    "payloadLayout=bin-and-source-v1" \
    "platform=darwin-arm64" \
    "rustToolchain=$RUST_VERSION-aarch64-apple-darwin" \
    "spinCrateSha256=$TAURI_CLI_SPIN_CRATE_SHA256" \
    "spinVersion=$TAURI_CLI_SPIN_VERSION" \
    "upstreamCargoLockSha256=$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" \
    "version=$TAURI_CLI_VERSION" \
    "xcodeBuild=$XCODE_BUILD_VERSION" \
    "xcodeVersion=$XCODE_VERSION"
}

cfw_verify_xcodegen_toolchain_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/xcodegen-$XCODEGEN_VERSION" \
    "$contract_toolchain_root/xcodegen-$XCODEGEN_VERSION.manifest.json" \
    "artifactKind=pinned-xcodegen-toolchain-v3" \
    "buildPolicy=isolated-resolved-swiftpm-v1" \
    "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
    "packageResolvedSha256=$XCODEGEN_PACKAGE_RESOLVED_SHA256" \
    "upstreamPackageResolvedSha256=$XCODEGEN_UPSTREAM_PACKAGE_RESOLVED_SHA256" \
    "dependencyPatchSha256=$XCODEGEN_DEPENDENCY_PATCH_SHA256" \
    "aexmlCommit=$XCODEGEN_AEXML_COMMIT" \
    "aexmlUpstreamManifestSha256=$XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256" \
    "aexmlPatchSha256=$XCODEGEN_AEXML_PATCH_SHA256" \
    "aexmlPatchedManifestSha256=$XCODEGEN_AEXML_PATCHED_MANIFEST_SHA256" \
    "patchSha256=$XCODEGEN_PATCH_SHA256" \
    "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256" \
    "platform=darwin-arm64" \
    "sourceArchiveSha256=$XCODEGEN_SOURCE_SHA256" \
    "sourceCommit=$XCODEGEN_COMMIT" \
    "version=$XCODEGEN_VERSION" \
    "xcodeBuild=$XCODE_BUILD_VERSION" \
    "xcodeVersion=$XCODE_VERSION"
}

cfw_verify_go_release_tools_source() {
  local contract_repository="$1"
  local module_root="$contract_repository/tools/go-release-tools"
  [[ -d "$module_root" && ! -L "$module_root" &&
    -f "$module_root/go.mod" && ! -L "$module_root/go.mod" &&
    -f "$module_root/go.sum" && ! -L "$module_root/go.sum" ]] || {
    echo "error: pinned Go release-tool module files are unavailable" >&2
    return 1
  }
  printf '%s  %s\n' \
    "$GO_RELEASE_TOOLS_GO_MOD_SHA256" "$module_root/go.mod" \
    "$GO_RELEASE_TOOLS_GO_SUM_SHA256" "$module_root/go.sum" |
    /usr/bin/shasum -a 256 --check >/dev/null
}

cfw_verify_go_release_tools_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_go_release_tools_source "$contract_repository" || return 1
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/go-workspace/bin" \
    "$contract_toolchain_root/go-workspace-bin.manifest.json" \
    "artifactKind=pinned-go-release-tools-v2" \
    "toolsGoModSha256=$GO_RELEASE_TOOLS_GO_MOD_SHA256" \
    "toolsGoSumSha256=$GO_RELEASE_TOOLS_GO_SUM_SHA256" \
    "goVersion=$GO_VERSION" \
    "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \
    "gomobileVersion=$GOMOBILE_VERSION" \
    "govulncheckModuleSum=$GOVULNCHECK_MODULE_SUM" \
    "govulncheckVersion=$GOVULNCHECK_VERSION" \
    "platform=darwin-arm64"
}

cfw_verify_go_module_cache_tree() {
  local contract_repository="$1"
  local contract_toolchain_root="$2"
  cfw_verify_release_toolchain_manifest \
    "$contract_repository" \
    "$contract_toolchain_root/go-workspace/pkg/mod" \
    "$contract_toolchain_root/go-module-cache.manifest.json" \
    "artifactKind=pinned-go-module-cache-v2" \
    "buildTags=$LIBBOX_BUILD_TAGS" \
    "goVersion=$GO_VERSION" \
    "moduleCacheContractSha256=$LIBBOX_MODULE_CACHE_CONTRACT_SHA256" \
    "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256" \
    "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256" \
    "platform=darwin-arm64" \
    "sourceCommit=$SING_BOX_COMMIT"
}

cfw_release_toolchain_tree_sha256() {
  local contract_manifest="$1"
  [[ $# -eq 1 ]] || {
    echo "error: cfw_release_toolchain_tree_sha256 requires one managed manifest path" >&2
    return 1
  }
  local contract_repository
  local contract_toolchain_root
  contract_repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
  contract_toolchain_root="$(dirname "$contract_manifest")"

  case "$(basename "$contract_manifest")" in
    "go-$GO_VERSION.manifest.json")
      cfw_verify_go_toolchain_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "node-$NODE_VERSION.manifest.json")
      cfw_verify_node_toolchain_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "npm-$NPM_VERSION.manifest.json")
      cfw_verify_npm_toolchain_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "xcodegen-$XCODEGEN_VERSION.manifest.json")
      cfw_verify_xcodegen_toolchain_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "tauri-cli-$TAURI_CLI_VERSION.manifest.json")
      cfw_verify_tauri_toolchain_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "go-workspace-bin.manifest.json")
      cfw_verify_go_release_tools_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "go-module-cache.manifest.json")
      cfw_verify_go_module_cache_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    "ui-node-modules.manifest.json")
      # shellcheck source=scripts/ui_dependency_contract.sh
      source "$contract_repository/scripts/ui_dependency_contract.sh"
      cfw_verify_ui_dependencies_tree "$contract_repository" "$contract_toolchain_root"
      ;;
    *)
      echo "error: unmanaged release-toolchain manifest: $contract_manifest" >&2
      return 1
      ;;
  esac
}
