#!/usr/bin/env bash
# Shared validation for the immutable upstream sing-box checkout and the exact
# downstream security, raw-packet, and DNS failover patches used by the macOS
# libbox build.
# Source this file only after scripts/dependency_pins.env.

libbox_sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

libbox_require_regular_file() {
  local path="$1"
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "error: required regular file is missing or is a symlink: $path" >&2
    return 1
  fi
}

libbox_repository_relative_path() {
  local repo_root="$1"
  local relative_path="$2"
  local description="$3"
  local component
  local -a components
  if [[ "$relative_path" == /* ]]; then
    echo "error: $description path must be repository-relative" >&2
    return 1
  fi
  IFS='/' read -r -a components <<<"$relative_path"
  for component in "${components[@]}"; do
    if [[ -z "$component" || "$component" == "." || "$component" == ".." ]]; then
      echo "error: $description path has an unsafe component" >&2
      return 1
    fi
  done
  printf '%s/%s\n' "$repo_root" "$relative_path"
}

libbox_security_patch_path() {
  libbox_repository_relative_path "$1" "$SING_BOX_SECURITY_PATCH_PATH" "sing-box security patch"
}

libbox_raw_packet_patch_path() {
  libbox_repository_relative_path "$1" "$SING_BOX_RAW_PACKET_PATCH_PATH" "sing-box raw packet patch"
}

libbox_dns_failover_patch_path() {
  libbox_repository_relative_path "$1" "$SING_BOX_DNS_FAILOVER_PATCH_PATH" "sing-box DNS failover patch"
}

libbox_validate_patches() {
  local repo_root="$1"
  local security_patch_path raw_packet_patch_path dns_failover_patch_path
  security_patch_path="$(libbox_security_patch_path "$repo_root")" || return 1
  raw_packet_patch_path="$(libbox_raw_packet_patch_path "$repo_root")" || return 1
  dns_failover_patch_path="$(libbox_dns_failover_patch_path "$repo_root")" || return 1
  libbox_require_regular_file "$security_patch_path" || return 1
  libbox_require_regular_file "$raw_packet_patch_path" || return 1
  libbox_require_regular_file "$dns_failover_patch_path" || return 1
  if [[ "$(libbox_sha256 "$security_patch_path")" != "$SING_BOX_SECURITY_PATCH_SHA256" ]]; then
    echo "error: sing-box security patch digest mismatch" >&2
    return 1
  fi
  if [[ "$(libbox_sha256 "$raw_packet_patch_path")" != "$SING_BOX_RAW_PACKET_PATCH_SHA256" ]]; then
    echo "error: sing-box raw packet patch digest mismatch" >&2
    return 1
  fi
  if [[ "$(libbox_sha256 "$dns_failover_patch_path")" != "$SING_BOX_DNS_FAILOVER_PATCH_SHA256" ]]; then
    echo "error: sing-box DNS failover patch digest mismatch" >&2
    return 1
  fi
}

libbox_validate_git_root() {
  local source_root="$1"
  local top_level
  top_level="$(git -C "$source_root" rev-parse --show-toplevel)" || return 1
  if [[ "$(cd "$top_level" && pwd -P)" != "$source_root" ]]; then
    echo "error: SING_BOX_SOURCE must name the checkout root" >&2
    return 1
  fi
  if [[ "$(git -C "$source_root" rev-parse HEAD)" != "$SING_BOX_COMMIT" ]]; then
    echo "error: sing-box checkout is not pinned commit $SING_BOX_COMMIT" >&2
    return 1
  fi
}

libbox_validate_upstream_source() {
  local repo_root="$1"
  local source_root="$2"
  local security_patch_path raw_packet_patch_path dns_failover_patch_path
  libbox_validate_patches "$repo_root" || return 1
  libbox_validate_git_root "$source_root" || return 1
  if [[ -n "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)" ]]; then
    echo "error: upstream sing-box checkout must be clean" >&2
    return 1
  fi
  libbox_require_regular_file "$source_root/go.mod" || return 1
  libbox_require_regular_file "$source_root/go.sum" || return 1
  if [[ "$(libbox_sha256 "$source_root/go.mod")" != "$SING_BOX_UPSTREAM_GO_MOD_SHA256" ]]; then
    echo "error: upstream sing-box go.mod digest mismatch" >&2
    return 1
  fi
  if [[ "$(libbox_sha256 "$source_root/go.sum")" != "$SING_BOX_UPSTREAM_GO_SUM_SHA256" ]]; then
    echo "error: upstream sing-box go.sum digest mismatch" >&2
    return 1
  fi
  security_patch_path="$(libbox_security_patch_path "$repo_root")" || return 1
  raw_packet_patch_path="$(libbox_raw_packet_patch_path "$repo_root")" || return 1
  dns_failover_patch_path="$(libbox_dns_failover_patch_path "$repo_root")" || return 1
  # Zero-context scalar replacements are admitted only after the exact upstream
  # commit and go.mod/go.sum digests above have been verified.
  if ! git -C "$source_root" apply --unidiff-zero --check \
    "$security_patch_path" \
    "$raw_packet_patch_path" \
    "$dns_failover_patch_path"; then
    echo "error: pinned patches do not apply to the pinned sing-box source" >&2
    return 1
  fi
}

libbox_combined_diff_sha256() {
  local source_root="$1"
  local temporary_directory temporary_index digest
  temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/cfw-libbox-index.XXXXXX")"
  temporary_index="$temporary_directory/index"
  if ! GIT_INDEX_FILE="$temporary_index" git -C "$source_root" read-tree HEAD ||
    ! GIT_INDEX_FILE="$temporary_index" git -C "$source_root" add -A -- .; then
    /bin/rm -r "$temporary_directory"
    return 1
  fi
  digest="$(
    GIT_INDEX_FILE="$temporary_index" git -C "$source_root" \
      -c core.autocrlf=false --no-pager \
      diff --cached --no-ext-diff --binary HEAD -- |
      shasum -a 256 | awk '{print $1}'
  )"
  /bin/rm -r "$temporary_directory"
  printf '%s\n' "$digest"
}

libbox_validate_patched_source() {
  local repo_root="$1"
  local source_root="$2"
  local actual_diff actual_combined_diff ignored_files security_patch_path raw_packet_patch_path dns_failover_patch_path
  libbox_validate_patches "$repo_root" || return 1
  libbox_validate_git_root "$source_root" || return 1

  ignored_files="$(git -C "$source_root" ls-files --others --ignored --exclude-standard)"
  if [[ -n "$ignored_files" ]]; then
    echo "error: patched sing-box checkout contains ignored files" >&2
    return 1
  fi
  actual_diff="$(
    git -C "$source_root" -c core.autocrlf=false --no-pager \
      diff --no-ext-diff --binary -- go.mod go.sum | shasum -a 256 | awk '{print $1}'
  )"
  if [[ "$actual_diff" != "$SING_BOX_PATCHED_DIFF_SHA256" ]]; then
    echo "error: patched sing-box security diff digest mismatch" >&2
    return 1
  fi
  actual_combined_diff="$(libbox_combined_diff_sha256 "$source_root")" || return 1
  if [[ "$actual_combined_diff" != "$SING_BOX_COMBINED_DIFF_SHA256" ]]; then
    echo "error: patched sing-box combined diff digest mismatch" >&2
    return 1
  fi
  libbox_require_regular_file "$source_root/go.mod" || return 1
  libbox_require_regular_file "$source_root/go.sum" || return 1
  if [[ "$(libbox_sha256 "$source_root/go.mod")" != "$SING_BOX_PATCHED_GO_MOD_SHA256" ]]; then
    echo "error: patched sing-box go.mod digest mismatch" >&2
    return 1
  fi
  if [[ "$(libbox_sha256 "$source_root/go.sum")" != "$SING_BOX_PATCHED_GO_SUM_SHA256" ]]; then
    echo "error: patched sing-box go.sum digest mismatch" >&2
    return 1
  fi
  security_patch_path="$(libbox_security_patch_path "$repo_root")" || return 1
  raw_packet_patch_path="$(libbox_raw_packet_patch_path "$repo_root")" || return 1
  dns_failover_patch_path="$(libbox_dns_failover_patch_path "$repo_root")" || return 1
  if ! git -C "$source_root" apply --reverse --check "$dns_failover_patch_path"; then
    echo "error: pinned DNS failover patch cannot be reversed cleanly" >&2
    return 1
  fi
  if ! git -C "$source_root" apply --reverse --check "$raw_packet_patch_path"; then
    echo "error: pinned raw packet patch cannot be reversed cleanly" >&2
    return 1
  fi
  if ! git -C "$source_root" apply --unidiff-zero --reverse --check \
    "$security_patch_path"; then
    echo "error: pinned security patch cannot be reversed cleanly" >&2
    return 1
  fi
}

# Verify the exact XCFramework tree and every provenance field emitted by
# build_libbox.sh. The three toolchain digests must already come from the
# managed tree verifiers; accepting caller-provided paths or a metadata subset
# would allow a stale but internally consistent Libbox artifact to be signed.
libbox_verify_xcframework_artifact() {
  if [[ $# -ne 6 ]]; then
    echo "error: libbox_verify_xcframework_artifact requires repository, artifact, manifest, and three verified Go tree digests" >&2
    return 1
  fi
  local repository="$1"
  local artifact="$2"
  local manifest="$3"
  local go_toolchain_tree_sha256="$4"
  local go_tools_tree_sha256="$5"
  local go_module_cache_tree_sha256="$6"

  PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "$repository/scripts/verify_artifact_manifest.py" \
    "$artifact" \
    "$manifest" \
    --algorithm sha256-tree-v1 \
    --exact-metadata \
    --print-tree-sha256 \
    --metadata "sourceTag=$SING_BOX_VERSION" \
    --metadata "sourceCommit=$SING_BOX_COMMIT" \
    --metadata "goVersion=$GO_VERSION" \
    --metadata "goToolchainTreeSha256=$go_toolchain_tree_sha256" \
    --metadata "goToolsTreeSha256=$go_tools_tree_sha256" \
    --metadata "goModuleCacheTreeSha256=$go_module_cache_tree_sha256" \
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
}
