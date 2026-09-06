#!/usr/bin/env bash
# Shared validation for the immutable upstream sing-box checkout and the exact
# downstream security, raw-packet, DNS failover, and endpoint conflict patches used by the macOS
# libbox build.
# Source this file only after scripts/dependency_pins.env.

libbox_contract_directory="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=scripts/release_python_launcher.sh
source "$libbox_contract_directory/release_python_launcher.sh"
unset libbox_contract_directory

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

libbox_git_execute() {
  if [[ $# -lt 3 ]]; then
    echo "error: libbox_git_execute requires source root, index selector, and Git arguments" >&2
    return 1
  fi
  local source_root="$1"
  local index_file="$2"
  shift 2
  local -a git_environment=(
    "HOME=/var/empty"
    "LANG=C"
    "LC_ALL=C"
    "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
    "GIT_ATTR_NOSYSTEM=1"
    "GIT_CONFIG_GLOBAL=/dev/null"
    "GIT_CONFIG_NOSYSTEM=1"
    "GIT_CONFIG_SYSTEM=/dev/null"
    "GIT_LITERAL_PATHSPECS=1"
    "GIT_NO_LAZY_FETCH=1"
    "GIT_NO_REPLACE_OBJECTS=1"
    "GIT_OPTIONAL_LOCKS=0"
  )
  if [[ "$source_root" != /* || ! -d "$source_root" || -L "$source_root" ]]; then
    echo "error: libbox Git source root must be an absolute real directory" >&2
    return 1
  fi
  if [[ -n "$index_file" ]]; then
    [[ "$index_file" == /* ]] || {
      echo "error: libbox temporary Git index must be absolute" >&2
      return 1
    }
    git_environment+=("GIT_INDEX_FILE=$index_file")
  fi
  /usr/bin/env -i "${git_environment[@]}" \
    /usr/bin/git --no-pager \
    -C "$source_root" \
    --work-tree="$source_root" \
    -c core.attributesFile=/dev/null \
    -c core.autocrlf=false \
    -c core.bare=false \
    -c core.checkStat=default \
    -c core.excludesFile=/dev/null \
    -c core.fileMode=true \
    -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null \
    -c core.ignoreCase=false \
    -c core.ignoreStat=false \
    -c core.precomposeUnicode=true \
    -c core.sparseCheckout=false \
    -c core.sparseCheckoutCone=false \
    -c core.symlinks=true \
    -c core.trustctime=true \
    -c core.untrackedCache=false \
    "$@"
}

libbox_git() {
  local source_root="$1"
  shift
  libbox_git_execute "$source_root" "" "$@"
}

libbox_git_with_index() {
  local source_root="$1"
  local index_file="$2"
  shift 2
  libbox_git_execute "$source_root" "$index_file" "$@"
}

libbox_require_absent_git_configuration() {
  local source_root="$1"
  local description="$2"
  shift 2
  local output status
  if output="$(libbox_git "$source_root" "$@" 2>&1)"; then
    echo "error: libbox Git refuses $description: $output" >&2
    return 1
  else
    status=$?
  fi
  if [[ $status -ne 1 || -n "$output" ]]; then
    echo "error: libbox Git could not verify absence of $description" >&2
    return 1
  fi
}

libbox_validate_git_controls() {
  local source_root="$1"
  local git_directory="$source_root/.git"
  local exclude_file="$git_directory/info/exclude"
  local attributes_file="$git_directory/info/attributes"
  local alternates_file="$git_directory/objects/info/alternates"
  local worktree_config="$git_directory/config.worktree"
  local index_report record line trimmed invalid_index=0
  if [[ ! -d "$git_directory" || -L "$git_directory" ]]; then
    echo "error: libbox source must be a standalone checkout with a real .git directory" >&2
    return 1
  fi
  if [[ -e "$alternates_file" || -L "$alternates_file" || \
    -e "$worktree_config" || -L "$worktree_config" ]]; then
    echo "error: libbox Git refuses alternate objects or per-worktree configuration" >&2
    return 1
  fi
  libbox_require_absent_git_configuration \
    "$source_root" \
    "an effective core.worktree configuration" \
    config --includes --show-origin --get-all core.worktree || return 1
  libbox_require_absent_git_configuration \
    "$source_root" \
    "local include configuration" \
    config --local --includes --show-origin --get-regexp \
    '^include(if\..*)?\.path$' || return 1
  libbox_require_absent_git_configuration \
    "$source_root" \
    "local filter configuration" \
    config --local --includes --show-origin --get-regexp '^filter\.' || return 1

  if [[ -e "$exclude_file" || -L "$exclude_file" ]]; then
    libbox_require_regular_file "$exclude_file" || return 1
    if [[ "$(/usr/bin/stat -f '%l' "$exclude_file")" != "1" || \
      "$(/usr/bin/stat -f '%z' "$exclude_file")" -gt 262144 ]]; then
      echo "error: libbox Git local exclude file is unsafe or unbounded" >&2
      return 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
      trimmed="${line#"${line%%[![:space:]]*}"}"
      if [[ -n "$trimmed" && "$trimmed" != \#* ]]; then
        echo "error: libbox Git local exclude file contains an active pattern" >&2
        return 1
      fi
    done < "$exclude_file"
  fi

  if [[ -e "$attributes_file" || -L "$attributes_file" ]]; then
    libbox_require_regular_file "$attributes_file" || return 1
    if [[ "$(/usr/bin/stat -f '%l' "$attributes_file")" != "1" || \
      "$(/usr/bin/stat -f '%z' "$attributes_file")" -gt 262144 ]]; then
      echo "error: libbox Git local attributes file is unsafe or unbounded" >&2
      return 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
      trimmed="${line#"${line%%[![:space:]]*}"}"
      if [[ -n "$trimmed" && "$trimmed" != \#* ]]; then
        echo "error: libbox Git local attributes file contains an active rule" >&2
        return 1
      fi
    done < "$attributes_file"
  fi

  index_report="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/cfw-libbox-index-flags.XXXXXX")" || return 1
  if ! libbox_git "$source_root" ls-files -v -z --cached > "$index_report"; then
    /bin/rm -f "$index_report"
    return 1
  fi
  while IFS= read -r -d '' record; do
    if [[ "$record" != "H "* ]]; then
      invalid_index=1
      break
    fi
  done < "$index_report"
  /bin/rm -f "$index_report"
  if [[ $invalid_index -ne 0 ]]; then
    echo "error: libbox Git index contains non-default visibility flags" >&2
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

libbox_validate_module_cache_packages() {
  local description="$1"
  local package_kind="$2"
  shift 2
  if [[ $# -eq 0 ]]; then
    echo "error: libbox module cache contract has no $description packages" >&2
    return 1
  fi

  local package normalized component seen=" "
  local -a components
  for package in "$@"; do
    case "$package_kind" in
      local)
        if [[ "$package" != "." && ! "$package" =~ ^\./[A-Za-z0-9._@+~-]+(/[A-Za-z0-9._@+~-]+)*$ ]]; then
          echo "error: libbox module cache contract has an unsafe $description package: $package" >&2
          return 1
        fi
        ;;
      module)
        if [[ ! "$package" =~ ^[A-Za-z0-9._@+~-]+(/[A-Za-z0-9._@+~-]+)+$ ]]; then
          echo "error: libbox module cache contract has an unsafe $description package: $package" >&2
          return 1
        fi
        ;;
      *)
        echo "error: unsupported libbox module cache package kind: $package_kind" >&2
        return 1
        ;;
    esac
    if [[ "$package" != "." ]]; then
      normalized="${package#./}"
      IFS='/' read -r -a components <<<"$normalized"
      for component in "${components[@]}"; do
        if [[ -z "$component" || "$component" == "." || "$component" == ".." ]]; then
          echo "error: libbox module cache contract has an unsafe $description package: $package" >&2
          return 1
        fi
      done
    fi
    if [[ "$seen" == *" $package "* ]]; then
      echo "error: libbox module cache contract repeats $description package: $package" >&2
      return 1
    fi
    seen+="$package "
  done
}

libbox_load_module_cache_contract() {
  if [[ $# -ne 1 ]]; then
    echo "error: libbox_load_module_cache_contract requires the repository root" >&2
    return 1
  fi
  local repo_root="$1"
  local contract_relative="${LIBBOX_MODULE_CACHE_CONTRACT_PATH:-}"
  local expected_sha256="${LIBBOX_MODULE_CACHE_CONTRACT_SHA256:-}"
  local contract_path actual_sha256 array_name declaration
  if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: libbox module cache contract digest pin is missing or malformed" >&2
    return 1
  fi
  contract_path="$(
    libbox_repository_relative_path \
      "$repo_root" \
      "$contract_relative" \
      "libbox module cache contract"
  )" || return 1
  libbox_require_regular_file "$contract_path" || return 1
  actual_sha256="$(libbox_sha256 "$contract_path")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "error: libbox module cache contract digest mismatch" >&2
    return 1
  fi

  # shellcheck source=scripts/libbox_module_cache_contract.bash
  source "$contract_path"
  for array_name in \
    LIBBOX_MODULE_BUILD_PACKAGES \
    LIBBOX_GOMOBILE_BIND_PACKAGES \
    LIBBOX_RACE_TEST_PACKAGES \
    LIBBOX_TEST_PACKAGES \
    LIBBOX_COMPILE_TEST_PACKAGES \
    LIBBOX_VET_PACKAGES; do
    declaration="$(declare -p "$array_name" 2>/dev/null)" || {
      echo "error: libbox module cache contract is missing array $array_name" >&2
      return 1
    }
    case "$declaration" in
      "declare -a "* | "declare -ar "*) ;;
      *)
        echo "error: libbox module cache contract value $array_name is not an array" >&2
        return 1
        ;;
    esac
  done

  libbox_validate_module_cache_packages \
    "build" local "${LIBBOX_MODULE_BUILD_PACKAGES[@]}" || return 1
  libbox_validate_module_cache_packages \
    "gomobile bind" module "${LIBBOX_GOMOBILE_BIND_PACKAGES[@]}" || return 1
  libbox_validate_module_cache_packages \
    "race-test" local "${LIBBOX_RACE_TEST_PACKAGES[@]}" || return 1
  libbox_validate_module_cache_packages \
    "test" local "${LIBBOX_TEST_PACKAGES[@]}" || return 1
  libbox_validate_module_cache_packages \
    "compile-test" local "${LIBBOX_COMPILE_TEST_PACKAGES[@]}" || return 1
  libbox_validate_module_cache_packages \
    "vet" local "${LIBBOX_VET_PACKAGES[@]}" || return 1

  readonly -a \
    LIBBOX_MODULE_BUILD_PACKAGES \
    LIBBOX_GOMOBILE_BIND_PACKAGES \
    LIBBOX_RACE_TEST_PACKAGES \
    LIBBOX_TEST_PACKAGES \
    LIBBOX_COMPILE_TEST_PACKAGES \
    LIBBOX_VET_PACKAGES
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

libbox_endpoint_conflict_patch_path() {
  libbox_repository_relative_path "$1" "$SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH" "sing-box endpoint conflict patch"
}

libbox_validate_patches() {
  local repo_root="$1"
  local security_patch_path raw_packet_patch_path dns_failover_patch_path endpoint_conflict_patch_path
  security_patch_path="$(libbox_security_patch_path "$repo_root")" || return 1
  raw_packet_patch_path="$(libbox_raw_packet_patch_path "$repo_root")" || return 1
  dns_failover_patch_path="$(libbox_dns_failover_patch_path "$repo_root")" || return 1
  endpoint_conflict_patch_path="$(libbox_endpoint_conflict_patch_path "$repo_root")" || return 1
  libbox_require_regular_file "$security_patch_path" || return 1
  libbox_require_regular_file "$raw_packet_patch_path" || return 1
  libbox_require_regular_file "$dns_failover_patch_path" || return 1
  libbox_require_regular_file "$endpoint_conflict_patch_path" || return 1
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
  if [[ "$(libbox_sha256 "$endpoint_conflict_patch_path")" != "$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256" ]]; then
    echo "error: sing-box endpoint conflict patch digest mismatch" >&2
    return 1
  fi
}

libbox_validate_git_root() {
  local source_root="$1"
  local top_level
  libbox_validate_git_controls "$source_root" || return 1
  top_level="$(libbox_git "$source_root" rev-parse --show-toplevel)" || return 1
  if [[ "$(cd "$top_level" && pwd -P)" != "$source_root" ]]; then
    echo "error: SING_BOX_SOURCE must name the checkout root" >&2
    return 1
  fi
  if [[ "$(libbox_git "$source_root" rev-parse HEAD)" != "$SING_BOX_COMMIT" ]]; then
    echo "error: sing-box checkout is not pinned commit $SING_BOX_COMMIT" >&2
    return 1
  fi
}

libbox_validate_upstream_source() {
  local repo_root="$1"
  local source_root="$2"
  local security_patch_path raw_packet_patch_path dns_failover_patch_path endpoint_conflict_patch_path
  libbox_validate_patches "$repo_root" || return 1
  libbox_validate_git_root "$source_root" || return 1
  if [[ -n "$(libbox_git "$source_root" status --porcelain=v1 --untracked-files=all)" ]]; then
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
  endpoint_conflict_patch_path="$(libbox_endpoint_conflict_patch_path "$repo_root")" || return 1
  # Zero-context patches are admitted only after the exact upstream commit and
  # go.mod/go.sum digests above have been verified.
  if ! libbox_git "$source_root" apply --whitespace=error-all --unidiff-zero --check \
    "$security_patch_path" \
    "$raw_packet_patch_path" \
    "$dns_failover_patch_path" \
    "$endpoint_conflict_patch_path"; then
    echo "error: pinned patches do not apply to the pinned sing-box source" >&2
    return 1
  fi
}

libbox_canonical_diff() {
  local source_root="$1"
  shift
  # Full object IDs and explicit diff settings keep the release digest independent
  # of clone depth, object population, and operator Git configuration.
  libbox_git "$source_root" \
    -c diff.interHunkContext=0 \
    -c diff.suppressBlankEmpty=false \
    --no-pager diff \
    --no-color \
    --no-ext-diff \
    --no-textconv \
    --binary \
    --full-index \
    --no-renames \
    --no-indent-heuristic \
    --diff-algorithm=myers \
    --unified=3 \
    -O/dev/null \
    --src-prefix=a/ \
    --dst-prefix=b/ \
    "$@"
}

libbox_dependency_diff_sha256() {
  local source_root="$1"
  libbox_canonical_diff "$source_root" -- go.mod go.sum |
    shasum -a 256 | awk '{print $1}'
}

libbox_combined_diff_sha256() {
  local source_root="$1"
  local temporary_directory temporary_index digest
  temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/cfw-libbox-index.XXXXXX")"
  temporary_index="$temporary_directory/index"
  if ! libbox_git_with_index "$source_root" "$temporary_index" read-tree HEAD ||
    ! libbox_git_with_index "$source_root" "$temporary_index" add -A -- .; then
    /bin/rm -r "$temporary_directory"
    return 1
  fi
  digest="$(
    libbox_git_with_index "$source_root" "$temporary_index" \
      -c diff.interHunkContext=0 \
      -c diff.suppressBlankEmpty=false \
      --no-pager diff \
      --no-color \
      --no-ext-diff \
      --no-textconv \
      --binary \
      --full-index \
      --no-renames \
      --no-indent-heuristic \
      --diff-algorithm=myers \
      --unified=3 \
      -O/dev/null \
      --src-prefix=a/ \
      --dst-prefix=b/ \
      --cached HEAD -- |
      shasum -a 256 | awk '{print $1}'
  )"
  /bin/rm -r "$temporary_directory"
  printf '%s\n' "$digest"
}

libbox_validate_patched_source() {
  local repo_root="$1"
  local source_root="$2"
  local actual_diff actual_combined_diff ignored_files security_patch_path raw_packet_patch_path dns_failover_patch_path endpoint_conflict_patch_path
  libbox_validate_patches "$repo_root" || return 1
  libbox_validate_git_root "$source_root" || return 1

  ignored_files="$(libbox_git "$source_root" ls-files --others --ignored --exclude-standard)"
  if [[ -n "$ignored_files" ]]; then
    echo "error: patched sing-box checkout contains ignored files" >&2
    return 1
  fi
  actual_diff="$(libbox_dependency_diff_sha256 "$source_root")"
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
  endpoint_conflict_patch_path="$(libbox_endpoint_conflict_patch_path "$repo_root")" || return 1
  if ! libbox_git "$source_root" apply --whitespace=error-all --unidiff-zero --reverse --check \
    "$endpoint_conflict_patch_path"; then
    echo "error: pinned endpoint conflict patch cannot be reversed cleanly" >&2
    return 1
  fi
  if ! libbox_git "$source_root" apply --whitespace=error-all --reverse --check "$dns_failover_patch_path"; then
    echo "error: pinned DNS failover patch cannot be reversed cleanly" >&2
    return 1
  fi
  if ! libbox_git "$source_root" apply --whitespace=error-all --unidiff-zero --reverse --check \
    "$raw_packet_patch_path"; then
    echo "error: pinned raw packet patch cannot be reversed cleanly" >&2
    return 1
  fi
  if ! libbox_git "$source_root" apply --whitespace=error-all --unidiff-zero --reverse --check \
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

  cfw_run_release_python_script \
    "$repository" \
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
    --metadata "endpointConflictPatchSha256=$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256" \
    --metadata "patchedDiffSha256=$SING_BOX_PATCHED_DIFF_SHA256" \
    --metadata "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256" \
    --metadata "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256" \
    --metadata "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256"
}
