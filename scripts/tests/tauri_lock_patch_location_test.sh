#!/bin/bash -p
# Prove the pinned Tauri lock patch is independent of an enclosing Git worktree.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
readonly repo_root
readonly lock_patch="$repo_root/scripts/tauri-cli-2.11.4-spin-0.9.9.patch"
readonly inside_parent="$repo_root/target/release-gate-tests"
readonly outside_parent="/private/tmp"
inside_root=""
outside_root=""

cleanup() {
  local original_status=$?
  local cleanup_failed=0
  trap - EXIT
  if [[ -n "${inside_root:-}" ]]; then
    if [[ "$inside_root" == "$inside_parent/tauri-lock-patch-location."* && \
      -d "$inside_root" && ! -L "$inside_root" ]]; then
      /bin/rm -rf -- "$inside_root" || cleanup_failed=1
    else
      echo "error: refusing to clean an unexpected in-repository fixture" >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "${outside_root:-}" ]]; then
    if [[ "$outside_root" == "$outside_parent/tauri-lock-patch-location."* && \
      -d "$outside_root" && ! -L "$outside_root" ]]; then
      /bin/rm -rf -- "$outside_root" || cleanup_failed=1
    else
      echo "error: refusing to clean an unexpected external fixture" >&2
      cleanup_failed=1
    fi
  fi
  if (( cleanup_failed != 0 )); then
    exit 1
  fi
  exit "$original_status"
}
trap cleanup EXIT

write_lock() {
  [[ $# -eq 3 ]] || return 2
  local output="$1"
  local version="$2"
  local checksum="$3"
  local line
  {
    for ((line = 1; line <= 6299; line += 1)); do
      printf '# fixture line %d\n' "$line"
    done
    printf 'version = "%s"\n' "$version"
    printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    printf 'checksum = "%s"\n' "$checksum"
  } >"$output"
}

verify_patch_location() {
  [[ $# -eq 2 ]] || return 2
  local fixture_root="$1"
  local expect_parent_repository="$2"
  local staging="$fixture_root/staging"
  local source_root="$staging/tauri-cli-2.11.4"
  local cargo_lock="$source_root/Cargo.lock"
  local expected_lock="$fixture_root/expected.Cargo.lock"
  local actual_sha256 expected_sha256 discovered_repository

  /bin/mkdir -m 0700 "$staging" "$source_root"
  write_lock \
    "$cargo_lock" \
    "0.9.8" \
    "6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67"
  write_lock \
    "$expected_lock" \
    "0.9.9" \
    "3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e"

  if [[ "$expect_parent_repository" == "yes" ]]; then
    discovered_repository="$(/usr/bin/git -C "$source_root" rev-parse --show-toplevel)"
    [[ "$discovered_repository" == "$repo_root" ]] || {
      echo "error: nested fixture did not discover the enclosing repository" >&2
      return 1
    }
  fi
  if GIT_CEILING_DIRECTORIES="$staging" \
    /usr/bin/git -C "$source_root" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "error: Tauri patch fixture escaped its Git discovery ceiling" >&2
    return 1
  fi

  GIT_CEILING_DIRECTORIES="$staging" \
    /usr/bin/git -C "$source_root" apply --unidiff-zero --check "$lock_patch"
  GIT_CEILING_DIRECTORIES="$staging" \
    /usr/bin/git -C "$source_root" apply --unidiff-zero "$lock_patch"
  /usr/bin/cmp -s "$cargo_lock" "$expected_lock" || {
    echo "error: Tauri lock patch did not modify the exact extracted lock" >&2
    return 1
  }
  actual_sha256="$(/usr/bin/shasum -a 256 "$cargo_lock" | /usr/bin/awk '{print $1}')"
  expected_sha256="$(/usr/bin/shasum -a 256 "$expected_lock" | /usr/bin/awk '{print $1}')"
  [[ "$actual_sha256" == "$expected_sha256" ]] || {
    echo "error: Tauri lock patch result digest differs by staging location" >&2
    return 1
  }
  GIT_CEILING_DIRECTORIES="$staging" \
    /usr/bin/git -C "$source_root" apply --unidiff-zero --reverse --check "$lock_patch"
}

/bin/mkdir -p "$inside_parent"
inside_root="$(/usr/bin/mktemp -d \
  "$inside_parent/tauri-lock-patch-location.XXXXXX")"
outside_root="$(/usr/bin/mktemp -d \
  "$outside_parent/tauri-lock-patch-location.XXXXXX")"
readonly inside_root outside_root

repository_lock_before="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.lock" | /usr/bin/awk '{print $1}')"
repository_status_before="$(/usr/bin/git -C "$repo_root" status --porcelain=v1 --untracked-files=no)"
verify_patch_location "$inside_root" yes
verify_patch_location "$outside_root" no
repository_lock_after="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.lock" | /usr/bin/awk '{print $1}')"
repository_status_after="$(/usr/bin/git -C "$repo_root" status --porcelain=v1 --untracked-files=no)"
[[ "$repository_lock_after" == "$repository_lock_before" ]] || {
  echo "error: Tauri lock patch location test changed the repository Cargo.lock" >&2
  exit 1
}
[[ "$repository_status_after" == "$repository_status_before" ]] || {
  echo "error: Tauri lock patch location test changed the parent repository" >&2
  exit 1
}

echo "Tauri lock patch location test passed"
