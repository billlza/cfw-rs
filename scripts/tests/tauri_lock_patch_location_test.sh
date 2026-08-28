#!/bin/bash -p
# Prove Tauri lock patching and Cargo workspace discovery are independent of an
# enclosing release worktree.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../.." && /bin/pwd -P)"
readonly repo_root
# shellcheck source=scripts/release_python_launcher.sh
source "$repo_root/scripts/release_python_launcher.sh"
readonly lock_patch="$repo_root/scripts/tauri-cli-2.11.4-spin-0.9.9.patch"
readonly cargo_bin="${CFW_RELEASE_CARGO_EXECUTABLE:-}"
readonly python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
readonly inside_parent="$repo_root/target/release-gate-tests"
readonly outside_parent="/private/tmp"
inside_root=""
outside_root=""

[[ -x "$cargo_bin" && -x "$python_bin" ]] || {
  echo "error: closed Cargo and Python are required for the Tauri location test" >&2
  exit 1
}

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

verify_cargo_workspace_location() {
  [[ $# -eq 2 ]] || return 2
  local fixture_root="$1"
  local expect_parent_repository="$2"
  local staging="$fixture_root/cargo-staging"
  local source_root="$staging/tauri-cli-2.11.4"
  local cargo_manifest="$source_root/Cargo.toml"
  local source_lock="$source_root/Cargo.lock"
  local workspace_manifest="$staging/Cargo.toml"
  local workspace_lock="$staging/Cargo.lock"
  local cargo_home="$fixture_root/cargo-home"
  local metadata_json="$fixture_root/metadata.json"
  local metadata_stderr="$fixture_root/metadata.stderr"
  local fetch_stdout="$fixture_root/fetch.stdout"
  local fetch_stderr="$fixture_root/fetch.stderr"
  local ambient_stdout="$fixture_root/ambient.stdout"
  local ambient_stderr="$fixture_root/ambient.stderr"
  local source_configuration="$staging/.cargo/config.toml"
  local no_sentinel_status no_root_lock_status
  local source_lock_sha256_before workspace_manifest_sha256

  /bin/mkdir -m 0700 "$staging" "$cargo_home"
  /bin/mkdir -m 0755 "$source_root" "$source_root/src"
  {
    printf '[package]\n'
    printf 'name = "tauri-cli"\n'
    printf 'version = "2.11.4"\n'
    printf 'edition = "2021"\n'
  } >"$cargo_manifest"
  printf 'fn main() {}\n' >"$source_root/src/main.rs"
  {
    printf '# This file is automatically @generated by Cargo.\n'
    printf '# It is not intended for manual editing.\n'
    printf 'version = 4\n\n'
    printf '[[package]]\n'
    printf 'name = "tauri-cli"\n'
    printf 'version = "2.11.4"\n'
  } >"$source_lock"

  set +e
  (
    cd "$repo_root"
    CARGO_HOME="$cargo_home" "$cargo_bin" metadata \
      --manifest-path "$cargo_manifest" \
      --locked \
      --offline \
      --no-deps \
      --format-version 1
  ) >"$fixture_root/no-sentinel.stdout" \
    2>"$fixture_root/no-sentinel.stderr"
  no_sentinel_status=$?
  set -e
  if [[ "$expect_parent_repository" == "yes" ]]; then
    [[ "$no_sentinel_status" -ne 0 ]] || {
      echo "error: nested Cargo fixture did not discover the enclosing workspace" >&2
      return 1
    }
    /usr/bin/grep -Fq \
      "current package believes it's in a workspace when it's not" \
      "$fixture_root/no-sentinel.stderr" || {
      echo "error: nested Cargo fixture failed for an unexpected reason" >&2
      return 1
    }
  else
    [[ "$no_sentinel_status" -eq 0 ]] || {
      echo "error: external Cargo fixture was not standalone before isolation" >&2
      return 1
    }
  fi

  {
    printf '[workspace]\n'
    printf 'members = ["tauri-cli-2.11.4"]\n'
    printf 'resolver = "2"\n'
  } >"$workspace_manifest"
  /bin/chmod 0600 "$workspace_manifest"
  workspace_manifest_sha256="$(
    printf '[workspace]\nmembers = ["tauri-cli-2.11.4"]\nresolver = "2"\n' |
      /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
  )"
  printf '%s  %s\n' "$workspace_manifest_sha256" "$workspace_manifest" |
    /usr/bin/shasum -a 256 --check >/dev/null
  [[ "$(/usr/bin/stat -f '%Lp' "$workspace_manifest")" == "600" ]] || {
    echo "error: Tauri fixture workspace manifest mode differs" >&2
    return 1
  }

  set +e
  (
    cd "$repo_root"
    CARGO_HOME="$cargo_home" "$cargo_bin" fetch \
      --manifest-path "$cargo_manifest" \
      --locked \
      --offline \
      --target aarch64-apple-darwin
  ) >"$fixture_root/no-root-lock.stdout" \
    2>"$fixture_root/no-root-lock.stderr"
  no_root_lock_status=$?
  set -e
  [[ "$no_root_lock_status" -ne 0 ]] || {
    echo "error: locked Tauri fetch accepted a missing workspace root lock" >&2
    return 1
  }
  /usr/bin/grep -Fq "cannot create the lock file" \
    "$fixture_root/no-root-lock.stderr" || {
    echo "error: missing Tauri workspace root lock failed unexpectedly" >&2
    return 1
  }

  /usr/bin/install -m 0600 "$source_lock" "$workspace_lock"
  /usr/bin/cmp -s "$source_lock" "$workspace_lock" || {
    echo "error: Tauri fixture workspace lock differs from its source lock" >&2
    return 1
  }
  [[ "$(/usr/bin/stat -f '%Lp' "$workspace_lock")" == "600" ]] || {
    echo "error: Tauri fixture workspace lock mode differs" >&2
    return 1
  }
  source_lock_sha256_before="$(
    /usr/bin/shasum -a 256 "$source_lock" | /usr/bin/awk '{print $1}'
  )"
  printf '%s  %s\n' "$source_lock_sha256_before" "$workspace_lock" |
    /usr/bin/shasum -a 256 --check >/dev/null

  (
    cd "$repo_root"
    CARGO_HOME="$cargo_home" "$cargo_bin" metadata \
      --manifest-path "$cargo_manifest" \
      --locked \
      --offline \
      --no-deps \
      --format-version 1
  ) >"$metadata_json" 2>"$metadata_stderr"
  [[ ! -s "$metadata_stderr" ]] || {
    echo "error: isolated Tauri Cargo metadata emitted diagnostics" >&2
    return 1
  }
  "$python_bin" -I -S -B -W error - \
    "$metadata_json" "$staging" "$cargo_manifest" <<'PY'
import json
from pathlib import Path
import sys

metadata_path, expected_workspace, expected_manifest = sys.argv[1:]
with Path(metadata_path).open(encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("workspace_root") != expected_workspace:
    raise SystemExit("error: Cargo metadata escaped the Tauri staging workspace")
packages = value.get("packages")
members = value.get("workspace_members")
if not isinstance(packages, list) or len(packages) != 1:
    raise SystemExit("error: Tauri staging workspace has the wrong package set")
if not isinstance(members, list) or len(members) != 1:
    raise SystemExit("error: Tauri staging workspace has the wrong member set")
package = packages[0]
if (
    package.get("name") != "tauri-cli"
    or package.get("version") != "2.11.4"
    or package.get("manifest_path") != expected_manifest
    or package.get("id") != members[0]
):
    raise SystemExit("error: Tauri staging workspace member identity differs")
PY

  (
    cd "$repo_root"
    CARGO_HOME="$cargo_home" "$cargo_bin" fetch \
      --manifest-path "$cargo_manifest" \
      --locked \
      --offline \
      --target aarch64-apple-darwin
  ) >"$fetch_stdout" 2>"$fetch_stderr"
  [[ ! -s "$fetch_stdout" && ! -s "$fetch_stderr" ]] || {
    echo "error: isolated Tauri Cargo fetch emitted diagnostics" >&2
    return 1
  }
  /usr/bin/cmp -s "$source_lock" "$workspace_lock" || {
    echo "error: Cargo changed a Tauri fixture lock" >&2
    return 1
  }
  printf '%s  %s\n' "$source_lock_sha256_before" "$source_lock" |
    /usr/bin/shasum -a 256 --check >/dev/null
  printf '%s  %s\n' "$source_lock_sha256_before" "$workspace_lock" |
    /usr/bin/shasum -a 256 --check >/dev/null
  printf '%s  %s\n' "$workspace_manifest_sha256" "$workspace_manifest" |
    /usr/bin/shasum -a 256 --check >/dev/null

  /bin/mkdir -m 0700 "$staging/.cargo"
  printf '[build]\njobs = "invalid"\n' >"$source_configuration"
  if cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/release_cargo_inputs.py" \
    reject-ambient --repository "$repo_root" --release-home "$HOME" \
    --additional-working-directory "$source_root" \
    >"$ambient_stdout" 2>"$ambient_stderr"; then
    echo "error: Tauri source ancestor Cargo configuration was accepted" >&2
    return 1
  fi
  /usr/bin/grep -Fq "$source_configuration" "$ambient_stderr" || {
    echo "error: Tauri source ancestor Cargo rejection lacked the exact path" >&2
    return 1
  }
}

/bin/mkdir -p "$inside_parent"
inside_root="$(/usr/bin/mktemp -d \
  "$inside_parent/tauri-lock-patch-location.XXXXXX")"
outside_root="$(/usr/bin/mktemp -d \
  "$outside_parent/tauri-lock-patch-location.XXXXXX")"
readonly inside_root outside_root

repository_manifest_before="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.toml" | /usr/bin/awk '{print $1}')"
repository_lock_before="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.lock" | /usr/bin/awk '{print $1}')"
repository_status_before="$(/usr/bin/git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
verify_patch_location "$inside_root" yes
verify_patch_location "$outside_root" no
verify_cargo_workspace_location "$inside_root" yes
verify_cargo_workspace_location "$outside_root" no
repository_manifest_after="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.toml" | /usr/bin/awk '{print $1}')"
repository_lock_after="$(/usr/bin/shasum -a 256 "$repo_root/Cargo.lock" | /usr/bin/awk '{print $1}')"
repository_status_after="$(/usr/bin/git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
[[ "$repository_manifest_after" == "$repository_manifest_before" ]] || {
  echo "error: Tauri staging location test changed the repository Cargo.toml" >&2
  exit 1
}
[[ "$repository_lock_after" == "$repository_lock_before" ]] || {
  echo "error: Tauri lock patch location test changed the repository Cargo.lock" >&2
  exit 1
}
[[ "$repository_status_after" == "$repository_status_before" ]] || {
  echo "error: Tauri lock patch location test changed the parent repository" >&2
  exit 1
}

echo "Tauri lock patch location test passed"
