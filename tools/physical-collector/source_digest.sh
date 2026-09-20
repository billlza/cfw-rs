#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$repository"

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

if find . -type l -print -quit | grep -q .; then
  echo "error: collector source closure contains a symbolic link" >&2
  exit 1
fi

paths="$(mktemp -t cfw-collector-paths.XXXXXX)"
manifest="$(mktemp -t cfw-collector-manifest.XXXXXX)"
trap 'rm -f "$paths" "$manifest"' EXIT

LC_ALL=C find . -type f \
  ! -name '.collector-source-sha256' \
  ! -name 'physical-collector' \
  -print | LC_ALL=C sort >"$paths"

printf 'cfw-physical-collector-source-v1\n' >"$manifest"
while IFS= read -r relative; do
  path="${relative#./}"
  if [[ ! "$path" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "error: non-canonical collector source path: $path" >&2
    exit 1
  fi
  size="$(wc -c <"$relative" | tr -d '[:space:]')"
  digest="$(sha256_file "$relative")"
  printf '%s\t%s\t%s\n' "$digest" "$size" "$path" >>"$manifest"
done <"$paths"

sha256_stdin <"$manifest"
