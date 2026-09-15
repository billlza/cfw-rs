#!/bin/bash -p
# Go adds -lobjc once per package containing Objective-C source. Apple's linker
# ignores later copies and warns. Keep the first runtime library argument while
# preserving every other argument and every compiler/linker diagnostic.
set -euo pipefail

clang="${DEVELOPER_DIR:-}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
if [[ "$clang" != /* || ! -x "$clang" || -z "${DEVELOPER_DIR:-}" ]]; then
  echo "error: the selected Xcode Clang linker is unavailable" >&2
  exit 1
fi

arguments=()
objc_seen=0
for argument in "$@"; do
  if [[ "$argument" == -lobjc ]]; then
    if [[ $objc_seen -eq 1 ]]; then
      continue
    fi
    objc_seen=1
  fi
  arguments+=("$argument")
done
exec "$clang" "${arguments[@]}"
