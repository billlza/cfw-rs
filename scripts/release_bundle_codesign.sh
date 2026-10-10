#!/bin/bash
# Source-only boundary for code-signing distributable bundle content. The
# transaction-owned caller keeps its private default umask; this subshell
# narrows only the files that codesign creates inside the bundle.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "error: release_bundle_codesign.sh must be sourced" >&2
  exit 2
fi

cfw_codesign_distribution_bundle() (
  umask 022
  exec /usr/bin/codesign "$@"
)
