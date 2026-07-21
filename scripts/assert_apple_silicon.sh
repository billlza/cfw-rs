#!/usr/bin/env bash
# Refuse non–Apple Silicon hosts. Clash for Mac never supports Intel / Universal Binary.
set -euo pipefail

arch="$(uname -m)"
if [[ "$arch" != "arm64" ]]; then
  echo "error: Clash for Mac is Apple Silicon only (got uname -m=$arch)" >&2
  echo "Intel Mac and Universal Binary builds are permanently unsupported." >&2
  exit 1
fi

if command -v rustc >/dev/null 2>&1; then
  host="$(rustc -vV | awk -F': ' '/^host:/{print $2}')"
  case "$host" in
    aarch64-apple-darwin) ;;
    *)
      echo "error: rustc host must be aarch64-apple-darwin (got $host)" >&2
      exit 1
      ;;
  esac
fi

echo "ok: Apple Silicon (arm64) host"
