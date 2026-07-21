#!/usr/bin/env bash
# Fetch pinned clash-rs aarch64 into resources/cores/clash-rs.
# Values MUST match PINNED_CLASH_RS_* in crates/cfw-runtime/src/lib.rs.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
./scripts/assert_apple_silicon.sh

VERSION="v0.10.7"
URL="https://github.com/Watfaq/clash-rs/releases/download/${VERSION}/clash-rs-aarch64-apple-darwin"
SHA256="d1be0a2c2bf8ecbb4841a4992b24b6bcb5b5de46214215934ac2eb18cdc9f0c9"
DEST="apps/cfw-tauri-shell/resources/cores/clash-rs"

if [[ -f "$DEST" ]] && shasum -a 256 "$DEST" | grep -qi "$SHA256"; then
  echo "clash-rs already present and verified: $DEST"
  exit 0
fi

echo "==> downloading clash-rs ${VERSION} (aarch64-apple-darwin)"
mkdir -p "$(dirname "$DEST")"
tmp_bin="$(mktemp)"
trap 'rm -f "$tmp_bin"' EXIT
curl -fsSL --connect-timeout 10 -o "$tmp_bin" "$URL"

actual="$(shasum -a 256 "$tmp_bin" | cut -d' ' -f1)"
if [[ "$actual" != "$SHA256" ]]; then
  echo "error: checksum mismatch (expected $SHA256, got $actual)" >&2
  exit 1
fi

# Reject accidental Intel downloads even if checksum somehow matched a wrong pin.
if file "$tmp_bin" | grep -qi 'x86_64'; then
  echo "error: Intel binary refused (Apple Silicon only)" >&2
  exit 1
fi

install -m 0755 "$tmp_bin" "$DEST"
echo "==> installed verified clash-rs -> $DEST"
