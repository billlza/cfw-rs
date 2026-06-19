#!/usr/bin/env bash
# Fetch the pinned mihomo core into resources/cores/clash-darwin.
#
# The core is gitignored (it's a large binary, reproducible from a pinned
# version + SHA-256). These values MUST match the PINNED_MIHOMO_* constants in
# crates/cfw-runtime/src/lib.rs. The checksum is of the *decompressed* binary.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

VERSION="v1.19.27"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/mihomo-darwin-arm64-${VERSION}.gz"
SHA256="6f01da0543dc3043b7e1a79fae421f0f3003cc05bcd6a1d0a211eb9ddc5656d6"
DEST="apps/cfw-tauri-shell/resources/cores/clash-darwin"

if [[ -f "$DEST" ]] && shasum -a 256 "$DEST" | grep -qi "$SHA256"; then
  echo "core already present and verified: $DEST"
  exit 0
fi

echo "==> downloading mihomo ${VERSION} (arm64)"
mkdir -p "$(dirname "$DEST")"
tmp_gz="$(mktemp)"
tmp_bin="$(mktemp)"
trap 'rm -f "$tmp_gz" "$tmp_bin"' EXIT
curl -fsSL --connect-timeout 10 -o "$tmp_gz" "$URL"
gunzip -c "$tmp_gz" > "$tmp_bin"

actual="$(shasum -a 256 "$tmp_bin" | cut -d' ' -f1)"
if [[ "$actual" != "$SHA256" ]]; then
  echo "error: checksum mismatch (expected $SHA256, got $actual)" >&2
  exit 1
fi

install -m 0755 "$tmp_bin" "$DEST"
echo "==> installed verified core -> $DEST"
