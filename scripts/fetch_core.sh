#!/usr/bin/env bash
# Fetch the pinned mihomo core into resources/cores/clash-darwin.
#
# The core is gitignored (it's a large binary, reproducible from a pinned
# version + SHA-256). These values MUST match the PINNED_MIHOMO_* constants in
# crates/cfw-runtime/src/lib.rs. The checksum is of the *decompressed* binary.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
./scripts/assert_apple_silicon.sh

VERSION="v1.19.28"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/mihomo-darwin-arm64-${VERSION}.gz"
SHA256="55b7286331cb30a54b2564013b02b84a0c280e8b690bd1e5da4b9d4f4ca007ac"
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
