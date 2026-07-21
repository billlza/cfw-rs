#!/usr/bin/env bash
# Mihomo fallback controller smoke (secondary core).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
./scripts/assert_apple_silicon.sh

BIN="${CFW_MIHOMO_BIN:-apps/cfw-tauri-shell/resources/cores/clash-darwin}"
if [[ ! -x "$BIN" ]]; then
  ./scripts/fetch_core.sh
  BIN="apps/cfw-tauri-shell/resources/cores/clash-darwin"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/cfw-mihomo-smoke.XXXXXX")"
trap 'kill "$core_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

cat >"$work/config.yaml" <<'EOF'
mixed-port: 17991
external-controller: 127.0.0.1:19091
mode: rule
log-level: warning
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
EOF

"$BIN" -d "$work" -f "$work/config.yaml" >"$work/core.log" 2>&1 &
core_pid=$!

ready=0
for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:19091/configs" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "error: mihomo controller never became ready" >&2
  cat "$work/core.log" >&2 || true
  exit 1
fi

for path in /configs /proxies /connections /version; do
  echo "==> GET $path"
  curl -fsS "http://127.0.0.1:19091$path" | python3 -c 'import json,sys; json.load(sys.stdin); print("ok")'
done

echo "mihomo fallback smoke passed"
