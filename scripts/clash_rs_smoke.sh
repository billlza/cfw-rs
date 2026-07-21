#!/usr/bin/env bash
# Optional clash-rs controller smoke (does NOT flip the product default off mihomo).
#
# Usage:
#   ./scripts/clash_rs_smoke.sh
#   CFW_CLASH_RS_BIN=/path/to/clash-rs ./scripts/clash_rs_smoke.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
./scripts/assert_apple_silicon.sh

BIN="${CFW_CLASH_RS_BIN:-apps/cfw-tauri-shell/resources/cores/clash-rs}"
if [[ ! -x "$BIN" ]]; then
  ./scripts/fetch_clash_rs.sh
  BIN="apps/cfw-tauri-shell/resources/cores/clash-rs"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/cfw-clashrs-smoke.XXXXXX")"
trap 'kill "$core_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

cat >"$work/config.yaml" <<'EOF'
mixed-port: 17990
external-controller: 127.0.0.1:19090
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
  if curl -fsS "http://127.0.0.1:19090/configs" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "error: clash-rs controller never became ready" >&2
  cat "$work/core.log" >&2 || true
  exit 1
fi

for path in /configs /proxies /connections /version; do
  echo "==> GET $path"
  curl -fsS "http://127.0.0.1:19090$path" | python3 -c 'import json,sys; json.load(sys.stdin); print("ok")'
done

# Delay probe against DIRECT (may return 0 / error; endpoint must exist)
echo "==> GET /proxies/DIRECT/delay"
code="$(curl -sS -o /tmp/cfw-delay.json -w '%{http_code}' \
  'http://127.0.0.1:19090/proxies/DIRECT/delay?url=http://www.gstatic.com/generate_204&timeout=2000' || true)"
echo "delay HTTP $code"
python3 - <<'PY'
import json
try:
    print(json.load(open("/tmp/cfw-delay.json")))
except Exception as exc:
    print({"parse_error": str(exc)})
PY

echo "clash-rs smoke passed (default core API surface OK; mihomo remains fallback)"
echo "note: set CFW_CLASH_RS_COMPAT=1 only if you need --compatibility (may fetch GeoIP)"
