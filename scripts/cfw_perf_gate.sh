#!/usr/bin/env bash
# Record arm64 controller probe metrics. Does NOT claim 「3× CFW」 without a
# same-machine CFW baseline JSON (see docs/performance-stability-targets.md).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
./scripts/assert_apple_silicon.sh

BASE_URL="${CFW_PERF_BASE:-http://127.0.0.1:9090}"
OUT_DIR="${CFW_PERF_OUT:-target/perf-gate}"
mkdir -p "$OUT_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$OUT_DIR/cfw-perf-$stamp.json"

if ! curl -fsS --connect-timeout 2 "$BASE_URL/configs" >/dev/null 2>&1; then
  cat >"$out" <<EOF
{
  "status": "skipped",
  "reason": "controller not reachable at $BASE_URL",
  "claim_3x_cfw": false,
  "note": "Do not advertise 3× CFW until a same-machine CFW baseline is compared."
}
EOF
  echo "perf-gate skipped (no live controller); wrote $out"
  # Soft gate: recording skip is success for CI until a dedicated runner owns a core.
  exit 0
fi

python3 scripts/perf_probe.py \
  --base-url "$BASE_URL" \
  --samples "${CFW_PERF_SAMPLES:-5}" \
  --out "$out" \
  || true

python3 - <<PY
import json, pathlib
path = pathlib.Path("$out")
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {"raw": path.read_text()[:2000]}
data["claim_3x_cfw"] = False
data["note"] = (
    "Metrics recorded only. Do not advertise 3× CFW until a same-machine "
    "CFW 0.20.39 baseline JSON is compared on Apple Silicon."
)
path.write_text(json.dumps(data, indent=2) + "\n")
print(path)
PY
