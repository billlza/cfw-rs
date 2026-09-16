#!/bin/bash -p
# Deterministic unsigned CI lane (task 8.4) that exercises the canonical Evidence
# Manifest validator both ways: a well-formed manifest must be accepted and a set
# of known-bad manifests must be rejected. This lane only *consumes*
# scripts/evidence_manifest.py; it never edits the validator internals.
#
# The lane is fail-closed (Requirements 4.1, 6.5): a missing interpreter, a
# missing validator, an accepted bad manifest, or a rejected good manifest all
# abort the lane with a nonzero exit and a specific message. No "|| true", no
# swallowed status, no unconditional skips.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
validator="$repo_root/scripts/evidence_manifest.py"
python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"

if [[ ! -x "$python_bin" ]]; then
  echo "error: closed release Python is required for the evidence manifest lane" >&2
  exit 1
fi
if [[ ! -f "$validator" ]]; then
  echo "error: evidence manifest validator is missing: $validator" >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cfw-evidence-lane.XXXXXX")"
trap '/bin/rm -rf "$workdir"' EXIT

# Emit one good manifest and several distinct bad manifests into $workdir. Each
# bad manifest isolates a different masking/promotion defect the validator must
# reject.
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - "$workdir" <<'PY'
import json
import sys
from pathlib import Path

workdir = Path(sys.argv[1])
commit = "a" * 40
toolchain = "b" * 64
signed_app = "c" * 64
sha = "d" * 64


def report(report_id, kind, bindings):
    return {
        "id": report_id,
        "kind": kind,
        "path": f"reports/{report_id}.json",
        "sha256": sha,
        "status": "passed",
        "bindings": bindings,
    }


def good():
    source_bindings = {"commit": commit}
    return {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": {
            "commit": commit,
            "toolchain_sha256": toolchain,
            "signed_app_sha256": signed_app,
        },
        "reports": [
            report("source-hash", "source_hash", source_bindings),
            report("boundary", "boundary_scan", source_bindings),
        ],
        "capabilities": [
            {
                "id": "global-authority",
                "highest_level": "Source_Implemented",
                "levels": {
                    "Source_Implemented": {"report_ids": ["source-hash", "boundary"]}
                },
            }
        ],
    }


valid = good()
(workdir / "good.json").write_text(json.dumps(valid), encoding="utf-8")

# Bad #1: a masked/skipped report status must never count as evidence.
masked = good()
masked["reports"][0]["status"] = "skipped"
(workdir / "bad-masked-status.json").write_text(json.dumps(masked), encoding="utf-8")

# Bad #2: over-promotion - claim an installed level with only source evidence.
promoted = good()
promoted["capabilities"][0]["highest_level"] = "Unsigned_CI_Verified"
(workdir / "bad-over-promotion.json").write_text(json.dumps(promoted), encoding="utf-8")

# Bad #3: a stale commit binding cannot be reused for this candidate.
stale = good()
stale["reports"][0]["bindings"]["commit"] = "e" * 40
(workdir / "bad-stale-binding.json").write_text(json.dumps(stale), encoding="utf-8")

# Bad #4: duplicate JSON keys must be rejected before interpretation.
(workdir / "bad-duplicate-keys.json").write_text(
    '{"schema_version": 1, "schema_version": 1, "manifest_version": '
    '"evidence-manifest-v1", "identity": {}, "reports": [], "capabilities": []}',
    encoding="utf-8",
)
PY

# Positive case: the good manifest must be accepted (exit 0).
if ! PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error \
  "$validator" "$workdir/good.json" >/dev/null; then
  echo "error: evidence manifest lane rejected a well-formed manifest" >&2
  exit 1
fi
echo "evidence manifest lane: well-formed manifest accepted"

# Negative cases: each known-bad manifest must be rejected (nonzero exit). A
# validator that accepts any of them fails this lane immediately.
for bad in bad-masked-status bad-over-promotion bad-stale-binding bad-duplicate-keys; do
  if PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error \
    "$validator" "$workdir/$bad.json" >/dev/null 2>&1; then
    echo "error: evidence manifest validator accepted a known-bad manifest: $bad" >&2
    exit 1
  fi
  echo "evidence manifest lane: rejected known-bad manifest ($bad)"
done

echo "evidence manifest lane verified: positive and negative cases pass"
