#!/usr/bin/env bash
# Exercises the deterministic evidence-manifest CI lane end to end: the lane must
# succeed against the checked-in validator (positive path) and its internal
# negative cases must all be rejected. A regression that makes the validator
# accept masked, over-promoted, stale, or duplicate-key manifests fails here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
lane="$repo_root/scripts/verify_evidence_manifest_lane.sh"

if [[ ! -x "$lane" && ! -f "$lane" ]]; then
  echo "error: evidence manifest lane script is missing: $lane" >&2
  exit 1
fi

output="$(bash "$lane")"
printf '%s\n' "$output"

for expected in \
  "well-formed manifest accepted" \
  "rejected known-bad manifest (bad-masked-status)" \
  "rejected known-bad manifest (bad-over-promotion)" \
  "rejected known-bad manifest (bad-stale-binding)" \
  "rejected known-bad manifest (bad-duplicate-keys)" \
  "positive and negative cases pass"; do
  if ! printf '%s\n' "$output" | grep -Fq "$expected"; then
    echo "error: evidence manifest lane did not report: $expected" >&2
    exit 1
  fi
done

echo "evidence manifest lane test passed"
