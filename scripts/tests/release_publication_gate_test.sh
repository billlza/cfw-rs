#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$repo_root/scripts/release_publication_gate.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-publication-fixture.XXXXXX")"
trap '/bin/rm -rf "$fixture_root"' EXIT

prepared="$fixture_root/prepared"
app="$fixture_root/Fixture.app"
mkdir -p \
  "$prepared/source/application" \
  "$prepared/source/dependency" \
  "$prepared/licenses/application" \
  "$prepared/licenses/dependency" \
  "$prepared/artifacts" \
  "$prepared/graphs" \
  "$app/Contents"

printf '%s\n' 'fixture application source' >"$prepared/source/application/main.txt"
printf '%s\n' 'fixture dependency source' >"$prepared/source/dependency/lib.txt"
printf '%s\n' 'GPL-3.0-or-later fixture text' >"$prepared/licenses/application/LICENSE"
printf '%s\n' 'MIT fixture text' >"$prepared/licenses/dependency/LICENSE"
printf '%s\n' '{"artifact":"fixture"}' >"$prepared/artifacts/fixture-manifest.json"
printf '%s\n' '{"graph":"fixture"}' >"$prepared/graphs/fixture-graph.json"
printf '%s\n' 'fixture app payload' >"$app/Contents/payload.txt"

python3 - "$prepared/closure-components.json" <<'PY'
import json
import sys
from pathlib import Path

payload = {
    "schema_version": 1,
    "fixture": True,
    "product": {
        "name": "Publication Fixture",
        "version": "1.0.0",
        "build_number": "1",
    },
    "components": [
        {
            "id": "application:fixture@1.0.0",
            "name": "Publication Fixture",
            "version": "1.0.0",
            "ecosystem": "application",
            "scope": "runtime",
            "purl": "pkg:generic/publication-fixture@1.0.0",
            "license_expression": "GPL-3.0-or-later",
            "copyright_text": "Copyright 2026 fixture",
            "license_files": ["licenses/application/LICENSE"],
            "source_path": "source/application",
        },
        {
            "id": "cargo:fixture-dependency@2.0.0",
            "name": "fixture-dependency",
            "version": "2.0.0",
            "ecosystem": "cargo",
            "scope": "runtime",
            "purl": "pkg:cargo/fixture-dependency@2.0.0",
            "license_expression": "MIT",
            "copyright_text": "Copyright fixture dependency authors",
            "license_files": ["licenses/dependency/LICENSE"],
            "source_path": "source/dependency",
        },
    ],
    "build_tools": [],
    "relationships": [
        {
            "source": "application:fixture@1.0.0",
            "target": "cargo:fixture-dependency@2.0.0",
            "type": "DEPENDS_ON",
        }
    ],
    "artifacts": [
        {
            "id": "artifact:fixture",
            "kind": "fixture-manifest",
            "path": "artifacts/fixture-manifest.json",
            "component_ids": ["application:fixture@1.0.0"],
        }
    ],
    "graphs": [
        {
            "id": "graph:fixture",
            "kind": "fixture-graph",
            "path": "graphs/fixture-graph.json",
            "component_ids": [
                "application:fixture@1.0.0",
                "cargo:fixture-dependency@2.0.0",
            ],
        }
    ],
}
Path(sys.argv[1]).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
PY

machine="$fixture_root/machine-closure.json"
closure_sha="$(python3 "$repo_root/scripts/publication_evidence.py" draft \
  --prepared "$prepared" \
  --app "$app" \
  --output "$machine" \
  --fixture)"

bad_license="$fixture_root/bad-license"
cp -R "$prepared" "$bad_license"
python3 - "$bad_license/closure-components.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["components"][1]["license_expression"] = "NOASSERTION"
path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
PY
if python3 "$repo_root/scripts/publication_evidence.py" draft \
  --prepared "$bad_license" \
  --app "$app" \
  --output "$fixture_root/bad-license.json" \
  --fixture 2>"$fixture_root/bad-license.stderr"; then
  echo "error: publication draft accepted NOASSERTION" >&2
  exit 1
fi
grep -Fq "unreviewed license expression" "$fixture_root/bad-license.stderr"

reverse_payload="$fixture_root/reverse-payload"
cp -R "$prepared" "$reverse_payload"
mkdir -p "$reverse_payload/source/application/reverse"
printf '%s\n' 'reference-only payload' >"$reverse_payload/source/application/reverse/forbidden.bin"
if python3 "$repo_root/scripts/publication_evidence.py" draft \
  --prepared "$reverse_payload" \
  --app "$app" \
  --output "$fixture_root/reverse-payload.json" \
  --fixture 2>"$fixture_root/reverse-payload.stderr"; then
  echo "error: publication draft accepted reverse payload" >&2
  exit 1
fi
grep -Fq "reference-only reverse payload is forbidden" "$fixture_root/reverse-payload.stderr"

review="$fixture_root/legal-review.json"
python3 - "$review" "$closure_sha" <<'PY'
import json
import sys
from pathlib import Path

review = {
    "schema_version": 1,
    "decision": "approved",
    "reviewer": "Fixture Reviewer",
    "reviewed_at": "2026-07-22T00:00:00Z",
    "closure_sha256": sys.argv[2],
    "component_ids": [
        "application:fixture@1.0.0",
        "cargo:fixture-dependency@2.0.0",
    ],
    "license_texts_reviewed": True,
    "source_scope_reviewed": True,
    "notes": "Fixture review exercises the sealed evidence contract.",
}
Path(sys.argv[1]).write_text(json.dumps(review, sort_keys=True), encoding="utf-8")
PY

evidence="$fixture_root/evidence"
python3 "$repo_root/scripts/publication_evidence.py" finalize \
  --prepared "$prepared" \
  --app "$app" \
  --review "$review" \
  --output "$evidence" \
  --fixture
python3 "$repo_root/scripts/publication_evidence.py" verify \
  --evidence "$evidence" \
  --app "$app" \
  --fixture

if python3 "$repo_root/scripts/publication_evidence.py" verify \
  --evidence "$fixture_root/missing" \
  --app "$app" \
  --fixture 2>"$fixture_root/missing.stderr"; then
  echo "error: publication gate accepted missing evidence" >&2
  exit 1
fi
grep -Eq "No such file or directory|does not exist" "$fixture_root/missing.stderr"

if CFW_PUBLICATION_EVIDENCE_DIR="$evidence" \
  verify_release_publication_evidence "$app" 2>"$fixture_root/fixed-path.stderr"; then
  echo "error: production publication gate accepted a non-candidate app" >&2
  exit 1
fi
grep -Fq "accepts only the fixed 0.4.0 signed app" "$fixture_root/fixed-path.stderr"

printf '%s\n' 'modified app payload' >"$app/Contents/payload.txt"
if python3 "$repo_root/scripts/publication_evidence.py" verify \
  --evidence "$evidence" \
  --app "$app" \
  --fixture 2>"$fixture_root/app-tamper.stderr"; then
  echo "error: publication verifier accepted an app not bound by the closure" >&2
  exit 1
fi
grep -Fq "signed app differs from publication evidence" "$fixture_root/app-tamper.stderr"
printf '%s\n' 'fixture app payload' >"$app/Contents/payload.txt"

printf '%s\n' 'tampered' >>"$evidence/licenses/dependency/LICENSE"
if python3 "$repo_root/scripts/publication_evidence.py" verify \
  --evidence "$evidence" \
  --app "$app" \
  --fixture 2>"$fixture_root/tamper.stderr"; then
  echo "error: publication verifier accepted tampered evidence" >&2
  exit 1
fi
grep -Fq "added, removed, or modified" "$fixture_root/tamper.stderr"

echo "release publication evidence fixture passed and tampering failed closed"
