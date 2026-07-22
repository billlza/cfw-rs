#!/usr/bin/env bash
# Cargo build scripts may validate local prebuilt native inputs, but may not
# download dependencies or recursively invoke another build system.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

build_scripts="$(git ls-files '**/build.rs' 'build.rs')"
if [[ -z "$build_scripts" ]]; then
  echo "error: no tracked Cargo build scripts found" >&2
  exit 1
fi

while IFS= read -r build_script; do
  if grep -En \
    'std::process|Command::new|reqwest|ureq|curl|wget|git clone|https?://|xcodebuild|swift build|go run|npm |cargo (build|run)' \
    "$build_script"; then
    echo "error: forbidden network or recursive build action in $build_script" >&2
    exit 1
  fi
done <<<"$build_scripts"

python3 - "$repo_root/apps/cfw-tauri-shell/tauri.conf.json" <<'PY'
import json
from pathlib import Path
import sys

config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if config.get("bundle", {}).get("createUpdaterArtifacts") is not False:
    raise SystemExit(
        "error: Tauri automatic updater artifacts bypass the reviewed publication gate"
    )
PY

for release_script in scripts/make_dmg.sh scripts/make_updater_manifest.sh; do
  grep -Fq "source \"\$repo_root/scripts/release_publication_gate.sh\"" "$release_script" || {
    echo "error: $release_script does not source the publication gate" >&2
    exit 1
  }
  grep -Fq 'verify_release_publication_evidence' "$release_script" || {
    echo "error: $release_script does not enforce the publication gate" >&2
    exit 1
  }
done

echo "Cargo build-script boundary verified"
