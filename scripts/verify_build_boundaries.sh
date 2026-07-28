#!/usr/bin/env bash
# Cargo build scripts may validate local prebuilt native inputs, but may not
# download dependencies or recursively invoke another build system.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
cfw_require_supported_python

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_release_authority_gate.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_pinned_build_inputs.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_production_boundary_removal.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_native_product_graph.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/notarization_transaction.py --self-check

# Confirm the Signed_Installed physical-evidence aggregator is wired to all four
# harnesses and the Evidence_Manifest level order. This is a source-boundary
# contract check only; the physical evidence itself requires signed Apple
# Silicon runs on two macOS versions and is captured separately.
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/harness/physical_evidence_aggregator.py --self-check

# Confirm the final-candidate notarization/installed binder (Task 12.2) is wired
# to the physical-evidence aggregator, the sealed-closure pins, and the
# path/name-only updater-key blocker, and that it requires the full inside-out
# identity set plus the installed-matrix/packet/performance/security/soak report
# families across both required macOS run sets. This is a source-boundary
# contract check only; the notarization/staple/Gatekeeper and physical evidence
# themselves require a signed, notarized candidate captured separately.
PYTHONDONTWRITEBYTECODE=1 python3 -B -c 'from scripts.publication.final_candidate import self_check; self_check(); print("final candidate binder self-check ok")'

# Confirm the immutable sealed outer Evidence Manifest and publication gate
# (Task 12.3) is wired to the Evidence_Manifest level order, the physical
# aggregator, the sealed closure, the final-candidate binder, and the
# path/name-only updater-key blocker, and that an empty gate table authorizes no
# evidence level and refuses publication. This is a source-boundary contract
# check only; sealing the manifest additionally requires the signed, notarized,
# and physical evidence captured separately.
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/sealed_evidence_manifest.py self-check

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
