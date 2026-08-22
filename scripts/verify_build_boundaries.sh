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

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_physical_capture_readiness.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_production_boundary_removal.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_native_product_graph.py

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/notarization_transaction.py --self-check

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/dmg_notarization_transaction.py self-check

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/release_artifact_set.py self-check

# Reject duplicate string keys inside the release-set policy literals. Python
# accepts them silently, which could otherwise weaken an exact-field contract.
PYTHONDONTWRITEBYTECODE=1 python3 -B - scripts/release_artifact_set.py <<'PY'
import ast
from pathlib import Path
import sys

path = Path(sys.argv[1])
tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
for node in ast.walk(tree):
    if isinstance(node, ast.Set):
        values = [item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
    elif isinstance(node, ast.Dict):
        values = [item.value for item in node.keys if isinstance(item, ast.Constant) and isinstance(item.value, str)]
    else:
        continue
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise SystemExit(
            f"error: duplicate release policy literal at line {node.lineno}: {duplicates}"
        )
PY

# Confirm the Signed_Installed physical-evidence aggregate v5 / receipt v3 /
# proof v3 / collector-policy v3 gate is wired to packet and lifecycle v3 plus performance and
# adversarial v2, the source-pinned PS256 Cloud KMS HSM policy bytes, and the
# Evidence_Manifest level order.
# This is a source-boundary contract check only;
# the physical evidence itself requires signed runs on one Apple Silicon Mac
# across both source-pinned clean macOS environments and an externally
# provisioned collector trust root.
/opt/homebrew/bin/python3 -I -S -B scripts/harness/physical_machine_identity.py --self-check
/opt/homebrew/bin/python3 -I -S -B scripts/harness/physical_collector_request.py self-check
/opt/homebrew/bin/python3 -I -S -B scripts/harness/physical_evidence_aggregator.py --self-check

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

# The production composer is deliberately distinct from the generic fixture-
# capable validators. Its source-bound self-check fixes the 40020 -> 40021
# sequence and proves that the requirements-derived nine-capability inventory
# is complete before any physical or publication evidence is considered.
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/production_release_evidence.py self-check

for fragment in \
  'VALIDATION_BUILD = "40020"' \
  'FINAL_BUILD = "40021"' \
  'prepare_physical_candidate_manifest' \
  'seal_production_evidence' \
  'require_clean=True' \
  'validate_published_transaction_receipt' \
  'validate_source_gate_document' \
  'validate_ci_lane_document' \
  'build_manifest' \
  '_require_final_inputs_unchanged' \
  'expected_report_contracts' \
  'artifact_hash_manifest_sha256' \
  'fixture=False' \
  'require_verified=True' \
  'artifacts_permitted'; do
  grep -Fq "$fragment" scripts/publication/orchestrator.py || {
    echo "error: production release orchestrator is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'CAPABILITY_SECTION' \
  'require_complete_capability_set' \
  'expected_report_contracts' \
  'require_fixed_evidence_mapping' \
  'unknown numbered section' \
  'does not cover every numbered requirement exactly once'; do
  grep -Fq "$fragment" scripts/release_capability_inventory.py || {
    echo "error: release capability inventory validator is missing $fragment" >&2
    exit 1
  }
done

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

grep -Fq 'scripts/dmg_notarization_transaction.py' scripts/make_dmg.sh || {
  echo "error: DMG packaging bypasses its durable notarization transaction" >&2
  exit 1
}
if grep -Eq 'notarytool[[:space:]]+submit|--wait|/bin/ln' scripts/make_dmg.sh; then
  echo "error: DMG packaging contains a raw or non-transactional publication path" >&2
  exit 1
fi
grep -Fq 'seal-updater' scripts/make_updater_manifest.sh || {
  echo "error: updater packaging does not seal its complete versioned set" >&2
  exit 1
}
if grep -Fq '/bin/ln' scripts/make_updater_manifest.sh; then
  echo "error: updater packaging publishes independent hard links" >&2
  exit 1
fi
for fragment in \
  '--seal-assets' \
  'seal_release_upload_artifacts' \
  'seal-release' \
  'verify_release_upload_artifacts' \
  'scripts/release_artifact_set.py' \
  'verify-release'; do
  grep -Fq -- "$fragment" scripts/release_publication_gate.sh || {
    echo "error: upload publication gate is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'cfw-distribution-release-set-seal-v1' \
  'signed_app_tree_sha256' \
  'read_updater_app_manifest' \
  'read_dmg_app_manifest' \
  'publication_closure' \
  'verify_publication_semantics' \
  'cfw-publication-upload-bundle-manifest-v1' \
  'MODIFICATIONS.md' \
  'PUBLICATION_BUNDLE_MANIFEST_NAME' \
  'MAX_PUBLICATION_BUNDLE_BYTES' \
  'MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE' \
  'MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES' \
  '_validate_publication_bundle' \
  'seal_distribution_set' \
  'verify_distribution_set'; do
  grep -Fq "$fragment" scripts/release_artifact_set.py || {
    echo "error: release artifact set is missing $fragment" >&2
    exit 1
  }
done

echo "Cargo build-script boundary verified"
