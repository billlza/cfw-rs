#!/bin/bash -p
# Cargo build scripts may validate local prebuilt native inputs, but may not
# download dependencies or recursively invoke another build system.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
cd "$repo_root"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
if [[ -z "$python_bin" ]]; then
  python_bin="$(command -v python3)"
fi
readonly python_bin
cfw_require_supported_python "$python_bin"

cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_release_authority_gate.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_pinned_source_contract.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_release_build_allocations.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_physical_capture_readiness.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_production_boundary_removal.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/verify_native_product_graph.py"
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/notarization_transaction.py" --self-check
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/dmg_notarization_transaction.py" self-check
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/release_artifact_set.py" self-check

# Reject duplicate string keys inside the release-set policy literals. Python
# accepts them silently, which could otherwise weaken an exact-field contract.
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
  scripts/release_artifact_set.py <<'PY'
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
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/harness/physical_machine_identity.py" --self-check
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/harness/physical_collector_request.py" self-check
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/harness/physical_evidence_aggregator.py" --self-check

# Confirm the immutable sealed outer Evidence Manifest and publication gate
# (Task 12.3) is wired to the Evidence_Manifest level order, the physical
# aggregator, the sealed closure, and the nested final-candidate binder, plus the
# path/name-only updater-key blocker, and that an empty gate table authorizes no
# evidence level and refuses publication. This is a source-boundary contract
# check only; sealing the manifest additionally requires the signed, notarized,
# and physical evidence captured separately.
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/sealed_evidence_manifest.py" self-check

# The production composer is deliberately distinct from the generic fixture-
# capable validators. Its pure source-bound self-check is valid in either
# closed production or unsigned-validation CI. Commands that create or seal
# evidence still require the production wrapper and production admission.
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/production_release_evidence.py" self-check

for fragment in \
  'ACTIVE_RELEASE_GENERATION' \
  'VALIDATION_BUILD = ACTIVE_RELEASE_GENERATION.validation_build' \
  'FINAL_BUILD = ACTIVE_RELEASE_GENERATION.final_build' \
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
  grep -Fq -- "$fragment" scripts/publication/orchestrator.py || {
    echo "error: production release orchestrator is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'ACTIVE_RELEASE_GENERATION' \
  'BUILD_NUMBER: Final = ACTIVE_RELEASE_GENERATION.validation_build' \
  'FINAL_BUILD_NUMBER: Final = ACTIVE_RELEASE_GENERATION.final_build' \
  'target/release-worktrees/{BUILD_NUMBER}' \
  'target/candidates/{VERSION}/validation/{BUILD_NUMBER}/signed' \
  'target/candidates/{VERSION}/signed' \
  'notarized-release-v1' \
  '_matching_clean_source_identity' \
  'parse_service_maintenance_receipt' \
  'cfw-current-service-authority-recovery-intent-v1' \
  'recover-installed-40019-global-authority' \
  'AUTHORITY_RECOVERY_PENDING_INTENT_NAME' \
  'service_event_contract' \
  'exclusive_release_maintenance_lock' \
  'require_decommissioned_service_transaction' \
  'candidate_toolchain_override' \
  'fixed release worktree and local toolchain must be real directories'; do
  grep -Fq -- "$fragment" scripts/dormant_app_install.py || {
    echo "error: dormant installer is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'cfw-current-service-transaction-v2' \
  'cfw-current-service-authority-recovery-intent-v1' \
  'recover-installed-40019-global-authority' \
  'AUTHORITY_RECOVERY_PENDING_INTENT_NAME' \
  'prepare_authority_recovery' \
  'unregister-proxy-agent' \
  'unregister-global-authority' \
  'register-global-authority' \
  'register-proxy-agent' \
  'capture_cfw_guard(self.runner, require_cfm_absent=False)' \
  'service_install_evidence_invalid' \
  'installation["previous"] != intent["previous"]' \
  '--final'; do
  grep -Fq -- "$fragment" scripts/current_service_transaction.py || {
    echo "error: current-service transaction is missing $fragment" >&2
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
  grep -Fq -- "$fragment" scripts/release_capability_inventory.py || {
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

"$python_bin" -I -S -B -W error - \
  "$repo_root/apps/cfw-tauri-shell/tauri.conf.json" <<'PY'
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
  grep -Fq -- "$fragment" scripts/release_artifact_set.py || {
    echo "error: release artifact set is missing $fragment" >&2
    exit 1
  }
done

echo "Cargo build-script boundary verified"
