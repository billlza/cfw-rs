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
  "$repo_root/scripts/release_artifact_set_cli.py" self-check
cfw_run_release_python_script "$repo_root" \
  "$repo_root/scripts/ga_runtime_acceptance_cli.py" self-check

# These modules own source-only self-check functions, while the exporter's
# direct CLI requires closed production admission and the environment module's
# direct mode performs a live observation. Import only the pure functions inside
# this isolated boundary; never observe or mutate the release host from CI.
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
  "$repo_root" <<'PY'
from pathlib import Path
import sys

repository = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(repository))

from scripts.ga_acceptance_environment import self_check as environment_self_check
from scripts.ga_acceptance_journal_export import self_check as journal_export_self_check

environment_self_check()
journal_export_self_check()
PY

for release_helper in \
  scripts/run_ga_signing_attempt.sh \
  scripts/run_notarization_transaction.sh \
  scripts/run_ga_acceptance_journal_export.sh \
  scripts/run_ga_runtime_acceptance.sh; do
  [[ -f "$release_helper" && ! -L "$release_helper" && -O "$release_helper" && \
    -x "$release_helper" ]] || {
    echo "error: release helper is not one executable regular file: $release_helper" >&2
    exit 1
  }
done

for release_module in \
  scripts/notarization_executor.py \
  scripts/release_executor_source.py \
  scripts/signing_reconciliation.py \
  scripts/ga_acceptance_environment.py \
  scripts/ga_acceptance_journal_export.py; do
  [[ -f "$release_module" && ! -L "$release_module" && -O "$release_module" && \
    -r "$release_module" && ! -x "$release_module" ]] || {
    echo "error: release module is not one owned source-only file: $release_module" >&2
    exit 1
  }
done

release_library="scripts/release_bundle_codesign.sh"
readonly release_library
[[ -f "$release_library" && ! -L "$release_library" && \
  -r "$release_library" && ! -x "$release_library" ]] || {
  echo "error: release library is not one source-only regular file: $release_library" >&2
  exit 1
}

for release_cli in \
  scripts/release_artifact_set_cli.py \
  scripts/ga_runtime_acceptance_cli.py; do
  [[ -f "$release_cli" && ! -L "$release_cli" && -x "$release_cli" ]] || {
    echo "error: release CLI is not one executable regular file: $release_cli" >&2
    exit 1
  }
done

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
  'ACTIVE_RELEASE_IDENTITY' \
  'STAGES: Final = ("prepackage", "ga-acceptance", "publication")' \
  'cfm-candidate-freeze-intent-v3' \
  'verify_frozen_candidate' \
  'verify_signing_transformation_receipt' \
  'validate_published_transaction_receipt' \
  '_validate_signing_notarization_binding' \
  'validate_ci_lane_document' \
  'validate_hosted_ci_receipt_offline' \
  'live_verify_hosted_ci_receipt' \
  'ACCEPTANCE_INPUT_ROOT: Final = ACCEPTANCE_ROOT_RELATIVE' \
  'MIGRATION_JOURNAL_INPUT: Final = MIGRATION_RELATIVE' \
  'INSTALL_JOURNAL_INPUT: Final = INSTALL_RELATIVE' \
  'SERVICE_JOURNAL_INPUT: Final = SERVICE_RELATIVE' \
  'SERVICE_ENVIRONMENT_INPUT: Final = ENVIRONMENT_RELATIVE' \
  'STAGE_SCHEMA_VERSIONS: Final = {' \
  '"prepackage": 1' \
  '"ga-acceptance": 2' \
  '"publication": 2' \
  'verify_ga_acceptance_journal_export' \
  'def _verified_migration_journals(repository: Path) -> dict[str, Any]:' \
  'verified = verify_ga_acceptance_journal_export(repository)' \
  'migration = _verified_migration_journals(repository)' \
  '"migration_journals": {' \
  'validate_ga_runtime_acceptance' \
  'ga_environment_sha256' \
  'cfm-ga-acceptance-seal-v2' \
  'cfm-ga-publication-seal-v2' \
  'cfm-ga-runtime-acceptance-v2' \
  'build_manifest' \
  'verify_stage'; do
  grep -Fq -- "$fragment" scripts/publication/ga_release_contract.py || {
    echo "error: GA release contract is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'seal_prepackage' \
  'seal_ga_acceptance' \
  'seal_publication'; do
  grep -Fq -- "$fragment" scripts/publication/orchestrator.py || {
    echo "error: production release orchestrator is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'BUILD_NUMBER: Final = ACTIVE_RELEASE_IDENTITY.ga_build' \
  'REPOSITORY_RELATIVE: Final = FROZEN_GA_REPOSITORY_RELATIVE' \
  'CANDIDATE_RELATIVE: Final = ga_signed_root(Path("."))' \
  'NATIVE_PRODUCTS_RELATIVE: Final = ga_signed_native_products_root(' \
  'artifact_kind="notarized-ga-candidate-v1"' \
  '_clean_profile_sources' \
  'require_frozen_sources_unchanged' \
  'scripts/run_release_app_verifier.sh' \
  'parse_service_maintenance_receipt' \
  'cfw-current-service-authority-recovery-intent-v1' \
  'recover-installed-40019-global-authority' \
  'AUTHORITY_RECOVERY_PENDING_INTENT_NAME' \
  'service_event_contract' \
  'DOCUMENT: Final = "cfw-dormant-app-install-v2"' \
  'SERVICE_TRANSACTION_DOCUMENT: Final = "cfw-current-service-transaction-v3"' \
  'ga_environment_sha256' \
  'exclusive_release_maintenance_lock' \
  'require_decommissioned_service_transaction' \
  'SUPPORTED_PREDECESSORS' \
  'resolve_predecessor' \
  'bind_journal_predecessor' \
  'require_target_application_present' \
  'predecessor_unsupported' \
  'predecessor_identity_mismatch' \
  'previous_app_absent' \
  'supports_authority_recovery_intent' \
  'candidate_toolchain_override' \
  '--final is retired'; do
  grep -Fq -- "$fragment" scripts/dormant_app_install.py || {
    echo "error: dormant installer is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'cfw-current-service-transaction-v3' \
  'ENVIRONMENT_NAME: Final = "environment.json"' \
  'ga_environment_sha256' \
  'cfw-current-service-authority-recovery-intent-v1' \
  'recover-installed-40019-global-authority' \
  'AUTHORITY_RECOVERY_PENDING_INTENT_NAME' \
  'prepare_authority_recovery' \
  'unregister-installed-40019-proxy-agent' \
  'unregister-installed-40019-global-authority' \
  'unregister-proxy-agent' \
  'unregister-global-authority' \
  'INSTALLED_40019_ACTIONS' \
  'CURRENT_PREDECESSOR_ACTIONS' \
  'SUPPORTED_PREDECESSORS' \
  'register-global-authority' \
  'register-proxy-agent' \
  'verify-dormant' \
  'capture_cfw_guard(self.runner, require_cfm_absent=False)' \
  'service_install_evidence_invalid' \
  'installation["previous"] != intent["previous"]' \
  '--final is retired'; do
  grep -Fq -- "$fragment" scripts/current_service_transaction.py || {
    echo "error: current-service transaction is missing $fragment" >&2
    exit 1
  }
done

for contract in \
  'scripts/candidate_freeze.py:cfm-candidate-freeze-intent-v3' \
  'scripts/candidate_freeze.py:selected_possession_verifier(repository, root)' \
  'scripts/candidate_freeze.py:updater_verifier_unavailable' \
  'scripts/candidate_freeze.py:signing-output' \
  'scripts/signing_attempt_transaction.py:cfm-ga-signing-attempt-v1' \
  'scripts/signing_attempt_transaction.py:verification_blocked' \
  'scripts/signing_attempt_transaction.py:production_embedded_verifier_session' \
  'scripts/signing_attempt_transaction.py:fsync_private_tree(attempt.work)' \
  'scripts/signing_attempt_transaction.py:possession_verifier=possession_verifier' \
  'scripts/signing_attempt_transaction.py:publish_private_directory_exclusive' \
  'scripts/signing_attempt_transaction.py:verify_attempt_receipt' \
  'scripts/signing_attempt_transaction.py:outcome_unknown' \
  'scripts/run_ga_signing_attempt.sh:--transaction-owned' \
  'scripts/run_ga_signing_attempt.sh:target/candidates/0.4.0/ga/40042' \
  'scripts/verify_signing_transformation.py:cfm-ga-signing-transformation-v2' \
  'scripts/verify_signing_transformation.py:cfm-candidate-freeze-intent-v3' \
  'scripts/verify_signing_transformation.py:RECOVERABLE_VERIFICATION_ERROR_CODES' \
  'scripts/verify_signing_transformation.py:def load_attempt_receipt(' \
  'scripts/release_artifact_set.py:def _updater_verification_session(' \
  'scripts/notarization_transaction.py:signing_transformation_receipt_sha256' \
  'scripts/notarization_transaction.py:validate_published_transaction_receipt' \
  'scripts/ga_acceptance_environment.py:DOCUMENT: Final = "cfm-ga-environment-identity-v1"' \
  'scripts/ga_acceptance_environment.py:def environment_sha256(' \
  'scripts/ga_acceptance_environment.py:def require_same_environment(' \
  'scripts/ga_acceptance_journal_export.py:INTENT_DOCUMENT: Final = "cfm-ga-journal-export-intent-v1"' \
  'scripts/ga_acceptance_journal_export.py:RECEIPT_DOCUMENT: Final = "cfm-ga-journal-export-receipt-v1"' \
  'scripts/ga_acceptance_journal_export.py:ENVIRONMENT_RELATIVE: Final = SERVICE_RELATIVE / service.ENVIRONMENT_NAME' \
  'scripts/ga_acceptance_journal_export.py:def export_ga_acceptance_journals(' \
  'scripts/ga_acceptance_journal_export.py:def recover_ga_acceptance_journal_export(' \
  'scripts/ga_acceptance_journal_export.py:def verify_ga_acceptance_journal_export(' \
  'scripts/ga_acceptance_journal_export.py:publish_private_directory_exclusive(' \
  'scripts/run_ga_acceptance_journal_export.sh:cfw_seal_release_tool_environment production' \
  'scripts/run_ga_acceptance_journal_export.sh:cfw_select_release_apple_toolchain' \
  'scripts/run_ga_acceptance_journal_export.sh:cfw_run_release_python_script' \
  'scripts/run_ga_acceptance_journal_export.sh:scripts/ga_acceptance_journal_export.py' \
  'scripts/ga_runtime_acceptance.py:cfm-ga-runtime-acceptance-v2' \
  'scripts/ga_runtime_acceptance.py:cfm-ga-runtime-check-v2' \
  'scripts/ga_runtime_acceptance.py:cfm-ga-command-observation-v2' \
  'scripts/ga_runtime_acceptance.py:cfm-ga-runtime-collection-intent-v2' \
  'scripts/ga_runtime_acceptance.py:cfm-ga-runtime-collection-event-v2' \
  'scripts/ga_runtime_acceptance.py:ENVIRONMENT_RELATIVE as JOURNAL_EXPORT_ENVIRONMENT_RELATIVE' \
  'scripts/ga_runtime_acceptance.py:ENVIRONMENT_RELATIVE: Final = JOURNAL_EXPORT_ENVIRONMENT_RELATIVE' \
  'scripts/ga_runtime_acceptance.py:validate_ga_runtime_acceptance' \
  'scripts/ga_runtime_acceptance.py:COLLECTION_RELATIVE: Final = ACCEPTANCE_ROOT_RELATIVE / "runtime-collection"' \
  'scripts/ga_runtime_acceptance.py:def collect_ga_runtime_acceptance(' \
  'scripts/ga_runtime_acceptance.py:def recover_ga_runtime_collection(' \
  'scripts/run_ga_runtime_acceptance.sh:cfw_seal_release_tool_environment production' \
  'scripts/run_ga_runtime_acceptance.sh:cfw_select_release_apple_toolchain' \
  'scripts/run_ga_runtime_acceptance.sh:scripts/ga_runtime_acceptance_cli.py' \
  'scripts/ga_runtime_acceptance_cli.py:derive_runtime_expectation' \
  'scripts/release_artifact_set_cli.py:verify_prepackage_authorization' \
  'scripts/release_artifact_set_cli.py:verify_publication_authorization' \
  'scripts/publication/ga_release_contract.py:def verify_stage(' \
  'scripts/publication/ga_release_contract.py:def derive_runtime_expectation(' \
  'scripts/github_hosted_ci_receipt.py:cfw-github-hosted-ci-receipt-v3' \
  'scripts/github_hosted_ci_receipt.py:REPOSITORY_ID: Final = 1_306_403_473' \
  'scripts/github_hosted_ci_receipt.py:WORKFLOW_ID: Final = 316_580_234' \
  'scripts/github_hosted_ci_receipt.py:WORKFLOW_SOURCE_STEP_PREFIX: Final =' \
  'scripts/github_hosted_ci_receipt.py:EXPECTED_JOB_NAMES: Final = frozenset(' \
  'scripts/github_hosted_ci_receipt.py:/attempts/{attempt}/jobs' \
  'scripts/github_hosted_ci_receipt.py:def _check_runs_api_path(' \
  'scripts/github_hosted_ci_receipt.py:?filter=latest&per_page=100&page=1' \
  'scripts/github_hosted_ci_receipt.py:def _annotations_api_path(' \
  'scripts/github_hosted_ci_receipt.py:def _workflow_contents_api_path(' \
  'scripts/github_hosted_ci_receipt.py:def _project_workflow_source(' \
  'scripts/github_hosted_ci_receipt.py:workflow_sha256' \
  'scripts/github_hosted_ci_receipt.py:def _project_check_runs(' \
  'scripts/github_hosted_ci_receipt.py:def _require_empty_annotations(' \
  'scripts/github_hosted_ci_receipt.py:def validate_receipt_offline(' \
  'scripts/github_hosted_ci_receipt.py:def verify_receipt(' \
  'scripts/publication/ga_release_contract.py:def _require_hosted_ci_source_binding(' \
  'scripts/publication/ga_release_contract.py:"workflow_sha256"' \
  'scripts/publication/artifact_preparation.py:"hosted-ci-receipt": fixed_ga_root / "stage-inputs/hosted-ci.json"' \
  'scripts/publication/closure.py:"hosted-ci-receipt"' \
  'scripts/publication/final_candidate.py:ga_root(Path()) / "stage-inputs/final-candidate"' \
  'scripts/publication/sealed_manifest.py:ga_root(Path()) / "stage-inputs/sealed-manifest"'; do
  contract_path="${contract%%:*}"
  contract_fragment="${contract#*:}"
  grep -Fq -- "$contract_fragment" "$contract_path" || {
    echo "error: $contract_path is missing $contract_fragment" >&2
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
  grep -Fq 'verify_release_prepackage_evidence' "$release_script" || {
    echo "error: $release_script does not enforce the prepackage gate" >&2
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
  '--seal-prepackage' \
  '--capture-hosted-ci' \
  '--verify-hosted-ci' \
  '--seal-ga-acceptance' \
  '--seal-publication' \
  'verify_release_prepackage_evidence' \
  'verify_release_ga_acceptance_evidence' \
  'verify_release_publication_evidence' \
  'seal-release' \
  'verify_release_upload_artifacts' \
  'scripts/release_artifact_set_cli.py' \
  'verify-release'; do
  grep -Fq -- "$fragment" scripts/release_publication_gate.sh || {
    echo "error: upload publication gate is missing $fragment" >&2
    exit 1
  }
done

for fragment in \
  'cfw-updater-release-set-seal-v2' \
  'cfw-dmg-release-set-seal-v2' \
  'cfw-ga-distribution-package-set-seal-v1' \
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
  'prepackage_stage_verifier' \
  'publication_stage_verifier' \
  'seal_distribution_set' \
  'verify_distribution_set'; do
  grep -Fq -- "$fragment" scripts/release_artifact_set.py || {
    echo "error: release artifact set is missing $fragment" >&2
    exit 1
  }
done

echo "Cargo build-script boundary verified"
