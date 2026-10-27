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

build_scripts="$(git ls-files '**/build.rs' 'build.rs' 'apps/cfw-tauri-shell/build_support/macos.rs')"
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

if grep -Eq 'notarytool[[:space:]]+submit|--wait|/bin/ln' scripts/make_dmg.sh; then
  echo "error: DMG packaging contains a raw or non-transactional publication path" >&2
  exit 1
fi
if grep -Fq '/bin/ln' scripts/make_updater_manifest.sh; then
  echo "error: updater packaging publishes independent hard links" >&2
  exit 1
fi

echo "Cargo build-script boundary verified"
