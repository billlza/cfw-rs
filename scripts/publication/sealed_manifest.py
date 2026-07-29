"""Immutable sealed outer Evidence Manifest and publication gate (Task 12.3).

This module is the *outermost* release gate. It adds no competing framework: it
composes the pieces the earlier waves already implemented, each consumed as a
black box, into one canonical, self-sealing, immutable document:

* the P0 source / build-boundary gates (``scripts/verify_release_authority_gate.py``,
  ``scripts/verify_production_boundary_removal.py``,
  ``scripts/verify_native_product_graph.py``,
  ``scripts/verify_pinned_build_inputs.py``,
  ``scripts/verify_build_boundaries.sh``,
  ``scripts/release_workspace_secret_gate.sh``) recorded as content-addressed
  command results bound to one commit;
* the deterministic unsigned-CI lane set recorded as content-addressed command
  results bound to one commit *and* one toolchain digest;
* the wave-11 physical / signed-installed aggregate
  (``harness.physical_evidence_aggregator``), which alone may grant
  ``Signed_Installed_Verified``;
* the task-12.1 sealed source / license / vulnerability / SBOM closure
  (``publication.sealed_closure``);
* the task-12.2 final-candidate notarization / installed binding
  (``publication.final_candidate``);
* the path/name-only workspace secret-material blocker
  (``release_secret_material_blocker``), which never opens a key file; and
* the canonical inner Evidence_Manifest validator (``scripts/evidence_manifest.py``),
  which owns per-capability level closure, content-addressed report bindings,
  and identity binding.

On top of those it enforces the rules that only the outer seal can enforce
(Requirements 1.1, 1.2, 4.1, 5.1, 6.5, 7.5, 8.1):

1. **Exactly one highest level per capability.** The capability table is
   *derived* from the inner manifest, deduplicated, and sorted; a duplicate or
   conflicting level claim for the same capability is rejected.
2. **No level skipping and no masking.** A capability may claim a level only
   when that level's gate *and* every predecessor gate passed. A gate that is
   ``failed``, ``blocked``, or ``not-run`` caps every capability below it, so a
   failed lower level can never be masked by a higher claim.
3. **Everything is bound by content digest.** Reports and documents are bound by
   SHA-256 together with the commit, the product version/build number, the exact
   final artifact hashes, and the sealed-closure plus final-candidate digests.
4. **The manifest is self-sealing and immutable.** ``manifest_sha256`` is the
   digest of the manifest's own canonical body; :func:`seal_manifest` refuses to
   overwrite an existing seal; and :func:`validate_sealed_evidence_manifest`
   re-derives every derived field from the embedded evidence, so any hand-edited
   field is rejected.
5. **Publication is fail closed.** Publication artifacts may be created only
   when the P0 source, unsigned-CI, signed-installed, sealed-closure,
   final-candidate, and release-secret-custody gates all pass and every capability
   has reached the sealed level. There is no fallback, no override flag, and no
   way to convert an unavailable input into success.

In an environment without signed, notarized, or physical inputs the manifest
seals to ``blocked`` with explicit ``blocked_inputs`` and the publication gate
refuses. It never fabricates acceptance and never claims
``Sealed_Release_Evidence``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .common import (
    MAX_JSON_BYTES,
    PublicationError,
    canonical_json,
    read_regular,
    require_exact_keys,
    require_sha256,
    safe_relative,
    sha256_bytes,
    sha256_file,
    write_new,
)

try:  # pragma: no cover - import shim exercised by both invocation styles
    from scripts.evidence_manifest import (
        LEVEL_INDEX,
        LEVEL_ORDER,
        EvidenceManifestError,
        validate_evidence_manifest,
    )
    from scripts.harness.physical_evidence_aggregator import (
        GRANTED_LEVEL as PHYSICAL_GRANTED_LEVEL,
        PhysicalEvidenceError,
        load_physical_evidence_artifact,
    )
    from scripts.harness.raw_artifacts import (
        CollectorTrustNotConfiguredError,
        CollectorTrustPolicy,
        RawArtifactError,
        load_release_trust_policy,
        parse_descriptor,
    )
    from scripts.release_build_identity import BuildIdentityError, canonical_build_version
    from scripts.release_secret_material_blocker import (
        SecretMaterialReleaseBlock,
        evaluate_workspace,
    )
except ImportError:  # pragma: no cover - CLI invocation style
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from scripts.evidence_manifest import (
        LEVEL_INDEX,
        LEVEL_ORDER,
        EvidenceManifestError,
        validate_evidence_manifest,
    )
    from scripts.harness.physical_evidence_aggregator import (
        GRANTED_LEVEL as PHYSICAL_GRANTED_LEVEL,
        PhysicalEvidenceError,
        load_physical_evidence_artifact,
    )
    from scripts.harness.raw_artifacts import (
        CollectorTrustNotConfiguredError,
        CollectorTrustPolicy,
        RawArtifactError,
        load_release_trust_policy,
        parse_descriptor,
    )
    from scripts.release_build_identity import BuildIdentityError, canonical_build_version
    from scripts.release_secret_material_blocker import (
        SecretMaterialReleaseBlock,
        evaluate_workspace,
    )

from scripts.publication.final_candidate import (  # noqa: E402
    PRODUCT_VERSION,
    VERIFIED as CANDIDATE_VERIFIED,
    validate_final_candidate_binding,
)
from scripts.publication.sealed_closure import (  # noqa: E402
    SEALED as CLOSURE_SEALED,
    validate_sealed_closure,
)
from scripts.release_capability_inventory import (  # noqa: E402
    INVENTORY_PATH as CAPABILITY_INVENTORY_PATH,
    require_complete_capability_set,
    require_fixed_evidence_mapping,
)


SCHEMA_VERSION = 1
DOCUMENT_KIND = "sealed-outer-evidence-manifest-v1"
DOCUMENT_VISIBILITY = "private-release-operations"

# Outer manifest statuses. ``sealed`` is only reachable when every composed gate
# passes; otherwise the manifest seals to ``blocked``.
SEALED = "sealed"
BLOCKED = "blocked"
STATUSES = frozenset({SEALED, BLOCKED})

# Gate statuses. Only ``passed`` contributes evidence; ``failed`` (a recorded
# failure), ``blocked`` (an environment-gated input), and ``not-run`` (an absent
# input) all keep publication fail closed.
PASSED = "passed"
FAILED = "failed"
NOT_RUN = "not-run"
GATE_STATUSES = frozenset({PASSED, FAILED, BLOCKED, NOT_RUN})

# Accepted per-command result statuses inside the source / CI gate documents.
# Only ``passed`` counts; every other value - including the masking values
# ``skipped``, ``masked``, ``timeout``, and ``malformed`` - fails its gate
# (Requirement 6.5). An unknown status string is malformed and is rejected.
RESULT_STATUSES = frozenset(
    {"passed", "failed", "blocked", "not-run", "skipped", "masked", "timeout", "malformed"}
)

MACOS_MIN = "15.0"
ARCH = "arm64"
LICENSE = "GPL-3.0-or-later"
SOURCE_GATE_SCHEMA_VERSION = 1
SOURCE_GATE_DOCUMENT = "p0-source-gates-v1"

# The evidence hierarchy is imported from the canonical Evidence_Manifest so the
# level names can never drift: Source_Implemented < Unsigned_CI_Verified <
# Signed_Installed_Verified < Sealed_Release_Evidence.
SOURCE_LEVEL, UNSIGNED_LEVEL, INSTALLED_LEVEL, SEALED_LEVEL = LEVEL_ORDER

# The six gates the outer seal composes, in evidence order. ``GATE_LEVEL`` maps
# each gate to the single evidence level it authorizes; a gate that is not
# ``passed`` caps every capability at the level below it.
GATE_ORDER = (
    "p0_source",
    "unsigned_ci",
    "signed_installed",
    "sealed_closure",
    "final_candidate",
    "release_secret_custody",
)
GATE_LEVEL: dict[str, str] = {
    "p0_source": SOURCE_LEVEL,
    "unsigned_ci": UNSIGNED_LEVEL,
    "signed_installed": INSTALLED_LEVEL,
    "sealed_closure": SEALED_LEVEL,
    "final_candidate": SEALED_LEVEL,
    # Workspace secret custody is a release blocker (Requirement 8.1).
    "release_secret_custody": SEALED_LEVEL,
}

# The gates whose input is supplied per environment (``None`` means "not
# available here"). Secret custody is always derived from the workspace.
COMPOSED_INPUTS = (
    "p0_source",
    "unsigned_ci",
    "signed_installed",
    "sealed_closure",
    "final_candidate",
)
RELEASE_SECRET_GATE = "release_secret_custody"

# The P0 source / boundary gates that must all pass before any capability may
# claim Source_Implemented. Each entry is a real repository gate script; a
# missing script fails closed (the gate cannot be proven at all).
REQUIRED_SOURCE_GATES: dict[str, str] = {
    "release-authority-gate": "scripts/verify_release_authority_gate.py",
    "production-boundary-removal": "scripts/verify_production_boundary_removal.py",
    "native-product-graph": "scripts/verify_native_product_graph.py",
    "pinned-build-inputs": "scripts/verify_pinned_build_inputs.py",
    "build-script-boundary": "scripts/verify_build_boundaries.sh",
    "workspace-secret-gate": "scripts/release_workspace_secret_gate.sh",
}

# The deterministic unsigned-CI lanes that must all pass before any capability
# may claim Unsigned_CI_Verified. A missing lane is skipped evidence and is
# rejected; an unknown lane is malformed and is rejected.
REQUIRED_CI_LANES: tuple[str, ...] = (
    "build-script-boundary",
    "ci-no-masking",
    "evidence-manifest-lane",
    "version-contract",
    "rust-fmt",
    "rust-locked-metadata",
    "rust-clippy",
    "rust-test",
    "rust-target-audit",
    "cargo-deny",
    "node-install",
    "node-test",
    "node-build",
    "node-audit",
    "swift-format-lint",
    "swift-package-test",
    "xcode-project-verify",
    "xcode-unsigned-test",
    "xcode-analyze",
    "libbox-module-verify",
    "libbox-govulncheck",
    "libbox-build",
    "release-tooling-tests",
    "shell-syntax",
    "shellcheck",
    "unsigned-candidate",
)

# Feature documents bound by content digest. The manifest records the exact
# reviewed specification it was sealed against, so a later edit invalidates it.
REQUIRED_DOCUMENTS: dict[str, str] = {
    "requirements": "docs/release/macos15-network-extension-migration/requirements.md",
    "design": "docs/release/macos15-network-extension-migration/design.md",
    "tasks": "docs/release/macos15-network-extension-migration/tasks.md",
    "capability-inventory": CAPABILITY_INVENTORY_PATH,
}

# Publication documents bound by content digest from the sealed closure. Each
# entry is (document id, closure section, digest field).
PUBLICATION_DOCUMENTS: tuple[tuple[str, str, str], ...] = (
    ("corresponding-source-tree", "corresponding_source", "sha256"),
    ("corresponding-source-archive", "corresponding_source", "archive_sha256"),
    ("modification-notice", "modification_notice", "sha256"),
    ("third-party-notices", "third_party_notices", "sha256"),
    ("artifact-hash-manifest", "artifact_hash_manifest", "sha256"),
    ("spdx-sbom", "sbom", "spdx_sha256"),
    ("cyclonedx-sbom", "sbom", "cyclonedx_sha256"),
)

# Where the release pipeline stages the composed inputs and the one sealed
# manifest, alongside the existing 0.4.0 candidate/publication layout.
DEFAULT_EVIDENCE_DIRECTORY = "target/candidates/0.4.0/release/sealed-manifest"
DEFAULT_MANIFEST_NAME = "sealed-evidence-manifest.json"
DEFAULT_MANIFEST_PATH = f"{DEFAULT_EVIDENCE_DIRECTORY}/{DEFAULT_MANIFEST_NAME}"

ENVIRONMENT_INPUT_FILES: dict[str, str] = {
    "p0_source": "p0-source-gates.json",
    "unsigned_ci": "unsigned-ci-lanes.json",
    "signed_installed": "physical-evidence.json",
    "sealed_closure": "sealed-closure.json",
    "final_candidate": "final-candidate.json",
}
PRESENT = "present"

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RESULT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

MAX_RESULTS = 256
MAX_COMMAND_LENGTH = 1024
MAX_EXIT_CODE = 255
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


# --------------------------------------------------------------------------
# Scalar helpers
# --------------------------------------------------------------------------


def _require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a 40-hex commit hash")
    return value


def _require_result_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not RESULT_ID_RE.fullmatch(value):
        raise PublicationError(f"{label} is not a canonical lane identifier")
    return value


def _require_command(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_COMMAND_LENGTH
        or value.strip() != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PublicationError(f"{label} is not a bounded single-line command")
    return value


def _product(value: object) -> dict[str, str]:
    identity = require_exact_keys(value, {"version", "build_number"}, "product")
    if identity["version"] != PRODUCT_VERSION:
        raise PublicationError(f"sealed manifest product.version must be {PRODUCT_VERSION}")
    try:
        build_number = canonical_build_version(
            identity["build_number"], "sealed manifest product.build_number"
        )
    except BuildIdentityError as error:
        raise PublicationError(str(error)) from error
    return {"version": PRODUCT_VERSION, "build_number": build_number}


# --------------------------------------------------------------------------
# Recorded command results (P0 source gates and unsigned CI lanes)
# --------------------------------------------------------------------------


def _result_entry(
    raw: object,
    index: int,
    label: str,
    fields: set[str],
    commit: str,
    toolchain_sha256: str | None,
    release_source_sha256: str | None,
) -> dict[str, Any]:
    """Normalize one recorded command result and reject every masking shape."""
    entry = require_exact_keys(raw, fields, f"{label}[{index}]")
    identifier = _require_result_id(entry["id"], f"{label}[{index}].id")
    status = entry["status"]
    if status not in RESULT_STATUSES:
        raise PublicationError(f"{label} {identifier!r} status {status!r} is not a known result")
    exit_code = entry["exit_code"]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise PublicationError(f"{label} {identifier!r} exit_code is not an integer")
    if exit_code < 0 or exit_code > MAX_EXIT_CODE:
        raise PublicationError(f"{label} {identifier!r} exit_code is outside 0..{MAX_EXIT_CODE}")
    if status == PASSED and exit_code != 0:
        # ``|| true`` / swallowed exit status: a nonzero command can never be
        # recorded as a pass.
        raise PublicationError(
            f"{label} {identifier!r} masks a nonzero exit status behind a passed result"
        )
    if status != PASSED and exit_code == 0:
        raise PublicationError(
            f"{label} {identifier!r} records a {status!r} result with a successful exit status"
        )
    normalized: dict[str, Any] = {
        "id": identifier,
        "status": status,
        "exit_code": exit_code,
        "log_sha256": require_sha256(entry["log_sha256"], f"{label} {identifier!r} log_sha256"),
        "commit": _require_commit(entry["commit"], f"{label} {identifier!r} commit"),
    }
    if normalized["commit"] != commit:
        # A result captured at another commit is a stale binding.
        raise PublicationError(
            f"{label} {identifier!r} is bound to a different commit than the manifest"
        )
    if "script" in fields:
        script = entry["script"]
        if not isinstance(script, str):
            raise PublicationError(f"{label} {identifier!r} script is not a string")
        safe_relative(script, f"{label} {identifier!r} script")
        normalized["script"] = script
    if "command" in fields:
        normalized["command"] = _require_command(
            entry["command"], f"{label} {identifier!r} command"
        )
    if toolchain_sha256 is not None:
        bound = require_sha256(
            entry["toolchain_sha256"], f"{label} {identifier!r} toolchain_sha256"
        )
        if bound != toolchain_sha256:
            raise PublicationError(
                f"{label} {identifier!r} is bound to a different toolchain than the manifest"
            )
        normalized["toolchain_sha256"] = bound
    if release_source_sha256 is not None:
        source_bound = require_sha256(
            entry["release_source_sha256"],
            f"{label} {identifier!r} release_source_sha256",
        )
        if source_bound != release_source_sha256:
            raise PublicationError(
                f"{label} {identifier!r} is bound to different release source bytes"
            )
        normalized["release_source_sha256"] = source_bound
    return normalized


def _result_set(
    raw: object,
    label: str,
    fields: set[str],
    required: tuple[str, ...],
    commit: str,
    toolchain_sha256: str | None,
    release_source_sha256: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list) or not raw:
        raise PublicationError(f"{label} must be a non-empty list of recorded results")
    if len(raw) > MAX_RESULTS:
        raise PublicationError(f"{label} declares too many results")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        entry = _result_entry(
            item,
            index,
            label,
            fields,
            commit,
            toolchain_sha256,
            release_source_sha256,
        )
        if entry["id"] in seen:
            raise PublicationError(f"{label} repeats the {entry['id']!r} result")
        seen.add(entry["id"])
        normalized.append(entry)
    unknown = sorted(seen - set(required))
    if unknown:
        raise PublicationError(f"{label} declares unknown results: {unknown}")
    missing = sorted(set(required) - seen)
    if missing:
        # A missing required command is skipped evidence and fails closed.
        raise PublicationError(f"{label} is missing required results: {missing}")
    normalized.sort(key=lambda entry: entry["id"])
    failures = sorted(entry["id"] for entry in normalized if entry["status"] != PASSED)
    return normalized, failures


def _source_gate_document(
    repository: Path, value: object, commit: str
) -> tuple[dict[str, Any], list[str]]:
    payload = require_exact_keys(
        value,
        {"schema_version", "document", "gates"},
        "p0 source gate document",
    )
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SOURCE_GATE_SCHEMA_VERSION
        or payload["document"] != SOURCE_GATE_DOCUMENT
    ):
        raise PublicationError("p0 source gate document has an unsupported schema")
    gates, failures = _result_set(
        payload["gates"],
        "p0 source gate",
        {"id", "script", "status", "exit_code", "log_sha256", "commit"},
        tuple(REQUIRED_SOURCE_GATES),
        commit,
        None,
        None,
    )
    for gate in gates:
        expected = REQUIRED_SOURCE_GATES[gate["id"]]
        if gate["script"] != expected:
            raise PublicationError(
                f"p0 source gate {gate['id']!r} does not name its repository gate script"
            )
        path = repository / expected
        if path.is_symlink() or not path.is_file():
            # The gate cannot be proven if the gate script is absent.
            raise PublicationError(f"p0 source gate script is missing: {expected}")
    return {
        "schema_version": SOURCE_GATE_SCHEMA_VERSION,
        "document": SOURCE_GATE_DOCUMENT,
        "gates": gates,
    }, failures


def _ci_lane_document(
    value: object,
    commit: str,
    expected_release_source_sha256: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    payload = require_exact_keys(
        value,
        {
            "schema_version",
            "document",
            "release_source_sha256",
            "toolchain_sha256",
            "lanes",
        },
        "unsigned CI lane document",
    )
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 2
        or payload["document"] != "unsigned-ci-lanes-v2"
    ):
        raise PublicationError("unsigned CI lane document has an unsupported schema")
    release_source_sha256 = require_sha256(
        payload["release_source_sha256"], "unsigned CI release_source_sha256"
    )
    if (
        expected_release_source_sha256 is not None
        and release_source_sha256 != expected_release_source_sha256
    ):
        raise PublicationError("unsigned CI evidence is bound to different release source bytes")
    toolchain = require_sha256(payload["toolchain_sha256"], "unsigned CI toolchain_sha256")
    lanes, failures = _result_set(
        payload["lanes"],
        "unsigned CI lane",
        {
            "id",
            "command",
            "status",
            "exit_code",
            "log_sha256",
            "commit",
            "release_source_sha256",
            "toolchain_sha256",
        },
        REQUIRED_CI_LANES,
        commit,
        toolchain,
        release_source_sha256,
    )
    return {
        "schema_version": 2,
        "document": "unsigned-ci-lanes-v2",
        "release_source_sha256": release_source_sha256,
        "toolchain_sha256": toolchain,
        "lanes": lanes,
    }, failures


def validate_source_gate_document(
    repository: Path,
    value: object,
    commit: str,
) -> tuple[dict[str, Any], list[str]]:
    """Public composition boundary for the fixed P0 source-gate document."""
    return _source_gate_document(repository, value, commit)


def validate_ci_lane_document(
    value: object,
    commit: str,
    expected_release_source_sha256: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Public composition boundary for the fixed unsigned-CI lane document."""
    return _ci_lane_document(value, commit, expected_release_source_sha256)


# --------------------------------------------------------------------------
# Composed gate evaluation
# --------------------------------------------------------------------------


def _gate(status: str, evidence: Any) -> dict[str, Any]:
    if status not in GATE_STATUSES:
        raise PublicationError(f"gate status {status!r} is not a known gate status")
    return {"status": status, "evidence": evidence}


def _release_secret_gate(workspace_root: Path) -> dict[str, Any]:
    """Derive typed workspace secret custody by path/name only."""
    try:
        responses = list(evaluate_workspace(workspace_root))
    except SecretMaterialReleaseBlock as error:
        raise PublicationError(
            f"release secret-material blocker failed closed: {error}"
        ) from error
    blocks = [
        {
            # Path and name only; the key file is never opened or read.
            "path": response.detected_path,
            "name": response.detected_name,
            "credential_kind": response.credential_kind.value,
            "relocation_target": response.relocation_target,
            "exposure_plausible": response.exposure_plausible,
            "rotation_required": response.rotation_required,
            "required_trust_action": response.required_trust_action.value,
            "updater_trust_migration_required": (
                response.updater_trust_migration_required
            ),
            "notary_profile_reprovision_required": (
                response.notary_profile_reprovision_required
            ),
            "trust_domain_identification_required": (
                response.trust_domain_identification_required
            ),
        }
        for response in responses
    ]
    status = FAILED if blocks else PASSED
    return _gate(status, {"blocks": blocks})


def _signed_installed_gate(
    value: object,
    product: dict[str, str],
    *,
    evidence_root: Path,
    trust_policy: CollectorTrustPolicy | None,
    fixture: bool,
) -> dict[str, Any]:
    try:
        aggregate_artifact = parse_descriptor(
            value,
            expected_kinds={"physical-aggregate"},
            label="signed-installed aggregate artifact",
        ).as_dict()
    except RawArtifactError as error:
        raise PublicationError(f"signed-installed descriptor is invalid: {error}") from error
    try:
        policy = load_release_trust_policy() if trust_policy is None else trust_policy
    except CollectorTrustNotConfiguredError:
        return _gate(BLOCKED, None)
    except RawArtifactError as error:
        raise PublicationError(f"collector trust policy is invalid: {error}") from error
    try:
        summary = load_physical_evidence_artifact(
            aggregate_artifact,
            evidence_root=evidence_root,
            trust_policy=policy,
            fixture=fixture,
        )
    except (PhysicalEvidenceError, RawArtifactError) as error:
        raise PublicationError(f"signed-installed evidence is invalid: {error}") from error
    if summary["granted_level"] != INSTALLED_LEVEL:
        raise PublicationError("signed-installed aggregate does not grant the installed level")
    candidate = summary["candidate"]
    if candidate["version"] != product["version"] or (
        candidate["build_number"] != product["build_number"]
    ):
        raise PublicationError("signed-installed evidence does not match the manifest product")
    return _gate(
        PASSED,
        {
            "granted_level": summary["granted_level"],
            "runs": summary["runs"],
            "reports": summary["reports"],
            "signed_app_tree_sha256": candidate["signed_app_tree_sha256"],
            "app_manifest_sha256": candidate["app_manifest_sha256"],
            "trust_policy_sha256": summary["trust_policy_sha256"],
            "aggregate_artifact": summary["aggregate_artifact"],
            "private_archive": summary["private_archive"],
        },
    )


def _sealed_closure_gate(
    repository: Path, value: object, product: dict[str, str], commit: str, fixture: bool
) -> dict[str, Any]:
    try:
        closure = validate_sealed_closure(repository, value, fixture=fixture)
    except PublicationError as error:
        raise PublicationError(f"sealed closure is invalid: {error}") from error
    if closure["product"]["version"] != product["version"] or (
        closure["product"]["build_number"] != product["build_number"]
    ):
        raise PublicationError("sealed closure does not match the manifest product")
    if closure["commit"] != commit:
        raise PublicationError("sealed closure is bound to a different commit")
    status = PASSED if closure["status"] == CLOSURE_SEALED else BLOCKED
    return _gate(
        status,
        {
            "closure_status": closure["status"],
            "closure_sha256": closure["closure_sha256"],
            "blocked_inputs": sorted(closure["blocked_inputs"]),
            "signed_app_sha256": (closure["signed_app"] or {}).get("sha256"),
            "xcframework_sha256": (closure["xcframework"] or {}).get("sha256"),
            "artifact_hash_manifest_sha256": closure["artifact_hash_manifest"]["sha256"],
        },
    )


def _final_candidate_gate(
    repository: Path,
    value: object,
    product: dict[str, str],
    commit: str,
    fixture: bool,
    workspace_root: Path,
    physical_evidence_root: Path,
    physical_trust_policy: CollectorTrustPolicy | None,
) -> dict[str, Any]:
    try:
        binding = validate_final_candidate_binding(
            repository,
            value,
            fixture=fixture,
            workspace_root=workspace_root,
            physical_evidence_root=physical_evidence_root,
            physical_trust_policy=physical_trust_policy,
        )
    except PublicationError as error:
        raise PublicationError(f"final candidate binding is invalid: {error}") from error
    if binding["product"] != product:
        raise PublicationError("final candidate binding does not match the manifest product")
    if binding["commit"] != commit:
        raise PublicationError("final candidate binding is bound to a different commit")
    artifacts = binding["final_artifacts"]
    status = PASSED if binding["status"] == CANDIDATE_VERIFIED else BLOCKED
    return _gate(
        status,
        {
            "binding_status": binding["status"],
            "binding_sha256": binding["binding_sha256"],
            "blocked_inputs": sorted(binding["blocked_inputs"]),
            "signed_app_tree_sha256": artifacts["signed_app_tree_sha256"],
            "app_manifest_sha256": artifacts["app_manifest_sha256"],
            "xcframework_sha256": binding["xcframework"]["xcframework_sha256"],
            "artifact_hash_manifest_sha256": artifacts["artifact_hash_manifest"]["sha256"],
            "final_artifact_hashes": sorted(
                {entry["sha256"] for entry in artifacts["artifact_hash_manifest"]["entries"]}
            ),
            "report_bindings": len(binding["report_bindings"]),
            "installed_runs": [entry["os"] for entry in binding["installed_runs"]],
            "trust_policy_sha256": binding["physical_trust_policy_sha256"],
            "aggregate_artifact": binding["physical_evidence"],
            "private_archive": binding["physical_archive"],
        },
    )


def _cross_bind_gates(gates: dict[str, dict[str, Any]], payload: dict[str, Any]) -> None:
    """Reject inputs that describe different candidates or stale evidence."""
    closure = gates["sealed_closure"]["evidence"]
    candidate = gates["final_candidate"]["evidence"]
    installed = gates["signed_installed"]["evidence"]

    if closure is not None and candidate is not None:
        if closure["signed_app_sha256"] is not None and (
            closure["signed_app_sha256"] != candidate["signed_app_tree_sha256"]
        ):
            raise PublicationError(
                "sealed closure and final candidate bind different signed app trees"
            )
        if closure["xcframework_sha256"] is not None and (
            closure["xcframework_sha256"] != candidate["xcframework_sha256"]
        ):
            raise PublicationError(
                "sealed closure and final candidate bind different libbox XCFrameworks"
            )
    if installed is not None and candidate is not None:
        if installed["signed_app_tree_sha256"] != candidate["signed_app_tree_sha256"]:
            raise PublicationError(
                "signed-installed evidence and final candidate bind different signed app trees"
            )
        if installed["app_manifest_sha256"] != candidate["app_manifest_sha256"]:
            raise PublicationError(
                "signed-installed evidence and final candidate bind different app manifests"
            )
        if installed["trust_policy_sha256"] != candidate["trust_policy_sha256"]:
            raise PublicationError(
                "signed-installed evidence and final candidate bind different "
                "collector trust policies"
            )
        if installed["aggregate_artifact"] != candidate["aggregate_artifact"]:
            raise PublicationError(
                "final candidate binds a different physical aggregate artifact than the manifest"
            )
        if installed["private_archive"] != candidate["private_archive"]:
            raise PublicationError(
                "signed-installed and final-candidate gates derived different private archives"
            )
        # Both public inputs carry only the same strict aggregate descriptor;
        # the raw aggregate and descendants stay in the retained private root.
        embedded = payload["final_candidate"].get("physical_evidence")
        if embedded != payload["signed_installed"]:
            raise PublicationError(
                "final candidate binds a different physical evidence descriptor than the manifest"
            )


# --------------------------------------------------------------------------
# Inner Evidence_Manifest composition
# --------------------------------------------------------------------------


def _inner_manifest(
    repository: Path,
    value: object,
    commit: str,
    gates: dict[str, dict[str, Any]],
    *,
    fixture: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Validate the canonical inner Evidence_Manifest and derive its claims."""
    if not isinstance(value, dict):
        raise PublicationError("inner Evidence_Manifest must be a JSON object")
    try:
        summary = validate_evidence_manifest(value)
    except EvidenceManifestError as error:
        raise PublicationError(f"inner Evidence_Manifest is invalid: {error}") from error

    capability_ids = [capability["id"] for capability in summary["capabilities"]]
    require_complete_capability_set(repository, capability_ids)
    require_fixed_evidence_mapping(value)

    # Production seals reopen every raw report from the release repository.
    # The generic inner validator accepts content-addressed descriptors without
    # a reports root, but the publication boundary must not seal hashes whose
    # bytes are missing. Fixture mode remains hermetic and is never publishable.
    if not fixture:
        for report in summary["reports"].values():
            relative = safe_relative(report["path"], f"report {report['id']} path")
            path = repository.joinpath(*relative.parts)
            if sha256_file(path) != report["sha256"]:
                raise PublicationError(
                    f"inner Evidence_Manifest raw report differs from its binding: {report['id']}"
                )

    identity = summary["identity"]
    if identity["commit"] != commit:
        raise PublicationError("inner Evidence_Manifest is bound to a different commit")
    ci = gates["unsigned_ci"]["evidence"]
    if ci is not None and identity["toolchain_sha256"] != ci["toolchain_sha256"]:
        raise PublicationError(
            "inner Evidence_Manifest is bound to a different toolchain than the CI lanes"
        )
    candidate = gates["final_candidate"]["evidence"]
    if candidate is not None and identity["signed_app_sha256"] != (
        candidate["signed_app_tree_sha256"]
    ):
        raise PublicationError(
            "inner Evidence_Manifest is bound to a different signed app tree than the candidate"
        )
    installed = gates["signed_installed"]["evidence"]
    if installed is not None and identity["signed_app_sha256"] != (
        installed["signed_app_tree_sha256"]
    ):
        raise PublicationError(
            "inner Evidence_Manifest is bound to a different signed app tree than the "
            "signed-installed evidence"
        )

    reports = summary["reports"]
    capabilities: list[dict[str, Any]] = []
    seen: set[str] = set()
    for capability in value["capabilities"]:
        identifier = capability["id"]
        if identifier in seen:
            # Defense in depth: exactly one highest level per capability.
            raise PublicationError(f"capability {identifier!r} is declared more than once")
        seen.add(identifier)
        level_digests = {
            level: sorted({reports[report_id]["sha256"] for report_id in entry["report_ids"]})
            for level, entry in capability["levels"].items()
        }
        capabilities.append(
            {
                "id": identifier,
                "highest_level": capability["highest_level"],
                "level_report_digests": level_digests,
            }
        )
    capabilities.sort(key=lambda entry: entry["id"])
    report_digests = sorted({report["sha256"] for report in reports.values()})
    return identity, capabilities, report_digests


def _level_ceiling(gates: dict[str, dict[str, Any]]) -> int | None:
    """Return the deepest level index every required gate authorizes, or None."""
    ceiling: int | None = None
    for index, level in enumerate(LEVEL_ORDER):
        required = [
            name for name in GATE_ORDER if LEVEL_INDEX[GATE_LEVEL[name]] <= LEVEL_INDEX[level]
        ]
        if all(gates[name]["status"] == PASSED for name in required):
            ceiling = index
        else:
            break
    return ceiling


def _blocking_gate(gates: dict[str, dict[str, Any]], level_index: int) -> tuple[str, str]:
    for name in GATE_ORDER:
        if LEVEL_INDEX[GATE_LEVEL[name]] <= level_index and gates[name]["status"] != PASSED:
            return name, gates[name]["status"]
    raise PublicationError("no blocking gate found for a refused promotion")


def _enforce_promotion(gates: dict[str, dict[str, Any]], capabilities: list[dict[str, Any]]) -> None:
    """Refuse every capability level that its gates do not authorize."""
    ceiling = _level_ceiling(gates)
    for capability in capabilities:
        claimed = LEVEL_INDEX[capability["highest_level"]]
        if ceiling is None or claimed > ceiling:
            gate, status = _blocking_gate(gates, claimed)
            raise PublicationError(
                f"capability {capability['id']!r} claims {capability['highest_level']} but the "
                f"{gate} gate is {status}: promotion is refused"
            )


# --------------------------------------------------------------------------
# Document bindings
# --------------------------------------------------------------------------


def _documents(repository: Path, gates: dict[str, dict[str, Any]], closure: object) -> list[dict[str, Any]]:
    """Bind every feature and publication document by content digest."""
    documents: list[dict[str, Any]] = []
    for identifier, relative in REQUIRED_DOCUMENTS.items():
        safe_relative(relative, f"document {identifier}")
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise PublicationError(f"required feature document is missing: {relative}")
        documents.append(
            {
                "id": identifier,
                "kind": "specification",
                "path": relative,
                "sha256": sha256_file(path),
                "source": "repository",
            }
        )
    if gates["sealed_closure"]["evidence"] is not None and isinstance(closure, dict):
        for identifier, section, field in PUBLICATION_DOCUMENTS:
            block = closure.get(section)
            if not isinstance(block, dict) or field not in block:
                raise PublicationError(
                    f"sealed closure does not bind the {identifier} publication document"
                )
            documents.append(
                {
                    "id": identifier,
                    "kind": "publication",
                    "path": None,
                    "sha256": require_sha256(block[field], f"publication document {identifier}"),
                    "source": "sealed_closure",
                }
            )
    documents.sort(key=lambda entry: entry["id"])
    identifiers = [entry["id"] for entry in documents]
    if len(set(identifiers)) != len(identifiers):
        raise PublicationError("document bindings repeat an identifier")
    return documents


# --------------------------------------------------------------------------
# Publication gate
# --------------------------------------------------------------------------


def publication_decision(
    gates: dict[str, dict[str, Any]],
    capabilities: list[dict[str, Any]],
    *,
    fixture: bool = False,
) -> dict[str, Any]:
    """Decide whether publication artifacts may be created. Fail closed.

    Publication requires every composed gate to pass - P0 source implementation,
    unsigned CI, signed-installed evidence, sealed closure, the final-candidate
    binding, and workspace secret custody - and every capability to have reached
    ``Sealed_Release_Evidence``. There is no override and no fallback.
    """
    refusals = [
        f"gate:{name}={gates[name]['status']}"
        for name in GATE_ORDER
        if gates[name]["status"] != PASSED
    ]
    refusals.extend(
        f"capability:{capability['id']}={capability['highest_level']}"
        for capability in capabilities
        if capability["highest_level"] != SEALED_LEVEL
    )
    if fixture:
        # Fixtures may prove that every substantive gate would pass, but a test
        # document must never itself authorize creation of publication assets.
        refusals.append("fixture-mode")
    refusals.sort()
    allowed = not refusals
    return {
        "allowed": allowed,
        "artifacts_permitted": allowed,
        "refusals": refusals,
    }


# --------------------------------------------------------------------------
# Build + validate
# --------------------------------------------------------------------------


def _manifest_body(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "manifest_sha256"}


REQUEST_FIELDS = {
    "product",
    "commit",
    "evidence_manifest",
    "p0_source",
    "unsigned_ci",
    "signed_installed",
    "sealed_closure",
    "final_candidate",
}

DOCUMENT_FIELDS = {
    "schema_version",
    "document",
    "visibility",
    "fixture",
    "status",
    "blocked_inputs",
    "publication",
    "product",
    "commit",
    "platform",
    "documents",
    "gates",
    "capabilities",
    "bindings",
    "evidence_manifest",
    "p0_source",
    "unsigned_ci",
    "signed_installed",
    "sealed_closure",
    "final_candidate",
}


def build_sealed_evidence_manifest(
    repository: Path,
    request: object,
    *,
    fixture: bool,
    workspace_root: Path | None = None,
    physical_evidence_root: Path | None = None,
    physical_trust_policy: CollectorTrustPolicy | None = None,
) -> dict[str, Any]:
    """Assemble the canonical, self-sealing outer Evidence Manifest.

    Every composed input may be ``None``, meaning "not available in this
    environment"; its gate becomes ``not-run``, the manifest seals to ``blocked``,
    and publication is refused. Nothing here can convert an absent input into
    acceptance.
    """
    root = repository if workspace_root is None else workspace_root
    evidence_root = repository if physical_evidence_root is None else physical_evidence_root
    payload = require_exact_keys(request, REQUEST_FIELDS, "sealed evidence manifest request")
    product = _product(payload["product"])
    commit = _require_commit(payload["commit"], "repository commit")

    gates: dict[str, dict[str, Any]] = {}
    source_document = None
    ci_document = None

    if payload["p0_source"] is None:
        gates["p0_source"] = _gate(NOT_RUN, None)
    else:
        source_document, failures = _source_gate_document(repository, payload["p0_source"], commit)
        gates["p0_source"] = _gate(
            PASSED if not failures else FAILED,
            {"gates": len(source_document["gates"]), "failed": failures},
        )
    if payload["unsigned_ci"] is None:
        gates["unsigned_ci"] = _gate(NOT_RUN, None)
    else:
        ci_document, failures = _ci_lane_document(payload["unsigned_ci"], commit)
        gates["unsigned_ci"] = _gate(
            PASSED if not failures else FAILED,
            {
                "release_source_sha256": ci_document["release_source_sha256"],
                "toolchain_sha256": ci_document["toolchain_sha256"],
                "lanes": len(ci_document["lanes"]),
                "failed": failures,
            },
        )
    if payload["signed_installed"] is None:
        gates["signed_installed"] = _gate(NOT_RUN, None)
    else:
        gates["signed_installed"] = _signed_installed_gate(
            payload["signed_installed"],
            product,
            evidence_root=evidence_root,
            trust_policy=physical_trust_policy,
            fixture=fixture,
        )
    if payload["sealed_closure"] is None:
        gates["sealed_closure"] = _gate(NOT_RUN, None)
    else:
        gates["sealed_closure"] = _sealed_closure_gate(
            repository, payload["sealed_closure"], product, commit, fixture
        )
    if payload["final_candidate"] is None:
        gates["final_candidate"] = _gate(NOT_RUN, None)
    else:
        gates["final_candidate"] = _final_candidate_gate(
            repository,
            payload["final_candidate"],
            product,
            commit,
            fixture,
            root,
            evidence_root,
            physical_trust_policy,
        )
    gates[RELEASE_SECRET_GATE] = _release_secret_gate(root)

    _cross_bind_gates(gates, payload)

    identity, capabilities, report_digests = _inner_manifest(
        repository,
        payload["evidence_manifest"],
        commit,
        gates,
        fixture=fixture,
    )
    # No level skipping and no masking: every claimed level must be authorized by
    # its own gate and every predecessor gate.
    _enforce_promotion(gates, capabilities)

    documents = _documents(repository, gates, payload["sealed_closure"])
    closure_evidence = gates["sealed_closure"]["evidence"]
    candidate_evidence = gates["final_candidate"]["evidence"]
    installed_evidence = gates["signed_installed"]["evidence"]

    bindings = {
        "commit": commit,
        "release_source_sha256": (
            None if ci_document is None else ci_document["release_source_sha256"]
        ),
        "product": product,
        "identity": identity,
        "documents_sha256": sha256_bytes(canonical_json(documents)),
        "evidence_manifest_sha256": sha256_bytes(canonical_json(payload["evidence_manifest"])),
        "report_digests": report_digests,
        "sealed_closure_sha256": (
            None if closure_evidence is None else closure_evidence["closure_sha256"]
        ),
        "final_candidate_sha256": (
            None if candidate_evidence is None else candidate_evidence["binding_sha256"]
        ),
        "signed_app_tree_sha256": (
            None if candidate_evidence is None else candidate_evidence["signed_app_tree_sha256"]
        ),
        "app_manifest_sha256": (
            None if candidate_evidence is None else candidate_evidence["app_manifest_sha256"]
        ),
        "final_artifact_hash_manifest_sha256": (
            None
            if candidate_evidence is None
            else candidate_evidence["artifact_hash_manifest_sha256"]
        ),
        "final_artifact_hashes": (
            [] if candidate_evidence is None else candidate_evidence["final_artifact_hashes"]
        ),
        "installed_runs": [] if installed_evidence is None else installed_evidence["runs"],
        "physical_trust_policy_sha256": (
            None
            if installed_evidence is None
            else installed_evidence["trust_policy_sha256"]
        ),
        "physical_aggregate_sha256": (
            None
            if installed_evidence is None
            else installed_evidence["aggregate_artifact"]["sha256"]
        ),
        "physical_private_archive_sha256": (
            None
            if installed_evidence is None
            else installed_evidence["private_archive"]["binding_sha256"]
        ),
    }

    blocked_inputs = sorted(name for name in GATE_ORDER if gates[name]["status"] != PASSED)
    status = SEALED if not blocked_inputs else BLOCKED
    publication = publication_decision(gates, capabilities, fixture=fixture)

    body = {
        "schema_version": SCHEMA_VERSION,
        "document": DOCUMENT_KIND,
        "visibility": DOCUMENT_VISIBILITY,
        "fixture": bool(fixture),
        "status": status,
        "blocked_inputs": blocked_inputs,
        "publication": publication,
        "product": product,
        "commit": commit,
        "platform": {"macos_min": MACOS_MIN, "arch": ARCH, "license": LICENSE},
        "documents": documents,
        "gates": {name: gates[name] for name in sorted(gates)},
        "capabilities": capabilities,
        "bindings": bindings,
        "evidence_manifest": payload["evidence_manifest"],
        "p0_source": source_document,
        "unsigned_ci": ci_document,
        "signed_installed": payload["signed_installed"],
        "sealed_closure": payload["sealed_closure"],
        "final_candidate": payload["final_candidate"],
    }
    # Self-sealing: the digest covers the manifest's own canonical body.
    body["manifest_sha256"] = sha256_bytes(canonical_json(body))
    return body


def validate_sealed_evidence_manifest(
    repository: Path,
    document: object,
    *,
    fixture: bool,
    workspace_root: Path | None = None,
    physical_evidence_root: Path | None = None,
    physical_trust_policy: CollectorTrustPolicy | None = None,
    require_sealed: bool = False,
) -> dict[str, Any]:
    """Fail-closed validation of a sealed outer Evidence Manifest.

    Re-derives every derived field from the embedded evidence - the gate table,
    the capability levels, the document digests, the bindings, the publication
    decision, and the self-seal digest - so any hand-edited field is rejected.
    With ``require_sealed`` a ``blocked`` manifest is rejected as well, so an
    incomplete environment can never be promoted.
    """
    root = repository if workspace_root is None else workspace_root
    parsed = require_exact_keys(
        document, DOCUMENT_FIELDS | {"manifest_sha256"}, "sealed evidence manifest"
    )
    if (
        type(parsed["schema_version"]) is not int
        or parsed["schema_version"] != SCHEMA_VERSION
        or parsed["document"] != DOCUMENT_KIND
    ):
        raise PublicationError("sealed evidence manifest has an unsupported schema/document kind")
    if parsed["visibility"] != DOCUMENT_VISIBILITY:
        raise PublicationError("sealed evidence manifest is not private release-operations evidence")
    if parsed["fixture"] is not bool(fixture):
        raise PublicationError("sealed evidence manifest fixture mode mismatch")
    if parsed["status"] not in STATUSES:
        raise PublicationError("sealed evidence manifest status is not sealed/blocked")
    if parsed["platform"] != {"macos_min": MACOS_MIN, "arch": ARCH, "license": LICENSE}:
        raise PublicationError("sealed evidence manifest platform contract does not match Release")

    request = {
        "product": parsed["product"],
        "commit": parsed["commit"],
        "evidence_manifest": parsed["evidence_manifest"],
        "p0_source": parsed["p0_source"],
        "unsigned_ci": parsed["unsigned_ci"],
        "signed_installed": parsed["signed_installed"],
        "sealed_closure": parsed["sealed_closure"],
        "final_candidate": parsed["final_candidate"],
    }
    rebuilt = build_sealed_evidence_manifest(
        repository,
        request,
        fixture=fixture,
        workspace_root=root,
        physical_evidence_root=physical_evidence_root,
        physical_trust_policy=physical_trust_policy,
    )

    if sorted(parsed["blocked_inputs"]) != rebuilt["blocked_inputs"]:
        raise PublicationError("sealed evidence manifest blocked-input set is inconsistent")
    if parsed["status"] != rebuilt["status"]:
        raise PublicationError("sealed evidence manifest status disagrees with its bound inputs")
    if parsed["gates"] != rebuilt["gates"]:
        raise PublicationError("sealed evidence manifest gate table does not match its inputs")
    if parsed["capabilities"] != rebuilt["capabilities"]:
        raise PublicationError(
            "sealed evidence manifest capability levels do not match the inner Evidence_Manifest"
        )
    if parsed["documents"] != rebuilt["documents"]:
        raise PublicationError(
            "sealed evidence manifest document bindings do not match their content digests"
        )
    if parsed["bindings"] != rebuilt["bindings"]:
        raise PublicationError("sealed evidence manifest bindings do not match its inputs")
    if parsed["publication"] != rebuilt["publication"]:
        raise PublicationError("sealed evidence manifest publication decision was hand-edited")
    if parsed["manifest_sha256"] != rebuilt["manifest_sha256"]:
        raise PublicationError("sealed evidence manifest content digest mismatch")
    if sha256_bytes(canonical_json(_manifest_body(parsed))) != parsed["manifest_sha256"]:
        raise PublicationError("sealed evidence manifest is not self-sealed")

    if require_sealed and rebuilt["status"] != SEALED:
        raise PublicationError(
            "sealed evidence manifest is environment-gated (blocked) and cannot be promoted: "
            f"{rebuilt['blocked_inputs']}"
        )
    return rebuilt


def authorize_publication_artifacts(
    repository: Path,
    document: object,
    *,
    workspace_root: Path | None = None,
    physical_evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Authorize creating publication artifacts, or refuse. There is no override.

    Publication artifacts may only be created after this function returns: it
    validates the sealed manifest, refuses a ``blocked`` manifest, and refuses
    any manifest whose gates or capability levels are not fully sealed.
    """
    if not isinstance(document, dict) or document.get("fixture") is not False:
        raise PublicationError("fixture evidence can never authorize publication artifacts")
    try:
        production_policy = load_release_trust_policy()
    except (CollectorTrustNotConfiguredError, RawArtifactError) as error:
        raise PublicationError(
            "production collector trust policy is unavailable for publication authorization"
        ) from error
    result = validate_sealed_evidence_manifest(
        repository,
        document,
        fixture=False,
        workspace_root=workspace_root,
        physical_evidence_root=physical_evidence_root,
        physical_trust_policy=production_policy,
        require_sealed=True,
    )
    decision = result["publication"]
    if not decision["allowed"] or not decision["artifacts_permitted"]:
        raise PublicationError(
            "publication artifacts are refused by the sealed Evidence Manifest: "
            f"{decision['refusals']}"
        )
    return result


# --------------------------------------------------------------------------
# Immutable sealing and canonical loading
# --------------------------------------------------------------------------


def seal_manifest(path: Path, document: dict[str, Any]) -> None:
    """Write the sealed manifest exactly once; never overwrite an existing seal."""
    if path.is_symlink() or path.exists():
        raise PublicationError(
            f"refusing to overwrite an existing sealed Evidence Manifest: {path}"
        )
    # ``write_new`` opens with O_EXCL, so a concurrent writer cannot win a race.
    write_new(path, canonical_json(document))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationError(f"sealed evidence manifest has a duplicate field: {key!r}")
        result[key] = value
    return result


def load_sealed_manifest(path: Path) -> Any:
    """Load one sealed manifest with canonical, duplicate-rejecting parsing."""
    data = read_regular(path, min(MAX_MANIFEST_BYTES, MAX_JSON_BYTES))
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"sealed evidence manifest is not canonical JSON: {error}") from error


# --------------------------------------------------------------------------
# Environment status (which composed inputs exist at all)
# --------------------------------------------------------------------------


def environment_status(
    repository: Path,
    *,
    evidence_directory: Path | None = None,
    manifest_path: Path | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Report which composed inputs exist, without fabricating any of them."""
    directory = (
        repository / DEFAULT_EVIDENCE_DIRECTORY if evidence_directory is None else evidence_directory
    )
    manifest = repository / DEFAULT_MANIFEST_PATH if manifest_path is None else manifest_path
    root = repository if workspace_root is None else workspace_root
    inputs: dict[str, dict[str, str]] = {}
    blocked: list[str] = []
    for name in COMPOSED_INPUTS:
        candidate = directory / ENVIRONMENT_INPUT_FILES[name]
        present = candidate.is_file() and not candidate.is_symlink()
        inputs[name] = {"path": str(candidate), "state": PRESENT if present else NOT_RUN}
        if not present:
            blocked.append(name)
    gate = _release_secret_gate(root)
    if gate["status"] != PASSED:
        blocked.append(RELEASE_SECRET_GATE)
    sealed_present = manifest.is_file() and not manifest.is_symlink()
    return {
        "evidence_directory": str(directory),
        "manifest_path": str(manifest),
        "manifest_state": PRESENT if sealed_present else NOT_RUN,
        "inputs": inputs,
        "workspace_secret_blocks": gate["evidence"]["blocks"],
        "blocked_inputs": sorted(blocked),
        "status": BLOCKED if blocked else "inputs-present",
    }


def self_check() -> None:
    """Verify the outer seal's wiring without any evidence file."""
    if LEVEL_ORDER != (
        "Source_Implemented",
        "Unsigned_CI_Verified",
        "Signed_Installed_Verified",
        "Sealed_Release_Evidence",
    ):
        raise PublicationError("evidence level order drifted from the Evidence_Manifest")
    if PHYSICAL_GRANTED_LEVEL != INSTALLED_LEVEL:
        raise PublicationError("the physical aggregator no longer grants the installed level")
    if set(GATE_LEVEL) != set(GATE_ORDER) or len(GATE_ORDER) != 6:
        raise PublicationError("publication gate wiring is inconsistent")
    if set(COMPOSED_INPUTS) | {RELEASE_SECRET_GATE} != set(GATE_ORDER):
        raise PublicationError("composed input wiring is inconsistent")
    if set(ENVIRONMENT_INPUT_FILES) != set(COMPOSED_INPUTS):
        raise PublicationError("composed input file wiring is inconsistent")
    if not REQUIRED_SOURCE_GATES or not REQUIRED_CI_LANES or not REQUIRED_DOCUMENTS:
        raise PublicationError("required gate/lane/document wiring is empty")
    for name in GATE_ORDER:
        if GATE_LEVEL[name] not in LEVEL_ORDER:
            raise PublicationError(f"gate {name} authorizes an unknown evidence level")
    # A gate table where nothing passed must authorize no level at all and must
    # refuse publication: the fail-closed default.
    empty = {name: {"status": NOT_RUN, "evidence": None} for name in GATE_ORDER}
    if _level_ceiling(empty) is not None:
        raise PublicationError("an empty gate table must authorize no evidence level")
    if publication_decision(empty, [])["allowed"]:
        raise PublicationError("an empty gate table must refuse publication")
    if load_physical_evidence_artifact is None or evaluate_workspace is None:
        raise PublicationError("outer seal is not wired to its dependencies")
    if validate_sealed_closure is None or validate_final_candidate_binding is None:
        raise PublicationError("outer seal is not wired to the sealed closure / final candidate")
    if validate_evidence_manifest is None:
        raise PublicationError("outer seal is not wired to the canonical Evidence_Manifest")
