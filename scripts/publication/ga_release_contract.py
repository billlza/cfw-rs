"""Read-only three-stage release contract for the single v0.4.0 GA identity.

The only production state transition is::

    prepackage -> ga-acceptance -> publication

Each stage is derived by reopening every required input and validating the
exact 40043 identity.  State mutation is owned by ``orchestrator``; this module
only composes expected bytes and reopens immutable evidence.
Assurance-only physical, performance, and capability-report evidence is kept
outside this graph and can never satisfy a missing GA-required input.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any, Final

from .common import (
    MAX_JSON_BYTES,
    PublicationError,
    canonical_json,
    enumerate_tree,
    read_regular,
    require_exact_keys,
    require_sha256,
    safe_relative,
    sha256_bytes,
    sha256_file,
    tree_digest,
)
from .durable_file import (
    exclusive_rooted_directory_lock,
    read_private_directory_contents_locked,
)
from .graph_model import load_pins
from .release_app_verifier import verify_release_app
from .release_environment import release_tool_environment
from .sealed_manifest import validate_ci_lane_document
from scripts.candidate_artifact_binding import (
    CandidateBindingError,
    validate_candidate_app_manifest,
)
from scripts.candidate_freeze import (
    CandidateFreezeError,
    verify_frozen_candidate,
)
from scripts.gatekeeper_assessment import (
    GatekeeperEvidenceError,
    validate_evidence as validate_gatekeeper_evidence,
)
from scripts.github_hosted_ci_receipt import (
    validate_receipt_offline as validate_hosted_ci_receipt_offline,
    verify_receipt as live_verify_hosted_ci_receipt,
)
from scripts.ga_acceptance_journal_export import (
    ACCEPTANCE_ROOT_RELATIVE,
    ENVIRONMENT_RELATIVE,
    GAAcceptanceJournalExportError,
    INSTALL_RELATIVE,
    MIGRATION_RELATIVE,
    SERVICE_RELATIVE,
    verify_ga_acceptance_journal_export,
)
from scripts.hash_artifact import build_manifest
from scripts.notarization_transaction import (
    TransactionContext,
    TransactionError,
    validate_published_transaction_receipt,
)
from scripts.release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    ReleaseWorkspaceError,
    bundle_build_identity,
    ga_root,
    verify_ga_workspace_path_preconditions,
)
from scripts.release_executor_source import (
    ExecutorSource,
    capture_executor_source,
    require_executor_unchanged,
    require_historical_executor,
    validate_source_identity,
)
from scripts.repository_source_identity import SourceIdentityError, identity_at_commit
from scripts.verify_notary_log import (
    NotaryLogError,
    validate_files as validate_notary_files,
)
from scripts.verify_signing_transformation import (
    SigningTransformationError,
    canonical_json as canonical_signing_transformation_json,
    verify_retained_receipt as verify_signing_transformation_receipt,
)


PRODUCT_VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
GA_BUILD: Final = ACTIVE_RELEASE_IDENTITY.ga_build
TEAM_ID: Final = "YKUPL7Z869"
NOTARY_PROFILE: Final = "clashformac-notary"
STAGES: Final = ("prepackage", "ga-acceptance", "publication")
GATE_CLASS: Final = "ga_required"
PASSED: Final = "passed"
BLOCKED: Final = "blocked"
ELIGIBLE: Final = "eligible"

CANDIDATE_ROOT: Final = Path(f"target/candidates/{PRODUCT_VERSION}")
GA_ROOT: Final = ga_root(Path("."))
ASSURANCE_ROOT: Final = CANDIDATE_ROOT / "assurance"
SIGNED_ROOT: Final = GA_ROOT / "signed"
SIGNED_APP: Final = SIGNED_ROOT / "Clash for Mac.app"
SIGNED_APP_MANIFEST: Final = SIGNED_ROOT / "Clash for Mac.app.manifest.json"
GA_NATIVE_PRODUCTS: Final = GA_ROOT / "signing-output/signed-native-products"
SIGNING_TRANSFORMATION: Final = GA_ROOT / "signing-output/signing-transformation.json"
CANDIDATE_FREEZE_INTENT: Final = GA_ROOT / "candidate-freeze/intent.json"
PRODUCT_INPUT: Final = GA_ROOT / "product-input.json"

STAGE_INPUT_ROOT: Final = GA_ROOT / "stage-inputs"
LOCAL_CI_INPUT: Final = STAGE_INPUT_ROOT / "local-ci-lanes.json"
HOSTED_CI_INPUT: Final = STAGE_INPUT_ROOT / "hosted-ci.json"
PUBLICATION_INPUT_ROOT: Final = STAGE_INPUT_ROOT / "publication"
ACCEPTANCE_INPUT_ROOT: Final = ACCEPTANCE_ROOT_RELATIVE
MIGRATION_JOURNAL_INPUT: Final = MIGRATION_RELATIVE
INSTALL_JOURNAL_INPUT: Final = INSTALL_RELATIVE
SERVICE_JOURNAL_INPUT: Final = SERVICE_RELATIVE
SERVICE_ENVIRONMENT_INPUT: Final = ENVIRONMENT_RELATIVE
RUNTIME_ACCEPTANCE_INPUT: Final = ACCEPTANCE_INPUT_ROOT / "runtime-acceptance.json"
RUNTIME_EVIDENCE_INPUT: Final = ACCEPTANCE_INPUT_ROOT / "runtime-evidence"

PACKAGE_ROOT: Final = GA_ROOT / "packages"
DMG_SET: Final = PACKAGE_ROOT / f"dmg/v{PRODUCT_VERSION}"
UPDATER_SET: Final = PACKAGE_ROOT / f"updater/v{PRODUCT_VERSION}"
PREPACKAGE_OUTPUT: Final = GA_ROOT / "prepackage"
GA_ACCEPTANCE_OUTPUT: Final = GA_ROOT / "ga-acceptance"
PUBLICATION_OUTPUT: Final = GA_ROOT / "publication"

NOTARY_ARCHIVE: Final = (
    SIGNED_ROOT / f"Clash.for.Mac_{PRODUCT_VERSION}_{GA_BUILD}_notary.zip"
)
NOTARY_RESULT: Final = SIGNED_ROOT / "notarization.json"
NOTARY_LOG: Final = SIGNED_ROOT / "notarization-log.json"
GATEKEEPER_EVIDENCE: Final = SIGNED_ROOT / "gatekeeper.json"

PREPACKAGE_DOCUMENT: Final = "cfm-ga-prepackage-seal-v2"
GA_ACCEPTANCE_DOCUMENT: Final = "cfm-ga-acceptance-seal-v3"
PUBLICATION_DOCUMENT: Final = "cfm-ga-publication-seal-v3"
RUNTIME_ACCEPTANCE_DOCUMENT: Final = "cfm-ga-runtime-acceptance-v2"
GA_APP_ARTIFACT_KIND: Final = "notarized-ga-candidate-v1"
STAGE_SCHEMA_VERSIONS: Final = {
    "prepackage": 2,
    "ga-acceptance": 3,
    "publication": 3,
}

STAGE_DOCUMENTS: Final = {
    "prepackage": PREPACKAGE_DOCUMENT,
    "ga-acceptance": GA_ACCEPTANCE_DOCUMENT,
    "publication": PUBLICATION_DOCUMENT,
}
STAGE_OUTPUTS: Final = {
    "prepackage": PREPACKAGE_OUTPUT,
    "ga-acceptance": GA_ACCEPTANCE_OUTPUT,
    "publication": PUBLICATION_OUTPUT,
}
STAGE_FILE_NAMES: Final = {
    "prepackage": frozenset(
        {"hosted-ci.json", "local-ci-lanes.json", "manifest.json"}
    ),
    "ga-acceptance": frozenset({"manifest.json"}),
    "publication": frozenset(
        {
            "manifest.json",
            "legal-review.json",
            "sbom.cyclonedx.json",
            "sbom.spdx.json",
        }
    ),
}
GA_RUNTIME_CHECKS: Final = frozenset(
    {
        "credential_leak_scan",
        "dns_traffic",
        "exact_dmg_install",
        "high_risk_rejections",
        "launch",
        "legacy_cfw_preserved",
        "network_extension",
        "service_registration",
        "shutdown_restore",
        "system_extension",
        "tcp_traffic",
        "udp_traffic",
    }
)


def _path(repository: Path, relative: Path) -> Path:
    return repository.joinpath(*relative.parts)


def _canonical_source_repository(repository: Path) -> Path:
    repository = Path(repository)
    try:
        resolved = repository.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise PublicationError("GA release repository is unavailable") from error
    if (
        repository.absolute() != resolved
        or resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise PublicationError("GA release repository is not one canonical owned directory")
    return resolved


def _canonical_repository(repository: Path) -> Path:
    resolved = _canonical_source_repository(repository)
    ga_directory = _path(resolved, GA_ROOT)
    try:
        with exclusive_rooted_directory_lock(resolved, ga_directory):
            pass
    except PublicationError as error:
        raise PublicationError(
            "GA root must be reached through canonical owned directories without symlinks"
        ) from error
    return resolved


def _repo_relative(repository: Path, path: Path) -> str:
    try:
        relative = path.relative_to(repository)
    except ValueError as error:
        raise PublicationError("GA evidence path is outside the repository") from error
    return safe_relative(relative.as_posix(), "GA evidence path").as_posix()


def _parse_strict_json(data: bytes, path: Path, *, canonical: bool = True) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PublicationError(f"GA JSON repeats field {key!r}: {path}")
            value[key] = item
        return value

    def reject_constant(token: str) -> Any:
        raise PublicationError(f"GA JSON contains non-finite constant {token}: {path}")

    try:
        value = json.loads(
            data,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except PublicationError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise PublicationError(f"GA JSON is invalid: {path}") from error
    if canonical:
        try:
            encoded = canonical_json(value)
        except (RecursionError, UnicodeError) as error:
            raise PublicationError(f"GA JSON is not canonical: {path}") from error
        if encoded != data:
            raise PublicationError(f"GA JSON is not canonical: {path}")
    return value


def _load_strict_json(path: Path, *, canonical: bool = True) -> Any:
    return _parse_strict_json(read_regular(path), path, canonical=canonical)


def _record(repository: Path, path: Path) -> dict[str, str]:
    return {
        "path": _repo_relative(repository, path),
        "sha256": sha256_file(path),
    }


def _tree_record(repository: Path, path: Path) -> dict[str, str]:
    entries = enumerate_tree(path)
    if not any(entry.get("type") == "file" for entry in entries):
        raise PublicationError(f"GA evidence tree contains no files: {path}")
    return {
        "path": _repo_relative(repository, path),
        "sha256": tree_digest(entries),
    }


def _require_real_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublicationError(f"required GA directory is unavailable: {path}") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise PublicationError(f"required GA path is not a real directory: {path}")


def _require_private_regular(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublicationError(f"private GA adapter is unavailable: {path}") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise PublicationError(f"GA adapter is not one owned 0600 regular file: {path}")


def _release_environment(repository: Path) -> dict[str, str]:
    pins = load_pins(repository / "scripts/dependency_pins.env")
    return release_tool_environment(repository, pins)


def _validate_release_application(
    repository: Path, environment: dict[str, str]
) -> None:
    verify_release_app(
        repository=repository,
        environment=environment,
    )


def _verify_publication_adapter(repository: Path) -> None:
    from . import release_contract

    expected_app = _path(repository, SIGNED_APP)
    expected_native = _path(repository, GA_NATIVE_PRODUCTS)
    expected_evidence = _path(repository, PUBLICATION_INPUT_ROOT)
    if (
        release_contract.signed_app(repository) != expected_app
        or release_contract.native_products_root(repository, GA_BUILD)
        != expected_native
        or release_contract.evidence_root(repository) != expected_evidence
    ):
        raise PublicationError(
            "GA publication verifier adapter is not migrated to ga/40043; "
            "legacy path fallback is forbidden"
        )


def _verified_legal_source_closure(
    repository: Path, app: Path
) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        from .verify import verify_evidence as verify_publication_evidence
    except ImportError as error:
        raise PublicationError(
            "GA publication verifier adapter cannot load after identity migration"
        ) from error

    _verify_publication_adapter(repository)
    root = _path(repository, PUBLICATION_INPUT_ROOT)
    try:
        verify_publication_evidence(root, app, False, repository=repository)
    except (OSError, PublicationError, ValueError) as error:
        raise PublicationError("GA legal/source/SBOM closure is invalid") from error
    required = (
        "evidence-manifest.json",
        "inventory.json",
        "legal-review.json",
        "machine-closure.json",
        "sbom.cyclonedx.json",
        "sbom.spdx.json",
    )
    tree_before = _tree_record(repository, root)
    records = {name: _record(repository, root / name) for name in required}
    copies = {
        name: canonical_json(_load_strict_json(root / name))
        for name in (
            "legal-review.json",
            "sbom.cyclonedx.json",
            "sbom.spdx.json",
        )
    }
    if _tree_record(repository, root) != tree_before:
        raise PublicationError("GA legal/source/SBOM closure changed while reopening")
    return {"tree": tree_before, "documents": records}, copies


def _validate_signing_notarization_binding(
    *,
    candidate_freeze_intent_sha256: str,
    transformation: dict[str, Any],
    transformation_sha256: str,
    notarization_receipt: dict[str, Any],
    app_manifest_tree_sha256: str,
    app_manifest_sha256: str,
) -> None:
    expected = {
        "candidate_freeze_intent_sha256": candidate_freeze_intent_sha256,
        "pre_sign_app_manifest_sha256": transformation[
            "pre_sign_app_manifest_sha256"
        ],
        "pre_sign_app_tree_sha256": transformation["pre_sign_app_tree_sha256"],
        "signed_app_tree_sha256": transformation["signed_app_tree_sha256"],
        "signing_transformation_receipt_sha256": transformation_sha256,
    }
    if (
        any(notarization_receipt.get(name) != digest for name, digest in expected.items())
        or notarization_receipt.get("pre_staple_app_tree_sha256")
        != transformation["signed_app_tree_sha256"]
        or notarization_receipt.get("post_staple_app_tree_sha256")
        != app_manifest_tree_sha256
        or notarization_receipt.get("app_manifest_sha256") != app_manifest_sha256
    ):
        raise PublicationError(
            "notarization or app-manifest bytes differ from the signing transformation"
        )


def _require_hosted_ci_source_binding(
    hosted_ci: object,
    *,
    candidate_freeze_intent_sha256: str,
    release_source_sha256: str,
    repository_commit: str,
) -> None:
    if not isinstance(hosted_ci, dict):
        raise PublicationError("hosted CI receipt is not an object")
    workflow = hosted_ci.get("workflow")
    workflow_source = workflow.get("source") if isinstance(workflow, dict) else None
    workflow_sha256 = (
        require_sha256(
            workflow_source.get("sha256"),
            "hosted CI workflow-file source",
        )
        if isinstance(workflow_source, dict)
        else None
    )
    if workflow_sha256 is None or hosted_ci.get("source") != {
        "candidate_freeze_intent_sha256": candidate_freeze_intent_sha256,
        "release_source_sha256": release_source_sha256,
        "repository_commit": repository_commit,
        "workflow_sha256": workflow_sha256,
    }:
        raise PublicationError("hosted CI receipt differs from the frozen candidate")


def _prepackage_ci_bindings(
    repository: Path,
    normalized_ci: dict[str, Any],
    hosted_ci: dict[str, Any],
) -> dict[str, Any]:
    return {
        "hosted": {
            "path": _repo_relative(
                repository, _path(repository, PREPACKAGE_OUTPUT / "hosted-ci.json")
            ),
            "repository_id": hosted_ci["repository"]["id"],
            "run_attempt": hosted_ci["run"]["run_attempt"],
            "run_id": hosted_ci["run"]["id"],
            "sha256": sha256_bytes(canonical_json(hosted_ci)),
            "workflow_id": hosted_ci["workflow"]["id"],
        },
        "local_deterministic": {
            "path": _repo_relative(
                repository, _path(repository, PREPACKAGE_OUTPUT / "local-ci-lanes.json")
            ),
            "sha256": sha256_bytes(canonical_json(normalized_ci)),
            "toolchain_sha256": normalized_ci["toolchain_sha256"],
        },
    }


def _verified_prepackage_inputs(
    repository: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, bytes]]:
    repository = _canonical_repository(repository)
    try:
        verify_ga_workspace_path_preconditions(repository)
    except ReleaseWorkspaceError as error:
        raise PublicationError(str(error)) from error
    if (PRODUCT_VERSION, GA_BUILD) != ("0.4.0", "40043"):
        raise PublicationError("prepackage requires the fixed v0.4.0/40043 identity")
    try:
        frozen = verify_frozen_candidate(repository)
    except CandidateFreezeError as error:
        raise PublicationError(f"candidate-freeze receipt is not reusable: {error}") from error
    expected_intent = _path(repository, CANDIDATE_FREEZE_INTENT)
    if frozen.intent_path != expected_intent or frozen.root != _path(repository, GA_ROOT):
        raise PublicationError("candidate-freeze receipt is outside the fixed GA root")
    intent = require_exact_keys(
        _load_strict_json(expected_intent),
        {
            "allocation_ledger_sha256",
            "build_number",
            "consumption_state",
            "document",
            "entitlements_tree_sha256",
            "native_products_tree_sha256",
            "pre_sign_app_tree_sha256",
            "pre_sign_tree_sha256",
            "product_input_document_sha256",
            "product_input_sha256",
            "product_version",
            "profiles_tree_sha256",
            "release_source_sha256",
            "repository_commit",
            "schema_version",
            "signing_preflight_sha256",
            "signing_plan_sha256",
            "updater_embedded_public_key_sha256",
            "updater_key_possession_proof_sha256",
            "updater_tauri_config_sha256",
        },
        "candidate-freeze intent",
    )
    if (
        intent["document"] != "cfm-candidate-freeze-intent-v3"
        or type(intent["schema_version"]) is not int
        or intent["schema_version"] != 3
        or intent["product_version"] != PRODUCT_VERSION
        or intent["build_number"] != GA_BUILD
        or intent["consumption_state"] != "candidate_frozen_consumed"
        or sha256_file(expected_intent) != frozen.intent_sha256
    ):
        raise PublicationError("candidate-freeze intent is not the active consumed GA")

    product_input_path = _path(repository, PRODUCT_INPUT)
    product_input = require_exact_keys(
        _load_strict_json(product_input_path),
        {"document", "product", "schema_version", "source", "toolchain"},
        "frozen product input",
    )
    if (
        product_input["document"] != "cfm-ga-product-input-v1"
        or type(product_input["schema_version"]) is not int
        or product_input["schema_version"] != 1
        or product_input["product"]
        != {"build_number": GA_BUILD, "version": PRODUCT_VERSION}
        or product_input["source"]
        != {
            "release_source_sha256": intent["release_source_sha256"],
            "repository_commit": intent["repository_commit"],
        }
        or sha256_file(product_input_path) != intent["product_input_document_sha256"]
    ):
        raise PublicationError("frozen product input differs from candidate-freeze")
    toolchain = product_input["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "cargoWorkspaceSourcesTreeSha256",
        "goModuleCacheTreeSha256",
        "goToolchainTreeSha256",
        "goToolsTreeSha256",
        "nodeToolchainTreeSha256",
        "tauriToolchainTreeSha256",
        "toolchainSha256",
        "uiDependenciesTreeSha256",
        "xcodegenToolchainTreeSha256",
    }:
        raise PublicationError("frozen toolchain identity has an unexpected field set")
    for name, digest in toolchain.items():
        require_sha256(digest, f"frozen toolchain {name}")

    ci_path = _path(repository, LOCAL_CI_INPUT)
    ci_value = _load_strict_json(ci_path)
    normalized_ci, failures = validate_ci_lane_document(
        ci_value,
        intent["repository_commit"],
        intent["release_source_sha256"],
    )
    if failures:
        raise PublicationError(
            f"local deterministic CI lanes are not all passing: {failures}"
        )
    if normalized_ci["toolchain_sha256"] != toolchain["toolchainSha256"]:
        raise PublicationError(
            "local deterministic CI lanes and frozen candidate use different toolchains"
        )
    hosted_ci = validate_hosted_ci_receipt_offline(repository)
    _require_hosted_ci_source_binding(
        hosted_ci,
        candidate_freeze_intent_sha256=frozen.intent_sha256,
        release_source_sha256=intent["release_source_sha256"],
        repository_commit=intent["repository_commit"],
    )

    source_identity = {
        "repositoryCommit": intent["repository_commit"],
        "releaseSourceSha256": intent["release_source_sha256"],
    }
    app = _path(repository, SIGNED_APP)
    app_manifest_path = _path(repository, SIGNED_APP_MANIFEST)
    try:
        app_manifest = validate_candidate_app_manifest(
            app_manifest_path,
            app,
            artifact_kind=GA_APP_ARTIFACT_KIND,
            build_number=GA_BUILD,
            source_identity=source_identity,
            toolchain_metadata=toolchain,
            team_id=TEAM_ID,
        )
    except (CandidateBindingError, OSError, ValueError) as error:
        raise PublicationError("signed GA app manifest is invalid") from error
    if app_manifest.get("algorithm") != "sha256-tree-v2":
        raise PublicationError("signed GA app manifest must use sha256-tree-v2")
    bundle_identity = bundle_build_identity(app)
    if (
        bundle_identity.product_version != PRODUCT_VERSION
        or bundle_identity.build_version != GA_BUILD
    ):
        raise PublicationError("signed application is not exactly v0.4.0/40043")
    environment = _release_environment(repository)
    _validate_release_application(repository, environment)

    try:
        notarization_publication = validate_published_transaction_receipt(
            TransactionContext(
                repository=repository,
                build_kind="ga",
                build_number=GA_BUILD,
                staged_app=None,
                native_products=_path(repository, GA_NATIVE_PRODUCTS),
                notary_profile=NOTARY_PROFILE,
                repository_commit=intent["repository_commit"],
                release_source_sha256=intent["release_source_sha256"],
                deployment_target="15.0",
                toolchain_metadata=dict(toolchain),
            )
        )
    except (OSError, TransactionError, ValueError) as error:
        raise PublicationError(
            "GA notarization publication receipt cannot be independently reopened"
        ) from error
    notarization_receipt = notarization_publication.receipt
    retained_signed_app = notarization_publication.retained_signed_app
    if retained_signed_app is None:
        raise PublicationError("GA notarization has no verified retained signing input")
    transformation_path = _path(repository, SIGNING_TRANSFORMATION)
    try:
        transformation = verify_signing_transformation_receipt(repository, retained_signed_app)
    except (OSError, SigningTransformationError, ValueError) as error:
        raise PublicationError(
            "GA signing transformation cannot be independently reopened"
        ) from error
    transformation_sha256 = sha256_bytes(
        canonical_signing_transformation_json(transformation)
    )
    if sha256_file(transformation_path) != transformation_sha256:
        raise PublicationError(
            "GA signing transformation path differs from its verified receipt"
        )
    _validate_signing_notarization_binding(
        candidate_freeze_intent_sha256=frozen.intent_sha256,
        transformation=transformation,
        transformation_sha256=transformation_sha256,
        notarization_receipt=notarization_receipt,
        app_manifest_tree_sha256=app_manifest["sha256"],
        app_manifest_sha256=sha256_file(app_manifest_path),
    )

    try:
        notary = validate_notary_files(
            _path(repository, NOTARY_RESULT),
            _path(repository, NOTARY_LOG),
            _path(repository, NOTARY_ARCHIVE),
        )
    except (NotaryLogError, OSError) as error:
        raise PublicationError("GA application notarization evidence is invalid") from error
    gatekeeper_path = _path(repository, GATEKEEPER_EVIDENCE)
    try:
        gatekeeper = validate_gatekeeper_evidence(
            _load_strict_json(gatekeeper_path),
            expected_assessment_type="execute",
            expected_primary_signature_context=False,
        )
    except GatekeeperEvidenceError as error:
        raise PublicationError("GA application Gatekeeper evidence is invalid") from error
    if gatekeeper["target_signed_app_tree_sha256"] != app_manifest["sha256"]:
        raise PublicationError("Gatekeeper evidence targets different GA app bytes")

    legal_source, legal_documents = _verified_legal_source_closure(repository, app)
    try:
        observed_app = build_manifest(app, algorithm=app_manifest["algorithm"])
    except (OSError, ValueError) as error:
        raise PublicationError("signed GA application cannot be rehashed") from error
    if observed_app.get("sha256") != app_manifest["sha256"]:
        raise PublicationError("signed GA application changed during prepackage")

    binding = {
        "candidate": {
            "app_manifest": _record(repository, app_manifest_path),
            "candidate_freeze": _record(repository, expected_intent),
            "notarization_receipt": _record(
                repository, notarization_publication.receipt_path
            ),
            "product_input": _record(repository, product_input_path),
            "signing_transformation": _record(
                repository, transformation_path
            ),
            "signed_app": {
                "path": _repo_relative(repository, app),
                "tree_sha256": app_manifest["sha256"],
            },
        },
        "ci": _prepackage_ci_bindings(repository, normalized_ci, hosted_ci),
        "legal_source": legal_source,
        "notarization": {
            "archive": _record(repository, _path(repository, NOTARY_ARCHIVE)),
            "gatekeeper": _record(repository, gatekeeper_path),
            "job_id": notary["jobId"],
            "log": _record(repository, _path(repository, NOTARY_LOG)),
            "profile": NOTARY_PROFILE,
            "result": _record(repository, _path(repository, NOTARY_RESULT)),
        },
        "source": {
            "release_source_sha256": intent["release_source_sha256"],
            "repository_commit": intent["repository_commit"],
        },
        "toolchain": toolchain,
    }
    return binding, normalized_ci, hosted_ci, legal_documents


def _stage_manifest(
    stage: str, bindings: dict[str, Any], executor_source: dict[str, str]
) -> dict[str, Any]:
    if stage not in STAGES:
        raise PublicationError(f"unknown GA release stage: {stage}")
    validate_source_identity(executor_source, "GA sealing executor")
    return {
        "authorization": {
            "create_packages": stage == "prepackage",
            "upload": stage == "publication",
        },
        "bindings": bindings,
        "document": STAGE_DOCUMENTS[stage],
        "executor_source": dict(executor_source),
        "ga_status": ELIGIBLE if stage == "publication" else BLOCKED,
        "gate_class": GATE_CLASS,
        "gate_status": PASSED,
        "product": {"build_number": GA_BUILD, "version": PRODUCT_VERSION},
        "schema_version": STAGE_SCHEMA_VERSIONS[stage],
        "stage": stage,
    }


def _validate_stage_manifest(value: object, stage: str) -> dict[str, Any]:
    manifest = require_exact_keys(
        value,
        {
            "authorization",
            "bindings",
            "document",
            "executor_source",
            "ga_status",
            "gate_class",
            "gate_status",
            "product",
            "schema_version",
            "stage",
        },
        f"{stage} manifest",
    )
    authorization = require_exact_keys(
        manifest["authorization"],
        {"create_packages", "upload"},
        f"{stage} authorization",
    )
    expected_authorization = {
        "create_packages": stage == "prepackage",
        "upload": stage == "publication",
    }
    if (
        manifest["document"] != STAGE_DOCUMENTS[stage]
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != STAGE_SCHEMA_VERSIONS[stage]
        or manifest["stage"] != stage
        or manifest["gate_class"] != GATE_CLASS
        or manifest["gate_status"] != PASSED
        or manifest["ga_status"]
        != (ELIGIBLE if stage == "publication" else BLOCKED)
        or manifest["product"]
        != {"build_number": GA_BUILD, "version": PRODUCT_VERSION}
        or any(type(authorization[key]) is not bool for key in authorization)
        or authorization != expected_authorization
        or not isinstance(manifest["bindings"], dict)
        or not manifest["bindings"]
    ):
        raise PublicationError(f"{stage} manifest identity or status is invalid")
    validate_source_identity(manifest["executor_source"], "GA sealing executor")
    return manifest


def _prepackage_files(
    repository: Path,
    executor_source: dict[str, str],
    *,
    expected_live_hosted_ci: dict[str, Any] | None = None,
) -> dict[str, bytes]:
    bindings, ci_document, hosted_ci, _legal_documents = _verified_prepackage_inputs(
        repository
    )
    if expected_live_hosted_ci is not None and hosted_ci != expected_live_hosted_ci:
        raise PublicationError(
            "hosted CI receipt changed after live prepackage revalidation"
        )
    manifest = _stage_manifest("prepackage", bindings, executor_source)
    return {
        "hosted-ci.json": canonical_json(hosted_ci),
        "local-ci-lanes.json": canonical_json(ci_document),
        "manifest.json": canonical_json(manifest),
    }


def _require_artifact_set_adapter(repository: Path):
    try:
        from scripts import release_artifact_set
    except ImportError as error:
        raise PublicationError(
            "GA package verifier adapter cannot load after identity migration"
        ) from error

    expected = _repo_relative(repository, _path(repository, SIGNED_APP))
    if release_artifact_set.CANDIDATE_APP_RELATIVE != expected:
        raise PublicationError(
            "GA package verifier adapter is not migrated to ga/40043; "
            "legacy package fallback is forbidden"
        )
    return release_artifact_set


def _verified_package_sets(
    repository: Path, prepackage: dict[str, Any]
) -> dict[str, Any]:
    artifact_set = _require_artifact_set_adapter(repository)
    source = prepackage["bindings"]["source"]
    expected_source = {
        "repository_commit": source["repository_commit"],
        "release_source_sha256": source["release_source_sha256"],
    }
    try:
        dmg = artifact_set.verify_dmg_set(
            _path(repository, DMG_SET),
            repository=repository,
            version=PRODUCT_VERSION,
            expected_source_identity=expected_source,
            prepackage_stage_verifier=verify_prepackage_authorization,
        )
        updater = artifact_set.verify_updater_set(
            _path(repository, UPDATER_SET),
            repository=repository,
            version=PRODUCT_VERSION,
            expected_source_identity=expected_source,
            prepackage_stage_verifier=verify_prepackage_authorization,
        )
    except (OSError, ValueError, artifact_set.ArtifactSetError) as error:
        raise PublicationError("GA DMG or updater set is not exactly sealed") from error
    expected_tree = prepackage["bindings"]["candidate"]["signed_app"]["tree_sha256"]
    for label, seal in (("DMG", dmg), ("updater", updater)):
        candidate = seal.get("candidate_app")
        if (
            not isinstance(candidate, dict)
            or candidate.get("build_number") != GA_BUILD
            or candidate.get("signed_app_tree_sha256") != expected_tree
            or candidate.get("path") != _repo_relative(repository, _path(repository, SIGNED_APP))
        ):
            raise PublicationError(f"{label} set does not contain the exact GA application")
    if dmg.get("build_number") != GA_BUILD:
        raise PublicationError("DMG set has the wrong GA build number")
    return {
        "dmg": {
            "dmg_sha256": dmg["artifacts"]["dmg"]["sha256"],
            "gatekeeper_sha256": dmg["artifacts"]["gatekeeper"]["sha256"],
            "seal": _record(repository, _path(repository, DMG_SET) / "dmg-set.seal.json"),
            "tree": _tree_record(repository, _path(repository, DMG_SET)),
        },
        "updater": {
            "archive_sha256": updater["artifacts"]["archive"]["sha256"],
            "seal": _record(
                repository,
                _path(repository, UPDATER_SET) / "updater-set.seal.json",
            ),
            "tree": _tree_record(repository, _path(repository, UPDATER_SET)),
        },
    }


def _verified_migration_journals(repository: Path) -> dict[str, Any]:
    repository = _canonical_repository(repository)
    try:
        verified = verify_ga_acceptance_journal_export(repository)
    except (OSError, GAAcceptanceJournalExportError) as error:
        raise PublicationError("atomic GA migration journal export is invalid") from error
    verified = require_exact_keys(
        verified,
        {
            "candidate",
            "environment",
            "export",
            "install_journal",
            "previous",
            "service_journal",
        },
        "verified GA migration journals",
    )
    environment = require_exact_keys(
        verified["environment"],
        {"document", "record", "sha256"},
        "verified GA migration environment",
    )
    export = require_exact_keys(
        verified["export"],
        {"intent", "receipt", "record"},
        "verified GA migration export",
    )
    install_journal = require_exact_keys(
        verified["install_journal"],
        {"document", "record"},
        "verified GA install journal",
    )
    service_journal = require_exact_keys(
        verified["service_journal"],
        {"events", "intent", "record"},
        "verified GA service journal",
    )
    require_sha256(environment["sha256"], "verified GA environment digest")
    expected_records = {
        "environment": _record(repository, _path(repository, SERVICE_ENVIRONMENT_INPUT)),
        "export": _tree_record(repository, _path(repository, MIGRATION_JOURNAL_INPUT)),
        "install": _record(repository, _path(repository, INSTALL_JOURNAL_INPUT)),
        "service": _tree_record(repository, _path(repository, SERVICE_JOURNAL_INPUT)),
    }
    if (
        environment["record"] != expected_records["environment"]
        or export["record"] != expected_records["export"]
        or install_journal["record"] != expected_records["install"]
        or service_journal["record"] != expected_records["service"]
        or verified["candidate"] != install_journal["document"]["candidate"]
        or verified["previous"] != install_journal["document"]["previous"]
        or service_journal["intent"]["candidate"] != verified["candidate"]
        or service_journal["intent"]["previous"] != verified["previous"]
        or service_journal["intent"]["ga_environment_sha256"]
        != environment["sha256"]
        or install_journal["document"]["ga_environment_sha256"]
        != environment["sha256"]
    ):
        raise PublicationError(
            "atomic GA migration journal export differs from its reopened fixed records"
        )
    return verified


def _expected_candidate_from_prepackage(
    prepackage: dict[str, Any],
) -> dict[str, str]:
    try:
        bindings = prepackage["bindings"]
        return {
            "build_number": GA_BUILD,
            "manifest_sha256": bindings["candidate"]["app_manifest"]["sha256"],
            "release_source_sha256": bindings["source"][
                "release_source_sha256"
            ],
            "repository_commit": bindings["source"]["repository_commit"],
            "tree_sha256": bindings["candidate"]["signed_app"]["tree_sha256"],
            "version": PRODUCT_VERSION,
        }
    except (KeyError, TypeError) as error:
        raise PublicationError(
            "prepackage omits the candidate identity required for GA migration"
        ) from error


def _require_migration_matches_prepackage(
    prepackage: dict[str, Any],
    migration: dict[str, Any],
) -> None:
    expected_candidate = _expected_candidate_from_prepackage(prepackage)
    try:
        install_journal = migration["install_journal"]["document"]
        closed_migration = (
            install_journal["phase"] == "installed"
            and install_journal["candidate"]["build_number"] == GA_BUILD
            and install_journal["previous"]["build_number"] == "40041"
            and all(
                segment["after"] is not None
                for segment in install_journal["guards"]
            )
        )
        candidate_matches = (
            migration["candidate"] == expected_candidate
            and install_journal["candidate"] == expected_candidate
        )
    except (KeyError, TypeError) as error:
        raise PublicationError(
            "GA migration export omits its pre-runtime candidate identity"
        ) from error
    if not closed_migration:
        raise PublicationError(
            "install journal is not a closed 40041 to 40043 migration"
        )
    if not candidate_matches:
        raise PublicationError(
            "GA migration export targets different bytes than prepackage"
        )


def _verified_acceptance_inputs(
    repository: Path,
    prepackage: dict[str, Any],
    packages: dict[str, Any],
) -> dict[str, Any]:
    migration = _verified_migration_journals(repository)
    _require_migration_matches_prepackage(prepackage, migration)
    runtime = _verified_runtime_acceptance_adapter(
        repository,
        packages=packages,
        ga_environment_sha256=migration["environment"]["sha256"],
        install_journal_sha256=migration["install_journal"]["record"]["sha256"],
        service_journal_tree_sha256=migration["service_journal"]["record"]["sha256"],
    )
    return {
        "adapter": runtime["adapter"],
        "ga_environment_sha256": migration["environment"]["sha256"],
        "migration_journals": {
            "environment": migration["environment"]["record"],
            "export": migration["export"]["record"],
            "install": migration["install_journal"]["record"],
            "service": migration["service_journal"]["record"],
        },
        "runtime_evidence": runtime["runtime_evidence"],
    }


def _verified_runtime_acceptance_adapter(
    repository: Path,
    *,
    packages: dict[str, Any],
    ga_environment_sha256: str,
    install_journal_sha256: str,
    service_journal_tree_sha256: str,
) -> dict[str, Any]:
    """Require a real raw-evidence verifier; never trust a local passed summary."""

    repository = _canonical_repository(repository)
    acceptance_path = _path(repository, RUNTIME_ACCEPTANCE_INPUT)
    raw_evidence_root = _path(repository, RUNTIME_EVIDENCE_INPUT)

    try:
        from scripts.ga_runtime_acceptance import validate_ga_runtime_acceptance
    except ImportError as error:
        raise PublicationError(
            "GA runtime acceptance producer/verifier is not implemented; "
            "a local all-passed summary cannot authorize release"
        ) from error
    expected = {
        "checks": tuple(sorted(GA_RUNTIME_CHECKS)),
        "document": RUNTIME_ACCEPTANCE_DOCUMENT,
        "dmg_sha256": packages["dmg"]["dmg_sha256"],
        "dmg_gatekeeper_sha256": packages["dmg"]["gatekeeper_sha256"],
        "dmg_set_seal_sha256": packages["dmg"]["seal"]["sha256"],
        "from_build": "40041",
        "ga_environment_sha256": ga_environment_sha256,
        "install_journal_sha256": install_journal_sha256,
        "product_version": PRODUCT_VERSION,
        "service_journal_tree_sha256": service_journal_tree_sha256,
        "to_build": GA_BUILD,
    }
    try:
        result = validate_ga_runtime_acceptance(
            repository=repository,
            acceptance_path=acceptance_path,
            raw_evidence_root=raw_evidence_root,
            expected=expected,
            prepackage_stage_verifier=verify_prepackage_authorization,
        )
    except (OSError, ValueError) as error:
        raise PublicationError("GA runtime raw evidence is invalid") from error
    result = require_exact_keys(
        result,
        {"adapter", "runtime_evidence"},
        "verified GA runtime acceptance",
    )
    for name in ("adapter", "runtime_evidence"):
        record = require_exact_keys(
            result[name], {"path", "sha256"}, f"GA runtime {name} record"
        )
        safe_relative(record["path"], f"GA runtime {name} path")
        require_sha256(record["sha256"], f"GA runtime {name} digest")
    _require_private_regular(acceptance_path)
    _require_real_directory(raw_evidence_root)
    reopened = {
        "adapter": _record(repository, acceptance_path),
        "runtime_evidence": _tree_record(repository, raw_evidence_root),
    }
    if result != reopened:
        raise PublicationError(
            "GA runtime verifier did not bind the fixed adapter and raw-evidence paths"
        )
    return result


def _ga_acceptance_files(
    repository: Path, prepackage: dict[str, Any], executor_source: dict[str, str]
) -> dict[str, bytes]:
    packages = _verified_package_sets(repository, prepackage)
    runtime = _verified_acceptance_inputs(repository, prepackage, packages)
    bindings = {
        "package_sets": packages,
        "prepackage_manifest_sha256": sha256_file(
            _path(repository, PREPACKAGE_OUTPUT) / "manifest.json"
        ),
        "runtime_acceptance": runtime,
    }
    return {
        "manifest.json": canonical_json(
            _stage_manifest("ga-acceptance", bindings, executor_source)
        )
    }


def _publication_files(
    repository: Path,
    prepackage: dict[str, Any],
    ga_acceptance: dict[str, Any],
    executor_source: dict[str, str],
) -> dict[str, bytes]:
    legal_source, copies = _verified_legal_source_closure(
        repository, _path(repository, SIGNED_APP)
    )
    if legal_source != prepackage["bindings"]["legal_source"]:
        raise PublicationError("legal/source/SBOM closure changed after prepackage")
    bindings = {
        "ga_acceptance_manifest_sha256": sha256_file(
            _path(repository, GA_ACCEPTANCE_OUTPUT) / "manifest.json"
        ),
        "legal_source": legal_source,
        "package_sets": ga_acceptance["bindings"]["package_sets"],
        "prepackage_manifest_sha256": sha256_file(
            _path(repository, PREPACKAGE_OUTPUT) / "manifest.json"
        ),
    }
    return {
        "manifest.json": canonical_json(
            _stage_manifest("publication", bindings, executor_source)
        ),
        **copies,
    }


def _read_stage_files(repository: Path, stage: str) -> dict[str, bytes]:
    output = _path(repository, STAGE_OUTPUTS[stage])
    names = STAGE_FILE_NAMES[stage]
    parent = output.parent
    with exclusive_rooted_directory_lock(repository, parent) as descriptor:
        return read_private_directory_contents_locked(
            descriptor,
            parent,
            output.name,
            {name: MAX_JSON_BYTES for name in names},
        )


def _manifest_from_files(stage: str, files: dict[str, bytes], path: Path) -> dict[str, Any]:
    if set(files) != set(STAGE_FILE_NAMES[stage]):
        raise PublicationError(f"{stage} stage has an unexpected file set")
    return _validate_stage_manifest(
        _parse_strict_json(files["manifest.json"], path / "manifest.json"),
        stage,
    )


def _compose_stage_files(
    repository: Path,
    stage: str,
    executor_source: dict[str, str],
    *,
    require_live_hosted_ci: bool = False,
) -> dict[str, bytes]:
    """Reopen product inputs under one already verified sealing identity."""

    repository = _canonical_repository(repository)
    if stage not in STAGES:
        raise PublicationError(f"unknown GA release stage: {stage}")
    live_hosted_ci = (
        live_verify_hosted_ci_receipt(repository)
        if require_live_hosted_ci
        else None
    )
    if stage == "prepackage":
        return _prepackage_files(
            repository,
            executor_source,
            expected_live_hosted_ci=live_hosted_ci,
        )
    if stage == "ga-acceptance":
        prepackage = _verify_stage(repository, "prepackage")
        return _ga_acceptance_files(repository, prepackage, executor_source)
    prepackage = _verify_stage(repository, "prepackage")
    ga_acceptance = _verify_stage(repository, "ga-acceptance")
    return _publication_files(repository, prepackage, ga_acceptance, executor_source)


def _current_stage_executor(repository: Path) -> ExecutorSource:
    executor = capture_executor_source(Path(__file__).resolve().parents[2])
    require_historical_executor(repository, executor)
    return executor


def build_expected_stage_files(
    repository: Path,
    stage: str,
    *,
    executor: ExecutorSource,
    require_live_hosted_ci: bool = False,
) -> dict[str, bytes]:
    """Compose a new seal with the actual clean executor's source identity."""

    repository = _canonical_repository(repository)
    if _current_stage_executor(repository) != executor:
        raise PublicationError("GA sealing executor differs from the running source")
    expected = _compose_stage_files(
        repository,
        stage,
        executor.identity,
        require_live_hosted_ci=require_live_hosted_ci,
    )
    require_executor_unchanged(executor)
    return expected


def _verify_stage(repository: Path, stage: str) -> dict[str, Any]:
    if stage not in STAGES:
        raise PublicationError(f"unknown GA release stage: {stage}")
    observed = _read_stage_files(repository, stage)
    manifest = _manifest_from_files(stage, observed, _path(repository, STAGE_OUTPUTS[stage]))
    executor_source = manifest["executor_source"]
    try:
        historical = identity_at_commit(repository, executor_source["repositoryCommit"])
    except (OSError, SourceIdentityError, ValueError) as error:
        raise PublicationError("GA sealing executor Git history is unavailable") from error
    validate_source_identity(historical, "historical GA sealing executor")
    if historical != executor_source:
        raise PublicationError("GA sealing executor differs from its historical source")
    expected = _compose_stage_files(repository, stage, executor_source)
    if observed != expected:
        raise PublicationError(f"sealed {stage} stage differs from reopened GA inputs")
    repeated = _read_stage_files(repository, stage)
    if repeated != observed:
        raise PublicationError(f"sealed {stage} stage changed while reopening GA inputs")
    return manifest


def verify_stage(repository: Path, stage: str) -> dict[str, Any]:
    """Purely reopen one stage and every predecessor; never creates evidence."""

    repository = _canonical_repository(repository)
    verifier = _current_stage_executor(repository)
    manifest = _verify_stage(repository, stage)
    require_executor_unchanged(verifier)
    return manifest


def verify_prepackage_authorization(repository: Path) -> dict[str, Any]:
    """Reopen prepackage and return the exact artifact-set binding schema."""

    repository = _canonical_repository(repository)
    artifact_set = _require_artifact_set_adapter(repository)
    manifest_path = _path(repository, PREPACKAGE_OUTPUT) / "manifest.json"
    try:
        before = artifact_set._artifact_record(
            manifest_path,
            artifact_set.MAX_PUBLICATION_DOCUMENT_BYTES,
        )
        verify_stage(repository, "prepackage")
        after = artifact_set._artifact_record(
            manifest_path,
            artifact_set.MAX_PUBLICATION_DOCUMENT_BYTES,
        )
    except (OSError, ValueError, artifact_set.ArtifactSetError) as error:
        raise PublicationError("fixed GA prepackage stage authorization is invalid") from error
    if after != before:
        raise PublicationError("GA prepackage stage manifest changed during authorization")
    return artifact_set._validate_prepackage_binding(
        {
            "manifest": after,
            "manifest_path": _repo_relative(repository, manifest_path),
        },
        repository,
    )


def verify_publication_authorization(repository: Path) -> dict[str, Any]:
    """Reopen the complete publication stage in artifact-set binding form."""

    repository = _canonical_repository(repository)
    artifact_set = _require_artifact_set_adapter(repository)
    prepackage = verify_stage(repository, "prepackage")
    publication = verify_stage(repository, "publication")
    try:
        prepackage_legal = prepackage["bindings"]["legal_source"]
        publication_legal = publication["bindings"]["legal_source"]
    except (KeyError, TypeError) as error:
        raise PublicationError("GA publication stage omits its legal-source binding") from error
    if publication_legal != prepackage_legal:
        raise PublicationError("GA publication and prepackage legal sources differ")
    prepackage_path = _path(repository, PREPACKAGE_OUTPUT) / "manifest.json"
    publication_path = _path(repository, PUBLICATION_OUTPUT) / "manifest.json"
    return {
        "legal_source": publication_legal,
        "prepackage_manifest": artifact_set._artifact_record(
            prepackage_path,
            artifact_set.MAX_PUBLICATION_DOCUMENT_BYTES,
        ),
        "prepackage_manifest_path": _repo_relative(repository, prepackage_path),
        "publication_manifest": artifact_set._artifact_record(
            publication_path,
            artifact_set.MAX_PUBLICATION_DOCUMENT_BYTES,
        ),
        "publication_manifest_path": _repo_relative(repository, publication_path),
    }


def derive_runtime_expectation(repository: Path) -> dict[str, Any]:
    """Derive the fixed runtime inputs without reading runtime-produced evidence."""

    repository = _canonical_repository(repository)
    prepackage = verify_stage(repository, "prepackage")
    packages = _verified_package_sets(repository, prepackage)
    migration = _verified_migration_journals(repository)
    _require_migration_matches_prepackage(prepackage, migration)
    return {
        "checks": tuple(sorted(GA_RUNTIME_CHECKS)),
        "document": RUNTIME_ACCEPTANCE_DOCUMENT,
        "dmg_gatekeeper_sha256": packages["dmg"]["gatekeeper_sha256"],
        "dmg_set_seal_sha256": packages["dmg"]["seal"]["sha256"],
        "dmg_sha256": packages["dmg"]["dmg_sha256"],
        "from_build": "40041",
        "ga_environment_sha256": migration["environment"]["sha256"],
        "install_journal_sha256": migration["install_journal"]["record"]["sha256"],
        "product_version": PRODUCT_VERSION,
        "service_journal_tree_sha256": migration["service_journal"]["record"]["sha256"],
        "to_build": GA_BUILD,
    }


def self_check(repository: Path) -> None:
    repository = _canonical_source_repository(repository)
    if (
        ACTIVE_RELEASE_IDENTITY.product_version != "0.4.0"
        or ACTIVE_RELEASE_IDENTITY.ga_build != "40043"
        or _path(repository, GA_ROOT)
        != repository / "target/candidates/0.4.0/ga/40043"
        or STAGES != ("prepackage", "ga-acceptance", "publication")
        or STAGE_SCHEMA_VERSIONS
        != {"prepackage": 2, "ga-acceptance": 3, "publication": 3}
        or ACCEPTANCE_INPUT_ROOT.parent != STAGE_INPUT_ROOT
        or MIGRATION_JOURNAL_INPUT.parent != ACCEPTANCE_INPUT_ROOT
        or INSTALL_JOURNAL_INPUT.parent != MIGRATION_JOURNAL_INPUT
        or SERVICE_JOURNAL_INPUT.parent != MIGRATION_JOURNAL_INPUT
        or SERVICE_ENVIRONMENT_INPUT.parent != SERVICE_JOURNAL_INPUT
        or any(
            _path(repository, output).is_relative_to(_path(repository, ASSURANCE_ROOT))
            for output in STAGE_OUTPUTS.values()
        )
    ):
        raise PublicationError("three-stage GA publication contract is inconsistent")
    required_text = " ".join(
        str(path)
        for path in (
            HOSTED_CI_INPUT,
            LOCAL_CI_INPUT,
            PUBLICATION_INPUT_ROOT,
            ACCEPTANCE_INPUT_ROOT,
            DMG_SET,
            UPDATER_SET,
        )
    )
    if any(name in required_text for name in ("physical", "performance", "99-report")):
        raise PublicationError("assurance-only evidence leaked into the GA-required graph")
