"""Production-only v0.4.0 release-evidence composition.

This module is the missing orchestration boundary between the existing strict
validators.  It has no fixture mode, caller-selected build numbers, optional
evidence, or success override.  The fixed 40020 validation candidate must be
approved before the fixed 40021 final candidate, and every request field is
derived by reopening canonical release artifacts.

The workflow is intentionally layered. ``prepare_physical_candidate_manifest``
freezes the exact signed/notarized physical-runtime candidate before collection.
It is deliberately not the later distribution seal: DMG, updater signature, and
remote assets are created only after this evidence gate and are bound by the
separate final distribution artifact-set transaction. ``seal_production_evidence``
requires the independently signed physical aggregate to bind this exact digest,
then atomically writes every intermediate request and the sealed outer manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any

from .common import (
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
    write_new,
)
from .final_candidate import (
    REQUIRED_NESTED_CODE,
    TEAM_ID,
    build_final_candidate_binding,
    validate_final_candidate_binding,
)
from .release_contract import RELEASE_VERSION
from .sealed_closure import (
    build_sealed_closure,
    derive_supply_chain,
    validate_sealed_closure,
)
from .sealed_manifest import (
    build_sealed_evidence_manifest,
    validate_ci_lane_document,
    validate_sealed_evidence_manifest,
    validate_source_gate_document,
)
from .verify import verify_evidence as verify_publication_evidence
from scripts.candidate_artifact_binding import (
    validate_candidate_app_manifest,
    validate_ci_toolchain_evidence,
)
from scripts.gatekeeper_assessment import (
    GatekeeperEvidenceError,
    validate_evidence as validate_gatekeeper_evidence,
)
from scripts.hash_artifact import build_manifest
from scripts.harness.physical_evidence_aggregator import (
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
from scripts.notarization_transaction import (
    PublishedTransactionEvidence,
    TransactionContext,
    TransactionError,
    validate_published_transaction_receipt,
)
from scripts.release_build_identity import bundle_build_identity
from scripts.release_capability_inventory import (
    CAPABILITY_IDS,
    expected_capability_levels,
    expected_report_contracts,
    validate_inventory,
)
from scripts.repository_source_identity import SourceIdentityError, current_identity
from scripts.validated_candidate_evidence import (
    ValidatedCandidateError,
    validate_candidate_review,
)
from scripts.verify_notary_log import NotaryLogError, validate_files as validate_notary_files


PRODUCT_VERSION = RELEASE_VERSION
VALIDATION_BUILD = "40020"
FINAL_BUILD = "40021"

CANDIDATE_ROOT = Path("target/candidates/0.4.0")
FINAL_NATIVE_PRODUCTS = CANDIDATE_ROOT / "release-build" / FINAL_BUILD / "native-products"
SIGNED_ROOT = CANDIDATE_ROOT / "signed"
SIGNED_APP = SIGNED_ROOT / "Clash for Mac.app"
SIGNED_APP_MANIFEST = SIGNED_ROOT / "Clash for Mac.app.manifest.json"
VALIDATED_REVIEW = CANDIDATE_ROOT / "review" / "validated-candidate.json"
PUBLICATION_ROOT = CANDIDATE_ROOT / "release" / "publication"
SOURCE_GATE_INPUT = (
    CANDIDATE_ROOT / "release" / "evidence-inputs" / "p0-source-gates.json"
)
FINAL_CANDIDATE_INPUT = CANDIDATE_ROOT / "release" / "final-candidate"
PHYSICAL_CANDIDATE_MANIFEST = (
    FINAL_CANDIDATE_INPUT / "physical-candidate-artifact-hash-manifest.json"
)
PHYSICAL_COLLECTOR_CANDIDATE = (
    FINAL_CANDIDATE_INPUT / "physical-collector-candidate.json"
)
PHYSICAL_EVIDENCE_INPUT = FINAL_CANDIDATE_INPUT / "physical-evidence.json"
SEALED_OUTPUT = CANDIDATE_ROOT / "release" / "sealed-manifest"

NOTARY_ARCHIVE_NAME = f"Clash.for.Mac_{PRODUCT_VERSION}_{FINAL_BUILD}_notary.zip"
NOTARY_ARCHIVE = SIGNED_ROOT / NOTARY_ARCHIVE_NAME
NOTARY_RESULT = SIGNED_ROOT / "notarization.json"
NOTARY_LOG = SIGNED_ROOT / "notarization-log.json"
GATEKEEPER_EVIDENCE = SIGNED_ROOT / "gatekeeper.json"
LIBBOX = Path("target/native-dependencies/Libbox.xcframework")
LIBBOX_MANIFEST = Path("target/native-dependencies/Libbox.xcframework.manifest.json")

MAX_COMMAND_OUTPUT = 8 * 1024 * 1024
CODESIGN_FIELD_RE = re.compile(r"^(Identifier|TeamIdentifier|CDHash)=(.+)$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ProductionContext:
    repository: Path
    source_identity: dict[str, str]
    review: dict[str, Any]
    ci_document: dict[str, Any]
    toolchain_metadata: dict[str, str]
    app_manifest: dict[str, Any]
    machine_closure: dict[str, Any]
    publication_inventory: dict[str, Any]
    notary_log: dict[str, Any]
    gatekeeper: dict[str, Any]
    libbox_manifest: dict[str, Any]
    transaction: PublishedTransactionEvidence


def _path(repository: Path, relative: Path) -> Path:
    return repository.joinpath(*relative.parts)


def _repo_relative(repository: Path, path: Path) -> str:
    try:
        relative = path.relative_to(repository)
    except ValueError as error:
        raise PublicationError(
            f"release evidence path is outside the repository: {path}"
        ) from error
    return safe_relative(relative.as_posix(), "release evidence path").as_posix()


def _load_strict_json(path: Path, *, canonical: bool = False) -> Any:
    data = read_regular(path)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PublicationError(f"JSON evidence repeats the field {key!r}: {path}")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"JSON evidence is invalid: {path}") from error
    if canonical and canonical_json(value) != data:
        raise PublicationError(f"JSON evidence is not canonical: {path}")
    return value


def _run_checked(
    command: list[str],
    repository: Path,
    label: str,
    *,
    timeout: float = 900,
    output_limit: int = MAX_COMMAND_OUTPUT,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": str(Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        process = subprocess.Popen(
            command,
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise PublicationError(f"{label} could not start") from error
    if process.stdout is None or process.stderr is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise PublicationError(f"{label} output pipes are unavailable")

    selector = selectors.DefaultSelector()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublicationError(f"{label} exceeded its time limit")
            for key, _events in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.fd].extend(chunk)
                if sum(len(buffer) for buffer in buffers.values()) > output_limit:
                    raise PublicationError(f"{label} output exceeds its fixed bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicationError(f"{label} exceeded its time limit")
        returncode = process.wait(timeout=remaining)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            os.killpg(process.pid, signal.SIGKILL)
            raise PublicationError(f"{label} left a descendant process running")
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise PublicationError(f"{label} exceeded its time limit") from error
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    completed = subprocess.CompletedProcess(
        command,
        returncode,
        bytes(buffers[stdout_fd]),
        bytes(buffers[stderr_fd]),
    )
    if completed.returncode != 0:
        raise PublicationError(f"{label} failed with exit code {completed.returncode}")
    return completed


def _validate_release_application(repository: Path) -> None:
    _run_checked(
        [
            "/bin/bash",
            str(repository / "scripts/verify_release_app.sh"),
            str(_path(repository, SIGNED_APP)),
            str(_path(repository, FINAL_NATIVE_PRODUCTS)),
        ],
        repository,
        "final release application verification",
    )


def _production_context(repository: Path) -> ProductionContext:
    repository = repository.resolve(strict=True)
    try:
        source_identity = current_identity(repository, require_clean=True)
        validate_inventory(repository)
        review = validate_candidate_review(
            repository,
            _path(repository, VALIDATED_REVIEW),
            FINAL_BUILD,
            expected_source_identity=source_identity,
        )
    except (OSError, SourceIdentityError, ValidatedCandidateError, ValueError) as error:
        raise PublicationError(
            f"validated {VALIDATION_BUILD} candidate is unavailable: {error}"
        ) from error
    if review["product"] != {"version": PRODUCT_VERSION, "build_number": VALIDATION_BUILD}:
        raise PublicationError(
            f"validated candidate is not exactly build {VALIDATION_BUILD}"
        )

    candidate = review["candidate"]
    ci_path = repository.joinpath(*safe_relative(candidate["ci_evidence_path"]).parts)
    toolchain_path = repository.joinpath(
        *safe_relative(candidate["toolchain_binding_path"]).parts
    )
    try:
        toolchain_metadata = validate_ci_toolchain_evidence(
            ci_path,
            toolchain_path,
            source_identity["repositoryCommit"],
            source_identity["releaseSourceSha256"],
        )
    except (OSError, ValueError) as error:
        raise PublicationError(
            f"validated {VALIDATION_BUILD} CI/toolchain evidence failed: {error}"
        ) from error
    ci_document = _load_strict_json(ci_path, canonical=True)

    app = _path(repository, SIGNED_APP)
    app_manifest_path = _path(repository, SIGNED_APP_MANIFEST)
    try:
        app_manifest = validate_candidate_app_manifest(
            app_manifest_path,
            app,
            artifact_kind="notarized-release-v1",
            build_number=FINAL_BUILD,
            source_identity=source_identity,
            toolchain_metadata=toolchain_metadata,
            team_id=TEAM_ID,
        )
    except (OSError, ValueError) as error:
        raise PublicationError(f"final {FINAL_BUILD} app manifest failed: {error}") from error
    identity = bundle_build_identity(app)
    if identity.product_version != PRODUCT_VERSION or identity.build_version != FINAL_BUILD:
        raise PublicationError(
            f"final signed application is not exactly {PRODUCT_VERSION} build {FINAL_BUILD}"
        )
    _validate_release_application(repository)

    publication_root = _path(repository, PUBLICATION_ROOT)
    try:
        verify_publication_evidence(publication_root, app, False)
    except (OSError, PublicationError, ValueError) as error:
        raise PublicationError(f"final publication closure is invalid: {error}") from error
    machine = _load_strict_json(publication_root / "machine-closure.json", canonical=True)
    inventory = _load_strict_json(publication_root / "inventory.json", canonical=True)
    if machine["product"] != {
        "name": "Clash for Mac",
        "version": PRODUCT_VERSION,
        "build_number": FINAL_BUILD,
    }:
        raise PublicationError(
            f"publication closure is not for final build {FINAL_BUILD}"
        )
    if machine["app"]["sha256"] != app_manifest["sha256"]:
        raise PublicationError("publication closure and final app manifest bind different trees")

    try:
        notary_log = validate_notary_files(
            _path(repository, NOTARY_RESULT),
            _path(repository, NOTARY_LOG),
            _path(repository, NOTARY_ARCHIVE),
        )
    except (OSError, NotaryLogError) as error:
        raise PublicationError(f"final notarization evidence is invalid: {error}") from error
    gatekeeper_value = _load_strict_json(_path(repository, GATEKEEPER_EVIDENCE), canonical=True)
    try:
        gatekeeper = validate_gatekeeper_evidence(
            gatekeeper_value,
            expected_assessment_type="execute",
            expected_primary_signature_context=False,
        )
    except GatekeeperEvidenceError as error:
        raise PublicationError(f"final Gatekeeper evidence is invalid: {error}") from error
    if gatekeeper["target_signed_app_tree_sha256"] != app_manifest["sha256"]:
        raise PublicationError("Gatekeeper evidence targets a different final app tree")

    transaction_context = TransactionContext(
        repository=repository,
        build_kind="release",
        build_number=FINAL_BUILD,
        staged_app=None,
        native_products=_path(repository, FINAL_NATIVE_PRODUCTS),
        notary_profile="clashformac-notary",
        repository_commit=source_identity["repositoryCommit"],
        release_source_sha256=source_identity["releaseSourceSha256"],
        deployment_target="15.0",
        toolchain_metadata=toolchain_metadata,
    )
    try:
        transaction = validate_published_transaction_receipt(transaction_context)
    except (OSError, TransactionError, ValueError) as error:
        raise PublicationError(
            f"final notarization transaction receipt is invalid: {error}"
        ) from error
    receipt = transaction.receipt
    expected_receipt_bindings = {
        "submission_id": notary_log["jobId"],
        "archive_sha256": sha256_file(_path(repository, NOTARY_ARCHIVE)),
        "accepted_notary_log_sha256": sha256_file(_path(repository, NOTARY_LOG)),
        "notarization_result_sha256": sha256_file(_path(repository, NOTARY_RESULT)),
        "gatekeeper_evidence_sha256": sha256_file(
            _path(repository, GATEKEEPER_EVIDENCE)
        ),
        "app_manifest_sha256": sha256_file(_path(repository, SIGNED_APP_MANIFEST)),
        "post_staple_app_tree_sha256": app_manifest["sha256"],
    }
    if any(receipt.get(key) != value for key, value in expected_receipt_bindings.items()):
        raise PublicationError(
            "notarization transaction receipt does not bind the reopened final artifacts"
        )

    libbox_manifest = _load_strict_json(_path(repository, LIBBOX_MANIFEST))
    context = ProductionContext(
        repository=repository,
        source_identity=source_identity,
        review=review,
        ci_document=ci_document,
        toolchain_metadata=toolchain_metadata,
        app_manifest=app_manifest,
        machine_closure=machine,
        publication_inventory=inventory,
        notary_log=notary_log,
        gatekeeper=gatekeeper,
        libbox_manifest=libbox_manifest,
        transaction=transaction,
    )
    _verified_libbox_tree(context)
    return context


def _verified_libbox_tree(context: ProductionContext) -> str:
    manifest = context.libbox_manifest
    algorithm = manifest.get("algorithm")
    if algorithm not in {"sha256-tree-v1", "sha256-tree-v2"}:
        raise PublicationError("libbox XCFramework manifest algorithm is unsupported")
    try:
        actual = build_manifest(
            _path(context.repository, LIBBOX),
            algorithm=algorithm,
        )
    except (OSError, ValueError) as error:
        raise PublicationError("libbox XCFramework tree cannot be rehashed") from error
    compared = {"root", "sha256", "entries"}
    if algorithm == "sha256-tree-v2":
        compared.add("rootMode")
    if any(manifest.get(key) != actual.get(key) for key in compared):
        raise PublicationError(
            "libbox XCFramework differs from its physical-candidate manifest"
        )
    return require_sha256(actual.get("sha256"), "libbox XCFramework tree digest")


def _physical_candidate_hash_manifest(context: ProductionContext) -> dict[str, Any]:
    repository = context.repository
    publication = _path(repository, PUBLICATION_ROOT)
    attempt_root = (
        CANDIDATE_ROOT / "notary-attempts" / "release" / FINAL_BUILD
    )
    receipt_sha256 = sha256_file(context.transaction.receipt_path)
    if receipt_sha256 != sha256_bytes(canonical_json(context.transaction.receipt)):
        raise PublicationError(
            "notarization transaction receipt changed after read-only validation"
        )
    libbox_tree_sha256 = _verified_libbox_tree(context)
    entries = [
        {"path": "artifacts/final-app-tree", "sha256": context.app_manifest["sha256"]},
        {
            "path": "artifacts/final-app-manifest",
            "sha256": sha256_file(_path(repository, SIGNED_APP_MANIFEST)),
        },
        {
            "path": "artifacts/libbox-xcframework-tree",
            "sha256": libbox_tree_sha256,
        },
        {
            "path": "artifacts/libbox-xcframework-manifest",
            "sha256": sha256_file(_path(repository, LIBBOX_MANIFEST)),
        },
        {
            "path": "artifacts/notarization-archive",
            "sha256": sha256_file(_path(repository, NOTARY_ARCHIVE)),
        },
        {
            "path": "artifacts/notarization-result",
            "sha256": sha256_file(_path(repository, NOTARY_RESULT)),
        },
        {
            "path": "artifacts/notarization-log",
            "sha256": sha256_file(_path(repository, NOTARY_LOG)),
        },
        {
            "path": "artifacts/notarization-transaction-intent",
            "sha256": sha256_file(_path(repository, attempt_root / "intent.json")),
        },
        {
            "path": "artifacts/notarization-transaction-events",
            "sha256": require_sha256(
                build_manifest(
                    _path(repository, attempt_root / "events"),
                    algorithm="sha256-tree-v2",
                ).get("sha256"),
                "notarization transaction event tree",
            ),
        },
        {
            "path": "artifacts/notarization-transaction-receipt",
            "sha256": receipt_sha256,
        },
        {
            "path": "artifacts/gatekeeper-evidence",
            "sha256": sha256_file(_path(repository, GATEKEEPER_EVIDENCE)),
        },
        {
            "path": "artifacts/publication-machine-closure",
            "sha256": sha256_file(publication / "machine-closure.json"),
        },
        {
            "path": "artifacts/publication-inventory",
            "sha256": sha256_file(publication / "inventory.json"),
        },
        {
            "path": "artifacts/publication-evidence-manifest",
            "sha256": sha256_file(publication / "evidence-manifest.json"),
        },
        {
            "path": "artifacts/sbom-spdx",
            "sha256": sha256_file(publication / "sbom.spdx.json"),
        },
        {
            "path": "artifacts/sbom-cyclonedx",
            "sha256": sha256_file(publication / "sbom.cyclonedx.json"),
        },
    ]
    entries.sort(key=lambda entry: entry["path"])
    return {"entries": entries, "sha256": tree_digest(entries)}


def _physical_collector_candidate(
    context: ProductionContext, manifest: dict[str, Any]
) -> dict[str, str]:
    """Derive the sole candidate projection accepted by collector requests."""

    return {
        "version": PRODUCT_VERSION,
        "build_number": FINAL_BUILD,
        "app_manifest_sha256": sha256_file(
            _path(context.repository, SIGNED_APP_MANIFEST)
        ),
        "signed_app_tree_sha256": context.app_manifest["sha256"],
        "artifact_hash_manifest_sha256": require_sha256(
            manifest.get("sha256"), "physical candidate artifact-hash manifest"
        ),
        "built_at": context.transaction.prepared_at,
    }


def _require_real_directory(path: Path, *, create: bool = False) -> None:
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise PublicationError(f"release evidence directory is not real: {path}")


def prepare_physical_candidate_manifest(repository: Path) -> dict[str, Any]:
    """Freeze the signed/notarized runtime candidate physical collection may bind."""
    context = _production_context(repository)
    manifest = _physical_candidate_hash_manifest(context)
    collector_candidate = _physical_collector_candidate(context, manifest)
    output = _path(context.repository, PHYSICAL_CANDIDATE_MANIFEST)
    candidate_output = _path(context.repository, PHYSICAL_COLLECTOR_CANDIDATE)
    _require_real_directory(output.parent.parent)
    _require_real_directory(output.parent, create=True)
    if (
        output.exists()
        or output.is_symlink()
        or candidate_output.exists()
        or candidate_output.is_symlink()
    ):
        raise PublicationError(
            "refusing to replace physical candidate preparation outputs"
        )
    try:
        write_new(candidate_output, canonical_json(collector_candidate))
        write_new(output, canonical_json(manifest))
    except BaseException:
        if not output.exists() and not output.is_symlink():
            candidate_output.unlink(missing_ok=True)
        raise
    if _load_strict_json(candidate_output, canonical=True) != collector_candidate:
        raise PublicationError(
            "physical collector candidate changed after publication"
        )
    if _load_strict_json(output, canonical=True) != manifest:
        raise PublicationError(
            "physical candidate artifact-hash manifest changed after publication"
        )
    return manifest


def _parse_codesign_details(output: bytes, label: str) -> dict[str, str]:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PublicationError(f"{label} codesign details are not UTF-8") from error
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = CODESIGN_FIELD_RE.fullmatch(line.strip())
        if match is None:
            continue
        key, value = match.groups()
        if key in fields:
            raise PublicationError(f"{label} codesign details repeat {key}")
        fields[key] = value
    if set(fields) != {"Identifier", "TeamIdentifier", "CDHash"}:
        raise PublicationError(f"{label} codesign details omit identity fields")
    if fields["TeamIdentifier"] != TEAM_ID:
        raise PublicationError(f"{label} codesign Team ID is not {TEAM_ID}")
    if not CDHASH_RE.fullmatch(fields["CDHash"]):
        raise PublicationError(f"{label} Code Directory hash is malformed")
    return fields


def _requirement_digest(output: bytes, label: str) -> str:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise PublicationError(f"{label} designated requirement is not UTF-8") from error
    requirements = [line.strip() for line in lines if line.strip().startswith("designated =>")]
    if len(requirements) != 1:
        raise PublicationError(f"{label} has no unique designated requirement")
    return sha256_bytes((requirements[0] + "\n").encode("utf-8"))


def _nested_code(context: ProductionContext) -> list[dict[str, Any]]:
    repository = context.repository
    app = _path(repository, SIGNED_APP)
    packet_extension = (
        app
        / "Contents/Library/SystemExtensions"
        / "com.bill.clashformac.packet-tunnel.systemextension"
    )
    proxy_agent = app / "Contents/Library/LoginItems/CFWProxyAgent.app"
    targets: dict[str, tuple[str, Path, Path | None]] = {
        "host": (
            "Contents/MacOS/clash-for-mac",
            app,
            app / "Contents/embedded.provisionprofile",
        ),
        "packet-tunnel": (
            "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension",
            packet_extension,
            packet_extension / "Contents/embedded.provisionprofile",
        ),
        "global-authority": (
            "Contents/Library/HelperTools/CFWGlobalAuthority",
            app / "Contents/Library/HelperTools/CFWGlobalAuthority",
            None,
        ),
        "proxy-agent": (
            "Contents/Library/LoginItems/CFWProxyAgent.app",
            proxy_agent,
            proxy_agent / "Contents/embedded.provisionprofile",
        ),
    }
    if set(targets) != set(REQUIRED_NESTED_CODE):
        raise PublicationError("inside-out code capture does not cover every final role")
    libbox_sha256 = context.libbox_manifest["sha256"]
    result: list[dict[str, Any]] = []
    for role in sorted(targets):
        relative, target, profile = targets[role]
        details_result = _run_checked(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(target)],
            repository,
            f"{role} codesign identity capture",
        )
        details = _parse_codesign_details(
            details_result.stdout + details_result.stderr, role
        )
        if details["Identifier"] != REQUIRED_NESTED_CODE[role]:
            raise PublicationError(f"{role} codesign identifier is unexpected")
        requirement_result = _run_checked(
            ["/usr/bin/codesign", "-d", "-r-", str(target)],
            repository,
            f"{role} designated requirement capture",
        )
        entitlements_result = _run_checked(
            ["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(target)],
            repository,
            f"{role} entitlement capture",
        )
        entitlements = entitlements_result.stdout
        if not entitlements:
            raise PublicationError(f"{role} signed entitlements are empty")
        if profile is None:
            provisioning = "not-required"
        else:
            if profile.is_symlink() or not profile.is_file():
                raise PublicationError(f"{role} embedded provisioning profile is unavailable")
            sha256_file(profile)
            provisioning = "embedded-profile"
        result.append(
            {
                "role": role,
                "path": relative,
                "bundle_id": details["Identifier"],
                "team_id": details["TeamIdentifier"],
                "cdhash": details["CDHash"],
                "designated_requirement_sha256": _requirement_digest(
                    requirement_result.stdout + requirement_result.stderr, role
                ),
                "entitlements_sha256": sha256_bytes(entitlements),
                "provisioning": provisioning,
                "libbox_xcframework_sha256": libbox_sha256,
            }
        )
    return result


def _receipt_finalization_evidence(
    context: ProductionContext,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Translate only a fully validated publish-ready receipt into final claims."""
    receipt = context.transaction.receipt
    if (
        receipt.get("state") != "publish-ready"
        or receipt.get("post_staple_app_tree_sha256") != context.app_manifest["sha256"]
        or receipt.get("submission_id") != context.notary_log["jobId"]
        or receipt.get("archive_sha256") != context.notary_log["sha256"]
    ):
        raise PublicationError(
            "validated notarization receipt cannot derive finalization evidence"
        )
    captured_at = receipt["sealed_at"]
    return (
        {
            "status": "Accepted",
            "id": receipt["submission_id"],
            "submission_sha256": receipt["archive_sha256"],
            "target_signed_app_tree_sha256": receipt[
                "post_staple_app_tree_sha256"
            ],
            "captured_at": captured_at,
        },
        {
            # This is a derivation of the validated receipt's publish-ready
            # state and post-staple tree, never an operator assertion.
            "stapled": True,
            "target_signed_app_tree_sha256": receipt[
                "post_staple_app_tree_sha256"
            ],
            "captured_at": captured_at,
        },
    )


def _observe_signed_app_tree(context: ProductionContext) -> dict[str, str]:
    """Perform a fresh race-detecting tree-v2 scan and timestamp its completion."""
    try:
        observed = build_manifest(
            _path(context.repository, SIGNED_APP),
            algorithm="sha256-tree-v2",
        )
    except (OSError, ValueError) as error:
        raise PublicationError("post-verification app tree could not be rehashed") from error
    digest = require_sha256(observed.get("sha256"), "post-verification app tree")
    if digest != context.app_manifest["sha256"]:
        raise PublicationError(
            "post-verification app tree differs from the receipt-bound final candidate"
        )
    observed_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    return {"app_tree_sha256": digest, "observed_at": observed_at}


def _sealed_closure_request(
    context: ProductionContext, artifact_manifest: dict[str, Any]
) -> dict[str, Any]:
    publication = _path(context.repository, PUBLICATION_ROOT)
    licenses = publication / "licenses"
    license_entries = enumerate_tree(licenses)
    if not any(entry["type"] == "file" for entry in license_entries):
        raise PublicationError("reviewed third-party license tree contains no files")
    supply_chain = derive_supply_chain(context.repository)
    ci_sha256 = sha256_file(
        context.repository.joinpath(
            *safe_relative(context.review["candidate"]["ci_evidence_path"]).parts
        )
    )
    return {
        "product": context.machine_closure["product"],
        "commit": context.source_identity["repositoryCommit"],
        "sbom": {
            "components": context.machine_closure["components"],
            "build_tools": context.machine_closure["build_tools"],
            "relationships": context.machine_closure["relationships"],
        },
        "ccs": {
            "sha256": context.machine_closure["corresponding_source"]["sha256"],
            "archive_sha256": context.publication_inventory[
                "corresponding_source_archive_sha256"
            ],
        },
        "modification_notice": {
            "sha256": sha256_file(context.repository / "CHANGELOG.md")
        },
        "third_party_notices": {"sha256": tree_digest(license_entries)},
        "artifact_hash_manifest": artifact_manifest,
        "signed_app": {"sha256": context.app_manifest["sha256"]},
        "xcframework": {"sha256": context.libbox_manifest["sha256"]},
        "vulnerability_reports": [
            {
                "id": "govulncheck-libbox",
                "tool": "govulncheck",
                "tool_version": supply_chain["toolchain_versions"]["govulncheck"],
                "target": "libbox-macos-arm64",
                # The complete canonical CI record is retained and reopened;
                # it transitively binds the libbox-govulncheck command log.
                "sha256": ci_sha256,
            }
        ],
    }


def _raw_report(
    context: ProductionContext,
    report_id: str,
    kind: str,
    path: Path,
    bindings: dict[str, str],
) -> dict[str, Any]:
    return {
        "id": report_id,
        "kind": kind,
        "path": _repo_relative(context.repository, path),
        "sha256": sha256_file(path),
        "status": "passed",
        "bindings": bindings,
    }


def _inner_evidence_manifest(context: ProductionContext) -> dict[str, Any]:
    commit = context.source_identity["repositoryCommit"]
    toolchain = context.ci_document["toolchain_sha256"]
    signed_app = context.app_manifest["sha256"]
    identity = {
        "commit": commit,
        "toolchain_sha256": toolchain,
        "signed_app_sha256": signed_app,
    }
    source_binding = {"commit": commit}
    ci_binding = {"commit": commit, "toolchain_sha256": toolchain}
    signed_binding = {**ci_binding, "signed_app_sha256": signed_app}
    reports: list[dict[str, Any]] = []
    source_kinds = {"source_hash", "boundary_scan"}
    unsigned_kinds = {"unsigned_artifact", "deterministic_test"}
    for contract in expected_report_contracts():
        kind = contract["kind"]
        bindings = (
            source_binding
            if kind in source_kinds
            else ci_binding
            if kind in unsigned_kinds
            else signed_binding
        )
        relative = safe_relative(contract["path"], f"report {contract['id']} path")
        reports.append(
            _raw_report(
                context,
                contract["id"],
                kind,
                context.repository.joinpath(*relative.parts),
                bindings,
            )
        )
    return {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": identity,
        "reports": reports,
        "capabilities": [
            {
                "id": capability,
                "highest_level": "Sealed_Release_Evidence",
                "levels": expected_capability_levels(capability),
            }
            for capability in CAPABILITY_IDS
        ],
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_outputs(repository: Path, documents: dict[str, object]) -> Path:
    destination = _path(repository, SEALED_OUTPUT)
    parent = destination.parent
    _require_real_directory(parent)
    if destination.exists() or destination.is_symlink():
        raise PublicationError(f"refusing to replace sealed production evidence: {destination}")
    staging = Path(tempfile.mkdtemp(prefix=".sealed-manifest.", dir=parent))
    try:
        os.chmod(staging, 0o700)
        for name in sorted(documents):
            if Path(name).name != name:
                raise PublicationError(f"sealed output name is unsafe: {name}")
            write_new(staging / name, canonical_json(documents[name]))
        _fsync_directory(staging)
        staging.rename(destination)
        _fsync_directory(parent)
    except BaseException:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
        raise
    return destination


def _require_physical_candidate_binding(
    context: ProductionContext,
    physical_candidate: dict[str, Any],
    physical_candidate_manifest: dict[str, Any],
) -> None:
    expected = {
        "version": PRODUCT_VERSION,
        "build_number": FINAL_BUILD,
        "signed_app_tree_sha256": context.app_manifest["sha256"],
        "app_manifest_sha256": sha256_file(
            _path(context.repository, SIGNED_APP_MANIFEST)
        ),
        "artifact_hash_manifest_sha256": physical_candidate_manifest["sha256"],
        "built_at": context.transaction.prepared_at,
    }
    if any(physical_candidate[key] != value for key, value in expected.items()):
        raise PublicationError(
            "physical aggregate does not bind the exact receipt-prepared "
            f"{FINAL_BUILD} candidate"
        )


def _validated_final_binding(
    context: ProductionContext,
    request: dict[str, Any],
    trust_policy: CollectorTrustPolicy,
) -> dict[str, Any]:
    binding = build_final_candidate_binding(
        context.repository,
        request,
        fixture=False,
        physical_evidence_root=context.repository,
        physical_trust_policy=trust_policy,
    )
    validate_final_candidate_binding(
        context.repository,
        binding,
        fixture=False,
        physical_evidence_root=context.repository,
        physical_trust_policy=trust_policy,
        require_verified=True,
    )
    return binding


def _validated_outer_manifest(
    context: ProductionContext,
    request: dict[str, Any],
    trust_policy: CollectorTrustPolicy,
) -> dict[str, Any]:
    manifest = build_sealed_evidence_manifest(
        context.repository,
        request,
        fixture=False,
        physical_evidence_root=context.repository,
        physical_trust_policy=trust_policy,
    )
    validate_sealed_evidence_manifest(
        context.repository,
        manifest,
        fixture=False,
        physical_evidence_root=context.repository,
        physical_trust_policy=trust_policy,
        require_sealed=True,
    )
    if not manifest["publication"]["artifacts_permitted"]:
        raise PublicationError("sealed production evidence did not authorize publication")
    return manifest


def _require_final_inputs_unchanged(
    context: ProductionContext,
    expected_physical_candidate_manifest: dict[str, Any],
) -> None:
    try:
        observed_source = current_identity(context.repository, require_clean=True)
    except (OSError, SourceIdentityError) as error:
        raise PublicationError("release source identity cannot be rechecked") from error
    if observed_source != context.source_identity:
        raise PublicationError("release source identity changed during evidence sealing")
    try:
        verify_publication_evidence(
            _path(context.repository, PUBLICATION_ROOT),
            _path(context.repository, SIGNED_APP),
            False,
        )
    except (OSError, PublicationError, ValueError) as error:
        raise PublicationError(
            "publication inputs changed during evidence sealing"
        ) from error
    if _physical_candidate_hash_manifest(context) != expected_physical_candidate_manifest:
        raise PublicationError(
            "physical-candidate inputs changed during evidence sealing"
        )


def seal_production_evidence(repository: Path) -> dict[str, Any]:
    """Compose every production request and seal only complete real evidence."""
    context = _production_context(repository)
    artifact_path = _path(context.repository, PHYSICAL_CANDIDATE_MANIFEST)
    physical_candidate_manifest = _load_strict_json(artifact_path, canonical=True)
    expected_artifact_manifest = _physical_candidate_hash_manifest(context)
    if physical_candidate_manifest != expected_artifact_manifest:
        raise PublicationError(
            "prepared physical candidate manifest drifted from real artifacts"
        )

    source_path = _path(context.repository, SOURCE_GATE_INPUT)
    source_document = _load_strict_json(source_path, canonical=True)
    normalized_source, source_failures = validate_source_gate_document(
        context.repository,
        source_document,
        context.source_identity["repositoryCommit"],
        context.source_identity["releaseSourceSha256"],
    )
    if source_failures:
        raise PublicationError(f"P0 source gates are not all passing: {source_failures}")
    normalized_ci, ci_failures = validate_ci_lane_document(
        context.ci_document,
        context.source_identity["repositoryCommit"],
        context.source_identity["releaseSourceSha256"],
    )
    if ci_failures:
        raise PublicationError(
            f"validated {VALIDATION_BUILD} CI lanes are not all passing: {ci_failures}"
        )

    physical_path = _path(context.repository, PHYSICAL_EVIDENCE_INPUT)
    physical_document = _load_strict_json(physical_path, canonical=True)
    try:
        descriptor = parse_descriptor(
            physical_document,
            expected_kinds={"physical-aggregate"},
            label="production physical aggregate",
        ).as_dict()
        trust_policy = load_release_trust_policy()
        physical_summary = load_physical_evidence_artifact(
            descriptor,
            evidence_root=context.repository,
            trust_policy=trust_policy,
            fixture=False,
        )
    except CollectorTrustNotConfiguredError as error:
        raise PublicationError("production collector trust policy is not configured") from error
    except (OSError, PhysicalEvidenceError, RawArtifactError) as error:
        raise PublicationError(f"production physical aggregate is invalid: {error}") from error
    physical_candidate = require_exact_keys(
        physical_summary["candidate"],
        {
            "version",
            "build_number",
            "signed_app_tree_sha256",
            "app_manifest_sha256",
            "artifact_hash_manifest_sha256",
            "built_at",
        },
        "physical aggregate candidate",
    )
    _require_physical_candidate_binding(
        context,
        physical_candidate,
        physical_candidate_manifest,
    )

    nested_code = _nested_code(context)
    closure_request = _sealed_closure_request(context, physical_candidate_manifest)
    closure = build_sealed_closure(context.repository, closure_request, fixture=False)
    validate_sealed_closure(
        context.repository, closure, fixture=False, require_sealed=True
    )
    inner_manifest = _inner_evidence_manifest(context)
    notarization_evidence, staple_evidence = _receipt_finalization_evidence(context)
    supply_chain = derive_supply_chain(context.repository)
    post_verification = _observe_signed_app_tree(context)
    final_request = {
        "product": {"version": PRODUCT_VERSION, "build_number": FINAL_BUILD},
        "commit": context.source_identity["repositoryCommit"],
        "final_artifacts": {
            "signed_app_tree_sha256": context.app_manifest["sha256"],
            "app_manifest_sha256": sha256_file(_path(context.repository, SIGNED_APP_MANIFEST)),
            "built_at": context.transaction.prepared_at,
            "artifact_hash_manifest": physical_candidate_manifest,
        },
        "xcframework": {
            "path": LIBBOX.as_posix(),
            "xcframework_sha256": context.libbox_manifest["sha256"],
            "manifest_sha256": sha256_file(_path(context.repository, LIBBOX_MANIFEST)),
            "upstream_commit": supply_chain["patched_source"][
                "upstream_commit"
            ],
            "combined_diff_sha256": supply_chain["patched_source"][
                "combined_diff_sha256"
            ],
        },
        "nested_code": nested_code,
        "notarization": notarization_evidence,
        "staple": staple_evidence,
        "gatekeeper": context.gatekeeper,
        "physical_evidence": descriptor,
        "post_verification": post_verification,
    }
    final_binding = _validated_final_binding(context, final_request, trust_policy)

    outer_request = {
        "product": {"version": PRODUCT_VERSION, "build_number": FINAL_BUILD},
        "commit": context.source_identity["repositoryCommit"],
        "evidence_manifest": inner_manifest,
        "p0_source": normalized_source,
        "unsigned_ci": normalized_ci,
        "signed_installed": descriptor,
        "sealed_closure": closure,
        "final_candidate": final_binding,
    }
    _validated_outer_manifest(context, outer_request, trust_policy)

    # The first complete outer pass reopens every bound input. Record a fresh
    # app-tree observation only after that pass, then rebuild both seals so the
    # recorded timestamp and digest are the ones publication actually binds.
    post_verification = _observe_signed_app_tree(context)
    final_request["post_verification"] = post_verification
    final_binding = _validated_final_binding(context, final_request, trust_policy)
    outer_request["final_candidate"] = final_binding
    outer = _validated_outer_manifest(context, outer_request, trust_policy)

    _require_final_inputs_unchanged(context, physical_candidate_manifest)
    final_guard = _observe_signed_app_tree(context)
    if final_guard["app_tree_sha256"] != post_verification["app_tree_sha256"]:
        raise PublicationError("final app tree changed before sealed evidence publication")

    destination = _publish_outputs(
        context.repository,
        {
            "p0-source-gates.json": normalized_source,
            "unsigned-ci-lanes.json": normalized_ci,
            "physical-evidence.json": descriptor,
            "sealed-closure.request.json": closure_request,
            "sealed-closure.json": closure,
            "final-candidate.request.json": final_request,
            "final-candidate.json": final_binding,
            "evidence-manifest.json": inner_manifest,
            "sealed-evidence-manifest.request.json": outer_request,
            "sealed-evidence-manifest.json": outer,
        },
    )
    published = _load_strict_json(
        destination / "sealed-evidence-manifest.json", canonical=True
    )
    validate_sealed_evidence_manifest(
        context.repository,
        published,
        fixture=False,
        physical_evidence_root=context.repository,
        physical_trust_policy=trust_policy,
        require_sealed=True,
    )
    return published


def self_check(repository: Path) -> None:
    if (PRODUCT_VERSION, VALIDATION_BUILD, FINAL_BUILD) != ("0.4.0", "40020", "40021"):
        raise PublicationError("production release build identity drifted")
    if len(CAPABILITY_IDS) != 9:
        raise PublicationError("production release capability inventory is not fixed to nine")
    contracts = expected_report_contracts()
    if len(contracts) != 99 or len({contract["id"] for contract in contracts}) != 99:
        raise PublicationError("production release report policy is not exactly 99 unique reports")
    paths_by_kind = {
        kind: {contract["path"] for contract in contracts if contract["kind"] == kind}
        for kind in {
            "unsigned_artifact",
            "deterministic_test",
            "physical_machine",
            "packet_evidence",
        }
    }
    expected_paths = {
        "unsigned_artifact": {
            f"target/candidates/0.4.0/validation/{VALIDATION_BUILD}/signed/"
            "Clash for Mac.app.manifest.json"
        },
        "deterministic_test": {
            f"target/candidates/0.4.0/validation/{VALIDATION_BUILD}/evidence/"
            "unsigned-ci-lanes.json"
        },
        "physical_machine": {PHYSICAL_EVIDENCE_INPUT.as_posix()},
        "packet_evidence": {PHYSICAL_EVIDENCE_INPUT.as_posix()},
    }
    if paths_by_kind != expected_paths:
        raise PublicationError("production release report paths drifted from the fixed sequence")
    validate_inventory(repository)
