"""Pre-nonce GA-candidate identity capture.

One fixed verifier execution produces five distinct, context-bound observation
artifacts before nonce issuance.  The lifecycle module later reopens those
exact bytes through its one 32-probe post-nonce materialization path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Final

from scripts.harness import lifecycle_matrix
from scripts.harness.lifecycle_matrix import (
    IDENTITY_GA_BUILD,
    IDENTITY_FIXED_COMMAND,
    IDENTITY_FIXED_COMMAND_SHA256,
    IDENTITY_OBSERVATION_DOCUMENT,
    IDENTITY_OBSERVATION_SCHEMA_VERSION,
    IDENTITY_OBSERVATION_MAXIMUM_BYTES,
    IDENTITY_PROBE_IDS,
    IDENTITY_VERIFIER_OUTPUT_LIMIT,
    IDENTITY_VERIFIER_ROLE,
    LifecycleMatrixError,
    PROBE_SPECS,
    parse_lifecycle_environment,
    validate_identity_observation,
)
from scripts.harness.physical_collector_request import (
    GA_RELEASE_BUILD,
    PRODUCT_VERSION,
    PhysicalCollectorRequestError,
    validate_context,
)
from scripts.harness.physical_machine_identity import PhysicalMachineIdentityError
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    load_json_bytes,
)
from scripts.hash_artifact import build_manifest
from scripts.physical_capture.archive import (
    ArchivedFile,
    PhysicalCaptureArchiveError,
    SecureArchive,
)
from scripts.physical_capture.execution import (
    CommandResult,
    CommandSpec,
    ProbeExecutionError,
    command_sha256,
)
from scripts.physical_capture.observation import (
    ObservationCapture,
    PhysicalObservationError,
)
from scripts.physical_capture.session import (
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)


GA_VERSION: Final = PRODUCT_VERSION
GA_BUILD: Final = GA_RELEASE_BUILD
VERIFIER_RELATIVE: Final = Path(IDENTITY_FIXED_COMMAND[0])
FINAL_APP_RELATIVE: Final = Path(IDENTITY_FIXED_COMMAND[1])
FINAL_NATIVE_PRODUCTS_RELATIVE: Final = Path(IDENTITY_FIXED_COMMAND[2])
VERIFIER_TIMEOUT_SECONDS: Final = 600.0
OBSERVATION_DIRECTORY: Final = "raw/lifecycle/observations"

_PROOF_CANDIDATE_FIELDS: Final = (
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "artifact_hash_manifest_sha256",
)
_ENVIRONMENT_CONTEXT_FIELDS: Final = (
    "machine_sha256",
    "machine_identity_scheme",
    "hardware_model",
    "virtualization_present",
    "boot_environment_sha256",
    "boot_environment_scheme",
    "macos_build",
)


class IdentityProbeError(RuntimeError):
    """Identity observations or events could not be proven and retained."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class IdentityObservationArtifact:
    probe_id: str
    archived: ArchivedFile

    def descriptor(self) -> dict[str, object]:
        return self.archived.descriptor("lifecycle-observation")


@dataclass(frozen=True, slots=True)
class IdentityObservationBatch:
    batch_sha256: str
    candidate_tree_sha256: str
    started_at: str
    finished_at: str
    artifacts: tuple[IdentityObservationArtifact, ...]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            f"{artifact.probe_id}:observation": artifact.descriptor()
            for artifact in self.artifacts
        }


def _validate_source_contract() -> None:
    identity_specs = {
        probe_id for probe_id, spec in PROBE_SPECS.items() if spec[0] == "identity"
    }
    if (
        identity_specs != set(IDENTITY_PROBE_IDS)
        or GA_VERSION != lifecycle_matrix.PRODUCT_VERSION
        or GA_BUILD != IDENTITY_GA_BUILD
        or command_sha256(IDENTITY_FIXED_COMMAND) != IDENTITY_FIXED_COMMAND_SHA256
    ):
        raise IdentityProbeError(
            "identity_source_contract_drift",
            "identity adapter and lifecycle source contracts disagree",
        )
    for probe_id in IDENTITY_PROBE_IDS:
        if PROBE_SPECS[probe_id] != ("identity", 0, "identity-verified", {}):
            raise IdentityProbeError(
                "identity_source_contract_drift",
                f"identity lifecycle contract drifted for {probe_id}",
            )


def _fixed_command(repository: Path) -> tuple[CommandSpec, Path]:
    app = repository / FINAL_APP_RELATIVE
    return (
        CommandSpec(
            role=IDENTITY_VERIFIER_ROLE,
            argv=(
                str(repository / VERIFIER_RELATIVE),
                str(app),
                str(repository / FINAL_NATIVE_PRODUCTS_RELATIVE),
            ),
            cwd=repository,
            timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
            accepted_exit_codes=frozenset({0}),
            stdout_limit=IDENTITY_VERIFIER_OUTPUT_LIMIT,
            stderr_limit=IDENTITY_VERIFIER_OUTPUT_LIMIT,
        ),
        app,
    )


def _candidate_tree_sha256(app: Path) -> str:
    try:
        manifest = build_manifest(app, algorithm="sha256-tree-v2")
        digest = manifest["sha256"]
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise IdentityProbeError(
            "candidate_tree_unreadable",
            "cannot securely hash the fixed final-candidate application tree",
        ) from error
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise IdentityProbeError(
            "candidate_tree_unreadable",
            "final-candidate tree hash is not a canonical SHA-256",
        )
    return digest


def _parse_utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IdentityProbeError("identity_time_invalid", f"{label} is not UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise IdentityProbeError(
            "identity_time_invalid", f"{label} is not ISO-8601"
        ) from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise IdentityProbeError("identity_time_invalid", f"{label} is not UTC")
    return parsed


def _capture_inputs(
    context: object, environment: object
) -> tuple[dict[str, Any], str, dict[str, Any], datetime]:
    try:
        validated_context = validate_context(context)
        parsed_environment = parse_lifecycle_environment(
            environment, "identity capture.environment"
        )
    except (
        OSError,
        LifecycleMatrixError,
        PhysicalCollectorRequestError,
        PhysicalMachineIdentityError,
        RawArtifactError,
    ) as error:
        raise IdentityProbeError(
            "identity_context_invalid",
            "identity capture context/environment failed strict revalidation",
        ) from error
    candidate = validated_context["candidate"]
    if (
        candidate["version"] != GA_VERSION
        or candidate["build_number"] != GA_BUILD
    ):
        raise IdentityProbeError(
            "not_final_candidate",
            f"identity capture requires {GA_VERSION} build {GA_BUILD}",
        )
    run = validated_context["run"]
    for field in _ENVIRONMENT_CONTEXT_FIELDS:
        if parsed_environment[field] != run[field]:
            raise IdentityProbeError(
                "identity_environment_drift",
                f"identity lifecycle environment differs from run context at {field}",
            )
    initialized_at = _parse_utc(
        validated_context["initialized_at"], "identity context.initialized_at"
    )
    return copy.deepcopy(candidate), run["run_id"], parsed_environment, initialized_at


def _decode_result_output(value: bytes, label: str) -> str:
    if not isinstance(value, bytes) or len(value) > IDENTITY_VERIFIER_OUTPUT_LIMIT:
        raise IdentityProbeError(
            "identity_verifier_output_invalid", f"identity verifier {label} is unbounded"
        )
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IdentityProbeError(
            "identity_verifier_output_invalid",
            f"identity verifier {label} is not UTF-8",
        ) from error
    if "\x00" in text:
        raise IdentityProbeError(
            "identity_verifier_output_invalid",
            f"identity verifier {label} contains a NUL byte",
        )
    return text


def _validated_result(
    result: CommandResult, command: CommandSpec
) -> tuple[str, str]:
    if (
        result.role != command.role
        or result.argv_sha256 != command_sha256(command.argv)
        or type(result.exit_code) is not int
        or result.exit_code != 0
    ):
        raise IdentityProbeError(
            "identity_verifier_result_drift",
            "identity verifier result differs from the fixed execution contract",
        )
    return (
        _decode_result_output(result.stdout, "stdout"),
        _decode_result_output(result.stderr, "stderr"),
    )


def _logical_command(
    result: CommandResult, stdout: str, stderr: str
) -> dict[str, Any]:
    return {
        "role": IDENTITY_VERIFIER_ROLE,
        "command": list(IDENTITY_FIXED_COMMAND),
        "command_sha256": IDENTITY_FIXED_COMMAND_SHA256,
        "exit_code": 0,
        "duration_ms": result.duration_ms,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stdout": stdout,
        "stderr": stderr,
    }


def _observation_relative(probe_id: str) -> str:
    if probe_id not in IDENTITY_PROBE_IDS:
        raise IdentityProbeError(
            "identity_probe_invalid", "identity observation probe is not source-pinned"
        )
    return f"{OBSERVATION_DIRECTORY}/{probe_id}.json"


def _archive_root(archive: SecureArchive) -> Path:
    return (
        archive.repository / "target" / archive.root_relative_to_target
    ).absolute()


def _publish_observation(
    capture: ObservationCapture,
    archive: SecureArchive,
    *,
    probe_id: str,
    document: dict[str, Any],
    candidate: dict[str, Any],
    run_id: str,
    environment: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> IdentityObservationArtifact:
    try:
        validate_identity_observation(
            document,
            probe_id=probe_id,
            candidate={key: candidate[key] for key in _PROOF_CANDIDATE_FIELDS},
            run_id=run_id,
            environment=environment,
            started_at=started_at,
            finished_at=finished_at,
        )
    except LifecycleMatrixError as error:
        raise IdentityProbeError(
            "identity_observation_invalid",
            f"generated identity observation is invalid for {probe_id}",
        ) from error
    data = canonical_json(document) + b"\n"
    if len(data) > IDENTITY_OBSERVATION_MAXIMUM_BYTES:
        raise IdentityProbeError(
            "identity_observation_too_large",
            "identity observation exceeds the lifecycle-observation byte contract",
        )
    relative = _observation_relative(probe_id)
    try:
        observation = capture.write_bytes(
            subject=f"{probe_id}:observation",
            kind="lifecycle-observation",
            relative=relative,
            data=data,
            maximum=IDENTITY_OBSERVATION_MAXIMUM_BYTES,
        )
        archived = archive.describe_file(
            relative, maximum=IDENTITY_OBSERVATION_MAXIMUM_BYTES
        )
        if observation.descriptor.as_dict() != archived.descriptor("lifecycle-observation"):
            raise IdentityProbeError(
                "identity_observation_drift",
                f"captured identity observation descriptor drifted for {probe_id}",
            )
    except (
        PhysicalCaptureArchiveError,
        PhysicalCaptureSessionError,
        PhysicalObservationError,
    ) as error:
        raise IdentityProbeError(
            "identity_observation_archive_failed",
            f"cannot exclusively archive identity observation {probe_id}",
        ) from error
    descriptor = archived.descriptor("lifecycle-observation")
    try:
        with ArtifactReader(_archive_root(archive)) as reader:
            reopened_descriptor, reopened = reader.read(
                descriptor,
                expected_kinds={"lifecycle-observation"},
                label=f"identity observation {probe_id}",
            )
            if reopened_descriptor.as_dict() != descriptor or reopened != data:
                raise IdentityProbeError(
                    "identity_observation_drift",
                    f"reopened identity observation differs for {probe_id}",
                )
            value = load_json_bytes(reopened, f"identity observation {probe_id}")
            validate_identity_observation(
                value,
                probe_id=probe_id,
                candidate={key: candidate[key] for key in _PROOF_CANDIDATE_FIELDS},
                run_id=run_id,
                environment=environment,
                started_at=started_at,
                finished_at=finished_at,
            )
            reader.verify_all_unchanged(final_path=relative)
    except RawArtifactError as error:
        raise IdentityProbeError(
            "identity_observation_drift",
            f"cannot securely reopen identity observation {probe_id}",
        ) from error
    return IdentityObservationArtifact(probe_id=probe_id, archived=archived)


def capture_identity_observation(
    *,
    session: PhysicalCaptureSession,
    context: object,
    environment: object,
) -> IdentityObservationBatch:
    """Run the fixed verifier once and retain five pre-nonce observations."""

    if not isinstance(session, PhysicalCaptureSession):
        raise IdentityProbeError(
            "invalid_session",
            "identity capture requires a locked PhysicalCaptureSession",
        )
    try:
        capture = session.observation_capture()
    except PhysicalCaptureSessionError as error:
        raise IdentityProbeError(
            "identity_collection_closed",
            "identity verifier may run only while pre-nonce collection is open",
        ) from error
    archive = session.archive
    _validate_source_contract()
    candidate, run_id, parsed_environment, initialized_at = _capture_inputs(
        context, environment
    )
    command, app = _fixed_command(archive.repository)
    before = _candidate_tree_sha256(app)
    if before != candidate["signed_app_tree_sha256"]:
        raise IdentityProbeError(
            "identity_candidate_binding_mismatch",
            "run context candidate tree differs from the fixed final app",
        )
    try:
        result = capture.run_command(command)
    except (PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise IdentityProbeError(
            "identity_verifier_failed", "fixed release identity verifier failed"
        ) from error
    stdout, stderr = _validated_result(result, command)
    after = _candidate_tree_sha256(app)
    if after != before:
        raise IdentityProbeError(
            "candidate_tree_drift",
            "fixed final-candidate tree changed while identity verifier ran",
        )
    started_at = result.started_at
    finished_at = result.completed_at
    if not initialized_at <= _parse_utc(started_at, "identity started_at"):
        raise IdentityProbeError(
            "identity_time_invalid", "identity verifier predates its run context"
        )
    logical_command = _logical_command(result, stdout, stderr)
    batch_material = {
        "schema_version": IDENTITY_OBSERVATION_SCHEMA_VERSION,
        "document": IDENTITY_OBSERVATION_DOCUMENT,
        "candidate": copy.deepcopy(candidate),
        "run_id": run_id,
        "environment": copy.deepcopy(parsed_environment),
        "command": logical_command,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    batch_sha256 = hashlib.sha256(canonical_json(batch_material)).hexdigest()
    documents = {
        probe_id: {
            **copy.deepcopy(batch_material),
            "batch_sha256": batch_sha256,
            "probe_id": probe_id,
        }
        for probe_id in IDENTITY_PROBE_IDS
    }
    proof_candidate = {key: candidate[key] for key in _PROOF_CANDIDATE_FIELDS}
    try:
        for probe_id, document in documents.items():
            validate_identity_observation(
                document,
                probe_id=probe_id,
                candidate=proof_candidate,
                run_id=run_id,
                environment=parsed_environment,
                started_at=started_at,
                finished_at=finished_at,
            )
    except LifecycleMatrixError as error:
        raise IdentityProbeError(
            "identity_observation_invalid",
            "fixed verifier output cannot form identity observations",
        ) from error

    artifacts = tuple(
        _publish_observation(
            capture,
            archive,
            probe_id=probe_id,
            document=documents[probe_id],
            candidate=candidate,
            run_id=run_id,
            environment=parsed_environment,
            started_at=started_at,
            finished_at=finished_at,
        )
        for probe_id in IDENTITY_PROBE_IDS
    )
    paths = {artifact.archived.relative_path for artifact in artifacts}
    digests = {artifact.archived.sha256 for artifact in artifacts}
    if len(paths) != len(IDENTITY_PROBE_IDS) or len(digests) != len(IDENTITY_PROBE_IDS):
        raise IdentityProbeError(
            "identity_observation_reuse",
            "identity observations reuse a path or byte digest",
        )
    try:
        with ArtifactReader(_archive_root(archive)) as reader:
            for artifact in artifacts:
                reader.read(
                    artifact.descriptor(),
                    expected_kinds={"lifecycle-observation"},
                    label=f"identity batch {artifact.probe_id}",
                )
            reader.verify_all_unchanged()
    except RawArtifactError as error:
        raise IdentityProbeError(
            "identity_observation_drift",
            "identity observation batch drifted before capture completed",
        ) from error
    try:
        session.require_collection_open()
    except PhysicalCaptureSessionError as error:
        raise IdentityProbeError(
            "identity_collection_closed",
            "identity collection closed before its observation batch completed",
        ) from error
    return IdentityObservationBatch(
        batch_sha256=batch_sha256,
        candidate_tree_sha256=before,
        started_at=started_at,
        finished_at=finished_at,
        artifacts=artifacts,
    )


__all__ = [
    "IDENTITY_PROBE_IDS",
    "IdentityObservationArtifact",
    "IdentityObservationBatch",
    "IdentityProbeError",
    "capture_identity_observation",
]
