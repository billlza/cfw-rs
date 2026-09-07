"""Two-phase production lifecycle capture and deterministic event materialization.

The pre-nonce phase invokes only the fixed installed lifecycle probe and
the fixed final-candidate identity verifier.  It retains exactly 32 proof-free
probe observations plus the eight special raw artifacts required by the matrix.
After ``RAW_COMPLETED`` and nonce receipt, materialization reopens that frozen
40-subject manifest and emits exactly 32 proof-bound lifecycle events.  No
post-nonce command execution or caller-supplied observation path is supported.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Any, Final, Mapping

from scripts.harness.lifecycle_matrix import (
    EVENT_DOCUMENT,
    EVENT_SCHEMA_VERSION,
    EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS,
    EXPECTED_LIFECYCLE_RAW_SUBJECTS,
    IDENTITY_PROBE_IDS,
    LIFECYCLE_PROBE_EXECUTABLE,
    PROBE_SPECS,
    LifecycleMatrixError,
    lifecycle_probe_command,
    validate_lifecycle_event,
    validate_lifecycle_observation,
)
from scripts.harness.physical_collector_request import (
    PhysicalCollectorRequestError,
    validate_context,
)
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    load_json_bytes,
    parse_descriptor,
    parse_proof_binding,
)

from .archive import ArchivedFile, PhysicalCaptureArchiveError
from .execution import CommandSpec, ProbeExecutionError
from .identity import (
    IdentityProbeError,
    capture_identity_observation,
)
from .observation import (
    ObservationArtifact,
    ObservationCapture,
    PhysicalObservationError,
)
from .session import CaptureState, PhysicalCaptureSession, PhysicalCaptureSessionError


OBSERVATION_DIRECTORY: Final = "raw/lifecycle/observations"
EVENT_DIRECTORY: Final = "raw/lifecycle/events"
PROBE_OUTPUT_ROOT: Final = Path(
    "/Library/Application Support/Clash for Mac/ReleaseVerification/"
    "Lifecycle/Output"
)
MAX_OBSERVATION_BYTES: Final = 1024 * 1024
MAX_PROBE_STDERR_BYTES: Final = 64 * 1024
PROBE_TIMEOUT_SECONDS: Final = 600.0

_CONTEXT_ENVIRONMENT_FIELDS: Final = (
    "machine_sha256",
    "machine_identity_scheme",
    "hardware_model",
    "virtualization_present",
    "boot_environment_sha256",
    "boot_environment_scheme",
    "macos_build",
)

# Each special result is written by the fixed installed helper to one fixed
# root-owned output file.  Its observation must predeclare the exact final
# descriptor path; the collector copies and byte-compares that file before it
# accepts the observation bytes.
_SPECIAL_FILES: Final[dict[str, tuple[tuple[str, str, str], ...]]] = {
    "renderer-ready-v2": (
        ("renderer-ready-v2:trace", "renderer-ready-trace", "renderer-ready-v2-trace.json"),
    ),
    "network-extension-approval": (
        (
            "network-extension-approval:trace",
            "network-extension-trace",
            "network-extension-approval-trace.json",
        ),
    ),
    "network-extension-denial": (
        (
            "network-extension-denial:trace",
            "network-extension-trace",
            "network-extension-denial-trace.json",
        ),
    ),
    "network-extension-pending": (
        (
            "network-extension-pending:trace",
            "network-extension-trace",
            "network-extension-pending-trace.json",
        ),
    ),
    "sleep-wake": (
        ("sleep-wake:trace", "sleep-wake-trace", "sleep-wake-trace.json"),
        ("sleep-wake:packet", "packet-pcap", "sleep-wake.pcap"),
    ),
    "wkwebview-850x603": (
        (
            "wkwebview-850x603:metadata",
            "wkwebview-metadata",
            "wkwebview-850x603-metadata.json",
        ),
        (
            "wkwebview-850x603:pixels",
            "wkwebview-rgba",
            "wkwebview-850x603.rgba",
        ),
    ),
}


class LifecycleCaptureError(RuntimeError):
    """Lifecycle capture or materialization failed its closed source contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class LifecycleObservationBatch:
    artifacts: tuple[ObservationArtifact, ...]
    environment: dict[str, Any]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            artifact.subject: artifact.descriptor.as_dict()
            for artifact in self.artifacts
        }


@dataclass(frozen=True, slots=True)
class LifecycleEventArtifact:
    probe_id: str
    archived: ArchivedFile
    document: dict[str, Any]
    environment: dict[str, Any]
    attributes: dict[str, Any]

    def descriptor(self) -> dict[str, object]:
        return self.archived.descriptor("lifecycle-event")


@dataclass(frozen=True, slots=True)
class LifecycleEventBatch:
    artifacts: tuple[LifecycleEventArtifact, ...]
    raw_bindings: tuple[dict[str, object], ...]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            artifact.probe_id: artifact.descriptor()
            for artifact in self.artifacts
        }


@dataclass(slots=True)
class _CaptureBatchState:
    session: PhysicalCaptureSession
    context: dict[str, Any]
    capture: ObservationCapture
    artifacts: dict[str, ObservationArtifact]
    environment: dict[str, Any] | None = None
    identity_captured: bool = False


def _archive_root(session: PhysicalCaptureSession) -> Path:
    return (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    ).absolute()


def _proof_free(data: bytes, label: str) -> None:
    if b'"proof"' in data or b'"run_nonce"' in data:
        raise LifecycleCaptureError(
            "pre_nonce_proof_material",
            f"{label} contains forbidden proof or nonce material",
        )


def _require_installed_probe() -> None:
    helper = Path(LIFECYCLE_PROBE_EXECUTABLE)
    try:
        helper_metadata = helper.lstat()
        output_metadata = PROBE_OUTPUT_ROOT.lstat()
    except OSError as error:
        raise LifecycleCaptureError(
            "lifecycle_probe_unavailable",
            "the fixed installed lifecycle probe/output root is unavailable",
        ) from error
    if (
        not stat.S_ISREG(helper_metadata.st_mode)
        or helper_metadata.st_uid != 0
        or helper_metadata.st_nlink != 1
        or helper_metadata.st_mode & 0o022
        or helper_metadata.st_mode & 0o111 == 0
        or not stat.S_ISDIR(output_metadata.st_mode)
        or output_metadata.st_uid != 0
        or stat.S_IMODE(output_metadata.st_mode) != 0o700
    ):
        raise LifecycleCaptureError(
            "lifecycle_probe_untrusted",
            "the fixed lifecycle probe/output root is not root-owned and immutable",
        )


def _observation_descriptor(value: Any, probe_id: str) -> dict[str, object]:
    try:
        descriptor = parse_descriptor(
            value,
            expected_kinds={"lifecycle-observation"},
            label=f"{probe_id}.observation descriptor",
        )
    except RawArtifactError as error:
        raise LifecycleCaptureError(
            "lifecycle_observation_invalid",
            f"{probe_id} observation descriptor is invalid",
        ) from error
    expected_path = f"{OBSERVATION_DIRECTORY}/{probe_id}.json"
    if descriptor.path != expected_path:
        raise LifecycleCaptureError(
            "lifecycle_observation_path_invalid",
            f"{probe_id} observation path is not source-pinned",
        )
    return descriptor.as_dict()


def _declared_special_descriptors(
    observation: Mapping[str, Any], probe_id: str
) -> dict[str, dict[str, object]]:
    evidence = observation.get("evidence")
    specs = _SPECIAL_FILES.get(probe_id, ())
    if not specs:
        if evidence is not None:
            raise LifecycleCaptureError(
                "lifecycle_special_evidence_invalid",
                f"{probe_id} declared unexpected special evidence",
            )
        return {}
    if not isinstance(evidence, dict):
        raise LifecycleCaptureError(
            "lifecycle_special_evidence_invalid",
            f"{probe_id} omitted its special evidence descriptors",
        )
    keys = {
        "renderer-ready-v2": ("trace_artifact",),
        "network-extension-approval": ("trace_artifact",),
        "network-extension-denial": ("trace_artifact",),
        "network-extension-pending": ("trace_artifact",),
        "sleep-wake": ("trace_artifact", "capture_artifact"),
        "wkwebview-850x603": ("metadata_artifact", "pixels_artifact"),
    }[probe_id]
    if set(evidence) != set(keys) or len(keys) != len(specs):
        raise LifecycleCaptureError(
            "lifecycle_special_evidence_invalid",
            f"{probe_id} special evidence field set differs",
        )
    result: dict[str, dict[str, object]] = {}
    for key, (subject, kind, filename) in zip(keys, specs, strict=True):
        try:
            descriptor = parse_descriptor(
                evidence[key],
                expected_kinds={kind},
                label=f"{probe_id}.{key}",
            )
        except RawArtifactError as error:
            raise LifecycleCaptureError(
                "lifecycle_special_evidence_invalid",
                f"{probe_id} special evidence descriptor is invalid",
            ) from error
        if descriptor.path != f"{OBSERVATION_DIRECTORY}/{filename}":
            raise LifecycleCaptureError(
                "lifecycle_special_evidence_invalid",
                f"{probe_id} special evidence path is not source-pinned",
            )
        result[subject] = descriptor.as_dict()
    return result


def _context_matches_observation(
    context: Mapping[str, Any], parsed: Mapping[str, Any], probe_id: str
) -> None:
    if (
        parsed["candidate"] != context["candidate"]
        or parsed["run_id"] != context["run"]["run_id"]
    ):
        raise LifecycleCaptureError(
            "lifecycle_context_mismatch",
            f"{probe_id} observation candidate/run differs from the initialized context",
        )
    for field in _CONTEXT_ENVIRONMENT_FIELDS:
        if parsed["environment"][field] != context["run"][field]:
            raise LifecycleCaptureError(
                "lifecycle_environment_mismatch",
                f"{probe_id} observation environment differs at {field}",
            )


def _capture_standard_probe(
    state: _CaptureBatchState, probe_id: str
) -> tuple[ObservationArtifact, ...]:
    if probe_id in IDENTITY_PROBE_IDS:
        raise LifecycleCaptureError(
            "lifecycle_registry_drift", "identity probe reached the standard adapter"
        )
    category, expected_exit, _terminal, _attributes = PROBE_SPECS[probe_id]
    del category
    argv = tuple(lifecycle_probe_command(probe_id))
    spec = CommandSpec(
        role="lifecycle-observation-probe",
        argv=argv,
        cwd=PROBE_OUTPUT_ROOT,
        timeout_seconds=PROBE_TIMEOUT_SECONDS,
        accepted_exit_codes=frozenset({expected_exit}),
        stdout_limit=MAX_OBSERVATION_BYTES,
        stderr_limit=MAX_PROBE_STDERR_BYTES,
    )
    try:
        result = state.capture.run_command(spec)
    except (PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise LifecycleCaptureError(
            "lifecycle_probe_failed", f"fixed lifecycle probe failed for {probe_id}"
        ) from error
    if result.stderr:
        raise LifecycleCaptureError(
            "lifecycle_probe_stderr", f"fixed lifecycle probe emitted stderr for {probe_id}"
        )
    try:
        observation = load_json_bytes(result.stdout, f"{probe_id} lifecycle observation")
        if (
            not isinstance(observation, dict)
            or canonical_json(observation) + b"\n" != result.stdout
        ):
            raise RawArtifactError("lifecycle observation is not canonical JSON")
    except RawArtifactError as error:
        raise LifecycleCaptureError(
            "lifecycle_observation_invalid",
            f"fixed lifecycle probe output is invalid for {probe_id}",
        ) from error
    _proof_free(result.stdout, f"{probe_id} observation")
    if (
        observation.get("probe_id") != probe_id
        or observation.get("command") != list(argv)
        or observation.get("started_at") != result.started_at
        or observation.get("finished_at") != result.completed_at
        or observation.get("exit_code") != result.exit_code
    ):
        raise LifecycleCaptureError(
            "lifecycle_command_binding_mismatch",
            f"{probe_id} observation differs from the command that produced it",
        )

    copied: list[ObservationArtifact] = []
    declared_special = _declared_special_descriptors(observation, probe_id)
    for subject, kind, filename in _SPECIAL_FILES.get(probe_id, ()):
        expected = declared_special[subject]
        try:
            artifact = state.capture.copy_file(
                subject=subject,
                kind=kind,
                source=PROBE_OUTPUT_ROOT / probe_id / filename,
                relative=str(expected["path"]),
            )
            data = state.session.archive.read_bytes(
                str(expected["path"]), maximum=int(expected["size"])
            )
        except (
            PhysicalCaptureArchiveError,
            PhysicalCaptureSessionError,
            PhysicalObservationError,
        ) as error:
            raise LifecycleCaptureError(
                "lifecycle_special_copy_failed",
                f"cannot retain fixed special evidence for {probe_id}",
            ) from error
        if artifact.descriptor.as_dict() != expected:
            raise LifecycleCaptureError(
                "lifecycle_special_descriptor_mismatch",
                f"{probe_id} special evidence differs from its helper descriptor",
            )
        _proof_free(data, f"{probe_id} special evidence")
        copied.append(artifact)

    try:
        observation_artifact = state.capture.write_bytes(
            subject=f"{probe_id}:observation",
            kind="lifecycle-observation",
            relative=f"{OBSERVATION_DIRECTORY}/{probe_id}.json",
            data=result.stdout,
            maximum=MAX_OBSERVATION_BYTES,
        )
    except (PhysicalCaptureSessionError, PhysicalObservationError) as error:
        raise LifecycleCaptureError(
            "lifecycle_observation_archive_failed",
            f"cannot retain lifecycle observation for {probe_id}",
        ) from error
    _observation_descriptor(observation_artifact.descriptor.as_dict(), probe_id)
    try:
        with ArtifactReader(_archive_root(state.session)) as reader:
            descriptor, reopened = reader.read(
                observation_artifact.descriptor.as_dict(),
                expected_kinds={"lifecycle-observation"},
                label=f"{probe_id} retained observation",
            )
            if descriptor != observation_artifact.descriptor or reopened != result.stdout:
                raise RawArtifactError("retained lifecycle observation drifted")
            parsed = validate_lifecycle_observation(
                observation,
                artifacts=reader,
                probe_id=probe_id,
            )
            reader.verify_all_unchanged(final_path=descriptor.path)
    except (LifecycleMatrixError, RawArtifactError) as error:
        raise LifecycleCaptureError(
            "lifecycle_observation_invalid",
            f"retained lifecycle observation failed validation for {probe_id}",
        ) from error
    _context_matches_observation(state.context, parsed, probe_id)
    if state.environment is None:
        state.environment = copy.deepcopy(parsed["environment"])
    elif state.environment != parsed["environment"]:
        raise LifecycleCaptureError(
            "lifecycle_environment_mismatch",
            "lifecycle observations disagree on one operation environment",
        )
    return (observation_artifact, *copied)


def _capture_identity_probe(
    state: _CaptureBatchState, probe_id: str
) -> tuple[ObservationArtifact, ...]:
    if probe_id not in IDENTITY_PROBE_IDS or state.environment is None:
        raise LifecycleCaptureError(
            "lifecycle_registry_drift",
            "identity capture requires a prior non-identity environment observation",
        )
    if not state.identity_captured:
        try:
            batch = capture_identity_observation(
                session=state.session,
                context=state.context,
                environment=state.environment,
            )
        except IdentityProbeError as error:
            raise LifecycleCaptureError(
                "lifecycle_identity_capture_failed",
                "fixed lifecycle identity batch failed",
            ) from error
        try:
            for artifact in batch.artifacts:
                descriptor = artifact.descriptor()
                state.artifacts[f"{artifact.probe_id}:observation"] = (
                    ObservationArtifact(
                        f"{artifact.probe_id}:observation",
                        parse_descriptor(
                            descriptor,
                            expected_kinds={"lifecycle-observation"},
                            label=f"identity observation {artifact.probe_id}",
                        ),
                    )
                )
        except RawArtifactError as error:
            raise LifecycleCaptureError(
                "lifecycle_identity_capture_failed",
                "fixed lifecycle identity batch returned an invalid descriptor",
            ) from error
        state.identity_captured = True
    artifact = state.artifacts.get(f"{probe_id}:observation")
    if artifact is None:
        raise LifecycleCaptureError(
            "lifecycle_identity_capture_failed",
            f"identity batch omitted {probe_id}",
        )
    return (artifact,)


def _materialize_probe(
    session: PhysicalCaptureSession,
    proof: dict[str, Any],
    manifest: Mapping[str, dict[str, object]],
    probe_id: str,
) -> LifecycleEventArtifact:
    observation_descriptor = manifest.get(f"{probe_id}:observation")
    if not isinstance(observation_descriptor, dict):
        raise LifecycleCaptureError(
            "lifecycle_manifest_invalid", f"frozen manifest omits {probe_id}:observation"
        )
    root = _archive_root(session)
    try:
        with ArtifactReader(root) as reader:
            _descriptor, observation = reader.read_json(
                observation_descriptor,
                expected_kind="lifecycle-observation",
                label=f"frozen lifecycle observation {probe_id}",
            )
            parsed = validate_lifecycle_observation(
                observation,
                artifacts=reader,
                probe_id=probe_id,
            )
            reader.verify_all_unchanged()
    except (LifecycleMatrixError, RawArtifactError) as error:
        raise LifecycleCaptureError(
            "lifecycle_manifest_invalid",
            f"cannot reopen frozen lifecycle observation {probe_id}",
        ) from error
    proof_candidate = {
        key: parsed["candidate"][key]
        for key in (
            "version",
            "build_number",
            "app_manifest_sha256",
            "signed_app_tree_sha256",
            "artifact_hash_manifest_sha256",
        )
    }
    if proof_candidate != proof["candidate"] or parsed["run_id"] != proof["run_id"]:
        raise LifecycleCaptureError(
            "lifecycle_proof_mismatch",
            f"{probe_id} frozen observation differs from the nonce proof",
        )
    document = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "document": EVENT_DOCUMENT,
        "proof": copy.deepcopy(proof),
        "probe_id": probe_id,
        "observation_artifact": copy.deepcopy(observation_descriptor),
    }
    try:
        with ArtifactReader(root) as reader:
            validate_lifecycle_event(
                document,
                artifacts=reader,
                probe_id=probe_id,
                proof=proof,
                environment=parsed["environment"],
                report_attributes=parsed["attributes"],
            )
    except (LifecycleMatrixError, RawArtifactError) as error:
        raise LifecycleCaptureError(
            "lifecycle_event_invalid",
            f"derived lifecycle event failed validation for {probe_id}",
        ) from error
    data = canonical_json(document) + b"\n"
    relative = f"{EVENT_DIRECTORY}/{probe_id}.json"
    try:
        archived = session.archive.write_bytes(
            relative,
            data,
            maximum=MAX_OBSERVATION_BYTES,
        )
    except PhysicalCaptureArchiveError as error:
        if error.code != "archive_destination_exists":
            raise LifecycleCaptureError(
                "lifecycle_event_archive_failed",
                f"cannot archive derived lifecycle event {probe_id}",
            ) from error
        try:
            reopened = session.archive.read_bytes(
                relative,
                maximum=MAX_OBSERVATION_BYTES,
            )
        except PhysicalCaptureArchiveError as reopen_error:
            raise LifecycleCaptureError(
                "lifecycle_event_retry_unreadable",
                f"cannot reopen existing lifecycle event {probe_id}",
            ) from reopen_error
        if not hmac.compare_digest(reopened, data):
            raise LifecycleCaptureError(
                "lifecycle_event_retry_mismatch",
                f"existing lifecycle event differs on retry for {probe_id}",
            ) from error
        archived = ArchivedFile(
            relative,
            len(reopened),
            hashlib.sha256(reopened).hexdigest(),
        )
    return LifecycleEventArtifact(
        probe_id,
        archived,
        document,
        copy.deepcopy(parsed["environment"]),
        copy.deepcopy(parsed["attributes"]),
    )


# Literal, immutable, exact 32-probe closure.  The readiness gate verifies both
# functions in every entry remain reachable from the production collector.
LIFECYCLE_PRODUCER_REGISTRY = MappingProxyType({
    "inside-out-signatures": (_capture_identity_probe, _materialize_probe),
    "team-id": (_capture_identity_probe, _materialize_probe),
    "bundle-identifiers": (_capture_identity_probe, _materialize_probe),
    "entitlements": (_capture_identity_probe, _materialize_probe),
    "provisioning": (_capture_identity_probe, _materialize_probe),
    "daemon-registration-approval": (_capture_standard_probe, _materialize_probe),
    "daemon-registration-denial": (_capture_standard_probe, _materialize_probe),
    "system-extension-approval": (_capture_standard_probe, _materialize_probe),
    "system-extension-pending": (_capture_standard_probe, _materialize_probe),
    "system-extension-restart": (_capture_standard_probe, _materialize_probe),
    "network-extension-approval": (_capture_standard_probe, _materialize_probe),
    "network-extension-denial": (_capture_standard_probe, _materialize_probe),
    "network-extension-pending": (_capture_standard_probe, _materialize_probe),
    "renderer-ready-v2": (_capture_standard_probe, _materialize_probe),
    "upgrade": (_capture_standard_probe, _materialize_probe),
    "replacement": (_capture_standard_probe, _materialize_probe),
    "downgrade-refusal": (_capture_standard_probe, _materialize_probe),
    "install-cleanup": (_capture_standard_probe, _materialize_probe),
    "uninstall-cleanup": (_capture_standard_probe, _materialize_probe),
    "login": (_capture_standard_probe, _materialize_probe),
    "logout": (_capture_standard_probe, _materialize_probe),
    "lock": (_capture_standard_probe, _materialize_probe),
    "fast-user-switching": (_capture_standard_probe, _materialize_probe),
    "concurrent-starts": (_capture_standard_probe, _materialize_probe),
    "cancellation": (_capture_standard_probe, _materialize_probe),
    "sleep-wake": (_capture_standard_probe, _materialize_probe),
    "wkwebview-850x603": (_capture_standard_probe, _materialize_probe),
    "reboot-recovery": (_capture_standard_probe, _materialize_probe),
    "host-crash": (_capture_standard_probe, _materialize_probe),
    "global-authority-crash": (_capture_standard_probe, _materialize_probe),
    "proxy-agent-crash": (_capture_standard_probe, _materialize_probe),
    "provider-crash": (_capture_standard_probe, _materialize_probe),
})


def capture_lifecycle_observations(
    *, session: PhysicalCaptureSession, context: object
) -> LifecycleObservationBatch:
    """Capture the exact proof-free 40-subject lifecycle pre-nonce set."""

    if not isinstance(session, PhysicalCaptureSession):
        raise LifecycleCaptureError(
            "invalid_session", "lifecycle capture requires a locked physical session"
        )
    try:
        validated_context = validate_context(context)
        capture = session.observation_capture()
    except (
        OSError,
        PhysicalCollectorRequestError,
        PhysicalCaptureSessionError,
    ) as error:
        raise LifecycleCaptureError(
            "lifecycle_context_invalid",
            "lifecycle capture context/session failed strict revalidation",
        ) from error
    _require_installed_probe()
    state = _CaptureBatchState(session, validated_context, capture, {})
    ordered_probes = (
        *sorted(set(PROBE_SPECS) - set(IDENTITY_PROBE_IDS)),
        *IDENTITY_PROBE_IDS,
    )
    for probe_id in ordered_probes:
        capture_probe, _materialize = LIFECYCLE_PRODUCER_REGISTRY[probe_id]
        for artifact in capture_probe(state, probe_id):
            existing = state.artifacts.get(artifact.subject)
            if existing is not None and existing != artifact:
                raise LifecycleCaptureError(
                    "lifecycle_observation_reuse",
                    f"lifecycle capture produced conflicting subject {artifact.subject}",
                )
            state.artifacts[artifact.subject] = artifact
    if state.environment is None or set(state.artifacts) != EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS:
        raise LifecycleCaptureError(
            "lifecycle_observation_set_invalid",
            "lifecycle pre-nonce subjects differ from the exact 40-subject contract",
        )
    artifacts = tuple(state.artifacts[subject] for subject in sorted(state.artifacts))
    if (
        len({artifact.descriptor.path for artifact in artifacts}) != len(artifacts)
        or len({artifact.descriptor.sha256 for artifact in artifacts}) != len(artifacts)
    ):
        raise LifecycleCaptureError(
            "lifecycle_observation_reuse",
            "lifecycle observations reuse a path or byte digest",
        )
    session.require_collection_open()
    return LifecycleObservationBatch(artifacts, copy.deepcopy(state.environment))


def materialize_lifecycle_events(
    *, session: PhysicalCaptureSession, proof: object
) -> LifecycleEventBatch:
    """Derive exactly 32 proof events from the frozen 40-subject manifest."""

    if not isinstance(session, PhysicalCaptureSession):
        raise LifecycleCaptureError(
            "invalid_session", "lifecycle materialization requires a locked session"
        )
    if session.state is not CaptureState.NONCE_RECEIVED:
        raise LifecycleCaptureError(
            "lifecycle_materialization_phase_invalid",
            "lifecycle events may be materialized only after nonce receipt",
        )
    try:
        parsed_proof = parse_proof_binding(proof, "lifecycle proof")
        frozen = session.load_observation_manifest().descriptor_mapping()
    except (RawArtifactError, PhysicalCaptureSessionError, PhysicalObservationError) as error:
        raise LifecycleCaptureError(
            "lifecycle_manifest_invalid",
            "cannot reopen the frozen lifecycle observation manifest",
        ) from error
    lifecycle_manifest = {
        subject: descriptor
        for subject, descriptor in frozen.items()
        if isinstance(descriptor, dict)
        and str(descriptor.get("path", "")).startswith(f"{OBSERVATION_DIRECTORY}/")
    }
    if set(lifecycle_manifest) != EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS:
        raise LifecycleCaptureError(
            "lifecycle_manifest_invalid",
            "frozen lifecycle manifest differs from the exact 40-subject contract",
        )
    events: list[LifecycleEventArtifact] = []
    for probe_id in sorted(PROBE_SPECS):
        _capture, materialize_probe = LIFECYCLE_PRODUCER_REGISTRY[probe_id]
        event = materialize_probe(session, parsed_proof, lifecycle_manifest, probe_id)
        # A second direct validation keeps registry output on the report
        # validator's public path and makes the production reachability explicit.
        try:
            with ArtifactReader(_archive_root(session)) as reader:
                validate_lifecycle_event(
                    event.document,
                    artifacts=reader,
                    probe_id=probe_id,
                    proof=parsed_proof,
                    environment=event.environment,
                    report_attributes=event.attributes,
                )
        except (LifecycleMatrixError, RawArtifactError) as error:
            raise LifecycleCaptureError(
                "lifecycle_event_invalid",
                f"materialized lifecycle event failed final validation for {probe_id}",
            ) from error
        events.append(event)
    if {event.probe_id for event in events} != set(PROBE_SPECS):
        raise LifecycleCaptureError(
            "lifecycle_event_set_invalid",
            "materialized lifecycle event set differs from the exact 32 probes",
        )
    raw_bindings = [
        {"subject": subject, "descriptor": copy.deepcopy(descriptor)}
        for subject, descriptor in lifecycle_manifest.items()
    ]
    raw_bindings.extend(
        {
            "subject": event.probe_id,
            "descriptor": event.descriptor(),
        }
        for event in events
    )
    subjects = {str(binding["subject"]) for binding in raw_bindings}
    descriptors = [binding["descriptor"] for binding in raw_bindings]
    if (
        subjects != EXPECTED_LIFECYCLE_RAW_SUBJECTS
        or len(subjects) != len(raw_bindings)
        or len({str(descriptor["path"]) for descriptor in descriptors})
        != len(descriptors)
        or len({str(descriptor["sha256"]) for descriptor in descriptors})
        != len(descriptors)
    ):
        raise LifecycleCaptureError(
            "lifecycle_raw_binding_set_invalid",
            "lifecycle materialization did not produce one exact 72-subject set",
        )
    if session.state is not CaptureState.NONCE_RECEIVED:
        raise LifecycleCaptureError(
            "lifecycle_materialization_phase_invalid",
            "lifecycle session changed state during materialization",
        )
    return LifecycleEventBatch(
        tuple(events),
        tuple(sorted(raw_bindings, key=lambda binding: str(binding["subject"]))),
    )


__all__ = [
    "LIFECYCLE_PRODUCER_REGISTRY",
    "LifecycleCaptureError",
    "LifecycleEventBatch",
    "LifecycleObservationBatch",
    "capture_lifecycle_observations",
    "materialize_lifecycle_events",
]
