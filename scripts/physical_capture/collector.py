#!/usr/bin/env python3
"""Fixed-lane entry point for complete session-owned physical capture.

The CLI accepts no executable, argv, session path, context path, or output
path.  A lane enum selects source-owned paths below ``target/``; initialization
derives its context from the fixed final candidate and archives the exact
inputs inside the locked session.  Four immutable producer checkpoints form
one frozen raw union before the journaled nonce/report/receipt finalization.
All process execution remains inside the reviewed producer modules.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path, PurePosixPath
import re
import sys
from types import MappingProxyType
from typing import Any, Callable, Final, Mapping, Sequence

if __package__ in {None, ""}:  # pragma: no cover - production direct-script path
    _SOURCE_ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_SOURCE_ROOT))

from scripts.harness import performance_ledger as performance_contract
from scripts.harness.performance_ledger import PerformanceLedgerError
from scripts.harness.packet_evidence import (
    EXPECTED_PACKET_RAW_SUBJECTS,
    OPTIONAL_PACKET_RAW_SUBJECTS,
)
from scripts.harness.physical_collector_request import (
    PhysicalCollectorRequestError,
    initialize_context,
    validate_context,
)
from scripts.harness.raw_artifacts import (
    ARTIFACT_KINDS,
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    load_json_file,
    parse_descriptor,
)
from scripts.physical_capture.adversarial import (
    PRE_NONCE_SUBJECTS as ADVERSARIAL_PRE_NONCE_SUBJECTS,
    capture_adversarial_observations,
)
from scripts.physical_capture.archive import (
    ArchivedFile,
    PendingFile,
    PhysicalCaptureArchiveError,
    SecureArchive,
)
from scripts.physical_capture.composition import (
    PhysicalCaptureCompositionError,
    publish_physical_evidence,
)
from scripts.physical_capture.finalize import (
    PhysicalCaptureFinalizationError,
    finalize_session,
    load_finalized_run_record,
)
from scripts.physical_capture.lifecycle import (
    EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS,
    capture_lifecycle_observations,
)
from scripts.physical_capture.packet import capture_packet_observations
from scripts.physical_capture.policy import (
    PhysicalCapturePolicyError,
    require_current_collector_source_activation,
)
from scripts.physical_capture.performance import (
    FAILURE_RESTORATION_RELATIVE,
    INTENT_OBSERVATION_SUBJECT,
    LEDGER_OBSERVATION_SUBJECT,
    MAX_RESTART_RECOVERY_ATTEMPTS,
    OBSERVATION_DIRECTORY,
    RESTART_RECOVERY_FILENAME_RE,
    RESTORATION_OBSERVATION_SUBJECT,
    PerformanceCaptureError,
    PerformanceObservationBatch,
    RestartRecoveryStatus,
    capture_performance_observations,
    recover_interrupted_performance_shaping,
    validate_restart_recovery_chain,
    validate_shaping_restoration_failure,
)
from scripts.physical_capture.performance_operator import (
    PerformanceOperatorAdapterError,
    SignalCancellation,
    TerminalCheckpointPrompt,
    TerminalPerformanceOperator,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
    SessionEventView,
)


FAILURE_DOCUMENT: Final = "cfw-physical-performance-collector-failure-v2"
FAILURE_RECOVERY_DOCUMENT: Final = "cfw-physical-collector-failure-recovery-v1"
INPUT_DOCUMENT: Final = "cfw-physical-performance-collector-input-v1"
PRODUCER_CHECKPOINT_DOCUMENT: Final = "cfw-physical-producer-checkpoint-v1"
PRODUCER_CHECKPOINT_SCHEMA_VERSION: Final = 2
PRODUCER_ATTEMPT_DOCUMENT: Final = "cfw-physical-producer-attempt-v1"
PRODUCER_ATTEMPT_SCHEMA_VERSION: Final = 1
CONTEXT_RELATIVE: Final = "inputs/run-context.json"
PARAMETERS_RELATIVE: Final = "inputs/performance-parameters.json"
FAILURE_RELATIVE: Final = "failures/performance-collector.json"
FAILURE_RECOVERY_RELATIVE: Final = "failures/recovery.json"
PRODUCER_CHECKPOINT_DIRECTORY: Final = "checkpoints/producers"
PRODUCER_ATTEMPT_DIRECTORY: Final = "checkpoints/producer-attempts"
MAX_CANDIDATE_BYTES: Final = 8 * 1024 * 1024
MAX_INPUT_BYTES: Final = 8 * 1024 * 1024
MAX_PRODUCER_CHECKPOINT_BYTES: Final = 1024 * 1024
MAX_PRODUCER_ATTEMPT_BYTES: Final = 64 * 1024
ROOT_PRODUCER_CHECKPOINT_SHA256: Final = "0" * 64

REPOSITORY: Final = Path(__file__).resolve().parents[2]
FINAL_CANDIDATE: Final = (
    REPOSITORY
    / "target/candidates/0.4.0/release/final-candidate/"
    "physical-collector-candidate.json"
)
LANES: Final = {
    "macos15": {
        "run_id": "run-40029-macos15",
        "session_prefix": "physical-capture/v040/macos15",
    },
    "current-macos": {
        "run_id": "run-40029-current-macos",
        "session_prefix": "physical-capture/v040/current-macos",
    },
}
ATTEMPTS: Final = ("01", "02", "03")
NETWORK_PROFILES: Final = {
    "controlled-ethernet": "controlled Ethernet release network",
    "controlled-wifi": "controlled Wi-Fi release network",
}
POWER_SOURCES: Final = ("ac", "battery")
PRODUCER_ORDER: Final = ("lifecycle", "adversarial", "packet", "performance")

_LIFECYCLE_SPECIAL_KINDS: Final = {
    "renderer-ready-v2:trace": "renderer-ready-trace",
    "network-extension-approval:trace": "network-extension-trace",
    "network-extension-denial:trace": "network-extension-trace",
    "network-extension-pending:trace": "network-extension-trace",
    "sleep-wake:trace": "sleep-wake-trace",
    "sleep-wake:packet": "packet-pcap",
    "wkwebview-850x603:metadata": "wkwebview-metadata",
    "wkwebview-850x603:pixels": "wkwebview-rgba",
}

_ERROR_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class PhysicalCollectorDriverError(RuntimeError):
    """The fixed collector entry cannot safely continue this session."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ArchiveState:
    kind: str
    names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ProducerProgress:
    completed: dict[str, dict[str, dict[str, object]]]
    checkpoint_sha256: dict[str, str]
    started_harness: str | None


def _lane(value: str) -> dict[str, str]:
    try:
        return LANES[value]
    except KeyError as error:  # pragma: no cover - argparse enforces choices
        raise PhysicalCollectorDriverError(
            "invalid_lane", "physical collector lane is not source-owned"
        ) from error


def _session_root(lane_name: str, attempt: str) -> str:
    lane = _lane(lane_name)
    if attempt not in ATTEMPTS:
        raise PhysicalCollectorDriverError(
            "invalid_attempt", "physical collector attempt is not source-owned"
        )
    return f"{lane['session_prefix']}/attempt-{attempt}"


def _collector_intent_sha256(
    lane_name: str,
    attempt: str,
    context_data: bytes,
    parameter_data: bytes,
) -> str:
    _session_root(lane_name, attempt)
    intent = {
        "schema_version": 1,
        "document": INPUT_DOCUMENT,
        "lane": lane_name,
        "attempt": attempt,
        "context_sha256": hashlib.sha256(context_data).hexdigest(),
        "parameters_sha256": hashlib.sha256(parameter_data).hexdigest(),
    }
    return hashlib.sha256(canonical_json(intent)).hexdigest()


def _abandonment_predecessor(
    session: PhysicalCaptureSession,
) -> SessionEventView:
    try:
        event = session.last_event_view()
        if (
            event.event is not CaptureEvent.SESSION_ABANDONED
            or event.from_state is None
            or event.to_state is not CaptureState.ABANDONED
        ):
            raise PhysicalCaptureSessionError(
                "journal_tip_invalid",
                "journal tip is not a source-owned abandonment event",
            )
    except (
        PhysicalCaptureSessionError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt abandonment event failed strict reopening",
        ) from error
    return event


def _validate_abandonment_closure(session: PhysicalCaptureSession) -> None:
    if session.state is not CaptureState.ABANDONED:
        raise PhysicalCollectorDriverError(
            "previous_attempt_not_abandoned",
            "a new attempt is forbidden until the prior session is abandoned",
        )
    abandonment = _abandonment_predecessor(session)
    assert abandonment.from_state is not None
    try:
        predecessor = session.event_view(abandonment.sequence - 1)
    except PhysicalCaptureSessionError as error:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt abandonment predecessor cannot be reopened",
        ) from error
    if predecessor.event_sha256 != abandonment.previous_event_sha256:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt abandonment predecessor differs from its hash chain",
        )
    from_state = abandonment.from_state
    previous_event_sha256 = abandonment.previous_event_sha256
    binding_sha256 = session.snapshot.last_binding_sha256
    closure_bindings: list[tuple[str, str]] = []

    failure_names = _namespace_names(session.archive, "failures")
    try:
        failure_pending = (
            session.archive.pending_files("failures") if failure_names else ()
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt failure closure cannot be inspected",
        ) from error
    if failure_pending:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt failure closure is still pending",
        )
    if failure_names:
        if len(failure_names) != 1:
            raise PhysicalCollectorDriverError(
                "previous_attempt_abandonment_invalid",
                "previous attempt has multiple failure closure records",
            )
        filename = failure_names[0]
        relative = f"failures/{filename}"
        try:
            data = session.archive.read_bytes(relative, maximum=64 * 1024)
            if filename == Path(FAILURE_RECOVERY_RELATIVE).name:
                _validate_failure_recovery_record(
                    data,
                    session=session,
                    expected_state=from_state,
                    expected_journal_tip_sha256=previous_event_sha256,
                )
            else:
                _validate_source_failure_record(
                    data,
                    filename=filename,
                    session=session,
                    expected_state=from_state,
                    expected_journal_tip_sha256=previous_event_sha256,
                    expected_recorded_at=predecessor.recorded_at,
                )
            archived = session.archive.describe_file(
                relative, maximum=64 * 1024
            )
        except (
            PhysicalCaptureArchiveError,
            PhysicalCollectorDriverError,
        ) as error:
            raise PhysicalCollectorDriverError(
                "previous_attempt_abandonment_invalid",
                "previous attempt failure closure failed strict reopening",
            ) from error
        closure_bindings.append(("failure", archived.sha256))

    performance_names = _namespace_names(
        session.archive, OBSERVATION_DIRECTORY
    )
    try:
        performance_pending = (
            session.archive.pending_files(OBSERVATION_DIRECTORY)
            if performance_names
            else ()
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt performance closure cannot be inspected",
        ) from error
    if any(
        RESTART_RECOVERY_FILENAME_RE.fullmatch(
            Path(item.final_relative_path).name
        )
        for item in performance_pending
    ):
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt shaping recovery closure is still pending",
        )
    if any(
        RESTART_RECOVERY_FILENAME_RE.fullmatch(name)
        for name in performance_names
    ):
        try:
            descriptor = recover_performance_session(
                session=session,
                context={},
                operator=object(),
            )
            performance_binding = descriptor["sha256"]
            if not isinstance(performance_binding, str):
                raise PhysicalCollectorDriverError(
                    "recovery_abandonment_invalid",
                    "shaping recovery descriptor has no canonical digest",
                )
        except (KeyError, PhysicalCollectorDriverError) as error:
            raise PhysicalCollectorDriverError(
                "previous_attempt_abandonment_invalid",
                "previous attempt shaping recovery failed strict reopening",
            ) from error
        closure_bindings.append(("performance-recovery", performance_binding))

    try:
        resolution_binding = session.resolution_binding_for_last_event(
            CaptureEvent.SESSION_ABANDONED
        )
    except PhysicalCaptureSessionError as error:
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt journal recovery closure failed strict reopening",
        ) from error
    if resolution_binding is not None:
        closure_bindings.append(("journal-resolution", resolution_binding))

    if (
        len(closure_bindings) != 1
        or closure_bindings[0][1] != binding_sha256
    ):
        raise PhysicalCollectorDriverError(
            "previous_attempt_abandonment_invalid",
            "previous attempt abandonment has no unique bound closure record",
        )


def _require_previous_attempt_abandoned(lane_name: str, attempt: str) -> None:
    _session_root(lane_name, attempt)
    index = ATTEMPTS.index(attempt)
    if index == 0:
        return
    previous = ATTEMPTS[index - 1]
    try:
        with PhysicalCaptureSession.open(
            REPOSITORY, _session_root(lane_name, previous)
        ) as session:
            state = session.state
            if state is CaptureState.ABANDONED:
                _validate_abandonment_closure(session)
    except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError) as error:
        try:
            if PhysicalCaptureSession.uninitialized_quarantined(
                REPOSITORY, _session_root(lane_name, previous)
            ):
                return
        except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError):
            pass
        raise PhysicalCollectorDriverError(
            "previous_attempt_unavailable",
            "collector attempts must be initialized in a contiguous sequence",
        ) from error
    if state is not CaptureState.ABANDONED:
        raise PhysicalCollectorDriverError(
            "previous_attempt_not_abandoned",
            "a new attempt is forbidden until the prior session is abandoned",
        )


def _performance_archive_state(archive: SecureArchive) -> _ArchiveState:
    try:
        names = archive.list_names(OBSERVATION_DIRECTORY)
    except PhysicalCaptureArchiveError as error:
        if error.code == "directory_not_found":
            return _ArchiveState("fresh", ())
        raise PhysicalCollectorDriverError(
            "performance_archive_unreadable",
            "performance observation namespace cannot be inspected",
        ) from error
    name_set = set(names)
    completed = {
        "sample-ledger.json",
        "shaping-intent.json",
        "shaping-restoration.json",
    }
    if name_set == completed:
        return _ArchiveState("complete", names)
    recovery_names = {
        name for name in names if RESTART_RECOVERY_FILENAME_RE.fullmatch(name)
    }
    if (
        "shaping-restoration-failed.json" in name_set
        or recovery_names
        or (
            "shaping-intent.json" in name_set
            and "shaping-restoration.json" not in name_set
        )
    ):
        return _ArchiveState("recovery_required", names)
    if {
        "shaping-intent.json",
        "shaping-restoration.json",
    }.issubset(name_set) and "sample-ledger.json" not in name_set:
        return _ArchiveState("restored_incomplete", names)
    if not names:
        return _ArchiveState("fresh", names)
    return _ArchiveState("invalid", names)


def _load_archived_inputs(session: PhysicalCaptureSession) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        context_data = session.archive.read_bytes(
            CONTEXT_RELATIVE, maximum=MAX_INPUT_BYTES
        )
        parameter_data = session.archive.read_bytes(
            PARAMETERS_RELATIVE, maximum=MAX_INPUT_BYTES
        )
        context = load_json_bytes(
            context_data,
            "archived physical run context",
        )
        parameters = load_json_bytes(
            parameter_data,
            "archived performance parameters",
        )
        if not isinstance(context, dict) or not isinstance(parameters, dict):
            raise RawArtifactError("archived collector inputs must be objects")
        if (
            canonical_json(context) + b"\n" != context_data
            or canonical_json(parameters) + b"\n" != parameter_data
        ):
            raise RawArtifactError("archived collector inputs are not canonical JSON")
        validated_context = validate_context(context)
    except (
        OSError,
        PhysicalCaptureArchiveError,
        PhysicalCollectorRequestError,
        RawArtifactError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "collector_inputs_invalid",
            "fixed archived collector inputs failed strict revalidation",
        ) from error
    return validated_context, parameters


def _checkpoint_relative(harness: str) -> str:
    if harness not in PRODUCER_ORDER:
        raise PhysicalCollectorDriverError(
            "invalid_harness", "physical producer is not source-owned"
        )
    return f"{PRODUCER_CHECKPOINT_DIRECTORY}/{harness}.json"


def _attempt_relative(harness: str) -> str:
    if harness not in PRODUCER_ORDER:
        raise PhysicalCollectorDriverError(
            "invalid_harness", "physical producer is not source-owned"
        )
    return f"{PRODUCER_ATTEMPT_DIRECTORY}/{harness}.json"


def _expected_subject_sets(harness: str) -> tuple[frozenset[str], frozenset[str]]:
    if harness == "adversarial":
        required = frozenset(ADVERSARIAL_PRE_NONCE_SUBJECTS)
        return required, required
    if harness == "lifecycle":
        required = frozenset(EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS)
        return required, required
    if harness == "packet":
        return (
            frozenset(EXPECTED_PACKET_RAW_SUBJECTS),
            frozenset(EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS),
        )
    if harness == "performance":
        required = frozenset(
            {
                LEDGER_OBSERVATION_SUBJECT,
                INTENT_OBSERVATION_SUBJECT,
                RESTORATION_OBSERVATION_SUBJECT,
            }
        )
        return required, required
    raise PhysicalCollectorDriverError(
        "invalid_harness", "physical producer is not source-owned"
    )


def _expected_subject_kind(harness: str, subject: str) -> str:
    if harness == "lifecycle":
        if subject in _LIFECYCLE_SPECIAL_KINDS:
            return _LIFECYCLE_SPECIAL_KINDS[subject]
        if subject.endswith(":observation"):
            return "lifecycle-observation"
    elif harness == "adversarial":
        if subject.startswith("observation:"):
            return "adversarial-case-observation"
        if subject.startswith(("client-signature:", "server-signature:")):
            return "adversarial-signature-observation"
        if subject.startswith("secret-coverage:"):
            return "adversarial-secret-coverage"
    elif harness == "packet":
        if subject.endswith((":product-state", ":restore-state")):
            return "packet-product-state-observation"
        if subject.endswith(":capture-provenance"):
            return "packet-capture-provenance"
        if subject.endswith(":send-attempt"):
            return "packet-send-attempt"
        if ":" not in subject:
            return "packet-pcap"
    elif harness == "performance":
        kinds = {
            LEDGER_OBSERVATION_SUBJECT: "performance-sample-ledger",
            INTENT_OBSERVATION_SUBJECT: "performance-shaping-transaction",
            RESTORATION_OBSERVATION_SUBJECT: "performance-shaping-transaction",
        }
        if subject in kinds:
            return kinds[subject]
    raise PhysicalCollectorDriverError(
        "producer_subject_kind_unknown",
        f"{harness} subject {subject!r} has no source-owned artifact kind",
    )


def _normalize_producer_descriptors(
    harness: str, value: object
) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping):
        raise PhysicalCollectorDriverError(
            "producer_observation_set_invalid",
            f"{harness} producer did not return a descriptor mapping",
        )
    if any(not isinstance(subject, str) for subject in value):
        raise PhysicalCollectorDriverError(
            "producer_observation_set_invalid",
            f"{harness} producer returned a non-string subject",
        )
    subjects = frozenset(value)
    required, allowed = _expected_subject_sets(harness)
    if not required <= subjects <= allowed:
        raise PhysicalCollectorDriverError(
            "producer_observation_set_invalid",
            f"{harness} producer subjects differ from the source-owned closure",
        )
    normalized: dict[str, dict[str, object]] = {}
    paths: set[str] = set()
    digests: set[str] = set()
    prefix = f"raw/{harness}/observations/"
    try:
        for subject in sorted(subjects):
            descriptor = parse_descriptor(
                value[subject],
                expected_kinds=ARTIFACT_KINDS,
                label=f"{harness} checkpoint.{subject}",
            )
            expected_kind = _expected_subject_kind(harness, subject)
            if descriptor.kind != expected_kind:
                raise RawArtifactError(
                    f"{harness} observation kind differs for subject {subject!r}"
                )
            if not descriptor.path.startswith(prefix):
                raise RawArtifactError(
                    f"{harness} observation path is outside its fixed namespace"
                )
            if descriptor.path in paths or descriptor.sha256 in digests:
                raise RawArtifactError(
                    f"{harness} observation reuses a path or byte digest"
                )
            paths.add(descriptor.path)
            digests.add(descriptor.sha256)
            normalized[subject] = descriptor.as_dict()
    except (KeyError, RawArtifactError) as error:
        raise PhysicalCollectorDriverError(
            "producer_observation_set_invalid",
            f"{harness} producer descriptors failed strict validation",
        ) from error
    return normalized


def _namespace_names(archive: SecureArchive, relative: str) -> tuple[str, ...]:
    try:
        return archive.list_names(relative)
    except PhysicalCaptureArchiveError as error:
        if error.code == "directory_not_found":
            return ()
        raise PhysicalCollectorDriverError(
            "producer_namespace_unreadable",
            "physical producer namespace cannot be securely inspected",
        ) from error


def _producer_session_identity(
    session: PhysicalCaptureSession,
) -> tuple[str, str]:
    event_fields = {
        "schema_version",
        "document",
        "sequence",
        "event",
        "from_state",
        "to_state",
        "recorded_at",
        "previous_event_sha256",
        "binding_sha256",
    }
    try:
        context_data = session.archive.read_bytes(
            CONTEXT_RELATIVE, maximum=MAX_INPUT_BYTES
        )
        parameter_data = session.archive.read_bytes(
            PARAMETERS_RELATIVE, maximum=MAX_INPUT_BYTES
        )
        context = load_json_bytes(context_data, "producer-bound run context")
        parameters = load_json_bytes(
            parameter_data, "producer-bound performance parameters"
        )
        if (
            not isinstance(context, dict)
            or not isinstance(parameters, dict)
            or canonical_json(context) + b"\n" != context_data
            or canonical_json(parameters) + b"\n" != parameter_data
        ):
            raise RawArtifactError("producer inputs are not canonical JSON")
        root = session.archive.root_relative_to_target
        identities = [
            (lane_name, attempt)
            for lane_name in LANES
            for attempt in ATTEMPTS
            if root == _session_root(lane_name, attempt)
        ]
        if len(identities) != 1:
            raise RawArtifactError(
                "producer archive root is not one fixed lane and attempt"
            )
        lane_name, attempt = identities[0]
        if context.get("run", {}).get("os") != lane_name:
            raise RawArtifactError("producer context lane differs from its archive root")
        intent_sha256 = _collector_intent_sha256(
            lane_name, attempt, context_data, parameter_data
        )
        start_data = session.archive.read_bytes(
            "journal/00000001.json", maximum=64 * 1024
        )
        collection_data = session.archive.read_bytes(
            "journal/00000002.json", maximum=64 * 1024
        )
        start = exact_object(
            load_json_bytes(start_data, "producer-bound session start"),
            event_fields,
            "producer-bound session start",
        )
        collection = exact_object(
            load_json_bytes(collection_data, "producer-bound collection start"),
            event_fields,
            "producer-bound collection start",
        )
        start_sha256 = hashlib.sha256(start_data).hexdigest()
        collection_sha256 = hashlib.sha256(collection_data).hexdigest()
        if (
            canonical_json(start) + b"\n" != start_data
            or canonical_json(collection) + b"\n" != collection_data
            or start.get("schema_version") != 1
            or start.get("document") != "cfw-physical-capture-event-v1"
            or start.get("sequence") != 1
            or start.get("event") != CaptureEvent.SESSION_STARTED.value
            or start.get("from_state") is not None
            or start.get("to_state") != CaptureState.INITIALIZED.value
            or start.get("previous_event_sha256")
            != ROOT_PRODUCER_CHECKPOINT_SHA256
            or start.get("binding_sha256") != intent_sha256
            or collection.get("schema_version") != 1
            or collection.get("document") != "cfw-physical-capture-event-v1"
            or collection.get("sequence") != 2
            or collection.get("event") != CaptureEvent.COLLECTION_STARTED.value
            or collection.get("from_state") != CaptureState.INITIALIZED.value
            or collection.get("to_state") != CaptureState.COLLECTING.value
            or collection.get("previous_event_sha256") != start_sha256
            or collection.get("binding_sha256") != intent_sha256
        ):
            raise RawArtifactError(
                "producer session identity differs from its archived intent"
            )
        return intent_sha256, collection_sha256
    except (PhysicalCaptureArchiveError, RawArtifactError) as error:
        raise PhysicalCollectorDriverError(
            "producer_session_identity_invalid",
            "physical producer session identity failed strict reopening",
        ) from error


def _producer_namespace_entries(
    session: PhysicalCaptureSession,
    directory: str,
) -> tuple[frozenset[str], tuple[PendingFile, ...]]:
    allowed = {f"{harness}.json" for harness in PRODUCER_ORDER}
    names = _namespace_names(session.archive, directory)
    if not names:
        return frozenset(), ()
    try:
        pending = session.archive.pending_files(directory)
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "producer_namespace_unreadable",
            "physical producer transaction namespace cannot be inspected",
        ) from error
    pending_names = {Path(item.relative_path).name for item in pending}
    finals = frozenset(name for name in names if name in allowed)
    if (
        len(pending_names) != len(pending)
        or set(names) != set(finals) | pending_names
        or any(Path(item.final_relative_path).name not in allowed for item in pending)
    ):
        raise PhysicalCollectorDriverError(
            "producer_transaction_namespace_invalid",
            "producer transaction namespace contains an unknown or malformed file",
        )
    return finals, pending


def _read_producer_attempt(
    session: PhysicalCaptureSession,
    harness: str,
    *,
    predecessor_checkpoint_sha256: str,
) -> str:
    relative = _attempt_relative(harness)
    try:
        data = session.archive.read_bytes(
            relative, maximum=MAX_PRODUCER_ATTEMPT_BYTES
        )
        value = load_json_bytes(data, f"{harness} producer attempt")
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
            raise RawArtifactError("producer attempt is not canonical JSON")
        attempt = exact_object(
            value,
            {
                "schema_version",
                "document",
                "harness",
                "order_index",
                "session_intent_sha256",
                "collection_event_sha256",
                "predecessor_checkpoint_sha256",
            },
            f"{harness} producer attempt",
        )
        intent_sha256, collection_event_sha256 = _producer_session_identity(session)
        if (
            type(attempt["schema_version"]) is not int
            or attempt["schema_version"] != PRODUCER_ATTEMPT_SCHEMA_VERSION
            or attempt["document"] != PRODUCER_ATTEMPT_DOCUMENT
            or attempt["harness"] != harness
            or type(attempt["order_index"]) is not int
            or attempt["order_index"] != PRODUCER_ORDER.index(harness)
            or attempt["session_intent_sha256"] != intent_sha256
            or attempt["collection_event_sha256"] != collection_event_sha256
            or attempt["predecessor_checkpoint_sha256"]
            != predecessor_checkpoint_sha256
        ):
            raise RawArtifactError("producer attempt identity is invalid")
        return hashlib.sha256(data).hexdigest()
    except (PhysicalCaptureArchiveError, RawArtifactError) as error:
        raise PhysicalCollectorDriverError(
            "producer_attempt_invalid",
            f"{harness} producer attempt failed strict reopening",
        ) from error


def _write_producer_attempt(
    session: PhysicalCaptureSession,
    harness: str,
    *,
    predecessor_checkpoint_sha256: str,
) -> str:
    data = _producer_attempt_bytes(
        session,
        harness,
        predecessor_checkpoint_sha256=predecessor_checkpoint_sha256,
    )
    try:
        archived = session.archive.write_bytes(
            _attempt_relative(harness),
            data,
            maximum=MAX_PRODUCER_ATTEMPT_BYTES,
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "producer_attempt_failed",
            f"{harness} producer attempt could not be durably recorded",
        ) from error
    expected_sha256 = hashlib.sha256(data).hexdigest()
    if archived.sha256 != expected_sha256 or _read_producer_attempt(
        session,
        harness,
        predecessor_checkpoint_sha256=predecessor_checkpoint_sha256,
    ) != expected_sha256:
        raise PhysicalCollectorDriverError(
            "producer_attempt_failed",
            f"{harness} producer attempt changed after publication",
        )
    return expected_sha256


def _producer_attempt_bytes(
    session: PhysicalCaptureSession,
    harness: str,
    *,
    predecessor_checkpoint_sha256: str,
) -> bytes:
    intent_sha256, collection_event_sha256 = _producer_session_identity(session)
    document = {
        "schema_version": PRODUCER_ATTEMPT_SCHEMA_VERSION,
        "document": PRODUCER_ATTEMPT_DOCUMENT,
        "harness": harness,
        "order_index": PRODUCER_ORDER.index(harness),
        "session_intent_sha256": intent_sha256,
        "collection_event_sha256": collection_event_sha256,
        "predecessor_checkpoint_sha256": predecessor_checkpoint_sha256,
    }
    try:
        return canonical_json(document) + b"\n"
    except RawArtifactError as error:  # pragma: no cover - fixed source data
        raise PhysicalCollectorDriverError(
            "producer_attempt_failed",
            f"{harness} producer attempt cannot be encoded",
        ) from error


def _verify_producer_files(
    session: PhysicalCaptureSession,
    harness: str,
    observations: Mapping[str, Mapping[str, object]],
) -> None:
    expected_names = {
        Path(str(descriptor["path"])).name for descriptor in observations.values()
    }
    observed_names = set(
        _namespace_names(session.archive, f"raw/{harness}/observations")
    )
    if observed_names != expected_names:
        raise PhysicalCollectorDriverError(
            "producer_namespace_drifted",
            f"{harness} observation namespace differs from its durable checkpoint",
        )
    try:
        for subject, descriptor in observations.items():
            observed = session.archive.describe_file(
                str(descriptor["path"]), maximum=int(descriptor["size"])
            ).descriptor(str(descriptor["kind"]))
            if observed != descriptor:
                raise PhysicalCollectorDriverError(
                    "producer_observation_drifted",
                    f"{harness} retained bytes drifted for subject {subject}",
                )
    except (KeyError, TypeError, ValueError, PhysicalCaptureArchiveError) as error:
        if isinstance(error, PhysicalCollectorDriverError):
            raise
        raise PhysicalCollectorDriverError(
            "producer_observation_unreadable",
            f"{harness} retained observations cannot be securely reopened",
        ) from error


def _read_producer_checkpoint(
    session: PhysicalCaptureSession,
    harness: str,
    *,
    producer_attempt_sha256: str,
) -> tuple[dict[str, dict[str, object]], str]:
    relative = _checkpoint_relative(harness)
    try:
        data = session.archive.read_bytes(
            relative, maximum=MAX_PRODUCER_CHECKPOINT_BYTES
        )
        value = load_json_bytes(data, f"{harness} producer checkpoint")
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
            raise RawArtifactError("producer checkpoint is not canonical JSON")
        checkpoint = exact_object(
            value,
            {
                "schema_version",
                "document",
                "harness",
                "producer_attempt_sha256",
                "observations",
            },
            f"{harness} producer checkpoint",
        )
        if (
            type(checkpoint["schema_version"]) is not int
            or checkpoint["schema_version"] != PRODUCER_CHECKPOINT_SCHEMA_VERSION
            or checkpoint["document"] != PRODUCER_CHECKPOINT_DOCUMENT
            or checkpoint["harness"] != harness
            or checkpoint["producer_attempt_sha256"]
            != producer_attempt_sha256
        ):
            raise RawArtifactError("producer checkpoint identity is invalid")
        observations = _normalize_producer_descriptors(
            harness, checkpoint["observations"]
        )
        _verify_producer_files(session, harness, observations)
        return observations, hashlib.sha256(data).hexdigest()
    except (
        PhysicalCaptureArchiveError,
        RawArtifactError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "producer_checkpoint_invalid",
            f"{harness} producer checkpoint failed strict reopening",
        ) from error


def _write_producer_checkpoint(
    session: PhysicalCaptureSession,
    harness: str,
    observations: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    progress = _producer_progress(session)
    if progress.started_harness != harness:
        raise PhysicalCollectorDriverError(
            "producer_checkpoint_without_attempt",
            f"{harness} checkpoint has no matching durable producer attempt",
        )
    predecessor_sha256 = (
        ROOT_PRODUCER_CHECKPOINT_SHA256
        if not progress.completed
        else progress.checkpoint_sha256[PRODUCER_ORDER[len(progress.completed) - 1]]
    )
    attempt_sha256 = _read_producer_attempt(
        session,
        harness,
        predecessor_checkpoint_sha256=predecessor_sha256,
    )
    normalized = _normalize_producer_descriptors(harness, observations)
    _verify_producer_files(session, harness, normalized)
    document = {
        "schema_version": PRODUCER_CHECKPOINT_SCHEMA_VERSION,
        "document": PRODUCER_CHECKPOINT_DOCUMENT,
        "harness": harness,
        "producer_attempt_sha256": attempt_sha256,
        "observations": normalized,
    }
    data = canonical_json(document) + b"\n"
    try:
        archived = session.archive.write_bytes(
            _checkpoint_relative(harness),
            data,
            maximum=MAX_PRODUCER_CHECKPOINT_BYTES,
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "producer_checkpoint_failed",
            f"{harness} producer checkpoint could not be durably recorded",
        ) from error
    if archived.sha256 != hashlib.sha256(data).hexdigest():
        raise PhysicalCollectorDriverError(
            "producer_checkpoint_failed",
            f"{harness} producer checkpoint digest differs after publication",
        )
    reopened, reopened_sha256 = _read_producer_checkpoint(
        session, harness, producer_attempt_sha256=attempt_sha256
    )
    if reopened != normalized or reopened_sha256 != archived.sha256:
        raise PhysicalCollectorDriverError(
            "producer_checkpoint_failed",
            f"{harness} producer checkpoint changed after publication",
        )
    return normalized


def _producer_progress(
    session: PhysicalCaptureSession,
    *,
    ignored_attempt_pending: PendingFile | None = None,
) -> _ProducerProgress:
    attempt_names, attempt_pending = _producer_namespace_entries(
        session, PRODUCER_ATTEMPT_DIRECTORY
    )
    checkpoint_names, checkpoint_pending = _producer_namespace_entries(
        session, PRODUCER_CHECKPOINT_DIRECTORY
    )
    unexpected_attempt_pending = tuple(
        item for item in attempt_pending if item != ignored_attempt_pending
    )
    if unexpected_attempt_pending or checkpoint_pending:
        raise PhysicalCollectorDriverError(
            "producer_transaction_recovery_required",
            "producer transaction contains an interrupted pending publication",
        )
    completed: dict[str, dict[str, dict[str, object]]] = {}
    checkpoint_sha256: dict[str, str] = {}
    predecessor_sha256 = ROOT_PRODUCER_CHECKPOINT_SHA256
    started_harness: str | None = None
    for index, harness in enumerate(PRODUCER_ORDER):
        attempt_name = f"{harness}.json"
        checkpoint_name = f"{harness}.json"
        has_attempt = attempt_name in attempt_names
        has_checkpoint = checkpoint_name in checkpoint_names
        later_names = {f"{item}.json" for item in PRODUCER_ORDER[index + 1 :]}
        if not has_attempt:
            if has_checkpoint or attempt_names & later_names or checkpoint_names & later_names:
                raise PhysicalCollectorDriverError(
                    "producer_transaction_order_invalid",
                    "producer attempts and checkpoints are not one contiguous prefix",
                )
            break
        attempt_sha256 = _read_producer_attempt(
            session,
            harness,
            predecessor_checkpoint_sha256=predecessor_sha256,
        )
        if not has_checkpoint:
            if attempt_names & later_names or checkpoint_names & later_names:
                raise PhysicalCollectorDriverError(
                    "producer_transaction_order_invalid",
                    "producer attempts and checkpoints cross an incomplete producer",
                )
            started_harness = harness
            break
        observations, observed_checkpoint_sha256 = _read_producer_checkpoint(
            session,
            harness,
            producer_attempt_sha256=attempt_sha256,
        )
        if harness != PRODUCER_ORDER[len(completed)]:
            raise PhysicalCollectorDriverError(
                "producer_checkpoint_order_invalid",
                "producer checkpoints are not a contiguous source-owned prefix",
            )
        completed[harness] = observations
        checkpoint_sha256[harness] = observed_checkpoint_sha256
        predecessor_sha256 = observed_checkpoint_sha256
    return _ProducerProgress(completed, checkpoint_sha256, started_harness)


def _completed_producers(
    session: PhysicalCaptureSession,
) -> dict[str, dict[str, dict[str, object]]]:
    return _producer_progress(session).completed


def _load_producer_checkpoint(
    session: PhysicalCaptureSession, harness: str
) -> dict[str, dict[str, object]] | None:
    if harness not in PRODUCER_ORDER:
        raise PhysicalCollectorDriverError(
            "invalid_harness", "physical producer is not source-owned"
        )
    return _producer_progress(session).completed.get(harness)


def _discard_safe_pending_attempt_marker(session: PhysicalCaptureSession) -> None:
    attempt_names, attempt_pending = _producer_namespace_entries(
        session, PRODUCER_ATTEMPT_DIRECTORY
    )
    _checkpoint_names, checkpoint_pending = _producer_namespace_entries(
        session, PRODUCER_CHECKPOINT_DIRECTORY
    )
    if not attempt_pending and not checkpoint_pending:
        return
    if checkpoint_pending or len(attempt_pending) != 1:
        raise PhysicalCollectorDriverError(
            "producer_transaction_ambiguous",
            "producer transaction has an ambiguous interrupted publication",
        )
    pending = attempt_pending[0]
    target_name = Path(pending.final_relative_path).name
    if target_name in attempt_names:
        raise PhysicalCollectorDriverError(
            "producer_transaction_ambiguous",
            "producer attempt has both pending and committed publications",
        )
    try:
        pending_harness = target_name.removesuffix(".json")
        expected_index = PRODUCER_ORDER.index(pending_harness)
    except ValueError as error:
        raise PhysicalCollectorDriverError(
            "producer_transaction_ambiguous",
            "pending producer attempt does not target a source-owned harness",
        ) from error

    # Ignore this one pending marker while reopening the committed prefix.  A
    # marker write returns only after exclusive rename+fsync, so pending-only
    # proves the handler was never invoked and is the sole safe discard case.
    progress = _producer_progress(
        session, ignored_attempt_pending=pending
    )
    if (
        progress.started_harness is not None
        or expected_index != len(progress.completed)
        or any(
            _namespace_names(session.archive, f"raw/{harness}/observations")
            for harness in PRODUCER_ORDER[expected_index:]
        )
    ):
        raise PhysicalCollectorDriverError(
            "producer_transaction_ambiguous",
            "pending attempt is not the next side-effect-free producer",
        )
    predecessor_sha256 = (
        ROOT_PRODUCER_CHECKPOINT_SHA256
        if not progress.completed
        else progress.checkpoint_sha256[
            PRODUCER_ORDER[len(progress.completed) - 1]
        ]
    )
    expected = _producer_attempt_bytes(
        session,
        pending_harness,
        predecessor_checkpoint_sha256=predecessor_sha256,
    )
    try:
        observed = session.archive.read_pending_fragment(
            pending, maximum=MAX_PRODUCER_ATTEMPT_BYTES
        )
        if not expected.startswith(observed):
            raise PhysicalCollectorDriverError(
                "producer_transaction_ambiguous",
                "pending producer attempt is not an expected write prefix",
            )
        session.archive.discard_pending(pending)
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "producer_transaction_recovery_failed",
            "pending producer attempt could not be durably discarded",
        ) from error
    _producer_progress(session)


def _freeze_complete_observations(
    session: PhysicalCaptureSession,
    completed: Mapping[str, Mapping[str, Mapping[str, object]]],
) -> None:
    if tuple(completed) != PRODUCER_ORDER:
        return
    union: dict[str, object] = {}
    for harness in PRODUCER_ORDER:
        for subject, descriptor in completed[harness].items():
            if subject in union:
                raise PhysicalCollectorDriverError(
                    "producer_subject_reuse",
                    f"raw subject {subject!r} is reused across physical producers",
                )
            union[subject] = dict(descriptor)
    manifest = session.complete_observations(union)
    if len(manifest.observations) != len(union):
        raise PhysicalCollectorDriverError(
            "raw_completion_failed",
            "frozen raw manifest differs from the complete producer union",
        )


def _error_code(error: BaseException) -> str:
    value = getattr(error, "code", "unexpected_performance_failure")
    if not isinstance(value, str) or _ERROR_CODE_RE.fullmatch(value) is None:
        return "unexpected_performance_failure"
    return value


def _failure_record(
    session: PhysicalCaptureSession,
    *,
    relative: str,
    expected: Mapping[str, object],
):
    filename = Path(relative).name
    directory = Path(relative).parent.as_posix()
    fields = set(expected)
    try:
        expected_data = canonical_json(dict(expected)) + b"\n"
    except RawArtifactError as error:  # pragma: no cover - source-owned values
        raise PhysicalCollectorDriverError(
            "collector_failure_record_failed",
            "collector failure record cannot be encoded",
        ) from error

    def validate(data: bytes) -> None:
        try:
            value = load_json_bytes(data, "physical collector failure record")
            record = exact_object(
                value, fields, "physical collector failure record"
            )
            timestamp = record["state_recorded_at"]
            if (
                canonical_json(record) + b"\n" != data
                or any(record[key] != item for key, item in expected.items())
                or not isinstance(timestamp, str)
                or not timestamp.endswith("Z")
                or datetime.fromisoformat(timestamp[:-1] + "+00:00")
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
                != timestamp
            ):
                raise RawArtifactError("collector failure record identity differs")
        except (KeyError, RawArtifactError, TypeError, ValueError) as error:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_invalid",
                "existing physical collector failure record is invalid",
            ) from error

    names = _namespace_names(session.archive, directory)
    try:
        pending = (
            session.archive.pending_files(directory) if names else ()
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "collector_failure_record_unreadable",
            "collector failure namespace cannot be inspected",
        ) from error
    pending_names = {Path(item.relative_path).name for item in pending}
    finals = {name for name in names if name not in pending_names}
    target_pending = tuple(
        item for item in pending if item.final_relative_path == relative
    )
    if any(item not in target_pending for item in pending):
        raise PhysicalCollectorDriverError(
            "collector_failure_record_ambiguous",
            "another collector failure publication is pending",
        )
    if finals - {filename}:
        raise PhysicalCollectorDriverError(
            "collector_failure_record_ambiguous",
            "collector failure namespace contains another final record",
        )
    if filename in finals:
        if target_pending:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_ambiguous",
                "collector failure has both pending and final bytes",
            )
        try:
            data = session.archive.read_bytes(relative, maximum=64 * 1024)
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_unreadable",
                "collector failure record cannot be reopened",
            ) from error
        validate(data)
        return session.archive.describe_file(relative, maximum=64 * 1024)
    if target_pending:
        if len(target_pending) != 1:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_ambiguous",
                "collector failure has multiple pending publications",
            )
        candidate = target_pending[0]
        try:
            data = session.archive.read_pending_fragment(
                candidate, maximum=64 * 1024
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_unreadable",
                "pending collector failure record is unsafe",
            ) from error
        if data == expected_data:
            session.archive.publish_pending(candidate)
            return session.archive.describe_file(relative, maximum=64 * 1024)
        if expected_data.startswith(data):
            session.archive.discard_pending(candidate)
        else:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_invalid",
                "pending collector failure is not an expected write prefix",
            )
    try:
        archived = session.archive.write_bytes(
            relative, expected_data, maximum=64 * 1024
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "collector_failure_record_failed",
            "collector failure record could not be durably published",
        ) from error
    validate(session.archive.read_bytes(relative, maximum=64 * 1024))
    return archived


def _validate_source_failure_record(
    data: bytes,
    *,
    filename: str,
    session: PhysicalCaptureSession,
    expected_state: CaptureState | None = None,
    expected_journal_tip_sha256: str | None = None,
    expected_recorded_at: datetime | None = None,
) -> None:
    required_state = session.state if expected_state is None else expected_state
    required_journal_tip = (
        session.snapshot.last_event_sha256
        if expected_journal_tip_sha256 is None
        else expected_journal_tip_sha256
    )
    required_recorded_at = (
        session.snapshot.last_recorded_at
        if expected_recorded_at is None
        else expected_recorded_at
    )
    required_recorded_at_text = required_recorded_at.astimezone(
        timezone.utc
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        value = load_json_bytes(data, "reopened collector failure")
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
            raise RawArtifactError("collector failure is not canonical JSON")
        document = value.get("document")
        if document == FAILURE_DOCUMENT:
            expected_fields = {
                "schema_version",
                "document",
                "code",
                "state_recorded_at",
                "state",
                "archive_root",
                "journal_tip_sha256",
            }
            if filename != Path(FAILURE_RELATIVE).name:
                raise RawArtifactError("generic failure filename is invalid")
        elif document == "cfw-physical-producer-failure-v2":
            expected_fields = {
                "schema_version",
                "document",
                "harness",
                "code",
                "state_recorded_at",
                "state",
                "archive_root",
                "journal_tip_sha256",
            }
            harness = value.get("harness")
            if (
                harness not in PRODUCER_ORDER
                or filename != f"{harness}-collector.json"
            ):
                raise RawArtifactError("producer failure filename is invalid")
        else:
            raise RawArtifactError("collector failure document is unknown")
        timestamp = value.get("state_recorded_at")
        if (
            set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or not isinstance(value.get("code"), str)
            or _ERROR_CODE_RE.fullmatch(value["code"]) is None
            or value.get("state") != required_state.value
            or value.get("archive_root")
            != session.archive.root_relative_to_target
            or not isinstance(value.get("journal_tip_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", value["journal_tip_sha256"]
            )
            is None
            or value["journal_tip_sha256"] != required_journal_tip
            or not isinstance(timestamp, str)
            or timestamp != required_recorded_at_text
            or not timestamp.endswith("Z")
            or datetime.fromisoformat(timestamp[:-1] + "+00:00")
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
            != timestamp
        ):
            raise RawArtifactError("collector failure identity is invalid")
    except (RawArtifactError, TypeError, ValueError) as error:
        raise PhysicalCollectorDriverError(
            "collector_failure_record_invalid",
            "durable collector failure record failed strict reopening",
        ) from error


def _failure_recovery_bytes(
    session: PhysicalCaptureSession,
    pending,
    observed: bytes,
) -> bytes:
    value = {
        "schema_version": 1,
        "document": FAILURE_RECOVERY_DOCUMENT,
        "state": session.state.value,
        "archive_root": session.archive.root_relative_to_target,
        "journal_tip_sha256": session.snapshot.last_event_sha256,
        "pending_relative_path": pending.relative_path,
        "pending_final_relative_path": pending.final_relative_path,
        "pending_size": len(observed),
        "pending_sha256": hashlib.sha256(observed).hexdigest(),
        "action": "abandon-after-interrupted-failure-record",
    }
    try:
        return canonical_json(value) + b"\n"
    except RawArtifactError as error:  # pragma: no cover - fixed values
        raise PhysicalCollectorDriverError(
            "collector_failure_recovery_failed",
            "collector failure recovery cannot be encoded",
        ) from error


def _validate_failure_recovery_record(
    data: bytes,
    *,
    session: PhysicalCaptureSession,
    pending=None,
    observed: bytes | None = None,
    expected_state: CaptureState | None = None,
    expected_journal_tip_sha256: str | None = None,
) -> None:
    required_state = session.state if expected_state is None else expected_state
    required_journal_tip = (
        session.snapshot.last_event_sha256
        if expected_journal_tip_sha256 is None
        else expected_journal_tip_sha256
    )
    fields = {
        "schema_version",
        "document",
        "state",
        "archive_root",
        "journal_tip_sha256",
        "pending_relative_path",
        "pending_final_relative_path",
        "pending_size",
        "pending_sha256",
        "action",
    }
    try:
        value = load_json_bytes(data, "collector failure recovery")
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or canonical_json(value) + b"\n" != data
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("document") != FAILURE_RECOVERY_DOCUMENT
            or value.get("state") != required_state.value
            or value.get("archive_root")
            != session.archive.root_relative_to_target
            or value.get("journal_tip_sha256") != required_journal_tip
            or not isinstance(value.get("pending_relative_path"), str)
            or not isinstance(value.get("pending_final_relative_path"), str)
            or PurePosixPath(value["pending_relative_path"]).parent.as_posix()
            != "failures"
            or PurePosixPath(
                value["pending_final_relative_path"]
            ).parent.as_posix()
            != "failures"
            or PurePosixPath(value["pending_final_relative_path"]).name
            not in {
                Path(FAILURE_RELATIVE).name,
                *(f"{harness}-collector.json" for harness in PRODUCER_ORDER),
            }
            or type(value.get("pending_size")) is not int
            or not 0 <= value["pending_size"] <= 64 * 1024
            or not isinstance(value.get("pending_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["pending_sha256"])
            is None
            or value.get("action")
            != "abandon-after-interrupted-failure-record"
        ):
            raise RawArtifactError("collector failure recovery identity is invalid")
        pending_name = PurePosixPath(value["pending_relative_path"]).name
        final_name = PurePosixPath(value["pending_final_relative_path"]).name
        if value["pending_relative_path"] != f"failures/{pending_name}":
            raise RawArtifactError("collector failure pending path is not canonical")
        if re.fullmatch(
            rf"[.]{re.escape(final_name)}[.]pending-[0-9a-f]{{32}}",
            pending_name,
        ) is None:
            raise RawArtifactError("collector failure pending binding is invalid")
        if pending is not None and (
            value["pending_relative_path"] != pending.relative_path
            or value["pending_final_relative_path"]
            != pending.final_relative_path
        ):
            raise RawArtifactError("collector failure pending path changed")
        if observed is not None and (
            value["pending_size"] != len(observed)
            or value["pending_sha256"]
            != hashlib.sha256(observed).hexdigest()
        ):
            raise RawArtifactError("collector failure pending bytes changed")
    except (RawArtifactError, TypeError, ValueError) as error:
        raise PhysicalCollectorDriverError(
            "collector_failure_recovery_invalid",
            "collector failure recovery failed strict reopening",
        ) from error


def _write_or_reopen_failure_recovery(
    session: PhysicalCaptureSession,
    pending,
    observed: bytes,
):
    expected = _failure_recovery_bytes(session, pending, observed)
    names = _namespace_names(session.archive, "failures")
    recovery_pending = tuple(
        item
        for item in session.archive.pending_files("failures")
        if item.final_relative_path == FAILURE_RECOVERY_RELATIVE
    )
    recovery_name = Path(FAILURE_RECOVERY_RELATIVE).name
    if recovery_name in names:
        if recovery_pending:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_ambiguous",
                "failure recovery has both pending and final bytes",
            )
        data = session.archive.read_bytes(
            FAILURE_RECOVERY_RELATIVE, maximum=64 * 1024
        )
        if data != expected:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_invalid",
                "failure recovery differs from the interrupted record",
            )
    elif recovery_pending:
        if len(recovery_pending) != 1:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_ambiguous",
                "failure recovery has multiple pending publications",
            )
        candidate = recovery_pending[0]
        try:
            data = session.archive.read_pending_fragment(
                candidate, maximum=64 * 1024
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_unreadable",
                "pending failure recovery is unsafe",
            ) from error
        if data == expected:
            session.archive.publish_pending(candidate)
        elif expected.startswith(data):
            session.archive.discard_pending(candidate)
            session.archive.write_bytes(
                FAILURE_RECOVERY_RELATIVE, expected, maximum=64 * 1024
            )
        else:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_invalid",
                "pending failure recovery is not an expected write prefix",
            )
    else:
        session.archive.write_bytes(
            FAILURE_RECOVERY_RELATIVE, expected, maximum=64 * 1024
        )
    reopened = session.archive.read_bytes(
        FAILURE_RECOVERY_RELATIVE, maximum=64 * 1024
    )
    if reopened != expected:
        raise PhysicalCollectorDriverError(
            "collector_failure_recovery_invalid",
            "failure recovery changed after publication",
        )
    _validate_failure_recovery_record(
        reopened, session=session, pending=pending, observed=observed
    )
    return session.archive.describe_file(
        FAILURE_RECOVERY_RELATIVE, maximum=64 * 1024
    )


def _resume_failure_abandonment(session: PhysicalCaptureSession) -> bool:
    names = _namespace_names(session.archive, "failures")
    if not names:
        return False
    try:
        pending = session.archive.pending_files("failures")
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "collector_failure_namespace_unreadable",
            "collector failure namespace cannot be inspected",
        ) from error
    pending_names = {Path(item.relative_path).name for item in pending}
    finals = {name for name in names if name not in pending_names}
    recovery_name = Path(FAILURE_RECOVERY_RELATIVE).name
    source_finals = finals - {recovery_name}
    source_pending = tuple(
        item
        for item in pending
        if item.final_relative_path != FAILURE_RECOVERY_RELATIVE
    )
    recovery_pending = tuple(
        item
        for item in pending
        if item.final_relative_path == FAILURE_RECOVERY_RELATIVE
    )
    if len(source_finals) > 1 or len(source_pending) > 1:
        raise PhysicalCollectorDriverError(
            "collector_failure_record_ambiguous",
            "collector failure namespace is not one recoverable transaction",
        )
    allowed_source_names = {
        Path(FAILURE_RELATIVE).name,
        *(f"{harness}-collector.json" for harness in PRODUCER_ORDER),
    }
    if not source_finals <= allowed_source_names or any(
        Path(item.final_relative_path).name not in allowed_source_names
        for item in source_pending
    ):
        raise PhysicalCollectorDriverError(
            "collector_failure_record_ambiguous",
            "collector failure namespace contains an unknown source record",
        )

    if recovery_name in finals or recovery_pending:
        if source_finals:
            raise PhysicalCollectorDriverError(
                "collector_failure_recovery_ambiguous",
                "failure recovery cannot coexist with a final source failure",
            )
        if source_pending:
            source = source_pending[0]
            try:
                observed = session.archive.read_pending_fragment(
                    source, maximum=64 * 1024
                )
            except PhysicalCaptureArchiveError as error:
                raise PhysicalCollectorDriverError(
                    "collector_failure_record_unreadable",
                    "pending source failure is unsafe",
                ) from error
            recovery = _write_or_reopen_failure_recovery(
                session, source, observed
            )
            session.archive.discard_pending(source)
        else:
            if recovery_pending:
                raise PhysicalCollectorDriverError(
                    "collector_failure_recovery_ambiguous",
                    "pending recovery has no source failure bytes",
                )
            recovery = session.archive.describe_file(
                FAILURE_RECOVERY_RELATIVE, maximum=64 * 1024
            )
            data = session.archive.read_bytes(
                FAILURE_RECOVERY_RELATIVE, maximum=64 * 1024
            )
            _validate_failure_recovery_record(data, session=session)
        session.abandon(binding_sha256=recovery.sha256)
        return True

    if source_finals:
        filename = next(iter(source_finals))
        relative = f"failures/{filename}"
        data = session.archive.read_bytes(relative, maximum=64 * 1024)
        _validate_source_failure_record(
            data, filename=filename, session=session
        )
        archived = session.archive.describe_file(relative, maximum=64 * 1024)
        session.abandon(binding_sha256=archived.sha256)
        return True

    if source_pending:
        source = source_pending[0]
        try:
            observed = session.archive.read_pending_fragment(
                source, maximum=64 * 1024
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalCollectorDriverError(
                "collector_failure_record_unreadable",
                "pending source failure is unsafe",
            ) from error
        filename = Path(source.final_relative_path).name
        try:
            _validate_source_failure_record(
                observed, filename=filename, session=session
            )
        except PhysicalCollectorDriverError:
            try:
                parsed = load_json_bytes(
                    observed, "pending collector failure record"
                )
            except RawArtifactError:
                parsed = None
            if (
                isinstance(parsed, dict)
                and observed.endswith(b"\n")
                and canonical_json(parsed) + b"\n" == observed
            ):
                raise
            recovery = _write_or_reopen_failure_recovery(
                session, source, observed
            )
            session.archive.discard_pending(source)
            session.abandon(binding_sha256=recovery.sha256)
            return True
        session.archive.publish_pending(source)
        archived = session.archive.describe_file(
            source.final_relative_path, maximum=64 * 1024
        )
        session.abandon(binding_sha256=archived.sha256)
        return True
    raise PhysicalCollectorDriverError(
        "collector_failure_record_ambiguous",
        "collector failure namespace contains no recoverable source record",
    )


def _record_and_abandon(
    session: PhysicalCaptureSession, *, code: str
) -> None:
    if _ERROR_CODE_RE.fullmatch(code) is None:
        code = "unexpected_performance_failure"
    expected = {
        "schema_version": 1,
        "document": FAILURE_DOCUMENT,
        "code": code,
        "state_recorded_at": session.snapshot.last_recorded_at
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "state": session.state.value,
        "archive_root": session.archive.root_relative_to_target,
        "journal_tip_sha256": session.snapshot.last_event_sha256,
    }
    try:
        archived = _failure_record(
            session,
            relative=FAILURE_RELATIVE,
            expected=expected,
        )
        snapshot = session.abandon(binding_sha256=archived.sha256)
    except (
        PhysicalCaptureArchiveError,
        PhysicalCaptureSessionError,
        RawArtifactError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "session_abandonment_failed",
            "performance failure could not be durably recorded and abandoned",
        ) from error
    if snapshot.state is not CaptureState.ABANDONED:
        raise PhysicalCollectorDriverError(
            "session_abandonment_failed",
            "performance failure did not enter the abandoned terminal state",
        )


def _reopen_completed_performance(
    session: PhysicalCaptureSession,
) -> dict[str, dict[str, object]]:
    try:
        ledger_data = session.archive.read_bytes(
            f"{OBSERVATION_DIRECTORY}/sample-ledger.json",
            maximum=MAX_INPUT_BYTES,
        )
        ledger = load_json_bytes(ledger_data, "reopened performance ledger")
        evidence_root = (
            session.archive.repository
            / "target"
            / session.archive.root_relative_to_target
        ).absolute()
        with ArtifactReader(evidence_root) as artifacts:
            performance_contract.validate_performance_ledger(
                ledger, artifacts=artifacts
            )
        files = {
            "performance:sample-ledger": (
                "sample-ledger.json",
                performance_contract.LEDGER_KIND,
            ),
            "performance:shaping-intent": (
                "shaping-intent.json",
                performance_contract.SHAPING_KIND,
            ),
            "performance:shaping-restoration": (
                "shaping-restoration.json",
                performance_contract.SHAPING_KIND,
            ),
        }
        return {
            subject: session.archive.describe_file(
                f"{OBSERVATION_DIRECTORY}/{filename}"
            ).descriptor(kind)
            for subject, (filename, kind) in files.items()
        }
    except (
        PerformanceLedgerError,
        PhysicalCaptureArchiveError,
        RawArtifactError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "completed_performance_invalid",
            "existing completed performance observations failed strict reopening",
        ) from error


def collect_performance_session(
    *,
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> dict[str, dict[str, object]]:
    state = _performance_archive_state(session.archive)
    if state.kind == "complete":
        return _reopen_completed_performance(session)
    if state.kind == "recovery_required":
        raise PhysicalCollectorDriverError(
            "performance_recovery_required",
            "interrupted shaping must be recovered before this session is abandoned",
        )
    if state.kind == "restored_incomplete":
        _record_and_abandon(session, code="performance_ledger_interrupted")
        raise PhysicalCollectorDriverError(
            "performance_session_abandoned",
            "shaping was restored but the incomplete ledger requires a fresh session",
        )
    if state.kind != "fresh":
        raise PhysicalCollectorDriverError(
            "performance_archive_invalid",
            "performance observation namespace contains an unknown partial state",
        )
    try:
        batch: PerformanceObservationBatch = capture_performance_observations(
            session=session,
            context=context,
            parameters=parameters,
            operator=operator,
            cancelled=cancelled,
        )
    except Exception as error:
        after = _performance_archive_state(session.archive)
        if after.kind == "recovery_required":
            raise PhysicalCollectorDriverError(
                "performance_recovery_required",
                "performance failed with shaping recovery still required",
            ) from error
        _record_and_abandon(session, code=_error_code(error))
        raise PhysicalCollectorDriverError(
            "performance_session_abandoned",
            "performance capture failed and its session was abandoned",
        ) from error
    return batch.descriptor_mapping()


def _reopen_performance_recovery_state(
    session: PhysicalCaptureSession,
    state: _ArchiveState,
    *,
    journal_tip: SessionEventView,
    abandonment_recorded_at: datetime,
) -> tuple[ArchivedFile | None, RestartRecoveryStatus | None, dict[str, Any]]:
    if journal_tip.to_state is not CaptureState.COLLECTING:
        raise PhysicalCollectorDriverError(
            "recovery_state_invalid",
            "shaping recovery journal tip is not collecting",
        )
    recovery_matches = sorted(
        (
            (name, match)
            for name in state.names
            if (match := RESTART_RECOVERY_FILENAME_RE.fullmatch(name))
            is not None
        ),
        key=lambda item: item[0],
    )
    attempts = [
        int(match.group("attempt")) for _name, match in recovery_matches
    ]
    if (
        attempts != list(range(1, len(attempts) + 1))
        or len(attempts) > MAX_RESTART_RECOVERY_ATTEMPTS
    ):
        raise PhysicalCollectorDriverError(
            "recovery_state_invalid",
            "shaping recovery attempts are not a contiguous bounded sequence",
        )
    try:
        pending = session.archive.pending_files(OBSERVATION_DIRECTORY)
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCollectorDriverError(
            "recovery_state_invalid",
            "shaping recovery namespace cannot be inspected",
        ) from error
    if pending:
        raise PhysicalCollectorDriverError(
            "recovery_state_invalid",
            "shaping recovery namespace still has a pending publication",
        )
    allowed_names = {
        "shaping-intent.json",
        Path(FAILURE_RESTORATION_RELATIVE).name,
        *(name for name, _match in recovery_matches),
    }
    if (
        "shaping-intent.json" not in state.names
        or set(state.names) - allowed_names
    ):
        raise PhysicalCollectorDriverError(
            "recovery_state_invalid",
            "shaping recovery namespace has unexpected files",
        )

    context, _parameters = _load_archived_inputs(session)
    candidate = context["candidate"]
    run = context["run"]
    if not isinstance(candidate, dict) or not isinstance(run, dict):
        raise RawArtifactError("validated shaping recovery context is not an object")
    context_artifact = session.archive.describe_file(
        CONTEXT_RELATIVE, maximum=MAX_INPUT_BYTES
    )
    intent_relative = f"{OBSERVATION_DIRECTORY}/shaping-intent.json"
    intent_data = session.archive.read_bytes(
        intent_relative, maximum=MAX_INPUT_BYTES
    )
    intent = load_json_bytes(intent_data, "reopened shaping intent")
    if canonical_json(intent) + b"\n" != intent_data:
        raise RawArtifactError("reopened shaping intent is not canonical JSON")
    parsed_intent = performance_contract._intent(
        intent, candidate=candidate, run=run
    )
    if parsed_intent["captured_at"] < journal_tip.recorded_at:
        raise RawArtifactError("reopened shaping intent commands predate collection")
    intent_artifact = session.archive.describe_file(
        intent_relative, maximum=MAX_INPUT_BYTES
    )
    restoration_failure_recorded_at = None
    if Path(FAILURE_RESTORATION_RELATIVE).name in state.names:
        restoration_failure_data = session.archive.read_bytes(
            FAILURE_RESTORATION_RELATIVE,
            maximum=MAX_INPUT_BYTES,
        )
        restoration_failure_recorded_at = validate_shaping_restoration_failure(
            restoration_failure_data,
            expected_candidate=candidate,
            expected_run=run,
            expected_state=journal_tip.to_state.value,
            expected_archive_root=session.archive.root_relative_to_target,
            expected_journal_tip_sha256=journal_tip.event_sha256,
            expected_context_sha256=context_artifact.sha256,
            expected_shaping_intent_sha256=intent_artifact.sha256,
            parsed_intent=parsed_intent,
            abandonment_recorded_at=abandonment_recorded_at,
        )
    if not recovery_matches:
        return None, None, context

    recovery_records = [
        (
            attempt,
            session.archive.read_bytes(
                f"{OBSERVATION_DIRECTORY}/{name}",
                maximum=MAX_INPUT_BYTES,
            ),
        )
        for attempt, (name, _match) in zip(
            attempts, recovery_matches, strict=True
        )
    ]
    relative = f"{OBSERVATION_DIRECTORY}/{recovery_matches[-1][0]}"
    archived = session.archive.describe_file(relative, maximum=MAX_INPUT_BYTES)
    status = validate_restart_recovery_chain(
        recovery_records,
        expected_candidate=candidate,
        expected_run=run,
        expected_state=journal_tip.to_state.value,
        expected_archive_root=session.archive.root_relative_to_target,
        expected_journal_tip_sha256=journal_tip.event_sha256,
        expected_context_sha256=context_artifact.sha256,
        expected_shaping_intent_sha256=intent_artifact.sha256,
        intent_created_at=parsed_intent["created_at"],
        restoration_failure_recorded_at=restoration_failure_recorded_at,
        predecessor_recorded_at=journal_tip.recorded_at,
        abandonment_recorded_at=abandonment_recorded_at,
    )
    return archived, status, context


def _abandon_recovered_performance_session(
    session: PhysicalCaptureSession, archived: ArchivedFile
) -> dict[str, object]:
    try:
        snapshot = session.abandon(binding_sha256=archived.sha256)
    except PhysicalCaptureSessionError as error:
        raise PhysicalCollectorDriverError(
            "session_abandonment_failed",
            "recovered performance session could not be abandoned",
        ) from error
    if (
        snapshot.state is not CaptureState.ABANDONED
        or snapshot.last_binding_sha256 != archived.sha256
    ):
        raise PhysicalCollectorDriverError(
            "session_abandonment_failed",
            "recovered performance session did not bind its abandonment",
        )
    return archived.descriptor(performance_contract.SHAPING_KIND)


def recover_performance_session(
    *, session: PhysicalCaptureSession, context: object, operator: object
) -> dict[str, object]:
    del context
    state = _performance_archive_state(session.archive)
    if session.state is CaptureState.ABANDONED:
        try:
            abandonment = session.last_event_view()
            if (
                abandonment.event is not CaptureEvent.SESSION_ABANDONED
                or abandonment.from_state is not CaptureState.COLLECTING
            ):
                raise PhysicalCaptureSessionError(
                    "journal_tip_invalid",
                    "shaping recovery has no collecting abandonment predecessor",
                )
            journal_tip = session.event_view(abandonment.sequence - 1)
            if journal_tip.event_sha256 != abandonment.previous_event_sha256:
                raise PhysicalCaptureSessionError(
                    "journal_tip_invalid",
                    "shaping recovery predecessor differs from its hash chain",
                )
            archived, status, _archived_context = (
                _reopen_performance_recovery_state(
                    session,
                    state,
                    journal_tip=journal_tip,
                    abandonment_recorded_at=abandonment.recorded_at,
                )
            )
        except (
            KeyError,
            PerformanceCaptureError,
            PerformanceLedgerError,
            PhysicalCaptureArchiveError,
            PhysicalCaptureSessionError,
            PhysicalCollectorDriverError,
            RawArtifactError,
        ) as error:
            raise PhysicalCollectorDriverError(
                "recovery_abandonment_invalid",
                "abandoned shaping recovery record cannot be strictly reopened",
            ) from error
        if (
            archived is None
            or status is not RestartRecoveryStatus.COMPLETE
            or session.snapshot.last_binding_sha256 != archived.sha256
        ):
            raise PhysicalCollectorDriverError(
                "recovery_abandonment_invalid",
                "abandoned session is not bound to a complete shaping recovery",
            )
        return archived.descriptor(performance_contract.SHAPING_KIND)

    if state.kind != "recovery_required":
        raise PhysicalCollectorDriverError(
            "performance_recovery_not_required",
            "fixed shaping recovery is forbidden without an interrupted shaping record",
        )
    try:
        journal_tip = session.last_event_view()
        archived, status, archived_context = _reopen_performance_recovery_state(
            session,
            state,
            journal_tip=journal_tip,
            abandonment_recorded_at=datetime.now(timezone.utc).replace(
                microsecond=0
            ),
        )
    except (
        KeyError,
        PerformanceCaptureError,
        PerformanceLedgerError,
        PhysicalCaptureArchiveError,
        PhysicalCaptureSessionError,
        PhysicalCollectorDriverError,
        RawArtifactError,
    ) as error:
        raise PhysicalCollectorDriverError(
            "performance_recovery_state_invalid",
            "interrupted shaping recovery state cannot be strictly reopened",
        ) from error
    if status is RestartRecoveryStatus.COMPLETE:
        if archived is None:  # pragma: no cover - status implies a record
            raise PhysicalCollectorDriverError(
                "performance_recovery_state_invalid",
                "complete shaping recovery has no archived record",
            )
        return _abandon_recovered_performance_session(session, archived)

    artifact = recover_interrupted_performance_shaping(
        session=session, context=archived_context, operator=operator
    )
    refreshed_state = _performance_archive_state(session.archive)
    archived, status, _reopened_context = _reopen_performance_recovery_state(
        session,
        refreshed_state,
        journal_tip=journal_tip,
        abandonment_recorded_at=datetime.now(timezone.utc).replace(
            microsecond=0
        ),
    )
    if (
        archived is None
        or status is not RestartRecoveryStatus.COMPLETE
        or archived.sha256 != artifact.descriptor.sha256
    ):
        raise PhysicalCollectorDriverError(
            "performance_recovery_state_invalid",
            "new shaping recovery did not strictly reopen as complete",
        )
    return _abandon_recovered_performance_session(session, archived)


def _collect_adversarial_producer(
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> dict[str, dict[str, object]]:
    del context, parameters, operator, cancelled
    return capture_adversarial_observations(
        session=session
    ).descriptor_mapping()


def _collect_lifecycle_producer(
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> dict[str, dict[str, object]]:
    del parameters, operator, cancelled
    return capture_lifecycle_observations(
        session=session, context=context
    ).descriptor_mapping()


def _collect_packet_producer(
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> dict[str, dict[str, object]]:
    del parameters, operator, cancelled
    return capture_packet_observations(session=session, context=context)


def _collect_performance_producer(
    session: PhysicalCaptureSession,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> dict[str, dict[str, object]]:
    return collect_performance_session(
        session=session,
        context=context,
        parameters=parameters,
        operator=operator,
        cancelled=cancelled,
    )


PRODUCER_REGISTRY = MappingProxyType({
    "adversarial": _collect_adversarial_producer,
    "lifecycle": _collect_lifecycle_producer,
    "packet": _collect_packet_producer,
    "performance": _collect_performance_producer,
})


def _record_producer_failure(
    session: PhysicalCaptureSession, harness: str, error: BaseException
) -> None:
    if session.state is not CaptureState.COLLECTING:
        return
    code = _error_code(error)
    expected = {
        "schema_version": 1,
        "document": "cfw-physical-producer-failure-v2",
        "harness": harness,
        "code": code,
        "state_recorded_at": session.snapshot.last_recorded_at
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "state": session.state.value,
        "archive_root": session.archive.root_relative_to_target,
        "journal_tip_sha256": session.snapshot.last_event_sha256,
    }
    try:
        archived = _failure_record(
            session,
            relative=f"failures/{harness}-collector.json",
            expected=expected,
        )
        session.abandon(binding_sha256=archived.sha256)
    except (PhysicalCaptureArchiveError, PhysicalCaptureSessionError, RawArtifactError) as cleanup:
        raise PhysicalCollectorDriverError(
            "session_abandonment_failed",
            f"{harness} failure could not be durably recorded and abandoned",
        ) from cleanup


def _collect_harness_session(
    *,
    session: PhysicalCaptureSession,
    harness: str,
    context: object,
    parameters: object,
    operator: object,
    cancelled: Callable[[], bool],
) -> tuple[dict[str, dict[str, object]], bool]:
    if harness not in PRODUCER_REGISTRY:
        raise PhysicalCollectorDriverError(
            "invalid_harness", "physical producer is not source-owned"
        )
    if not session.is_terminal and _resume_failure_abandonment(session):
        raise PhysicalCollectorDriverError(
            "collector_failure_resumed",
            "a durable prior collector failure was completed as abandonment",
        )
    if session.state is CaptureState.RAW_COMPLETE:
        progress = _producer_progress(session)
        if tuple(progress.completed) != PRODUCER_ORDER or progress.started_harness:
            raise PhysicalCollectorDriverError(
                "raw_complete_transaction_invalid",
                "RAW_COMPLETED lacks the exact producer transaction closure",
            )
        manifest = session.load_observation_manifest().descriptor_mapping()
        expected_union = {
            subject: descriptor
            for producer in PRODUCER_ORDER
            for subject, descriptor in progress.completed[producer].items()
        }
        if manifest != expected_union:
            raise PhysicalCollectorDriverError(
                "raw_complete_union_invalid",
                "RAW_COMPLETED manifest differs from the producer checkpoint union",
            )
        prefix = f"raw/{harness}/observations/"
        selected = {
            subject: descriptor
            for subject, descriptor in manifest.items()
            if str(descriptor.get("path", "")).startswith(prefix)
        }
        return _normalize_producer_descriptors(harness, selected), True
    if session.state is not CaptureState.COLLECTING:
        raise PhysicalCollectorDriverError(
            "producer_collection_phase_invalid",
            f"physical producer is forbidden from state {session.state.value!r}",
        )

    try:
        _discard_safe_pending_attempt_marker(session)
        progress = _producer_progress(session)
    except PhysicalCollectorDriverError as error:
        _record_producer_failure(session, harness, error)
        raise
    completed = progress.completed
    if tuple(completed) == PRODUCER_ORDER:
        try:
            _freeze_complete_observations(session, completed)
        except BaseException as error:
            if not session.is_terminal:
                _record_producer_failure(session, harness, error)
            raise
        return completed[harness], True
    if progress.started_harness is not None:
        started_harness = progress.started_harness
        interrupted = PhysicalCollectorDriverError(
            "producer_attempt_interrupted",
            f"{started_harness} has a durable attempt without a completed checkpoint",
        )
        if started_harness == "performance":
            state = _performance_archive_state(session.archive)
            if state.kind == "recovery_required":
                raise PhysicalCollectorDriverError(
                    "performance_recovery_required",
                    "interrupted shaping must be recovered before abandonment",
                )
            if state.kind == "complete":
                if harness != started_harness:
                    raise PhysicalCollectorDriverError(
                        "producer_order_invalid",
                        "completed interrupted performance must be reopened explicitly",
                    )
                try:
                    observations = _reopen_completed_performance(session)
                    checkpoint = _write_producer_checkpoint(
                        session, started_harness, observations
                    )
                    completed = _completed_producers(session)
                    _freeze_complete_observations(session, completed)
                    return checkpoint, session.state is CaptureState.RAW_COMPLETE
                except BaseException as error:
                    if not session.is_terminal:
                        _record_producer_failure(session, harness, error)
                    raise
        _record_producer_failure(session, started_harness, interrupted)
        raise interrupted

    existing = completed.get(harness)
    if existing is not None:
        return existing, False
    next_harness = PRODUCER_ORDER[len(completed)]
    if harness != next_harness:
        raise PhysicalCollectorDriverError(
            "producer_order_invalid",
            f"next physical producer must be {next_harness!r}",
        )

    for unstarted in PRODUCER_ORDER[len(completed) :]:
        if _namespace_names(
            session.archive, f"raw/{unstarted}/observations"
        ):
            partial = PhysicalCollectorDriverError(
                "producer_partial_state",
                f"{unstarted} has raw bytes without a durable producer attempt",
            )
            _record_producer_failure(session, harness, partial)
            raise partial

    handler = PRODUCER_REGISTRY[harness]
    try:
        predecessor_sha256 = (
            ROOT_PRODUCER_CHECKPOINT_SHA256
            if not completed
            else progress.checkpoint_sha256[
                PRODUCER_ORDER[len(completed) - 1]
            ]
        )
        _write_producer_attempt(
            session,
            harness,
            predecessor_checkpoint_sha256=predecessor_sha256,
        )
        observations = handler(
            session, context, parameters, operator, cancelled
        )
        checkpoint = _write_producer_checkpoint(session, harness, observations)
        completed = _completed_producers(session)
        _freeze_complete_observations(session, completed)
        return checkpoint, session.state is CaptureState.RAW_COMPLETE
    except BaseException as error:
        if session.is_terminal:
            raise
        if (
            harness == "performance"
            and isinstance(error, PhysicalCollectorDriverError)
            and error.code == "performance_recovery_required"
        ):
            raise
        _record_producer_failure(session, harness, error)
        raise


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a finite positive number") from error
    if not math.isfinite(parsed) or not 0 < parsed <= 1_000_000:
        raise argparse.ArgumentTypeError("must be within 0 < value <= 1000000")
    return parsed


def _initialize(arguments: argparse.Namespace) -> None:
    try:
        require_current_collector_source_activation()
    except PhysicalCapturePolicyError as error:
        raise PhysicalCollectorDriverError(
            "collector_source_closure_unactivated",
            "physical collector source closure is not activated for production receipts",
        ) from error
    lane = _lane(arguments.lane)
    _require_previous_attempt_abandoned(arguments.lane, arguments.attempt)
    try:
        candidate = load_json_file(
            FINAL_CANDIDATE,
            maximum=MAX_CANDIDATE_BYTES,
            label="fixed final physical candidate",
        )
        context = initialize_context(
            candidate,
            run_id=lane["run_id"],
            clean_install_confirmed=arguments.confirm_clean_install,
        )
    except (OSError, PhysicalCollectorRequestError, RawArtifactError) as error:
        raise PhysicalCollectorDriverError(
            "collector_initialization_failed",
            "fixed final candidate or live physical lane failed initialization",
        ) from error
    if context["run"]["os"] != arguments.lane:
        raise PhysicalCollectorDriverError(
            "collector_lane_mismatch",
            "live OS does not match the selected source-owned lane",
        )
    run = context["run"]
    parameters = {
        "machine": {
            "architecture": "arm64",
            "macos_version": run["macos_version"],
            "macos_build": run["macos_build"],
            "hardware_model": run["hardware_model"],
            "machine_sha256": run["machine_sha256"],
            "clean_install": True,
        },
        "network": {
            "description": NETWORK_PROFILES[arguments.network_profile],
            "uplink_mbps": arguments.uplink_mbps,
        },
        "power": {
            "source": arguments.power_source,
            "low_power_mode": arguments.low_power_mode,
        },
    }
    try:
        performance_contract._parameters(parameters, run)
        context_bytes = canonical_json(context) + b"\n"
        parameter_bytes = canonical_json(parameters) + b"\n"
        intent_sha256 = _collector_intent_sha256(
            arguments.lane,
            arguments.attempt,
            context_bytes,
            parameter_bytes,
        )
    except (PerformanceLedgerError, RawArtifactError) as error:
        raise PhysicalCollectorDriverError(
            "collector_parameters_invalid",
            "performance parameters failed the fixed ledger contract",
        ) from error
    session = PhysicalCaptureSession.create(
        REPOSITORY,
        _session_root(arguments.lane, arguments.attempt),
        intent_sha256=intent_sha256,
    )
    try:
        session.archive.write_bytes(
            CONTEXT_RELATIVE, context_bytes, maximum=MAX_INPUT_BYTES
        )
        session.archive.write_bytes(
            PARAMETERS_RELATIVE, parameter_bytes, maximum=MAX_INPUT_BYTES
        )
        snapshot = session.append(
            CaptureEvent.COLLECTION_STARTED, binding_sha256=intent_sha256
        )
        if snapshot.state is not CaptureState.COLLECTING:
            raise PhysicalCollectorDriverError(
                "collector_initialization_failed",
                "initialized session did not enter the collecting state",
            )
    except Exception as error:
        try:
            if not session.is_terminal:
                _record_and_abandon(session, code=_error_code(error))
        finally:
            session.close()
        raise
    session.close()


def _collect(
    lane_name: str, attempt: str, harness: str
) -> tuple[dict[str, dict[str, object]], bool]:
    with PhysicalCaptureSession.open(
        REPOSITORY, _session_root(lane_name, attempt)
    ) as session, SignalCancellation() as cancellation:
        context, parameters = _load_archived_inputs(session)
        if context["run"]["os"] != lane_name:
            raise PhysicalCollectorDriverError(
                "collector_lane_mismatch",
                "archived context differs from the selected source-owned lane",
            )
        operator = TerminalPerformanceOperator(
            TerminalCheckpointPrompt(cancellation.cancelled)
        )
        return _collect_harness_session(
            session=session,
            harness=harness,
            context=context,
            parameters=parameters,
            operator=operator,
            cancelled=cancellation.cancelled,
        )


def _recover(lane_name: str, attempt: str) -> dict[str, object]:
    with PhysicalCaptureSession.recover(
        REPOSITORY, _session_root(lane_name, attempt)
    ) as session, SignalCancellation() as cancellation:
        if not session.is_terminal and _resume_failure_abandonment(session):
            raise PhysicalCollectorDriverError(
                "collector_failure_resumed",
                "a durable prior collector failure was completed as abandonment",
            )
        context, _parameters = _load_archived_inputs(session)
        if context["run"]["os"] != lane_name:
            raise PhysicalCollectorDriverError(
                "collector_lane_mismatch",
                "archived context differs from the selected source-owned lane",
            )
        operator = TerminalPerformanceOperator(
            TerminalCheckpointPrompt(cancellation.cancelled)
        )
        return recover_performance_session(
            session=session, context=context, operator=operator
        )


def _recover_journal(lane_name: str, attempt: str) -> CaptureState:
    with PhysicalCaptureSession.recover(
        REPOSITORY,
        _session_root(lane_name, attempt),
        discard_incomplete=True,
    ) as session:
        if not session.is_terminal and _resume_failure_abandonment(session):
            return session.state
        if session.state is CaptureState.INITIALIZED:
            try:
                context, parameters = _load_archived_inputs(session)
                if context["run"]["os"] != lane_name:
                    raise PhysicalCollectorDriverError(
                        "collector_lane_mismatch",
                        "archived context differs from the selected source-owned lane",
                    )
                performance_contract._parameters(
                    parameters, context["run"]
                )
                context_data = session.archive.read_bytes(
                    CONTEXT_RELATIVE, maximum=MAX_INPUT_BYTES
                )
                parameter_data = session.archive.read_bytes(
                    PARAMETERS_RELATIVE, maximum=MAX_INPUT_BYTES
                )
                intent_sha256 = _collector_intent_sha256(
                    lane_name,
                    attempt,
                    context_data,
                    parameter_data,
                )
                if session.snapshot.last_binding_sha256 != intent_sha256:
                    raise PhysicalCollectorDriverError(
                        "collector_intent_mismatch",
                        "initialized session differs from its archived input intent",
                    )
                session.append(
                    CaptureEvent.COLLECTION_STARTED,
                    binding_sha256=intent_sha256,
                )
            except (
                PhysicalCaptureArchiveError,
                PhysicalCollectorDriverError,
                PerformanceLedgerError,
                RawArtifactError,
            ) as error:
                _record_and_abandon(
                    session, code="collector_initialization_interrupted"
                )
                raise PhysicalCollectorDriverError(
                    "collector_initialization_abandoned",
                    "interrupted initialization lacked one exact recoverable input set",
                ) from error
        return session.state


def _finalize(lane_name: str, attempt: str) -> dict[str, Any]:
    with PhysicalCaptureSession.open(
        REPOSITORY, _session_root(lane_name, attempt)
    ) as session:
        context, _parameters = _load_archived_inputs(session)
        if context["run"]["os"] != lane_name:
            raise PhysicalCollectorDriverError(
                "collector_lane_mismatch",
                "archived context differs from the selected source-owned lane",
            )
        return finalize_session(session=session, context=context)


def _finalized_record(lane_name: str, attempt: str) -> dict[str, Any]:
    _require_previous_attempt_abandoned(lane_name, attempt)
    with PhysicalCaptureSession.open(
        REPOSITORY, _session_root(lane_name, attempt)
    ) as session:
        context, _parameters = _load_archived_inputs(session)
        if context["run"]["os"] != lane_name:
            raise PhysicalCollectorDriverError(
                "collector_lane_mismatch",
                "archived context differs from the selected source-owned lane",
            )
        record = load_finalized_run_record(session)
        if record.get("run", {}).get("os") != lane_name:
            raise PhysicalCollectorDriverError(
                "run_record_lane_mismatch",
                "finalized run record differs from its fixed lane",
            )
        return record


def _publish(macos15_attempt: str, current_macos_attempt: str) -> dict[str, Any]:
    records = (
        _finalized_record("macos15", macos15_attempt),
        _finalized_record("current-macos", current_macos_attempt),
    )
    return publish_physical_evidence(REPOSITORY, records)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("initialize")
    initialize.add_argument("--lane", required=True, choices=tuple(LANES))
    initialize.add_argument("--attempt", required=True, choices=ATTEMPTS)
    initialize.add_argument("--confirm-clean-install", action="store_true")
    initialize.add_argument(
        "--network-profile", required=True, choices=tuple(NETWORK_PROFILES)
    )
    initialize.add_argument("--uplink-mbps", required=True, type=_positive_float)
    initialize.add_argument(
        "--power-source", required=True, choices=POWER_SOURCES
    )
    initialize.add_argument("--low-power-mode", action="store_true")
    collect = commands.add_parser("collect")
    collect.add_argument("--lane", required=True, choices=tuple(LANES))
    collect.add_argument("--attempt", required=True, choices=ATTEMPTS)
    collect.add_argument(
        "--harness", required=True, choices=tuple(PRODUCER_REGISTRY)
    )
    recover = commands.add_parser("recover-performance")
    recover.add_argument("--lane", required=True, choices=tuple(LANES))
    recover.add_argument("--attempt", required=True, choices=ATTEMPTS)
    recover_journal = commands.add_parser("recover-journal")
    recover_journal.add_argument(
        "--lane", required=True, choices=tuple(LANES)
    )
    recover_journal.add_argument(
        "--attempt", required=True, choices=ATTEMPTS
    )
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--lane", required=True, choices=tuple(LANES))
    finalize.add_argument("--attempt", required=True, choices=ATTEMPTS)
    publish = commands.add_parser("publish")
    publish.add_argument(
        "--macos15-attempt", required=True, choices=ATTEMPTS
    )
    publish.add_argument(
        "--current-macos-attempt", required=True, choices=ATTEMPTS
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "initialize":
            _initialize(arguments)
            print(
                "initialized fixed physical session for "
                f"{arguments.lane} attempt {arguments.attempt}"
            )
        elif arguments.command == "collect":
            descriptors, raw_complete = _collect(
                arguments.lane, arguments.attempt, arguments.harness
            )
            print(
                f"{arguments.harness} observations retained: "
                f"{len(descriptors)} subjects; "
                f"raw_complete={'yes' if raw_complete else 'no'}"
            )
        elif arguments.command == "recover-performance":
            _recover(arguments.lane, arguments.attempt)
            print(
                "fixed shaping resources restored; session abandoned and a fresh "
                "full run is required"
            )
        elif arguments.command == "recover-journal":
            state = _recover_journal(arguments.lane, arguments.attempt)
            print(f"journal recovery completed in state {state.value}")
        elif arguments.command == "finalize":
            record = _finalize(arguments.lane, arguments.attempt)
            print(
                "physical run finalized: "
                f"{record['run']['os']} {record['run']['run_id']}"
            )
        elif arguments.command == "publish":
            descriptor = _publish(
                arguments.macos15_attempt, arguments.current_macos_attempt
            )
            print(
                "physical evidence published at the fixed private boundary: "
                f"{descriptor['sha256']}"
            )
        else:  # pragma: no cover - argparse owns the enum
            raise AssertionError("physical collector command dispatch drifted")
        return 0
    except (
        OSError,
        PerformanceCaptureError,
        PerformanceOperatorAdapterError,
        PhysicalCaptureArchiveError,
        PhysicalCaptureCompositionError,
        PhysicalCaptureFinalizationError,
        PhysicalCaptureSessionError,
        PhysicalCollectorDriverError,
        RawArtifactError,
    ) as error:
        print(
            f"error[{_error_code(error)}]: physical collector failed closed: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPTS",
    "LANES",
    "NETWORK_PROFILES",
    "PRODUCER_ORDER",
    "PRODUCER_REGISTRY",
    "PhysicalCollectorDriverError",
    "_collect_harness_session",
    "collect_performance_session",
    "main",
    "recover_performance_session",
]
