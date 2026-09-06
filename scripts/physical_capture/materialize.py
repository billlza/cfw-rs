"""Deterministically materialize physical harness reports from retained raw bytes.

The functions in this module do not execute probes and do not accept a
``passed`` flag.  They derive every report field from source-pinned matrix
constants and already-retained raw artifacts, then immediately run the existing
harness validator over the proposed document.  The caller remains responsible
for publishing the returned canonical JSON through the private archive writer.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
from pathlib import Path
from typing import Any, Mapping

from scripts.harness.adversarial_clients import (
    BASELINE_SPEC,
    HARNESS_VERSION as ADVERSARIAL_VERSION,
    REQUIRED_CASES as ADVERSARIAL_CASES,
    SECRET_SURFACES as ADVERSARIAL_SECRET_SURFACES,
    case_spec as adversarial_case_spec,
    validate_adversarial_matrix,
)
from scripts.harness.lifecycle_matrix import (
    EVENT_DOCUMENT as LIFECYCLE_EVENT_DOCUMENT,
    EVENT_SCHEMA_VERSION as LIFECYCLE_EVENT_SCHEMA_VERSION,
    HARNESS_VERSION as LIFECYCLE_VERSION,
    IDENTITY_PROBE_IDS,
    PROBE_SPECS,
    validate_lifecycle_matrix,
)
from scripts.harness.packet_capture import timestamp_fraction
from scripts.harness.packet_evidence import (
    EXPECTED_PACKET_RAW_SUBJECTS,
    HARNESS_VERSION as PACKET_VERSION,
    OPTIONAL_PACKET_RAW_SUBJECTS,
    PACKET_STAGES,
    REQUIRED_CASES as PACKET_CASES,
    validate_packet_evidence,
)
from scripts.harness.performance_gates import (
    HARNESS_VERSION as PERFORMANCE_VERSION,
    PerformanceGateError,
    percentiles,
    validate_performance_evidence,
)
from scripts.harness.performance_ledger import (
    LEDGER_KIND as PERFORMANCE_LEDGER_KIND,
    LEDGER_SUBJECT as PERFORMANCE_LEDGER_SUBJECT,
    SHAPING_INTENT_SUBJECT,
    SHAPING_RESTORATION_SUBJECT,
    WEAK_NETWORK_PROFILES,
    PerformanceLedgerError,
    validate_performance_ledger,
)
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    exact_object,
    parse_proof_binding,
)

from .session import CaptureState, PhysicalCaptureSession, PhysicalCaptureSessionError


REPORT_KINDS = {
    "lifecycle": "lifecycle-report",
    "packet": "packet-report",
    "performance": "performance-report",
    "adversarial": "adversarial-report",
}
PACKET_MATERIAL_FIELDS = {
    "token",
    "window_start_token",
    "window_end_token",
    "observation_ms",
    "quic_version",
    "capture_filter_sha256",
    "capture_command_sha256",
    "send_command_sha256",
    "artifact",
    "state_artifact",
    "restore_state_artifact",
    "provenance_artifact",
    "attempt_artifact",
}
PLATFORM_FIELDS = {"architecture", "macos_version", "hardware_model", "clean_install"}


class PhysicalMaterializationError(ValueError):
    """Retained raw evidence cannot materialize one valid source-pinned report."""


@dataclass(frozen=True, slots=True)
class MaterializedReport:
    harness: str
    tool_version: str
    document: dict[str, Any]
    raw_bindings: tuple[dict[str, Any], ...]


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    try:
        return exact_object(value, fields, label)
    except RawArtifactError as error:
        raise PhysicalMaterializationError(str(error)) from error


def _proof(value: Any, label: str) -> dict[str, Any]:
    try:
        return parse_proof_binding(value, label)
    except RawArtifactError as error:
        raise PhysicalMaterializationError(str(error)) from error


def _read_json(
    artifacts: ArtifactReader,
    value: Any,
    *,
    expected_kind: str,
    label: str,
) -> tuple[Any, Any]:
    try:
        return artifacts.read_json(
            value, expected_kind=expected_kind, label=label
        )
    except RawArtifactError as error:
        raise PhysicalMaterializationError(str(error)) from error


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PhysicalMaterializationError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalMaterializationError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PhysicalMaterializationError(f"{label} must use UTC")
    return parsed


def _require_signing_time(value: Any, completed: datetime) -> str:
    signed = _timestamp(value, "signed_at")
    if signed < completed or signed > datetime.now(timezone.utc):
        raise PhysicalMaterializationError(
            "report signed_at predates raw completion or is future-dated"
        )
    return value


def _platform(value: Any) -> dict[str, Any]:
    platform = _exact(value, PLATFORM_FIELDS, "physical report platform")
    return copy.deepcopy(platform)


def _normalized_bindings(
    harness: str, values: list[dict[str, Any]]
) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "harness": harness,
            "subject": value["subject"],
            "descriptor": copy.deepcopy(value["descriptor"]),
        }
        for value in values
    )


def compose_lifecycle_report(
    *,
    evidence_root: Path,
    event_artifacts: Mapping[str, Any],
    signed_at: str,
) -> MaterializedReport:
    if set(event_artifacts) != set(PROBE_SPECS):
        raise PhysicalMaterializationError(
            "lifecycle event set differs from the source-pinned probe matrix"
        )
    probes: list[dict[str, Any]] = []
    starts: list[tuple[datetime, str]] = []
    finishes: list[tuple[datetime, str]] = []
    common_proof: dict[str, Any] | None = None
    common_environment: dict[str, Any] | None = None
    with ArtifactReader(evidence_root) as artifacts:
        for probe_id in sorted(PROBE_SPECS):
            descriptor, raw = _read_json(
                artifacts,
                event_artifacts[probe_id],
                expected_kind="lifecycle-event",
                label=f"lifecycle material.{probe_id}",
            )
            if not isinstance(raw, dict):
                raise PhysicalMaterializationError("lifecycle raw event is not an object")
            if (
                type(raw.get("schema_version")) is not int
                or raw.get("schema_version") != LIFECYCLE_EVENT_SCHEMA_VERSION
                or raw.get("document") != LIFECYCLE_EVENT_DOCUMENT
                or raw.get("probe_id") != probe_id
            ):
                raise PhysicalMaterializationError(
                    f"{probe_id} lifecycle event schema/subject differs"
                )
            proof = _proof(raw.get("proof"), f"{probe_id}.proof")
            _observation_descriptor, observation = _read_json(
                artifacts,
                raw.get("observation_artifact"),
                expected_kind="lifecycle-observation",
                label=f"lifecycle material.{probe_id}.observation",
            )
            if not isinstance(observation, dict):
                raise PhysicalMaterializationError(
                    f"{probe_id} lifecycle observation is not an object"
                )
            environment = observation.get("environment")
            if not isinstance(environment, dict):
                raise PhysicalMaterializationError(
                    f"{probe_id} lifecycle environment is not an object"
                )
            if common_proof is None:
                common_proof = proof
                common_environment = copy.deepcopy(environment)
            elif proof != common_proof or environment != common_environment:
                raise PhysicalMaterializationError(
                    "lifecycle raw events disagree on proof or environment"
                )
            attributes = (
                {} if probe_id in IDENTITY_PROBE_IDS else observation.get("attributes")
            )
            if not isinstance(attributes, dict):
                raise PhysicalMaterializationError(
                    f"{probe_id} lifecycle attributes are not an object"
                )
            started_at = observation.get("started_at")
            finished_at = observation.get("finished_at")
            starts.append(
                (_timestamp(started_at, f"{probe_id}.started_at"), started_at)
            )
            finishes.append(
                (_timestamp(finished_at, f"{probe_id}.finished_at"), finished_at)
            )
            probes.append(
                {
                    "id": probe_id,
                    "attributes": copy.deepcopy(attributes),
                    "artifact": descriptor.as_dict(),
                }
            )
        assert common_proof is not None and common_environment is not None
    _, captured_at = min(starts, key=lambda item: item[0])
    completed, completed_at = max(finishes, key=lambda item: item[0])
    document = {
        "schema_version": 4,
        "harness_version": LIFECYCLE_VERSION,
        "proof": copy.deepcopy(common_proof),
        "environment": common_environment,
        "captured_at": captured_at,
        "completed_at": completed_at,
        "signed_at": _require_signing_time(signed_at, completed),
        "probes": probes,
    }
    with ArtifactReader(evidence_root) as artifacts:
        try:
            result = validate_lifecycle_matrix(document, artifacts)
        except (RawArtifactError, ValueError) as error:
            raise PhysicalMaterializationError(
                f"materialized lifecycle report failed its source validator: {error}"
            ) from error
    return MaterializedReport(
        "lifecycle",
        LIFECYCLE_VERSION,
        document,
        _normalized_bindings("lifecycle", result["artifacts"]),
    )


def compose_packet_report(
    *,
    evidence_root: Path,
    platform: Any,
    proof: Any,
    case_material: Mapping[str, Any],
    signed_at: str,
) -> MaterializedReport:
    if set(case_material) != set(PACKET_CASES):
        raise PhysicalMaterializationError(
            "packet material differs from the source-pinned case matrix"
    )
    cases: list[dict[str, Any]] = []
    parsed_proof = _proof(proof, "packet material.proof")
    starts: list[tuple[Fraction, str]] = []
    finishes: list[tuple[Fraction, str]] = []
    with ArtifactReader(evidence_root) as artifacts:
        for case_id in sorted(PACKET_CASES):
            material = _exact(
                case_material[case_id],
                PACKET_MATERIAL_FIELDS,
                f"packet material.{case_id}",
            )
            provenance_descriptor, provenance = _read_json(
                artifacts,
                material["provenance_artifact"],
                expected_kind="packet-capture-provenance",
                label=f"packet material.{case_id}.provenance",
            )
            if not isinstance(provenance, dict):
                raise PhysicalMaterializationError(
                    f"{case_id} capture provenance is not an object"
                )
            _attempt_descriptor, attempt = _read_json(
                artifacts,
                material["attempt_artifact"],
                expected_kind="packet-send-attempt",
                label=f"packet material.{case_id}.attempt",
            )
            if not isinstance(attempt, dict):
                raise PhysicalMaterializationError(
                    f"{case_id} send attempt is not an object"
                )
            try:
                starts.append(
                    (
                        timestamp_fraction(provenance.get("started_at")),
                        provenance["started_at"],
                    )
                )
                finishes.append(
                    (
                        timestamp_fraction(attempt.get("recorded_at")),
                        attempt["recorded_at"],
                    )
                )
                restore = material["restore_state_artifact"]
                if restore is not None:
                    _restore_descriptor, restore_value = _read_json(
                        artifacts,
                        restore,
                        expected_kind="packet-product-state-observation",
                        label=f"packet material.{case_id}.restore-state",
                    )
                    recorded_ms = restore_value["event"]["recorded_unix_ms"]
                    restore_time = Fraction(recorded_ms, 1000)
                    if restore_time > finishes[-1][0]:
                        restored_at = datetime.fromtimestamp(
                            float(restore_time), timezone.utc
                        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                        finishes[-1] = (restore_time, restored_at)
            except (KeyError, TypeError, ValueError) as error:
                raise PhysicalMaterializationError(
                    f"{case_id} capture provenance has invalid timestamps"
                ) from error
            spec = PACKET_CASES[case_id]
            cases.append(
                {
                    "id": case_id,
                    "protocol": spec.protocol,
                    "family": spec.family,
                    "resolver_role": spec.resolver_role,
                    "vantage": spec.vantage,
                    "token_observed": spec.token_observed,
                    **copy.deepcopy(material),
                    "provenance_artifact": provenance_descriptor.as_dict(),
                }
            )
        _, captured_at = min(starts, key=lambda item: item[0])
        _, completed_at = max(finishes, key=lambda item: item[0])
    document = {
        "schema_version": 4,
        "harness_version": PACKET_VERSION,
        "proof": copy.deepcopy(parsed_proof),
        "platform": _platform(platform),
        "captured_at": captured_at,
        "completed_at": completed_at,
        "signed_at": _require_signing_time(
            signed_at, _timestamp(completed_at, "packet.completed_at")
        ),
        "cases": cases,
    }
    with ArtifactReader(evidence_root) as artifacts:
        try:
            result = validate_packet_evidence(document, artifacts)
        except (RawArtifactError, ValueError) as error:
            raise PhysicalMaterializationError(
                f"materialized packet report failed its source validator: {error}"
            ) from error
    return MaterializedReport(
        "packet",
        PACKET_VERSION,
        document,
        _normalized_bindings("packet", result["artifacts"]),
    )


def _packet_material_from_manifest(
    *,
    evidence_root: Path,
    descriptors: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    subjects = set(descriptors)
    if not EXPECTED_PACKET_RAW_SUBJECTS <= subjects or not subjects <= (
        EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS
    ):
        raise PhysicalMaterializationError(
            "frozen packet observations differ from the source-pinned subject matrix"
        )
    material: dict[str, dict[str, Any]] = {}
    with ArtifactReader(evidence_root) as artifacts:
        for case_id, spec in PACKET_CASES.items():
            provenance_descriptor, provenance = _read_json(
                artifacts,
                descriptors[f"{case_id}:capture-provenance"],
                expected_kind="packet-capture-provenance",
                label=f"frozen packet observation.{case_id}.provenance",
            )
            attempt_descriptor, attempt = _read_json(
                artifacts,
                descriptors[f"{case_id}:send-attempt"],
                expected_kind="packet-send-attempt",
                label=f"frozen packet observation.{case_id}.attempt",
            )
            if not isinstance(provenance, dict) or not isinstance(attempt, dict):
                raise PhysicalMaterializationError(
                    f"{case_id} frozen packet JSON is not an object"
                )
            try:
                stages = attempt["stages"]
                if not isinstance(stages, list) or len(stages) != len(PACKET_STAGES):
                    raise ValueError("sender stage count differs")
                common_flags = {
                    "--case",
                    "--stage",
                    "--protocol",
                    "--family",
                    "--resolver-role",
                    "--token",
                    "--quic-version",
                    "--absence-window-ms",
                }
                socket_flags = {
                    "--local-address",
                    "--local-port",
                    "--remote-address",
                    "--remote-port",
                }
                expected_flags = (
                    common_flags
                    if spec.protocol == "dns"
                    else common_flags | socket_flags
                )
                expected_quic = 1 if spec.protocol == "quic" else 0
                tokens: list[str] = []
                command_sha256s: list[str] = []
                for stage_name, stage in zip(PACKET_STAGES, stages, strict=True):
                    if not isinstance(stage, dict) or stage.get("stage") != stage_name:
                        raise ValueError("sender stage identity differs")
                    sender = stage["command"]
                    if not isinstance(sender, dict):
                        raise ValueError("sender command is not an object")
                    argv = sender["argv"]
                    if (
                        not isinstance(argv, list)
                        or len(argv) < 5
                        or (len(argv) - 5) % 2 != 0
                    ):
                        raise ValueError("sender argv shape differs")
                    flags = dict(zip(argv[5::2], argv[6::2], strict=True))
                    if set(flags) != expected_flags:
                        raise ValueError("sender flags differ")
                    if (
                        flags["--case"] != case_id
                        or flags["--stage"] != stage_name
                        or flags["--protocol"] != spec.protocol
                        or flags["--family"] != spec.family
                        or flags["--resolver-role"] != spec.resolver_role
                        or int(flags["--quic-version"]) != expected_quic
                    ):
                        raise ValueError("sender case identity differs")
                    token = flags["--token"]
                    command_sha256 = sender["argv_sha256"]
                    if not isinstance(token, str) or not isinstance(
                        command_sha256, str
                    ):
                        raise ValueError("sender binding type differs")
                    tokens.append(token)
                    command_sha256s.append(command_sha256)
                started = timestamp_fraction(provenance["started_at"])
                completed = timestamp_fraction(provenance["completed_at"])
                milliseconds = (completed - started) * 1000
                if milliseconds.denominator != 1:
                    raise ValueError("capture duration is not integral milliseconds")
                quic_version = provenance["quic_version"]
                material[case_id] = {
                    "token": tokens[1],
                    "window_start_token": tokens[0],
                    "window_end_token": tokens[2],
                    "observation_ms": int(milliseconds),
                    "quic_version": quic_version,
                    "capture_filter_sha256": provenance["capture_filter_sha256"],
                    "capture_command_sha256": provenance["capture_command"][
                        "argv_sha256"
                    ],
                    "send_command_sha256": hashlib.sha256(
                        canonical_json(command_sha256s)
                    ).hexdigest(),
                    "artifact": copy.deepcopy(descriptors[case_id]),
                    "state_artifact": copy.deepcopy(
                        descriptors[f"{case_id}:product-state"]
                    ),
                    "restore_state_artifact": copy.deepcopy(
                        descriptors.get(f"{case_id}:restore-state")
                    ),
                    "provenance_artifact": provenance_descriptor.as_dict(),
                    "attempt_artifact": attempt_descriptor.as_dict(),
                }
            except (KeyError, TypeError, ValueError) as error:
                raise PhysicalMaterializationError(
                    f"{case_id} frozen packet observations cannot derive report material"
                ) from error
    return material


def materialize_packet_report(
    *,
    session: PhysicalCaptureSession,
    proof: Any,
    platform: Any,
    signed_at: str,
) -> MaterializedReport:
    """Compose Packet v4 only from the session's frozen pre-nonce manifest."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PhysicalMaterializationError(
            "packet materialization requires a locked physical capture session"
        )
    if session.state is not CaptureState.NONCE_RECEIVED:
        raise PhysicalMaterializationError(
            "packet materialization is allowed only after nonce receipt"
        )
    try:
        manifest = session.load_observation_manifest()
    except PhysicalCaptureSessionError as error:
        raise PhysicalMaterializationError(
            "packet materialization cannot reopen the frozen observation manifest"
        ) from error
    packet_descriptors = {
        observation.subject: observation.descriptor.as_dict()
        for observation in manifest.observations
        if observation.descriptor.path.startswith("raw/packet/observations/")
    }
    evidence_root = (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    ).absolute()
    material = _packet_material_from_manifest(
        evidence_root=evidence_root,
        descriptors=packet_descriptors,
    )
    return compose_packet_report(
        evidence_root=evidence_root,
        platform=platform,
        proof=proof,
        case_material=material,
        signed_at=signed_at,
    )


def _performance_report_document(
    *,
    proof: Any,
    signed_at: str,
    ledger_descriptor: dict[str, Any],
    derived: dict[str, Any],
) -> dict[str, Any]:
    proof_value = _proof(proof, "performance proof")
    candidate_fields = {
        "version",
        "build_number",
        "app_manifest_sha256",
        "signed_app_tree_sha256",
        "artifact_hash_manifest_sha256",
    }
    if proof_value["candidate"] != {
        key: derived["candidate"][key] for key in candidate_fields
    } or proof_value["run_id"] != derived["run"]["run_id"]:
        raise PhysicalMaterializationError(
            "performance proof differs from the frozen proof-free ledger"
        )
    baseline = percentiles(derived["throughput"]["baseline_mbps"])["p50"]
    measured = percentiles(derived["throughput"]["measured_mbps"])["p50"]
    if baseline <= 0:
        raise PhysicalMaterializationError("performance baseline p50 is not positive")
    by_subject = {
        entry["subject"]: entry["descriptor"] for entry in derived["artifacts"]
    }
    return {
        "schema_version": 3,
        "harness_version": PERFORMANCE_VERSION,
        "captured_at": derived["captured_at"].isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "completed_at": derived["completed_at"].isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "signed_at": _require_signing_time(signed_at, derived["completed_at"]),
        "proof": copy.deepcopy(proof_value),
        "parameters": copy.deepcopy(derived["parameters"]),
        "weak_network": [
            {
                "id": profile_id,
                "control": {
                    key: value
                    for key, value in WEAK_NETWORK_PROFILES[profile_id].items()
                    if key != "pipe_id"
                },
                "recovery_ms": percentiles(derived["weak_network"][profile_id]),
            }
            for profile_id in sorted(WEAK_NETWORK_PROFILES)
        ],
        "latency": {
            field: percentiles(derived["latency"][field])
            for field in ("connect_ms", "disconnect_ms", "added_latency_percent")
        },
        "throughput": {
            "baseline_mbps": baseline,
            "measured_mbps": measured,
            "ratio_percent": 100.0 * measured / baseline,
        },
        "resources": {
            field: percentiles(derived["resources"][field])
            for field in ("active_idle_cpu_percent", "active_rss_mib")
        },
        "switch_cycle": {
            field: derived["switch_cycle"][field]
            for field in ("switch_count", "rss_growth_mib", "fd_growth")
        },
        "soak": {
            field: derived["soak"][field]
            for field in (
                "duration_hours",
                "heartbeat_count",
                "traffic_count",
                "crash_count",
            )
        },
        "ledger_artifact": copy.deepcopy(ledger_descriptor),
        "shaping_intent_artifact": copy.deepcopy(by_subject[SHAPING_INTENT_SUBJECT]),
        "shaping_restoration_artifact": copy.deepcopy(
            by_subject[SHAPING_RESTORATION_SUBJECT]
        ),
    }


def compose_performance_report(
    *,
    session: PhysicalCaptureSession,
    proof: Any,
    signed_at: str,
) -> MaterializedReport:
    """Compose Performance v3 only from the session's frozen manifest."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PhysicalMaterializationError(
            "performance materialization requires a locked physical capture session"
        )
    if session.state is not CaptureState.NONCE_RECEIVED:
        raise PhysicalMaterializationError(
            "performance materialization is allowed only after nonce receipt"
        )
    try:
        manifest = session.load_observation_manifest()
    except PhysicalCaptureSessionError as error:
        raise PhysicalMaterializationError(
            "performance materialization cannot reopen the frozen observation manifest"
        ) from error
    prefix = "performance:"
    descriptors = {
        observation.subject.removeprefix(prefix): observation.descriptor.as_dict()
        for observation in manifest.observations
        if observation.subject.startswith(prefix)
        and observation.descriptor.path.startswith("raw/performance/observations/")
    }
    required = {
        PERFORMANCE_LEDGER_SUBJECT,
        SHAPING_INTENT_SUBJECT,
        SHAPING_RESTORATION_SUBJECT,
    }
    if set(descriptors) != required:
        raise PhysicalMaterializationError(
            "frozen performance manifest has an incomplete or unknown subject set"
        )
    evidence_root = (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    ).absolute()
    with ArtifactReader(evidence_root) as artifacts:
        ledger_descriptor, ledger = _read_json(
            artifacts,
            descriptors[PERFORMANCE_LEDGER_SUBJECT],
            expected_kind=PERFORMANCE_LEDGER_KIND,
            label="frozen performance sample ledger",
        )
        if not isinstance(ledger, dict):
            raise PhysicalMaterializationError(
                "frozen performance sample ledger is not an object"
            )
        if ledger.get("shaping") != {
            "intent_artifact": descriptors[SHAPING_INTENT_SUBJECT],
            "restoration_artifact": descriptors[SHAPING_RESTORATION_SUBJECT],
        }:
            raise PhysicalMaterializationError(
                "frozen performance ledger binds different shaping observations"
            )
        try:
            derived = validate_performance_ledger(ledger, artifacts=artifacts)
        except (PerformanceLedgerError, RawArtifactError) as error:
            raise PhysicalMaterializationError(
                f"frozen performance observations are invalid: {error}"
            ) from error
    try:
        document = _performance_report_document(
            proof=proof,
            signed_at=signed_at,
            ledger_descriptor=ledger_descriptor.as_dict(),
            derived=derived,
        )
    except PerformanceGateError as error:
        raise PhysicalMaterializationError(
            f"frozen performance summaries cannot be derived: {error}"
        ) from error
    with ArtifactReader(evidence_root) as artifacts:
        try:
            result = validate_performance_evidence(document, artifacts)
        except PerformanceGateError as error:
            raise PhysicalMaterializationError(
                f"materialized performance report failed its source validator: {error}"
            ) from error
    return MaterializedReport(
        "performance",
        PERFORMANCE_VERSION,
        document,
        _normalized_bindings("performance", result["artifacts"]),
    )


def compose_adversarial_report(
    *,
    evidence_root: Path,
    platform: Any,
    transcript_artifacts: Mapping[str, Any],
    signed_at: str,
) -> MaterializedReport:
    expected_transcripts = {"baseline", *ADVERSARIAL_CASES}
    if set(transcript_artifacts) != expected_transcripts:
        raise PhysicalMaterializationError(
            "adversarial material differs from the source-pinned matrix"
        )
    proof: dict[str, Any] | None = None
    starts: list[datetime] = []
    finishes: list[datetime] = []
    coverage_entries: list[dict[str, Any]] = []
    with ArtifactReader(evidence_root) as artifacts:
        def transcript(subject: str) -> tuple[dict[str, Any], dict[str, Any]]:
            nonlocal proof
            descriptor, value = _read_json(
                artifacts,
                transcript_artifacts[subject],
                expected_kind="adversarial-transcript",
                label=f"adversarial {subject} transcript",
            )
            if not isinstance(value, dict) or value.get("case_id") != subject:
                raise PhysicalMaterializationError(
                    "adversarial transcript differs from its retained subject"
                )
            current_proof = _proof(value.get("proof"), f"{subject}.proof")
            if proof is None:
                proof = current_proof
            elif current_proof != proof:
                raise PhysicalMaterializationError(
                    "adversarial transcripts disagree on proof"
                )
            starts.append(_timestamp(value.get("started_at"), f"{subject}.started_at"))
            finishes.append(_timestamp(value.get("finished_at"), f"{subject}.finished_at"))
            return descriptor.as_dict(), value

        baseline_descriptor, _baseline_value = transcript("baseline")
        cases: list[dict[str, Any]] = []
        for case_id in sorted(ADVERSARIAL_CASES):
            descriptor, value = transcript(case_id)
            spec = adversarial_case_spec(case_id)
            coverage = value.get("secret_coverage_artifact")
            if spec.secret_surface is not None:
                if not isinstance(coverage, dict):
                    raise PhysicalMaterializationError(
                        f"{case_id} transcript secret coverage descriptor is absent"
                    )
                coverage_entries.append(
                    {"case_id": case_id, "descriptor": copy.deepcopy(coverage)}
                )
            cases.append(
                {
                    "id": case_id,
                    "category": spec.category,
                    "role": spec.role,
                    "precondition": spec.precondition,
                    "event": spec.event,
                    "artifact": descriptor,
                }
            )
        assert proof is not None
    if {entry["case_id"] for entry in coverage_entries} != set(
        ADVERSARIAL_SECRET_SURFACES
    ):
        raise PhysicalMaterializationError(
            "adversarial secret coverage differs from the source-pinned surfaces"
        )
    completed_at = max(finishes)
    document = {
        "schema_version": 3,
        "harness_version": ADVERSARIAL_VERSION,
        "proof": copy.deepcopy(proof),
        "captured_at": min(starts).isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "signed_at": _require_signing_time(signed_at, completed_at),
        "platform": _platform(platform),
        "secret_coverage_manifest_sha256": hashlib.sha256(
            canonical_json(sorted(coverage_entries, key=lambda entry: entry["case_id"]))
        ).hexdigest(),
        "baseline": {
            "id": "baseline",
            "category": BASELINE_SPEC.category,
            "role": BASELINE_SPEC.role,
            "precondition": BASELINE_SPEC.precondition,
            "event": BASELINE_SPEC.event,
            "artifact": baseline_descriptor,
        },
        "cases": cases,
    }
    with ArtifactReader(evidence_root) as artifacts:
        try:
            result = validate_adversarial_matrix(document, artifacts)
        except (RawArtifactError, ValueError) as error:
            raise PhysicalMaterializationError(
                f"materialized adversarial report failed its source validator: {error}"
            ) from error
    return MaterializedReport(
        "adversarial",
        ADVERSARIAL_VERSION,
        document,
        _normalized_bindings("adversarial", result["artifacts"]),
    )


def materialize_adversarial_report(
    *,
    session: PhysicalCaptureSession,
    proof: Any,
    platform: Any,
    signed_at: str,
) -> MaterializedReport:
    """Derive Adversarial v3 from the frozen manifest without rerunning probes."""

    from .adversarial import (
        AdversarialCaptureError,
        materialize_adversarial_transcripts,
    )

    try:
        batch = materialize_adversarial_transcripts(session=session, proof=proof)
    except AdversarialCaptureError as error:
        raise PhysicalMaterializationError(
            f"adversarial frozen transcript materialization failed: {error}"
        ) from error
    evidence_root = (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    ).absolute()
    return compose_adversarial_report(
        evidence_root=evidence_root,
        platform=platform,
        transcript_artifacts=batch.descriptor_mapping(),
        signed_at=signed_at,
    )
