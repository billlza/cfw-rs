"""Crash-conservative post-nonce finalization for one physical capture run.

This module never executes a physical probe.  It reopens the immutable raw
manifest, performs the two one-shot Cloud Run transactions through the session
journal, deterministically materializes the four reports, and commits one
strictly revalidated run record.  Existing derived files are accepted only
when their bounded canonical bytes are identical to the expected document.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Final, Mapping

from scripts.harness.adversarial_clients import (
    AdversarialMatrixError,
    validate_adversarial_matrix,
)
from scripts.harness.lifecycle_matrix import (
    LifecycleMatrixError,
    validate_lifecycle_matrix,
)
from scripts.harness.packet_evidence import (
    PacketEvidenceError,
    validate_packet_evidence,
)
from scripts.harness.performance_gates import (
    PerformanceGateError,
    validate_performance_evidence,
)
from scripts.harness.physical_collector_request import (
    EXPECTED_REPORTS,
    PhysicalCollectorRequestError,
    build_nonce_request,
    build_receipt_request,
)
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    parse_descriptor,
)

from .adversarial import AdversarialCaptureError
from .archive import ArchivedFile, PhysicalCaptureArchiveError
from .cloud_run import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    CloudRunClient,
    PreSendError,
)
from .composition import (
    PhysicalCaptureCompositionError,
    compose_receipt_bindings,
    compose_run_record,
)
from .lifecycle import LifecycleCaptureError, materialize_lifecycle_events
from .materialize import (
    MaterializedReport,
    PhysicalMaterializationError,
    compose_lifecycle_report,
    compose_performance_report,
    materialize_adversarial_report,
    materialize_packet_report,
)
from .proof import PhysicalCaptureProofError, ProofMaterial, build_proof_material
from .session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
    PhysicalCaptureSessionError,
)
from .transaction import (
    NONCE_RESPONSE_RELATIVE_PATH,
    RECEIPT_REQUEST_RELATIVE_PATH,
    RECEIPT_RESPONSE_RELATIVE_PATH,
    PhysicalCaptureTransaction,
    PhysicalCaptureTransactionError,
)


SIGNING_TIME_RELATIVE: Final = "derived/report-signing-time.json"
REPORT_SET_RELATIVE: Final = "derived/report-set.json"
RECEIPT_BINDINGS_RELATIVE: Final = "derived/receipt-bindings.json"
RUN_RECORD_RELATIVE: Final = "derived/run-record.json"
REPORT_DIRECTORY: Final = "derived/reports"
SIGNING_TIME_DOCUMENT: Final = "cfw-physical-report-signing-time-v1"
REPORT_SET_DOCUMENT: Final = "cfw-physical-report-set-v1"
MAX_DERIVED_DOCUMENT_BYTES: Final = 8 * 1024 * 1024
MAX_REPORT_BYTES: Final = 4 * 1024 * 1024


class PhysicalCaptureFinalizationError(RuntimeError):
    """One post-nonce phase cannot safely advance or resume."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _archive_root(session: PhysicalCaptureSession) -> Path:
    return (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    ).absolute()


def _write_or_reopen_exact(
    session: PhysicalCaptureSession,
    relative: str,
    data: bytes,
    *,
    maximum: int,
) -> ArchivedFile:
    try:
        return session.archive.write_or_reopen_exact(
            relative, data, maximum=maximum
        )
    except PhysicalCaptureArchiveError as error:
        code = (
            "derived_archive_mismatch"
            if error.code
            in {"archive_publish_mismatch", "pending_archive_mismatch"}
            else "derived_archive_failed"
        )
        raise PhysicalCaptureFinalizationError(
            code,
            f"derived physical document could not be exactly reopened at {relative}",
        ) from error


def _write_or_reopen_json(
    session: PhysicalCaptureSession,
    relative: str,
    value: Mapping[str, Any],
    *,
    maximum: int,
) -> ArchivedFile:
    try:
        data = canonical_json(dict(value)) + b"\n"
    except RawArtifactError as error:
        raise PhysicalCaptureFinalizationError(
            "derived_document_invalid",
            f"derived physical document is not canonical at {relative}",
        ) from error
    if len(data) > maximum:
        raise PhysicalCaptureFinalizationError(
            "derived_document_too_large",
            f"derived physical document exceeds its fixed bound at {relative}",
        )
    return _write_or_reopen_exact(
        session, relative, data, maximum=maximum
    )


def _load_json(
    session: PhysicalCaptureSession,
    relative: str,
    *,
    maximum: int,
    label: str,
) -> tuple[dict[str, Any], ArchivedFile]:
    try:
        data = session.archive.read_bytes(relative, maximum=maximum)
        value = load_json_bytes(data, label)
        archived = session.archive.describe_file(relative, maximum=maximum)
        if (
            not isinstance(value, dict)
            or canonical_json(value) + b"\n" != data
            or archived != ArchivedFile(
                relative, len(data), hashlib.sha256(data).hexdigest()
            )
        ):
            raise RawArtifactError(f"{label} is not canonical stable JSON")
        return value, archived
    except (PhysicalCaptureArchiveError, RawArtifactError) as error:
        raise PhysicalCaptureFinalizationError(
            "derived_document_unreadable", f"{label} cannot be strictly reopened"
        ) from error


def _nonce_response(session: PhysicalCaptureSession) -> dict[str, Any]:
    value, _archived = _load_json(
        session,
        NONCE_RESPONSE_RELATIVE_PATH,
        maximum=MAX_RESPONSE_BYTES,
        label="archived nonce response",
    )
    return value


def _receipt_response(session: PhysicalCaptureSession) -> dict[str, Any]:
    value, _archived = _load_json(
        session,
        RECEIPT_RESPONSE_RELATIVE_PATH,
        maximum=MAX_RESPONSE_BYTES,
        label="archived receipt response",
    )
    return value


def _receipt_request(session: PhysicalCaptureSession) -> dict[str, Any]:
    value, _archived = _load_json(
        session,
        RECEIPT_REQUEST_RELATIVE_PATH,
        maximum=MAX_REQUEST_BYTES,
        label="archived receipt request",
    )
    return value


def _load_or_create_signing_time(session: PhysicalCaptureSession) -> str:
    try:
        value, _archived = _load_json(
            session,
            SIGNING_TIME_RELATIVE,
            maximum=64 * 1024,
            label="physical report signing time",
        )
    except PhysicalCaptureFinalizationError as error:
        if error.code != "derived_document_unreadable":
            raise
        value = {
            "schema_version": 1,
            "document": SIGNING_TIME_DOCUMENT,
            "signed_at": _utc_now(),
        }
        _write_or_reopen_json(
            session, SIGNING_TIME_RELATIVE, value, maximum=64 * 1024
        )
    try:
        normalized = exact_object(
            value,
            {"schema_version", "document", "signed_at"},
            "physical report signing time",
        )
    except RawArtifactError as error:
        raise PhysicalCaptureFinalizationError(
            "report_signing_time_invalid",
            "physical report signing time has an unexpected field set",
        ) from error
    if (
        type(normalized["schema_version"]) is not int
        or normalized["schema_version"] != 1
        or normalized["document"] != SIGNING_TIME_DOCUMENT
        or not isinstance(normalized["signed_at"], str)
    ):
        raise PhysicalCaptureFinalizationError(
            "report_signing_time_invalid",
            "physical report signing time identity is invalid",
        )
    try:
        parsed = datetime.fromisoformat(normalized["signed_at"][:-1] + "+00:00")
    except (ValueError, TypeError) as error:
        raise PhysicalCaptureFinalizationError(
            "report_signing_time_invalid",
            "physical report signing time is not canonical UTC",
        ) from error
    if (
        not normalized["signed_at"].endswith("Z")
        or parsed.microsecond != 0
        or parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
        != normalized["signed_at"]
        or parsed > datetime.now(timezone.utc)
    ):
        raise PhysicalCaptureFinalizationError(
            "report_signing_time_invalid",
            "physical report signing time is future-dated or non-canonical",
        )
    return normalized["signed_at"]


def _report_metadata(
    session: PhysicalCaptureSession, report: MaterializedReport
) -> dict[str, Any]:
    expected = EXPECTED_REPORTS.get(report.harness)
    if expected is None or report.tool_version != expected[0]:
        raise PhysicalCaptureFinalizationError(
            "report_identity_invalid", "materialized report identity is not source-owned"
        )
    relative = f"{REPORT_DIRECTORY}/{report.harness}.json"
    archived = _write_or_reopen_json(
        session, relative, report.document, maximum=MAX_REPORT_BYTES
    )
    descriptor = archived.descriptor(expected[1])
    try:
        return {
            "tool_version": report.tool_version,
            "captured_at": report.document["captured_at"],
            "completed_at": report.document["completed_at"],
            "signed_at": report.document["signed_at"],
            "artifact": descriptor,
        }
    except KeyError as error:
        raise PhysicalCaptureFinalizationError(
            "report_identity_invalid", "materialized report omitted its time bounds"
        ) from error


def _materialize_report_set(
    session: PhysicalCaptureSession,
    context: Mapping[str, Any],
    proof: ProofMaterial,
) -> dict[str, Any]:
    signed_at = _load_or_create_signing_time(session)
    run = context.get("run")
    if not isinstance(run, dict):
        raise PhysicalCaptureFinalizationError(
            "run_context_invalid", "physical run context omitted its platform"
        )
    platform = {
        "architecture": "arm64",
        "macos_version": run.get("macos_version"),
        "hardware_model": run.get("hardware_model"),
        "clean_install": True,
    }
    try:
        lifecycle_events = materialize_lifecycle_events(
            session=session, proof=proof.proof
        )
        evidence_root = _archive_root(session)
        reports = (
            compose_lifecycle_report(
                evidence_root=evidence_root,
                event_artifacts=lifecycle_events.descriptor_mapping(),
                signed_at=signed_at,
            ),
            materialize_packet_report(
                session=session,
                proof=proof.proof,
                platform=platform,
                signed_at=signed_at,
            ),
            compose_performance_report(
                session=session, proof=proof.proof, signed_at=signed_at
            ),
            materialize_adversarial_report(
                session=session,
                proof=proof.proof,
                platform=platform,
                signed_at=signed_at,
            ),
        )
    except (
        AdversarialCaptureError,
        LifecycleCaptureError,
        PhysicalMaterializationError,
    ) as error:
        raise PhysicalCaptureFinalizationError(
            "report_materialization_failed",
            "frozen raw observations could not materialize all four reports",
        ) from error
    report_map: dict[str, dict[str, Any]] = {}
    raw_bindings: list[dict[str, Any]] = []
    for report in reports:
        if report.harness in report_map:
            raise PhysicalCaptureFinalizationError(
                "report_identity_invalid", "materialized report harness is duplicated"
            )
        report_map[report.harness] = _report_metadata(session, report)
        raw_bindings.extend(copy.deepcopy(report.raw_bindings))
    try:
        report_names = session.archive.list_names(REPORT_DIRECTORY)
        report_pending = session.archive.pending_files(REPORT_DIRECTORY)
    except PhysicalCaptureArchiveError as error:
        raise PhysicalCaptureFinalizationError(
            "report_namespace_unreadable",
            "materialized report namespace cannot be inspected",
        ) from error
    if report_pending or set(report_names) != {
        f"{harness}.json" for harness in EXPECTED_REPORTS
    }:
        raise PhysicalCaptureFinalizationError(
            "report_namespace_invalid",
            "materialized report namespace is incomplete or has pending bytes",
        )
    if set(report_map) != set(EXPECTED_REPORTS):
        raise PhysicalCaptureFinalizationError(
            "report_identity_invalid", "materialized report set is incomplete"
        )
    return {
        "schema_version": 1,
        "document": REPORT_SET_DOCUMENT,
        "reports": report_map,
        "raw_artifacts": sorted(
            raw_bindings,
            key=lambda binding: (binding["harness"], binding["subject"]),
        ),
    }


def _validator_for(harness: str) -> Any:
    return {
        "adversarial": validate_adversarial_matrix,
        "lifecycle": validate_lifecycle_matrix,
        "packet": validate_packet_evidence,
        "performance": validate_performance_evidence,
    }[harness]


def _validate_report_set(
    session: PhysicalCaptureSession, value: Any
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    try:
        report_set = exact_object(
            value,
            {"schema_version", "document", "reports", "raw_artifacts"},
            "physical report set",
        )
    except RawArtifactError as error:
        raise PhysicalCaptureFinalizationError(
            "report_set_invalid", "physical report set has an unexpected field set"
        ) from error
    reports = report_set["reports"]
    raw_artifacts = report_set["raw_artifacts"]
    if (
        type(report_set["schema_version"]) is not int
        or report_set["schema_version"] != 1
        or report_set["document"] != REPORT_SET_DOCUMENT
        or not isinstance(reports, dict)
        or set(reports) != set(EXPECTED_REPORTS)
        or not isinstance(raw_artifacts, list)
    ):
        raise PhysicalCaptureFinalizationError(
            "report_set_invalid", "physical report set identity or closure is invalid"
        )
    try:
        normalized_bindings = compose_receipt_bindings(reports, raw_artifacts)
    except PhysicalCaptureCompositionError as error:
        raise PhysicalCaptureFinalizationError(
            "report_set_invalid", "physical report bindings failed strict composition"
        ) from error
    if raw_artifacts != normalized_bindings["raw_artifacts"]:
        raise PhysicalCaptureFinalizationError(
            "report_set_invalid",
            "physical report raw bindings are not in canonical source order",
        )

    root = _archive_root(session)
    normalized_reports: dict[str, dict[str, Any]] = {}
    try:
        with ArtifactReader(root) as artifacts:
            for harness in sorted(EXPECTED_REPORTS):
                metadata = reports[harness]
                descriptor, document = artifacts.read_json(
                    metadata["artifact"],
                    expected_kind=EXPECTED_REPORTS[harness][1],
                    label=f"materialized {harness} report",
                )
                if not isinstance(document, dict):
                    raise RawArtifactError(f"{harness} report is not an object")
                result = _validator_for(harness)(document, artifacts)
                expected_metadata = {
                    "tool_version": EXPECTED_REPORTS[harness][0],
                    "captured_at": document.get("captured_at"),
                    "completed_at": document.get("completed_at"),
                    "signed_at": document.get("signed_at"),
                    "artifact": descriptor.as_dict(),
                }
                if metadata != expected_metadata:
                    raise RawArtifactError(
                        f"{harness} report metadata differs from its bytes"
                    )
                actual_raw = sorted(
                    (
                        {
                            "harness": harness,
                            "subject": binding["subject"],
                            "descriptor": binding["descriptor"],
                        }
                        for binding in result["artifacts"]
                    ),
                    key=lambda binding: binding["subject"],
                )
                expected_raw = sorted(
                    (
                        binding
                        for binding in raw_artifacts
                        if binding.get("harness") == harness
                    ),
                    key=lambda binding: binding["subject"],
                )
                if actual_raw != expected_raw:
                    raise RawArtifactError(
                        f"{harness} raw bindings differ from report validation"
                    )
                normalized_reports[harness] = copy.deepcopy(metadata)
            artifacts.verify_all_unchanged()
    except (
        AdversarialMatrixError,
        KeyError,
        LifecycleMatrixError,
        PacketEvidenceError,
        PerformanceGateError,
        RawArtifactError,
        TypeError,
    ) as error:
        raise PhysicalCaptureFinalizationError(
            "report_set_invalid",
            "materialized reports or retained raw bindings failed reopening",
        ) from error
    return normalized_reports, copy.deepcopy(normalized_bindings["raw_artifacts"])


def _load_report_set(session: PhysicalCaptureSession) -> dict[str, Any]:
    value, _archived = _load_json(
        session,
        REPORT_SET_RELATIVE,
        maximum=MAX_DERIVED_DOCUMENT_BYTES,
        label="physical report set",
    )
    _validate_report_set(session, value)
    return value


def _ensure_reports(
    session: PhysicalCaptureSession,
    context: Mapping[str, Any],
    proof: ProofMaterial,
) -> dict[str, Any]:
    if session.state is CaptureState.NONCE_RECEIVED:
        report_set = _materialize_report_set(session, context, proof)
        _validate_report_set(session, report_set)
        archived = _write_or_reopen_json(
            session,
            REPORT_SET_RELATIVE,
            report_set,
            maximum=MAX_DERIVED_DOCUMENT_BYTES,
        )
        snapshot = session.append(
            CaptureEvent.REPORTS_COMPOSED, binding_sha256=archived.sha256
        )
        if snapshot.state is not CaptureState.REPORTS_COMPOSED:
            raise PhysicalCaptureFinalizationError(
                "report_state_invalid", "report composition entered an unsafe state"
            )
        return report_set
    return _load_report_set(session)


def _ensure_bindings(
    session: PhysicalCaptureSession, report_set: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        expected = compose_receipt_bindings(
            report_set["reports"], report_set["raw_artifacts"]
        )
    except (KeyError, PhysicalCaptureCompositionError) as error:
        raise PhysicalCaptureFinalizationError(
            "receipt_bindings_invalid", "report set cannot compose receipt bindings"
        ) from error
    if session.state is CaptureState.REPORTS_COMPOSED:
        archived = _write_or_reopen_json(
            session,
            RECEIPT_BINDINGS_RELATIVE,
            expected,
            maximum=MAX_DERIVED_DOCUMENT_BYTES,
        )
        snapshot = session.append(
            CaptureEvent.BINDINGS_COMPOSED, binding_sha256=archived.sha256
        )
        if snapshot.state is not CaptureState.BINDINGS_COMPOSED:
            raise PhysicalCaptureFinalizationError(
                "receipt_bindings_state_invalid",
                "receipt bindings entered an unsafe state",
            )
        return expected
    observed, _archived = _load_json(
        session,
        RECEIPT_BINDINGS_RELATIVE,
        maximum=MAX_DERIVED_DOCUMENT_BYTES,
        label="physical receipt bindings",
    )
    if observed != expected:
        raise PhysicalCaptureFinalizationError(
            "receipt_bindings_invalid",
            "archived receipt bindings differ from the verified report set",
        )
    return observed


def _issue_or_reopen_nonce(
    session: PhysicalCaptureSession,
    context: Mapping[str, Any],
    client: CloudRunClient | None,
) -> dict[str, Any]:
    if session.state in {
        CaptureState.RAW_COMPLETE,
        CaptureState.NONCE_REQUEST_PREPARED,
    }:
        try:
            selected_client = CloudRunClient() if client is None else client
            request = build_nonce_request(context)
            response = PhysicalCaptureTransaction(
                session, selected_client
            ).issue_nonce(request)
        except (
            OSError,
            PhysicalCollectorRequestError,
            PhysicalCaptureTransactionError,
            PreSendError,
        ) as error:
            raise PhysicalCaptureFinalizationError(
                "nonce_transaction_failed",
                "physical nonce transaction could not safely complete",
            ) from error
        return response.as_dict()
    return _nonce_response(session)


def _issue_or_reopen_receipt(
    session: PhysicalCaptureSession,
    context: Mapping[str, Any],
    nonce: Mapping[str, Any],
    bindings: Mapping[str, Any],
    client: CloudRunClient | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if session.state in {
        CaptureState.BINDINGS_COMPOSED,
        CaptureState.RECEIPT_REQUEST_PREPARED,
    }:
        try:
            selected_client = CloudRunClient() if client is None else client
            request = build_receipt_request(context, nonce, bindings)
            response = PhysicalCaptureTransaction(
                session, selected_client
            ).issue_receipt(request)
        except (
            OSError,
            PhysicalCollectorRequestError,
            PhysicalCaptureTransactionError,
            PreSendError,
        ) as error:
            raise PhysicalCaptureFinalizationError(
                "receipt_transaction_failed",
                "physical receipt transaction could not safely complete",
            ) from error
        return request, response.as_dict()
    return _receipt_request(session), _receipt_response(session)


def load_finalized_run_record(
    session: PhysicalCaptureSession,
) -> dict[str, Any]:
    if session.state is not CaptureState.FINALIZED:
        raise PhysicalCaptureFinalizationError(
            "run_not_finalized", "physical run is not in the finalized state"
        )
    value, archived = _load_json(
        session,
        RUN_RECORD_RELATIVE,
        maximum=MAX_DERIVED_DOCUMENT_BYTES,
        label="physical run record",
    )
    if session.snapshot.last_binding_sha256 != archived.sha256:
        raise PhysicalCaptureFinalizationError(
            "run_record_binding_invalid",
            "finalized session is not bound to its exact run record",
        )
    return value


def finalize_session(
    *,
    session: PhysicalCaptureSession,
    context: Mapping[str, Any],
    client: CloudRunClient | None = None,
) -> dict[str, Any]:
    """Advance or strictly resume one run from RAW_COMPLETE to FINALIZED."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PhysicalCaptureFinalizationError(
            "invalid_session", "finalization requires a locked physical session"
        )
    if session.interrupted_attempt:
        try:
            session.resolve_interrupted_attempt()
        except PhysicalCaptureSessionError as error:
            raise PhysicalCaptureFinalizationError(
                "network_outcome_recovery_failed",
                "interrupted Cloud transaction could not be closed as outcome unknown",
            ) from error
        raise PhysicalCaptureFinalizationError(
            "network_outcome_unknown",
            "interrupted Cloud transaction outcome is unknown; this attempt is terminal",
        )
    if session.state is CaptureState.FINALIZED:
        return load_finalized_run_record(session)
    allowed = {
        CaptureState.RAW_COMPLETE,
        CaptureState.NONCE_REQUEST_PREPARED,
        CaptureState.NONCE_RECEIVED,
        CaptureState.REPORTS_COMPOSED,
        CaptureState.BINDINGS_COMPOSED,
        CaptureState.RECEIPT_REQUEST_PREPARED,
        CaptureState.RECEIPT_RECEIVED,
    }
    if session.state not in allowed:
        raise PhysicalCaptureFinalizationError(
            "finalization_phase_invalid",
            f"physical finalization is forbidden from state {session.state.value!r}",
        )
    nonce = _issue_or_reopen_nonce(session, context, client)
    try:
        proof = build_proof_material(context, nonce)
    except PhysicalCaptureProofError as error:
        raise PhysicalCaptureFinalizationError(
            "proof_material_invalid",
            "archived nonce cannot derive proof for the current physical run",
        ) from error
    report_set = _ensure_reports(session, context, proof)
    _validate_report_set(session, report_set)
    bindings = _ensure_bindings(session, report_set)
    request, response = _issue_or_reopen_receipt(
        session, context, nonce, bindings, client
    )
    try:
        run_record = compose_run_record(context, request, response)
    except PhysicalCaptureCompositionError as error:
        raise PhysicalCaptureFinalizationError(
            "run_record_invalid",
            "signed receipt cannot compose a valid physical run record",
        ) from error
    archived = _write_or_reopen_json(
        session,
        RUN_RECORD_RELATIVE,
        run_record,
        maximum=MAX_DERIVED_DOCUMENT_BYTES,
    )
    if session.state is CaptureState.RECEIPT_RECEIVED:
        snapshot = session.append(
            CaptureEvent.RUN_FINALIZED, binding_sha256=archived.sha256
        )
        if snapshot.state is not CaptureState.FINALIZED:
            raise PhysicalCaptureFinalizationError(
                "run_finalization_state_invalid",
                "physical run record entered an unsafe final state",
            )
    return load_finalized_run_record(session)


__all__ = [
    "PhysicalCaptureFinalizationError",
    "RUN_RECORD_RELATIVE",
    "finalize_session",
    "load_finalized_run_record",
]
