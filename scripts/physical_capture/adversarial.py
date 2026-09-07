"""Production adversarial observation capture and post-nonce materialization.

The producer executes only source-pinned absolute helpers through
``ObservationCapture``.  Physical observations, code-signature assessments,
server log records, reset attestations, and secret-coverage manifests are
retained before nonce issuance.  The post-nonce phase only reopens the frozen
observation manifest and derives proof-bearing transcripts from those bytes.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import plistlib
import re
import stat
from typing import Any, Final, Mapping

from scripts.harness.adversarial_clients import (
    AUTHORITY_PROCESS_IMAGE_PATH,
    AUTHORITY_SIGNING_ID,
    HOST_REQUIREMENT_SHA256,
    HOST_REQUIREMENT_TEXT,
    LOG_PREDICATE,
    LOG_PREDICATE_SHA256,
    OBSERVATION_DOCUMENT,
    PRODUCT_HOST_SIGNING_ID,
    PRODUCT_OBSERVATION_CATEGORY,
    PRODUCT_OBSERVATION_PREFIX,
    PRODUCT_OBSERVATION_SUBSYSTEM,
    PRODUCT_TEAM_ID,
    PROBE_RESULT_DOCUMENT,
    REQUIRED_CASES,
    REQUIRED_RAW_SUBJECTS,
    RESET_RESULT_DOCUMENT,
    SIGNATURE_DOCUMENT,
    AdversarialMatrixError,
    build_adversarial_transcript,
    case_spec,
    expected_identity_conditions,
    validate_case_observation,
    validate_secret_coverage,
    validate_signature_observation,
)
from scripts.harness.raw_artifacts import (
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    parse_proof_binding,
    read_regular_file_bytes,
    require_sha256,
)

from .archive import ArchivedFile, PhysicalCaptureArchiveError, SecureArchive
from .execution import CommandResult, CommandSpec, ProbeExecutionError
from .observation import ObservationArtifact, ObservationCapture, PhysicalObservationError
from .session import CaptureState, PhysicalCaptureSession, PhysicalCaptureSessionError


PROBE_ROOT: Final = Path(
    "/Library/Application Support/Clash for Mac/ReleaseVerification/Adversarial"
)
STANDARD_PROBE: Final = PROBE_ROOT / "CFWAdversarialProbe"
IDENTITY_VARIANT_ROOT: Final = PROBE_ROOT / "IdentityVariants"
FIXTURE_ROOT: Final = PROBE_ROOT / "PhysicalFixtures"
CODESIGN: Final = Path("/usr/bin/codesign")
LOG: Final = Path("/usr/bin/log")
PGREP: Final = Path("/usr/bin/pgrep")
SUDO: Final = Path("/usr/bin/sudo")

OBSERVATION_DIRECTORY: Final = "raw/adversarial/observations"
TRANSCRIPT_DIRECTORY: Final = "raw/adversarial"
MAX_HELPER_OUTPUT: Final = 1024 * 1024
MAX_CODESIGN_OUTPUT: Final = 256 * 1024
MAX_LOG_OUTPUT: Final = 1024 * 1024
MAX_BINARY_BYTES: Final = 64 * 1024 * 1024
PRECONDITION_UNAVAILABLE_EXIT: Final = 69
CASE_TIMEOUT_SECONDS: Final = 60.0
DESTRUCTIVE_TIMEOUT_SECONDS: Final = 180.0
RESET_TIMEOUT_SECONDS: Final = 120.0
SIGNATURE_TIMEOUT_SECONDS: Final = 30.0
LOG_TIMEOUT_SECONDS: Final = 30.0
MAX_CASE_CONCURRENCY: Final = 1

PROBE_RESULT_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "request_sha256",
    "process",
    "euid",
    "audit_session_id",
    "pre_state_sha256",
    "post_state_sha256",
    "cleanup_state",
    "boundary_evidence",
    "secret_coverage",
    "pre_reset_state_sha256",
}
RESET_RESULT_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "post_reset_state_sha256",
    "cleanup_state",
    "contamination_detected",
}
PROCESS_FIELDS: Final = {"pid", "start_unix_ms"}
FRESHNESS_FIELDS: Final = {
    "captured_pid",
    "captured_start_unix_ms",
    "current_pid",
    "current_start_unix_ms",
    "captured_audit_session_id",
    "current_audit_session_id",
}
XPC_BOUNDARY_FIELDS: Final = {"connection_outcome", "transport_error_code"}
PRECONDITION_DOCUMENT: Final = "cfw-adversarial-precondition-unavailable-v1"
PRECONDITION_FIELDS: Final = {
    "schema_version",
    "document",
    "code",
    "case_id",
    "fixture_id",
}

# Cross-language source contract for fixtures that the signed probe refuses to
# synthesize. A typed non-zero result is diagnostic only and can never become
# an observation or satisfy the required matrix.
SOURCE_FIXED_PRECONDITIONS: Final[dict[str, str]] = {
    "wrong-uid": "root-owned-uid-launcher",
    "wrong-audit-session": "isolated-audit-session-controller",
    "stale-pid-evidence": "pid-reuse-window-controller",
    "stale-audit-evidence": "isolated-audit-session-controller",
    "inactive-console-user": "isolated-console-session-controller",
    "replayed-operation": "authority-operation-replay-controller",
    "replayed-start-ticket": "authority-operation-replay-controller",
    "duplicate-redemption": "authority-operation-replay-controller",
    "replay-cursor-rollback": "root-owned-authority-journal-snapshot",
    "authority-journal-truncation": "root-owned-authority-journal-snapshot",
    "authority-journal-tamper": "root-owned-authority-journal-snapshot",
    "authority-journal-symlink": "root-owned-authority-journal-snapshot",
    "request-flood": "bounded-authority-load-controller",
    "in-flight-saturation": "bounded-authority-load-controller",
    "event-queue-saturation": "bounded-authority-load-controller",
    "heartbeat-loss": "signed-owner-liveness-controller",
    "fast-user-switching-race": "fast-user-switch-controller",
    "late-callback": "signed-owner-liveness-controller",
    "secret-extraction-logs": "root-owned-secret-canary-scanner",
    "secret-extraction-preferences": "root-owned-secret-canary-scanner",
    "secret-extraction-journal": "root-owned-secret-canary-scanner",
    "secret-extraction-crash-records": "root-owned-secret-canary-scanner",
    "secret-extraction-snapshots": "root-owned-secret-canary-scanner",
    "secret-extraction-evidence": "root-owned-secret-canary-scanner",
}
EXTERNAL_FIXTURE_SPECS: Final[dict[str, dict[str, object]]] = {
    "authority-operation-replay-controller": {
        "target": "CFWAdversarialAuthorityOperationReplayController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialAuthorityOperationReplayController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": False,
        "reset_required": False,
    },
    "bounded-authority-load-controller": {
        "target": "CFWAdversarialBoundedAuthorityLoadController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialBoundedAuthorityLoadController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": False,
        "reset_required": False,
    },
    "fast-user-switch-controller": {
        "target": "CFWAdversarialFastUserSwitchController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialFastUserSwitchController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "isolated-audit-session-controller": {
        "target": "CFWAdversarialIsolatedAuditSessionController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialIsolatedAuditSessionController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "isolated-console-session-controller": {
        "target": "CFWAdversarialIsolatedConsoleSessionController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialIsolatedConsoleSessionController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "pid-reuse-window-controller": {
        "target": "CFWAdversarialPidReuseWindowController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialPidReuseWindowController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": False,
        "reset_required": True,
    },
    "root-owned-authority-journal-snapshot": {
        "target": "CFWAdversarialRootOwnedAuthorityJournalSnapshot",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialRootOwnedAuthorityJournalSnapshot/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "root-owned-secret-canary-scanner": {
        "target": "CFWAdversarialRootOwnedSecretCanaryScanner",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialRootOwnedSecretCanaryScanner/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "root-owned-uid-launcher": {
        "target": "CFWAdversarialRootOwnedUidLauncher",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialRootOwnedUidLauncher/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": True,
        "reset_required": True,
    },
    "signed-owner-liveness-controller": {
        "target": "CFWAdversarialSignedOwnerLivenessController",
        "source_path": "native/macos/PhysicalFixtures/CFWAdversarialSignedOwnerLivenessController/main.swift",
        "executable": "CFWAdversarialFixture",
        "privileged": False,
        "reset_required": False,
    },
}
PRIVILEGED_FIXTURES: Final = frozenset(
    fixture_id
    for fixture_id, fixture_spec in EXTERNAL_FIXTURE_SPECS.items()
    if fixture_spec["privileged"] is True
)

IDENTITY_CASES: Final = frozenset(
    case_id for case_id, spec in REQUIRED_CASES.items() if spec.category == "identity"
)
DESTRUCTIVE_CASES: Final = frozenset(
    case_id for case_id, spec in REQUIRED_CASES.items() if spec.reset_required
)
PRE_NONCE_SUBJECTS: Final = REQUIRED_RAW_SUBJECTS - {
    "baseline",
    *REQUIRED_CASES,
}

_METADATA_PATTERNS: Final = {
    "signing_id": re.compile(r"^Identifier=(?P<value>[^\r\n]+)$", re.MULTILINE),
    "team_id": re.compile(r"^TeamIdentifier=(?P<value>[^\r\n]+)$", re.MULTILINE),
    "cdhash": re.compile(r"^CDHash=(?P<value>[0-9A-Fa-f]{40,64})$", re.MULTILINE),
}
_BOOT_UUID_RE: Final = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)


class AdversarialCaptureError(RuntimeError):
    """A physical case, cleanup, or retained observation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AdversarialObservationBatch:
    artifacts: tuple[ObservationArtifact, ...]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            artifact.subject: artifact.descriptor.as_dict()
            for artifact in self.artifacts
        }


@dataclass(frozen=True, slots=True)
class AdversarialTranscriptArtifact:
    case_id: str
    archived: ArchivedFile

    def descriptor(self) -> dict[str, object]:
        return self.archived.descriptor("adversarial-transcript")


@dataclass(frozen=True, slots=True)
class AdversarialTranscriptBatch:
    artifacts: tuple[AdversarialTranscriptArtifact, ...]
    raw_bindings: tuple[dict[str, object], ...]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {artifact.case_id: artifact.descriptor() for artifact in self.artifacts}


@dataclass(frozen=True, slots=True)
class _SignatureMaterial:
    assessed_at: str
    process_image_path: str
    binary_sha256: str
    cdhash: str
    team_id: str
    signing_id: str
    designated_requirement_sha256: str
    entitlements_sha256: str
    has_required_app_group: bool
    codesign_command_sha256: str
    codesign_output_sha256: str


def _archive_root(archive: SecureArchive) -> Path:
    return (archive.repository / "target" / archive.root_relative_to_target).absolute()


def _probe_path(case_id: str) -> Path:
    fixture_id = SOURCE_FIXED_PRECONDITIONS.get(case_id)
    if fixture_id is not None:
        fixture_spec = EXTERNAL_FIXTURE_SPECS[fixture_id]
        return FIXTURE_ROOT / fixture_id / case_id / str(fixture_spec["executable"])
    if case_id in IDENTITY_CASES:
        return IDENTITY_VARIANT_ROOT / case_id / "CFWAdversarialProbe"
    return STANDARD_PROBE


def _probe_argv(case_id: str, operation: str) -> tuple[str, ...]:
    if operation not in {"execute", "reset"}:
        raise AdversarialCaptureError(
            "source_contract_drift", "adversarial fixture operation is not fixed"
        )
    fixture_id = SOURCE_FIXED_PRECONDITIONS.get(case_id)
    path = str(_probe_path(case_id))
    if fixture_id in PRIVILEGED_FIXTURES:
        return (str(SUDO), "-n", path, operation, case_id)
    return (path, operation, case_id)


def _require_source_fixed_fixture(case_id: str) -> None:
    fixture_id = SOURCE_FIXED_PRECONDITIONS.get(case_id)
    if fixture_id is None:
        return
    try:
        for directory in (
            PROBE_ROOT,
            FIXTURE_ROOT,
            FIXTURE_ROOT / fixture_id,
            FIXTURE_ROOT / fixture_id / case_id,
        ):
            directory_metadata = directory.lstat()
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != 0
                or directory_metadata.st_mode & 0o022
            ):
                raise AdversarialCaptureError(
                    "physical_precondition_unavailable",
                    f"{case_id} fixture ancestor {fixture_id} is not root-owned and immutable",
                )
        path = _probe_path(case_id)
        metadata = path.lstat()
    except OSError as error:
        raise AdversarialCaptureError(
            "physical_precondition_unavailable",
            f"{case_id} requires source-fixed fixture {fixture_id}",
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or metadata.st_mode & 0o111 == 0
    ):
        raise AdversarialCaptureError(
            "physical_precondition_unavailable",
            f"{case_id} source-fixed fixture {fixture_id} is not root-owned and immutable",
        )


def _require_privileged_fixture_ticket(
    capture: ObservationCapture, case_id: str
) -> None:
    fixture_id = SOURCE_FIXED_PRECONDITIONS.get(case_id)
    if fixture_id not in PRIVILEGED_FIXTURES:
        return
    try:
        capture.run_command(
            _command(
                role="adversarial-sudo-preflight",
                argv=(str(SUDO), "-n", "-v"),
                timeout=10.0,
                stdout_limit=0,
                stderr_limit=4096,
            )
        )
    except (
        PhysicalCaptureSessionError,
        PhysicalObservationError,
        ProbeExecutionError,
    ) as error:
        raise AdversarialCaptureError(
            "physical_precondition_unavailable",
            f"{case_id} requires an active sudo ticket for fixture {fixture_id}",
        ) from error


def _preflight_source_fixed_fixtures() -> None:
    for case_id in sorted(SOURCE_FIXED_PRECONDITIONS):
        _require_source_fixed_fixture(case_id)
    identity_paths = {
        case_id: _probe_path(case_id) for case_id in sorted(IDENTITY_CASES)
    }
    if len(set(identity_paths.values())) != len(identity_paths):
        raise AdversarialCaptureError(
            "identity_fixture_reuse",
            "identity fixtures must use ten distinct source-fixed paths",
        )
    try:
        binary_digests = {
            case_id: hashlib.sha256(
                read_regular_file_bytes(path, maximum=MAX_BINARY_BYTES)
            ).hexdigest()
            for case_id, path in identity_paths.items()
        }
    except (OSError, RawArtifactError) as error:
        raise AdversarialCaptureError(
            "identity_fixture_unavailable",
            "identity fixture bytes cannot be securely preflighted",
        ) from error
    if len(set(binary_digests.values())) != len(binary_digests):
        raise AdversarialCaptureError(
            "identity_fixture_reuse",
            "identity fixtures must use ten distinct executable byte digests",
        )


def _case_timeout(case_id: str) -> float:
    return DESTRUCTIVE_TIMEOUT_SECONDS if case_id in DESTRUCTIVE_CASES else CASE_TIMEOUT_SECONDS


def _strict_helper_json(result: CommandResult, *, label: str) -> dict[str, Any]:
    if result.stderr:
        raise AdversarialCaptureError(
            "helper_stderr_nonempty", f"{label} emitted unexpected stderr bytes"
        )
    try:
        value = load_json_bytes(result.stdout, label)
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != result.stdout:
            raise AdversarialCaptureError(
                "helper_output_noncanonical", f"{label} output is not canonical JSON"
            )
        return value
    except RawArtifactError as error:
        raise AdversarialCaptureError(
            "helper_output_invalid", f"{label} output is not strict JSON"
        ) from error


def _sha256(value: Any, label: str) -> str:
    try:
        return require_sha256(value, label)
    except RawArtifactError as error:
        raise AdversarialCaptureError("invalid_digest", str(error)) from error


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AdversarialCaptureError(
            "invalid_helper_identity", f"{label} must be a positive bounded integer"
        )
    return value


def _nonnegative_integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AdversarialCaptureError(
            "invalid_helper_identity", f"{label} must be a nonnegative bounded integer"
        )
    return value


def _parse_process(value: Any, label: str) -> dict[str, int]:
    try:
        raw = exact_object(value, PROCESS_FIELDS, label)
    except RawArtifactError as error:
        raise AdversarialCaptureError("invalid_helper_identity", str(error)) from error
    return {
        "pid": _positive_integer(raw["pid"], f"{label}.pid", 2**31 - 1),
        "start_unix_ms": _positive_integer(
            raw["start_unix_ms"], f"{label}.start_unix_ms", 9_999_999_999_999
        ),
    }


def _parse_probe_result(result: CommandResult, case_id: str) -> dict[str, Any]:
    spec = case_spec(case_id)
    try:
        raw = exact_object(
            _strict_helper_json(result, label=f"adversarial probe {case_id}"),
            PROBE_RESULT_FIELDS,
            f"adversarial probe {case_id}",
        )
    except RawArtifactError as error:
        raise AdversarialCaptureError("probe_result_invalid", str(error)) from error
    if (
        raw["schema_version"] != 1
        or raw["document"] != PROBE_RESULT_DOCUMENT
        or raw["case_id"] != case_id
        or raw["cleanup_state"] != spec.cleanup_state
    ):
        raise AdversarialCaptureError(
            "probe_result_invalid", f"{case_id} probe result differs from its source contract"
        )
    process = _parse_process(raw["process"], f"{case_id}.process")
    euid = _nonnegative_integer(raw["euid"], f"{case_id}.euid", 2**32 - 1)
    audit_session = _nonnegative_integer(
        raw["audit_session_id"], f"{case_id}.audit_session_id", 2**32 - 1
    )
    request_sha256 = _sha256(raw["request_sha256"], f"{case_id}.request_sha256")
    pre_state = _sha256(raw["pre_state_sha256"], f"{case_id}.pre_state_sha256")
    post_state = _sha256(raw["post_state_sha256"], f"{case_id}.post_state_sha256")
    if (spec.state_relation == "unchanged") != (pre_state == post_state):
        raise AdversarialCaptureError(
            "probe_state_relation_invalid", f"{case_id} state relation differs"
        )

    evidence = raw["boundary_evidence"]
    if spec.decision_source.startswith("authority_") or spec.decision_source == "secret_coverage":
        if evidence != {}:
            raise AdversarialCaptureError(
                "probe_boundary_invalid", f"{case_id} returned unexpected boundary evidence"
            )
    elif spec.decision_source == "xpc_requirement":
        try:
            parsed_evidence = exact_object(evidence, XPC_BOUNDARY_FIELDS, f"{case_id}.boundary")
        except RawArtifactError as error:
            raise AdversarialCaptureError("probe_boundary_invalid", str(error)) from error
        if parsed_evidence["connection_outcome"] != "invalidated_before_export":
            raise AdversarialCaptureError(
                "probe_boundary_invalid", f"{case_id} XPC connection was not invalidated"
            )
        if parsed_evidence["transport_error_code"] != "global_authority_interrupted":
            raise AdversarialCaptureError(
                "probe_boundary_invalid",
                f"{case_id} did not retain the actual XPC transport error",
            )
    elif spec.decision_source == "identity_freshness":
        try:
            parsed_evidence = exact_object(evidence, FRESHNESS_FIELDS, f"{case_id}.boundary")
        except RawArtifactError as error:
            raise AdversarialCaptureError("probe_boundary_invalid", str(error)) from error
        for field in ("captured_pid", "current_pid"):
            _positive_integer(parsed_evidence[field], f"{case_id}.{field}", 2**31 - 1)
        for field in ("captured_start_unix_ms", "current_start_unix_ms"):
            _positive_integer(parsed_evidence[field], f"{case_id}.{field}", 9_999_999_999_999)
        for field in ("captured_audit_session_id", "current_audit_session_id"):
            _nonnegative_integer(parsed_evidence[field], f"{case_id}.{field}", 2**32 - 1)
    else:  # pragma: no cover - guarded by the source-contract self-check
        raise AdversarialCaptureError(
            "source_contract_drift", f"unsupported decision source for {case_id}"
        )

    coverage: dict[str, Any] | None = None
    if spec.secret_surface is None:
        if raw["secret_coverage"] != {}:
            raise AdversarialCaptureError(
                "unexpected_secret_coverage", f"{case_id} returned secret coverage"
            )
    else:
        try:
            coverage = validate_secret_coverage(raw["secret_coverage"], case_id=case_id)
        except AdversarialMatrixError as error:
            raise AdversarialCaptureError(
                "secret_coverage_invalid", f"{case_id} secret coverage failed validation"
            ) from error

    reset_before = raw["pre_reset_state_sha256"]
    if spec.reset_required:
        reset_before = _sha256(reset_before, f"{case_id}.pre_reset_state_sha256")
    elif reset_before != "":
        raise AdversarialCaptureError(
            "unexpected_reset_state", f"{case_id} returned an unexpected reset state"
        )
    return {
        **raw,
        "request_sha256": request_sha256,
        "process": process,
        "euid": euid,
        "audit_session_id": audit_session,
        "pre_state_sha256": pre_state,
        "post_state_sha256": post_state,
        "boundary_evidence": copy.deepcopy(evidence),
        "secret_coverage": coverage,
        "pre_reset_state_sha256": reset_before,
    }


def _raise_precondition_unavailable(result: CommandResult, case_id: str) -> None:
    try:
        raw = exact_object(
            _strict_helper_json(
                result, label=f"adversarial precondition {case_id}"
            ),
            PRECONDITION_FIELDS,
            f"adversarial precondition {case_id}",
        )
    except RawArtifactError as error:
        raise AdversarialCaptureError(
            "precondition_result_invalid",
            f"{case_id} precondition failure is not a strict typed document",
        ) from error
    expected_fixture = SOURCE_FIXED_PRECONDITIONS.get(case_id)
    if (
        result.exit_code != PRECONDITION_UNAVAILABLE_EXIT
        or raw["schema_version"] != 1
        or raw["document"] != PRECONDITION_DOCUMENT
        or raw["code"] != "physical_precondition_unavailable"
        or raw["case_id"] != case_id
        or raw["fixture_id"] != expected_fixture
    ):
        raise AdversarialCaptureError(
            "precondition_result_invalid",
            f"{case_id} precondition failure differs from the source contract",
        )
    raise AdversarialCaptureError(
        "physical_precondition_unavailable",
        f"{case_id} requires source-fixed fixture {expected_fixture}",
    )


def _parse_reset_result(result: CommandResult, case_id: str) -> dict[str, Any]:
    try:
        raw = exact_object(
            _strict_helper_json(result, label=f"adversarial reset {case_id}"),
            RESET_RESULT_FIELDS,
            f"adversarial reset {case_id}",
        )
    except RawArtifactError as error:
        raise AdversarialCaptureError("reset_result_invalid", str(error)) from error
    if (
        raw["schema_version"] != 1
        or raw["document"] != RESET_RESULT_DOCUMENT
        or raw["case_id"] != case_id
        or raw["cleanup_state"] != "off"
        or raw["contamination_detected"] is not False
    ):
        raise AdversarialCaptureError(
            "reset_result_invalid", f"{case_id} reset did not prove a clean Off state"
        )
    return {
        **raw,
        "post_reset_state_sha256": _sha256(
            raw["post_reset_state_sha256"], f"{case_id}.post_reset_state_sha256"
        ),
    }


def _command(
    *,
    role: str,
    argv: tuple[str, ...],
    timeout: float,
    accepted_exit_codes: frozenset[int] = frozenset({0}),
    stdout_limit: int = MAX_HELPER_OUTPUT,
    stderr_limit: int = 0,
) -> CommandSpec:
    return CommandSpec(
        role=role,
        argv=argv,
        cwd=PROBE_ROOT,
        timeout_seconds=timeout,
        accepted_exit_codes=accepted_exit_codes,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )


def _execute_probe(capture: ObservationCapture, case_id: str) -> tuple[CommandResult, dict[str, Any]]:
    _require_privileged_fixture_ticket(capture, case_id)
    try:
        result = capture.run_command(
            _command(
                role="adversarial-probe",
                argv=_probe_argv(case_id, "execute"),
                timeout=_case_timeout(case_id),
                accepted_exit_codes=frozenset({0, PRECONDITION_UNAVAILABLE_EXIT}),
            )
        )
    except (PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise AdversarialCaptureError(
            "probe_execution_failed", f"fixed adversarial probe failed for {case_id}"
        ) from error
    if result.exit_code == PRECONDITION_UNAVAILABLE_EXIT:
        _raise_precondition_unavailable(result, case_id)
    return result, _parse_probe_result(result, case_id)


def _execute_reset(capture: ObservationCapture, case_id: str) -> dict[str, Any]:
    try:
        result = capture.run_command(
            _command(
                role="adversarial-reset",
                argv=_probe_argv(case_id, "reset"),
                timeout=RESET_TIMEOUT_SECONDS,
            )
        )
        return _parse_reset_result(result, case_id)
    except (
        AdversarialCaptureError,
        PhysicalCaptureSessionError,
        PhysicalObservationError,
        ProbeExecutionError,
    ) as error:
        raise AdversarialCaptureError(
            "cleanup_failed",
            f"{case_id} reset could not prove restoration; the batch is polluted",
        ) from error


def _decode_text(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AdversarialCaptureError(
            "codesign_output_invalid", f"{label} is not UTF-8"
        ) from error


def _single_metadata(text: str, field: str, *, allow_absent: bool = False) -> str:
    values = [match.group("value") for match in _METADATA_PATTERNS[field].finditer(text)]
    if allow_absent and not values:
        return ""
    if len(values) != 1 or not values[0]:
        raise AdversarialCaptureError(
            "codesign_output_invalid", f"codesign output has no unique {field}"
        )
    return values[0]


def _extract_requirement(data: bytes) -> bytes:
    text = _decode_text(data, "designated requirement output")
    marker = "designated =>"
    offset = text.find(marker)
    if offset < 0:
        raise AdversarialCaptureError(
            "codesign_output_invalid", "codesign omitted the designated requirement"
        )
    value = text[offset:].strip().encode("utf-8")
    if not value or len(value) > MAX_CODESIGN_OUTPUT:
        raise AdversarialCaptureError(
            "codesign_output_invalid", "designated requirement output is unbounded"
        )
    return value


def _extract_entitlements(data: bytes) -> tuple[bytes, bool]:
    start = data.find(b"<?xml")
    end = data.rfind(b"</plist>")
    if start < 0 or end < start:
        normalized = plistlib.dumps({}, fmt=plistlib.FMT_XML, sort_keys=True)
        return normalized, False
    xml = data[start : end + len(b"</plist>")]
    try:
        value = plistlib.loads(xml)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise AdversarialCaptureError(
            "codesign_output_invalid", "codesign entitlements are not a valid plist"
        ) from error
    if not isinstance(value, dict):
        raise AdversarialCaptureError(
            "codesign_output_invalid", "codesign entitlements are not a dictionary"
        )
    normalized = plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)
    groups = value.get("com.apple.security.application-groups")
    required = f"{PRODUCT_TEAM_ID}.group.com.bill.clashformac"
    has_required_group = isinstance(groups, list) and required in groups
    return normalized, has_required_group


def _run_codesign(
    capture: ObservationCapture,
    *,
    role: str,
    argv: tuple[str, ...],
    accepted_exit_codes: frozenset[int] = frozenset({0}),
) -> CommandResult:
    try:
        return capture.run_command(
            _command(
                role=role,
                argv=argv,
                timeout=SIGNATURE_TIMEOUT_SECONDS,
                accepted_exit_codes=accepted_exit_codes,
                stdout_limit=MAX_CODESIGN_OUTPUT,
                stderr_limit=MAX_CODESIGN_OUTPUT,
            )
        )
    except (PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise AdversarialCaptureError(
            "codesign_assessment_failed", f"fixed codesign assessment failed for {argv[-1]}"
        ) from error


def _capture_signature_material(
    capture: ObservationCapture, *, path: Path, role_prefix: str
) -> _SignatureMaterial:
    try:
        before = read_regular_file_bytes(path, maximum=MAX_BINARY_BYTES)
    except (OSError, RawArtifactError) as error:
        raise AdversarialCaptureError(
            "signed_binary_unreadable", f"cannot securely read fixed signed binary {path}"
        ) from error
    commands = (
        _run_codesign(
            capture,
            role=f"{role_prefix}-metadata",
            argv=(str(CODESIGN), "--display", "--verbose=4", str(path)),
        ),
        _run_codesign(
            capture,
            role=f"{role_prefix}-requirement",
            argv=(str(CODESIGN), "--display", "--requirements", "-", str(path)),
        ),
        _run_codesign(
            capture,
            role=f"{role_prefix}-entitlements",
            argv=(str(CODESIGN), "--display", "--entitlements", ":-", str(path)),
        ),
        _run_codesign(
            capture,
            role=f"{role_prefix}-verify",
            argv=(str(CODESIGN), "--verify", "--strict", "--verbose=4", str(path)),
        ),
    )
    try:
        after = read_regular_file_bytes(path, maximum=MAX_BINARY_BYTES)
    except (OSError, RawArtifactError) as error:
        raise AdversarialCaptureError(
            "signed_binary_unreadable", f"cannot re-read fixed signed binary {path}"
        ) from error
    if before != after:
        raise AdversarialCaptureError(
            "signed_binary_drifted", f"fixed signed binary changed during codesign assessment: {path}"
        )
    metadata = _decode_text(commands[0].stdout + commands[0].stderr, "codesign metadata")
    requirement = _extract_requirement(commands[1].stdout + commands[1].stderr)
    entitlements, required_group = _extract_entitlements(
        commands[2].stdout + commands[2].stderr
    )
    command_material = [command.argv_sha256 for command in commands]
    output_material = [
        {
            "stdout_sha256": hashlib.sha256(command.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(command.stderr).hexdigest(),
            "exit_code": command.exit_code,
        }
        for command in commands
    ]
    observed_team = _single_metadata(metadata, "team_id", allow_absent=True)
    if observed_team == "not set":
        observed_team = ""
    return _SignatureMaterial(
        assessed_at=commands[0].started_at,
        process_image_path=str(path),
        binary_sha256=hashlib.sha256(before).hexdigest(),
        cdhash=_single_metadata(metadata, "cdhash").lower(),
        team_id=observed_team,
        signing_id=_single_metadata(metadata, "signing_id"),
        designated_requirement_sha256=hashlib.sha256(requirement).hexdigest(),
        entitlements_sha256=hashlib.sha256(entitlements).hexdigest(),
        has_required_app_group=required_group,
        codesign_command_sha256=hashlib.sha256(canonical_json(command_material)).hexdigest(),
        codesign_output_sha256=hashlib.sha256(canonical_json(output_material)).hexdigest(),
    )


def _validate_client_signature_semantics(
    case_id: str,
    material: _SignatureMaterial,
    *,
    baseline_requirement_sha256: str,
) -> None:
    spec = case_spec(case_id)
    if case_id == "wrong-team-id":
        if material.team_id == PRODUCT_TEAM_ID:
            raise AdversarialCaptureError(
                "identity_precondition_missing", "wrong-team-id still uses the product Team"
            )
    elif material.team_id != PRODUCT_TEAM_ID:
        raise AdversarialCaptureError(
            "identity_precondition_missing", f"{case_id} does not use the product Team"
        )
    if case_id in {"wrong-bundle-identifier", "same-team-unknown-bundle"}:
        if material.signing_id == PRODUCT_HOST_SIGNING_ID:
            raise AdversarialCaptureError(
                "identity_precondition_missing", f"{case_id} did not vary the signing ID"
            )
    elif material.signing_id != PRODUCT_HOST_SIGNING_ID:
        raise AdversarialCaptureError(
            "identity_precondition_missing", f"{case_id} signing ID drifted"
        )
    if case_id == "wrong-entitlement":
        if material.has_required_app_group:
            raise AdversarialCaptureError(
                "identity_precondition_missing", "wrong-entitlement retains the product app group"
            )
    elif not material.has_required_app_group:
        raise AdversarialCaptureError(
            "identity_precondition_missing", f"{case_id} omits the product app group"
        )
    if case_id == "wrong-designated-requirement":
        if material.designated_requirement_sha256 == baseline_requirement_sha256:
            raise AdversarialCaptureError(
                "identity_precondition_missing", "wrong-designated-requirement did not vary"
            )
    elif case_id not in {"wrong-team-id", "wrong-bundle-identifier", "same-team-unknown-bundle"}:
        if material.designated_requirement_sha256 != baseline_requirement_sha256:
            raise AdversarialCaptureError(
                "identity_precondition_missing", f"{case_id} designated requirement drifted"
            )
    if spec.category == "identity" and spec.identity_mismatch is None:
        raise AdversarialCaptureError(
            "source_contract_drift", f"identity case {case_id} has no pinned mismatch"
        )


def _signature_document(
    *,
    case_id: str,
    kind: str,
    process: Mapping[str, int],
    material: _SignatureMaterial,
) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "document": SIGNATURE_DOCUMENT,
        "case_id": case_id,
        "kind": kind,
        "process": dict(process),
        "process_image_path": material.process_image_path,
        "binary_sha256": material.binary_sha256,
        "cdhash": material.cdhash,
        "team_id": material.team_id,
        "signing_id": material.signing_id,
        "designated_requirement_sha256": material.designated_requirement_sha256,
        "entitlements_sha256": material.entitlements_sha256,
        "conditions": expected_identity_conditions("baseline" if kind == "server" else case_id),
        "codesign_command_sha256": material.codesign_command_sha256,
        "codesign_output_sha256": material.codesign_output_sha256,
        "exit_code": 0,
        "assessed_at": material.assessed_at,
    }
    try:
        return validate_signature_observation(document, case_id=case_id, kind=kind)
    except AdversarialMatrixError as error:
        raise AdversarialCaptureError(
            "signature_observation_invalid", f"{case_id} {kind} signature is invalid"
        ) from error


def _parse_log_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AdversarialCaptureError("unified_log_invalid", f"{label} is not a timestamp")
    candidate = value.replace(" ", "T", 1)
    if candidate.endswith("Z"):
        normalized = candidate
    else:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as error:
            raise AdversarialCaptureError(
                "unified_log_invalid", f"{label} is not ISO-8601"
            ) from error
        if parsed.utcoffset() is None:
            raise AdversarialCaptureError(
                "unified_log_invalid", f"{label} has no timezone"
            )
        normalized = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
    return normalized


def _log_value(record: Mapping[str, Any], *keys: str) -> Any:
    values = [record[key] for key in keys if key in record]
    if len(values) != 1:
        raise AdversarialCaptureError(
            "unified_log_invalid", f"Unified Log record lacks one of {keys!r}"
        )
    return values[0]


def _query_product_events(
    capture: ObservationCapture,
    *,
    started_at: str,
    finished_at: str,
) -> list[dict[str, Any]]:
    result = capture.run_command(
        _command(
            role="adversarial-unified-log",
            argv=(
                str(LOG),
                "show",
                "--style",
                "ndjson",
                "--info",
                "--start",
                started_at,
                "--end",
                finished_at,
                "--predicate",
                LOG_PREDICATE,
            ),
            timeout=LOG_TIMEOUT_SECONDS,
            stdout_limit=MAX_LOG_OUTPUT,
            stderr_limit=MAX_CODESIGN_OUTPUT,
        )
    )
    records: list[dict[str, Any]] = []
    for index, line in enumerate(result.stdout.splitlines()):
        if not line:
            continue
        try:
            raw = load_json_bytes(line, f"Unified Log line {index}")
        except RawArtifactError as error:
            raise AdversarialCaptureError(
                "unified_log_invalid", "Unified Log ndjson output is malformed"
            ) from error
        if not isinstance(raw, dict):
            raise AdversarialCaptureError(
                "unified_log_invalid", "Unified Log line is not an object"
            )
        message = _log_value(raw, "eventMessage", "message")
        if not isinstance(message, str) or not message.startswith(PRODUCT_OBSERVATION_PREFIX):
            continue
        encoded = message[len(PRODUCT_OBSERVATION_PREFIX) :].encode("utf-8")
        try:
            event = load_json_bytes(encoded, f"Unified Log event {index}")
        except RawArtifactError as error:
            raise AdversarialCaptureError(
                "unified_log_invalid", "product observation event is malformed"
            ) from error
        if not isinstance(event, dict) or canonical_json(event) != encoded:
            raise AdversarialCaptureError(
                "unified_log_invalid", "product observation event is not canonical"
            )
        boot_uuid = _log_value(raw, "bootUUID", "boot_uuid")
        if not isinstance(boot_uuid, str) or _BOOT_UUID_RE.fullmatch(boot_uuid) is None:
            raise AdversarialCaptureError(
                "unified_log_invalid", "Unified Log boot UUID is invalid"
            )
        records.append(
            {
                "log": {
                    "event_type": _log_value(raw, "eventType", "event_type"),
                    "message_type": _log_value(raw, "messageType", "message_type"),
                    "subsystem": _log_value(raw, "subsystem"),
                    "category": _log_value(raw, "category"),
                    "process_image_path": _log_value(
                        raw, "processImagePath", "process_image_path"
                    ),
                    "process_id": _log_value(raw, "processID", "process_id"),
                    "boot_uuid": boot_uuid.upper(),
                    "timestamp": _parse_log_timestamp(
                        _log_value(raw, "timestamp"), f"Unified Log line {index}.timestamp"
                    ),
                    "event_message_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
                },
                "event": event,
            }
        )
    return records


def _matching_server_record(
    records: list[dict[str, Any]], *, case_id: str, request_sha256: str, peer_pid: int
) -> dict[str, Any]:
    spec = case_spec(case_id)
    selected: list[dict[str, Any]] = []
    for record in records:
        event = record["event"]
        if event.get("event") != spec.event:
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if spec.decision_source == "authority_journal":
            matches = payload.get("journal_input_sha256") == request_sha256
        elif spec.decision_source == "authority_peer":
            matches = payload.get("peer_pid") == peer_pid
        else:
            matches = (
                payload.get("peer_pid") == peer_pid
                and payload.get("request_sha256") == request_sha256
            )
        if matches:
            selected.append(record)
    if len(selected) != 1:
        raise AdversarialCaptureError(
            "server_trace_ambiguous",
            f"{case_id} has {len(selected)} matching product server observations",
        )
    return selected[0]


def _require_authority_pid(
    capture: ObservationCapture, expected_process: Mapping[str, int]
) -> None:
    try:
        result = capture.run_command(
            _command(
                role="adversarial-authority-process",
                argv=(str(PGREP), "-x", "CFWGlobalAuthority"),
                timeout=10.0,
                stdout_limit=4096,
                stderr_limit=4096,
            )
        )
        pids = {
            int(line)
            for line in _decode_text(result.stdout, "Authority process query").splitlines()
            if line
        }
    except (ValueError, PhysicalCaptureSessionError, PhysicalObservationError, ProbeExecutionError) as error:
        raise AdversarialCaptureError(
            "authority_process_unavailable", "cannot prove the running Authority process"
        ) from error
    if pids != {expected_process["pid"]}:
        raise AdversarialCaptureError(
            "authority_process_drifted", "Authority process changed between observations"
        )


def _xpc_requirement_assessment(
    capture: ObservationCapture, *, path: Path
) -> tuple[str, int]:
    result = _run_codesign(
        capture,
        role="adversarial-xpc-requirement",
        argv=(
            str(CODESIGN),
            "--verify",
            "--strict",
            f"-R={HOST_REQUIREMENT_TEXT}",
            str(path),
        ),
        accepted_exit_codes=frozenset({3}),
    )
    material = {
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "argv_sha256": result.argv_sha256,
        "exit_code": result.exit_code,
    }
    return hashlib.sha256(canonical_json(material)).hexdigest(), result.exit_code


def _boundary_record(
    *,
    case_id: str,
    probe: Mapping[str, Any],
    records: list[dict[str, Any]],
    requirement_assessment: tuple[str, int] | None,
) -> dict[str, Any]:
    spec = case_spec(case_id)
    if spec.decision_source == "xpc_requirement":
        if requirement_assessment is None:
            raise AdversarialCaptureError(
                "xpc_requirement_unproven", f"{case_id} lacks its OS requirement assessment"
            )
        accepted_count = 0
        for record in records:
            event = record["event"]
            payload = event.get("payload")
            if (
                event.get("event") == "peer_authorization_decision"
                and isinstance(payload, dict)
                and payload.get("peer_pid") == probe["process"]["pid"]
                and payload.get("accepted") is True
            ):
                accepted_count += 1
        evidence: dict[str, Any] = {
            "listener_requirement_sha256": HOST_REQUIREMENT_SHA256,
            "codesign_assessment_sha256": requirement_assessment[0],
            "codesign_exit_code": requirement_assessment[1],
            "connection_outcome": probe["boundary_evidence"]["connection_outcome"],
            "transport_error_code": probe["boundary_evidence"]["transport_error_code"],
            "accepted_event_count": accepted_count,
            "search_predicate_sha256": LOG_PREDICATE_SHA256,
        }
        document = "cfw-adversarial-xpc-requirement-result-v1"
    elif spec.decision_source == "identity_freshness":
        evidence = copy.deepcopy(probe["boundary_evidence"])
        document = "cfw-adversarial-identity-freshness-result-v1"
    elif spec.decision_source == "secret_coverage":
        evidence = {
            "coverage_subject": f"secret-coverage:{case_id}",
            "enumeration_complete": True,
        }
        document = "cfw-adversarial-secret-decision-v1"
    else:  # pragma: no cover - caller branches on the same source value
        raise AdversarialCaptureError(
            "source_contract_drift", f"{case_id} does not use a boundary record"
        )
    return {
        "schema_version": 1,
        "document": document,
        "case_id": case_id,
        "source": spec.decision_source,
        "request_sha256": probe["request_sha256"],
        "actual_code": spec.actual_code,
        "accepted": spec.accepted,
        "pre_state_sha256": probe["pre_state_sha256"],
        "post_state_sha256": probe["post_state_sha256"],
        "cleanup_state": probe["cleanup_state"],
        "evidence": evidence,
    }


def _write_observation(
    capture: ObservationCapture,
    archive: SecureArchive,
    *,
    subject: str,
    kind: str,
    filename: str,
    document: Mapping[str, Any],
) -> ObservationArtifact:
    data = canonical_json(document) + b"\n"
    artifact = capture.write_bytes(
        subject=subject,
        kind=kind,
        relative=f"{OBSERVATION_DIRECTORY}/{filename}",
        data=data,
    )
    try:
        with ArtifactReader(_archive_root(archive)) as reader:
            descriptor, reopened = reader.read(
                artifact.descriptor.as_dict(), expected_kinds={kind}, label=subject
            )
            if descriptor != artifact.descriptor or reopened != data:
                raise AdversarialCaptureError(
                    "observation_drifted", f"retained observation drifted for {subject}"
                )
            reader.verify_all_unchanged(final_path=artifact.descriptor.path)
    except RawArtifactError as error:
        raise AdversarialCaptureError(
            "observation_drifted", f"cannot securely reopen observation {subject}"
        ) from error
    return artifact


def _observation_document(
    *,
    case_id: str,
    command: CommandResult,
    probe: Mapping[str, Any],
    server_record: Mapping[str, Any],
    boundary_record: Mapping[str, Any],
    isolation: Mapping[str, Any],
) -> dict[str, Any]:
    spec = case_spec(case_id)
    document = {
        "schema_version": 1,
        "document": OBSERVATION_DOCUMENT,
        "case_id": case_id,
        "category": spec.category,
        "role": spec.role,
        "precondition": spec.precondition,
        "request_sha256": probe["request_sha256"],
        "command": {
            "role": command.role,
            "argv_sha256": command.argv_sha256,
            "started_at": command.started_at,
            "finished_at": command.completed_at,
            "duration_ms": command.duration_ms,
            "exit_code": command.exit_code,
        },
        "client_runtime": {
            "process": copy.deepcopy(probe["process"]),
            "euid": probe["euid"],
            "audit_session_id": probe["audit_session_id"],
        },
        "client_signature_subject": f"client-signature:{case_id}",
        "server_signature_subject": f"server-signature:{case_id}",
        "secret_coverage_subject": (
            f"secret-coverage:{case_id}" if spec.secret_surface is not None else ""
        ),
        "server_record": copy.deepcopy(server_record),
        "boundary_record": copy.deepcopy(boundary_record),
        "isolation": copy.deepcopy(isolation),
    }
    try:
        return validate_case_observation(document, case_id=case_id)
    except AdversarialMatrixError as error:
        raise AdversarialCaptureError(
            "case_observation_invalid", f"{case_id} observation failed its source validator"
        ) from error


def _capture_case(
    *,
    capture: ObservationCapture,
    archive: SecureArchive,
    case_id: str,
    baseline_requirement_sha256: str,
    authority_process: Mapping[str, int] | None,
) -> tuple[list[ObservationArtifact], str, dict[str, int]]:
    spec = case_spec(case_id)
    _require_source_fixed_fixture(case_id)
    client_path = _probe_path(case_id)
    client_material = _capture_signature_material(
        capture, path=client_path, role_prefix="adversarial-client-signature"
    )
    server_material = _capture_signature_material(
        capture,
        path=Path(AUTHORITY_PROCESS_IMAGE_PATH),
        role_prefix="adversarial-server-signature",
    )
    if (
        server_material.team_id != PRODUCT_TEAM_ID
        or server_material.signing_id != AUTHORITY_SIGNING_ID
    ):
        raise AdversarialCaptureError(
            "authority_signature_invalid", "installed Authority identity differs from source"
        )
    if case_id == "baseline":
        baseline_requirement_sha256 = client_material.designated_requirement_sha256
    _validate_client_signature_semantics(
        case_id,
        client_material,
        baseline_requirement_sha256=baseline_requirement_sha256,
    )

    executed = False
    reset: dict[str, Any] | None = None
    try:
        command, probe = _execute_probe(capture, case_id)
        executed = True
        records = _query_product_events(
            capture, started_at=command.started_at, finished_at=command.completed_at
        )
        if spec.reset_required:
            reset = _execute_reset(capture, case_id)
            if reset["post_reset_state_sha256"] != probe["pre_reset_state_sha256"]:
                raise AdversarialCaptureError(
                    "cleanup_failed",
                    f"{case_id} reset state differs from its pre-isolation snapshot",
                )
        if spec.decision_source.startswith("authority_"):
            server_record = _matching_server_record(
                records,
                case_id=case_id,
                request_sha256=probe["request_sha256"],
                peer_pid=probe["process"]["pid"],
            )
            event_process = _parse_process(
                server_record["event"].get("process"), f"{case_id}.server_event.process"
            )
            authority_process = event_process
            payload = server_record["event"].get("payload")
            if not isinstance(payload, dict) or any(
                payload.get(field) != probe[field]
                for field in ("pre_state_sha256", "post_state_sha256", "cleanup_state")
            ):
                raise AdversarialCaptureError(
                    "server_probe_state_mismatch",
                    f"{case_id} helper state differs from the product server record",
                )
            boundary_record: dict[str, Any] = {}
            requirement_assessment = None
        else:
            if authority_process is None:
                raise AdversarialCaptureError(
                    "authority_process_unavailable",
                    "baseline Authority observation must precede boundary-only cases",
                )
            _require_authority_pid(capture, authority_process)
            requirement_assessment = (
                _xpc_requirement_assessment(capture, path=client_path)
                if spec.decision_source == "xpc_requirement"
                else None
            )
            boundary_record = _boundary_record(
                case_id=case_id,
                probe=probe,
                records=records,
                requirement_assessment=requirement_assessment,
            )
            server_record = {}
        assert authority_process is not None
        client_signature = _signature_document(
            case_id=case_id,
            kind="client",
            process=probe["process"],
            material=client_material,
        )
        server_signature = _signature_document(
            case_id=case_id,
            kind="server",
            process=authority_process,
            material=server_material,
        )
        isolation = {
            "mode": spec.isolation_mode,
            "reset_required": spec.reset_required,
            "reset_performed": spec.reset_required,
            "reset_verified": spec.reset_required,
            "contamination_detected": False,
            "pre_reset_state_sha256": (
                probe["pre_reset_state_sha256"] if spec.reset_required else ""
            ),
            "post_reset_state_sha256": (
                reset["post_reset_state_sha256"] if reset is not None else ""
            ),
        }
        observation = _observation_document(
            case_id=case_id,
            command=command,
            probe=probe,
            server_record=server_record,
            boundary_record=boundary_record,
            isolation=isolation,
        )
        artifacts = [
            _write_observation(
                capture,
                archive,
                subject=f"client-signature:{case_id}",
                kind="adversarial-signature-observation",
                filename=f"{case_id}.client-signature.json",
                document=client_signature,
            ),
            _write_observation(
                capture,
                archive,
                subject=f"server-signature:{case_id}",
                kind="adversarial-signature-observation",
                filename=f"{case_id}.server-signature.json",
                document=server_signature,
            ),
        ]
        if probe["secret_coverage"] is not None:
            artifacts.append(
                _write_observation(
                    capture,
                    archive,
                    subject=f"secret-coverage:{case_id}",
                    kind="adversarial-secret-coverage",
                    filename=f"{case_id}.secret-coverage.json",
                    document=probe["secret_coverage"],
                )
            )
        artifacts.append(
            _write_observation(
                capture,
                archive,
                subject=f"observation:{case_id}",
                kind="adversarial-case-observation",
                filename=f"{case_id}.case.json",
                document=observation,
            )
        )
        return artifacts, baseline_requirement_sha256, dict(authority_process)
    except BaseException:
        if spec.reset_required and executed and reset is None:
            try:
                _execute_reset(capture, case_id)
            except AdversarialCaptureError as cleanup_error:
                raise AdversarialCaptureError(
                    "cleanup_failed",
                    f"{case_id} failed and emergency cleanup could not be proven",
                ) from cleanup_error
        raise


def capture_adversarial_observations(
    *, session: PhysicalCaptureSession
) -> AdversarialObservationBatch:
    """Execute the fixed 32-case matrix sequentially and retain proof-free bytes."""

    if not isinstance(session, PhysicalCaptureSession):
        raise AdversarialCaptureError(
            "invalid_session", "adversarial capture requires a locked physical session"
        )
    if MAX_CASE_CONCURRENCY != 1:
        raise AdversarialCaptureError(
            "source_contract_drift", "machine-wide adversarial cases must remain sequential"
        )
    try:
        capture = session.observation_capture()
    except PhysicalCaptureSessionError as error:
        raise AdversarialCaptureError(
            "collection_closed", "adversarial probes may run only before RAW_COMPLETED"
        ) from error
    _preflight_source_fixed_fixtures()
    artifacts: list[ObservationArtifact] = []
    baseline_requirement_sha256 = ""
    authority_process: dict[str, int] | None = None
    for case_id in ("baseline", *sorted(REQUIRED_CASES)):
        captured, baseline_requirement_sha256, authority_process = _capture_case(
            capture=capture,
            archive=session.archive,
            case_id=case_id,
            baseline_requirement_sha256=baseline_requirement_sha256,
            authority_process=authority_process,
        )
        artifacts.extend(captured)
    subjects = {artifact.subject for artifact in artifacts}
    paths = {artifact.descriptor.path for artifact in artifacts}
    digests = {artifact.descriptor.sha256 for artifact in artifacts}
    if (
        subjects != PRE_NONCE_SUBJECTS
        or len(paths) != len(artifacts)
        or len(digests) != len(artifacts)
    ):
        raise AdversarialCaptureError(
            "observation_set_invalid", "adversarial pre-nonce observation set is incomplete or reused"
        )
    session.require_collection_open()
    return AdversarialObservationBatch(tuple(artifacts))


def _read_manifest_json(
    artifacts: ArtifactReader,
    *,
    descriptor: Mapping[str, object],
    expected_kind: str,
    label: str,
) -> tuple[dict[str, object], dict[str, Any]]:
    try:
        reopened_descriptor, data = artifacts.read(
            descriptor, expected_kinds={expected_kind}, label=label
        )
        value = load_json_bytes(data, label)
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != data:
            raise AdversarialCaptureError(
                "frozen_observation_invalid", f"{label} is not canonical JSON"
            )
        return reopened_descriptor.as_dict(), value
    except RawArtifactError as error:
        raise AdversarialCaptureError(
            "frozen_observation_unreadable", f"cannot reopen frozen {label}"
        ) from error


def _require_materialization_phase(session: PhysicalCaptureSession) -> None:
    try:
        state = session.state
    except PhysicalCaptureSessionError as error:
        raise AdversarialCaptureError(
            "materialization_phase_invalid", "cannot reopen adversarial materialization session"
        ) from error
    if state is not CaptureState.NONCE_RECEIVED:
        raise AdversarialCaptureError(
            "materialization_phase_invalid",
            "adversarial transcripts may be materialized only after nonce receipt",
        )


def _write_or_reopen_exact_transcript(
    archive: SecureArchive,
    *,
    relative: str,
    data: bytes,
    maximum: int,
) -> ArchivedFile:
    """Publish once, or prove that a prior post-nonce publication is identical."""

    try:
        return archive.write_or_reopen_exact(
            relative, data, maximum=maximum
        )
    except PhysicalCaptureArchiveError as error:
        code = (
            "transcript_archive_mismatch"
            if error.code
            in {"archive_publish_mismatch", "pending_archive_mismatch"}
            else "transcript_archive_failed"
        )
        raise AdversarialCaptureError(
            code,
            f"cannot exactly archive or reopen transcript {relative}",
        ) from error


def materialize_adversarial_transcripts(
    *, session: PhysicalCaptureSession, proof: object
) -> AdversarialTranscriptBatch:
    """Reopen only the frozen manifest and derive the 33 final transcripts."""

    if not isinstance(session, PhysicalCaptureSession):
        raise AdversarialCaptureError(
            "invalid_session", "adversarial materialization requires a locked session"
        )
    _require_materialization_phase(session)
    try:
        parsed_proof = parse_proof_binding(proof, "adversarial proof")
        manifest = session.load_observation_manifest().descriptor_mapping()
    except (RawArtifactError, PhysicalCaptureSessionError, PhysicalObservationError) as error:
        raise AdversarialCaptureError(
            "frozen_manifest_invalid", "cannot reopen the frozen pre-nonce manifest"
        ) from error
    adversarial_manifest = {
        subject: descriptor
        for subject, descriptor in manifest.items()
        if isinstance(descriptor, dict)
        and str(descriptor.get("path", "")).startswith(f"{OBSERVATION_DIRECTORY}/")
    }
    if set(adversarial_manifest) != PRE_NONCE_SUBJECTS:
        raise AdversarialCaptureError(
            "frozen_manifest_invalid",
            "frozen adversarial observation subjects differ from the source contract",
        )
    archive = session.archive
    output: list[AdversarialTranscriptArtifact] = []
    raw_bindings: list[dict[str, object]] = []
    with ArtifactReader(_archive_root(archive)) as reader:
        for case_id in ("baseline", *sorted(REQUIRED_CASES)):
            observation_descriptor, observation = _read_manifest_json(
                reader,
                descriptor=adversarial_manifest[f"observation:{case_id}"],
                expected_kind="adversarial-case-observation",
                label=f"{case_id} case observation",
            )
            client_descriptor, client = _read_manifest_json(
                reader,
                descriptor=adversarial_manifest[f"client-signature:{case_id}"],
                expected_kind="adversarial-signature-observation",
                label=f"{case_id} client signature",
            )
            server_descriptor, server = _read_manifest_json(
                reader,
                descriptor=adversarial_manifest[f"server-signature:{case_id}"],
                expected_kind="adversarial-signature-observation",
                label=f"{case_id} server signature",
            )
            spec = case_spec(case_id)
            coverage_descriptor: dict[str, object] | None = None
            coverage: dict[str, Any] | None = None
            if spec.secret_surface is not None:
                coverage_descriptor, coverage = _read_manifest_json(
                    reader,
                    descriptor=adversarial_manifest[f"secret-coverage:{case_id}"],
                    expected_kind="adversarial-secret-coverage",
                    label=f"{case_id} secret coverage",
                )
            document = build_adversarial_transcript(
                case_id=case_id,
                proof=parsed_proof,
                observation_artifact=observation_descriptor,
                observation=observation,
                client_signature_artifact=client_descriptor,
                client_signature=client,
                server_signature_artifact=server_descriptor,
                server_signature=server,
                secret_coverage_artifact=coverage_descriptor,
                secret_coverage=coverage,
            )
            data = canonical_json(document) + b"\n"
            relative = f"{TRANSCRIPT_DIRECTORY}/{case_id}.json"
            archived = _write_or_reopen_exact_transcript(
                archive,
                relative=relative,
                data=data,
                maximum=1024 * 1024,
            )
            output.append(AdversarialTranscriptArtifact(case_id, archived))
            raw_bindings.extend(
                [
                    {"subject": f"observation:{case_id}", "descriptor": observation_descriptor},
                    {"subject": f"client-signature:{case_id}", "descriptor": client_descriptor},
                    {"subject": f"server-signature:{case_id}", "descriptor": server_descriptor},
                    {
                        "subject": case_id,
                        "descriptor": archived.descriptor("adversarial-transcript"),
                    },
                ]
            )
            if coverage_descriptor is not None:
                raw_bindings.append(
                    {
                        "subject": f"secret-coverage:{case_id}",
                        "descriptor": coverage_descriptor,
                    }
                )
        reader.verify_all_unchanged()
    _require_materialization_phase(session)
    if {binding["subject"] for binding in raw_bindings} != REQUIRED_RAW_SUBJECTS:
        raise AdversarialCaptureError(
            "raw_binding_set_invalid", "materialized adversarial raw binding set is incomplete"
        )
    try:
        names = session.archive.list_names(TRANSCRIPT_DIRECTORY)
        pending = session.archive.pending_files(TRANSCRIPT_DIRECTORY)
    except PhysicalCaptureArchiveError as error:
        raise AdversarialCaptureError(
            "transcript_namespace_unreadable",
            "adversarial transcript namespace cannot be inspected",
        ) from error
    expected_names = {
        "observations",
        "baseline.json",
        *(f"{case_id}.json" for case_id in REQUIRED_CASES),
    }
    if pending or set(names) != expected_names:
        raise AdversarialCaptureError(
            "transcript_namespace_invalid",
            "adversarial transcript namespace is incomplete or has pending bytes",
        )
    return AdversarialTranscriptBatch(
        tuple(output),
        tuple(sorted(raw_bindings, key=lambda binding: str(binding["subject"]))),
    )


__all__ = [
    "AdversarialCaptureError",
    "AdversarialObservationBatch",
    "AdversarialTranscriptBatch",
    "EXTERNAL_FIXTURE_SPECS",
    "MAX_CASE_CONCURRENCY",
    "SOURCE_FIXED_PRECONDITIONS",
    "capture_adversarial_observations",
    "materialize_adversarial_transcripts",
]
