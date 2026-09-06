#!/usr/bin/env python3
"""Strict proof-to-byte validation for the installed adversarial matrix.

The source-pinned case table is the sole place that assigns matrix semantics.
Reports cannot declare their own expected outcome.  Every final transcript is
recomputed from one immutable pre-nonce case observation, independent client
and server code-signature observations, the matching product-owned Unified Log
record, and (for secret cases) a complete canary coverage manifest.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Final, Mapping

if __package__:
    from .physical_machine_identity import (
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .raw_artifacts import (
        ArtifactDescriptor,
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_file,
        parse_descriptor,
        parse_proof_binding,
        require_sha256,
    )
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from physical_machine_identity import (  # type: ignore
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from raw_artifacts import (  # type: ignore
        ArtifactDescriptor,
        ArtifactReader,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_file,
        parse_descriptor,
        parse_proof_binding,
        require_sha256,
    )


SCHEMA_VERSION: Final = 3
HARNESS_VERSION: Final = "adversarial-clients-v3"
PRODUCT_VERSION: Final = "0.4.0"
MAX_REPORT_BYTES: Final = 1 * 1024 * 1024
MAX_OBSERVATION_BYTES: Final = 1 * 1024 * 1024
MAX_SIGNATURE_BYTES: Final = 256 * 1024
MAX_COVERAGE_BYTES: Final = 1 * 1024 * 1024

PRODUCT_TEAM_ID: Final = "YKUPL7Z869"
PRODUCT_HOST_SIGNING_ID: Final = "com.bill.clashformac"
AUTHORITY_SIGNING_ID: Final = "com.bill.clashformac.global-authority"
AUTHORITY_PROCESS_IMAGE_PATH: Final = (
    "/Applications/Clash for Mac.app/Contents/Library/HelperTools/CFWGlobalAuthority"
)

OBSERVATION_DOCUMENT: Final = "cfw-adversarial-case-observation-v1"
SIGNATURE_DOCUMENT: Final = "cfw-adversarial-signature-observation-v1"
COVERAGE_DOCUMENT: Final = "cfw-adversarial-secret-coverage-v1"
PRODUCT_OBSERVATION_DOCUMENT: Final = "cfw-product-observation-event-v1"
PRODUCT_OBSERVATION_PREFIX: Final = "cfw-release-observation-v1 "
PRODUCT_OBSERVATION_SUBSYSTEM: Final = "com.bill.clashformac"
PRODUCT_OBSERVATION_CATEGORY: Final = "release-observation"
PRODUCT_OBSERVATION_COMPONENT: Final = "global_authority"
PROBE_RESULT_DOCUMENT: Final = "cfw-adversarial-probe-result-v1"
RESET_RESULT_DOCUMENT: Final = "cfw-adversarial-reset-result-v1"

ADVERSARIAL_RAW_KINDS: Final = frozenset(
    {
        "adversarial-case-observation",
        "adversarial-secret-coverage",
        "adversarial-signature-observation",
        "adversarial-transcript",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CDHASH_RE = re.compile(r"^[0-9a-f]{40,64}$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
STABLE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
EVENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
BOOT_UUID_RE = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)

IDENTITY_CONDITION_NAMES: Final = (
    "audit_evidence_fresh",
    "audit_session",
    "console_user",
    "designated_requirement",
    "entitlements",
    "euid",
    "pid_fresh",
    "role_binding",
    "signing_id",
    "team_id",
)
IDENTITY_CONDITION_FIELDS: Final = set(IDENTITY_CONDITION_NAMES)
SECRET_SURFACES: Final = {
    "secret-extraction-logs": "unified-logs",
    "secret-extraction-preferences": "preferences",
    "secret-extraction-journal": "authority-journal",
    "secret-extraction-crash-records": "crash-records",
    "secret-extraction-snapshots": "authority-snapshots",
    "secret-extraction-evidence": "release-evidence",
}


@dataclass(frozen=True, slots=True)
class AdversarialCaseSpec:
    category: str
    role: str
    precondition: str
    event: str
    accepted: bool
    actual_code: str
    cleanup_state: str
    state_relation: str
    isolation_mode: str
    reset_required: bool
    decision_source: str = "authority_operation"
    identity_mismatch: str | None = None
    secret_surface: str | None = None


def _case(
    category: str,
    precondition: str,
    event: str,
    accepted: bool,
    actual_code: str,
    cleanup_state: str,
    *,
    state_relation: str = "unchanged",
    isolation_mode: str = "exclusive-machine",
    reset_required: bool = False,
    decision_source: str = "authority_operation",
    identity_mismatch: str | None = None,
    secret_surface: str | None = None,
) -> AdversarialCaseSpec:
    return AdversarialCaseSpec(
        category=category,
        role="host",
        precondition=precondition,
        event=event,
        accepted=accepted,
        actual_code=actual_code,
        cleanup_state=cleanup_state,
        state_relation=state_relation,
        isolation_mode=isolation_mode,
        reset_required=reset_required,
        decision_source=decision_source,
        identity_mismatch=identity_mismatch,
        secret_surface=secret_surface,
    )


BASELINE_SPEC: Final = _case(
    "baseline",
    "authorized-product-host",
    "peer_authorization_decision",
    True,
    "accepted",
    "off",
    decision_source="authority_peer",
)

# The actual stable code and event are derived from this table and compared with
# the product-owned server observation.  Callers cannot supply an expected code.
REQUIRED_CASES: Final[dict[str, AdversarialCaseSpec]] = {
    "wrong-team-id": _case(
        "identity",
        "peer-team-mismatch",
        "xpc_requirement_rejection",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="signed-variant",
        decision_source="xpc_requirement",
        identity_mismatch="team_id",
    ),
    "wrong-bundle-identifier": _case(
        "identity",
        "peer-signing-identifier-mismatch",
        "xpc_requirement_rejection",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="signed-variant",
        decision_source="xpc_requirement",
        identity_mismatch="signing_id",
    ),
    "wrong-designated-requirement": _case(
        "identity",
        "peer-designated-requirement-mismatch",
        "xpc_requirement_rejection",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="signed-variant",
        decision_source="xpc_requirement",
        identity_mismatch="designated_requirement",
    ),
    "wrong-entitlement": _case(
        "identity",
        "peer-entitlements-mismatch",
        "xpc_requirement_rejection",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="signed-variant",
        decision_source="xpc_requirement",
        identity_mismatch="entitlements",
    ),
    "wrong-uid": _case(
        "identity",
        "peer-euid-mismatch",
        "peer_authorization_decision",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="privileged-uid",
        reset_required=True,
        decision_source="authority_peer",
        identity_mismatch="euid",
    ),
    "wrong-audit-session": _case(
        "identity",
        "peer-audit-session-mismatch",
        "peer_authorization_decision",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="isolated-audit-session",
        reset_required=True,
        decision_source="authority_peer",
        identity_mismatch="audit_session",
    ),
    "stale-pid-evidence": _case(
        "identity",
        "peer-pid-evidence-stale",
        "identity_evidence_rejection",
        False,
        "stale_evidence",
        "off",
        isolation_mode="pid-reuse-window",
        reset_required=True,
        decision_source="identity_freshness",
        identity_mismatch="pid_fresh",
    ),
    "stale-audit-evidence": _case(
        "identity",
        "peer-audit-evidence-stale",
        "identity_evidence_rejection",
        False,
        "stale_evidence",
        "off",
        isolation_mode="isolated-audit-session",
        reset_required=True,
        decision_source="identity_freshness",
        identity_mismatch="audit_evidence_fresh",
    ),
    "inactive-console-user": _case(
        "identity",
        "peer-console-user-inactive",
        "peer_authorization_decision",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="isolated-console-session",
        reset_required=True,
        decision_source="authority_peer",
        identity_mismatch="console_user",
    ),
    "same-team-unknown-bundle": _case(
        "identity",
        "peer-role-bundle-unknown",
        "xpc_requirement_rejection",
        False,
        "global_authority_identity_rejected",
        "off",
        isolation_mode="signed-variant",
        decision_source="xpc_requirement",
        identity_mismatch="role_binding",
    ),
    "replayed-operation": _case(
        "replay",
        "operation-context-already-consumed",
        "operation_decision",
        False,
        "replay_rejected",
        "off",
        decision_source="authority_operation",
    ),
    "replayed-start-ticket": _case(
        "replay",
        "start-ticket-already-redeemed",
        "operation_decision",
        False,
        "ticket_already_redeemed",
        "off",
        decision_source="authority_operation",
    ),
    "duplicate-redemption": _case(
        "replay",
        "ticket-second-redemption",
        "operation_decision",
        False,
        "ticket_already_redeemed",
        "off",
        decision_source="authority_operation",
    ),
    "replay-cursor-rollback": _case(
        "replay",
        "durable-replay-cursor-rollback",
        "journal_integrity_decision",
        False,
        "journal_corrupt",
        "quarantined",
        state_relation="changed",
        isolation_mode="journal-snapshot",
        reset_required=True,
        decision_source="authority_journal",
    ),
    "authority-journal-truncation": _case(
        "journal",
        "authority-journal-truncated",
        "journal_integrity_decision",
        False,
        "journal_corrupt",
        "quarantined",
        state_relation="changed",
        isolation_mode="journal-snapshot",
        reset_required=True,
        decision_source="authority_journal",
    ),
    "authority-journal-tamper": _case(
        "journal",
        "authority-journal-bit-tamper",
        "journal_integrity_decision",
        False,
        "journal_corrupt",
        "quarantined",
        state_relation="changed",
        isolation_mode="journal-snapshot",
        reset_required=True,
        decision_source="authority_journal",
    ),
    "authority-journal-symlink": _case(
        "journal",
        "authority-journal-symlink",
        "journal_integrity_decision",
        False,
        "journal_corrupt",
        "quarantined",
        state_relation="changed",
        isolation_mode="journal-snapshot",
        reset_required=True,
        decision_source="authority_journal",
    ),
    "oversize-message": _case(
        "protocol",
        "request-exceeds-message-bound",
        "operation_decision",
        False,
        "invalid_message",
        "off",
        decision_source="authority_operation",
    ),
    "deep-message": _case(
        "protocol",
        "request-exceeds-nesting-bound",
        "operation_decision",
        False,
        "invalid_message",
        "off",
        decision_source="authority_operation",
    ),
    "noncanonical-message": _case(
        "protocol",
        "request-is-noncanonical",
        "operation_decision",
        False,
        "invalid_message",
        "off",
        decision_source="authority_operation",
    ),
    "request-flood": _case(
        "backpressure",
        "bounded-read-request-flood",
        "operation_decision",
        False,
        "resource_exhausted",
        "off",
        decision_source="authority_operation",
    ),
    "in-flight-saturation": _case(
        "backpressure",
        "mutating-transaction-capacity-saturated",
        "operation_decision",
        False,
        "busy",
        "off",
        decision_source="authority_operation",
    ),
    "event-queue-saturation": _case(
        "backpressure",
        "peer-event-queue-capacity-saturated",
        "operation_decision",
        False,
        "resource_exhausted",
        "off",
        decision_source="authority_operation",
    ),
    "heartbeat-loss": _case(
        "liveness",
        "owner-heartbeat-expired",
        "lease_liveness_decision",
        False,
        "owner_unresponsive",
        "off",
        state_relation="changed",
        decision_source="authority_liveness",
    ),
    "fast-user-switching-race": _case(
        "liveness",
        "console-owner-changed-during-operation",
        "lease_liveness_decision",
        False,
        "stale_operation",
        "off",
        state_relation="changed",
        isolation_mode="fast-user-switch",
        reset_required=True,
        decision_source="authority_liveness",
    ),
    "late-callback": _case(
        "liveness",
        "owner-callback-after-revocation",
        "lease_liveness_decision",
        False,
        "stale_operation",
        "off",
        decision_source="authority_liveness",
    ),
    **{
        case_id: _case(
            "secret",
            f"canary-injected-{surface}",
            "secret_coverage_manifest",
            True,
            "secret_absent",
            "off",
            isolation_mode="secret-canary",
            reset_required=True,
            decision_source="secret_coverage",
            secret_surface=surface,
        )
        for case_id, surface in SECRET_SURFACES.items()
    },
}


class AdversarialMatrixError(ValueError):
    """Adversarial evidence is incomplete, drifted, or not fail-closed."""


def case_spec(case_id: str) -> AdversarialCaseSpec:
    if case_id == "baseline":
        return BASELINE_SPEC
    try:
        return REQUIRED_CASES[case_id]
    except (KeyError, TypeError) as error:
        raise AdversarialMatrixError(f"unknown adversarial case: {case_id!r}") from error


def required_case_ids() -> tuple[str, ...]:
    return tuple(sorted(REQUIRED_CASES))


def all_subject_ids() -> tuple[str, ...]:
    return ("baseline", *required_case_ids())


def required_raw_subjects() -> frozenset[str]:
    subjects: set[str] = set()
    for subject in all_subject_ids():
        subjects.update(
            {
                subject,
                f"observation:{subject}",
                f"client-signature:{subject}",
                f"server-signature:{subject}",
            }
        )
    subjects.update(f"secret-coverage:{case_id}" for case_id in SECRET_SURFACES)
    return frozenset(subjects)


REQUIRED_RAW_SUBJECTS: Final = required_raw_subjects()


def expected_raw_kind(subject: str) -> str:
    if subject not in REQUIRED_RAW_SUBJECTS:
        raise AdversarialMatrixError(f"unknown adversarial raw subject: {subject!r}")
    if subject.startswith("observation:"):
        return "adversarial-case-observation"
    if subject.startswith(("client-signature:", "server-signature:")):
        return "adversarial-signature-observation"
    if subject.startswith("secret-coverage:"):
        return "adversarial-secret-coverage"
    return "adversarial-transcript"


def expected_identity_conditions(case_id: str) -> dict[str, str]:
    spec = case_spec(case_id)
    values = {name: "match" for name in IDENTITY_CONDITION_NAMES}
    if spec.identity_mismatch is not None:
        values[spec.identity_mismatch] = "mismatch"
    return values


def validate_source_contract() -> None:
    """Fail if the checked-in matrix stops representing the reviewed 32 cases."""

    if len(REQUIRED_CASES) != 32 or len(set(REQUIRED_CASES)) != 32:
        raise AdversarialMatrixError("source-pinned adversarial matrix must contain 32 cases")
    identity = {
        case_id: spec for case_id, spec in REQUIRED_CASES.items() if spec.category == "identity"
    }
    if len(identity) != 10 or any(spec.identity_mismatch is None for spec in identity.values()):
        raise AdversarialMatrixError(
            "source-pinned identity matrix must contain ten single-mismatch cases"
        )
    if len(REQUIRED_RAW_SUBJECTS) != 138:
        raise AdversarialMatrixError(
            "source-pinned adversarial raw contract must contain 138 subjects"
        )
    if {spec.secret_surface for spec in REQUIRED_CASES.values() if spec.category == "secret"} != set(
        SECRET_SURFACES.values()
    ):
        raise AdversarialMatrixError("source-pinned secret matrix coverage differs")
    if BASELINE_SPEC.accepted is not True or BASELINE_SPEC.actual_code != "accepted":
        raise AdversarialMatrixError("source-pinned baseline must be accepted")
    supported_sources = {
        "authority_peer",
        "authority_operation",
        "authority_journal",
        "authority_liveness",
        "xpc_requirement",
        "identity_freshness",
        "secret_coverage",
    }
    if any(spec.decision_source not in supported_sources for spec in REQUIRED_CASES.values()):
        raise AdversarialMatrixError("source-pinned matrix uses an unsupported decision source")


validate_source_contract()


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AdversarialMatrixError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AdversarialMatrixError(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise AdversarialMatrixError(f"{label} must use UTC")
    return parsed


def _unix_milliseconds(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 9_999_999_999_999:
        raise AdversarialMatrixError(f"{label} must be a positive bounded Unix millisecond")
    return value


def _positive_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AdversarialMatrixError(f"{label} must be a positive bounded integer")
    return value


def _nonnegative_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AdversarialMatrixError(f"{label} must be a nonnegative bounded integer")
    return value


def _bounded_text(value: Any, label: str, maximum: int = 256, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise AdversarialMatrixError(f"{label} must be bounded printable text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise AdversarialMatrixError(f"{label} contains invalid Unicode") from error
    if (
        (not empty and not value)
        or size > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise AdversarialMatrixError(f"{label} must be bounded printable text")
    return value


def _sha256(value: Any, label: str) -> str:
    try:
        return require_sha256(value, label)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error


def _platform(value: Any) -> dict[str, Any]:
    try:
        platform = exact_object(
            value,
            {"architecture", "macos_version", "hardware_model", "clean_install"},
            "platform",
        )
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise AdversarialMatrixError("adversarial matrix requires a clean Apple Silicon machine")
    _bounded_text(platform["macos_version"], "platform.macos_version")
    try:
        validate_physical_hardware_model(platform["hardware_model"])
    except PhysicalMachineIdentityError as error:
        raise AdversarialMatrixError("platform.hardware_model is invalid") from error
    return platform


def _process(value: Any, label: str) -> dict[str, int]:
    try:
        process = exact_object(value, {"pid", "start_unix_ms"}, label)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    return {
        "pid": _positive_int(process["pid"], f"{label}.pid", 2**31 - 1),
        "start_unix_ms": _unix_milliseconds(
            process["start_unix_ms"], f"{label}.start_unix_ms"
        ),
    }


def _identity_conditions(value: Any, case_id: str, label: str) -> dict[str, str]:
    try:
        conditions = exact_object(value, IDENTITY_CONDITION_FIELDS, label)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    expected = expected_identity_conditions(case_id)
    if conditions != expected:
        raise AdversarialMatrixError(
            f"{label} differs from the source-pinned single-condition precondition"
        )
    return dict(conditions)


SIGNATURE_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "kind",
    "process",
    "process_image_path",
    "binary_sha256",
    "cdhash",
    "team_id",
    "signing_id",
    "designated_requirement_sha256",
    "entitlements_sha256",
    "conditions",
    "codesign_command_sha256",
    "codesign_output_sha256",
    "exit_code",
    "assessed_at",
}


def validate_signature_observation(
    value: Any,
    *,
    case_id: str,
    kind: str,
) -> dict[str, Any]:
    try:
        raw = exact_object(value, SIGNATURE_FIELDS, f"{case_id}.{kind} signature")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["document"] != SIGNATURE_DOCUMENT
        or raw["case_id"] != case_id
        or raw["kind"] != kind
        or kind not in {"client", "server"}
    ):
        raise AdversarialMatrixError(f"{case_id}.{kind} signature schema binding differs")
    process = _process(raw["process"], f"{case_id}.{kind}.process")
    path = _bounded_text(
        raw["process_image_path"], f"{case_id}.{kind}.process_image_path", 1024
    )
    if not path.startswith("/") or "/../" in f"{path}/" or "//" in path:
        raise AdversarialMatrixError(f"{case_id}.{kind} process image path is not canonical")
    team_id = _bounded_text(raw["team_id"], f"{case_id}.{kind}.team_id", 10, empty=True)
    if team_id and TEAM_ID_RE.fullmatch(team_id) is None:
        raise AdversarialMatrixError(f"{case_id}.{kind}.team_id is invalid")
    signing_id = _bounded_text(raw["signing_id"], f"{case_id}.{kind}.signing_id", 128)
    cdhash = raw["cdhash"]
    if not isinstance(cdhash, str) or CDHASH_RE.fullmatch(cdhash) is None:
        raise AdversarialMatrixError(f"{case_id}.{kind}.cdhash is invalid")
    conditions = _identity_conditions(
        raw["conditions"],
        "baseline" if kind == "server" else case_id,
        f"{case_id}.{kind}.conditions",
    )
    if kind == "server":
        if (
            path != AUTHORITY_PROCESS_IMAGE_PATH
            or team_id != PRODUCT_TEAM_ID
            or signing_id != AUTHORITY_SIGNING_ID
            or any(value != "match" for value in conditions.values())
        ):
            raise AdversarialMatrixError(
                f"{case_id} server signature is not the fixed product Authority identity"
            )
    else:
        spec = case_spec(case_id)
        if case_id == "wrong-team-id":
            if team_id == PRODUCT_TEAM_ID:
                raise AdversarialMatrixError("wrong-team-id used the product Team ID")
        elif team_id != PRODUCT_TEAM_ID:
            raise AdversarialMatrixError(f"{case_id} client is not signed by the product Team")
        if case_id in {"wrong-bundle-identifier", "same-team-unknown-bundle"}:
            if signing_id == PRODUCT_HOST_SIGNING_ID:
                raise AdversarialMatrixError(f"{case_id} did not vary the signing identifier")
        elif spec.identity_mismatch not in {"signing_id", "role_binding"} and signing_id != PRODUCT_HOST_SIGNING_ID:
            raise AdversarialMatrixError(f"{case_id} client signing identifier drifted")
    if raw["exit_code"] != 0:
        raise AdversarialMatrixError(f"{case_id}.{kind} codesign assessment failed")
    _timestamp(raw["assessed_at"], f"{case_id}.{kind}.assessed_at")
    return {
        **raw,
        "process": process,
        "process_image_path": path,
        "team_id": team_id,
        "signing_id": signing_id,
        "binary_sha256": _sha256(raw["binary_sha256"], f"{case_id}.{kind}.binary_sha256"),
        "designated_requirement_sha256": _sha256(
            raw["designated_requirement_sha256"],
            f"{case_id}.{kind}.designated_requirement_sha256",
        ),
        "entitlements_sha256": _sha256(
            raw["entitlements_sha256"], f"{case_id}.{kind}.entitlements_sha256"
        ),
        "codesign_command_sha256": _sha256(
            raw["codesign_command_sha256"], f"{case_id}.{kind}.codesign_command_sha256"
        ),
        "codesign_output_sha256": _sha256(
            raw["codesign_output_sha256"], f"{case_id}.{kind}.codesign_output_sha256"
        ),
        "conditions": conditions,
    }


COVERAGE_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "surface",
    "canary_sha256",
    "started_at",
    "finished_at",
    "enumeration_complete",
    "unreadable_count",
    "excluded_count",
    "entry_count",
    "total_scanned_bytes",
    "total_match_count",
    "entries",
}
COVERAGE_ENTRY_FIELDS: Final = {
    "location_sha256",
    "content_sha256",
    "scanned_bytes",
    "match_count",
}
MAX_SECRET_COVERAGE_ENTRIES: Final = 4_096
MAX_SECRET_COVERAGE_ENTRY_BYTES: Final = 64 * 1_024 * 1_024
MAX_SECRET_COVERAGE_TOTAL_BYTES: Final = 512 * 1_024 * 1_024


def validate_secret_coverage(value: Any, *, case_id: str) -> dict[str, Any]:
    spec = case_spec(case_id)
    if spec.secret_surface is None:
        raise AdversarialMatrixError(f"{case_id} is not a source-pinned secret surface")
    try:
        raw = exact_object(value, COVERAGE_FIELDS, f"{case_id}.secret_coverage")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    unreadable_count = _nonnegative_int(
        raw["unreadable_count"], f"{case_id}.coverage.unreadable_count",
        MAX_SECRET_COVERAGE_ENTRIES,
    )
    excluded_count = _nonnegative_int(
        raw["excluded_count"], f"{case_id}.coverage.excluded_count",
        MAX_SECRET_COVERAGE_ENTRIES,
    )
    total_match_count = _nonnegative_int(
        raw["total_match_count"], f"{case_id}.coverage.total_match_count",
        MAX_SECRET_COVERAGE_TOTAL_BYTES,
    )
    entry_count = _positive_int(
        raw["entry_count"], f"{case_id}.coverage.entry_count",
        MAX_SECRET_COVERAGE_ENTRIES,
    )
    declared_total_bytes = _nonnegative_int(
        raw["total_scanned_bytes"], f"{case_id}.coverage.total_scanned_bytes",
        MAX_SECRET_COVERAGE_TOTAL_BYTES,
    )
    if (
        raw["schema_version"] != 1
        or raw["document"] != COVERAGE_DOCUMENT
        or raw["case_id"] != case_id
        or raw["surface"] != spec.secret_surface
        or raw["enumeration_complete"] is not True
        or unreadable_count != 0
        or excluded_count != 0
        or total_match_count != 0
    ):
        raise AdversarialMatrixError(f"{case_id} secret coverage is incomplete or observed a canary")
    started = _timestamp(raw["started_at"], f"{case_id}.coverage.started_at")
    finished = _timestamp(raw["finished_at"], f"{case_id}.coverage.finished_at")
    if not started < finished or (finished - started).total_seconds() > 600:
        raise AdversarialMatrixError(f"{case_id} secret coverage duration is invalid")
    values = raw["entries"]
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= MAX_SECRET_COVERAGE_ENTRIES
    ):
        raise AdversarialMatrixError(f"{case_id} secret coverage entries are absent")
    entries: list[dict[str, Any]] = []
    locations: list[str] = []
    total_bytes = 0
    total_matches = 0
    for index, value_entry in enumerate(values):
        try:
            entry = exact_object(
                value_entry,
                COVERAGE_ENTRY_FIELDS,
                f"{case_id}.secret_coverage.entries[{index}]",
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        location = _sha256(
            entry["location_sha256"], f"{case_id}.coverage.entries[{index}].location"
        )
        scanned = _nonnegative_int(
            entry["scanned_bytes"], f"{case_id}.coverage.entries[{index}].scanned_bytes",
            MAX_SECRET_COVERAGE_ENTRY_BYTES,
        )
        matches = _nonnegative_int(
            entry["match_count"], f"{case_id}.coverage.entries[{index}].match_count"
        )
        normalized = {
            "location_sha256": location,
            "content_sha256": _sha256(
                entry["content_sha256"], f"{case_id}.coverage.entries[{index}].content"
            ),
            "scanned_bytes": scanned,
            "match_count": matches,
        }
        entries.append(normalized)
        locations.append(location)
        total_bytes += scanned
        total_matches += matches
        if total_bytes > MAX_SECRET_COVERAGE_TOTAL_BYTES:
            raise AdversarialMatrixError(
                f"{case_id} secret coverage exceeds the total byte bound"
            )
    if entries != sorted(entries, key=lambda entry: entry["location_sha256"]):
        raise AdversarialMatrixError(f"{case_id} secret coverage entries are not canonical")
    if len(set(locations)) != len(locations):
        raise AdversarialMatrixError(f"{case_id} secret coverage repeats a location")
    if (
        entry_count != len(entries)
        or declared_total_bytes != total_bytes
        or total_matches != 0
    ):
        raise AdversarialMatrixError(f"{case_id} secret coverage totals differ")
    return {
        **raw,
        "canary_sha256": _sha256(raw["canary_sha256"], f"{case_id}.canary_sha256"),
        "entries": entries,
    }


PRODUCT_EVENT_FIELDS: Final = {
    "schema_version",
    "document",
    "component",
    "event",
    "sequence",
    "recorded_unix_ms",
    "process",
    "candidate",
    "payload",
}
PRODUCT_CANDIDATE_FIELDS: Final = {"version", "build_number"}
AUTHORITY_PEER_PAYLOAD_FIELDS: Final = {
    "role",
    "peer_pid",
    "euid",
    "audit_session_id",
    "connection_identity_sha256",
    "accepted",
    "actual_code",
    "pre_state_sha256",
    "post_state_sha256",
    "cleanup_state",
}
AUTHORITY_OPERATION_PAYLOAD_FIELDS: Final = {
    *AUTHORITY_PEER_PAYLOAD_FIELDS,
    "request_sha256",
}
AUTHORITY_JOURNAL_PAYLOAD_FIELDS: Final = {
    "journal_input_sha256",
    "actual_code",
    "pre_state_sha256",
    "post_state_sha256",
    "cleanup_state",
}
LOG_RECORD_FIELDS: Final = {
    "event_type",
    "message_type",
    "subsystem",
    "category",
    "process_image_path",
    "process_id",
    "boot_uuid",
    "timestamp",
    "event_message_sha256",
}
SERVER_RECORD_FIELDS: Final = {"log", "event"}

HOST_REQUIREMENT_TEXT: Final = (
    'anchor apple generic and identifier "com.bill.clashformac" '
    "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
    "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
    'and certificate leaf[subject.OU] = "YKUPL7Z869" '
    'and entitlement["com.apple.security.application-groups"] = '
    '"YKUPL7Z869.group.com.bill.clashformac"'
)
HOST_REQUIREMENT_SHA256: Final = hashlib.sha256(
    HOST_REQUIREMENT_TEXT.encode("utf-8")
).hexdigest()
LOG_PREDICATE: Final = (
    'subsystem == "com.bill.clashformac" AND '
    'category == "release-observation" AND '
    'eventMessage BEGINSWITH "cfw-release-observation-v1 "'
)
LOG_PREDICATE_SHA256: Final = hashlib.sha256(LOG_PREDICATE.encode("utf-8")).hexdigest()


def _connection_identity_sha256(role: str, pid: int, euid: int, audit_session_id: int) -> str:
    material = bytearray(role.encode("utf-8"))
    for value in (pid, euid, audit_session_id):
        material.extend(value.to_bytes(4, "big", signed=False))
    return hashlib.sha256(material).hexdigest()


def _state_fields(
    raw: Mapping[str, Any], *, case_id: str, prefix: str = ""
) -> tuple[str, str, str]:
    spec = case_spec(case_id)
    pre_key = f"{prefix}pre_state_sha256"
    post_key = f"{prefix}post_state_sha256"
    cleanup_key = f"{prefix}cleanup_state"
    pre = _sha256(raw[pre_key], f"{case_id}.{pre_key}")
    post = _sha256(raw[post_key], f"{case_id}.{post_key}")
    cleanup = raw[cleanup_key]
    if cleanup != spec.cleanup_state:
        raise AdversarialMatrixError(f"{case_id} cleanup state differs from source contract")
    if (spec.state_relation == "unchanged") != (pre == post):
        raise AdversarialMatrixError(f"{case_id} pre/post state relation differs")
    return pre, post, cleanup


def _product_event(
    value: Any,
    *,
    case_id: str,
    request_sha256: str,
) -> dict[str, Any]:
    spec = case_spec(case_id)
    try:
        event = exact_object(value, PRODUCT_EVENT_FIELDS, f"{case_id}.server_event")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if (
        event["schema_version"] != 1
        or event["document"] != PRODUCT_OBSERVATION_DOCUMENT
        or event["component"] != PRODUCT_OBSERVATION_COMPONENT
        or event["event"] != spec.event
    ):
        raise AdversarialMatrixError(f"{case_id} server event differs from source contract")
    _positive_int(event["sequence"], f"{case_id}.server_event.sequence")
    _unix_milliseconds(event["recorded_unix_ms"], f"{case_id}.server_event.recorded_unix_ms")
    process = _process(event["process"], f"{case_id}.server_event.process")
    try:
        candidate = exact_object(
            event["candidate"], PRODUCT_CANDIDATE_FIELDS, f"{case_id}.server_event.candidate"
        )
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if candidate["version"] != PRODUCT_VERSION:
        raise AdversarialMatrixError(f"{case_id} server event candidate version differs")
    _bounded_text(candidate["build_number"], f"{case_id}.candidate.build_number", 18)
    if spec.decision_source in {"authority_peer", "authority_operation", "authority_liveness"}:
        expected_fields = (
            AUTHORITY_PEER_PAYLOAD_FIELDS
            if spec.decision_source == "authority_peer"
            else AUTHORITY_OPERATION_PAYLOAD_FIELDS
        )
        try:
            payload = exact_object(
                event["payload"], expected_fields, f"{case_id}.server_event.payload"
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        peer_pid = _positive_int(payload["peer_pid"], f"{case_id}.peer_pid", 2**31 - 1)
        euid = _nonnegative_int(payload["euid"], f"{case_id}.euid", 2**32 - 1)
        audit_session = _nonnegative_int(
            payload["audit_session_id"], f"{case_id}.audit_session_id", 2**32 - 1
        )
        identity = payload["connection_identity_sha256"]
        connection_was_accepted = spec.accepted or spec.decision_source in {
            "authority_operation",
            "authority_liveness",
        }
        if connection_was_accepted:
            identity = _sha256(identity, f"{case_id}.connection_identity_sha256")
            expected_identity = _connection_identity_sha256(
                spec.role, peer_pid, euid, audit_session
            )
            if identity != expected_identity:
                raise AdversarialMatrixError(
                    f"{case_id} connection identity digest differs from kernel attributes"
                )
        elif identity is not None:
            raise AdversarialMatrixError(
                f"{case_id} rejected connection unexpectedly has an accepted identity digest"
            )
        if (
            payload["role"] != spec.role
            or payload["accepted"] is not spec.accepted
            or payload["actual_code"] != spec.actual_code
        ):
            raise AdversarialMatrixError(
                f"{case_id} server decision/code differs from source-pinned semantics"
            )
        if spec.decision_source != "authority_peer" and payload["request_sha256"] != request_sha256:
            raise AdversarialMatrixError(f"{case_id} server raw request digest differs")
        pre, post, cleanup = _state_fields(payload, case_id=case_id)
        normalized_payload = {
            **payload,
            "peer_pid": peer_pid,
            "euid": euid,
            "audit_session_id": audit_session,
            "connection_identity_sha256": identity,
            "pre_state_sha256": pre,
            "post_state_sha256": post,
            "cleanup_state": cleanup,
        }
    elif spec.decision_source == "authority_journal":
        try:
            payload = exact_object(
                event["payload"], AUTHORITY_JOURNAL_PAYLOAD_FIELDS,
                f"{case_id}.server_event.payload",
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        if (
            payload["journal_input_sha256"] != request_sha256
            or payload["actual_code"] != spec.actual_code
        ):
            raise AdversarialMatrixError(f"{case_id} journal input/code differs")
        pre, post, cleanup = _state_fields(payload, case_id=case_id)
        normalized_payload = {
            **payload,
            "pre_state_sha256": pre,
            "post_state_sha256": post,
            "cleanup_state": cleanup,
        }
    else:
        raise AdversarialMatrixError(f"{case_id} does not use an Authority event")
    actual_code = normalized_payload["actual_code"]
    if not isinstance(actual_code, str) or STABLE_CODE_RE.fullmatch(actual_code) is None:
        raise AdversarialMatrixError(f"{case_id} actual stable code is invalid")
    return {
        **event,
        "process": process,
        "candidate": dict(candidate),
        "payload": normalized_payload,
    }


def validate_server_record(
    value: Any,
    *,
    case_id: str,
    request_sha256: str,
) -> dict[str, Any]:
    try:
        raw = exact_object(value, SERVER_RECORD_FIELDS, f"{case_id}.server_record")
        log = exact_object(raw["log"], LOG_RECORD_FIELDS, f"{case_id}.server_record.log")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    event = _product_event(raw["event"], case_id=case_id, request_sha256=request_sha256)
    if (
        log["event_type"] != "logEvent"
        or log["message_type"] != "Info"
        or log["subsystem"] != PRODUCT_OBSERVATION_SUBSYSTEM
        or log["category"] != PRODUCT_OBSERVATION_CATEGORY
        or log["process_image_path"] != AUTHORITY_PROCESS_IMAGE_PATH
        or log["process_id"] != event["process"]["pid"]
        or not isinstance(log["boot_uuid"], str)
        or BOOT_UUID_RE.fullmatch(log["boot_uuid"]) is None
    ):
        raise AdversarialMatrixError(f"{case_id} Unified Log provenance differs")
    _timestamp(log["timestamp"], f"{case_id}.server_record.log.timestamp")
    digest = _sha256(log["event_message_sha256"], f"{case_id}.event_message_sha256")
    expected_message = PRODUCT_OBSERVATION_PREFIX.encode("utf-8") + canonical_json(event)
    if digest != hashlib.sha256(expected_message).hexdigest():
        raise AdversarialMatrixError(f"{case_id} Unified Log message digest differs")
    return {"log": dict(log), "event": event}


BOUNDARY_RECORD_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "source",
    "request_sha256",
    "actual_code",
    "accepted",
    "pre_state_sha256",
    "post_state_sha256",
    "cleanup_state",
    "evidence",
}
XPC_REQUIREMENT_DOCUMENT: Final = "cfw-adversarial-xpc-requirement-result-v1"
IDENTITY_FRESHNESS_DOCUMENT: Final = "cfw-adversarial-identity-freshness-result-v1"
SECRET_DECISION_DOCUMENT: Final = "cfw-adversarial-secret-decision-v1"
XPC_REQUIREMENT_EVIDENCE_FIELDS: Final = {
    "listener_requirement_sha256",
    "codesign_assessment_sha256",
    "codesign_exit_code",
    "connection_outcome",
    "transport_error_code",
    "accepted_event_count",
    "search_predicate_sha256",
}
IDENTITY_FRESHNESS_EVIDENCE_FIELDS: Final = {
    "captured_pid",
    "captured_start_unix_ms",
    "current_pid",
    "current_start_unix_ms",
    "captured_audit_session_id",
    "current_audit_session_id",
}
SECRET_DECISION_EVIDENCE_FIELDS: Final = {
    "coverage_subject",
    "enumeration_complete",
}


def validate_boundary_record(
    value: Any, *, case_id: str, request_sha256: str
) -> dict[str, Any]:
    spec = case_spec(case_id)
    try:
        raw = exact_object(value, BOUNDARY_RECORD_FIELDS, f"{case_id}.boundary_record")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    documents = {
        "xpc_requirement": XPC_REQUIREMENT_DOCUMENT,
        "identity_freshness": IDENTITY_FRESHNESS_DOCUMENT,
        "secret_coverage": SECRET_DECISION_DOCUMENT,
    }
    expected_document = documents.get(spec.decision_source)
    if (
        expected_document is None
        or raw["schema_version"] != 1
        or raw["document"] != expected_document
        or raw["case_id"] != case_id
        or raw["source"] != spec.decision_source
        or raw["request_sha256"] != request_sha256
        or raw["actual_code"] != spec.actual_code
        or raw["accepted"] is not spec.accepted
    ):
        raise AdversarialMatrixError(f"{case_id} non-server decision binding differs")
    pre, post, cleanup = _state_fields(raw, case_id=case_id)
    if spec.decision_source == "xpc_requirement":
        try:
            evidence = exact_object(
                raw["evidence"], XPC_REQUIREMENT_EVIDENCE_FIELDS,
                f"{case_id}.boundary_record.evidence",
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        if (
            evidence["listener_requirement_sha256"] != HOST_REQUIREMENT_SHA256
            or evidence["codesign_exit_code"] != 3
            or evidence["connection_outcome"] != "invalidated_before_export"
            or evidence["transport_error_code"] != "global_authority_interrupted"
            or evidence["accepted_event_count"] != 0
            or evidence["search_predicate_sha256"] != LOG_PREDICATE_SHA256
        ):
            raise AdversarialMatrixError(f"{case_id} OS XPC requirement rejection is unproven")
        _sha256(evidence["codesign_assessment_sha256"], f"{case_id}.codesign_assessment")
    elif spec.decision_source == "identity_freshness":
        try:
            evidence = exact_object(
                raw["evidence"], IDENTITY_FRESHNESS_EVIDENCE_FIELDS,
                f"{case_id}.boundary_record.evidence",
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        captured_pid = _positive_int(evidence["captured_pid"], f"{case_id}.captured_pid")
        current_pid = _positive_int(evidence["current_pid"], f"{case_id}.current_pid")
        captured_start = _unix_milliseconds(
            evidence["captured_start_unix_ms"], f"{case_id}.captured_start_unix_ms"
        )
        current_start = _unix_milliseconds(
            evidence["current_start_unix_ms"], f"{case_id}.current_start_unix_ms"
        )
        captured_audit = _nonnegative_int(
            evidence["captured_audit_session_id"], f"{case_id}.captured_audit_session_id",
            2**32 - 1,
        )
        current_audit = _nonnegative_int(
            evidence["current_audit_session_id"], f"{case_id}.current_audit_session_id",
            2**32 - 1,
        )
        if case_id == "stale-pid-evidence":
            if captured_pid != current_pid or captured_start == current_start:
                raise AdversarialMatrixError("stale-pid-evidence does not prove PID reuse")
        elif captured_audit == current_audit:
            raise AdversarialMatrixError("stale-audit-evidence does not prove session drift")
    else:
        try:
            evidence = exact_object(
                raw["evidence"], SECRET_DECISION_EVIDENCE_FIELDS,
                f"{case_id}.boundary_record.evidence",
            )
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        if (
            evidence["coverage_subject"] != f"secret-coverage:{case_id}"
            or evidence["enumeration_complete"] is not True
        ):
            raise AdversarialMatrixError(f"{case_id} coverage decision is incomplete")
    return {
        **raw,
        "pre_state_sha256": pre,
        "post_state_sha256": post,
        "cleanup_state": cleanup,
        "evidence": dict(evidence),
    }


ISOLATION_FIELDS: Final = {
    "mode",
    "reset_required",
    "reset_performed",
    "reset_verified",
    "contamination_detected",
    "pre_reset_state_sha256",
    "post_reset_state_sha256",
}


def _isolation(value: Any, case_id: str) -> dict[str, Any]:
    spec = case_spec(case_id)
    try:
        raw = exact_object(value, ISOLATION_FIELDS, f"{case_id}.isolation")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if (
        raw["mode"] != spec.isolation_mode
        or raw["reset_required"] is not spec.reset_required
        or raw["contamination_detected"] is not False
    ):
        raise AdversarialMatrixError(f"{case_id} isolation contract differs")
    before = raw["pre_reset_state_sha256"]
    after = raw["post_reset_state_sha256"]
    if spec.reset_required:
        before = _sha256(before, f"{case_id}.isolation.pre_reset_state_sha256")
        after = _sha256(after, f"{case_id}.isolation.post_reset_state_sha256")
        if (
            raw["reset_performed"] is not True
            or raw["reset_verified"] is not True
            or before != after
        ):
            raise AdversarialMatrixError(f"{case_id} required reset is not proven")
    elif (
        raw["reset_performed"] is not False
        or raw["reset_verified"] is not False
        or before != ""
        or after != ""
    ):
        raise AdversarialMatrixError(f"{case_id} declared an unexpected reset")
    return {**raw, "pre_reset_state_sha256": before, "post_reset_state_sha256": after}


COMMAND_FIELDS: Final = {
    "role",
    "argv_sha256",
    "started_at",
    "finished_at",
    "duration_ms",
    "exit_code",
}
CLIENT_RUNTIME_FIELDS: Final = {"process", "euid", "audit_session_id"}
OBSERVATION_FIELDS: Final = {
    "schema_version",
    "document",
    "case_id",
    "category",
    "role",
    "precondition",
    "request_sha256",
    "command",
    "client_runtime",
    "client_signature_subject",
    "server_signature_subject",
    "secret_coverage_subject",
    "server_record",
    "boundary_record",
    "isolation",
}


def _client_runtime(value: Any, case_id: str) -> dict[str, Any]:
    try:
        raw = exact_object(value, CLIENT_RUNTIME_FIELDS, f"{case_id}.client_runtime")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    return {
        "process": _process(raw["process"], f"{case_id}.client_runtime.process"),
        "euid": _nonnegative_int(raw["euid"], f"{case_id}.client_runtime.euid", 2**32 - 1),
        "audit_session_id": _nonnegative_int(
            raw["audit_session_id"], f"{case_id}.client_runtime.audit_session_id", 2**32 - 1
        ),
    }


def validate_case_observation(value: Any, *, case_id: str) -> dict[str, Any]:
    spec = case_spec(case_id)
    try:
        raw = exact_object(value, OBSERVATION_FIELDS, f"{case_id}.observation")
        command = exact_object(raw["command"], COMMAND_FIELDS, f"{case_id}.observation.command")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if (
        raw["schema_version"] != 1
        or raw["document"] != OBSERVATION_DOCUMENT
        or raw["case_id"] != case_id
        or raw["category"] != spec.category
        or raw["role"] != spec.role
        or raw["precondition"] != spec.precondition
        or raw["client_signature_subject"] != f"client-signature:{case_id}"
        or raw["server_signature_subject"] != f"server-signature:{case_id}"
        or raw["secret_coverage_subject"]
        != (f"secret-coverage:{case_id}" if spec.secret_surface is not None else "")
    ):
        raise AdversarialMatrixError(f"{case_id} observation binding differs")
    request_sha256 = _sha256(raw["request_sha256"], f"{case_id}.request_sha256")
    runtime = _client_runtime(raw["client_runtime"], case_id)
    if command["role"] != "adversarial-probe" or command["exit_code"] != 0:
        raise AdversarialMatrixError(f"{case_id} fixed probe command did not succeed")
    _sha256(command["argv_sha256"], f"{case_id}.command.argv_sha256")
    started = _timestamp(command["started_at"], f"{case_id}.command.started_at")
    finished = _timestamp(command["finished_at"], f"{case_id}.command.finished_at")
    duration_ms = _positive_int(command["duration_ms"], f"{case_id}.command.duration_ms", 600_000)
    elapsed_ms = round((finished - started).total_seconds() * 1000)
    if finished <= started or abs(elapsed_ms - duration_ms) > 2_000:
        raise AdversarialMatrixError(f"{case_id} command timing is inconsistent")
    if spec.decision_source.startswith("authority_"):
        if raw["boundary_record"] != {}:
            raise AdversarialMatrixError(f"{case_id} unexpectedly binds a non-server decision")
        record: dict[str, Any] = validate_server_record(
            raw["server_record"], case_id=case_id, request_sha256=request_sha256
        )
        recorded = record["event"]["recorded_unix_ms"]
        started_ms = round(started.timestamp() * 1000)
        finished_ms = round(finished.timestamp() * 1000)
        if not started_ms - 5_000 <= recorded <= finished_ms + 5_000:
            raise AdversarialMatrixError(f"{case_id} server event is outside the command window")
        payload = record["event"]["payload"]
        if spec.decision_source in {
            "authority_peer",
            "authority_operation",
            "authority_liveness",
        } and (
            payload["peer_pid"] != runtime["process"]["pid"]
            or payload["euid"] != runtime["euid"]
            or payload["audit_session_id"] != runtime["audit_session_id"]
        ):
            raise AdversarialMatrixError(
                f"{case_id} helper runtime differs from server-observed peer identity"
            )
        decision = {
            "accepted": spec.accepted,
            "actual_code": payload["actual_code"],
            "pre_state_sha256": payload["pre_state_sha256"],
            "post_state_sha256": payload["post_state_sha256"],
            "cleanup_state": payload["cleanup_state"],
        }
        boundary: dict[str, Any] = {}
    else:
        if raw["server_record"] != {}:
            raise AdversarialMatrixError(f"{case_id} invents an unavailable server callback")
        boundary = validate_boundary_record(
            raw["boundary_record"], case_id=case_id, request_sha256=request_sha256
        )
        record = {}
        decision = {
            "accepted": boundary["accepted"],
            "actual_code": boundary["actual_code"],
            "pre_state_sha256": boundary["pre_state_sha256"],
            "post_state_sha256": boundary["post_state_sha256"],
            "cleanup_state": boundary["cleanup_state"],
        }
    return {
        **raw,
        "request_sha256": request_sha256,
        "command": {**command, "duration_ms": duration_ms},
        "client_runtime": runtime,
        "server_record": record,
        "boundary_record": boundary,
        "decision": decision,
        "isolation": _isolation(raw["isolation"], case_id),
    }


TRANSCRIPT_FIELDS: Final = {
    "schema_version",
    "proof",
    "case_id",
    "category",
    "role",
    "precondition",
    "event",
    "command",
    "started_at",
    "finished_at",
    "exit_code",
    "request_sha256",
    "peer",
    "decision",
    "pre_state_sha256",
    "post_state_sha256",
    "cleanup_state",
    "isolation",
    "observation_artifact",
    "client_signature_artifact",
    "server_signature_artifact",
    "secret_coverage_artifact",
}
TRANSCRIPT_PEER_FIELDS: Final = {
    "pid",
    "start_unix_ms",
    "euid",
    "audit_session_id",
    "process_image_path",
    "team_id",
    "signing_id",
    "designated_requirement_sha256",
    "entitlements_sha256",
    "binary_sha256",
    "cdhash",
}
TRANSCRIPT_DECISION_FIELDS: Final = {"source", "accepted", "actual_code"}
REPORT_ENTRY_FIELDS: Final = {
    "id",
    "category",
    "role",
    "precondition",
    "event",
    "artifact",
}


def _descriptor(value: Any, expected_kind: str, label: str) -> ArtifactDescriptor:
    try:
        return parse_descriptor(value, expected_kinds={expected_kind}, label=label)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error


def _empty_or_descriptor(value: Any, expected_kind: str, label: str) -> ArtifactDescriptor | None:
    if value == {}:
        return None
    return _descriptor(value, expected_kind, label)


def _read_json(
    artifacts: ArtifactReader,
    descriptor: Any,
    *,
    expected_kind: str,
    label: str,
) -> tuple[ArtifactDescriptor, Any]:
    try:
        return artifacts.read_json(descriptor, expected_kind=expected_kind, label=label)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error


def _validate_signature_pair(
    *,
    case_id: str,
    client: dict[str, Any],
    server: dict[str, Any],
    observation: dict[str, Any],
) -> None:
    if client["process"] != observation["client_runtime"]["process"]:
        raise AdversarialMatrixError(f"{case_id} client signature process differs from helper")
    if observation["server_record"]:
        event = observation["server_record"]["event"]
        if server["process"] != event["process"]:
            raise AdversarialMatrixError(
                f"{case_id} server signature process differs from Authority envelope"
            )
        if server["process"]["pid"] != observation["server_record"]["log"]["process_id"]:
            raise AdversarialMatrixError(
                f"{case_id} server signature PID differs from Unified Log"
            )
    command_started = _timestamp(
        observation["command"]["started_at"], f"{case_id}.command.started_at"
    )
    for kind, signature in (("client", client), ("server", server)):
        assessed = _timestamp(
            signature["assessed_at"], f"{case_id}.{kind}.assessed_at"
        )
        if assessed > command_started or (command_started - assessed).total_seconds() > 600:
            raise AdversarialMatrixError(
                f"{case_id} {kind} signature is not a fresh precondition observation"
            )


def build_adversarial_transcript(
    *,
    case_id: str,
    proof: Any,
    observation_artifact: Any,
    observation: Any,
    client_signature_artifact: Any,
    client_signature: Any,
    server_signature_artifact: Any,
    server_signature: Any,
    secret_coverage_artifact: Any = None,
    secret_coverage: Any = None,
) -> dict[str, Any]:
    """Derive one final transcript solely from frozen pre-nonce documents."""

    spec = case_spec(case_id)
    try:
        parsed_proof = parse_proof_binding(proof, f"{case_id}.proof")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    observation_descriptor = _descriptor(
        observation_artifact,
        "adversarial-case-observation",
        f"{case_id}.observation_artifact",
    )
    client_descriptor = _descriptor(
        client_signature_artifact,
        "adversarial-signature-observation",
        f"{case_id}.client_signature_artifact",
    )
    server_descriptor = _descriptor(
        server_signature_artifact,
        "adversarial-signature-observation",
        f"{case_id}.server_signature_artifact",
    )
    normalized_observation = validate_case_observation(observation, case_id=case_id)
    normalized_client = validate_signature_observation(
        client_signature, case_id=case_id, kind="client"
    )
    normalized_server = validate_signature_observation(
        server_signature, case_id=case_id, kind="server"
    )
    _validate_signature_pair(
        case_id=case_id,
        client=normalized_client,
        server=normalized_server,
        observation=normalized_observation,
    )
    coverage_descriptor: ArtifactDescriptor | None = None
    if spec.secret_surface is None:
        if secret_coverage_artifact not in (None, {}) or secret_coverage is not None:
            raise AdversarialMatrixError(f"{case_id} unexpectedly supplies secret coverage")
    else:
        if secret_coverage_artifact in (None, {}) or secret_coverage is None:
            raise AdversarialMatrixError(f"{case_id} omits secret coverage")
        coverage_descriptor = _descriptor(
            secret_coverage_artifact,
            "adversarial-secret-coverage",
            f"{case_id}.secret_coverage_artifact",
        )
        validate_secret_coverage(secret_coverage, case_id=case_id)

    runtime = normalized_observation["client_runtime"]
    decision = normalized_observation["decision"]
    return {
        "schema_version": 3,
        "proof": parsed_proof,
        "case_id": case_id,
        "category": spec.category,
        "role": spec.role,
        "precondition": spec.precondition,
        "event": spec.event,
        "command": [parsed_proof["collector"]["version"], "adversarial", case_id],
        "started_at": normalized_observation["command"]["started_at"],
        "finished_at": normalized_observation["command"]["finished_at"],
        "exit_code": normalized_observation["command"]["exit_code"],
        "request_sha256": normalized_observation["request_sha256"],
        "peer": {
            "pid": runtime["process"]["pid"],
            "start_unix_ms": runtime["process"]["start_unix_ms"],
            "euid": runtime["euid"],
            "audit_session_id": runtime["audit_session_id"],
            "process_image_path": normalized_client["process_image_path"],
            "team_id": normalized_client["team_id"],
            "signing_id": normalized_client["signing_id"],
            "designated_requirement_sha256": normalized_client[
                "designated_requirement_sha256"
            ],
            "entitlements_sha256": normalized_client["entitlements_sha256"],
            "binary_sha256": normalized_client["binary_sha256"],
            "cdhash": normalized_client["cdhash"],
        },
        "decision": {
            "source": spec.decision_source,
            "accepted": decision["accepted"],
            "actual_code": decision["actual_code"],
        },
        "pre_state_sha256": decision["pre_state_sha256"],
        "post_state_sha256": decision["post_state_sha256"],
        "cleanup_state": decision["cleanup_state"],
        "isolation": normalized_observation["isolation"],
        "observation_artifact": observation_descriptor.as_dict(),
        "client_signature_artifact": client_descriptor.as_dict(),
        "server_signature_artifact": server_descriptor.as_dict(),
        "secret_coverage_artifact": (
            coverage_descriptor.as_dict() if coverage_descriptor is not None else {}
        ),
    }


def _validate_transcript(
    value: Any,
    *,
    case_id: str,
    proof: dict[str, Any],
    artifacts: ArtifactReader,
) -> tuple[
    datetime,
    datetime,
    list[dict[str, Any]],
    str | None,
    tuple[int, int, int] | None,
]:
    spec = case_spec(case_id)
    try:
        transcript = exact_object(value, TRANSCRIPT_FIELDS, f"{case_id}.transcript")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if (
        transcript["schema_version"] != 3
        or parse_proof_binding(transcript["proof"], f"{case_id}.transcript.proof") != proof
        or transcript["case_id"] != case_id
        or transcript["category"] != spec.category
        or transcript["role"] != spec.role
        or transcript["precondition"] != spec.precondition
        or transcript["event"] != spec.event
        or transcript["command"] != [proof["collector"]["version"], "adversarial", case_id]
    ):
        raise AdversarialMatrixError(f"{case_id} transcript source binding differs")

    observation_descriptor, observation_value = _read_json(
        artifacts,
        transcript["observation_artifact"],
        expected_kind="adversarial-case-observation",
        label=f"{case_id}.observation_artifact",
    )
    observation = validate_case_observation(observation_value, case_id=case_id)
    client_descriptor, client_value = _read_json(
        artifacts,
        transcript["client_signature_artifact"],
        expected_kind="adversarial-signature-observation",
        label=f"{case_id}.client_signature_artifact",
    )
    server_descriptor, server_value = _read_json(
        artifacts,
        transcript["server_signature_artifact"],
        expected_kind="adversarial-signature-observation",
        label=f"{case_id}.server_signature_artifact",
    )
    client = validate_signature_observation(client_value, case_id=case_id, kind="client")
    server = validate_signature_observation(server_value, case_id=case_id, kind="server")
    _validate_signature_pair(
        case_id=case_id, client=client, server=server, observation=observation
    )
    if observation["server_record"]:
        event_candidate = observation["server_record"]["event"]["candidate"]
        if event_candidate["build_number"] != proof["candidate"]["build_number"]:
            raise AdversarialMatrixError(
                f"{case_id} Authority event build differs from the proof candidate"
            )

    coverage_descriptor = _empty_or_descriptor(
        transcript["secret_coverage_artifact"],
        "adversarial-secret-coverage",
        f"{case_id}.secret_coverage_artifact",
    )
    coverage_digest: str | None = None
    bindings = [
        {"subject": f"observation:{case_id}", "descriptor": observation_descriptor.as_dict()},
        {"subject": f"client-signature:{case_id}", "descriptor": client_descriptor.as_dict()},
        {"subject": f"server-signature:{case_id}", "descriptor": server_descriptor.as_dict()},
    ]
    if spec.secret_surface is None:
        if coverage_descriptor is not None:
            raise AdversarialMatrixError(f"{case_id} unexpectedly binds secret coverage")
    else:
        if coverage_descriptor is None:
            raise AdversarialMatrixError(f"{case_id} omits its secret coverage manifest")
        reopened_descriptor, coverage_value = _read_json(
            artifacts,
            coverage_descriptor.as_dict(),
            expected_kind="adversarial-secret-coverage",
            label=f"{case_id}.secret_coverage_artifact",
        )
        coverage = validate_secret_coverage(coverage_value, case_id=case_id)
        coverage_digest = coverage["canary_sha256"]
        bindings.append(
            {
                "subject": f"secret-coverage:{case_id}",
                "descriptor": reopened_descriptor.as_dict(),
            }
        )

    runtime = observation["client_runtime"]
    normalized_peer = {
        "pid": runtime["process"]["pid"],
        "start_unix_ms": runtime["process"]["start_unix_ms"],
        "euid": runtime["euid"],
        "audit_session_id": runtime["audit_session_id"],
        "process_image_path": client["process_image_path"],
        "team_id": client["team_id"],
        "signing_id": client["signing_id"],
        "designated_requirement_sha256": client["designated_requirement_sha256"],
        "entitlements_sha256": client["entitlements_sha256"],
        "binary_sha256": client["binary_sha256"],
        "cdhash": client["cdhash"],
    }
    normalized_decision = {
        "source": spec.decision_source,
        "accepted": observation["decision"]["accepted"],
        "actual_code": observation["decision"]["actual_code"],
    }
    try:
        exact_object(transcript["peer"], TRANSCRIPT_PEER_FIELDS, f"{case_id}.transcript.peer")
        exact_object(
            transcript["decision"],
            TRANSCRIPT_DECISION_FIELDS,
            f"{case_id}.transcript.decision",
        )
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    expected_copies = {
        "exit_code": observation["command"]["exit_code"],
        "request_sha256": observation["request_sha256"],
        "peer": normalized_peer,
        "decision": normalized_decision,
        "pre_state_sha256": observation["decision"]["pre_state_sha256"],
        "post_state_sha256": observation["decision"]["post_state_sha256"],
        "cleanup_state": observation["decision"]["cleanup_state"],
        "isolation": observation["isolation"],
    }
    for field, expected in expected_copies.items():
        if transcript[field] != expected:
            raise AdversarialMatrixError(
                f"{case_id} transcript {field} differs from retained pre-nonce bytes"
            )
    started = _timestamp(transcript["started_at"], f"{case_id}.started_at")
    finished = _timestamp(transcript["finished_at"], f"{case_id}.finished_at")
    if (
        transcript["started_at"] != observation["command"]["started_at"]
        or transcript["finished_at"] != observation["command"]["finished_at"]
    ):
        raise AdversarialMatrixError(f"{case_id} transcript timestamps differ from observation")
    sequence_key = None
    if observation["server_record"]:
        event = observation["server_record"]["event"]
        sequence_key = (
            server["process"]["pid"],
            server["process"]["start_unix_ms"],
            event["sequence"],
        )
    return started, finished, bindings, coverage_digest, sequence_key


def _coverage_root(bindings: list[dict[str, Any]]) -> str:
    entries = [
        {
            "case_id": binding["subject"].removeprefix("secret-coverage:"),
            "descriptor": binding["descriptor"],
        }
        for binding in sorted(bindings, key=lambda item: item["subject"])
        if binding["subject"].startswith("secret-coverage:")
    ]
    if {entry["case_id"] for entry in entries} != set(SECRET_SURFACES):
        raise AdversarialMatrixError("secret coverage manifest does not cover every source surface")
    return hashlib.sha256(canonical_json(entries)).hexdigest()


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    try:
        document = exact_object(
            value,
            {
                "schema_version",
                "harness_version",
                "proof",
                "captured_at",
                "completed_at",
                "signed_at",
                "platform",
                "secret_coverage_manifest_sha256",
                "baseline",
                "cases",
            },
            "adversarial matrix",
        )
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    if document["schema_version"] != SCHEMA_VERSION:
        raise AdversarialMatrixError(f"adversarial schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise AdversarialMatrixError(
            f"adversarial harness_version must be {HARNESS_VERSION!r}"
        )
    proof = parse_proof_binding(document["proof"])
    if proof["candidate"]["version"] != PRODUCT_VERSION:
        raise AdversarialMatrixError("adversarial evidence is not for version 0.4.0")
    _platform(document["platform"])

    entries: dict[str, dict[str, Any]] = {}
    try:
        baseline = exact_object(document["baseline"], REPORT_ENTRY_FIELDS, "baseline")
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error
    entries["baseline"] = baseline
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise AdversarialMatrixError("adversarial matrix must contain every case exactly once")
    for index, raw_case in enumerate(cases):
        try:
            entry = exact_object(raw_case, REPORT_ENTRY_FIELDS, f"cases[{index}]")
        except RawArtifactError as error:
            raise AdversarialMatrixError(str(error)) from error
        case_id = entry["id"]
        if not isinstance(case_id, str) or case_id not in REQUIRED_CASES:
            raise AdversarialMatrixError(f"unknown adversarial case: {case_id!r}")
        if case_id in entries:
            raise AdversarialMatrixError(f"duplicate adversarial case: {case_id!r}")
        entries[case_id] = entry
    if set(entries) != set(all_subject_ids()):
        raise AdversarialMatrixError("adversarial matrix is missing a required case")

    starts: list[datetime] = []
    finishes: list[datetime] = []
    bindings: list[dict[str, Any]] = []
    canary_digests: set[str] = set()
    sequence_keys: set[tuple[int, int, int]] = set()
    identity_client_paths: set[str] = set()
    identity_client_binaries: set[str] = set()
    request_digests: set[str] = set()
    baseline_euid: int | None = None
    baseline_audit_session: int | None = None
    baseline_peer: dict[str, Any] | None = None

    for case_id in all_subject_ids():
        entry = entries[case_id]
        spec = case_spec(case_id)
        expected_entry = {
            "id": case_id,
            "category": spec.category,
            "role": spec.role,
            "precondition": spec.precondition,
            "event": spec.event,
        }
        for field, expected in expected_entry.items():
            if entry[field] != expected:
                raise AdversarialMatrixError(f"{case_id} report entry {field} differs")
        transcript_descriptor, transcript_value = _read_json(
            artifacts,
            entry["artifact"],
            expected_kind="adversarial-transcript",
            label=f"{case_id}.artifact",
        )
        started, finished, nested, canary, sequence_key = _validate_transcript(
            transcript_value,
            case_id=case_id,
            proof=proof,
            artifacts=artifacts,
        )
        starts.append(started)
        finishes.append(finished)
        bindings.append({"subject": case_id, "descriptor": transcript_descriptor.as_dict()})
        bindings.extend(nested)
        if canary is not None:
            canary_digests.add(canary)
        if sequence_key is not None:
            if sequence_key in sequence_keys:
                raise AdversarialMatrixError(
                    "server event process/sequence identity is reused"
                )
            sequence_keys.add(sequence_key)

        transcript = transcript_value
        request = transcript["request_sha256"]
        if request == proof["run_nonce"] or request in request_digests:
            raise AdversarialMatrixError(f"{case_id} request digest is reused")
        request_digests.add(request)
        peer = transcript["peer"]
        if case_id == "baseline":
            baseline_euid = peer["euid"]
            baseline_audit_session = peer["audit_session_id"]
            baseline_peer = dict(peer)
        elif case_id == "wrong-uid" and peer["euid"] == baseline_euid:
            raise AdversarialMatrixError("wrong-uid did not vary the server-observed euid")
        elif case_id == "wrong-audit-session" and peer["audit_session_id"] == baseline_audit_session:
            raise AdversarialMatrixError(
                "wrong-audit-session did not vary the server-observed audit session"
            )

        if spec.category == "identity":
            if baseline_peer is None:  # pragma: no cover - baseline is source ordered first
                raise AdversarialMatrixError("baseline identity is unavailable")
            signing_fields = {
                "team_id": peer["team_id"],
                "signing_id": peer["signing_id"],
                "designated_requirement_sha256": peer[
                    "designated_requirement_sha256"
                ],
                "entitlements_sha256": peer["entitlements_sha256"],
            }
            baseline_signing = {
                field: baseline_peer[field] for field in signing_fields
            }
            if case_id == "wrong-team-id":
                if (
                    signing_fields["team_id"] == baseline_signing["team_id"]
                    or signing_fields["signing_id"] != baseline_signing["signing_id"]
                ):
                    raise AdversarialMatrixError(
                        "wrong-team-id did not isolate a non-product Team/ad-hoc peer"
                    )
            elif case_id in {"wrong-bundle-identifier", "same-team-unknown-bundle"}:
                if (
                    signing_fields["team_id"] != baseline_signing["team_id"]
                    or signing_fields["signing_id"] == baseline_signing["signing_id"]
                    or signing_fields["entitlements_sha256"]
                    != baseline_signing["entitlements_sha256"]
                ):
                    raise AdversarialMatrixError(
                        f"{case_id} did not isolate the source-pinned bundle/role condition"
                    )
            elif case_id == "wrong-designated-requirement":
                if (
                    signing_fields["team_id"] != baseline_signing["team_id"]
                    or signing_fields["signing_id"] != baseline_signing["signing_id"]
                    or signing_fields["entitlements_sha256"]
                    != baseline_signing["entitlements_sha256"]
                    or signing_fields["designated_requirement_sha256"]
                    == baseline_signing["designated_requirement_sha256"]
                ):
                    raise AdversarialMatrixError(
                        "wrong-designated-requirement did not isolate its policy condition"
                    )
            elif case_id == "wrong-entitlement":
                if (
                    signing_fields["team_id"] != baseline_signing["team_id"]
                    or signing_fields["signing_id"] != baseline_signing["signing_id"]
                    or signing_fields["designated_requirement_sha256"]
                    != baseline_signing["designated_requirement_sha256"]
                    or signing_fields["entitlements_sha256"]
                    == baseline_signing["entitlements_sha256"]
                ):
                    raise AdversarialMatrixError(
                        "wrong-entitlement did not isolate its policy condition"
                    )
            elif any(
                signing_fields[field] != baseline_signing[field]
                for field in signing_fields
            ):
                raise AdversarialMatrixError(
                    f"{case_id} changed an unrelated code-signature policy condition"
                )
            if peer["process_image_path"] in identity_client_paths:
                raise AdversarialMatrixError("identity cases reuse one client path")
            if peer["binary_sha256"] in identity_client_binaries:
                raise AdversarialMatrixError("identity cases reuse one client binary")
            identity_client_paths.add(peer["process_image_path"])
            identity_client_binaries.add(peer["binary_sha256"])

    if len(canary_digests) != 1:
        raise AdversarialMatrixError(
            "secret coverage surfaces do not bind one fresh one-way canary digest"
        )
    paths = [binding["descriptor"]["path"] for binding in bindings]
    subjects = [binding["subject"] for binding in bindings]
    if len(paths) != len(set(paths)) or len(subjects) != len(set(subjects)):
        raise AdversarialMatrixError("adversarial raw bindings reuse a subject or path")
    coverage_root = _coverage_root(bindings)
    if document["secret_coverage_manifest_sha256"] != coverage_root:
        raise AdversarialMatrixError("secret coverage manifest digest differs")

    captured_at = _timestamp(document["captured_at"], "captured_at")
    completed_at = _timestamp(document["completed_at"], "completed_at")
    signed_at = _timestamp(document["signed_at"], "signed_at")
    if captured_at != min(starts) or completed_at != max(finishes) or not completed_at <= signed_at:
        raise AdversarialMatrixError(
            "captured_at/completed_at/signed_at do not cover every adversarial case"
        )
    if signed_at > datetime.now(timezone.utc):
        raise AdversarialMatrixError("adversarial signed_at is future-dated")

    return {
        "document": document,
        "proof": proof,
        "started_at": captured_at,
        "completed_at": completed_at,
        "artifacts": sorted(bindings, key=lambda item: item["subject"]),
        "secret_coverage_manifest_sha256": coverage_root,
    }


def validate_adversarial_matrix(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
    try:
        return _validate(value, artifacts)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error


def load_adversarial_matrix(path: Path, *, evidence_root: Path) -> dict[str, Any]:
    try:
        value = load_json_file(path, maximum=MAX_REPORT_BYTES, label="adversarial report")
        with ArtifactReader(evidence_root) as artifacts:
            return validate_adversarial_matrix(value, artifacts)
    except RawArtifactError as error:
        raise AdversarialMatrixError(str(error)) from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = load_adversarial_matrix(
            arguments.report, evidence_root=arguments.evidence_root
        )
    except (AdversarialMatrixError, OSError) as error:
        raise SystemExit(f"error: adversarial evidence failed: {error}") from error
    print(
        "adversarial raw evidence structurally verified (collector signature not checked): "
        f"{len(result['artifacts'])} raw artifacts"
    )


if __name__ == "__main__":
    main()
