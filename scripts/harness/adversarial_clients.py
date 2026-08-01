#!/usr/bin/env python3
"""Proof-to-byte separately-signed adversarial client matrix.

Client signature assessments and every baseline/attack transcript are reopened
from strict artifact descriptors. Authorization decisions, denial codes,
cleanup, secret absence, exit codes, client identity, and request nonces are
recomputed from the transcript bytes. Aggregate-level collector signature
verification supplies the external provenance trust boundary.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
import re
from typing import Any

if __package__:
    from .physical_machine_identity import (
        PhysicalMachineIdentityError,
        validate_physical_hardware_model,
    )
    from .raw_artifacts import (
        ArtifactReader,
        RawArtifactError,
        exact_object,
        load_json_file,
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
        ArtifactReader,
        RawArtifactError,
        exact_object,
        load_json_file,
        parse_proof_binding,
        require_sha256,
    )


SCHEMA_VERSION = 2
HARNESS_VERSION = "adversarial-clients-v2"
PRODUCT_VERSION = "0.4.0"
MAX_REPORT_BYTES = 1 * 1024 * 1024
CDHASH_RE = re.compile(r"^[0-9a-f]{40,64}$")
DENIAL_CODE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]{0,63}$")
TEAM_ID = "YKUPL7Z869"
ALLOWED_SIGNING_ID = "com.bill.clashformac"


# id -> (category, client, denial code, cleanup)
REQUIRED_CASES: dict[str, tuple[str, str, str, str]] = {
    "wrong-team-id": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-bundle-identifier": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-designated-requirement": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-entitlement": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-uid": ("identity", "denied", "unauthorizedPeer", "off"),
    "wrong-audit-session": ("identity", "denied", "unauthorizedPeer", "off"),
    "stale-pid-evidence": ("identity", "denied", "unauthorizedPeer", "off"),
    "stale-audit-evidence": ("identity", "denied", "unauthorizedPeer", "off"),
    "inactive-console-user": ("identity", "denied", "consoleUserMismatch", "off"),
    "same-team-unknown-bundle": ("identity", "denied", "unauthorizedPeer", "off"),
    "replayed-operation": ("replay", "allowed", "replayRejected", "off"),
    "replayed-start-ticket": ("replay", "allowed", "ticketReplayRejected", "off"),
    "duplicate-redemption": ("replay", "allowed", "ticketAlreadyRedeemed", "off"),
    "replay-cursor-rollback": ("replay", "allowed", "replayRejected", "quarantined"),
    "authority-journal-truncation": (
        "journal",
        "allowed",
        "journalIntegrityFailure",
        "quarantined",
    ),
    "authority-journal-tamper": (
        "journal",
        "allowed",
        "journalIntegrityFailure",
        "quarantined",
    ),
    "authority-journal-symlink": (
        "journal",
        "allowed",
        "journalIntegrityFailure",
        "quarantined",
    ),
    "oversize-message": ("protocol", "allowed", "protocolViolation", "off"),
    "deep-message": ("protocol", "allowed", "protocolViolation", "off"),
    "noncanonical-message": ("protocol", "allowed", "protocolViolation", "off"),
    "request-flood": ("backpressure", "allowed", "resourceExhausted", "off"),
    "in-flight-saturation": ("backpressure", "allowed", "resourceExhausted", "off"),
    "event-queue-saturation": ("backpressure", "allowed", "resourceExhausted", "off"),
    "heartbeat-loss": ("liveness", "allowed", "leaseRevoked", "off"),
    "fast-user-switching-race": ("liveness", "allowed", "leaseRevoked", "off"),
    "late-callback": ("liveness", "allowed", "staleOperation", "off"),
    "secret-extraction-logs": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-preferences": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-journal": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-crash-records": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-snapshots": ("secret", "allowed", "secretAbsent", "off"),
    "secret-extraction-evidence": ("secret", "allowed", "secretAbsent", "off"),
}

PLATFORM_FIELDS = {"architecture", "macos_version", "hardware_model", "clean_install"}
SIGNING_FIELDS = {"team_id", "allowed_client", "denied_client"}
IDENTITY_FIELDS = {
    "signing_id",
    "cdhash",
    "designated_requirement_sha256",
    "binary_sha256",
    "evidence_artifact",
}
BASELINE_FIELDS = {"client", "artifact"}
CASE_FIELDS = {"id", "category", "client", "artifact"}
SIGNATURE_EVIDENCE_FIELDS = {
    "schema_version",
    "proof",
    "client",
    "team_id",
    "signing_id",
    "cdhash",
    "designated_requirement_sha256",
    "binary_sha256",
    "command",
    "exit_code",
    "assessed_at",
}
TRANSCRIPT_FIELDS = {
    "schema_version",
    "proof",
    "case_id",
    "category",
    "client",
    "client_binary_sha256",
    "request_nonce",
    "command",
    "started_at",
    "finished_at",
    "exit_code",
    "events",
}
TRANSCRIPT_EVENT_FIELDS = {
    "sequence",
    "type",
    "case_id",
    "outcome",
    "denial_code",
    "cleanup",
    "secret_observed",
}


class AdversarialMatrixError(ValueError):
    """Adversarial evidence is incomplete, drifted, or not fail-closed."""


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


def _bounded_text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise AdversarialMatrixError(f"{label} must be bounded printable text")
    return value


def _platform(value: Any) -> dict[str, Any]:
    platform = exact_object(value, PLATFORM_FIELDS, "platform")
    if platform["architecture"] != "arm64" or platform["clean_install"] is not True:
        raise AdversarialMatrixError("adversarial matrix requires a clean Apple Silicon machine")
    _bounded_text(platform["macos_version"], "platform.macos_version")
    try:
        validate_physical_hardware_model(platform["hardware_model"])
    except PhysicalMachineIdentityError as error:
        raise AdversarialMatrixError("platform.hardware_model is invalid") from error
    return platform


def _identity(value: Any, client: str) -> dict[str, Any]:
    identity = exact_object(value, IDENTITY_FIELDS, f"signing.{client}_client")
    signing_id = _bounded_text(identity["signing_id"], f"signing.{client}.signing_id")
    cdhash = identity["cdhash"]
    if not isinstance(cdhash, str) or not CDHASH_RE.fullmatch(cdhash):
        raise AdversarialMatrixError(f"signing.{client}.cdhash is invalid")
    return {
        "signing_id": signing_id,
        "cdhash": cdhash,
        "designated_requirement_sha256": require_sha256(
            identity["designated_requirement_sha256"],
            f"signing.{client}.designated_requirement_sha256",
        ),
        "binary_sha256": require_sha256(
            identity["binary_sha256"], f"signing.{client}.binary_sha256"
        ),
        "evidence_artifact": identity["evidence_artifact"],
    }


def _validate_signature_evidence(
    value: Any,
    *,
    client: str,
    identity: dict[str, Any],
    proof: dict[str, Any],
) -> datetime:
    evidence = exact_object(
        value, SIGNATURE_EVIDENCE_FIELDS, f"signing.{client}.raw_evidence"
    )
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1:
        raise AdversarialMatrixError(f"signing.{client} evidence schema_version must be 1")
    if parse_proof_binding(evidence["proof"], f"signing.{client}.raw_evidence.proof") != proof:
        raise AdversarialMatrixError(f"signing.{client} evidence proof differs from its report")
    expected = {
        "client": client,
        "team_id": TEAM_ID,
        "signing_id": identity["signing_id"],
        "cdhash": identity["cdhash"],
        "designated_requirement_sha256": identity["designated_requirement_sha256"],
        "binary_sha256": identity["binary_sha256"],
    }
    for field, wanted in expected.items():
        if evidence[field] != wanted:
            raise AdversarialMatrixError(f"signing.{client} raw {field} differs from its report")
    if evidence["command"] != [proof["collector"]["version"], "client-signature", client]:
        raise AdversarialMatrixError(f"signing.{client} assessment command is not canonical")
    if evidence["exit_code"] != 0:
        raise AdversarialMatrixError(f"signing.{client} assessment command failed")
    return _timestamp(evidence["assessed_at"], f"signing.{client}.assessed_at")


def _signing(
    value: Any, proof: dict[str, Any], artifacts: ArtifactReader
) -> tuple[dict[str, Any], list[dict[str, Any]], list[datetime]]:
    signing = exact_object(value, SIGNING_FIELDS, "signing")
    if signing["team_id"] != TEAM_ID:
        raise AdversarialMatrixError("signing.team_id is not the product Team ID")
    identities = {
        client: _identity(signing[f"{client}_client"], client)
        for client in ("allowed", "denied")
    }
    if identities["allowed"]["signing_id"] != ALLOWED_SIGNING_ID:
        raise AdversarialMatrixError("allowed client is not the signed Host identity")
    if identities["denied"]["signing_id"] == ALLOWED_SIGNING_ID:
        raise AdversarialMatrixError("denied client must have a distinct signing identifier")
    if identities["allowed"]["cdhash"] == identities["denied"]["cdhash"]:
        raise AdversarialMatrixError("allowed and denied clients must be separately signed")
    if identities["allowed"]["binary_sha256"] == identities["denied"]["binary_sha256"]:
        raise AdversarialMatrixError("allowed and denied client binaries must differ")
    bindings: list[dict[str, Any]] = []
    assessed_at: list[datetime] = []
    for client, identity in identities.items():
        descriptor, evidence = artifacts.read_json(
            identity["evidence_artifact"],
            expected_kind="client-signature-evidence",
            label=f"signing.{client}.evidence_artifact",
        )
        assessed_at.append(
            _validate_signature_evidence(
                evidence, client=client, identity=identity, proof=proof
            )
        )
        bindings.append(
            {
                "subject": f"client-signature:{client}",
                "descriptor": descriptor.as_dict(),
            }
        )
    return identities, bindings, assessed_at


def _events(
    value: Any,
    *,
    case_id: str,
    outcome: str,
    denial_code: str,
    cleanup: str,
) -> None:
    if not isinstance(value, list) or len(value) != 3:
        raise AdversarialMatrixError(f"{case_id} transcript must have three events")
    expected = (
        (0, "attack-started", "", "", False),
        (1, "authorization-decision", outcome, denial_code, False),
        (2, "attack-finished", "", "", False),
    )
    for index, (sequence, event_type, event_outcome, event_code, secret) in enumerate(expected):
        event = exact_object(value[index], TRANSCRIPT_EVENT_FIELDS, f"{case_id}.events[{index}]")
        wanted = {
            "sequence": sequence,
            "type": event_type,
            "case_id": case_id,
            "outcome": event_outcome,
            "denial_code": event_code,
            "cleanup": cleanup if index == 1 else "",
            "secret_observed": secret,
        }
        if event != wanted:
            raise AdversarialMatrixError(f"{case_id}.events[{index}] differs from required outcome")


def _validate_transcript(
    value: Any,
    *,
    case_id: str,
    category: str,
    client: str,
    identity: dict[str, Any],
    proof: dict[str, Any],
    expected_outcome: str,
    expected_code: str,
    expected_cleanup: str,
    nonces: set[str],
) -> tuple[datetime, datetime]:
    transcript = exact_object(value, TRANSCRIPT_FIELDS, f"{case_id}.transcript")
    if type(transcript["schema_version"]) is not int or transcript["schema_version"] != 1:
        raise AdversarialMatrixError(f"{case_id} transcript schema_version must be 1")
    if parse_proof_binding(transcript["proof"], f"{case_id}.transcript.proof") != proof:
        raise AdversarialMatrixError(f"{case_id} transcript proof differs from its report")
    bindings = {
        "case_id": case_id,
        "category": category,
        "client": client,
        "client_binary_sha256": identity["binary_sha256"],
    }
    for field, expected in bindings.items():
        if transcript[field] != expected:
            raise AdversarialMatrixError(f"{case_id} transcript {field} binding differs")
    nonce = require_sha256(transcript["request_nonce"], f"{case_id}.request_nonce")
    if nonce == proof["run_nonce"] or nonce in nonces:
        raise AdversarialMatrixError(f"{case_id} request nonce is reused")
    nonces.add(nonce)
    if transcript["command"] != [proof["collector"]["version"], "adversarial", case_id]:
        raise AdversarialMatrixError(f"{case_id} transcript command is not canonical")
    started = _timestamp(transcript["started_at"], f"{case_id}.started_at")
    finished = _timestamp(transcript["finished_at"], f"{case_id}.finished_at")
    duration = (finished - started).total_seconds()
    if duration <= 0 or duration > 600:
        raise AdversarialMatrixError(f"{case_id} transcript duration is outside 0..10min")
    expected_exit = 0 if expected_outcome == "authorized" else 77
    if transcript["exit_code"] != expected_exit:
        raise AdversarialMatrixError(f"{case_id} transcript exit_code differs from its outcome")
    if expected_code and not DENIAL_CODE_RE.fullmatch(expected_code):
        raise AdversarialMatrixError(f"{case_id} expected denial code is invalid")
    _events(
        transcript["events"],
        case_id=case_id,
        outcome=expected_outcome,
        denial_code=expected_code,
        cleanup=expected_cleanup,
    )
    return started, finished


def _validate(value: Any, artifacts: ArtifactReader) -> dict[str, Any]:
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
            "signing",
            "baseline",
            "cases",
        },
        "adversarial matrix",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise AdversarialMatrixError(f"adversarial schema_version must be {SCHEMA_VERSION}")
    if document["harness_version"] != HARNESS_VERSION:
        raise AdversarialMatrixError(
            f"adversarial harness_version must be {HARNESS_VERSION!r}"
        )
    proof = parse_proof_binding(document["proof"])
    if proof["candidate"]["version"] != PRODUCT_VERSION:
        raise AdversarialMatrixError("adversarial evidence is not for version 0.4.0")
    _platform(document["platform"])
    identities, bindings, signature_times = _signing(
        document["signing"], proof, artifacts
    )
    nonces: set[str] = set()
    starts: list[datetime] = []
    finishes: list[datetime] = []

    baseline = exact_object(document["baseline"], BASELINE_FIELDS, "baseline")
    if baseline["client"] != "allowed":
        raise AdversarialMatrixError("baseline must use the allowed client")
    descriptor, transcript = artifacts.read_json(
        baseline["artifact"],
        expected_kind="adversarial-transcript",
        label="baseline.artifact",
    )
    baseline_started, baseline_finished = _validate_transcript(
        transcript,
        case_id="baseline",
        category="baseline",
        client="allowed",
        identity=identities["allowed"],
        proof=proof,
        expected_outcome="authorized",
        expected_code="",
        expected_cleanup="off",
        nonces=nonces,
    )
    starts.append(baseline_started)
    finishes.append(baseline_finished)
    bindings.append({"subject": "baseline", "descriptor": descriptor.as_dict()})

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise AdversarialMatrixError("adversarial matrix must contain every case exactly once")
    seen: set[str] = set()
    for index, raw_case in enumerate(cases):
        case = exact_object(raw_case, CASE_FIELDS, f"cases[{index}]")
        case_id = case["id"]
        if not isinstance(case_id, str) or case_id not in REQUIRED_CASES:
            raise AdversarialMatrixError(f"unknown adversarial case: {case_id!r}")
        if case_id in seen:
            raise AdversarialMatrixError(f"duplicate adversarial case: {case_id!r}")
        seen.add(case_id)
        category, client, denial_code, cleanup = REQUIRED_CASES[case_id]
        if case["category"] != category or case["client"] != client:
            raise AdversarialMatrixError(f"{case_id} category/client binding differs")
        descriptor, transcript = artifacts.read_json(
            case["artifact"],
            expected_kind="adversarial-transcript",
            label=f"{case_id}.artifact",
        )
        started, finished = _validate_transcript(
            transcript,
            case_id=case_id,
            category=category,
            client=client,
            identity=identities[client],
            proof=proof,
            expected_outcome="denied",
            expected_code=denial_code,
            expected_cleanup=cleanup,
            nonces=nonces,
        )
        starts.append(started)
        finishes.append(finished)
        bindings.append({"subject": case_id, "descriptor": descriptor.as_dict()})
    if seen != set(REQUIRED_CASES):
        raise AdversarialMatrixError("adversarial matrix is missing a required case")
    if not starts or max(signature_times) > min(starts):
        raise AdversarialMatrixError(
            "client signature assessments must precede adversarial transcripts"
        )
    if _timestamp(document["captured_at"], "captured_at") != min(
        starts + signature_times
    ):
        raise AdversarialMatrixError("captured_at differs from the earliest raw evidence")
    completed_at = _timestamp(document["completed_at"], "completed_at")
    signed_at = _timestamp(document["signed_at"], "signed_at")
    if completed_at != max(finishes + signature_times) or signed_at < completed_at:
        raise AdversarialMatrixError(
            "completed_at/signed_at do not cover every adversarial transcript"
        )
    return {
        "document": document,
        "proof": proof,
        "started_at": min(starts + signature_times),
        "completed_at": completed_at,
        "artifacts": bindings,
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
