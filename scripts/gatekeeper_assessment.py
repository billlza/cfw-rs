#!/usr/bin/env python3
"""Capture and validate fail-closed Gatekeeper evidence.

An ``spctl --assess`` exit status is not sufficient evidence: when system
policy assessments are disabled, ``spctl`` can report an otherwise unnotarized
Developer ID product as accepted with ``override=security disabled``.  This
module therefore proves the global assessment switch first, rejects every
override, requires a notarized Developer ID policy result and matching signed
identity, and binds the raw status, assessment, and signing output to SHA-256
digests.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

if __package__:
    from .hash_artifact import build_manifest
else:
    from hash_artifact import build_manifest


EXPECTED_TEAM_ID = "YKUPL7Z869"
LEGACY_EVIDENCE_SCHEMA_VERSION = 1
LEGACY_EVIDENCE_DOCUMENT_KIND = "gatekeeper-assessment-evidence-v1"
POLICY_EVIDENCE_SCHEMA_VERSION = 2
POLICY_EVIDENCE_DOCUMENT_KIND = "gatekeeper-assessment-evidence-v2"
EVIDENCE_SCHEMA_VERSION = 3
EVIDENCE_DOCUMENT_KIND = "gatekeeper-assessment-evidence-v3"
MAX_OUTPUT_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEVELOPER_ID_RE = re.compile(r"^Developer ID Application: .+ \(([A-Z0-9]{10})\)$")
SECURE_TIMESTAMP_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r" {0,1}([1-9]|[12][0-9]|3[01]), ([0-9]{4}) at "
    r"([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$"
)
STATUS_COMMAND = ("/usr/sbin/spctl", "--status")
CODESIGN_COMMAND_PREFIX = ("/usr/bin/codesign", "-d", "--verbose=4")
CAPTURE_ENVIRONMENT = {"LC_ALL": "C", "LANG": "C"}


class GatekeeperEvidenceError(ValueError):
    """Gatekeeper is disabled or the captured assessment is not trustworthy."""


def _bounded_output(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GatekeeperEvidenceError(f"{label} is empty or is not text")
    if len(value.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise GatekeeperEvidenceError(f"{label} exceeds {MAX_OUTPUT_BYTES} bytes")
    if "\x00" in value:
        raise GatekeeperEvidenceError(f"{label} contains a NUL byte")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise GatekeeperEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _require_utc_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GatekeeperEvidenceError("captured_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GatekeeperEvidenceError("captured_at is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise GatekeeperEvidenceError("captured_at must use UTC")
    return value


def _reject_diagnostic_lines(lines: list[str], label: str) -> None:
    if any(line.casefold().startswith(("warning:", "error:")) for line in lines):
        raise GatekeeperEvidenceError(f"{label} contains a warning or error diagnostic")


def _reject_noncanonical_known_fields(
    lines: list[str],
    canonical_fields: tuple[str, ...],
    label: str,
) -> None:
    expected = {field.casefold(): field for field in canonical_fields}
    for line in lines:
        match = re.match(r"(?i)^([a-z][a-z0-9]*)\s*=", line)
        if match is None:
            continue
        canonical = expected.get(match.group(1).casefold())
        if canonical is not None and not line.startswith(f"{canonical}="):
            raise GatekeeperEvidenceError(
                f"{label} contains a noncanonical {canonical} field"
            )


def validate_status_output(value: object) -> str:
    """Require the only successful global Gatekeeper state."""
    output = _bounded_output(value, "spctl status output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines != ["assessments enabled"]:
        raise GatekeeperEvidenceError(
            "Gatekeeper assessments are not provably enabled "
            f"(spctl --status returned {lines!r})"
        )
    return output


def _parse_assessment_output(
    value: object,
    expected_team_id: str,
    *,
    require_origin: bool,
    expected_target: str | None = None,
) -> tuple[str, str | None, str]:
    output = _bounded_output(value, "spctl assessment output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _reject_diagnostic_lines(lines, "spctl assessment output")
    if any(re.match(r"(?i)^override\s*=", line) for line in lines):
        raise GatekeeperEvidenceError(
            "Gatekeeper assessment used a security override instead of policy"
        )
    _reject_noncanonical_known_fields(
        lines,
        ("source", "origin", "override"),
        "spctl assessment output",
    )
    accepted = [line for line in lines if re.fullmatch(r".+:\s+accepted", line)]
    if len(accepted) != 1:
        raise GatekeeperEvidenceError("spctl assessment output does not report accepted")
    if expected_target is not None and accepted != [f"{expected_target}: accepted"]:
        raise GatekeeperEvidenceError(
            "spctl assessment accepted line does not identify the exact target"
        )

    sources = [line.partition("=")[2] for line in lines if line.startswith("source=")]
    if sources != ["Notarized Developer ID"]:
        raise GatekeeperEvidenceError(
            "Gatekeeper source is not exactly Notarized Developer ID"
        )
    if any(
        re.match(r"(?i)^origin\s*=", line) is not None
        and not line.startswith("origin=")
        for line in lines
    ):
        raise GatekeeperEvidenceError("Gatekeeper output has a malformed origin field")
    origins = [line.partition("=")[2] for line in lines if line.startswith("origin=")]
    if len(origins) > 1 or (require_origin and len(origins) != 1):
        raise GatekeeperEvidenceError("Gatekeeper output has no unique signing origin")
    if not origins:
        return sources[0], None, output
    origin = origins[0]
    match = DEVELOPER_ID_RE.fullmatch(origin)
    if match is None or match.group(1) != expected_team_id:
        raise GatekeeperEvidenceError(
            f"Gatekeeper origin is not a Developer ID Application for {expected_team_id}"
        )
    return sources[0], origin, output


def validate_assessment_output(
    value: object,
    expected_team_id: str = EXPECTED_TEAM_ID,
    *,
    expected_target: str | None = None,
) -> tuple[str, str, str]:
    """Validate legacy spctl output, which must report the signing origin."""
    source, origin, output = _parse_assessment_output(
        value,
        expected_team_id,
        require_origin=True,
        expected_target=expected_target,
    )
    if origin is None:
        raise GatekeeperEvidenceError("Gatekeeper output has no unique signing origin")
    return source, origin, output


def validate_current_assessment_output(
    value: object,
    expected_team_id: str = EXPECTED_TEAM_ID,
    *,
    expected_target: str | None = None,
) -> tuple[str, str | None, str]:
    """Validate current spctl output while preserving an honestly absent origin."""
    return _parse_assessment_output(
        value,
        expected_team_id,
        require_origin=False,
        expected_target=expected_target,
    )


def validate_codesign_output(
    value: object, expected_team_id: str = EXPECTED_TEAM_ID
) -> tuple[str, str]:
    """Return the leaf signing authority and normalized raw codesign output."""
    output = _bounded_output(value, "codesign detail output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _reject_diagnostic_lines(lines, "codesign detail output")
    _reject_noncanonical_known_fields(
        lines,
        ("Authority", "TeamIdentifier", "Timestamp", "Signature"),
        "codesign detail output",
    )
    authorities = [
        line.partition("=")[2] for line in lines if line.startswith("Authority=")
    ]
    if not authorities:
        raise GatekeeperEvidenceError("codesign output has no signing authority")
    authority = authorities[0]
    match = DEVELOPER_ID_RE.fullmatch(authority)
    developer_id_authorities = [
        item for item in authorities if DEVELOPER_ID_RE.fullmatch(item)
    ]
    if (
        match is None
        or match.group(1) != expected_team_id
        or developer_id_authorities != [authority]
    ):
        raise GatekeeperEvidenceError(
            f"leaf signing authority is not Developer ID Application for {expected_team_id}"
        )
    team_identifiers = [
        line.partition("=")[2]
        for line in lines
        if line.startswith("TeamIdentifier=")
    ]
    if team_identifiers != [expected_team_id]:
        raise GatekeeperEvidenceError("codesign output has the wrong TeamIdentifier")
    if "Signature=adhoc" in lines:
        raise GatekeeperEvidenceError("ad-hoc signing is not Gatekeeper evidence")
    timestamps = [
        line.partition("=")[2] for line in lines if line.startswith("Timestamp=")
    ]
    if len(timestamps) != 1:
        raise GatekeeperEvidenceError("codesign output has no secure timestamp")
    timestamp_match = SECURE_TIMESTAMP_RE.fullmatch(timestamps[0])
    if timestamp_match is None:
        raise GatekeeperEvidenceError("codesign output has no secure timestamp")
    month = (
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ).index(timestamp_match.group(1)) + 1
    try:
        datetime(
            int(timestamp_match.group(3)),
            month,
            int(timestamp_match.group(2)),
            int(timestamp_match.group(4)),
            int(timestamp_match.group(5)),
            int(timestamp_match.group(6)),
        )
    except ValueError as error:
        raise GatekeeperEvidenceError(
            "codesign output has no secure timestamp"
        ) from error
    return authority, output


def _canonical_recorded_target(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\0" in value
        or not Path(value).is_absolute()
        or os.path.normpath(value) != value
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper assessed_target is not a canonical absolute path"
        )
    return value


def _assessment_command(
    target: str,
    assessment_type: str,
    primary_signature_context: bool,
) -> list[str]:
    if assessment_type not in {"execute", "open"}:
        raise GatekeeperEvidenceError("Gatekeeper assessment type is invalid")
    command = [
        "/usr/sbin/spctl",
        "--assess",
        "--type",
        assessment_type,
    ]
    if primary_signature_context:
        command.extend(["--context", "context:primary-signature"])
    command.extend(["--verbose=4", target])
    return command


def _require_exact_command(
    value: object,
    expected: list[str],
    label: str,
) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != expected
    ):
        raise GatekeeperEvidenceError(f"Gatekeeper {label} is not exact")
    return value


def _target_identity(target: Path, assessment_type: str) -> tuple[str, str]:
    try:
        manifest = build_manifest(target, algorithm="sha256-tree-v2")
    except (OSError, ValueError, KeyError) as error:
        raise GatekeeperEvidenceError(
            "cannot derive the exact Gatekeeper target identity"
        ) from error
    if assessment_type == "execute" and target.is_dir():
        digest = manifest.get("sha256")
        algorithm = "sha256-tree-v2"
    elif assessment_type == "open" and target.is_file():
        entries = manifest.get("entries")
        digest = (
            entries[0].get("sha256")
            if isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], dict)
            else None
        )
        algorithm = "sha256-file"
    else:
        raise GatekeeperEvidenceError(
            "Gatekeeper target type is incompatible with its assessment type"
        )
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise GatekeeperEvidenceError(
            "Gatekeeper target identity is not a lowercase SHA-256"
        )
    return digest, algorithm


def validate_evidence(
    value: object,
    expected_team_id: str = EXPECTED_TEAM_ID,
    *,
    expected_assessment_type: str | None = None,
    expected_primary_signature_context: bool | None = None,
    expected_target: Path | str | None = None,
) -> dict[str, Any]:
    if (expected_assessment_type is None) != (
        expected_primary_signature_context is None
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper expected assessment policy is incomplete"
        )
    if expected_assessment_type is not None and (
        expected_assessment_type not in {"execute", "open"}
        or not isinstance(expected_primary_signature_context, bool)
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper expected assessment policy is invalid"
        )
    legacy_fields = {
        "schema_version",
        "document",
        "assessment",
        "source",
        "assessment_source",
        "assessments_enabled",
        "authority",
        "origin",
        "status_output",
        "status_output_sha256",
        "assessment_output",
        "assessment_output_sha256",
        "codesign_output",
        "codesign_output_sha256",
        "target_signed_app_tree_sha256",
        "captured_at",
    }
    policy_fields = legacy_fields | {
        "assessment_exit_code",
        "assessment_type",
        "codesign_exit_code",
        "identity_source",
        "origin_status",
        "post_status_exit_code",
        "post_status_output",
        "post_status_output_sha256",
        "primary_signature_context",
        "signing_team_id",
        "status_exit_code",
    }
    current_fields = policy_fields | {
        "assessed_target",
        "target_identity_algorithm",
        "status_command",
        "assessment_command",
        "codesign_command",
        "post_status_command",
        "command_environment",
    }
    if not isinstance(value, dict):
        raise GatekeeperEvidenceError("Gatekeeper evidence has an unexpected field set")
    if type(value.get("schema_version")) is not int:
        raise GatekeeperEvidenceError("Gatekeeper evidence schema/document is unsupported")
    schema_identity = (value.get("schema_version"), value.get("document"))
    if schema_identity == (
        LEGACY_EVIDENCE_SCHEMA_VERSION,
        LEGACY_EVIDENCE_DOCUMENT_KIND,
    ):
        if set(value) != legacy_fields:
            raise GatekeeperEvidenceError(
                "Gatekeeper evidence has an unexpected field set"
            )
        current = False
        target_bound = False
    elif schema_identity == (
        POLICY_EVIDENCE_SCHEMA_VERSION,
        POLICY_EVIDENCE_DOCUMENT_KIND,
    ):
        if set(value) != policy_fields:
            raise GatekeeperEvidenceError(
                "Gatekeeper evidence has an unexpected field set"
            )
        current = True
        target_bound = False
    elif schema_identity == (EVIDENCE_SCHEMA_VERSION, EVIDENCE_DOCUMENT_KIND):
        if set(value) != current_fields:
            raise GatekeeperEvidenceError(
                "Gatekeeper evidence has an unexpected field set"
            )
        current = True
        target_bound = True
    else:
        raise GatekeeperEvidenceError("Gatekeeper evidence schema/document is unsupported")
    if expected_assessment_type is not None and not current:
        raise GatekeeperEvidenceError(
            "legacy Gatekeeper evidence does not bind an assessment policy"
        )
    if (
        expected_assessment_type is not None
        and (
            value["assessment_type"] != expected_assessment_type
            or value["primary_signature_context"]
            is not expected_primary_signature_context
        )
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper assessment policy differs from the required policy"
        )
    if value["assessment"] != "accepted" or value["source"] != "spctl":
        raise GatekeeperEvidenceError("Gatekeeper evidence is not an accepted spctl assessment")
    if value["assessments_enabled"] is not True:
        raise GatekeeperEvidenceError("Gatekeeper assessments_enabled is not true")

    status_output = validate_status_output(value["status_output"])
    if _sha256_text(status_output) != _require_sha256(
        value["status_output_sha256"], "status_output_sha256"
    ):
        raise GatekeeperEvidenceError("Gatekeeper status output digest mismatch")

    assessed_target: str | None = None
    expected_target_identity: tuple[str, str] | None = None
    if target_bound:
        assessed_target = _canonical_recorded_target(value["assessed_target"])
        expected_target_algorithm = (
            "sha256-tree-v2"
            if value["assessment_type"] == "execute"
            else "sha256-file"
        )
        if value["target_identity_algorithm"] != expected_target_algorithm:
            raise GatekeeperEvidenceError(
                "Gatekeeper target identity algorithm is unsupported"
            )
        _require_exact_command(
            value["status_command"],
            list(STATUS_COMMAND),
            "status command",
        )
        _require_exact_command(
            value["assessment_command"],
            _assessment_command(
                assessed_target,
                value["assessment_type"],
                value["primary_signature_context"],
            ),
            "assessment command",
        )
        _require_exact_command(
            value["codesign_command"],
            [*CODESIGN_COMMAND_PREFIX, assessed_target],
            "codesign command",
        )
        _require_exact_command(
            value["post_status_command"],
            list(STATUS_COMMAND),
            "post-status command",
        )
        if value["command_environment"] != CAPTURE_ENVIRONMENT:
            raise GatekeeperEvidenceError(
                "Gatekeeper command environment is not the minimal C locale"
            )
        if expected_target is not None:
            expected_target_text = _canonical_recorded_target(
                str(expected_target)
            )
            if assessed_target != expected_target_text:
                raise GatekeeperEvidenceError(
                    "Gatekeeper evidence assesses a different target"
                )
            expected_target_identity = _target_identity(
                Path(expected_target_text),
                value["assessment_type"],
            )
    elif expected_target is not None:
        raise GatekeeperEvidenceError(
            "legacy Gatekeeper evidence does not bind an exact target"
        )

    if current:
        assessment_source, origin, assessment_output = (
            validate_current_assessment_output(
                value["assessment_output"],
                expected_team_id,
                expected_target=assessed_target,
            )
        )
    else:
        assessment_source, origin, assessment_output = validate_assessment_output(
            value["assessment_output"], expected_team_id
        )
    if _sha256_text(assessment_output) != _require_sha256(
        value["assessment_output_sha256"], "assessment_output_sha256"
    ):
        raise GatekeeperEvidenceError("Gatekeeper assessment output digest mismatch")

    authority, codesign_output = validate_codesign_output(
        value["codesign_output"], expected_team_id
    )
    if _sha256_text(codesign_output) != _require_sha256(
        value["codesign_output_sha256"], "codesign_output_sha256"
    ):
        raise GatekeeperEvidenceError("Gatekeeper codesign output digest mismatch")
    if current:
        post_status_output = validate_status_output(value["post_status_output"])
        if _sha256_text(post_status_output) != _require_sha256(
            value["post_status_output_sha256"],
            "post_status_output_sha256",
        ):
            raise GatekeeperEvidenceError(
                "Gatekeeper post-status output digest mismatch"
            )
    if value["assessment_source"] != assessment_source:
        raise GatekeeperEvidenceError("Gatekeeper assessment_source differs from raw output")
    if value["origin"] != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin differs from raw output")
    if value["authority"] != authority:
        raise GatekeeperEvidenceError("Gatekeeper authority differs from raw output")
    if current:
        if (
            isinstance(value["status_exit_code"], bool)
            or value["status_exit_code"] != 0
            or isinstance(value["assessment_exit_code"], bool)
            or value["assessment_exit_code"] != 0
            or isinstance(value["codesign_exit_code"], bool)
            or value["codesign_exit_code"] != 0
            or isinstance(value["post_status_exit_code"], bool)
            or value["post_status_exit_code"] != 0
            or value["assessment_type"] not in {"execute", "open"}
            or not isinstance(value["primary_signature_context"], bool)
            or value["signing_team_id"] != expected_team_id
        ):
            raise GatekeeperEvidenceError(
                "Gatekeeper command or signing context is inconsistent"
            )
        if origin is None:
            if (
                value["origin"] is not None
                or value["origin_status"] != "not-reported-by-spctl"
                or value["identity_source"] != "codesign-leaf-authority"
            ):
                raise GatekeeperEvidenceError(
                    "Gatekeeper absent-origin evidence is inconsistent"
                )
        elif (
            value["origin"] != origin
            or value["origin_status"] != "reported-by-spctl"
            or value["identity_source"] != "spctl-origin"
            or authority != origin
        ):
            raise GatekeeperEvidenceError(
                "Gatekeeper reported origin differs from signing authority"
            )
    elif authority != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin and leaf signing authority differ")

    target_identity_sha256 = _require_sha256(
        value["target_signed_app_tree_sha256"],
        "target_signed_app_tree_sha256",
    )
    if expected_target_identity is not None and expected_target_identity != (
        target_identity_sha256,
        value["target_identity_algorithm"],
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper evidence differs from the exact target identity"
        )

    return {
        **value,
        "target_signed_app_tree_sha256": target_identity_sha256,
        "captured_at": _require_utc_timestamp(value["captured_at"]),
    }


def _merged_output(completed: subprocess.CompletedProcess[str]) -> str:
    pieces: list[str] = []
    for output in (completed.stdout, completed.stderr):
        if not output:
            continue
        if pieces and not pieces[-1].endswith("\n"):
            pieces.append("\n")
        pieces.append(output)
    return "".join(pieces)


def _run(command: list[str], label: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60,
            env=CAPTURE_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise GatekeeperEvidenceError(f"cannot capture {label}: {error}") from error


def capture(
    target: Path,
    assessment_type: str,
    *,
    primary_signature_context: bool,
    expected_team_id: str = EXPECTED_TEAM_ID,
) -> dict[str, Any]:
    if (
        not target.is_absolute()
        or target.is_symlink()
        or not target.exists()
        or target.resolve(strict=True) != target
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper target must be an existing absolute non-symlink path"
        )
    target_text = str(target)
    before_target_sha256, target_identity_algorithm = _target_identity(
        target,
        assessment_type,
    )
    status_command = list(STATUS_COMMAND)
    status = _run(status_command, "spctl status")
    status_output = _merged_output(status)
    # Parse the effective state even when spctl uses a non-zero exit status for
    # ``assessments disabled`` so the operator sees the actual release blocker.
    validate_status_output(status_output)
    if status.returncode != 0:
        raise GatekeeperEvidenceError(
            f"spctl --status failed with exit code {status.returncode}"
        )
    # The enabled-state proof is intentionally completed before assessment.

    assessment_command = _assessment_command(
        target_text,
        assessment_type,
        primary_signature_context,
    )
    assessment = _run(assessment_command, "spctl assessment")
    assessment_output = _merged_output(assessment)
    if assessment.returncode != 0:
        raise GatekeeperEvidenceError(
            f"spctl assessment failed with exit code {assessment.returncode}"
        )
    assessment_source, origin, assessment_output = validate_current_assessment_output(
        assessment_output,
        expected_team_id,
        expected_target=target_text,
    )

    codesign_command = [*CODESIGN_COMMAND_PREFIX, target_text]
    signature = _run(
        codesign_command,
        "codesign details",
    )
    codesign_output = _merged_output(signature)
    if signature.returncode != 0:
        raise GatekeeperEvidenceError(
            f"codesign detail capture failed with exit code {signature.returncode}"
        )
    authority, codesign_output = validate_codesign_output(
        codesign_output, expected_team_id
    )
    if origin is not None and authority != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin and leaf signing authority differ")

    post_status_command = list(STATUS_COMMAND)
    post_status = _run(post_status_command, "post-assessment spctl status")
    post_status_output = _merged_output(post_status)
    validate_status_output(post_status_output)
    if post_status.returncode != 0:
        raise GatekeeperEvidenceError(
            "post-assessment spctl --status failed with exit code "
            f"{post_status.returncode}"
        )

    if origin is None:
        origin_status = "not-reported-by-spctl"
        identity_source = "codesign-leaf-authority"
    else:
        origin_status = "reported-by-spctl"
        identity_source = "spctl-origin"

    after_target_sha256, after_target_identity_algorithm = _target_identity(
        target,
        assessment_type,
    )
    if (
        after_target_sha256 != before_target_sha256
        or after_target_identity_algorithm != target_identity_algorithm
    ):
        raise GatekeeperEvidenceError(
            "Gatekeeper target changed during assessment capture"
        )

    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "document": EVIDENCE_DOCUMENT_KIND,
        "assessment": "accepted",
        "source": "spctl",
        "assessment_source": assessment_source,
        "assessments_enabled": True,
        "authority": authority,
        "origin": origin,
        "origin_status": origin_status,
        "identity_source": identity_source,
        "signing_team_id": expected_team_id,
        "status_exit_code": status.returncode,
        "assessment_exit_code": assessment.returncode,
        "codesign_exit_code": signature.returncode,
        "post_status_exit_code": post_status.returncode,
        "assessment_type": assessment_type,
        "primary_signature_context": primary_signature_context,
        "assessed_target": target_text,
        "target_identity_algorithm": target_identity_algorithm,
        "target_signed_app_tree_sha256": after_target_sha256,
        "status_command": status_command,
        "assessment_command": assessment_command,
        "codesign_command": codesign_command,
        "post_status_command": post_status_command,
        "command_environment": dict(CAPTURE_ENVIRONMENT),
        "post_status_output": post_status_output,
        "post_status_output_sha256": _sha256_text(post_status_output),
        "status_output": status_output,
        "status_output_sha256": _sha256_text(status_output),
        "assessment_output": assessment_output,
        "assessment_output_sha256": _sha256_text(assessment_output),
        "codesign_output": codesign_output,
        "codesign_output_sha256": _sha256_text(codesign_output),
    }


def _write_new(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GatekeeperEvidenceError(f"refusing to replace evidence output: {path}")
    parent = path.parent
    metadata = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
        raise GatekeeperEvidenceError("evidence output parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(parent, flags)
    except OSError as error:
        raise GatekeeperEvidenceError(
            "cannot open the evidence output parent for durability"
        ) from error
    try:
        opened = os.fstat(directory_descriptor)
        rebound = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (rebound.st_dev, rebound.st_ino)
        ):
            raise GatekeeperEvidenceError(
                "evidence output parent changed during durability sync"
            )
        os.fsync(directory_descriptor)
    except OSError as error:
        raise GatekeeperEvidenceError(
            "cannot make the evidence output directory durable"
        ) from error
    finally:
        os.close(directory_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--assessment-type", choices=("execute", "open"), required=True)
    parser.add_argument("--primary-signature-context", action="store_true")
    parser.add_argument("--target-signed-app-tree-sha256")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if (arguments.output is None) != (
        arguments.target_signed_app_tree_sha256 is None
    ):
        parser.error(
            "--output and --target-signed-app-tree-sha256 must be supplied together"
        )

    try:
        core = capture(
            arguments.target,
            arguments.assessment_type,
            primary_signature_context=arguments.primary_signature_context,
        )
        if arguments.output is not None:
            if (
                arguments.target_signed_app_tree_sha256
                != core["target_signed_app_tree_sha256"]
            ):
                raise GatekeeperEvidenceError(
                    "caller target digest differs from the captured target"
                )
            captured_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
            evidence = validate_evidence(
                {
                    **core,
                    "captured_at": captured_at,
                },
                expected_assessment_type=arguments.assessment_type,
                expected_primary_signature_context=(
                    arguments.primary_signature_context
                ),
                expected_target=arguments.target,
            )
            _write_new(arguments.output, evidence)
        print(
            "Gatekeeper verified: assessments enabled, "
            f"source={core['assessment_source']}, "
            f"origin-status={core['origin_status']}, "
            f"identity-source={core['identity_source']}, "
            f"authority={core['authority']}"
        )
    except GatekeeperEvidenceError as error:
        raise SystemExit(f"error: Gatekeeper: {error}") from error


if __name__ == "__main__":
    main()
