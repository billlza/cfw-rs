#!/usr/bin/env python3
"""Capture and validate fail-closed Gatekeeper evidence.

An ``spctl --assess`` exit status is not sufficient evidence: when system
policy assessments are disabled, ``spctl`` can report an otherwise unnotarized
Developer ID product as accepted with ``override=security disabled``.  This
module therefore proves the global assessment switch first, rejects every
override, requires a notarized Developer ID origin, and binds the raw status,
assessment, and signing output to SHA-256 digests.
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


EXPECTED_TEAM_ID = "YKUPL7Z869"
EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_DOCUMENT_KIND = "gatekeeper-assessment-evidence-v1"
MAX_OUTPUT_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEVELOPER_ID_RE = re.compile(r"^Developer ID Application: .+ \(([A-Z0-9]{10})\)$")


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


def validate_assessment_output(
    value: object, expected_team_id: str = EXPECTED_TEAM_ID
) -> tuple[str, str, str]:
    """Return the notarization source, origin, and normalized raw output."""
    output = _bounded_output(value, "spctl assessment output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _reject_diagnostic_lines(lines, "spctl assessment output")
    lowered = [line.lower() for line in lines]
    if any(line.startswith("override=") for line in lowered):
        raise GatekeeperEvidenceError(
            "Gatekeeper assessment used a security override instead of policy"
        )
    if not any(re.fullmatch(r".+:\s+accepted", line) for line in lines):
        raise GatekeeperEvidenceError("spctl assessment output does not report accepted")

    sources = [line.partition("=")[2] for line in lines if line.startswith("source=")]
    if sources != ["Notarized Developer ID"]:
        raise GatekeeperEvidenceError(
            "Gatekeeper source is not exactly Notarized Developer ID"
        )
    origins = [line.partition("=")[2] for line in lines if line.startswith("origin=")]
    if len(origins) != 1:
        raise GatekeeperEvidenceError("Gatekeeper output has no unique signing origin")
    origin = origins[0]
    match = DEVELOPER_ID_RE.fullmatch(origin)
    if match is None or match.group(1) != expected_team_id:
        raise GatekeeperEvidenceError(
            f"Gatekeeper origin is not a Developer ID Application for {expected_team_id}"
        )
    return sources[0], origin, output


def validate_codesign_output(
    value: object, expected_team_id: str = EXPECTED_TEAM_ID
) -> tuple[str, str]:
    """Return the leaf signing authority and normalized raw codesign output."""
    output = _bounded_output(value, "codesign detail output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _reject_diagnostic_lines(lines, "codesign detail output")
    authorities = [
        line.partition("=")[2] for line in lines if line.startswith("Authority=")
    ]
    if not authorities:
        raise GatekeeperEvidenceError("codesign output has no signing authority")
    authority = authorities[0]
    match = DEVELOPER_ID_RE.fullmatch(authority)
    if match is None or match.group(1) != expected_team_id:
        raise GatekeeperEvidenceError(
            f"leaf signing authority is not Developer ID Application for {expected_team_id}"
        )
    if f"TeamIdentifier={expected_team_id}" not in lines:
        raise GatekeeperEvidenceError("codesign output has the wrong TeamIdentifier")
    if "Signature=adhoc" in lines:
        raise GatekeeperEvidenceError("ad-hoc signing is not Gatekeeper evidence")
    timestamps = [line for line in lines if line.startswith("Timestamp=")]
    if len(timestamps) != 1 or timestamps[0] == "Timestamp=none":
        raise GatekeeperEvidenceError("codesign output has no secure timestamp")
    return authority, output


def validate_evidence(
    value: object, expected_team_id: str = EXPECTED_TEAM_ID
) -> dict[str, Any]:
    fields = {
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
    if not isinstance(value, dict) or set(value) != fields:
        raise GatekeeperEvidenceError("Gatekeeper evidence has an unexpected field set")
    if (
        value["schema_version"] != EVIDENCE_SCHEMA_VERSION
        or value["document"] != EVIDENCE_DOCUMENT_KIND
    ):
        raise GatekeeperEvidenceError("Gatekeeper evidence schema/document is unsupported")
    if value["assessment"] != "accepted" or value["source"] != "spctl":
        raise GatekeeperEvidenceError("Gatekeeper evidence is not an accepted spctl assessment")
    if value["assessments_enabled"] is not True:
        raise GatekeeperEvidenceError("Gatekeeper assessments_enabled is not true")

    status_output = validate_status_output(value["status_output"])
    if _sha256_text(status_output) != _require_sha256(
        value["status_output_sha256"], "status_output_sha256"
    ):
        raise GatekeeperEvidenceError("Gatekeeper status output digest mismatch")

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
    if value["assessment_source"] != assessment_source:
        raise GatekeeperEvidenceError("Gatekeeper assessment_source differs from raw output")
    if value["origin"] != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin differs from raw output")
    if value["authority"] != authority:
        raise GatekeeperEvidenceError("Gatekeeper authority differs from raw output")
    if authority != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin and leaf signing authority differ")

    return {
        **value,
        "target_signed_app_tree_sha256": _require_sha256(
            value["target_signed_app_tree_sha256"],
            "target_signed_app_tree_sha256",
        ),
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
    if not target.is_absolute() or target.is_symlink() or not target.exists():
        raise GatekeeperEvidenceError(
            "Gatekeeper target must be an existing absolute non-symlink path"
        )
    status = _run(["/usr/sbin/spctl", "--status"], "spctl status")
    status_output = _merged_output(status)
    # Parse the effective state even when spctl uses a non-zero exit status for
    # ``assessments disabled`` so the operator sees the actual release blocker.
    validate_status_output(status_output)
    if status.returncode != 0:
        raise GatekeeperEvidenceError(
            f"spctl --status failed with exit code {status.returncode}"
        )
    # The enabled-state proof is intentionally completed before assessment.

    assessment_command = [
        "/usr/sbin/spctl",
        "--assess",
        "--type",
        assessment_type,
    ]
    if primary_signature_context:
        assessment_command.extend(["--context", "context:primary-signature"])
    assessment_command.extend(["--verbose=4", str(target)])
    assessment = _run(assessment_command, "spctl assessment")
    assessment_output = _merged_output(assessment)
    if assessment.returncode != 0:
        raise GatekeeperEvidenceError(
            f"spctl assessment failed with exit code {assessment.returncode}"
        )
    assessment_source, origin, assessment_output = validate_assessment_output(
        assessment_output, expected_team_id
    )

    signature = _run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(target)],
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
    if authority != origin:
        raise GatekeeperEvidenceError("Gatekeeper origin and leaf signing authority differ")

    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "document": EVIDENCE_DOCUMENT_KIND,
        "assessment": "accepted",
        "source": "spctl",
        "assessment_source": assessment_source,
        "assessments_enabled": True,
        "authority": authority,
        "origin": origin,
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
            captured_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
            evidence = validate_evidence(
                {
                    **core,
                    "target_signed_app_tree_sha256": (
                        arguments.target_signed_app_tree_sha256
                    ),
                    "captured_at": captured_at,
                }
            )
            _write_new(arguments.output, evidence)
        print(
            "Gatekeeper verified: assessments enabled, "
            f"source={core['assessment_source']}, origin={core['origin']}"
        )
    except GatekeeperEvidenceError as error:
        raise SystemExit(f"error: Gatekeeper: {error}") from error


if __name__ == "__main__":
    main()
