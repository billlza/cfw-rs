"""Deterministic Gatekeeper raw-evidence fixture shared by publication tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.gatekeeper_assessment import (
    EVIDENCE_DOCUMENT_KIND,
    EVIDENCE_SCHEMA_VERSION,
    EXPECTED_TEAM_ID,
    LEGACY_EVIDENCE_DOCUMENT_KIND,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
)


AUTHORITY = f"Developer ID Application: Example Release ({EXPECTED_TEAM_ID})"
STATUS_OUTPUT = "assessments enabled\n"
ASSESSMENT_OUTPUT = (
    "/Applications/Clash for Mac.app: accepted\n"
    "source=Notarized Developer ID\n"
    f"origin={AUTHORITY}\n"
)
CODESIGN_OUTPUT = (
    "Executable=/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac\n"
    f"Authority={AUTHORITY}\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
    "Timestamp=Jul 26, 2026 at 12:00:00\n"
    f"TeamIdentifier={EXPECTED_TEAM_ID}\n"
)
MACOS_27_ASSESSMENT_OUTPUT = (
    "/Applications/Clash for Mac.app: accepted\n"
    "source=Notarized Developer ID\n"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fixture(
    target_signed_app_tree_sha256: str,
    captured_at: str,
    assessed_target: str | Path = "/Applications/Clash for Mac.app",
) -> dict:
    target = str(assessed_target)
    assessment_output = ASSESSMENT_OUTPUT.replace(
        "/Applications/Clash for Mac.app",
        target,
        1,
    )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "document": EVIDENCE_DOCUMENT_KIND,
        "assessment": "accepted",
        "source": "spctl",
        "assessment_source": "Notarized Developer ID",
        "assessments_enabled": True,
        "authority": AUTHORITY,
        "origin": AUTHORITY,
        "origin_status": "reported-by-spctl",
        "identity_source": "spctl-origin",
        "signing_team_id": EXPECTED_TEAM_ID,
        "status_exit_code": 0,
        "assessment_exit_code": 0,
        "codesign_exit_code": 0,
        "post_status_exit_code": 0,
        "assessment_type": "execute",
        "primary_signature_context": False,
        "status_output": STATUS_OUTPUT,
        "status_output_sha256": _digest(STATUS_OUTPUT),
        "assessment_output": assessment_output,
        "assessment_output_sha256": _digest(assessment_output),
        "codesign_output": CODESIGN_OUTPUT,
        "codesign_output_sha256": _digest(CODESIGN_OUTPUT),
        "post_status_output": STATUS_OUTPUT,
        "post_status_output_sha256": _digest(STATUS_OUTPUT),
        "target_signed_app_tree_sha256": target_signed_app_tree_sha256,
        "assessed_target": target,
        "target_identity_algorithm": "sha256-tree-v2",
        "status_command": ["/usr/sbin/spctl", "--status"],
        "assessment_command": [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            target,
        ],
        "codesign_command": [
            "/usr/bin/codesign",
            "-d",
            "--verbose=4",
            target,
        ],
        "post_status_command": ["/usr/sbin/spctl", "--status"],
        "command_environment": {"LC_ALL": "C", "LANG": "C"},
        "captured_at": captured_at,
    }


def legacy_fixture(target_signed_app_tree_sha256: str, captured_at: str) -> dict:
    value = fixture(target_signed_app_tree_sha256, captured_at)
    for field in (
        "origin_status",
        "identity_source",
        "signing_team_id",
        "status_exit_code",
        "assessment_exit_code",
        "codesign_exit_code",
        "post_status_exit_code",
        "assessment_type",
        "primary_signature_context",
        "post_status_output",
        "post_status_output_sha256",
        "assessed_target",
        "target_identity_algorithm",
        "status_command",
        "assessment_command",
        "codesign_command",
        "post_status_command",
        "command_environment",
    ):
        del value[field]
    value["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    value["document"] = LEGACY_EVIDENCE_DOCUMENT_KIND
    return value


def macos_27_fixture(
    target_signed_app_tree_sha256: str,
    captured_at: str,
    assessed_target: str | Path = "/Applications/Clash for Mac.app",
) -> dict:
    value = fixture(
        target_signed_app_tree_sha256,
        captured_at,
        assessed_target,
    )
    assessment_output = MACOS_27_ASSESSMENT_OUTPUT.replace(
        "/Applications/Clash for Mac.app",
        str(assessed_target),
        1,
    )
    value["assessment_output"] = assessment_output
    value["assessment_output_sha256"] = _digest(assessment_output)
    value["origin"] = None
    value["origin_status"] = "not-reported-by-spctl"
    value["identity_source"] = "codesign-leaf-authority"
    return value
