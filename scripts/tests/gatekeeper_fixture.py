"""Deterministic Gatekeeper raw-evidence fixture shared by publication tests."""

from __future__ import annotations

import hashlib

from scripts.gatekeeper_assessment import (
    EVIDENCE_DOCUMENT_KIND,
    EVIDENCE_SCHEMA_VERSION,
    EXPECTED_TEAM_ID,
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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fixture(target_signed_app_tree_sha256: str, captured_at: str) -> dict:
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "document": EVIDENCE_DOCUMENT_KIND,
        "assessment": "accepted",
        "source": "spctl",
        "assessment_source": "Notarized Developer ID",
        "assessments_enabled": True,
        "authority": AUTHORITY,
        "origin": AUTHORITY,
        "status_output": STATUS_OUTPUT,
        "status_output_sha256": _digest(STATUS_OUTPUT),
        "assessment_output": ASSESSMENT_OUTPUT,
        "assessment_output_sha256": _digest(ASSESSMENT_OUTPUT),
        "codesign_output": CODESIGN_OUTPUT,
        "codesign_output_sha256": _digest(CODESIGN_OUTPUT),
        "target_signed_app_tree_sha256": target_signed_app_tree_sha256,
        "captured_at": captured_at,
    }
