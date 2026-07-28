from __future__ import annotations

import copy
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.gatekeeper_assessment import (
    EVIDENCE_DOCUMENT_KIND,
    EVIDENCE_SCHEMA_VERSION,
    EXPECTED_TEAM_ID,
    GatekeeperEvidenceError,
    capture,
    validate_assessment_output,
    validate_codesign_output,
    validate_evidence,
    validate_status_output,
)


REPOSITORY = Path(__file__).resolve().parents[2]

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


def _evidence() -> dict:
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
        "target_signed_app_tree_sha256": "a" * 64,
        "captured_at": "2026-07-26T12:00:01Z",
    }


class GatekeeperStatusTests(unittest.TestCase):
    def test_enabled_status_is_accepted(self) -> None:
        self.assertEqual(validate_status_output(STATUS_OUTPUT), STATUS_OUTPUT)

    def test_disabled_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "not provably enabled"):
            validate_status_output("assessments disabled\n")

    def test_ambiguous_extra_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "not provably enabled"):
            validate_status_output("assessments enabled\noverride=security disabled\n")


class GatekeeperAssessmentTests(unittest.TestCase):
    def test_notarized_developer_id_assessment_is_accepted(self) -> None:
        source, origin, raw = validate_assessment_output(ASSESSMENT_OUTPUT)
        self.assertEqual(source, "Notarized Developer ID")
        self.assertEqual(origin, AUTHORITY)
        self.assertEqual(raw, ASSESSMENT_OUTPUT)

    def test_security_disabled_override_is_rejected_even_when_accepted(self) -> None:
        output = (
            "/tmp/Clash for Mac.app: accepted\n"
            "source=Unnotarized Developer ID\n"
            "override=security disabled\n"
        )
        with self.assertRaisesRegex(GatekeeperEvidenceError, "security override"):
            validate_assessment_output(output)

    def test_unnotarized_source_is_rejected(self) -> None:
        output = ASSESSMENT_OUTPUT.replace(
            "source=Notarized Developer ID", "source=Unnotarized Developer ID"
        )
        with self.assertRaisesRegex(GatekeeperEvidenceError, "Notarized Developer ID"):
            validate_assessment_output(output)

    def test_foreign_team_origin_is_rejected(self) -> None:
        output = ASSESSMENT_OUTPUT.replace(EXPECTED_TEAM_ID, "AAAAAAAAAA")
        with self.assertRaisesRegex(GatekeeperEvidenceError, EXPECTED_TEAM_ID):
            validate_assessment_output(output)

    def test_assessment_warning_line_is_release_blocking(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "warning or error"):
            validate_assessment_output(ASSESSMENT_OUTPUT + "warning: degraded check\n")

    def test_codesign_warning_line_is_release_blocking(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "warning or error"):
            validate_codesign_output(CODESIGN_OUTPUT + "warning: degraded check\n")


class GatekeeperEvidenceTests(unittest.TestCase):
    def test_complete_raw_evidence_round_trips(self) -> None:
        self.assertEqual(validate_evidence(_evidence()), _evidence())

    def test_disabled_boolean_is_rejected(self) -> None:
        value = _evidence()
        value["assessments_enabled"] = False
        with self.assertRaisesRegex(GatekeeperEvidenceError, "assessments_enabled"):
            validate_evidence(value)

    def test_assessment_output_digest_tampering_is_rejected(self) -> None:
        value = _evidence()
        value["assessment_output_sha256"] = "b" * 64
        with self.assertRaisesRegex(GatekeeperEvidenceError, "digest mismatch"):
            validate_evidence(value)

    def test_declared_origin_cannot_differ_from_raw_output(self) -> None:
        value = _evidence()
        value["origin"] = f"Developer ID Application: Other ({EXPECTED_TEAM_ID})"
        with self.assertRaisesRegex(GatekeeperEvidenceError, "differs from raw output"):
            validate_evidence(value)

    def test_missing_raw_field_is_rejected(self) -> None:
        value = _evidence()
        del value["status_output"]
        with self.assertRaisesRegex(GatekeeperEvidenceError, "unexpected field set"):
            validate_evidence(value)

    def test_unsupported_schema_is_rejected(self) -> None:
        value = _evidence()
        value["schema_version"] = 2
        with self.assertRaisesRegex(GatekeeperEvidenceError, "unsupported"):
            validate_evidence(value)

    def test_capture_does_not_assess_after_disabled_status(self) -> None:
        disabled = subprocess.CompletedProcess(
            ["/usr/sbin/spctl", "--status"], 1, "assessments disabled\n", ""
        )
        calls: list[str] = []

        def fake_run(command: list[str], label: str):
            calls.append(label)
            return copy.deepcopy(disabled)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Clash for Mac.app"
            target.mkdir()
            with patch("scripts.gatekeeper_assessment._run", side_effect=fake_run):
                with self.assertRaisesRegex(GatekeeperEvidenceError, "not provably enabled"):
                    capture(
                        target.resolve(),
                        "execute",
                        primary_signature_context=False,
                    )
        self.assertEqual(calls, ["spctl status"])


class GatekeeperReleaseScriptWiringTests(unittest.TestCase):
    def test_every_release_assessment_uses_the_enabled_state_gate(self) -> None:
        for relative in ("scripts/verify_release_app.sh", "scripts/make_dmg.sh"):
            with self.subTest(relative=relative):
                source = (REPOSITORY / relative).read_text(encoding="utf-8")
                self.assertIn("scripts/gatekeeper_assessment.py", source)
                self.assertNotIn("spctl --assess", source)
        signed = (REPOSITORY / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        transaction = (REPOSITORY / "scripts/notarization_transaction.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/notarization_transaction.py", signed)
        self.assertIn("capture as capture_gatekeeper", transaction)
        self.assertIn("validate_gatekeeper_evidence", transaction)
        self.assertNotIn("spctl --assess", transaction)

    def test_signed_candidate_retrieves_and_validates_the_notary_log(self) -> None:
        shell = (REPOSITORY / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        transaction = (REPOSITORY / "scripts/notarization_transaction.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/notarization_transaction.py", shell)
        self.assertIn('"notarytool",\n            "log"', transaction)
        self.assertIn("validate_documents", transaction)
        self.assertIn('"notarization-log.json"', transaction)

    def test_dmg_retrieves_and_publishes_bound_notarization_evidence(self) -> None:
        source = (REPOSITORY / "scripts/make_dmg.sh").read_text(encoding="utf-8")
        self.assertIn("notarytool log", source)
        self.assertIn("scripts/verify_notary_log.py", source)
        self.assertIn("--output \"$gatekeeper_evidence\"", source)
        self.assertIn(".dmg.manifest.json", source)


if __name__ == "__main__":
    unittest.main()
