from __future__ import annotations

import copy
import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.gatekeeper_assessment as gatekeeper_module
from scripts.gatekeeper_assessment import (
    EVIDENCE_DOCUMENT_KIND,
    EVIDENCE_SCHEMA_VERSION,
    EXPECTED_TEAM_ID,
    GatekeeperEvidenceError,
    LEGACY_EVIDENCE_DOCUMENT_KIND,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    POLICY_EVIDENCE_DOCUMENT_KIND,
    POLICY_EVIDENCE_SCHEMA_VERSION,
    capture,
    validate_current_assessment_output,
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
MACOS_27_ASSESSMENT_OUTPUT = (
    "/Applications/Clash for Mac.app: accepted\n"
    "source=Notarized Developer ID\n"
)
CODESIGN_OUTPUT = (
    "Executable=/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac\n"
    f"Authority={AUTHORITY}\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
    "Timestamp=Jul 26, 2026 at 12:00:00\n"
    f"TeamIdentifier={EXPECTED_TEAM_ID}\n"
)
ASSESSMENT_TARGET = "/Applications/Clash for Mac.app"


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
        "assessment_output": ASSESSMENT_OUTPUT,
        "assessment_output_sha256": _digest(ASSESSMENT_OUTPUT),
        "codesign_output": CODESIGN_OUTPUT,
        "codesign_output_sha256": _digest(CODESIGN_OUTPUT),
        "post_status_output": STATUS_OUTPUT,
        "post_status_output_sha256": _digest(STATUS_OUTPUT),
        "target_signed_app_tree_sha256": "a" * 64,
        "assessed_target": ASSESSMENT_TARGET,
        "target_identity_algorithm": "sha256-tree-v2",
        "status_command": ["/usr/sbin/spctl", "--status"],
        "assessment_command": [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            ASSESSMENT_TARGET,
        ],
        "codesign_command": [
            "/usr/bin/codesign",
            "-d",
            "--verbose=4",
            ASSESSMENT_TARGET,
        ],
        "post_status_command": ["/usr/sbin/spctl", "--status"],
        "command_environment": {"LC_ALL": "C", "LANG": "C"},
        "captured_at": "2026-07-26T12:00:01Z",
    }


def _policy_evidence() -> dict:
    value = _evidence()
    for field in (
        "assessed_target",
        "target_identity_algorithm",
        "status_command",
        "assessment_command",
        "codesign_command",
        "post_status_command",
        "command_environment",
    ):
        del value[field]
    value["schema_version"] = POLICY_EVIDENCE_SCHEMA_VERSION
    value["document"] = POLICY_EVIDENCE_DOCUMENT_KIND
    return value


def _legacy_evidence() -> dict:
    value = _policy_evidence()
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
    ):
        del value[field]
    value["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    value["document"] = LEGACY_EVIDENCE_DOCUMENT_KIND
    return value


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

    def test_current_parser_preserves_absent_origin(self) -> None:
        source, origin, raw = validate_current_assessment_output(
            MACOS_27_ASSESSMENT_OUTPUT
        )
        self.assertEqual(source, "Notarized Developer ID")
        self.assertIsNone(origin)
        self.assertEqual(raw, MACOS_27_ASSESSMENT_OUTPUT)

    def test_current_parser_binds_the_exact_accepted_target(self) -> None:
        self.assertEqual(
            validate_current_assessment_output(
                MACOS_27_ASSESSMENT_OUTPUT,
                expected_target=ASSESSMENT_TARGET,
            )[0],
            "Notarized Developer ID",
        )
        with self.assertRaisesRegex(GatekeeperEvidenceError, "exact target"):
            validate_current_assessment_output(
                MACOS_27_ASSESSMENT_OUTPUT,
                expected_target="/Applications/Other.app",
            )

    def test_legacy_parser_still_rejects_absent_origin(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "origin"):
            validate_assessment_output(MACOS_27_ASSESSMENT_OUTPUT)

    def test_current_parser_rejects_malformed_or_duplicate_origin(self) -> None:
        for origin_lines in (
            "origin=\n",
            f"origin={AUTHORITY}\norigin={AUTHORITY}\n",
            f"Origin={AUTHORITY}\n",
            "origin =not-an-origin\n",
        ):
            with self.subTest(origin_lines=origin_lines):
                with self.assertRaises(GatekeeperEvidenceError):
                    validate_current_assessment_output(
                        MACOS_27_ASSESSMENT_OUTPUT + origin_lines
                    )

    def test_assessment_known_fields_require_canonical_casing_and_spacing(self) -> None:
        for line in (
            "Source=Unnotarized Developer ID",
            "source =Notarized Developer ID",
            f"Origin={AUTHORITY}",
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(
                    GatekeeperEvidenceError,
                    "noncanonical",
                ):
                    validate_current_assessment_output(
                        MACOS_27_ASSESSMENT_OUTPUT + line + "\n"
                    )

    def test_security_disabled_override_is_rejected_even_when_accepted(self) -> None:
        output = (
            "/tmp/Clash for Mac.app: accepted\n"
            "source=Unnotarized Developer ID\n"
            "override=security disabled\n"
        )
        with self.assertRaisesRegex(GatekeeperEvidenceError, "security override"):
            validate_assessment_output(output)

    def test_override_case_and_spacing_cannot_bypass_rejection(self) -> None:
        for override in ("Override=security disabled", "override =security disabled"):
            with self.subTest(override=override):
                with self.assertRaisesRegex(GatekeeperEvidenceError, "security override"):
                    validate_current_assessment_output(
                        MACOS_27_ASSESSMENT_OUTPUT + override + "\n"
                    )

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

    def test_codesign_known_fields_require_canonical_casing_and_spacing(self) -> None:
        for line in (
            "authority=Developer ID Application: Other (YKUPL7Z869)",
            "TeamIdentifier =AAAAAAAAAA",
            "timestamp=none",
            "Signature =adhoc",
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(
                    GatekeeperEvidenceError,
                    "noncanonical",
                ):
                    validate_codesign_output(CODESIGN_OUTPUT + line + "\n")

    def test_codesign_timestamp_must_be_unique_and_parseable(self) -> None:
        for timestamp in (
            "Timestamp=\n",
            "Timestamp=none\n",
            "Timestamp=garbage\n",
            "Timestamp=Feb 30, 2026 at 12:00:00\n",
            "Timestamp=Jul 26, 2026 at 25:00:00\n",
        ):
            with self.subTest(timestamp=timestamp):
                output = re.sub(r"^Timestamp=.*$", timestamp.rstrip("\n"), CODESIGN_OUTPUT, flags=re.MULTILINE)
                with self.assertRaisesRegex(GatekeeperEvidenceError, "secure timestamp"):
                    validate_codesign_output(output)

        duplicate = CODESIGN_OUTPUT + "Timestamp=Jul 26, 2026 at 12:00:01\n"
        with self.assertRaisesRegex(GatekeeperEvidenceError, "secure timestamp"):
            validate_codesign_output(duplicate)


class GatekeeperEvidenceTests(unittest.TestCase):
    @staticmethod
    def _retargeted_evidence(target: Path, digest: str) -> dict:
        target_text = str(target)
        value = _evidence()
        value["assessed_target"] = target_text
        value["target_signed_app_tree_sha256"] = digest
        value["assessment_output"] = ASSESSMENT_OUTPUT.replace(
            ASSESSMENT_TARGET,
            target_text,
            1,
        )
        value["assessment_output_sha256"] = _digest(
            value["assessment_output"]
        )
        value["assessment_command"] = [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            target_text,
        ]
        value["codesign_command"] = [
            "/usr/bin/codesign",
            "-d",
            "--verbose=4",
            target_text,
        ]
        return value

    def test_complete_raw_evidence_round_trips(self) -> None:
        self.assertEqual(validate_evidence(_evidence()), _evidence())

    def test_legacy_v1_evidence_remains_strictly_valid(self) -> None:
        self.assertEqual(validate_evidence(_legacy_evidence()), _legacy_evidence())

    def test_policy_v2_evidence_remains_strictly_valid(self) -> None:
        self.assertEqual(validate_evidence(_policy_evidence()), _policy_evidence())

    def test_expected_policy_rejects_legacy_evidence_without_policy_fields(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "does not bind"):
            validate_evidence(
                _legacy_evidence(),
                expected_assessment_type="execute",
                expected_primary_signature_context=False,
            )

    def test_expected_policy_rejects_context_substitution(self) -> None:
        value = _evidence()
        value["assessment_type"] = "open"
        value["primary_signature_context"] = True
        value["target_identity_algorithm"] = "sha256-file"
        value["assessment_command"] = [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "--verbose=4",
            ASSESSMENT_TARGET,
        ]
        with self.assertRaisesRegex(GatekeeperEvidenceError, "required policy"):
            validate_evidence(
                value,
                expected_assessment_type="execute",
                expected_primary_signature_context=False,
            )

    def test_expected_dmg_policy_accepts_only_open_primary_signature(self) -> None:
        value = _evidence()
        value["assessment_type"] = "open"
        value["primary_signature_context"] = True
        value["target_identity_algorithm"] = "sha256-file"
        value["assessment_command"] = [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "--verbose=4",
            ASSESSMENT_TARGET,
        ]
        self.assertEqual(
            validate_evidence(
                value,
                expected_assessment_type="open",
                expected_primary_signature_context=True,
            ),
            value,
        )

    def test_incomplete_expected_policy_is_rejected(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "incomplete"):
            validate_evidence(
                _evidence(),
                expected_assessment_type="execute",
            )

    def test_macos_27_absent_origin_evidence_round_trips(self) -> None:
        value = _evidence()
        value["assessment_output"] = MACOS_27_ASSESSMENT_OUTPUT
        value["assessment_output_sha256"] = _digest(MACOS_27_ASSESSMENT_OUTPUT)
        value["origin"] = None
        value["origin_status"] = "not-reported-by-spctl"
        value["identity_source"] = "codesign-leaf-authority"
        self.assertEqual(validate_evidence(value), value)

    def test_absent_origin_mode_cannot_be_declared_for_reported_origin(self) -> None:
        value = _evidence()
        value["origin"] = None
        value["origin_status"] = "not-reported-by-spctl"
        value["identity_source"] = "codesign-leaf-authority"
        with self.assertRaises(GatekeeperEvidenceError):
            validate_evidence(value)

    def test_absent_raw_origin_cannot_claim_reported_identity(self) -> None:
        value = _evidence()
        value["assessment_output"] = MACOS_27_ASSESSMENT_OUTPUT
        value["assessment_output_sha256"] = _digest(MACOS_27_ASSESSMENT_OUTPUT)
        with self.assertRaises(GatekeeperEvidenceError):
            validate_evidence(value)

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

    def test_exact_target_and_command_tampering_is_rejected(self) -> None:
        for field, mutation in (
            ("assessed_target", "/Applications/Other.app"),
            ("assessment_command", ["/usr/sbin/spctl", "--status"]),
            ("codesign_command", ["/usr/bin/codesign", "-d"]),
            ("command_environment", {"LANG": "C"}),
        ):
            with self.subTest(field=field):
                value = _evidence()
                value[field] = mutation
                with self.assertRaises(GatekeeperEvidenceError):
                    validate_evidence(value)

    def test_expected_target_rejects_v2_and_foreign_v3_evidence(self) -> None:
        with self.assertRaisesRegex(GatekeeperEvidenceError, "does not bind"):
            validate_evidence(
                _policy_evidence(),
                expected_target=ASSESSMENT_TARGET,
            )
        with self.assertRaisesRegex(GatekeeperEvidenceError, "different target"):
            validate_evidence(
                _evidence(),
                expected_target="/Applications/Other.app",
            )

    def test_expected_existing_target_recomputes_exact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "Clash for Mac.app"
            executable = target / "Contents/MacOS/clash-for-mac"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"signed-target")
            digest = gatekeeper_module.build_manifest(
                target,
                algorithm="sha256-tree-v2",
            )["sha256"]
            value = self._retargeted_evidence(target, digest)

            self.assertEqual(
                validate_evidence(value, expected_target=target),
                value,
            )
            value["target_signed_app_tree_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                GatekeeperEvidenceError,
                "exact target identity",
            ):
                validate_evidence(value, expected_target=target)

    def test_expected_missing_target_cannot_skip_digest_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "Missing.app"
            value = self._retargeted_evidence(target, "a" * 64)
            with self.assertRaisesRegex(
                GatekeeperEvidenceError,
                "cannot derive the exact",
            ):
                validate_evidence(value, expected_target=target)

    def test_rehashed_noncanonical_codesign_field_is_rejected(self) -> None:
        value = _evidence()
        value["codesign_output"] += "TeamIdentifier =AAAAAAAAAA\n"
        value["codesign_output_sha256"] = _digest(value["codesign_output"])
        with self.assertRaisesRegex(GatekeeperEvidenceError, "noncanonical"):
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
        for version in (0, 4, True, 2.0, "2"):
            with self.subTest(version=version):
                value = _evidence()
                value["schema_version"] = version
                with self.assertRaisesRegex(GatekeeperEvidenceError, "unsupported"):
                    validate_evidence(value)

    def test_schema_document_cross_version_mismatch_is_rejected(self) -> None:
        value = _evidence()
        value["document"] = LEGACY_EVIDENCE_DOCUMENT_KIND
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

    def test_capture_emits_v3_without_fabricating_missing_origin(self) -> None:
        responses = {
            "spctl status": subprocess.CompletedProcess([], 0, STATUS_OUTPUT, ""),
            "spctl assessment": subprocess.CompletedProcess(
                [], 0, "", MACOS_27_ASSESSMENT_OUTPUT
            ),
            "codesign details": subprocess.CompletedProcess(
                [], 0, "", CODESIGN_OUTPUT
            ),
            "post-assessment spctl status": subprocess.CompletedProcess(
                [], 0, STATUS_OUTPUT, ""
            ),
        }
        calls: list[str] = []

        def fake_run(command: list[str], label: str):
            calls.append(label)
            result = copy.deepcopy(responses[label])
            if label == "spctl assessment":
                result.stderr = result.stderr.replace(
                    "/Applications/Clash for Mac.app",
                    command[-1],
                    1,
                )
            return result

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Clash for Mac.app"
            target.mkdir()
            with patch("scripts.gatekeeper_assessment._run", side_effect=fake_run):
                captured = capture(
                    target.resolve(),
                    "execute",
                    primary_signature_context=False,
                )

        self.assertEqual(
            calls,
            [
                "spctl status",
                "spctl assessment",
                "codesign details",
                "post-assessment spctl status",
            ],
        )
        self.assertEqual(captured["schema_version"], 3)
        self.assertEqual(captured["assessed_target"], str(target.resolve()))
        self.assertEqual(
            captured["assessment_command"][-1],
            str(target.resolve()),
        )
        self.assertEqual(
            captured["command_environment"],
            {"LC_ALL": "C", "LANG": "C"},
        )
        self.assertIsNone(captured["origin"])
        self.assertEqual(
            captured["identity_source"],
            "codesign-leaf-authority",
        )
        self.assertEqual(captured["origin_status"], "not-reported-by-spctl")

    def test_capture_rejects_target_identity_change(self) -> None:
        responses = {
            "spctl status": subprocess.CompletedProcess([], 0, STATUS_OUTPUT, ""),
            "spctl assessment": subprocess.CompletedProcess(
                [], 0, "", MACOS_27_ASSESSMENT_OUTPUT
            ),
            "codesign details": subprocess.CompletedProcess(
                [], 0, "", CODESIGN_OUTPUT
            ),
            "post-assessment spctl status": subprocess.CompletedProcess(
                [], 0, STATUS_OUTPUT, ""
            ),
        }

        def fake_run(command: list[str], label: str):
            result = copy.deepcopy(responses[label])
            if label == "spctl assessment":
                result.stderr = result.stderr.replace(
                    ASSESSMENT_TARGET,
                    command[-1],
                    1,
                )
            return result

        with tempfile.TemporaryDirectory() as directory:
            target = (Path(directory) / "Clash for Mac.app").resolve()
            target.mkdir()
            with patch.object(
                gatekeeper_module,
                "_target_identity",
                side_effect=[
                    ("a" * 64, "sha256-tree-v2"),
                    ("b" * 64, "sha256-tree-v2"),
                ],
            ), patch.object(
                gatekeeper_module,
                "_run",
                side_effect=fake_run,
            ):
                with self.assertRaisesRegex(
                    GatekeeperEvidenceError,
                    "changed during",
                ):
                    capture(
                        target,
                        "execute",
                        primary_signature_context=False,
                    )

    def test_open_capture_binds_the_exact_file_bytes(self) -> None:
        responses = {
            "spctl status": subprocess.CompletedProcess([], 0, STATUS_OUTPUT, ""),
            "spctl assessment": subprocess.CompletedProcess(
                [], 0, "", MACOS_27_ASSESSMENT_OUTPUT
            ),
            "codesign details": subprocess.CompletedProcess(
                [], 0, "", CODESIGN_OUTPUT
            ),
            "post-assessment spctl status": subprocess.CompletedProcess(
                [], 0, STATUS_OUTPUT, ""
            ),
        }

        def fake_run(command: list[str], label: str):
            result = copy.deepcopy(responses[label])
            if label == "spctl assessment":
                result.stderr = result.stderr.replace(
                    ASSESSMENT_TARGET,
                    command[-1],
                    1,
                )
            return result

        with tempfile.TemporaryDirectory() as directory:
            target = (Path(directory) / "Clash-for-Mac.dmg").resolve()
            target_bytes = b"synthetic notarized disk image"
            target.write_bytes(target_bytes)
            with patch.object(
                gatekeeper_module,
                "_run",
                side_effect=fake_run,
            ):
                captured = capture(
                    target,
                    "open",
                    primary_signature_context=True,
                )

        self.assertEqual(captured["assessed_target"], str(target))
        self.assertEqual(captured["target_identity_algorithm"], "sha256-file")
        self.assertEqual(
            captured["target_signed_app_tree_sha256"],
            hashlib.sha256(target_bytes).hexdigest(),
        )
        self.assertEqual(
            captured["assessment_command"],
            [
                "/usr/sbin/spctl",
                "--assess",
                "--type",
                "open",
                "--context",
                "context:primary-signature",
                "--verbose=4",
                str(target),
            ],
        )

    def test_command_capture_uses_only_the_c_locale(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "ok\n", "")
        with patch.object(
            gatekeeper_module.subprocess,
            "run",
            return_value=completed,
        ) as run:
            gatekeeper_module._run(list(gatekeeper_module.STATUS_COMMAND), "status")
        self.assertEqual(
            run.call_args.kwargs["env"],
            {"LC_ALL": "C", "LANG": "C"},
        )

    def test_evidence_write_fsyncs_file_and_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper.json"
            with patch.object(
                gatekeeper_module.os,
                "fsync",
                wraps=os.fsync,
            ) as fsync:
                gatekeeper_module._write_new(output, {"ok": True})
            self.assertEqual(fsync.call_count, 2)


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
