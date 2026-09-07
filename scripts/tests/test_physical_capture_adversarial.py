from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.harness.adversarial_clients import REQUIRED_CASES, REQUIRED_RAW_SUBJECTS
from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture import observation
from scripts.physical_capture import adversarial as adversarial_capture
from scripts.physical_capture.adversarial import (
    AdversarialCaptureError,
    EXTERNAL_FIXTURE_SPECS,
    SOURCE_FIXED_PRECONDITIONS,
    materialize_adversarial_transcripts,
)
from scripts.physical_capture.archive import (
    PRIVATE_FILE_MODE,
    PhysicalCaptureArchiveError,
)
from scripts.physical_capture.execution import CommandResult
from scripts.physical_capture.materialize import materialize_adversarial_report
from scripts.physical_capture.session import CaptureEvent, PhysicalCaptureSession
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class PhysicalAdversarialCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["adversarial"]
        self.raw = self.fixture.raw_bindings[0]

    def _binding(self, subject: str) -> dict:
        return copy.deepcopy(
            next(
                binding["descriptor"]
                for binding in self.raw
                if binding["harness"] == "adversarial"
                and binding["subject"] == subject
            )
        )

    def _frozen_session(self, *, omit: str | None = None) -> PhysicalCaptureSession:
        repository = self.root / f"session-{hashlib.sha256(str(omit).encode()).hexdigest()[:8]}"
        (repository / "target").mkdir(parents=True)
        session = PhysicalCaptureSession.create(
            repository,
            "physical-capture/adversarial",
            intent_sha256=hashlib.sha256(b"adversarial-intent").hexdigest(),
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=hashlib.sha256(b"adversarial-collection").hexdigest(),
        )
        capture = session.observation_capture()
        transcript_subjects = {"baseline", *REQUIRED_CASES}
        pre_nonce_subjects = REQUIRED_RAW_SUBJECTS - transcript_subjects
        descriptors: dict[str, dict[str, object]] = {}
        for subject in sorted(pre_nonce_subjects):
            if subject == omit:
                continue
            source = self._binding(subject)
            data = (self.root / source["path"]).read_bytes()
            filename = subject.replace(":", "-") + ".json"
            artifact = capture.write_bytes(
                subject=subject,
                kind=source["kind"],
                relative=f"raw/adversarial/observations/{filename}",
                data=data,
            )
            descriptors[subject] = artifact.descriptor.as_dict()
        session.complete_observations(descriptors)
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
        ):
            session.append(
                event,
                binding_sha256=hashlib.sha256(event.value.encode("ascii")).hexdigest(),
            )
        self.addCleanup(session.close)
        return session

    def test_post_nonce_materializer_only_reopens_frozen_manifest(self) -> None:
        session = self._frozen_session()
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("post-nonce adversarial command reran"),
        ) as runner:
            batch = materialize_adversarial_transcripts(
                session=session, proof=self.document["proof"]
            )
        runner.assert_not_called()
        self.assertEqual(len(batch.artifacts), len(REQUIRED_CASES) + 1)
        self.assertEqual(
            {binding["subject"] for binding in batch.raw_bindings},
            REQUIRED_RAW_SUBJECTS,
        )

    def test_post_nonce_materializer_retries_only_exact_prior_bytes(self) -> None:
        session = self._frozen_session()
        original = session.archive.write_bytes
        writes = 0

        def interrupted(relative: str, data: bytes, *, maximum: int):
            nonlocal writes
            writes += 1
            if writes == 5:
                raise PhysicalCaptureArchiveError(
                    "injected_interruption", "simulated post-nonce interruption"
                )
            return original(relative, data, maximum=maximum)

        with patch.object(session.archive, "write_bytes", side_effect=interrupted):
            with self.assertRaises(AdversarialCaptureError) as raised:
                materialize_adversarial_transcripts(
                    session=session, proof=self.document["proof"]
                )
        self.assertEqual(raised.exception.code, "transcript_archive_failed")
        retained = {
            name: session.archive.read_bytes(f"raw/adversarial/{name}")
            for name in session.archive.list_names("raw/adversarial")
            if name.endswith(".json")
        }
        self.assertEqual(len(retained), 4)

        batch = materialize_adversarial_transcripts(
            session=session, proof=self.document["proof"]
        )
        self.assertEqual(len(batch.artifacts), len(REQUIRED_CASES) + 1)
        for name, frozen_bytes in retained.items():
            self.assertEqual(
                session.archive.read_bytes(f"raw/adversarial/{name}"), frozen_bytes
            )

    def test_materializer_crosses_earlier_finals_to_recover_later_pending(self) -> None:
        session = self._frozen_session()
        original = session.archive.write_bytes
        writes = 0
        pending_path: Path | None = None

        def interrupted(relative: str, data: bytes, *, maximum: int):
            nonlocal writes, pending_path
            writes += 1
            if writes == 5:
                final = Path(relative).name
                pending_path = (
                    session.archive.repository
                    / "target"
                    / session.archive.root_relative_to_target
                    / "raw/adversarial"
                    / (f".{final}.pending-" + "a" * 32)
                )
                pending_path.write_bytes(data[:23])
                pending_path.chmod(PRIVATE_FILE_MODE)
                raise PhysicalCaptureArchiveError(
                    "injected_interruption", "simulated pending transcript"
                )
            return original(relative, data, maximum=maximum)

        with patch.object(session.archive, "write_bytes", side_effect=interrupted):
            with self.assertRaises(AdversarialCaptureError):
                materialize_adversarial_transcripts(
                    session=session, proof=self.document["proof"]
                )
        self.assertIsNotNone(pending_path)
        assert pending_path is not None
        self.assertTrue(pending_path.exists())

        batch = materialize_adversarial_transcripts(
            session=session, proof=self.document["proof"]
        )
        self.assertEqual(len(batch.artifacts), len(REQUIRED_CASES) + 1)
        self.assertFalse(pending_path.exists())
        self.assertEqual(session.archive.pending_files("raw/adversarial"), ())

    def test_post_nonce_materializer_rejects_mismatched_prior_bytes(self) -> None:
        session = self._frozen_session()
        session.archive.write_bytes(
            "raw/adversarial/baseline.json", b"{}\n", maximum=1024 * 1024
        )
        with self.assertRaises(AdversarialCaptureError) as raised:
            materialize_adversarial_transcripts(
                session=session, proof=self.document["proof"]
            )
        self.assertEqual(raised.exception.code, "transcript_archive_mismatch")

    def test_post_nonce_materializer_rejects_missing_precondition_observation(self) -> None:
        session = self._frozen_session(omit="observation:wrong-team-id")
        with self.assertRaisesRegex(AdversarialCaptureError, "subjects differ"):
            materialize_adversarial_transcripts(
                session=session, proof=self.document["proof"]
            )

    def test_report_materializer_never_reruns_physical_commands(self) -> None:
        session = self._frozen_session()
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("post-nonce adversarial command reran"),
        ) as runner:
            report = materialize_adversarial_report(
                session=session,
                proof=self.document["proof"],
                platform=self.document["platform"],
                signed_at=self.document["signed_at"],
            )
        runner.assert_not_called()
        self.assertEqual(report.document["schema_version"], 3)
        self.assertEqual(len(report.raw_bindings), len(REQUIRED_RAW_SUBJECTS))

    def test_xpc_requirement_assessment_uses_codesign_requirement_argument(self) -> None:
        result = Mock(
            stdout=b"",
            stderr=b"requirement rejected",
            argv_sha256="a" * 64,
            exit_code=3,
        )
        with patch.object(
            adversarial_capture, "_run_codesign", return_value=result
        ) as runner:
            assessment, exit_code = adversarial_capture._xpc_requirement_assessment(
                Mock(), path=Path("/fixed/signed-client")
            )

        self.assertEqual(len(assessment), 64)
        self.assertEqual(exit_code, 3)
        call = runner.call_args.kwargs
        self.assertEqual(call["accepted_exit_codes"], frozenset({3}))
        requirement_arguments = [
            value for value in call["argv"] if value.startswith("-R=")
        ]
        self.assertEqual(
            requirement_arguments,
            [f"-R={adversarial_capture.HOST_REQUIREMENT_TEXT}"],
        )
        self.assertNotIn("-R", call["argv"])

    def test_cleanup_failure_aborts_before_any_observation_is_archived(self) -> None:
        digest = "a" * 64
        signature = adversarial_capture._SignatureMaterial(
            assessed_at="2026-07-27T12:00:00Z",
            process_image_path="/fixed/probe",
            binary_sha256=digest,
            cdhash="b" * 40,
            team_id="YKUPL7Z869",
            signing_id="com.bill.clashformac",
            designated_requirement_sha256=digest,
            entitlements_sha256="b" * 64,
            has_required_app_group=True,
            codesign_command_sha256="c" * 64,
            codesign_output_sha256="d" * 64,
        )
        command = Mock(
            role="adversarial-probe",
            argv_sha256="e" * 64,
            started_at="2026-07-27T12:00:01Z",
            completed_at="2026-07-27T12:00:02Z",
            duration_ms=1000,
            exit_code=0,
        )
        probe = {
            "request_sha256": "f" * 64,
            "process": {"pid": 42, "start_unix_ms": 1_800_000_000_000},
            "euid": 0,
            "audit_session_id": 100_001,
            "pre_state_sha256": digest,
            "post_state_sha256": digest,
            "cleanup_state": "off",
            "boundary_evidence": {},
            "secret_coverage": None,
            "pre_reset_state_sha256": digest,
        }
        cleanup = AdversarialCaptureError("cleanup_failed", "polluted")
        server_signature = replace(
            signature,
            process_image_path=(
                "/Applications/Clash for Mac.app/Contents/Library/HelperTools/"
                "CFWGlobalAuthority"
            ),
            signing_id="com.bill.clashformac.global-authority",
        )
        with (
            patch.object(adversarial_capture, "_require_source_fixed_fixture"),
            patch.object(
                adversarial_capture,
                "_capture_signature_material",
                side_effect=[signature, server_signature],
            ),
            patch.object(
                adversarial_capture, "_validate_client_signature_semantics"
            ),
            patch.object(
                adversarial_capture,
                "_execute_probe",
                return_value=(command, probe),
            ),
            patch.object(adversarial_capture, "_query_product_events", return_value=[]),
            patch.object(
                adversarial_capture, "_execute_reset", side_effect=cleanup
            ) as reset,
            patch.object(adversarial_capture, "_write_observation") as writer,
        ):
            with self.assertRaisesRegex(AdversarialCaptureError, "emergency cleanup"):
                adversarial_capture._capture_case(
                    capture=Mock(),
                    archive=Mock(),
                    case_id="wrong-uid",
                    baseline_requirement_sha256=digest,
                    authority_process={"pid": 7, "start_unix_ms": 1_799_999_000_000},
                )
        self.assertEqual(reset.call_count, 2)
        writer.assert_not_called()

    def test_source_fixed_fixture_map_covers_only_unimplemented_cases(self) -> None:
        in_process = {
            "wrong-team-id",
            "wrong-bundle-identifier",
            "wrong-designated-requirement",
            "wrong-entitlement",
            "same-team-unknown-bundle",
            "oversize-message",
            "deep-message",
            "noncanonical-message",
        }
        self.assertEqual(
            set(SOURCE_FIXED_PRECONDITIONS), set(REQUIRED_CASES) - in_process
        )
        self.assertEqual(len(SOURCE_FIXED_PRECONDITIONS), 24)

    def test_external_fixture_specs_close_exact_ten_controller_contract(self) -> None:
        expected_fixture_ids = set(SOURCE_FIXED_PRECONDITIONS.values())
        self.assertEqual(set(EXTERNAL_FIXTURE_SPECS), expected_fixture_ids)
        self.assertEqual(len(EXTERNAL_FIXTURE_SPECS), 10)
        targets: set[str] = set()
        for spec in EXTERNAL_FIXTURE_SPECS.values():
            self.assertEqual(
                set(spec),
                {
                    "target",
                    "source_path",
                    "executable",
                    "privileged",
                    "reset_required",
                },
            )
            target = spec["target"]
            self.assertIsInstance(target, str)
            self.assertNotIn(target, targets)
            targets.add(target)
            self.assertEqual(
                spec["source_path"],
                f"native/macos/PhysicalFixtures/{target}/main.swift",
            )
            self.assertEqual(spec["executable"], "CFWAdversarialFixture")

    def test_fixed_fixture_argv_never_accepts_a_caller_command_or_path(self) -> None:
        for case_id, fixture_id in SOURCE_FIXED_PRECONDITIONS.items():
            expected = str(
                adversarial_capture.FIXTURE_ROOT
                / fixture_id
                / case_id
                / "CFWAdversarialFixture"
            )
            argv = adversarial_capture._probe_argv(case_id, "execute")
            self.assertIn(expected, argv)
            self.assertEqual(argv[-2:], ("execute", case_id))
            self.assertNotIn("/bin/sh", argv)
            self.assertNotIn("-c", argv)

    def test_typed_precondition_failure_never_becomes_a_probe_result(self) -> None:
        case_id = "request-flood"
        document = {
            "schema_version": 1,
            "document": adversarial_capture.PRECONDITION_DOCUMENT,
            "code": "physical_precondition_unavailable",
            "case_id": case_id,
            "fixture_id": SOURCE_FIXED_PRECONDITIONS[case_id],
        }
        result = CommandResult(
            role="adversarial-probe",
            argv_sha256="a" * 64,
            started_at="2026-08-02T00:00:00.000000Z",
            completed_at="2026-08-02T00:00:01.000000Z",
            duration_ms=1_000,
            exit_code=adversarial_capture.PRECONDITION_UNAVAILABLE_EXIT,
            stdout=canonical_json(document) + b"\n",
            stderr=b"",
        )
        capture = Mock()
        capture.run_command.return_value = result
        with self.assertRaises(AdversarialCaptureError) as raised:
            adversarial_capture._execute_probe(capture, case_id)
        self.assertEqual(raised.exception.code, "physical_precondition_unavailable")

    def test_typed_precondition_rejects_fixture_id_drift(self) -> None:
        case_id = "request-flood"
        document = {
            "schema_version": 1,
            "document": adversarial_capture.PRECONDITION_DOCUMENT,
            "code": "physical_precondition_unavailable",
            "case_id": case_id,
            "fixture_id": "different-controller",
        }
        result = CommandResult(
            role="adversarial-probe",
            argv_sha256="a" * 64,
            started_at="2026-08-02T00:00:00.000000Z",
            completed_at="2026-08-02T00:00:01.000000Z",
            duration_ms=1_000,
            exit_code=adversarial_capture.PRECONDITION_UNAVAILABLE_EXIT,
            stdout=canonical_json(document) + b"\n",
            stderr=b"",
        )
        capture = Mock()
        capture.run_command.return_value = result
        with self.assertRaises(AdversarialCaptureError) as raised:
            adversarial_capture._execute_probe(capture, case_id)
        self.assertEqual(raised.exception.code, "precondition_result_invalid")

    def test_missing_fixture_stops_before_any_receipt_bound_subject(self) -> None:
        unavailable = AdversarialCaptureError(
            "physical_precondition_unavailable", "missing fixed fixture"
        )
        with (
            patch.object(
                adversarial_capture,
                "_require_source_fixed_fixture",
                side_effect=unavailable,
            ),
            patch.object(adversarial_capture, "_write_observation") as writer,
        ):
            with self.assertRaises(AdversarialCaptureError) as raised:
                adversarial_capture._capture_case(
                    capture=Mock(),
                    archive=Mock(),
                    case_id="request-flood",
                    baseline_requirement_sha256="a" * 64,
                    authority_process={"pid": 7, "start_unix_ms": 1},
                )
        self.assertEqual(raised.exception.code, "physical_precondition_unavailable")
        writer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
