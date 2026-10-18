from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from scripts.physical_capture.finalize import (
    PhysicalCaptureFinalizationError,
    REPORT_SET_DOCUMENT,
    _load_or_create_signing_time,
    _validate_report_set,
    _write_or_reopen_json,
    finalize_session,
)
from scripts.physical_capture.archive import PRIVATE_FILE_MODE
from scripts.tests.physical_evidence_fixture import (
    PhysicalEvidenceFixture,
    fixture_packet_policy,
)
from scripts.physical_capture.session import (
    CaptureEvent,
    CaptureState,
    PhysicalCaptureSession,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class PhysicalCaptureFinalizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir()
        self.session = PhysicalCaptureSession.create(
            self.repository, "finalize", intent_sha256=_digest("intent")
        )
        self.addCleanup(self.session.close)
        self.session.append(
            CaptureEvent.COLLECTION_STARTED, binding_sha256=_digest("collect")
        )

    def raw_complete(self) -> None:
        artifact = self.session.observation_capture().write_bytes(
            subject="test:observation",
            kind="performance-sample-ledger",
            relative="raw/performance/observations/test.json",
            data=b'{"proof_free":true}\n',
        )
        self.session.complete_observations(
            {artifact.subject: artifact.descriptor.as_dict()}
        )

    def test_exact_derived_write_is_idempotent_but_never_replaceable(self) -> None:
        value = {"schema_version": 1, "document": "test-derived"}
        first = _write_or_reopen_json(
            self.session, "derived/test.json", value, maximum=4096
        )
        second = _write_or_reopen_json(
            self.session, "derived/test.json", value, maximum=4096
        )
        self.assertEqual(first, second)
        with self.assertRaises(PhysicalCaptureFinalizationError) as raised:
            _write_or_reopen_json(
                self.session,
                "derived/test.json",
                {**value, "changed": True},
                maximum=4096,
            )
        self.assertEqual(raised.exception.code, "derived_archive_mismatch")

    def test_derived_prefix_pending_is_recovered_without_residue(self) -> None:
        value = {"schema_version": 1, "document": "test-derived-pending"}
        data = (
            b'{"document":"test-derived-pending","schema_version":1}\n'
        )
        self.session.archive.ensure_directory("derived")
        pending = (
            self.repository
            / "target/finalize/derived"
            / (".test-pending.json.pending-" + "a" * 32)
        )
        pending.write_bytes(data[:13])
        pending.chmod(PRIVATE_FILE_MODE)
        archived = _write_or_reopen_json(
            self.session,
            "derived/test-pending.json",
            value,
            maximum=4096,
        )
        self.assertEqual(archived.size, len(data))
        self.assertFalse(pending.exists())
        self.assertEqual(
            self.session.archive.read_bytes("derived/test-pending.json"), data
        )

    def test_report_signing_time_is_fixed_once(self) -> None:
        first = _load_or_create_signing_time(self.session)
        second = _load_or_create_signing_time(self.session)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("Z"))

        signing_time = self.repository / "target/finalize/derived/report-signing-time.json"
        signing_time.write_text(
            '{"document":"cfw-physical-report-signing-time-v1",'
            '"schema_version":1,"signed_at":"2026-08-02T00:00:00.000Z"}\n',
            encoding="utf-8",
        )
        with self.assertRaises(PhysicalCaptureFinalizationError) as raised:
            _load_or_create_signing_time(self.session)
        self.assertEqual(raised.exception.code, "report_signing_time_invalid")

    def test_interrupted_nonce_attempt_becomes_terminal_without_retry(self) -> None:
        self.raw_complete()
        self.session.append(
            CaptureEvent.NONCE_REQUEST_PREPARED,
            binding_sha256=_digest("nonce-request"),
        )
        self.session.append(
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            binding_sha256=_digest("nonce-request"),
        )

        class _ForbiddenClient:
            def issue_nonce(self, _request: object) -> object:
                raise AssertionError("interrupted transaction must not retry")

            def issue_receipt(self, _request: object) -> object:
                raise AssertionError("interrupted transaction must not retry")

        with self.assertRaises(PhysicalCaptureFinalizationError) as raised:
            finalize_session(
                session=self.session,
                context={},
                client=_ForbiddenClient(),
            )
        self.assertEqual(raised.exception.code, "network_outcome_unknown")
        self.assertEqual(self.session.state, CaptureState.NONCE_OUTCOME_UNKNOWN)

    def test_report_set_reopens_report_bytes_and_exact_raw_bindings(self) -> None:
        evidence_root = self.repository / "target/evidence-fixture"
        fixture = PhysicalEvidenceFixture(evidence_root)
        reports = {
            binding["harness"]: {
                "tool_version": binding["tool_version"],
                "captured_at": binding["captured_at"],
                "completed_at": binding["completed_at"],
                "signed_at": binding["signed_at"],
                "artifact": copy.deepcopy(binding["descriptor"]),
            }
            for binding in fixture.report_bindings[0]
        }
        report_set = {
            "schema_version": 1,
            "document": REPORT_SET_DOCUMENT,
            "reports": reports,
            "raw_artifacts": sorted(
                copy.deepcopy(fixture.raw_bindings[0]),
                key=lambda binding: (binding["harness"], binding["subject"]),
            ),
        }
        fake_session = SimpleNamespace(
            archive=SimpleNamespace(
                repository=self.repository,
                root_relative_to_target="evidence-fixture",
            )
        )
        with fixture_packet_policy():
            normalized_reports, normalized_raw = _validate_report_set(
                fake_session, report_set
            )
        self.assertEqual(set(normalized_reports), set(reports))
        self.assertEqual(len(normalized_raw), len(fixture.raw_bindings[0]))

        report_set["reports"]["packet"]["captured_at"] = (
            "2026-07-27T00:00:00Z"
        )
        with fixture_packet_policy():
            with self.assertRaises(PhysicalCaptureFinalizationError) as raised:
                _validate_report_set(fake_session, report_set)
        self.assertEqual(raised.exception.code, "report_set_invalid")


if __name__ == "__main__":
    unittest.main()
