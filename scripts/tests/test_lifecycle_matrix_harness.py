from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.harness.lifecycle_matrix import (
    PROBE_SPECS,
    REQUIRED_PROBES,
    LifecycleMatrixError,
    probe_matrix,
    required_probe_ids,
    validate_lifecycle_matrix,
)
from scripts.harness.raw_artifacts import ArtifactReader
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class LifecycleMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["lifecycle"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self, document: dict | None = None) -> dict:
        with ArtifactReader(self.root) as artifacts:
            return validate_lifecycle_matrix(
                self.document if document is None else document, artifacts
            )

    def raw_probe(self, index: int) -> tuple[dict, dict]:
        probe = self.document["probes"][index]
        path = self.root / probe["artifact"]["path"]
        return probe, json.loads(path.read_text(encoding="utf-8"))

    def test_full_matrix_reopens_every_raw_event(self) -> None:
        result = self.validate()
        self.assertEqual(set(result["probes"]), set(REQUIRED_PROBES))
        self.assertEqual(required_probe_ids(), frozenset(PROBE_SPECS))
        self.assertEqual(set(probe_matrix()), set(PROBE_SPECS))

    def test_missing_probe_fails_closed(self) -> None:
        self.document["probes"].pop()
        with self.assertRaisesRegex(LifecycleMatrixError, "every required probe"):
            self.validate()

    def test_raw_command_exit_code_mismatch_fails(self) -> None:
        probe, raw = self.raw_probe(0)
        raw["exit_code"] = 99
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "exit_code differs"):
            self.validate()

    def test_raw_event_sequence_mismatch_fails(self) -> None:
        probe, raw = self.raw_probe(0)
        raw["events"][1]["observation"] = "handwritten-passed"
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "required sequence"):
            self.validate()

    def test_report_attribute_disagrees_with_raw_bytes(self) -> None:
        probe = next(
            item
            for item in self.document["probes"]
            if item["id"] == "fast-user-switching"
        )
        probe["attributes"]["user_count"] = 3
        with self.assertRaisesRegex(LifecycleMatrixError, "attributes differ"):
            self.validate()

    def test_raw_candidate_run_binding_mismatch_fails(self) -> None:
        probe, raw = self.raw_probe(0)
        raw["proof"]["run_id"] = "foreign-run"
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "proof binding differs"):
            self.validate()

    def test_raw_environment_mismatch_fails(self) -> None:
        probe, raw = self.raw_probe(0)
        raw["environment"]["macos_build"] = "23F79"
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "environment differs"):
            self.validate()

    def test_replayed_raw_event_descriptor_fails(self) -> None:
        self.document["probes"][1]["artifact"] = copy.deepcopy(
            self.document["probes"][0]["artifact"]
        )
        with self.assertRaisesRegex(LifecycleMatrixError, "reuses artifact"):
            self.validate()

    def test_handwritten_status_field_is_not_accepted(self) -> None:
        self.document["probes"][0]["status"] = "passed"
        with self.assertRaisesRegex(LifecycleMatrixError, "unknown fields"):
            self.validate()

    def test_capture_timestamp_must_come_from_raw_events(self) -> None:
        self.document["captured_at"] = "2026-07-22T01:00:00Z"
        with self.assertRaisesRegex(LifecycleMatrixError, "earliest raw"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
