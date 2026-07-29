from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.harness.performance_gates import (
    PerformanceGateError,
    percentiles,
    validate_performance_evidence,
)
from scripts.harness.raw_artifacts import ArtifactReader
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class PerformanceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["performance"]
        self.artifact = self.document["samples_artifact"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def raw(self) -> dict:
        return json.loads((self.root / self.artifact["path"]).read_text(encoding="utf-8"))

    def validate(self) -> dict:
        with ArtifactReader(self.root) as artifacts:
            return validate_performance_evidence(self.document, artifacts)

    def test_all_summaries_are_recomputed_from_raw_bytes(self) -> None:
        result = self.validate()
        self.assertEqual(result["artifacts"][0]["subject"], "measurements")
        self.assertEqual(percentiles([1.0, 2.0, 3.0]), {"p50": 2.0, "p95": 3.0, "p99": 3.0})

    def test_declared_percentile_disagrees_with_raw_samples(self) -> None:
        self.document["latency"]["connect_ms"]["p95"] = 1.0
        with self.assertRaisesRegex(PerformanceGateError, "does not match the raw"):
            self.validate()

    def test_raw_sample_drift_fails_before_semantics(self) -> None:
        path = self.root / self.artifact["path"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(PerformanceGateError, "size does not match"):
            self.validate()

    def test_raw_sample_threshold_violation_fails(self) -> None:
        raw = self.raw()
        raw["latency"]["connect_ms"] = [7000.0] * 20
        self.fixture.rewrite_json(self.artifact, raw)
        self.document["latency"]["connect_ms"] = percentiles([7000.0] * 20)
        with self.assertRaisesRegex(PerformanceGateError, "exceeds"):
            self.validate()

    def test_throughput_declaration_is_derived_from_raw_samples(self) -> None:
        self.document["throughput"]["ratio_percent"] = 99.0
        with self.assertRaisesRegex(PerformanceGateError, "ratio declaration differs"):
            self.validate()

    def test_switch_count_is_derived_from_contiguous_raw_records(self) -> None:
        raw = self.raw()
        raw["switch_cycle"]["records"][3]["index"] = 9
        self.fixture.rewrite_json(self.artifact, raw)
        with self.assertRaisesRegex(PerformanceGateError, "not contiguous"):
            self.validate()

    def test_soak_duration_is_derived_from_raw_timestamps(self) -> None:
        raw = self.raw()
        raw["soak"]["ended_at"] = "2026-07-28T11:00:00Z"
        self.fixture.rewrite_json(self.artifact, raw)
        self.document["soak"]["duration_hours"] = 23.0
        with self.assertRaisesRegex(PerformanceGateError, "fails the gate"):
            self.validate()

    def test_soak_crash_events_cannot_be_declared_away(self) -> None:
        raw = self.raw()
        raw["soak"]["crash_events"] = [
            {"timestamp": "2026-07-27T13:00:00Z", "code": "providerCrash"}
        ]
        self.fixture.rewrite_json(self.artifact, raw)
        with self.assertRaisesRegex(PerformanceGateError, "crash_count declaration differs"):
            self.validate()

    def test_raw_candidate_run_binding_mismatch_fails(self) -> None:
        raw = self.raw()
        raw["proof"]["run_nonce"] = "e" * 64
        self.fixture.rewrite_json(self.artifact, raw)
        with self.assertRaisesRegex(PerformanceGateError, "proof differs"):
            self.validate()

    def test_raw_completion_must_equal_soak_completion(self) -> None:
        raw = self.raw()
        raw["completed_at"] = "2026-07-28T11:59:59Z"
        self.fixture.rewrite_json(self.artifact, raw)
        with self.assertRaisesRegex(PerformanceGateError, "soak completion"):
            self.validate()

    def test_report_signature_must_follow_raw_completion(self) -> None:
        self.document["signed_at"] = "2026-07-28T11:59:59Z"
        with self.assertRaisesRegex(PerformanceGateError, "predates raw completion"):
            self.validate()

    def test_shaping_control_command_failure_fails(self) -> None:
        raw = self.raw()
        raw["weak_network"][0]["control"]["command_exit_code"] = 1
        self.fixture.rewrite_json(self.artifact, raw)
        with self.assertRaisesRegex(PerformanceGateError, "not zero"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
