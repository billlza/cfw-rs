from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.harness.performance_gates import (
    PerformanceGateError,
    validate_performance_evidence,
)
from scripts.harness.performance_ledger import (
    PerformanceLedgerError,
    _log_query_timestamp,
    _oslog_timestamp,
)
from scripts.harness.raw_artifacts import ArtifactReader, load_json_bytes
from scripts.tests.physical_evidence_fixture import PhysicalEvidenceFixture


class PerformanceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = copy.deepcopy(self.fixture.report_documents[0]["performance"])
        self.ledger_artifact = self.document["ledger_artifact"]

    def read(self, descriptor: dict[str, object]) -> dict[str, object]:
        data = (self.root / str(descriptor["path"])).read_bytes()
        value = load_json_bytes(data, "performance test artifact")
        self.assertIsInstance(value, dict)
        return value

    def rewrite_ledger(self, ledger: dict[str, object]) -> None:
        self.fixture.rewrite_json(self.ledger_artifact, ledger)
        self.document["ledger_artifact"] = self.ledger_artifact

    @staticmethod
    def rewrite_command_stdout(command: dict[str, object], stdout: str) -> None:
        encoded = stdout.encode("utf-8")
        command["stdout"] = stdout
        command["stdout_size"] = len(encoded)
        command["stdout_sha256"] = hashlib.sha256(encoded).hexdigest()

    def validate(self) -> dict[str, object]:
        with ArtifactReader(self.root) as artifacts:
            return validate_performance_evidence(self.document, artifacts)

    def test_complete_three_artifact_ledger_passes(self) -> None:
        result = self.validate()
        self.assertEqual(
            {entry["subject"] for entry in result["artifacts"]},
            {"sample-ledger", "shaping-intent", "shaping-restoration"},
        )
        self.assertEqual(
            self.document["soak"],
            {
                "duration_hours": 3.005,
                "heartbeat_count": 37,
                "traffic_count": 13,
                "crash_count": 0,
            },
        )

    def test_deleting_any_sample_fails_exact_count(self) -> None:
        ledger = self.read(self.ledger_artifact)
        ledger["samples"].pop(100)  # type: ignore[index,union-attr]
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "exactly 353 samples"):
            self.validate()

    def test_two_endpoint_fake_three_hour_soak_fails_continuity(self) -> None:
        ledger = self.read(self.ledger_artifact)
        samples = ledger["samples"]  # type: ignore[index]
        ledger["samples"] = [  # type: ignore[index]
            sample
            for sample in samples  # type: ignore[union-attr]
            if sample["kind"] not in {"soak-heartbeat", "soak-traffic"}
            or sample["measurement"]["index"] in {0, 36, 12}
        ]
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "exactly 353 samples"):
            self.validate()

    def test_wrong_process_roster_is_rejected(self) -> None:
        ledger = self.read(self.ledger_artifact)
        sample = ledger["samples"][0]  # type: ignore[index]
        sample["roster"][0]["pid"] += 1
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "PID set|Host differs|did not find"):
            self.validate()

    def test_wrong_generation_is_rejected(self) -> None:
        ledger = self.read(self.ledger_artifact)
        sample = ledger["samples"][0]  # type: ignore[index]
        sample["generation"] += 1
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "generation.*drifted"):
            self.validate()

    def test_missing_restoration_artifact_blocks(self) -> None:
        restoration = self.document["shaping_restoration_artifact"]
        (self.root / restoration["path"]).unlink()
        with self.assertRaisesRegex(PerformanceGateError, "cannot be opened|missing|unavailable"):
            self.validate()

    def test_restoration_query_must_equal_original_state(self) -> None:
        restoration_descriptor = self.document["shaping_restoration_artifact"]
        restoration = self.read(restoration_descriptor)
        command = restoration["transactions"][0]["restoration_queries"][0]  # type: ignore[index]
        self.rewrite_command_stdout(command, "40001: still active\n")
        self.fixture.rewrite_json(restoration_descriptor, restoration)
        ledger = self.read(self.ledger_artifact)
        ledger["shaping"]["restoration_artifact"] = restoration_descriptor  # type: ignore[index]
        self.document["shaping_restoration_artifact"] = restoration_descriptor
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "restoration query differs"):
            self.validate()

    def test_shaping_requires_packet_filter_already_enabled(self) -> None:
        intent_descriptor = self.document["shaping_intent_artifact"]
        intent = self.read(intent_descriptor)
        command = intent["original_state"]["pf_status_query"]  # type: ignore[index]
        self.rewrite_command_stdout(command, "Status: Disabled\n")
        self.fixture.rewrite_json(intent_descriptor, intent)
        ledger = self.read(self.ledger_artifact)
        ledger["shaping"]["intent_artifact"] = intent_descriptor  # type: ignore[index]
        self.document["shaping_intent_artifact"] = intent_descriptor
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "not already enabled"):
            self.validate()

    def test_shaping_effective_pf_rules_must_be_exact(self) -> None:
        restoration_descriptor = self.document["shaping_restoration_artifact"]
        restoration = self.read(restoration_descriptor)
        command = restoration["transactions"][0]["effective_queries"][1]  # type: ignore[index]
        self.rewrite_command_stdout(
            command,
            command["stdout"] + "pass out all\n",  # type: ignore[operator]
        )
        self.fixture.rewrite_json(restoration_descriptor, restoration)
        ledger = self.read(self.ledger_artifact)
        ledger["shaping"]["restoration_artifact"] = restoration_descriptor  # type: ignore[index]
        self.document["shaping_restoration_artifact"] = restoration_descriptor
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "exact reviewed PF rules"):
            self.validate()

    def test_off_generation_may_be_nonzero_after_real_transition(self) -> None:
        ledger = self.read(self.ledger_artifact)
        off_generations = [
            sample["generation"]
            for sample in ledger["samples"]  # type: ignore[index]
            if sample["mode"] == "off"
        ]
        self.assertTrue(any(generation > 0 for generation in off_generations))
        self.validate()

    def test_runtime_codesign_identity_cannot_be_declared_away(self) -> None:
        ledger = self.read(self.ledger_artifact)
        process = ledger["samples"][0]["roster"][0]  # type: ignore[index]
        process["runtime_signing_command"]["stderr"] = ""
        process["runtime_signing_command"]["stderr_size"] = 0
        process["runtime_signing_command"]["stderr_sha256"] = hashlib.sha256(b"").hexdigest()
        self.rewrite_ledger(ledger)
        with self.assertRaisesRegex(PerformanceGateError, "runtime code identity differs"):
            self.validate()

    def test_report_summary_is_recomputed_from_ledger(self) -> None:
        self.document["throughput"]["ratio_percent"] = 100.0
        with self.assertRaisesRegex(PerformanceGateError, "throughput summary differs"):
            self.validate()

    def test_raw_byte_drift_fails_before_semantics(self) -> None:
        path = self.root / self.ledger_artifact["path"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(PerformanceGateError, "size does not match"):
            self.validate()

    def test_report_signature_must_follow_ledger_completion(self) -> None:
        self.document["signed_at"] = "2026-07-27T12:00:00Z"
        with self.assertRaisesRegex(PerformanceGateError, "signed before"):
            self.validate()


class PerformanceTimestampTests(unittest.TestCase):
    def test_actual_ndjson_oslog_timestamp_shape_is_accepted(self) -> None:
        parsed = _oslog_timestamp(
            "2026-08-01 20:04:51.924344+0000", "product log timestamp"
        )
        self.assertEqual(parsed.isoformat(), "2026-08-01T20:04:51.924344+00:00")

    def test_non_oslog_timestamp_shape_is_rejected(self) -> None:
        with self.assertRaisesRegex(PerformanceLedgerError, "OSLog timestamp"):
            _oslog_timestamp("2026-08-01T20:04:51.924Z", "product log timestamp")

    def test_log_show_cli_boundary_shape_is_accepted(self) -> None:
        parsed = _log_query_timestamp(
            "2026-08-01 20:04:51", "product log query end"
        )
        self.assertEqual(parsed.isoformat(), "2026-08-01T20:04:51+00:00")

    def test_iso_timestamp_is_not_accepted_as_log_show_cli_boundary(self) -> None:
        with self.assertRaisesRegex(PerformanceLedgerError, "log-show boundary"):
            _log_query_timestamp("2026-08-01T20:04:51Z", "product log query end")


if __name__ == "__main__":
    unittest.main()
