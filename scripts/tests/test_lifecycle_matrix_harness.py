from __future__ import annotations

import copy
from datetime import datetime
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

    def named_raw_probe(self, probe_id: str) -> tuple[dict, dict]:
        probe = next(item for item in self.document["probes"] if item["id"] == probe_id)
        path = self.root / probe["artifact"]["path"]
        return probe, json.loads(path.read_text(encoding="utf-8"))

    def artifact_json(self, descriptor: dict) -> dict:
        return json.loads((self.root / descriptor["path"]).read_text(encoding="utf-8"))

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

    def test_renderer_ready_requires_exact_signed_two_process_order(self) -> None:
        probe, raw = self.named_raw_probe("renderer-ready-v2")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        trace = self.artifact_json(trace_descriptor)
        trace["events"][4], trace["events"][5] = trace["events"][5], trace["events"][4]
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "ordered sequence"):
            self.validate()

    def test_renderer_ready_requires_matching_release_signatures(self) -> None:
        probe, raw = self.named_raw_probe("renderer-ready-v2")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        trace = self.artifact_json(trace_descriptor)
        trace["processes"][1]["team_id"] = "WRONGTEAM1"
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "release identity"):
            self.validate()

    def test_renderer_ready_rejects_pid_reuse_with_a_different_start(self) -> None:
        probe, raw = self.named_raw_probe("renderer-ready-v2")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        trace = self.artifact_json(trace_descriptor)
        trace["processes"][1]["pid"] = trace["processes"][0]["pid"]
        self.assertNotEqual(
            trace["processes"][1]["start_unix_us"],
            trace["processes"][0]["start_unix_us"],
        )
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "PIDs are not distinct"):
            self.validate()

    def test_renderer_ready_rejects_child_start_outside_trace_window(self) -> None:
        probe, raw = self.named_raw_probe("renderer-ready-v2")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        trace = self.artifact_json(trace_descriptor)
        trace["processes"][1]["start_unix_us"] = (
            trace["processes"][0]["start_unix_us"] - 1
        )
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "parent/child trace window"):
            self.validate()

    def test_renderer_ready_rejects_child_start_at_trace_completion(self) -> None:
        probe, raw = self.named_raw_probe("renderer-ready-v2")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        trace = self.artifact_json(trace_descriptor)
        completed_at = datetime.fromisoformat(
            trace["completed_at"].removesuffix("Z") + "+00:00"
        )
        trace["processes"][1]["start_unix_us"] = int(
            completed_at.timestamp() * 1_000_000
        )
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "parent/child trace window"):
            self.validate()

    def test_network_extension_outcomes_are_typed_raw_traces(self) -> None:
        for probe_id in (
            "network-extension-approval",
            "network-extension-denial",
            "network-extension-pending",
        ):
            with self.subTest(probe_id=probe_id):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    fixture = PhysicalEvidenceFixture(root)
                    document = fixture.report_documents[0]["lifecycle"]
                    probe = next(
                        item for item in document["probes"] if item["id"] == probe_id
                    )
                    raw = json.loads(
                        (root / probe["artifact"]["path"]).read_text(encoding="utf-8")
                    )
                    trace_descriptor = raw["evidence"]["trace_artifact"]
                    trace = json.loads(
                        (root / trace_descriptor["path"]).read_text(encoding="utf-8")
                    )
                    trace["events"][-1]["state"] = "handwritten-passed"
                    fixture.rewrite_json(trace_descriptor, trace)
                    fixture.rewrite_json(probe["artifact"], raw)
                    with ArtifactReader(root) as artifacts:
                        with self.assertRaisesRegex(
                            LifecycleMatrixError, "typed state sequence"
                        ):
                            validate_lifecycle_matrix(document, artifacts)

    def test_sleep_wake_requires_post_wake_token_in_packet_bytes(self) -> None:
        probe, raw = self.named_raw_probe("sleep-wake")
        trace_descriptor = raw["evidence"]["trace_artifact"]
        capture_descriptor = raw["evidence"]["capture_artifact"]
        trace = self.artifact_json(trace_descriptor)
        capture_path = self.root / capture_descriptor["path"]
        capture = capture_path.read_bytes()
        token = trace["post_wake_token"].encode("ascii")
        self.assertIn(token, capture)
        self.fixture.rewrite(capture_descriptor, capture.replace(token, b"x" * len(token)))
        trace["capture_sha256"] = capture_descriptor["sha256"]
        self.fixture.rewrite_json(trace_descriptor, trace)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(
            LifecycleMatrixError, "post-wake traffic|required unique token"
        ):
            self.validate()

    def test_wkwebview_requires_exact_850x603_metadata(self) -> None:
        probe, raw = self.named_raw_probe("wkwebview-850x603")
        metadata_descriptor = raw["evidence"]["metadata_artifact"]
        metadata = self.artifact_json(metadata_descriptor)
        metadata["viewport_width_css_pixels"] = 849
        self.fixture.rewrite_json(metadata_descriptor, metadata)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "850x603"):
            self.validate()

    def test_wkwebview_requires_nonblank_raw_rgba_pixels(self) -> None:
        probe, raw = self.named_raw_probe("wkwebview-850x603")
        metadata_descriptor = raw["evidence"]["metadata_artifact"]
        pixels_descriptor = raw["evidence"]["pixels_artifact"]
        metadata = self.artifact_json(metadata_descriptor)
        blank = b"\x00\x00\x00\xff" * (
            metadata["pixel_width"] * metadata["pixel_height"]
        )
        self.fixture.rewrite(pixels_descriptor, blank)
        metadata["pixels_sha256"] = pixels_descriptor["sha256"]
        self.fixture.rewrite_json(metadata_descriptor, metadata)
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "blank or insufficiently rendered"):
            self.validate()

    def test_generic_probe_cannot_replace_raw_evidence_with_a_status_string(self) -> None:
        probe, raw = self.named_raw_probe("login")
        raw["evidence"] = {"status": "passed"}
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "evidence must be null"):
            self.validate()

    def test_lifecycle_v2_raw_event_is_rejected_without_compatibility_fallback(self) -> None:
        probe, raw = self.raw_probe(0)
        raw["schema_version"] = 1
        self.fixture.rewrite_json(probe["artifact"], raw)
        with self.assertRaisesRegex(LifecycleMatrixError, "schema_version must be 2"):
            self.validate()

    def test_lifecycle_v2_report_is_rejected_without_compatibility_fallback(self) -> None:
        self.document["schema_version"] = 2
        self.document["harness_version"] = "lifecycle-matrix-v2"
        with self.assertRaisesRegex(LifecycleMatrixError, "schema_version must be 3"):
            self.validate()

    def test_schema_versions_require_json_integers(self) -> None:
        for invalid in (3.0, True):
            with self.subTest(scope="report", invalid=invalid):
                document = copy.deepcopy(self.document)
                document["schema_version"] = invalid
                with self.assertRaisesRegex(LifecycleMatrixError, "schema_version must be 3"):
                    self.validate(document)

        probe, original = self.raw_probe(0)
        try:
            for invalid in (2.0, True):
                with self.subTest(scope="raw-event", invalid=invalid):
                    raw = copy.deepcopy(original)
                    raw["schema_version"] = invalid
                    self.fixture.rewrite_json(probe["artifact"], raw)
                    with self.assertRaisesRegex(
                        LifecycleMatrixError, "schema_version must be 2"
                    ):
                        self.validate()
        finally:
            self.fixture.rewrite_json(probe["artifact"], original)


if __name__ == "__main__":
    unittest.main()
